import { readdirSync, readFileSync, existsSync } from "fs";
import { join, resolve } from "path";

interface PostureArea {
  name: string;
  risk: "critical" | "high" | "medium" | "low";
  files: string[];
  description: string;
}

interface PostureResult {
  riskProfile: "critical" | "high" | "medium" | "low";
  summary: string;
  sensitiveAreas: PostureArea[];
  guardRecommendations: string[];
  highRiskWorkflows: string[];
  priorityFixes: string[];
  stats: { files: number; dirs: number; hasAuth: boolean; hasPayments: boolean; hasPII: boolean; hasInfra: boolean };
}

function tryRead(path: string): string | null {
  try { return existsSync(path) ? readFileSync(path, "utf-8") : null; } catch { return null; }
}

function countFiles(dir: string, depth: number = 0): { files: number; dirs: number } {
  if (depth > 5) return { files: 0, dirs: 0 };
  let files = 0, dirs = 0;
  const skip = new Set(["node_modules", ".git", ".next", "build", "dist", "coverage"]);
  try {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (skip.has(entry.name)) continue;
      if (entry.isDirectory()) { dirs++; const sub = countFiles(join(dir, entry.name), depth + 1); files += sub.files; dirs += sub.dirs; }
      else if (entry.isFile()) files++;
    }
  } catch { /* skip */ }
  return { files, dirs };
}

function findFiles(dir: string, patterns: string[], depth: number = 0): string[] {
  if (depth > 6) return [];
  const results: string[] = [];
  const skip = new Set(["node_modules", ".git", ".next", "build", "dist", "coverage"]);
  try {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (skip.has(entry.name)) continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) results.push(...findFiles(full, patterns, depth + 1));
      else if (entry.isFile()) {
        const name = entry.name.toLowerCase();
        if (patterns.some(p => name.includes(p))) results.push(full);
      }
    }
  } catch { /* skip */ }
  return results;
}

export function repoSecurityPosture(path: string, format: "markdown" | "json" = "markdown"): string {
  const root = resolve(path);
  const pkg = tryRead(join(root, "package.json"));
  const deps = pkg ? Object.keys({ ...JSON.parse(pkg).dependencies, ...JSON.parse(pkg).devDependencies }) : [];
  const has = (s: string) => deps.some(d => d.includes(s));

  const { files, dirs } = countFiles(root);
  const sensitiveAreas: PostureArea[] = [];
  const highRiskWorkflows: string[] = [];
  const priorityFixes: string[] = [];
  const guardRecommendations: string[] = [];

  // --- Auth surface ---
  const hasAuth = has("clerk") || has("next-auth") || has("@auth/") || has("@supabase/auth") || has("firebase");
  const authFiles = findFiles(root, ["auth", "login", "signup", "session", "middleware", "proxy"]);
  if (authFiles.length > 0) {
    sensitiveAreas.push({ name: "Authentication", risk: "critical", files: authFiles.slice(0, 10),
      description: "Auth logic — any vulnerability here means full account takeover." });
    guardRecommendations.push("Enable strict review for auth/ and middleware files.");
  }

  // --- Payment surface ---
  const hasPayments = has("stripe") || has("@polar") || has("lemonsqueezy");
  const paymentFiles = findFiles(root, ["payment", "stripe", "checkout", "billing", "subscription", "webhook"]);
  if (paymentFiles.length > 0) {
    sensitiveAreas.push({ name: "Payments", risk: "critical", files: paymentFiles.slice(0, 10),
      description: "Payment flow — financial impact, PCI-DSS scope." });
    highRiskWorkflows.push("Payment webhook endpoints must verify signatures.");
    guardRecommendations.push("Block PRs touching payment files without review.");
  }

  // --- PII / user data ---
  const hasPII = has("prisma") || has("drizzle") || has("@supabase") || has("mongoose");
  const piiFiles = findFiles(root, ["user", "profile", "account", "patient", "customer", "personal"]);
  if (piiFiles.length > 0) {
    sensitiveAreas.push({ name: "PII / User Data", risk: "high", files: piiFiles.slice(0, 10),
      description: "Contains user personal data — GDPR/CCPA scope." });
    priorityFixes.push("Ensure all PII queries have access control (RLS or WHERE userId).");
  }

  // --- Admin surface ---
  const adminFiles = findFiles(root, ["admin", "dashboard", "internal", "management"]);
  if (adminFiles.length > 0) {
    sensitiveAreas.push({ name: "Admin / Internal", risk: "high", files: adminFiles.slice(0, 10),
      description: "Admin interfaces — privilege escalation target." });
    guardRecommendations.push("Admin routes need role-based access control check.");
  }

  // --- API surface ---
  const apiFiles = findFiles(root, ["route.ts", "route.js", "api"]);
  if (apiFiles.length > 0) {
    sensitiveAreas.push({ name: "API Surface", risk: "medium", files: apiFiles.slice(0, 10),
      description: `${apiFiles.length} API endpoints — attack surface for injection and auth bypass.` });
    if (apiFiles.length > 20) highRiskWorkflows.push("Large API surface — consider API gateway rate limiting.");
  }

  // --- Infrastructure ---
  const hasInfra = existsSync(join(root, "Dockerfile")) || existsSync(join(root, "docker-compose.yml")) ||
    existsSync(join(root, "terraform")) || existsSync(join(root, ".github/workflows"));
  const infraFiles = findFiles(root, ["dockerfile", "docker-compose", ".tf", "workflow", "deploy"]);
  if (infraFiles.length > 0) {
    sensitiveAreas.push({ name: "Infrastructure / CI/CD", risk: "high", files: infraFiles.slice(0, 10),
      description: "Infrastructure configs — supply chain and deployment risks." });
    highRiskWorkflows.push("CI/CD config changes should require approval.");
  }

  // --- Secrets ---
  const envFiles = [".env", ".env.local", ".env.production", ".env.example"].filter(f => existsSync(join(root, f)));
  if (envFiles.length > 0) {
    const gitignore = tryRead(join(root, ".gitignore")) ?? "";
    if (!/\.env/.test(gitignore)) {
      priorityFixes.push("CRITICAL: .env files not in .gitignore — secrets at risk!");
    }
    sensitiveAreas.push({ name: "Secrets / Config", risk: "critical", files: envFiles.map(f => join(root, f)),
      description: `${envFiles.length} env file(s) with potential secrets.` });
  }

  // --- Risk profile ---
  const criticalAreas = sensitiveAreas.filter(a => a.risk === "critical").length;
  const highAreas = sensitiveAreas.filter(a => a.risk === "high").length;
  const riskProfile: PostureResult["riskProfile"] = criticalAreas >= 2 ? "critical" : criticalAreas >= 1 ? "high" : highAreas >= 2 ? "medium" : "low";

  // --- Guard mode recommendation ---
  if (riskProfile === "critical" || riskProfile === "high") {
    guardRecommendations.push("Run GuardVibe on every PR (review_pr with fail_on=high).");
    guardRecommendations.push("Enable pre-commit hook (guardvibe hook install).");
    guardRecommendations.push("Run scan_secrets_history to check for leaked secrets in git history.");
  }
  if (hasPayments) guardRecommendations.push("Run policy_check with PCI-DSS framework.");
  if (hasPII) guardRecommendations.push("Run policy_check with GDPR framework.");

  const result: PostureResult = {
    riskProfile,
    summary: `${files} files across ${sensitiveAreas.length} sensitive areas. Risk: ${riskProfile.toUpperCase()}.`,
    sensitiveAreas,
    guardRecommendations,
    highRiskWorkflows,
    priorityFixes,
    stats: { files, dirs, hasAuth, hasPayments, hasPII, hasInfra },
  };

  if (format === "json") return JSON.stringify(result);

  const lines = [
    `# GuardVibe Repository Security Posture`,
    ``,
    `**Risk Profile:** ${riskProfile.toUpperCase()}`,
    `**Files:** ${files} | **Sensitive Areas:** ${sensitiveAreas.length}`,
    ``,
  ];

  if (sensitiveAreas.length > 0) {
    lines.push(`## Sensitive Areas`, ``);
    for (const area of sensitiveAreas) {
      lines.push(`### [${area.risk.toUpperCase()}] ${area.name}`, area.description,
        `Files: ${area.files.slice(0, 5).map(f => f.replace(root, ".")).join(", ")}`, ``);
    }
  }

  if (highRiskWorkflows.length > 0) {
    lines.push(`## High-Risk Workflows`, ``);
    highRiskWorkflows.forEach(w => lines.push(`- ${w}`));
    lines.push(``);
  }

  if (priorityFixes.length > 0) {
    lines.push(`## Priority Fixes`, ``);
    priorityFixes.forEach(f => lines.push(`- ${f}`));
    lines.push(``);
  }

  if (guardRecommendations.length > 0) {
    lines.push(`## Guard Mode Recommendations`, ``);
    guardRecommendations.forEach(r => lines.push(`- ${r}`));
  }

  return lines.join("\n");
}
