/**
 * Remediation Plan — generates a mandatory section-by-section
 * remediation checklist from full_audit results.
 *
 * Problem: AI assistants run full_audit, see 6 sections, but only fix
 * the "code" section (pattern-match findings) and skip secrets,
 * dependencies, config, taint, and auth-coverage.
 *
 * Solution: This tool takes audit results and produces an ordered,
 * section-by-section plan with specific tool calls and actions for
 * EVERY section that has findings. The AI MUST complete each section
 * before moving to the next.
 */

import { runFullAudit, type AuditResult, type AuditSection } from "./full-audit.js";
import { resolve } from "node:path";

export interface RemediationStep {
  section: string;
  priority: number;
  status: "requires_action" | "clean";
  findingCount: number;
  critical: number;
  high: number;
  medium: number;
  actions: RemediationAction[];
}

export interface RemediationAction {
  order: number;
  tool: string;
  params: Record<string, string>;
  purpose: string;
  mandatory: boolean;
}

export interface RemediationPlan {
  auditHash: string;
  verdict: string;
  totalSections: number;
  sectionsRequiringAction: number;
  sectionsClean: number;
  steps: RemediationStep[];
  completionCriteria: string;
  warning: string;
}

function buildSectionActions(section: AuditSection, projectPath: string): RemediationAction[] {
  const actions: RemediationAction[] = [];
  const path = projectPath;

  switch (section.name) {
    case "code":
      if (section.findings > 0) {
        actions.push({
          order: 1,
          tool: "scan_directory",
          params: { path, format: "json" },
          purpose: "Get full list of code findings with file locations and fix suggestions.",
          mandatory: true,
        });
        if (section.critical > 0 || section.high > 0) {
          actions.push({
            order: 2,
            tool: "fix_code",
            params: { path, format: "json" },
            purpose: `Fix all ${section.critical} critical and ${section.high} high severity code findings. Use fix_code for each file with findings.`,
            mandatory: true,
          });
          actions.push({
            order: 3,
            tool: "verify_fix",
            params: {},
            purpose: "Verify each fix resolved the vulnerability. Call verify_fix after each file edit.",
            mandatory: true,
          });
        }
        actions.push({
          order: 4,
          tool: "scan_directory",
          params: { path, format: "json" },
          purpose: "Re-scan to confirm code findings are resolved.",
          mandatory: true,
        });
      }
      break;

    case "secrets":
      if (section.findings > 0) {
        actions.push({
          order: 1,
          tool: "scan_secrets",
          params: { path, format: "json" },
          purpose: `List all ${section.findings} detected secrets with file locations.`,
          mandatory: true,
        });
        actions.push({
          order: 2,
          tool: "manual_action",
          params: {},
          purpose: "For EACH secret found: (1) Add the file to .gitignore if it's a .env file, (2) Move hardcoded secrets to environment variables, (3) Rotate any exposed API keys/tokens — they are compromised once committed.",
          mandatory: true,
        });
        actions.push({
          order: 3,
          tool: "scan_secrets_history",
          params: { path },
          purpose: "Check git history for previously committed secrets that need rotation.",
          mandatory: true,
        });
        actions.push({
          order: 4,
          tool: "scan_secrets",
          params: { path, format: "json" },
          purpose: "Re-scan to confirm all secrets are resolved.",
          mandatory: true,
        });
      }
      break;

    case "dependencies":
      if (section.findings > 0) {
        actions.push({
          order: 1,
          tool: "scan_dependencies",
          params: { manifest_path: "package.json", format: "json" },
          purpose: `List all ${section.findings} vulnerable packages with CVE details.`,
          mandatory: true,
        });
        actions.push({
          order: 2,
          tool: "manual_action",
          params: {},
          purpose: "For EACH vulnerable dependency: (1) Run 'npm audit fix' or 'npm update <package>' to patch, (2) If breaking change, pin to latest secure version, (3) If abandoned package, find alternative.",
          mandatory: true,
        });
        actions.push({
          order: 3,
          tool: "check_package_health",
          params: { name: "<each_vulnerable_package>" },
          purpose: "Verify replacement packages are healthy and maintained.",
          mandatory: false,
        });
        actions.push({
          order: 4,
          tool: "scan_dependencies",
          params: { manifest_path: "package.json", format: "json" },
          purpose: "Re-scan to confirm all dependency CVEs are resolved.",
          mandatory: true,
        });
      }
      break;

    case "config":
      if (section.findings > 0) {
        actions.push({
          order: 1,
          tool: "audit_config",
          params: { path, format: "json" },
          purpose: `List all ${section.findings} configuration issues with file locations.`,
          mandatory: true,
        });
        actions.push({
          order: 2,
          tool: "explain_remediation",
          params: { ruleId: "<each_config_rule_id>" },
          purpose: "Get fix guidance for each config finding. Apply fixes to next.config, middleware, .env, vercel.json etc.",
          mandatory: true,
        });
        actions.push({
          order: 3,
          tool: "audit_config",
          params: { path, format: "json" },
          purpose: "Re-scan to confirm config issues are resolved.",
          mandatory: true,
        });
      }
      break;

    case "taint":
      if (section.findings > 0) {
        actions.push({
          order: 1,
          tool: "analyze_cross_file_dataflow",
          params: { path },
          purpose: `Trace all ${section.findings} tainted data flows from source to sink.`,
          mandatory: true,
        });
        actions.push({
          order: 2,
          tool: "manual_action",
          params: {},
          purpose: "For EACH tainted flow: add input validation/sanitization at the source, or output encoding at the sink. Common fixes: zod validation for user input, parameterized queries for SQL, DOMPurify for HTML output.",
          mandatory: true,
        });
        actions.push({
          order: 3,
          tool: "analyze_cross_file_dataflow",
          params: { path },
          purpose: "Re-analyze to confirm tainted flows are resolved.",
          mandatory: true,
        });
      }
      break;

    case "auth-coverage":
      if (section.findings > 0) {
        actions.push({
          order: 1,
          tool: "auth_coverage",
          params: { path, format: "json" },
          purpose: `List all ${section.findings} unprotected routes that need auth guards.`,
          mandatory: true,
        });
        actions.push({
          order: 2,
          tool: "manual_action",
          params: {},
          purpose: "For EACH unprotected route: (1) Add auth middleware or auth check (Clerk/NextAuth/Supabase), (2) If route is intentionally public, add it to .guardviberc authExceptions, (3) Consider adding middleware.ts for blanket protection.",
          mandatory: true,
        });
        actions.push({
          order: 3,
          tool: "auth_coverage",
          params: { path, format: "json" },
          purpose: "Re-check to confirm all routes are protected.",
          mandatory: true,
        });
      }
      break;
  }

  return actions;
}

/**
 * Generate a section-by-section remediation plan from audit results.
 * This forces AI assistants to address ALL sections, not just code.
 */
export function generateRemediationPlan(
  auditResult: AuditResult,
  projectPath: string,
): RemediationPlan {
  // Priority order: secrets first (compromised creds), then code, deps, config, taint, auth
  const priorityMap: Record<string, number> = {
    secrets: 1,
    code: 2,
    dependencies: 3,
    config: 4,
    taint: 5,
    "auth-coverage": 6,
  };

  const steps: RemediationStep[] = auditResult.sections.map((section) => ({
    section: section.name,
    priority: priorityMap[section.name] ?? 99,
    status: section.findings > 0 ? "requires_action" as const : "clean" as const,
    findingCount: section.findings,
    critical: section.critical,
    high: section.high,
    medium: section.medium,
    actions: buildSectionActions(section, projectPath),
  }));

  // Sort by priority
  steps.sort((a, b) => a.priority - b.priority);

  const sectionsRequiringAction = steps.filter(s => s.status === "requires_action").length;
  const sectionsClean = steps.filter(s => s.status === "clean").length;

  return {
    auditHash: auditResult.resultHash,
    verdict: auditResult.verdict,
    totalSections: steps.length,
    sectionsRequiringAction,
    sectionsClean,
    steps,
    completionCriteria: `All ${steps.length} sections must show 0 findings. Run verify_remediation after completing all steps to confirm.`,
    warning: sectionsRequiringAction > 1
      ? `IMPORTANT: ${sectionsRequiringAction} sections need fixes. Do NOT skip any section. Complete them in order: ${steps.filter(s => s.status === "requires_action").map(s => s.section).join(" → ")}. Run verify_remediation when done.`
      : sectionsRequiringAction === 1
      ? `1 section needs fixes: ${steps.find(s => s.status === "requires_action")!.section}. Run verify_remediation when done.`
      : "All sections clean. No remediation needed.",
  };
}

export function formatRemediationPlan(plan: RemediationPlan, format: "markdown" | "json"): string {
  if (format === "json") {
    return JSON.stringify(plan);
  }

  const lines: string[] = [
    "# GuardVibe Remediation Plan",
    "",
    `**Audit verdict:** ${plan.verdict} | **Sections requiring action:** ${plan.sectionsRequiringAction}/${plan.totalSections}`,
    "",
  ];

  if (plan.warning) {
    lines.push(`> **${plan.warning}**`, "");
  }

  for (const step of plan.steps) {
    const icon = step.status === "clean" ? "✅" : "🔴";
    lines.push(`## ${icon} Section: ${step.section} (Priority ${step.priority})`);
    lines.push("");

    if (step.status === "clean") {
      lines.push("No findings — no action needed.");
      lines.push("");
      continue;
    }

    lines.push(`**Findings:** ${step.findingCount} total (${step.critical} critical, ${step.high} high, ${step.medium} medium)`);
    lines.push("");

    for (const action of step.actions) {
      const req = action.mandatory ? "**[MANDATORY]**" : "[optional]";
      if (action.tool === "manual_action") {
        lines.push(`${action.order}. ${req} ${action.purpose}`);
      } else {
        lines.push(`${action.order}. ${req} Call \`${action.tool}\` — ${action.purpose}`);
      }
    }

    lines.push("");
  }

  lines.push("---");
  lines.push(`**Completion:** ${plan.completionCriteria}`);
  lines.push(`**Audit hash:** \`${plan.auditHash}\``);

  return lines.join("\n");
}
