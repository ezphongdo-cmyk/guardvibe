import { execFileSync } from "child_process";
import { extname, basename } from "path";
import { analyzeCode, type Finding } from "./check-code.js";
import type { SecurityRule } from "../data/rules/types.js";
import { EXTENSION_MAP, CONFIG_FILE_MAP } from "../utils/constants.js";

interface DiffHunk {
  startLine: number;
  lineCount: number;
}

interface PrFinding {
  rule: SecurityRule;
  match: string;
  line: number;
  file: string;
  inDiff: boolean;
  confidence: number;
  exploitability: "proven" | "likely" | "possible" | "theoretical";
  impactArea: string;
}

interface AnnotationOutput {
  path: string;
  start_line: number;
  end_line: number;
  annotation_level: "failure" | "warning" | "notice";
  message: string;
  title: string;
}

function execGit(args: string[], cwd: string): string {
  try {
    return execFileSync("git", args, { cwd, encoding: "utf-8", timeout: 15000 });
  } catch {
    return "";
  }
}

function getChangedFiles(cwd: string, base: string): string[] {
  const output = execGit(["diff", "--name-only", base], cwd);
  return output.trim().split("\n").filter(Boolean);
}

function getDiffHunks(cwd: string, base: string, file: string): DiffHunk[] {
  const output = execGit(["diff", "-U0", base, "--", file], cwd);
  const hunks: DiffHunk[] = [];
  const hunkPattern = /@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@/g;
  let match;
  while ((match = hunkPattern.exec(output)) !== null) {
    const start = parseInt(match[1], 10);
    const count = match[2] ? parseInt(match[2], 10) : 1;
    hunks.push({ startLine: start, lineCount: count });
  }
  return hunks;
}

function getFileContent(cwd: string, file: string): string | null {
  try {
    return execFileSync("git", ["show", `HEAD:${file}`], { cwd, encoding: "utf-8", timeout: 10000 });
  } catch {
    return null;
  }
}

function isLineInDiff(line: number, hunks: DiffHunk[]): boolean {
  return hunks.some(h => line >= h.startLine && line < h.startLine + h.lineCount);
}

function detectLanguage(filePath: string): string | null {
  const ext = extname(filePath).toLowerCase();
  if (EXTENSION_MAP[ext]) return EXTENSION_MAP[ext];
  if (basename(filePath).startsWith("Dockerfile") || ext === ".dockerfile") return "dockerfile";
  return CONFIG_FILE_MAP[basename(filePath)] ?? null;
}

function assessConfidence(rule: SecurityRule, match: string): number {
  // Higher confidence for specific patterns (secrets, hardcoded values)
  if (rule.id.startsWith("VG0") || rule.id.startsWith("VG6")) return 0.95; // core + secrets
  if (rule.severity === "critical") return 0.90;
  if (rule.severity === "high") return 0.80;
  if (rule.severity === "medium") return 0.70;
  return 0.60;
}

function assessExploitability(rule: SecurityRule): "proven" | "likely" | "possible" | "theoretical" {
  // Hardcoded secrets, SQL injection, XSS = proven exploitable
  if (["VG001", "VG002", "VG003", "VG010", "VG042", "VG408"].includes(rule.id)) return "proven";
  if (rule.severity === "critical") return "likely";
  if (rule.severity === "high") return "possible";
  return "theoretical";
}

function detectImpactArea(file: string, rule: SecurityRule): string {
  if (file.includes("/api/") || file.includes("route.")) return "API surface";
  if (file.includes("middleware") || file.includes("proxy.")) return "Auth/routing layer";
  if (file.includes("action") || file.includes("server")) return "Server action";
  if (file.includes(".env")) return "Secrets/config";
  if (file.includes("payment") || file.includes("stripe") || file.includes("checkout")) return "Payment flow";
  if (file.includes("auth") || file.includes("login") || file.includes("session")) return "Authentication";
  if (rule.compliance?.some(c => c.includes("PCI"))) return "Payment/PCI scope";
  if (rule.compliance?.some(c => c.includes("HIPAA"))) return "Healthcare/PHI scope";
  return "Application code";
}

function severityToLevel(severity: string): "failure" | "warning" | "notice" {
  if (severity === "critical" || severity === "high") return "failure";
  if (severity === "medium") return "warning";
  return "notice";
}

export function reviewPr(
  cwd: string = process.cwd(),
  base: string = "main",
  format: "markdown" | "json" | "annotations" = "markdown",
  diffOnly: boolean = true,
  failOn: "critical" | "high" | "medium" | "low" | "none" = "high",
  rules?: SecurityRule[]
): string {
  const changedFiles = getChangedFiles(cwd, base);
  if (changedFiles.length === 0) {
    if (format === "json") return JSON.stringify({ summary: { total: 0, files: 0 }, findings: [] });
    if (format === "annotations") return JSON.stringify([]);
    return "# GuardVibe PR Review\n\nNo changed files found.";
  }

  const allFindings: PrFinding[] = [];
  const scannedFiles: string[] = [];

  for (const file of changedFiles) {
    const language = detectLanguage(file);
    if (!language) continue;

    const content = getFileContent(cwd, file);
    if (!content) continue;

    scannedFiles.push(file);
    const hunks = getDiffHunks(cwd, base, file);
    const findings = analyzeCode(content, language, undefined, file, cwd, rules);

    for (const f of findings) {
      const inDiff = isLineInDiff(f.line, hunks);
      allFindings.push({
        rule: f.rule, match: f.match, line: f.line, file, inDiff,
        confidence: assessConfidence(f.rule, f.match),
        exploitability: assessExploitability(f.rule),
        impactArea: detectImpactArea(file, f.rule),
      });
    }
  }

  const reportFindings = diffOnly ? allFindings.filter(f => f.inDiff) : allFindings;

  const critical = reportFindings.filter(f => f.rule.severity === "critical").length;
  const high = reportFindings.filter(f => f.rule.severity === "high").length;
  const medium = reportFindings.filter(f => f.rule.severity === "medium").length;
  const total = reportFindings.length;

  const failThresholds: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const failLevel = failThresholds[failOn] ?? -1;
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const blocked = failLevel >= 0 && reportFindings.some(f => (severityOrder[f.rule.severity] ?? 4) <= failLevel);

  // --- ANNOTATIONS FORMAT (for GitHub Check Runs) ---
  if (format === "annotations") {
    const annotations: AnnotationOutput[] = reportFindings.map(f => ({
      path: f.file,
      start_line: f.line,
      end_line: f.line,
      annotation_level: severityToLevel(f.rule.severity),
      message: `${f.rule.description}\n\nFix: ${f.rule.fix}${f.rule.fixCode ? "\n\n" + f.rule.fixCode : ""}`,
      title: `[${f.rule.severity.toUpperCase()}] ${f.rule.name} (${f.rule.id})`,
    }));
    return JSON.stringify(annotations);
  }

  // --- JSON FORMAT ---
  if (format === "json") {
    return JSON.stringify({
      summary: {
        total, critical, high, medium,
        files: scannedFiles.length, changedFiles: changedFiles.length,
        diffOnly, blocked, failOn, base,
      },
      findings: reportFindings.map(f => ({
        id: f.rule.id, name: f.rule.name, severity: f.rule.severity,
        owasp: f.rule.owasp, file: f.file, line: f.line, match: f.match,
        inDiff: f.inDiff, fix: f.rule.fix, fixCode: f.rule.fixCode,
        compliance: f.rule.compliance,
        confidence: f.confidence,
        exploitability: f.exploitability,
        impactArea: f.impactArea,
      })),
    });
  }

  // --- MARKDOWN FORMAT (for PR comment) ---
  const existingFindings = diffOnly ? allFindings.filter(f => !f.inDiff) : [];

  const lines: string[] = [
    `## GuardVibe PR Security Review`,
    ``,
    `**Base:** ${base} | **Files changed:** ${changedFiles.length} | **Scanned:** ${scannedFiles.length}`,
    `**Mode:** ${diffOnly ? "diff-only (new code)" : "full file"}`,
    ``,
  ];

  if (blocked) {
    lines.push(`> **BLOCKED** — ${failOn}-severity or above findings detected.`, ``);
  }

  if (total === 0) {
    lines.push(`**No security issues in ${diffOnly ? "changed lines" : "changed files"}.** All clear!`);
    if (existingFindings.length > 0) {
      lines.push(``, `*Note: ${existingFindings.length} pre-existing issue(s) in unchanged code.*`);
    }
    return lines.join("\n");
  }

  lines.push(`| Severity | Count |`, `|----------|-------|`);
  if (critical > 0) lines.push(`| Critical | ${critical} |`);
  if (high > 0) lines.push(`| High | ${high} |`);
  if (medium > 0) lines.push(`| Medium | ${medium} |`);
  lines.push(``);

  const byFile = new Map<string, PrFinding[]>();
  for (const f of reportFindings) {
    const existing = byFile.get(f.file) ?? [];
    existing.push(f);
    byFile.set(f.file, existing);
  }

  for (const [file, findings] of byFile) {
    lines.push(`### \`${file}\``, ``);
    for (const f of findings) {
      const badge = f.rule.severity.toUpperCase();
      lines.push(
        `- **[${badge}]** ${f.rule.name} (${f.rule.id}) — line ${f.line}`,
        `  ${f.rule.fix}`,
      );
      if (f.rule.fixCode) {
        lines.push(`  \`\`\``, `  ${f.rule.fixCode.split("\n")[0]}`, `  \`\`\``);
      }
      lines.push(``);
    }
  }

  if (existingFindings.length > 0) {
    lines.push(`---`, ``, `*${existingFindings.length} pre-existing issue(s) in unchanged code (not shown).*`);
  }

  return lines.join("\n");
}
