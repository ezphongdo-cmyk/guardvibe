import { owaspRules, type SecurityRule } from "../data/rules/index.js";
import { loadConfig } from "../utils/config.js";

export interface Finding {
  rule: SecurityRule;
  match: string;
  line: number;
}

interface Suppression {
  line: number;
  ruleId: string | null; // null = suppress all rules
}

function parseSuppressionsFromCode(lines: string[]): Suppression[] {
  const suppressions: Suppression[] = [];
  const pattern = /(?:\/\/|#|<!--)\s*guardvibe-ignore(?:-next-line)?\s*(VG\d+)?\s*(?:-->)?/i;

  for (let i = 0; i < lines.length; i++) {
    const match = pattern.exec(lines[i]);
    if (!match) continue;

    const ruleId = match[1] || null;
    const isNextLine = lines[i].includes("guardvibe-ignore-next-line");

    if (isNextLine) {
      suppressions.push({ line: i + 2, ruleId }); // next line (1-indexed)
    } else {
      suppressions.push({ line: i + 1, ruleId }); // same line (1-indexed)
    }
  }

  return suppressions;
}

function isLineSuppressed(suppressions: Suppression[], line: number, ruleId: string): boolean {
  return suppressions.some(s => s.line === line && (s.ruleId === null || s.ruleId === ruleId));
}

/**
 * Check if a match falls entirely within a comment line.
 * Supports //, #, /asterisk, <!-- style comments.
 */
function isInComment(lines: string[], lineNumber: number): boolean {
  const line = lines[lineNumber - 1];
  if (!line) return false;
  const trimmed = line.trimStart();
  return (
    trimmed.startsWith("//") ||
    trimmed.startsWith("#") ||
    trimmed.startsWith("*") ||
    trimmed.startsWith("<!--") ||
    trimmed.startsWith("/*")
  );
}

/**
 * Check if a match on a given line is inside a string value used as a
 * human-readable message (UI label, error text) rather than an actual secret.
 */
function isHumanReadableString(lines: string[], lineNumber: number): boolean {
  const line = lines[lineNumber - 1];
  if (!line) return false;

  // Extract the string value portion after the key assignment
  const strMatch = /[:=]\s*["'`]([^"'`]{10,})["'`]/.exec(line);
  if (!strMatch) return false;
  const value = strMatch[1];

  // If the value contains 4+ words it's a natural-language sentence, not a secret
  const words = value.split(/\s+/);
  if (words.length >= 4) return true;

  return false;
}

export function analyzeCode(
  code: string,
  language: string,
  framework?: string,
  filePath?: string,
  configDir?: string,
  rules?: SecurityRule[]
): Finding[] {
  const config = loadConfig(configDir);
  const findings: Finding[] = [];
  const lines = code.split("\n");
  const suppressions = parseSuppressionsFromCode(lines);

  const effectiveRules = rules ?? owaspRules;

  for (const rule of effectiveRules) {
    if (!rule.languages.includes(language)) continue;

    // Config: skip disabled rules
    if (config.rules.disable.includes(rule.id)) continue;

    // Skip CI/CD rules: when filePath is given, require .github/workflows path.
    // When no filePath (MCP call), allow if language is yaml.
    if (rule.id.startsWith("VG21") && filePath && !filePath.includes(".github/workflows")) continue;
    if (rule.id.startsWith("VG21") && !filePath && language !== "yaml") continue;

    // Skip npm package rules (VG863/VG864/VG865): only apply to package.json files
    if ((rule.id === "VG863" || rule.id === "VG864" || rule.id === "VG865") && filePath && !filePath.endsWith("package.json")) continue;
    rule.pattern.lastIndex = 0;

    // Apply severity override from config
    const effectiveRule = config.rules.severity[rule.id]
      ? { ...rule, severity: config.rules.severity[rule.id] as any }
      : rule;

    let match: RegExpExecArray | null;
    while ((match = rule.pattern.exec(code)) !== null) {
      const beforeMatch = code.substring(0, match.index);
      const lineNumber = beforeMatch.split("\n").length;

      if (isLineSuppressed(suppressions, lineNumber, rule.id)) continue;

      // Skip matches on comment lines for code-pattern rules.
      // CVE version rules (VG9xx) scan package.json so they're exempt.
      if (!rule.id.startsWith("VG9")) {
        if (isInComment(lines, lineNumber)) continue;
      }

      // Skip hardcoded-credential rules when the value is a human-readable sentence
      if (rule.id === "VG001" || rule.id === "VG062") {
        if (isHumanReadableString(lines, lineNumber)) continue;
      }

      findings.push({
        rule: effectiveRule,
        match: match[0].substring(0, 80),
        line: lineNumber,
      });
    }
  }

  return findings;
}

export function formatFindingsJson(findings: Finding[], extra?: Record<string, unknown>): string {
  const critical = findings.filter(f => f.rule.severity === "critical").length;
  const high = findings.filter(f => f.rule.severity === "high").length;
  const medium = findings.filter(f => f.rule.severity === "medium").length;
  const low = findings.filter(f => f.rule.severity === "low").length;

  return JSON.stringify({
    summary: {
      total: findings.length, critical, high, medium, low,
      blocked: critical > 0 || high > 0,
      ...extra,
    },
    findings: findings.map(f => ({
      id: f.rule.id, name: f.rule.name, severity: f.rule.severity,
      owasp: f.rule.owasp, line: f.line, match: f.match,
      fix: f.rule.fix, fixCode: f.rule.fixCode, compliance: f.rule.compliance,
    })),
  });
}

export function checkCode(
  code: string,
  language: string,
  framework?: string,
  filePath?: string,
  configDir?: string,
  format: "markdown" | "json" = "markdown",
  rules?: SecurityRule[]
): string {
  const findings = analyzeCode(code, language, framework, filePath, configDir, rules);

  if (format === "json") {
    return formatFindingsJson(findings);
  }

  if (findings.length === 0) {
    return formatCleanReport(language, framework);
  }

  return formatReport(findings, language, framework);
}

function formatCleanReport(language: string, framework?: string): string {
  const ctx = framework ? ` (${framework})` : "";
  return [
    `# GuardVibe Security Report`,
    ``,
    `**Language:** ${language}${ctx}`,
    `**Status:** No security issues detected`,
    ``,
    `The code looks clean! Here are some general tips:`,
    `- Keep dependencies updated (\`npm audit\`)`,
    `- Validate all user input with schemas (zod, joi)`,
    `- Use environment variables for secrets`,
    `- Add rate limiting to API endpoints`,
  ].join("\n");
}

function formatReport(
  findings: Finding[],
  language: string,
  framework?: string
): string {
  const ctx = framework ? ` (${framework})` : "";

  // Severity ordering
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  // Group findings by rule.id
  const grouped = new Map<string, Finding[]>();
  for (const finding of findings) {
    const existing = grouped.get(finding.rule.id);
    if (existing) {
      existing.push(finding);
    } else {
      grouped.set(finding.rule.id, [finding]);
    }
  }

  // Sort groups by severity (critical first)
  const sortedGroups = Array.from(grouped.entries()).sort(([, aFindings], [, bFindings]) => {
    return severityOrder[aFindings[0].rule.severity] - severityOrder[bFindings[0].rule.severity];
  });

  // Count total findings (deduplicated groups count as 1 issue each for summary)
  const allFindings = findings;
  const criticalCount = allFindings.filter((f) => f.rule.severity === "critical").length;
  const highCount = allFindings.filter((f) => f.rule.severity === "high").length;
  const mediumCount = allFindings.filter((f) => f.rule.severity === "medium").length;

  const lines = [
    `# GuardVibe Security Report`,
    ``,
    `**Language:** ${language}${ctx}`,
    `**Issues found:** ${allFindings.length}`,
    `**Breakdown:** ${criticalCount} critical, ${highCount} high, ${mediumCount} medium`,
    ``,
    `---`,
    ``,
  ];

  for (const [, groupFindings] of sortedGroups) {
    const first = groupFindings[0];
    const icon =
      first.rule.severity === "critical"
        ? "CRITICAL"
        : first.rule.severity === "high"
          ? "HIGH"
          : first.rule.severity === "medium"
            ? "MEDIUM"
            : "LOW";

    if (groupFindings.length > 2) {
      // Deduplicated grouped format
      const lineList = groupFindings.map((f) => `~${f.line}`).join(", ");
      lines.push(
        `## [${icon}] ${first.rule.name} (${first.rule.id})`,
        ``,
        `**OWASP:** ${first.rule.owasp}`,
        `**Occurrences:** ${groupFindings.length} (lines: ${lineList})`,
        `**Example match:** \`${first.match}\``,
        ``,
        first.rule.description,
        ``,
        `**Fix:** ${first.rule.fix}`,
        ...(first.rule.fixCode ? [``, `**Secure code:**`, `\`\`\``, first.rule.fixCode, `\`\`\``] : []),
        ``,
        `---`,
        ``
      );
    } else {
      // Individual format for 1-2 matches
      for (const finding of groupFindings) {
        lines.push(
          `## [${icon}] ${finding.rule.name} (${finding.rule.id})`,
          ``,
          `**OWASP:** ${finding.rule.owasp}`,
          `**Line:** ~${finding.line}`,
          `**Match:** \`${finding.match}\``,
          ``,
          finding.rule.description,
          ``,
          `**Fix:** ${finding.rule.fix}`,
          ...(finding.rule.fixCode ? [``, `**Secure code:**`, `\`\`\``, finding.rule.fixCode, `\`\`\``] : []),
          ``,
          `---`,
          ``
        );
      }
    }
  }

  return lines.join("\n");
}
