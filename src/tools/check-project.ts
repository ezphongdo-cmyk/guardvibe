import { analyzeCode, formatFindingsJson, type Finding } from "./check-code.js";
import type { SecurityRule } from "../data/rules/types.js";

interface FileInput {
  path: string;
  content: string;
}

interface FileResult {
  path: string;
  findings: Finding[];
}

const extensionMap: Record<string, string> = {
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".mts": "typescript",
  ".cts": "typescript",
  ".py": "python",
  ".go": "go",
  ".html": "html",
  ".sql": "sql",
  ".sh": "shell",
  ".bash": "shell",
  ".dockerfile": "dockerfile",
  ".yml": "yaml",
  ".yaml": "yaml",
  ".tf": "terraform",
  ".toml": "toml", ".json": "json",
};

const configFileMap: Record<string, string> = {
  "vercel.json": "vercel-config",
  "next.config.js": "nextjs-config",
  "next.config.mjs": "nextjs-config",
  "next.config.ts": "nextjs-config",
  "docker-compose.yml": "docker-compose",
  "docker-compose.yaml": "docker-compose",
  "fly.toml": "fly-config",
  "render.yaml": "render-config",
  "netlify.toml": "netlify-config",
};

function detectLanguage(filePath: string): string | null {
  const fileName = filePath.split("/").pop() ?? "";
  if (fileName.startsWith("Dockerfile") || fileName.endsWith(".dockerfile")) {
    return "dockerfile";
  }
  const configLang = configFileMap[fileName];
  if (configLang) return configLang;
  const ext = filePath.match(/\.[^.]+$/)?.[0]?.toLowerCase();
  return ext ? extensionMap[ext] ?? null : null;
}

function calculateScore(critical: number, high: number, medium: number, fileCount: number = 1): number {
  const weighted = critical * 10 + high * 3 + medium * 1;
  const density = weighted / Math.max(fileCount, 1);
  return Math.max(0, Math.min(100, Math.round(100 - density * 20)));
}

function scoreToGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

export function checkProject(files: FileInput[], format: "markdown" | "json" = "markdown", rules?: SecurityRule[]): string {
  const results: FileResult[] = [];
  const skippedFiles: string[] = [];

  for (const file of files) {
    const language = detectLanguage(file.path);
    if (!language) {
      skippedFiles.push(file.path);
      continue;
    }
    const findings = analyzeCode(file.content, language, undefined, file.path, undefined, rules);
    if (findings.length > 0) {
      results.push({ path: file.path, findings });
    }
  }

  const scannedCount = files.length - skippedFiles.length;
  const allFindings = results.flatMap((r) => r.findings);
  const totalCritical = allFindings.filter((f) => f.rule.severity === "critical").length;
  const totalHigh = allFindings.filter((f) => f.rule.severity === "high").length;
  const totalMedium = allFindings.filter((f) => f.rule.severity === "medium").length;
  const totalIssues = totalCritical + totalHigh + totalMedium;
  const score = calculateScore(totalCritical, totalHigh, totalMedium, scannedCount);
  const grade = scoreToGrade(score);

  if (format === "json") {
    return formatFindingsJson(allFindings, { grade, score });
  }

  const lines: string[] = [
    `# GuardVibe Project Security Report`,
    ``,
    `Files scanned: ${scannedCount}`,
    `Total issues: ${totalIssues}`,
    `Security Score: ${grade} (${score}/100)`,
    ``,
  ];

  if (totalIssues > 0) {
    lines.push(`## Summary`, ``);
    lines.push(`| Severity | Count |`);
    lines.push(`|----------|-------|`);
    if (totalCritical > 0) lines.push(`| Critical | ${totalCritical}     |`);
    if (totalHigh > 0) lines.push(`| High     | ${totalHigh}     |`);
    if (totalMedium > 0) lines.push(`| Medium   | ${totalMedium}     |`);
    lines.push(``);

    // Top issues sorted by severity
    const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const allIssues = results.flatMap((r) =>
      r.findings.map((f) => ({
        severity: f.rule.severity,
        order: severityOrder[f.rule.severity] ?? 99,
        text: `[${f.rule.severity.toUpperCase()}] ${f.rule.name} in ${r.path} (${f.rule.id})`,
      }))
    );
    allIssues.sort((a, b) => a.order - b.order);

    if (allIssues.length > 0) {
      lines.push(`## Top Issues`);
      const topN = allIssues.slice(0, 10);
      topN.forEach((issue, i) => {
        lines.push(`${i + 1}. ${issue.text}`);
      });
      lines.push(``);
    }

    lines.push(`---`, ``);

    // Per-file details
    for (const r of results) {
      const fileIssueCount = r.findings.length;
      lines.push(`## File: ${r.path} (${fileIssueCount} issues)`, ``);

      // Group findings by rule.id to match check-code formatting
      const grouped = new Map<string, Finding[]>();
      for (const finding of r.findings) {
        const existing = grouped.get(finding.rule.id);
        if (existing) {
          existing.push(finding);
        } else {
          grouped.set(finding.rule.id, [finding]);
        }
      }

      const sortedGroups = Array.from(grouped.entries()).sort(([, aFindings], [, bFindings]) => {
        return (severityOrder[aFindings[0].rule.severity] ?? 99) - (severityOrder[bFindings[0].rule.severity] ?? 99);
      });

      for (const [, groupFindings] of sortedGroups) {
        const first = groupFindings[0];
        const icon = first.rule.severity.toUpperCase();

        if (groupFindings.length > 2) {
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
    }
  } else {
    lines.push(
      `## No Issues Found`,
      ``,
      `All ${scannedCount} files passed security checks. Great job!`,
      ``,
      `**Tips to stay secure:**`,
      `- Keep dependencies updated`,
      `- Validate all user input with schemas`,
      `- Use environment variables for secrets`,
      `- Add rate limiting to API endpoints`,
    );
  }

  if (skippedFiles.length > 0) {
    lines.push(``, `*Skipped ${skippedFiles.length} files with unsupported extensions.*`);
  }

  return lines.join("\n");
}
