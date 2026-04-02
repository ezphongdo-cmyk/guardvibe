import { createRequire } from "module";
import { readFileSync, statSync } from "fs";
import { extname, basename, resolve } from "path";
import { createHash, randomUUID } from "crypto";
import { analyzeCode, formatFindingsJson, type Finding } from "./check-code.js";
import { loadConfig } from "../utils/config.js";
import type { SecurityRule } from "../data/rules/types.js";
import { DEFAULT_EXCLUDES, EXTENSION_MAP, CONFIG_FILE_MAP } from "../utils/constants.js";
import { walkDirectory } from "../utils/walk-directory.js";

const require = createRequire(import.meta.url);
const pkg = require("../../package.json") as { version: string };

// GuardVibe version — used in scan metadata
const GUARDVIBE_VERSION = pkg.version;

interface ScanResult {
  path: string;
  findings: Finding[];
}

interface ScanMetadata {
  scanId: string;
  timestamp: string;
  guardvibeVersion: string;
  ruleCount: number;
  scanDurationMs: number;
  filesScanned: number;
  filesSkipped: number;
  fileHashes: Record<string, string>;
}

interface BaselineEntry {
  id: string;
  name: string;
  severity: string;
  file: string;
  line: number;
  match: string;
}

interface BaselineReport {
  scanId: string;
  timestamp: string;
}

interface BaselineDiff {
  new: BaselineEntry[];
  fixed: BaselineEntry[];
  unchanged: BaselineEntry[];
}


function hashContent(content: string): string {
  return createHash("sha256").update(content).digest("hex").substring(0, 16);
}

function findingsToBaseline(scanResults: ScanResult[]): BaselineEntry[] {
  const entries: BaselineEntry[] = [];
  for (const result of scanResults) {
    for (const f of result.findings) {
      entries.push({
        id: f.rule.id,
        name: f.rule.name,
        severity: f.rule.severity,
        file: result.path,
        line: f.line,
        match: f.match,
      });
    }
  }
  return entries;
}

function computeBaselineDiff(current: BaselineEntry[], previous: BaselineEntry[]): BaselineDiff {
  const prevKey = (e: BaselineEntry) => `${e.id}:${e.file}:${e.match}`;
  const currKey = (e: BaselineEntry) => `${e.id}:${e.file}:${e.match}`;

  const prevSet = new Set(previous.map(prevKey));
  const currSet = new Set(current.map(currKey));

  return {
    new: current.filter(e => !prevSet.has(currKey(e))),
    fixed: previous.filter(e => !currSet.has(prevKey(e))),
    unchanged: current.filter(e => prevSet.has(currKey(e))),
  };
}

export function scanDirectory(
  path: string,
  recursive: boolean = true,
  exclude: string[] = [],
  format: "markdown" | "json" = "markdown",
  rules?: SecurityRule[],
  baselinePath?: string
): string {
  const startTime = performance.now();
  const scanId = randomUUID();
  const scanRoot = resolve(path);
  const config = loadConfig(scanRoot);
  const excludes = new Set([...DEFAULT_EXCLUDES, ...exclude, ...config.scan.exclude]);
  const maxSize = config.scan.maxFileSize;
  const filePaths: string[] = [];
  walkDirectory(scanRoot, recursive, excludes, filePaths);

  const scanResults: ScanResult[] = [];
  const skippedFiles: string[] = [];
  const fileHashes: Record<string, string> = {};
  const effectiveRules = rules ?? [];

  for (const filePath of filePaths) {
    try {
      const stat = statSync(filePath);
      if (stat.size > maxSize) {
        skippedFiles.push(`${filePath} (too large: ${Math.round(stat.size / 1024)}KB)`);
        continue;
      }

      const content = readFileSync(filePath, "utf-8");
      fileHashes[filePath] = hashContent(content);

      const ext = extname(filePath).toLowerCase();
      let language = EXTENSION_MAP[ext];
      if (!language && (basename(filePath).startsWith("Dockerfile") || ext === ".dockerfile")) {
        language = "dockerfile";
      }
      if (!language) {
        language = CONFIG_FILE_MAP[basename(filePath)];
      }
      if (!language) continue;

      const findings = analyzeCode(content, language, undefined, filePath, scanRoot, rules);
      if (findings.length > 0) {
        scanResults.push({ path: filePath, findings });
      }
    } catch {
      skippedFiles.push(`${filePath} (read error)`);
    }
  }

  const scanDurationMs = Math.round(performance.now() - startTime);

  const metadata: ScanMetadata = {
    scanId,
    timestamp: new Date().toISOString(),
    guardvibeVersion: GUARDVIBE_VERSION,
    ruleCount: effectiveRules.length > 0 ? effectiveRules.length : 239,
    scanDurationMs,
    filesScanned: filePaths.length - skippedFiles.length,
    filesSkipped: skippedFiles.length,
    fileHashes,
  };

  // Scoring
  const allFindings = scanResults.flatMap(r => r.findings);
  const totalCritical = allFindings.filter(f => f.rule.severity === "critical").length;
  const totalHigh = allFindings.filter(f => f.rule.severity === "high").length;
  const totalMedium = allFindings.filter(f => f.rule.severity === "medium").length;
  const totalIssues = totalCritical + totalHigh + totalMedium;
  // Score based on weighted issue density (per file), not raw counts.
  // This makes scoring fair for both small and large projects.
  const filesScanned = scanResults.length || 1;
  const weightedIssues = totalCritical * 10 + totalHigh * 3 + totalMedium * 1;
  const density = weightedIssues / filesScanned;
  // density 0 = 100, density >= 5 = 0
  const score = Math.max(0, Math.min(100, Math.round(100 - density * 20)));
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";

  // Baseline comparison
  let baselineDiff: BaselineDiff | null = null;
  let previousBaseline: { report: BaselineReport; findings: BaselineEntry[] } | null = null;
  if (baselinePath) {
    try {
      const baselineContent = readFileSync(resolve(baselinePath), "utf-8");
      const parsed = JSON.parse(baselineContent);
      previousBaseline = {
        report: { scanId: parsed.metadata?.scanId ?? "unknown", timestamp: parsed.metadata?.timestamp ?? "unknown" },
        findings: parsed.baseline ?? [],
      };
      const currentEntries = findingsToBaseline(scanResults);
      baselineDiff = computeBaselineDiff(currentEntries, previousBaseline.findings);
    } catch {
      // baseline file unreadable, skip comparison
    }
  }

  if (format === "json") {
    const findingsWithFiles = scanResults.flatMap(r =>
      r.findings.map(f => ({ ...f, rule: f.rule, file: r.path }))
    );
    const baseJson: Record<string, unknown> = {
      summary: {
        total: allFindings.length,
        critical: totalCritical, high: totalHigh, medium: totalMedium,
        low: allFindings.filter(f => f.rule.severity === "low").length,
        blocked: totalCritical > 0 || totalHigh > 0,
        grade, score,
      },
      metadata,
      findings: findingsWithFiles.map(f => ({
        id: f.rule.id, name: f.rule.name, severity: f.rule.severity,
        owasp: f.rule.owasp, line: f.line, match: f.match, file: (f as any).file,
        fix: f.rule.fix, fixCode: f.rule.fixCode, compliance: f.rule.compliance,
      })),
      baseline: findingsToBaseline(scanResults),
    };

    if (baselineDiff) {
      baseJson.baselineDiff = {
        previousScanId: previousBaseline?.report.scanId,
        previousTimestamp: previousBaseline?.report.timestamp,
        new: baselineDiff.new.length,
        fixed: baselineDiff.fixed.length,
        unchanged: baselineDiff.unchanged.length,
        newFindings: baselineDiff.new,
        fixedFindings: baselineDiff.fixed,
      };
    }

    return JSON.stringify(baseJson);
  }

  // Markdown output
  const lines: string[] = [
    `# GuardVibe Directory Security Report`,
    ``,
    `Scan ID: ${scanId}`,
    `Timestamp: ${metadata.timestamp}`,
    `Directory: ${scanRoot}`,
    `Files scanned: ${metadata.filesScanned}`,
    `Total issues: ${totalIssues}`,
    `Security Score: ${grade} (${score}/100)`,
    `Scan duration: ${scanDurationMs}ms`,
    `GuardVibe: v${GUARDVIBE_VERSION} (${metadata.ruleCount} rules)`,
    ``,
  ];

  // Baseline diff section
  if (baselineDiff && previousBaseline) {
    lines.push(
      `## Baseline Comparison`,
      ``,
      `Previous scan: ${previousBaseline.report.scanId} (${previousBaseline.report.timestamp})`,
      ``,
      `| Status | Count |`,
      `|--------|-------|`,
      `| New findings | ${baselineDiff.new.length} |`,
      `| Fixed findings | ${baselineDiff.fixed.length} |`,
      `| Unchanged | ${baselineDiff.unchanged.length} |`,
      ``,
    );

    if (baselineDiff.new.length > 0) {
      lines.push(`### New Findings`, ``);
      for (const entry of baselineDiff.new) {
        lines.push(`- [${entry.severity.toUpperCase()}] ${entry.name} (${entry.id}) in ${entry.file}:${entry.line}`);
      }
      lines.push(``);
    }

    if (baselineDiff.fixed.length > 0) {
      lines.push(`### Fixed Findings`, ``);
      for (const entry of baselineDiff.fixed) {
        lines.push(`- ~~[${entry.severity.toUpperCase()}] ${entry.name} (${entry.id}) in ${entry.file}:${entry.line}~~`);
      }
      lines.push(``);
    }
  }

  if (totalIssues > 0) {
    lines.push(`## Summary`, ``, `| Severity | Count |`, `|----------|-------|`);
    if (totalCritical > 0) lines.push(`| Critical | ${totalCritical}     |`);
    if (totalHigh > 0) lines.push(`| High     | ${totalHigh}     |`);
    if (totalMedium > 0) lines.push(`| Medium   | ${totalMedium}     |`);
    lines.push(``);

    const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const topIssues = scanResults.flatMap(r =>
      r.findings.map(f => ({
        text: `[${f.rule.severity.toUpperCase()}] ${f.rule.name} in ${r.path} (${f.rule.id})`,
        order: severityOrder[f.rule.severity] ?? 99,
      }))
    ).sort((a, b) => a.order - b.order).slice(0, 10);

    lines.push(`## Top Issues`);
    topIssues.forEach((issue, i) => lines.push(`${i + 1}. ${issue.text}`));
    lines.push(``, `---`, ``);

    for (const result of scanResults) {
      lines.push(`## File: ${result.path} (${result.findings.length} issues)`, ``);
      for (const f of result.findings) {
        const icon = f.rule.severity.toUpperCase();
        lines.push(
          `### [${icon}] ${f.rule.name} (${f.rule.id})`,
          `**Line:** ~${f.line} | **Match:** \`${f.match}\``,
          `${f.rule.description}`,
          `**Fix:** ${f.rule.fix}`,
          ...(f.rule.fixCode ? [``, `**Secure code:**`, `\`\`\``, f.rule.fixCode, `\`\`\``] : []),
          ``
        );
      }
      lines.push(`---`, ``);
    }
  } else {
    lines.push(`## No Issues Found`, ``, `All files passed security checks.`);
  }

  if (skippedFiles.length > 0) {
    lines.push(``, `**Skipped files:**`);
    for (const s of skippedFiles) lines.push(`- ${s}`);
  }

  return lines.join("\n");
}
