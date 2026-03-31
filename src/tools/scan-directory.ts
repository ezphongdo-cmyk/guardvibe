import { readdirSync, readFileSync, statSync } from "fs";
import { join, extname, basename, resolve } from "path";
import { analyzeCode, formatFindingsJson, type Finding } from "./check-code.js";
import { loadConfig } from "../utils/config.js";
import type { SecurityRule } from "../data/rules/types.js";

const DEFAULT_EXCLUDES = new Set([
  "node_modules", ".git", "build", "dist", "vendor", "__pycache__",
  ".next", ".nuxt", ".svelte-kit", "target", "bin", "obj",
  "coverage", ".turbo", ".venv", "venv",
]);

const EXTENSION_MAP: Record<string, string> = {
  ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
  ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
  ".py": "python", ".go": "go", ".html": "html",
  ".sql": "sql", ".sh": "shell", ".bash": "shell",
  ".yml": "yaml", ".yaml": "yaml",
  ".tf": "terraform",
  ".toml": "toml", ".json": "json",
};

const CONFIG_FILE_MAP: Record<string, string> = {
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

interface ScanResult {
  path: string;
  findings: Finding[];
}

function walkDirectory(
  dir: string,
  recursive: boolean,
  excludes: Set<string>,
  results: string[]
): void {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (excludes.has(entry.name)) continue;
    const fullPath = join(dir, entry.name);

    if (entry.isDirectory() && recursive) {
      walkDirectory(fullPath, recursive, excludes, results);
    } else if (entry.isFile()) {
      const ext = extname(entry.name).toLowerCase();
      if (EXTENSION_MAP[ext]) {
        results.push(fullPath);
      }
      // Also detect Dockerfiles and config files by name
      if (entry.name.startsWith("Dockerfile") || entry.name.endsWith(".dockerfile")) {
        results.push(fullPath);
      }
      if (CONFIG_FILE_MAP[entry.name] && !results.includes(fullPath)) {
        results.push(fullPath);
      }
    }
  }
}

export function scanDirectory(
  path: string,
  recursive: boolean = true,
  exclude: string[] = [],
  format: "markdown" | "json" = "markdown",
  rules?: SecurityRule[]
): string {
  const scanRoot = resolve(path);
  const config = loadConfig(scanRoot);
  const excludes = new Set([...DEFAULT_EXCLUDES, ...exclude, ...config.scan.exclude]);
  const maxSize = config.scan.maxFileSize;
  const filePaths: string[] = [];
  walkDirectory(scanRoot, recursive, excludes, filePaths);

  const scanResults: ScanResult[] = [];
  const skippedFiles: string[] = [];

  for (const filePath of filePaths) {
    try {
      const stat = statSync(filePath);
      if (stat.size > maxSize) {
        skippedFiles.push(`${filePath} (too large: ${Math.round(stat.size / 1024)}KB)`);
        continue;
      }

      const content = readFileSync(filePath, "utf-8");
      const ext = extname(filePath).toLowerCase();
      let language = EXTENSION_MAP[ext];
      // Detect Dockerfile by name
      if (!language && (basename(filePath).startsWith("Dockerfile") || ext === ".dockerfile")) {
        language = "dockerfile";
      }
      // Detect config files by name
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

  // Scoring
  const allFindings = scanResults.flatMap(r => r.findings);
  const totalCritical = allFindings.filter(f => f.rule.severity === "critical").length;
  const totalHigh = allFindings.filter(f => f.rule.severity === "high").length;
  const totalMedium = allFindings.filter(f => f.rule.severity === "medium").length;
  const totalIssues = totalCritical + totalHigh + totalMedium;
  const score = Math.max(0, Math.min(100, 100 - totalCritical * 25 - totalHigh * 10 - totalMedium * 5));
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";

  if (format === "json") {
    const findingsWithFiles = scanResults.flatMap(r =>
      r.findings.map(f => ({ ...f, rule: f.rule, file: r.path }))
    );
    return formatFindingsJson(findingsWithFiles, { grade, score });
  }

  const lines: string[] = [
    `# GuardVibe Directory Security Report`,
    ``,
    `Directory: ${scanRoot}`,
    `Files scanned: ${filePaths.length - skippedFiles.length}`,
    `Total issues: ${totalIssues}`,
    `Security Score: ${grade} (${score}/100)`,
    ``,
  ];

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
