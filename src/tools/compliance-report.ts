import { readdirSync, readFileSync, statSync } from "fs";
import { join, extname, basename, resolve } from "path";
import { analyzeCode, type Finding } from "./check-code.js";
import { loadConfig } from "../utils/config.js";
import type { SecurityRule } from "../data/rules/types.js";

const EXTENSION_MAP: Record<string, string> = {
  ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
  ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
  ".py": "python", ".go": "go", ".html": "html",
  ".sql": "sql", ".sh": "shell", ".bash": "shell",
  ".yml": "yaml", ".yaml": "yaml", ".tf": "terraform",
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

const DEFAULT_EXCLUDES = new Set([
  "node_modules", ".git", "build", "dist", "vendor", "__pycache__",
  ".next", ".nuxt", "coverage", ".turbo",
]);

function walkDir(dir: string, excludes: Set<string>, results: string[]): void {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    if (excludes.has(entry.name)) continue;
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      walkDir(fullPath, excludes, results);
    } else if (entry.isFile()) {
      const ext = extname(entry.name).toLowerCase();
      if (EXTENSION_MAP[ext] || entry.name.startsWith("Dockerfile") || CONFIG_FILE_MAP[entry.name]) {
        results.push(fullPath);
      }
    }
  }
}

export function complianceReport(path: string, framework: string, format: "markdown" | "json" = "markdown", rules?: SecurityRule[]): string {
  const scanRoot = resolve(path);
  const config = loadConfig(scanRoot);
  const excludes = new Set([...DEFAULT_EXCLUDES, ...config.scan.exclude]);
  const filePaths: string[] = [];
  walkDir(scanRoot, excludes, filePaths);

  // Scan all files
  const allFindings: Array<Finding & { filePath: string }> = [];
  for (const filePath of filePaths) {
    try {
      const stat = statSync(filePath);
      if (stat.size > config.scan.maxFileSize) continue;
      const content = readFileSync(filePath, "utf-8");
      const ext = extname(filePath).toLowerCase();
      let language = EXTENSION_MAP[ext];
      if (!language && basename(filePath).startsWith("Dockerfile")) language = "dockerfile";
      if (!language) language = CONFIG_FILE_MAP[basename(filePath)];
      if (!language) continue;
      const findings = analyzeCode(content, language, undefined, filePath, scanRoot, rules);
      for (const f of findings) {
        allFindings.push({ ...f, filePath });
      }
    } catch { /* skip */ }
  }

  // Filter by framework
  const frameworkUpper = framework.toUpperCase();
  const relevant = allFindings.filter(f =>
    f.rule.compliance?.some(c => {
      if (frameworkUpper === "ALL") return true;
      return c.toUpperCase().startsWith(frameworkUpper);
    })
  );

  // Group by control
  const controlMap = new Map<string, Array<{ finding: typeof relevant[0] }>>();
  for (const f of relevant) {
    for (const c of f.rule.compliance || []) {
      if (frameworkUpper !== "ALL" && !c.toUpperCase().startsWith(frameworkUpper)) continue;
      const existing = controlMap.get(c) || [];
      existing.push({ finding: f });
      controlMap.set(c, existing);
    }
  }

  const lines: string[] = [
    `# GuardVibe Compliance Report`,
    ``,
    `Framework: ${framework}`,
    `Directory: ${scanRoot}`,
    `Files scanned: ${filePaths.length}`,
    `Compliance issues: ${relevant.length}`,
    ``,
  ];

  if (format === "json") {
    const controls: Record<string, Array<{ id: string; name: string; severity: string; file: string; line: number }>> = {};
    for (const [control, items] of controlMap.entries()) {
      controls[control] = items.map(i => ({
        id: i.finding.rule.id, name: i.finding.rule.name,
        severity: i.finding.rule.severity, file: i.finding.filePath, line: i.finding.line,
      }));
    }
    return JSON.stringify({ summary: { framework, total: relevant.length, controls: controlMap.size }, controls });
  }

  if (controlMap.size === 0) {
    lines.push(`## No Compliance Issues`, ``, `No issues mapped to ${framework} controls were found.`);
    return lines.join("\n");
  }

  // Sort controls
  const sortedControls = [...controlMap.entries()].sort((a, b) => a[0].localeCompare(b[0]));

  lines.push(`## Summary`, ``, `| Control | Issues |`, `|---------|--------|`);
  for (const [control, items] of sortedControls) {
    lines.push(`| ${control} | ${items.length} |`);
  }
  lines.push(``);

  lines.push(`---`, ``);

  for (const [control, items] of sortedControls) {
    lines.push(`## ${control}`, ``);
    for (const item of items) {
      const f = item.finding;
      lines.push(
        `- **[${f.rule.severity.toUpperCase()}]** ${f.rule.name} (${f.rule.id}) in \`${f.filePath}\`:${f.line}`,
      );
    }
    lines.push(``);
  }

  return lines.join("\n");
}
