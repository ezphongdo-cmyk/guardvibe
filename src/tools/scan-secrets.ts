import { existsSync, readdirSync, readFileSync, statSync } from "fs";
import { basename, dirname, extname, join, relative, resolve } from "path";
import { secretPatterns, calculateEntropy } from "../data/secret-patterns.js";
import { loadConfig } from "../utils/config.js";

export interface SecretFinding {
  provider: string;
  severity: "critical" | "high" | "medium";
  file: string;
  line: number;
  match: string;
  fix: string;
}

interface GitignoreEntry {
  baseDir: string;
  content: string;
}

const DEFAULT_SECRET_EXCLUDES = new Set(["node_modules", ".git", "build", "dist"]);
const SOURCE_FILE_EXTENSIONS = new Set([
  ".js", ".jsx", ".mjs", ".cjs",
  ".ts", ".tsx", ".mts", ".cts",
  ".py", ".go", ".html", ".sql",
  ".sh", ".bash", ".yml", ".yaml", ".tf",
]);
const CONFIG_FILE_EXTENSIONS = new Set([".yml", ".yaml", ".toml", ".json", ".cfg", ".ini", ".conf"]);

export function scanContent(content: string, filename: string): SecretFinding[] {
  const findings: SecretFinding[] = [];

  for (const sp of secretPatterns) {
    sp.pattern.lastIndex = 0;
    let match;
    while ((match = sp.pattern.exec(content)) !== null) {
      const beforeMatch = content.substring(0, match.index);
      const lineNumber = beforeMatch.split("\n").length;
      findings.push({
        provider: sp.provider,
        severity: sp.severity,
        file: filename,
        line: lineNumber,
        match: match[0].substring(0, 40) + (match[0].length > 40 ? "..." : ""),
        fix: sp.fix,
      });
    }
  }

  if (basename(filename).startsWith(".env")) {
    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith("#")) continue;
      const eqIdx = line.indexOf("=");
      if (eqIdx === -1) continue;
      const value = line.substring(eqIdx + 1).replace(/^['"]|['"]$/g, "");
      if (value.length >= 20 && calculateEntropy(value) > 4.5) {
        const alreadyFound = findings.some((finding) => finding.line === i + 1);
        if (!alreadyFound) {
          findings.push({
            provider: "High-Entropy Secret",
            severity: "high",
            file: filename,
            line: i + 1,
            match: line.substring(0, 40) + "...",
            fix: "This looks like a secret (high entropy). Ensure this file is in .gitignore.",
          });
        }
      }
    }
  }

  return findings;
}

function walkForSecrets(dir: string, recursive: boolean, results: string[], excludes: Set<string>): void {
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
      walkForSecrets(fullPath, recursive, results, excludes);
      continue;
    }

    if (!entry.isFile()) continue;

    const name = entry.name;
    const ext = extname(name).toLowerCase();

    if (name.startsWith(".env") || CONFIG_FILE_EXTENSIONS.has(ext) || SOURCE_FILE_EXTENSIONS.has(ext)) {
      results.push(fullPath);
    }
  }
}

function findGitRoot(startDir: string): string | null {
  let current = resolve(startDir);

  while (true) {
    if (existsSync(join(current, ".git"))) return current;
    const parent = dirname(current);
    if (parent === current) return null;
    current = parent;
  }
}

function collectGitignoreEntries(startDir: string): GitignoreEntry[] {
  const entries: GitignoreEntry[] = [];
  const gitRoot = findGitRoot(startDir);
  let current = resolve(startDir);

  while (true) {
    const gitignorePath = join(current, ".gitignore");
    if (existsSync(gitignorePath)) {
      try {
        entries.push({ baseDir: current, content: readFileSync(gitignorePath, "utf-8") });
      } catch {
        // Ignore unreadable .gitignore files.
      }
    }

    if (current === gitRoot) break;

    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }

  return entries;
}

function isEnvCoveredByGitignore(envFile: string, gitignoreEntries: GitignoreEntry[]): boolean {
  const envName = basename(envFile);

  return gitignoreEntries.some(({ baseDir, content }) => {
    const relativePath = relative(baseDir, envFile).replace(/\\/g, "/");
    return (
      content.includes(envName) ||
      content.includes(relativePath) ||
      content.includes(`/${relativePath}`) ||
      content.includes(".env*") ||
      content.includes(".env")
    );
  });
}

export function scanSecrets(path: string, recursive: boolean = true, format: "markdown" | "json" = "markdown"): string {
  const targetPath = resolve(path);
  const filePaths: string[] = [];

  let targetStat;
  try {
    targetStat = statSync(targetPath);
  } catch {
    return `# GuardVibe Secret Scan Report\n\nError: Could not access path: ${path}`;
  }

  const scanRoot = targetStat.isDirectory() ? targetPath : dirname(targetPath);
  const config = loadConfig(scanRoot);
  const excludes = new Set([...DEFAULT_SECRET_EXCLUDES, ...config.scan.exclude]);

  if (targetStat.isFile()) {
    filePaths.push(targetPath);
  } else {
    walkForSecrets(targetPath, recursive, filePaths, excludes);
  }

  const uniquePaths = [...new Set(filePaths)];
  const allFindings: SecretFinding[] = [];

  for (const filePath of uniquePaths) {
    try {
      const stat = statSync(filePath);
      if (stat.size > config.scan.maxFileSize) continue;
      const content = readFileSync(filePath, "utf-8");
      allFindings.push(...scanContent(content, filePath));
    } catch {
      // Skip unreadable files.
    }
  }

  const envFiles = uniquePaths.filter((filePath) => basename(filePath).startsWith(".env"));
  for (const envFile of envFiles) {
    const gitignoreEntries = collectGitignoreEntries(dirname(envFile));
    if (isEnvCoveredByGitignore(envFile, gitignoreEntries)) continue;

    const envName = basename(envFile);
    allFindings.push({
      provider: ".env not in .gitignore",
      severity: "critical",
      file: envFile,
      line: 0,
      match: `${envName} is not listed in .gitignore`,
      fix: `Add '${envName}' or '.env*' to .gitignore immediately.`,
    });
  }

  if (format === "json") {
    const critCount = allFindings.filter(f => f.severity === "critical").length;
    const highCount = allFindings.filter(f => f.severity === "high").length;
    const medCount = allFindings.length - critCount - highCount;
    return JSON.stringify({
      summary: { total: allFindings.length, critical: critCount, high: highCount, medium: medCount, blocked: critCount > 0 || highCount > 0 },
      findings: allFindings.map(f => ({ provider: f.provider, severity: f.severity, file: f.file, line: f.line, match: f.match, fix: f.fix })),
    });
  }

  const lines: string[] = [
    "# GuardVibe Secret Scan Report",
    "",
    `Files scanned: ${uniquePaths.length}`,
    `Secrets found: ${allFindings.length}`,
  ];

  if (allFindings.length > 0) {
    const critCount = allFindings.filter((finding) => finding.severity === "critical").length;
    const highCount = allFindings.filter((finding) => finding.severity === "high").length;
    lines.push(`Risk Level: ${critCount > 0 ? "Critical" : highCount > 0 ? "High" : "Medium"}`);
    lines.push("", "---", "", "## Findings", "");

    const order: Record<string, number> = { critical: 0, high: 1, medium: 2 };
    allFindings.sort((left, right) => order[left.severity] - order[right.severity]);

    for (const finding of allFindings) {
      lines.push(
        `### [${finding.severity.toUpperCase()}] ${finding.provider}`,
        `**File:** ${finding.file}${finding.line > 0 ? `:${finding.line}` : ""}`,
        `**Match:** \`${finding.match}\``,
        `**Fix:** ${finding.fix}`,
        "",
      );
    }
  } else {
    lines.push("Risk Level: None", "", "No secrets detected. Good job keeping your code clean!");
  }

  return lines.join("\n");
}
