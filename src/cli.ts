#!/usr/bin/env node

import { createRequire } from "module";
import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync, unlinkSync, statSync } from "fs";
import { join, dirname } from "path";
import { homedir } from "os";

const require = createRequire(import.meta.url);
const pkg = require("../package.json") as { version: string };

const GUARDVIBE_MCP_CONFIG = {
  command: "npx",
  args: ["-y", "guardvibe"],
};

interface McpConfig {
  mcpServers?: Record<string, unknown>;
  [key: string]: unknown;
}

const platforms: Record<string, { path: string; description: string }> = {
  claude: {
    path: join(process.cwd(), ".claude.json"),
    description: "Claude Code (.claude.json)",
  },
  gemini: {
    path: join(homedir(), ".gemini", "settings.json"),
    description: "Gemini CLI (~/.gemini/settings.json)",
  },
  cursor: {
    path: join(process.cwd(), ".cursor", "mcp.json"),
    description: "Cursor (.cursor/mcp.json)",
  },
};

function readJsonFile(filePath: string): McpConfig | null {
  try {
    const content = readFileSync(filePath, "utf-8");
    return JSON.parse(content);
  } catch {
    return null;
  }
}

function writeJsonFile(filePath: string, data: McpConfig): void {
  const dir = dirname(filePath);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  writeFileSync(filePath, JSON.stringify(data, null, 2) + "\n", "utf-8");
}

function setupPlatform(name: string): boolean {
  const platform = platforms[name];
  if (!platform) return false;

  const existing = readJsonFile(platform.path);

  if (existing) {
    if (!existing.mcpServers) {
      existing.mcpServers = {};
    }
    if ((existing.mcpServers as Record<string, unknown>)["guardvibe"]) {
      console.log(`  [OK] GuardVibe already configured in ${platform.description}`);
      // Still ensure security guidance and .gitignore are set up
      setupSecurityGuide(name);
      return true;
    }
    (existing.mcpServers as Record<string, unknown>)["guardvibe"] = GUARDVIBE_MCP_CONFIG;
    writeJsonFile(platform.path, existing);
  } else {
    writeJsonFile(platform.path, {
      mcpServers: {
        guardvibe: GUARDVIBE_MCP_CONFIG,
      },
    });
  }

  console.log(`  [OK] Added MCP server to ${platform.description}`);

  // Set up platform-specific security guidance + universal security rules
  setupSecurityGuide(name);

  return true;
}

// ── Universal security rules (shared across all AI platforms) ────────

const SECURITY_RULES = `## Security Rules (enforced by GuardVibe MCP)

### Mandatory checks
- AFTER writing any API route, Server Action, or database query: use the guardvibe scan_file MCP tool on the file
- BEFORE committing: use the guardvibe scan_staged MCP tool
- When GuardVibe reports HIGH or CRITICAL: fix immediately before moving on
- BEFORE creating a PR: use scan_changed_files to review all changes

### Writing secure code
- Every API route handler MUST have auth check before DB access
- Every POST endpoint MUST have input validation (zod/joi schema)
- Never pass user input to innerHTML, eval, exec, or raw SQL
- Never pass user-controlled URLs to fetch() without allowlist validation
- Always use select: in Prisma/Drizzle queries from Server Actions (never return full objects to client)
- Always validate redirect URLs against trusted domain allowlist
- Set security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- Verify webhook signatures before processing events
- Use parameterized queries, never string concatenation/template literals for SQL

### When in doubt
- Use the guardvibe explain_remediation MCP tool with the rule ID for detailed fix guidance
- Use the guardvibe check_code MCP tool to verify a code snippet is secure before applying
`;

function setupSecurityGuide(platformName: string): void {
  // 1. Platform-specific guidance file
  if (platformName === "claude") setupClaudeGuide();
  else if (platformName === "cursor") setupCursorGuide();
  else if (platformName === "gemini") setupGeminiGuide();

  // 2. Platform-specific .gitignore entries
  const gitignoreEntries: Record<string, string[]> = {
    claude: [".claude.json", ".claude/", "CLAUDE.md"],
    cursor: [".cursor/", ".cursorrules"],
    gemini: ["GEMINI.md"],
  };
  const entries = gitignoreEntries[platformName] || [];
  // Always add .guardvibe/ (stats directory) to .gitignore
  entries.push(".guardvibe/");
  if (entries.length > 0) addToGitignore(entries);
}

function setupClaudeGuide(): void {
  // Claude Code hooks
  const claudeSettingsDir = join(process.cwd(), ".claude");
  if (!existsSync(claudeSettingsDir)) mkdirSync(claudeSettingsDir, { recursive: true });

  const claudeSettingsPath = join(claudeSettingsDir, "settings.json");
  const existingSettings = readJsonFile(claudeSettingsPath) || {};
  if (!(existingSettings as any).hooks) (existingSettings as any).hooks = {};
  if (!(existingSettings as any).hooks.PostToolUse) {
    (existingSettings as any).hooks.PostToolUse = [
      {
        matcher: "Edit|Write",
        hooks: [{
          type: "command",
          command: "jq -r '.tool_input.file_path' | xargs npx -y guardvibe check --format markdown 2>/dev/null || true"
        }]
      }
    ];
  }
  writeJsonFile(claudeSettingsPath, existingSettings as any);
  console.log(`  [OK] Claude Code hooks configured (.claude/settings.json)`);

  // CLAUDE.md
  const claudeMdPath = join(process.cwd(), "CLAUDE.md");
  if (existsSync(claudeMdPath)) {
    const content = readFileSync(claudeMdPath, "utf-8");
    if (!content.includes("GuardVibe")) {
      writeFileSync(claudeMdPath, content + "\n" + SECURITY_RULES, "utf-8");
      console.log(`  [OK] GuardVibe rules added to CLAUDE.md`);
    }
  } else {
    writeFileSync(claudeMdPath, `# Project Guidelines\n\n${SECURITY_RULES}`, "utf-8");
    console.log(`  [OK] Created CLAUDE.md with security rules`);
  }
}

function setupCursorGuide(): void {
  // .cursorrules — Cursor reads this file for AI instructions
  const cursorrules = join(process.cwd(), ".cursorrules");
  if (existsSync(cursorrules)) {
    const content = readFileSync(cursorrules, "utf-8");
    if (!content.includes("GuardVibe")) {
      writeFileSync(cursorrules, content + "\n" + SECURITY_RULES, "utf-8");
      console.log(`  [OK] GuardVibe rules added to .cursorrules`);
    }
  } else {
    writeFileSync(cursorrules, SECURITY_RULES, "utf-8");
    console.log(`  [OK] Created .cursorrules with security rules`);
  }
}

function setupGeminiGuide(): void {
  // GEMINI.md — Gemini CLI reads this for project context
  const geminiMd = join(process.cwd(), "GEMINI.md");
  if (existsSync(geminiMd)) {
    const content = readFileSync(geminiMd, "utf-8");
    if (!content.includes("GuardVibe")) {
      writeFileSync(geminiMd, content + "\n" + SECURITY_RULES, "utf-8");
      console.log(`  [OK] GuardVibe rules added to GEMINI.md`);
    }
  } else {
    writeFileSync(geminiMd, `# Project Guidelines\n\n${SECURITY_RULES}`, "utf-8");
    console.log(`  [OK] Created GEMINI.md with security rules`);
  }
}


function addToGitignore(entries: string[]): void {
  const gitignorePath = join(process.cwd(), ".gitignore");
  let content = "";
  try {
    content = readFileSync(gitignorePath, "utf-8");
  } catch { /* no .gitignore yet */ }

  const missing = entries.filter(e => !content.split("\n").some(line => line.trim() === e));
  if (missing.length === 0) return;

  const block = `\n# GuardVibe (auto-added by guardvibe init)\n${missing.join("\n")}\n`;
  writeFileSync(gitignorePath, content.trimEnd() + block, "utf-8");
  console.log(`  [OK] Added ${missing.join(", ")} to .gitignore`);
}

// ── Pre-commit hook ──────────────────────────────────────────────────

const HOOK_SCRIPT = `#!/bin/sh
# GuardVibe pre-commit security hook
# Installed by: npx guardvibe hook install

echo "🔒 GuardVibe: scanning staged files..."

# Run guardvibe scan on staged files
RESULT=$(npx -y guardvibe-scan 2>&1)
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  echo ""
  echo "$RESULT"
  echo ""
  echo "❌ GuardVibe: security issues found. Fix them or commit with --no-verify to skip."
  exit 1
fi

echo "✅ GuardVibe: all checks passed."
`;

function installHook(): void {
  const gitDir = join(process.cwd(), ".git");
  if (!existsSync(gitDir)) {
    console.error("  [ERR] Not a git repository. Run this from your project root.");
    process.exit(1);
  }

  const hooksDir = join(gitDir, "hooks");
  if (!existsSync(hooksDir)) {
    mkdirSync(hooksDir, { recursive: true });
  }

  const hookPath = join(hooksDir, "pre-commit");

  if (existsSync(hookPath)) {
    const existing = readFileSync(hookPath, "utf-8");
    if (existing.includes("GuardVibe")) {
      console.log("  [OK] GuardVibe pre-commit hook already installed.");
      return;
    }
    // Append to existing hook
    writeFileSync(hookPath, existing + "\n" + HOOK_SCRIPT, "utf-8");
    console.log("  [OK] GuardVibe added to existing pre-commit hook.");
  } else {
    writeFileSync(hookPath, HOOK_SCRIPT, "utf-8");
    chmodSync(hookPath, 0o755);
    console.log("  [OK] Pre-commit hook installed at .git/hooks/pre-commit");
  }
}

function uninstallHook(): void {
  const hookPath = join(process.cwd(), ".git", "hooks", "pre-commit");
  if (!existsSync(hookPath)) {
    console.log("  [OK] No pre-commit hook found.");
    return;
  }

  const content = readFileSync(hookPath, "utf-8");
  if (!content.includes("GuardVibe")) {
    console.log("  [OK] Pre-commit hook exists but doesn't contain GuardVibe.");
    return;
  }

  // Remove GuardVibe section
  const cleaned = content
    .replace(/\n?# GuardVibe pre-commit security hook[\s\S]*?GuardVibe: all checks passed[."]*\n?/g, "")
    .trim();

  if (!cleaned || cleaned === "#!/bin/sh") {
    unlinkSync(hookPath);
    console.log("  [OK] Pre-commit hook removed.");
  } else {
    writeFileSync(hookPath, cleaned + "\n", "utf-8");
    console.log("  [OK] GuardVibe removed from pre-commit hook (other hooks preserved).");
  }
}

// ── GitHub Actions workflow ──────────────────────────────────────────

const GITHUB_ACTIONS_WORKFLOW = `name: GuardVibe Security Scan

on:
  pull_request:
    branches: [main, master]
  push:
    branches: [main, master]

permissions:
  contents: read
  security-events: write

jobs:
  security-scan:
    name: Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false

      - uses: actions/setup-node@v4
        with:
          node-version: "22"

      - name: Run GuardVibe security scan
        run: npx -y guardvibe-scan --format sarif --output guardvibe-results.sarif

      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: guardvibe-results.sarif
          category: guardvibe
`;

function generateGitHubActions(): void {
  const workflowDir = join(process.cwd(), ".github", "workflows");
  if (!existsSync(workflowDir)) {
    mkdirSync(workflowDir, { recursive: true });
  }

  const workflowPath = join(workflowDir, "guardvibe.yml");
  if (existsSync(workflowPath)) {
    console.log("  [OK] .github/workflows/guardvibe.yml already exists.");
    return;
  }

  writeFileSync(workflowPath, GITHUB_ACTIONS_WORKFLOW, "utf-8");
  console.log("  [OK] Created .github/workflows/guardvibe.yml");
  console.log("  [OK] SARIF results will appear in GitHub Security tab.");
}

// ── Scan CLI (for pre-commit hook and CI) ────────────────────────────

const SCAN_SCRIPT_DETECTED = process.argv[1]?.endsWith("guardvibe-scan") ||
  process.argv[1]?.endsWith("guardvibe-scan.js");

if (SCAN_SCRIPT_DETECTED) {
  runScan();
} else {
  main();
}

/**
 * Check if scan results should cause a non-zero exit based on --fail-on flag.
 * Default: "critical" — only exit 1 on critical findings.
 * Options: "critical", "high", "medium", "low", "none"
 */
function shouldFail(result: string, failOn: string): boolean {
  if (failOn === "none") return false;
  const levels: Record<string, string[]> = {
    low: ["critical", "high", "medium", "low"],
    medium: ["critical", "high", "medium"],
    high: ["critical", "high"],
    critical: ["critical"],
  };
  const failLevels = levels[failOn] || levels.critical;

  // Try JSON format first
  try {
    const parsed = JSON.parse(result);
    if (parsed.summary) {
      return failLevels.some(level => (parsed.summary[level] ?? 0) > 0);
    }
    if (parsed.findings) {
      return parsed.findings.some((f: any) => failLevels.includes(f.severity));
    }
  } catch { /* not JSON, try markdown tags */ }

  // Markdown format: check for [SEVERITY] tags
  const tags = failLevels.map(l => `[${l.toUpperCase()}]`);
  return tags.some(tag => result.includes(tag));
}

function parseArgs(args: string[]): { flags: Record<string, string | true>; positional: string[] } {
  const flags: Record<string, string | true> = {};
  const positional: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith("--")) {
      const key = args[i].slice(2);
      const next = args[i + 1];
      if (next && !next.startsWith("--")) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(args[i]);
    }
  }
  return { flags, positional };
}

async function runScan(): Promise<void> {
  const args = process.argv.slice(2);
  const { flags } = parseArgs(args);
  const format = (flags.format as string) ?? "markdown";
  const outputFile = (flags.output as string) ?? null;

  let result: string;

  if (format === "sarif") {
    const { exportSarif } = await import("./tools/export-sarif.js");
    result = exportSarif(process.cwd());
  } else {
    const { scanStaged } = await import("./tools/scan-staged.js");
    result = scanStaged(process.cwd(), format === "json" ? "json" : "markdown");
  }

  if (outputFile) {
    writeFileSync(outputFile, result, "utf-8");
    console.log(`  [OK] Results written to ${outputFile}`);
  } else {
    console.log(result);
  }

  if (format !== "sarif") {
    const failOn = (flags["fail-on"] as string) ?? "high";
    if (shouldFail(result, failOn)) process.exit(1);
  }
}

async function runDirectoryScan(targetPath: string, flags: Record<string, string | true>): Promise<void> {
  const { scanDirectory } = await import("./tools/scan-directory.js");
  const { resolve } = await import("path");

  const format = (flags.format as string) ?? "markdown";
  const outputFile = (flags.output as string) ?? null;
  const baselinePath = (flags.baseline as string) ?? null;
  const saveBaseline = flags["save-baseline"] === true || typeof flags["save-baseline"] === "string";
  const scanPath = resolve(targetPath);

  let result: string;

  if (format === "sarif") {
    const { exportSarif } = await import("./tools/export-sarif.js");
    result = exportSarif(scanPath);
  } else {
    result = scanDirectory(scanPath, true, [], format === "json" ? "json" : "markdown", undefined, baselinePath ?? undefined);
  }

  if (outputFile) {
    writeFileSync(outputFile, result, "utf-8");
    console.log(`  [OK] Results written to ${outputFile}`);
  } else {
    console.log(result);
  }

  // Auto-save baseline for future diff comparisons
  if (saveBaseline && format === "json") {
    const baselineFile = typeof flags["save-baseline"] === "string"
      ? flags["save-baseline"]
      : join(scanPath, ".guardvibe-baseline.json");
    writeFileSync(baselineFile, result, "utf-8");
    console.log(`  [OK] Baseline saved to ${baselineFile}`);
  }

  if (format !== "sarif") {
    const failOn = (flags["fail-on"] as string) ?? "critical";
    if (shouldFail(result, failOn)) process.exit(1);
  }
}

async function runDiffScan(base: string, flags: Record<string, string | true>): Promise<void> {
  const { execFileSync } = await import("child_process");
  const { resolve, extname, basename } = await import("path");
  const { analyzeCode } = await import("./tools/check-code.js");
  const { EXTENSION_MAP, CONFIG_FILE_MAP } = await import("./utils/constants.js");

  const format = (flags.format as string) ?? "markdown";
  const outputFile = (flags.output as string) ?? null;
  const root = resolve(".");

  let changedFiles: string[];
  try {
    const output = execFileSync("git", ["diff", "--name-only", "--diff-filter=ACMR", base], { cwd: root, encoding: "utf-8" });
    changedFiles = output.trim().split("\n").filter(Boolean);
  } catch {
    console.error("  [ERR] Failed to get git diff. Ensure you're in a git repository.");
    process.exit(1);
  }

  if (changedFiles.length === 0) {
    console.log("  No changed files to scan.");
    return;
  }

  const allFindings: Array<{ file: string; severity: string; name: string; id: string; line: number; fix: string }> = [];

  for (const relPath of changedFiles) {
    const fullPath = resolve(root, relPath);
    if (!existsSync(fullPath)) continue;

    const ext = extname(relPath).toLowerCase();
    let language = EXTENSION_MAP[ext];
    if (!language && basename(relPath).startsWith("Dockerfile")) language = "dockerfile";
    if (!language) language = CONFIG_FILE_MAP[basename(relPath)];
    if (!language) continue;

    try {
      const content = readFileSync(fullPath, "utf-8");
      const findings = analyzeCode(content, language, undefined, fullPath, root);
      for (const f of findings) {
        allFindings.push({ file: relPath, severity: f.rule.severity, name: f.rule.name, id: f.rule.id, line: f.line, fix: f.rule.fix });
      }
    } catch { /* skip */ }
  }

  let result: string;
  if (format === "json") {
    const critical = allFindings.filter(f => f.severity === "critical").length;
    const high = allFindings.filter(f => f.severity === "high").length;
    const medium = allFindings.filter(f => f.severity === "medium").length;
    result = JSON.stringify({
      summary: { total: allFindings.length, critical, high, medium, changedFiles: changedFiles.length, blocked: critical > 0 || high > 0 },
      findings: allFindings,
    });
  } else {
    const lines = [`# GuardVibe Diff Report`, ``, `Base: ${base}`, `Changed files: ${changedFiles.length}`, `Issues: ${allFindings.length}`, ``];
    if (allFindings.length === 0) {
      lines.push(`All changed files passed security checks.`);
    } else {
      const sev: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      allFindings.sort((a, b) => (sev[a.severity] ?? 99) - (sev[b.severity] ?? 99));
      for (const f of allFindings) {
        lines.push(`- [${f.severity.toUpperCase()}] **${f.name}** (${f.id}) in ${f.file}:${f.line}`);
        lines.push(`  Fix: ${f.fix}`);
      }
    }
    result = lines.join("\n");
  }

  if (outputFile) {
    writeFileSync(outputFile, result, "utf-8");
    console.log(`  [OK] Results written to ${outputFile}`);
  } else {
    console.log(result);
  }

  const failOn = (flags["fail-on"] as string) ?? "critical";
  if (failOn !== "none") {
    const failLevels: Record<string, string[]> = {
      low: ["critical", "high", "medium", "low"],
      medium: ["critical", "high", "medium"],
      high: ["critical", "high"],
      critical: ["critical"],
    };
    const levels = failLevels[failOn] || failLevels.critical;
    if (allFindings.some(f => levels.includes(f.severity))) process.exit(1);
  }
}

async function runFileCheck(filePath: string, flags: Record<string, string | true>): Promise<void> {
  const { checkCode } = await import("./tools/check-code.js");
  const { resolve, extname, basename } = await import("path");

  const resolved = resolve(filePath);
  if (!existsSync(resolved)) {
    console.error(`  [ERR] File not found: ${resolved}`);
    process.exit(1);
  }

  const content = readFileSync(resolved, "utf-8");
  const ext = extname(resolved).toLowerCase();

  const extMap: Record<string, string> = {
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".py": "python", ".go": "go", ".html": "html", ".sql": "sql",
    ".sh": "shell", ".bash": "shell", ".yml": "yaml", ".yaml": "yaml",
    ".tf": "terraform", ".toml": "toml", ".json": "json",
  };

  let language = extMap[ext];
  if (!language && basename(resolved).startsWith("Dockerfile")) language = "dockerfile";
  if (!language) {
    console.error(`  [ERR] Unsupported file type: ${ext}`);
    process.exit(1);
  }

  const format = (flags.format as string) ?? "markdown";
  const result = checkCode(content, language, undefined, resolved, undefined, format === "json" ? "json" : "markdown");

  const outputFile = (flags.output as string) ?? null;
  if (outputFile) {
    writeFileSync(outputFile, result, "utf-8");
    console.log(`  [OK] Results written to ${outputFile}`);
  } else {
    console.log(result);
  }

  const failOn = (flags["fail-on"] as string) ?? "critical";
  if (shouldFail(result, failOn)) process.exit(1);
}

// ── Main CLI ─────────────────────────────────────────────────────────

function printUsage(): void {
  console.log(`
  GuardVibe Security - CLI

  Commands:
    npx guardvibe scan [path]        Scan a directory for security issues
    npx guardvibe diff [base]        Scan only changed files since a git ref
    npx guardvibe check <file>       Scan a single file for security issues
    npx guardvibe init <platform>    Setup MCP server configuration
    npx guardvibe hook install       Install pre-commit security hook
    npx guardvibe hook uninstall     Remove pre-commit security hook
    npx guardvibe ci github          Generate GitHub Actions workflow

  Scan CLI (used by pre-commit hook and CI):
    npx guardvibe-scan               Scan git-staged files
    npx guardvibe-scan --format sarif --output results.sarif

  Options:
    --format <type>       Output format: markdown (default), json, sarif
    --output <file>       Write results to file instead of stdout
    --fail-on <level>     Exit 1 when findings at this level or above exist
                          critical (default) | high | medium | low | none
    --baseline <file>     Compare against a previous scan JSON for fix tracking
    --save-baseline       Save current scan as baseline (.guardvibe-baseline.json)
    --version, -V         Print version and exit
    --help, -h            Show this help message

  MCP Platforms:
    claude    Claude Code (.claude.json + CLAUDE.md + hooks)
    cursor    Cursor (.cursor/mcp.json + .cursorrules)
    gemini    Gemini CLI (~/.gemini/settings.json + GEMINI.md)
    all       All platforms at once

  Supported File Types:
    .js .jsx .mjs .cjs .ts .tsx .mts .cts .py .go .html .sql
    .sh .bash .yml .yaml .tf .toml .json Dockerfile

  Examples:
    npx guardvibe scan .
    npx guardvibe scan ./src --format json
    npx guardvibe scan . --format sarif --output results.sarif
    npx guardvibe scan . --format json --save-baseline
    npx guardvibe scan . --baseline .guardvibe-baseline.json
    npx guardvibe check src/app/api/route.ts
    npx guardvibe check package.json
    npx guardvibe init claude
    npx guardvibe hook install
    npx guardvibe ci github
`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes("--version") || args.includes("-V")) {
    console.log(pkg.version);
    process.exit(0);
  }

  if (args[0] === "--help" || args[0] === "-h") {
    printUsage();
    process.exit(0);
  }

  // No args: if stdin is a pipe, start MCP server; if TTY, show help
  if (args.length === 0) {
    if (process.stdin.isTTY) {
      printUsage();
      process.exit(0);
    } else {
      // Started by MCP client (Claude Code, Cursor, etc.) — launch MCP server
      const { startMcpServer } = await import("./index.js");
      await startMcpServer();
      return;
    }
  }

  const command = args[0];

  if (command === "init") {
    const platform = args[1]?.toLowerCase();
    if (!platform) {
      console.error("  Please specify a platform: claude, gemini, cursor, or all");
      process.exit(1);
    }

    console.log(`\n  GuardVibe Security Setup\n`);

    if (platform === "all") {
      for (const name of Object.keys(platforms)) {
        setupPlatform(name);
      }
    } else if (platforms[platform]) {
      setupPlatform(platform);
    } else {
      console.error(`  Unknown platform: ${platform}`);
      console.error(`  Available: claude, gemini, cursor, all`);
      process.exit(1);
    }

    console.log(`\n  [OK] Ready! Start coding securely.\n`);
  } else if (command === "hook") {
    const action = args[1]?.toLowerCase();
    console.log(`\n  GuardVibe Pre-Commit Hook\n`);

    if (action === "install") {
      installHook();
    } else if (action === "uninstall") {
      uninstallHook();
    } else {
      console.error("  Usage: npx guardvibe hook install|uninstall");
      process.exit(1);
    }

    console.log();
  } else if (command === "scan") {
    const cliArgs = args.slice(1);
    const { flags, positional } = parseArgs(cliArgs);
    const targetPath = positional[0] ?? ".";
    // If target is a file (not directory), auto-redirect to check mode
    if (targetPath !== "." && existsSync(targetPath) && !statSync(targetPath).isDirectory()) {
      console.log(`  [INFO] "${targetPath}" is a file. Running: guardvibe check ${targetPath}\n`);
      await runFileCheck(targetPath, flags);
    } else {
      await runDirectoryScan(targetPath, flags);
    }
  } else if (command === "diff") {
    const cliArgs = args.slice(1);
    const { flags, positional } = parseArgs(cliArgs);
    const base = positional[0] ?? "main";
    await runDiffScan(base, flags);
  } else if (command === "check") {
    const cliArgs = args.slice(1);
    const { flags, positional } = parseArgs(cliArgs);
    const filePath = positional[0];
    if (!filePath) {
      console.error("  Please specify a file: npx guardvibe check <file>");
      process.exit(1);
    }
    await runFileCheck(filePath, flags);
  } else if (command === "ci") {
    const provider = args[1]?.toLowerCase();
    console.log(`\n  GuardVibe CI/CD Setup\n`);

    if (provider === "github") {
      generateGitHubActions();
    } else {
      console.error("  Usage: npx guardvibe ci github");
      console.error("  (more CI providers coming soon)");
      process.exit(1);
    }

    console.log();
  } else {
    console.error(`  Unknown command: ${command}`);
    printUsage();
    process.exit(1);
  }
}
