#!/usr/bin/env node

import { createRequire } from "module";
import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync, unlinkSync } from "fs";
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
  return true;
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

      - name: Install dependencies
        run: npm ci

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
    const hasBlocking = result.includes("[CRITICAL]") || result.includes("[HIGH]");
    if (hasBlocking) process.exit(1);
  }
}

async function runDirectoryScan(targetPath: string, flags: Record<string, string | true>): Promise<void> {
  const { scanDirectory } = await import("./tools/scan-directory.js");
  const { resolve } = await import("path");

  const format = (flags.format as string) ?? "markdown";
  const outputFile = (flags.output as string) ?? null;
  const scanPath = resolve(targetPath);

  let result: string;

  if (format === "sarif") {
    const { exportSarif } = await import("./tools/export-sarif.js");
    result = exportSarif(scanPath);
  } else {
    result = scanDirectory(scanPath, true, [], format === "json" ? "json" : "markdown");
  }

  if (outputFile) {
    writeFileSync(outputFile, result, "utf-8");
    console.log(`  [OK] Results written to ${outputFile}`);
  } else {
    console.log(result);
  }

  if (format !== "sarif") {
    const hasBlocking = result.includes("[CRITICAL]") || result.includes("[HIGH]");
    if (hasBlocking) process.exit(1);
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

  const hasBlocking = result.includes("[CRITICAL]") || result.includes("[HIGH]");
  if (hasBlocking) process.exit(1);
}

// ── Main CLI ─────────────────────────────────────────────────────────

function printUsage(): void {
  console.log(`
  GuardVibe Security - CLI

  Commands:
    npx guardvibe scan [path]        Scan a directory for security issues
    npx guardvibe check <file>       Scan a single file for security issues
    npx guardvibe init <platform>    Setup MCP server configuration
    npx guardvibe hook install       Install pre-commit security hook
    npx guardvibe hook uninstall     Remove pre-commit security hook
    npx guardvibe ci github          Generate GitHub Actions workflow

  Scan CLI (used by pre-commit hook and CI):
    npx guardvibe-scan               Scan git-staged files
    npx guardvibe-scan --format sarif --output results.sarif

  Options:
    --format <type>   Output format: markdown (default), json, sarif
    --output <file>   Write results to file instead of stdout
    --version, -V     Print version and exit
    --help, -h        Show this help message

  MCP Platforms:
    claude    Claude Code (.claude.json in project root)
    gemini    Gemini CLI (~/.gemini/settings.json)
    cursor    Cursor (.cursor/mcp.json)
    all       All platforms at once

  Supported File Types:
    .js .jsx .mjs .cjs .ts .tsx .mts .cts .py .go .html .sql
    .sh .bash .yml .yaml .tf .toml .json Dockerfile

  Examples:
    npx guardvibe scan .
    npx guardvibe scan ./src --format json
    npx guardvibe scan . --format sarif --output results.sarif
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
    await runDirectoryScan(targetPath, flags);
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
