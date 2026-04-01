#!/usr/bin/env node

import { createRequire } from "module";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { checkCode } from "./tools/check-code.js";

const require = createRequire(import.meta.url);
const pkg = require("../package.json") as { version: string };
import { checkProject } from "./tools/check-project.js";
import { getSecurityDocs } from "./tools/get-security-docs.js";
import { checkDependencies } from "./tools/check-deps.js";
import { scanDirectory } from "./tools/scan-directory.js";
import { scanDependencies } from "./tools/scan-dependencies.js";
import { scanSecrets } from "./tools/scan-secrets.js";
import { scanStaged } from "./tools/scan-staged.js";
import { complianceReport } from "./tools/compliance-report.js";
import { exportSarif } from "./tools/export-sarif.js";
import { checkPackageHealth } from "./tools/check-package-health.js";
import { fixCode } from "./tools/fix-code.js";
import { auditConfig } from "./tools/audit-config.js";
import { generatePolicy } from "./tools/generate-policy.js";
import { reviewPr } from "./tools/review-pr.js";
import { scanSecretsHistory } from "./tools/scan-secrets-history.js";
import { policyCheck } from "./tools/policy-check.js";
import { analyzeTaint, formatTaintFindings } from "./tools/taint-analysis.js";
import { checkCommand } from "./tools/check-command.js";
import { scanConfigChange } from "./tools/scan-config-change.js";
import { repoSecurityPosture } from "./tools/repo-posture.js";
import { explainRemediation } from "./tools/explain-remediation.js";
import { discoverPlugins } from "./plugins/loader.js";
import { builtinRules } from "./data/rules/index.js";
import type { SecurityRule } from "./data/rules/types.js";
import { loadConfig } from "./utils/config.js";
import { setRules, getRules } from "./utils/rule-registry.js";

const server = new McpServer({
  name: "guardvibe",
  version: pkg.version,
});

// Tool 1: Analyze code for security vulnerabilities
server.tool(
  "check_code",
  "Analyze code for security vulnerabilities (OWASP Top 10, XSS, SQL injection, insecure patterns). Use this when reviewing or writing code to catch security issues early.",
  {
    code: z.string().describe("The code snippet to analyze"),
    language: z
      .enum(["javascript", "typescript", "python", "go", "dockerfile", "html", "sql", "shell", "yaml", "terraform", "firestore"])
      .describe("Programming language of the code"),
    framework: z
      .string()
      .optional()
      .describe("Framework context (e.g. express, nextjs, fastapi, react, django)"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format: markdown (human) or json (machine-readable for agents)"),
  },
  async ({ code, language, framework, format }) => {
    const rules = getRules();
    const results = checkCode(code, language, framework, undefined, undefined, format, rules);
    return {
      content: [{ type: "text", text: results }],
    };
  }
);

// Tool 2: Scan entire project for security vulnerabilities
server.tool(
  "check_project",
  "Scan multiple files for security vulnerabilities and generate a project-wide security report with a security score. Use this for comprehensive security audits.",
  {
    files: z
      .array(
        z.object({
          path: z.string().describe("Relative file path (e.g. src/app.ts)"),
          content: z.string().describe("File source code"),
        })
      )
      .describe("List of files to scan: [{path, content}]"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format: markdown (human) or json (machine-readable for agents)"),
  },
  async ({ files, format }) => {
    const rules = getRules();
    const results = checkProject(files, format, rules);
    return {
      content: [{ type: "text", text: results }],
    };
  }
);

// Tool 3: Get security documentation and best practices (renumbered from Tool 2)
server.tool(
  "get_security_docs",
  "Get security best practices and guidance for a specific topic, framework, or vulnerability type. Use this to learn how to write secure code.",
  {
    topic: z
      .string()
      .describe(
        'Security topic to look up (e.g. "express authentication", "sql injection prevention", "nextjs csrf", "react xss", "owasp top 10")'
      ),
  },
  async ({ topic }) => {
    const docs = getSecurityDocs(topic);
    return {
      content: [{ type: "text", text: docs }],
    };
  }
);

// Tool 4: Check dependencies for known vulnerabilities
const packageSchema = z.object({
  name: z.string().describe("Package name (e.g. lodash, express, django)"),
  version: z.string().describe("Package version (e.g. 4.17.20)"),
  ecosystem: z
    .enum(["npm", "PyPI", "Go"])
    .default("npm")
    .describe("Package ecosystem"),
});

server.tool(
  "check_dependencies",
  "Check npm, PyPI, or Go packages for known security vulnerabilities (CVEs) using the OSV database. Use this before adding new dependencies or to audit existing ones.",
  {
    packages: z.preprocess(
      (val) => {
        if (typeof val === "string") {
          try {
            return JSON.parse(val);
          } catch {
            return val;
          }
        }
        return val;
      },
      z.array(packageSchema)
    ).describe("List of packages to check: [{name, version, ecosystem}]"),
  },
  async ({ packages }) => {
    const results = await checkDependencies(packages);
    return {
      content: [{ type: "text", text: results }],
    };
  }
);

// Tool 5: Scan directory for security vulnerabilities (filesystem-native)
server.tool(
  "scan_directory",
  "Scan an entire project directory for security vulnerabilities. Reads files directly from the filesystem — no need to pass file contents. Returns a security score (A-F) and detailed findings. Includes scan metadata (ID, timestamp, duration, file hashes) for audit trails. Use baseline to compare with a previous scan.",
  {
    path: z.string().describe("Directory path to scan (e.g. './src', '.')"),
    recursive: z.boolean().optional().default(true).describe("Scan subdirectories"),
    exclude: z.array(z.string()).optional().default([]).describe("Additional directories to exclude"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format: markdown (human) or json (machine-readable for agents)"),
    baseline: z.string().optional().describe("Path to a previous scan JSON output file for baseline comparison (new/fixed/unchanged findings)"),
  },
  async ({ path, recursive, exclude, format, baseline }) => {
    const rules = getRules();
    const results = scanDirectory(path, recursive, exclude, format, rules, baseline);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 6: Scan manifest/lockfile for dependency vulnerabilities
server.tool(
  "scan_dependencies",
  "Parse a lockfile or manifest (package.json, package-lock.json, requirements.txt, go.mod) and check all dependencies for known CVEs via the OSV database. Reads the file directly.",
  {
    manifest_path: z.string().describe("Path to manifest file (e.g. 'package.json', 'requirements.txt', 'go.mod')"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format: markdown (human) or json (machine-readable for agents)"),
  },
  async ({ manifest_path, format }) => {
    const results = await scanDependencies(manifest_path, format);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 7: Scan for leaked secrets, API keys, and credentials
server.tool(
  "scan_secrets",
  "Scan files and directories for leaked secrets, API keys, tokens, and credentials. Checks .env files, config files, and source code. Verifies .gitignore coverage.",
  {
    path: z.string().describe("File or directory path to scan"),
    recursive: z.boolean().optional().default(true).describe("Scan subdirectories"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format: markdown (human) or json (machine-readable for agents)"),
  },
  async ({ path, recursive, format }) => {
    const results = scanSecrets(path, recursive, format);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 8: Scan git-staged files before committing
server.tool(
  "scan_staged",
  "Scan git-staged files for security vulnerabilities before committing. Run this before every commit to catch issues early. No input needed — automatically reads staged files.",
  {
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format: markdown (human) or json (machine-readable for agents)"),
  },
  async ({ format }) => {
    const rules = getRules();
    const results = scanStaged(process.cwd(), format, rules);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 9: Generate compliance-focused security report
server.tool(
  "compliance_report",
  "Generate a compliance-focused security report mapped to SOC2, PCI-DSS, HIPAA, GDPR, or ISO27001 controls. Scans a directory and groups findings by compliance control. Includes exploit scenarios and audit evidence for each finding. Use mode=executive for a C-level summary.",
  {
    path: z.string().describe("Directory to scan"),
    framework: z.enum(["SOC2", "PCI-DSS", "HIPAA", "GDPR", "ISO27001", "all"]).describe("Compliance framework"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format: markdown (human) or json (machine-readable for agents)"),
    mode: z.enum(["full", "executive"]).default("full").describe("Report mode: full (detailed) or executive (C-level summary)"),
  },
  async ({ path, framework, format, mode }) => {
    const rules = getRules();
    const results = complianceReport(path, framework, format, rules, mode);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 10: Export scan results in SARIF v2.1.0 format
server.tool(
  "export_sarif",
  "Scan a directory and export results in SARIF v2.1.0 format for CI/CD integration (GitHub, GitLab, Azure DevOps). Returns JSON string.",
  {
    path: z.string().describe("Directory to scan"),
  },
  async ({ path }) => {
    const rules = getRules();
    const results = exportSarif(path, rules);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 11: Check package health and typosquat risk
server.tool(
  "check_package_health",
  "Check npm packages for typosquat risk, maintenance status, adoption metrics, and deprecation. Use this before adding new dependencies to catch suspicious or risky packages.",
  {
    packages: z.array(z.string()).describe("List of package names to check (e.g. ['lodash', 'expres', 'react-qeury'])"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format: markdown (human) or json (machine-readable for agents)"),
  },
  async ({ packages, format }) => {
    const results = await checkPackageHealth(packages, format);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 12: Auto-fix security vulnerabilities
server.tool(
  "fix_code",
  "Analyze code for security vulnerabilities and return fix suggestions with concrete patches. The AI agent can apply these patches to automatically fix issues. Returns structured fix data including before/after code, severity, and line numbers.",
  {
    code: z.string().describe("The code snippet to analyze and fix"),
    language: z
      .enum(["javascript", "typescript", "python", "go", "dockerfile", "html", "sql", "shell", "yaml", "terraform", "firestore"])
      .describe("Programming language of the code"),
    framework: z
      .string()
      .optional()
      .describe("Framework context (e.g. express, nextjs, fastapi, react, django)"),
    format: z.enum(["markdown", "json"]).default("json").describe("Output format: json (for agent auto-fix) or markdown (human review)"),
  },
  async ({ code, language, framework, format }) => {
    const rules = getRules();
    const results = fixCode(code, language, framework, undefined, format, rules);
    return {
      content: [{ type: "text", text: results }],
    };
  }
);

// Tool 13: Cross-file configuration security audit
server.tool(
  "audit_config",
  "Audit project configuration files (next.config, middleware/proxy, .env, vercel.json) together for cross-file security issues. Detects gaps that single-file scanning misses: missing security headers, unprotected routes, exposed secrets, middleware/route mismatches.",
  {
    path: z.string().describe("Project root directory to audit"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
  },
  async ({ path, format }) => {
    const results = auditConfig(path, format);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 14: Generate security policies based on detected stack
server.tool(
  "generate_policy",
  "Scan a project to detect its stack (Next.js, Supabase, Stripe, etc.) and generate tailored security policies: CSP headers, CORS config, Supabase RLS suggestions, rate limiting config, and security headers.",
  {
    path: z.string().describe("Project root directory to scan"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
  },
  async ({ path, format }) => {
    const results = generatePolicy(path, format);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 15: PR Security Review — diff-only scanning with annotations
server.tool(
  "review_pr",
  "Review a pull request for security issues. Scans only changed lines (diff-only mode) and produces output for GitHub Check Runs, PR comments, or inline annotations. Supports severity gating to block PRs.",
  {
    path: z.string().default(".").describe("Repository root path"),
    base: z.string().default("main").describe("Base branch to diff against"),
    format: z.enum(["markdown", "json", "annotations"]).default("markdown").describe("Output: markdown (PR comment), json (structured), annotations (GitHub Check Runs)"),
    diff_only: z.boolean().default(true).describe("Only report findings in changed lines (true) or all findings in changed files (false)"),
    fail_on: z.enum(["critical", "high", "medium", "low", "none"]).default("high").describe("Block PR if findings at this severity or above exist"),
  },
  async ({ path, base, format, diff_only, fail_on }) => {
    const rules = getRules();
    const results = reviewPr(path, base, format, diff_only, fail_on, rules);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 16: Git History Secret Scan
server.tool(
  "scan_secrets_history",
  "Scan git history for leaked secrets. Finds secrets that were committed in the past — even if they were later removed. Marks each finding as 'active' (still in code) or 'removed' (in git history only, needs rotation).",
  {
    path: z.string().describe("Repository root path"),
    max_commits: z.number().default(100).describe("Maximum number of commits to scan"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
  },
  async ({ path, max_commits, format }) => {
    const results = scanSecretsHistory(path, max_commits, format);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 17: Compliance Policy Check
server.tool(
  "policy_check",
  "Check project against compliance policies defined in .guardviberc. Supports custom frameworks, severity thresholds, required controls, and risk exceptions. Returns pass/fail with details.",
  {
    path: z.string().describe("Project root directory"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
  },
  async ({ path, format }) => {
    const rules = getRules();
    const results = policyCheck(path, format, rules);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 18: Taint/Dataflow Analysis
server.tool(
  "analyze_dataflow",
  "Track user input (request body, URL params, form data) flowing into dangerous sinks (SQL queries, eval, file operations, redirects). Detects injection vulnerabilities that regex rules miss by following variable assignments through code.",
  {
    code: z.string().describe("Code to analyze for tainted data flows"),
    language: z.enum(["javascript", "typescript"]).describe("Language (JS/TS only)"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
  },
  async ({ code, language, format }) => {
    const findings = analyzeTaint(code, language);
    if (findings.length === 0) {
      if (format === "json") return { content: [{ type: "text", text: JSON.stringify({ summary: { total: 0 }, findings: [] }) }] };
      return { content: [{ type: "text", text: "No tainted data flows detected." }] };
    }
    const results = formatTaintFindings(findings, format);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 19: Shell Command Risk Analyzer
server.tool(
  "check_command",
  "Analyze a shell command for security risks before execution. Returns allow/ask/deny verdict with blast radius, safer alternatives, and context-aware risk assessment. Detects: destructive ops, git history rewrites, secret exposure, data exfiltration, deploy triggers, privilege escalation, database drops.",
  {
    command: z.string().describe("Shell command to analyze"),
    cwd: z.string().default(".").describe("Current working directory"),
    branch: z.string().optional().describe("Current git branch (for branch-specific risk)"),
    format: z.enum(["markdown", "json"]).default("json").describe("Output format"),
  },
  async ({ command, cwd, branch, format }) => {
    const results = checkCommand(command, cwd, branch, format);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 20: Config Change Security Analyzer
server.tool(
  "scan_config_change",
  "Compare before/after versions of a config file to detect security downgrades: CORS relaxation, CSP weakening, HSTS removal, debug mode, cookie flag changes, TLS disabling, new hardcoded secrets, removed security headers.",
  {
    before: z.string().describe("Previous config file content"),
    after: z.string().describe("New config file content"),
    file_path: z.string().default("config").describe("Config file path for context"),
    format: z.enum(["markdown", "json"]).default("json").describe("Output format"),
  },
  async ({ before, after, file_path, format }) => {
    const results = scanConfigChange(before, after, file_path, format);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 21: Repository Security Posture
server.tool(
  "repo_security_posture",
  "Analyze a repository's overall security posture. Maps sensitive areas (auth, payments, PII, admin, API, infrastructure), identifies high-risk workflows, recommends guard mode, and lists priority fixes.",
  {
    path: z.string().describe("Repository root path"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
  },
  async ({ path, format }) => {
    const results = repoSecurityPosture(path, format);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 22: Explain Remediation
server.tool(
  "explain_remediation",
  "Deep explanation of a security finding: why it's risky, real-world impact, exploit scenario, minimum fix, secure alternative, breaking risk assessment, and test strategy. Helps agents apply fixes correctly.",
  {
    rule_id: z.string().describe("GuardVibe rule ID (e.g. VG001, VG402)"),
    code: z.string().optional().describe("Affected code snippet for context"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format"),
  },
  async ({ rule_id, code, format }) => {
    const rules = getRules();
    const results = explainRemediation(rule_id, code, format, rules);
    return { content: [{ type: "text", text: results }] };
  }
);

async function main() {
  // Load plugins
  const config = loadConfig(process.cwd());
  const plugins = await discoverPlugins(process.cwd(), config.plugins);

  if (plugins.loaded.length > 0) {
    console.error(`[guardvibe] Loaded ${plugins.loaded.length} plugin(s): ${plugins.loaded.join(", ")}`);
  }
  for (const err of plugins.errors) {
    console.error(`[guardvibe] Plugin warning: ${err}`);
  }

  // Merge rules: builtin + plugin
  const allRules: SecurityRule[] = [...builtinRules, ...plugins.rules];

  // Register plugin tools
  for (const tool of plugins.tools) {
    server.tool(
      tool.name,
      tool.description,
      tool.schema as any,
      async (input: any) => {
        try {
          const result = await tool.handler(input);
          return { content: [{ type: "text" as const, text: result }] };
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          return { content: [{ type: "text" as const, text: `Plugin error (${tool.name}): ${msg}` }] };
        }
      }
    );
  }

  // Store merged rules for tool handlers
  setRules(allRules);

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("GuardVibe Security MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
