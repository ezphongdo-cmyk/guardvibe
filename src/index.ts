#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { checkCode } from "./tools/check-code.js";
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
import { discoverPlugins } from "./plugins/loader.js";
import { builtinRules } from "./data/rules/index.js";
import type { SecurityRule } from "./data/rules/types.js";
import { loadConfig } from "./utils/config.js";

const server = new McpServer({
  name: "guardvibe",
  version: "1.3.2",
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
    const rules = (globalThis as any).__guardvibe_rules as SecurityRule[] | undefined;
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
    const rules = (globalThis as any).__guardvibe_rules as SecurityRule[] | undefined;
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
  "Scan an entire project directory for security vulnerabilities. Reads files directly from the filesystem — no need to pass file contents. Returns a security score (A-F) and detailed findings.",
  {
    path: z.string().describe("Directory path to scan (e.g. './src', '.')"),
    recursive: z.boolean().optional().default(true).describe("Scan subdirectories"),
    exclude: z.array(z.string()).optional().default([]).describe("Additional directories to exclude"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format: markdown (human) or json (machine-readable for agents)"),
  },
  async ({ path, recursive, exclude, format }) => {
    const rules = (globalThis as any).__guardvibe_rules as SecurityRule[] | undefined;
    const results = scanDirectory(path, recursive, exclude, format, rules);
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
    const rules = (globalThis as any).__guardvibe_rules as SecurityRule[] | undefined;
    const results = scanStaged(process.cwd(), format, rules);
    return { content: [{ type: "text", text: results }] };
  }
);

// Tool 9: Generate compliance-focused security report
server.tool(
  "compliance_report",
  "Generate a compliance-focused security report mapped to SOC2, PCI-DSS, or HIPAA controls. Scans a directory and groups findings by compliance control.",
  {
    path: z.string().describe("Directory to scan"),
    framework: z.enum(["SOC2", "PCI-DSS", "HIPAA", "all"]).describe("Compliance framework"),
    format: z.enum(["markdown", "json"]).default("markdown").describe("Output format: markdown (human) or json (machine-readable for agents)"),
  },
  async ({ path, framework, format }) => {
    const rules = (globalThis as any).__guardvibe_rules as SecurityRule[] | undefined;
    const results = complianceReport(path, framework, format, rules);
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
    const rules = (globalThis as any).__guardvibe_rules as SecurityRule[] | undefined;
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
    const rules = (globalThis as any).__guardvibe_rules as SecurityRule[] | undefined;
    const results = fixCode(code, language, framework, undefined, format, rules);
    return {
      content: [{ type: "text", text: results }],
    };
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
        const result = await tool.handler(input);
        return { content: [{ type: "text" as const, text: result }] };
      }
    );
  }

  // Store merged rules for tool handlers
  (globalThis as any).__guardvibe_rules = allRules;

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("GuardVibe Security MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
