import { readdirSync, readFileSync, statSync } from "fs";
import { join, extname, basename, resolve } from "path";
import { analyzeCode, type Finding } from "./check-code.js";
import { loadConfig, type CompliancePolicy, type PolicyException } from "../utils/config.js";
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
  "next.config.js": "nextjs-config", "next.config.mjs": "nextjs-config", "next.config.ts": "nextjs-config",
  "docker-compose.yml": "docker-compose", "docker-compose.yaml": "docker-compose",
};

const DEFAULT_EXCLUDES = new Set([
  "node_modules", ".git", "build", "dist", "vendor", "__pycache__",
  ".next", ".nuxt", "coverage", ".turbo",
]);

interface PolicyFinding {
  rule: SecurityRule;
  match: string;
  line: number;
  filePath: string;
  controls: string[];
  excepted: boolean;
  exceptionReason?: string;
}

interface PolicyResult {
  pass: boolean;
  findings: PolicyFinding[];
  exceptions: PolicyFinding[];
  summary: {
    total: number;
    excepted: number;
    blocking: number;
    frameworks: string[];
    failOn: string;
    requiredControlsStatus: Record<string, "pass" | "fail">;
  };
}

function walkDir(dir: string, excludes: Set<string>, results: string[]): void {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    if (excludes.has(entry.name)) continue;
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) walkDir(fullPath, excludes, results);
    else if (entry.isFile()) {
      const ext = extname(entry.name).toLowerCase();
      if (EXTENSION_MAP[ext] || entry.name.startsWith("Dockerfile") || CONFIG_FILE_MAP[entry.name]) {
        results.push(fullPath);
      }
    }
  }
}

function isExcepted(ruleId: string, filePath: string, exceptions: PolicyException[]): PolicyException | null {
  for (const exc of exceptions) {
    if (exc.ruleId !== ruleId && exc.ruleId !== "*") continue;

    // Check expiration
    if (exc.expiresAt) {
      const expiry = new Date(exc.expiresAt);
      if (expiry < new Date()) continue; // expired
    }

    // Check file scope
    if (exc.files && exc.files.length > 0) {
      const matches = exc.files.some(pattern => {
        if (pattern.includes("*")) {
          const regex = new RegExp(pattern.replace(/\*/g, ".*"));
          return regex.test(filePath);
        }
        return filePath.includes(pattern);
      });
      if (!matches) continue;
    }

    return exc;
  }
  return null;
}

function getControlsForRule(rule: SecurityRule, frameworks: string[]): string[] {
  if (!rule.compliance) return [];
  return rule.compliance.filter(c => {
    const prefix = c.split(":")[0].toUpperCase();
    return frameworks.some(f => f.toUpperCase() === prefix || f.toUpperCase() === "ALL");
  });
}

export function policyCheck(
  path: string,
  format: "markdown" | "json" = "markdown",
  rules?: SecurityRule[]
): string {
  const scanRoot = resolve(path);
  const config = loadConfig(scanRoot);
  const policy = config.compliance;

  if (!policy) {
    const msg = "No compliance policy defined. Add a `compliance` section to .guardviberc.";
    if (format === "json") return JSON.stringify({ error: msg });
    return `# GuardVibe Policy Check\n\n${msg}\n\nExample:\n\`\`\`json\n{\n  "compliance": {\n    "frameworks": ["SOC2", "GDPR"],\n    "failOn": "high",\n    "exceptions": [],\n    "requiredControls": ["SOC2:CC6.1"]\n  }\n}\n\`\`\``;
  }

  const excludes = new Set([...DEFAULT_EXCLUDES, ...config.scan.exclude]);
  const filePaths: string[] = [];
  walkDir(scanRoot, excludes, filePaths);

  const policyFindings: PolicyFinding[] = [];
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const failLevel = severityOrder[policy.failOn] ?? 1;

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
        const controls = getControlsForRule(f.rule, policy.frameworks);
        if (controls.length === 0) continue;

        const exception = isExcepted(f.rule.id, filePath, policy.exceptions);
        policyFindings.push({
          rule: f.rule, match: f.match, line: f.line, filePath,
          controls,
          excepted: !!exception,
          exceptionReason: exception?.reason,
        });
      }
    } catch { /* skip */ }
  }

  const activeFindings = policyFindings.filter(f => !f.excepted);
  const exceptedFindings = policyFindings.filter(f => f.excepted);
  const blockingFindings = activeFindings.filter(f => (severityOrder[f.rule.severity] ?? 4) <= failLevel);

  // Required controls check
  const controlStatus: Record<string, "pass" | "fail"> = {};
  if (policy.requiredControls) {
    for (const ctrl of policy.requiredControls) {
      const violations = activeFindings.filter(f => f.controls.includes(ctrl));
      controlStatus[ctrl] = violations.length === 0 ? "pass" : "fail";
    }
  }

  const pass = blockingFindings.length === 0 && !Object.values(controlStatus).includes("fail");

  const result: PolicyResult = {
    pass,
    findings: activeFindings,
    exceptions: exceptedFindings,
    summary: {
      total: policyFindings.length,
      excepted: exceptedFindings.length,
      blocking: blockingFindings.length,
      frameworks: policy.frameworks,
      failOn: policy.failOn,
      requiredControlsStatus: controlStatus,
    },
  };

  if (format === "json") {
    return JSON.stringify({
      pass: result.pass,
      summary: result.summary,
      findings: result.findings.map(f => ({
        id: f.rule.id, name: f.rule.name, severity: f.rule.severity,
        file: f.filePath, line: f.line, controls: f.controls,
        fix: f.rule.fix,
      })),
      exceptions: result.exceptions.map(f => ({
        id: f.rule.id, name: f.rule.name, severity: f.rule.severity,
        file: f.filePath, line: f.line, reason: f.exceptionReason,
      })),
    });
  }

  // Markdown
  const lines: string[] = [
    `# GuardVibe Policy Check`,
    ``,
    `**Result:** ${pass ? "PASS" : "FAIL"}`,
    `**Frameworks:** ${policy.frameworks.join(", ")}`,
    `**Fail threshold:** ${policy.failOn}`,
    `**Directory:** ${scanRoot}`,
    ``,
    `| Metric | Count |`,
    `|--------|-------|`,
    `| Total compliance findings | ${policyFindings.length} |`,
    `| Excepted (accepted risk) | ${exceptedFindings.length} |`,
    `| Blocking (above threshold) | ${blockingFindings.length} |`,
    ``,
  ];

  // Required controls
  if (Object.keys(controlStatus).length > 0) {
    lines.push(`## Required Controls`, ``, `| Control | Status |`, `|---------|--------|`);
    for (const [ctrl, status] of Object.entries(controlStatus)) {
      lines.push(`| ${ctrl} | ${status === "pass" ? "PASS" : "**FAIL**"} |`);
    }
    lines.push(``);
  }

  // Blocking findings
  if (blockingFindings.length > 0) {
    lines.push(`## Blocking Findings`, ``);
    for (const f of blockingFindings) {
      lines.push(
        `- **[${f.rule.severity.toUpperCase()}]** ${f.rule.name} (${f.rule.id}) in \`${f.filePath}\`:${f.line}`,
        `  Controls: ${f.controls.join(", ")} | Fix: ${f.rule.fix}`,
        ``,
      );
    }
  }

  // Exceptions
  if (exceptedFindings.length > 0) {
    lines.push(`## Accepted Exceptions`, ``);
    for (const f of exceptedFindings) {
      lines.push(
        `- ~~${f.rule.name} (${f.rule.id})~~ in \`${f.filePath}\`:${f.line} — *${f.exceptionReason}*`,
      );
    }
    lines.push(``);
  }

  if (pass && blockingFindings.length === 0) {
    lines.push(`All compliance checks passed.`);
  }

  return lines.join("\n");
}
