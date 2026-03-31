import { readdirSync, readFileSync, statSync } from "fs";
import { join, extname, basename, resolve } from "path";
import { analyzeCode, type Finding } from "./check-code.js";
import { owaspRules } from "../data/rules/index.js";
import { loadConfig } from "../utils/config.js";
import type { SecurityRule } from "../data/rules/types.js";

const EXTENSION_MAP: Record<string, string> = {
  ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
  ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
  ".py": "python", ".go": "go", ".html": "html",
  ".sql": "sql", ".sh": "shell", ".bash": "shell",
  ".yml": "yaml", ".yaml": "yaml", ".tf": "terraform", ".json": "json",
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
      if (EXTENSION_MAP[ext] || entry.name.startsWith("Dockerfile")) {
        results.push(fullPath);
      }
    }
  }
}

interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note";
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: { startLine: number };
    };
  }>;
}

function severityToLevel(severity: string): "error" | "warning" | "note" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

export function exportSarif(path: string, rules?: SecurityRule[]): string {
  const scanRoot = resolve(path);
  const config = loadConfig(scanRoot);
  const excludes = new Set([...DEFAULT_EXCLUDES, ...config.scan.exclude]);
  const filePaths: string[] = [];
  walkDir(scanRoot, excludes, filePaths);

  const allResults: SarifResult[] = [];

  for (const filePath of filePaths) {
    try {
      const stat = statSync(filePath);
      if (stat.size > config.scan.maxFileSize) continue;
      const content = readFileSync(filePath, "utf-8");
      const ext = extname(filePath).toLowerCase();
      let language = EXTENSION_MAP[ext];
      if (!language && basename(filePath).startsWith("Dockerfile")) language = "dockerfile";
      if (!language) continue;

      const findings = analyzeCode(content, language, undefined, filePath, scanRoot, rules);

      for (const f of findings) {
        allResults.push({
          ruleId: f.rule.id,
          level: severityToLevel(f.rule.severity),
          message: {
            text: `${f.rule.name}: ${f.rule.description} Fix: ${f.rule.fix}`,
          },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: filePath },
              region: { startLine: f.line },
            },
          }],
        });
      }
    } catch { /* skip */ }
  }

  // Build SARIF rules from all known rules (deduped by what was found)
  const foundRuleIds = new Set(allResults.map(r => r.ruleId));
  const sarifRules = owaspRules
    .filter(r => foundRuleIds.has(r.id))
    .map(r => ({
      id: r.id,
      name: r.name,
      shortDescription: { text: r.name },
      fullDescription: { text: r.description },
      helpUri: `https://guardvibe.dev`,
      properties: {
        tags: [r.owasp],
        ...(r.compliance ? { compliance: r.compliance } : {}),
      },
    }));

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "GuardVibe",
          version: "0.10.0",
          informationUri: "https://guardvibe.dev",
          rules: sarifRules,
        },
      },
      results: allResults,
    }],
  };

  return JSON.stringify(sarif, null, 2);
}
