import { owaspRules, type SecurityRule } from "../data/rules/index.js";
import { analyzeCode, type Finding } from "./check-code.js";

export interface FixSuggestion {
  ruleId: string;
  ruleName: string;
  severity: string;
  line: number;
  match: string;
  description: string;
  fix: string;
  fixCode?: string;
  patch?: string; // line-level replacement suggestion
}

/**
 * Analyze code and return structured fix suggestions that an AI agent can apply.
 */
export function fixCode(
  code: string,
  language: string,
  framework?: string,
  filePath?: string,
  format: "markdown" | "json" = "json",
  rules?: SecurityRule[]
): string {
  const effectiveRules = rules ?? owaspRules;
  const findings = analyzeCode(code, language, framework, filePath, undefined, effectiveRules);

  if (findings.length === 0) {
    if (format === "json") {
      return JSON.stringify({ status: "clean", fixes: [] });
    }
    return "# GuardVibe Auto-Fix\n\n**Status:** No security issues found. Code is clean!";
  }

  const suggestions = generateFixSuggestions(findings, code);

  if (format === "json") {
    return JSON.stringify({
      status: "issues_found",
      total: suggestions.length,
      fixes: suggestions,
    });
  }

  return formatFixMarkdown(suggestions);
}

function generateFixSuggestions(findings: Finding[], code: string): FixSuggestion[] {
  const lines = code.split("\n");
  const seen = new Set<string>();
  const suggestions: FixSuggestion[] = [];

  for (const finding of findings) {
    // Deduplicate by rule+line
    const key = `${finding.rule.id}:${finding.line}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const sourceLine = lines[finding.line - 1] || "";
    const patch = generatePatch(finding, sourceLine);

    suggestions.push({
      ruleId: finding.rule.id,
      ruleName: finding.rule.name,
      severity: finding.rule.severity,
      line: finding.line,
      match: finding.match,
      description: finding.rule.description,
      fix: finding.rule.fix,
      fixCode: finding.rule.fixCode,
      patch,
    });
  }

  // Sort by severity (critical first)
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  suggestions.sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4));

  return suggestions;
}

/**
 * Generate a concrete patch suggestion for the matched line.
 * Returns a before/after replacement when possible.
 */
function generatePatch(finding: Finding, sourceLine: string): string | undefined {
  const { rule } = finding;

  switch (rule.id) {
    // Hardcoded credentials -> env var
    case "VG001":
    case "VG062": {
      const match = /(\w+)\s*[:=]\s*['"][^'"]+['"]/.exec(sourceLine);
      if (match) {
        const varName = match[1];
        const envName = varName.replace(/([a-z])([A-Z])/g, "$1_$2").toUpperCase();
        return `// Before:\n${sourceLine.trim()}\n// After:\nconst ${varName} = process.env.${envName};`;
      }
      break;
    }

    // innerHTML -> textContent
    case "VG012":
    case "VG408": {
      if (sourceLine.includes("innerHTML")) {
        return `// Before:\n${sourceLine.trim()}\n// After:\n${sourceLine.trim().replace("innerHTML", "textContent")}`;
      }
      if (sourceLine.includes("dangerouslySetInnerHTML")) {
        return '// Replace dangerouslySetInnerHTML with a sanitizer:\nimport DOMPurify from "dompurify";\n// Use: <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }} />';
      }
      break;
    }

    // SQL injection -> parameterized
    case "VG010": {
      return "// Replace template literal interpolation with parameterized query:\n// Before: query(`SELECT * FROM users WHERE id = ${id}`)\n// After:  query('SELECT * FROM users WHERE id = $1', [id])";
    }

    // Missing auth -> add auth check
    case "VG002":
    case "VG420":
    case "VG952": {
      return '// Add authentication check at the start:\nconst { userId } = await auth();\nif (!userId) return new Response("Unauthorized", { status: 401 });';
    }

    // Mass assignment -> explicit fields
    case "VG953": {
      return "// Replace spread with explicit field selection:\n// Before: data: { ...req.body }\n// After:  const { field1, field2 } = schema.parse(req.body);\n//         data: { field1, field2 }";
    }

    // CORS wildcard -> specific origin
    case "VG040":
    case "VG403": {
      return '// Replace wildcard with specific origin:\n// Before: "Access-Control-Allow-Origin": "*"\n// After:  "Access-Control-Allow-Origin": process.env.ALLOWED_ORIGIN';
    }

    // Error leak -> generic message
    case "VG959": {
      return '// Replace error details with generic message:\ncatch (error) {\n  console.error("Internal error:", error);\n  return Response.json({ error: "Something went wrong" }, { status: 500 });\n}';
    }

    // BOLA -> add ownership check
    case "VG950":
    case "VG951": {
      return "// Add ownership check to the query:\n// Before: where: { id: params.id }\n// After:  where: { id: params.id, userId }";
    }

    default:
      break;
  }

  // Fallback: no specific patch
  return undefined;
}

function formatFixMarkdown(suggestions: FixSuggestion[]): string {
  const lines = [
    "# GuardVibe Auto-Fix Suggestions",
    "",
    `**Issues found:** ${suggestions.length}`,
    "",
    "Apply these fixes to resolve security vulnerabilities:",
    "",
    "---",
    "",
  ];

  for (let i = 0; i < suggestions.length; i++) {
    const s = suggestions[i];
    const severity = s.severity.toUpperCase();

    lines.push(
      `## Fix ${i + 1}: ${s.ruleName} (${s.ruleId})`,
      "",
      `**Severity:** ${severity}`,
      `**Line:** ${s.line}`,
      `**Match:** \`${s.match}\``,
      "",
      s.description,
      "",
      `**How to fix:** ${s.fix}`,
      "",
    );

    if (s.patch) {
      lines.push("**Suggested patch:**", "```", s.patch, "```", "");
    }

    if (s.fixCode) {
      lines.push("**Reference secure code:**", "```", s.fixCode, "```", "");
    }

    lines.push("---", "");
  }

  return lines.join("\n");
}
