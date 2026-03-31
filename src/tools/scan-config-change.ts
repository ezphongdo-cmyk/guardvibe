// guardvibe-ignore — config change analyzer contains security pattern descriptions
/**
 * Config change analyzer — compares before/after config to detect security downgrades.
 */

export interface ConfigChangeFinding {
  severity: "critical" | "high" | "medium" | "low";
  category: string;
  title: string;
  description: string;
  recommendation: string;
}

const DOWNGRADE_CHECKS: Array<{
  pattern: RegExp; category: string; title: string;
  severity: "critical" | "high" | "medium" | "low";
  check: (before: string, after: string) => boolean;
  description: string; recommendation: string;
}> = [
  { pattern: /Access-Control-Allow-Origin/i, category: "cors", title: "CORS relaxed to wildcard",
    severity: "high", check: (_b, a) => /Access-Control-Allow-Origin.*\*/.test(a),
    description: "CORS set to wildcard — any website can make requests.", recommendation: "Use specific origins." },

  { pattern: /Content-Security-Policy/i, category: "csp", title: "CSP weakened",
    severity: "high", check: (b, a) => (/Content-Security-Policy/.test(b) && !/Content-Security-Policy/.test(a)) ||
      (/unsafe-inline/.test(a) && !/unsafe-inline/.test(b)) || (/unsafe-eval/.test(a) && !/unsafe-eval/.test(b)),
    description: "CSP removed or unsafe directives added.", recommendation: "Keep strict CSP. Use nonces." },

  { pattern: /Strict-Transport-Security/i, category: "headers", title: "HSTS removed",
    severity: "high", check: (b, a) => /Strict-Transport-Security/.test(b) && !/Strict-Transport-Security/.test(a),
    description: "HSTS removed — browsers may use HTTP.", recommendation: "Restore HSTS header." },

  { pattern: /debug|DEBUG/, category: "debug", title: "Debug mode enabled",
    severity: "medium", check: (_b, a) => /debug\s*[:=]\s*true|DEBUG\s*[:=]\s*(?:true|1|"1")/i.test(a),
    description: "Debug mode exposes errors and internal info.", recommendation: "Disable for production." },

  { pattern: /secure|httpOnly|sameSite/i, category: "cookies", title: "Cookie security downgraded",
    severity: "high", check: (b, a) =>
      (/secure\s*:\s*true/.test(b) && /secure\s*:\s*false/.test(a)) ||
      (/httpOnly\s*:\s*true/.test(b) && /httpOnly\s*:\s*false/.test(a)) ||
      (/sameSite.*(?:strict|lax)/i.test(b) && /sameSite.*none/i.test(a)),
    description: "Cookie flags weakened — session hijacking or CSRF risk.", recommendation: "Set secure: true, httpOnly: true, sameSite: 'lax'." },

  { pattern: /force_https|rejectUnauthorized|NODE_TLS/i, category: "tls", title: "TLS weakened",
    severity: "critical", check: (_b, a) =>
      /force_https\s*=\s*false/.test(a) || /rejectUnauthorized\s*:\s*false/.test(a) || /NODE_TLS_REJECT_UNAUTHORIZED.*0/.test(a),
    description: "TLS verification disabled or HTTPS not enforced.", recommendation: "Never disable TLS verification." },

  { pattern: /productionBrowserSourceMaps|devtool/i, category: "config", title: "Source maps enabled",
    severity: "medium", check: (_b, a) => /productionBrowserSourceMaps\s*:\s*true/.test(a),
    description: "Source maps expose original code in production.", recommendation: "Set to false." },

  { pattern: /poweredByHeader/i, category: "config", title: "Framework version exposed",
    severity: "low", check: (b, a) => /poweredByHeader\s*:\s*false/.test(b) && /poweredByHeader\s*:\s*true/.test(a),
    description: "X-Powered-By re-enabled.", recommendation: "Set poweredByHeader: false." },

  { pattern: /remotePatterns/i, category: "config", title: "Image wildcard added",
    severity: "high", check: (_b, a) => /hostname\s*:\s*["'](?:\*\*|\*)["']/.test(a),
    description: "Wildcard image hostname enables SSRF.", recommendation: "Use specific hostnames." },

  { pattern: /privileged/i, category: "docker", title: "Privileged mode enabled",
    severity: "critical", check: (_b, a) => /privileged\s*:\s*true/.test(a),
    description: "Container has full host access.", recommendation: "Remove privileged: true." },

  { pattern: /0\.0\.0\.0/, category: "network", title: "Bound to all interfaces",
    severity: "medium", check: (b, a) => !b.includes("0.0.0.0") && a.includes("0.0.0.0"),
    description: "Service exposed on all network interfaces.", recommendation: "Bind to 127.0.0.1." },
];

export function scanConfigChange(
  before: string, after: string, filePath: string = "config",
  format: "markdown" | "json" = "json"
): string {
  const findings: ConfigChangeFinding[] = [];

  for (const rule of DOWNGRADE_CHECKS) {
    if (!rule.pattern.test(before) && !rule.pattern.test(after)) continue;
    if (rule.check(before, after)) {
      findings.push({ severity: rule.severity, category: rule.category, title: rule.title,
        description: rule.description, recommendation: rule.recommendation });
    }
  }

  // Removed security headers
  for (const h of ["X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]) {
    if (before.includes(h) && !after.includes(h)) {
      findings.push({ severity: "medium", category: "headers", title: `${h} removed`,
        description: `${h} was removed from config.`, recommendation: `Restore ${h}.` });
    }
  }

  // New secrets
  const secretRe = /(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL)\w*\s*[:=]\s*["']?([A-Za-z0-9_\-]{12,})/gi;
  const prevSecrets = new Set([...before.matchAll(secretRe)].map(m => m[1]));
  for (const m of after.matchAll(secretRe)) {
    if (!prevSecrets.has(m[1])) {
      findings.push({ severity: "critical", category: "secrets", title: "New secret hardcoded",
        description: "A new secret value added to config file.", recommendation: "Use environment variables." });
    }
  }

  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => (order[a.severity] ?? 4) - (order[b.severity] ?? 4));

  if (format === "json") {
    return JSON.stringify({
      summary: { total: findings.length, critical: findings.filter(f => f.severity === "critical").length,
        high: findings.filter(f => f.severity === "high").length, file: filePath, downgradeDetected: findings.length > 0 },
      findings,
    });
  }

  const lines = [`## GuardVibe Config Change Analysis`, ``, `**File:** ${filePath}`, `**Downgrades:** ${findings.length}`, ``];
  if (findings.length === 0) { lines.push("No security downgrades detected."); return lines.join("\n"); }
  for (const f of findings) {
    lines.push(`### [${f.severity.toUpperCase()}] ${f.title}`, f.description, `**Fix:** ${f.recommendation}`, ``);
  }
  return lines.join("\n");
}
