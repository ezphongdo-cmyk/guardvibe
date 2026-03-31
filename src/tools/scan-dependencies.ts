import { readFileSync } from "fs";
import { basename } from "path";
import { parseManifest } from "../utils/manifest-parser.js";
import { queryOsvBatch, formatVulnerability, normalizeSeverity } from "../utils/osv-client.js";

export async function scanDependencies(manifestPath: string, format: "markdown" | "json" = "markdown"): Promise<string> {
  let content: string;
  try {
    content = readFileSync(manifestPath, "utf-8");
  } catch {
    return `# GuardVibe Dependency Report\n\nError: Could not read file: ${manifestPath}`;
  }

  const filename = basename(manifestPath);
  let packages;
  try {
    packages = parseManifest(content, filename);
  } catch (e) {
    const msg = e instanceof Error ? e.message : "Unknown error";
    return `# GuardVibe Dependency Report\n\nError: ${msg}`;
  }

  if (packages.length === 0) {
    return `# GuardVibe Dependency Report\n\nFile: ${manifestPath}\nPackages found: 0\n\nNo packages to check.`;
  }

  const lines: string[] = [
    `# GuardVibe Dependency Report`,
    ``,
    `File: ${manifestPath}`,
    `Packages checked: ${packages.length}`,
    `Database: OSV (Google Open Source Vulnerabilities)`,
    ``,
    `---`,
    ``,
  ];

  let vulnResults: Map<string, any[]>;
  try {
    vulnResults = await queryOsvBatch(packages);
  } catch {
    lines.push(`Error: Could not reach OSV API. Check your network connection.`);
    return lines.join("\n");
  }

  let totalVulns = 0;
  const criticalPackages: string[] = [];

  // Build per-package vulnerability data
  const pkgResults: Array<{ name: string; version: string; ecosystem: string; vulnerabilities: any[] }> = [];

  for (const pkg of packages) {
    const key = `${pkg.name}@${pkg.version}`;
    const vulns = vulnResults.get(key) || [];

    if (vulns.length === 0) continue;

    totalVulns += vulns.length;
    criticalPackages.push(key);
    pkgResults.push({
      name: pkg.name, version: pkg.version, ecosystem: pkg.ecosystem,
      vulnerabilities: vulns.map(v => ({
        id: v.id, severity: normalizeSeverity(v), summary: v.summary,
        fixedIn: (v.affected ?? []).flatMap((a: any) => (a.ranges ?? []).flatMap((r: any) => r.events.filter((e: any) => e.fixed).map((e: any) => e.fixed))).join(", ") || undefined,
        url: v.references?.[0]?.url,
      })),
    });

    lines.push(`## ${key} (${pkg.ecosystem}) — ${vulns.length} vulnerabilities`, ``);
    for (const vuln of vulns) {
      lines.push(formatVulnerability(vuln), ``);
    }
  }

  if (format === "json") {
    const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const pr of pkgResults) {
      for (const v of pr.vulnerabilities) {
        if (v.severity in sevCounts) sevCounts[v.severity as keyof typeof sevCounts]++;
      }
    }
    return JSON.stringify({
      summary: { total: packages.length, vulnerable: criticalPackages.length, ...sevCounts },
      packages: pkgResults,
    });
  }

  lines.push(`---`, ``, `## Summary`, ``);

  if (totalVulns === 0) {
    lines.push(`All ${packages.length} packages are clean. No known vulnerabilities found.`);
  } else {
    lines.push(`**${totalVulns} vulnerabilities** found in ${criticalPackages.length} packages:`, ``);
    for (const pkg of criticalPackages) lines.push(`- ${pkg}`);
    lines.push(``, `**Action:** Update affected packages to their fixed versions.`);
  }

  return lines.join("\n");
}
