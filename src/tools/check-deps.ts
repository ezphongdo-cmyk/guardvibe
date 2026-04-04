import { queryOsv, formatVulnerability } from "../utils/osv-client.js";

interface PackageInput {
  name: string;
  version: string;
  ecosystem: string;
}

export async function checkDependencies(
  packages: PackageInput[]
): Promise<string> {
  const results: string[] = [
    `# GuardVibe Dependency Security Report`,
    ``,
    `**Packages checked:** ${packages.length}`,
    `**Database:** OSV (Google Open Source Vulnerabilities)`,
    ``,
    `---`,
    ``,
  ];

  let totalVulns = 0;
  const criticalPackages: string[] = [];

  for (const pkg of packages) {
    try {
      const vulns = await queryOsv(pkg.name, pkg.version, pkg.ecosystem);

      if (vulns.length === 0) {
        results.push(`## ${pkg.name}@${pkg.version} (${pkg.ecosystem})`);
        results.push(`No known vulnerabilities found.`);
        results.push(``);
      } else {
        totalVulns += vulns.length;
        criticalPackages.push(`${pkg.name}@${pkg.version}`);

        results.push(
          `## ${pkg.name}@${pkg.version} (${pkg.ecosystem}) - ${vulns.length} vulnerabilities found`
        );
        results.push(``);

        for (const vuln of vulns) {
          results.push(formatVulnerability(vuln));
          results.push(``);
        }
      }
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown error";
      results.push(`## ${pkg.name}@${pkg.version} (${pkg.ecosystem})`);
      results.push(`Error checking package: ${message}`);
      results.push(``);
    }
  }

  // Summary
  results.push(`---`);
  results.push(``);
  results.push(`## Summary`);

  if (totalVulns === 0) {
    results.push(
      `All ${packages.length} packages are clean. No known vulnerabilities found.`
    );
  } else {
    results.push(
      `**${totalVulns} vulnerabilities** found in ${criticalPackages.length} packages:`
    );
    for (const pkg of criticalPackages) {
      results.push(`- ${pkg}`);
    }
    results.push(``);
    results.push(
      `**Action:** Update affected packages to their fixed versions.`
    );
  }

  return results.join("\n");
}
