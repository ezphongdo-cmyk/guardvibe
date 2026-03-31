import { detectTyposquat } from "../utils/typosquat.js";

interface RegistryData {
  exists: boolean;
  downloads: number;
  lastPublish: string;
  maintainers: number;
  deprecated: boolean;
}

interface HealthFlag {
  type: "typosquat" | "deprecated" | "unmaintained" | "low_adoption" | "single_maintainer" | "new_package";
  message: string;
  confidence?: number;
}

export interface PackageHealthResult {
  name: string;
  exists: boolean;
  risk: "critical" | "high" | "medium" | "low";
  flags: HealthFlag[];
  registry?: {
    downloads: number;
    lastPublish: string;
    maintainers: number;
    deprecated: boolean;
  };
  similarTo?: string;
}

export function assessPackageRisk(name: string, data: RegistryData): PackageHealthResult {
  const flags: HealthFlag[] = [];
  let similarTo: string | undefined;

  if (!data.exists) {
    return {
      name, exists: false, risk: "critical",
      flags: [{ type: "typosquat", message: `Package "${name}" does not exist on npm. Possible typosquat or misspelling.` }],
    };
  }

  // Typosquat check
  const typo = detectTyposquat(name);
  if (typo) {
    flags.push({
      type: "typosquat",
      message: `Suspicious similarity to "${typo.similarTo}" (popular package). Possible typosquat.`,
      confidence: typo.confidence,
    });
    similarTo = typo.similarTo;
  }

  // Deprecated
  if (data.deprecated) {
    flags.push({ type: "deprecated", message: "Package is marked as deprecated." });
  }

  // Unmaintained: last publish > 2 years ago
  if (data.lastPublish) {
    const lastPub = new Date(data.lastPublish);
    const twoYearsAgo = new Date();
    twoYearsAgo.setFullYear(twoYearsAgo.getFullYear() - 2);
    if (lastPub < twoYearsAgo) {
      flags.push({ type: "unmaintained", message: `Last published ${lastPub.toISOString().split("T")[0]} (over 2 years ago).` });
    }

    // New package: < 30 days old with low downloads
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    if (lastPub > thirtyDaysAgo && data.downloads < 100) {
      flags.push({ type: "new_package", message: "New package (published within 30 days) with low downloads." });
    }
  }

  // Low adoption
  if (data.downloads < 100) {
    flags.push({ type: "low_adoption", message: `Very low weekly downloads (${data.downloads}).` });
  }

  // Single maintainer + low downloads
  if (data.maintainers === 1 && data.downloads < 100) {
    flags.push({ type: "single_maintainer", message: "Only 1 maintainer with low adoption." });
  }

  // Determine risk level
  let risk: "critical" | "high" | "medium" | "low" = "low";
  if (flags.some(f => f.type === "typosquat")) {
    risk = "critical";
  } else if (flags.some(f => f.type === "deprecated" || f.type === "unmaintained") ||
             (flags.some(f => f.type === "single_maintainer") && data.downloads < 100)) {
    risk = "high";
  } else if (flags.some(f => f.type === "low_adoption" || f.type === "new_package")) {
    risk = "medium";
  }

  return {
    name, exists: true, risk, flags,
    registry: {
      downloads: data.downloads,
      lastPublish: data.lastPublish,
      maintainers: data.maintainers,
      deprecated: data.deprecated,
    },
    similarTo,
  };
}

async function fetchRegistryData(name: string): Promise<RegistryData> {
  try {
    const [metaRes, downloadsRes] = await Promise.all([
      fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`, { signal: AbortSignal.timeout(5000) }),
      fetch(`https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(name)}`, { signal: AbortSignal.timeout(5000) }),
    ]);

    if (metaRes.status === 404) {
      return { exists: false, downloads: 0, lastPublish: "", maintainers: 0, deprecated: false };
    }

    if (!metaRes.ok) {
      throw new Error(`npm registry error: ${metaRes.status}`);
    }

    const meta = await metaRes.json() as any;
    const latestVersion = meta["dist-tags"]?.latest;
    const lastPublish = meta.time?.modified ?? meta.time?.[latestVersion] ?? "";
    const maintainers = meta.maintainers?.length ?? 0;
    const deprecated = !!meta.versions?.[latestVersion]?.deprecated;

    let downloads = 0;
    if (downloadsRes.ok) {
      const dlData = await downloadsRes.json() as any;
      downloads = dlData.downloads ?? 0;
    }

    return { exists: true, downloads, lastPublish, maintainers, deprecated };
  } catch {
    return { exists: false, downloads: 0, lastPublish: "", maintainers: 0, deprecated: false };
  }
}

export async function checkPackageHealth(
  packages: string[],
  format: "markdown" | "json" = "markdown"
): Promise<string> {
  const results: PackageHealthResult[] = [];

  for (const name of packages) {
    const data = await fetchRegistryData(name);
    results.push(assessPackageRisk(name, data));
  }

  if (format === "json") {
    return JSON.stringify({ packages: results });
  }

  // Markdown output
  const lines: string[] = [
    "# GuardVibe Package Health Report",
    "",
    `Packages checked: ${packages.length}`,
    "",
  ];

  const riskyPackages = results.filter(r => r.risk !== "low");
  if (riskyPackages.length === 0) {
    lines.push("All packages look healthy. No issues detected.");
    return lines.join("\n");
  }

  lines.push(`Issues found in ${riskyPackages.length} package(s):`, "", "---", "");

  for (const result of results) {
    if (result.flags.length === 0) continue;

    lines.push(`## ${result.name} — Risk: ${result.risk.toUpperCase()}`, "");
    if (!result.exists) {
      lines.push("**Package does not exist on npm.**", "");
      continue;
    }
    if (result.registry) {
      lines.push(
        `- Weekly downloads: ${result.registry.downloads.toLocaleString()}`,
        `- Last published: ${result.registry.lastPublish.split("T")[0]}`,
        `- Maintainers: ${result.registry.maintainers}`,
        `- Deprecated: ${result.registry.deprecated ? "Yes" : "No"}`,
        "",
      );
    }
    for (const flag of result.flags) {
      lines.push(`- **[${flag.type.toUpperCase()}]** ${flag.message}`);
    }
    if (result.similarTo) {
      lines.push(`- Did you mean **${result.similarTo}**?`);
    }
    lines.push("", "---", "");
  }

  return lines.join("\n");
}
