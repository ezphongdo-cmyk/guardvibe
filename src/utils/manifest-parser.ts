export interface ParsedPackage {
  name: string;
  version: string;
  ecosystem: string;
}

type PackageAccumulator = Map<string, ParsedPackage>;

export function parseManifest(content: string, filename: string): ParsedPackage[] {
  const lower = filename.toLowerCase();

  if (lower === "package-lock.json") return parsePackageLock(content);
  if (lower === "package.json") return parsePackageJson(content);
  if (lower === "yarn.lock") return parseYarnLock(content);
  if (lower === "pnpm-lock.yaml") return parsePnpmLock(content);
  if (lower === "requirements.txt") return parseRequirementsTxt(content);
  if (lower === "go.mod") return parseGoMod(content);

  throw new Error(`Unsupported manifest format: ${filename}`);
}

function addPackage(packages: PackageAccumulator, pkg: ParsedPackage): void {
  const key = `${pkg.ecosystem}:${pkg.name}@${pkg.version}`;
  packages.set(key, pkg);
}

function sanitizeVersion(rawVersion: string): string | null {
  const trimmed = rawVersion.trim();
  if (!trimmed) return null;

  if (
    trimmed.startsWith("file:") ||
    trimmed.startsWith("link:") ||
    trimmed.startsWith("workspace:") ||
    trimmed.startsWith("git+") ||
    trimmed.startsWith("github:") ||
    trimmed.startsWith("http://") ||
    trimmed.startsWith("https://")
  ) {
    return null;
  }

  const normalized = trimmed.replace(/^[\^~<>=\sv]*/g, "");
  return normalized || null;
}

function parsePackageJson(content: string): ParsedPackage[] {
  const pkg = JSON.parse(content);
  const packages: PackageAccumulator = new Map();

  for (const section of ["dependencies", "devDependencies", "optionalDependencies"]) {
    for (const [name, ver] of Object.entries(pkg[section] || {})) {
      const version = sanitizeVersion(String(ver));
      if (!version) continue;
      addPackage(packages, { name, version, ecosystem: "npm" });
    }
  }

  return [...packages.values()];
}

function parsePackageLock(content: string): ParsedPackage[] {
  const lock = JSON.parse(content);
  const packages: PackageAccumulator = new Map();

  if (lock.packages && typeof lock.packages === "object") {
    for (const [pkgPath, info] of Object.entries(lock.packages)) {
      if (pkgPath === "") continue;
      const pkg = info as { version?: string };
      if (!pkg.version) continue;

      const name = pkgPath.split("node_modules/").filter(Boolean).at(-1);
      if (!name) continue;

      addPackage(packages, { name, version: pkg.version, ecosystem: "npm" });
    }
  }

  if (packages.size === 0 && lock.dependencies && typeof lock.dependencies === "object") {
    walkPackageLockDependencies(lock.dependencies as Record<string, unknown>, packages);
  }

  return [...packages.values()];
}

function walkPackageLockDependencies(
  dependencies: Record<string, unknown>,
  packages: PackageAccumulator
): void {
  for (const [name, info] of Object.entries(dependencies)) {
    if (!info || typeof info !== "object") continue;
    const pkg = info as { version?: string; dependencies?: Record<string, unknown> };

    if (pkg.version) {
      addPackage(packages, { name, version: pkg.version, ecosystem: "npm" });
    }

    if (pkg.dependencies) {
      walkPackageLockDependencies(pkg.dependencies, packages);
    }
  }
}

function parseYarnLock(content: string): ParsedPackage[] {
  const packages: PackageAccumulator = new Map();

  // yarn.lock v1 format:
  // "package@^version":
  //   version "1.2.3"
  //   resolved "https://registry.yarnpkg.com/..."
  //   integrity sha512-...
  //
  // yarn berry (v2+) format:
  // "package@npm:^version":
  //   version: 1.2.3
  //   resolution: "package@npm:1.2.3"

  const lines = content.split("\n");
  let currentName: string | null = null;

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();

    // Skip comments and empty lines
    if (!line || line.startsWith("#")) {
      currentName = null;
      continue;
    }

    // Package header line (not indented)
    if (!line.startsWith(" ") && !line.startsWith("\t")) {
      // Extract package name from patterns like:
      // "axios@^1.7.0, axios@^1.7.9":
      // axios@^1.7.0:
      const headerMatch = line.match(/^"?(@?[^@\s,"]+)@/);
      if (headerMatch) {
        currentName = headerMatch[1];
      } else {
        currentName = null;
      }
      continue;
    }

    // Version line (indented)
    if (currentName) {
      // v1: '  version "1.7.9"'
      const v1Match = line.match(/^\s+version\s+"([^"]+)"/);
      if (v1Match) {
        const version = sanitizeVersion(v1Match[1]);
        if (version) {
          addPackage(packages, { name: currentName, version, ecosystem: "npm" });
        }
        currentName = null;
        continue;
      }
      // berry: '  version: 1.7.9'
      const berryMatch = line.match(/^\s+version:\s+(.+)/);
      if (berryMatch) {
        const version = sanitizeVersion(berryMatch[1].trim().replace(/^"|"$/g, ""));
        if (version) {
          addPackage(packages, { name: currentName, version, ecosystem: "npm" });
        }
        currentName = null;
        continue;
      }
    }
  }

  return [...packages.values()];
}

function parsePnpmLock(content: string): ParsedPackage[] {
  const packages: PackageAccumulator = new Map();

  // pnpm-lock.yaml format (v6+):
  //   /@scope/package@1.2.3:
  //     resolution: {integrity: sha512-...}
  //
  // pnpm-lock.yaml format (v9+):
  //   '@scope/package@1.2.3':
  //     resolution: {integrity: sha512-...}
  //
  // Also handles packages section:
  //   /package@1.2.3:

  const lines = content.split("\n");

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();

    // Match package entries like:
    // '/@scope/package@1.2.3:'  or  '  /@scope/package@1.2.3:'
    // '/package@1.2.3:'
    // '@scope/package@1.2.3':   (v9+ quoted format)
    const pnpmMatch = line.match(
      /^\s+['"]?\/?(@?[a-zA-Z0-9][\w./-]*?)@(\d[^:'"\s]*)['"]?\s*:/
    );
    if (pnpmMatch) {
      const name = pnpmMatch[1];
      const version = sanitizeVersion(pnpmMatch[2]);
      if (version && name) {
        addPackage(packages, { name, version, ecosystem: "npm" });
      }
    }
  }

  return [...packages.values()];
}

function parseRequirementsTxt(content: string): ParsedPackage[] {
  const packages: PackageAccumulator = new Map();

  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-")) continue;

    const match = trimmed.match(/^([a-zA-Z0-9_.-]+)==([a-zA-Z0-9_.+-]+)/);
    if (!match) continue;

    addPackage(packages, {
      name: match[1],
      version: match[2],
      ecosystem: "PyPI",
    });
  }

  return [...packages.values()];
}

function parseGoMod(content: string): ParsedPackage[] {
  const packages: PackageAccumulator = new Map();
  const lines = content.split("\n");
  let inRequireBlock = false;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith("//")) continue;

    if (line.startsWith("require (")) {
      inRequireBlock = true;
      continue;
    }

    if (inRequireBlock && line === ")") {
      inRequireBlock = false;
      continue;
    }

    const candidate = inRequireBlock ? line : line.startsWith("require ") ? line.slice("require ".length).trim() : "";
    if (!candidate) continue;

    const match = candidate.match(/^(\S+)\s+v?([^\s]+)(?:\s+\/\/.*)?$/);
    if (!match) continue;

    addPackage(packages, {
      name: match[1],
      version: match[2].replace(/^v/, ""),
      ecosystem: "Go",
    });
  }

  return [...packages.values()];
}
