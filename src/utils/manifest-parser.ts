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
