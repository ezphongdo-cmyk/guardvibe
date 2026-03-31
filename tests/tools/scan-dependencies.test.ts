import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { scanDependencies } from "../../src/tools/scan-dependencies.js";

const tempDirs: string[] = [];
const originalFetch = globalThis.fetch;

function createTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

describe("scan_dependencies", () => {
  afterEach(() => {
    globalThis.fetch = originalFetch;
    while (tempDirs.length > 0) {
      rmSync(tempDirs.pop()!, { recursive: true, force: true });
    }
  });

  it("reports OSV availability errors instead of false clean results", async () => {
    globalThis.fetch = async () => ({
      ok: false,
      status: 503,
      statusText: "Service Unavailable",
      json: async () => ({}),
    }) as Response;

    const dir = createTempDir("guardvibe-deps-");
    const manifestPath = join(dir, "package.json");
    writeFileSync(manifestPath, JSON.stringify({
      dependencies: {
        lodash: "^4.17.21",
      },
    }));

    const report = await scanDependencies(manifestPath);
    assert(report.includes("Error: Could not reach OSV API"));
    assert(!report.includes("All 1 packages are clean"));
  });

  it("reports clean packages when OSV returns no vulnerabilities", async () => {
    globalThis.fetch = async () => ({
      ok: true,
      json: async () => ({ results: [{ vulns: [] }] }),
    }) as Response;

    const dir = createTempDir("guardvibe-deps-");
    const manifestPath = join(dir, "package.json");
    writeFileSync(manifestPath, JSON.stringify({
      dependencies: {
        zod: "^3.25.0",
      },
    }));

    const report = await scanDependencies(manifestPath);
    assert(report.includes("All 1 packages are clean"));
  });
});
