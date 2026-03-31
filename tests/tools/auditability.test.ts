import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, readFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { scanDirectory } from "../../src/tools/scan-directory.js";

const tempDirs: string[] = [];

function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "gv-audit-trail-"));
  tempDirs.push(dir);
  return dir;
}

describe("scan metadata (audit trail)", () => {
  afterEach(() => {
    while (tempDirs.length > 0) {
      rmSync(tempDirs.pop()!, { recursive: true, force: true });
    }
  });

  it("JSON output includes scan metadata", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "app.ts"), `export function hello() { return "world"; }`);
    const result = scanDirectory(dir, true, [], "json");
    const parsed = JSON.parse(result);
    assert(parsed.metadata, "Should have metadata");
    assert(typeof parsed.metadata.scanId === "string", "Should have scanId");
    assert(parsed.metadata.scanId.includes("-"), "scanId should be UUID format");
    assert(typeof parsed.metadata.timestamp === "string", "Should have timestamp");
    assert(parsed.metadata.timestamp.includes("T"), "timestamp should be ISO format");
    assert(typeof parsed.metadata.guardvibeVersion === "string", "Should have version");
    assert(typeof parsed.metadata.ruleCount === "number", "Should have ruleCount");
    assert(typeof parsed.metadata.scanDurationMs === "number", "Should have scanDuration");
    assert(typeof parsed.metadata.filesScanned === "number", "Should have filesScanned");
    assert(typeof parsed.metadata.filesSkipped === "number", "Should have filesSkipped");
    assert(typeof parsed.metadata.fileHashes === "object", "Should have fileHashes");
  });

  it("JSON output includes file hashes", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "app.ts"), `const x = 1;`);
    writeFileSync(join(dir, "lib.ts"), `const y = 2;`);
    const result = scanDirectory(dir, true, [], "json");
    const parsed = JSON.parse(result);
    const hashes = parsed.metadata.fileHashes;
    const hashKeys = Object.keys(hashes);
    assert(hashKeys.length >= 2, "Should hash multiple files");
    assert(hashKeys.every((k: string) => typeof hashes[k] === "string" && hashes[k].length === 16),
      "Hashes should be 16-char hex strings");
  });

  it("markdown output includes scan ID and timestamp", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "app.ts"), `const x = 1;`);
    const result = scanDirectory(dir, true, [], "markdown");
    assert(result.includes("Scan ID:"), "Should include scan ID");
    assert(result.includes("Timestamp:"), "Should include timestamp");
    assert(result.includes("Scan duration:"), "Should include scan duration");
    assert(result.includes("GuardVibe:"), "Should include version info");
  });

  it("each scan gets a unique ID", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "app.ts"), `const x = 1;`);
    const result1 = JSON.parse(scanDirectory(dir, true, [], "json"));
    const result2 = JSON.parse(scanDirectory(dir, true, [], "json"));
    assert.notEqual(result1.metadata.scanId, result2.metadata.scanId, "Scan IDs should be unique");
  });

  it("JSON output includes baseline data for future comparisons", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "app.ts"), `const password = "hunter2";`);
    const result = JSON.parse(scanDirectory(dir, true, [], "json"));
    assert(Array.isArray(result.baseline), "Should include baseline array");
    assert(result.baseline.length > 0, "Should have baseline entries for findings");
    assert(result.baseline[0].id, "Baseline entries should have rule id");
    assert(result.baseline[0].file, "Baseline entries should have file path");
  });
});

describe("baseline comparison mode", () => {
  afterEach(() => {
    while (tempDirs.length > 0) {
      rmSync(tempDirs.pop()!, { recursive: true, force: true });
    }
  });

  it("detects new findings when compared to empty baseline", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "app.ts"), `const password = "hunter2";`);

    // Create empty baseline
    const baselinePath = join(dir, "baseline.json");
    writeFileSync(baselinePath, JSON.stringify({
      metadata: { scanId: "prev-scan-id", timestamp: "2024-01-01T00:00:00Z" },
      baseline: [],
    }));

    const result = JSON.parse(scanDirectory(dir, true, [], "json", undefined, baselinePath));
    assert(result.baselineDiff, "Should have baselineDiff");
    assert(result.baselineDiff.new > 0, "Should have new findings");
    assert(result.baselineDiff.fixed === 0, "Should have no fixed findings");
    assert(result.baselineDiff.previousScanId === "prev-scan-id");
  });

  it("detects fixed findings when issues are removed", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "app.ts"), `export function hello() { return "world"; }`);

    // Create baseline with a previous finding
    const baselinePath = join(dir, "baseline.json");
    writeFileSync(baselinePath, JSON.stringify({
      metadata: { scanId: "prev-scan", timestamp: "2024-01-01T00:00:00Z" },
      baseline: [{
        id: "VG001", name: "Hardcoded credentials", severity: "critical",
        file: join(dir, "app.ts"), line: 1, match: 'password = "hunter2"',
      }],
    }));

    const result = JSON.parse(scanDirectory(dir, true, [], "json", undefined, baselinePath));
    assert(result.baselineDiff, "Should have baselineDiff");
    assert(result.baselineDiff.fixed > 0, "Should detect fixed findings");
    assert(result.baselineDiff.new === 0, "Should have no new findings");
  });

  it("detects unchanged findings", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "app.ts"), `const password = "hunter2";`);

    // First scan to get baseline
    const firstScan = JSON.parse(scanDirectory(dir, true, [], "json"));
    const baselinePath = join(dir, "baseline.json");
    writeFileSync(baselinePath, JSON.stringify(firstScan));

    // Second scan with same code
    const result = JSON.parse(scanDirectory(dir, true, [], "json", undefined, baselinePath));
    assert(result.baselineDiff, "Should have baselineDiff");
    assert(result.baselineDiff.unchanged > 0, "Should have unchanged findings");
    assert(result.baselineDiff.new === 0, "No new findings expected");
    assert(result.baselineDiff.fixed === 0, "No fixed findings expected");
  });

  it("markdown output includes baseline comparison section", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "app.ts"), `const password = "hunter2";`);

    const baselinePath = join(dir, "baseline.json");
    writeFileSync(baselinePath, JSON.stringify({
      metadata: { scanId: "prev-scan", timestamp: "2024-01-01T00:00:00Z" },
      baseline: [],
    }));

    const result = scanDirectory(dir, true, [], "markdown", undefined, baselinePath);
    assert(result.includes("Baseline Comparison"), "Should include baseline section");
    assert(result.includes("New findings"), "Should show new findings count");
    assert(result.includes("Fixed findings"), "Should show fixed findings count");
  });

  it("handles missing baseline file gracefully", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "app.ts"), `const x = 1;`);
    // Non-existent baseline path
    const result = scanDirectory(dir, true, [], "json", undefined, "/nonexistent/baseline.json");
    const parsed = JSON.parse(result);
    assert(!parsed.baselineDiff, "Should not have baselineDiff when file is missing");
  });

  it("handles corrupted baseline file gracefully", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "app.ts"), `const x = 1;`);
    const baselinePath = join(dir, "baseline.json");
    writeFileSync(baselinePath, "not json");
    const result = scanDirectory(dir, true, [], "json", undefined, baselinePath);
    const parsed = JSON.parse(result);
    assert(!parsed.baselineDiff, "Should not have baselineDiff when file is corrupted");
  });
});
