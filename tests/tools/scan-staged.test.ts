import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "child_process";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { scanStaged } from "../../src/tools/scan-staged.js";

const tempDirs: string[] = [];

function createGitRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), "guardvibe-staged-"));
  tempDirs.push(dir);
  execFileSync("git", ["init", "-b", "main"], { cwd: dir });
  return dir;
}

describe("scan_staged", () => {
  afterEach(() => {
    while (tempDirs.length > 0) {
      rmSync(tempDirs.pop()!, { recursive: true, force: true });
    }
  });

  it("scans staged terraform files", () => {
    const repoDir = createGitRepo();
    const filePath = join(repoDir, "main.tf");
    writeFileSync(filePath, 'resource "aws_s3_bucket" "example" {\n  acl = "public"\n}\n');
    execFileSync("git", ["add", "main.tf"], { cwd: repoDir });

    const report = scanStaged(repoDir);
    assert(report.includes("Staged files scanned: 1"));
    assert(report.includes("VG300"));
    assert(report.includes("main.tf"));
  });
});
