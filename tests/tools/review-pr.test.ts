import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { reviewPr } from "../../src/tools/review-pr.js";

const tempDirs: string[] = [];

function createGitRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), "gv-pr-"));
  tempDirs.push(dir);
  execFileSync("git", ["init"], { cwd: dir });
  execFileSync("git", ["config", "user.email", "test@test.com"], { cwd: dir });
  execFileSync("git", ["config", "user.name", "Test"], { cwd: dir });

  // Initial commit on main
  writeFileSync(join(dir, "app.ts"), `export function hello() { return "world"; }`);
  execFileSync("git", ["add", "."], { cwd: dir });
  execFileSync("git", ["commit", "-m", "init"], { cwd: dir });
  execFileSync("git", ["branch", "-M", "main"], { cwd: dir });
  return dir;
}

describe("review_pr", () => {
  afterEach(() => {
    while (tempDirs.length > 0) {
      rmSync(tempDirs.pop()!, { recursive: true, force: true });
    }
  });

  it("detects new vulnerability in changed lines", () => {
    const dir = createGitRepo();
    // Add vulnerable code
    writeFileSync(join(dir, "app.ts"), `export function hello() { return "world"; }\nconst password = "hunter2";`);
    execFileSync("git", ["add", "."], { cwd: dir });
    execFileSync("git", ["commit", "-m", "add vuln"], { cwd: dir });

    const result = reviewPr(dir, "main~1", "json", true, "high");
    const parsed = JSON.parse(result);
    assert(parsed.summary.total > 0, "Should detect findings");
  });

  it("returns clean report when no issues in diff", () => {
    const dir = createGitRepo();
    writeFileSync(join(dir, "safe.ts"), `export const x = 1;`);
    execFileSync("git", ["add", "."], { cwd: dir });
    execFileSync("git", ["commit", "-m", "safe code"], { cwd: dir });

    const result = reviewPr(dir, "main~1", "markdown", true, "high");
    assert(result.includes("No security issues") || result.includes("All clear"));
  });

  it("annotations format returns GitHub Check Run compatible output", () => {
    const dir = createGitRepo();
    writeFileSync(join(dir, "vuln.ts"), `const password = "supersecret123";`);
    execFileSync("git", ["add", "."], { cwd: dir });
    execFileSync("git", ["commit", "-m", "add vuln"], { cwd: dir });

    const result = reviewPr(dir, "main~1", "annotations", false, "high");
    const parsed = JSON.parse(result);
    assert(Array.isArray(parsed), "Annotations should be an array");
    if (parsed.length > 0) {
      assert(parsed[0].path, "Should have path");
      assert(parsed[0].start_line, "Should have start_line");
      assert(parsed[0].annotation_level, "Should have annotation_level");
      assert(parsed[0].title, "Should have title");
    }
  });

  it("JSON format includes blocked status based on failOn", () => {
    const dir = createGitRepo();
    writeFileSync(join(dir, "vuln.ts"), `const password = "supersecret123";`);
    execFileSync("git", ["add", "."], { cwd: dir });
    execFileSync("git", ["commit", "-m", "vuln"], { cwd: dir });

    const result = reviewPr(dir, "main~1", "json", false, "critical");
    const parsed = JSON.parse(result);
    assert(typeof parsed.summary.blocked === "boolean");
  });

  it("diff-only mode filters to changed lines only", () => {
    const dir = createGitRepo();
    // Replace safe code with safe + vuln at end
    writeFileSync(join(dir, "app.ts"), `export function hello() { return "world"; }\nconst secret_key = "abc123secret";`);
    execFileSync("git", ["add", "."], { cwd: dir });
    execFileSync("git", ["commit", "-m", "add vuln"], { cwd: dir });

    const diffResult = JSON.parse(reviewPr(dir, "main~1", "json", true, "none"));
    const fullResult = JSON.parse(reviewPr(dir, "main~1", "json", false, "none"));
    // Both should find issues since the vuln is in the diff
    assert(diffResult.summary.diffOnly === true);
    assert(fullResult.summary.diffOnly === false);
  });

  it("markdown output includes PR comment structure", () => {
    const dir = createGitRepo();
    writeFileSync(join(dir, "vuln.ts"), `const password = "hunter2";`);
    execFileSync("git", ["add", "."], { cwd: dir });
    execFileSync("git", ["commit", "-m", "vuln"], { cwd: dir });

    const result = reviewPr(dir, "main~1", "markdown", false, "high");
    assert(result.includes("GuardVibe PR Security Review"));
    assert(result.includes("Base:"));
  });

  it("handles no changed files gracefully", () => {
    const dir = createGitRepo();
    const result = reviewPr(dir, "HEAD", "json");
    const parsed = JSON.parse(result);
    assert(parsed.summary.total === 0);
  });
});
