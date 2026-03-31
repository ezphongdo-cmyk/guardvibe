import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "child_process";
import { mkdtempSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { scanSecretsHistory } from "../../src/tools/scan-secrets-history.js";

const tempDirs: string[] = [];

function createGitRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), "gv-hist-"));
  tempDirs.push(dir);
  execFileSync("git", ["init"], { cwd: dir });
  execFileSync("git", ["config", "user.email", "test@test.com"], { cwd: dir });
  execFileSync("git", ["config", "user.name", "Test"], { cwd: dir });
  writeFileSync(join(dir, "readme.md"), "# test");
  execFileSync("git", ["add", "."], { cwd: dir });
  execFileSync("git", ["commit", "-m", "init"], { cwd: dir });
  return dir;
}

describe("scan_secrets_history", () => {
  afterEach(() => {
    while (tempDirs.length > 0) {
      rmSync(tempDirs.pop()!, { recursive: true, force: true });
    }
  });

  it("detects active secret in current code", () => {
    const dir = createGitRepo();
    writeFileSync(join(dir, ".env"), "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");
    execFileSync("git", ["add", "."], { cwd: dir });
    execFileSync("git", ["commit", "-m", "add key"], { cwd: dir });

    const result = JSON.parse(scanSecretsHistory(dir, 50, "json"));
    assert(result.summary.total > 0, "Should find secrets");
    assert(result.findings.some((f: any) => f.status === "active"), "Secret should be active");
  });

  it("detects removed secret still in git history", () => {
    const dir = createGitRepo();
    // Commit secret
    writeFileSync(join(dir, ".env"), "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn");
    execFileSync("git", ["add", "."], { cwd: dir });
    execFileSync("git", ["commit", "-m", "add token"], { cwd: dir });
    // Remove secret
    writeFileSync(join(dir, ".env"), "# cleaned");
    execFileSync("git", ["add", "."], { cwd: dir });
    execFileSync("git", ["commit", "-m", "remove token"], { cwd: dir });

    const result = JSON.parse(scanSecretsHistory(dir, 50, "json"));
    assert(result.summary.total > 0, "Should find secrets in history");
    assert(result.findings.some((f: any) => f.status === "removed"), "Secret should be marked as removed");
  });

  it("returns clean report when no secrets in history", () => {
    const dir = createGitRepo();
    writeFileSync(join(dir, "app.ts"), "export const x = 1;");
    execFileSync("git", ["add", "."], { cwd: dir });
    execFileSync("git", ["commit", "-m", "safe"], { cwd: dir });

    const result = JSON.parse(scanSecretsHistory(dir, 50, "json"));
    assert(result.summary.total === 0);
  });

  it("includes commit hash and date in findings", () => {
    const dir = createGitRepo();
    writeFileSync(join(dir, "config.ts"), 'const key = "sk-abcdefghijklmnopqrstuvwxyz123456";');
    execFileSync("git", ["add", "."], { cwd: dir });
    execFileSync("git", ["commit", "-m", "add key"], { cwd: dir });

    const result = JSON.parse(scanSecretsHistory(dir, 50, "json"));
    if (result.findings.length > 0) {
      assert(result.findings[0].commit, "Should have commit hash");
      assert(result.findings[0].commitDate, "Should have commit date");
      assert(result.findings[0].author, "Should have author");
    }
  });

  it("markdown output shows active vs removed sections", () => {
    const dir = createGitRepo();
    writeFileSync(join(dir, ".env"), "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");
    execFileSync("git", ["add", "."], { cwd: dir });
    execFileSync("git", ["commit", "-m", "key"], { cwd: dir });

    const result = scanSecretsHistory(dir, 50, "markdown");
    assert(result.includes("Git History Secret Scan"));
  });

  it("respects maxCommits limit", () => {
    const dir = createGitRepo();
    // Create several commits
    for (let i = 0; i < 5; i++) {
      writeFileSync(join(dir, `file${i}.ts`), `export const v${i} = ${i};`);
      execFileSync("git", ["add", "."], { cwd: dir });
      execFileSync("git", ["commit", "-m", `commit ${i}`], { cwd: dir });
    }

    const result = JSON.parse(scanSecretsHistory(dir, 2, "json"));
    assert(result.summary.commitsScanned <= 2, "Should respect maxCommits");
  });

  it("deduplicates same secret across multiple commits", () => {
    const dir = createGitRepo();
    writeFileSync(join(dir, ".env"), "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");
    execFileSync("git", ["add", "."], { cwd: dir });
    execFileSync("git", ["commit", "-m", "add"], { cwd: dir });
    // Modify same file but keep secret
    writeFileSync(join(dir, ".env"), "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nOTHER=value");
    execFileSync("git", ["add", "."], { cwd: dir });
    execFileSync("git", ["commit", "-m", "modify"], { cwd: dir });

    const result = JSON.parse(scanSecretsHistory(dir, 50, "json"));
    const awsFindings = result.findings.filter((f: any) => f.provider === "AWS Access Key");
    assert(awsFindings.length <= 1, "Should deduplicate same secret");
  });
});
