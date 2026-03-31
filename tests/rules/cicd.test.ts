import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeCode } from "../../src/tools/check-code.js";

describe("CI/CD Rules", () => {
  it("VG210: detects secrets in run step", () => {
    const code = "run: deploy --token ${{ secrets.DEPLOY_TOKEN }}";
    const findings = analyzeCode(code, "yaml", undefined, ".github/workflows/deploy.yml");
    assert(findings.some(f => f.rule.id === "VG210"));
  });

  it("VG212: detects unpinned action", () => {
    const code = "uses: actions/checkout@main ";
    const findings = analyzeCode(code, "yaml", undefined, ".github/workflows/ci.yml");
    assert(findings.some(f => f.rule.id === "VG212"));
  });

  it("VG213: detects write-all permissions", () => {
    const code = "permissions: write-all";
    const findings = analyzeCode(code, "yaml", undefined, ".github/workflows/ci.yml");
    assert(findings.some(f => f.rule.id === "VG213"));
  });

  it("does not trigger CI rules on non-workflow yaml", () => {
    const code = "permissions: write-all";
    const findings = analyzeCode(code, "yaml", undefined, "config/settings.yml");
    assert(!findings.some(f => f.rule.id === "VG213"));
  });
});
