import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeCode, checkCode } from "../../src/tools/check-code.js";

describe("analyzeCode", () => {
  it("returns structured findings", () => {
    const findings = analyzeCode('const password = "abc123"', "javascript");
    assert(findings.length > 0);
    assert(findings[0].rule.id === "VG001");
    assert(typeof findings[0].line === "number");
    assert(typeof findings[0].match === "string");
  });

  it("returns empty array for clean code", () => {
    const findings = analyzeCode("const x = 1 + 2;", "javascript");
    assert.strictEqual(findings.length, 0);
  });

  it("filters by language", () => {
    const findings = analyzeCode("eval(x)", "go");
    assert(!findings.some(f => f.rule.id === "VG014"));
  });
});

describe("checkCode", () => {
  it("returns markdown report string", () => {
    const report = checkCode('const password = "abc"', "javascript");
    assert(report.includes("# GuardVibe Security Report"));
    assert(report.includes("VG001"));
  });

  it("returns clean report for safe code", () => {
    const report = checkCode("const x = 1;", "javascript");
    assert(report.includes("No security issues detected"));
  });
});
