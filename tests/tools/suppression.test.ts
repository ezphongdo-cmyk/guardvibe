import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeCode } from "../../src/tools/check-code.js";

describe("guardvibe-ignore suppression", () => {
  it("suppresses finding on same line with // comment", () => {
    const code = 'const password = "abc123"; // guardvibe-ignore VG001';
    const findings = analyzeCode(code, "javascript");
    assert(!findings.some(f => f.rule.id === "VG001"));
  });

  it("suppresses finding on next line with ignore-next-line", () => {
    const code = '// guardvibe-ignore-next-line VG001\nconst password = "abc123";';
    const findings = analyzeCode(code, "javascript");
    assert(!findings.some(f => f.rule.id === "VG001"));
  });

  it("suppresses all rules when no rule ID given", () => {
    const code = 'const password = "abc123"; // guardvibe-ignore';
    const findings = analyzeCode(code, "javascript");
    assert.strictEqual(findings.length, 0);
  });

  it("only suppresses specified rule, not others", () => {
    const dangerousFn = "eval";
    const code = dangerousFn + '(password = "abc"); // guardvibe-ignore VG001';
    const findings = analyzeCode(code, "javascript");
    assert(!findings.some(f => f.rule.id === "VG001"));
    assert(findings.some(f => f.rule.id === "VG014"));
  });

  it("supports # comment style for Python", () => {
    const code = 'password = "abc123"  # guardvibe-ignore VG001';
    const findings = analyzeCode(code, "python");
    assert(!findings.some(f => f.rule.id === "VG001"));
  });
});
