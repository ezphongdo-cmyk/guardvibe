import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { checkCode } from "../../src/tools/check-code.js";

describe("JSON Output Mode", () => {
  it("check_code returns valid JSON when format is json", () => {
    const code = 'const password = "secret123";';
    const result = checkCode(code, "javascript", undefined, undefined, undefined, "json");
    const parsed = JSON.parse(result);
    assert(parsed.summary, "Should have summary");
    assert(typeof parsed.summary.total === "number");
    assert(typeof parsed.summary.blocked === "boolean");
    assert(Array.isArray(parsed.findings));
    if (parsed.findings.length > 0) {
      assert(parsed.findings[0].id);
      assert(parsed.findings[0].severity);
      assert(parsed.findings[0].fix);
    }
  });

  it("check_code returns markdown by default", () => {
    const code = 'const password = "secret123";';
    const result = checkCode(code, "javascript");
    assert(result.startsWith("# GuardVibe"));
  });

  it("JSON blocked is true when critical/high findings exist", () => {
    const code = 'const password = "secret123";';
    const result = checkCode(code, "javascript", undefined, undefined, undefined, "json");
    const parsed = JSON.parse(result);
    assert.strictEqual(parsed.summary.blocked, parsed.summary.critical > 0 || parsed.summary.high > 0);
  });

  it("JSON returns empty findings for clean code", () => {
    const code = "const x = 1 + 2;";
    const result = checkCode(code, "javascript", undefined, undefined, undefined, "json");
    const parsed = JSON.parse(result);
    assert.strictEqual(parsed.summary.total, 0);
    assert.strictEqual(parsed.summary.blocked, false);
    assert.strictEqual(parsed.findings.length, 0);
  });
});
