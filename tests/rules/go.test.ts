import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { goRules } from "../../src/data/rules/go.js";

function testRule(ruleId: string, code: string, shouldMatch: boolean) {
  const rule = goRules.find(r => r.id === ruleId);
  assert(rule, `Rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  const matched = rule.pattern.test(code);
  assert.strictEqual(matched, shouldMatch,
    `${ruleId} ${shouldMatch ? "should match" : "should NOT match"}: ${code.substring(0, 60)}`);
}

describe("Go Rules", () => {
  it("VG110: detects fmt.Sprintf in SQL", () => {
    testRule("VG110", 'db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))', true);
  });
  it("VG110: ignores parameterized query", () => {
    testRule("VG110", 'db.Query("SELECT * FROM users WHERE id = $1", id)', false);
  });
  it("VG112: detects template.HTML()", () => {
    testRule("VG112", 'template.HTML(userInput)', true);
  });
  it("VG114: detects md5.New()", () => {
    testRule("VG114", 'h := md5.New()', true);
  });
});
