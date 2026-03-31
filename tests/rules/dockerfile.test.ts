import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { dockerfileRules } from "../../src/data/rules/dockerfile.js";

function testRule(ruleId: string, code: string, shouldMatch: boolean) {
  const rule = dockerfileRules.find(r => r.id === ruleId);
  assert(rule, `Rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  const matched = rule.pattern.test(code);
  assert.strictEqual(matched, shouldMatch,
    `${ruleId} ${shouldMatch ? "should match" : "should NOT match"}: ${code.substring(0, 60)}`);
}

describe("Dockerfile Rules", () => {
  it("VG202: detects latest tag", () => {
    testRule("VG202", "FROM node:latest ", true);
  });
  it("VG203: detects secrets in ENV", () => {
    testRule("VG203", "ENV SECRET_KEY=mysecret123", true);
  });
  it("VG204: detects ADD for local files", () => {
    testRule("VG204", "ADD ./src /app/src", true);
  });
});
