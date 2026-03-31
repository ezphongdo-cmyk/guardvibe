import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { deploymentRules } from "../../src/data/rules/deployment.js";

function testRule(ruleId: string, code: string, shouldMatch: boolean) {
  const rule = deploymentRules.find((r) => r.id === ruleId);
  assert(rule, `Rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  const matched = rule.pattern.test(code);
  assert.strictEqual(
    matched,
    shouldMatch,
    `${ruleId} ${shouldMatch ? "should match" : "should NOT match"}: ${code.substring(0, 80)}`
  );
}

describe("Deployment Config Rules", () => {
  it("VG500: detects CORS wildcard in vercel.json headers", () => {
    testRule("VG500", '"headers": [{ "key": "Access-Control-Allow-Origin", "value": "*" }]', true);
  });
  it("VG503: detects crons config", () => {
    testRule("VG503", '"crons": [{ "path": "/api/cleanup", "schedule": "0 * * * *" }]', true);
  });
  it("VG506: detects hardcoded secret in vercel.json", () => {
    testRule("VG506", '"env": { "SECRET_KEY": "sk_live_abc123def456" }', true);
  });
  it("VG507: detects wildcard remote image pattern", () => {
    testRule("VG507", 'remotePatterns: [{ hostname: "**" }]', true);
  });
  it("VG509: detects poweredByHeader not disabled", () => {
    testRule("VG509", "poweredByHeader: true", true);
  });
  it("VG515: detects privileged container", () => {
    testRule("VG515", "privileged: true", true);
  });
  it("VG514: detects hardcoded secret in docker-compose env", () => {
    testRule("VG514", "environment:\n  - SECRET_KEY=mysecretvalue123", true);
  });
  it("VG517: detects secret in fly.toml env", () => {
    testRule("VG517", '[env]\nSECRET_KEY = "hardcoded_value"', true);
  });
});
