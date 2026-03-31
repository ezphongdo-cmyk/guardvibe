import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { serviceRules } from "../../src/data/rules/services.js";

function testRule(ruleId: string, code: string, shouldMatch: boolean) {
  const rule = serviceRules.find((r) => r.id === ruleId);
  assert(rule, `Rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  const matched = rule.pattern.test(code);
  assert.strictEqual(matched, shouldMatch,
    `${ruleId} ${shouldMatch ? "should match" : "should NOT match"}: ${code.substring(0, 80)}`);
}

describe("Service Rules", () => {
  it("VG621: detects hardcoded Resend key", () => {
    testRule("VG621", 'const resend = new Resend("re_abc123def456ghi789")', true);
  });
  it("VG621: allows env var Resend key", () => {
    testRule("VG621", "const resend = new Resend(process.env.RESEND_API_KEY)", false);
  });
  it("VG625: detects Upstash in client code", () => {
    testRule("VG625", '"use client";\nconst url = process.env.UPSTASH_REDIS_REST_URL;', true);
  });
  it("VG627: detects NEXT_PUBLIC Redis", () => {
    testRule("VG627", "NEXT_PUBLIC_UPSTASH_REDIS_REST_TOKEN=xxx", true);
  });
  it("VG630: detects Pinecone key in client", () => {
    testRule("VG630", '"use client";\nconst key = process.env.PINECONE_API_KEY;', true);
  });
  it("VG636: detects PII in analytics", () => {
    testRule("VG636", 'posthog.capture("signup", { email: user.email })', true);
  });
  it("VG636: allows non-PII analytics", () => {
    testRule("VG636", 'posthog.capture("signup", { plan: "pro" })', false);
  });
});
