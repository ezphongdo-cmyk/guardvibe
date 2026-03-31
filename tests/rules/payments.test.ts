import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { paymentRules } from "../../src/data/rules/payments.js";

function testRule(ruleId: string, code: string, shouldMatch: boolean) {
  const rule = paymentRules.find((r) => r.id === ruleId);
  assert(rule, `Rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  const matched = rule.pattern.test(code);
  assert.strictEqual(
    matched,
    shouldMatch,
    `${ruleId} ${shouldMatch ? "should match" : "should NOT match"}: ${code.substring(0, 80)}`,
  );
}

describe("Payment Rules", () => {
  it("VG600: detects Stripe secret key in client code", () => {
    testRule("VG600", '"use client";\nconst key = sk_live_abc123;', true);
  });
  it("VG603: detects hardcoded Stripe key", () => {
    testRule(
      "VG603",
      'const stripe = new Stripe("sk_live_abc123def456")',
      true,
    );
  });
  it("VG603: allows env var Stripe key", () => {
    testRule(
      "VG603",
      "const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)",
      false,
    );
  });
  it("VG604: detects NEXT_PUBLIC Stripe secret", () => {
    testRule("VG604", "NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_xxx", true);
  });
  it("VG604: allows NEXT_PUBLIC publishable key", () => {
    testRule(
      "VG604",
      "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_xxx",
      false,
    );
  });
});
