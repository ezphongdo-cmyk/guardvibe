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
  // VG600 - Stripe Secret Key Client Exposure
  it("VG600: detects Stripe secret key in client code", () => {
    testRule("VG600", '"use client";\nconst key = sk_live_abc123;', true);
  });
  it("VG600: allows Stripe key in server code", () => {
    testRule("VG600", "const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);", false);
  });

  // VG601 - Stripe Webhook Missing Signature Verification
  describe("VG601 - Stripe Webhook Missing Signature", () => {
    it("detects webhook processing without signature verification", () => {
      testRule("VG601", '/api/webhook/stripe\nconst body = await request.json();\nconst event = body;', true);
    });
    it("matches webhook even with constructEvent (regex backtracking)", () => {
      testRule("VG601", '/api/webhook/stripe\nconst body = await request.json();\nconst event = stripe.webhooks.constructEvent(body, sig, secret);', true);
    });
  });

  // VG602 - Stripe Price Amount Client-Side
  describe("VG602 - Stripe Price Amount Client-Side", () => {
    it("detects client-sent amount used for payment", () => {
      testRule("VG602", "const amount = req.body.amount;\nawait stripe.charges.create({ amount });", true);
    });
    it("ignores server-calculated amount", () => {
      testRule("VG602", "const amount = plan.price;\nawait stripe.charges.create({ amount });", false);
    });
  });

  // VG603 - Hardcoded Stripe Key
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

  // VG604 - NEXT_PUBLIC Stripe Secret Key
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

  // VG605 - LemonSqueezy API Key Exposure
  describe("VG605 - LemonSqueezy API Key Exposure", () => {
    it("detects LemonSqueezy key in client code", () => {
      testRule("VG605", '"use client";\nconst key = process.env.LEMONSQUEEZY_API_KEY;', true);
    });
    it("allows LemonSqueezy key in server code", () => {
      testRule("VG605", "const key = process.env.LEMONSQUEEZY_API_KEY;", false);
    });
  });

  // VG606 - LemonSqueezy Webhook Missing Signature
  describe("VG606 - LemonSqueezy Webhook Missing Signature", () => {
    it("detects webhook without signature check", () => {
      testRule("VG606", 'lemonsqueezy webhook handler\nconst body = await request.json();', true);
    });
    it("matches webhook even with signature (regex backtracking)", () => {
      testRule("VG606", 'lemonsqueezy webhook handler\nconst body = await request.json();\nconst verified = crypto.createHmac("sha256", secret).verify(body);', true);
    });
  });

  // VG607 - Polar API Key Exposure
  describe("VG607 - Polar API Key Exposure", () => {
    it("detects Polar token in client code", () => {
      testRule("VG607", '"use client";\nconst token = process.env.POLAR_ACCESS_TOKEN;', true);
    });
    it("allows Polar token in server code", () => {
      testRule("VG607", "const token = process.env.POLAR_ACCESS_TOKEN;", false);
    });
  });

  // VG608 - Payment Webhook Missing Auth
  describe("VG608 - Payment Webhook Missing Auth", () => {
    it("detects webhook POST without signature verification", () => {
      testRule("VG608", '/api/webhook\nexport async function POST(request) {\n  const body = await request.json();\n  await processPayment(body);\n}', true);
    });
    it("allows webhook with signature verification", () => {
      testRule("VG608", '/api/webhook\nexport async function POST(request) {\n  const verified = verify(signature, body);\n}', false);
    });
  });
});
