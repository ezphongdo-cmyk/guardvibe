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
  // VG620 - Resend API Key Client Exposure
  describe("VG620 - Resend API Key Client Exposure", () => {
    it("detects RESEND_API_KEY in client code", () => {
      testRule("VG620", '"use client";\nconst key = process.env.RESEND_API_KEY;', true);
    });
    it("detects re_ key pattern in client code", () => {
      testRule("VG620", '"use client";\nconst key = "re_ABCDEFGHIJKLMNOPQRSTUVWXYZabc";', true);
    });
    it("allows RESEND_API_KEY in server code", () => {
      testRule("VG620", "const key = process.env.RESEND_API_KEY;", false);
    });
  });

  // VG621 - Hardcoded Resend API Key
  it("VG621: detects hardcoded Resend key", () => {
    testRule("VG621", 'const resend = new Resend("re_abc123def456ghi789")', true);
  });
  it("VG621: allows env var Resend key", () => {
    testRule("VG621", "const resend = new Resend(process.env.RESEND_API_KEY)", false);
  });

  // VG622 - Email Content Injection
  describe("VG622 - Email Content Injection", () => {
    it("detects user input in email to field via resend", () => {
      testRule("VG622", 'resend.emails.send({\n  to: req.body.email,\n  subject: "Hello"\n})', true);
    });
    it("detects user input in email subject via nodemailer", () => {
      testRule("VG622", 'nodemailer.send({\n  subject: formData.get("subject")\n})', true);
    });
    it("ignores static email fields", () => {
      testRule("VG622", 'resend.emails.send({\n  to: "admin@example.com",\n  subject: "Report"\n})', false);
    });
  });

  // VG625 - Upstash Redis URL Client Exposure
  it("VG625: detects Upstash in client code", () => {
    testRule("VG625", '"use client";\nconst url = process.env.UPSTASH_REDIS_REST_URL;', true);
  });
  it("VG625: detects KV_REST_API_TOKEN in client code", () => {
    testRule("VG625", '"use client";\nconst token = process.env.KV_REST_API_TOKEN;', true);
  });
  it("VG625: allows Upstash in server code", () => {
    testRule("VG625", "const url = process.env.UPSTASH_REDIS_REST_URL;", false);
  });

  // VG626 - Hardcoded Redis Connection String
  describe("VG626 - Hardcoded Redis Connection String", () => {
    it("detects hardcoded Redis URL", () => {
      testRule("VG626", 'const redis = new Redis({ url: "https://us1-abc-12345.upstash.io" })', true);
    });
    it("detects hardcoded redis:// connection", () => {
      testRule("VG626", 'redis.connect({ url: "redis://default:password@localhost:6379" })', true);
    });
    it("ignores env var Redis URL", () => {
      testRule("VG626", "const redis = new Redis({ url: process.env.REDIS_URL })", false);
    });
  });

  // VG627 - NEXT_PUBLIC Redis Credentials
  it("VG627: detects NEXT_PUBLIC Redis", () => {
    testRule("VG627", "NEXT_PUBLIC_UPSTASH_REDIS_REST_TOKEN=xxx", true);
  });
  it("VG627: detects NEXT_PUBLIC KV URL", () => {
    testRule("VG627", "NEXT_PUBLIC_KV_REST_API_URL=https://example.com", true);
  });
  it("VG627: allows server-side Redis env", () => {
    testRule("VG627", "UPSTASH_REDIS_REST_TOKEN=xxx", false);
  });

  // VG630 - Pinecone API Key Client Exposure
  it("VG630: detects Pinecone key in client", () => {
    testRule("VG630", '"use client";\nconst key = process.env.PINECONE_API_KEY;', true);
  });
  it("VG630: allows Pinecone key in server", () => {
    testRule("VG630", "const key = process.env.PINECONE_API_KEY;", false);
  });

  // VG631 - NEXT_PUBLIC Pinecone Key
  describe("VG631 - NEXT_PUBLIC Pinecone Key", () => {
    it("detects NEXT_PUBLIC Pinecone API key", () => {
      testRule("VG631", "NEXT_PUBLIC_PINECONE_API_KEY=pc-xxx", true);
    });
    it("allows server-side Pinecone key", () => {
      testRule("VG631", "PINECONE_API_KEY=pc-xxx", false);
    });
  });

  // VG635 - PostHog Secret API Key Exposure
  describe("VG635 - PostHog Secret API Key Exposure", () => {
    it("detects PostHog personal key in client code", () => {
      testRule("VG635", '"use client";\nconst key = process.env.POSTHOG_PERSONAL_API_KEY;', true);
    });
    it("detects phx_ key pattern in client code", () => {
      testRule("VG635", '"use client";\nconst key = "phx_ABCDEFGHIJKLMNOPQRSTUVWXYZabc";', true);
    });
    it("allows PostHog project key in client", () => {
      testRule("VG635", '"use client";\nconst key = "phc_projectkey123";', false);
    });
  });

  // VG636 - Analytics PII Data Exposure
  it("VG636: detects PII in analytics", () => {
    testRule("VG636", 'posthog.capture("signup", { email: user.email })', true);
  });
  it("VG636: allows non-PII analytics", () => {
    testRule("VG636", 'posthog.capture("signup", { plan: "pro" })', false);
  });

  // VG637 - Google Analytics PII Tracking
  describe("VG637 - Google Analytics PII Tracking", () => {
    it("detects gtag with email", () => {
      testRule("VG637", 'gtag("event", "purchase", { email: user.email })', true);
    });
    it("detects dataLayer.push with phone", () => {
      testRule("VG637", 'dataLayer.push({ event: "signup", phone: user.phone })', true);
    });
    it("ignores gtag without PII", () => {
      testRule("VG637", 'gtag("event", "purchase", { value: 29.99 })', false);
    });
  });
});
