import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { webSecurityRules } from "../../src/data/rules/web-security.js";

function testRule(ruleId: string, code: string, shouldMatch: boolean) {
  const rule = webSecurityRules.find((r) => r.id === ruleId);
  assert(rule, `Rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  const matched = rule.pattern.test(code);
  assert.strictEqual(matched, shouldMatch,
    `${ruleId} ${shouldMatch ? "should match" : "should NOT match"}: ${code.substring(0, 80)}`);
}

describe("Web Security Rules", () => {
  it("VG651: detects hardcoded webhook secret", () => {
    testRule("VG651", 'const webhookSecret = "whsec_abc123def456ghi789"', true);
  });
  it("VG655: detects NEXT_PUBLIC with SECRET", () => {
    testRule("VG655", "NEXT_PUBLIC_WEBHOOK_SECRET=abc123", true);
  });
  it("VG655: allows NEXT_PUBLIC without sensitive keyword", () => {
    testRule("VG655", "NEXT_PUBLIC_APP_URL=https://example.com", false);
  });
  it("VG662: detects source maps enabled", () => {
    testRule("VG662", "productionBrowserSourceMaps: true", true);
  });
  it("VG675: detects OpenAI key in client", () => {
    testRule("VG675", '"use client";\nconst key = process.env.OPENAI_API_KEY;', true);
  });
  it("VG676: detects NEXT_PUBLIC AI key", () => {
    testRule("VG676", "NEXT_PUBLIC_OPENAI_API_KEY=sk-xxx", true);
  });
  it("VG677: detects hardcoded OpenAI key", () => {
    testRule("VG677", 'const openai = new OpenAI({ apiKey: "sk-abc123def456ghi789" })', true);
  });
  it("VG677: allows env var OpenAI key", () => {
    testRule("VG677", "const openai = new OpenAI()", false);
  });

  describe("VG678 - Missing X-Content-Type-Options Header", () => {
    it("detects sendFile response without nosniff header", () => {
      testRule("VG678", `app.get("/uploads/:name", (req, res) => {
  const filePath = path.join(uploadDir, req.params.name);
  res.sendFile(filePath);
  res.end();
});`, true);
    });
    it("does not match when nosniff header is present", () => {
      testRule("VG678", `app.get("/uploads/:name", (req, res) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.sendFile(filePath);
});`, false);
    });
  });
});
