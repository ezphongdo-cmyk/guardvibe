import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { nextjsRules } from "../../src/data/rules/nextjs.js";

function testRule(ruleId: string, code: string, shouldMatch: boolean) {
  const rule = nextjsRules.find((r) => r.id === ruleId);
  assert(rule, `Rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  const matched = rule.pattern.test(code);
  assert.strictEqual(
    matched,
    shouldMatch,
    `${ruleId} ${shouldMatch ? "should match" : "should NOT match"}: ${code.substring(0, 80)}`
  );
}

describe("Next.js Rules", () => {
  it("VG400: detects process.env in use client file", () => {
    testRule("VG400", '"use client";\nconst key = process.env.SECRET_KEY;', true);
  });
  it("VG400: allows NEXT_PUBLIC_ in client component", () => {
    testRule("VG400", '"use client";\nconst key = process.env.NEXT_PUBLIC_APP_URL;', false);
  });
  it("VG401: detects server action without validation", () => {
    testRule("VG401", '"use server";\nexport async function createUser(formData: FormData) {\n  const name = formData.get("name");\n  await db.insert(name);\n}', true);
  });
  it("VG401: allows server action with zod parse", () => {
    testRule("VG401", '"use server";\nexport async function createUser(formData: FormData) {\n  const data = schema.parse(formData);\n}', false);
  });
  it("VG402: detects server action without auth", () => {
    testRule("VG402", '"use server";\nexport async function deleteUser(id: string) {\n  await db.delete(id);\n}', true);
  });
  it("VG402: allows server action with auth()", () => {
    testRule("VG402", '"use server";\nexport async function deleteUser(id: string) {\n  const session = await auth();\n  await db.delete(id);\n}', false);
  });
  it("VG403: detects CORS wildcard in route handler", () => {
    testRule("VG403", 'export async function GET() {\n  return new Response("ok", { headers: { "Access-Control-Allow-Origin": "*" } });\n}', true);
  });
  it("VG408: detects innerHTML usage", () => {
    testRule("VG408", "dangerouslySetInnerHTML={{ __html: userContent }}", true);
  });
  it("VG409: detects redirect with user input", () => {
    testRule("VG409", 'redirect(searchParams.get("next"))', true);
  });
  it("VG411: detects NEXT_PUBLIC with secret keyword", () => {
    testRule("VG411", "NEXT_PUBLIC_SECRET_KEY=abc123", true);
  });
  it("VG411: allows NEXT_PUBLIC_APP_URL", () => {
    testRule("VG411", "NEXT_PUBLIC_APP_URL=https://example.com", false);
  });

  describe("VG413 - Missing serverActions.allowedOrigins", () => {
    it("detects serverActions config without allowedOrigins", () => {
      testRule("VG413", 'serverActions: { bodySizeLimit: "2mb" }', true);
    });
    it("detects experimental serverActions without allowedOrigins", () => {
      testRule("VG413", 'experimental: { serverActions: { enabled: true } }', true);
    });
    it("ignores serverActions with allowedOrigins", () => {
      testRule("VG413", 'serverActions: { allowedOrigins: ["myapp.com"] }', false);
    });
  });
});
