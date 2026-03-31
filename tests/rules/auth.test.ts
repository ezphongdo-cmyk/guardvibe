import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { authRules } from "../../src/data/rules/auth.js";

function testRule(ruleId: string, code: string, shouldMatch: boolean) {
  const rule = authRules.find((r) => r.id === ruleId);
  assert(rule, `Rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  const matched = rule.pattern.test(code);
  assert.strictEqual(
    matched,
    shouldMatch,
    `${ruleId} ${shouldMatch ? "should match" : "should NOT match"}: ${code.substring(0, 80)}`
  );
}

describe("Auth Rules", () => {
  it("VG422: detects CLERK_SECRET_KEY in client code", () => {
    testRule("VG422", '"use client";\nconst key = process.env.CLERK_SECRET_KEY;', true);
  });
  it("VG423: detects hardcoded NEXTAUTH_SECRET", () => {
    testRule("VG423", 'NEXTAUTH_SECRET: "my-hardcoded-secret-value"', true);
  });
  it("VG423: allows env reference for AUTH_SECRET", () => {
    testRule("VG423", "AUTH_SECRET=process.env.AUTH_SECRET", false);
  });
  it("VG424: detects session token in localStorage", () => {
    testRule("VG424", 'localStorage.setItem("authToken", token)', true);
  });
  it("VG424: detects password in localStorage", () => {
    testRule("VG424", 'localStorage.setItem("password", userPassword)', true);
  });
  it("VG424: detects secret in localStorage", () => {
    testRule("VG424", 'localStorage.setItem("secret", mySecret)', true);
  });
  it("VG424: detects apiKey in localStorage", () => {
    testRule("VG424", 'localStorage.setItem("apiKey", key)', true);
  });
  it("VG424: detects credentials in localStorage", () => {
    testRule("VG424", 'localStorage.setItem("credentials", creds)', true);
  });
  it("VG424: allows non-auth localStorage usage", () => {
    testRule("VG424", 'localStorage.setItem("theme", "dark")', false);
  });
  it("VG427: detects getSession instead of getUser on server", () => {
    testRule("VG427", "const { data } = await supabase.auth.getSession()", true);
  });

  // Supabase Auth rules
  it("VG443: detects admin auth in client code", () => {
    testRule("VG443", '"use client";\nawait supabase.auth.admin.deleteUser(id)', true);
  });
  it("VG443: allows admin auth in server code", () => {
    testRule("VG443", 'await supabase.auth.admin.deleteUser(id)', false);
  });
  it("VG445: detects manual supabase token in localStorage", () => {
    testRule("VG445", 'localStorage.setItem("sb_access_token", session.access_token)', true);
  });
  it("VG445: allows non-supabase localStorage", () => {
    testRule("VG445", 'localStorage.setItem("theme", "dark")', false);
  });
});
