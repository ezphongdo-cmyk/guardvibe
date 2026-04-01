import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { coreRules } from "../../src/data/rules/core.js";

function testRule(ruleId: string, code: string, language: string, shouldMatch: boolean) {
  const rule = coreRules.find(r => r.id === ruleId);
  assert(rule, `Rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  const matched = rule.pattern.test(code);
  assert.strictEqual(matched, shouldMatch,
    `${ruleId} ${shouldMatch ? "should match" : "should NOT match"}: ${code.substring(0, 60)}`);
}

describe("Core Rules", () => {
  describe("VG001 - Hardcoded credentials", () => {
    it("detects hardcoded password", () => {
      testRule("VG001", 'const password = "hunter2"', "javascript", true);
    });
    it("detects JWT_SECRET", () => {
      testRule("VG001", 'const JWT_SECRET = "my-super-secret-jwt-key"', "javascript", true);
    });
    it("detects APP_SECRET", () => {
      testRule("VG001", "APP_SECRET = 'long-secret-value-here'", "python", true);
    });
    it("detects SIGNING_KEY", () => {
      testRule("VG001", 'const SIGNING_KEY = "abc123def456"', "javascript", true);
    });
    it("ignores env var usage", () => {
      testRule("VG001", "const password = process.env.PASSWORD", "javascript", false);
    });
  });

  describe("VG003 - Cloud API keys", () => {
    it("detects AWS key", () => {
      testRule("VG003", "const key = 'AKIAIOSFODNN7EXAMPLE'", "javascript", true);
    });
    it("detects GitHub token", () => {
      testRule("VG003", "const token = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn'", "javascript", true);
    });
    it("detects short Stripe live key", () => {
      testRule("VG003", 'const stripe = new Stripe("sk_live_abc123")', "javascript", true);
    });
    it("detects long Stripe live key", () => {
      const fakeKey = "sk_" + "live_51Oj" + "KEBsFakeKeyHere";
      testRule("VG003", `const key = "${fakeKey}"`, "javascript", true);
    });
    it("detects Stripe restricted key", () => {
      testRule("VG003", 'const key = "rk_live_51OjKEBs2kFE"', "javascript", true);
    });
  });

  describe("VG010 - SQL injection", () => {
    it("detects template literal in query", () => {
      testRule("VG010", "db.query(`SELECT * FROM users WHERE id = ${userId}`)", "javascript", true);
    });
    it("ignores parameterized query", () => {
      testRule("VG010", 'db.query("SELECT * FROM users WHERE id = $1", [userId])', "javascript", false);
    });
  });

  describe("VG014 - eval / dynamic code execution", () => {
    it("detects eval call", () => {
      testRule("VG014", "eval(userInput)", "javascript", true);
    });
    it("detects new Function constructor", () => {
      testRule("VG014", "const fn = new Function(userInput)", "javascript", true);
    });
    it("detects Python eval", () => {
      testRule("VG014", "result = eval(expr)", "python", true);
    });
  });

  describe("VG060 - Weak hashing", () => {
    it("detects md5", () => {
      testRule("VG060", 'createHash("md5")', "javascript", true);
    });
    it("detects Python hashlib.md5", () => {
      testRule("VG060", "hashlib.md5(password.encode())", "python", true);
    });
    it("detects Python hashlib.sha1", () => {
      testRule("VG060", "hashlib.sha1(data)", "python", true);
    });
    it("ignores sha256", () => {
      testRule("VG060", 'createHash("sha256")', "javascript", false);
    });
  });

  describe("VG062 - Hardcoded secret in variable", () => {
    it("detects const secret with string literal", () => {
      testRule("VG062", 'const secret = "mysupersecretkey123"', "javascript", true);
    });
    it("detects const password with long value", () => {
      testRule("VG062", 'const password = "hunter2hunter2"', "javascript", true);
    });
    it("detects const apiKey assignment", () => {
      testRule("VG062", 'const apiKey = "abcdef1234567890"', "typescript", true);
    });
    it("detects let privateKey assignment", () => {
      testRule("VG062", 'let privateKey = "long-private-key-value-here"', "javascript", true);
    });
    it("detects Python password assignment", () => {
      testRule("VG062", 'password = "mysecretpassword123"', "python", true);
    });
    it("detects dbPassword assignment", () => {
      testRule("VG062", 'const dbPassword = "postgres_pass_123"', "typescript", true);
    });
    it("ignores env variable usage", () => {
      testRule("VG062", "const secret = process.env.SECRET", "javascript", false);
    });
    it("ignores short values (likely placeholders)", () => {
      testRule("VG062", 'const secret = "short"', "javascript", false);
    });
  });

  describe("VG104 - CORS Origin Reflection", () => {
    it("detects origin header reflection via assignment", () => {
      testRule("VG104", "Access-Control-Allow-Origin = req.headers.origin", "javascript", true);
    });
    it("detects reflecting via req.header('origin')", () => {
      testRule("VG104", "origin: req.header('origin')", "javascript", true);
    });
    it("ignores static origin value", () => {
      testRule("VG104", "origin: 'https://myapp.com'", "javascript", false);
    });
  });

  describe("VG105 - JWT Algorithm None Attack", () => {
    it("detects jwt.verify without algorithms option", () => {
      testRule("VG105", "jwt.verify(token, secret)", "javascript", true);
    });
    it("detects algorithms with none allowed", () => {
      testRule("VG105", 'jwt.verify(token, secret, { algorithms: ["none"] })', "javascript", true);
    });
    it("ignores jwt.verify with explicit algorithms", () => {
      testRule("VG105", 'jwt.verify(token, secret, { algorithms: ["HS256"] })', "javascript", false);
    });
  });

  describe("VG106 - Timing-Unsafe Secret Comparison", () => {
    it("detects token === comparison", () => {
      testRule("VG106", 'if (token === expectedToken)', "javascript", true);
    });
    it("detects secret !== comparison", () => {
      testRule("VG106", 'if (secret !== storedSecret)', "javascript", true);
    });
    it("detects apiKey == comparison", () => {
      testRule("VG106", 'if (apiKey == providedKey)', "javascript", true);
    });
    it("ignores non-secret comparison", () => {
      testRule("VG106", 'if (name === "admin")', "javascript", false);
    });
  });

  describe("VG107 - ReDoS via User-Controlled RegExp", () => {
    it("detects new RegExp with req.query", () => {
      testRule("VG107", "const re = new RegExp(req.query.search)", "javascript", true);
    });
    it("detects new RegExp with userInput", () => {
      testRule("VG107", "const re = new RegExp(userInput)", "javascript", true);
    });
    it("ignores new RegExp with static string", () => {
      testRule("VG107", 'const re = new RegExp("^[a-z]+$")', "javascript", false);
    });
  });
});
