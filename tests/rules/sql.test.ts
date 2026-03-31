import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { sqlRules } from "../../src/data/rules/sql.js";

function testRule(ruleId: string, code: string, shouldMatch: boolean) {
  const rule = sqlRules.find(r => r.id === ruleId);
  assert(rule, `Rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  const matched = rule.pattern.test(code);
  assert.strictEqual(matched, shouldMatch,
    `${ruleId} ${shouldMatch ? "should match" : "should NOT match"}: ${code.substring(0, 80)}`);
}

describe("SQL Rules", () => {
  describe("VG540 - Destructive DDL", () => {
    it("detects DROP TABLE", () => {
      testRule("VG540", "DROP TABLE users;", true);
    });
    it("detects DROP DATABASE", () => {
      testRule("VG540", "DROP DATABASE production;", true);
    });
    it("detects DROP TABLE IF EXISTS", () => {
      testRule("VG540", "DROP TABLE IF EXISTS sessions;", true);
    });
    it("ignores SELECT", () => {
      testRule("VG540", "SELECT * FROM users;", false);
    });
    it("ignores CREATE TABLE", () => {
      testRule("VG540", "CREATE TABLE users (id INT);", false);
    });
  });

  describe("VG541 - Dangerous GRANT", () => {
    it("detects GRANT ALL PRIVILEGES ON *.*", () => {
      testRule("VG541", "GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%';", true);
    });
    it("detects GRANT ALL ON schema", () => {
      testRule("VG541", "GRANT ALL ON public.users TO app_user;", true);
    });
    it("ignores specific grants", () => {
      testRule("VG541", "GRANT SELECT, INSERT ON users TO app_role;", false);
    });
    it("ignores REVOKE", () => {
      testRule("VG541", "REVOKE ALL PRIVILEGES ON *.* FROM 'user'@'%';", false);
    });
  });

  describe("VG542 - DELETE/UPDATE without WHERE", () => {
    it("detects DELETE FROM without WHERE", () => {
      testRule("VG542", "DELETE FROM users;", true);
    });
    it("detects UPDATE without WHERE", () => {
      testRule("VG542", "UPDATE users SET role = 'admin';", true);
    });
    it("ignores DELETE with WHERE", () => {
      testRule("VG542", "DELETE FROM users WHERE id = 1;", false);
    });
    it("ignores UPDATE with WHERE", () => {
      testRule("VG542", "UPDATE users SET role = 'admin' WHERE id = 1;", false);
    });
  });

  describe("VG543 - Stacked queries", () => {
    it("detects stacked DROP", () => {
      testRule("VG543", "SELECT * FROM users WHERE id = 1; DROP TABLE users;", true);
    });
    it("detects stacked INSERT", () => {
      testRule("VG543", "SELECT 1; INSERT INTO admins VALUES ('hacker');", true);
    });
    it("detects stacked UNION", () => {
      testRule("VG543", "SELECT * FROM x; UNION SELECT password FROM users", true);
    });
    it("ignores single SELECT", () => {
      testRule("VG543", "SELECT * FROM users WHERE id = 1;", false);
    });
  });
});
