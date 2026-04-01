import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { terraformRules } from "../../src/data/rules/terraform.js";

function testRule(ruleId: string, code: string, shouldMatch: boolean) {
  const rule = terraformRules.find(r => r.id === ruleId);
  assert(rule, `Rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  const matched = rule.pattern.test(code);
  assert.strictEqual(matched, shouldMatch,
    `${ruleId} ${shouldMatch ? "should match" : "should NOT match"}: ${code.substring(0, 60)}`);
}

describe("Terraform Rules", () => {
  it("VG300: detects public S3 ACL", () => {
    testRule("VG300", 'acl = "public-read"', true);
  });
  it("VG301: detects open security group", () => {
    testRule("VG301", 'cidr_blocks = ["0.0.0.0/0"]', true);
  });
  it("VG301: ignores restricted CIDR", () => {
    testRule("VG301", 'cidr_blocks = ["10.0.0.0/8"]', false);
  });
  it("VG303: detects IAM wildcard action", () => {
    testRule("VG303", 'Action = "*"', true);
  });
  it("VG304: detects hardcoded password", () => {
    testRule("VG304", 'password = "SuperSecret123!"', true);
  });

  describe("VG305 - Terraform State File Tracked in Git", () => {
    it("detects terraform.tfstate reference", () => {
      testRule("VG305", "terraform.tfstate", true);
    });
    it("detects .tfstate file reference", () => {
      testRule("VG305", "backup.tfstate", true);
    });
    it("ignores terraform.tf file", () => {
      testRule("VG305", "main.tf", false);
    });
  });
});
