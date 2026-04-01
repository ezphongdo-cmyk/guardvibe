import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { dockerfileRules } from "../../src/data/rules/dockerfile.js";

function testRule(ruleId: string, code: string, shouldMatch: boolean) {
  const rule = dockerfileRules.find(r => r.id === ruleId);
  assert(rule, `Rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  const matched = rule.pattern.test(code);
  assert.strictEqual(matched, shouldMatch,
    `${ruleId} ${shouldMatch ? "should match" : "should NOT match"}: ${code.substring(0, 60)}`);
}

describe("Dockerfile Rules", () => {
  it("VG202: detects latest tag", () => {
    testRule("VG202", "FROM node:latest ", true);
  });
  it("VG203: detects secrets in ENV", () => {
    testRule("VG203", "ENV SECRET_KEY=mysecret123", true);
  });
  it("VG204: detects ADD for local files", () => {
    testRule("VG204", "ADD ./src /app/src", true);
  });

  describe("VG205 - Docker Socket Mount", () => {
    it("detects -v docker socket mount", () => {
      testRule("VG205", "-v /var/run/docker.sock:/var/run/docker.sock", true);
    });
    it("detects --volume docker socket mount", () => {
      testRule("VG205", "--volume /var/run/docker.sock:/var/run/docker.sock", true);
    });
    it("detects docker-compose volumes socket mount", () => {
      testRule("VG205", "volumes: /var/run/docker.sock:/var/run/docker.sock", true);
    });
    it("ignores normal volume mount", () => {
      testRule("VG205", "-v /data/app:/app/data", false);
    });
  });

  describe("VG206 - Dockerfile Missing HEALTHCHECK", () => {
    it("detects Dockerfile with CMD but no HEALTHCHECK", () => {
      testRule("VG206", 'FROM node:20-alpine\nRUN npm install\nCMD ["node", "server.js"]', true);
    });
    it("detects Dockerfile with ENTRYPOINT but no HEALTHCHECK", () => {
      testRule("VG206", 'FROM node:20-alpine\nRUN npm install\nENTRYPOINT ["node", "server.js"]', true);
    });
    it("ignores Dockerfile without CMD or ENTRYPOINT", () => {
      testRule("VG206", "FROM node:20-alpine\nRUN npm install\nEXPOSE 3000", false);
    });
  });
});
