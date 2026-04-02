import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { deploymentRules } from "../../src/data/rules/deployment.js";

function testRule(ruleId: string, code: string, shouldMatch: boolean) {
  const rule = deploymentRules.find((r) => r.id === ruleId);
  assert(rule, `Rule ${ruleId} not found`);
  rule.pattern.lastIndex = 0;
  const matched = rule.pattern.test(code);
  assert.strictEqual(
    matched,
    shouldMatch,
    `${ruleId} ${shouldMatch ? "should match" : "should NOT match"}: ${code.substring(0, 80)}`
  );
}

describe("Deployment Config Rules", () => {
  it("VG500: detects CORS wildcard in vercel.json headers", () => {
    testRule("VG500", '"headers": [{ "key": "Access-Control-Allow-Origin", "value": "*" }]', true);
  });
  it("VG503: detects crons config", () => {
    testRule("VG503", '"crons": [{ "path": "/api/cleanup", "schedule": "0 * * * *" }]', true);
  });
  it("VG506: detects hardcoded secret in vercel.json", () => {
    testRule("VG506", '"env": { "SECRET_KEY": "sk_live_abc123def456" }', true);
  });
  it("VG507: detects wildcard remote image pattern", () => {
    testRule("VG507", 'remotePatterns: [{ hostname: "**" }]', true);
  });
  it("VG509: detects poweredByHeader not disabled", () => {
    testRule("VG509", "poweredByHeader: true", true);
  });
  it("VG515: detects privileged container", () => {
    testRule("VG515", "privileged: true", true);
  });
  it("VG514: detects hardcoded secret in docker-compose env", () => {
    testRule("VG514", "environment:\n  - SECRET_KEY=mysecretvalue123", true);
  });
  it("VG517: detects secret in fly.toml env", () => {
    testRule("VG517", '[env]\nSECRET_KEY = "hardcoded_value"', true);
  });

  describe("VG521 - Kubernetes Privileged Container", () => {
    it("detects privileged: true in securityContext", () => {
      testRule("VG521", "securityContext:\n  privileged: true", true);
    });
    it("ignores privileged: false", () => {
      testRule("VG521", "securityContext:\n  privileged: false", false);
    });
  });

  describe("VG522 - Kubernetes Secrets in ConfigMap", () => {
    it("detects password in ConfigMap", () => {
      testRule("VG522", "kind: ConfigMap\nmetadata:\n  name: app-config\ndata:\n  password: s3cret123", true);
    });
    it("detects api-key in ConfigMap", () => {
      testRule("VG522", "kind: ConfigMap\nmetadata:\n  name: app-config\ndata:\n  api-key: abc123def456", true);
    });
    it("ignores ConfigMap with non-sensitive data", () => {
      testRule("VG522", "kind: ConfigMap\nmetadata:\n  name: app-config\ndata:\n  log-level: info", false);
    });
  });

  describe("VG523 - Kubernetes Host Namespace Sharing", () => {
    it("detects hostNetwork: true", () => {
      testRule("VG523", "hostNetwork: true", true);
    });
    it("detects hostPID: true", () => {
      testRule("VG523", "hostPID: true", true);
    });
    it("detects hostIPC: true", () => {
      testRule("VG523", "hostIPC: true", true);
    });
    it("ignores hostNetwork: false", () => {
      testRule("VG523", "hostNetwork: false", false);
    });
  });

  describe("VG524 - Data URL or Blob URL in User-Controlled src/href", () => {
    it("detects data: URL in src attribute", () => {
      testRule("VG524", `<img src={"data:" + userContent} />`, true);
    });
    it("detects javascript: URL in href attribute", () => {
      testRule("VG524", `<a href={"javascript:" + payload} />`, true);
    });
    it("ignores relative path in src", () => {
      testRule("VG524", `<img src={"/images/" + filename} />`, false);
    });
    it("ignores static src attribute", () => {
      testRule("VG524", `<img src="/images/logo.png" />`, false);
    });
  });
});
