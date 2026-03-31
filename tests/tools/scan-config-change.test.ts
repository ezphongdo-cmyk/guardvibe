import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { scanConfigChange } from "../../src/tools/scan-config-change.js";

describe("scan_config_change", () => {
  it("detects CORS wildcard introduction", () => {
    const before = '{ "headers": [{ "key": "Access-Control-Allow-Origin", "value": "https://app.com" }] }';
    const after = '{ "headers": [{ "key": "Access-Control-Allow-Origin", "value": "*" }] }';
    const r = JSON.parse(scanConfigChange(before, after, "vercel.json"));
    assert(r.summary.total > 0);
    assert(r.findings.some((f: any) => f.category === "cors"));
  });

  it("detects HSTS removal", () => {
    const before = 'headers: [{ key: "Strict-Transport-Security", value: "max-age=63072000" }]';
    const after = 'headers: [{ key: "X-Frame-Options", value: "DENY" }]';
    const r = JSON.parse(scanConfigChange(before, after));
    assert(r.findings.some((f: any) => f.title.includes("HSTS")));
  });

  it("detects debug mode enabled", () => {
    const before = "debug: false";
    const after = "debug: true";
    const r = JSON.parse(scanConfigChange(before, after));
    assert(r.findings.some((f: any) => f.category === "debug"));
  });

  it("detects TLS weakening", () => {
    const before = "rejectUnauthorized: true";
    const after = "rejectUnauthorized: false";
    const r = JSON.parse(scanConfigChange(before, after));
    assert(r.findings.some((f: any) => f.category === "tls"));
  });

  it("detects new hardcoded secret", () => {
    const before = "{}";
    const after = 'SECRET_KEY: "abcdef123456789012"';
    const r = JSON.parse(scanConfigChange(before, after));
    assert(r.findings.some((f: any) => f.category === "secrets"));
  });

  it("detects removed security header", () => {
    const before = '{ "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff" }';
    const after = '{ "X-Content-Type-Options": "nosniff" }';
    const r = JSON.parse(scanConfigChange(before, after));
    assert(r.findings.some((f: any) => f.title.includes("X-Frame-Options")));
  });

  it("returns clean when no downgrade", () => {
    const before = "debug: false";
    const after = "debug: false";
    const r = JSON.parse(scanConfigChange(before, after));
    assert(r.summary.total === 0);
  });

  it("detects privileged container", () => {
    const before = "privileged: false";
    const after = "privileged: true";
    const r = JSON.parse(scanConfigChange(before, after));
    assert(r.findings.some((f: any) => f.category === "docker"));
  });

  it("markdown format works", () => {
    const r = scanConfigChange("debug: false", "debug: true", "config.ts", "markdown");
    assert(r.includes("Config Change Analysis"));
  });
});
