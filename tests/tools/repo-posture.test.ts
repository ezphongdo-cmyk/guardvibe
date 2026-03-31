import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { repoSecurityPosture } from "../../src/tools/repo-posture.js";

const tempDirs: string[] = [];
function tmp() { const d = mkdtempSync(join(tmpdir(), "gv-post-")); tempDirs.push(d); return d; }

describe("repo_security_posture", () => {
  afterEach(() => { while (tempDirs.length) rmSync(tempDirs.pop()!, { recursive: true, force: true }); });

  it("detects auth surface", () => {
    const d = tmp();
    writeFileSync(join(d, "package.json"), JSON.stringify({ dependencies: { "@clerk/nextjs": "5.0.0" } }));
    mkdirSync(join(d, "src", "auth"), { recursive: true });
    writeFileSync(join(d, "src", "auth", "login.ts"), "export function login() {}");
    const r = JSON.parse(repoSecurityPosture(d, "json"));
    assert(r.sensitiveAreas.some((a: any) => a.name === "Authentication"));
  });

  it("detects payment surface", () => {
    const d = tmp();
    writeFileSync(join(d, "package.json"), JSON.stringify({ dependencies: { stripe: "14.0.0" } }));
    mkdirSync(join(d, "src"), { recursive: true });
    writeFileSync(join(d, "src", "stripe-webhook.ts"), "export function webhook() {}");
    const r = JSON.parse(repoSecurityPosture(d, "json"));
    assert(r.sensitiveAreas.some((a: any) => a.name === "Payments"));
  });

  it("returns risk profile", () => {
    const d = tmp();
    writeFileSync(join(d, "package.json"), JSON.stringify({ dependencies: {} }));
    const r = JSON.parse(repoSecurityPosture(d, "json"));
    assert(["critical", "high", "medium", "low"].includes(r.riskProfile));
  });

  it("markdown format works", () => {
    const d = tmp();
    writeFileSync(join(d, "package.json"), JSON.stringify({ dependencies: {} }));
    const r = repoSecurityPosture(d, "markdown");
    assert(r.includes("Security Posture"));
  });
});
