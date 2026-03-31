import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { auditConfig } from "../../src/tools/audit-config.js";

const tempDirs: string[] = [];

function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "gv-audit-"));
  tempDirs.push(dir);
  return dir;
}

describe("audit_config", () => {
  afterEach(() => {
    while (tempDirs.length > 0) {
      rmSync(tempDirs.pop()!, { recursive: true, force: true });
    }
  });

  it("returns clean report when no config files exist", () => {
    const dir = createTempDir();
    const result = auditConfig(dir);
    assert(result.includes("No Issues Found"));
  });

  it("detects missing CSP when headers() exists without CSP", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "next.config.ts"), `
      export default {
        async headers() {
          return [{
            source: "/(.*)",
            headers: [
              { key: "X-Frame-Options", value: "DENY" },
            ]
          }];
        }
      };
    `);
    const result = auditConfig(dir);
    assert(result.includes("AC001"), "Should detect missing CSP");
    assert(result.includes("Content-Security-Policy"));
  });

  it("detects missing HSTS when headers() exists without HSTS", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "next.config.mjs"), `
      export default {
        async headers() {
          return [{
            source: "/(.*)",
            headers: [
              { key: "Content-Security-Policy", value: "default-src 'self'" },
            ]
          }];
        }
      };
    `);
    const result = auditConfig(dir);
    assert(result.includes("AC002"), "Should detect missing HSTS");
  });

  it("detects no headers() function at all", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "next.config.js"), `module.exports = { reactStrictMode: true };`);
    const result = auditConfig(dir);
    assert(result.includes("AC005"), "Should detect missing headers()");
  });

  it("detects middleware without auth", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "next.config.ts"), `export default {};`);
    writeFileSync(join(dir, "middleware.ts"), `
      import { NextResponse } from 'next/server';
      export function middleware(request) {
        return NextResponse.next();
      }
      export const config = { matcher: ["/dashboard/:path*"] };
    `);
    const result = auditConfig(dir);
    assert(result.includes("AC010"), "Should detect middleware without auth");
  });

  it("detects Next.js project without middleware", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "next.config.ts"), `export default {};`);
    const result = auditConfig(dir);
    assert(result.includes("AC012"), "Should detect missing middleware");
  });

  it("detects .env not in .gitignore", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, ".env"), `DATABASE_URL=postgres://localhost/db`);
    writeFileSync(join(dir, ".gitignore"), `node_modules\n`);
    const result = auditConfig(dir);
    assert(result.includes("AC020"), "Should detect .env not in .gitignore");
  });

  it("does not flag .env when .gitignore covers it", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, ".env"), `DATABASE_URL=postgres://localhost/db`);
    writeFileSync(join(dir, ".gitignore"), `.env\nnode_modules\n`);
    const result = auditConfig(dir);
    assert(!result.includes("AC020"), "Should not flag when .gitignore covers .env");
  });

  it("detects NEXT_PUBLIC_ secret exposure in .env", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, ".env"), `NEXT_PUBLIC_SECRET_KEY=abc123\n`);
    writeFileSync(join(dir, ".gitignore"), `.env\n`);
    const result = auditConfig(dir);
    assert(result.includes("AC021"), "Should detect NEXT_PUBLIC_ secret");
  });

  it("does not flag NEXT_PUBLIC_PUBLISHABLE_KEY", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, ".env"), `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_test_123\n`);
    writeFileSync(join(dir, ".gitignore"), `.env\n`);
    const result = auditConfig(dir);
    assert(!result.includes("AC021"), "Should not flag publishable key");
  });

  it("detects real secrets in .env.example", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, ".env.example"), `STRIPE_SECRET_KEY=sk_live_abcdefghijklmnop\n`);
    writeFileSync(join(dir, ".gitignore"), `.env\n`);
    const result = auditConfig(dir);
    assert(result.includes("AC022"), "Should detect real secrets in .env.example");
  });

  it("detects cron endpoint without CRON_SECRET verification", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "vercel.json"), JSON.stringify({
      crons: [{ path: "/api/cron/cleanup", schedule: "0 0 * * *" }]
    }));
    mkdirSync(join(dir, "app", "api", "cron", "cleanup"), { recursive: true });
    writeFileSync(join(dir, "app", "api", "cron", "cleanup", "route.ts"), `
      export async function GET() {
        await cleanupOldData();
        return Response.json({ ok: true });
      }
    `);
    const result = auditConfig(dir);
    assert(result.includes("AC030"), "Should detect cron without CRON_SECRET");
  });

  it("does not flag cron endpoint that checks CRON_SECRET", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "vercel.json"), JSON.stringify({
      crons: [{ path: "/api/cron/cleanup", schedule: "0 0 * * *" }]
    }));
    mkdirSync(join(dir, "app", "api", "cron", "cleanup"), { recursive: true });
    writeFileSync(join(dir, "app", "api", "cron", "cleanup", "route.ts"), `
      export async function GET(request: Request) {
        const auth = request.headers.get("authorization");
        if (auth !== \`Bearer \${process.env.CRON_SECRET}\`) {
          return new Response("Unauthorized", { status: 401 });
        }
        await cleanupOldData();
        return Response.json({ ok: true });
      }
    `);
    const result = auditConfig(dir);
    assert(!result.includes("AC030"), "Should not flag cron with CRON_SECRET");
  });

  it("detects route handlers without auth when no middleware", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "next.config.ts"), `export default {};`);
    mkdirSync(join(dir, "app", "api", "users"), { recursive: true });
    writeFileSync(join(dir, "app", "api", "users", "route.ts"), `
      export async function GET() {
        const users = await db.user.findMany();
        return Response.json(users);
      }
    `);
    const result = auditConfig(dir);
    assert(result.includes("AC040"), "Should detect unauthed route handlers");
  });

  it("detects poweredByHeader: true", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "next.config.ts"), `export default { poweredByHeader: true };`);
    const result = auditConfig(dir);
    assert(result.includes("AC050"));
  });

  it("detects productionBrowserSourceMaps: true", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "next.config.ts"), `export default { productionBrowserSourceMaps: true };`);
    const result = auditConfig(dir);
    assert(result.includes("AC051"));
  });

  it("JSON format returns valid JSON with summary", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "next.config.ts"), `export default { poweredByHeader: true };`);
    const result = auditConfig(dir, "json");
    const parsed = JSON.parse(result);
    assert(typeof parsed.summary === "object");
    assert(typeof parsed.summary.total === "number");
    assert(Array.isArray(parsed.issues));
  });

  it("detects wildcard remote image pattern", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "next.config.ts"), `
      export default {
        images: {
          remotePatterns: [{ hostname: "**" }]
        }
      };
    `);
    const result = auditConfig(dir);
    assert(result.includes("AC052"));
  });

  it("detects hardcoded secret in vercel.json", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "vercel.json"), JSON.stringify({
      env: { "SECRET_KEY": "abcdefghijklmnop" }
    }));
    const result = auditConfig(dir);
    assert(result.includes("AC031"), "Should detect hardcoded secret in vercel.json");
  });
});
