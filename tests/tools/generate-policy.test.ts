import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { generatePolicy } from "../../src/tools/generate-policy.js";

const tempDirs: string[] = [];

function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "gv-policy-"));
  tempDirs.push(dir);
  return dir;
}

function writePackageJson(dir: string, deps: Record<string, string> = {}, devDeps: Record<string, string> = {}): void {
  writeFileSync(join(dir, "package.json"), JSON.stringify({
    name: "test-project",
    dependencies: deps,
    devDependencies: devDeps,
  }));
}

describe("generate_policy", () => {
  afterEach(() => {
    while (tempDirs.length > 0) {
      rmSync(tempDirs.pop()!, { recursive: true, force: true });
    }
  });

  it("detects Next.js framework", () => {
    const dir = createTempDir();
    writePackageJson(dir, { next: "14.0.0", react: "18.0.0" });
    const result = generatePolicy(dir);
    assert(result.includes("nextjs"), "Should detect Next.js");
  });

  it("detects Supabase and generates RLS suggestions", () => {
    const dir = createTempDir();
    writePackageJson(dir, { "@supabase/supabase-js": "2.0.0", next: "14.0.0" });
    const result = generatePolicy(dir);
    assert(result.includes("supabase"), "Should detect Supabase");
    assert(result.includes("Row-Level Security"), "Should include RLS suggestions");
    assert(result.includes("ENABLE ROW LEVEL SECURITY"), "Should include RLS SQL");
  });

  it("detects Stripe and includes in CSP/CORS", () => {
    const dir = createTempDir();
    writePackageJson(dir, { stripe: "14.0.0", next: "14.0.0" });
    const result = generatePolicy(dir);
    assert(result.includes("stripe"), "Should detect Stripe");
    assert(result.includes("js.stripe.com"), "CSP should include Stripe");
  });

  it("detects Clerk auth and includes in CSP", () => {
    const dir = createTempDir();
    writePackageJson(dir, { "@clerk/nextjs": "5.0.0", next: "14.0.0" });
    const result = generatePolicy(dir);
    assert(result.includes("clerk"), "Should detect Clerk");
    assert(result.includes("clerk.accounts.dev"), "CSP should include Clerk");
  });

  it("detects AI providers and adjusts rate limiting", () => {
    const dir = createTempDir();
    writePackageJson(dir, { openai: "4.0.0", next: "14.0.0" });
    const result = generatePolicy(dir);
    assert(result.includes("openai"), "Should detect OpenAI");
    assert(result.includes("api.openai.com"), "CSP connect-src should include OpenAI");
    assert(result.includes("20 req"), "AI projects should have lower API rate limit");
  });

  it("detects Vercel Blob storage and includes in CSP", () => {
    const dir = createTempDir();
    writePackageJson(dir, { "@vercel/blob": "1.0.0", next: "14.0.0" });
    const result = generatePolicy(dir);
    assert(result.includes("vercel-blob"), "Should detect Vercel Blob");
    assert(result.includes("blob.vercel-storage.com"), "CSP should include Blob URL");
  });

  it("detects PostHog analytics", () => {
    const dir = createTempDir();
    writePackageJson(dir, { "posthog-js": "1.0.0", next: "14.0.0" });
    const result = generatePolicy(dir);
    assert(result.includes("posthog"), "Should detect PostHog");
    assert(result.includes("posthog.com"), "CSP should include PostHog");
  });

  it("detects Sentry", () => {
    const dir = createTempDir();
    writePackageJson(dir, { "@sentry/nextjs": "8.0.0", next: "14.0.0" });
    const result = generatePolicy(dir);
    assert(result.includes("sentry"), "Should detect Sentry");
    assert(result.includes("sentry.io"), "CSP should include Sentry");
  });

  it("generates Upstash rate limit code when Upstash is detected", () => {
    const dir = createTempDir();
    writePackageJson(dir, { "@upstash/redis": "1.0.0", "@upstash/ratelimit": "1.0.0", next: "14.0.0" });
    const result = generatePolicy(dir);
    assert(result.includes("upstash-redis"), "Should detect Upstash");
    assert(result.includes("Ratelimit"), "Should include Upstash rate limit code");
  });

  it("generates valid JSON output", () => {
    const dir = createTempDir();
    writePackageJson(dir, { next: "14.0.0", stripe: "14.0.0", "@supabase/supabase-js": "2.0.0" });
    const result = generatePolicy(dir, "json");
    const parsed = JSON.parse(result);
    assert(typeof parsed.stack === "object");
    assert(typeof parsed.csp === "string");
    assert(typeof parsed.cors === "object");
    assert(Array.isArray(parsed.rls));
    assert(typeof parsed.rateLimiting === "object");
    assert(Array.isArray(parsed.headers));
  });

  it("includes essential security headers", () => {
    const dir = createTempDir();
    writePackageJson(dir, { next: "14.0.0" });
    const result = generatePolicy(dir);
    assert(result.includes("Strict-Transport-Security"));
    assert(result.includes("X-Frame-Options"));
    assert(result.includes("X-Content-Type-Options"));
    assert(result.includes("Referrer-Policy"));
    assert(result.includes("Permissions-Policy"));
  });

  it("CSP includes essential directives", () => {
    const dir = createTempDir();
    writePackageJson(dir, { next: "14.0.0" });
    const result = generatePolicy(dir, "json");
    const parsed = JSON.parse(result);
    assert(parsed.csp.includes("default-src"));
    assert(parsed.csp.includes("script-src"));
    assert(parsed.csp.includes("object-src 'none'"));
    assert(parsed.csp.includes("frame-ancestors 'none'"));
  });

  it("detects Sanity CMS and includes CDN in CSP", () => {
    const dir = createTempDir();
    writePackageJson(dir, { "@sanity/client": "6.0.0", next: "14.0.0" });
    const result = generatePolicy(dir);
    assert(result.includes("sanity"), "Should detect Sanity");
    assert(result.includes("cdn.sanity.io"), "CSP should include Sanity CDN");
  });

  it("detects Cloudinary storage", () => {
    const dir = createTempDir();
    writePackageJson(dir, { cloudinary: "2.0.0", next: "14.0.0" });
    const result = generatePolicy(dir);
    assert(result.includes("cloudinary"), "Should detect Cloudinary");
    assert(result.includes("res.cloudinary.com"), "CSP should include Cloudinary");
  });

  it("works with empty project (no package.json)", () => {
    const dir = createTempDir();
    const result = generatePolicy(dir);
    assert(result.includes("unknown"), "Framework should be unknown");
    assert(result.includes("Content-Security-Policy"), "Should still generate CSP");
  });

  it("generates ORM-level RLS suggestions for Prisma without Supabase", () => {
    const dir = createTempDir();
    writePackageJson(dir, { prisma: "5.0.0", "@prisma/client": "5.0.0", next: "14.0.0" });
    const result = generatePolicy(dir);
    assert(result.includes("ORM-level"), "Should suggest ORM-level access control");
  });

  it("detects Supabase subscription RLS when payments present", () => {
    const dir = createTempDir();
    writePackageJson(dir, { "@supabase/supabase-js": "2.0.0", stripe: "14.0.0", next: "14.0.0" });
    const result = generatePolicy(dir);
    assert(result.includes("subscriptions"), "Should include subscription RLS when Stripe + Supabase");
  });
});
