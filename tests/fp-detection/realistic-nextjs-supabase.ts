/**
 * False Positive Detection Test
 *
 * This file contains SAFE code patterns from a real Next.js + Supabase project.
 * GuardVibe should NOT flag any of these. If it does, it's a false positive.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeCode } from "../../src/tools/check-code.js";

// ============================================================
// SAFE CODE SAMPLES — should produce ZERO findings
// ============================================================

const safeServerComponent = `
// app/dashboard/page.tsx — Server Component (no 'use client')
import { createClient } from "@/utils/supabase/server";
import { redirect } from "next/navigation";

export default async function DashboardPage() {
  const supabase = await createClient();
  const { data: { user }, error } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const { data: posts } = await supabase
    .from("posts")
    .select("id, title, created_at")
    .eq("user_id", user.id);

  return (
    <div>
      <h1>Dashboard</h1>
      {posts?.map(post => <div key={post.id}>{post.title}</div>)}
    </div>
  );
}
`;

const safeServerAction = `
"use server";
import { z } from "zod";
import { auth } from "@clerk/nextjs/server";
import { revalidatePath } from "next/cache";

const createPostSchema = z.object({
  title: z.string().min(1).max(200),
  content: z.string().min(1),
});

export async function createPost(formData: FormData) {
  const { userId } = await auth();
  if (!userId) throw new Error("Unauthorized");

  const data = createPostSchema.parse({
    title: formData.get("title"),
    content: formData.get("content"),
  });

  await db.post.create({ data: { ...data, userId } });
  revalidatePath("/dashboard");
}
`;

const safeRouteHandler = `
// app/api/posts/route.ts
import { auth } from "@clerk/nextjs/server";
import { NextResponse } from "next/server";

export async function GET() {
  const { userId } = await auth();
  if (!userId) return new Response("Unauthorized", { status: 401 });

  const posts = await prisma.post.findMany({
    where: { userId },
    select: { id: true, title: true, createdAt: true },
  });

  return NextResponse.json(posts);
}

export async function POST(request: Request) {
  const { userId } = await auth();
  if (!userId) return new Response("Unauthorized", { status: 401 });

  const body = await request.json();
  const post = await prisma.post.create({ data: { ...body, userId } });
  return NextResponse.json(post, { status: 201 });
}
`;

const safeEnvUsage = `
// lib/supabase/server.ts
import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";

export async function createClient() {
  const cookieStore = await cookies();
  return createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll: () => cookieStore.getAll(),
        setAll: (c) => c.forEach(({ name, value, options }) =>
          cookieStore.set(name, value, options)
        ),
      },
    }
  );
}
`;

const safeMiddleware = `
// middleware.ts
import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

export async function middleware(request: NextRequest) {
  const response = NextResponse.next({ request });
  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll: () => request.cookies.getAll(),
        setAll: (cookies) => cookies.forEach(({ name, value, options }) =>
          response.cookies.set(name, value, options)
        ),
      },
    }
  );
  await supabase.auth.getUser();
  return response;
}

export const config = {
  matcher: ["/dashboard/:path*", "/api/:path*"],
};
`;

const safeCommentWithPatterns = `
// This module handles password reset flow
// Previously we used: const password = "hardcoded"; // this was the old insecure way
// Now we use environment variables for all secrets
// See: https://docs.example.com/auth/api_key_rotation

/**
 * Security notes:
 * - Always use parameterized queries: db.query('SELECT * FROM users WHERE id = $1', [id])
 * - Don't set innerHTML directly
 * - Avoid CORS wildcard: Access-Control-Allow-Origin: *
 */
export function resetPassword(userId: string) {
  // Implementation uses proper env vars
  const secret = process.env.RESET_SECRET;
  return { success: true };
}
`;

const safeFixCodeExample = `
// Example from security documentation:
// BAD:  const apiKey = "sk-12345678901234567890"
// GOOD: const apiKey = process.env.API_KEY
//
// BAD:  db.query(\\\`SELECT * FROM users WHERE id = \\\${userId}\\\`)
// GOOD: db.query('SELECT * FROM users WHERE id = $1', [userId])

export function getConfig() {
  return {
    apiKey: process.env.API_KEY,
    dbUrl: process.env.DATABASE_URL,
  };
}
`;

const safeExpressWithHelmet = `
import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

const app = express();
app.use(helmet());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});
`;

const safeNextConfig = `
// next.config.ts
const nextConfig = {
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Strict-Transport-Security", value: "max-age=63072000" },
        ],
      },
    ];
  },
};
export default nextConfig;
`;

const safeTypescriptTypes = `
// types/auth.ts — just type definitions, no runtime code
interface AuthConfig {
  secret: string;
  apiKey: string;
  password: string;
  privateKey: string;
}

type TokenPayload = {
  userId: string;
  role: "admin" | "user";
  expiresIn: string;
};

// This is a type, not a hardcoded value
const defaultConfig: AuthConfig = {
  secret: process.env.AUTH_SECRET!,
  apiKey: process.env.API_KEY!,
  password: process.env.DB_PASSWORD!,
  privateKey: process.env.PRIVATE_KEY!,
};
`;

const safeStringWithKeywords = `
// UI labels and error messages — these contain security keywords but are just strings
const MESSAGES = {
  passwordReset: "Your password has been reset successfully",
  apiKeyRotated: "API key has been rotated. Please update your integration.",
  secretExpired: "Your secret token has expired. Please generate a new one.",
  loginFailed: "Invalid password. Please try again.",
};

// Validation error messages
function getErrorMessage(field: string): string {
  switch (field) {
    case "password": return "Password must be at least 8 characters";
    case "api_key": return "Invalid API key format";
    case "secret_key": return "Secret key is required";
    default: return "Invalid input";
  }
}

// Log messages (not logging actual secrets)
console.log("Password reset requested for user");
console.log("API key rotation completed");
`;

const safePrismaWithSelect = `
"use server";
import { auth } from "@clerk/nextjs/server";

export async function getUser(id: string) {
  const { userId } = await auth();
  if (!userId) throw new Error("Unauthorized");

  return prisma.user.findUnique({
    where: { id },
    select: { id: true, name: true, email: true, avatar: true },
  });
}

export async function listUsers() {
  const { userId } = await auth();
  if (!userId) throw new Error("Unauthorized");

  return prisma.user.findMany({
    select: { id: true, name: true },
    take: 50,
  });
}
`;

const safeWebhookHandler = `
// app/api/webhook/stripe/route.ts
import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(request: Request) {
  const body = await request.text();
  const signature = request.headers.get("stripe-signature")!;

  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(
      body,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET!
    );
  } catch (err) {
    return new Response("Invalid signature", { status: 401 });
  }

  switch (event.type) {
    case "checkout.session.completed":
      // handle payment
      break;
  }

  return new Response("OK");
}
`;

// ============================================================
// TESTS
// ============================================================

describe("False Positive Detection — Safe Next.js + Supabase Patterns", () => {
  const testCases = [
    { name: "Server Component with Supabase", code: safeServerComponent, lang: "typescript" },
    { name: "Server Action with validation + auth", code: safeServerAction, lang: "typescript" },
    { name: "Route Handler with auth", code: safeRouteHandler, lang: "typescript" },
    { name: "Supabase SSR client setup", code: safeEnvUsage, lang: "typescript" },
    { name: "Middleware with Supabase session refresh", code: safeMiddleware, lang: "typescript" },
    { name: "Comments containing security keywords", code: safeCommentWithPatterns, lang: "typescript" },
    { name: "Fix/example code in comments", code: safeFixCodeExample, lang: "typescript" },
    { name: "Express with helmet + rate limiting", code: safeExpressWithHelmet, lang: "typescript" },
    { name: "Next.js config with security headers", code: safeNextConfig, lang: "typescript" },
    { name: "TypeScript type definitions with secret fields", code: safeTypescriptTypes, lang: "typescript" },
    { name: "UI strings containing security keywords", code: safeStringWithKeywords, lang: "typescript" },
    { name: "Prisma with select (no data leak)", code: safePrismaWithSelect, lang: "typescript" },
    { name: "Webhook with signature verification", code: safeWebhookHandler, lang: "typescript" },
  ];

  for (const tc of testCases) {
    it(`should NOT flag: ${tc.name}`, () => {
      const findings = analyzeCode(tc.code, tc.lang);
      if (findings.length > 0) {
        const details = findings.map(f =>
          `  - ${f.rule.id} (${f.rule.name}) line ${f.line}: "${f.match}"`
        ).join("\n");
        assert.fail(
          `False positives found in "${tc.name}":\n${details}`
        );
      }
    });
  }
});
