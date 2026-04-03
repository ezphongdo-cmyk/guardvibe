import { readFileSync, existsSync, readdirSync } from "fs";
import { join, resolve, extname } from "path";

interface StackDetection {
  framework: string | null;
  css: string[];
  auth: string[];
  database: string[];
  payments: string[];
  ai: string[];
  storage: string[];
  cms: string[];
  analytics: string[];
  cdns: string[];
}

interface PolicyOutput {
  stack: StackDetection;
  csp: string;
  cors: CorsPolicy;
  rls: RlsSuggestion[];
  rateLimiting: RateLimitConfig;
  headers: HeaderPolicy[];
}

interface CorsPolicy {
  allowedOrigins: string[];
  allowedMethods: string[];
  allowedHeaders: string[];
  maxAge: number;
}

interface RlsSuggestion {
  table: string;
  policy: string;
  description: string;
}

interface RateLimitConfig {
  global: { requests: number; window: string };
  auth: { requests: number; window: string };
  api: { requests: number; window: string };
}

interface HeaderPolicy {
  key: string;
  value: string;
  description: string;
}

function tryRead(path: string): string | null {
  try {
    return existsSync(path) ? readFileSync(path, "utf-8") : null;
  } catch { return null; }
}

function collectSourceFiles(dir: string, results: string[], depth = 0): void {
  if (depth > 6) return;
  const skip = new Set(["node_modules", ".git", ".next", "build", "dist", "coverage", ".turbo", "vendor"]);
  try {
    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (skip.has(entry.name)) continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        collectSourceFiles(full, results, depth + 1);
      } else if (entry.isFile()) {
        const ext = extname(entry.name).toLowerCase();
        if ([".ts", ".tsx", ".js", ".jsx", ".mjs", ".env", ".json", ".toml", ".yaml", ".yml"].includes(ext) ||
            entry.name === ".env" || entry.name === ".env.local" || entry.name === ".env.example") {
          results.push(full);
        }
      }
    }
  } catch { /* skip */ }
}

function detectStack(root: string): StackDetection {
  const pkg = tryRead(join(root, "package.json"));
  const deps = pkg ? { ...JSON.parse(pkg).dependencies, ...JSON.parse(pkg).devDependencies } : {};
  const depKeys = Object.keys(deps);

  const files: string[] = [];
  collectSourceFiles(root, files);
  const allContent = files.slice(0, 200).map(f => {
    try { return readFileSync(f, "utf-8").substring(0, 5000); } catch { return ""; }
  }).join("\n");

  const has = (pattern: string) => depKeys.some(d => d.includes(pattern)) || allContent.includes(pattern);

  const stack: StackDetection = {
    framework: null,
    css: [], auth: [], database: [], payments: [],
    ai: [], storage: [], cms: [], analytics: [], cdns: [],
  };

  // Framework
  if (has("next")) stack.framework = "nextjs";
  else if (has("nuxt")) stack.framework = "nuxt";
  else if (has("svelte")) stack.framework = "sveltekit";
  else if (has("astro")) stack.framework = "astro";
  else if (has("remix")) stack.framework = "remix";

  // CSS
  if (has("tailwindcss")) stack.css.push("tailwindcss");
  if (has("@radix-ui") || has("shadcn")) stack.css.push("radix-ui");

  // Auth
  if (has("@clerk")) stack.auth.push("clerk");
  if (has("next-auth") || has("@auth/")) stack.auth.push("next-auth");
  if (has("@supabase/auth")) stack.auth.push("supabase-auth");
  if (has("firebase/auth") || has("firebase-admin")) stack.auth.push("firebase-auth");
  if (has("@descope")) stack.auth.push("descope");

  // Database
  if (has("@supabase")) stack.database.push("supabase");
  if (has("prisma") || has("@prisma")) stack.database.push("prisma");
  if (has("drizzle")) stack.database.push("drizzle");
  if (has("@neondatabase") || has("@vercel/postgres")) stack.database.push("neon");
  if (has("mongoose") || has("mongodb")) stack.database.push("mongodb");
  if (has("@upstash/redis")) stack.database.push("upstash-redis");

  // Payments
  if (has("stripe")) stack.payments.push("stripe");
  if (has("@polar")) stack.payments.push("polar");
  if (has("lemonsqueezy") || has("@lemonsqueezy")) stack.payments.push("lemonsqueezy");

  // AI
  if (has("openai") || has("@ai-sdk") || has("OPENAI_API_KEY")) stack.ai.push("openai");
  if (has("anthropic") || has("ANTHROPIC_API_KEY")) stack.ai.push("anthropic");
  if (has("@google/generative-ai") || has("@ai-sdk/google")) stack.ai.push("google-ai");

  // Storage
  if (has("@vercel/blob")) stack.storage.push("vercel-blob");
  if (has("@aws-sdk/client-s3") || has("aws-sdk")) stack.storage.push("s3");
  if (has("cloudinary")) stack.storage.push("cloudinary");
  if (has("@uploadthing")) stack.storage.push("uploadthing");

  // CMS
  if (has("sanity") || has("@sanity")) stack.cms.push("sanity");
  if (has("contentful")) stack.cms.push("contentful");

  // Analytics
  if (has("@vercel/analytics")) stack.analytics.push("vercel-analytics");
  if (has("posthog") || has("@posthog")) stack.analytics.push("posthog");
  if (has("@sentry")) stack.analytics.push("sentry");

  // CDN detection from content
  const cdnPatterns: [string, RegExp][] = [
    ["fonts.googleapis.com", /fonts\.googleapis\.com/],
    ["fonts.gstatic.com", /fonts\.gstatic\.com/],
    ["cdn.jsdelivr.net", /cdn\.jsdelivr\.net/],
    ["unpkg.com", /unpkg\.com/],
    ["cdnjs.cloudflare.com", /cdnjs\.cloudflare\.com/],
    ["vercel.live", /vercel\.live/],
    ["va.vercel-scripts.com", /va\.vercel-scripts\.com/],
  ];
  for (const [cdn, pattern] of cdnPatterns) {
    if (pattern.test(allContent)) stack.cdns.push(cdn);
  }

  return stack;
}

function generateCSP(stack: StackDetection): string {
  const directives: Record<string, string[]> = {
    "default-src": ["'self'"],
    "script-src": ["'self'"],
    "style-src": ["'self'", "'unsafe-inline'"],
    "img-src": ["'self'", "data:", "blob:"],
    "font-src": ["'self'"],
    "connect-src": ["'self'"],
    "frame-src": ["'none'"],
    "object-src": ["'none'"],
    "base-uri": ["'self'"],
    "form-action": ["'self'"],
    "frame-ancestors": ["'none'"],
  };

  // Script sources
  if (stack.framework === "nextjs") {
    directives["script-src"].push("'unsafe-eval'"); // needed for dev, remove in production ideally
  }
  if (stack.analytics.includes("vercel-analytics")) {
    directives["script-src"].push("https://va.vercel-scripts.com");
    directives["connect-src"].push("https://vitals.vercel-insights.com");
  }
  if (stack.analytics.includes("posthog")) {
    directives["script-src"].push("https://us.i.posthog.com", "https://eu.i.posthog.com");
    directives["connect-src"].push("https://us.i.posthog.com", "https://eu.i.posthog.com");
  }
  if (stack.analytics.includes("sentry")) {
    directives["script-src"].push("https://*.sentry.io");
    directives["connect-src"].push("https://*.sentry.io");
  }

  // Image sources
  if (stack.storage.includes("vercel-blob")) {
    directives["img-src"].push("https://*.public.blob.vercel-storage.com");
  }
  if (stack.storage.includes("s3")) {
    directives["img-src"].push("https://*.s3.amazonaws.com");
  }
  if (stack.storage.includes("cloudinary")) {
    directives["img-src"].push("https://res.cloudinary.com");
  }
  if (stack.storage.includes("uploadthing")) {
    directives["img-src"].push("https://utfs.io");
  }
  if (stack.cms.includes("sanity")) {
    directives["img-src"].push("https://cdn.sanity.io");
  }
  if (stack.cms.includes("contentful")) {
    directives["img-src"].push("https://images.ctfassets.net");
  }

  // Font sources
  for (const cdn of stack.cdns) {
    if (cdn.includes("fonts.googleapis")) {
      directives["style-src"].push("https://fonts.googleapis.com");
      directives["font-src"].push("https://fonts.gstatic.com");
    }
    if (cdn.includes("jsdelivr") || cdn.includes("unpkg") || cdn.includes("cdnjs")) {
      directives["script-src"].push(`https://${cdn}`);
    }
  }

  // Connect sources for auth
  if (stack.auth.includes("clerk")) {
    directives["connect-src"].push("https://*.clerk.accounts.dev", "https://clerk.com");
    directives["script-src"].push("https://*.clerk.accounts.dev");
    directives["frame-src"] = ["'self'", "https://*.clerk.accounts.dev"];
  }
  if (stack.auth.includes("supabase-auth")) {
    directives["connect-src"].push("https://*.supabase.co");
  }
  if (stack.auth.includes("firebase-auth")) {
    directives["connect-src"].push("https://*.firebaseapp.com", "https://*.googleapis.com");
    directives["frame-src"] = ["'self'", "https://*.firebaseapp.com"];
  }

  // Connect sources for payments
  if (stack.payments.includes("stripe")) {
    directives["script-src"].push("https://js.stripe.com");
    directives["frame-src"] = [...(directives["frame-src"].includes("'none'") ? ["'self'"] : directives["frame-src"]), "https://js.stripe.com"];
    directives["connect-src"].push("https://api.stripe.com");
  }

  // Connect sources for AI
  if (stack.ai.includes("openai")) directives["connect-src"].push("https://api.openai.com");
  if (stack.ai.includes("anthropic")) directives["connect-src"].push("https://api.anthropic.com");
  if (stack.ai.includes("google-ai")) directives["connect-src"].push("https://generativelanguage.googleapis.com");

  // Database connect
  if (stack.database.includes("supabase")) {
    directives["connect-src"].push("https://*.supabase.co");
  }

  // Deduplicate
  for (const key of Object.keys(directives)) {
    directives[key] = [...new Set(directives[key])];
  }

  return Object.entries(directives)
    .map(([key, values]) => `${key} ${values.join(" ")}`)
    .join("; ");
}

function generateCORS(stack: StackDetection): CorsPolicy {
  const origins: string[] = [];
  if (stack.auth.includes("clerk")) origins.push("https://*.clerk.accounts.dev");
  if (stack.payments.includes("stripe")) origins.push("https://js.stripe.com");

  return {
    allowedOrigins: origins.length > 0 ? origins : ["https://yourdomain.com"],
    allowedMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
    maxAge: 86400,
  };
}

function generateRLS(stack: StackDetection): RlsSuggestion[] {
  const suggestions: RlsSuggestion[] = [];

  if (stack.database.includes("supabase")) {
    suggestions.push(
      {
        table: "profiles",
        policy: `CREATE POLICY "Users can view own profile" ON profiles FOR SELECT USING (auth.uid() = id);`,
        description: "Restrict profile reads to the owner only.",
      },
      {
        table: "profiles",
        policy: `CREATE POLICY "Users can update own profile" ON profiles FOR UPDATE USING (auth.uid() = id) WITH CHECK (auth.uid() = id);`,
        description: "Restrict profile updates to the owner only.",
      },
      {
        table: "*",
        policy: `ALTER TABLE your_table ENABLE ROW LEVEL SECURITY;`,
        description: "Enable RLS on every table. Without RLS enabled, all data is publicly accessible via the Supabase client.",
      },
      {
        table: "*",
        policy: `REVOKE ALL ON your_table FROM anon; GRANT SELECT ON your_table TO anon;`,
        description: "Restrict anonymous role to read-only on public tables.",
      },
    );

    if (stack.payments.length > 0) {
      suggestions.push({
        table: "subscriptions",
        policy: `CREATE POLICY "Users can view own subscription" ON subscriptions FOR SELECT USING (auth.uid() = user_id);`,
        description: "Protect subscription data — users should only see their own.",
      });
    }
  }

  if (stack.database.includes("prisma") || stack.database.includes("drizzle")) {
    suggestions.push({
      table: "N/A (ORM-level)",
      policy: `// Always filter by authenticated user\nconst items = await prisma.item.findMany({ where: { userId: session.user.id } });`, // guardvibe-ignore VG955
      description: "Without RLS, enforce row-level access in your ORM queries. Always include user ID in WHERE clauses.",
    });
  }

  return suggestions;
}

function generateRateLimiting(stack: StackDetection): RateLimitConfig {
  return {
    global: { requests: 100, window: "1m" },
    auth: { requests: 5, window: "1m" },
    api: stack.ai.length > 0
      ? { requests: 20, window: "1m" }
      : { requests: 60, window: "1m" },
  };
}

function generateHeaders(stack: StackDetection): HeaderPolicy[] {
  const headers: HeaderPolicy[] = [
    { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload", description: "Enforce HTTPS for all connections." },
    { key: "X-Frame-Options", value: "DENY", description: "Prevent clickjacking by blocking iframe embedding." },
    { key: "X-Content-Type-Options", value: "nosniff", description: "Prevent MIME-type sniffing attacks." },
    { key: "Referrer-Policy", value: "strict-origin-when-cross-origin", description: "Control referrer information sent to other sites." },
    { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()", description: "Disable sensitive browser APIs unless explicitly needed." },
  ];

  if (stack.framework === "nextjs") {
    headers.push({ key: "X-DNS-Prefetch-Control", value: "on", description: "Enable DNS prefetching for performance." });
  }

  return headers;
}

export function generatePolicy(
  path: string,
  format: "markdown" | "json" = "markdown"
): string {
  const root = resolve(path);
  const stack = detectStack(root);
  const csp = generateCSP(stack);
  const cors = generateCORS(stack);
  const rls = generateRLS(stack);
  const rateLimiting = generateRateLimiting(stack);
  const headers = generateHeaders(stack);

  const policy: PolicyOutput = { stack, csp, cors, rls, rateLimiting, headers };

  if (format === "json") {
    return JSON.stringify(policy);
  }

  const lines: string[] = [
    `# GuardVibe Security Policy Generator`,
    ``,
    `Directory: ${root}`,
    ``,
    `## Detected Stack`,
    `- Framework: ${stack.framework ?? "unknown"}`,
  ];
  if (stack.auth.length > 0) lines.push(`- Auth: ${stack.auth.join(", ")}`);
  if (stack.database.length > 0) lines.push(`- Database: ${stack.database.join(", ")}`);
  if (stack.payments.length > 0) lines.push(`- Payments: ${stack.payments.join(", ")}`);
  if (stack.ai.length > 0) lines.push(`- AI: ${stack.ai.join(", ")}`);
  if (stack.storage.length > 0) lines.push(`- Storage: ${stack.storage.join(", ")}`);
  if (stack.cms.length > 0) lines.push(`- CMS: ${stack.cms.join(", ")}`);
  if (stack.analytics.length > 0) lines.push(`- Analytics: ${stack.analytics.join(", ")}`);
  lines.push(``);

  lines.push(
    `## Content-Security-Policy`,
    ``,
    "```",
    csp,
    "```",
    ``,
    `### Next.js Configuration`,
    ``,
    "```typescript",
    `// next.config.ts`,
    `async headers() {`, // guardvibe-ignore
    `  return [{`,
    `    source: "/(.*)",`,
    `    headers: [`,
    `      { key: "Content-Security-Policy", value: \`${csp}\` },`,
    ...headers.map(h => `      { key: "${h.key}", value: "${h.value}" },`),
    `    ]`,
    `  }];`,
    `}`,
    "```",
    ``,
  );

  lines.push(
    `## CORS Policy`,
    ``,
    "```typescript",
    `// Recommended CORS configuration`,
    `const corsConfig = {`,
    `  allowedOrigins: ${JSON.stringify(cors.allowedOrigins)},`,
    `  allowedMethods: ${JSON.stringify(cors.allowedMethods)},`,
    `  allowedHeaders: ${JSON.stringify(cors.allowedHeaders)},`,
    `  maxAge: ${cors.maxAge},`,
    `};`,
    "```",
    ``,
  );

  if (rls.length > 0) {
    lines.push(`## Row-Level Security Suggestions`, ``);
    for (const r of rls) {
      lines.push(
        `### ${r.table}`,
        r.description,
        "```sql",
        r.policy,
        "```",
        ``,
      );
    }
  }

  lines.push(
    `## Rate Limiting`,
    ``,
    `| Endpoint | Limit | Window |`,
    `|----------|-------|--------|`,
    `| Global | ${rateLimiting.global.requests} req | ${rateLimiting.global.window} |`,
    `| Auth (login/register) | ${rateLimiting.auth.requests} req | ${rateLimiting.auth.window} |`,
    `| API | ${rateLimiting.api.requests} req | ${rateLimiting.api.window} |`,
    ``,
  );

  if (stack.database.includes("upstash-redis")) {
    lines.push(
      `### Upstash Rate Limit Implementation`,
      ``,
      "```typescript",
      `import { Ratelimit } from "@upstash/ratelimit";`,
      `import { Redis } from "@upstash/redis";`,
      ``,
      `const ratelimit = new Ratelimit({`,
      `  redis: Redis.fromEnv(),`,
      `  limiter: Ratelimit.slidingWindow(${rateLimiting.api.requests}, "${rateLimiting.api.window}"),`,
      `});`,
      "```",
      ``,
    );
  }

  lines.push(
    `## Security Headers`,
    ``,
    `| Header | Value | Purpose |`,
    `|--------|-------|---------|`,
  );
  for (const h of headers) {
    lines.push(`| ${h.key} | ${h.value} | ${h.description} |`);
  }

  return lines.join("\n");
}
