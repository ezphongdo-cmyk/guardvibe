// Popular npm packages for typosquat detection
export const POPULAR_PACKAGES = [
  // React ecosystem
  "react", "react-dom", "react-router", "react-router-dom", "react-hook-form",
  "@tanstack/react-query", "react-icons", "react-select",
  // Next.js
  "next", "@next/font", "@next/mdx",
  // Vue / Svelte / Angular
  "vue", "svelte", "nuxt", "@angular/core",
  // State management
  "zustand", "jotai", "redux", "@reduxjs/toolkit", "mobx", "valtio",
  // Styling
  "tailwindcss", "postcss", "autoprefixer", "sass", "styled-components",
  "@emotion/react", "@emotion/styled", "clsx", "tailwind-merge",
  // UI frameworks
  "@radix-ui/react-dialog", "@radix-ui/react-popover", "@radix-ui/react-select",
  "@radix-ui/react-tooltip", "@radix-ui/react-dropdown-menu",
  "class-variance-authority", "lucide-react",
  // Build tools
  "typescript", "vite", "esbuild", "webpack", "turbo", "tsup", "tsx",
  // Testing
  "vitest", "jest", "@testing-library/react", "playwright", "cypress",
  // HTTP / API
  "axios", "ky", "got", "node-fetch", "undici",
  // Validation
  "zod", "yup", "joi", "valibot", "ajv",
  // Database / ORM
  "prisma", "@prisma/client", "drizzle-orm", "drizzle-kit",
  "mongoose", "typeorm", "knex", "pg", "mysql2", "better-sqlite3",
  // Auth
  "@clerk/nextjs", "@clerk/clerk-sdk-node", "next-auth", "@auth/core",
  "passport", "jsonwebtoken", "bcrypt", "bcryptjs",
  // Supabase
  "@supabase/supabase-js", "@supabase/ssr",
  // Payments
  "stripe", "@stripe/stripe-js",
  // Email
  "resend", "nodemailer", "@sendgrid/mail",
  // AI
  "ai", "@ai-sdk/react", "@ai-sdk/openai", "@ai-sdk/anthropic", "@ai-sdk/google",
  "openai", "@anthropic-ai/sdk",
  // Server frameworks
  "express", "fastify", "hono", "koa",
  // Utilities
  "lodash", "lodash-es", "date-fns", "dayjs", "uuid", "nanoid",
  "dotenv", "chalk", "commander", "inquirer", "ora", "execa",
  "fs-extra", "glob", "minimatch", "semver", "debug",
  // File handling
  "sharp", "multer", "formidable",
  // Logging / monitoring
  "winston", "pino", "@sentry/nextjs",
  // MCP
  "@modelcontextprotocol/sdk",
];

export function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }

  return dp[m][n];
}

interface TyposquatResult {
  similarTo: string;
  confidence: number;
}

export function detectTyposquat(name: string): TyposquatResult | null {
  const lower = name.toLowerCase();

  // Exact match = not a typosquat
  if (POPULAR_PACKAGES.includes(lower)) return null;

  // Strip scope for comparison
  const bareName = lower.startsWith("@") ? lower.split("/").pop() ?? lower : lower;

  let bestMatch: string | null = null;
  let bestDistance = Infinity;

  for (const popular of POPULAR_PACKAGES) {
    const popularBare = popular.startsWith("@") ? popular.split("/").pop() ?? popular : popular;

    // Only compare if lengths are within 2 chars
    if (Math.abs(bareName.length - popularBare.length) > 2) continue;

    const dist = levenshtein(bareName, popularBare);

    if (dist > 0 && dist <= 2 && dist < bestDistance) {
      bestDistance = dist;
      bestMatch = popular;
    }
  }

  if (!bestMatch) return null;

  // Confidence: distance 1 = 0.9, distance 2 = 0.7
  const confidence = bestDistance === 1 ? 0.9 : 0.7;

  return { similarTo: bestMatch, confidence };
}
