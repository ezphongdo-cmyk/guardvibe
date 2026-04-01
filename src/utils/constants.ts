/**
 * Shared constants used across GuardVibe tools.
 * Single source of truth — all tool modules import from here.
 */

/** Maps file extensions to language identifiers for security analysis. */
export const EXTENSION_MAP: Record<string, string> = {
  ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
  ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
  ".py": "python", ".go": "go", ".html": "html",
  ".sql": "sql", ".sh": "shell", ".bash": "shell",
  ".yml": "yaml", ".yaml": "yaml",
  ".tf": "terraform",
  ".toml": "toml", ".json": "json",
};

/** Maps well-known config filenames to their language/type identifier. */
export const CONFIG_FILE_MAP: Record<string, string> = {
  "vercel.json": "vercel-config",
  "next.config.js": "nextjs-config",
  "next.config.mjs": "nextjs-config",
  "next.config.ts": "nextjs-config",
  "docker-compose.yml": "docker-compose",
  "docker-compose.yaml": "docker-compose",
  "fly.toml": "fly-config",
  "render.yaml": "render-config",
  "netlify.toml": "netlify-config",
};

/** Directory names excluded from filesystem scans by default. */
export const DEFAULT_EXCLUDES = new Set([
  "node_modules", ".git", "build", "dist", "vendor", "__pycache__",
  ".next", ".nuxt", ".svelte-kit", "target", "bin", "obj",
  "coverage", ".turbo", ".venv", "venv",
]);
