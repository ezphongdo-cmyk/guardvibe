/**
 * CLI: guardvibe fix <file>
 * Get security fix suggestions for a file.
 */
import { readFileSync } from "fs";
import { resolve, extname } from "path";
import { parseArgs } from "./args.js";
import { fixCode } from "../tools/fix-code.js";
import { EXTENSION_MAP } from "../utils/constants.js";

export async function runFix(args: string[]): Promise<void> {
  const { flags, positional } = parseArgs(args);
  const filePath = positional[0];
  if (!filePath) {
    console.error("  [ERR] Please specify a file: npx guardvibe fix src/app/api/route.ts");
    process.exit(1);
  }

  const resolved = resolve(filePath);
  let content: string;
  try {
    content = readFileSync(resolved, "utf-8");
  } catch {
    console.error(`  [ERR] Could not read file: ${resolved}`);
    process.exit(1);
  }

  const ext = extname(resolved).toLowerCase();
  const language = EXTENSION_MAP[ext];
  if (!language) {
    console.error(`  [ERR] Unsupported file type: ${ext}`);
    process.exit(1);
  }

  const format = (flags.format === "json" ? "json" : "markdown") as "markdown" | "json";
  const result = fixCode(content, language, undefined, resolved, format);
  console.log(result);
}
