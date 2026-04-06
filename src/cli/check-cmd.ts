/**
 * CLI: guardvibe check-cmd "<command>"
 * Check if a shell command is safe to execute.
 */
import { parseArgs } from "./args.js";
import { checkCommand } from "../tools/check-command.js";

export async function runCheckCmd(args: string[]): Promise<void> {
  const { flags, positional } = parseArgs(args);
  const command = positional.join(" ");
  if (!command) {
    console.error('  [ERR] Please specify a command: npx guardvibe check-cmd "rm -rf /"');
    process.exit(1);
  }

  const format = (flags.format === "json" ? "json" : "markdown") as "markdown" | "json";
  const result = checkCommand(command, process.cwd(), undefined, format);
  console.log(result);
}
