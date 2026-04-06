/**
 * CLI: guardvibe compliance [path] --framework SOC2
 * Generate compliance report mapping findings to framework controls.
 */

import { writeFileSync, existsSync, mkdirSync } from "fs";
import { resolve, dirname } from "path";
import { parseArgs, validateFormat, getOutputPath, getStringFlag } from "./args.js";
import { complianceReport } from "../tools/compliance-report.js";

const VALID_FRAMEWORKS = new Set(["SOC2", "PCI-DSS", "HIPAA", "GDPR", "ISO27001", "EUAIACT"]);

export async function runCompliance(args: string[]): Promise<void> {
  const { flags, positional } = parseArgs(args);
  const targetPath = resolve(positional[0] ?? ".");
  const framework = getStringFlag(flags, "framework") ?? "SOC2";
  const format = validateFormat(flags);
  const outputFile = getOutputPath(flags);

  if (!VALID_FRAMEWORKS.has(framework)) {
    console.error(`  [ERR] Invalid framework "${framework}". Use: ${[...VALID_FRAMEWORKS].join(", ")}`);
    process.exit(1);
  }

  const formatArg = format === "json" ? "json" as const : "markdown" as const;
  const result = complianceReport(targetPath, framework, formatArg);

  if (outputFile) {
    const dir = dirname(outputFile);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    writeFileSync(outputFile, result, "utf-8");
    console.log(`  [OK] Results written to ${outputFile}`);
  } else {
    console.log(result);
  }
}
