import { readFileSync } from "fs";
import { join, resolve } from "path";

export interface PolicyException {
  ruleId: string;
  reason: string;
  approvedBy?: string;
  expiresAt?: string;  // ISO date — exception expires after this date
  files?: string[];    // only apply to these files (glob patterns)
}

export interface CompliancePolicy {
  frameworks: string[];           // ["SOC2", "GDPR", "ISO27001"]
  failOn: "critical" | "high" | "medium" | "low";
  exceptions: PolicyException[];
  requiredControls?: string[];    // controls that MUST pass, e.g. ["SOC2:CC6.1"]
}

export interface GuardVibeConfig {
  rules: {
    disable: string[];
    severity: Record<string, string>;
  };
  scan: {
    exclude: string[];
    maxFileSize: number;
  };
  plugins: string[];
  compliance?: CompliancePolicy;
}

const DEFAULT_CONFIG: GuardVibeConfig = {
  rules: { disable: [], severity: {} },
  scan: { exclude: [], maxFileSize: 500 * 1024 },
  plugins: [],
  compliance: undefined,
};

const configCache = new Map<string, GuardVibeConfig>();

function cloneDefaultConfig(): GuardVibeConfig {
  return {
    rules: { disable: [...DEFAULT_CONFIG.rules.disable], severity: { ...DEFAULT_CONFIG.rules.severity } },
    scan: { exclude: [...DEFAULT_CONFIG.scan.exclude], maxFileSize: DEFAULT_CONFIG.scan.maxFileSize },
    plugins: [...DEFAULT_CONFIG.plugins],
  };
}

export function loadConfig(dir?: string): GuardVibeConfig {
  const configDir = resolve(dir || process.cwd());
  const cached = configCache.get(configDir);
  if (cached) return cached;

  const configPath = join(configDir, ".guardviberc");
  let resolvedConfig = cloneDefaultConfig();

  try {
    const content = readFileSync(configPath, "utf-8");
    const parsed = JSON.parse(content);

    resolvedConfig = {
      rules: {
        disable: Array.isArray(parsed.rules?.disable) ? parsed.rules.disable : [],
        severity: typeof parsed.rules?.severity === "object" && parsed.rules.severity !== null
          ? parsed.rules.severity : {},
      },
      scan: {
        exclude: Array.isArray(parsed.scan?.exclude) ? parsed.scan.exclude : [],
        maxFileSize: typeof parsed.scan?.maxFileSize === "number"
          ? parsed.scan.maxFileSize : DEFAULT_CONFIG.scan.maxFileSize,
      },
      plugins: Array.isArray(parsed.plugins) ? parsed.plugins : [],
      compliance: parsed.compliance ? {
        frameworks: Array.isArray(parsed.compliance.frameworks) ? parsed.compliance.frameworks : [],
        failOn: parsed.compliance.failOn ?? "high",
        exceptions: Array.isArray(parsed.compliance.exceptions) ? parsed.compliance.exceptions : [],
        requiredControls: Array.isArray(parsed.compliance.requiredControls) ? parsed.compliance.requiredControls : undefined,
      } : undefined,
    };
  } catch {}

  configCache.set(configDir, resolvedConfig);
  return resolvedConfig;
}

export function resetConfigCache(): void {
  configCache.clear();
}
