import { readdirSync } from "fs";
import { join, resolve, isAbsolute } from "path";
import type { SecurityRule } from "../data/rules/types.js";
import type { GuardVibePlugin, GuardVibeTool } from "./types.js";

interface ValidationResult {
  valid: boolean;
  rules: SecurityRule[];
  tools: GuardVibeTool[];
  errors: string[];
}

function isValidRule(rule: any): rule is SecurityRule {
  return (
    rule &&
    typeof rule === "object" &&
    typeof rule.id === "string" &&
    typeof rule.name === "string" &&
    typeof rule.severity === "string" &&
    typeof rule.description === "string" &&
    rule.pattern instanceof RegExp &&
    Array.isArray(rule.languages) &&
    typeof rule.fix === "string"
  );
}

export function validatePlugin(raw: any): ValidationResult {
  const errors: string[] = [];

  if (!raw || typeof raw !== "object") {
    return { valid: false, rules: [], tools: [], errors: ["Plugin is not an object"] };
  }

  if (typeof raw.name !== "string" || !raw.name) {
    return { valid: false, rules: [], tools: [], errors: ["Plugin missing 'name'"] };
  }

  if (typeof raw.version !== "string" || !raw.version) {
    return { valid: false, rules: [], tools: [], errors: ["Plugin missing 'version'"] };
  }

  const rules: SecurityRule[] = [];
  if (Array.isArray(raw.rules)) {
    for (const rule of raw.rules) {
      if (isValidRule(rule)) {
        rules.push(rule);
      } else {
        errors.push(`Invalid rule skipped: ${rule?.id ?? "unknown"}`);
      }
    }
  }

  const tools: GuardVibeTool[] = [];
  if (Array.isArray(raw.tools)) {
    for (const tool of raw.tools) {
      if (tool && typeof tool.name === "string" && typeof tool.handler === "function") {
        tools.push(tool);
      } else {
        errors.push(`Invalid tool skipped: ${tool?.name ?? "unknown"}`);
      }
    }
  }

  return { valid: true, rules, tools, errors };
}

const PLUGIN_PATTERNS = [
  /^guardvibe-rules-/,
  /^@guardvibe\/rules-/,
  /^@guardvibe-pro\/rules-/,
];

function findPluginPackages(nodeModulesDir: string): string[] {
  const found: string[] = [];

  let entries: string[];
  try {
    entries = readdirSync(nodeModulesDir);
  } catch {
    return found;
  }

  for (const entry of entries) {
    if (PLUGIN_PATTERNS[0].test(entry)) {
      found.push(entry);
      continue;
    }

    if (entry === "@guardvibe" || entry === "@guardvibe-pro") {
      try {
        const scopedEntries = readdirSync(join(nodeModulesDir, entry));
        for (const scoped of scopedEntries) {
          if (scoped.startsWith("rules-")) {
            found.push(`${entry}/${scoped}`);
          }
        }
      } catch {}
    }
  }

  return found;
}

async function loadPluginModule(specifier: string, baseDir: string): Promise<GuardVibePlugin | null> {
  try {
    let modulePath: string;

    if (specifier.startsWith(".") || isAbsolute(specifier)) {
      modulePath = resolve(baseDir, specifier);
    } else {
      modulePath = join(baseDir, "node_modules", specifier);
    }

    const mod = await import(modulePath);
    const plugin = mod.default ?? mod.plugin ?? mod;

    return plugin;
  } catch (err) {
    console.error(`[guardvibe] Failed to load plugin "${specifier}": ${err instanceof Error ? err.message : err}`);
    return null;
  }
}

export interface LoadedPlugins {
  rules: SecurityRule[];
  tools: GuardVibeTool[];
  loaded: string[];
  errors: string[];
}

export async function discoverPlugins(baseDir: string, configPlugins: string[] = []): Promise<LoadedPlugins> {
  const result: LoadedPlugins = { rules: [], tools: [], loaded: [], errors: [] };
  const seen = new Set<string>();

  // 1. Convention-based discovery
  const nodeModulesDir = join(baseDir, "node_modules");
  const conventionPackages = findPluginPackages(nodeModulesDir);

  for (const pkgName of conventionPackages) {
    if (seen.has(pkgName)) continue;
    seen.add(pkgName);

    const raw = await loadPluginModule(pkgName, baseDir);
    if (!raw) {
      result.errors.push(`Failed to load: ${pkgName}`);
      continue;
    }

    const validation = validatePlugin(raw);
    if (!validation.valid) {
      result.errors.push(`Invalid plugin ${pkgName}: ${validation.errors.join(", ")}`);
      continue;
    }

    result.rules.push(...validation.rules);
    result.tools.push(...validation.tools);
    result.loaded.push(pkgName);
    if (validation.errors.length > 0) {
      result.errors.push(...validation.errors.map(e => `${pkgName}: ${e}`));
    }
  }

  // 2. Config-based plugins
  for (const specifier of configPlugins) {
    if (seen.has(specifier)) continue;
    seen.add(specifier);

    const raw = await loadPluginModule(specifier, baseDir);
    if (!raw) {
      result.errors.push(`Failed to load: ${specifier}`);
      continue;
    }

    const validation = validatePlugin(raw);
    if (!validation.valid) {
      result.errors.push(`Invalid plugin ${specifier}: ${validation.errors.join(", ")}`);
      continue;
    }

    result.rules.push(...validation.rules);
    result.tools.push(...validation.tools);
    result.loaded.push(specifier);
    if (validation.errors.length > 0) {
      result.errors.push(...validation.errors.map(e => `${specifier}: ${e}`));
    }
  }

  return result;
}
