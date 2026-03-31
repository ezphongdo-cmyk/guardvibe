import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { discoverPlugins } from "../../src/plugins/loader.js";

describe("Plugin Integration", () => {
  it("discovers and loads a convention-named plugin from node_modules", async () => {
    const projectDir = mkdtempSync(join(tmpdir(), "gv-plugin-test-"));
    const pluginDir = join(projectDir, "node_modules", "guardvibe-rules-test");
    mkdirSync(pluginDir, { recursive: true });

    writeFileSync(join(pluginDir, "package.json"), JSON.stringify({
      name: "guardvibe-rules-test", version: "1.0.0", type: "module", main: "index.js",
    }));
    writeFileSync(join(pluginDir, "index.js"), `
      export default {
        name: "guardvibe-rules-test",
        version: "1.0.0",
        description: "Test plugin",
        license: "free",
        rules: [
          {
            id: "PLUG001",
            name: "Plugin Test Rule",
            severity: "medium",
            owasp: "A05:2025 Security Misconfiguration",
            description: "A test rule from a plugin",
            pattern: /PLUGIN_VULNERABLE_PATTERN/g,
            languages: ["javascript"],
            fix: "Fix the pattern",
          },
        ],
      };
    `);

    const result = await discoverPlugins(projectDir);
    assert.strictEqual(result.loaded.length, 1);
    assert.strictEqual(result.loaded[0], "guardvibe-rules-test");
    assert.strictEqual(result.rules.length, 1);
    assert.strictEqual(result.rules[0].id, "PLUG001");

    rmSync(projectDir, { recursive: true });
  });

  it("discovers scoped plugin @guardvibe/rules-*", async () => {
    const projectDir = mkdtempSync(join(tmpdir(), "gv-scoped-test-"));
    const pluginDir = join(projectDir, "node_modules", "@guardvibe", "rules-nextjs-pro");
    mkdirSync(pluginDir, { recursive: true });

    writeFileSync(join(pluginDir, "package.json"), JSON.stringify({
      name: "@guardvibe/rules-nextjs-pro", version: "1.0.0", type: "module", main: "index.js",
    }));
    writeFileSync(join(pluginDir, "index.js"), `
      export const plugin = {
        name: "@guardvibe/rules-nextjs-pro",
        version: "1.0.0",
        license: "pro",
        rules: [
          {
            id: "PRO001",
            name: "Pro Rule",
            severity: "high",
            owasp: "A01:2025 Broken Access Control",
            description: "A pro rule",
            pattern: /PRO_PATTERN/g,
            languages: ["typescript"],
            fix: "Upgrade to pro",
          },
        ],
      };
    `);

    const result = await discoverPlugins(projectDir);
    assert.strictEqual(result.loaded.length, 1);
    assert.strictEqual(result.rules[0].id, "PRO001");

    rmSync(projectDir, { recursive: true });
  });

  it("loads config-specified plugins", async () => {
    const projectDir = mkdtempSync(join(tmpdir(), "gv-config-plugin-"));
    const pluginDir = join(projectDir, "node_modules", "my-custom-security");
    mkdirSync(pluginDir, { recursive: true });

    writeFileSync(join(pluginDir, "package.json"), JSON.stringify({
      name: "my-custom-security", version: "1.0.0", type: "module", main: "index.js",
    }));
    writeFileSync(join(pluginDir, "index.js"), `
      export default {
        name: "my-custom-security",
        version: "1.0.0",
        rules: [
          {
            id: "CUSTOM001",
            name: "Custom Rule",
            severity: "low",
            owasp: "A05:2025 Security Misconfiguration",
            description: "Custom",
            pattern: /CUSTOM_PATTERN/g,
            languages: ["javascript"],
            fix: "Fix",
          },
        ],
      };
    `);

    const result = await discoverPlugins(projectDir, ["my-custom-security"]);
    assert.strictEqual(result.loaded.length, 1);
    assert.strictEqual(result.rules[0].id, "CUSTOM001");

    rmSync(projectDir, { recursive: true });
  });

  it("gracefully handles missing plugin", async () => {
    const result = await discoverPlugins("/tmp", ["nonexistent-plugin"]);
    assert.strictEqual(result.loaded.length, 0);
    assert(result.errors.length > 0);
  });

  it("deduplicates plugins found by both convention and config", async () => {
    const projectDir = mkdtempSync(join(tmpdir(), "gv-dedup-"));
    const pluginDir = join(projectDir, "node_modules", "guardvibe-rules-dedup");
    mkdirSync(pluginDir, { recursive: true });

    writeFileSync(join(pluginDir, "package.json"), JSON.stringify({
      name: "guardvibe-rules-dedup", version: "1.0.0", type: "module", main: "index.js",
    }));
    writeFileSync(join(pluginDir, "index.js"), `
      export default {
        name: "guardvibe-rules-dedup",
        version: "1.0.0",
        rules: [{ id: "DEDUP001", name: "Dedup", severity: "low", owasp: "A05:2025", description: "d", pattern: /x/g, languages: ["javascript"], fix: "f" }],
      };
    `);

    const result = await discoverPlugins(projectDir, ["guardvibe-rules-dedup"]);
    assert.strictEqual(result.loaded.length, 1);
    assert.strictEqual(result.rules.length, 1);

    rmSync(projectDir, { recursive: true });
  });
});
