import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { validatePlugin, discoverPlugins } from "../../src/plugins/loader.js";
import type { GuardVibePlugin } from "../../src/plugins/types.js";

describe("validatePlugin", () => {
  it("accepts valid plugin", () => {
    const plugin: GuardVibePlugin = {
      name: "test-plugin", version: "1.0.0",
      rules: [{
        id: "T001", name: "Test", severity: "medium",
        owasp: "A05:2025", description: "Test",
        pattern: /test/g, languages: ["javascript"], fix: "Fix",
      }],
    };
    const result = validatePlugin(plugin);
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.rules.length, 1);
  });

  it("rejects plugin without name", () => {
    const result = validatePlugin({ version: "1.0.0" } as any);
    assert.strictEqual(result.valid, false);
  });

  it("rejects plugin without version", () => {
    const result = validatePlugin({ name: "test" } as any);
    assert.strictEqual(result.valid, false);
  });

  it("filters out invalid rules", () => {
    const plugin: any = {
      name: "test", version: "1.0.0",
      rules: [
        { id: "T001", name: "Valid", severity: "high", owasp: "A01:2025", description: "d", pattern: /x/g, languages: ["javascript"], fix: "f" },
        { id: "T002", name: "Missing pattern" },
        "not a rule",
      ],
    };
    const result = validatePlugin(plugin);
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.rules.length, 1);
    assert.strictEqual(result.rules[0].id, "T001");
  });

  it("returns empty rules for plugin with no rules", () => {
    const plugin: GuardVibePlugin = { name: "empty", version: "1.0.0" };
    const result = validatePlugin(plugin);
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.rules.length, 0);
  });
});

describe("discoverPlugins", () => {
  it("returns empty array when no plugins found", async () => {
    const plugins = await discoverPlugins("/nonexistent/path");
    assert.strictEqual(plugins.loaded.length, 0);
  });
});
