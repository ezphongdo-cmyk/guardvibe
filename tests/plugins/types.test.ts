import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { GuardVibePlugin, GuardVibeTool } from "../../src/plugins/types.js";

describe("Plugin Types", () => {
  it("accepts a valid plugin with rules only", () => {
    const plugin: GuardVibePlugin = {
      name: "test-plugin",
      version: "1.0.0",
      rules: [
        {
          id: "TEST001", name: "Test Rule", severity: "medium",
          owasp: "A05:2025 Security Misconfiguration",
          description: "Test rule", pattern: /test/g,
          languages: ["javascript"], fix: "Fix it",
        },
      ],
    };
    assert.strictEqual(plugin.name, "test-plugin");
    assert.strictEqual(plugin.rules!.length, 1);
    assert.strictEqual(plugin.rules![0].id, "TEST001");
  });

  it("accepts a valid plugin with tools only", () => {
    const tool: GuardVibeTool = {
      name: "test_tool", description: "A test tool",
      schema: { input: { type: "string" } },
      handler: async () => "result",
    };
    const plugin: GuardVibePlugin = { name: "test-tools-plugin", version: "1.0.0", tools: [tool] };
    assert.strictEqual(plugin.tools!.length, 1);
    assert.strictEqual(plugin.tools![0].name, "test_tool");
  });

  it("accepts minimal plugin", () => {
    const plugin: GuardVibePlugin = { name: "minimal", version: "0.1.0" };
    assert.strictEqual(plugin.name, "minimal");
    assert.strictEqual(plugin.rules, undefined);
    assert.strictEqual(plugin.tools, undefined);
  });

  it("accepts plugin with all metadata", () => {
    const plugin: GuardVibePlugin = {
      name: "full-plugin", version: "2.0.0", description: "Full featured plugin",
      author: "GokLab", license: "pro", rules: [], tools: [],
    };
    assert.strictEqual(plugin.license, "pro");
    assert.strictEqual(plugin.author, "GokLab");
  });
});
