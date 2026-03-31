import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parseManifest } from "../../src/utils/manifest-parser.js";

describe("manifest parser", () => {
  it("deduplicates repeated package.json dependencies and skips unsupported sources", () => {
    const packages = parseManifest(JSON.stringify({
      dependencies: {
        react: "^18.2.0",
        localLib: "file:../local-lib",
      },
      devDependencies: {
        react: "^18.2.0",
      },
      optionalDependencies: {
        tslib: "~2.6.0",
      },
    }), "package.json");

    assert.deepStrictEqual(packages, [
      { name: "react", version: "18.2.0", ecosystem: "npm" },
      { name: "tslib", version: "2.6.0", ecosystem: "npm" },
    ]);
  });

  it("extracts nested package-lock package names correctly", () => {
    const packages = parseManifest(JSON.stringify({
      packages: {
        "": {},
        "node_modules/a": { version: "1.0.0" },
        "node_modules/a/node_modules/b": { version: "2.0.0" },
      },
    }), "package-lock.json");

    assert.deepStrictEqual(packages, [
      { name: "a", version: "1.0.0", ecosystem: "npm" },
      { name: "b", version: "2.0.0", ecosystem: "npm" },
    ]);
  });

  it("deduplicates repeated go.mod requirements", () => {
    const packages = parseManifest(`
module example.com/app

require (
  github.com/go-chi/chi/v5 v5.0.10
)

require github.com/go-chi/chi/v5 v5.0.10
`, "go.mod");

    assert.deepStrictEqual(packages, [
      { name: "github.com/go-chi/chi/v5", version: "5.0.10", ecosystem: "Go" },
    ]);
  });

  it("rejects unsupported legacy manifests", () => {
    assert.throws(() => parseManifest("GEM", "Gemfile.lock"), /Unsupported manifest format/);
    assert.throws(() => parseManifest("[[package]]", "Cargo.lock"), /Unsupported manifest format/);
  });
});
