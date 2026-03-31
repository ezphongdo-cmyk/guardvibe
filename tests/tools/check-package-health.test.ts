import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { assessPackageRisk } from "../../src/tools/check-package-health.js";

describe("Package Risk Assessment (offline)", () => {
  it("flags typosquat as critical", () => {
    const result = assessPackageRisk("expres", {
      exists: true, downloads: 50, lastPublish: new Date().toISOString(), maintainers: 1, deprecated: false,
    });
    assert.strictEqual(result.risk, "critical");
    assert(result.flags.some(f => f.type === "typosquat"));
    assert.strictEqual(result.similarTo, "express");
  });

  it("flags deprecated as high", () => {
    const result = assessPackageRisk("some-package", {
      exists: true, downloads: 5000, lastPublish: "2025-01-01", maintainers: 3, deprecated: true,
    });
    assert.strictEqual(result.risk, "high");
    assert(result.flags.some(f => f.type === "deprecated"));
  });

  it("flags unmaintained package", () => {
    const result = assessPackageRisk("some-package", {
      exists: true, downloads: 5000, lastPublish: "2023-01-01", maintainers: 1, deprecated: false,
    });
    assert(result.flags.some(f => f.type === "unmaintained"));
  });

  it("flags low adoption", () => {
    const result = assessPackageRisk("some-package", {
      exists: true, downloads: 50, lastPublish: "2026-03-01", maintainers: 1, deprecated: false,
    });
    assert(result.flags.some(f => f.type === "low_adoption"));
  });

  it("returns low risk for healthy package", () => {
    const result = assessPackageRisk("express", {
      exists: true, downloads: 30000000, lastPublish: "2026-03-15", maintainers: 5, deprecated: false,
    });
    assert.strictEqual(result.risk, "low");
    assert.strictEqual(result.flags.length, 0);
  });

  it("handles non-existent package", () => {
    const result = assessPackageRisk("nonexistent-xyz-123", {
      exists: false, downloads: 0, lastPublish: "", maintainers: 0, deprecated: false,
    });
    assert.strictEqual(result.risk, "critical");
  });
});
