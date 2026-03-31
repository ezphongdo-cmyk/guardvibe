import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { detectTyposquat, levenshtein } from "../../src/utils/typosquat.js";

describe("Levenshtein Distance", () => {
  it("identical strings = 0", () => {
    assert.strictEqual(levenshtein("express", "express"), 0);
  });
  it("one char difference = 1", () => {
    assert.strictEqual(levenshtein("express", "expresss"), 1);
  });
  it("two char swap = 2", () => {
    assert.strictEqual(levenshtein("express", "exprses"), 2);
  });
  it("completely different", () => {
    assert(levenshtein("abc", "xyz") > 2);
  });
});

describe("Typosquat Detection", () => {
  it("detects typosquat of express", () => {
    const result = detectTyposquat("expres");
    assert(result);
    assert.strictEqual(result!.similarTo, "express");
    assert(result!.confidence > 0.5);
  });
  it("detects typosquat with extra char", () => {
    const result = detectTyposquat("expresss");
    assert(result);
    assert.strictEqual(result!.similarTo, "express");
  });
  it("detects typosquat of react", () => {
    const result = detectTyposquat("recat");
    assert(result);
    assert.strictEqual(result!.similarTo, "react");
  });
  it("returns null for legitimate package", () => {
    assert.strictEqual(detectTyposquat("express"), null);
  });
  it("returns null for unrelated package", () => {
    assert.strictEqual(detectTyposquat("my-custom-lib"), null);
  });
});
