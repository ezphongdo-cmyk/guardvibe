import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeCode } from "../../src/tools/check-code.js";

function hasRule(code: string, ruleId: string, lang = "typescript"): boolean {
  const findings = analyzeCode(code, lang);
  return findings.some(f => f.rule.id === ruleId);
}

describe("OWASP API Security Rules", () => {
  // API1 — BOLA
  describe("VG950 - BOLA: Direct Object Reference", () => {
    it("detects findUnique with req.params.id without ownership", () => {
      assert(hasRule(
        `const item = await prisma.item.findUnique({ where: { id: req.params.id } });`,
        "VG950"
      ));
    });
    it("detects findFirst with params.id", () => {
      assert(hasRule(
        `const user = await db.user.findFirst({ where: { id: params.id } });`,
        "VG950"
      ));
    });
  });

  describe("VG951 - BOLA: Delete/Update Without Ownership", () => {
    it("detects delete with req.params.id only", () => {
      assert(hasRule(
        `await prisma.post.delete({ where: { id: req.params.id } });`,
        "VG951"
      ));
    });
    it("allows delete with userId in where clause", () => {
      assert(!hasRule(
        `await prisma.post.delete({ where: { id: req.params.id, userId } });`,
        "VG951"
      ));
    });
  });

  // API3 — Mass Assignment
  describe("VG953 - Mass Assignment: Spread Request Body", () => {
    it("detects spreading req.body into create", () => {
      assert(hasRule(
        `await prisma.user.create({ ...req.body });`,
        "VG953"
      ));
    });
    it("detects data: body in update", () => {
      assert(hasRule(
        `await prisma.user.update({ where: { id }, data: body });`,
        "VG953"
      ));
    });
  });

  describe("VG954 - Mass Assignment: Object.assign", () => {
    it("detects Object.assign(user, req.body)", () => {
      assert(hasRule(
        `Object.assign(user, req.body);`,
        "VG954"
      ));
    });
    it("detects Object.assign(item, input)", () => {
      assert(hasRule(
        `Object.assign(item, input);`,
        "VG954"
      ));
    });
  });

  // API4 — Resource Consumption
  describe("VG955 - Missing Pagination", () => {
    it("detects findMany without limit/take", () => {
      assert(hasRule(
        `const items = await prisma.item.findMany({ where: { active: true } });`,
        "VG955"
      ));
    });
    it("allows findMany with take", () => {
      assert(!hasRule(
        `const items = await prisma.item.findMany({ where: { active: true }, take: 20 });`,
        "VG955"
      ));
    });
  });

  // API8 — Security Misconfiguration
  describe("VG959 - Verbose Error Leaks", () => {
    it("detects error.message in response", () => {
      assert(hasRule(
        `catch (error) { return Response.json({ error: error.message }, { status: 500 }); }`,
        "VG959"
      ));
    });
    it("detects error.stack in response", () => {
      assert(hasRule(
        `catch (err) { res.json({ error: err.stack }); }`,
        "VG959"
      ));
    });
  });
});
