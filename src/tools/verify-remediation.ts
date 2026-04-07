/**
 * Verify Remediation — compares before/after audit results and
 * explicitly flags sections that were skipped or not improved.
 *
 * This is the final gate: AI assistants MUST call this after
 * completing remediation. It refuses to return PASS unless
 * ALL sections are addressed.
 */

import { runFullAudit, type AuditResult } from "./full-audit.js";
import { resolve } from "node:path";

export interface SectionComparison {
  section: string;
  before: { findings: number; critical: number; high: number; medium: number };
  after: { findings: number; critical: number; high: number; medium: number };
  findingsResolved: number;
  findingsRemaining: number;
  findingsNew: number;
  status: "fully_resolved" | "improved" | "unchanged" | "worsened";
  skipped: boolean;
}

export interface RemediationVerification {
  overallStatus: "complete" | "incomplete" | "failed";
  beforeHash: string;
  afterHash: string;
  beforeVerdict: string;
  afterVerdict: string;
  beforeScore: number;
  afterScore: number;
  sections: SectionComparison[];
  skippedSections: string[];
  unresolvedCritical: number;
  unresolvedHigh: number;
  summary: string;
  nextActions: string[];
}

/**
 * Run a fresh audit and compare against the "before" snapshot.
 * Returns a detailed section-by-section comparison showing what
 * was fixed, what was skipped, and what remains.
 */
export async function verifyRemediation(
  beforeResult: AuditResult,
  projectPath: string,
): Promise<RemediationVerification> {
  const afterResult = await runFullAudit(resolve(projectPath));

  const sections: SectionComparison[] = [];
  const skippedSections: string[] = [];
  let unresolvedCritical = 0;
  let unresolvedHigh = 0;

  // Compare each section from before
  for (const beforeSection of beforeResult.sections) {
    const afterSection = afterResult.sections.find(s => s.name === beforeSection.name);
    const after = afterSection ?? { findings: 0, critical: 0, high: 0, medium: 0 };

    const findingsResolved = Math.max(0, beforeSection.findings - after.findings);
    const findingsNew = Math.max(0, after.findings - beforeSection.findings);
    const findingsRemaining = after.findings;

    let status: SectionComparison["status"];
    if (after.findings === 0) {
      status = "fully_resolved";
    } else if (after.findings < beforeSection.findings) {
      status = "improved";
    } else if (after.findings === beforeSection.findings) {
      status = "unchanged";
    } else {
      status = "worsened";
    }

    // A section is "skipped" if it had findings before and nothing changed
    const skipped = beforeSection.findings > 0 && status === "unchanged";
    if (skipped) {
      skippedSections.push(beforeSection.name);
    }

    unresolvedCritical += after.critical;
    unresolvedHigh += after.high;

    sections.push({
      section: beforeSection.name,
      before: {
        findings: beforeSection.findings,
        critical: beforeSection.critical,
        high: beforeSection.high,
        medium: beforeSection.medium,
      },
      after: {
        findings: after.findings,
        critical: after.critical,
        high: after.high,
        medium: after.medium,
      },
      findingsResolved,
      findingsRemaining,
      findingsNew,
      status,
      skipped,
    });
  }

  // Check for new sections in after that weren't in before
  for (const afterSection of afterResult.sections) {
    if (!sections.find(s => s.section === afterSection.name)) {
      sections.push({
        section: afterSection.name,
        before: { findings: 0, critical: 0, high: 0, medium: 0 },
        after: {
          findings: afterSection.findings,
          critical: afterSection.critical,
          high: afterSection.high,
          medium: afterSection.medium,
        },
        findingsResolved: 0,
        findingsRemaining: afterSection.findings,
        findingsNew: afterSection.findings,
        status: afterSection.findings > 0 ? "worsened" : "fully_resolved",
        skipped: false,
      });
    }
  }

  // Overall status
  let overallStatus: RemediationVerification["overallStatus"];
  if (afterResult.verdict === "PASS") {
    overallStatus = "complete";
  } else if (skippedSections.length > 0) {
    overallStatus = "incomplete";
  } else if (unresolvedCritical > 0) {
    overallStatus = "failed";
  } else {
    overallStatus = "incomplete";
  }

  // Build summary
  const totalBefore = beforeResult.summary.totalFindings;
  const totalAfter = afterResult.summary.totalFindings;
  const totalFixed = totalBefore - totalAfter;

  let summary: string;
  if (overallStatus === "complete") {
    summary = `Remediation complete. All findings resolved. Score: ${beforeResult.score} → ${afterResult.score}. Verdict: PASS.`;
  } else if (skippedSections.length > 0) {
    summary = `INCOMPLETE — ${skippedSections.length} section(s) were SKIPPED: ${skippedSections.join(", ")}. ${totalFixed} findings fixed out of ${totalBefore}, but ${totalAfter} remain. The skipped sections were not addressed at all.`;
  } else {
    summary = `${totalFixed} findings fixed (${totalBefore} → ${totalAfter}), but ${unresolvedCritical} critical and ${unresolvedHigh} high remain. Score: ${beforeResult.score} → ${afterResult.score}.`;
  }

  // Next actions for incomplete remediation
  const nextActions: string[] = [];
  for (const section of sections) {
    if (section.skipped) {
      nextActions.push(`[SKIPPED] Section "${section.section}": ${section.before.findings} findings were completely ignored. Run the appropriate tool to fix them.`);
    } else if (section.status === "improved" && section.findingsRemaining > 0) {
      nextActions.push(`[PARTIAL] Section "${section.section}": ${section.findingsResolved} fixed, ${section.findingsRemaining} remaining (${section.after.critical} critical, ${section.after.high} high).`);
    } else if (section.status === "worsened") {
      nextActions.push(`[WORSENED] Section "${section.section}": findings increased from ${section.before.findings} to ${section.after.findings}. Investigate new findings.`);
    }
  }

  if (skippedSections.length > 0) {
    nextActions.push(`\nACTION REQUIRED: Go back and address ALL skipped sections before declaring remediation complete. Use remediation_plan to get the specific tool sequence for each section.`);
  }

  return {
    overallStatus,
    beforeHash: beforeResult.resultHash,
    afterHash: afterResult.resultHash,
    beforeVerdict: beforeResult.verdict,
    afterVerdict: afterResult.verdict,
    beforeScore: beforeResult.score,
    afterScore: afterResult.score,
    sections,
    skippedSections,
    unresolvedCritical,
    unresolvedHigh,
    summary,
    nextActions,
  };
}

export function formatRemediationVerification(
  result: RemediationVerification,
  format: "markdown" | "json",
): string {
  if (format === "json") {
    return JSON.stringify(result);
  }

  const lines: string[] = [
    "# GuardVibe Remediation Verification",
    "",
  ];

  // Status banner
  if (result.overallStatus === "complete") {
    lines.push("## ✅ COMPLETE — All sections clear");
  } else if (result.overallStatus === "incomplete") {
    lines.push("## ❌ INCOMPLETE — Sections were skipped or partially fixed");
  } else {
    lines.push("## ❌ FAILED — Critical findings remain");
  }

  lines.push("");
  lines.push(`| Metric | Before | After |`);
  lines.push(`|--------|--------|-------|`);
  lines.push(`| Verdict | ${result.beforeVerdict} | ${result.afterVerdict} |`);
  lines.push(`| Score | ${result.beforeScore}/100 | ${result.afterScore}/100 |`);
  lines.push(`| Hash | \`${result.beforeHash}\` | \`${result.afterHash}\` |`);
  lines.push("");

  // Section-by-section comparison
  lines.push("## Section Comparison");
  lines.push("");
  lines.push("| Section | Before | After | Status | Skipped? |");
  lines.push("|---------|--------|-------|--------|----------|");

  for (const s of result.sections) {
    const statusIcon = s.status === "fully_resolved" ? "✅"
      : s.status === "improved" ? "🔶"
      : s.status === "unchanged" ? "🔴"
      : "⛔";
    const skippedMark = s.skipped ? "**YES — NOT ADDRESSED**" : "no";
    lines.push(`| ${s.section} | ${s.before.findings} | ${s.after.findings} | ${statusIcon} ${s.status} | ${skippedMark} |`);
  }

  // Skipped sections warning
  if (result.skippedSections.length > 0) {
    lines.push("");
    lines.push("## ⚠️ SKIPPED SECTIONS");
    lines.push("");
    lines.push("The following sections had findings but were **completely ignored** during remediation:");
    lines.push("");
    for (const name of result.skippedSections) {
      const section = result.sections.find(s => s.section === name)!;
      lines.push(`- **${name}**: ${section.before.findings} findings (${section.before.critical} critical, ${section.before.high} high) — ZERO progress`);
    }
    lines.push("");
    lines.push("> **You cannot declare remediation complete while sections are skipped.** Use `remediation_plan` to get the specific actions for each skipped section.");
  }

  // Next actions
  if (result.nextActions.length > 0) {
    lines.push("");
    lines.push("## Next Actions");
    lines.push("");
    for (const action of result.nextActions) {
      lines.push(`- ${action}`);
    }
  }

  // Summary
  lines.push("");
  lines.push("---");
  lines.push(`**${result.summary}**`);

  return lines.join("\n");
}
