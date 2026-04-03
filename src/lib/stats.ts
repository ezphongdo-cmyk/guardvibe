import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { join, resolve } from "path";

// ─── Types ────────────────────────────────────────────────────────

export interface MonthlyStats {
  scans: number;
  filesScanned: number;
  findingsTotal: number;
  findingsFixed: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface GradeEntry {
  date: string; // YYYY-MM-DD
  grade: string;
  score: number;
}

export interface StatsData {
  version: number;
  firstScan: string;
  lastScan: string;
  totals: {
    scans: number;
    filesScanned: number;
    findingsTotal: number;
    findingsFixed: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    autoFixesApplied: number;
    secretsCaught: number;
    dependencyCVEs: number;
  };
  monthly: Record<string, MonthlyStats>;
  tools: Record<string, number>;
  topRules: Record<string, number>;
  grades: GradeEntry[];
}

// ─── Helpers ──────────────────────────────────────────────────────

function emptyStats(): StatsData {
  return {
    version: 1,
    firstScan: "",
    lastScan: "",
    totals: {
      scans: 0,
      filesScanned: 0,
      findingsTotal: 0,
      findingsFixed: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      autoFixesApplied: 0,
      secretsCaught: 0,
      dependencyCVEs: 0,
    },
    monthly: {},
    tools: {},
    topRules: {},
    grades: [],
  };
}

function getMonthKey(): string {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
}

function getTodayKey(): string {
  return new Date().toISOString().slice(0, 10);
}

function statsDir(projectRoot: string): string {
  return join(resolve(projectRoot), ".guardvibe");
}

function statsPath(projectRoot: string): string {
  return join(statsDir(projectRoot), "stats.json");
}

// ─── Core I/O ─────────────────────────────────────────────────────

export function loadStats(projectRoot: string): StatsData {
  try {
    const p = statsPath(projectRoot);
    if (!existsSync(p)) return emptyStats();
    const raw = readFileSync(p, "utf-8");
    return JSON.parse(raw) as StatsData;
  } catch {
    return emptyStats();
  }
}

function saveStats(projectRoot: string, data: StatsData): void {
  try {
    const dir = statsDir(projectRoot);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(statsPath(projectRoot), JSON.stringify(data, null, 2), "utf-8");
  } catch {
    // Stats write failure must never break scans — silently continue
  }
}

function ensureMonth(data: StatsData, key: string): MonthlyStats {
  if (!data.monthly[key]) {
    data.monthly[key] = {
      scans: 0, filesScanned: 0, findingsTotal: 0, findingsFixed: 0,
      critical: 0, high: 0, medium: 0, low: 0,
    };
  }
  return data.monthly[key];
}

// ─── Recording Functions ──────────────────────────────────────────

export interface ScanResult {
  toolName: string;
  filesScanned: number;
  findings: Array<{
    severity: string;
    ruleId: string;
  }>;
}

export function recordScan(projectRoot: string, result: ScanResult): void {
  const data = loadStats(projectRoot);
  const now = new Date().toISOString();
  const month = getMonthKey();

  if (!data.firstScan) data.firstScan = now;
  data.lastScan = now;

  // Totals
  data.totals.scans++;
  data.totals.filesScanned += result.filesScanned;
  data.totals.findingsTotal += result.findings.length;

  // Severity counts
  for (const f of result.findings) {
    const sev = f.severity as keyof Pick<typeof data.totals, "critical" | "high" | "medium" | "low">;
    if (sev in data.totals && typeof data.totals[sev] === "number") {
      (data.totals[sev] as number)++;
    }
    // Top rules
    data.topRules[f.ruleId] = (data.topRules[f.ruleId] || 0) + 1;
  }

  // Tool usage
  data.tools[result.toolName] = (data.tools[result.toolName] || 0) + 1;

  // Monthly
  const m = ensureMonth(data, month);
  m.scans++;
  m.filesScanned += result.filesScanned;
  m.findingsTotal += result.findings.length;
  for (const f of result.findings) {
    const sev = f.severity as keyof MonthlyStats;
    if (sev in m && typeof m[sev] === "number") {
      (m[sev] as number)++;
    }
  }

  saveStats(projectRoot, data);
}

export function recordFix(projectRoot: string, fixCount: number): void {
  const data = loadStats(projectRoot);
  const month = getMonthKey();

  data.totals.findingsFixed += fixCount;
  data.totals.autoFixesApplied += fixCount;
  const m = ensureMonth(data, month);
  m.findingsFixed += fixCount;

  saveStats(projectRoot, data);
}

export function recordSecrets(projectRoot: string, count: number): void {
  const data = loadStats(projectRoot);
  data.totals.secretsCaught += count;
  saveStats(projectRoot, data);
}

export function recordDependencyCVEs(projectRoot: string, count: number): void {
  const data = loadStats(projectRoot);
  data.totals.dependencyCVEs += count;
  saveStats(projectRoot, data);
}

export function recordGrade(projectRoot: string, grade: string, score: number): void {
  const data = loadStats(projectRoot);
  const today = getTodayKey();

  // Replace today's entry if exists, otherwise append
  const idx = data.grades.findIndex((g) => g.date === today);
  if (idx >= 0) {
    data.grades[idx] = { date: today, grade, score };
  } else {
    data.grades.push({ date: today, grade, score });
    // Keep last 90 days max
    if (data.grades.length > 90) data.grades = data.grades.slice(-90);
  }

  saveStats(projectRoot, data);
}

// ─── Summary Line (appended to scan output) ───────────────────────

export function getSummaryLine(
  projectRoot: string,
  currentFindings: number,
  format: "markdown" | "json"
): string {
  try {
    const data = loadStats(projectRoot);
    const month = getMonthKey();
    const m = data.monthly[month];
    const monthlyFixed = m?.findingsFixed ?? 0;
    const monthlyTotal = m?.findingsTotal ?? 0;

    // Latest grade
    const latestGrade = data.grades.length > 0
      ? data.grades[data.grades.length - 1]
      : null;

    // Trend: compare current grade to first grade this month
    const monthGrades = data.grades.filter((g) => g.date.startsWith(month));
    let trend = "";
    if (monthGrades.length >= 2) {
      const first = monthGrades[0].score;
      const last = monthGrades[monthGrades.length - 1].score;
      if (last > first) trend = " (improving)";
      else if (last < first) trend = " (declining)";
    }

    if (format === "json") {
      return JSON.stringify({
        guardvibeStats: {
          sessionFindings: currentFindings,
          monthlyTotal,
          monthlyFixed,
          allTimeFixed: data.totals.findingsFixed,
          currentGrade: latestGrade?.grade ?? null,
          trend: trend.replace(/[() ]/g, "") || "stable",
        },
      });
    }

    // Markdown — single line
    const parts = [
      `${currentFindings} issues caught`,
      monthlyFixed > 0 ? `${monthlyFixed} fixed this month` : null,
      latestGrade ? `Grade: ${latestGrade.grade}${trend}` : null,
    ].filter(Boolean);

    return `\n---\n**GuardVibe** · ${parts.join(" · ")}`;
  } catch {
    return "";
  }
}

// ─── Dashboard (security_stats tool) ──────────────────────────────

export function generateDashboard(
  projectRoot: string,
  period: "week" | "month" | "all",
  format: "markdown" | "json"
): string {
  const data = loadStats(projectRoot);

  if (data.totals.scans === 0) {
    const empty = "No security scans recorded yet. GuardVibe will track statistics automatically as you scan files.";
    return format === "json"
      ? JSON.stringify({ status: "empty", message: empty })
      : empty;
  }

  const month = getMonthKey();
  const m = data.monthly[month] ?? {
    scans: 0, filesScanned: 0, findingsTotal: 0, findingsFixed: 0,
    critical: 0, high: 0, medium: 0, low: 0,
  };

  // Top rules — sorted by count
  const topRules = Object.entries(data.topRules)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5);

  // Top tools — sorted by count
  const topTools = Object.entries(data.tools)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5);

  // Grade trend
  const recentGrades = data.grades.slice(-7);
  const gradeStr = recentGrades.map((g) => `${g.grade} (${g.date.slice(5)})`).join(" -> ");

  // Fix rate
  const fixRate = data.totals.findingsTotal > 0
    ? Math.round((data.totals.findingsFixed / data.totals.findingsTotal) * 100)
    : 0;
  const monthFixRate = m.findingsTotal > 0
    ? Math.round((m.findingsFixed / m.findingsTotal) * 100)
    : 0;

  if (format === "json") {
    return JSON.stringify({
      project: projectRoot,
      period,
      currentMonth: m,
      allTime: data.totals,
      fixRate: { monthly: monthFixRate, allTime: fixRate },
      topRules,
      topTools,
      gradeHistory: recentGrades,
      firstScan: data.firstScan,
      lastScan: data.lastScan,
    });
  }

  // Markdown dashboard
  const lines = [
    `# GuardVibe Security Dashboard`,
    ``,
    `**Project:** ${projectRoot}`,
    `**Tracking since:** ${data.firstScan.slice(0, 10)}`,
    `**Last scan:** ${data.lastScan.slice(0, 10)}`,
    ``,
    `## Impact Summary`,
    `| Metric | This Month | All Time |`,
    `|--------|-----------|----------|`,
    `| Scans run | ${m.scans} | ${data.totals.scans} |`,
    `| Files protected | ${m.filesScanned} | ${data.totals.filesScanned} |`,
    `| Vulnerabilities caught | ${m.findingsTotal} | ${data.totals.findingsTotal} |`,
    `| Vulnerabilities fixed | ${m.findingsFixed} | ${data.totals.findingsFixed} |`,
    `| Fix rate | ${monthFixRate}% | ${fixRate}% |`,
    `| Secrets intercepted | — | ${data.totals.secretsCaught} |`,
    `| Dependency CVEs found | — | ${data.totals.dependencyCVEs} |`,
    ``,
  ];

  if (recentGrades.length > 0) {
    lines.push(`## Security Grade Trend`, gradeStr, ``);
  }

  if (topRules.length > 0) {
    lines.push(`## Top Caught Vulnerabilities`);
    for (const [ruleId, count] of topRules) {
      lines.push(`- ${ruleId} — ${count} times`);
    }
    lines.push(``);
  }

  if (topTools.length > 0) {
    lines.push(`## Most Used Tools`);
    for (const [tool, count] of topTools) {
      lines.push(`- ${tool} — ${count} calls`);
    }
    lines.push(``);
  }

  lines.push(`---`, `Protected by GuardVibe · guardvibe.dev`);

  return lines.join("\n");
}
