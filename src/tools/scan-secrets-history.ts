import { execFileSync } from "child_process";
import { resolve } from "path";
import { scanContent, type SecretFinding } from "./scan-secrets.js";

export interface HistorySecretFinding extends SecretFinding {
  commit: string;
  commitDate: string;
  author: string;
  status: "active" | "removed";
}

interface CommitInfo {
  hash: string;
  date: string;
  author: string;
}

function execGit(args: string[], cwd: string): string {
  try {
    return execFileSync("git", args, { cwd, encoding: "utf-8", timeout: 30000 });
  } catch {
    return "";
  }
}

function getCommitList(cwd: string, maxCommits: number): CommitInfo[] {
  const output = execGit(["log", `--max-count=${maxCommits}`, "--format=%H|||%aI|||%an", "--all"], cwd);
  return output.trim().split("\n").filter(Boolean).map(line => {
    const [hash, date, author] = line.split("|||");
    return { hash, date, author };
  });
}

function getCommitDiff(cwd: string, commitHash: string): string {
  return execGit(["diff-tree", "--no-commit-id", "-r", "--diff-filter=ACMR", "--name-only", commitHash], cwd);
}

function getFileAtCommit(cwd: string, commitHash: string, filePath: string): string | null {
  try {
    return execFileSync("git", ["show", `${commitHash}:${filePath}`], {
      cwd, encoding: "utf-8", timeout: 10000,
    });
  } catch {
    return null;
  }
}

function _fileExistsAtHead(cwd: string, filePath: string): boolean {
  const result = execGit(["cat-file", "-e", `HEAD:${filePath}`], cwd);
  // cat-file -e returns empty on success, error message on failure
  return result === "";
}

function getFileAtHead(cwd: string, filePath: string): string | null {
  try {
    return execFileSync("git", ["show", `HEAD:${filePath}`], {
      cwd, encoding: "utf-8", timeout: 10000,
    });
  } catch {
    return null;
  }
}

export function scanSecretsHistory(
  path: string,
  maxCommits: number = 100,
  format: "markdown" | "json" = "markdown"
): string {
  const cwd = resolve(path);
  const commits = getCommitList(cwd, maxCommits);

  if (commits.length === 0) {
    if (format === "json") return JSON.stringify({ summary: { total: 0, commits: 0 }, findings: [] });
    return "# GuardVibe Git History Secret Scan\n\nNo git history found.";
  }

  const allFindings: HistorySecretFinding[] = [];
  const seenKeys = new Set<string>();

  // Scan secrets introduced in each commit's changed files
  for (const commit of commits) {
    const changedFiles = getCommitDiff(cwd, commit.hash).trim().split("\n").filter(Boolean);

    for (const file of changedFiles) {
      // Only scan files likely to contain secrets
      if (/\.(png|jpg|gif|ico|woff|ttf|eot|svg|mp4|webm|zip|tar|gz|lock)$/i.test(file)) continue;

      const content = getFileAtCommit(cwd, commit.hash, file);
      if (!content || content.length > 500_000) continue;

      const findings = scanContent(content, file);
      for (const f of findings) {
        const key = `${f.provider}:${file}:${f.match}`;
        if (seenKeys.has(key)) continue;
        seenKeys.add(key);

        // Check if this secret still exists at HEAD
        const headContent = getFileAtHead(cwd, file);
        const stillPresent = headContent ? headContent.includes(f.match.replace("...", "")) : false;

        allFindings.push({
          ...f,
          commit: commit.hash.substring(0, 8),
          commitDate: commit.date,
          author: commit.author,
          status: stillPresent ? "active" : "removed",
        });
      }
    }
  }

  // Sort: active first, then by severity
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2 };
  allFindings.sort((a, b) => {
    if (a.status !== b.status) return a.status === "active" ? -1 : 1;
    return (severityOrder[a.severity] ?? 3) - (severityOrder[b.severity] ?? 3);
  });

  const activeCount = allFindings.filter(f => f.status === "active").length;
  const removedCount = allFindings.filter(f => f.status === "removed").length;

  if (format === "json") {
    return JSON.stringify({
      summary: {
        total: allFindings.length,
        active: activeCount,
        removed: removedCount,
        commitsScanned: commits.length,
        critical: allFindings.filter(f => f.severity === "critical").length,
        high: allFindings.filter(f => f.severity === "high").length,
      },
      findings: allFindings.map(f => ({
        provider: f.provider, severity: f.severity, file: f.file,
        line: f.line, match: f.match, fix: f.fix,
        commit: f.commit, commitDate: f.commitDate, author: f.author,
        status: f.status,
      })),
    });
  }

  const lines: string[] = [
    `# GuardVibe Git History Secret Scan`,
    ``,
    `Commits scanned: ${commits.length}`,
    `Secrets found: ${allFindings.length}`,
    `Active (still in code): ${activeCount}`,
    `Removed (in git history only): ${removedCount}`,
    ``,
  ];

  if (allFindings.length === 0) {
    lines.push(`No secrets found in git history. Clean!`);
    return lines.join("\n");
  }

  if (activeCount > 0) {
    lines.push(`## Active Secrets (URGENT — still in codebase)`, ``);
    for (const f of allFindings.filter(f => f.status === "active")) {
      lines.push(
        `### [${f.severity.toUpperCase()}] ${f.provider}`,
        `**File:** ${f.file}:${f.line}`,
        `**Match:** \`${f.match}\``,
        `**Introduced:** ${f.commit} (${f.commitDate.split("T")[0]}) by ${f.author}`,
        `**Fix:** ${f.fix}`,
        ``,
      );
    }
  }

  if (removedCount > 0) {
    lines.push(`## Removed Secrets (still in git history — rotate these!)`, ``);
    lines.push(`> These secrets were removed from the codebase but remain in git history.`);
    lines.push(`> Anyone with repo access can find them. **Rotate all of these immediately.**`, ``);
    for (const f of allFindings.filter(f => f.status === "removed")) {
      lines.push(
        `- **[${f.severity.toUpperCase()}] ${f.provider}** in \`${f.file}\` — commit ${f.commit} (${f.commitDate.split("T")[0]})`,
        `  Match: \`${f.match}\` | Fix: ${f.fix}`,
        ``,
      );
    }
  }

  return lines.join("\n");
}
