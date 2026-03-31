// guardvibe-ignore — this file analyzes shell commands for security risks
import { resolve, basename } from "path";
import { existsSync, readdirSync } from "fs";

export interface CommandVerdict {
  verdict: "allow" | "ask" | "deny";
  risk: "critical" | "high" | "medium" | "low" | "none";
  confidence: number;
  category: string;
  reason: string;
  blastRadius: string;
  saferAlternative?: string;
  confirmationText?: string;
  details: string[];
}

interface CommandPattern {
  pattern: RegExp;
  category: string;
  verdict: "ask" | "deny";
  risk: "critical" | "high" | "medium" | "low";
  reason: string;
  blastRadius: string;
  saferAlternative?: string;
}

const DESTRUCTIVE_PATTERNS: CommandPattern[] = [
  // --- CRITICAL: data destruction ---
  { pattern: /\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?(-[a-zA-Z]*r[a-zA-Z]*\s+)?\/(?!\w)/, category: "filesystem-destroy",
    verdict: "deny", risk: "critical", reason: "Deletes from root filesystem",
    blastRadius: "Entire system", saferAlternative: "Specify exact path: rm -rf ./specific-dir" },
  { pattern: /\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+(?:~|\/home|\$HOME)/, category: "filesystem-destroy",
    verdict: "deny", risk: "critical", reason: "Recursive delete on home directory",
    blastRadius: "All user data", saferAlternative: "Specify the exact subdirectory" },
  { pattern: /\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+\.\s*$/, category: "filesystem-destroy",
    verdict: "deny", risk: "critical", reason: "Recursive delete on current directory",
    blastRadius: "Entire project", saferAlternative: "Delete specific files or use git clean -fd" },
  { pattern: /\bmkfs\b|\bdd\s+.*of=\/dev/, category: "filesystem-destroy",
    verdict: "deny", risk: "critical", reason: "Disk formatting / raw device write",
    blastRadius: "Entire disk/partition" },
  { pattern: />\s*\/dev\/sd[a-z]|>\s*\/dev\/nvme/, category: "filesystem-destroy",
    verdict: "deny", risk: "critical", reason: "Direct write to disk device",
    blastRadius: "Entire disk" },

  // --- HIGH: git history rewrite ---
  { pattern: /\bgit\s+push\s+.*--force(?!-with-lease)/, category: "git-rewrite",
    verdict: "ask", risk: "high", reason: "Force push overwrites remote history",
    blastRadius: "All collaborators lose commits", saferAlternative: "git push --force-with-lease" },
  { pattern: /\bgit\s+reset\s+--hard/, category: "git-rewrite",
    verdict: "ask", risk: "high", reason: "Hard reset discards uncommitted changes",
    blastRadius: "All staged and unstaged changes lost", saferAlternative: "git stash first, then reset" },
  { pattern: /\bgit\s+clean\s+-[a-zA-Z]*f/, category: "git-rewrite",
    verdict: "ask", risk: "high", reason: "Removes untracked files permanently",
    blastRadius: "All untracked files deleted", saferAlternative: "git clean -n (dry run first)" },
  { pattern: /\bgit\s+rebase\b/, category: "git-rewrite",
    verdict: "ask", risk: "medium", reason: "Rebase rewrites commit history",
    blastRadius: "Affected branch history", saferAlternative: "git merge (preserves history)" },
  { pattern: /\bgit\s+filter-branch\b|\bgit-filter-repo\b/, category: "git-rewrite",
    verdict: "ask", risk: "high", reason: "Rewrites entire repository history",
    blastRadius: "All commits, all collaborators affected" },

  // --- HIGH: deploy / publish ---
  { pattern: /\bnpm\s+publish\b/, category: "deploy",
    verdict: "ask", risk: "high", reason: "Publishes package to npm registry",
    blastRadius: "Public registry, all consumers", saferAlternative: "npm publish --dry-run first" },
  { pattern: /\bvercel\s+--prod\b|\bvercel\s+deploy\s+--prod/, category: "deploy",
    verdict: "ask", risk: "high", reason: "Deploys to production",
    blastRadius: "Production users", saferAlternative: "vercel (preview deploy first)" },
  { pattern: /\bdocker\s+push\b/, category: "deploy",
    verdict: "ask", risk: "high", reason: "Pushes container image to registry",
    blastRadius: "All image consumers" },
  { pattern: /\bterraform\s+(?:apply|destroy)\b/, category: "deploy",
    verdict: "ask", risk: "high", reason: "Modifies cloud infrastructure",
    blastRadius: "Cloud resources", saferAlternative: "terraform plan first" },
  { pattern: /\bkubectl\s+delete\b/, category: "deploy",
    verdict: "ask", risk: "high", reason: "Deletes Kubernetes resources",
    blastRadius: "Running services", saferAlternative: "kubectl delete --dry-run=client first" },

  // --- HIGH: secret exposure ---
  { pattern: /\benv\b|\bprintenv\b|\bset\b.*\|/, category: "secret-exposure",
    verdict: "ask", risk: "medium", reason: "May print environment variables containing secrets",
    blastRadius: "Secrets visible in terminal output" },
  { pattern: /\bcat\s+.*\.env\b|\bcat\s+.*secret|\bcat\s+.*credential/, category: "secret-exposure",
    verdict: "ask", risk: "high", reason: "Reads file likely containing secrets",
    blastRadius: "Secrets visible in output", saferAlternative: "Check .env exists without reading: ls -la .env" },
  { pattern: /\becho\s+.*(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL)/, category: "secret-exposure",
    verdict: "ask", risk: "high", reason: "Echoing potential secret value",
    blastRadius: "Secret visible in terminal/logs" },

  // --- HIGH: network exfiltration ---
  { pattern: /\bcurl\s+.*-(?:d|X\s*POST)\s+.*(?:pastebin|requestbin|webhook\.site|ngrok|pipedream)/, category: "exfiltration",
    verdict: "deny", risk: "critical", reason: "Sending data to external paste/webhook service",
    blastRadius: "Data exfiltration to third party" },
  { pattern: /\bcurl\s+.*--upload-file/, category: "exfiltration",
    verdict: "ask", risk: "high", reason: "Uploading file to external URL",
    blastRadius: "File contents sent externally" },
  { pattern: /\bwget\s+-O\s*-\s*.*\|\s*(?:bash|sh|zsh)/, category: "remote-exec",
    verdict: "deny", risk: "critical", reason: "Downloading and executing remote script",
    blastRadius: "Arbitrary code execution", saferAlternative: "Download first, review, then execute" },
  { pattern: /\bcurl\s+.*\|\s*(?:bash|sh|zsh)/, category: "remote-exec",
    verdict: "deny", risk: "critical", reason: "Piping remote content to shell",
    blastRadius: "Arbitrary code execution", saferAlternative: "Download first, review, then execute" },

  // --- MEDIUM: permission changes ---
  { pattern: /\bchmod\s+777\b/, category: "permission",
    verdict: "ask", risk: "medium", reason: "Sets world-readable/writable/executable permissions",
    blastRadius: "File accessible by all users", saferAlternative: "chmod 755 (dirs) or chmod 644 (files)" },
  { pattern: /\bchown\s+-R\s+root/, category: "permission",
    verdict: "ask", risk: "medium", reason: "Recursively changes ownership to root",
    blastRadius: "May lock out normal user access" },
  { pattern: /\bsudo\s/, category: "privilege-escalation",
    verdict: "ask", risk: "medium", reason: "Elevated privilege execution",
    blastRadius: "System-level access" },

  // --- MEDIUM: process/service manipulation ---
  { pattern: /\bkill\s+-9\b|\bkillall\b|\bpkill\b/, category: "process",
    verdict: "ask", risk: "medium", reason: "Forcefully terminates processes",
    blastRadius: "Running services may crash", saferAlternative: "kill (SIGTERM) instead of kill -9 (SIGKILL)" },
  { pattern: /\bsystemctl\s+(?:stop|restart|disable)\b/, category: "process",
    verdict: "ask", risk: "medium", reason: "Modifies system services",
    blastRadius: "Service availability affected" },

  // --- MEDIUM: database operations ---
  { pattern: /\bdrop\s+(?:database|table|schema)\b/i, category: "database",
    verdict: "deny", risk: "critical", reason: "Drops database object permanently",
    blastRadius: "Permanent data loss" },
  { pattern: /\btruncate\s+table\b/i, category: "database",
    verdict: "ask", risk: "high", reason: "Deletes all rows from table",
    blastRadius: "All table data lost" },
  { pattern: /\bDELETE\s+FROM\s+\w+\s*;?\s*$/i, category: "database",
    verdict: "ask", risk: "high", reason: "DELETE without WHERE clause deletes all rows",
    blastRadius: "All table data", saferAlternative: "Add WHERE clause" },
];

function analyzeContext(command: string, cwd: string): string[] {
  const details: string[] = [];

  // Check if command touches secret files
  const secretFiles = [".env", ".env.local", ".env.production", "credentials.json", "serviceAccountKey.json"];
  for (const sf of secretFiles) {
    if (command.includes(sf)) {
      details.push(`Accesses secret file: ${sf}`);
    }
  }

  // Check if cwd is a git repo
  if (existsSync(resolve(cwd, ".git"))) {
    if (/\bgit\s+push/.test(command)) {
      details.push("Pushes to remote repository from git-tracked directory");
    }
  }

  // Check if deploy configs exist and command may affect them
  const deployFiles = ["vercel.json", "fly.toml", "Dockerfile", "docker-compose.yml", ".github/workflows"];
  for (const df of deployFiles) {
    if (command.includes(basename(df)) || command.includes(df)) {
      details.push(`Modifies deploy config: ${df}`);
    }
  }

  // Check if touching CI/CD
  if (/\.github\/workflows|\.gitlab-ci|Jenkinsfile|\.circleci/.test(command)) {
    details.push("Modifies CI/CD pipeline configuration");
  }

  // Check if redirect/pipe to external
  if (/\|\s*(?:nc|netcat|ncat|socat)\b/.test(command)) {
    details.push("Pipes output through network tool — possible data exfiltration");
  }

  // Check for base64 encoding (obfuscation)
  if (/base64/.test(command) && /curl|wget|nc/.test(command)) {
    details.push("Combines encoding with network access — possible obfuscated exfiltration");
  }

  return details;
}

export function checkCommand(
  command: string,
  cwd: string = ".",
  branch?: string,
  format: "markdown" | "json" = "json"
): string {
  const resolvedCwd = resolve(cwd);
  const contextDetails = analyzeContext(command, resolvedCwd);

  let worstVerdict: CommandVerdict = {
    verdict: "allow",
    risk: "none",
    confidence: 0.9,
    category: "safe",
    reason: "No security risks detected",
    blastRadius: "None",
    details: contextDetails,
  };

  const riskOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, none: 4 };

  for (const pattern of DESTRUCTIVE_PATTERNS) {
    if (pattern.pattern.test(command)) {
      const currentRisk = riskOrder[worstVerdict.risk] ?? 4;
      const newRisk = riskOrder[pattern.risk] ?? 4;

      if (newRisk < currentRisk) {
        worstVerdict = {
          verdict: pattern.verdict,
          risk: pattern.risk,
          confidence: 0.85,
          category: pattern.category,
          reason: pattern.reason,
          blastRadius: pattern.blastRadius,
          saferAlternative: pattern.saferAlternative,
          confirmationText: pattern.verdict === "ask"
            ? `This command ${pattern.reason.toLowerCase()}. Proceed?`
            : undefined,
          details: contextDetails,
        };
      } else {
        // Still collect additional details
        worstVerdict.details.push(`Also matched: ${pattern.category} — ${pattern.reason}`);
      }
    }
  }

  // Branch-specific risks
  if (branch && ["main", "master", "production"].includes(branch)) {
    if (/\bgit\s+push\b/.test(command) && worstVerdict.verdict === "allow") {
      worstVerdict = {
        ...worstVerdict,
        verdict: "ask",
        risk: "medium",
        category: "protected-branch",
        reason: `Pushing to protected branch: ${branch}`,
        blastRadius: "Production codebase",
        confirmationText: `You are pushing to ${branch}. This affects production. Proceed?`,
      };
    }
  }

  // Boost confidence based on context
  if (contextDetails.length > 0 && worstVerdict.verdict !== "allow") {
    worstVerdict.confidence = Math.min(0.95, worstVerdict.confidence + contextDetails.length * 0.02);
  }

  if (format === "json") {
    return JSON.stringify(worstVerdict);
  }

  // Markdown
  const icon = worstVerdict.verdict === "deny" ? "BLOCKED"
    : worstVerdict.verdict === "ask" ? "NEEDS CONFIRMATION" : "SAFE";

  const lines = [
    `## GuardVibe Command Check: ${icon}`,
    ``,
    `**Command:** \`${command}\``,
    `**Verdict:** ${worstVerdict.verdict.toUpperCase()}`,
    `**Risk:** ${worstVerdict.risk}`,
    `**Category:** ${worstVerdict.category}`,
    `**Confidence:** ${Math.round(worstVerdict.confidence * 100)}%`,
    ``,
    `**Reason:** ${worstVerdict.reason}`,
    `**Blast radius:** ${worstVerdict.blastRadius}`,
  ];

  if (worstVerdict.saferAlternative) {
    lines.push(`**Safer alternative:** ${worstVerdict.saferAlternative}`);
  }
  if (worstVerdict.confirmationText) {
    lines.push(``, `> ${worstVerdict.confirmationText}`);
  }
  if (worstVerdict.details.length > 0) {
    lines.push(``, `**Context:**`);
    for (const d of worstVerdict.details) lines.push(`- ${d}`);
  }

  return lines.join("\n");
}
