import type { SecurityRule } from "./types.js";

export const shellRules: SecurityRule[] = [
  {
    id: "VG530",
    name: "Pipe to shell execution",
    severity: "critical",
    owasp: "A02:2025 Injection",
    description:
      "Piping downloaded content directly to a shell interpreter (curl|bash, wget|sh) executes arbitrary remote code without inspection.",
    pattern: /(?:curl|wget)\s+[^|]*\|\s*(?:bash|sh|zsh|ksh|dash|source\s+\/dev\/stdin)|base64\s+(?:-d|--decode)\s+[^|]*\|\s*(?:bash|sh)/gi,
    languages: ["shell"],
    fix: "Download the script first, inspect it, then execute: curl -o script.sh URL && chmod +x script.sh && ./script.sh",
    fixCode:
      "# Download first, inspect, then run\ncurl -fsSL https://example.com/install.sh -o install.sh\ncat install.sh  # inspect it\nchmod +x install.sh\n./install.sh",
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1"],
  },
  {
    id: "VG531",
    name: "Dangerous file permissions",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "chmod 777 or overly permissive permissions (o+w) make files world-writable, creating a security risk.",
    pattern: /chmod\s+(?:777|666|a\+w|o\+w)\s+/gi,
    languages: ["shell"],
    fix: "Use least-privilege permissions. Typical: 755 for executables, 644 for files, 700 for private dirs.",
    fixCode:
      "# Use restrictive permissions\nchmod 755 script.sh    # owner rwx, others rx\nchmod 644 config.txt   # owner rw, others r\nchmod 700 ~/.ssh       # owner only",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req7"],
  },
  {
    id: "VG502",
    name: "Destructive rm command",
    severity: "critical",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "rm -rf on root or system directories can destroy the entire filesystem.",
    pattern: /rm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+(?:\/\s|\/\*|\/etc|\/usr|\/var|\/home|\/boot|\/sys|\/proc|\$\{?\w*\}?\s*\/)/gi,
    languages: ["shell"],
    fix: "Never rm -rf system directories. Use safeguards: check variables are non-empty before deletion.",
    fixCode:
      '# Always guard rm -rf with variable checks\nif [ -n "$DIR" ] && [ "$DIR" != "/" ]; then\n  rm -rf "$DIR"\nfi\n\n# Or use safe-rm: apt install safe-rm',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG533",
    name: "Password in command line",
    severity: "critical",
    owasp: "A07:2025 Auth Failures",
    description:
      "Passing passwords via echo/pipe to sudo or as command-line arguments exposes them in process lists and shell history.",
    pattern: /(?:echo\s+['"]?[^'"|\n]+['"]?\s*\|\s*sudo\s+-[Ss]|(?:mysql|psql|mongosh?)\s+.*-p\s*['"]?\w+['"]?)/gi,
    languages: ["shell"],
    fix: "Use SSH keys, sudo NOPASSWD for CI, or credential files instead of inline passwords.",
    fixCode:
      "# Use sudoers NOPASSWD for CI\n# visudo: user ALL=(ALL) NOPASSWD: /usr/bin/apt\n\n# Use .pgpass for PostgreSQL\necho 'host:5432:db:user:pass' > ~/.pgpass\nchmod 600 ~/.pgpass\n\n# Use mysql_config_editor for MySQL\nmysql_config_editor set --login-path=local --password",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req8", "HIPAA:§164.312(a)"],
  },
  {
    id: "VG534",
    name: "Unsafe eval/exec in shell",
    severity: "high",
    owasp: "A02:2025 Injection",
    description:
      "Using eval with variables in shell scripts can lead to code injection if the variable contains malicious input.",
    pattern: /\beval\s+['"]?\$[\{(]?\w+/gi,
    languages: ["shell"],
    fix: "Avoid eval with variables. Use arrays or direct execution instead.",
    fixCode:
      '# Instead of: eval "$cmd"\n# Use arrays:\ncmd=(ls -la /tmp)\n"${cmd[@]}"\n\n# Or case-based dispatch:\ncase "$action" in\n  start) start_service ;;\n  stop) stop_service ;;\nesac',
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1"],
  },
];
