import type { SecurityRule } from "./types.js";

export const sqlRules: SecurityRule[] = [
  {
    id: "VG540",
    name: "Destructive DDL statement",
    severity: "critical",
    owasp: "A01:2025 Broken Access Control",
    description:
      "DROP TABLE/DATABASE in SQL can permanently destroy data. Ensure this is intentional and authorized.",
    pattern: /\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW)\s+(?:IF\s+EXISTS\s+)?)/gi,
    languages: ["sql"],
    fix: "Use migrations for schema changes. Restrict DROP privileges to admin roles only. Always backup before destructive DDL.",
    fixCode:
      "-- Use migrations instead of raw DROP\n-- In a migration file:\nALTER TABLE users RENAME TO users_backup;\n\n-- Restrict privileges\nREVOKE DROP ON SCHEMA public FROM app_user;",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req7"],
  },
  {
    id: "VG541",
    name: "Dangerous GRANT statement",
    severity: "critical",
    owasp: "A01:2025 Broken Access Control",
    description:
      "GRANT ALL PRIVILEGES or GRANT with wildcard grants excessive permissions. Follow the principle of least privilege.",
    pattern: /\bGRANT\s+ALL\s+(?:PRIVILEGES\s+)?ON\s+/gi,
    languages: ["sql"],
    fix: "Grant only the specific privileges needed: GRANT SELECT, INSERT ON table TO role.",
    fixCode:
      "-- Least privilege: grant only what's needed\nGRANT SELECT, INSERT ON users TO app_role;\n\n-- Never: GRANT ALL PRIVILEGES ON *.* TO 'user'@'%';",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req7", "HIPAA:§164.312(a)"],
  },
  {
    id: "VG542",
    name: "DELETE/UPDATE without WHERE",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "DELETE or UPDATE without a WHERE clause affects all rows in the table, which is almost always unintentional.",
    pattern: /\b(?:DELETE\s+FROM\s+\w+\s*;|UPDATE\s+\w+\s+SET\s+(?:(?!WHERE)[^;])*;)/gi,
    languages: ["sql"],
    fix: "Always include a WHERE clause. For bulk operations, use explicit WHERE 1=1 to show intent.",
    fixCode:
      "-- Always include WHERE\nDELETE FROM sessions WHERE expired_at < NOW();\n\n-- If you really want all rows, be explicit\nDELETE FROM temp_data WHERE 1=1;  -- explicit intent",
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG543",
    name: "SQL comment injection / stacked queries",
    severity: "high",
    owasp: "A02:2025 Injection",
    description:
      "SQL comment markers (--) or stacked queries (;) combined with suspicious keywords suggest SQL injection payload.",
    pattern: /;\s*(?:DROP|DELETE|INSERT|UPDATE|ALTER|GRANT|REVOKE|EXEC|EXECUTE|UNION)\b/gi,
    languages: ["sql"],
    fix: "Use parameterized queries. Never concatenate user input into SQL. Use an ORM where possible.",
    fixCode:
      "-- Use parameterized queries in application code\n-- Node.js: db.query('SELECT * FROM users WHERE id = $1', [id])\n-- Python: cursor.execute('SELECT * FROM users WHERE id = %s', (id,))",
    compliance: ["SOC2:CC7.1", "PCI-DSS:Req6.5.1"],
  },
];
