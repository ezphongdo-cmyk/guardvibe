import type { SecurityRule } from "./types.js";

// === Go-specific rules ===
export const goRules: SecurityRule[] = [
  {
    id: "VG110",
    name: "Go SQL injection via fmt.Sprintf",
    severity: "critical",
    owasp: "A02:2025 Injection",
    description:
      "Using fmt.Sprintf to build SQL queries allows SQL injection attacks.",
    pattern: /(?:db\.(?:Query|Exec|QueryRow)|\.Query|\.Exec)\s*\(\s*fmt\.Sprintf/gi,
    languages: ["go"],
    fix: "Use parameterized queries: db.Query('SELECT * FROM users WHERE id = $1', id). Never use fmt.Sprintf for SQL.",
    fixCode: "// Use parameterized queries\nrows, err := db.Query(\"SELECT * FROM users WHERE id = $1\", id)",
  },
  {
    id: "VG111",
    name: "Go command injection via os/exec",
    severity: "critical",
    owasp: "A02:2025 Injection",
    description:
      "User input passed to os/exec command functions allows arbitrary command execution.",
    pattern: /exec\.Command\s*\(\s*(?:fmt\.Sprintf|[^")\s]+\s*\+|[^")]*\+)/gi,
    languages: ["go"],
    fix: "Validate and sanitize all input before passing to exec.Command. Use an allowlist of permitted commands.",
    fixCode: "// Validate input, use allowlist\ncmd := exec.Command(\"ls\", \"-la\", safeDir)",
  },
  {
    id: "VG112",
    name: "Go unescaped HTML template",
    severity: "high",
    owasp: "A02:2025 Injection",
    description:
      "Using template.HTML() bypasses Go's automatic HTML escaping, enabling XSS.",
    pattern: /template\.HTML\s*\(/gi,
    languages: ["go"],
    fix: "Avoid template.HTML() with user input. Use html/template which auto-escapes by default.",
    fixCode: "// Use html/template which auto-escapes\n// Avoid template.HTML() with user input\ntmpl.Execute(w, data) // auto-escaped",
  },
  {
    id: "VG113",
    name: "Go HTTP handler without auth",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "HTTP handler registered without authentication middleware.",
    pattern: /(?:http\.HandleFunc|mux\.HandleFunc|\.HandleFunc)\s*\(\s*['"]\/(?:api|admin|users|account|dashboard)/gi,
    languages: ["go"],
    fix: "Wrap handlers with authentication middleware: http.Handle('/api/', authMiddleware(handler)).",
    fixCode: "// Wrap with auth middleware\nhttp.Handle(\"/api/\", authMiddleware(apiHandler))",
  },
  {
    id: "VG114",
    name: "Go weak hashing",
    severity: "critical",
    owasp: "A07:2025 Auth Failures",
    description:
      "Using md5 or sha1 for hashing. These are cryptographically broken for security purposes.",
    pattern: /(?:md5\.New|sha1\.New|md5\.Sum|sha1\.Sum)\s*\(/gi,
    languages: ["go"],
    fix: "Use crypto/sha256 or golang.org/x/crypto/bcrypt for password hashing.",
    fixCode: "// Use bcrypt for passwords\nimport \"golang.org/x/crypto/bcrypt\"\nhash, _ := bcrypt.GenerateFromPassword([]byte(password), 12)",
  },
  {
    id: "VG115",
    name: "Go CORS wildcard",
    severity: "high",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "CORS configured with wildcard origin allows any website to access your API.",
    pattern: /(?:Access-Control-Allow-Origin|AllowOrigins|allowOrigins)['"]?\]?\s*[:=,]\s*['"]?\s*\*/gi,
    languages: ["go"],
    fix: "Set specific allowed origins instead of wildcard '*'.",
    fixCode: "// Specify allowed origins\nw.Header().Set(\"Access-Control-Allow-Origin\", \"https://myapp.com\")",
  },
];
