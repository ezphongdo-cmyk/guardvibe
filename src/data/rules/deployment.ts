import type { SecurityRule } from "./types.js";

// Security rules for deployment config files
export const deploymentRules: SecurityRule[] = [
  // vercel.json / vercel.ts
  {
    id: "VG500",
    name: "Vercel CORS Wildcard",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Vercel config sets Access-Control-Allow-Origin to wildcard (*), allowing any website to make requests.",
    pattern: /["']Access-Control-Allow-Origin["'][\s\S]*?["']\*["']/g,
    languages: ["vercel-config", "json"],
    fix: "Restrict CORS to specific trusted origins.",
    fixCode:
      '// vercel.json\n{\n  "headers": [{\n    "source": "/api/(.*)",\n    "headers": [{ "key": "Access-Control-Allow-Origin", "value": "https://yourdomain.com" }]\n  }]\n}',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG501",
    name: "Vercel Internal Rewrite Exposure",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Vercel rewrites expose internal service URLs to the public internet.",
    pattern:
      /["']rewrites["']\s*:\s*\[[\s\S]*?["']destination["']\s*:\s*["']https?:\/\/(?:localhost|127\.0\.0\.1|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)/g,
    languages: ["vercel-config", "json"],
    fix: "Do not rewrite to internal network addresses. Use Vercel environment variables for service URLs.",
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG503",
    name: "Vercel Cron Missing Secret Verification",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Cron jobs are configured but the endpoint may not verify CRON_SECRET. Anyone could trigger the cron endpoint manually.",
    pattern:
      /["']crons["']\s*:\s*\[[\s\S]*?["']path["']\s*:\s*["'][^"']+["']/g,
    languages: ["vercel-config", "json"],
    fix: "Verify the CRON_SECRET header in your cron endpoint.",
    fixCode:
      '// app/api/cron/route.ts\nexport async function GET(request: Request) {\n  const authHeader = request.headers.get("authorization");\n  if (authHeader !== `Bearer ${process.env.CRON_SECRET}`) {\n    return new Response("Unauthorized", { status: 401 });\n  }\n}',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG504",
    name: "Excessive Function Duration",
    severity: "medium",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "Function maxDuration is set very high. Long-running functions increase costs and attack surface.",
    pattern: /["']maxDuration["']\s*:\s*(?:[3-9]\d{2}|[1-9]\d{3,})/g,
    languages: ["vercel-config", "json"],
    fix: "Set maxDuration to the minimum required. Default 300s is sufficient for most use cases.",
  },
  {
    id: "VG506",
    name: "Hardcoded Secret in Vercel Config",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "Secret or API key hardcoded in vercel.json. This file is committed to git.",
    pattern:
      /["'](?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL)\w*["']\s*:\s*["'][A-Za-z0-9_\-]{12,}["']/gi,
    languages: ["vercel-config", "json"],
    fix: "Use Vercel environment variables (vercel env add) instead of hardcoding in config files.",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req2.3"],
  },

  // next.config
  {
    id: "VG507",
    name: "Wildcard Remote Image Pattern",
    severity: "high",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "next.config allows images from any hostname. This enables SSRF and hotlinking attacks.",
    pattern: /remotePatterns\s*:\s*\[[\s\S]*?hostname\s*:\s*["'](?:\*\*|\*)["']/g,
    languages: ["nextjs-config", "javascript", "typescript"],
    fix: "Restrict remotePatterns to specific trusted hostnames.",
    fixCode:
      '// next.config.ts\nimages: {\n  remotePatterns: [\n    { protocol: "https", hostname: "images.example.com" },\n  ]\n}',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG509",
    name: "Powered By Header Enabled",
    severity: "low",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "X-Powered-By header reveals Next.js framework. This helps attackers target known vulnerabilities.",
    pattern: /poweredByHeader\s*:\s*true/g,
    languages: ["nextjs-config", "javascript", "typescript"],
    fix: "Set poweredByHeader to false in next.config.ts.",
    fixCode: "// next.config.ts\nconst config = {\n  poweredByHeader: false,\n};",
  },
  {
    id: "VG510",
    name: "Next Config CORS Wildcard",
    severity: "high",
    owasp: "A01:2025 Broken Access Control",
    description:
      "Next.js config headers() sets Access-Control-Allow-Origin to wildcard (*).",
    pattern:
      /headers\s*\(\s*\)\s*\{[\s\S]*?Access-Control-Allow-Origin[\s\S]*?["']\*["']/g,
    languages: ["nextjs-config", "javascript", "typescript"],
    fix: "Restrict CORS to specific trusted origins.",
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG512",
    name: "Source Maps in Production",
    severity: "medium",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "Source maps enabled in production expose original source code to attackers.",
    pattern:
      /devtool\s*:\s*["'](?:source-map|eval-source-map|cheap-source-map)["']/g,
    languages: ["nextjs-config", "javascript", "typescript"],
    fix: "Disable source maps in production.",
    fixCode:
      "// next.config.ts\nconst config = {\n  productionBrowserSourceMaps: false,\n};",
    compliance: ["SOC2:CC6.1"],
  },

  // docker-compose.yml
  {
    id: "VG513",
    name: "Docker Compose Public Port Binding",
    severity: "medium",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "Port bound to 0.0.0.0 exposes the service to all network interfaces.",
    pattern: /ports\s*:\s*\n\s*-\s*["']?0\.0\.0\.0:/gm,
    languages: ["docker-compose", "yaml"],
    fix: "Bind to 127.0.0.1 for local-only access.",
    fixCode: '# Bind to localhost only\nports:\n  - "127.0.0.1:3000:3000"',
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG514",
    name: "Docker Compose Hardcoded Secret",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "Secret hardcoded in docker-compose environment section. Use Docker secrets or .env file.",
    pattern:
      /environment\s*:\s*\n(?:\s*-\s*|\s*\w+\s*:\s*)[\s\S]*?(?:SECRET|PASSWORD|TOKEN|KEY|CREDENTIAL)\w*\s*[=:]\s*\S{8,}/gi,
    languages: ["docker-compose", "yaml"],
    fix: "Use Docker secrets or reference a .env file instead of hardcoding.",
    fixCode:
      "# Use .env file\nservices:\n  app:\n    env_file:\n      - .env",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req2.3"],
  },
  {
    id: "VG515",
    name: "Docker Compose Privileged Container",
    severity: "critical",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "Container runs in privileged mode with full host access. This is a severe security risk.",
    pattern: /privileged\s*:\s*true/g,
    languages: ["docker-compose", "yaml"],
    fix: "Remove privileged: true. Use specific capabilities (cap_add) if needed.",
    fixCode:
      "# Instead of privileged: true, use specific capabilities\nservices:\n  app:\n    cap_add:\n      - NET_ADMIN",
    compliance: ["SOC2:CC6.1"],
  },
  {
    id: "VG516",
    name: "Docker Compose Host Volume Mount",
    severity: "high",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "Mounting the entire host filesystem gives the container excessive access.",
    pattern: /volumes\s*:\s*\n\s*-\s*["']?(?:\/:|\/etc|\/var|\/root|\/home)\s*:/gm,
    languages: ["docker-compose", "yaml"],
    fix: "Mount only specific directories needed by the application.",
    fixCode:
      "# Mount only what's needed\nvolumes:\n  - ./data:/app/data",
    compliance: ["SOC2:CC6.1"],
  },

  // fly.toml / render.yaml / netlify.toml
  {
    id: "VG517",
    name: "Platform Config Hardcoded Secret",
    severity: "critical",
    owasp: "A07:2025 Sensitive Data Exposure",
    description:
      "Secret hardcoded in deployment platform config file. These files are committed to git.",
    pattern:
      /\[env\][\s\S]*?(?:SECRET|PASSWORD|TOKEN|KEY|CREDENTIAL)\w*\s*=\s*["']?[A-Za-z0-9_\-]{12,}/gi,
    languages: ["fly-config", "render-config", "netlify-config", "toml"],
    fix: "Use your platform's secret management (fly secrets set, Render env groups, Netlify env vars).",
    fixCode:
      '# fly.toml — don\'t put secrets here\n# Instead: fly secrets set SECRET_KEY=value\n\n[env]\n  LOG_LEVEL = "info"',
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req2.3"],
  },
  {
    id: "VG518",
    name: "Platform Internal Port Exposed",
    severity: "medium",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "Internal service port (database, cache) is exposed publicly.",
    pattern: /internal_port\s*=\s*(?:5432|3306|6379|27017|9200|2379)/g,
    languages: ["fly-config", "toml"],
    fix: "Don't expose database or cache ports publicly. Use internal networking.",
    compliance: ["SOC2:CC6.6"],
  },
  {
    id: "VG520",
    name: "Missing HTTPS Redirect",
    severity: "medium",
    owasp: "A05:2025 Security Misconfiguration",
    description:
      "No HTTP to HTTPS redirect configured. Traffic may be sent unencrypted.",
    pattern: /force_https\s*=\s*false/g,
    languages: ["fly-config", "toml"],
    fix: "Enable force_https to redirect all HTTP traffic to HTTPS.",
    compliance: ["SOC2:CC6.1", "PCI-DSS:Req4.1"],
  },
];
