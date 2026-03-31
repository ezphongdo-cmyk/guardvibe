import type { SecurityRule } from "./types.js";

// Supply chain and package security rules
export const supplyChainRules: SecurityRule[] = [
  {
    id: "VG860",
    name: "Malicious postinstall Script",
    severity: "critical",
    owasp: "A03:2025 Software Supply Chain Failures",
    description:
      "postinstall or preinstall script contains network requests, eval, or exec. This is the #1 npm supply chain attack vector.",
    pattern:
      /["'](?:post|pre)install["']\s*:\s*["'][^"']*(?:curl|wget|http|https|eval|exec|node\s+-e|sh\s+-c|bash\s+-c)/gi,
    languages: ["json"],
    fix: "Review postinstall scripts carefully. Remove or replace packages with suspicious install scripts.",
    fixCode:
      '// Safe: no network/exec in install scripts\n"scripts": {\n  "postinstall": "prisma generate"\n}\n\n// DANGEROUS: network calls in install\n// "postinstall": "node -e \\"require(\'https\').get(...)\\""',
    compliance: ["SOC2:CC7.1"],
  },
  {
    id: "VG861",
    name: "GitHub Actions persist-credentials Not Disabled",
    severity: "medium",
    owasp: "A01:2025 Broken Access Control",
    description:
      "actions/checkout with persist-credentials enabled (default: true) leaves Git credentials on the runner. Third-party actions in later steps can push to your repository.",
    pattern:
      /uses:\s*actions\/checkout@[\s\S]{0,200}?uses:\s*(?!actions\/)[^\s]+@/g,
    languages: ["yaml"],
    fix: "Add persist-credentials: false to actions/checkout when using third-party actions.",
    fixCode:
      "- uses: actions/checkout@v4\n  with:\n    persist-credentials: false",
    compliance: ["SOC2:CC6.1"],
  },
];
