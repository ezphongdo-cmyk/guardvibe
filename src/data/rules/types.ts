export interface SecurityRule {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  owasp: string;
  description: string;
  pattern: RegExp;
  languages: string[];
  fix: string;
  fixCode?: string;  // copy-paste-ready secure code example
  compliance?: string[];  // e.g. ["SOC2:CC6.1", "PCI-DSS:Req6", "HIPAA:§164.312(a)", "GDPR:Art32", "ISO27001:A.8.24"]
  exploit?: string;  // How this vulnerability can be exploited
  audit?: string;    // How to demonstrate this in a compliance audit
}
