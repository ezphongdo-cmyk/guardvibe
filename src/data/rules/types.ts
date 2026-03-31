export interface SecurityRule {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  owasp: string;
  description: string;
  pattern: RegExp;
  languages: string[];
  fix: string;
  fixCode?: string;  // NEW: copy-paste-ready secure code example
  compliance?: string[];  // e.g. ["SOC2:CC6.1", "PCI-DSS:Req6", "HIPAA:§164.312(a)"]
}
