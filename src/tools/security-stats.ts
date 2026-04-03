import { generateDashboard } from "../lib/stats.js";

/**
 * security_stats MCP tool handler.
 * Returns cumulative security statistics and grade trend for the project.
 */
export function securityStats(
  projectRoot: string,
  period: "week" | "month" | "all" = "month",
  format: "markdown" | "json" = "markdown"
): string {
  return generateDashboard(projectRoot, period, format);
}
