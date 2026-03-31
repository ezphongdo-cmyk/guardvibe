import type { SecurityRule } from "../data/rules/types.js";

export interface GuardVibeTool {
  name: string;
  description: string;
  schema: Record<string, unknown>;
  handler: (input: any) => Promise<string>;
}

export interface GuardVibePlugin {
  name: string;
  version: string;
  description?: string;
  author?: string;
  license?: "free" | "pro";
  rules?: SecurityRule[];
  tools?: GuardVibeTool[];
}
