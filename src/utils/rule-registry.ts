import type { SecurityRule } from "../data/rules/types.js";

let registeredRules: SecurityRule[] = [];

export function setRules(rules: SecurityRule[]) {
  registeredRules = rules;
}

export function getRules(): SecurityRule[] {
  return registeredRules;
}
