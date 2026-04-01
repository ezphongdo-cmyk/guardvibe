# Contributing to GuardVibe

Thank you for your interest in contributing to GuardVibe. This guide covers everything you need to get started.

## Development Setup

```bash
git clone https://github.com/goklab/guardvibe.git
cd guardvibe
npm install
npm run build
npm test
```

Requirements:
- Node.js >= 18.0.0
- npm >= 9

## Project Structure

```
src/
  index.ts            # MCP server entry point
  cli.ts              # CLI commands (init, hook, scan, ci)
  data/
    rules/
      types.ts        # SecurityRule interface
      core.ts         # OWASP core rules
      nextjs.ts       # Next.js rules
      auth.ts         # Auth rules (Clerk, Auth.js, Supabase)
      ...             # Per-category rule modules
  tools/              # MCP tool implementations
  plugins/
    types.ts          # GuardVibePlugin interface
    loader.ts         # Plugin discovery and loading
  utils/
    config.ts         # .guardviberc config loading
```

## Adding a New Security Rule

### 1. Choose the right module

Rules live in `src/data/rules/`. Pick the module that matches the category (e.g., `nextjs.ts` for Next.js rules, `core.ts` for OWASP rules). Create a new module only if no existing one fits.

### 2. Define the rule

Every rule implements the `SecurityRule` interface:

```typescript
interface SecurityRule {
  id: string;          // Unique ID, e.g. "VG042"
  name: string;        // Human-readable name
  severity: "critical" | "high" | "medium" | "low" | "info";
  owasp: string;       // OWASP category, e.g. "A03:2025 Injection"
  description: string; // What the rule detects and why it matters
  pattern: RegExp;     // Regex with global flag (/g)
  languages: string[]; // File types: "javascript", "typescript", "python", etc.
  fix: string;         // How to fix the issue
  fixCode?: string;    // Copy-paste secure code example (strongly recommended)
  compliance?: string[];  // e.g. ["SOC2:CC6.1", "PCI-DSS:Req6"]
  exploit?: string;    // How this vulnerability can be exploited
  audit?: string;      // How to verify in a compliance audit
}
```

### 3. Guidelines for rules

- **Every rule must have `fixCode`** -- provide a concrete, copy-paste-ready secure code example.
- **Use specific regex patterns** -- avoid overly broad patterns that match comments, strings, or variable names.
- **Set appropriate severity** -- `critical` for RCE/auth bypass, `high` for data exposure, `medium` for misconfig, `low` for best practices, `info` for informational.
- **Test the pattern** against real-world code samples, including negative cases (code that should not trigger).

### 4. Register the rule

Add your rule to the array exported by the module. If you created a new module, import and spread it into the combined rules array in the module index.

### 5. Write tests

Add test cases in the corresponding test file under `src/data/rules/`. Each rule needs at minimum:
- One positive case (code that should trigger the rule)
- One negative case (safe code that should not trigger)

## Running Tests

```bash
npm test              # Run all tests
npm run build         # TypeScript compilation (catches type errors)
```

## Creating a Plugin

Plugins are npm packages that export a `GuardVibePlugin` object:

```typescript
import type { GuardVibePlugin } from "guardvibe/plugins";

const plugin: GuardVibePlugin = {
  name: "my-rules",
  version: "1.0.0",
  description: "My custom security rules",
  rules: [
    {
      id: "CUSTOM001",
      name: "My Custom Rule",
      severity: "high",
      owasp: "A01:2025 Broken Access Control",
      description: "Detects ...",
      pattern: /some_pattern/g,
      languages: ["javascript", "typescript"],
      fix: "How to fix",
      fixCode: "// Secure code example",
    },
  ],
};

export default plugin;
```

Plugins can also export custom `tools` (implementing `GuardVibeTool`). Name your package `guardvibe-rules-<name>` for automatic discovery.

## Pull Request Guidelines

1. **One concern per PR.** Don't mix rule additions with refactors.
2. **All tests must pass.** Run `npm test` and `npm run build` before submitting.
3. **Include fixCode.** Every new rule should have a secure code example.
4. **Describe the threat.** PR description should explain what vulnerability the rule detects and a real-world scenario.
5. **No breaking changes** to the `SecurityRule` interface without discussion in an issue first.

## Code Style

- TypeScript (strict mode)
- No emojis in source code or rule text
- Use `const` over `let` where possible
- Regex patterns use the `/g` flag
- Keep rule descriptions concise but specific
- Prefer explicit types over `any`

## Reporting Security Issues

To report a vulnerability in GuardVibe itself, email security@goklab.com or open a GitHub issue.

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 license.
