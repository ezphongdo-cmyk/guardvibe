# Changelog

All notable changes to GuardVibe are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.7.1] - 2026-04-01

### Added
- 10 new XSS/injection rules covering form actions, file uploads, rich text editors, and template injection

## [1.7.0] - 2026-04-01

### Added
- 24 new rules from proactive threat research
- Supply chain attack detection rules
- CI/CD pipeline security rules
- Kubernetes misconfiguration detection
- AI/LLM security rules
- New CVE version intelligence entries

## [1.6.1] - 2026-04-01

### Added
- 4 new supply-chain rules for npm publish leak protection

### Security
- Self-hardening of the publish pipeline to prevent accidental credential leaks

## [1.6.0] - 2026-03-31

### Added
- Agent-native security layer
- Command guard for dangerous shell operations
- Config diff tool for detecting security regressions
- Repository security posture scoring
- Deep remediation with expanded fix suggestions

## [1.5.0] - 2026-03-31

### Added
- PR review security scanning
- Git history scan for leaked secrets
- Policy engine with compliance enforcement
- Taint analysis for data flow tracking
- 100% fixCode coverage across all rules
- Expanded patch generation for auto-fix suggestions

## [1.4.0] - 2026-03-31

### Added
- `check_package_health` tool for typosquat detection, maintenance status, and adoption metrics
- `exploit` and `audit` fields on SecurityRule for compliance demonstrations
- fixCode secure code examples added to all 25 rules that were missing them

### Changed
- Compliance mapping deepened with GDPR and ISO 27001 controls
- Performance improvements for large project scanning

## [1.3.3] - 2026-03-31

### Fixed
- Node.js 18 compatibility issue

### Security
- npm provenance via Sigstore for cryptographic package signing
- Branch protection enabled (force push disabled on main)
- Tag protection for version tags (`v*`)
- Minimal CI permissions (`contents: read` only)

## [1.3.2] - 2026-03-31

### Changed
- Rebranded project as GuardVibe with new description and metadata

## [0.6.1] - 2026-03-30

### Fixed
- OSV severity normalization returning incorrect values

### Changed
- Updated MCP SDK dependency

## [0.6.0] - 2026-03-30

### Added
- `.guardviberc` configuration file support with rule disable, severity override, and scan exclusions
- Compliance mapping for SOC2, PCI-DSS, and HIPAA with `compliance_report` tool
- Terraform IaC security rules (VG300-VG304): S3, IAM, RDS, security groups
- SARIF v2.1.0 output for CI/CD integration (`export_sarif` tool)

### Fixed
- `scan_dependencies` severity and summary showing undefined when fetching OSV details

## [0.5.0] - 2026-03-30

### Added
- `fixCode` field on SecurityRule type with secure code examples for core, Go, Java, PHP, Ruby rules
- `scan_staged` tool for pre-commit security scanning
- Dockerfile security rules (VG200-VG204): root user, secrets in ENV, untagged images
- CI/CD security rules (VG210-VG213): secrets interpolation, unpinned actions, write-all permissions
- Security guides for Django, NestJS, Hono, Supabase, and tRPC
- fixCode snippets rendered in security reports

### Changed
- Renamed project from VibeGuard to GuardVibe across entire codebase
- Cleaned up all old VibeGuard references and outdated specs

## [0.4.0] - 2026-03-30

### Added
- `scan_directory` tool for filesystem-native project scanning
- `scan_dependencies` tool with manifest parsing and OSV batch query
- `scan_secrets` tool with pattern-based and entropy-based secret detection
- `guardvibe-ignore` inline comment suppression (supports `//`, `#`, `<!-- -->`)
- Finding deduplication in analysis pipeline

### Changed
- `check_project` refactored to use structured findings instead of string parsing
- Extracted `analyzeCode()` as reusable analysis function
- Rules split into per-language modules for maintainability

## [0.3.0] - 2026-03-30

### Added
- Project scanning with `check_project` tool
- CLI auto-setup (`npx guardvibe init`) for Claude Code, Cursor, Gemini CLI
- Go security rules (SQL injection, command injection, template escaping)
- Java security rules
- PHP security rules
- Ruby security rules
- Test infrastructure with tsx and node:test
- Rule tests for core, Go, Java, PHP, Ruby

## [0.2.0] - 2026-03-30

### Added
- New security rules for Python
- Improved Python support

## [0.1.0] - 2026-03-30

### Added
- Initial release as VibeGuard Security MCP server
- Core OWASP security rules (SQL injection, XSS, CSRF, command injection)
- `check_code` tool for code snippet analysis
- MCP server with stdio transport
