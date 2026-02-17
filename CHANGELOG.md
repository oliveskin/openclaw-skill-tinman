# Changelog

All notable changes to this project will be documented in this file.

## [0.6.3] - 2026-02-17

### Added
- `/tinman oilcan` command for plain-language Oilcan setup and stream status.
- `/tinman oilcan --json` for machine-readable status output.

### Changed
- Update skill metadata/description to include Oilcan event streaming and setup helper.
- Add feedback/updates contact reference to `@cantshutup_`.

## [0.6.2] - 2026-02-08

### Added
- Local live event stream for dashboards/visualizers: emits `~/.openclaw/workspace/tinman-events.jsonl`.
- `/tinman scan`, `/tinman sweep`, and `/tinman watch` now append structured JSONL events (best-effort, never breaks skill execution).

### Changed
- `watch` now blocks non-loopback Gateway URLs by default; remote endpoints require `--allow-remote-gateway`.
- JSONL event emission now applies basic redaction/truncation for obvious secret-like values.

## [0.6.1] - 2026-02-08

### Changed
- Update eval dependency to `tinman-openclaw-eval>=0.3.2` (288 probes, updated categories/aliases).
- Update skill metadata and docs to reflect current probe count and category names.
- Remove remaining non-ASCII warning glyphs to avoid encoding issues in terminals/Clawdhub packaging.

## [0.6.0] - 2026-02-01

### Added
- **Security Check System** - `/tinman check <tool> <args>` for pre-execution security verification
- **Security Modes** - `/tinman mode <level>` with three protection levels:
  | Mode | SAFE | REVIEW (S1-S2) | BLOCKED (S3-S4) |
  |------|------|----------------|-----------------|
  | `safer` (default) | Proceed | Ask human | Block |
  | `risky` | Proceed | Auto-approve | Block |
  | `yolo` | Proceed | Auto-approve | Warn only |
- **Allowlist Management** - `/tinman allow` and `/tinman allowlist` commands
- **Verdict System** - SAFE/REVIEW/BLOCKED with severity, confidence, and recommendations
- **168 Detection Patterns** across 16 categories:
  - credential_theft (39), windows_attack (32), crypto_wallet (15)
  - linux_persistence (12), network_exfil (11), macos_attack (9)
  - shell_injection (7), browser_data (6), destructive (6)
  - privilege_escalation (5), mcp_attack (5), git_hooks (5)
  - cloud_metadata (4), container_escape (4), process_spawn (4), evasion (4)
- **Agent Self-Protection** - Add to SOUL.md for autonomous security enforcement

### Changed
- Refactored suspicious tool detection to use new CheckResult system
- Consolidated all legacy patterns into categorized PATTERN_CATEGORIES

## [0.5.1] - 2026-02-01

### Added
- `/tinman init` command for easy workspace setup

### Fixed
- Watch stop now works with PID-based process management
- Fixed crash when tool args are dict instead of string

## [0.5.0] - 2026-02-01

### Added
- Evasion/Bypass detection (30 probes): Unicode homoglyphs, URL/base64/hex encoding, shell injection
- Memory poisoning attacks (25 probes): Context injection, RAG poisoning, history fabrication
- Platform-specific attacks (35 probes): Windows, macOS, Linux, cloud metadata
- 50+ new suspicious tool detection patterns

### Changed
- Total probes increased from 180 to 270+
- Attack categories expanded from 10 to 13

## [0.4.0] - 2026-01-31

### Added
- Financial/Crypto attacks (26 probes): BTC, ETH, SOL, Base wallet theft
- Unauthorized action detection (28 probes)
- MCP server attacks (20 probes)
- Indirect injection (20 probes)

## [0.3.0] - 2026-01-30

### Added
- Real-time monitoring via Gateway WebSocket
- `/tinman watch` command with realtime and polling modes

## [0.2.0] - 2026-01-29

### Added
- `/tinman sweep` - Proactive security testing with synthetic attack probes

## [0.1.0] - 2026-01-28

### Added
- Initial release
- `/tinman scan` - Analyze recent sessions
- `/tinman report` - View findings
- Core failure classification for prompt injection, tool exfil, context bleed
