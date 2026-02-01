# Changelog

All notable changes to this project will be documented in this file.

## [0.6.0] - 2026-02-01

### Added
- **Security Check System** - `/tinman check <tool> <args>` for pre-execution security verification
- **Security Modes** - Three protection levels: `safer` (default), `risky`, `yolo`
  - `safer`: Ask human for REVIEW actions, block high-risk
  - `risky`: Auto-approve REVIEW, still block S4 critical
  - `yolo`: Warn only, never block (for testing/research)
- **Allowlist Management** - `/tinman allow` and `/tinman allowlist` commands
- **Verdict System** - SAFE/REVIEW/BLOCKED with severity, confidence, and recommendations
- **Pattern Categories** - 12 categorized pattern groups (credential_theft, crypto_wallet, windows_attack, etc.)

### Changed
- Refactored suspicious tool detection to use new CheckResult system
- Removed legacy pattern checking (replaced by run_check())

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
