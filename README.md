# Tinman Skill for OpenClaw

AI security scanner for [OpenClaw](https://openclaw.ai) - powered by [AgentTinman](https://github.com/oliveskin/Agent-Tinman).

Discovers prompt injection, tool exfil, context bleed, evasion attacks, memory poisoning, and other security issues in your AI assistant sessions, then proposes mitigations mapped to OpenClaw's security controls.

## What's New in v0.5.1

- **`/tinman init`** - New command for easy workspace setup
- **Watch stop** - `--stop` flag now works with PID-based process management
- **Bug fix** - Fixed crash when tool args are dict instead of string

### v0.5.0
- **270+ attack probes** - Expanded from 180 to 270+ probes across 13 categories
- **Evasion/Bypass detection** - Unicode homoglyphs, URL/base64/hex encoding, shell injection
- **Memory poisoning attacks** - Context injection, RAG poisoning, history fabrication
- **Platform-specific attacks** - Windows (mimikatz, schtasks, PowerShell IEX, certutil), macOS (LaunchAgents, keychain), Linux (systemd, cron), cloud metadata
- **Enhanced detection patterns** - 50+ new suspicious tool patterns

### v0.4.0
- **180+ attack probes** - More than doubled coverage from 80 to 180+ probes
- **Financial/Crypto attacks** - BTC, ETH, Solana, Base wallet theft, exchange API keys, transaction signing
- **Unauthorized action detection** - Catches agents taking actions without explicit consent
- **MCP server attacks** - Tool injection, server manipulation, cross-MCP exfiltration
- **Indirect injection** - Attacks via files, URLs, documents, configs, emails

### v0.3.0
- **Real-time monitoring** - WebSocket connection to Gateway for instant event analysis
- **`/tinman watch`** - Two modes: real-time (via Gateway) or polling (periodic scans)

### v0.2.0
- **`/tinman sweep`** - Proactive security testing with synthetic attack probes

## Installation

```bash
# Clone to your OpenClaw workspace skills directory
cd ~/.openclaw/workspace/skills
git clone https://github.com/oliveskin/openclaw-skill-tinman tinman

# Install dependencies
cd tinman
pip install -r requirements.txt
```

Or install from ClawHub: https://clawhub.ai/oliveskin/agent-tinman

## Usage

In any OpenClaw channel (WhatsApp, Telegram, Discord, etc.):

```bash
# First time setup
/tinman init                         # Initialize workspace and config

# Scan real sessions for issues
/tinman scan                         # Analyze last 24 hours
/tinman scan --hours 48              # Analyze last 48 hours
/tinman scan --focus prompt_injection

# View findings
/tinman report                       # View latest findings

# Proactive security sweep
/tinman sweep                        # Run 270+ attack probes
/tinman sweep --category tool_exfil  # Focus on exfiltration
/tinman sweep --category financial   # Crypto wallet attacks
/tinman sweep --category evasion_bypass  # Encoding tricks
/tinman sweep --severity S3          # High severity only

# Continuous monitoring
/tinman watch                        # Real-time via Gateway WebSocket
/tinman watch --gateway ws://host:port  # Custom gateway URL
/tinman watch --mode polling         # Fallback: periodic scans
/tinman watch --stop                 # Stop background watch process
```

## Attack Categories

| Category | Probes | Examples |
|----------|--------|----------|
| **Prompt Injection** | 15 | Jailbreaks, DAN, instruction override |
| **Tool Exfiltration** | 42 | SSH keys, cloud creds, supply-chain tokens, DB passwords |
| **Context Bleed** | 14 | Cross-session leaks, memory extraction |
| **Privilege Escalation** | 15 | Sandbox escape, elevation bypass |
| **Supply Chain** | 18 | Malicious skills, dependency attacks |
| **Financial/Crypto** | 26 | BTC/ETH/SOL/Base wallets, exchange APIs, transaction signing |
| **Unauthorized Action** | 28 | Actions without consent, implicit execution |
| **MCP Attacks** | 20 | MCP tool abuse, server injection, cross-MCP exfil |
| **Indirect Injection** | 20 | Injection via files, URLs, documents, configs |
| **Evasion Bypass** | 30 | Unicode bypass, URL/base64/hex encoding, shell injection |
| **Memory Poisoning** | 25 | Context injection, RAG poisoning, history fabrication |
| **Platform Specific** | 35 | Windows (mimikatz, PowerShell), macOS (LaunchAgents), Linux (systemd), cloud metadata |

## Detection Patterns

The skill detects suspicious tool calls including:

- **Credential access** - SSH keys, .env files, cloud configs, API tokens
- **Crypto wallets** - Bitcoin, Ethereum, Solana, Base, MetaMask, Phantom
- **Supply chain tokens** - NPM, PyPI, Cargo, Docker, Gem credentials
- **Windows attacks** - mimikatz, schtasks, PowerShell IEX, certutil, registry
- **macOS attacks** - LaunchAgents, keychain dumps, plist manipulation
- **Linux attacks** - systemd persistence, cron jobs, proc filesystem
- **Cloud metadata** - AWS/GCP/Azure instance metadata access
- **Evasion techniques** - Unicode normalization, base64/hex encoding, shell injection
- **Network exfil** - curl, wget, netcat, DNS exfiltration

## Severity Levels

| Level | Description | Action |
|-------|-------------|--------|
| **S4** | Critical | Immediate action required |
| **S3** | High | Mitigation recommended |
| **S2** | Medium | Review recommended |
| **S1** | Low | Monitor |
| **S0** | Info | Observation only |

## How It Works

1. **Scan**: Fetches recent sessions → Converts to Tinman trace format → Runs FailureClassifier
2. **Sweep**: Runs synthetic attack probes → Tests defenses → Reports vulnerabilities
3. **Watch**: Connects to Gateway WebSocket → Streams events in real-time → Classifies failures as they happen
4. **Report**: Generates actionable findings with OpenClaw-specific mitigations

## Privacy

- All analysis runs locally on your machine
- No session data is sent externally
- Findings stored only in your workspace
- Respects OpenClaw's session isolation

## Requirements

- OpenClaw (any recent version)
- Python 3.10+
- AgentTinman >= 0.2.1
- tinman-openclaw-eval >= 0.3.0

## Links

- [AgentTinman](https://github.com/oliveskin/Agent-Tinman) - AI Failure Mode Research
- [Eval Harness](https://github.com/oliveskin/tinman-openclaw-eval) - Security Testing
- [OpenClaw](https://github.com/openclaw/openclaw) - Personal AI Assistant
- [ClawHub](https://clawhub.ai/oliveskin/agent-tinman) - Skill Registry

## License

Apache-2.0
