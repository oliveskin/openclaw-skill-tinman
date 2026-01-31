# Tinman Skill for OpenClaw

AI security scanner for [OpenClaw](https://openclaw.ai) - powered by [AgentTinman](https://github.com/oliveskin/Agent-Tinman).

Discovers prompt injection, tool exfil, context bleed, and other security issues in your AI assistant sessions, then proposes mitigations mapped to OpenClaw's security controls.

## What's New in v0.2.0

- **`/tinman sweep`** - Proactive security testing with 80+ synthetic attack probes
- **Tinman Integration** - Uses `FailureClassifier` for deep analysis
- **Attack Categories** - Prompt injection, tool exfil, context bleed, privilege escalation

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
# Scan real sessions for issues
/tinman scan                         # Analyze last 24 hours
/tinman scan --hours 48              # Analyze last 48 hours
/tinman scan --focus prompt_injection

# View findings
/tinman report                       # View latest findings

# Proactive security sweep (NEW)
/tinman sweep                        # Run 80+ attack probes
/tinman sweep --category tool_exfil  # Focus on exfiltration
/tinman sweep --severity S3          # High severity only

# Continuous monitoring
/tinman watch                        # Hourly scans
```

## Attack Categories

| Category | Attacks | Examples |
|----------|---------|----------|
| **Prompt Injection** | 15 | Jailbreaks, DAN, instruction override |
| **Tool Exfiltration** | 18 | SSH keys, credentials, network exfil |
| **Context Bleed** | 14 | Cross-session leaks, memory extraction |
| **Privilege Escalation** | 15 | Sandbox escape, elevation bypass |

## Severity Levels

- **S4**: Critical - immediate action required
- **S3**: High - mitigation recommended
- **S2**: Medium - review recommended
- **S1**: Low - monitor
- **S0**: Info - observation only

## How It Works

1. **Scan**: Fetches recent sessions → Converts to Tinman trace format → Runs FailureClassifier
2. **Sweep**: Runs synthetic attack probes → Tests defenses → Reports vulnerabilities
3. **Report**: Generates actionable findings with OpenClaw-specific mitigations

## Privacy

- All analysis runs locally on your machine
- No session data is sent externally
- Findings stored only in your workspace
- Respects OpenClaw's session isolation

## Requirements

- OpenClaw (any recent version)
- Python 3.10+
- AgentTinman >= 0.1.60
- tinman-openclaw-eval >= 0.1.1

## Links

- [AgentTinman](https://github.com/oliveskin/Agent-Tinman) - AI Failure Mode Research
- [Eval Harness](https://github.com/oliveskin/tinman-openclaw-eval) - Security Testing
- [OpenClaw](https://github.com/openclaw/openclaw) - Personal AI Assistant
- [ClawHub](https://clawhub.ai/oliveskin/agent-tinman) - Skill Registry

## License

Apache-2.0
