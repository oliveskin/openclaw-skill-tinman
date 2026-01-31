# Tinman Skill for OpenClaw

Proactive AI failure-mode research for [OpenClaw](https://openclaw.ai).

Tinman discovers prompt injection, tool misuse, context bleed, and other failure modes in your AI assistant sessions, then proposes mitigations mapped to OpenClaw's security controls.

## Installation

```bash
# Clone to your OpenClaw workspace skills directory
cd ~/.openclaw/workspace/skills
git clone https://github.com/oliveskin/openclaw-skill-tinman tinman

# Install dependencies
cd tinman
pip install -r requirements.txt
```

## Usage

In any OpenClaw channel (WhatsApp, Telegram, Discord, etc.):

```
/tinman scan                         # Analyze last 24 hours
/tinman scan --hours 48              # Analyze last 48 hours
/tinman scan --focus prompt_injection
/tinman report                       # View findings
/tinman watch                        # Continuous monitoring
```

## What It Finds

| Category | Description | Mitigation |
|----------|-------------|------------|
| **Prompt Injection** | Jailbreaks, instruction override | SOUL.md guardrails |
| **Tool Misuse** | Unauthorized access, exfil attempts | Sandbox denylist |
| **Context Bleed** | Cross-session data leakage | Session isolation |
| **Reasoning Failures** | Logic errors, hallucinations | Model selection |

## Severity Levels

- **S4**: Critical - immediate action required
- **S3**: High - mitigation recommended
- **S2**: Medium - review recommended
- **S1**: Low - monitor
- **S0**: Info - observation only

## Configuration

Create `~/.openclaw/workspace/tinman.yaml`:

```yaml
mode: shadow                    # shadow or lab
focus:
  - prompt_injection
  - tool_use
  - context_bleed
severity_threshold: S2          # Minimum severity to report
auto_watch: false               # Auto-start monitoring
```

## How It Works

1. Fetches recent sessions via OpenClaw's `sessions_*` tools
2. Converts sessions to Tinman's trace format
3. Runs failure classification with heuristics + patterns
4. Generates actionable report with OpenClaw-specific mitigations
5. Optionally runs in continuous watch mode

## Privacy

- All analysis runs locally on your machine
- No session data is sent externally
- Findings stored only in your workspace
- Respects OpenClaw's session isolation

## Requirements

- OpenClaw (any recent version)
- Python 3.10+
- tinman >= 0.1.60

## Links

- [Tinman](https://github.com/oliveskin/Agent-Tinman) - Forward-Deployed Research Agent
- [OpenClaw](https://github.com/openclaw/openclaw) - Personal AI Assistant
- [PyPI](https://pypi.org/project/AgentTinman/) - Tinman package

## License

Apache-2.0
