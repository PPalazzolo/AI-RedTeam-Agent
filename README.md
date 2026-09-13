# OWASP Agentic AI Red Team Playground

A security testing playground for agentic AI systems, mapped to the
[OWASP Agentic AI Top 10 (2026)](https://owasp.org/) (**ASI01–ASI10**). It ships in two
forms that share the same threat model and scenario library:

- a **command-line framework** (`redteam/`) for scripted, CI-friendly runs, and
- a **local web app** (`owasp-redteam-playground/`) that drives the same attacks from a
  browser via a guided wizard.

Both treat any target as a callable `(str) -> str`, so they are agent-agnostic, and both
bundle a deliberately vulnerable reference OpenAI agent so you can verify the harness
end-to-end before pointing it at a real system.

> ⚠️ **Authorized testing only.** Run this exclusively against systems you own or have
> explicit written permission to test.

## What it tests

| ID | Category | What's exercised |
|---|---|---|
| ASI01 | Agent Goal Hijack | Direct & indirect prompt injection, forged agent-to-agent overrides |
| ASI02 | Tool Misuse & Exploitation | Coerced privileged calls, unsafe tool chaining, MCP descriptor poisoning |
| ASI03 | Identity & Privilege Abuse | Credential extraction, cross-agent delegation, fake admin agents |
| ASI04 | Agentic Supply Chain | Poisoned templates, typosquatted MCP tools, malicious agent cards |
| ASI05 | Unexpected Code Execution | Shell injection, `eval()` coercion, hallucinated backdoors |
| ASI06 | Memory & Context Poisoning | False rule injection, cross-user contamination, RAG poisoning |
| ASI07 | Insecure Inter-Agent Communication | Token replay, unsigned messages, MITM tampering, A2A spoofing |
| ASI08 | Cascading Failures | Planner poisoning, auto-remediation loops, IR cascade |
| ASI09 | Human-Agent Trust Exploitation | HITL fatigue, fabricated explainability, social engineering |
| ASI10 | Rogue Agents | Reward hacking, goal drift, workflow hijacking, self-replication |

Each category runs 3–4 scenarios. The default suite is **38 tests**.

## Repository layout

```
.
├── redteam/                      Command-line framework (the core engine)
│   ├── agentic_redteam.py        10 attack suites + AgenticRedTeam + TestReport
│   ├── demo_agent.py             Reference OpenAI agent (intentionally vulnerable soft target)
│   ├── run_redteam.py            CLI entry point: runs the suites against the demo agent
│   └── docs/                     Threat model, architecture, scenario design
├── owasp-redteam-playground/     Local web app (browser UI over the same scenarios)
│   ├── app.py                    Flask app (routes only)
│   ├── start.sh                  Single-command launcher
│   ├── core/                     Config, scenarios, agent factory, detector, runner, report
│   └── static/                   Frontend (vanilla HTML/CSS/JS)
├── security-report-*.html        Pre-rendered example reports from prior runs
└── OWASP Playground App.mov      Screen recording of the web app in action
```

## Which one should I use?

| | CLI (`redteam/`) | Web app (`owasp-redteam-playground/`) |
|---|---|---|
| Best for | Automation, CI, scripted regression | Interactive exploration, demos, editing payloads live |
| Setup | `pip install openai` | `./start.sh` (auto-creates a venv) |
| Configuration | Env vars + constants in `run_redteam.py` | Browser wizard + Settings page |
| Output | `results.json` + console + HTML | Live-streaming results + downloadable HTML report |
| API key | `OPENAI_API_KEY` env var | Saved to `~/.owasp-redteam/config.json` (mode 0600) |

The two are independent orchestration layers today (the web app reads its own scenario
manifest). Unifying them is a planned cleanup, not a blocker.

## Quick start

### Command line

```bash
cd redteam
pip install openai
export OPENAI_API_KEY=sk-...
python run_redteam.py
```

Prints a full console report, writes `results.json`, and exits non-zero if any
vulnerabilities were found. See [`redteam/README.md`](redteam/README.md) for configuration,
exit codes, and how to target your own agent.

### Web app

```bash
cd owasp-redteam-playground
./start.sh
```

First run creates a `.venv` and installs Flask + the OpenAI SDK; every run starts the server
on `http://localhost:5050` and opens your browser. Paste your OpenAI key under **Settings**,
then walk through the 5-step wizard. See
[`owasp-redteam-playground/README.md`](owasp-redteam-playground/README.md) for the full flow
and extension points.

## Prerequisites

- Python 3.10+
- An OpenAI API key (only needed to run against the bundled demo agent)
- For the CLI: `pip install openai`. For the web app: nothing — `start.sh` provisions a venv.

## Security & privacy

- **Authorized testing only** — use this only against agents you own or have written
  permission to test.
- Keep API keys in environment variables or the web app's `0600` config file; never commit
  them. The config file lives at `~/.owasp-redteam/config.json`, outside any git repo.
- Reports include the prompts sent and the first ~500 chars of each agent response. Treat
  them as sensitive and redact before sharing.
- The web app is **local-only** (binds to `127.0.0.1`) and its **Advanced: edit code** tab
  `exec`s arbitrary Python in-process — never expose it on a network or run untrusted code.

## See also

- [`redteam/README.md`](redteam/README.md) — the CLI framework in detail
- [`owasp-redteam-playground/README.md`](owasp-redteam-playground/README.md) — the web app
- [`redteam/docs/THREAT_MODEL.md`](redteam/docs/THREAT_MODEL.md) — full threat model and the
  mapping between OWASP categories and the 38 scenarios
- [`redteam/docs/ARCHITECTURE.md`](redteam/docs/ARCHITECTURE.md) — internal design
- [`redteam/docs/TEST_SCENARIO_DESIGN.md`](redteam/docs/TEST_SCENARIO_DESIGN.md) — rationale
  and methodology for each attack scenario
