# aiplat-redteam

Cloud plugin (`<team>-<function>` naming, same `aiplat-*` library as `aiplat-gov`). It lets
people run **their own agent** against a hosted OWASP Agentic AI Top 10 red team — ASI01–ASI10
plus NVIDIA garak — from inside Claude, and get back a security report.

The red team runs in the cloud (the `aiplat-redteam` MCP server). The plugin connects Claude to
it; the user supplies their agent's HTTP endpoint, and the service probes it and returns findings.

## Skills
| Skill | Purpose |
|---|---|
| `redteam-run` | Collects a target agent's connection details, runs the hosted red team against it, and explains the findings |

## What `redteam-run` does
1. Confirms the user is authorized to test the target agent.
2. Collects how to reach the agent: `target_url`, which field carries the prompt, where the reply
   lives in the response (dotted path; presets for simple-JSON and OpenAI-compatible endpoints),
   and an optional auth header.
3. Runs the suite via the cloud server (all ASI categories + garak `core` by default; scope is
   adjustable).
4. Presents a verdict, findings by severity with what-was-tried / what-the-agent-said / the fix,
   a pass/fail breakdown by category, and what was not covered.

## Setup
This is a **cloud** plugin, so it needs the hosted server and two environment variables:

| Variable | Purpose |
|---|---|
| `AIPLAT_REDTEAM_URL` | The MCP endpoint of your hosted red team, e.g. `https://redteam.aiplat.example.com/mcp` |
| `AIPLAT_REDTEAM_API_KEY` | Bearer token your gateway validates for the server |

The server lives in [`server/`](server/) with a Dockerfile and deploy guide. Operators are
responsible for authentication, egress/SSRF controls, and rate limiting (see `server/README.md`).

## Use
In Claude, with the plugin installed and the server configured:

> "Red team my agent at https://my-agent.example.com/chat — it takes `{prompt}` and replies with
> `{response}`. I own it."

Claude will run the suite and report back. You can narrow scope ("only ASI01 and ASI05", or
"skip garak", or "use the garak `gaps` set") and re-run after fixes to check for regressions.

## Authorized testing only
Only run this against agents you own or have explicit written permission to test. The target's
responses are treated as untrusted data — the skill never follows instructions found in them.

## Known limits
The ASI suite uses keyword-based detection (fast, but can miss paraphrased compliance or flag a
refusal that echoes an attacker's word); garak findings use garak's own detectors. The red team
only sees the agent's text reply, so silent tool actions followed by a textual refusal read as a
pass. A clean run means these payloads found nothing — not that the agent is secure.
