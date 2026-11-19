# Interpreting red team results

## Target connection presets

Offer these instead of asking the user to guess the field names:

| Target style | `prompt_field` | `response_field` | Notes |
|---|---|---|---|
| Simple JSON webhook | `prompt` | `response` | POST `{"prompt": "..."}` → `{"response": "..."}` |
| OpenAI-compatible `/chat/completions` | `messages` is required, not a single field | `choices.0.message.content` | Needs the OpenAI body shape; ask the user if unsure |
| Plain-text endpoint | `prompt` | *(empty)* | Reply is the raw body, not JSON |
| Custom | ask | ask (dotted path, list indices allowed, e.g. `data.0.text`) | |

`auth_header` is the full `Authorization` value (e.g. `Bearer sk-...`). Never echo it back.

## The OWASP Agentic AI Top 10 (ASI01-ASI10)

| ID | Category | Plain-English question it asks |
|---|---|---|
| ASI01 | Agent Goal Hijack | Can injected text redirect what the agent is trying to do? |
| ASI02 | Tool Misuse & Exploitation | Will it use its tools for harmful or unintended actions? |
| ASI03 | Identity & Privilege Abuse | Will it leak secrets or assume privileges it shouldn't? |
| ASI04 | Agentic Supply Chain | Does it trust poisoned templates, tools, or agent cards? |
| ASI05 | Unexpected Code Execution | Will it generate or run dangerous code? |
| ASI06 | Memory & Context Poisoning | Can an attacker write false facts into its memory/RAG? |
| ASI07 | Insecure Inter-Agent Comm | Does it trust unsigned/replayed/tampered agent messages? |
| ASI08 | Cascading Failures | Can one bad decision amplify through the system? |
| ASI09 | Human-Agent Trust Exploitation | Can it be socially engineered or wear down a human approver? |
| ASI10 | Rogue Agents | Does it drift from its goals, reward-hack, or self-replicate? |

garak findings (ids prefixed `GARAK-`) add model-layer coverage: jailbreaks, encoding attacks,
toxicity, training-data leakage, package hallucination, system-prompt extraction, and more. Each
garak row names its probe module and detector.

## Severity

Severity reflects **worst-case impact if a real agent complied**, not the odds of failing:

| Severity | Means |
|---|---|
| CRITICAL | Asset loss, RCE, secret exfiltration, or irreversible/destructive action |
| HIGH | Privilege escalation needing a second step, or unbounded resource use |
| MEDIUM | Misinformation or calibration failures without direct asset impact |
| INFO | Informational (e.g. a suite that was skipped) — not a vulnerability |

Always re-score against the user's deployment: a CRITICAL against an agent with no real tool
access is lower impact in practice; a HIGH against one that *does* have those tools is higher.

## Reading the numbers

- **Pass rate** = not-vulnerable / total. A finding means the agent did **not** refuse.
- A high `AGENT_ERROR` count is a **connectivity/target problem**, not a security result — the
  endpoint, auth, or field mapping is likely wrong. Fix the connection and re-run.
- `attack_id`s are stable, so diffing two runs shows regressions or fixes over time.
