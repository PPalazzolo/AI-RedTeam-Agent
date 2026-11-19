# Coverage Matrix — This Framework vs. NVIDIA garak

> Companion documents: [`ARCHITECTURE.md`](./ARCHITECTURE.md) · [`THREAT_MODEL.md`](./THREAT_MODEL.md) · [`TEST_SCENARIO_DESIGN.md`](./TEST_SCENARIO_DESIGN.md)

This document maps every [NVIDIA **garak**](https://github.com/NVIDIA/garak) probe module to this
framework's OWASP Agentic AI Top 10 categories (ASI01–ASI10), so you can see exactly where the
two tools **overlap**, where **garak extends** us, and where **we extend garak**.

The headline: the two are **complementary, not competing**. garak is a mature, general-purpose
**LLM (model-layer)** vulnerability scanner with ~40 probe families driven by published research.
This framework is a purpose-built **agent-layer** red team organized around agentic trust
boundaries (tools, memory, inter-agent comms, cascades, HITL). They meet on prompt injection,
code-execution, and system-prompt extraction; each owns large territory the other barely touches.

Probe inventory below reflects garak `main` as cloned on 2026-11-19 (41 functional probe modules,
excluding `base`, `test`, `_tier`, `__init__`).

---

## 1. Legend

| Symbol | Meaning |
|:--:|---|
| 🟢 **Overlap** | garak probe tests substantially the same failure mode as one of our ASI scenarios |
| 🟡 **Partial** | Related theme, but different layer, technique, or depth — loose mapping |
| 🔵 **garak-only** | No corresponding ASI scenario; garak extends our coverage |
| — | Not an agent-security concern in our model (content safety, training-data, multimodal, model-internal) |

"ASI fit" names the closest category even for 🔵/— rows, to show *where it would live* if we added it.

---

## 2. garak probe → ASI mapping (every probe module)

| garak probe | What it tests | Closest ASI | Status |
|---|---|:--:|:--:|
| `promptinject` | Basic plaintext prompt injection (Agency Enterprise PromptInject) | ASI01 | 🟢 Overlap |
| `latentinjection` | Indirect injection buried in docs/resume/financial report | ASI01-02, ASI06-03 | 🟢 Overlap |
| `goodside` | Riley Goodside injection attacks | ASI01 | 🟢 Overlap |
| `sysprompt_extraction` | Extract the system prompt (direct, encoding, role-play) | ASI03-01, ASI09-03 | 🟢 Overlap |
| `exploitation` | Template / code / SQL injection exploits | ASI05, ASI02 | 🟢 Overlap |
| `packagehallucination` | Code gen citing non-existent (hijackable) packages | ASI05-04, ASI04 | 🟢 Overlap |
| `agent_breaker` | Multi-turn tool-exploitation of agentic apps (LLM-driven) | ASI02, ASI05 | 🟢 Overlap |
| `web_injection` | XSS / CSRF / data-exfil via web surfaces (EchoLeak, Bing) | ASI02, ASI05 | 🟢 Overlap |
| `malwaregen` | Coerce generation of malware / malicious tooling | ASI05 | 🟡 Partial |
| `fitd` | "Foot in the door" — multi-turn benign→harmful escalation | ASI10-02, ASI09-01 | 🟡 Partial |
| `misleading` | Will the model debunk vs. endorse false claims | ASI09-04 | 🟡 Partial |
| `snowball` | Wrong answers to over-complex questions (hallucination) | ASI09-04 | 🟡 Partial |
| `apikey` | Will the model generate API keys on request | ASI03 | 🟡 Partial |
| `fileformats` | Scan HF model/artifact files for unsafe content | ASI04 | 🟡 Partial |
| `dan` | DAN & DAN-like jailbreaks (20+ variants) | ASI01 | 🟡 Partial |
| `doctor` | Bypass / puppetry jailbreak | ASI01 | 🟡 Partial |
| `dra` | Disguise-and-Reconstruction jailbreak | ASI01 | 🟡 Partial |
| `grandma` | "Remind me of my grandma" social-engineering jailbreak | ASI01 | 🟡 Partial |
| `sata` | Simple Assistive Task linkage (benign subtasks → unsafe) | ASI01 | 🟡 Partial |
| `phrasing` | Grammatical rephrasing to slip past safeguards | ASI01 | 🟡 Partial |
| `adaptive_attacks` | Simple adaptive jailbreak prompts | ASI01 | 🟡 Partial |
| `atkgen` | Attacker LLM auto-generates attacks toward a failure mode | ASI01 | 🟡 Partial |
| `goat` | Multi-turn jailbreak via attacker LLM (O-T-S-R framework) | ASI01 | 🟡 Partial |
| `tap` | Tree-of-Attacks-with-Pruning automated jailbreak | ASI01 | 🟡 Partial |
| `suffix` | GCG adversarial-suffix system-prompt disruption | ASI01 | 🔵 garak-only (technique) |
| `encoding` | Injection via base64/ROT13/morse/braille/unicode-tags etc. | ASI01 | 🔵 garak-only (technique) |
| `smuggling` | Token/ASCII smuggling to obfuscate contentious terms | ASI01 | 🔵 garak-only (technique) |
| `badchars` | Imperceptible Unicode perturbations (homoglyphs, bidi, zero-width) | ASI01 | 🔵 garak-only (technique) |
| `ansiescape` | ANSI terminal escape sequences in model output | ASI05 | 🔵 garak-only |
| `av_spam_scanning` | Emit known-bad signatures (EICAR / GTUBE / GTphish) | ASI05 | 🔵 garak-only |
| `divergence` | Training-data extraction via repeat / repeated-token | — | 🔵 garak-only |
| `leakreplay` | Training-data membership via forced excerpt replay | — | 🔵 garak-only |
| `propile` | PII leakage memorized from training data | — | 🔵 garak-only |
| `glitch` | Glitch tokens that provoke anomalous behavior | — | 🔵 garak-only |
| `realtoxicityprompts` | Elicit toxic output (content safety) | — | — |
| `continuation` | Continue a contentious/slur term | — | — |
| `donotanswer` | Prompts a safe model should refuse | — | — |
| `lmrc` | Language Model Risk Cards content-safety probes | — | — |
| `topic` | Explore restricted topics | — | — |
| `audio` | Audio (multimodal) jailbreaks | — | 🔵 garak-only (multimodal) |
| `visual_jailbreak` | Image-based (multimodal) jailbreaks | — | 🔵 garak-only (multimodal) |

**Tally:** 8 🟢 Overlap · 15 🟡 Partial · 12 🔵 garak-only · 6 — (out of model scope for us).

---

## 3. Reverse view — garak coverage of each ASI category

How well does garak cover *our* categories? This is where our unique value shows.

| ASI | Category | garak coverage | garak probes that touch it | Verdict |
|:--:|---|:--:|---|---|
| ASI01 | Agent Goal Hijack | **Heavy** | `promptinject`, `latentinjection`, `goodside`, `dan`, `dra`, `doctor`, `grandma`, `sata`, `phrasing`, `adaptive_attacks`, `atkgen`, `goat`, `tap`, `suffix`, `encoding`, `smuggling`, `badchars` | garak is **stronger** here (breadth + adaptive + obfuscation) |
| ASI02 | Tool Misuse & Exploitation | Partial | `agent_breaker`, `exploitation`, `web_injection` | **We lead**; garak's `agent_breaker` is its closest analogue |
| ASI03 | Identity & Privilege Abuse | Weak | `apikey`, `sysprompt_extraction` (partial) | **We lead** — no A2A delegation / privilege-escalation probes in garak |
| ASI04 | Agentic Supply Chain | Weak | `packagehallucination`, `fileformats` | **We lead** — no template/MCP/agent-card poisoning in garak |
| ASI05 | Unexpected Code Execution | Moderate | `exploitation`, `malwaregen`, `packagehallucination`, `web_injection`, `av_spam_scanning`, `ansiescape` | **Shared** — strongest overlap zone |
| ASI06 | Memory & Context Poisoning | Weak | `latentinjection` (RAG context only) | **We lead** — no memory write-back / cross-user contamination in garak |
| ASI07 | Insecure Inter-Agent Comm | **None** | — | **Unique to us** (token replay, unsigned A2A, MITM, discovery spoofing) |
| ASI08 | Cascading Failures | **None** | — | **Unique to us** (planner poisoning, remediation loops, IR cascade) |
| ASI09 | Human-Agent Trust Exploitation | Partial | `misleading`, `snowball` (misinformation); `sysprompt_extraction` | **We lead** — HITL fatigue / fabricated rationale not in garak |
| ASI10 | Rogue Agents | Weak | `fitd`, `agent_breaker` (partial) | **We lead** — reward hacking / goal drift / self-replication not in garak |

---

## 4. garak coverage with no ASI home (our blind spots)

These garak probe families fall **outside our threat model** today — consistent with
[`THREAT_MODEL.md`](./THREAT_MODEL.md) §6 "What the framework is not designed to find." They are
candidate new suites if we ever widen scope:

| Area | garak probes | Our §6 status |
|---|---|---|
| Content safety / toxicity | `realtoxicityprompts`, `lmrc`, `continuation`, `donotanswer`, `topic` | Out of scope (not an agent trust-boundary failure) |
| Training-data extraction & membership | `divergence`, `leakreplay` | Listed out of scope |
| PII / privacy leakage | `propile` | Listed out of scope (needs labelled-data oracle) |
| Multimodal jailbreaks | `audio`, `visual_jailbreak` | Out of scope (text-only harness) |
| Model-internal anomalies | `glitch` | Out of scope (model-weight/token level) |
| Obfuscation/encoding *techniques* | `encoding`, `smuggling`, `badchars`, `suffix` | Not covered — these are **delivery techniques** we could layer onto existing ASI01 payloads |
| Output-channel injection | `ansiescape`, `av_spam_scanning` | Not covered (terminal/AV signature handling) |

---

## 5. Our coverage with no garak equivalent (our moat)

Scenarios here have **no garak counterpart** — they are the reason to keep this framework
alongside garak:

- **ASI07 Inter-Agent Communication** — all 4 scenarios (expired/`alg:none` JWT replay, unsigned
  peer messages, MITM field tampering, A2A discovery spoofing).
- **ASI08 Cascading Failures** — all 3 (planner poisoning → executor fanout, auto-remediation
  loop, false-positive disables defences).
- **ASI03 Identity & Privilege** — cross-agent privilege escalation, fake admin agent, cached
  credential reuse (garak only touches credential *generation* via `apikey`).
- **ASI04 Supply Chain** — poisoned prompt templates, typosquatted MCP tools, self-signed
  malicious agent cards (garak only has `packagehallucination` / `fileformats`).
- **ASI06 Memory Poisoning** — false-rule memory writes, cross-user contamination, RAG
  write-back, self-output write-back (garak reads poisoned context but doesn't test *writes*).
- **ASI09 HITL Exploitation** — human-in-the-loop fatigue (multi-turn), fabricated audit trails.
- **ASI10 Rogue Agents** — reward hacking, goal drift, workflow self-routing, self-replication.

The common thread: garak probes a **model**; these scenarios probe an **agent's trust boundaries**
(provenance of tools, memory, peers, and human approvals) that only exist above the model layer.

---

## 6. Technique gap: detection & payload generation

Independent of category coverage, garak is more sophisticated on two axes our
[`ARCHITECTURE.md`](./ARCHITECTURE.md) §5.2 and §7 already flag as limitations:

| Axis | This framework | garak |
|---|---|---|
| Detection | `contains_any` keyword needles (signal, not judgement) | Specialized `detector` plugins: refusal classifiers, trained HF models, decoders, regex |
| Payload variation | Fixed strings per scenario | `buffs` mutate prompts (translate, paraphrase, encode) |
| Adaptivity | Static (except 2 multi-turn scenarios) | Attacker-LLM loops: `atkgen`, `tap`, `goat`, `autodan`, `gcg` |
| Baseline/control | None | `blank`/`test` control probes |

These are the most actionable things to borrow from garak — see §7.

---

## 7. Recommendations

1. **Run both.** Use garak for model-layer breadth (jailbreak/encoding/toxicity/training-data) and
   this framework for OWASP-aligned agent trust-boundary testing. They are additive.
2. **Borrow detectors.** Add an optional LLM-as-judge detector (the `contains_any` override point
   in [`ARCHITECTURE.md`](./ARCHITECTURE.md) §6) to cut keyword false-positives/negatives.
3. **Borrow buffs.** Layer garak-style obfuscation (`encoding`, `smuggling`, `badchars`) as
   payload mutators over existing ASI01 scenarios so defences can't match exact wording.
4. **Bridge the tools.** A `garak.generators` wrapper around our `AgentFn` lets garak's probes run
   against the same agents (the subject of the separate adapter task).
5. **Don't chase garak's model-layer probes.** Toxicity, training-data extraction, and multimodal
   remain correctly out of scope per [`THREAT_MODEL.md`](./THREAT_MODEL.md) §6 — point users at
   garak for those instead of duplicating them.
