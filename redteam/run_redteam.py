#!/usr/bin/env python3
"""
run_redteam.py – Entry point for the OWASP Agentic AI Top 10 red team suite.

Quick start (demo agent):
    export OPENAI_API_KEY=sk-...
    pip install openai
    python run_redteam.py

Targeting your real agent instead:
    Replace `from demo_agent import demo_agent` with your own callable that
    accepts a str prompt and returns a str response, then pass it to
    AgenticRedTeam as agent_fn.

    Example:
        def my_real_agent(prompt: str) -> str:
            return your_agent.invoke(prompt)

        runner = AgenticRedTeam(agent_fn=my_real_agent, target_name="Prod Agent v2")

Running only specific categories:
    from agentic_redteam import ASI01_GoalHijack, ASI05_RCE

    runner = AgenticRedTeam(
        agent_fn=demo_agent,
        suites=[ASI01_GoalHijack, ASI05_RCE],
    )
"""

import sys
from demo_agent import demo_agent
from agentic_redteam import (
    AgenticRedTeam,
    ASI01_GoalHijack,
    ASI02_ToolMisuse,
    ASI03_IdentityPrivilegeAbuse,
    ASI04_SupplyChain,
    ASI05_RCE,
    ASI06_MemoryContextPoisoning,
    ASI07_InterAgentComm,
    ASI08_CascadingFailures,
    ASI09_HumanTrustExploitation,
    ASI10_RogueAgents,
)

# ── Configuration ─────────────────────────────────────────────────────────────

TARGET_NAME   = "Demo OpenAI Agent (gpt-4o)"
RESULTS_FILE  = "results.json"

# Seconds between individual API calls.
# Increase to 2.0+ if you hit rate limits on a free-tier key.
CALL_DELAY    = 1.2

# To run only a subset, comment out categories you want to skip.
SUITES_TO_RUN = [
    ASI01_GoalHijack,
    ASI02_ToolMisuse,
    ASI03_IdentityPrivilegeAbuse,
    ASI04_SupplyChain,
    ASI05_RCE,
    ASI06_MemoryContextPoisoning,
    ASI07_InterAgentComm,
    ASI08_CascadingFailures,
    ASI09_HumanTrustExploitation,
    ASI10_RogueAgents,
]

# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"\nOWASP Agentic AI Top 10 (2026) – Red Team")
    print(f"Target : {TARGET_NAME}")
    print(f"Suites : {len(SUITES_TO_RUN)} categories")
    print(f"Output : {RESULTS_FILE}\n")

    runner = AgenticRedTeam(
        agent_fn=demo_agent,
        target_name=TARGET_NAME,
        delay=CALL_DELAY,
        suites=SUITES_TO_RUN,
    )

    try:
        report = runner.run_all()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Exiting.")
        sys.exit(1)

    report.print_report()
    report.to_json(RESULTS_FILE)

    # Exit with non-zero code if any vulnerabilities were found —
    # useful for CI/CD pipelines that want to gate on red team results.
    summary = report.summary()
    sys.exit(1 if summary["vulnerable"] > 0 else 0)
