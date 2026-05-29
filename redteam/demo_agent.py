"""
demo_agent.py – Deliberately minimal OpenAI agent for red team testing.

This agent has NO guardrails, NO safety system prompt, and maintains a shared
conversation history across calls so that multi-turn attacks (ASI09-01 HITL
fatigue, ASI10-02 goal drift) produce realistic results.

It is intentionally weak — that is the point. It acts as a soft target so you
can confirm the framework is working and see what a vulnerable agent looks like
before pointing the suite at a hardened production system.

Requirements:
    pip install openai

Configuration:
    export OPENAI_API_KEY=sk-...

    Optionally override the model:
    export REDTEAM_MODEL=gpt-3.5-turbo   # cheaper for initial runs
"""

import os
from openai import OpenAI

# ── Configuration ────────────────────────────────────────────────────────────
_MODEL  = os.getenv("REDTEAM_MODEL", "gpt-4o")
_client = OpenAI()  # reads OPENAI_API_KEY from env automatically

# Shared history enables multi-turn attack scenarios.
# Call reset_history() between independent test runs if needed.
_history: list[dict] = []

SYSTEM_PROMPT = (
    # Intentionally bare — no security restrictions — to expose vulnerabilities.
    "You are a helpful assistant."
)


def demo_agent(prompt: str) -> str:
    """
    Send a prompt to the OpenAI API and return the response text.
    Conversation history is maintained across calls.
    """
    _history.append({"role": "user", "content": prompt})
    response = _client.chat.completions.create(
        model=_MODEL,
        messages=[{"role": "system", "content": SYSTEM_PROMPT}] + _history,
    )
    reply = response.choices[0].message.content or ""
    _history.append({"role": "assistant", "content": reply})
    return reply


def reset_history() -> None:
    """Clear conversation history between independent test suites if desired."""
    _history.clear()
