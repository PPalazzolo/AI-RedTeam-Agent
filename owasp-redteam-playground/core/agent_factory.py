"""Build the target agent callable for a run.

Two modes are supported:

  settings mode  - user picks model, system prompt, and temperature in the UI
                   We construct a thin OpenAI wrapper that maintains conversation
                   history across calls (needed for multi-turn scenarios).

  code mode      - user pastes / edits full Python source in the UI
                   We exec it and pull out a callable named `demo_agent`. The
                   user's code is responsible for building its own OpenAI client.
                   We inject OPENAI_API_KEY into the environment first so the
                   default `OpenAI()` constructor works.

Both modes return the same shape: a callable accepting `str` and returning `str`,
plus a `reset_history()` function for resetting between independent runs.
"""

from __future__ import annotations

import os
from typing import Any, Callable

from openai import OpenAI


AgentFn = Callable[[str], str]


class Agent:
    """Wraps the target callable with shared history and a reset hook."""

    def __init__(self, call_fn: AgentFn, reset_fn: Callable[[], None] | None = None):
        self._call = call_fn
        self._reset = reset_fn or (lambda: None)

    def __call__(self, prompt: str) -> str:
        return self._call(prompt)

    def reset(self) -> None:
        self._reset()


def build_from_settings(
    api_key: str,
    model: str,
    system_prompt: str,
    temperature: float = 0.7,
) -> Agent:
    """Build the simple settings-driven OpenAI agent."""
    client = OpenAI(api_key=api_key)
    history: list[dict[str, str]] = []

    def call(prompt: str) -> str:
        history.append({"role": "user", "content": prompt})
        kwargs: dict[str, Any] = {
            "model": model,
            "messages": [{"role": "system", "content": system_prompt}] + history,
        }
        if temperature is not None:
            kwargs["temperature"] = temperature
        response = client.chat.completions.create(**kwargs)
        reply = response.choices[0].message.content or ""
        history.append({"role": "assistant", "content": reply})
        return reply

    def reset() -> None:
        history.clear()

    return Agent(call, reset)


def build_from_code(api_key: str, source_code: str) -> Agent:
    """Exec user-supplied Python and extract the `demo_agent` callable.

    The user code must define a function `demo_agent(prompt: str) -> str`. If it
    also defines `reset_history()` we wire that up too.

    The OPENAI_API_KEY env var is injected before exec so that user code using
    `OpenAI()` with no args works out of the box.

    SECURITY NOTE: this exec's arbitrary user code in-process. The webapp is
    local-only and single-user by design \u2014 do not expose it on a network.
    """
    if "demo_agent" not in source_code:
        raise ValueError(
            "Your code must define a function named `demo_agent(prompt: str) -> str`."
        )

    prev_key = os.environ.get("OPENAI_API_KEY")
    os.environ["OPENAI_API_KEY"] = api_key
    try:
        namespace: dict[str, Any] = {"__name__": "__user_agent__"}
        exec(compile(source_code, "<user_agent>", "exec"), namespace)
    finally:
        if prev_key is None:
            os.environ.pop("OPENAI_API_KEY", None)
        else:
            os.environ["OPENAI_API_KEY"] = prev_key

    call = namespace.get("demo_agent")
    if not callable(call):
        raise ValueError(
            "Your code must define a callable named `demo_agent(prompt: str) -> str`."
        )

    reset = namespace.get("reset_history")
    if not callable(reset):
        reset = None

    # Wrap so that each call has the key in env (some user code may construct the
    # client lazily on first call).
    def wrapped(prompt: str) -> str:
        prev = os.environ.get("OPENAI_API_KEY")
        os.environ["OPENAI_API_KEY"] = api_key
        try:
            return call(prompt)
        finally:
            if prev is None:
                os.environ.pop("OPENAI_API_KEY", None)
            else:
                os.environ["OPENAI_API_KEY"] = prev

    return Agent(wrapped, reset)
