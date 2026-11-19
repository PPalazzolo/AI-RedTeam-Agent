"""
garak_target.py — Bridge between this framework's agents and NVIDIA garak.

garak's ``garak.generators.function.Single`` generator can call any Python
function with the signature::

    function(prompt: str, **kwargs) -> list[str | None]

This module exposes exactly such a function (``agent``) that forwards the
prompt to the *same* target this framework red-teams — by default the bundled
``demo_agent`` — so garak's probes exercise the identical system under test.

Why this exists
---------------
Our framework (``agentic_redteam.py``) is an *agent-layer* red team organized
around the OWASP Agentic AI Top 10. garak is a mature *model-layer* vulnerability
scanner with ~40 probe families (jailbreaks, encoding attacks, toxicity,
training-data leakage, etc.). Pointing garak at the same callable lets the two
tools **complement** each other against one target. See
``docs/GARAK_COVERAGE_MATRIX.md`` for exactly where each tool leads.

Selecting the target
--------------------
By default this wraps ``demo_agent.demo_agent``. To point garak at your own
agent instead, set an environment variable naming any ``(str) -> str`` callable
using ``module#callable`` syntax (the same contract our framework uses)::

    export GARAK_AGENT_FN=my_package.my_module#my_agent

The referenced callable must take a single ``str`` prompt and return a ``str``.

Usage (normally via run_garak.py, but also directly)::

    garak --target_type function \
          --target_name garak_target#agent \
          --probes encoding,latentinjection

Note: garak's function generator forbids a ``name`` parameter on the target
function, so this function deliberately does not accept one.
"""

from __future__ import annotations

import importlib
import os
from typing import Callable, List, Optional

# The (str) -> str contract shared with agentic_redteam.AgentFn.
AgentFn = Callable[[str], str]

_RESOLVED_FN: Optional[AgentFn] = None
_LIVE_FN: Optional[AgentFn] = None


def set_live_agent(fn: Optional[AgentFn]) -> None:
    """Inject the exact callable garak should target, overriding env/default.

    Used by ``garak_suite.GarakSuite`` so that an in-process garak run hits the
    *same* ``agent_fn`` the orchestrator is testing. Pass ``None`` to clear.
    Takes precedence over ``GARAK_AGENT_FN`` and the bundled demo agent.
    """
    global _LIVE_FN, _RESOLVED_FN
    _LIVE_FN = fn
    _RESOLVED_FN = None  # force re-resolution on next call


def _resolve_agent_fn() -> AgentFn:
    """Resolve the target callable once and cache it.

    Resolution order: an injected live agent (``set_live_agent``) >
    ``GARAK_AGENT_FN=module#callable`` > the bundled ``demo_agent.demo_agent``.
    """
    global _RESOLVED_FN
    if _LIVE_FN is not None:
        return _LIVE_FN
    if _RESOLVED_FN is not None:
        return _RESOLVED_FN

    spec = os.getenv("GARAK_AGENT_FN", "").strip()
    if spec:
        if "#" not in spec:
            raise ValueError(
                f"GARAK_AGENT_FN must be 'module#callable', got: {spec!r}"
            )
        module_name, fn_name = spec.split("#", 1)
        module = importlib.import_module(module_name)
        fn = getattr(module, fn_name)
        if not callable(fn):
            raise TypeError(f"{spec!r} does not resolve to a callable")
        _RESOLVED_FN = fn
        return _RESOLVED_FN

    # Default: the deliberately-unguarded reference agent.
    from demo_agent import demo_agent  # local import so --list_probes etc. are cheap

    _RESOLVED_FN = demo_agent
    return _RESOLVED_FN


def agent(prompt: str, **kwargs) -> List[Optional[str]]:
    """garak function-generator entry point.

    Takes a single prompt string, returns a one-element list containing the
    agent's response (garak expects ``list[str | None]``). Exceptions are
    converted to an ``[AGENT_ERROR] ...`` string — mirroring
    ``BaseAttackSuite.call`` — so a transient failure yields a result instead
    of aborting the whole garak run.
    """
    fn = _resolve_agent_fn()
    try:
        reply = fn(prompt)
    except Exception as exc:  # noqa: BLE001 — intentionally broad, see docstring
        return [f"[AGENT_ERROR] {type(exc).__name__}: {exc}"]
    return [reply if isinstance(reply, str) else str(reply)]
