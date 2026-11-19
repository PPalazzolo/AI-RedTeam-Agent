#!/usr/bin/env python3
"""
redteam_mcp_server.py — Hosted OWASP Agentic AI red team, exposed over MCP.

This is the *cloud* side of the ``aiplat-redteam`` plugin. It wraps the existing
red team engine (``agentic_redteam`` + the garak suite) and exposes it as an MCP
server over streamable HTTP, so Claude can run a user's own agent (reachable at
an HTTP endpoint) against the suite and get a structured report back.

Tools
-----
- ``list_suites()``     : available ASI categories and garak probe sets.
- ``run_redteam(...)``  : run the suite against a target HTTP agent; returns a report.
- ``health()``          : liveness/readiness probe.

Deploy
------
See ``README.md`` in this folder (Dockerfile provided). The engine is imported
from the red team package; set ``REDTEAM_PKG_DIR`` if it is not a sibling dir.

Authorized testing only — operators must ensure callers only target agents they
own or have written permission to test.
"""

from __future__ import annotations

import os
import sys
from typing import Dict, List, Optional
from urllib.parse import urlparse

# ── Locate and import the red team engine ─────────────────────────────────────
def _bootstrap_engine_path() -> None:
    candidates = [
        os.environ.get("REDTEAM_PKG_DIR"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "redteam"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "redteam"),
        "/app/redteam",
    ]
    for path in candidates:
        if path and os.path.isfile(os.path.join(path, "agentic_redteam.py")):
            if path not in sys.path:
                sys.path.insert(0, path)
            return
    raise RuntimeError(
        "Red team engine not found. Set REDTEAM_PKG_DIR to the directory that "
        "contains agentic_redteam.py (and garak_suite.py)."
    )


_bootstrap_engine_path()

from agentic_redteam import (  # noqa: E402
    AgenticRedTeam,
    ASI01_GoalHijack, ASI02_ToolMisuse, ASI03_IdentityPrivilegeAbuse,
    ASI04_SupplyChain, ASI05_RCE, ASI06_MemoryContextPoisoning,
    ASI07_InterAgentComm, ASI08_CascadingFailures,
    ASI09_HumanTrustExploitation, ASI10_RogueAgents,
)
from garak_suite import GarakSuite, COMPLEMENT_SETS  # noqa: E402
from target_adapter import make_http_target  # noqa: E402

from mcp.server.fastmcp import FastMCP  # noqa: E402

# Canonical ASI category registry (id -> (class, human name)).
ASI_SUITES = {
    "ASI01": (ASI01_GoalHijack, "Agent Goal Hijack"),
    "ASI02": (ASI02_ToolMisuse, "Tool Misuse & Exploitation"),
    "ASI03": (ASI03_IdentityPrivilegeAbuse, "Identity & Privilege Abuse"),
    "ASI04": (ASI04_SupplyChain, "Agentic Supply Chain"),
    "ASI05": (ASI05_RCE, "Unexpected Code Execution"),
    "ASI06": (ASI06_MemoryContextPoisoning, "Memory & Context Poisoning"),
    "ASI07": (ASI07_InterAgentComm, "Insecure Inter-Agent Communication"),
    "ASI08": (ASI08_CascadingFailures, "Cascading Failures"),
    "ASI09": (ASI09_HumanTrustExploitation, "Human-Agent Trust Exploitation"),
    "ASI10": (ASI10_RogueAgents, "Rogue Agents"),
}

# Safety caps so a single call can't run unbounded work.
MAX_GENERATIONS = 3
MIN_DELAY = 0.0

mcp = FastMCP(
    "aiplat-redteam",
    host=os.environ.get("HOST", "0.0.0.0"),
    port=int(os.environ.get("PORT", "8000")),
)


@mcp.tool()
def health() -> dict:
    """Liveness/readiness check. Returns engine + garak availability."""
    try:
        import garak  # noqa: F401
        garak_available = True
    except ImportError:
        garak_available = False
    return {"status": "ok", "garak_available": garak_available,
            "asi_categories": list(ASI_SUITES)}


@mcp.tool()
def list_suites() -> dict:
    """List the ASI categories and garak probe sets available to run."""
    try:
        import garak  # noqa: F401
        garak_available = True
    except ImportError:
        garak_available = False
    return {
        "asi_categories": {cid: name for cid, (_, name) in ASI_SUITES.items()},
        "garak_sets": {name: probes for name, probes in COMPLEMENT_SETS.items()},
        "garak_available": garak_available,
        "notes": "garak_set='' skips garak. 'full' is garak's entire default set and is slow.",
    }


@mcp.tool()
def run_redteam(
    target_url: str,
    prompt_field: str = "prompt",
    response_field: str = "response",
    method: str = "POST",
    auth_header: str = "",
    categories: Optional[List[str]] = None,
    garak_set: str = "core",
    garak_probes: str = "",
    generations: int = 1,
    delay: float = 0.3,
) -> dict:
    """Run the OWASP Agentic AI red team against a target HTTP agent.

    Parameters
    ----------
    target_url      : HTTP endpoint of the agent under test.
    prompt_field    : JSON field (POST) / query param (GET) carrying the prompt.
    response_field  : dotted path to the reply in a JSON response ('' = raw body).
                      e.g. OpenAI-compatible: 'choices.0.message.content'.
    method          : 'POST' (default) or 'GET'.
    auth_header     : full Authorization header value if the endpoint needs one.
    categories      : subset of ASI ids (e.g. ['ASI01','ASI05']); None = all 10.
    garak_set       : garak probe set to add ('core' default; '' to skip).
    garak_probes    : explicit garak probe override (comma-separated; wins over set).
    generations     : generations per garak prompt (capped at 3).
    delay           : seconds between individual target calls (rate-limit friendly).

    Returns a report dict: {target, timestamp, summary, results[...]}.
    Response text per result is truncated by the engine (~500 chars).
    """
    # ── validate & clamp ──────────────────────────────────────────────────────
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return {"error": f"invalid target_url: {target_url!r} (need http(s)://host/...)"}
    generations = max(1, min(int(generations), MAX_GENERATIONS))
    delay = max(MIN_DELAY, float(delay))

    if categories:
        unknown = [c for c in categories if c not in ASI_SUITES]
        if unknown:
            return {"error": f"unknown categories: {unknown}. Valid: {list(ASI_SUITES)}"}
        selected_ids = [c for c in ASI_SUITES if c in categories]  # canonical order
    else:
        selected_ids = list(ASI_SUITES)

    suites = [ASI_SUITES[c][0] for c in selected_ids]

    # ── configure garak suite via env (how GarakSuite reads its settings) ──────
    want_garak = bool(garak_set) or bool(garak_probes)
    if want_garak:
        os.environ.pop("REDTEAM_SKIP_GARAK", None)
        os.environ["GARAK_SUITE_SET"] = garak_set or "core"
        os.environ["GARAK_GENERATIONS"] = str(generations)
        if garak_probes:
            os.environ["GARAK_PROBES"] = garak_probes
        else:
            os.environ.pop("GARAK_PROBES", None)
        suites.append(GarakSuite)
    else:
        os.environ["REDTEAM_SKIP_GARAK"] = "1"

    # ── build the target callable and run ──────────────────────────────────────
    agent_fn = make_http_target(
        target_url=target_url,
        prompt_field=prompt_field,
        response_field=response_field,
        method=method,
        auth_header=auth_header or None,
    )
    target_name = f"{parsed.netloc}{parsed.path or ''}"

    runner = AgenticRedTeam(
        agent_fn=agent_fn,
        target_name=target_name,
        delay=delay,
        suites=suites,
    )
    report = runner.run_all()
    data = report.to_dict()

    # Convenience: connectivity signal + categories run (never leak the auth header).
    agent_errors = sum(1 for r in data["results"] if "[AGENT_ERROR]" in (r.get("response") or ""))
    data["meta"] = {
        "categories_run": selected_ids,
        "garak_set": (garak_set or None) if want_garak else None,
        "garak_probes": garak_probes or None,
        "generations": generations,
        "agent_error_count": agent_errors,
        "connectivity_ok": agent_errors < max(1, len(data["results"]) // 2),
    }
    return data


if __name__ == "__main__":
    # Streamable HTTP serves the MCP endpoint at /mcp on $HOST:$PORT.
    mcp.run(transport="streamable-http")
