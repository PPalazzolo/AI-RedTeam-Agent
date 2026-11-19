"""
target_adapter.py — Turn a user-supplied HTTP endpoint into an ``agent_fn``.

The red team engine treats any target as ``(str) -> str``. This adapter builds
such a callable around a remote HTTP agent so the hosted service can probe a
user's agent without any SDK coupling. Errors are returned as ``[AGENT_ERROR]``
strings (never raised) so a flaky target produces results rather than aborting
the whole run — matching the engine's own fault-isolation contract.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, Optional

import httpx

AgentFn = Callable[[str], str]


def _extract(data: Any, dotted_path: str) -> str:
    """Pull a value from nested JSON via a dotted path (list indices allowed).

    Example: ``choices.0.message.content`` -> data["choices"][0]["message"]["content"].
    An empty path returns the whole payload stringified.
    """
    if not dotted_path:
        return data if isinstance(data, str) else json.dumps(data)
    cur = data
    for part in dotted_path.split("."):
        if isinstance(cur, list):
            cur = cur[int(part)]
        elif isinstance(cur, dict):
            cur = cur[part]
        else:
            raise KeyError(f"cannot descend into {part!r} of {type(cur).__name__}")
    return cur if isinstance(cur, str) else json.dumps(cur)


def make_http_target(
    target_url: str,
    prompt_field: str = "prompt",
    response_field: str = "response",
    method: str = "POST",
    auth_header: Optional[str] = None,
    extra_headers: Optional[Dict[str, str]] = None,
    timeout: float = 60.0,
    body_template: Optional[Dict[str, Any]] = None,
) -> AgentFn:
    """Build an ``agent_fn(prompt) -> str`` that calls a remote HTTP agent.

    Parameters
    ----------
    target_url      : endpoint to call.
    prompt_field    : JSON field (POST) or query param (GET) to place the prompt in.
    response_field  : dotted path to the reply in a JSON response ('' = raw text/body).
    method          : 'POST' (default) or 'GET'.
    auth_header     : full Authorization header value, if the endpoint needs one.
    extra_headers   : any additional headers.
    timeout         : per-request timeout (seconds).
    body_template   : optional POST body; the literal string '{{PROMPT}}' in any
                      value is replaced with the prompt. Overrides prompt_field.
    """
    headers: Dict[str, str] = {"Content-Type": "application/json"}
    if auth_header:
        headers["Authorization"] = auth_header
    if extra_headers:
        headers.update(extra_headers)

    def _fill(obj: Any, prompt: str) -> Any:
        if isinstance(obj, str):
            return obj.replace("{{PROMPT}}", prompt)
        if isinstance(obj, dict):
            return {k: _fill(v, prompt) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_fill(v, prompt) for v in obj]
        return obj

    def agent_fn(prompt: str) -> str:
        try:
            if method.upper() == "GET":
                resp = httpx.get(
                    target_url, params={prompt_field: prompt},
                    headers=headers, timeout=timeout,
                )
            else:
                body = _fill(body_template, prompt) if body_template else {prompt_field: prompt}
                resp = httpx.post(target_url, json=body, headers=headers, timeout=timeout)
            resp.raise_for_status()
            ctype = resp.headers.get("content-type", "")
            if "application/json" in ctype or (response_field and not ctype.startswith("text/")):
                try:
                    return _extract(resp.json(), response_field)
                except (json.JSONDecodeError, KeyError, IndexError, ValueError):
                    return resp.text
            return resp.text
        except Exception as exc:  # noqa: BLE001 — surfaced as a result, never raised
            return f"[AGENT_ERROR] {type(exc).__name__}: {exc}"

    return agent_fn
