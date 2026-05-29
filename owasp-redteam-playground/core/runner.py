"""Orchestrate a red-team run and stream progress events.

Runs are managed in-memory: spin up a background thread, push test results onto
a queue, and let the SSE endpoint drain that queue.

A run goes through the following lifecycle events:
    started   -> {run_id, total}
    progress  -> {index, total, attack_id, status: "pending" | "running"}
    result    -> {index, total, attack_id, ...AttackResult fields}
    finished  -> {summary, results}
    error     -> {message}
"""

from __future__ import annotations

import json
import queue
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any

from . import scenarios as scenario_manifest
from . import agent_factory, detector


_RUNS: dict[str, "Run"] = {}
_RUNS_LOCK = threading.Lock()

# Cap stored runs to avoid memory growth across many sessions.
_MAX_RUNS = 50


class Run:
    """One red-team run. State is updated by a background thread."""

    def __init__(
        self,
        spec: dict[str, Any],
        target_name: str,
    ):
        self.id = uuid.uuid4().hex[:12]
        self.spec = spec
        self.target_name = target_name
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.status: str = "pending"
        self.error: str | None = None
        self.events: queue.Queue = queue.Queue()
        self.results: list[dict[str, Any]] = []
        self._thread: threading.Thread | None = None
        self._cancel = threading.Event()

    # ── Public API ──────────────────────────────────────────

    def start(self) -> None:
        self.status = "running"
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def cancel(self) -> None:
        self._cancel.set()

    def summary(self) -> dict[str, Any]:
        vuln = [r for r in self.results if r["vulnerable"]]
        by_sev: dict[str, int] = {}
        for r in vuln:
            by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
        return {
            "total_tests": len(self.results),
            "vulnerable": len(vuln),
            "not_vulnerable": len(self.results) - len(vuln),
            "by_severity": by_sev,
        }

    def to_report(self) -> dict[str, Any]:
        return {
            "target": self.target_name,
            "timestamp": self.timestamp,
            "summary": self.summary(),
            "results": self.results,
        }

    # ── Worker ──────────────────────────────────────────────

    def _emit(self, event_type: str, data: dict[str, Any]) -> None:
        self.events.put({"event": event_type, "data": data})

    def _run(self) -> None:
        try:
            agent = self._build_agent()
        except Exception as exc:
            self.status = "failed"
            self.error = str(exc)
            self._emit("error", {"message": self.error})
            self._emit("finished", self.to_report())
            return

        selected_ids: list[str] = self.spec["scenario_ids"]
        overrides: dict[str, str] = self.spec.get("payload_overrides", {})
        delay: float = float(self.spec.get("delay", 1.2))

        all_scenarios = {s["id"]: s for s in scenario_manifest.get_all()}
        run_list = [all_scenarios[sid] for sid in selected_ids if sid in all_scenarios]

        self._emit("started", {"run_id": self.id, "total": len(run_list)})

        for idx, scenario in enumerate(run_list):
            if self._cancel.is_set():
                self.status = "cancelled"
                break

            self._emit("progress", {
                "index": idx,
                "total": len(run_list),
                "attack_id": scenario["id"],
                "scenario": scenario["scenario"],
                "status": "running",
            })

            payload = overrides.get(scenario["id"], scenario["default_payload"])
            try:
                # Run multi-turn priming first (if any) so the conversation history
                # carries the cumulative pressure into the test payload.
                for primer in scenario.get("multi_turn", []) or []:
                    if self._cancel.is_set():
                        break
                    agent(primer)
                    time.sleep(delay)

                response = agent(payload)
                if delay > 0:
                    time.sleep(delay)
            except Exception as exc:
                response = f"[AGENT_ERROR] {exc}"

            vulnerable = detector.is_vulnerable(
                response,
                scenario.get("needles", []),
                scenario.get("anti_needles") or None,
            )
            result = {
                "attack_id": scenario["id"],
                "category": scenario["category"],
                "category_id": scenario["category_id"],
                "category_friendly": scenario["category_friendly"],
                "scenario": scenario["scenario"],
                "severity": scenario["severity"],
                "payload": payload,
                "response": response,
                "vulnerable": vulnerable,
                "evidence": scenario["evidence_template"] if vulnerable else "",
                "recommendation": scenario["recommendation"],
            }
            self.results.append(result)

            self._emit("result", {
                "index": idx,
                "total": len(run_list),
                **result,
            })

        if self.status != "cancelled":
            self.status = "finished"
        self._emit("finished", self.to_report())

    def _build_agent(self):
        spec = self.spec
        api_key = spec["api_key"]
        if not api_key:
            raise ValueError("OpenAI API key is not configured. Save it in Settings first.")

        mode = spec.get("agent_mode", "settings")
        if mode == "settings":
            return agent_factory.build_from_settings(
                api_key=api_key,
                model=spec.get("model", "gpt-4o"),
                system_prompt=spec.get("system_prompt", "You are a helpful assistant."),
                temperature=float(spec.get("temperature", 0.7)),
            )
        elif mode == "code":
            return agent_factory.build_from_code(
                api_key=api_key,
                source_code=spec["code"],
            )
        else:
            raise ValueError(f"Unknown agent mode: {mode}")


# ── Registry helpers ────────────────────────────────────────


def register(run: Run) -> None:
    with _RUNS_LOCK:
        _RUNS[run.id] = run
        if len(_RUNS) > _MAX_RUNS:
            # Drop oldest finished runs.
            for key in list(_RUNS.keys())[: len(_RUNS) - _MAX_RUNS]:
                if _RUNS[key].status in ("finished", "failed", "cancelled"):
                    _RUNS.pop(key, None)


def get(run_id: str) -> Run | None:
    return _RUNS.get(run_id)


def stream_events(run: Run):
    """Yield SSE-formatted lines for a run until it finishes."""
    while True:
        try:
            ev = run.events.get(timeout=30)
        except queue.Empty:
            # Heartbeat to keep proxies happy.
            yield ":\n\n"
            continue
        yield f"event: {ev['event']}\ndata: {json.dumps(ev['data'])}\n\n"
        if ev["event"] in ("finished", "error"):
            break
