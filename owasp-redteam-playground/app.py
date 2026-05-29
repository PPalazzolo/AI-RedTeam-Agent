#!/usr/bin/env python3
"""OWASP Agentic AI Red Team \u2014 web app.

Local-only Flask server. Routes are thin \u2014 all logic lives in core/.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    request,
    send_from_directory,
    stream_with_context,
)

# Make `core` importable when run as a script.
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from core import DOCS_REGISTRY, config, models, scenarios, report, runner  # noqa: E402

# The webapp lives next to the CLI tool, not inside it.
# Resources we read from the CLI (agent template, docs, how_it_works.html)
# all live under ../redteam/ relative to this file.
REDTEAM_ROOT = HERE.parent / "redteam"
DEMO_AGENT_PATH = REDTEAM_ROOT / "demo_agent.py"

app = Flask(
    __name__,
    static_folder=str(HERE / "static"),
    static_url_path="/static",
)


# ── HTML shell ──────────────────────────────────────────────


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/docs/how-it-works")
def how_it_works_redirect():
    # Serve the existing how_it_works.html from the redteam dir.
    path = REDTEAM_ROOT / "how_it_works.html"
    if not path.exists():
        abort(404)
    return send_from_directory(str(REDTEAM_ROOT), "how_it_works.html")


# ── Config ──────────────────────────────────────────────────


@app.route("/api/config", methods=["GET"])
def api_config_get():
    return jsonify(config.public_view())


@app.route("/api/config", methods=["POST"])
def api_config_post():
    body = request.get_json(force=True, silent=True) or {}
    allowed = {"api_key", "default_model", "default_temperature", "default_system_prompt"}
    updates = {k: v for k, v in body.items() if k in allowed}
    if "api_key" in updates:
        updates["api_key"] = str(updates["api_key"]).strip()
    config.save(updates)
    return jsonify(config.public_view())


# ── Static data ─────────────────────────────────────────────


@app.route("/api/models")
def api_models():
    return jsonify({"models": models.get_all()})


@app.route("/api/scenarios")
def api_scenarios():
    return jsonify({
        "categories": scenarios.categories(),
        "scenarios": scenarios.get_all(),
    })


@app.route("/api/agent-template")
def api_agent_template():
    if not DEMO_AGENT_PATH.exists():
        return jsonify({"source": "", "error": "demo_agent.py not found"}), 404
    return jsonify({"source": DEMO_AGENT_PATH.read_text(encoding="utf-8")})


# ── Runs ────────────────────────────────────────────────────


@app.route("/api/runs", methods=["POST"])
def api_runs_start():
    body = request.get_json(force=True, silent=True) or {}

    api_key = config.get_api_key()
    if not api_key:
        return jsonify({"error": "OpenAI API key is not configured. Save it in Settings first."}), 400

    scenario_ids = body.get("scenario_ids") or []
    if not scenario_ids:
        return jsonify({"error": "Select at least one scenario."}), 400

    agent_mode = body.get("agent_mode", "settings")
    if agent_mode not in ("settings", "code"):
        return jsonify({"error": f"Unknown agent_mode: {agent_mode}"}), 400

    if agent_mode == "code" and not body.get("code", "").strip():
        return jsonify({"error": "Code mode requires non-empty source code."}), 400

    model = body.get("model") or config.load()["default_model"]
    target_name = body.get("target_name") or f"Custom agent ({model})" if agent_mode == "code" else f"Settings agent ({model})"

    spec = {
        "api_key": api_key,
        "agent_mode": agent_mode,
        "model": model,
        "system_prompt": body.get("system_prompt") or config.load()["default_system_prompt"],
        "temperature": body.get("temperature", config.load()["default_temperature"]),
        "code": body.get("code", ""),
        "scenario_ids": scenario_ids,
        "payload_overrides": body.get("payload_overrides") or {},
        "delay": body.get("delay", 1.2),
    }

    run = runner.Run(spec=spec, target_name=target_name)
    runner.register(run)
    run.start()
    return jsonify({"run_id": run.id})


@app.route("/api/runs/<run_id>/events")
def api_runs_events(run_id: str):
    run = runner.get(run_id)
    if run is None:
        abort(404)

    def generate():
        yield from runner.stream_events(run)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.route("/api/runs/<run_id>/results")
def api_runs_results(run_id: str):
    run = runner.get(run_id)
    if run is None:
        abort(404)
    return jsonify(run.to_report())


@app.route("/api/runs/<run_id>/report.html")
def api_runs_report_html(run_id: str):
    run = runner.get(run_id)
    if run is None:
        abort(404)
    html = report.render(run.to_report())
    return Response(html, mimetype="text/html", headers={
        "Content-Disposition": f'attachment; filename="security-report-{run_id}.html"',
    })


@app.route("/api/runs/<run_id>/cancel", methods=["POST"])
def api_runs_cancel(run_id: str):
    run = runner.get(run_id)
    if run is None:
        abort(404)
    run.cancel()
    return jsonify({"ok": True})


# ── Docs ────────────────────────────────────────────────────


@app.route("/api/docs")
def api_docs_list():
    return jsonify({"docs": DOCS_REGISTRY})


@app.route("/api/docs/<doc_id>")
def api_docs_get(doc_id: str):
    entry = next((d for d in DOCS_REGISTRY if d["id"] == doc_id), None)
    if entry is None:
        abort(404)
    target = (HERE / entry["path"]).resolve()
    if not target.exists():
        abort(404)
    return Response(target.read_text(encoding="utf-8"),
                    mimetype="text/markdown" if entry["type"] == "markdown" else "text/html")


# ── Main ────────────────────────────────────────────────────


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5050"))
    print()
    print("  OWASP Agentic AI Red Team \u2014 webapp")
    print(f"  Open: http://localhost:{port}")
    print()
    print("  NOTE: this app is local-only and may exec user-supplied Python code")
    print("        in the 'advanced editor'. Do not expose it on a network.")
    print()
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
