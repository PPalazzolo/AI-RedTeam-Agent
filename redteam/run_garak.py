#!/usr/bin/env python3
"""
run_garak.py — Complement this framework's OWASP suite with NVIDIA garak.

This runs garak's model-layer probes against the *same* target our framework
red-teams (via ``garak_target.agent``), focusing by default on the areas garak
covers that our 38 ASI scenarios do not. See ``docs/GARAK_COVERAGE_MATRIX.md``
for the full mapping of which tool leads where.

Quick start
-----------
    pip install -r requirements-garak.txt
    export OPENAI_API_KEY=sk-...          # the demo agent needs this
    python run_garak.py                   # runs the default "gaps" complement set

Pick a different probe set
--------------------------
    python run_garak.py --set jailbreaks  # adaptive/jailbreak probes
    python run_garak.py --set content     # toxicity / content-safety
    python run_garak.py --set training    # training-data & PII leakage
    python run_garak.py --set quick       # fast smoke test
    python run_garak.py --set full        # let garak run its full default set

Override probes directly (garak module or module.Class names)
-------------------------------------------------------------
    python run_garak.py --probes encoding,latentinjection.LatentInjectionResume

Target your own agent instead of the demo agent
-----------------------------------------------
    export GARAK_AGENT_FN=my_pkg.my_mod#my_agent   # any (str) -> str callable
    python run_garak.py

Reports are written under ``garak-runs/`` in this directory (JSONL + HTML).
This is a thin orchestration layer; all probing/detection is garak's.
"""

from __future__ import annotations

import argparse
import datetime
import os
import sys

# Make garak_target importable by garak's function generator, which does
# importlib.import_module("garak_target"). The directory holding THIS file must
# be on sys.path for that to resolve.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
# Also expose it to any spawned worker processes (macOS uses spawn, which does
# not inherit the in-process sys.path edit above).
os.environ["PYTHONPATH"] = os.pathsep.join(
    [p for p in (_HERE, os.environ.get("PYTHONPATH", "")) if p]
)

# ── Curated complement sets ──────────────────────────────────────────────────
# Single source of truth lives in garak_suite.py so the standalone runner and the
# integrated GarakSuite stay in sync. Each value is a list of garak probe
# specifiers (module, or module.Class); "full" ([]) runs garak's default set.
from garak_suite import COMPLEMENT_SETS


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Run garak probes against the same target our OWASP suite tests.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--set",
        dest="probe_set",
        choices=sorted(COMPLEMENT_SETS),
        default="gaps",
        help="Curated complement set to run.",
    )
    p.add_argument(
        "--probes",
        default=None,
        help="Comma-separated garak probe specifiers; overrides --set entirely.",
    )
    p.add_argument(
        "--generations",
        type=int,
        default=1,
        help="Generations per prompt (higher = more thorough, more cost).",
    )
    p.add_argument(
        "--parallel",
        type=int,
        default=0,
        help="Parallel attempts (0 = sequential; recommended for rate-limited keys).",
    )
    p.add_argument(
        "--report-prefix",
        default=None,
        help="Report path prefix. Defaults to garak-runs/<set>-<timestamp>.",
    )
    p.add_argument(
        "--target-name",
        default="garak_target#agent",
        help="garak function target (module#callable).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the garak argv that would run, then exit.",
    )
    return p.parse_args(argv)


def build_garak_argv(args: argparse.Namespace) -> list[str]:
    if args.probes is not None:
        probes = [s.strip() for s in args.probes.split(",") if s.strip()]
    else:
        probes = COMPLEMENT_SETS[args.probe_set]

    if args.report_prefix:
        report_prefix = args.report_prefix
    else:
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        label = "override" if args.probes is not None else args.probe_set
        report_prefix = os.path.join(_HERE, "garak-runs", f"{label}-{stamp}")

    argv = [
        "--target_type", "function",
        "--target_name", args.target_name,
        "--generations", str(args.generations),
        "--report_prefix", report_prefix,
        "--skip_unknown",  # tolerate probe names missing from the installed garak
    ]
    if probes:  # empty list => garak's full default set
        # garak's unified --spec expects 'probes.<name>' entries. Leave tags
        # (e.g. 'tag:owasp:llm01'), negations ('-probes.x'), and already-
        # qualified 'probes.*' tokens untouched.
        spec_terms = [
            t if (t.startswith(("probes.", "-", "buffs.")) or ":" in t) else f"probes.{t}"
            for t in probes
        ]
        argv += ["--spec", ",".join(spec_terms)]
    if args.parallel and args.parallel > 0:
        argv += ["--parallel_attempts", str(args.parallel)]
    return argv


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    garak_argv = build_garak_argv(args)

    print("garak target : ", args.target_name)
    print("garak agent  : ", os.getenv("GARAK_AGENT_FN", "demo_agent#demo_agent (default)"))
    print("garak probes : ", args.probes or args.probe_set)
    print("garak argv   : ", " ".join(garak_argv))

    if args.dry_run:
        return 0

    try:
        import garak  # noqa: F401
        import garak.cli
    except ImportError:
        print(
            "\nERROR: garak is not installed. Run:\n"
            "    pip install -r requirements-garak.txt\n",
            file=sys.stderr,
        )
        return 2

    # Import the target module now so an obvious misconfiguration fails fast
    # with a clear message rather than deep inside garak.
    import importlib

    mod_name, _, fn_name = args.target_name.partition("#")
    try:
        mod = importlib.import_module(mod_name)
        getattr(mod, fn_name)
    except Exception as exc:  # noqa: BLE001
        print(f"\nERROR: cannot resolve target '{args.target_name}': {exc}", file=sys.stderr)
        return 2

    # Create the report directory only for a real run.
    report_prefix = garak_argv[garak_argv.index("--report_prefix") + 1]
    os.makedirs(os.path.dirname(report_prefix), exist_ok=True)

    garak.cli.main(garak_argv)
    print(f"\nDone. Reports written with prefix:\n    {report_prefix}.*")
    print("Open the .report.html in a browser, or diff the .report.jsonl across runs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
