"""Command line interface.

Usage:
  python -m aasef list [--scenarios DIR]
  python -m aasef run [--scenarios DIR] [--config NAME|all] [--seed N]
                      [--out DIR] [--traces DIR]
                      [--agent simulated|api] [--api-base-url URL]
                      [--api-key KEY] [--model NAME]

The simulated agent is the default and needs nothing else. The api
agent asks a real model through an OpenAI-compatible chat API:
set AASEF_API_BASE_URL (or pass --api-base-url), AASEF_API_KEY and
AASEF_MODEL, then run with --agent api.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .agents import CONFIG_BY_NAME, CONFIGS
from .model_adapter import ENV_BASE_URL, ApiModelAdapter
from .reporting import build_report, render_markdown, write_json
from .runner import run_all
from .scenario import Scenario


def _parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="aasef",
                                     description="AI Agent Security Evaluation Framework")
    sub = parser.add_subparsers(dest="command", required=True)
    list_cmd = sub.add_parser("list", help="list scenarios")
    list_cmd.add_argument("--scenarios", default="scenarios")
    run_cmd = sub.add_parser("run", help="run the evaluation")
    run_cmd.add_argument("--scenarios", default="scenarios")
    run_cmd.add_argument("--config", default="all",
                         help="baseline, hierarchy-aware, tool-side-enforced, or all")
    run_cmd.add_argument("--seed", type=int, default=0)
    run_cmd.add_argument("--out", default=None,
                         help="directory for report.json and report.md")
    run_cmd.add_argument("--traces", default=None,
                         help="directory for per-run JSONL traces")
    run_cmd.add_argument("--agent", default="simulated",
                         choices=["simulated", "api"],
                         help="simulated policies (default) or a real "
                         "model through a chat API")
    run_cmd.add_argument("--api-base-url", default=None,
                         help="chat API base URL (or set AASEF_API_BASE_URL)")
    run_cmd.add_argument("--api-key", default=None,
                         help="API key (or set AASEF_API_KEY; prefer the "
                         "environment variable, a flag shows in shell history)")
    run_cmd.add_argument("--model", default=None,
                         help="model name (or set AASEF_MODEL)")
    return parser.parse_args(argv)


def _load(scenarios_dir: str) -> list[Scenario]:
    scenarios = Scenario.load_all(scenarios_dir)
    if not scenarios:
        raise SystemExit(f"no scenarios found in {scenarios_dir}")
    return scenarios


def main(argv=None) -> int:
    args = _parse_args(argv)
    if args.command == "list":
        for scenario in _load(args.scenarios):
            print(f"{scenario.id:28s} {scenario.category:22s} {scenario.title}")
        return 0
    scenarios = _load(args.scenarios)
    if args.config == "all":
        configs = list(CONFIGS)
    elif args.config in CONFIG_BY_NAME:
        configs = [CONFIG_BY_NAME[args.config]]
    else:
        raise SystemExit(f"unknown config {args.config!r}")
    agent_factory = None
    if args.agent == "api":
        if not (args.api_base_url or os.environ.get(ENV_BASE_URL)):
            raise SystemExit(
                "no API base URL set: pass --api-base-url or set "
                "AASEF_API_BASE_URL to your chat API address, "
                "then run with --agent api")
        agent_factory = lambda config: ApiModelAdapter(
            config, base_url=args.api_base_url, api_key=args.api_key,
            model=args.model)
    results = run_all(scenarios, configs, seed=args.seed,
                      agent_factory=agent_factory)
    report = build_report(results, seed=args.seed)
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        write_json(report, out / "report.json")
        (out / "report.md").write_text(render_markdown(report), encoding="utf-8")
        print(f"wrote {out / 'report.json'} and {out / 'report.md'}")
    if args.traces:
        traces_dir = Path(args.traces)
        traces_dir.mkdir(parents=True, exist_ok=True)
        for result in results:
            name = f"{result.scenario_id}--{result.config}.jsonl"
            (traces_dir / name).write_text(result.trace.to_jsonl(), encoding="utf-8")
        print(f"wrote {len(results)} traces to {traces_dir}")
    for name, metrics in report["metrics"]["configs"].items():
        print(f"{name:20s} attack={metrics['attack_success_rate']:.1%} "
              f"task={metrics['task_completion_rate']:.1%} "
              f"false-refusal={metrics['false_refusal_rate']:.1%} "
              f"enforcement={metrics['policy_enforcement_effectiveness']:.1%}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
