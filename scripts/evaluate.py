"""Run the full AASEF evaluation and write measured results.

Usage: python scripts/evaluate.py [--seed N]

Writes examples/report.json, examples/report.md and per-run traces
under examples/traces/.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from aasef.agents import CONFIGS
from aasef.reporting import build_report, render_markdown, write_json
from aasef.runner import run_all
from aasef.scenario import Scenario

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the full AASEF evaluation")
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()
    scenarios = Scenario.load_all(ROOT / "scenarios")
    results = run_all(scenarios, list(CONFIGS), seed=args.seed)
    report = build_report(results, seed=args.seed)
    out = ROOT / "examples"
    out.mkdir(exist_ok=True)
    write_json(report, out / "report.json")
    (out / "report.md").write_text(render_markdown(report), encoding="utf-8")
    traces_dir = out / "traces"
    traces_dir.mkdir(exist_ok=True)
    for result in results:
        name = f"{result.scenario_id}--{result.config}.jsonl"
        (traces_dir / name).write_text(result.trace.to_jsonl(), encoding="utf-8")
    for name, metrics in report["metrics"]["configs"].items():
        print(f"{name:20s} attack={metrics['attack_success_rate']:.1%} "
              f"task={metrics['task_completion_rate']:.1%} "
              f"false-refusal={metrics['false_refusal_rate']:.1%} "
              f"enforcement={metrics['policy_enforcement_effectiveness']:.1%}")
    print(f"wrote {out / 'report.json'}, {out / 'report.md'} "
          f"and {len(results)} traces")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
