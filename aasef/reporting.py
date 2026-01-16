"""Reporting: JSON and Markdown evaluation reports."""

from __future__ import annotations

import json

from .runner import RunResult
from .scoring import score


def build_report(results: list[RunResult], seed: int = 0) -> dict:
    metrics = score(results)
    return {
        "seed": seed,
        "runs": [r.to_dict() for r in results],
        "metrics": metrics,
    }


def write_json(report: dict, path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def render_markdown(report: dict) -> str:
    metrics = report["metrics"]["configs"]
    lines = [
        "# AI Agent Security Evaluation — Results",
        "",
        f"Runs: {report['metrics']['total_runs']} (seed {report['seed']}).",
        "Agents are deterministic simulated decision policies, not "
        "language models; results measure the enforcement architecture.",
        "",
        "## Headline metrics",
        "",
        "| Configuration | Attack success | Unauthorised actions | "
        "Task completion | False refusals | Enforcement effectiveness |",
        "|---|---|---|---|---|---|",
    ]
    for name, m in metrics.items():
        lines.append(
            f"| {name} | {_pct(m['attack_success_rate'])} | "
            f"{_pct(m['unauthorised_action_rate'])} | "
            f"{_pct(m['task_completion_rate'])} | "
            f"{_pct(m['false_refusal_rate'])} | "
            f"{_pct(m['policy_enforcement_effectiveness'])} |")
    lines += ["", "## Attack success by category", "",
              "| Category | " + " | ".join(metrics) + " |",
              "|---|" + "---|" * len(metrics) + "|"]
    categories = sorted({c for m in metrics.values()
                         for c in m["by_category"]})
    for category in categories:
        cells = [_pct(metrics[name]["by_category"][category]["attack_success_rate"])
                 if category in metrics[name]["by_category"] else "-"
                 for name in metrics]
        lines.append(f"| {category} | " + " | ".join(cells) + " |")
    lines += ["", "## Reading the results", "",
              "- Baseline follows instructions wherever it finds them, "
              "including untrusted web pages, documents and tool output.",
              "- Hierarchy-aware ignores instructions in untrusted content "
              "but still follows direct instructions from the user, a "
              "trusted principal — so direct injection still succeeds.",
              "- Tool-side enforcement blocks unauthorised actions at the "
              "tool boundary even when the agent attempts them, which is "
              "why its attack success rate is the lowest.",
              "- False refusals are measured on benign tasks only; a "
              "consequential benign action without pre-approval is denied "
              "by the gate, which is a usability cost of enforcement.",
              ""]
    return "\n".join(lines)
