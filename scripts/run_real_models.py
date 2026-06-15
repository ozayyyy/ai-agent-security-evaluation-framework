"""Run the AASEF evaluation against a real model through a chat API.

Usage:
  AASEF_API_BASE_URL=http://127.0.0.1:8080 AASEF_API_KEY=... \\
      AASEF_MODEL=my-model python scripts/run_real_models.py
      [--scenarios DIR] [--config NAME|all] [--seed N]
      [--out FILE] [--api-base-url URL] [--api-key KEY] [--model NAME]

The model is reached through the same ``ApiModelAdapter`` the CLI's
``--agent api`` mode uses: any OpenAI-compatible chat completions
API, standard library only. Configuration is explicit arguments
first, then the environment variables ``AASEF_API_BASE_URL``,
``AASEF_API_KEY`` and ``AASEF_MODEL``; there are no built-in
defaults for the base URL or the model name, and the runner refuses
to run without them.

The report is a JSON file with the same shape as
``examples/report.json`` plus a ``real_model`` block (agent, model
name, model-call failure count). Two things are deliberately never
written to it:

- the API key, which is sent only as an ``Authorization`` header;
- the base URL and the text of model-call failures, because either
  can carry credentials (a key embedded in a URL, or a request URL
  inside an exception message). Only the failure count is recorded.

No real-model numbers are shipped with the framework: running this
needs the user's own key and endpoint, and the results depend on the
model used. Do not present a stub or simulated run as a real-model
result.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aasef.agents import CONFIG_BY_NAME, CONFIGS  # noqa: E402
from aasef.model_adapter import (ENV_API_KEY, ENV_BASE_URL, ENV_MODEL,  # noqa: E402
                                 ApiModelAdapter)
from aasef.reporting import build_report, write_json  # noqa: E402
from aasef.runner import run_all  # noqa: E402
from aasef.scenario import Scenario  # noqa: E402

DEFAULT_OUT = "examples/real-model-report.json"


def _parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the AASEF evaluation against a real model")
    parser.add_argument("--scenarios", default="scenarios")
    parser.add_argument("--config", default="all",
                        help="baseline, hierarchy-aware, "
                        "tool-side-enforced, or all")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--out", default=DEFAULT_OUT,
                        help="report JSON to write "
                        f"(default: {DEFAULT_OUT})")
    parser.add_argument("--api-base-url", default=None,
                        help="chat API base URL (or set AASEF_API_BASE_URL)")
    parser.add_argument("--api-key", default=None,
                        help="API key (or set AASEF_API_KEY; prefer the "
                        "environment variable, a flag shows in shell history)")
    parser.add_argument("--model", default=None,
                        help="model name (or set AASEF_MODEL)")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)
    base_url = args.api_base_url or os.environ.get(ENV_BASE_URL)
    model = args.model or os.environ.get(ENV_MODEL)
    if not base_url:
        print("no API base URL set: pass --api-base-url or set "
              f"{ENV_BASE_URL} to your chat API address",
              file=sys.stderr)
        return 2
    if not model:
        print("no model set: pass --model or set "
              f"{ENV_MODEL} to the model name to use",
              file=sys.stderr)
        return 2
    scenarios = Scenario.load_all(args.scenarios)
    if not scenarios:
        print(f"no scenarios found in {args.scenarios}", file=sys.stderr)
        return 2
    if args.config == "all":
        configs = list(CONFIGS)
    elif args.config in CONFIG_BY_NAME:
        configs = [CONFIG_BY_NAME[args.config]]
    else:
        print(f"unknown config {args.config!r}", file=sys.stderr)
        return 2
    adapters: list[ApiModelAdapter] = []

    def factory(config):
        adapter = ApiModelAdapter(config, base_url=base_url,
                                  api_key=args.api_key
                                  or os.environ.get(ENV_API_KEY),
                                  model=model)
        adapters.append(adapter)
        return adapter

    results = run_all(scenarios, configs, seed=args.seed,
                      agent_factory=factory)
    report = build_report(results, seed=args.seed)
    report["real_model"] = {
        "agent": "api",
        "model": model,
        "model_call_failures": sum(len(a.failures) for a in adapters),
        "note": "Real-model run. Numbers depend on the model used; "
                "they measure that model's susceptibility, not only "
                "the enforcement architecture.",
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    write_json(report, out)
    print(f"wrote {out}")
    for name, metrics in report["metrics"]["configs"].items():
        print(f"{name:20s} attack={metrics['attack_success_rate']:.1%} "
              f"task={metrics['task_completion_rate']:.1%} "
              f"false-refusal={metrics['false_refusal_rate']:.1%} "
              f"enforcement={metrics['policy_enforcement_effectiveness']:.1%}")
    failures = report["real_model"]["model_call_failures"]
    if failures:
        print(f"warning: {failures} model call(s) failed; those runs "
              f"continued with no actions", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
