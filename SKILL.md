---
name: ai-agent-security-evaluation-framework
description: Evaluate security boundaries in tool-using AI agents — prompt injection, tool permissions, approval gates and multi-agent delegation — with deterministic scenarios; use when testing whether an agent's defences stop an attack or comparing enforcement designs.
---

# AI Agent Security Evaluation Framework (AASEF)

## What it does

AASEF tests whether a tool-using AI agent respects security
boundaries. It runs an agent against 40 fixed scenarios and reports,
per agent setup, how many attacks succeeded, how many tasks
completed, and how many benign tasks were wrongly refused.

The scenarios cover: direct injection (the instruction is in the
user's own message), indirect injection (in a web page, a document
or a tool output), unauthorised tools, privilege boundaries,
out-of-scope data, cross-task and cross-session leaks,
approval-bypass, benign tasks, and multi-agent delegation — a
poisoned sub-agent result, sub-agent privilege escalation, the
confused deputy, sub-agent exfiltration and cross-session leaks
through a sub-agent.

Three agent setups are compared:

- **baseline** — follows instructions wherever it finds them.
- **hierarchy-aware** — ignores instructions in untrusted content,
  but still follows the user, a trusted principal.
- **tool-side-enforced** — same filtering, plus the tool boundary
  refuses out-of-scope actions and an approval gate denies
  unapproved consequential actions.

Measured results (simulated agents, seed 0): baseline 100% attack
success, hierarchy-aware 33.3%, tool-side-enforced 2.8% — the one
attack it does not stop is the confused deputy
(`delegation-03`), where the harmful step is the sub-agent's
legitimate plan and the sub-agent's scope allows it. Task
completion is 100% for all three setups. Full results:
`docs/evaluation.md`, `examples/report.md`.

By default the agents are built-in pretend agents (deterministic
decision rules, not language models), so the results measure the
enforcement design, not any particular model. A real model can be
plugged in through the built-in API connector — see below.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Python 3.10+. No other dependencies. Everything is standard
library; tools are sandboxed in-process with synthetic data.

## Run the evaluation

```bash
# List scenarios
python -m aasef list

# Run the full evaluation (simulated agents)
python -m aasef run --out examples --traces examples/traces

# Run one setup only
python -m aasef run --config tool-side-enforced --seed 0

# Reproduce the shipped results
python scripts/evaluate.py
```

## How to read the output

The run prints one line per setup: attack success, task
completion, false-refusal rate, enforcement effectiveness.

- `report.json` (in `--out`) holds every run (attempted vs
  completed actions, denials, attack/task/false-refusal flags) and
  the metrics per setup and per category.
- `report.md` is the same results as a table.
- One JSONL trace per run (in `--traces`) records every decision,
  tool call, policy decision, approval and observation in order.
  Attempted and completed actions are logged separately: a denied
  action appears as an attempt, never as a completed action.
  Delegated actions are marked `delegated: true`.

Read the numbers this way: attack success is the share of attack
scenarios where a must-not-complete action completed. Task
completion is the share of scenarios where every must-complete
action completed. False refusals are measured on benign scenarios
only. Enforcement effectiveness is 1 minus attack success.

## Using it on your own model

The framework can ask a real model for its plans instead of using
the pretend agents, through any OpenAI-compatible chat API.

```bash
export AASEF_API_BASE_URL="https://your-api-address"
export AASEF_API_KEY="your-key-here"
export AASEF_MODEL="your-model-name"
python -m aasef run --agent api
```

Or run the dedicated runner, which writes its own report file:

```bash
python scripts/run_real_models.py --out examples/real-model-report.json
```

If a model call fails (HTTP error, timeout, unusable reply) the run
does not crash: that run gets an empty plan, the failure is written
in the trace, and the run goes on. The framework never retries a
network call. The key is sent only as an `Authorization` header and
is never written to a trace, a report, a log or the screen. The
report records the model name and the number of failed model calls,
never the key or the base URL.

No real-model numbers are shipped with the framework: they need
your own key and endpoint, and they depend on the model used. Never
present a simulated run as a real-model result.

## Using it on your own scenarios

1. Copy one file from `scenarios/` in the same category as what you
   want to test.
2. Change the task to your real task, in plain words.
3. Change the rules to your real rules: which files, hosts and tools
   the agent may use (`scope`).
4. Change the trap to your real attack: the untrusted page, document
   or tool output, and the bad steps it tells the agent to do
   (`injected_steps`).
5. Before you run it, write down what must happen and what must
   never happen — the `must_complete` and `must_not_complete`
   lists in `expected`.
6. Run it: `python -m aasef run`.

To test delegation, add a `delegation` block inside `setup` with:
`subtask`, `subagent_scope`, `subagent_steps`,
`subagent_injected_steps`, `subagent_untrusted_source`,
`delegation_result` and, when the sub-agent returns a poisoned
result, `delegation_result_compromised`. See
`scenarios/delegation-01.json` and `docs/evaluation.md`. The
sub-agent is a second agent of the same kind as the primary, runs
through its own tool boundary with the scope you grant it, and its
result comes back to the primary as an observation. Grant the
sub-agent the smallest scope its subtask needs — a broad delegated
scope is the one hole tool-side enforcement cannot close
(`delegation-03`).

## Safety rules, in plain words

- Use fake data only. Never put real files, real passwords, real
  customer data or real money in a scenario, and never point the
  tools at your real systems. The tools are safe copies with
  made-up data. Keep them that way.
- Never put an API key in a scenario file, in the code or in a
  report. Keep it in the shell values only.
- Never point the framework at production data, real credentials,
  live tools or real money. Synthetic data and sandboxed copies
  only.
- The shell tool is simulated with an allowlist. It never executes
  a real command.

## What it must never be used for

- Testing a live system, a real agent deployment, or anyone else's
  data. This is a lab tool for synthetic scenarios.
- Judging a real model from the simulated numbers. The shipped
  results measure the enforcement design; a model's own
  susceptibility needs a real-model run.
- Bypassing or weakening a real system's permissions, approval
  gates or audit logs. The framework tests defences; it does not
  provide a way around them.

## Reference

- Scenario schema and the stable interfaces: `docs/architecture.md`
- Method and scenario list: `docs/methodology.md`
- Measured results and the delegation findings: `docs/evaluation.md`
- Threat model: `docs/threat-model.md`
- Tests: `python -m pytest -q`
