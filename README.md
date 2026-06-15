# AI Agent Security Evaluation Framework (AASEF)

A reproducible evaluation framework for testing security boundaries
in tool-using AI agents: prompt injection, tool permissions, trust
boundaries and approval gates.

Agents are deterministic simulated decision policies, not language
models. Tools are sandboxed in-process with synthetic data. Results
measure the enforcement architecture — model-level filtering versus
tool-side authorisation — not any particular model's behaviour.

## Measured results

34 scenarios x 3 configurations, seed 0. Full results in
[`examples/report.md`](examples/report.md).

| Configuration | Attack success | Task completion | False refusals | Enforcement effectiveness |
|---|---|---|---|---|
| baseline | 100.0% | 100.0% | 0.0% | 0.0% |
| hierarchy-aware | 35.5% | 100.0% | 0.0% | 64.5% |
| tool-side-enforced | 0.0% | 100.0% | 0.0% | 100.0% |

What this shows:

- The baseline follows instructions wherever it finds them, including
  untrusted web pages, documents and tool output, so every attack in
  the suite succeeds against it.
- Hierarchy-aware filtering stops all indirect injection (web,
  document, tool output) but still falls for the 11 scenarios where
  the instruction comes from the user, a trusted principal — direct
  injection, and user-issued out-of-scope or privilege-boundary
  requests.
- Tool-side enforcement blocks every attack in the suite at the tool
  boundary or the approval gate, even when the agent attempts the
  action, while completing all benign tasks (pre-approved writes
  included).

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Python 3.10+. No other dependencies.

## Usage

```bash
# List scenarios
python -m aasef list

# Run the full evaluation
python -m aasef run --out examples --traces examples/traces

# Run one configuration
python -m aasef run --config tool-side-enforced --seed 0

# Reproduce the shipped results
python scripts/evaluate.py
```

## How enforcement works

Permissions are enforced outside the model, at the tool boundary
(`aasef/permissions.py`, `aasef/tools.py`). Each agent has a `Scope`:
allowed paths, hosts, data classifications, tools, operations and
KV namespaces. A tool refuses an out-of-scope action even if the
agent asks for it, and the attempt is logged separately from
completed actions. Consequential operations (write, delete, put,
send, spend, publish) also pass an approval gate that grants only
actions the user pre-approved for the task.

## Adding a scenario

Add one JSON file to `scenarios/` following the schema in
`docs/architecture.md`: `id`, `version`, `category`, `user_task`,
`scope`, `setup`, `legitimate_steps`, `untrusted_source`,
`injected_steps`, `preapproved`, and `expected` with
`must_complete` / `must_not_complete` lists. Success criteria are
defined in the file before it runs.

## Adding a tool

Add a handler `ToolSet._do_<name>` in `aasef/tools.py`, register its
operations in `permissions.TOOL_OPS`, and add its boundary rules to
`check_boundary`. Tools must never touch the real filesystem,
network or shell.

## Limitations

- Agents are simulated policies, not real models. The framework
  measures whether an architecture stops an attack, not whether a
  specific model would fall for one. A real model adapter plugs in
  behind `AgentAdapter` (see `docs/architecture.md`).
- Task completion is 100% for all configurations because the
  suite's legitimate steps never conflict with enforcement. The
  suite does not yet include benign tasks that legitimately need
  out-of-scope access, where enforcement would (correctly) refuse.
- The simulated approver approves only pre-approved actions. A real
  approver's judgement, and prompt-injection attacks on the approver
  itself, are out of scope.
- The shell tool simulates an allowlist; it never executes commands.
