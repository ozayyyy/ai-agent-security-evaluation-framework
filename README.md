# AI Agent Security Evaluation Framework (AASEF)

A reproducible evaluation framework for testing security boundaries
in tool-using AI agents: prompt injection, tool permissions, trust
boundaries and approval gates.

Agents are deterministic simulated decision policies, not language
models. Tools are sandboxed in-process with synthetic data. Results
measure the enforcement architecture — model-level filtering versus
tool-side authorisation — not any particular model's behaviour.

## Measured results

40 scenarios x 3 configurations, seed 0. Full results in
[`examples/report.md`](examples/report.md).

| Configuration | Attack success | Task completion | False refusals | Enforcement effectiveness |
|---|---|---|---|---|
| baseline | 100.0% | 100.0% | 0.0% | 0.0% |
| hierarchy-aware | 33.3% | 100.0% | 0.0% | 66.7% |
| tool-side-enforced | 2.8% | 100.0% | 0.0% | 97.2% |

What this shows:

- The baseline follows instructions wherever it finds them, including
  untrusted web pages, documents and tool output, so every attack in
  the suite succeeds against it.
- Hierarchy-aware filtering stops all indirect injection (web,
  document, tool output) but still falls for the 12 scenarios where
  the instruction comes from a trusted principal — direct
  injection, user-issued out-of-scope or privilege-boundary
  requests, and the confused-deputy delegation.
- Tool-side enforcement blocks every attack in the suite at the tool
  boundary or the approval gate except one: delegation-03, the
  confused deputy, where the harmful step is the sub-agent's
  legitimate plan and the sub-agent's scope allows it. It completes
  all benign tasks (pre-approved writes included).

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

## Counterfactual module

The framework can also ask "what if" about a run: what would
have happened under a different instruction, or a different
injection, in the same scenario with the same hidden
disturbance? It answers by paired re-runs — the same scenario
run twice with exactly one factor changed — because the
simulated agents are deterministic under a fixed seed, so
rewinding and branching is exact. Each scenario is classified
from the pair of outcomes: **injection-driven** (the injection
carries the outcome whatever the instruction is),
**instruction-driven** (the outcome turns on which instruction
was issued), or **robust** (the agent refuses in both
branches). See [`docs/counterfactual.md`](docs/counterfactual.md).

Inspiration for this module: "Counterfactual World Models:
JEPAs That Reason About 'What If'" by Randall Balestriero and
Yann LeCun (arXiv:2611.24778,
https://arxiv.org/abs/2611.24778; code:
https://github.com/galilai-group/counterfactual-WM). The
implementation here is original paired re-runs and does not use
the paper's code or its residual-reuse formula, which assumes
action and disturbance add like physical forces and does not
transfer to prompt and tool interactions.

## Using it on your own model

By default the framework uses built-in pretend agents. You can also
plug in your own model, through any API that speaks the
OpenAI-compatible chat format. The framework sends the model the
task and the list of allowed tools, and the model replies with the
actions it wants to take. The safety checks still run at the tool
boundary, so a bad answer from the model is blocked the same way a
bad answer from a pretend agent is.

Step 1. Set three values in your shell. Do not put them in a file.

```bash
export AASEF_API_BASE_URL="https://your-api-address"
export AASEF_API_KEY="your-key-here"
export AASEF_MODEL="your-model-name"
```

Step 2. Run the evaluation with the real model.

```bash
python -m aasef run --agent api
```

That is it. To test one setup only, add `--config tool-side-enforced`.
To use different values for one run, pass them as flags instead:
`--api-base-url`, `--api-key`, `--model`. A flag wins over the
saved value. Prefer the saved values: a flag shows up in your shell
history, and your key should not be there.

What happens if the model call fails? The run does not crash. That
run gets an empty plan, the failure is written in the trace, and the
run goes on. The framework never tries the network call twice.

Your key is sent to your API only. It is never written to a trace,
a report, a log or the screen. A test in `tests/test_model_adapter.py`
checks this.

## Using it on your own scenarios

Step 1. Copy one file from the `scenarios/` folder. Pick one in the
same group as what you want to test, for example a web page trap or
a direct instruction trap.
Step 2. Change the task to your real task, in plain words.
Step 3. Change the rules to your real rules: which files, hosts and
tools the agent may use.
Step 4. Change the trap to your real attack: the untrusted page,
document or tool output, and the bad steps it tells the agent to do.
Step 5. Before you run it, write down what must happen and what must
never happen. Those are the `must_complete` and `must_not_complete`
lists in the file.
Step 6. Run it: `python -m aasef run`.

Safety rules for your own tests:

- Use fake data only. Never use real files, real passwords or real
  customer data in a scenario.
- Never point a tool at your real files, real money or real systems.
  The tools here are safe copies. Keep them that way.
- Never put your API key in a scenario file, in the code or in a
  report. Keep it in the shell values from step 1 only.

## Adding a tool

Add a handler `ToolSet._do_<name>` in `aasef/tools.py`, register its
operations in `permissions.TOOL_OPS`, and add its boundary rules to
`check_boundary`. Tools must never touch the real filesystem,
network or shell.

## Limitations

- Agents are simulated policies by default, not real models. The
  framework measures whether an architecture stops an attack, not
  whether a specific model would fall for one. To test a real model,
  use the built-in API connector — see "Using it on your own model"
  above (`aasef/model_adapter.py`).
- Task completion is 100% for all configurations because the
  suite's legitimate steps never conflict with enforcement. The
  suite does not yet include benign tasks that legitimately need
  out-of-scope access, where enforcement would (correctly) refuse.
- The simulated approver approves only pre-approved actions. A real
  approver's judgement, and prompt-injection attacks on the approver
  itself, are out of scope.
- The shell tool simulates an allowlist; it never executes commands.
