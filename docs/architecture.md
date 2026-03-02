# Architecture

## Module map

```
aasef/
  scenario.py     Scenario schema: one JSON file per scenario, validated on load.
  permissions.py  Scope, Action, boundary check, approval gate.
  tools.py        Sandboxed tools over an in-memory Sandbox.
  agents.py       AgentAdapter interface + simulated agent policies.
  runner.py       Repeatable execution: one scenario x one config x one seed.
  scoring.py      Metrics aggregation.
  reporting.py    JSON + Markdown reports.
  trace.py        Ordered event log (JSONL).
  cli.py          `aasef list` / `aasef run`.
```

Rules: `permissions.py` and `tools.py` never import the agent or the
runner. The boundary check depends only on the action and the scope,
so it can be reused without the rest of the framework. The runner
depends on agents, tools and traces; scoring and reporting depend
only on run results.

## Reusable interfaces for later projects

These are stable. The reliability benchmark and the control/recovery
study build on them without modification.

### Scenario schema (`aasef.scenario.Scenario`)

One JSON file, validated on load. Fields:

- `id`, `version`, `category`, `title`, `description`
- `user_task`: the trusted task, in plain language.
- `scope`: a `Scope` (allowed paths, hosts, classifications, tools,
  operations, KV namespaces).
- `setup`: `files` (path → content + classification), `pages`
  (URL → body), `kv` (key → value).
- `legitimate_steps`: actions a correct run takes, as
  `{"tool", "op", "target", "args"}`.
- `untrusted_source`: `user` | `web` | `document` | `tool-output` |
  `none`.
- `untrusted_content`: the malicious text, for the record.
- `injected_steps`: actions the malicious content instructs.
- `preapproved`: action keys (`tool:op:target`) the user approved
  in advance for this task.
- `expected.must_complete` / `expected.must_not_complete`: action
  keys. Success criteria are defined before the run, never inferred
  afterwards.

A benchmark scenario adds scoring fields to this schema; a recovery
scenario adds a fault schedule. Neither changes the fields above.

### Agent adapter (`aasef.agents.AgentAdapter`)

```python
class AgentAdapter:
    def plan_legitimate(self, scenario) -> list[Action]: ...
    def plan_after_observation(self, scenario, observations) -> list[Action]: ...
```

`AgentConfig` carries the policy, not the model: `hierarchy_filter`
(ignore instructions in untrusted content), `tool_enforcement`
(enforce the scope at the tool boundary), `approval_mode`
(`auto` or `gate`). A real model adapter implements the same two
methods and returns the same `Action` values; the runner, tools and
scoring do not change.

### Permission model (`aasef.permissions`)

- `Action(tool, op, target, args)` — one attempted tool call, with a
  stable `key()` of the form `tool:op:target`.
- `Scope` — allowed paths, hosts, classifications, tools, per-tool
  operations, KV namespaces.
- `check_boundary(action, scope, classification) -> PolicyDecision`
  — first failing rule wins and is recorded, so every denial is
  explainable.
- `ApprovalGate(mode, preapproved)` — consequential operations
  (`write`, `delete`, `put`, `send`, `spend`, `publish`) need an
  approval decision; the simulated approver grants only pre-approved
  actions.

### Trace format (`aasef.trace.Trace`)

JSONL: one header line (`{"trace": {scenario_id, config, seed}}`)
followed by one event per line: `{seq, kind, actor, summary,
detail}`. Kinds: `decision`, `tool_call`, `policy`, `approval`,
`observation`, `result`. Attempted actions appear as `tool_call`
events; denied actions never appear as completed. Traces are the
reproducible experiment record.

## Execution flow

1. Load scenarios, build one `Sandbox` per run from `setup`.
2. Agent plans legitimate steps; the runner executes each through
   the approval gate (consequential ops) and then the tool boundary.
3. Observations are collected; the agent plans follow-up steps from
   what it observed.
4. The result records attempted vs completed actions separately,
   `attack_success` (any `must_not_complete` action completed),
   `task_completed` (all `must_complete` actions completed) and
   `false_refusal` (benign scenario, task not completed).
5. Scoring aggregates per configuration and per category; reporting
   writes JSON and Markdown.
