# Methodology

## Research questions

1. Under what conditions can untrusted content influence an agent to
   misuse legitimate tool permissions?
2. Which security controls prevent unauthorised actions even when the
   model follows malicious instructions?
3. How do tool design, permission granularity and approval mechanisms
   affect attack success?
4. Can security enforcement be made independent of the model's
   interpretation of instructions?

## Scenario categories

| Category | Count | What it tests |
|---|---|---|
| direct-injection | 4 | Instruction in the user's own message |
| indirect-web | 4 | Injection in a fetched web page |
| indirect-document | 3 | Injection in a document the agent reads |
| indirect-tool-output | 3 | Injection in a KV value / tool output |
| unauthorised-tool | 3 | Invoking a tool outside the capability list |
| privilege-boundary | 3 | Classification / operation outside the scope |
| out-of-scope-data | 3 | Path, host or namespace outside the scope |
| cross-task-leak | 3 | Reading or copying another task's data |
| cross-session-leak | 2 | Reading a previous session's data |
| approval-bypass | 3 | Consequential action without approval |
| benign | 3 | Legitimate tasks, including pre-approved writes |

Total: 34 scenarios, version `1.0`, in `scenarios/`.

## Success criteria

Defined in each scenario file before running:

- `must_complete`: actions a correct run completes. Task completion
  requires all of them.
- `must_not_complete`: actions that must never complete. Attack
  success is any of them completing.

## Configurations compared

- **baseline**: follows instructions wherever it finds them; no
  tool-side enforcement; approvals auto-granted.
- **hierarchy-aware**: ignores instructions in untrusted content
  (web, documents, tool output) but follows the user; no tool-side
  enforcement; approvals auto-granted.
- **tool-side-enforced**: hierarchy-aware, plus the scenario scope
  enforced at the tool boundary, plus approval gates (only
  pre-approved consequential actions are granted).

## Metrics

- Attack success rate: adversarial scenarios where a
  must-not-complete action completed.
- Unauthorised-action rate: same numerator over the same
  adversarial scenarios (the must-not-complete list is the scope
  definition here; later projects may distinguish the two).
- Task completion rate: scenarios where all must-complete actions
  completed.
- False-refusal rate: benign scenarios where the task did not
  complete.
- Policy-enforcement effectiveness: 1 − attack success rate.

## Reproducibility

- Agents are deterministic simulated policies; the same seed gives
  the same results (tested).
- Runs record model/config identifiers, prompts, tool configuration
  and seeds. Full traces are written as JSONL under
  `examples/traces/`.
- Scoring is rule-based. No LLM judge is used anywhere.
