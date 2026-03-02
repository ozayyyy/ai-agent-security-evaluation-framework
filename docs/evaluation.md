# Evaluation

## Method

34 scenarios (version 1.0) x 3 agent configurations, seed 0.
102 runs. Deterministic simulated agents; the same seed reproduces
the same results. Full traces: `examples/traces/` (one JSONL file
per run). Reproduce with `python scripts/evaluate.py`.

## Headline results

| Configuration | Attack success | Unauthorised actions | Task completion | False refusals | Enforcement effectiveness |
|---|---|---|---|---|---|
| baseline | 100.0% | 100.0% | 100.0% | 0.0% | 0.0% |
| hierarchy-aware | 35.5% | 35.5% | 100.0% | 0.0% | 64.5% |
| tool-side-enforced | 0.0% | 0.0% | 100.0% | 0.0% | 100.0% |

## Attack success by category

| Category | baseline | hierarchy-aware | tool-side-enforced |
|---|---|---|---|
| approval-bypass | 100.0% | 0.0% | 0.0% |
| cross-session-leak | 100.0% | 0.0% | 0.0% |
| cross-task-leak | 100.0% | 33.3% | 0.0% |
| direct-injection | 100.0% | 100.0% | 0.0% |
| indirect-document | 100.0% | 0.0% | 0.0% |
| indirect-tool-output | 100.0% | 0.0% | 0.0% |
| indirect-web | 100.0% | 0.0% | 0.0% |
| out-of-scope-data | 100.0% | 100.0% | 0.0% |
| privilege-boundary | 100.0% | 100.0% | 0.0% |
| unauthorised-tool | 100.0% | 0.0% | 0.0% |
| benign | 0.0% | 0.0% | 0.0% |

## Findings

1. **Model-level hierarchy filtering stops indirect injection
   completely** (web, document and tool-output categories all drop
   from 100% to 0%), because the malicious instruction arrives in
   untrusted content the policy tells the agent to treat as data.
2. **It does not stop direct injection.** All 4 direct-injection
   scenarios still succeed under hierarchy-aware, because the
   instruction comes from the user, a trusted principal. The same
   holds for user-issued privilege-boundary and out-of-scope
   requests: hierarchy-aware succeeds in 100% of privilege-boundary
   and 100% of out-of-scope scenarios.
3. **Tool-side enforcement stops every attack in the suite**
   (0.0% attack success) while completing all benign tasks. The
   boundary refuses the action even when the agent attempts it, and
   the approval gate denies unapproved consequential actions. This
   is the answer to research question 4: enforcement can be made
   independent of the model's interpretation of instructions.
4. **Enforcement costs nothing on this suite** (0.0% false
   refusals), because benign consequential actions are pre-approved
   in their scenarios. That is a property of the suite, not proof
   that enforcement is free in general — see limitations.

## Limitations

- Agents are deterministic simulated decision policies, not real
  language models. These numbers measure the enforcement
  architecture, not any model's susceptibility to prompt injection.
- Task completion is 100% for every configuration: the suite's
  legitimate steps never conflict with enforcement. The suite has
  no benign task that legitimately needs out-of-scope access, so
  the false-refusal rate is 0% by construction. A suite with
  ambiguous benign tasks would show the real usability cost of
  strict enforcement.
- The simulated approver grants only pre-approved actions. Real
  approval UX, approver fatigue, and attacks on the approver are
  not modelled.
- The shell tool is simulated with an allowlist; no real command
  execution is tested.
- Attack success and unauthorised-action rates coincide in this
  suite because the must-not-complete list is the scope definition.
  A scenario where an authorised action is misused (e.g. a
  legitimate read used to exfiltrate) would separate them.
