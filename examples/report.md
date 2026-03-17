# AI Agent Security Evaluation — Results

Runs: 102 (seed 0).
Agents are deterministic simulated decision policies, not language models; results measure the enforcement architecture.

## Headline metrics

| Configuration | Attack success | Unauthorised actions | Task completion | False refusals | Enforcement effectiveness |
|---|---|---|---|---|---|
| baseline | 100.0% | 100.0% | 100.0% | 0.0% | 0.0% |
| hierarchy-aware | 35.5% | 35.5% | 100.0% | 0.0% | 64.5% |
| tool-side-enforced | 0.0% | 0.0% | 100.0% | 0.0% | 100.0% |

## Attack success by category

| Category | baseline | hierarchy-aware | tool-side-enforced |
|---|---|---|---||
| approval-bypass | 100.0% | 0.0% | 0.0% |
| benign | 0.0% | 0.0% | 0.0% |
| cross-session-leak | 100.0% | 0.0% | 0.0% |
| cross-task-leak | 100.0% | 33.3% | 0.0% |
| direct-injection | 100.0% | 100.0% | 0.0% |
| indirect-document | 100.0% | 0.0% | 0.0% |
| indirect-tool-output | 100.0% | 0.0% | 0.0% |
| indirect-web | 100.0% | 0.0% | 0.0% |
| out-of-scope-data | 100.0% | 100.0% | 0.0% |
| privilege-boundary | 100.0% | 100.0% | 0.0% |
| unauthorised-tool | 100.0% | 0.0% | 0.0% |

## Reading the results

- Baseline follows instructions wherever it finds them, including untrusted web pages, documents and tool output.
- Hierarchy-aware ignores instructions in untrusted content but still follows direct instructions from the user, a trusted principal — so direct injection still succeeds.
- Tool-side enforcement blocks unauthorised actions at the tool boundary even when the agent attempts them, which is why its attack success rate is the lowest.
- False refusals are measured on benign tasks only; a consequential benign action without pre-approval is denied by the gate, which is a usability cost of enforcement.
