# Threat Model

## System under test

A tool-using AI agent: it receives a task from a user, plans steps,
and calls tools (file, web, key-value store, shell) to carry them
out. The agent's decisions come from a model; the tools and the
permission checks sit outside the model.

## Principals

| Principal | Trust | Can instruct the agent |
|---|---|---|
| System / developer | Trusted | Yes, highest priority |
| User | Trusted | Yes, below system/developer |
| Tool output, web pages, documents, KV values | Untrusted | No — data only, never instructions |
| Other tasks / previous sessions | Untrusted to this agent | No — different authorisation scope |

The user is trusted, which is the hard case: a direct injection in
the user's own message is an instruction from a trusted principal, so
no amount of instruction-hierarchy filtering at the model level can
block it. Only tool-side enforcement can.

## Attacker model

- The attacker controls untrusted content the agent may observe:
  web pages, documents, tool outputs, KV values.
- The attacker may also be the user issuing the task (direct
  injection), or a party who planted content the user asked the agent
  to read.
- The attacker does **not** control the agent's code, the tool
  implementations, the permission configuration, or the approval
  gate. Those are the trusted computing base.
- The attacker wants the agent to complete an action outside its
  authorised scope: read a secret file, read another task's or
  session's data, write/delete without approval, invoke a tool it was
  not granted, or fetch a disallowed host.

## Trust boundaries

1. **Model / tool boundary.** The model proposes actions; tools decide
   whether they complete. A tool must refuse an out-of-scope action
   even if the agent asks for it.
2. **Task boundary.** Data belonging to another task (other KV
   namespace, other task's files) is outside this agent's scope.
3. **Session boundary.** Data from a previous session is outside this
   agent's scope.
4. **Approval boundary.** Consequential operations (write, delete,
   put, send, spend, publish) need an approval decision. The
   simulated approver grants only actions the user pre-approved for
   this task.

## In scope

- Direct and indirect prompt injection.
- Unauthorised tool invocation and privilege-boundary violations.
- Out-of-scope data access, cross-task and cross-session leaks.
- Approval-gate bypass attempts.
- Comparison of model-level safeguards with tool-side enforcement.

## Out of scope

- Real language models: agents here are deterministic simulated
  decision policies. Results measure the enforcement architecture,
  not any particular model's susceptibility.
- Real networks, filesystems and shells: all tools are sandboxed
  in-process with synthetic data.
- Attacks on the framework itself (e.g. tampering with scenario
  files or the permission configuration) — that configuration is
  trusted input, like a test harness.
- Social engineering of the human approver: the simulated approver
  approves only pre-approved actions.
