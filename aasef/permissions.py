"""Permission model for the AI Agent Security Evaluation Framework.

Permissions are enforced outside the model, at the tool / resource
boundary. An agent may *attempt* any action; the boundary decides
whether it completes. This module is the reusable permission model
later projects build on: a Scope describes what one agent is allowed
to do, and a PolicyDecision records every allow / deny.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Data classifications, least to most sensitive.
PUBLIC = "public"
INTERNAL = "internal"
SECRET = "secret"
CLASSIFICATIONS = (PUBLIC, INTERNAL, SECRET)

# Operations that have effects outside the agent's own working state.
# These always require an approval decision when gates are on.
CONSEQUENTIAL_OPS = {"write", "delete", "send", "spend", "publish", "put"}

# Tool capabilities: which operations each tool offers at all.
TOOL_OPS = {
    "file": {"read", "write", "delete", "list"},
    "web": {"fetch"},
    "kv": {"get", "put", "delete"},
    "shell": {"run"},
}


@dataclass(frozen=True)
class Action:
    """One attempted tool call. Plain data, JSON-serialisable."""

    tool: str
    op: str
    target: str
    args: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"tool": self.tool, "op": self.op, "target": self.target,
                "args": dict(self.args)}

    @classmethod
    def from_dict(cls, data: dict) -> "Action":
        return cls(tool=data["tool"], op=data["op"], target=data["target"],
                   args=dict(data.get("args", {})))

    def key(self) -> str:
        """Stable identity used when matching actions against expectations."""
        return f"{self.tool}:{self.op}:{self.target}"


@dataclass
class Scope:
    """What a single agent is authorised to do.

    allowed_paths: path prefixes the file tool may touch.
    allowed_hosts: hosts the web tool may fetch.
    allowed_classifications: data classifications the agent may read.
    allowed_tools: tools the agent may invoke at all.
    allowed_ops: per-tool operations, defaults to everything the tool offers.
    kv_namespaces: key namespaces (e.g. "task:current") the agent may use.
    """

    allowed_paths: tuple = ("/workspace/",)
    allowed_hosts: tuple = ("example.internal",)
    allowed_classifications: tuple = (PUBLIC, INTERNAL)
    allowed_tools: tuple = ("file", "web", "kv", "shell")
    allowed_ops: dict = field(default_factory=dict)
    kv_namespaces: tuple = ("task:current",)

    def ops_for(self, tool: str) -> set:
        if tool in self.allowed_ops:
            return set(self.allowed_ops[tool])
        return set(TOOL_OPS.get(tool, set()))

    def to_dict(self) -> dict:
        return {
            "allowed_paths": list(self.allowed_paths),
            "allowed_hosts": list(self.allowed_hosts),
            "allowed_classifications": list(self.allowed_classifications),
            "allowed_tools": list(self.allowed_tools),
            "allowed_ops": {k: sorted(v) for k, v in self.allowed_ops.items()},
            "kv_namespaces": list(self.kv_namespaces),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Scope":
        return cls(
            allowed_paths=tuple(data.get("allowed_paths", ["/workspace/"])),
            allowed_hosts=tuple(data.get("allowed_hosts", ["example.internal"])),
            allowed_classifications=tuple(
                data.get("allowed_classifications", [PUBLIC, INTERNAL])),
            allowed_tools=tuple(data.get("allowed_tools", list(TOOL_OPS))),
            allowed_ops={k: set(v) for k, v in data.get("allowed_ops", {}).items()},
            kv_namespaces=tuple(data.get("kv_namespaces", ["task:current"])),
        )


@dataclass
class PolicyDecision:
    """Outcome of one boundary check. Logged for every attempted action."""

    allowed: bool
    reason: str
    rule: str

    def to_dict(self) -> dict:
        return {"allowed": self.allowed, "reason": self.reason, "rule": self.rule}


def check_boundary(action: Action, scope: Scope,
                   classification: str = PUBLIC) -> PolicyDecision:
    """Decide whether an action may complete, at the tool boundary.

    Order matters: unknown tool, then capability, then operation,
    then target scope, then data classification. The first failing
    rule wins and is recorded, so a denial is always explainable.
    """
    if action.tool not in TOOL_OPS:
        return PolicyDecision(False, f"unknown tool {action.tool!r}", "unknown-tool")
    if action.tool not in scope.allowed_tools:
        return PolicyDecision(False,
                              f"tool {action.tool!r} not in agent capability list",
                              "tool-not-allowed")
    if action.op not in scope.ops_for(action.tool):
        return PolicyDecision(False,
                              f"operation {action.op!r} not allowed on {action.tool!r}",
                              "op-not-allowed")
    if action.tool == "file":
        if not any(action.target.startswith(p) for p in scope.allowed_paths):
            return PolicyDecision(False,
                                  f"path {action.target!r} outside allowed paths",
                                  "path-out-of-scope")
        if classification not in scope.allowed_classifications:
            return PolicyDecision(False,
                                  f"classification {classification!r} not allowed",
                                  "classification-out-of-scope")
    if action.tool == "web":
        host = action.target.split("/")[0]
        if host not in scope.allowed_hosts:
            return PolicyDecision(False, f"host {host!r} not allowed", "host-out-of-scope")
    if action.tool == "kv":
        # Namespace is the first two segments, e.g. "task:current".
        parts = action.target.split(":")
        ns = ":".join(parts[:2]) if len(parts) >= 2 else action.target
        if ns not in scope.kv_namespaces:
            return PolicyDecision(False,
                                  f"key namespace {ns!r} not allowed",
                                  "namespace-out-of-scope")
    if action.tool == "shell":
        if action.op != "run":
            return PolicyDecision(False, "shell only supports run", "op-not-allowed")
    return PolicyDecision(True, "allowed by scope", "allow")


class ApprovalGate:
    """Confirmation gate for consequential operations.

    The simulated approver approves only actions the user explicitly
    pre-approved for this task (the scenario's ``preapproved`` list).
    Everything else is denied, and the request and the decision are
    both recorded. Mode "auto" grants everything (the baseline
    configuration: the model decides for itself).
    """

    def __init__(self, mode: str = "gate", preapproved: tuple = ()):
        if mode not in ("auto", "gate"):
            raise ValueError(f"unknown approval mode {mode!r}")
        self.mode = mode
        self.preapproved = {a.key() if isinstance(a, Action) else a
                            for a in preapproved}

    def request(self, action: Action) -> PolicyDecision:
        if action.op not in CONSEQUENTIAL_OPS:
            return PolicyDecision(True, "not consequential, no approval needed",
                                  "not-consequential")
        if self.mode == "auto":
            return PolicyDecision(True, "auto-approved (no gate)", "auto-approve")
        if action.key() in self.preapproved:
            return PolicyDecision(True, "pre-approved by user for this task",
                                  "pre-approved")
        return PolicyDecision(False,
                              "consequential action without user approval",
                              "approval-denied")
