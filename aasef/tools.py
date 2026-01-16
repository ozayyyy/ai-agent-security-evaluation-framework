"""Sandboxed tools. All state is in-memory and synthetic.

No tool touches the real filesystem, network or shell. The file tool
works on a virtual directory tree, the web tool returns canned pages,
the key-value store is namespaced in memory, and the shell tool only
simulates a small allowlisted command set. Every call is checked
against the agent's Scope at the tool boundary before it runs.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .permissions import (Action, PolicyDecision, Scope, check_boundary,
                          PUBLIC)


@dataclass
class ToolResult:
    """Outcome of one tool call."""

    ok: bool
    output: str
    denied_reason: str = ""
    classification: str = PUBLIC

    def to_dict(self) -> dict:
        return {"ok": self.ok, "output": self.output,
                "denied_reason": self.denied_reason,
                "classification": self.classification}


@dataclass
class FileEntry:
    content: str
    classification: str = PUBLIC


# Commands the simulated shell may run, and their canned outputs.
# Anything else is refused at the boundary; nothing is ever executed.
SHELL_ALLOWLIST = {"echo", "date", "pwd", "whoami", "ls"}


class Sandbox:
    """The controlled environment: virtual files, canned web, namespaced KV."""

    def __init__(self, files: dict | None = None, pages: dict | None = None,
                 kv: dict | None = None):
        # files: path -> FileEntry (or plain string, treated as public)
        self.files: dict[str, FileEntry] = {}
        for path, entry in (files or {}).items():
            if isinstance(entry, FileEntry):
                self.files[path] = entry
            elif isinstance(entry, dict):
                self.files[path] = FileEntry(
                    content=entry.get("content", ""),
                    classification=entry.get("classification", PUBLIC))
            else:
                self.files[path] = FileEntry(content=str(entry))
        # pages: url -> body (untrusted content by definition)
        self.pages: dict[str, str] = dict(pages or {})
        # kv: key -> value; keys are namespaced, e.g. task:current:note
        self.kv: dict[str, str] = dict(kv or {})

    @classmethod
    def from_setup(cls, setup: dict) -> "Sandbox":
        return cls(files=setup.get("files", {}), pages=setup.get("pages", {}),
                   kv=setup.get("kv", {}))


class ToolSet:
    """All tools, sharing one sandbox and one scope."""

    def __init__(self, sandbox: Sandbox, scope: Scope):
        self.sandbox = sandbox
        self.scope = scope

    def call(self, action: Action) -> tuple[ToolResult, PolicyDecision]:
        """Run one action: boundary check first, tool second.

        Returns (result, decision). A denied action never reaches the
        tool implementation, so the tool cannot be tricked into
        completing it.
        """
        classification = self._classification_of(action)
        decision = check_boundary(action, self.scope, classification)
        if not decision.allowed:
            return ToolResult(False, "", denied_reason=decision.reason), decision
        handler = getattr(self, f"_do_{action.tool}", None)
        if handler is None:
            decision = PolicyDecision(False, f"no handler for {action.tool!r}",
                                      "unknown-tool")
            return ToolResult(False, "", denied_reason=decision.reason), decision
        result = handler(action)
        return result, decision

    def _classification_of(self, action: Action) -> str:
        if action.tool == "file" and action.target in self.sandbox.files:
            return self.sandbox.files[action.target].classification
        return PUBLIC

    # -- file tool -----------------------------------------------------
    def _do_file(self, action: Action) -> ToolResult:
        files = self.sandbox.files
        if action.op == "read":
            entry = files.get(action.target)
            if entry is None:
                return ToolResult(False, "", denied_reason="file not found")
            return ToolResult(True, entry.content, classification=entry.classification)
        if action.op == "list":
            names = sorted(p for p in files if p.startswith(action.target))
            return ToolResult(True, "\n".join(names))
        if action.op == "write":
            content = str(action.args.get("content", ""))
            files[action.target] = FileEntry(content=content,
                                             classification=PUBLIC)
            return ToolResult(True, f"wrote {action.target}")
        if action.op == "delete":
            if action.target not in files:
                return ToolResult(False, "", denied_reason="file not found")
            del files[action.target]
            return ToolResult(True, f"deleted {action.target}")
        return ToolResult(False, "", denied_reason=f"unknown file op {action.op!r}")

    # -- web tool ------------------------------------------------------
    def _do_web(self, action: Action) -> ToolResult:
        if action.op != "fetch":
            return ToolResult(False, "", denied_reason=f"unknown web op {action.op!r}")
        body = self.sandbox.pages.get(action.target)
        if body is None:
            return ToolResult(False, "", denied_reason="page not found")
        return ToolResult(True, body)

    # -- key-value tool ------------------------------------------------
    def _do_kv(self, action: Action) -> ToolResult:
        kv = self.sandbox.kv
        if action.op == "get":
            if action.target not in kv:
                return ToolResult(False, "", denied_reason="key not found")
            return ToolResult(True, kv[action.target])
        if action.op == "put":
            kv[action.target] = str(action.args.get("value", ""))
            return ToolResult(True, f"stored {action.target}")
        if action.op == "delete":
            if action.target not in kv:
                return ToolResult(False, "", denied_reason="key not found")
            del kv[action.target]
            return ToolResult(True, f"deleted {action.target}")
        return ToolResult(False, "", denied_reason=f"unknown kv op {action.op!r}")

    # -- shell tool (simulated, never executes) ------------------------
    def _do_shell(self, action: Action) -> ToolResult:
        if action.op != "run":
            return ToolResult(False, "", denied_reason=f"unknown shell op {action.op!r}")
        command = str(action.args.get("command", "")).strip()
        name = command.split()[0] if command.split() else ""
        if name not in SHELL_ALLOWLIST:
            return ToolResult(False, "",
                              denied_reason=f"command {name!r} not allowlisted")
        if name == "echo":
            return ToolResult(True, command[len("echo"):].strip())
        if name == "date":
            return ToolResult(True, "2026-11-24")
        if name == "pwd":
            return ToolResult(True, "/workspace")
        if name == "whoami":
            return ToolResult(True, "agent")
        if name == "ls":
            return ToolResult(True, "\n".join(sorted(self.sandbox.files)))
        return ToolResult(False, "", denied_reason="unhandled command")
