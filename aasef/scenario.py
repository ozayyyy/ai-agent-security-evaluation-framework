"""Scenario schema.

A scenario is one JSON file in ``scenarios/``. It fully describes a
task, the environment it runs in, the untrusted content it contains
and the expected outcome — success criteria are defined before the
scenario runs, never inferred afterwards. This schema is the reusable
interface later projects build on: a benchmark scenario is a scenario
with extra scoring fields, a recovery scenario is a scenario with a
fault schedule.

Required fields:
  id, version, category, title, user_task, scope, setup,
  legitimate_steps, expected
Optional fields:
  description, untrusted_source, untrusted_content, injected_steps,
  preapproved (list of action keys the user approved in advance)

``expected`` has two lists of action keys (``tool:op:target``):
  must_complete     — actions a correct run completes
  must_not_complete — actions that must never complete
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .permissions import Action, Scope

CATEGORIES = (
    "direct-injection",
    "indirect-web",
    "indirect-document",
    "indirect-tool-output",
    "unauthorised-tool",
    "privilege-boundary",
    "out-of-scope-data",
    "cross-task-leak",
    "cross-session-leak",
    "approval-bypass",
    "benign",
    "delegation",
)

# Where untrusted content comes from. "user" means the instruction
# arrived in the user's own message (direct injection): it is a
# trusted principal, which is exactly why it is hard to block at the
# model level. Anything else is untrusted data, never an instruction.
UNTRUSTED_SOURCES = ("user", "web", "document", "tool-output", "none")


@dataclass
class Scenario:
    id: str
    version: str
    category: str
    title: str
    user_task: str
    scope: Scope
    setup: dict
    legitimate_steps: list
    expected: dict
    description: str = ""
    untrusted_source: str = "none"
    untrusted_content: str = ""
    injected_steps: list = field(default_factory=list)
    preapproved: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "version": self.version, "category": self.category,
            "title": self.title, "description": self.description,
            "user_task": self.user_task, "scope": self.scope.to_dict(),
            "setup": self.setup,
            "legitimate_steps": [a.to_dict() for a in self.legitimate_steps],
            "untrusted_source": self.untrusted_source,
            "untrusted_content": self.untrusted_content,
            "injected_steps": [a.to_dict() for a in self.injected_steps],
            "preapproved": list(self.preapproved),
            "expected": self.expected,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Scenario":
        category = data["category"]
        if category not in CATEGORIES:
            raise ValueError(f"unknown category {category!r} in {data.get('id')}")
        source = data.get("untrusted_source", "none")
        if source not in UNTRUSTED_SOURCES:
            raise ValueError(f"unknown untrusted_source {source!r} in {data.get('id')}")
        expected = data["expected"]
        if not isinstance(expected, dict) or "must_complete" not in expected \
                or "must_not_complete" not in expected:
            raise ValueError(f"scenario {data.get('id')} missing expected lists")
        return cls(
            id=data["id"], version=str(data.get("version", "1.0")),
            category=category, title=data.get("title", ""),
            description=data.get("description", ""),
            user_task=data["user_task"],
            scope=Scope.from_dict(data.get("scope", {})),
            setup=data.get("setup", {}),
            legitimate_steps=[Action.from_dict(a)
                              for a in data.get("legitimate_steps", [])],
            untrusted_source=source,
            untrusted_content=data.get("untrusted_content", ""),
            injected_steps=[Action.from_dict(a)
                            for a in data.get("injected_steps", [])],
            preapproved=list(data.get("preapproved", [])),
            expected=expected,
        )

    @classmethod
    def load(cls, path: Path | str) -> "Scenario":
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    @classmethod
    def load_all(cls, directory: Path | str) -> list["Scenario"]:
        scenarios = []
        for path in sorted(Path(directory).glob("*.json")):
            scenarios.append(cls.load(path))
        ids = [s.id for s in scenarios]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate scenario ids")
        return scenarios
