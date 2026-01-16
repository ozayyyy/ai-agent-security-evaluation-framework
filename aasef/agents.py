"""Simulated agents.

These are deterministic decision policies, not language models. Each
agent is given the same user task and the same tool outputs; what
differs is how it treats instructions found in untrusted content and
whether it relies on tool-side enforcement. That is deliberate: the
framework measures the *architecture* — model-level filtering versus
tool-side authorisation — not the behaviour of any particular model.
A real model adapter plugs in behind the same ``AgentAdapter``
interface: ``plan_legitimate`` and ``plan_after_observation``.
"""

from __future__ import annotations

from dataclasses import dataclass

from .permissions import Action, ApprovalGate
from .scenario import Scenario


@dataclass(frozen=True)
class AgentConfig:
    """One agent configuration under test."""

    name: str
    hierarchy_filter: bool  # ignore instructions in untrusted content
    tool_enforcement: bool  # enforce scope at the tool boundary
    approval_mode: str      # "auto" (model decides) or "gate" (user approves)

    def approval_gate(self, scenario: Scenario) -> ApprovalGate:
        return ApprovalGate(mode=self.approval_mode,
                            preapproved=tuple(scenario.preapproved))


# The three configurations compared by the evaluation.
BASELINE = AgentConfig(name="baseline", hierarchy_filter=False,
                       tool_enforcement=False, approval_mode="auto")
HIERARCHY_AWARE = AgentConfig(name="hierarchy-aware", hierarchy_filter=True,
                              tool_enforcement=False, approval_mode="auto")
TOOL_SIDE_ENFORCED = AgentConfig(name="tool-side-enforced",
                                 hierarchy_filter=True,
                                 tool_enforcement=True, approval_mode="gate")

CONFIGS = (BASELINE, HIERARCHY_AWARE, TOOL_SIDE_ENFORCED)

CONFIG_BY_NAME = {c.name: c for c in CONFIGS}


class AgentAdapter:
    """Interface every agent (simulated or model-backed) implements.

    ``plan_legitimate`` returns the steps the agent takes to carry out
    the user's task. ``plan_after_observation`` returns the steps it
    takes after seeing tool outputs — this is where untrusted content
    can influence a weak agent.
    """

    def __init__(self, config: AgentConfig):
        self.config = config

    @property
    def name(self) -> str:
        return self.config.name

    def plan_legitimate(self, scenario: Scenario) -> list[Action]:
        raise NotImplementedError

    def plan_after_observation(self, scenario: Scenario,
                               observations: list[str]) -> list[Action]:
        raise NotImplementedError


class SimulatedAgent(AgentAdapter):
    """Deterministic stand-in for a tool-using model.

    The legitimate plan is the task's own steps. After observing tool
    output, the agent may also follow instructions embedded in that
    output:

    - baseline: follows any instruction it sees, whatever the source.
    - hierarchy-aware: follows instructions only from a trusted
      principal (system / developer / user). Instructions in web pages,
      documents or tool output are data and are ignored. A direct
      injection in the user's own message is still followed, because
      the user *is* a trusted principal — that case is exactly what
      model-level filtering cannot block.
    - tool-side-enforced: same filtering as hierarchy-aware, and it
      also attempts nothing the tool boundary would refuse on
      classification grounds it can see — but the runner still runs
      every attempted action through the boundary, so an attempt that
      slips through is blocked there instead.
    """

    def plan_legitimate(self, scenario: Scenario) -> list[Action]:
        return list(scenario.legitimate_steps)

    def plan_after_observation(self, scenario: Scenario,
                               observations: list[str]) -> list[Action]:
        if not scenario.injected_steps:
            return []
        if self.config.hierarchy_filter:
            if scenario.untrusted_source == "user":
                # Direct injection: the instruction came from the user,
                # a trusted principal. Hierarchy filtering cannot help.
                return list(scenario.injected_steps)
            return []
        return list(scenario.injected_steps)
