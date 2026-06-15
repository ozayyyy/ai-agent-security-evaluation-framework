"""AI Agent Security Evaluation Framework (AASEF).

Reproducible evaluation of security boundaries in tool-using AI
agents: prompt injection, tool permissions, trust boundaries and
approval gates. Agents are deterministic simulated decision policies;
tools are sandboxed in-process with synthetic data.
"""

from .agents import BASELINE, CONFIGS, HIERARCHY_AWARE, TOOL_SIDE_ENFORCED
from .model_adapter import ApiModelAdapter
from .permissions import Action, ApprovalGate, Scope
from .runner import run_all, run_scenario
from .scenario import Scenario
from .trace import Trace

__version__ = "0.1.0"

__all__ = [
    "Action", "ApprovalGate", "Scope", "Scenario", "Trace",
    "BASELINE", "HIERARCHY_AWARE", "TOOL_SIDE_ENFORCED", "CONFIGS",
    "ApiModelAdapter", "run_scenario", "run_all",
]
