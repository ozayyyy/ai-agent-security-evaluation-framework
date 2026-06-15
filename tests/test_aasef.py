"""Unit and integration tests for AASEF."""

from pathlib import Path

import pytest

from aasef.agents import (BASELINE, CONFIGS, HIERARCHY_AWARE,
                          TOOL_SIDE_ENFORCED, SimulatedAgent)
from aasef.permissions import (Action, ApprovalGate, Scope, check_boundary)
from aasef.reporting import build_report, render_markdown
from aasef.runner import run_all, run_scenario
from aasef.scenario import Scenario
from aasef.scoring import score
from aasef.tools import Sandbox, ToolSet
from aasef.trace import Trace

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "scenarios"


def load(scenario_id):
    return Scenario.load(SCENARIOS / f"{scenario_id}.json")


def all_scenarios():
    return Scenario.load_all(SCENARIOS)


# --- permission boundary -------------------------------------------------

def test_boundary_allows_in_scope_read():
    scope = Scope()
    decision = check_boundary(Action("file", "read", "/workspace/notes.txt"), scope)
    assert decision.allowed


def test_boundary_denies_path_outside_scope():
    scope = Scope()
    decision = check_boundary(Action("file", "read", "/etc/secret.key"), scope)
    assert not decision.allowed
    assert decision.rule == "path-out-of-scope"


def test_boundary_denies_secret_classification():
    scope = Scope()
    decision = check_boundary(Action("file", "read", "/workspace/vault.key"),
                              scope, classification="secret")
    assert not decision.allowed
    assert decision.rule == "classification-out-of-scope"


def test_boundary_denies_disallowed_host():
    scope = Scope()
    decision = check_boundary(Action("web", "fetch", "attacker.example.com/"), scope)
    assert not decision.allowed
    assert decision.rule == "host-out-of-scope"


def test_boundary_denies_other_task_namespace():
    scope = Scope()
    decision = check_boundary(Action("kv", "get", "task:other:api-key"), scope)
    assert not decision.allowed
    assert decision.rule == "namespace-out-of-scope"


def test_boundary_denies_tool_not_in_capability_list():
    scope = Scope(allowed_tools=("file", "web"))
    decision = check_boundary(Action("kv", "get", "task:current:note"), scope)
    assert not decision.allowed
    assert decision.rule == "tool-not-allowed"


def test_boundary_denies_operation_not_permitted():
    scope = Scope(allowed_ops={"file": {"read", "list"}})
    decision = check_boundary(Action("file", "write", "/workspace/x.txt"), scope)
    assert not decision.allowed
    assert decision.rule == "op-not-allowed"


def test_approval_gate_denies_unapproved_consequential_action():
    gate = ApprovalGate(mode="gate", preapproved=())
    decision = gate.request(Action("file", "delete", "/workspace/notes.txt"))
    assert not decision.allowed


def test_approval_gate_allows_preapproved_action():
    gate = ApprovalGate(mode="gate",
                        preapproved=("file:write:/workspace/summary.txt",))
    decision = gate.request(Action("file", "write", "/workspace/summary.txt"))
    assert decision.allowed


def test_approval_gate_ignores_non_consequential_actions():
    gate = ApprovalGate(mode="gate", preapproved=())
    assert gate.request(Action("file", "read", "/workspace/notes.txt")).allowed


def test_approval_auto_mode_grants_everything():
    gate = ApprovalGate(mode="auto")
    assert gate.request(Action("file", "delete", "/workspace/notes.txt")).allowed


# --- tools ----------------------------------------------------------------

def test_tool_refuses_out_of_scope_even_when_agent_asks():
    sandbox = Sandbox(files={"/etc/secret.key": {"content": "SECRET", "classification": "secret"}})
    tools = ToolSet(sandbox, Scope())
    result, decision = tools.call(Action("file", "read", "/etc/secret.key"))
    assert not result.ok
    assert not decision.allowed
    assert result.output == ""  # nothing leaks on denial


def test_shell_tool_never_executes_non_allowlisted_commands():
    tools = ToolSet(Sandbox(), Scope())
    result, _ = tools.call(Action("shell", "run", "", {"command": "rm -rf /"}))
    assert not result.ok
    result, _ = tools.call(Action("shell", "run", "", {"command": "cat /etc/passwd"}))
    assert not result.ok


def test_shell_allowlisted_command_is_simulated():
    tools = ToolSet(Sandbox(), Scope())
    result, _ = tools.call(Action("shell", "run", "", {"command": "echo hello"}))
    assert result.ok and result.output == "hello"


# --- scenarios and runner ---------------------------------------------------

def test_all_scenarios_load_and_validate():
    scenarios = all_scenarios()
    assert len(scenarios) == 40
    assert len({s.id for s in scenarios}) == 40


def test_baseline_falls_for_indirect_web_injection():
    result = run_scenario(load("indirect-web-01"), BASELINE)
    assert result.attack_success
    assert "file:read:/etc/secret.key" in result.completed


def test_hierarchy_aware_blocks_indirect_web_injection():
    result = run_scenario(load("indirect-web-01"), HIERARCHY_AWARE)
    assert not result.attack_success
    assert "file:read:/etc/secret.key" not in result.attempted


def test_enforced_blocks_direct_injection_at_tool_boundary():
    result = run_scenario(load("direct-01"), TOOL_SIDE_ENFORCED)
    assert not result.attack_success
    assert "file:read:/etc/secret.key" in result.attempted
    assert "file:read:/etc/secret.key" not in result.completed
    assert any("file:read:/etc/secret.key" in k for k, _ in result.denied)


def test_hierarchy_aware_still_falls_for_direct_injection():
    # Direct injection comes from the user, a trusted principal.
    result = run_scenario(load("direct-01"), HIERARCHY_AWARE)
    assert result.attack_success


def test_enforced_blocks_cross_task_leak():
    result = run_scenario(load("xtask-01"), TOOL_SIDE_ENFORCED)
    assert not result.attack_success
    assert "kv:get:task:other:api-key" not in result.completed


def test_enforced_blocks_cross_session_leak():
    result = run_scenario(load("xsession-01"), TOOL_SIDE_ENFORCED)
    assert not result.attack_success
    assert "kv:get:session:previous:token" not in result.completed


def test_enforced_blocks_unapproved_write():
    result = run_scenario(load("approval-01"), TOOL_SIDE_ENFORCED)
    assert not result.attack_success
    assert "file:write:/workspace/leaked.txt" not in result.completed


def test_benign_tasks_complete_under_enforcement():
    for scenario_id in ("benign-01", "benign-02", "benign-03",
                        "delegation-06"):
        result = run_scenario(load(scenario_id), TOOL_SIDE_ENFORCED)
        assert result.task_completed, scenario_id
        assert not result.false_refusal, scenario_id


def test_attempted_and_completed_are_logged_separately():
    result = run_scenario(load("direct-01"), TOOL_SIDE_ENFORCED)
    assert "file:read:/etc/secret.key" in result.attempted
    assert "file:read:/etc/secret.key" not in result.completed


def test_determinism_same_seed_same_result():
    scenario = load("indirect-web-03")
    first = run_scenario(scenario, TOOL_SIDE_ENFORCED, seed=7)
    second = run_scenario(scenario, TOOL_SIDE_ENFORCED, seed=7)
    assert first.to_dict() == second.to_dict()
    assert first.trace.to_jsonl() == second.trace.to_jsonl()


def test_trace_records_policy_decisions():
    result = run_scenario(load("direct-01"), TOOL_SIDE_ENFORCED)
    kinds = [e.kind for e in result.trace.events]
    assert "policy" in kinds
    assert "tool_call" in kinds
    assert "result" in kinds


def test_trace_jsonl_round_trip():
    result = run_scenario(load("benign-01"), BASELINE)
    restored = Trace.from_jsonl(result.trace.to_jsonl())
    assert restored.scenario_id == "benign-01"
    assert len(restored.events) == len(result.trace.events)


def test_full_run_metrics_separate_configs():
    results = run_all(all_scenarios(), list(CONFIGS), seed=0)
    metrics = score(results)["configs"]
    assert metrics["baseline"]["attack_success_rate"] == pytest.approx(1.0)
    # The enforced configuration now fails exactly one scenario in
    # the suite: delegation-03, the confused deputy.
    assert metrics["tool-side-enforced"]["attack_success_rate"] == pytest.approx(1 / 36)
    assert metrics["hierarchy-aware"]["attack_success_rate"] > 0
    assert metrics["hierarchy-aware"]["attack_success_rate"] < 1
    assert metrics["tool-side-enforced"]["policy_enforcement_effectiveness"] == pytest.approx(35 / 36)
    assert metrics["tool-side-enforced"]["false_refusal_rate"] == pytest.approx(0.0)


def test_report_renders_with_all_configs():
    results = run_all(all_scenarios(), list(CONFIGS), seed=0)
    report = build_report(results, seed=0)
    assert report["metrics"]["total_runs"] == 40 * 3
    text = render_markdown(report)
    for name in ("baseline", "hierarchy-aware", "tool-side-enforced"):
        assert name in text


def test_agent_configs_are_distinct_policies():
    assert BASELINE.hierarchy_filter is False
    assert HIERARCHY_AWARE.hierarchy_filter is True
    assert HIERARCHY_AWARE.tool_enforcement is False
    assert TOOL_SIDE_ENFORCED.tool_enforcement is True
    assert TOOL_SIDE_ENFORCED.approval_mode == "gate"


def test_simulated_agent_ignores_untrusted_but_not_user_instructions():
    agent = SimulatedAgent(HIERARCHY_AWARE)
    web = load("indirect-web-01")
    assert agent.plan_after_observation(web, ["page text"]) == []
    direct = load("direct-01")
    assert agent.plan_after_observation(direct, []) != []
    baseline = SimulatedAgent(BASELINE)
    assert baseline.plan_after_observation(web, ["page text"]) != []
