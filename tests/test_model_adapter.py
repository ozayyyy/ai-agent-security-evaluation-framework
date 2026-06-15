"""Tests for the API model adapter.

All tests are offline: they talk to a local test server (standard
library ``http.server``) that returns canned chat-completions
replies. No real API is called and no real key is used anywhere.
"""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from aasef.agents import BASELINE
from aasef.cli import main as cli_main
from aasef.model_adapter import ApiModelAdapter
from aasef.permissions import Action
from aasef.reporting import build_report, render_markdown
from aasef.runner import run_scenario
from aasef.scenario import Scenario

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "scenarios"

KEY = "SECRET-KEY-12345"


def load(scenario_id):
    return Scenario.load(SCENARIOS / f"{scenario_id}.json")


def chat_reply(content, model="test-model"):
    return {"id": "chatcmpl-test", "object": "chat.completion",
            "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant",
                                                 "content": content},
                         "finish_reason": "stop"}]}


class Handler(BaseHTTPRequestHandler):
    """Canned chat-completions server. Tests set the class state."""
    requests = []
    status = 200
    payload = {}
    delay = 0.0

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        Handler.requests.append({"path": self.path,
                                 "headers": dict(self.headers),
                                 "body": body})
        if Handler.delay:
            time.sleep(Handler.delay)
        data = json.dumps(Handler.payload).encode("utf-8")
        try:
            self.send_response(Handler.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *args):
        pass


@pytest.fixture()
def api_server():
    Handler.requests = []
    Handler.status = 200
    Handler.payload = chat_reply("[]")
    Handler.delay = 0.0
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def make_adapter(base_url, model="test-model", api_key=KEY, **kwargs):
    return ApiModelAdapter(BASELINE, base_url=base_url, api_key=api_key,
                           model=model, **kwargs)


def last_request_body():
    return json.loads(Handler.requests[-1]["body"])


# --- happy path ------------------------------------------------------------

def test_happy_path_returns_model_actions(api_server):
    Handler.payload = chat_reply(
        '[{"tool": "file", "op": "read", "target": "/workspace/notes.txt", '
        '"args": {}}]')
    adapter = make_adapter(api_server)
    plan = adapter.plan_legitimate(load("benign-01"))
    assert plan == [Action("file", "read", "/workspace/notes.txt")]
    body = last_request_body()
    assert body["model"] == "test-model"
    assert body["messages"][0]["role"] == "system"
    assert Handler.requests[-1]["headers"]["Authorization"] == f"Bearer {KEY}"
    assert Handler.requests[-1]["path"] == "/chat/completions"


def test_markdown_fenced_reply_is_parsed(api_server):
    Handler.payload = chat_reply(
        'Here is the plan:\n```json\n[{"tool": "web", "op": "fetch", '
        '"target": "example.internal/home"}]\n```')
    adapter = make_adapter(api_server)
    assert adapter.plan_legitimate(load("benign-01")) == [
        Action("web", "fetch", "example.internal/home")]


def test_plan_after_observation_includes_observations(api_server):
    Handler.payload = chat_reply("[]")
    adapter = make_adapter(api_server)
    adapter.plan_after_observation(load("benign-01"),
                                   ["file contents: hello"])
    assert "hello" in last_request_body()["messages"][1]["content"]


# --- failure handling: never crash, never retry ----------------------------

def test_malformed_reply_returns_empty_plan_and_records_failure(api_server):
    Handler.payload = chat_reply("this is not json at all")
    adapter = make_adapter(api_server)
    assert adapter.plan_legitimate(load("benign-01")) == []
    assert len(adapter.failures) == 1
    assert "JSON" in adapter.failures[0]


def test_http_500_returns_empty_plan_and_calls_once(api_server):
    Handler.status = 500
    Handler.payload = {"error": "boom"}
    adapter = make_adapter(api_server)
    assert adapter.plan_legitimate(load("benign-01")) == []
    assert len(adapter.failures) == 1
    assert len(Handler.requests) == 1  # no retry


def test_timeout_returns_empty_plan(api_server):
    Handler.delay = 2.0
    adapter = make_adapter(api_server, timeout=0.3)
    assert adapter.plan_legitimate(load("benign-01")) == []
    assert len(adapter.failures) == 1


def test_failure_recorded_in_trace_and_run_continues(api_server):
    Handler.status = 500
    Handler.payload = {"error": "boom"}
    adapter = make_adapter(api_server)
    result = run_scenario(load("benign-01"), BASELINE, agent=adapter)
    assert result is not None
    trace_text = result.trace.to_jsonl()
    assert "model call failed" in trace_text
    assert KEY not in trace_text


# --- validation: bad model output is dropped, never executed ---------------

def test_unknown_tool_op_and_target_are_dropped(api_server):
    Handler.payload = chat_reply(json.dumps([
        {"tool": "file", "op": "read", "target": "/workspace/notes.txt"},
        {"tool": "teleport", "op": "go", "target": "mars"},
        {"tool": "file", "op": "explode", "target": "/workspace/notes.txt"},
        {"tool": "file", "op": "read", "target": 42},
        "not an object",
        {"tool": "file", "op": "read", "target": "/workspace/report.md",
         "args": "not a dict"},
    ]))
    adapter = make_adapter(api_server)
    plan = adapter.plan_legitimate(load("benign-01"))
    assert plan == [Action("file", "read", "/workspace/notes.txt"),
                    Action("file", "read", "/workspace/report.md")]


# --- configuration: env vars, then CLI flags -------------------------------

def test_env_var_configuration(api_server, monkeypatch):
    monkeypatch.setenv("AASEF_API_BASE_URL", api_server)
    monkeypatch.setenv("AASEF_API_KEY", "env-key-999")
    monkeypatch.setenv("AASEF_MODEL", "env-model")
    Handler.payload = chat_reply("[]")
    adapter = ApiModelAdapter(BASELINE)
    adapter.plan_legitimate(load("benign-01"))
    body = last_request_body()
    assert body["model"] == "env-model"
    assert Handler.requests[-1]["headers"]["Authorization"] == "Bearer env-key-999"


def test_explicit_argument_overrides_env(api_server, monkeypatch):
    monkeypatch.setenv("AASEF_API_BASE_URL", "http://127.0.0.1:1/unused")
    monkeypatch.setenv("AASEF_API_KEY", "env-key-999")
    monkeypatch.setenv("AASEF_MODEL", "env-model")
    Handler.payload = chat_reply("[]")
    adapter = ApiModelAdapter(BASELINE, base_url=api_server,
                              api_key="flag-key", model="flag-model")
    adapter.plan_legitimate(load("benign-01"))
    body = last_request_body()
    assert body["model"] == "flag-model"
    assert Handler.requests[-1]["headers"]["Authorization"] == "Bearer flag-key"


def test_missing_base_url_raises_clear_error(monkeypatch):
    monkeypatch.delenv("AASEF_API_BASE_URL", raising=False)
    monkeypatch.setenv("AASEF_MODEL", "some-model")
    with pytest.raises(ValueError, match="AASEF_API_BASE_URL"):
        ApiModelAdapter(BASELINE)


def test_missing_model_raises_clear_error(api_server, monkeypatch):
    monkeypatch.delenv("AASEF_MODEL", raising=False)
    with pytest.raises(ValueError, match="AASEF_MODEL"):
        ApiModelAdapter(BASELINE, base_url=api_server)


def test_cli_api_without_base_url_fails_clearly(monkeypatch):
    monkeypatch.delenv("AASEF_API_BASE_URL", raising=False)
    with pytest.raises(SystemExit, match="AASEF_API_BASE_URL"):
        cli_main(["run", "--agent", "api", "--scenarios", str(SCENARIOS),
                  "--config", "baseline"])


# --- the API key never leaks into output -----------------------------------

def test_api_key_never_in_trace_or_report(api_server):
    Handler.payload = chat_reply(
        '[{"tool": "file", "op": "read", "target": "/workspace/notes.txt"}]')
    adapter = make_adapter(api_server)
    result = run_scenario(load("benign-01"), BASELINE, agent=adapter)
    trace_text = result.trace.to_jsonl()
    report = build_report([result], seed=0)
    assert KEY not in trace_text
    assert KEY not in json.dumps(report)
    assert KEY not in render_markdown(report)
