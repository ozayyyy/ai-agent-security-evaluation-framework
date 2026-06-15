"""Tests for scripts/run_real_models.py against a local stub endpoint.

The stub is a tiny OpenAI-compatible chat completions server on
localhost returning canned JSON. No real model is involved and no
real key exists: the "key" used here is a made-up test string, and
one test asserts it never appears in the written report.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TEST_KEY = "test-key-not-real"
CANNED_PLAN = [{"tool": "kv", "op": "get",
                "target": "task:current:note", "args": {}}]


def make_handler(mode):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            if self.path != "/chat/completions":
                self.send_response(404)
                self.end_headers()
                return
            if mode == "error":
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "stub failure"}')
                return
            payload = {"choices": [{"message": {
                "content": json.dumps(CANNED_PLAN)}}]}
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


@pytest.fixture()
def stub_server():
    """A stub endpoint on localhost. Yields (base_url, state).

    ``state["mode"]`` switches the stub between "ok" (canned plan)
    and "error" (HTTP 500) while the test runs.
    """
    state = {"mode": "ok"}

    def handler_factory(*args, **kwargs):
        return make_handler(state["mode"])(*args, **kwargs)

    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_factory)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield (f"http://127.0.0.1:{server.server_address[1]}", state)
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture()
def two_scenarios(tmp_path):
    """Two real scenario files in a temporary directory."""
    dest = tmp_path / "scenarios"
    dest.mkdir()
    for name in ("direct-01.json", "benign-01.json"):
        shutil.copy(ROOT / "scenarios" / name, dest / name)
    return dest


def run_script(env, *args):
    full_env = dict(os.environ)
    for key in ("AASEF_API_BASE_URL", "AASEF_API_KEY", "AASEF_MODEL"):
        full_env.pop(key, None)
    full_env.update(env)
    return subprocess.run(
        [sys.executable, "scripts/run_real_models.py", *args],
        cwd=ROOT, env=full_env, capture_output=True, text=True, timeout=120)


def test_stub_run_writes_report_without_key(stub_server, two_scenarios,
                                            tmp_path):
    base_url, _ = stub_server
    out = tmp_path / "report.json"
    proc = run_script(
        {"AASEF_API_BASE_URL": base_url, "AASEF_API_KEY": TEST_KEY,
         "AASEF_MODEL": "stub-model"},
        "--scenarios", str(two_scenarios), "--config", "baseline",
        "--out", str(out))
    assert proc.returncode == 0, proc.stderr
    text = out.read_text(encoding="utf-8")
    assert TEST_KEY not in text
    assert base_url not in text
    report = json.loads(text)
    assert report["metrics"]["total_runs"] == 2
    assert report["real_model"]["agent"] == "api"
    assert report["real_model"]["model"] == "stub-model"
    assert report["real_model"]["model_call_failures"] == 0
    assert len(report["runs"]) == 2


def test_stub_error_still_completes_with_failures_recorded(
        stub_server, two_scenarios, tmp_path):
    base_url, state = stub_server
    state["mode"] = "error"
    out = tmp_path / "report.json"
    proc = run_script(
        {"AASEF_API_BASE_URL": base_url, "AASEF_API_KEY": TEST_KEY,
         "AASEF_MODEL": "stub-model"},
        "--scenarios", str(two_scenarios), "--config", "baseline",
        "--out", str(out))
    assert proc.returncode == 0, proc.stderr
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["real_model"]["model_call_failures"] > 0
    assert all(r["attempted"] == [] for r in report["runs"])
    assert TEST_KEY not in out.read_text(encoding="utf-8")


def test_missing_endpoint_refuses_to_run(two_scenarios, tmp_path):
    proc = run_script(
        {}, "--scenarios", str(two_scenarios),
        "--out", str(tmp_path / "report.json"))
    assert proc.returncode != 0
    assert "AASEF_API_BASE_URL" in proc.stderr
    assert not (tmp_path / "report.json").exists()


def test_missing_model_refuses_to_run(stub_server, two_scenarios, tmp_path):
    base_url, _ = stub_server
    proc = run_script(
        {"AASEF_API_BASE_URL": base_url},
        "--scenarios", str(two_scenarios),
        "--out", str(tmp_path / "report.json"))
    assert proc.returncode != 0
    assert "AASEF_MODEL" in proc.stderr
    assert not (tmp_path / "report.json").exists()
