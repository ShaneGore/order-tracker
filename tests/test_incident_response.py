import json
import subprocess
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "incident-response"))

import service


@pytest.fixture
def incident_env(tmp_path, monkeypatch):
    incidents_dir = tmp_path / "incidents"
    monkeypatch.setattr(service, "INCIDENTS_DIR", incidents_dir)
    service._completed.clear()
    service._inflight.clear()
    monkeypatch.setattr(service, "COPILOT_MODE", "read-only")
    monkeypatch.setattr(service, "COPILOT_MAX_AI_CREDITS", 30)
    monkeypatch.setattr(service, "COPILOT_TIMEOUT_SECONDS", 5)
    monkeypatch.setattr(service, "fetch_json", lambda url, timeout=service.OBSERVABILITY_TIMEOUT_SECONDS: (_ for _ in ()).throw(ConnectionError("service unavailable")))
    yield incidents_dir
    service._completed.clear()
    service._inflight.clear()


@pytest.fixture
def client(incident_env):
    with TestClient(service.app) as test_client:
        yield test_client


PAYLOAD = {
    "status": "firing",
    "alerts": [
        {
            "status": "firing",
            "labels": {"alertname": "ResponderTest", "test": "true"},
            "annotations": {"summary": "Test notification; no incident to fix"},
            "startsAt": "2026-01-01T00:00:00Z",
            "endsAt": "2026-01-01T00:05:00Z",
        }
    ],
}


def test_health_endpoint(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_valid_webhook_payload(client, monkeypatch):
    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="notification is a test\n", stderr="")

    monkeypatch.setattr(service.subprocess, "run", fake_run)
    response = client.post("/alerts", json=PAYLOAD)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "accepted"
    assert len(body["incidents"]) == 1
    assert body["incidents"][0]["status"] == "processed"


def test_invalid_payload_handling(client):
    assert client.post("/alerts", json={"alerts": []}).status_code == 422
    assert client.post("/alerts", json={"foo": "bar"}).status_code == 422
    assert client.post("/alerts", content="{not json", headers={"content-type": "application/json"}).status_code == 422


def test_incident_directory_and_evidence_creation(client, incident_env, monkeypatch):
    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr(service.subprocess, "run", fake_run)
    response = client.post("/alerts", json=PAYLOAD)
    assert response.status_code == 200
    incident_dir = Path(response.json()["incidents"][0]["incident_dir"])
    assert incident_dir.exists()
    assert (incident_dir / "alert.json").exists()
    assert (incident_dir / "evidence.json").exists()
    assert (incident_dir / "copilot-response.txt").exists()
    assert (incident_dir / "execution.json").exists()

    evidence = json.loads((incident_dir / "evidence.json").read_text(encoding="utf-8"))
    assert evidence["affected_endpoint"] == "/api/orders/{order_id}"
    assert "prometheus" in evidence
    assert "loki" in evidence
def test_unavailable_observability_services_recorded(client, incident_env, monkeypatch):
    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr(service.subprocess, "run", fake_run)
    client.post("/alerts", json=PAYLOAD)
    incident_dir = next(incident_env.iterdir())
    evidence = json.loads((incident_dir / "evidence.json").read_text(encoding="utf-8"))
    assert evidence["prometheus"]["http_5xx_total_5m"]["error"] is not None
    assert evidence["loki"]["error"] is not None
    assert evidence["tempo"]["error"] is not None


def test_test_notification_invokes_copilot(client, incident_env, monkeypatch):
    calls = {"count": 0}

    def fake_run(command, **kwargs):
        calls["count"] += 1
        assert "--model=gpt-6-luna" in command
        return subprocess.CompletedProcess(command, 0, stdout="This is a test notification; no fix needed.\n", stderr="")

    monkeypatch.setattr(service.subprocess, "run", fake_run)
    response = client.post("/alerts", json=PAYLOAD)
    assert calls["count"] == 1
    incident_dir = Path(response.json()["incidents"][0]["incident_dir"])
    assert "test" in (incident_dir / "copilot-response.txt").read_text(encoding="utf-8").lower()
    execution = json.loads((incident_dir / "execution.json").read_text(encoding="utf-8"))
    assert "--model=gpt-6-luna" in execution["command"]
    assert execution["working_directory"] not in str(ROOT)


def test_no_application_file_modification_for_test_notification(client, incident_env, monkeypatch):
    app_file = ROOT / "app" / "main.py"
    before = app_file.read_bytes()

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="test notification; no fix\n", stderr="")

    monkeypatch.setattr(service.subprocess, "run", fake_run)
    client.post("/alerts", json=PAYLOAD)
    after = app_file.read_bytes()
    assert before == after

def test_copilot_timeout(client, incident_env, monkeypatch):
    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, timeout=1)

    monkeypatch.setattr(service.subprocess, "run", fake_run)
    response = client.post("/alerts", json=PAYLOAD)
    incident_dir = Path(response.json()["incidents"][0]["incident_dir"])
    execution = json.loads((incident_dir / "execution.json").read_text(encoding="utf-8"))
    assert execution["status"] == "failed"
    assert "timed out" in execution["error"]


def test_copilot_process_failure(client, incident_env, monkeypatch):
    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 2, stdout="", stderr="auth failed")

    monkeypatch.setattr(service.subprocess, "run", fake_run)
    response = client.post("/alerts", json=PAYLOAD)
    incident_dir = Path(response.json()["incidents"][0]["incident_dir"])
    execution = json.loads((incident_dir / "execution.json").read_text(encoding="utf-8"))
    assert execution["status"] == "failed"
    assert execution["exit_code"] == 2
    assert "auth failed" in execution["stderr"]


def test_duplicate_alert_behavior(client, incident_env, monkeypatch):
    calls = {"count": 0}

    def fake_run(command, **kwargs):
        calls["count"] += 1
        time.sleep(0.05)
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr(service.subprocess, "run", fake_run)
    first = client.post("/alerts", json=PAYLOAD)
    second = client.post("/alerts", json=PAYLOAD)
    assert first.json()["incidents"][0]["status"] == "processed"
    assert second.json()["incidents"][0]["status"] == "duplicate"
    assert calls["count"] == 1

def test_resolved_notification_does_not_launch_copilot(client, incident_env, monkeypatch):
    calls = {"count": 0}

    def fake_run(command, **kwargs):
        calls["count"] += 1
        return subprocess.CompletedProcess(command, 0, stdout="should not run", stderr="")

    monkeypatch.setattr(service.subprocess, "run", fake_run)
    resolved_payload = {
        "status": "resolved",
        "alerts": [
            {
                "status": "resolved",
                "labels": {"alertname": "Order Tracker HTTP 5xx responses"},
                "annotations": {"summary": "resolved"},
                "startsAt": "2026-01-01T00:00:00Z",
                "endsAt": "2026-01-01T00:05:00Z",
                "fingerprint": "resolved-fingerprint-1",
            }
        ],
    }
    response = client.post("/alerts", json=resolved_payload)
    assert response.status_code == 200
    result = response.json()["incidents"][0]
    assert result["status"] == "resolved"
    assert result["agent_launched"] is False
    assert calls["count"] == 0


def test_firing_real_alert_invokes_copilot(client, incident_env, monkeypatch):
    calls = {"count": 0}

    def fake_run(command, **kwargs):
        calls["count"] += 1
        return subprocess.CompletedProcess(command, 0, stdout="investigated; fixed", stderr="")

    monkeypatch.setattr(service.subprocess, "run", fake_run)
    firing_payload = {
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {"alertname": "Order Tracker HTTP 5xx responses"},
                "annotations": {
                    "summary": "Order Tracker API returned at least one HTTP 5xx response in the last 5 minutes",
                    "endpoint": "/api/orders/{order_id}",
                },
                "startsAt": "2026-01-01T00:00:00Z",
                "endsAt": "2026-01-01T00:05:00Z",
                "fingerprint": "firing-fingerprint-1",
            }
        ],
    }
    response = client.post("/alerts", json=firing_payload)
    assert response.status_code == 200
    result = response.json()["incidents"][0]
    assert result["status"] == "processed"
    assert calls["count"] == 1


def test_workspace_write_command_flags():
    command = service.build_copilot_command("prompt", "workspace-write", 30, ROOT)
    assert "--model=gpt-6-luna" in command
    assert "--max-ai-credits=30" in command
    assert f"--add-dir={ROOT}" in command
    assert f"--allow-tool=write({ROOT / 'app' / 'main.py'})" in command
    assert "--deny-tool=shell" in command
    assert "--disallow-temp-dir" in command
    assert "--allow-all" not in command
    assert "--yolo" not in command
    assert "--allow-all-tools" not in command


def test_credit_cap_minimum_enforced():
    with pytest.raises(ValueError):
        service.build_copilot_command("prompt", "workspace-write", 10, ROOT)



def test_read_only_command_flags():
    command = service.build_copilot_command("prompt", "read-only", 30, ROOT)
    assert "--model=gpt-6-luna" in command
    assert "--excluded-tools=write,shell" in command
    assert "--deny-tool=write" in command
    assert "--deny-tool=shell" in command
    assert "--allow-all" not in command
    assert "--yolo" not in command


def test_mocked_subprocess_command_includes_model(client, incident_env, monkeypatch):
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = list(command)
        captured["cwd"] = kwargs.get("cwd")
        return subprocess.CompletedProcess(command, 0, stdout="done", stderr="")

    monkeypatch.setattr(service.subprocess, "run", fake_run)
    client.post("/alerts", json=PAYLOAD)
    assert "--model=gpt-6-luna" in captured["command"]
    assert captured["cwd"] is not None
    assert str(ROOT) not in str(captured["cwd"])
SAVED_INCIDENT_DIR = ROOT / "incident-response" / "incidents" / "20261026T004747Z-e366b470"
SAVED_ALERT_PAYLOAD = json.loads((SAVED_INCIDENT_DIR / "alert.json").read_text(encoding="utf-8"))


def test_saved_incident_payload_does_not_overflow_timestamps(client, incident_env, monkeypatch):
    monkeypatch.setattr(service, "fetch_json", lambda url, timeout=service.OBSERVABILITY_TIMEOUT_SECONDS: {})
    calls = {"count": 0}

    def fake_run(command, **kwargs):
        calls["count"] += 1
        assert "--model=gpt-6-luna" in command
        return subprocess.CompletedProcess(command, 0, stdout="investigated; no credit spent", stderr="")

    monkeypatch.setattr(service.subprocess, "run", fake_run)

    response = client.post("/alerts", json=SAVED_ALERT_PAYLOAD)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "accepted"
    assert len(body["incidents"]) == 1
    result = body["incidents"][0]
    assert result["status"] == "processed"
    assert calls["count"] == 1

    incident_dir = Path(result["incident_dir"])
    assert incident_dir.exists()
    assert (incident_dir / "evidence.json").exists()
    evidence = json.loads((incident_dir / "evidence.json").read_text(encoding="utf-8"))
    assert evidence["time_window"]["alert_ends_at"] == "0001-01-01T00:00:00Z"
    assert evidence["time_window"]["end"].startswith("2026-10-26T00:47:20")
    assert evidence["loki"]["error"] is None
    assert evidence["tempo"]["error"] is None
    for query in evidence["prometheus"].values():
        assert query["error"] is None


def test_retry_failed_saved_incident_once(client, incident_env, monkeypatch):
    monkeypatch.setattr(service, "fetch_json", lambda url, timeout=service.OBSERVABILITY_TIMEOUT_SECONDS: {})

    def failing_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, timeout=1)

    monkeypatch.setattr(service.subprocess, "run", failing_run)
    first = client.post("/alerts", json=SAVED_ALERT_PAYLOAD)
    assert first.status_code == 200
    failed_result = first.json()["incidents"][0]
    assert failed_result["copilot_status"] == "failed"
    incident_id = failed_result["incident_id"]

    def successful_run(command, **kwargs):
        assert "--model=gpt-6-luna" in command
        return subprocess.CompletedProcess(command, 0, stdout="retried successfully", stderr="")

    monkeypatch.setattr(service.subprocess, "run", successful_run)
    retry_response = client.post(f"/retry/{incident_id}")
    assert retry_response.status_code == 200
    retry_body = retry_response.json()
    assert retry_body["retried_from"] == incident_id
    assert retry_body["incidents"][0]["status"] == "processed"

    second_retry = client.post(f"/retry/{incident_id}")
    assert second_retry.status_code == 409


def test_retry_rejects_already_successful_incident(client, incident_env, monkeypatch):
    monkeypatch.setattr(service, "fetch_json", lambda url, timeout=service.OBSERVABILITY_TIMEOUT_SECONDS: {})

    def successful_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setattr(service.subprocess, "run", successful_run)
    first = client.post("/alerts", json=SAVED_ALERT_PAYLOAD)
    incident_id = first.json()["incidents"][0]["incident_id"]

    response = client.post(f"/retry/{incident_id}")
    assert response.status_code == 409

def test_windows_copilot_cli_resolution(monkeypatch):
    def fake_which(name):
        if name == "copilot":
            return r"C:\Users\Shane\AppData\Roaming\npm\copilot.cmd"
        if name == "node":
            return r"C:\Program Files\nodejs\node.exe"
        return None

    monkeypatch.setattr(service.shutil, "which", fake_which)
    launcher = service.resolve_copilot_launcher()
    assert launcher == [
        r"C:\Program Files\nodejs\node.exe",
        r"C:\Users\Shane\AppData\Roaming\npm\node_modules\@github\copilot\npm-loader.js",
    ]


def test_copilot_resolution_fallback(monkeypatch):
    monkeypatch.setattr(service.shutil, "which", lambda name: None)
    assert service.resolve_copilot_launcher() == ["copilot"]


def test_command_construction_uses_resolved_launcher(monkeypatch):
    monkeypatch.setattr(
        service,
        "resolve_copilot_launcher",
        lambda: [r"C:\tools\node.exe", r"C:\tools\npm-loader.js"],
    )
    command = service.build_copilot_command("prompt", "workspace-write", 30, ROOT)
    assert command[:2] == [r"C:\tools\node.exe", r"C:\tools\npm-loader.js"]
    assert "-p" in command
    assert "--model=gpt-6-luna" in command
    assert "--max-ai-credits=30" in command
    assert f"--allow-tool=write({ROOT / 'app' / 'main.py'})" in command
