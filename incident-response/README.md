# Incident Responder

Host-side service for Question 5. It receives Grafana-style alert webhooks, collects
bounded observability evidence, and invokes the locally installed GitHub Copilot CLI
with `gpt-6-luna`.

## Start the responder

From the repository root:

```powershell
cd "C:\Users\Shane\Documents\Coding Projects\AI_devs_2026\order-tracker"
uv run --frozen uvicorn --app-dir incident-response service:app --host 0.0.0.0 --port 8001
```

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8001/healthz
```

## Submit the homework test payload

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8001/alerts -ContentType "application/json" -Body '{"alerts":[{"status":"firing","labels":{"alertname":"ResponderTest","test":"true"},"annotations":{"summary":"Test notification; no incident to fix"}}]}'
```

## Incident files

Each accepted alert creates a directory under:

`incident-response/incidents/<timestamp>-<id>/`

Files:

- `alert.json` - original alert payload
- `evidence.json` - alert metadata, affected endpoint, time window, Prometheus, Loki, and Tempo evidence
- `copilot-response.txt` - Copilot CLI final response
- `execution.json` - command, working directory, timestamps, exit code, stdout, stderr, and execution metadata

Display the final answer's last line:

```powershell
$latest = (Get-ChildItem incident-response\incidents -Directory | Sort-Object Name -Descending | Select-Object -First 1).FullName
(Get-Content "$latest\copilot-response.txt")[-1]
```
## Grafana webhook connectivity

Grafana runs in Docker and posts to `http://host.docker.internal:8001/alerts`.
The responder must therefore listen on `0.0.0.0`, not only `127.0.0.1`.

Diagnose connectivity from the Grafana container before triggering an incident:

```powershell
docker compose exec grafana wget -qO- http://host.docker.internal:8001/healthz
```

If this fails, check that the responder process is running and that Windows
Firewall allows the Docker Desktop/WSL virtual interface to reach port 8001.
Do not expose port 8001 publicly or configure router port forwarding; this is a
local development responder only.

## Grafana provisioning

The webhook contact point is version-controlled in
`config/grafana/alerting/contact-points.yaml` and attached to
`order-tracker-http-5xx` via rule-level `notification_settings.receiver`.

Restart Grafana after provisioning changes:

```powershell
docker compose up -d --force-recreate grafana
docker compose exec grafana wget -qO- http://localhost:3000/api/health
```

Verify the contact point and rule routing via Grafana's API:

```powershell
$auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("admin:admin"))
Invoke-RestMethod -Headers @{ Authorization = "Basic $auth" } http://127.0.0.1:3000/api/v1/provisioning/contact-points
Invoke-RestMethod -Headers @{ Authorization = "Basic $auth" } http://127.0.0.1:3000/api/v1/provisioning/alert-rules/order-tracker-http-5xx | Select-Object -ExpandProperty notification_settings
```

## Incident workflow commands

Stop an existing responder, then start in real incident mode:

```powershell
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*uvicorn*service:app*' } | Invoke-CimMethod -MethodName Terminate
$env:INCIDENT_AGENT_MODE = "workspace-write"
uv run --frozen uvicorn --app-dir incident-response service:app --host 0.0.0.0 --port 8001
```

Verify connectivity from Grafana:

```powershell
docker compose exec grafana wget -qO- http://host.docker.internal:8001/healthz
```

Trigger the incident once configuration is validated:

```powershell
curl.exe -i http://localhost:8000/api/orders/express-1002
```

After reviewing the agent's changes, rebuild and verify:

```powershell
docker compose up -d --build app
curl.exe -i http://localhost:8000/api/orders/express-1002
```

Resolved notifications are ignored by the responder and do not launch Copilot.
Duplicate firing notifications with the same alert fingerprint are deduplicated.
"""

## Agent mode

Default mode is `read-only`. To enable the future restricted workspace-write mode for
Question 6:

```powershell
$env:INCIDENT_AGENT_MODE = "workspace-write"
```

The credit cap is configurable with `INCIDENT_COPILOT_MAX_AI_CREDITS` (default `30`).
GitHub's credit cap is a soft limit, not a strict guarantee. The responder never uses
`--allow-all`, `--yolo`, autopilot, or an unlimited retry loop.

The `--allow-tool=write(app/main.py)` argument is a Copilot CLI tool-permission
restriction, not an OS-level sandbox. It prevents the agent from invoking the write
tool for other paths, but it is not by itself a hard filesystem security boundary.
`--add-dir` grants read access to the repository root, shell access remains denied,
and no allow-all/yolo/autopilot mode is used. Copilot is not permitted to restart
Docker or rebuild the application.
