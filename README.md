# Order Tracker

A small order tracking app for the AI Dev Tools Zoomcamp observability homework. It includes a web page, API, tests, and a Docker Compose setup. You add telemetry, alerts, and an incident responder in Homework 4.

The main user flow is creating an order and checking its status. Three sample orders are created on first startup.

## Run it

You need Docker with Compose. To run the tests, you also need Python 3.11+ and `uv`.

```bash
docker compose up --build -d --wait
```

Open <http://127.0.0.1:8000>. The API is at `/api/orders`, and the health check is at `/healthz`. Data is stored in a Docker volume and survives container recreation.

If port 8000 is occupied, set `ORDER_TRACKER_PORT`, for example:

```bash
ORDER_TRACKER_PORT=18080 docker compose up --build -d --wait
```

Run tests with `uv run --frozen pytest -q`. Stop the app with `docker compose down`. Add `-v` only if you also want to delete the order data.

## Observability stack

The Compose file also runs an OpenTelemetry Collector, Prometheus, Loki, Tempo, and Grafana.

Start everything:

```bash
docker compose up --build -d --wait
```

Application telemetry flow:

- Traces: FastAPI `GET /api/orders/{order_id}` creates one manual span. The app exports it over OTLP gRPC to `otel-collector:4317`; the Collector exports it over OTLP gRPC to `tempo:4317`; Grafana reads Tempo at `http://tempo:3200`.
- Metrics: the same endpoint increments `http.server.requests` with `http.route` and `http.response.status_code`. The app exports it over OTLP gRPC to the Collector; the Collector Prometheus exporter exposes it on `otel-collector:8889`; Prometheus scrapes that endpoint; Grafana reads Prometheus at `http://prometheus:9090`.
- Logs: the app structured logs are exported over OTLP gRPC to the Collector; the Collector exports them over OTLP HTTP to `http://loki:3100/otlp`; Grafana reads Loki at `http://loki:3100`.

Open Grafana at <http://127.0.0.1:3000> with `admin` / `admin`. The `Order Tracker HTTP` dashboard is provisioned under Observability.

Direct inspection endpoints:

- Prometheus: <http://127.0.0.1:9090>
- Tempo search: <http://127.0.0.1:3200/api/search?tags=service.name%3Dorder-tracker>
- Loki labels: <http://127.0.0.1:3100/loki/api/v1/labels>
- Collector health: <http://127.0.0.1:13133>

Console exporters are disabled by default. Set `OTEL_CONSOLE_EXPORTERS=true` for local debugging.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/` | Web page |
| GET | `/healthz` | Database health check |
| GET | `/api/orders` | List orders |
| POST | `/api/orders` | Create an order |
| GET | `/api/orders/{id}` | Check an order |
| PATCH | `/api/orders/{id}` | Change an order status |

## Incident responder

The host-side responder in `incident-response/` receives Grafana's webhook at
`http://host.docker.internal:8001/alerts`. Grafana runs in Docker, so the responder
must be started with Uvicorn bound to all interfaces:

```powershell
uv run --frozen uvicorn --app-dir incident-response service:app --host 0.0.0.0 --port 8001
```

For real incident mode:

```powershell
$env:INCIDENT_AGENT_MODE = "workspace-write"
uv run --frozen uvicorn --app-dir incident-response service:app --host 0.0.0.0 --port 8001
```

Grafana's contact point is provisioned in
`config/grafana/alerting/contact-points.yaml` and attached to the
`order-tracker-http-5xx` rule. Diagnose Docker-to-host connectivity before
triggering an incident:

```powershell
docker compose exec grafana wget -qO- http://host.docker.internal:8001/healthz
```

If this fails, confirm the responder process is running and that Windows Firewall
allows the Docker Desktop/WSL virtual interface to reach port 8001. Do not expose
port 8001 publicly or configure router port forwarding; this is a local development
responder only.

Resolved notifications are ignored by the responder and do not launch Copilot.
Duplicate firing notifications with the same alert fingerprint are deduplicated.

The Copilot `--allow-tool=write(app/main.py)` restriction is a CLI tool-permission
control, not an OS-level sandbox: it limits which tool calls the agent may make, but
it is not by itself a hard filesystem security boundary. Shell access remains denied
and no allow-all/yolo mode is used.

The app uses SQLite to keep setup small. Run one app container at a time. The course exercise is about detecting and handling an incident, not scaling the database.
