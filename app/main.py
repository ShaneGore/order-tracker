import logging
import os
import sys
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from opentelemetry import metrics, trace
from opentelemetry._logs import set_logger_provider
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor, ConsoleLogRecordExporter, SimpleLogRecordProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import ConsoleMetricExporter, PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter, SimpleSpanProcessor
from opentelemetry.trace import Status, StatusCode
from pydantic import BaseModel, Field


DB_PATH = Path(os.getenv("ORDER_DB_PATH", "data/orders.db"))
STATUSES = {"received", "preparing", "shipped", "delivered"}

class _SafeWriter:
    def write(self, data):
        try:
            return sys.stdout.write(data)
        except (ValueError, OSError):
            return len(data) if isinstance(data, str) else 0

    def flush(self):
        try:
            sys.stdout.flush()
        except (ValueError, OSError):
            pass


# OpenTelemetry setup: OTLP is the required pipeline; console exporters are optional
# for local debugging and are disabled by default.
OTEL_SERVICE_NAME = os.getenv("OTEL_SERVICE_NAME", "order-tracker")
OTEL_EXPORTER_OTLP_ENDPOINT = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
OTEL_CONSOLE_EXPORTERS = os.getenv("OTEL_CONSOLE_EXPORTERS", "false").lower() == "true"

otel_resource = Resource.create({"service.name": OTEL_SERVICE_NAME})

tracer_provider = TracerProvider(resource=otel_resource)
if OTEL_EXPORTER_OTLP_ENDPOINT:
    tracer_provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=OTEL_EXPORTER_OTLP_ENDPOINT, insecure=True))
    )
if OTEL_CONSOLE_EXPORTERS:
    tracer_provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter(out=_SafeWriter())))
trace.set_tracer_provider(tracer_provider)
tracer = trace.get_tracer(__name__)

metric_readers = []
if OTEL_EXPORTER_OTLP_ENDPOINT:
    metric_readers.append(
        PeriodicExportingMetricReader(
            OTLPMetricExporter(endpoint=OTEL_EXPORTER_OTLP_ENDPOINT, insecure=True),
            export_interval_millis=10000,
        )
    )
if OTEL_CONSOLE_EXPORTERS:
    metric_readers.append(
        PeriodicExportingMetricReader(
            ConsoleMetricExporter(out=_SafeWriter()), export_interval_millis=10000
        )
    )
meter_provider = MeterProvider(resource=otel_resource, metric_readers=metric_readers)
metrics.set_meter_provider(meter_provider)
meter = metrics.get_meter(__name__)

logger_provider = LoggerProvider(resource=otel_resource)
logger_provider.add_log_record_processor(
    BatchLogRecordProcessor(OTLPLogExporter(endpoint=OTEL_EXPORTER_OTLP_ENDPOINT, insecure=True))
)
if OTEL_CONSOLE_EXPORTERS:
    logger_provider.add_log_record_processor(
        SimpleLogRecordProcessor(ConsoleLogRecordExporter(out=_SafeWriter()))
    )
set_logger_provider(logger_provider)
logging_handler = LoggingHandler(level=logging.INFO, logger_provider=logger_provider)
logger = logging.getLogger("order-tracker")
logger.addHandler(logging_handler)
logger.setLevel(logging.INFO)
logger.propagate = True

ORDER_LOOKUP_ROUTE = "/api/orders/{order_id}"
order_lookup_counter = meter.create_counter(
    "http.server.requests",
    description="Number of HTTP requests for order lookups",
    unit="1",
)


def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    with connect() as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS orders (
                id TEXT PRIMARY KEY,
                customer TEXT NOT NULL,
                item TEXT NOT NULL,
                priority TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )"""
        )
        if db.execute("SELECT COUNT(*) FROM orders").fetchone()[0] == 0:
            now = datetime.now(timezone.utc)
            previous_month_end = now.replace(day=1) - timedelta(days=1)
            for order in (
                ("standard-1001", "Avery", "Notebook", "standard", "received", now),
                ("express-1002", "Sam", "Headphones", "express", "preparing", previous_month_end),
                ("standard-1003", "Riley", "Water bottle", "standard", "shipped", now),
            ):
                db.execute(
                    "INSERT INTO orders VALUES (?, ?, ?, ?, ?, ?)",
                    (*order[:5], order[5].isoformat()),
                )


def as_dict(row):
    return dict(row) if row else None


def order_detail(row):
    order = as_dict(row)
    if order["priority"] == "express":
        placed_at = datetime.fromisoformat(order["created_at"])
        estimated_at = placed_at + timedelta(days=2)
        order["estimated_delivery"] = estimated_at.date().isoformat()
    return order


class NewOrder(BaseModel):
    customer: str = Field(min_length=1, max_length=80)
    item: str = Field(min_length=1, max_length=120)
    priority: str = "standard"


class StatusUpdate(BaseModel):
    status: str


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Order Tracker", lifespan=lifespan)


@app.get("/")
def index():
    return FileResponse(Path(__file__).parent.parent / "static" / "index.html")


@app.get("/healthz")
def health():
    with connect() as db:
        db.execute("SELECT 1")
    return {"status": "ok"}


@app.get("/api/orders")
def list_orders():
    with connect() as db:
        rows = db.execute("SELECT * FROM orders ORDER BY created_at DESC").fetchall()
    return [as_dict(row) for row in rows]


def fetch_order(order_id: str):
    with connect() as db:
        row = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "Order not found")
    return order_detail(row)


@app.get("/api/orders/{order_id}")
def get_order(order_id: str):
    status_code = 200
    with tracer.start_as_current_span("GET " + ORDER_LOOKUP_ROUTE, record_exception=False, set_status_on_exception=False) as span:
        span.set_attribute("http.request.method", "GET")
        span.set_attribute("http.route", ORDER_LOOKUP_ROUTE)
        span.set_attribute("order.id", order_id)
        try:
            result = fetch_order(order_id)
            status_code = 200
            span.set_status(Status(StatusCode.OK))
            trace_id = format(span.get_span_context().trace_id, "032x")
            logger.info(
                "Order lookup succeeded",
                extra={
                    "order_id": order_id,
                    "status_code": status_code,
                    "trace_id": trace_id,
                    "route": ORDER_LOOKUP_ROUTE,
                },
            )
            return result
        except HTTPException as exc:
            status_code = exc.status_code
            trace_id = format(span.get_span_context().trace_id, "032x")
            if status_code >= 500:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR, str(exc)))
                logger.exception(
                    "Order lookup failed with server error",
                    extra={
                        "order_id": order_id,
                        "status_code": status_code,
                        "trace_id": trace_id,
                        "route": ORDER_LOOKUP_ROUTE,
                    },
                )
            else:
                logger.warning(
                    "Order lookup failed",
                    extra={
                        "order_id": order_id,
                        "status_code": status_code,
                        "trace_id": trace_id,
                        "route": ORDER_LOOKUP_ROUTE,
                    },
                )
            raise
        except Exception as exc:
            status_code = 500
            span.record_exception(exc)
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            trace_id = format(span.get_span_context().trace_id, "032x")
            logger.exception(
                "Order lookup failed unexpectedly",
                extra={
                    "order_id": order_id,
                    "status_code": status_code,
                    "trace_id": trace_id,
                    "route": ORDER_LOOKUP_ROUTE,
                },
            )
            raise HTTPException(500, "Internal server error") from exc
        finally:
            span.set_attribute("http.response.status_code", status_code)
            order_lookup_counter.add(
                1,
                {
                    "http.route": ORDER_LOOKUP_ROUTE,
                    "http.response.status_code": status_code,
                },
            )
            try:
                meter_provider.force_flush()
            except Exception:
                pass
            try:
                tracer_provider.force_flush()
            except Exception:
                pass
            try:
                logger_provider.force_flush()
            except Exception:
                pass


@app.post("/api/orders", status_code=201)
def create_order(order: NewOrder):
    if order.priority not in {"standard", "express"}:
        raise HTTPException(422, "Priority must be standard or express")
    order_id = str(uuid4())
    with connect() as db:
        db.execute(
            "INSERT INTO orders VALUES (?, ?, ?, ?, ?, ?)",
            (order_id, order.customer, order.item, order.priority, "received",
             datetime.now(timezone.utc).isoformat()),
        )
    return fetch_order(order_id)


@app.patch("/api/orders/{order_id}")
def update_status(order_id: str, update: StatusUpdate):
    if update.status not in STATUSES:
        raise HTTPException(422, "Invalid status")
    with connect() as db:
        cursor = db.execute(
            "UPDATE orders SET status = ? WHERE id = ?",
            (update.status, order_id),
        )
    if cursor.rowcount == 0:
        raise HTTPException(404, "Order not found")
    return fetch_order(order_id)
