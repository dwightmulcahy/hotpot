from __future__ import annotations

import math
import time
from typing import Any, Iterable

PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def _escape_label(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _number(value: Any) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = 0.0
    if not math.isfinite(number):
        number = 0.0
    if number.is_integer():
        return str(int(number))
    return format(number, ".12g")


def _sample(name: str, value: Any, labels: dict[str, Any] | None = None) -> str:
    if labels:
        rendered = ",".join(
            f'{key}="{_escape_label(label)}"' for key, label in sorted(labels.items())
        )
        return f"{name}{{{rendered}}} {_number(value)}"
    return f"{name} {_number(value)}"


def _metric(
    name: str,
    help_text: str,
    metric_type: str,
    samples: Iterable[tuple[Any, dict[str, Any] | None]],
) -> list[str]:
    lines = [f"# HELP {name} {help_text}", f"# TYPE {name} {metric_type}"]
    lines.extend(_sample(name, value, labels) for value, labels in samples)
    return lines


async def render_prometheus(server: Any) -> str:
    """Render a compact Prometheus/OpenMetrics-compatible snapshot.

    Hotpot intentionally exposes cumulative counters where possible. The dashboard
    derives rates and long-window trends from these counters instead of resetting
    counters inside the request path.
    """

    instance = str(server.settings.instance_id)
    labels = {"instance": instance}
    stats = server.stats
    resources = server.resources.snapshot()
    queue = server.telemetry_queue.snapshot()
    spool = await server.notification_spool.snapshot()
    upstream = server.upstream_health

    lines: list[str] = []
    lines += _metric(
        "hotpot_up",
        "Whether the configured upstream is currently healthy.",
        "gauge",
        [(1 if upstream.get("healthy") else 0, labels)],
    )
    lines += _metric(
        "hotpot_uptime_seconds",
        "Hotpot process uptime in seconds.",
        "gauge",
        [(max(0.0, time.monotonic() - server.started), labels)],
    )
    lines += _metric(
        "hotpot_proxy_requests_total",
        "Requests proxied to the protected upstream.",
        "counter",
        [(stats.get("proxied", 0), labels)],
    )
    lines += _metric(
        "hotpot_deception_events_total",
        "Requests handled by Hotpot deception rules.",
        "counter",
        [(stats.get("deceptions", 0), labels)],
    )
    lines += _metric(
        "hotpot_tarpits_active",
        "Currently active tarpit responses.",
        "gauge",
        [(stats.get("tarpits_active", 0), labels)],
    )
    lines += _metric(
        "hotpot_tarpits_total",
        "Total tarpit responses started.",
        "counter",
        [(stats.get("tarpits_total", 0), labels)],
    )
    lines += _metric(
        "hotpot_escalation_events_total",
        "Deception events by escalation level.",
        "counter",
        [
            (stats.get(f"escalation:{level}", 0), {**labels, "level": str(level)})
            for level in range(1, 5)
        ],
    )
    lines += _metric(
        "hotpot_upstream_failures_total",
        "Upstream proxy or health-check failures observed by Hotpot.",
        "counter",
        [
            (
                int(stats.get("upstream_errors", 0))
                + int(stats.get("healthcheck_errors", 0)),
                labels,
            )
        ],
    )
    lines += _metric(
        "hotpot_upstream_latency_milliseconds",
        "Latency of the most recent upstream health probe.",
        "gauge",
        [(upstream.get("latency_ms") or 0, labels)],
    )
    lines += _metric(
        "hotpot_telemetry_queue_depth",
        "Current in-memory auxiliary telemetry queue depth.",
        "gauge",
        [(queue.get("depth", 0), labels)],
    )
    lines += _metric(
        "hotpot_telemetry_queue_capacity",
        "Maximum in-memory auxiliary telemetry queue capacity.",
        "gauge",
        [(queue.get("capacity", 0), labels)],
    )
    lines += _metric(
        "hotpot_telemetry_queue_dropped_total",
        "Auxiliary telemetry work dropped because the bounded queue was full.",
        "counter",
        [(queue.get("dropped", 0), labels)],
    )
    lines += _metric(
        "hotpot_notification_spool_pending",
        "Durable notification jobs waiting for retry.",
        "gauge",
        [(spool.get("pending", 0), labels)],
    )
    lines += _metric(
        "hotpot_resource_active",
        "Current usage of a global Hotpot resource budget.",
        "gauge",
        [
            (resources.get("upstream_active", 0), {**labels, "resource": "upstream"}),
            (resources.get("websocket_active", 0), {**labels, "resource": "websocket"}),
            (
                resources.get("buffered_body_bytes", 0),
                {**labels, "resource": "buffered_body_bytes"},
            ),
        ],
    )
    lines += _metric(
        "hotpot_resource_capacity",
        "Configured capacity of a global Hotpot resource budget.",
        "gauge",
        [
            (
                resources.get("max_upstream_concurrent", 0),
                {**labels, "resource": "upstream"},
            ),
            (
                resources.get("max_websockets", 0),
                {**labels, "resource": "websocket"},
            ),
            (
                resources.get("max_buffered_body_bytes", 0),
                {**labels, "resource": "buffered_body_bytes"},
            ),
        ],
    )
    lines += _metric(
        "hotpot_resource_rejections_total",
        "Requests rejected by a global Hotpot resource budget.",
        "counter",
        [
            (
                resources.get("rejected_upstream", 0),
                {**labels, "resource": "upstream"},
            ),
            (
                resources.get("rejected_websocket", 0),
                {**labels, "resource": "websocket"},
            ),
            (
                resources.get("rejected_buffer", 0),
                {**labels, "resource": "buffered_body_bytes"},
            ),
        ],
    )
    lines += _metric(
        "hotpot_telemetry_errors_total",
        "Telemetry/storage errors observed without interrupting proxy traffic.",
        "counter",
        [(stats.get("telemetry_errors", 0), labels)],
    )
    return "\n".join(lines) + "\n"
