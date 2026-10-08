from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


def _parse_ts(value: str) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _path_family(path: str) -> str:
    raw = str(path or "").strip()
    if not raw:
        return "/"
    try:
        parsed = urlsplit(raw)
        value = parsed.path or "/"
    except ValueError:
        value = raw.split("?", 1)[0] or "/"
    parts = [part for part in value.split("/") if part]
    if not parts:
        return "/"
    # Scanner campaigns tend to vary filenames/IDs under a stable first segment.
    # Retaining at most two segments gives useful grouping without IP/geography.
    return "/" + "/".join(parts[:2]).lower()


def _clean(value: Any) -> str:
    raw = str(value or "").strip().lower()
    return "" if raw in {"", "unknown", "none", "n/a"} else raw


@dataclass
class _Campaign:
    signature: str
    label: str
    first_seen: datetime
    last_seen: datetime
    actors: set[str] = field(default_factory=set)
    source_ips: set[str] = field(default_factory=set)
    apps: set[str] = field(default_factory=set)
    categories: set[str] = field(default_factory=set)
    scanners: set[str] = field(default_factory=set)
    fingerprints: set[str] = field(default_factory=set)
    paths: dict[str, int] = field(default_factory=dict)
    hits: int = 0
    persisted_events: int = 0
    max_level: int = 1
    max_severity: int = 1

    def add(self, event: dict[str, Any], ts: datetime) -> None:
        self.first_seen = min(self.first_seen, ts)
        self.last_seen = max(self.last_seen, ts)
        actor = str(event.get("attacker_key") or event.get("client_ip") or "").strip()
        if actor:
            self.actors.add(actor)
        ip = str(event.get("client_ip") or "").strip()
        if ip:
            self.source_ips.add(ip)
        app = str(event.get("instance_name") or event.get("instance_id") or "").strip()
        if app:
            self.apps.add(app)
        category = str(event.get("category") or "").strip()
        if category:
            self.categories.add(category)
        scanner = str(
            event.get("scanner_family") or event.get("scanner") or ""
        ).strip()
        if scanner:
            self.scanners.add(scanner)
        fingerprint = str(event.get("fingerprint") or "").strip()
        if fingerprint:
            self.fingerprints.add(fingerprint)
        path = str(event.get("path") or "").strip()
        if path:
            self.paths[path] = self.paths.get(path, 0) + 1
        self.persisted_events += 1
        self.hits += 1 + max(0, int(event.get("suppressed_before", 0) or 0))
        self.max_level = max(
            self.max_level, int(event.get("escalation_level", 1) or 1)
        )
        self.max_severity = max(
            self.max_severity, int(event.get("severity", 1) or 1)
        )

    def as_dict(self) -> dict[str, Any]:
        seed = f"{self.signature}|{self.first_seen.isoformat()}"
        campaign_id = "campaign_" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
        top_paths = sorted(
            self.paths.items(), key=lambda item: (-item[1], item[0])
        )[:8]
        return {
            "campaign_id": campaign_id,
            "label": self.label,
            "signature": self.signature,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "duration_seconds": max(
                0, int((self.last_seen - self.first_seen).total_seconds())
            ),
            "actor_count": len(self.actors),
            "actors": sorted(self.actors)[:50],
            "source_ip_count": len(self.source_ips),
            "source_ips": sorted(self.source_ips)[:50],
            "app_count": len(self.apps),
            "apps": sorted(self.apps),
            "categories": sorted(self.categories),
            "scanners": sorted(self.scanners),
            "fingerprints": sorted(self.fingerprints)[:20],
            "hits": self.hits,
            "persisted_events": self.persisted_events,
            "max_level": self.max_level,
            "max_severity": self.max_severity,
            "top_paths": [
                {"path": path, "hits": hits} for path, hits in top_paths
            ],
            "scoring_effect": "none",
            "network_geography_used": False,
        }


class CampaignAnalyzer:
    """Correlate distributed scanner activity without changing actor scores."""

    def __init__(self, data_dir: Path) -> None:
        self.path = data_dir / "dashboard.sqlite3"
        self.lookback_hours = max(
            1, min(168, int(os.getenv("HOTPOT_CAMPAIGN_LOOKBACK_HOURS", "24")))
        )
        self.window_minutes = max(
            5, min(360, int(os.getenv("HOTPOT_CAMPAIGN_WINDOW_MINUTES", "60")))
        )
        self.min_actors = max(
            2, int(os.getenv("HOTPOT_CAMPAIGN_MIN_ACTORS", "2"))
        )
        self.min_hits = max(2, int(os.getenv("HOTPOT_CAMPAIGN_MIN_HITS", "5")))
        self.max_events = max(
            100, min(100000, int(os.getenv("HOTPOT_CAMPAIGN_MAX_EVENTS", "10000")))
        )

    @staticmethod
    def signature(event: dict[str, Any]) -> tuple[str, str]:
        category = _clean(event.get("category")) or "uncategorized"
        fingerprint = _clean(event.get("fingerprint"))
        scanner = _clean(event.get("scanner_family")) or _clean(event.get("scanner"))
        family = _path_family(str(event.get("path") or ""))
        if fingerprint:
            return (
                f"fingerprint:{fingerprint}|category:{category}",
                f"{scanner or 'scanner'} · {category}",
            )
        if scanner:
            return (
                f"scanner:{scanner}|category:{category}|path:{family}",
                f"{scanner} · {category}",
            )
        return (
            f"category:{category}|path:{family}",
            f"distributed probes · {category}",
        )

    async def analyze(self, limit: int = 20) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self._analyze_sync, limit)

    def _analyze_sync(self, limit: int) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.lookback_hours)
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                """
                SELECT instance_id, instance_name, event_id, ts, client_ip,
                       method, path, category, action, scanner, severity,
                       escalation_level, attacker_score, payload_json
                FROM events
                WHERE ts >= ?
                ORDER BY ts ASC, instance_id ASC, event_id ASC
                LIMIT ?
                """,
                (cutoff.isoformat(), self.max_events),
            ).fetchall()
        finally:
            conn.close()

        groups: dict[str, list[_Campaign]] = {}
        gap = timedelta(minutes=self.window_minutes)
        for row in rows:
            event = dict(row)
            try:
                payload = json.loads(event.pop("payload_json") or "{}")
                if isinstance(payload, dict):
                    event.update(payload)
            except (TypeError, json.JSONDecodeError):
                pass
            # Keep central app identity authoritative if payload omitted it.
            event.setdefault("instance_id", row["instance_id"])
            event.setdefault("instance_name", row["instance_name"])
            event.setdefault("client_ip", row["client_ip"])
            ts = _parse_ts(str(event.get("ts") or row["ts"]))
            if ts is None:
                continue
            signature, label = self.signature(event)
            buckets = groups.setdefault(signature, [])
            current = buckets[-1] if buckets else None
            if current is None or ts - current.last_seen > gap:
                current = _Campaign(signature, label, ts, ts)
                buckets.append(current)
            current.add(event, ts)

        campaigns = [
            campaign.as_dict()
            for buckets in groups.values()
            for campaign in buckets
            if len(campaign.actors) >= self.min_actors
            and campaign.hits >= self.min_hits
        ]
        campaigns.sort(
            key=lambda item: (
                int(item["max_level"]),
                int(item["hits"]),
                int(item["actor_count"]),
                str(item["last_seen"]),
            ),
            reverse=True,
        )
        return campaigns[: max(1, min(100, int(limit)))]

    def public_policy(self) -> dict[str, Any]:
        return {
            "lookback_hours": self.lookback_hours,
            "window_minutes": self.window_minutes,
            "min_actors": self.min_actors,
            "min_hits": self.min_hits,
            "max_events": self.max_events,
            "scoring_effect": "none",
            "network_geography_used": False,
        }
