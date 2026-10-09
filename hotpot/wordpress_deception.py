from __future__ import annotations

import hashlib
import json
import random
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class WordPressPersona:
    wordpress_version: str
    php_version: str
    theme: str
    site_name: str
    site_url: str
    locale: str
    timezone: str
    canary_path: str

    @classmethod
    def load_or_create(cls, data_dir: Path) -> "WordPressPersona":
        path = data_dir / "wordpress-persona.json"
        if path.exists():
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                return cls(**raw)
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                pass
        persona = cls(
            wordpress_version="6.4.3",
            php_version="8.1.27",
            theme="twentytwentythree",
            site_name="Monkey Head Brewing",
            site_url="https://www.monkeyheadbrewing.com",
            locale="en_US",
            timezone="America/Costa_Rica",
            canary_path="/wp-content/uploads/.cache/wp-maintenance.json",
        )
        try:
            path.write_text(json.dumps(persona.__dict__, indent=2, sort_keys=True), encoding="utf-8")
        except OSError:
            pass
        return persona

    def render(self, rule_name: str, fallback: str) -> str:
        p = self
        if rule_name == "wordpress-rest-api":
            return json.dumps({
                "name": p.site_name,
                "description": "",
                "url": p.site_url,
                "home": p.site_url,
                "namespaces": ["oembed/1.0", "wp/v2", "contact-form-7/v1"],
                "authentication": {},
                "_links": {"help": [{"href": p.site_url + p.canary_path}]},
            }, separators=(",", ":"))
        if rule_name == "wordpress-rest-users":
            return json.dumps([{
                "id": 1,
                "name": "admin",
                "slug": "admin",
                "link": p.site_url + "/author/admin/",
            }], separators=(",", ":"))
        if rule_name == "wordpress-rest-posts":
            return json.dumps([{
                "id": 42,
                "date": "2026-09-28T10:15:00",
                "slug": "oktoberfest",
                "status": "publish",
                "link": p.site_url + "/oktoberfest/",
                "title": {"rendered": "Oktoberfest"},
                "author": 1,
            }], separators=(",", ":"))
        if rule_name == "wordpress-readme":
            return (
                "<!doctype html><html><head><meta charset='UTF-8'><title>WordPress › ReadMe</title></head>"
                f"<body><h1>WordPress</h1><p>Semantic Personal Publishing Platform</p><p>Version {p.wordpress_version}</p></body></html>"
            )
        if rule_name == "wordpress-theme-style":
            return (
                f"/*\nTheme Name: Twenty Twenty-Three\nVersion: 1.4\nText Domain: {p.theme}\n"
                f"Requires PHP: 5.6\nTested with: {p.wordpress_version}\n*/\n"
            )
        if rule_name == "wordpress-sitemap":
            return (
                "<?xml version='1.0' encoding='UTF-8'?><sitemapindex xmlns='http://www.sitemaps.org/schemas/sitemap/0.9'>"
                f"<sitemap><loc>{p.site_url}/wp-sitemap-posts-post-1.xml</loc></sitemap></sitemapindex>"
            )
        if rule_name == "wordpress-feed":
            return (
                "<?xml version='1.0' encoding='UTF-8'?><rss version='2.0'><channel>"
                f"<title>{p.site_name}</title><link>{p.site_url}</link><generator>https://wordpress.org/?v={p.wordpress_version}</generator>"
                "</channel></rss>"
            )
        if rule_name == "wordpress-author-enum":
            return f"<!doctype html><title>admin – {p.site_name}</title><h1 class='author-title'>admin</h1>"
        if rule_name == "wordpress-canary":
            return json.dumps({"maintenance": False, "generated_by": "wp-cron"}, separators=(",", ":"))
        return fallback


@dataclass
class SessionState:
    session_id: str
    last_seen: float
    step: int = 0
    recent: deque[tuple[float, str]] = field(default_factory=deque)
    discovered_baits: set[str] = field(default_factory=set)


class DeceptionSessions:
    def __init__(self, timeout_seconds: float = 900.0):
        self.timeout_seconds = timeout_seconds
        self._sessions: dict[str, SessionState] = {}

    def observe(self, *, ip: str, fingerprint: str, path: str, rule_name: str, category: str) -> dict[str, Any]:
        now = time.monotonic()
        # The request fingerprint intentionally contains the path, so it is unsuitable
        # as the primary session key. Source IP keeps a scanner journey coherent across
        # endpoint changes; the fingerprint remains recorded on every event for analysis.
        key = ip
        state = self._sessions.get(key)
        if state is None or now - state.last_seen > self.timeout_seconds:
            session_id = hashlib.sha256(f"{ip}|{fingerprint}|{time.time_ns()}".encode()).hexdigest()[:16]
            state = SessionState(session_id=session_id, last_seen=now)
            self._sessions[key] = state
        state.last_seen = now
        state.step += 1
        state.recent.append((now, path))
        cutoff = now - 60.0
        while state.recent and state.recent[0][0] < cutoff:
            state.recent.popleft()

        hits_10s = sum(1 for ts, _ in state.recent if ts >= now - 10.0)
        hits_60s = len(state.recent)
        unique_paths_60s = len({p for _, p in state.recent})

        bait_id = self._bait_id(rule_name)
        bait_stage = None
        bait_followed = False
        if category == "wordpress-vulnerability-bait" and bait_id:
            state.discovered_baits.add(bait_id)
            bait_stage = "discovered"
        elif category == "wordpress-bait-followup" and bait_id:
            bait_followed = bait_id in state.discovered_baits
            bait_stage = "exploit-attempt" if bait_followed else "interacted"
        elif rule_name == "wordpress-canary":
            bait_id = "wordpress-canary"
            bait_stage = "canary-followed"
            bait_followed = True

        return {
            "session_id": state.session_id,
            "session_step": state.step,
            "hits_10s": hits_10s,
            "hits_60s": hits_60s,
            "unique_paths_60s": unique_paths_60s,
            "bait_id": bait_id,
            "bait_stage": bait_stage,
            "bait_followed": bait_followed,
        }

    @staticmethod
    def _bait_id(rule_name: str) -> str | None:
        if "file-manager" in rule_name:
            return "wp-file-manager-legacy"
        if "contact-form-7" in rule_name:
            return "contact-form-7-legacy"
        return None


def velocity_severity_bonus(observation: dict[str, Any]) -> int:
    if observation["hits_10s"] >= 8 or observation["unique_paths_60s"] >= 12:
        return 2
    if observation["hits_10s"] >= 4 or observation["unique_paths_60s"] >= 6:
        return 1
    return 0


def tarpit_profile(*, rule_name: str, observation: dict[str, Any], fingerprint: str,
                   base_initial: float, base_chunk_delay: float) -> dict[str, Any]:
    seed = int(hashlib.sha256(f"{fingerprint}|{rule_name}".encode()).hexdigest()[:8], 16)
    rng = random.Random(seed)
    aggressive = observation["hits_10s"] >= 6 or observation["bait_stage"] in {"exploit-attempt", "canary-followed"}
    if "xmlrpc" in rule_name:
        style = "fake-processing"
        initial = max(base_initial, 1.5)
        chunk = max(base_chunk_delay, 1.2)
        size = 24
    elif aggressive:
        style = "burst-then-stall"
        initial = max(base_initial, 0.25)
        chunk = max(base_chunk_delay, 3.0)
        size = 64
    elif "login" in rule_name or "install" in rule_name:
        style = "slow-headers"
        initial = max(base_initial, 2.0)
        chunk = max(base_chunk_delay, 1.5)
        size = 24
    else:
        style = "chunked-drip"
        initial = base_initial
        chunk = base_chunk_delay
        size = 32
    return {
        "style": style,
        "initial_delay": initial * rng.uniform(0.85, 1.15),
        "chunk_delay": chunk * rng.uniform(0.80, 1.25),
        "chunk_size": size,
    }
