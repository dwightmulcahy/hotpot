from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from aiohttp import web

from .bot_intelligence import IPverseBotIntelligence
from .intelligence import actor_fingerprint, classify, escalation_for
from .store import AttackerState
from .wordpress_deception import (
    DeceptionSessions,
    WordPressPersona,
    tarpit_profile,
    velocity_severity_bonus,
)


class ProductionDeceptionMixin:
    """Production-safe WordPress deception and journey correlation.

    Hotpot's legacy base class owns the original deception implementation, but the
    production server overrides that path for durability, rate limiting, telemetry,
    and notification resilience. This mixin deliberately sits before HotpotServer in
    the MRO so the production path receives the same persona/session intelligence
    while retaining those production safeguards.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.wordpress_persona = WordPressPersona.load_or_create(self.settings.data_dir)
        self.deception_sessions = DeceptionSessions(timeout_seconds=900.0)
        self.bot_intelligence = IPverseBotIntelligence(self.settings.data_dir)
        self.stats["bot_verified"] = 0
        self.stats["bot_claimed"] = 0
        self.stats["bot_spoofed"] = 0

    async def startup(self, app: web.Application) -> None:
        await super().startup(app)
        await self.bot_intelligence.start()

    async def shutdown(self, app: web.Application) -> None:
        await self.bot_intelligence.stop()
        await super().shutdown(app)

    def _actor_fingerprint(self, request: web.Request, identity, classification) -> str:
        version = getattr(request, "version", None)
        http_version = ""
        if version is not None:
            http_version = f"HTTP/{version.major}.{version.minor}"
        return actor_fingerprint(
            actor_key=identity.actor_key,
            user_agent=request.headers.get("User-Agent", ""),
            scanner_family=classification.scanner_family,
            accept=request.headers.get("Accept", ""),
            accept_language=request.headers.get("Accept-Language", ""),
            accept_encoding=request.headers.get("Accept-Encoding", ""),
            http_version=http_version,
            source_type=identity.source_type,
            worker_zone=identity.worker_zone,
        )

    async def status(self, request: web.Request) -> web.Response:
        response = await super().status(request)
        payload: dict[str, Any] = (
            json.loads(response.body.decode("utf-8")) if response.body else {}
        )
        payload["wordpress_persona"] = {
            "version": self.wordpress_persona.wordpress_version,
            "php_version": self.wordpress_persona.php_version,
            "theme": self.wordpress_persona.theme,
            "locale": self.wordpress_persona.locale,
            "timezone": self.wordpress_persona.timezone,
        }
        payload["deception_correlation"] = {
            "session_timeout_seconds": int(self.deception_sessions.timeout_seconds),
            "journey_identity": "path-independent actor fingerprint",
            "request_identity": "path-specific behavioral fingerprint",
        }
        payload["bot_intelligence"] = self.bot_intelligence.status()
        return web.json_response(payload, headers={"Cache-Control": "no-store"})

    async def deception(self, request: web.Request, rule) -> web.StreamResponse:
        identity = self.client_identity(request)
        client_ip = identity.client_ip
        actor_key = identity.actor_key
        user_agent = request.headers.get("User-Agent", "")
        classification = classify(
            user_agent, rule.category, request.method, request.path_qs
        )
        bot_observation = self.bot_intelligence.identify(client_ip, user_agent)
        actor_fp = self._actor_fingerprint(request, identity, classification)
        observation = self.deception_sessions.observe(
            actor_fingerprint=actor_fp,
            request_fingerprint=classification.fingerprint,
            path=request.path_qs,
            rule_name=rule.name,
            category=rule.category,
            bait_id=rule.bait_id,
            bait_stage=rule.bait_stage,
        )
        severity = min(
            5,
            classification.severity
            + velocity_severity_bonus(observation)
            + (1 if bot_observation.spoofed else 0),
        )
        response_text = (
            self.wordpress_persona.render(rule.name, rule.response)
            if rule.profile == "wordpress"
            else rule.response
        )

        now = time.monotonic()
        persist_event = True
        suppressed_before = 0
        prior = AttackerState(actor_key, 0, 0, None, None, None, None, 1)
        profile: dict[str, Any] | None = None
        try:
            async with self.intelligence_lock:
                cached = self.runtime_attackers.get(actor_key)
                if cached is None:
                    try:
                        prior = await self.store.state_for(actor_key)
                    except Exception:
                        self.stats["telemetry_errors"] += 1
                        self.stats["sqlite_read_errors"] += 1
                    prior_hits = prior.hits
                    prior_score = prior.score
                else:
                    prior_hits, prior_score, _ = cached

                escalation = escalation_for(
                    prior_hits=prior_hits,
                    prior_score=prior_score,
                    severity=severity,
                    base_seconds=self.settings.tarpit_max_seconds,
                    max_escalated_seconds=self.settings.tarpit_escalated_max_seconds,
                )
                observed_hits = prior_hits + 1
                self.runtime_attackers[actor_key] = (
                    observed_hits,
                    escalation.score,
                    now,
                )

                effective_action = rule.action
                if escalation.force_tarpit and self.settings.tarpit_enabled:
                    effective_action = "tarpit"

                if effective_action == "tarpit" and self.settings.tarpit_enabled:
                    profile = tarpit_profile(
                        rule_name=rule.name,
                        observation=observation,
                        fingerprint=classification.fingerprint,
                        base_initial=self.settings.tarpit_initial_delay,
                        base_chunk_delay=self.settings.tarpit_chunk_delay,
                    )

                persist_event, suppressed_before = self.event_limiter.admit(
                    actor_key, now=now
                )
                event = {
                    "event": "deception",
                    "client_ip": client_ip,
                    "attacker_key": actor_key,
                    "actor_fingerprint": actor_fp,
                    "source_type": identity.source_type,
                    "worker_zone": identity.worker_zone,
                    "proxy_ip": identity.proxy_ip,
                    "client_ip_source": identity.source,
                    "trusted_proxy": identity.trusted_proxy,
                    "method": request.method,
                    "path": request.path_qs,
                    "host": request.host,
                    "user_agent": user_agent,
                    "referer": request.headers.get("Referer", ""),
                    "profile": rule.profile,
                    "rule": rule.name,
                    "category": rule.category,
                    "action": effective_action,
                    "rule_action": rule.action,
                    "scanner": classification.scanner,
                    "scanner_family": classification.scanner_family,
                    "fingerprint": classification.fingerprint,
                    "severity": severity,
                    "base_severity": classification.severity,
                    "escalation_level": escalation.level,
                    "attacker_score": escalation.score,
                    "prior_hits": prior_hits,
                    "observed_hits": observed_hits,
                    "session_id": observation["session_id"],
                    "session_step": observation["session_step"],
                    "hits_10s": observation["hits_10s"],
                    "hits_60s": observation["hits_60s"],
                    "unique_paths_60s": observation["unique_paths_60s"],
                    "bait_id": observation["bait_id"],
                    "bait_stage": observation["bait_stage"],
                    "bait_followed": observation["bait_followed"],
                    "tarpit_style": profile["style"] if profile else None,
                    "content_type": request.headers.get("Content-Type", ""),
                    "content_length": request.content_length,
                    "query_parameter_names": sorted(request.query.keys()),
                    **bot_observation.event_fields(),
                }
                if suppressed_before:
                    event["suppressed_before"] = suppressed_before
                if persist_event:
                    try:
                        await self.store.record(
                            event,
                            score=escalation.score,
                            escalation_level=escalation.level,
                        )
                    except Exception:
                        self.stats["telemetry_errors"] += 1
                        self.stats["sqlite_write_errors"] += 1
                else:
                    self.stats["events_suppressed_total"] += 1
        except Exception:
            effective_action = rule.action
            event = {
                "event": "deception",
                "client_ip": client_ip,
                "attacker_key": actor_key,
                "actor_fingerprint": actor_fp,
                "source_type": identity.source_type,
                "worker_zone": identity.worker_zone,
                "method": request.method,
                "path": request.path_qs,
                "profile": rule.profile,
                "rule": rule.name,
                "category": rule.category,
                "action": effective_action,
                "scanner": classification.scanner,
                "scanner_family": classification.scanner_family,
                "fingerprint": classification.fingerprint,
                "severity": severity,
                "base_severity": classification.severity,
                "escalation_level": 1,
                "attacker_score": severity,
                "prior_hits": 0,
                "observed_hits": 1,
                "session_id": observation["session_id"],
                "session_step": observation["session_step"],
                "hits_10s": observation["hits_10s"],
                "hits_60s": observation["hits_60s"],
                "unique_paths_60s": observation["unique_paths_60s"],
                "bait_id": observation["bait_id"],
                "bait_stage": observation["bait_stage"],
                "bait_followed": observation["bait_followed"],
                "tarpit_style": None,
                **bot_observation.event_fields(),
            }
            self.stats["telemetry_errors"] += 1
            escalation = type(
                "FallbackEscalation",
                (),
                {"level": 1, "tarpit_seconds": self.settings.tarpit_max_seconds},
            )()
            persist_event = True

        self.stats["deceptions"] += 1
        self.stats[f"category:{rule.category}"] += 1
        self.stats[f"scanner:{classification.scanner}"] += 1
        self.stats[f"escalation:{event.get('escalation_level', 1)}"] += 1
        if observation["bait_stage"]:
            self.stats[f"bait:{observation['bait_stage']}"] += 1
        if bot_observation.claimed_identity:
            self.stats["bot_claimed"] += 1
        if bot_observation.verified:
            self.stats["bot_verified"] += 1
        if bot_observation.spoofed:
            self.stats["bot_spoofed"] += 1
        if identity.source_type == "cloudflare-worker":
            self.stats["cloudflare_worker_events"] += 1
        if persist_event:
            self.stats["events_persisted_total"] += 1
            await self._safe_event_write(event)
            await self.maybe_notify(event)

        self.deceptions_since_prune += 1
        if self.deceptions_since_prune >= 1024:
            self._prune_runtime_attackers(now=now)
            self.deceptions_since_prune = 0

        if effective_action == "tarpit" and self.settings.tarpit_enabled:
            if profile is None:
                profile = tarpit_profile(
                    rule_name=rule.name,
                    observation=observation,
                    fingerprint=classification.fingerprint,
                    base_initial=self.settings.tarpit_initial_delay,
                    base_chunk_delay=self.settings.tarpit_chunk_delay,
                )
            return await self.tarpit(
                request,
                rule,
                response_text=response_text,
                max_seconds=escalation.tarpit_seconds,
                profile=profile,
            )

        return web.Response(
            status=rule.status,
            text=response_text,
            content_type=rule.content_type.split(";", 1)[0],
        )

    async def tarpit(
        self,
        request: web.Request,
        rule,
        *,
        response_text: str | None = None,
        max_seconds: float | None = None,
        profile: dict[str, Any] | None = None,
    ) -> web.StreamResponse:
        try:
            await asyncio.wait_for(self.tarpit_slots.acquire(), timeout=0.05)
        except TimeoutError:
            self.stats["tarpit_overflow"] += 1
            return web.Response(
                status=rule.status,
                text=response_text if response_text is not None else rule.response,
                content_type=rule.content_type.split(";", 1)[0],
            )

        self.stats["tarpits_total"] += 1
        self.stats["tarpits_active"] += 1
        started = time.monotonic()
        disconnected = False
        profile = profile or {
            "style": "chunked-drip",
            "initial_delay": self.settings.tarpit_initial_delay,
            "chunk_delay": self.settings.tarpit_chunk_delay,
            "chunk_size": 32,
        }
        try:
            await asyncio.sleep(float(profile["initial_delay"]))
            resp = web.StreamResponse(status=rule.status)
            resp.headers["Content-Type"] = rule.content_type
            await resp.prepare(request)
            body = (response_text if response_text is not None else rule.response).encode(
                "utf-8"
            ) or b" "
            pos = 0
            lifetime = (
                max_seconds
                if max_seconds is not None
                else self.settings.tarpit_max_seconds
            )
            while time.monotonic() - started < lifetime:
                chunk_size = max(1, int(profile["chunk_size"]))
                chunk = body[pos : pos + chunk_size]
                if not chunk:
                    pos = 0
                    chunk = b" "
                else:
                    pos += len(chunk)
                try:
                    await resp.write(chunk)
                except (ConnectionResetError, RuntimeError):
                    disconnected = True
                    break
                await asyncio.sleep(float(profile["chunk_delay"]))
            try:
                await resp.write_eof()
            except (ConnectionResetError, RuntimeError):
                disconnected = True
            return resp
        finally:
            self.stats["tarpits_active"] = max(
                0, self.stats["tarpits_active"] - 1
            )
            self.stats[
                "tarpits_disconnected" if disconnected else "tarpits_completed"
            ] += 1
            self.tarpit_slots.release()
