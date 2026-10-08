from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from aiohttp import web

from .campaigns import CampaignAnalyzer
from .cloudflare_cleanup import CloudflareCleanupQueue
from .cloudflare_transactional import (
    CloudflareTransactionError,
    TransactionalCloudflareEnforcer,
)
from .production import ProductionDashboard
from .storage_health import DashboardStorageHealth, pre_migration_backup


class TransactionalProductionDashboard(ProductionDashboard):
    """Production dashboard with verified external state and storage protection."""

    def __init__(self) -> None:
        data_dir = Path(os.getenv("HOTPOT_DASHBOARD_DATA_DIR", "/data"))
        self.pre_migration_backup = pre_migration_backup(data_dir)
        super().__init__()
        self.cloudflare_cleanup = CloudflareCleanupQueue(data_dir)
        self.storage_health = DashboardStorageHealth(data_dir)
        self.campaigns = CampaignAnalyzer(data_dir)

    async def refresh(self) -> None:
        await super().refresh()
        storage = await self.storage_health.maybe_snapshot()
        campaigns = await self.campaigns.analyze(limit=20)
        async with self.cache_lock:
            self.cache["storage_health"] = storage
            self.cache.setdefault("database", {})["storage_health"] = storage
            if self.pre_migration_backup:
                self.cache["database"]["pre_migration_backup"] = dict(
                    self.pre_migration_backup
                )
            self.cache["campaigns"] = campaigns
            self.cache["campaign_policy"] = self.campaigns.public_policy()
            summary = self.cache.setdefault("summary", {})
            summary["active_campaigns"] = len(campaigns)
            summary["high_risk_campaigns"] = sum(
                1 for campaign in campaigns if int(campaign.get("max_level", 1)) >= 4
            )

    async def _run_system_check(self) -> dict[str, Any]:
        report = await super()._run_system_check()
        storage = await self.storage_health.maybe_snapshot(force=True)
        status_map = {"healthy": "pass", "warning": "warning", "critical": "fail"}
        report.setdefault("checks", []).append(
            {
                "id": "storage-health",
                "name": "SQLite / disk health",
                "status": status_map.get(str(storage.get("status")), "fail"),
                "detail": (
                    f"quick_check={storage.get('quick_check')}; "
                    f"free={storage.get('filesystem', {}).get('free_percent', 0)}%; "
                    f"db={storage.get('database', {}).get('size_bytes', 0)} bytes; "
                    f"wal={storage.get('database', {}).get('wal_size_bytes', 0)} bytes"
                ),
            }
        )
        checks = report["checks"]
        failed = sum(1 for item in checks if item.get("status") == "fail")
        warnings = sum(1 for item in checks if item.get("status") == "warning")
        passed = sum(1 for item in checks if item.get("status") == "pass")
        report["summary"] = {
            "passed": passed,
            "warnings": warnings,
            "failed": failed,
        }
        report["status"] = "fail" if failed else "warning" if warnings else "pass"
        report["storage_health"] = storage
        return report

    def _cloudflare_enforcer(self) -> TransactionalCloudflareEnforcer:
        if self.client is None:
            raise RuntimeError("dashboard HTTP client is not ready")
        return TransactionalCloudflareEnforcer(self.cloudflare, self.client)

    async def _record_transaction_audit(
        self,
        *,
        event_type: str,
        message: str,
        recommendation_id: str | None,
        status: str,
        details: dict[str, Any],
    ) -> None:
        recorder = getattr(self.store, "record_dashboard_action", None)
        if recorder is None:
            return
        await recorder(
            event_type=event_type,
            message=message,
            principal="system",
            session_id=None,
            recommendation_id=recommendation_id,
            status=status,
            details=details,
        )

    async def _apply_one(self, recommendation: dict[str, Any]) -> dict[str, Any]:
        recommendation_id = str(recommendation.get("recommendation_id") or "")
        try:
            rules = await self._cloudflare_enforcer().apply(recommendation)
        except CloudflareTransactionError as exc:
            queued = await self.cloudflare_cleanup.enqueue(
                recommendation_id, exc.residual_rules
            )
            await self._record_transaction_audit(
                event_type="cloudflare_rollback_residual",
                message="Cloudflare apply failed and rollback left residual rules",
                recommendation_id=recommendation_id or None,
                status="failed",
                details={
                    "cleanup_jobs_created": queued,
                    "residual_rules": exc.residual_rules,
                    "error": str(exc),
                },
            )
            failed = await self.store.mark_apply_failed(
                recommendation_id,
                f"{type(exc).__name__}: {exc}; cleanup_jobs={queued}",
            )
            return failed or recommendation
        except Exception as exc:
            failed = await self.store.mark_apply_failed(
                recommendation_id, f"{type(exc).__name__}: {exc}"
            )
            return failed or recommendation

        applied = await self.store.mark_applied(recommendation_id, rules)
        await self._record_transaction_audit(
            event_type="cloudflare_apply_verified",
            message="Cloudflare enforcement was created and verified",
            recommendation_id=recommendation_id or None,
            status="applied",
            details={"rules": rules},
        )
        return applied or recommendation

    async def _maybe_reconcile_cloudflare(
        self, *, force: bool = False
    ) -> dict[str, Any]:
        report = await super()._maybe_reconcile_cloudflare(force=force)
        jobs = await self.cloudflare_cleanup.pending(limit=100)
        return {
            **report,
            "rollback_cleanup_jobs": jobs,
            "rollback_cleanup_pending": len(jobs),
        }

    async def api_repair_enforcement(self, request: web.Request) -> web.Response:
        self.require_auth(request)
        if request.headers.get("X-Hotpot-Action", "") != "repair":
            raise web.HTTPBadRequest(
                text="X-Hotpot-Action: repair header is required"
            )
        if not self.cloudflare.configured:
            raise web.HTTPServiceUnavailable(
                text="Cloudflare enforcement is disabled or incomplete"
            )
        recommendation_id = request.match_info.get("recommendation_id", "").strip()
        recommendation = await self.store.recommendation(recommendation_id)
        if recommendation is None:
            raise web.HTTPNotFound(text="recommendation not found")
        if recommendation.get("status") not in {"applied", "failed", "approved"}:
            raise web.HTTPConflict(
                text="only approved/applied/failed enforcement can be repaired"
            )
        try:
            rules = await self._cloudflare_enforcer().repair(recommendation)
        except CloudflareTransactionError as exc:
            queued = await self.cloudflare_cleanup.enqueue(
                recommendation_id, exc.residual_rules
            )
            await self._record_transaction_audit(
                event_type="cloudflare_repair_failed",
                message="Cloudflare repair failed and left residual rules",
                recommendation_id=recommendation_id,
                status="failed",
                details={
                    "cleanup_jobs_created": queued,
                    "residual_rules": exc.residual_rules,
                    "error": str(exc),
                },
            )
            return web.json_response(
                {"error": str(exc), "cleanup_jobs_created": queued},
                status=502,
                headers={"Cache-Control": "no-store"},
            )
        except Exception as exc:
            return web.json_response(
                {"error": f"{type(exc).__name__}: {exc}"},
                status=502,
                headers={"Cache-Control": "no-store"},
            )

        result = await self.store.mark_applied(recommendation_id, rules)
        await self._record_transaction_audit(
            event_type="cloudflare_repaired",
            message="Cloudflare enforcement was repaired and verified",
            recommendation_id=recommendation_id,
            status="applied",
            details={"rules": rules},
        )
        await self._maybe_reconcile_cloudflare(force=True)
        await self._refresh_response_cache()
        return web.json_response(
            result or recommendation,
            headers={"Cache-Control": "no-store"},
        )

    async def api_remove_orphan(self, request: web.Request) -> web.Response:
        self.require_auth(request)
        if request.headers.get("X-Hotpot-Action", "") != "remove-orphan":
            raise web.HTTPBadRequest(
                text="X-Hotpot-Action: remove-orphan header is required"
            )
        if not self.cloudflare.can_remove:
            raise web.HTTPServiceUnavailable(
                text="Cloudflare API token is required to remove orphaned rules"
            )
        try:
            payload = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="JSON body is required") from exc
        if not isinstance(payload, dict):
            raise web.HTTPBadRequest(text="JSON body must be an object")
        rule = {
            "zone_id": str(payload.get("zone_id") or "").strip(),
            "ruleset_id": str(payload.get("ruleset_id") or "").strip(),
            "rule_id": str(payload.get("rule_id") or "").strip(),
            "ref": str(payload.get("ref") or "").strip(),
        }
        if not rule["zone_id"] or not rule["ruleset_id"] or not rule["rule_id"]:
            raise web.HTTPBadRequest(
                text="zone_id, ruleset_id, and rule_id are required"
            )
        try:
            await self._cloudflare_enforcer().remove_rule(rule)
        except Exception as exc:
            return web.json_response(
                {"removed": False, "error": f"{type(exc).__name__}: {exc}"},
                status=502,
                headers={"Cache-Control": "no-store"},
            )
        job_id = payload.get("cleanup_job_id")
        if job_id is not None:
            try:
                await self.cloudflare_cleanup.mark_removed(int(job_id))
            except (TypeError, ValueError):
                pass
        await self._record_transaction_audit(
            event_type="cloudflare_orphan_removed",
            message="Orphaned Cloudflare rule was removed and verified",
            recommendation_id=str(payload.get("recommendation_id") or "") or None,
            status="removed",
            details={"rule": rule, "cleanup_job_id": job_id},
        )
        await self._maybe_reconcile_cloudflare(force=True)
        await self._refresh_response_cache()
        return web.json_response(
            {"removed": True, "rule": rule},
            headers={"Cache-Control": "no-store"},
        )

    async def api_cleanup_jobs(self, request: web.Request) -> web.Response:
        self.require_auth(request)
        jobs = await self.cloudflare_cleanup.pending(limit=100)
        return web.json_response(
            {"count": len(jobs), "jobs": jobs},
            headers={"Cache-Control": "no-store"},
        )
