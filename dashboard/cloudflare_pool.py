from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

from .cloudflare_enforcement_legacy import CloudflareEnforcementError

POOL_PROVIDER = "custom_waf_pool"
POOL_REF_PREFIX = "hotpot_pool_"
POOL_MAX_EXPRESSION_CHARS = 3900

_POOL_ACTIONS = {
    "recommend_challenge": ("managed_challenge", "hotpot_pool_challenge"),
    "recommend_block": ("block", "hotpot_pool_block"),
}
_POOL_IP_RE = re.compile(r"ip\.src\s+in\s+\{([^}]*)\}")


def pool_definition(recommendation_action: str) -> tuple[str, str]:
    try:
        return _POOL_ACTIONS[recommendation_action]
    except KeyError as exc:
        raise CloudflareEnforcementError(
            "recommendation does not use a pooled WAF action"
        ) from exc


def _normalized_ip(value: str) -> str:
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError as exc:
        raise CloudflareEnforcementError("invalid IP enforcement target") from exc


def _ip_sort_key(value: str) -> tuple[int, int]:
    address = ipaddress.ip_address(value)
    return address.version, int(address)


def pool_members(expression: str | None) -> set[str]:
    match = _POOL_IP_RE.search(str(expression or ""))
    if match is None:
        raise CloudflareEnforcementError(
            "Hotpot pooled WAF rule has an unrecognized expression"
        )
    members: set[str] = set()
    for raw in match.group(1).split():
        token = raw.strip()
        if not token:
            continue
        members.add(_normalized_ip(token))
    return members


def pool_expression(members: set[str], hosts: tuple[str, ...]) -> str:
    normalized = sorted({_normalized_ip(value) for value in members}, key=_ip_sort_key)
    if not normalized:
        raise CloudflareEnforcementError("pooled WAF rule cannot have an empty IP set")
    if not hosts:
        raise CloudflareEnforcementError(
            "pooled WAF rule has no configured protected hostnames"
        )
    actor = "ip.src in {" + " ".join(normalized) + "}"
    host_expr = " or ".join(
        f"http.host eq {json.dumps(host, ensure_ascii=True)}"
        for host in sorted(set(hosts))
    )
    expression = f"({actor}) and ({host_expr})"
    if len(expression) > POOL_MAX_EXPRESSION_CHARS:
        raise CloudflareEnforcementError(
            "Hotpot pooled WAF expression would exceed the safe Cloudflare "
            f"limit ({len(expression)} > {POOL_MAX_EXPRESSION_CHARS} characters)"
        )
    return expression


class PooledWAFMixin:
    @staticmethod
    def _uses_pooled_waf(recommendation: dict[str, Any]) -> bool:
        return (
            str(recommendation.get("target_type") or "") == "ip"
            and str(recommendation.get("action") or "") in _POOL_ACTIONS
        )

    def _all_hosts_for_zone(self, zone_id: str) -> tuple[str, ...]:
        hosts: set[str] = set()
        for target in self.config.targets.values():
            if str(target.zone_id) == zone_id:
                hosts.update(target.hosts)
        return tuple(sorted(hosts))

    async def _pool_snapshot(
        self, zone_id: str, recommendation_action: str
    ) -> tuple[str, list[dict[str, Any]], dict[str, Any] | None]:
        _, ref = pool_definition(recommendation_action)
        ruleset_id, rules = await self._entrypoint_ruleset(zone_id)
        current = next(
            (row for row in rules if str(row.get("ref") or "") == ref),
            None,
        )
        return ruleset_id, rules, current

    @staticmethod
    def _pool_description(recommendation_action: str) -> str:
        if recommendation_action == "recommend_block":
            return "Hotpot pooled temporary IP blocks"
        return "Hotpot pooled managed challenges"

    async def _patch_pool_rule(
        self,
        *,
        zone_id: str,
        ruleset_id: str,
        rule_id: str,
        recommendation_action: str,
        expression: str,
        position: dict[str, Any] | None = None,
    ) -> None:
        action, ref = pool_definition(recommendation_action)
        payload: dict[str, Any] = {
            "action": action,
            "expression": expression,
            "description": self._pool_description(recommendation_action),
            "ref": ref,
            "enabled": True,
        }
        if position:
            payload["position"] = position
        await self._request(
            "PATCH",
            f"/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}",
            payload=payload,
        )

    async def _ensure_block_before_challenge(
        self, zone_id: str, ruleset_id: str
    ) -> None:
        inspected = await self.inspect_zone(zone_id)
        rules = list(inspected.get("rules") or [])
        block = next(
            (row for row in rules if str(row.get("ref") or "") == "hotpot_pool_block"),
            None,
        )
        challenge = next(
            (
                row
                for row in rules
                if str(row.get("ref") or "") == "hotpot_pool_challenge"
            ),
            None,
        )
        if block is None or challenge is None:
            return
        block_index = rules.index(block)
        challenge_index = rules.index(challenge)
        if block_index < challenge_index:
            return
        block_id = str(block.get("id") or "")
        challenge_id = str(challenge.get("id") or "")
        if not block_id or not challenge_id:
            return
        await self._patch_pool_rule(
            zone_id=zone_id,
            ruleset_id=ruleset_id,
            rule_id=block_id,
            recommendation_action="recommend_block",
            expression=str(block.get("expression") or ""),
            position={"before": challenge_id},
        )

    async def _apply_pooled_waf(
        self, recommendation: dict[str, Any]
    ) -> list[dict[str, Any]]:
        recommendation_action = str(recommendation.get("action") or "")
        action, ref = pool_definition(recommendation_action)
        target = _normalized_ip(str(recommendation.get("target_value") or ""))
        zones = self._targets_for_recommendation(recommendation)
        stored: list[dict[str, Any]] = []
        added: list[dict[str, Any]] = []

        try:
            for zone_id in zones:
                hosts = self._all_hosts_for_zone(zone_id)
                ruleset_id, rules, current = await self._pool_snapshot(
                    zone_id, recommendation_action
                )
                reused = current is not None
                membership_added = False
                if current is None:
                    members = {target}
                    expression = pool_expression(members, hosts)
                    payload: dict[str, Any] = {
                        "action": action,
                        "expression": expression,
                        "description": self._pool_description(recommendation_action),
                        "ref": ref,
                        "enabled": True,
                    }
                    if recommendation_action == "recommend_block":
                        challenge = next(
                            (
                                row
                                for row in rules
                                if str(row.get("ref") or "")
                                == "hotpot_pool_challenge"
                            ),
                            None,
                        )
                        challenge_id = str((challenge or {}).get("id") or "")
                        if challenge_id:
                            payload["position"] = {"before": challenge_id}
                    _, response = await self._request(
                        "POST",
                        f"/zones/{zone_id}/rulesets/{ruleset_id}/rules",
                        payload=payload,
                    )
                    result = (response or {}).get("result") or {}
                    rule_id = ""
                    for row in result.get("rules") or []:
                        if isinstance(row, dict) and str(row.get("ref") or "") == ref:
                            rule_id = str(row.get("id") or "")
                            break
                    if not rule_id:
                        inspected = await self.inspect_zone(zone_id)
                        current = next(
                            (
                                row
                                for row in inspected.get("rules") or []
                                if str(row.get("ref") or "") == ref
                            ),
                            None,
                        )
                        rule_id = str((current or {}).get("id") or "")
                    if not rule_id:
                        raise CloudflareEnforcementError(
                            "Cloudflare pooled rule creation omitted the new rule id"
                        )
                    membership_added = True
                else:
                    rule_id = str(current.get("id") or "")
                    if not rule_id:
                        raise CloudflareEnforcementError(
                            "existing Hotpot pooled rule omitted rule id"
                        )
                    if str(current.get("action") or "") != action:
                        raise CloudflareEnforcementError(
                            "existing Hotpot pooled rule action does not match expected action"
                        )
                    members = pool_members(current.get("expression"))
                    membership_added = target not in members
                    members.add(target)
                    expression = pool_expression(members, hosts)
                    if (
                        membership_added
                        or str(current.get("expression") or "") != expression
                        or current.get("enabled", True) is False
                    ):
                        await self._patch_pool_rule(
                            zone_id=zone_id,
                            ruleset_id=ruleset_id,
                            rule_id=rule_id,
                            recommendation_action=recommendation_action,
                            expression=expression,
                        )

                await self._ensure_block_before_challenge(zone_id, ruleset_id)
                item = self._stored_rule(
                    zone_id=zone_id,
                    ruleset_id=ruleset_id,
                    rule_id=rule_id,
                    action=action,
                    expression=expression,
                    hosts=hosts,
                    ref=ref,
                    reused=reused,
                    provider=POOL_PROVIDER,
                    target_value=target,
                    scope="configured-hostnames",
                    shared=True,
                    membership_added=membership_added,
                )
                stored.append(item)
                if membership_added:
                    added.append(item)
            return stored
        except Exception:
            for item in reversed(added):
                try:
                    await self._remove_pool_membership(item)
                except Exception:
                    pass
            raise

    async def _remove_pool_membership(self, rule: dict[str, Any]) -> None:
        zone_id = str(rule.get("zone_id") or "")
        ref = str(rule.get("ref") or "")
        target = str(rule.get("target_value") or "").strip()
        if not zone_id or not ref:
            raise CloudflareEnforcementError(
                "stored pooled WAF metadata is incomplete"
            )
        inspected = await self.inspect_zone(zone_id)
        ruleset_id = str(inspected.get("ruleset_id") or rule.get("ruleset_id") or "")
        current = next(
            (
                row
                for row in inspected.get("rules") or []
                if str(row.get("ref") or "") == ref
            ),
            None,
        )
        if current is None:
            return
        rule_id = str(current.get("id") or "")
        if not rule_id or not ruleset_id:
            raise CloudflareEnforcementError(
                "current pooled WAF rule metadata is incomplete"
            )
        if not target:
            await self._request(
                "DELETE",
                f"/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}",
                allow_404=True,
            )
            return

        target = _normalized_ip(target)
        members = pool_members(current.get("expression"))
        if target not in members:
            return
        members.remove(target)
        if not members:
            await self._request(
                "DELETE",
                f"/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}",
                allow_404=True,
            )
            return

        action = str(rule.get("pool_action") or "")
        if not action:
            action = (
                "recommend_block"
                if str(current.get("action") or "") == "block"
                else "recommend_challenge"
            )
        expression = pool_expression(members, self._all_hosts_for_zone(zone_id))
        await self._patch_pool_rule(
            zone_id=zone_id,
            ruleset_id=ruleset_id,
            rule_id=rule_id,
            recommendation_action=action,
            expression=expression,
        )
        await self._ensure_block_before_challenge(zone_id, ruleset_id)

    async def inspect_pool_rule(
        self, zone_id: str, ref: str
    ) -> tuple[dict[str, Any], set[str]] | None:
        inspected = await self.inspect_zone(zone_id)
        current = next(
            (
                row
                for row in inspected.get("rules") or []
                if str(row.get("ref") or "") == ref
            ),
            None,
        )
        if current is None:
            return None
        return current, pool_members(current.get("expression"))
