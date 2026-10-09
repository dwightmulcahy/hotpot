from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Classification:
    scanner: str
    scanner_family: str
    fingerprint: str
    severity: int


_SCANNERS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"wpscan", re.I), "WPScan", "wordpress-scanner"),
    (re.compile(r"nikto", re.I), "Nikto", "web-vulnerability-scanner"),
    (re.compile(r"sqlmap", re.I), "sqlmap", "injection-scanner"),
    (re.compile(r"nuclei", re.I), "Nuclei", "template-scanner"),
    (re.compile(r"acunetix", re.I), "Acunetix", "web-vulnerability-scanner"),
    (re.compile(r"nessus", re.I), "Nessus", "vulnerability-scanner"),
    (re.compile(r"openvas|greenbone", re.I), "OpenVAS/Greenbone", "vulnerability-scanner"),
    (re.compile(r"gobuster", re.I), "Gobuster", "content-discovery"),
    (re.compile(r"dirbuster", re.I), "DirBuster", "content-discovery"),
    (re.compile(r"dirsearch", re.I), "dirsearch", "content-discovery"),
    (re.compile(r"ffuf", re.I), "ffuf", "content-discovery"),
    (re.compile(r"zgrab", re.I), "zgrab", "internet-scanner"),
    (re.compile(r"masscan", re.I), "masscan", "internet-scanner"),
    (re.compile(r"censys", re.I), "Censys", "internet-scanner"),
    (re.compile(r"shodan", re.I), "Shodan", "internet-scanner"),
)


def classify(user_agent: str, category: str, method: str, path: str) -> Classification:
    scanner = "unknown"
    family = "unknown"
    for pattern, name, scanner_family in _SCANNERS:
        if pattern.search(user_agent):
            scanner = name
            family = scanner_family
            break

    # These are deliberately broad labels only after a deception rule already matched.
    if scanner == "unknown":
        ua = user_agent.lower()
        if "python-requests" in ua or "aiohttp" in ua:
            scanner, family = "Python HTTP client", "scripted-client"
        elif ua.startswith("curl/") or ua.startswith("wget/"):
            scanner, family = "CLI HTTP client", "scripted-client"
        elif not user_agent.strip():
            scanner, family = "No User-Agent", "minimal-client"

    severity = _severity(category, method)
    normalized_ua = _normalize_user_agent(user_agent)
    material = f"{method.upper()}|{category}|{path.split('?', 1)[0]}|{family}|{normalized_ua}"
    fingerprint = hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:16]
    return Classification(
        scanner=scanner,
        scanner_family=family,
        fingerprint=fingerprint,
        severity=severity,
    )


def actor_fingerprint(
    *,
    actor_key: str,
    user_agent: str,
    scanner_family: str,
    accept: str = "",
    accept_language: str = "",
    accept_encoding: str = "",
    http_version: str = "",
    source_type: str = "ip",
    worker_zone: str | None = None,
) -> str:
    """Return a path-independent correlation fingerprint for one observed actor.

    The existing request fingerprint intentionally includes method/category/path and is
    useful for grouping repeated probes. Journey correlation needs a different key:
    one that stays stable as the scanner moves between endpoints while still reducing
    accidental coalescing of unrelated clients behind the same NAT address.

    Only low-sensitivity request traits are used. No cookies, authorization values,
    request bodies, credentials, or payload contents contribute to this identifier.
    ``actor_key`` already contains Hotpot's trusted network identity (including a
    trusted Cloudflare Worker zone when applicable).
    """
    material = "|".join(
        (
            actor_key.strip().lower() or "unknown",
            (source_type or "ip").strip().lower(),
            (worker_zone or "").strip().lower(),
            (scanner_family or "unknown").strip().lower(),
            _normalize_user_agent(user_agent),
            _normalize_header_value(accept, 192),
            _normalize_header_value(accept_language, 96),
            _normalize_header_value(accept_encoding, 96),
            (http_version or "").strip().lower()[:32],
        )
    )
    return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:20]


def _normalize_user_agent(user_agent: str) -> str:
    # Strip version-like digit runs so one tool upgrading does not produce a totally
    # different behavioral fingerprint.
    ua = user_agent.strip().lower()[:256]
    return re.sub(r"\d+(?:\.\d+)+", "<version>", ua)


def _normalize_header_value(value: str, limit: int) -> str:
    # Collapse insignificant whitespace while retaining capability/order hints that
    # are useful for distinguishing automated HTTP clients sharing one address.
    return " ".join(value.strip().lower().split())[:limit]


def _severity(category: str, method: str) -> int:
    category = category.lower()
    if any(token in category for token in ("secret", "env", "webshell", "rce", "phpunit")):
        return 5
    if any(token in category for token in ("git", "credential", "config")):
        return 4
    if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        return 4
    if "wordpress" in category or "admin" in category:
        return 3
    return 2


@dataclass(frozen=True)
class Escalation:
    level: int
    score: int
    force_tarpit: bool
    tarpit_seconds: float


def escalation_for(
    *,
    prior_hits: int,
    prior_score: int,
    severity: int,
    base_seconds: float,
    max_escalated_seconds: float,
) -> Escalation:
    """Compute a bounded repeat-offender escalation policy.

    The score is intentionally simple and explainable. Escalation never bypasses the
    global tarpit semaphore, so a repeat offender cannot reserve unlimited resources.
    """
    hits = prior_hits + 1
    score = prior_score + max(1, severity)

    if hits >= 20 or score >= 60:
        level, multiplier = 4, 3.0
    elif hits >= 10 or score >= 30:
        level, multiplier = 3, 2.25
    elif hits >= 3 or score >= 10:
        level, multiplier = 2, 1.5
    else:
        level, multiplier = 1, 1.0

    seconds = min(max_escalated_seconds, base_seconds * multiplier)
    return Escalation(
        level=level,
        score=score,
        force_tarpit=level >= 2,
        tarpit_seconds=seconds,
    )
