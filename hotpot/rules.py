from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Rule:
    profile: str
    name: str
    action: str
    paths: tuple[str, ...]
    path_prefixes: tuple[str, ...]
    regexes: tuple[re.Pattern[str], ...]
    methods: tuple[str, ...]
    response: str
    content_type: str
    status: int
    category: str
    headers: tuple[tuple[str, str], ...]
    tarpit_initial_delay: float | None
    tarpit_chunk_delay: float | None
    tarpit_chunk_size: int | None
    tarpit_max_seconds: float | None
    bait: str | None

    def matches(self, path: str, method: str) -> bool:
        method = method.upper()
        if self.methods and method not in self.methods:
            return False
        if path in self.paths:
            return True
        if any(path.startswith(prefix) for prefix in self.path_prefixes):
            return True
        return any(rx.search(path) for rx in self.regexes)


class RuleEngine:
    def __init__(self, rules: Iterable[Rule]):
        self.rules = tuple(rules)

    def match(self, path: str, method: str) -> Rule | None:
        for rule in self.rules:
            if rule.matches(path, method):
                return rule
        return None

    @classmethod
    def load(cls, profiles_dir: Path, profiles: tuple[str, ...]) -> "RuleEngine":
        rules: list[Rule] = []
        for profile in profiles:
            path = profiles_dir / f"{profile}.toml"
            if not path.exists():
                raise RuntimeError(f"Profile not found: {path}")
            with path.open("rb") as fh:
                raw = tomllib.load(fh)
            for item in raw.get("rule", []):
                raw_headers = item.get("headers", {})
                if not isinstance(raw_headers, dict):
                    raise RuntimeError(f"Rule {profile}/{item['name']} headers must be a TOML table")
                chunk_size = item.get("tarpit_chunk_size")
                if chunk_size is not None and int(chunk_size) < 1:
                    raise RuntimeError(
                        f"Rule {profile}/{item['name']} tarpit_chunk_size must be at least 1"
                    )
                rules.append(Rule(
                    profile=profile,
                    name=item["name"],
                    action=item.get("action", "deceive"),
                    paths=tuple(item.get("paths", [])),
                    path_prefixes=tuple(item.get("path_prefixes", [])),
                    regexes=tuple(re.compile(x, re.IGNORECASE) for x in item.get("regex", [])),
                    methods=tuple(x.upper() for x in item.get("methods", [])),
                    response=item.get("response", "Not Found"),
                    content_type=item.get("content_type", "text/plain; charset=utf-8"),
                    status=int(item.get("status", 200)),
                    category=item.get("category", profile),
                    headers=tuple((str(k), str(v)) for k, v in raw_headers.items()),
                    tarpit_initial_delay=(
                        float(item["tarpit_initial_delay"])
                        if "tarpit_initial_delay" in item else None
                    ),
                    tarpit_chunk_delay=(
                        float(item["tarpit_chunk_delay"])
                        if "tarpit_chunk_delay" in item else None
                    ),
                    tarpit_chunk_size=(int(chunk_size) if chunk_size is not None else None),
                    tarpit_max_seconds=(
                        float(item["tarpit_max_seconds"])
                        if "tarpit_max_seconds" in item else None
                    ),
                    bait=(str(item["bait"]) if item.get("bait") else None),
                ))
        return cls(rules)
