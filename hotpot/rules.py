from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


VALID_BAIT_STAGES = {"discovered", "interacted", "exploit-attempt", "canary-followed"}


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
    bait_id: str | None = None
    bait_stage: str | None = None

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
                bait_id = str(item.get("bait_id", "")).strip() or None
                bait_stage = str(item.get("bait_stage", "")).strip() or None
                if bait_stage and not bait_id:
                    raise RuntimeError(
                        f"Profile {profile} rule {item['name']} defines bait_stage without bait_id"
                    )
                if bait_stage and bait_stage not in VALID_BAIT_STAGES:
                    raise RuntimeError(
                        f"Profile {profile} rule {item['name']} has invalid bait_stage {bait_stage!r}"
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
                    bait_id=bait_id,
                    bait_stage=bait_stage,
                ))
        return cls(rules)
