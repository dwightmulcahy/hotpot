#!/usr/bin/env python3
"""Bundle release notes for the in-app "What's new" dialog.

Writes JSON with every stable release up to --upto, built from Conventional Commit
subjects between version tags. Run by the release workflow before the image is built (it
needs the git tags and history), so the app can show the notes without network access."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

CONVENTIONAL = re.compile(r"^(?P<type>[a-z][a-z0-9-]*)(?:\((?P<scope>[^)]+)\))?(?P<bang>!)?:\s+(?P<text>.+)$")
SEMVER = re.compile(r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
# what users notice; everything else is only counted as "internal changes"
SECTIONS = {"feat": "Features", "fix": "Bug fixes", "perf": "Performance",
            "security": "Security", "revert": "Reverts"}


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def semver(tag: str):
    m = SEMVER.fullmatch(tag)
    return tuple(map(int, m.groups())) if m else None


def stable_tags(upto: str) -> list[str]:
    """Stable tags reachable from `upto`, newest first. For a pre-release (v1.2.0-rc1)
    only the stable releases before it."""
    top, inclusive = semver(upto), True
    if top is None:
        top, inclusive = semver(upto.split("-", 1)[0]), False
        if top is None:
            raise ValueError(f"not a SemVer tag: {upto}")
    tags = [t for t in git("tag", "--merged", upto).splitlines()
            if semver(t) and (semver(t) <= top if inclusive else semver(t) < top)]
    return sorted(tags, key=semver, reverse=True)


def commits(tag: str, previous: str | None) -> list[tuple[str, str, str]]:
    out = git("log", "--no-merges", "--format=%h%x1f%s%x1f%b%x1e",
              f"{previous}..{tag}" if previous else tag)
    rows = []
    for rec in out.split("\x1e"):
        parts = rec.strip().split("\x1f")
        if len(parts) >= 2:
            rows.append((parts[0], parts[1].strip(), parts[2] if len(parts) > 2 else ""))
    return rows


def release(tag: str, previous: str | None) -> dict:
    groups: dict[str, list[dict]] = {}
    breaking, internal = [], 0
    for sha, subject, body in commits(tag, previous):
        m = CONVENTIONAL.match(subject)
        kind = m.group("type") if m else None
        text = (f"{m.group('scope')}: " if m and m.group("scope") else "") + (m.group("text") if m else subject)
        item = {"text": text, "sha": sha[:7]}
        if (m and m.group("bang")) or re.search(r"(?m)^BREAKING[ -]CHANGE:", body):
            breaking.append(item)
        elif kind in SECTIONS:
            groups.setdefault(kind, []).append(item)
        else:
            internal += 1
    sections = [{"type": "breaking", "title": "Breaking changes", "items": breaking}] if breaking else []
    sections += [{"type": k, "title": t, "items": groups[k]} for k, t in SECTIONS.items() if k in groups]
    return {"version": tag.lstrip("v"), "tag": tag, "previous": previous,
            "date": git("log", "-1", "--format=%cs", tag), "sections": sections, "internal": internal}


def build(upto: str, repository: str = "") -> dict:
    tags = stable_tags(upto)
    releases = [release(t, tags[i + 1] if i + 1 < len(tags) else None) for i, t in enumerate(tags)]
    return {"current": upto.lstrip("v"), "repository": repository, "releases": releases}


def main(argv=None) -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--upto", required=True, help="the release tag being built, e.g. v1.4.0")
    p.add_argument("--repository", default="", help="owner/name, for PR links")
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args(argv)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(build(a.upto, a.repository), ensure_ascii=False, indent=1) + "\n",
                        encoding="utf-8")


if __name__ == "__main__":
    main()
