#!/usr/bin/env python3
"""Generate grouped Conventional Commit release notes for manually tagged releases."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
from collections import defaultdict
from pathlib import Path

CONVENTIONAL_COMMIT = re.compile(
    r"^(?P<type>[a-z][a-z0-9-]*)(?:\((?P<scope>[^)]+)\))?(?P<breaking>!)?:\s+(?P<text>.+)$"
)
SEMVER = re.compile(r"^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SECTIONS = {
    "feat": ("✨", "Features"),
    "fix": ("🐛", "Bug fixes"),
    "perf": ("⚡", "Performance"),
    "security": ("🔒", "Security"),
    "refactor": ("♻️", "Refactoring"),
    "docs": ("📚", "Documentation"),
    "test": ("✅", "Tests"),
    "build": ("📦", "Build system"),
    "ci": ("👷", "Continuous integration"),
    "style": ("🎨", "Styles"),
    "revert": ("⏪", "Reverts"),
    "chore": ("🧹", "Maintenance"),
}


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def version_tuple(value: str) -> tuple[int, int, int] | None:
    match = SEMVER.fullmatch(value)
    if not match:
        return None
    return tuple(map(int, match.groups()))


def previous_tag(tag: str) -> str | None:
    """Use the greatest prior stable SemVer reachable from the tagged commit."""
    current = version_tuple(tag)
    if current is None:
        raise ValueError(f"Not a stable SemVer tag: {tag}")
    merged = git("tag", "--merged", tag).splitlines()
    candidates = [
        (version_tuple(candidate), candidate)
        for candidate in merged
        if version_tuple(candidate) is not None and version_tuple(candidate) < current
    ]
    return max(candidates, default=(None, None))[1]


def commit_subjects(tag: str, previous: str | None) -> list[tuple[str, str, str]]:
    revision = f"{previous}..{tag}" if previous else tag
    output = git("log", "--no-merges", "--format=%h%x1f%s%x1f%b%x1e", revision)
    records = []
    for record in output.split("\x1e"):
        parts = record.strip().split("\x1f")
        if len(parts) >= 2:
            records.append(
                (
                    parts[0].strip(),
                    parts[1].strip(),
                    parts[2].strip() if len(parts) >= 3 else "",
                )
            )
    return records


def render(tag: str, repository: str, project_name: str, image: str) -> str:
    previous = previous_tag(tag)
    grouped: dict[str, list[str]] = defaultdict(list)
    breaking: list[str] = []

    for record in commit_subjects(tag, previous):
        sha, subject = record[:2]
        body = record[2] if len(record) > 2 else ""
        match = CONVENTIONAL_COMMIT.match(subject)
        if match:
            commit_type = match.group("type")
            scope = match.group("scope")
            desc = match.group("text")
            label = f"**{scope}:** {desc}" if scope else desc
            is_breaking = bool(match.group("breaking")) or bool(
                re.search(r"(?m)^BREAKING(?: |-)?CHANGE:", body)
            )
            destination = breaking if is_breaking else grouped[commit_type]
        else:
            label = subject
            destination = grouped["other"]
        short = sha[:7]
        if repository:
            reference = f"[{short}](https://github.com/{repository}/commit/{sha})"
        else:
            reference = short
        destination.append(f"- {label} ({reference})")

    version = tag.removeprefix("v")
    lines = [f"# {project_name} {version}", ""]
    if previous:
        lines.extend([f"Changes since **{previous}**.", ""])
    if breaking:
        lines.extend(["## 💥 Breaking changes", "", *breaking, ""])
    for commit_type, (icon, title) in SECTIONS.items():
        entries = grouped.pop(commit_type, [])
        if entries:
            lines.extend([f"## {icon} {title}", "", *entries, ""])
    remaining = [entry for entries in grouped.values() for entry in entries]
    if remaining:
        lines.extend(["## 🔧 Other changes", "", *remaining, ""])
    lines.extend(
        [
            "## 🐳 Docker",
            "",
            "```bash",
            f"docker pull {image}:{version}",
            "```",
            "",
            "Multi-architecture image: `linux/amd64` and `linux/arm64`.",
            "",
        ]
    )
    if repository and previous:
        lines.append(
            f"**Full changelog:** https://github.com/{repository}/compare/{previous}...{tag}"
        )
    elif repository:
        lines.append(f"**Source:** https://github.com/{repository}/tree/{tag}")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(
        render(
            args.tag,
            os.environ.get("GITHUB_REPOSITORY", ""),
            args.project_name,
            args.image,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
