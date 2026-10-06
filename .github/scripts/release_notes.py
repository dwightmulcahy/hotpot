#!/usr/bin/env python3
"""Generate GitHub release notes from Conventional Commit messages."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path

CONVENTIONAL_RE = re.compile(
    r"^(?P<type>[A-Za-z][A-Za-z0-9_-]*)(?:\((?P<scope>[^)]+)\))?(?P<breaking>!)?:\s+(?P<description>.+)$"
)
BREAKING_RE = re.compile(r"(?:^|\n)BREAKING(?: |-)?CHANGE:\s*", re.IGNORECASE)

GROUPS = OrderedDict(
    [
        ("breaking", "💥 Breaking Changes"),
        ("feat", "🚀 Features"),
        ("fix", "🐛 Bug Fixes"),
        ("perf", "⚡ Performance"),
        ("security", "🔒 Security"),
        ("refactor", "♻️ Refactoring"),
        ("docs", "📝 Documentation"),
        ("test", "✅ Tests"),
        ("build", "📦 Build"),
        ("ci", "👷 CI"),
        ("chore", "🧹 Chores"),
        ("style", "🎨 Style"),
        ("revert", "⏪ Reverts"),
        ("other", "🔧 Other Changes"),
    ]
)


@dataclass(frozen=True)
class Commit:
    sha: str
    subject: str
    body: str


@dataclass(frozen=True)
class ParsedCommit:
    group: str
    scope: str | None
    description: str
    sha: str


def run_git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True).strip()


def find_previous_tag(current_tag: str) -> str | None:
    tags = run_git(
        "tag",
        "--merged",
        current_tag,
        "--sort=-version:refname",
        "--list",
        "v[0-9]*.[0-9]*.[0-9]*",
    ).splitlines()
    for tag in tags:
        if tag and tag != current_tag:
            return tag
    return None


def load_commits(current_tag: str, previous_tag: str | None) -> list[Commit]:
    revision = f"{previous_tag}..{current_tag}" if previous_tag else current_tag
    raw = subprocess.check_output(
        [
            "git",
            "log",
            "--no-merges",
            "--reverse",
            "--format=%H%x1f%s%x1f%b%x1e",
            revision,
        ],
        text=True,
    )
    commits: list[Commit] = []
    for record in raw.split("\x1e"):
        record = record.strip("\r\n")
        if not record:
            continue
        parts = record.split("\x1f", 2)
        if len(parts) != 3:
            continue
        commits.append(Commit(parts[0].strip(), parts[1].strip(), parts[2].strip()))
    return commits


def parse_commit(commit: Commit) -> ParsedCommit | None:
    match = CONVENTIONAL_RE.match(commit.subject)
    if not match:
        return ParsedCommit("other", None, commit.subject, commit.sha)

    commit_type = match.group("type").lower()
    scope = match.group("scope")
    description = match.group("description").strip()

    # Release bookkeeping should not pollute the human-facing changelog.
    if commit_type == "chore" and scope and scope.lower() == "release":
        return None

    breaking = bool(match.group("breaking")) or bool(BREAKING_RE.search(commit.body))
    group = "breaking" if breaking else commit_type if commit_type in GROUPS else "other"
    return ParsedCommit(group, scope, description, commit.sha)


def render_notes(
    commits: list[Commit], *, current_tag: str, previous_tag: str | None, repository: str
) -> str:
    grouped: dict[str, list[ParsedCommit]] = {key: [] for key in GROUPS}
    for commit in commits:
        parsed = parse_commit(commit)
        if parsed is not None:
            grouped[parsed.group].append(parsed)

    lines = ["## What's Changed", ""]
    visible_count = sum(len(items) for items in grouped.values())
    if visible_count == 0:
        lines.extend(["No changelog entries were found for this release.", ""])
    else:
        for key, title in GROUPS.items():
            entries = grouped[key]
            if not entries:
                continue
            lines.extend([f"### {title}", ""])
            for entry in entries:
                scope = f"**{entry.scope}:** " if entry.scope else ""
                short_sha = entry.sha[:7]
                commit_url = f"https://github.com/{repository}/commit/{entry.sha}"
                lines.append(f"- {scope}{entry.description} ([`{short_sha}`]({commit_url}))")
            lines.append("")

    if previous_tag:
        compare_url = f"https://github.com/{repository}/compare/{previous_tag}...{current_tag}"
        lines.append(f"**Full Changelog:** [{previous_tag}...{current_tag}]({compare_url})")
    else:
        history_url = f"https://github.com/{repository}/commits/{current_tag}"
        lines.append(f"**Full History:** [{current_tag}]({history_url})")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True, help="Current release tag, e.g. v0.5.0")
    parser.add_argument("--output", default="RELEASE_NOTES.md")
    parser.add_argument(
        "--repository",
        default=os.getenv("GITHUB_REPOSITORY", ""),
        help="GitHub repository in owner/name form",
    )
    args = parser.parse_args()

    if not args.repository:
        raise SystemExit("repository is required via --repository or GITHUB_REPOSITORY")

    previous_tag = find_previous_tag(args.tag)
    commits = load_commits(args.tag, previous_tag)
    notes = render_notes(
        commits,
        current_tag=args.tag,
        previous_tag=previous_tag,
        repository=args.repository,
    )
    output = Path(args.output)
    output.write_text(notes, encoding="utf-8")
    print(f"Generated {output} from {previous_tag or 'repository start'} through {args.tag}")


if __name__ == "__main__":
    main()
