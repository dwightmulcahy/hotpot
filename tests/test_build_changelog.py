"""Tests for scripts/build_changelog.py against a real throwaway git repository."""

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build_changelog.py"
spec = importlib.util.spec_from_file_location("build_changelog", SCRIPT)
assert spec and spec.loader
bc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bc)


class BuildChangelogTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        cwd = os.getcwd()
        os.chdir(tmp.name)
        self.addCleanup(os.chdir, cwd)

        def run(*a):
            subprocess.run(["git", *a], check=True, capture_output=True)

        run("init", "-q", "-b", "main")
        run("config", "user.email", "t@example.com")
        run("config", "user.name", "T")
        for msg, tag in [
            ("feat: first feature", "v0.1.0"),
            ("feat(ui): add tabs (#12)", None),
            ("fix: crash on start", None),
            ("ci: faster builds", None),
            ("feat!: new config format", None),
            ("fix: old flag\n\nBREAKING CHANGE: removed --x", None),
            ("just a message", "v0.2.0"),
            ("docs: readme", "v0.3.0-rc1"),
        ]:
            run("commit", "-q", "--allow-empty", "-m", msg)
            if tag:
                run("tag", tag)

    def test_build(self):
        data = bc.build("v0.2.0", "me/app")
        self.assertEqual((data["current"], data["repository"]), ("0.2.0", "me/app"))
        new, old = data["releases"]
        self.assertEqual(
            (new["version"], new["previous"], old["previous"]),
            ("0.2.0", "v0.1.0", None),
        )
        sections = {s["type"]: [i["text"] for i in s["items"]] for s in new["sections"]}
        self.assertEqual(
            sections,
            {
                "breaking": ["old flag", "new config format"],  # newest first
                "feat": ["ui: add tabs (#12)"],
                "fix": ["crash on start"],
            },
        )
        self.assertEqual(new["internal"], 2)
        self.assertEqual(len(new["date"]), 10)
        self.assertEqual(old["sections"][0]["items"][0]["text"], "first feature")

    def test_prerelease_lists_earlier_stable_releases(self):
        versions = [r["version"] for r in bc.build("v0.3.0-rc1")["releases"]]
        self.assertEqual(versions, ["0.2.0", "0.1.0"])
        with self.assertRaises(ValueError):
            bc.build("latest")

    def test_main_writes_json(self):
        bc.main(["--upto", "v0.1.0", "--output", "out/changelog.json"])
        data = json.loads(Path("out/changelog.json").read_text())
        self.assertEqual([r["tag"] for r in data["releases"]], ["v0.1.0"])
        self.assertEqual(data["repository"], "")


if __name__ == "__main__":
    unittest.main()
