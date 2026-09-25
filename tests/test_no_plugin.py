#!/usr/bin/env python3
"""No harness drives radare2 with the deleted r2sleigh plugin.

The plugin was deleted (ROADMAP: "The plugin and the snapshot bridge are
deleted"), but the scripts that drove it were not, and nothing ran them, so
they failed at their first command for months without anyone noticing: the
corpus matrix, the DecBench harness, the kernel smoke, the reversing
benchmark. Everything under ``tests/`` and ``scripts/`` now asks ``r2s``.

This keeps it that way:

* the plugin's own spellings -- its build directory, the command that swapped
  it in, and its render command -- appear nowhere under ``tests/`` or
  ``scripts/``;
* nothing there runs ``r2``/``radare2`` except the scripts that use radare2 as
  what AGENTS.md says it is: the differential target the engine is graded
  against, named in ``RADARE2_ORACLES`` with the reason.

    python3 -m unittest tests/test_no_plugin.py
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCANNED = ("tests", "scripts")
SKIPPED_DIRS = {"artifacts", "__pycache__", "fixtures"}
THIS = Path(__file__).resolve()

PLUGIN_SPELLINGS = (
    "r2plugin",  # the deleted crate's directory: `make -C r2plugin install`
    "a:sla",  # the command that swapped the plugin's architecture in
    "pd:s",  # the plugin's render command
)

# Where radare2 itself is run, and why that is allowed.
RADARE2_ORACLES = {
    "scripts/diff_r2.py": "the differential gate: radare2 is the target r2s is graded against",
    "scripts/esil_differential.py": "radare2's own lift is the reference the r2sleigh CLI's "
    "ESIL is stepped beside",
    "scripts/setup-runner.sh": "installs radare2 on a CI runner for its test binaries",
}

RADARE2_RUN = re.compile(
    r"(?:^|[\s;|&(`$])(?:r2|radare2)\s+-[A-Za-z]"  # a shell command with flags
    r"|[\[(,]\s*[\"'](?:r2|radare2)[\"']"  # a Python argv list or tuple
    r"|shutil\.which\(\s*[\"'](?:r2|radare2)[\"']"
    r"|\b(?:which|command -v)\s+(?:r2|radare2)\b",
    re.MULTILINE,
)


def scanned_files() -> list[Path]:
    files: list[Path] = []
    for top in SCANNED:
        for path in sorted((REPO / top).rglob("*")):
            if not path.is_file() or path.resolve() == THIS:
                continue
            if SKIPPED_DIRS & set(path.relative_to(REPO).parts):
                continue
            files.append(path)
    return files


def text_of(path: Path) -> str | None:
    data = path.read_bytes()
    if b"\0" in data[:4096]:
        return None
    return data.decode("utf-8", "replace")


class NoPluginTests(unittest.TestCase):
    def test_no_plugin_spelling_survives(self):
        offenders = []
        for path in scanned_files():
            text = text_of(path)
            if text is None:
                continue
            for spelling in PLUGIN_SPELLINGS:
                for number, line in enumerate(text.splitlines(), 1):
                    if spelling in line:
                        offenders.append(f"{path.relative_to(REPO)}:{number}: {spelling}")
        self.assertEqual(offenders, [], "the deleted plugin is still driven:\n" +
                         "\n".join(offenders))

    def test_radare2_runs_only_as_the_differential_target(self):
        offenders = []
        for path in scanned_files():
            relative = path.relative_to(REPO).as_posix()
            if relative in RADARE2_ORACLES:
                continue
            text = text_of(path)
            if text is None:
                continue
            for match in RADARE2_RUN.finditer(text):
                number = text.count("\n", 0, match.start()) + 1
                offenders.append(f"{relative}:{number}: {match.group(0).strip()}")
        self.assertEqual(offenders, [], "radare2 is run outside the differential scripts:\n" +
                         "\n".join(offenders))

    def test_the_oracle_list_names_files_that_exist(self):
        for relative in RADARE2_ORACLES:
            self.assertTrue((REPO / relative).is_file(), relative)

    def test_the_patterns_catch_what_they_are_for(self):
        self.assertIsNotNone(RADARE2_RUN.search("r2 -q -c 'aaa; afl' bin"))
        self.assertIsNotNone(RADARE2_RUN.search('subprocess.run(["r2", "-q", path])'))
        self.assertIsNotNone(RADARE2_RUN.search("found = shutil.which('radare2')"))
        self.assertIsNone(RADARE2_RUN.search("r2s -q -c pdd bin"))
        self.assertIsNone(RADARE2_RUN.search("the r2 differential"))


if __name__ == "__main__":
    unittest.main()
