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
    "scripts/test_esil_differential.py": "puts a stand-in `r2` on PATH to test the ESIL "
    "differential without radare2",
}

# What follows the program's name when it is run: a flag, a quoted or
# expanded argument, a redirect, a path, or (in a command string) the
# placeholder or the end of the literal it is concatenated to.
_ARGUMENT = r"(?:-|[\"'$<{]|\.{0,2}/|~)"
RADARE2_RUN = re.compile(
    # A shell command: the name in command position (after a line start, a
    # separator, a substitution, exec/sudo/then/do, and any VAR=value
    # assignments), with any argument -- flagless ones such as `r2 "$bin"`
    # included.
    r"(?:^|[;|&(`]|\$\(|\bexec\b|\bthen\b|\bdo\b|\bsudo\b)[ \t]*"
    r"(?:[A-Za-z_]\w*=\S*[ \t]+)*(?:r2|radare2)[ \t]+" + _ARGUMENT +
    # A command string: a literal that starts with the name and an argument,
    # as in `"r2 " + path` or f"r2 -q {binary}".
    r"|[\"'](?:r2|radare2)[ \t]+" + _ARGUMENT +
    # An argv element, or a lookup of the program.
    r"|[\[(,][ \t]*[\"'](?:r2|radare2)[\"']"
    r"|shutil\.which\([ \t]*[\"'](?:r2|radare2)[\"']"
    r"|\b(?:which|command -v|type)[ \t]+(?:r2|radare2)\b",
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
        runs = (
            "r2 -q -c 'aaa; afl' bin",
            'subprocess.run(["r2", "-q", path])',
            "found = shutil.which('radare2')",
            # Flagless and bare invocations.
            'r2 "$bin"',
            "  radare2 ./a.out",
            "out=$(r2 $bin <<< afl)",
            "R2_NOPLUGINS=1 r2 -A bin",
            "exec radare2 ~/bin/ls",
            'os.system("r2 " + path)',
            'command = f"r2 {binary}"',
            "if command -v r2 >/dev/null; then",
        )
        for text in runs:
            self.assertIsNotNone(RADARE2_RUN.search(text), text)
        for text in ("r2s -q -c pdd bin", "the r2 differential", "r2 is the oracle",
                     "echo radare2 installed", "r2sleigh -q", "sr2 -q"):
            self.assertIsNone(RADARE2_RUN.search(text), text)


if __name__ == "__main__":
    unittest.main()
