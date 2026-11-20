#!/usr/bin/env python3
"""Unit tests for the history gate. Pure Python: a stand-in r2s, no engine."""

from __future__ import annotations

import os
import pathlib
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import history_gate as gate  # noqa: E402

# A stand-in r2s: each `X @ A` prints one line; `remembers` prints another once `aa` ran.
FAKE = """#!/usr/bin/env python3
import sys
script = sys.argv[sys.argv.index("-c") + 1]
seen = False
for command in (part.strip() for part in script.split(";")):
    if command in ("aa", "afl"):
        seen = seen or command == "aa"
        if command == "afl":
            print("0x10 f\\n0x20 g")
        continue
    if command.endswith("0x30"):
        continue
    print(command + (" closed" if seen and REMEMBERS else ""))
"""


def fake(directory: pathlib.Path, remembers: bool) -> str:
    path = directory / ("remembers" if remembers else "forgets")
    path.write_text(FAKE.replace("REMEMBERS", str(remembers)))
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


class Plans(unittest.TestCase):
    def test_each_command_runs_after_aa_and_after_afl_against_itself_alone(self) -> None:
        case = gate.Case(pathlib.Path("b"), 0x10)
        self.assertIn(("aa; pdd @ 0x10", ["aa", "pdd @ 0x10"]), gate.scripts_of(case))
        self.assertIn(("afl; afi @ 0x10", ["afl", "afi @ 0x10"]), gate.scripts_of(case))
        self.assertEqual(len(gate.scripts_of(case)), 6)

    def test_a_session_asks_every_command_of_every_case_in_order(self) -> None:
        cases = [gate.Case(pathlib.Path("b"), 1), gate.Case(pathlib.Path("b"), 2)]
        self.assertEqual(gate.session_of(cases)[:4], ["pdd @ 0x1", "pdf @ 0x1", "afi @ 0x1", "pdd @ 0x2"])

    def test_decbench_cases_split_the_project_from_the_binary(self) -> None:
        cases = gate.decbench_cases(pathlib.Path("D"))
        self.assertEqual(len(cases), 20)
        self.assertIn(gate.Case(pathlib.Path("D/O2/gzip/stripped/gzip"), 0x4990), cases)


class Differences(unittest.TestCase):
    def test_equal_outputs_have_none(self) -> None:
        self.assertIsNone(gate.first_difference("a\nb\n", "a\nb\n"))

    def test_the_first_differing_line_is_named(self) -> None:
        self.assertEqual(gate.first_difference("a\nb\nc\n", "a\nx\nc\n"), (2, "b", "x"))

    def test_a_missing_line_is_a_difference(self) -> None:
        self.assertEqual(gate.first_difference("a\nb\n", "a\n"), (2, "b", "<end>"))

    def test_a_missing_final_newline_is_a_difference(self) -> None:
        self.assertIsNotNone(gate.first_difference("a\n", "a"))


class Runs(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.directory = pathlib.Path(self.temp.name)
        self.binary = self.directory / "bin"
        self.binary.write_bytes(b"\0")
        self.cases = [gate.Case(self.binary, 0x10), gate.Case(self.binary, 0x20)]

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_an_answer_independent_of_history_passes(self) -> None:
        self.assertEqual(gate.check(fake(self.directory, False), self.cases, 2, 60), [])

    def test_an_answer_aa_moves_fails_naming_the_script(self) -> None:
        moved = gate.check(fake(self.directory, True), self.cases, 2, 60)
        self.assertEqual(len(moved), 6, moved)
        self.assertTrue(all("aa; " in line for line in moved), moved)

    def test_a_listed_address_that_answers_nothing_is_no_pass(self) -> None:
        cases = self.cases + [gate.Case(self.binary, 0x30)]
        with self.assertRaises(gate.Unanswered):
            gate.check(fake(self.directory, False), cases, 2, 60)


if __name__ == "__main__":
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    unittest.main()
