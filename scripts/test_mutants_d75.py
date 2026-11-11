#!/usr/bin/env python3
"""Unit tests for D75's mutation target. A fake shell stands in for cargo; the last test reads the repository."""

from __future__ import annotations

import contextlib
import io
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import mutants_d75  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
GREEN = "test kept ... ok\ntest other ... ok\n\ntest result: ok. 2 passed\n"


class Shell:
    """Answers each command by the first entry whose key it contains; records what ran."""

    def __init__(self, answers):
        self.answers = answers
        self.ran = []

    def __call__(self, command):
        self.ran.append(command)
        for key, answer in self.answers:
            if key in command:
                return answer
        return 0, ""


def quiet(call):
    with contextlib.redirect_stdout(io.StringIO()) as out:
        result = call()
    return result, out.getvalue()


class Baseline(unittest.TestCase):
    """A red unmutated tree stops the script before any mutant is applied."""

    def red(self, answer):
        sh = Shell([("git diff", (0, "")), ("--no-run", (0, "")), ("cargo test", answer)])
        result, printed = quiet(lambda: mutants_d75.main(["name-trimmed", "name-lowercased"], sh))
        self.assertTrue(result, "a red baseline must exit nonzero")
        self.assertIn("fails on the unmutated tree", result)
        self.assertEqual(printed, "", "no mutant ran")
        self.assertFalse(any("--no-run" in c for c in sh.ran), sh.ran)

    def test_a_failing_test_unrelated_to_any_mutant_makes_it_fail(self):
        self.red((101, "test kept ... ok\ntest ast::red::unrelated ... FAILED\n\ntest result: FAILED.\n"))

    def test_a_command_that_fails_with_no_test_named_makes_it_fail(self):
        self.red((101, "error[E0433]: cannot find type\n"))

    def test_a_green_baseline_lists_what_each_command_passed(self):
        passed, reason = mutants_d75.baseline(["a", "b"], Shell([("", (0, GREEN))]))
        self.assertIsNone(reason)
        self.assertEqual(passed, {"a": {"kept", "other"}, "b": {"kept", "other"}})


class Kill(unittest.TestCase):
    """A mutant dies only by a test the baseline passed."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.cwd = os.getcwd()
        os.chdir(self.dir.name)
        pathlib.Path("f.rs").write_text("old\n")

    def tearDown(self):
        os.chdir(self.cwd)
        self.dir.cleanup()

    def mutant(self, answer):
        sh = Shell([("--no-run", (0, "")), ("cargo test", answer)])
        line, ok = mutants_d75.run("m", [("f.rs", "old", "new")], ["cargo test"], False, {"cargo test": {"kept"}}, sh)
        self.assertEqual(pathlib.Path("f.rs").read_text(), "old\n", "the file is restored")
        return line, ok

    def test_a_baseline_test_failing_kills(self):
        self.assertEqual(self.mutant((101, "test kept ... FAILED\n")), ("m: killed by kept (`cargo test`)", True))

    def test_a_failure_of_a_test_the_baseline_did_not_pass_is_no_kill(self):
        line, ok = self.mutant((101, "test kept ... ok\ntest unseen ... FAILED\n"))
        self.assertFalse(ok, line)

    def test_a_green_run_is_a_survivor(self):
        self.assertFalse(self.mutant((0, GREEN))[1])

    def test_a_mutant_that_does_not_build_is_wrong(self):
        sh = Shell([("--no-run", (101, ""))])
        line, ok = mutants_d75.run("m", [("f.rs", "old", "new")], ["cargo test"], False, {"cargo test": set()}, sh)
        self.assertEqual((line, ok), ("m: does not build under `cargo test`", False))


class Unbuilt(unittest.TestCase):
    """A predicate mutant dies only when its build fails naming a value out of scope."""

    def mutant(self, answer):
        sh = Shell([("cargo build", answer)])
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root, "f.rs")
            path.write_text("old\n")
            result = mutants_d75.run("m", [(str(path), "old", "new")], mutants_d75.UNBUILT, False, {}, sh)
            self.assertEqual(path.read_text(), "old\n", "the file is restored")
        return result

    def test_a_build_failing_on_a_name_out_of_scope_kills(self):
        self.assertTrue(self.mutant((101, "error[E0425]: cannot find value `args` in this scope\n"))[1])

    def test_a_build_that_passes_or_fails_otherwise_is_wrong(self):
        self.assertFalse(self.mutant((0, ""))[1])
        self.assertFalse(self.mutant((101, "error[E0308]: mismatched types\n"))[1])


class Timeout(unittest.TestCase):
    def test_a_command_past_its_time_exits_124_and_a_mutant_under_it_is_wrong(self):
        self.assertEqual(mutants_d75.shell("echo early; sleep 5", timeout=0.5), (124, "early\n"))
        sh = lambda command: (0, "") if "--no-run" in command else mutants_d75.shell("sleep 5", timeout=0.5)
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root, "f.rs")
            path.write_text("old\n")
            line, ok = mutants_d75.run("m", [(str(path), "old", "new")], ["cargo test"], False, {"cargo test": set()}, sh)
            self.assertEqual(path.read_text(), "old\n", "the file is restored")
        self.assertEqual((line, ok), ("m: `cargo test` exits 124 with no baseline test failing", False))


class Repository(unittest.TestCase):
    def test_every_mutant_applies_once_to_the_tree(self):
        cwd = os.getcwd()
        os.chdir(ROOT)
        try:
            result, printed = quiet(lambda: mutants_d75.main(["--check"], Shell([])))
        finally:
            os.chdir(cwd)
        self.assertEqual(result, 0, printed)
        self.assertEqual(printed.count("applies"), len(mutants_d75.MUTANTS))


if __name__ == "__main__":
    unittest.main()
