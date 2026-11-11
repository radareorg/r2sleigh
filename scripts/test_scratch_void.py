#!/usr/bin/env python3
"""Unit tests for the scratch-void gate (ROADMAP D203): classes, the known list, the ratchet and the floors."""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import scratch_void  # noqa: E402
from scratch_void import Graded  # noqa: E402

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tests" / "equiv"))
import r2s_batch  # noqa: E402


def answer(signature, premises=(), code="", refusal=None, kind="output"):
    record = {"signature": signature, "premises": list(premises), "code": code}
    return r2s_batch.Answer(0x1000, kind, record=record if kind == "output" else None, refusal=refusal)


def graded(name, **rows):
    out = Graded(name)
    out.rows = {fn: tuple(row) for fn, row in rows.items()}
    return out


class Classify(unittest.TestCase):
    def test_void_is_open_without_the_closed_world_premise(self):
        self.assertEqual(scratch_void.classify(answer("void fcn_10(void)", ["ub-free"])), "void-open")

    def test_void_under_the_closed_world_premise_is_decided_by_sites(self):
        self.assertEqual(scratch_void.classify(answer("void fcn_10(void)", ["closed-world"])), "void-closed")

    def test_a_pointer_to_void_is_a_value(self):
        self.assertEqual(scratch_void.classify(answer("void* fcn_10(void)")), "unproven:unstated")

    def test_the_cause_is_read_from_the_proof_line_only(self):
        proof = "uint64_t f(void) {\n    /* r2dec proof: 3 rendered; the result is unproven: Unread */\n}"
        self.assertEqual(scratch_void.classify(answer("uint64_t f(void)", code=proof)), "unproven:Unread")
        self.assertEqual(scratch_void.classify(answer("uint64_t f(void)", code="int Written = 1;")),
                         "unproven:unstated")

    def test_a_refusal_and_a_crash_are_their_own_classes(self):
        self.assertEqual(scratch_void.classify(answer("", refusal="too big")), "refused")
        self.assertEqual(scratch_void.classify(answer("", kind="crash")), "unanswered")

    def test_an_unparsable_signature_is_unanswered(self):
        self.assertEqual(scratch_void.classify(answer("not a prototype")), "unanswered")


class Known(unittest.TestCase):
    def read(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write(text)
        return scratch_void.read_known(pathlib.Path(f.name))

    def test_a_clone_entry_names_a_clone_symbol(self):
        known = self.read("# comment\nO2-find visit_open_fds.constprop.0.isra.0 clone IPA-SRA removed it\n")
        self.assertEqual(known, {("O2-find", "visit_open_fds.constprop.0.isra.0"): "clone"})
        with self.assertRaises(scratch_void.Ungradable):
            self.read("O2-find safe_atoi clone a plain name is never excused\n")

    def test_a_part_split_is_a_clone_and_a_cold_suffix_is_not(self):
        self.assertEqual(self.read("O2-grep add_count.part.0 clone it ends in error(2, ...)\n"),
                         {("O2-grep", "add_count.part.0"): "clone"})
        with self.assertRaises(scratch_void.Ungradable):
            self.read("O2-grep add_count.cold clone a cold block is no clone\n")

    def test_a_defect_names_its_owner(self):
        self.assertEqual(self.read("O2-find constrain_rate defect XMM0 written, D200 owns it\n"),
                         {("O2-find", "constrain_rate"): "defect"})
        with self.assertRaises(scratch_void.Ungradable):
            self.read("O2-find constrain_rate defect someone should look\n")

    def test_a_moving_void_may_be_any_name_and_needs_a_reason(self):
        self.assertEqual(self.read("O0-bz setExit moves D200 makes it Unproven\n"), {("O0-bz", "setExit"): "moves"})
        with self.assertRaises(scratch_void.Ungradable):
            self.read("O0-bz setExit moves\n")
        with self.assertRaises(scratch_void.Ungradable):
            self.read("O0-bz setExit maybe reason\n")


class Judge(unittest.TestCase):
    def test_a_false_void_fails_unless_a_clone_entry_names_it(self):
        build = graded("b", f=("void-open", "value"), g=("void-closed", "value"), h=("void-open", "void"))
        failures = scratch_void.judge([build], {("b", "g"): "clone"}, {}, (None, None))
        self.assertEqual(failures, ["FALSE VOID: b f"])
        self.assertEqual(scratch_void.judge([build], {("b", "g"): "clone", ("b", "f"): "defect"}, {}, (None, None)), [])

    def test_a_moves_entry_excuses_no_false_void(self):
        build = graded("b", f=("void-open", "value"))
        self.assertEqual(scratch_void.judge([build], {("b", "f"): "moves"}, {}, (None, None)), ["FALSE VOID: b f"])

    def test_a_void_the_baseline_renders_may_not_be_lost(self):
        baseline = {"builds": {"b": {"voids": ["f", "g", "h"]}}}
        build = graded("b", f=("void-open", "void"), g=("unproven:unstated", "void"), h=("unproven:Written", "void"))
        failures = scratch_void.judge([build], {("b", "h"): "moves"}, baseline, (None, None))
        self.assertEqual(failures, ["VOID LOST: b g (unproven:unstated)"])

    def test_an_unanswered_function_fails_unless_the_baseline_lists_it(self):
        build = graded("b", f=("unanswered", "value"), g=("unanswered", "void"))
        self.assertEqual(scratch_void.judge([build], {}, {}, (None, None)), ["UNANSWERED: b f", "UNANSWERED: b g"])
        listed = {"builds": {"b": {"voids": [], "unanswered": ["f"]}}}
        self.assertEqual(scratch_void.judge([build], {}, listed, (None, None)), ["UNANSWERED: b g"])

    def test_a_new_void_is_no_failure(self):
        baseline = {"builds": {"b": {"voids": []}}}
        build = graded("b", f=("void-open", "void"))
        self.assertEqual(scratch_void.judge([build], {}, baseline, (None, None)), [])

    def test_the_floors_count_open_world_and_all_voids(self):
        build = graded("b", f=("void-open", "void"), g=("void-closed", "void"), h=("void-closed", "void"))
        self.assertEqual(scratch_void.judge([build], {}, {}, (1, 3)), [])
        self.assertEqual(scratch_void.judge([build], {}, {}, (2, 4)),
                         ["FLOOR: open world void 1 under 2", "FLOOR: closed world void 3 under 4"])


class Main(unittest.TestCase):
    def run_main(self, results, *argv):
        with mock.patch.object(scratch_void, "grade", side_effect=lambda build, *_: results[build.name]), \
                contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            code = scratch_void.main(["--build", "b", "d", "s", *argv])
        return code, out.getvalue(), err.getvalue()

    def test_counts_per_class_are_printed_and_a_clean_run_exits_0(self):
        code, out, _ = self.run_main({"b": graded("b", f=("void-open", "void"), g=("unproven:unstated", "value"))})
        self.assertEqual(code, 0)
        self.assertIn("void-open                source void     1  source value     0", out)

    def test_a_baseline_is_not_recorded_over_a_false_void(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "baseline.json"
            code, _, err = self.run_main({"b": graded("b", f=("void-open", "value"))},
                                         "--baseline", str(path), "--accept-baseline")
            self.assertEqual((code, path.exists()), (1, False))
            self.assertIn("FALSE VOID: b f", err)

    def test_a_recorded_baseline_ratchets_the_next_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "baseline.json"
            self.assertEqual(self.run_main({"b": graded("b", f=("void-open", "void"))},
                                           "--baseline", str(path), "--accept-baseline")[0], 0)
            self.assertEqual(json.loads(path.read_text())["builds"]["b"]["voids"], ["f"])
            code, _, err = self.run_main({"b": graded("b", f=("unproven:unstated", "void"))}, "--baseline", str(path))
            self.assertEqual(code, 1)
            self.assertIn("VOID LOST: b f", err)

    def test_a_crash_fails_the_run_and_a_recorded_one_does_not(self):
        crashed = {"b": graded("b", f=("unanswered", "value"))}
        code, _, err = self.run_main(crashed)
        self.assertEqual(code, 1)
        self.assertIn("UNANSWERED: b f", err)
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "baseline.json"
            self.assertEqual(self.run_main(crashed, "--baseline", str(path), "--accept-baseline")[0], 0)
            self.assertEqual(json.loads(path.read_text())["builds"]["b"]["unanswered"], ["f"])
            self.assertEqual(self.run_main(crashed, "--baseline", str(path))[0], 0)

    def test_an_r2s_that_cannot_run_is_exit_2(self):
        with mock.patch.object(scratch_void, "truth", return_value={0x1000: scratch_void.Source("f", True)}), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            code = scratch_void.main(["--build", "b", "d", "s", "--r2s", "/nonexistent/r2s"])
        self.assertEqual(code, 2)
        self.assertIn("cannot run /nonexistent/r2s", err.getvalue())

    def test_no_build_is_exit_2(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(scratch_void.main([]), 2)


class Mutants(unittest.TestCase):
    def grade(self, stage, code, stderr):
        import subprocess
        import mutants_d203
        return mutants_d203.verdict(stage, subprocess.CompletedProcess([], code, "", stderr))

    def test_a_kill_needs_the_gates_own_failure_line(self):
        self.assertEqual(self.grade("gate", 1, "FALSE VOID: scratch tail_puts\n"),
                         ("killed: FALSE VOID: scratch tail_puts", True))
        self.assertIsNone(self.grade("gate", 1, "Traceback (most recent call last):\nKeyError: 'x'\n")[1])
        self.assertIsNone(self.grade("gate", 1, "UNANSWERED: scratch tail_puts\n")[1])

    def test_a_build_failure_or_refusal_grades_nothing(self):
        self.assertIsNone(self.grade("build", 1, "error[E0308]: mismatched types\n")[1])
        self.assertIsNone(self.grade("gate", 2, "refusing to grade: no build given\n")[1])
        self.assertEqual(self.grade("gate", 0, ""), ("survived the gate", False))

    def test_an_ungraded_mutant_is_wrong_whatever_it_must_do(self):
        import mutants_d203
        with mock.patch.object(mutants_d203, "gate", return_value=("gate", __import__("subprocess").CompletedProcess(
                [], 1, "", "Traceback (most recent call last):\n"))), tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "f.rs"
            path.write_text("a\n")
            line, ok = mutants_d203.run("m", [(str(path), "a\n", "b\n")], True, "", False, [])
            self.assertFalse(ok, line)
            self.assertEqual(path.read_text(), "a\n")

    def test_every_mutant_edit_applies_once_to_the_tree(self):
        import mutants_d203
        root = pathlib.Path(__file__).resolve().parent.parent
        for name, edits, must_die, why in mutants_d203.MUTANTS:
            for path, old, _ in edits:
                self.assertEqual((root / path).read_text().count(old), 1, f"{name}: {path}")
            self.assertTrue(must_die or why, f"{name} may live only with a reason")


if __name__ == "__main__":
    unittest.main()
