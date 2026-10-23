#!/usr/bin/env python3
"""Unit tests for the source-gold harness: what it reads as a prototype, as a real truth, and as a silent error.

Pure Python; every `r2s` answer is canned, so no binary runs.
"""

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
import differential_truth as dt  # noqa: E402


class ParsePrototype(unittest.TestCase):
    def test_a_function_pointer_parameter_is_one_parameter(self) -> None:
        proto = dt.parse_prototype("int run(int (*f)(int, int), char *s);")
        self.assertIsNotNone(proto)
        self.assertEqual(proto.names, ["f", "s"])
        self.assertEqual(proto.params, ["int (*)(int, int)", "char*"])

    def test_commas_inside_any_bracket_do_not_split(self) -> None:
        proto = dt.parse_prototype("void h(int (*a[2])(int, int), int b);")
        self.assertIsNotNone(proto)
        self.assertEqual(len(proto.params), 2)

    def test_the_spelling_r2s_prints_is_unchanged(self) -> None:
        proto = dt.parse_prototype("uint32_t fnv1a32(const uint8_t* p, uint64_t n)")
        self.assertIsNotNone(proto)
        self.assertEqual(proto.ret, "uint32_t")
        self.assertEqual(proto.params, ["const uint8_t*", "size_t"])
        self.assertEqual(proto.names, ["p", "n"])

    def test_void_and_nothing_have_no_parameters(self) -> None:
        for line in ("int main(void)", "int main()"):
            proto = dt.parse_prototype(line)
            self.assertIsNotNone(proto)
            self.assertEqual(proto.params, [])


class TruthIsReal(unittest.TestCase):
    def test_the_engines_own_placeholder_is_not_a_source_name(self) -> None:
        recovered = {0x1000: dt.Prototype("uint64_t", ["uint8_t*", "uint64_t"], ["arg0", "arg1"])}
        self.assertFalse(dt.truth_is_real(recovered))

    def test_a_source_name_makes_the_truth_real(self) -> None:
        mixed = {
            0x1000: dt.Prototype("uint64_t", ["uint8_t*"], ["arg0"]),
            0x2000: dt.Prototype("uint32_t", ["uint8_t*"], ["data"]),
        }
        self.assertTrue(dt.truth_is_real(mixed))

    def test_a_debug_build_whose_dwarf_failed_to_load_exits_2(self) -> None:
        # The debug build renders what the stripped one does: every parameter is `argN`.
        same = {0x1000: dt.Seen(dt.Prototype("uint64_t", ["uint8_t*"], ["arg0"]), False)}
        out, err = io.StringIO(), io.StringIO()
        argv = ["differential_truth.py", "--debug-build", "d", "--stripped-build", "s"]
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(dt, "signatures", return_value=same),
            mock.patch.object(dt, "names", return_value={0x1000: "fcn.1000"}),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            code = dt.main()
        self.assertEqual(code, 2, out.getvalue())
        self.assertIn("refusing to score", err.getvalue())
        self.assertNotIn("soundness_rate", out.getvalue())


def proto(ret: str, params: list[str], names: list[str] | None = None) -> "dt.Prototype":
    return dt.Prototype(ret, params, names if names is not None else [f"p{i}" for i in range(len(params))])


def run_gate(truth: dict, recovered: dict, *extra: str) -> tuple[int, dict, str]:
    """Exit code, report and stderr of main for a debug build with these prototypes and a stripped one with those.

    A function with a source-named parameter, right in both builds, keeps the truth real.
    """
    debug, stripped = pathlib.Path("debug"), pathlib.Path("stripped")
    anchor = {0x9000: dt.Seen(proto("int", ["int"], ["count"]), False)}
    seen = {debug: {**truth, **anchor}, stripped: {**recovered, **anchor}}
    out, err = io.StringIO(), io.StringIO()
    argv = ["differential_truth.py", "--debug-build", str(debug), "--stripped-build", str(stripped), *extra]
    with (
        mock.patch.object(sys, "argv", argv),
        mock.patch.object(dt, "signatures", side_effect=lambda binary, _r2s: seen[binary]),
        mock.patch.object(dt, "names", return_value={0x1000: "sym.f"}),
        contextlib.redirect_stdout(out),
        contextlib.redirect_stderr(err),
    ):
        code = dt.main()
    return code, json.loads(out.getvalue()), err.getvalue()


def graded(truth: dict, recovered: dict) -> dict:
    """The report main prints."""
    return run_gate(truth, recovered)[1]


class SilentBuckets(unittest.TestCase):
    """Every wrong fact lands in one bucket, so a fix can be graded by the bucket it empties."""

    def one(self, expected: str, said: str, where: str = "return", marked: bool = False) -> dict:
        if where == "return":
            truth, got = proto(expected, []), proto(said, [])
        else:
            truth, got = proto("int", [expected]), proto("int", [said])
        return graded({0x1000: dt.Seen(truth, False)}, {0x1000: dt.Seen(got, marked)})

    def test_each_kind_of_difference_has_its_bucket(self) -> None:
        cases = [
            ("return", "int", "size_t", "width_wider"),
            ("return", "uint32_t", "uint8_t", "width_narrower"),
            ("parameter", "int8_t", "uint8_t", "sign"),
            ("parameter", "const uint8_t*", "uint8_t*", "qualifier"),
            ("parameter", "const uint8_t*", "void*", "pointee"),
            ("parameter", "const uint8_t*", "size_t", "pointer_as_integer"),
            ("parameter", "size_t", "uint8_t*", "integer_as_pointer"),
            ("return", "void", "size_t", "void_vs_value"),
            ("return", "int", "void", "void_vs_value"),
            ("parameter", "float", "uint32_t", "other"),
        ]
        for where, expected, said, bucket in cases:
            with self.subTest(where=where, expected=expected, said=said):
                report = self.one(expected, said, where)
                self.assertEqual(report["silent_buckets"], {where: {bucket: 1}})
                self.assertEqual(report["marked_buckets"], {})

    def test_a_marked_error_is_bucketed_apart_and_is_not_silent(self) -> None:
        report = self.one("const uint8_t*", "size_t", "parameter", marked=True)
        self.assertEqual(report["silent_buckets"], {})
        self.assertEqual(report["marked_buckets"], {"parameter": {"pointer_as_integer": 1}})
        self.assertEqual(report["facts"]["silently_wrong"], 0)

    def test_the_silent_key_is_spelled_as_it_was(self) -> None:
        report = self.one("int", "size_t")
        self.assertEqual(report["silent"], ["sym.f return: expected 'int', said 'size_t'"])


def pddj_line(premises: list[str] | None = None, variables: list[dict] | None = None) -> str:
    """The last line `pddj` prints; it spells the word `residual` in its keys even where there is none."""
    answer = {
        "name": "fcn.00001000", "addr": 4096, "signature": "uint32_t fcn_1000(uint8_t* arg0)",
        "proof": {"total": 3, "rendered": 3, "residual": 0}, "residuals": [],
        "variables": variables or [],
    }
    if premises:
        answer["premises"] = premises
    return json.dumps(answer)


def canned(pdd: str, answer: str, afl: str = "0x00001000    1     10 fcn.00001000\n") -> "mock._patch":
    def run(binary: pathlib.Path, commands: str, r2s_bin: str) -> str:
        if commands == "afl":
            return afl
        # The shell prints the pdd text and then the JSON line, in the order of the commands.
        return pdd + answer + "\n" if commands.endswith("pdd; pddj") else pdd

    return mock.patch.object(dt, "r2s", side_effect=run)


CLEAN = "uint32_t fcn_1000(uint8_t* arg0)\n{\n    /* r2dec proof: no individual construct is marked */\n}\n"


class ReadsPddj(unittest.TestCase):
    """One invocation per function gives the header and the marker as before, and the premises beside them."""

    def read(self, pdd: str, answer: str) -> "dt.Seen":
        with canned(pdd, answer):
            return dt.signatures(pathlib.Path("b"), "r2s")[0x1000]

    def test_the_premises_a_rendering_assumed_are_read(self) -> None:
        seen = self.read(CLEAN, pddj_line(premises=["closed-world"]))
        self.assertEqual(seen.premises, ("closed-world",))
        self.assertEqual(seen.proto.ret, "uint32_t")

    def test_the_json_lines_own_keys_are_not_a_residual_marker(self) -> None:
        seen = self.read(CLEAN, pddj_line())
        self.assertFalse(seen.marked)
        self.assertEqual(seen.premises, ())

    def test_a_residual_in_the_text_still_marks(self) -> None:
        text = CLEAN.replace("}\n", "    return r2sleigh_residual_u32(1);\n}\n")
        self.assertTrue(self.read(text, pddj_line()).marked)

    def test_an_unreadable_answer_is_not_hidden(self) -> None:
        seen = self.read(CLEAN, "not json")
        self.assertIsNone(seen.premises)

    def test_the_basis_pddj_states_for_a_parameter_is_read_by_slot(self) -> None:
        variables = [{"name": "arg0", "type": "uint8_t*", "kind": "param", "location": "arg:0", "basis": "carrier-width"}]
        self.assertEqual(self.read(CLEAN, pddj_line(variables=variables)).basis, {0: "carrier-width"})
        plain = [{"name": "arg0", "type": "uint8_t*", "kind": "param", "location": "arg:0"}]
        self.assertEqual(self.read(CLEAN, pddj_line(variables=plain)).basis, {})


class PremisedClaims(unittest.TestCase):
    """A claim that rests on a premise stays scored as silent: the gate is not loosened for it."""

    def test_a_closed_world_void_is_counted_and_stays_silent(self) -> None:
        truth = {0x1000: dt.Seen(proto("int", []), False)}
        said = {0x1000: dt.Seen(proto("void", []), False, ("closed-world",))}
        report = graded(truth, said)
        self.assertEqual(report["facts"]["silently_wrong"], 1)
        self.assertEqual(report["silent"], ["sym.f return: expected 'int', said 'void'"])
        self.assertEqual(report["premised"], {"claims": 1, "silent": 1})

    def test_a_claim_with_no_premise_is_not_premised(self) -> None:
        truth = {0x1000: dt.Seen(proto("int", []), False)}
        said = {0x1000: dt.Seen(proto("void", []), False)}
        self.assertEqual(graded(truth, said)["premised"], {"claims": 0, "silent": 0})


class ReturnPresence(unittest.TestCase):
    def test_void_and_value_are_told_apart_in_both_directions(self) -> None:
        truth = {
            0x1000: dt.Seen(proto("void", []), False),
            0x2000: dt.Seen(proto("void", []), False),
            0x3000: dt.Seen(proto("int", []), False),
            0x4000: dt.Seen(proto("int", []), False),
            0x5000: dt.Seen(proto("int", []), False),
        }
        said = {
            0x1000: dt.Seen(proto("void", []), False),
            0x2000: dt.Seen(proto("size_t", []), True),
            0x3000: dt.Seen(proto("void", []), False, ("closed-world",)),
            0x4000: dt.Seen(proto("int", []), False),
            0x5000: dt.Seen(proto("void", []), True),
        }
        presence = graded(truth, said)["return_presence"]
        self.assertEqual(presence["void_to_void"], {"total": 1, "silent": 0, "premised": 0})
        self.assertEqual(presence["void_to_value"], {"total": 1, "silent": 0, "premised": 0})
        self.assertEqual(presence["value_to_void"], {"total": 2, "silent": 1, "premised": 1})
        self.assertEqual(presence["value_to_value"], {"total": 2, "silent": 0, "premised": 0})

    def test_every_cell_is_present_when_nothing_falls_in_it(self) -> None:
        presence = graded({}, {})["return_presence"]
        self.assertEqual(sorted(presence), ["value_to_value", "value_to_void", "void_to_value", "void_to_void"])


class MarkedBy(unittest.TestCase):
    def test_the_report_says_when_pddj_states_no_basis(self) -> None:
        truth = {0x1000: dt.Seen(proto("int", ["const char*"]), False)}
        said = {0x1000: dt.Seen(proto("int", ["size_t"]), True)}
        self.assertEqual(graded(truth, said)["marked_by"], {"residual": 1, "basis": "unavailable"})

    def test_a_stated_basis_groups_the_marked_parameters(self) -> None:
        truth = {0x1000: dt.Seen(proto("int", ["const char*", "int"]), False)}
        said = {0x1000: dt.Seen(proto("int", ["size_t", "size_t"]), True, (), {0: "carrier-width"})}
        marked = graded(truth, said)["marked_by"]
        self.assertEqual(marked["residual"], 2)
        self.assertEqual(marked["basis"], {"carrier-width": 1, "unstated": 1})


class Baseline(unittest.TestCase):
    """A recorded silent error is carried with its cause; any other is the failure the gate exists to catch."""

    TRUTH = {0x1000: dt.Seen(proto("int", []), False)}
    WRONG = {0x1000: dt.Seen(proto("size_t", []), False)}
    KEY = "sym.f return: expected 'int', said 'size_t'"

    def record(self, directory: str, why: dict | None) -> pathlib.Path:
        path = pathlib.Path(directory) / "baseline.json"
        path.write_text(json.dumps({"silent": [self.KEY], "why": why or {}}))
        return path

    def test_a_recorded_error_with_a_cause_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.record(directory, {self.KEY: "no sign is proven"})
            code, _, _ = run_gate(self.TRUTH, self.WRONG, "--baseline", str(path))
        self.assertEqual(code, 0)

    def test_a_new_silent_error_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "baseline.json"
            path.write_text(json.dumps({"silent": [], "why": {}}))
            code, _, err = run_gate(self.TRUTH, self.WRONG, "--baseline", str(path))
        self.assertEqual(code, 1)
        self.assertIn(f"SILENT ERROR: {self.KEY}", err)

    def test_a_recorded_error_with_no_cause_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.record(directory, None)
            code, _, err = run_gate(self.TRUTH, self.WRONG, "--baseline", str(path))
        self.assertEqual(code, 1)
        self.assertIn(f"NO CAUSE: {self.KEY}", err)

    def test_accepting_carries_the_cause_and_drops_the_fixed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.record(directory, {self.KEY: "no sign is proven", "gone": "was fixed"})
            code, _, _ = run_gate(self.TRUTH, self.WRONG, "--baseline", str(path), "--accept-baseline")
            written = json.loads(path.read_text())
        self.assertEqual(code, 0)
        self.assertEqual(written["why"], {self.KEY: "no sign is proven"})

    def test_accepting_an_error_with_no_cause_says_so(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "baseline.json"
            code, _, err = run_gate(self.TRUTH, self.WRONG, "--baseline", str(path), "--accept-baseline")
            written = json.loads(path.read_text())
        self.assertEqual(code, 1)
        self.assertIn(f"NO CAUSE: {self.KEY}", err)
        self.assertEqual(written["silent"], [self.KEY])


if __name__ == "__main__":
    unittest.main()
