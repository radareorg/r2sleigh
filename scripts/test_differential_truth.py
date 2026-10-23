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
        same = {0x1000: (dt.Prototype("uint64_t", ["uint8_t*"], ["arg0"]), False)}
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


def graded(truth: dict, recovered: dict) -> dict:
    """The report main prints for a debug build with these prototypes and a stripped build with those.

    A function with a source-named parameter, right in both builds, keeps the truth real.
    """
    debug, stripped = pathlib.Path("debug"), pathlib.Path("stripped")
    anchor = {0x9000: (proto("int", ["int"], ["count"]), False)}
    seen = {debug: {**truth, **anchor}, stripped: {**recovered, **anchor}}
    out = io.StringIO()
    argv = ["differential_truth.py", "--debug-build", str(debug), "--stripped-build", str(stripped)]
    with (
        mock.patch.object(sys, "argv", argv),
        mock.patch.object(dt, "signatures", side_effect=lambda binary, _r2s: seen[binary]),
        mock.patch.object(dt, "names", return_value={0x1000: "sym.f"}),
        contextlib.redirect_stdout(out),
        contextlib.redirect_stderr(io.StringIO()),
    ):
        dt.main()
    return json.loads(out.getvalue())


class SilentBuckets(unittest.TestCase):
    """Every wrong fact lands in one bucket, so a fix can be graded by the bucket it empties."""

    def one(self, expected: str, said: str, where: str = "return", marked: bool = False) -> dict:
        if where == "return":
            truth, got = proto(expected, []), proto(said, [])
        else:
            truth, got = proto("int", [expected]), proto("int", [said])
        return graded({0x1000: (truth, False)}, {0x1000: (got, marked)})

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


if __name__ == "__main__":
    unittest.main()
