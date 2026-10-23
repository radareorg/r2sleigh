#!/usr/bin/env python3
"""Unit tests for the source-gold harness: what it reads as a prototype, as a real truth, and as a silent error.

Pure Python; every `r2s` answer is canned, so no binary runs.
"""

from __future__ import annotations

import contextlib
import io
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


if __name__ == "__main__":
    unittest.main()
