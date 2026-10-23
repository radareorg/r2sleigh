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


if __name__ == "__main__":
    unittest.main()
