#!/usr/bin/env python3
"""The ternary census counts a `?:` by what wrote it, from the text of a rendering."""

from __future__ import annotations

import collections
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import ternary_census  # noqa: E402

GUARD = "x = (uint32_t)8U >= (uint32_t)32U ? (uint32_t)0U : (uint32_t)(a << (uint32_t)8U);"
WIDENED = "x = (uint64_t)(uint32_t)2U >= (uint64_t)64U ? (uint64_t)0U : (uint64_t)(a << (uint32_t)2U);"
SIGN_FILL = "x = (uint32_t)1U >= (uint32_t)32U ? a < 0U ? (uint32_t)-0x1 : (uint32_t)0U : (uint32_t)(a >> 1U);"
VARIABLE = "x = (uint32_t)n >= (uint32_t)32U ? (uint32_t)0U : (uint32_t)(a << n);"
SELECT = "x = (uint8_t)(a < b) ? a : b;"


def classes(line, absent=None):
    return collections.Counter(ternary_census.classify("    " + line, absent))


class TernaryCensus(unittest.TestCase):
    def test_a_literal_count_is_a_guard_by_its_cast_shape(self):
        self.assertEqual(classes(GUARD)["literal count single"], 1)
        self.assertEqual(classes(WIDENED)["literal count widened"], 1)
        self.assertEqual(classes(SIGN_FILL)["literal count arithmetic"], 1)

    def test_a_literal_guard_inside_an_expression_is_counted_anywhere_and_not_as_a_statement(self):
        found = classes("x = (uint32_t)(a | ((uint32_t)8U >= (uint32_t)32U ? (uint32_t)0U : b));")
        self.assertEqual((found["literal count anywhere"], found["literal count"]), (1, 0))

    def test_a_variable_count_is_a_guard_and_no_literal_one(self):
        found = classes(VARIABLE)
        self.assertEqual((found["guard"], found["literal count"]), (1, 0))

    def test_a_select_is_branch_born_only_where_the_other_build_lacks_the_line(self):
        line = "    " + SELECT
        self.assertEqual(classes(SELECT, collections.Counter())["branch-born"], 1)
        self.assertEqual(classes(SELECT, collections.Counter([line]))["data"], 1)
        self.assertEqual(classes(SELECT)["data"], 1)

    def test_a_ternary_inside_a_call_is_held_but_not_whole(self):
        found = classes("x = f(a ? b : c);")
        self.assertEqual((found["holding"], found["whole"]), (1, 0))
        self.assertEqual(classes(SELECT)["whole"], 1)

    def test_a_dump_is_counted_by_function(self):
        with tempfile.TemporaryDirectory() as tmp:
            dump = Path(tmp)
            (dump / "manifest.json").write_text("{}")
            rows = {"f": {"code": f"{GUARD}\n{SELECT}"}, "g": {"code": SELECT}, "h": {"code": None}}
            (dump / "O2.p.b.json").write_text(json.dumps(rows))
            found = ternary_census.census(dump)
        self.assertEqual(found["holding"], (3, 2))
        self.assertEqual(found["guard"], (1, 1))


if __name__ == "__main__":
    unittest.main()
