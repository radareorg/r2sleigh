#!/usr/bin/env python3
"""Unit tests for the differential's judged disagreements.

Pure Python; no binary runs.
"""

from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import diff_r2  # noqa: E402

TABLE = """
[[judged]]
command = "pd"
binaries = "arm*"
r2 = 'push \\{'
r2s = 'stmdb sp!'
verdict = "r2-right"
reason = "alias"

[[judged]]
command = "iS"
binaries = "*"
values = ["0x70000001"]
verdict = "unfilled"
reason = "processor-specific type"

[[judged]]
command = "px"
binaries = "gone"
verdict = "r2s-right"
reason = "nothing matches this"
"""


def judgments():
    with tempfile.TemporaryDirectory() as directory:
        path = pathlib.Path(directory) / "judged.toml"
        path.write_text(TABLE)
        return diff_r2.load_judgments(path)


class Judged(unittest.TestCase):
    def test_a_listing_pair_is_judged_by_both_lines_and_the_binary(self):
        table = judgments()
        pair = ("lines", ("0x10 push {fp, lr}", "0x10 stmdb sp!, {fp, lr}"))
        self.assertIsNotNone(diff_r2.judgment_for(table, "arm1.bin", "pd 8", pair))
        self.assertIsNone(diff_r2.judgment_for(table, "x86.bin", "pd 8", pair))
        other = ("lines", ("0x10 push {fp, lr}", "0x10 push {fp, lr}, extra"))
        self.assertIsNone(diff_r2.judgment_for(table, "arm1.bin", "pd 8", other))

    def test_a_value_is_judged_only_by_its_listed_values(self):
        table = judgments()
        self.assertIsNotNone(diff_r2.judgment_for(table, "any", "iS", ("value", 0x70000001)))
        self.assertIsNone(diff_r2.judgment_for(table, "any", "iS", ("value", 0x70000002)))

    def test_a_judgment_nothing_matched_is_left_unmatched(self):
        table = judgments()
        diff_r2.judgment_for(table, "arm1.bin", "pd 8", ("lines", ("push {r4}", "stmdb sp!, {r4}")))
        self.assertEqual([j["reason"] for j in table if j["matched"] == 0][-1], "nothing matches this")

    def test_an_unknown_verdict_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "judged.toml"
            path.write_text(TABLE.replace('"unfilled"', '"maybe"'))
            with self.assertRaises(ValueError):
                diff_r2.load_judgments(path)

    def test_every_listing_line_that_differs_is_one_disagreement(self):
        found = diff_r2.differences("pd 8", "exact", "0x1 nop\n0x2 ret\n", "0x1 nop\n0x2 leave\n0x3 ret\n")
        self.assertEqual(
            found, [("lines", ("0x2 leave", "0x2 ret")), ("lines", ("0x3 ret", None))]
        )


if __name__ == "__main__":
    unittest.main()
