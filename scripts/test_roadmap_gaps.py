#!/usr/bin/env python3
"""Unit tests for the gap table's gate (ROADMAP D349)."""

from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import roadmap_gaps  # noqa: E402

TABLE = roadmap_gaps.HEADER + "\n|-----|------|-------|------|------|-------|\n"


def tree(roadmap: str, adr: str = "") -> pathlib.Path:
    root = pathlib.Path(tempfile.mkdtemp())
    (root / "doc").mkdir()
    (root / "ROADMAP.md").write_text(roadmap)
    (root / "doc" / "adr-x.md").write_text(adr)
    return root


def gap(number, owner="r2ssa", rows="S1: D10", state="closed"):
    return f"| G{number} | a fact | {owner} | {rows} | a gate | {state} |\n"


ROWS = "| D10 | a row. Built | r2ssa; built |\n| D11 | a row | r2ssa; open |\n| D12 | a row, refused | r2ssa |\n"


class Gate(unittest.TestCase):
    def check(self, roadmap, adr=""):
        return roadmap_gaps.check(tree(roadmap, adr))

    def test_the_repository_passes(self):
        self.assertEqual(roadmap_gaps.check(roadmap_gaps.ROOT), [])

    def test_a_bare_citation_fails_and_a_worded_one_resolves(self):
        roadmap = ROWS + TABLE + gap(7)
        self.assertEqual(self.check(roadmap, "see gap G7 and Gap G7's row\n"), [])
        failures = self.check(roadmap, "see G7\n")
        self.assertEqual(len(failures), 1)
        self.assertIn("cite G7 as `gap G7`", failures[0])

    def test_a_citation_with_no_row_fails(self):
        failures = self.check(ROWS + TABLE + gap(7), "gap G8\n")
        self.assertEqual(len(failures), 1)
        self.assertIn("G8 has no row", failures[0])

    def test_g0_and_a_unit_are_no_gap(self):
        self.assertEqual(self.check(ROWS + TABLE + gap(7), "item G0; 64.38 G; 0.20 G; G9.5; DG7\n"), [])

    def test_no_table_fails(self):
        self.assertIn("no gap table", self.check(ROWS)[0])

    def test_one_owner_per_row(self):
        failures = self.check(ROWS + TABLE + gap(7, owner="r2ssa, r2engine"))
        self.assertEqual(len(failures), 1)
        self.assertIn("names one owner", failures[0])

    def test_closed_needs_every_row_built(self):
        self.assertEqual(self.check(ROWS + TABLE + gap(7, rows="S1: D10")), [])
        failures = self.check(ROWS + TABLE + gap(7, rows="S1: D10, D11"))
        self.assertIn("D11 is not built", failures[0])
        failures = self.check(ROWS + TABLE + gap(7, rows="S1: D99"))
        self.assertIn("D99 is not built", failures[0])

    def test_a_row_whose_state_cell_says_open_is_not_built(self):
        rows = "| D10 | half built | r2ssa; DWARF half built, proof kind open |\n"
        self.assertIn("D10 is not built", self.check(rows + TABLE + gap(7))[0])

    def test_open_fails_once_every_row_is_built(self):
        self.assertEqual(self.check(ROWS + TABLE + gap(7, rows="D10, D11", state="open")), [])
        self.assertIn("close it", self.check(ROWS + TABLE + gap(7, rows="D10", state="open"))[0])

    def test_refused_needs_a_refusing_row(self):
        self.assertEqual(self.check(ROWS + TABLE + gap(7, rows="D12", state="refused")), [])
        self.assertIn("no named D-row says refused", self.check(ROWS + TABLE + gap(7, rows="D11", state="refused"))[0])

    def test_planned_and_not_sliced_name_no_row(self):
        self.assertEqual(self.check(ROWS + TABLE + gap(7, rows="S34 step 1", state="planned")), [])
        self.assertEqual(self.check(ROWS + TABLE + gap(7, rows="none", state="not sliced")), [])
        self.assertIn("so it is `planned`", self.check(ROWS + TABLE + gap(7, rows="S34 step 1", state="open"))[0])
        self.assertIn("names D-rows", self.check(ROWS + TABLE + gap(7, rows="D11", state="planned"))[0])

    def test_a_state_outside_the_set_fails(self):
        self.assertIn("is none of", self.check(ROWS + TABLE + gap(7, state="master"))[0])

    def test_two_rows_for_one_gap_fail(self):
        self.assertIn("has two rows", self.check(ROWS + TABLE + gap(7) + gap(7))[0])


if __name__ == "__main__":
    unittest.main()
