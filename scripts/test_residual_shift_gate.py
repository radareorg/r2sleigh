#!/usr/bin/env python3
"""Unit tests for the `<< 32` residual gate (ROADMAP D211). Pure Python; no binary runs."""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import residual_shift_gate as gate  # noqa: E402

SITE = "x = (uint64_t)(uint32_t)f() | r2sleigh_residual_u64(3) << 32;\n"
ROADMAP = "| D413 | a row | a gate | open |\n| D300 | a row | a gate | built 1234 |\n"


def entry(**fields: object) -> dict:
    row = {"set": "O2", "binary": "grep_grep", "address": "0x8030", "sites": 1, "class": "c"}
    row.update(fields)
    if "proof" not in row and "row" not in row:
        row["row"] = "D413"
    return row


class Gate(unittest.TestCase):
    def judge(self, codes: dict, entries: list) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            renders = pathlib.Path(tmp) / "O2"
            renders.mkdir()
            rows = {address: {"code": code} for address, code in codes.items()}
            (renders / "grep_grep.json").write_text(json.dumps(rows))
            return gate.failures({"O2": renders}, entries, gate.open_rows(ROADMAP))

    def test_an_unlisted_site_fails(self) -> None:
        self.assertTrue(self.judge({"0x8030": SITE}, []))

    def test_a_listed_site_passes(self) -> None:
        self.assertEqual(self.judge({"0x8030": SITE}, [entry()]), [])

    def test_an_entry_whose_function_holds_no_site_fails(self) -> None:
        self.assertTrue(self.judge({"0x8030": "x = 1;\n"}, [entry()]))

    def test_more_sites_than_listed_fails(self) -> None:
        self.assertTrue(self.judge({"0x8030": SITE + SITE}, [entry()]))

    def test_a_row_roadmap_does_not_hold_open_fails(self) -> None:
        self.assertTrue(self.judge({"0x8030": SITE}, [entry(row="D300")]))
        self.assertTrue(self.judge({"0x8030": SITE}, [entry(row="D999")]))

    def test_an_entry_names_a_proof_or_a_row(self) -> None:
        proof = entry(proof="the hasher is called through a heap field")
        self.assertEqual(self.judge({"0x8030": SITE}, [proof]), [])
        neither = entry()
        del neither["row"]
        self.assertTrue(self.judge({"0x8030": SITE}, [neither]))

    def test_the_committed_table_parses_and_counts_its_sites(self) -> None:
        entries = gate.load(gate.TABLE)
        self.assertEqual(sum(row["sites"] for row in entries), 24)
        self.assertEqual(len(entries), 19)


if __name__ == "__main__":
    unittest.main()
