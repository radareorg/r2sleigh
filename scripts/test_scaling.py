#!/usr/bin/env python3
"""Unit tests for the scaling bench's arithmetic and generators (ROADMAP D404). No binary runs."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scaling  # noqa: E402


class Growth(unittest.TestCase):
    def test_a_linear_pass_reads_two_and_a_quadratic_four(self) -> None:
        fixed = 1_000_000_000
        self.assertEqual(scaling.growth(fixed, fixed + 5_000, fixed + 10_000), 2.0)
        self.assertEqual(scaling.growth(fixed, fixed + 5_000, fixed + 20_000), 4.0)

    def test_the_fixed_cost_hides_no_quadratic(self) -> None:
        # Ir(N) and Ir(2N) alone read 1.000015 here; less Ir(0) they read 4.
        fixed = 1_000_000_000
        self.assertGreater(scaling.growth(fixed, fixed + 5_000, fixed + 20_000), scaling.BUDGET)

    def test_a_size_that_costs_nothing_is_refused(self) -> None:
        self.assertIsNone(scaling.growth(10, 10, 12))
        self.assertIn("does not reach", scaling.verdict("d", None, 2.3, {}))


class Verdict(unittest.TestCase):
    def test_over_budget_fails_unless_open(self) -> None:
        self.assertIn("above 2.3", scaling.verdict("d", 3.9, 2.3, {}))
        self.assertIsNone(scaling.verdict("d", 3.9, 2.3, {"d": "D397"}))

    def test_an_open_dimension_that_holds_fails_until_its_entry_goes(self) -> None:
        self.assertIn("delete its OPEN entry (D397)", scaling.verdict("d", 2.0, 2.3, {"d": "D397"}))
        self.assertIsNone(scaling.verdict("d", 2.0, 2.3, {}))


class Generators(unittest.TestCase):
    def test_each_dimension_grows_its_source_with_n(self) -> None:
        for name, generate in scaling.DIMENSIONS.items():
            sizes = [len(generate(n)[1]) for n in (0, 8, 16)]
            self.assertLess(sizes[0], sizes[1], name)
            self.assertLess(sizes[1], sizes[2], name)
            self.assertIn(generate(8)[0], ("s", "c"), name)

    def test_the_sources_are_deterministic(self) -> None:
        for name, generate in scaling.DIMENSIONS.items():
            self.assertEqual(generate(16), generate(16), name)


if __name__ == "__main__":
    unittest.main()
