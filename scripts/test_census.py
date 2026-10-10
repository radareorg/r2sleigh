#!/usr/bin/env python3
"""Unit tests for the census's residual-site check on renderings the staged pipeline printed.

Pure Python; no binary runs.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import census  # noqa: E402

# RISC-V `shape_call_chain` before the frame-setup fact: two prologue adds counted, no site.
HIDDEN = """
    /* r2dec proof: no individual construct is marked; 142 source obligations: 92 rendered, 33 elided, 0 refused, 15 assumed (frame extent unproven), 2 residual; 39 statements rendered */
    {
        return (uint64_t)a0_3;
    }
"""

SITED = """
    /* r2dec proof: 2 constructs are marked below; 26 source obligations: 10 rendered, 12 elided, 0 refused, 4 residual; 6 statements rendered */
    {
        if (c) {
            return r2sleigh_residual_u64(1);
        }
        r2sleigh_residual_void(2); /* r2dec gap: TailTransferNotRendered at 0x401070 (render::control) */
    }
"""

UNACCOUNTED = """
    /* r2dec proof: no individual construct is marked; 10 source obligations: 8 rendered, 0 elided, 0 refused, 2 unaccounted; 3 statements rendered */
"""

# rv_O0g `sum_array`: ten private reads r2ssa seeds though nothing observes them, named.
PENDING = """
    /* r2dec proof: no individual construct is marked; 53 source obligations: 28 rendered, 15 elided, 0 refused, 10 residual (10 without a site: pending obligation seeding); 13 statements rendered */
"""

REFUSED = """/* r2sleigh refused sum_array: native effect obligations refused: 0 refused, 10 unaccounted (live-value-producer at 0x11e0:op:24), 0 conflicts */
"""


class ResidualSites(unittest.TestCase):
    def test_a_counted_residual_without_a_site_is_a_mismatch(self) -> None:
        self.assertEqual(census.site_mismatches(HIDDEN), ["2 residual, no site"])

    def test_each_site_in_the_text_is_counted(self) -> None:
        self.assertEqual(census.residual_sites(SITED), (2, 4, 0, 2))
        self.assertEqual(census.site_mismatches(SITED), [])

    def test_an_unaccounted_obligation_is_a_mismatch(self) -> None:
        self.assertEqual(census.site_mismatches(UNACCOUNTED), ["2 unaccounted"])

    def test_a_residual_without_a_site_under_a_named_cause_is_listed_not_failed(self) -> None:
        self.assertEqual(census.unsited(PENDING), {"pending obligation seeding": 10})
        self.assertEqual(census.site_mismatches(PENDING), [])
        unnamed = PENDING.replace("10 residual (10 without", "11 residual (10 without")
        self.assertEqual(census.site_mismatches(unnamed), ["1 residual, no site"])

    def test_a_refusal_has_no_proof_line_and_is_listed_with_its_kind(self) -> None:
        self.assertEqual(census.site_mismatches(REFUSED), [])
        found = census.REFUSED_UNACCOUNTED.search(REFUSED)
        self.assertEqual((found[1], found[2], found[3]), ("sum_array", "10", "live-value-producer at 0x11e0:op:24"))


if __name__ == "__main__":
    unittest.main()
