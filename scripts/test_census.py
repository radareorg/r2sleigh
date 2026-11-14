#!/usr/bin/env python3
"""Unit tests for the census's residual-site check on renderings the staged pipeline printed.

Pure Python; no binary runs.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
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


class ExponentFit(unittest.TestCase):
    def test_a_power_law_fits_its_exponent(self):
        slope, r2 = census.fit([(n, 3 * n**2) for n in (300, 600, 1200, 5000)])
        self.assertAlmostEqual(slope, 2.0)
        self.assertAlmostEqual(r2, 1.0)

    def test_a_sample_spans_every_size(self):
        rows = [(address, address // 10) for address in range(3000, 13000, 10)]
        picked = census.evenly(rows, 5)
        self.assertEqual(len(picked), 5)
        self.assertEqual(min(n for _, n in picked), 300)
        self.assertEqual(max(n for _, n in picked), 1299)



class HeapSites(unittest.TestCase):
    def test_a_site_is_its_first_two_project_frames_past_the_allocator(self):
        profile = {
            "ftbl": ["[root]", "0x1: alloc (alloc/src/alloc.rs:95:9)",
                     "0x2: push (r2ssa/src/graph.rs:485:23)", "0x3: seal (src/function/stage.rs:199:25)",
                     "0x4: main (r2s/src/main.rs:47:29)"],
            "pps": [{"gb": 300, "fs": [1, 2, 3, 4]}, {"gb": 0, "fs": [1, 4]}, {"gb": 20, "fs": [1, 2, 3]}],
        }
        sites = census.heap_sites(profile)
        site = "push (r2ssa/src/graph.rs:485:23) <- seal (src/function/stage.rs:199:25)"
        self.assertEqual(sites, {site: 320})


# F1 of crates/r2engine/tests/engine/structure.rs under two write orders: the loop's merge `rax_2` has a gap for
# its entry copy, and one order reads it as a variable in the exit after the loop.
EXIT_INLINED = """
    /* r2dec proof: 3 constructs are marked below; 36 source obligations: 20 rendered, 8 elided, 0 refused, 8 residual; 11 statements rendered; 1 never assigned, read as residuals (RAX_2) */
    {
        r2sleigh_residual_void(1); /* r2dec gap: ValuesNotRendered at 0x1009 (render::values) */
        rdi_1 = arg0;
        for (; ; ) {
            if (c) {
                return (uint64_t)r2sleigh_residual_u64(2);
            } else {
                rax_2 = (uint64_t)((uint64_t)r2sleigh_residual_u64(3) + (uint64_t)1U);
                continue;
            }
        }
        L1:
        {
            return (uint64_t)((uint64_t)rax_2 + (uint64_t)5U);
        }
    }
"""
EXIT_AFTER = EXIT_INLINED.replace("r2sleigh_residual_u64(2)", "rax_2").replace("20 rendered", "22 rendered")


def record(code, **parts):
    base = {"refused": None, "code": code, "proof": {"total": 36, "residual": 8}, "variables": [], "links": [],
            "lines": [{"line": 5, "addrs": [4096]}],
            "residuals": [{"site": 1, "type": "void", "cause": "gap", "gap": "ValuesNotRendered", "callee": None,
                           "reason": None, "line": 5}]}
    return {**base, **parts}


class WriteOrders(unittest.TestCase):
    def test_the_names_read_as_never_assigned_come_from_the_proof_line(self) -> None:
        self.assertEqual(census.never_assigned(EXIT_INLINED), ["RAX_2"])
        self.assertEqual(census.never_assigned(HIDDEN), [])

    def test_statements_are_leaves_without_control_or_site_numbers(self) -> None:
        leaves = census.leaf_statements(EXIT_INLINED)
        self.assertIn("rdi_1 = arg0;", leaves)
        self.assertIn("rax_2 = (uint64_t)((uint64_t)r2sleigh_residual_u64(N) + (uint64_t)1U);", leaves)
        self.assertIn("r2sleigh_residual_void(N); /* r2dec gap: ValuesNotRendered at 0x1009 (render::values) */", leaves)
        self.assertFalse([leaf for leaf in leaves if leaf.startswith(("for", "if", "continue", "L1"))])
        self.assertEqual(census.leaf_statements("L17: ;\nL4:\n    x = 1;\n"), ["x = 1;"])

    def test_a_layout_that_moves_only_control_moves_no_verdict(self) -> None:
        moved = EXIT_INLINED.replace("continue;", "goto L0;").replace("L1:", "L1: L2:")
        self.assertEqual(census.verdict_moves(census.fingerprint(record(EXIT_INLINED)),
                                              census.fingerprint(record(moved))), ([], None))

    def test_a_read_that_turns_from_a_residual_into_a_variable_is_a_moved_verdict(self) -> None:
        moves, refusal = census.verdict_moves(census.fingerprint(record(EXIT_INLINED)),
                                              census.fingerprint(record(EXIT_AFTER)))
        self.assertEqual((moves, refusal), (["statements"], None))

    def test_the_ledger_and_the_residual_sites_are_verdicts(self) -> None:
        natural = census.fingerprint(record(EXIT_INLINED))
        columns = census.fingerprint(record(EXIT_INLINED, proof={"total": 36, "residual": 6}))
        sites = census.fingerprint(record(EXIT_INLINED, lines=[{"line": 5, "addrs": [4100]}]))
        self.assertEqual(census.verdict_moves(natural, columns), (["proof"], None))
        self.assertEqual(census.verdict_moves(natural, sites), (["sites"], None))

    def test_a_selection_the_structurer_chose_differently_is_no_move(self) -> None:
        arms = EXIT_INLINED.replace("rdi_1 = arg0;", "x_1 = 1;\n        x_1 = 2;")
        selected = EXIT_INLINED.replace("rdi_1 = arg0;", "x_1 = c ? 1 : 2;")
        natural, mutant = census.fingerprint(record(arms)), census.fingerprint(record(selected))
        self.assertEqual(census.verdict_moves(natural, mutant), ([], None))
        self.assertNotEqual(natural["statements"], mutant["statements"])

    def test_a_statement_that_is_no_selection_is_a_move(self) -> None:
        other = EXIT_INLINED.replace("rdi_1 = arg0;", "x_1 = 1;\n        y_1 = 2;")
        lone = EXIT_INLINED.replace("rdi_1 = arg0;", "x_1 = c ? 1 : 2;")
        moves = census.verdict_moves(census.fingerprint(record(other)), census.fingerprint(record(lone)))
        self.assertEqual(moves, (["statements"], None))
        # A target assigned on one side only is no selection either.
        gone = census.fingerprint(record(EXIT_INLINED.replace("rdi_1 = arg0;", "")))
        self.assertEqual(census.verdict_moves(census.fingerprint(record(EXIT_INLINED)), gone)[0], ["statements"])

    def test_a_function_refused_under_one_side_only_is_reported_with_the_side(self) -> None:
        refused = census.fingerprint(record(REFUSED, refused={"kind": "rendering", "reason": "control certificate"}))
        natural = census.fingerprint(record(EXIT_INLINED))
        self.assertEqual(census.verdict_moves(natural, refused), ([], "refused only under the mutant"))
        self.assertEqual(census.verdict_moves(refused, natural), ([], "refused only at natural"))
        # No answer (a crash) is no fingerprint, and two of them agree.
        self.assertEqual(census.verdict_moves(natural, None), ([], "refused only under the mutant"))
        self.assertEqual(census.verdict_moves(None, natural), ([], "refused only at natural"))
        self.assertEqual(census.verdict_moves(None, None), ([], None))

    def test_a_verdict_that_moves_inside_a_refusal_is_a_moved_verdict(self) -> None:
        # ls-toybox 0x5323c: refused the same way, with 214 residual obligations on one side and 216 on the other.
        reason = {"kind": "rendering", "reason": "native effect obligations refused: 0 refused, 1 unaccounted"}
        was = census.fingerprint(record(REFUSED, refused=reason, proof={"total": 1252, "residual": 214}))
        now = census.fingerprint(record(REFUSED, refused=reason, proof={"total": 1252, "residual": 216}))
        self.assertEqual(census.verdict_moves(was, now), (["proof"], None))
        again = census.fingerprint(record(REFUSED, refused=reason, proof={"total": 1252, "residual": 214}))
        self.assertEqual(census.verdict_moves(was, again), ([], None))
        elsewhere = census.fingerprint(record(REFUSED, refused={**reason, "reason": reason["reason"] + " at 0x53748"},
                                              proof={"total": 1252, "residual": 214}))
        self.assertEqual(census.verdict_moves(was, elsewhere), (["refusal"], None))



# Run 43460444577 (Ge's tip 05da11feb against its base): each case's base and head allocation counts.
GE_TIP = {
    "0pack pdd @ 0x0058e3d0": (10_993_000, 11_219_817),
    "0pack pdd @ 0x0062ecf0": (12_322_511, 12_321_097),
    "pumasim pdd @ 0x0023fdf0": (27_296_158, 27_120_506),
    "pumasim pdd @ 0x004baf30": (20_561_863, 21_088_630),
    "pumasim afl": (99_622_591, 108_961_709),
    "0pack afl": (84_175_920, 88_592_097),
    "pumasim session: pdd of 50 functions": (149_880_316, 151_306_743),
}


class CountedBudget(unittest.TestCase):
    """D401: an allocation rise past 1.02 x the base fails unless a cause line names it."""

    def failing(self, entries):
        return sorted(case for case, (base, head) in GE_TIP.items()
                      if census.counted_rise("allocations", case, base, head, 1.02, entries))

    def test_ge_tip_fails_the_budget_on_four_cases(self) -> None:
        # 1.3 passed all seven; 1.02 fails afl twice, 0x4baf30 at 1.0256 and 0x58e3d0 at 1.0206.
        self.assertEqual(self.failing({}), ["0pack afl", "0pack pdd @ 0x0058e3d0",
                                            "pumasim afl", "pumasim pdd @ 0x004baf30"])

    def test_the_message_prints_the_ratio_to_four_places(self) -> None:
        base, head = GE_TIP["0pack pdd @ 0x0058e3d0"]
        rise = census.counted_rise("allocations", "0pack pdd @ 0x0058e3d0", base, head, 1.02, {})
        self.assertIn("1.0206x", rise)
        self.assertIn(f"| {base} | {head} | Dnnn |", rise)

    def test_a_cause_line_for_the_base_count_lets_the_rise_stand(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as ledger:
            ledger.write("# header\nallocations | pumasim afl | 99622591 | 108961709 | D367 | dispatch rounds\n")
        entries = census.causes(ledger.name)
        self.assertNotIn("pumasim afl", self.failing(entries))
        self.assertEqual(len(self.failing(entries)), 3)

    def test_a_cause_line_excuses_no_other_base_and_no_higher_head(self) -> None:
        entries = {("allocations", "pumasim afl", 99_622_590): (108_961_709, "D367", "x")}
        self.assertIn("pumasim afl", self.failing(entries))
        entries = {("allocations", "pumasim afl", 99_622_591): (108_961_708, "D367", "x")}
        self.assertIn("pumasim afl", self.failing(entries))

    def test_a_cause_line_without_a_row_is_refused(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as ledger:
            ledger.write("allocations | pumasim afl | 1 | 2 | because | slower\n")
        with self.assertRaises(SystemExit):
            census.causes(ledger.name)

    def test_the_committed_ledger_parses(self) -> None:
        census.causes()


class CountedInstructions(unittest.TestCase):
    """D343: D365's adaef5bf0 against its parent, cold pumasim 0x23fdf0 under qemu-x86_64 (contabo)."""

    def test_d365_fails_the_one_percent_budget(self) -> None:
        rise = census.counted_rise("instructions", "pumasim pdd @ 0x0023fdf0", 21_615_983_388,
                                   23_071_247_954, 1.01, {})
        self.assertIn("1.0673x", rise)


class CountedSpread(unittest.TestCase):
    """D343: one cause line holds two CI runs of the same pair, whose qemu counts moved by
    hundreds of instructions (43574739669, 43579827833 on rebuild-design-4)."""

    CASE = "pumasim pdd @ 0x0023fdf0"
    LINE = {("instructions", CASE, 36_156_969_404): (36_686_716_718, "D381", "x")}

    def rise(self, base, head, entries=None):
        return census.counted_rise("instructions", self.CASE, base, head, 1.01,
                                   self.LINE if entries is None else entries)

    def test_both_runs_stand_on_one_line(self) -> None:
        self.assertIsNone(self.rise(36_156_969_404, 36_686_716_718))
        self.assertIsNone(self.rise(36_156_968_947, 36_686_716_130))

    def test_a_far_base_and_a_higher_head_still_fail(self) -> None:
        self.assertIsNotNone(self.rise(36_100_000_000, 36_686_716_130))
        self.assertIsNotNone(self.rise(36_156_968_947, 36_700_000_000))
        self.assertIsNotNone(self.rise(36_156_968_947, 36_686_716_130, {}))

    def test_allocations_keep_the_exact_key(self) -> None:
        entries = {("allocations", "pumasim afl", 99_622_591): (108_961_709, "D367", "x")}
        self.assertIsNotNone(census.counted_rise("allocations", "pumasim afl", 99_622_592,
                                                 108_961_709, 1.02, entries))


class TimedCases(unittest.TestCase):
    """D402: the chain's analysed cases are timed, and a missing binary fails the run."""

    def test_the_analysed_cases_are_timed_and_counted(self) -> None:
        for case in (("pumasim", "aa; pdd @ 0x3b6b20"), ("bash", "aa; pdd @ 0x2e630")):
            self.assertIn(case, census.TIMED)
            self.assertIn(case, census.COUNTED)

    def test_a_missing_binary_fails(self) -> None:
        with tempfile.TemporaryDirectory() as empty:
            args = argparse.Namespace(bins=empty, r2s=["/nonexistent", "/nonexistent"], runs=1,
                                      count_r2s=None, budget=1.3, rss_budget=1.1, alloc_budget=1.02,
                                      heap_budget=1.05, causes=str(census.CAUSES))
            with self.assertRaises(SystemExit):
                census.time_cases(args)


class StatsRatchet(unittest.TestCase):
    """D403: the engine's work counts are held exactly, a rise and a fall alike."""

    def test_a_rebuild_more_or_fewer_moves(self) -> None:
        held = {("pumasim pdd @ 0x0023fdf0", "rebuilt"): 0, ("pumasim pdd @ 0x0023fdf0", "frames_built"): 40}
        rose = {**held, ("pumasim pdd @ 0x0023fdf0", "rebuilt"): 21}
        fell = {**held, ("pumasim pdd @ 0x0023fdf0", "frames_built"): 39}
        self.assertEqual(census.stats_moves(held, rose), ["pumasim pdd @ 0x0023fdf0: rebuilt 0 -> 21"])
        self.assertEqual(census.stats_moves(held, fell), ["pumasim pdd @ 0x0023fdf0: frames_built 40 -> 39"])
        self.assertEqual(census.stats_moves(held, dict(held)), [])

    def test_a_stat_one_side_lacks_moves(self) -> None:
        self.assertEqual(census.stats_moves({}, {("c", "table_seals"): 3}), ["c: table_seals absent -> 3"])

    def test_the_baseline_reads_back_what_the_printer_writes(self) -> None:
        text = "r2s: stats: sealed.computed 12\nr2s: stats: frames_built 7\n"
        self.assertEqual(census.STAT.findall(text), [("sealed.computed", "12"), ("frames_built", "7")])


if __name__ == "__main__":
    unittest.main()
