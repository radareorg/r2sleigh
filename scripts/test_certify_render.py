#!/usr/bin/env python3
"""Unit tests for the certification gate's reading of a rendering.

The gate decides whether a rendering reads a value nothing wrote. No proof
line excuses one: the renderer writes a read of a value C cannot name as a
residual. These pin that reading down on renderings the engine really printed.
They are pure Python and run no binary.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import certify_render as gate  # noqa: E402


def lines(text: str) -> list[str]:
    return gate.clean(text)


# `movq xmm0, rdi; pshufd xmm0, xmm0, 0x44; movhlps xmm0, xmm0; movq rax, xmm0;
# ret`, as the engine rendered it before the observation mask counted bytes.
# The argument was read and never admitted as a parameter, and the proof line's
# one value held from entry was the return-address slot, which the body never
# spells.
HI_QWORD_COUNTED = """
uint64_t _hi_qword(void)
{
    /* r2dec proof: no individual construct is marked; 14 source obligations: 11 rendered, 3 elided, 0 refused; 11 statements rendered; 1 held from entry */
    {
        uint64_t RDI_0;
        __uint128_t XMM0_1;
        XMM0_1 = (__uint128_t)RDI_0;
        uint32_t tmp_lane_100000310_1_0_1 = (uint32_t)RDI_0;
        uint32_t tmp_lane_100000310_2_1_1 = (uint32_t)(RDI_0 >> 32);
        uint64_t tmp_lane_100000310_41_8_1 = (uint64_t)(XMM0_1 >> 64);
        return tmp_lane_100000310_41_8_1;
    }
}
"""

# `lea rax, [rbx + rsi]; ret`, as the engine rendered it before residuals.
ENTRY_AND_ARGUMENT = """
uint64_t _both(void)
{
    /* r2dec proof: no individual construct is marked; 7 source obligations: 4 rendered, 3 elided, 0 refused; 3 statements rendered; 1 held from entry (RBX_0); 1 argument slot read with no parameter (RSI_0) */
    {
        uint64_t RSI_0;
        uint64_t RBX_0;
        return RBX_0 + RSI_0;
    }
}
"""

# `lea rax, [rbx + rsi]; ret`, as the engine renders it now: each read of a
# value C cannot name is a residual, and nothing is declared for it.
RESIDUALS = """
uint64_t _both(void)
{
    /* r2dec proof: 2 constructs are marked below; 7 source obligations: 4 rendered, 3 elided, 0 refused; 1 statements rendered; 1 held from entry, read as residuals (RBX_0); 1 argument slot read with no parameter, read as residuals (RSI_0) */
    {
        return r2sleigh_residual_u64(1) + r2sleigh_residual_u64(2);
    }
}
"""

# `mov rax, rbx; ret`: the one unassigned read is held from entry.
HELD_ONLY = """
uint64_t _from_rbx(void)
{
    /* r2dec proof: no individual construct is marked; 6 source obligations: 3 rendered, 3 elided, 0 refused; 2 statements rendered; 1 held from entry (RBX_0) */
    {
        uint64_t RBX_0;
        return RBX_0;
    }
}
"""


class DeclarationTests(unittest.TestCase):
    def test_a_return_is_not_a_declaration(self) -> None:
        self.assertIsNone(gate.DECLARATION.match("        return RSI_0;"))

    def test_a_goto_is_not_a_declaration(self) -> None:
        self.assertIsNone(gate.DECLARATION.match("    goto L2;"))

    def test_a_declaration_is_one(self) -> None:
        self.assertEqual(
            gate.DECLARATION.match("        const int8_t* name;").group(1), "name"
        )

    def test_a_name_returned_is_listed_once(self) -> None:
        # Taking `return RSI_0;` for a declaration listed the name twice, which
        # is the only reason a count that excused one of them left the other.
        self.assertEqual(
            gate.undefined_reads(
                lines(
                    """
    {
        uint64_t RSI_0;
        return RSI_0;
    }
"""
                )
            ),
            ["RSI_0"],
        )


class ProofAccountingTests(unittest.TestCase):
    def test_a_count_with_no_names_excuses_nothing(self) -> None:
        # The count excused the first unassigned read whatever it was, so this
        # rendering certified with an argument read and no parameter.
        report = gate.uncertified_reads(lines(HI_QWORD_COUNTED))
        self.assertIn("reads RDI_0 which nothing assigns", report)

    def test_a_value_held_from_entry_is_not_excused_by_the_proof_line(self) -> None:
        # The renderer spells such a read as a residual. A proof line naming
        # the value does not make a declared, unassigned object readable.
        self.assertIn("reads RBX_0 which nothing assigns", gate.uncertified_reads(lines(HELD_ONLY)))

    def test_every_unassigned_read_is_reported(self) -> None:
        report = gate.uncertified_reads(lines(ENTRY_AND_ARGUMENT))
        self.assertIn("RSI_0", report)
        self.assertIn("RBX_0", report)

    def test_a_residual_is_no_unassigned_read(self) -> None:
        self.assertEqual(gate.uncertified_reads(lines(RESIDUALS)), "")


if __name__ == "__main__":
    unittest.main()
