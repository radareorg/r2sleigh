#!/usr/bin/env python3
"""Unit tests for the arm64 guard-check counter (ROADMAP D248), on gcc 13.3's `canary_void` from scratch.c."""

from __future__ import annotations

import pathlib
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import arm64_canary  # noqa: E402

DUMP = """
0000000000000820 <__stack_chk_fail@plt>:
 820:	90000110 	adrp	x16, 20000 <__data_start>
 824:	d61f0220 	br	x17

0000000000000a60 <canary_void>:
 a60:	d10183ff 	sub	sp, sp, #0x60
 a7c:	f9400040 	ldr	x0, [x2]
 a98:	97ffff6e 	bl	850 <puts@plt>
 a9c:	f00000e0 	adrp	x0, 1f000 <__FRAME_END__+0x1e0f8>
 aa0:	f947f400 	ldr	x0, [x0, #4072]
 aa4:	f94027e2 	ldr	x2, [sp, #72]
 aa8:	f9400001 	ldr	x1, [x0]
 aac:	eb010042 	subs	x2, x2, x1
 ab0:	d2800001 	mov	x1, #0x0                   	// #0
 ab4:	54000081 	b.ne	ac4 <canary_void+0x64>  // b.any
 ab8:	a9457bfd 	ldp	x29, x30, [sp, #80]
 ac0:	d65f03c0 	ret
 ac4:	97ffff57 	bl	820 <__stack_chk_fail@plt>

0000000000000ad0 <canary_keeps>:
 ad0:	f00000e0 	adrp	x0, 1f000 <__FRAME_END__+0x1e0f8>
 ad4:	f9400001 	ldr	x1, [x0]
 ad8:	54000081 	b.ne	ae8 <canary_keeps+0x18>  // b.any
 adc:	aa1303e0 	mov	x0, x19
 ae0:	d65f03c0 	ret
 ae8:	97ffff57 	bl	820 <__stack_chk_fail@plt>
"""


class Check(unittest.TestCase):
    def measure(self, void):
        with mock.patch.object(arm64_canary.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 0, DUMP, "")), \
                mock.patch.object(arm64_canary.scratch_void, "truth", return_value={
                    at: arm64_canary.scratch_void.Source(name, name not in void)
                    for at, name in ((0xa60, "canary_void"), (0xad0, "canary_keeps"))}):
            return arm64_canary.measure(pathlib.Path("d"), "")

    def test_the_check_writes_x0_to_x2_and_is_the_void_functions_only_result(self):
        regs, checked, only = self.measure({"canary_void", "canary_keeps"})
        self.assertEqual((checked, dict(regs)), (2, {"x0": 2, "x1": 2, "x2": 1}))
        self.assertEqual(only, ["canary_void"])

    def test_a_value_function_is_never_counted(self):
        self.assertEqual(self.measure(set())[2], [])


if __name__ == "__main__":
    unittest.main()
