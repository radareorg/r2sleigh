#!/usr/bin/env python3
"""Tests for scripts/run_refuter.py: the protocol's framing, the comparison, and a replay of the
committed hand-made recording where a built r2s is at hand.

    python3 scripts/test_run_refuter.py
"""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_refuter as refuter  # noqa: E402

HASHES = refuter.ROOT / "tests/coverage/pinned/hashes_gcc_x64_O2"


def recording(**machine):
    return {
        "bias": "0x1000",
        "machine": {"results": {}, "writes": [], "returned_to": "0x7000", "store_trace": False, **machine},
    }


def answer(**fields):
    return {"stop": {"kind": "returned", "to": "0x7000"}, "results": {}, "writes": [], **fields}


class Protocol(unittest.TestCase):
    def test_a_packet_carries_its_checksum(self):
        self.assertEqual(refuter.framed("g"), b"$g#67")
        self.assertEqual(refuter.framed("m1000,4"), b"$m1000,4#" + f"{sum(b'm1000,4') % 256:02x}".encode())

    def test_a_reply_undoes_escapes_and_run_lengths(self):
        self.assertEqual(refuter.unescaped(b"0* "), b"0000")
        self.assertEqual(refuter.unescaped(b"a}\x5db"), b"a}b")


class Judge(unittest.TestCase):
    IMAGE = (0x0, 0x3000)

    def test_equal_values_agree(self):
        verdict = refuter.judge(
            recording(results={"RAX": "0x2a"}), answer(results={"RAX": "0x2a"}), self.IMAGE
        )
        self.assertEqual((verdict["refuted"], verdict["slid"]), ([], 0))

    def test_an_image_address_the_bias_moves_is_slid(self):
        verdict = refuter.judge(
            recording(results={"RAX": "0x3010"}), answer(results={"RAX": "0x2010"}), self.IMAGE
        )
        self.assertEqual((verdict["refuted"], verdict["slid"]), ([], 1))

    def test_a_different_value_or_byte_refutes(self):
        verdict = refuter.judge(
            recording(results={"RAX": "0x2"}, writes=[{"address": "0x8000", "bytes": "01"}]),
            answer(results={"RAX": "0x1"}, writes=[{"address": "0x8000", "bytes": "02"}]),
            self.IMAGE,
        )
        self.assertEqual(len(verdict["refuted"]), 2, verdict)

    def test_a_store_in_the_image_is_compared_at_its_loaded_address(self):
        verdict = refuter.judge(
            recording(writes=[{"address": "0x1010", "bytes": "05"}]),
            answer(writes=[{"address": "0x10", "bytes": "05"}]),
            self.IMAGE,
        )
        self.assertEqual(verdict["refuted"], [])

    def test_leaving_the_body_refutes_and_an_unmodelled_operation_is_unreplayed(self):
        left = refuter.judge(recording(), answer(stop={"kind": "left-body", "at": "0x10", "to": "0x99"}), self.IMAGE)
        self.assertEqual(len(left["refuted"]), 1)
        unmodelled = refuter.judge(recording(), answer(stop={"kind": "unmodelled", "at": "0x10"}), self.IMAGE)
        self.assertTrue(unmodelled["unreplayed"])


class Image(unittest.TestCase):
    def test_the_hashes_fixture_spans_its_loads(self):
        facts = refuter.elf_facts(HASHES)
        self.assertEqual(facts["type"], 2)
        self.assertEqual(facts["image"][0], 0x400000)


class Check(unittest.TestCase):
    def test_the_hand_made_recording_agrees(self):
        r2s = Path(os.environ.get("R2S", refuter.ROOT / "target/release/r2s"))
        if not r2s.exists():
            self.skipTest(f"no r2s at {r2s}")
        args = type("Args", (), {"recordings": [str(refuter.RECORDINGS / "hashes_fnv1a32.json")], "bins": None, "r2s": r2s})
        self.assertEqual(refuter.check(args), 0)

    def test_an_absent_binary_is_counted_never_passed(self):
        absent = {"binary": "tests/refuter/no-such-binary", "sha256": "0" * 64}
        self.assertIsNone(refuter.located(absent, None))


if __name__ == "__main__":
    unittest.main()
