#!/usr/bin/env python3
"""Unit tests for the memory site counter (ROADMAP D640) on committed `pddj` records.

Pure Python; no binary runs.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import memory_sites  # noqa: E402

DATA = Path(__file__).resolve().parent / "testdata" / "memory_sites"


def record(name):
    return next(iter(json.loads((DATA / name).read_text()).values()))


def measured(rec):
    return memory_sites.measure(rec, (), False)


class Sites(unittest.TestCase):
    def test_a_prelude_definition_is_no_site(self):
        # The round 14 to 17 regex counts the `static inline` definition too: 4.
        c, _ = measured(record("prelude_helper.json"))
        self.assertEqual(c["loads"], 3)
        self.assertEqual(c["residual_sites"], 1)

    def test_a_body_without_the_proof_comment_drops_the_prelude(self):
        rec = dict(record("prelude_helper.json"))
        rec["code"] = rec["code"].replace("/* r2dec proof", "/* proof")
        c, _ = measured(rec)
        self.assertEqual(c["loads"], 3)

    def test_typed_field_and_frame_offset(self):
        c, classes = measured(record("typed_and_frame.json"))
        self.assertEqual((c["loads"], c["stores"], c["typed_address_sites"]), (1, 1, 1))
        self.assertEqual(classes[("A1 stack, frame + K", "load")], 1)
        self.assertEqual(classes[("C1 parameter field, typed", "store")], 1)

    def test_the_byte_placeholder_is_not_typed(self):
        c, classes = measured(record("prelude_helper.json"))
        self.assertEqual(c["typed_address_sites"], 0)
        self.assertEqual(classes[("B1 global, named symbol", "load")], 1)

    def test_a_declared_object_is_typed_and_its_name_an_lvalue(self):
        rec = dict(record("prelude_helper.json"))
        rec["code"] = rec["code"].replace("extern char stderr[];", "extern struct _IO_FILE* stderr;")
        c, _ = measured(rec)
        self.assertEqual(c["typed_address_sites"], 1)
        rec["code"] = rec["code"].replace("r2sleigh_load_u64((void*)&stderr)", "(uint64_t)stderr")
        c, _ = measured(rec)
        self.assertEqual((c["loads"], c["lvalue_sites"]), (2, 1))

    def test_residual_sites_must_equal_the_listed_residuals(self):
        rec = dict(record("prelude_helper.json"))
        rec["residuals"] = []
        with self.assertRaises(SystemExit):
            measured(rec)

    def test_diff_fails_when_a_typed_counter_falls(self):
        with tempfile.TemporaryDirectory() as tmp:
            base, head = Path(tmp, "base"), Path(tmp, "head")
            base.mkdir()
            head.mkdir()
            rec = record("typed_and_frame.json")
            (base / "p_b.json").write_text(json.dumps({"0x2000": rec}))
            rec = dict(rec, code=rec["code"].replace("(void*)&arg0->f_10", "(void*)((uint64_t)arg0 + 16U)"))
            (head / "p_b.json").write_text(json.dumps({"0x2000": rec}))
            args = argparse.Namespace(dirs=[str(base), str(head)], bins=None, show=5)
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(memory_sites.diff(args), 1)
            self.assertIn("typed_address_sites 1 -> 0  FAIL", out.getvalue())
            args.dirs = [str(base), str(base)]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(memory_sites.diff(args), 0)


if __name__ == "__main__":
    unittest.main()
