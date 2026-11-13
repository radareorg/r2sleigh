#!/usr/bin/env python3
"""Unit tests for S35's clause counters (ROADMAP D277), with r2s and the sweep stubbed."""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import s35_clauses  # noqa: E402

GOLDEN = """# a census golden
NAME=afl
FILE=tests/fixtures/x
CMDS=afl
EXPECT=<<EOF
0x1000 sym._start
EOF
RUN

NAME=0x00001280
FILE=tests/fixtures/x
CMDS=aa; pdd @ 0x00001280
EXPECT=<<EOF
    r2sleigh_residual_void(4); /* r2dec gap: CallNotRendered at 0x1280:46 (render::values): call to __libc_start_main: an argument has no C spelling */
EOF
RUN
"""

SWEEP = """R2SLEIGH_COV_BINARY__b
R2SLEIGH_COV_BEGIN__f
x; /* r2dec gap: TailTransferNotRendered at 0x10 */
x; /* r2dec gap: TailTransferNotRendered at 0x14 */
R2SLEIGH_COV_END__f
R2SLEIGH_COV_BEGIN__g
/* call to Sleep: declaration has an argument this convention does not place */
R2SLEIGH_COV_END__g
stray r2dec gap: TailTransferNotRendered outside a function
"""

MORE = SWEEP + "R2SLEIGH_COV_BEGIN__h\ny; /* r2dec gap: TailTransferNotRendered at 0x20 */\nR2SLEIGH_COV_END__h\n"


def done(stdout):
    return subprocess.CompletedProcess([], 0, stdout, "")


def quiet(fn, *args):
    with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()):
        code = fn(*args)
    return code, out.getvalue()


class Seventh(unittest.TestCase):
    def census(self):
        root = pathlib.Path(tempfile.mkdtemp())
        (root / "x").write_text(GOLDEN)
        return root

    def test_only_the_goldens_that_call_it_are_read(self):
        tests = s35_clauses.goldens(self.census(), "call to __libc_start_main")
        self.assertEqual([(t.name, t.cmds) for t in tests], [("0x00001280", "aa; pdd @ 0x00001280")])

    def test_a_spelled_reason_passes_and_says_whether_it_names_the_argument(self):
        line = "/* r2dec gap: ...: call to __libc_start_main: argument 6 has no C spelling */"
        with mock.patch.object(s35_clauses.subprocess, "run", return_value=done(line)):
            code, out = quiet(s35_clauses.seventh, "r2s", self.census())
        self.assertEqual(code, 0)
        self.assertIn("(names its argument)", out)

    def test_import_unplaced_or_no_gap_fails(self):
        line = f"/* call to __libc_start_main: {s35_clauses.UNPLACED} */"
        for stdout in (line, "int main(void) {}"):
            with mock.patch.object(s35_clauses.subprocess, "run", return_value=done(stdout)):
                self.assertEqual(quiet(s35_clauses.seventh, "r2s", self.census())[0], 1, stdout)


class Sweep(unittest.TestCase):
    def test_counts_are_per_function(self):
        with mock.patch.object(s35_clauses.subprocess, "run", return_value=done(SWEEP)):
            tail = s35_clauses.sweep_counts("r2s", pathlib.Path("b"), s35_clauses.PATTERNS["tail"])
            win64 = s35_clauses.sweep_counts("r2s", pathlib.Path("b"), s35_clauses.PATTERNS["win64"])
        self.assertEqual((dict(tail), dict(win64)), ({"f": 2}, {"g": 1}))

    def test_tail_fails_on_a_rise_and_win64_on_any_site(self):
        outs = {"base": done(SWEEP), "head": done(MORE)}

        def run(argv, **kw):
            return outs[kw["env"]["R2SLEIGH_R2S"]]
        b = [pathlib.Path("b")]
        with mock.patch.object(s35_clauses.subprocess, "run", side_effect=run):
            self.assertEqual(quiet(s35_clauses.sweep, "tail", ["base", "head"], b)[0], 1)
            self.assertEqual(quiet(s35_clauses.sweep, "tail", ["head", "base"], b)[0], 0)
            self.assertEqual(quiet(s35_clauses.sweep, "win64", ["base", "base"], b)[0], 1)
        self.assertEqual(quiet(s35_clauses.sweep, "tail", ["one"], b)[0], 2)


class Probes(unittest.TestCase):
    def test_a_signed_pointer_fails_and_an_unsigned_one_passes(self):
        good = "extern uint32_t* wcsdup(const uint32_t*);\nint32_t mkdir(const char*, uint32_t);\n"
        with mock.patch.object(s35_clauses.subprocess, "run", return_value=done(good)):
            self.assertEqual(quiet(s35_clauses.probes, "r2s", pathlib.Path("b"))[0], 0)
        with mock.patch.object(s35_clauses.subprocess, "run", return_value=done(good + "size_t strnlen(const int8_t *, size_t);\n")):
            self.assertEqual(quiet(s35_clauses.probes, "r2s", pathlib.Path("b"))[0], 1)


class NamedType(unittest.TestCase):
    def rows(self, n):
        path = pathlib.Path(tempfile.mkdtemp()) / "rows.jsonl"
        verdicts = ["fp:library_named_type"] * n + ["tp", "fn:register_local_no_overlap"]
        path.write_text("".join(json.dumps({"verdict": v}) + "\n" for v in verdicts))
        return path

    def test_head_must_fall(self):
        self.assertEqual(quiet(s35_clauses.named_type, self.rows(5), self.rows(3)),
                         (0, "library_named_type: base 5, head 3\n"))
        self.assertEqual(quiet(s35_clauses.named_type, self.rows(3), self.rows(3))[0], 1)


if __name__ == "__main__":
    unittest.main()
