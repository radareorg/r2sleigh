#!/usr/bin/env python3
"""Unit tests for the source-gold harness: what it reads as a prototype, as a real truth, and as a silent error.

Pure Python; every `r2s` answer is canned, so no binary runs.
"""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest
from dataclasses import dataclass
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import differential_truth as dt  # noqa: E402


class ParsePrototype(unittest.TestCase):
    def test_a_function_pointer_parameter_is_one_parameter(self) -> None:
        proto = dt.parse_prototype("int run(int (*f)(int, int), char *s);")
        self.assertIsNotNone(proto)
        self.assertEqual(proto.names, ["f", "s"])
        self.assertEqual(proto.params, ["int (*)(int, int)", "char*"])

    def test_commas_inside_any_bracket_do_not_split(self) -> None:
        proto = dt.parse_prototype("void h(int (*a[2])(int, int), int b);")
        self.assertIsNotNone(proto)
        self.assertEqual(len(proto.params), 2)

    def test_the_spelling_r2s_prints_is_unchanged(self) -> None:
        proto = dt.parse_prototype("uint32_t fnv1a32(const uint8_t* p, uint64_t n)")
        self.assertIsNotNone(proto)
        self.assertEqual(proto.ret, "uint32_t")
        self.assertEqual(proto.params, ["const uint8_t*", "size_t"])
        self.assertEqual(proto.names, ["p", "n"])

    def test_void_and_nothing_have_no_parameters(self) -> None:
        for line in ("int main(void)", "int main()"):
            proto = dt.parse_prototype(line)
            self.assertIsNotNone(proto)
            self.assertEqual(proto.params, [])


class TruthIsReal(unittest.TestCase):
    def test_the_engines_own_placeholder_is_not_a_source_name(self) -> None:
        recovered = {0x1000: dt.Prototype("uint64_t", ["uint8_t*", "uint64_t"], ["arg0", "arg1"])}
        self.assertFalse(dt.truth_is_real(recovered))

    def test_a_source_name_makes_the_truth_real(self) -> None:
        mixed = {
            0x1000: dt.Prototype("uint64_t", ["uint8_t*"], ["arg0"]),
            0x2000: dt.Prototype("uint32_t", ["uint8_t*"], ["data"]),
        }
        self.assertTrue(dt.truth_is_real(mixed))

    def test_a_debug_build_whose_dwarf_failed_to_load_exits_2(self) -> None:
        # The debug build renders what the stripped one does: every parameter is `argN`.
        same = {0x1000: dt.Seen(dt.Prototype("uint64_t", ["uint8_t*"], ["arg0"]), False)}
        out, err = io.StringIO(), io.StringIO()
        argv = ["differential_truth.py", "--debug-build", "d", "--stripped-build", "s"]
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(dt, "signatures", return_value=same),
            mock.patch.object(dt, "listing", return_value={0x1000: "fcn.1000"}),
            mock.patch.object(dt, "dwarf_functions", return_value={0x1000}),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            code = dt.main()
        self.assertEqual(code, 2, out.getvalue())
        self.assertIn("refusing to score", err.getvalue())
        self.assertNotIn("soundness_rate", out.getvalue())


def proto(ret: str, params: list[str], names: list[str] | None = None) -> "dt.Prototype":
    return dt.Prototype(ret, params, names if names is not None else [f"p{i}" for i in range(len(params))])


def run_gate(truth: dict, recovered: dict, *extra: str, declared: set[int] | None = None) -> tuple[int, dict | None, str]:
    """Exit code, report and stderr of main for a debug build with these prototypes and a stripped one with those.

    A function with a source-named parameter, right in both builds, keeps the truth real. `declared` is the
    set of addresses the debug build's DWARF defines; by default every function of the debug build.
    """
    debug, stripped = pathlib.Path("debug"), pathlib.Path("stripped")
    anchor = {0x9000: dt.Seen(proto("int", ["int"], ["count"]), False)}
    seen = {debug: {**truth, **anchor}, stripped: {**recovered, **anchor}}
    out, err = io.StringIO(), io.StringIO()
    argv = ["differential_truth.py", "--debug-build", str(debug), "--stripped-build", str(stripped), *extra]
    with (
        mock.patch.object(sys, "argv", argv),
        mock.patch.object(
            dt, "signatures",
            side_effect=lambda binary, addresses, _r2s: {a: seen[binary][a] for a in addresses if a in seen[binary]},
        ),
        mock.patch.object(
            dt, "listing",
            side_effect=lambda binary, _r2s: {a: "sym.f" if a == 0x1000 else f"sym.f{a:x}" for a in seen[binary]},
        ),
        mock.patch.object(dt, "dwarf_functions", return_value=set(seen[debug]) if declared is None else declared),
        contextlib.redirect_stdout(out),
        contextlib.redirect_stderr(err),
    ):
        code = dt.main()
    return code, json.loads(out.getvalue()) if out.getvalue().strip() else None, err.getvalue()


def graded(truth: dict, recovered: dict) -> dict:
    """The report main prints."""
    return run_gate(truth, recovered)[1]


class SilentBuckets(unittest.TestCase):
    """Every wrong fact lands in one bucket, so a fix can be graded by the bucket it empties."""

    def one(self, expected: str, said: str, where: str = "return", marked: bool = False) -> dict:
        if where == "return":
            truth, got = proto(expected, []), proto(said, [])
        else:
            truth, got = proto("int", [expected]), proto("int", [said])
        return graded({0x1000: dt.Seen(truth, False)}, {0x1000: dt.Seen(got, marked)})

    def test_each_kind_of_difference_has_its_bucket(self) -> None:
        cases = [
            ("return", "int", "size_t", "width_wider"),
            ("return", "uint32_t", "uint8_t", "width_narrower"),
            ("parameter", "int8_t", "uint8_t", "sign"),
            ("parameter", "const uint8_t*", "uint8_t*", "qualifier"),
            ("parameter", "const uint8_t*", "void*", "pointee"),
            ("parameter", "const uint8_t*", "size_t", "pointer_as_integer"),
            ("parameter", "size_t", "uint8_t*", "integer_as_pointer"),
            ("return", "void", "size_t", "void_vs_value"),
            ("return", "int", "void", "void_vs_value"),
            ("parameter", "float", "uint32_t", "other"),
        ]
        for where, expected, said, bucket in cases:
            with self.subTest(where=where, expected=expected, said=said):
                report = self.one(expected, said, where)
                self.assertEqual(report["silent_buckets"], {where: {bucket: 1}})
                self.assertEqual(report["marked_buckets"], {})

    def test_a_marked_error_is_bucketed_apart_and_is_not_silent(self) -> None:
        report = self.one("const uint8_t*", "size_t", "parameter", marked=True)
        self.assertEqual(report["silent_buckets"], {})
        self.assertEqual(report["marked_buckets"], {"parameter": {"pointer_as_integer": 1}})
        self.assertEqual(report["facts"]["silently_wrong"], 0)

    def test_the_silent_key_is_spelled_as_it_was(self) -> None:
        report = self.one("int", "size_t")
        self.assertEqual(report["silent"], ["sym.f return: expected 'int', said 'size_t'"])


PRELUDE = "#include <stdint.h>\n\n"


@dataclass
class Fn:
    """A function as the fake shell knows it: what `pddj` prints, and the text `pdd` prints."""

    name: str
    record: dict
    body: str


def fn(signature: str, residual: int = 0, name: str = "fcn.00001000", addr: int = 0x1000,
       before: str = "", inside: str = "", refused: dict | None = None, **extra: object) -> Fn:
    """One function with every field the `pddj` contract asks for.

    `before` is what the unit defines above the header (a struct), `inside` is source text in the body.
    """
    marks = "    r2sleigh_residual_u32(1);\n" * residual
    body = f"{before}{signature}\n{{\n{inside}{marks}}}\n" if not refused else "/* r2sleigh refused f */\n"
    record = {
        "name": name, "addr": addr, "language": "c", "definition": "f",
        "signature": "" if refused else signature, "refused": refused,
        "code": PRELUDE + body,
        "proof": {"total": 3, "rendered": 3 - residual, "elided": 0, "refused": 0, "residual": residual,
                  "split": 0, "compiler_inserted": 0, "assumed": 0, "unaccounted": 0},
        "variables": [], "lines": [], "links": [], "residuals": [{"line": 1}] * residual, "calls": [],
        **extra,
    }
    return Fn(name, record, body)


ANCHOR_ADDRESS = 0x9000
ANCHOR = fn("int32_t anchor(int32_t count)", name="sym.anchor", addr=ANCHOR_ADDRESS)


def shell(builds: dict[pathlib.Path, dict[int, Fn]], indent: int | None = None, after: str = ""):
    """A stand-in for r2s that answers `afl`, `aflj`, `s`, `pdd` and `pddj` as r2s prints them."""

    def run(binary: pathlib.Path, commands: str, _r2s: str, **_: object) -> str:
        functions = builds[binary]
        at, out = 0, []
        for verb in (verb.strip() for verb in commands.split(";")):
            if verb == "afl":
                out += [f"0x{a:08x}    1     10 {f.name}\n" for a, f in sorted(functions.items())]
            elif verb == "aflj":
                rows = [{"addr": a, "name": f.name, "size": 10, "nbbs": 1, "confidence": "stated"}
                        for a, f in sorted(functions.items())]
                out.append(json.dumps(rows) + "\n")
            elif verb.startswith("s "):
                at = int(verb.split()[1], 16)
            elif verb == "pdd":
                out.append(functions[at].body)
            elif verb == "pddj":
                out.append(json.dumps(functions[at].record, indent=indent) + "\n" + (after + "\n" if after else ""))
        return "".join(out)

    return mock.patch.object(dt, "r2s", side_effect=run)


def run_main(debug: dict[int, Fn], stripped: dict[int, Fn], *extra: str, **options: object) -> tuple[int, dict | None, str]:
    """Exit code, report (None when none was printed) and stderr of main over a fake shell."""
    builds = {
        pathlib.Path("debug"): {**debug, ANCHOR_ADDRESS: ANCHOR},
        pathlib.Path("stripped"): {**stripped, ANCHOR_ADDRESS: ANCHOR},
    }
    argv = ["differential_truth.py", "--debug-build", "debug", "--stripped-build", "stripped", *extra]
    out, err = io.StringIO(), io.StringIO()
    with (
        mock.patch.object(sys, "argv", argv),
        shell(builds, **options),
        mock.patch.object(dt, "dwarf_functions", return_value=set(builds[pathlib.Path("debug")])),
        contextlib.redirect_stdout(out),
        contextlib.redirect_stderr(err),
    ):
        code = dt.main()
    return code, json.loads(out.getvalue()) if out.getvalue().strip() else None, err.getvalue()


INT = "int32_t f(void)"
SIZE_T = "uint64_t fcn_1000(void)"


class ReadsPddj(unittest.TestCase):
    """The gate reads `pddj` and nothing else, through the reader the equivalence gate and DecBench share."""

    def test_the_word_residual_in_the_code_is_not_a_marker(self) -> None:
        # The renderer states its residuals in `proof.residual`; an identifier that spells the word marks nothing.
        wrong = fn(SIZE_T, inside="    uint64_t residual_total = 0;\n")
        code, report, _ = run_main({0x1000: fn(INT)}, {0x1000: wrong})
        self.assertEqual(report["facts"]["silently_wrong"], 1)
        self.assertEqual(code, 1)

    def test_a_residual_the_proof_counts_marks_the_function(self) -> None:
        code, report, _ = run_main({0x1000: fn(INT)}, {0x1000: fn(SIZE_T, residual=1)})
        self.assertEqual((report["facts"]["silently_wrong"], report["facts"]["marked_wrong"]), (0, 1))
        self.assertEqual(code, 0)

    def test_pretty_printed_json_is_graded_as_the_one_line_form(self) -> None:
        # One JSON document however it is indented; read as lines, the keys spell `residual` and mark everything.
        args = ({0x1000: fn(INT)}, {0x1000: fn(SIZE_T)})
        plain, pretty = run_main(*args), run_main(*args, indent=2)
        self.assertEqual(pretty, plain)
        self.assertEqual(plain[1]["facts"]["silently_wrong"], 1)

    def test_a_line_after_the_json_fails_the_gate_instead_of_marking_everything(self) -> None:
        code, report, err = run_main({0x1000: fn(INT)}, {0x1000: fn(SIZE_T)}, after="note: render took 3ms")
        self.assertEqual(code, 2)
        self.assertIsNone(report)
        self.assertIn("UNREADABLE pddj: debug", err)
        self.assertIn("refusing to score", err)

    def test_an_answer_that_breaks_the_contract_fails_the_gate(self) -> None:
        broken = fn(SIZE_T)
        del broken.record["proof"]
        code, report, err = run_main({0x1000: fn(INT)}, {0x1000: broken})
        self.assertEqual(code, 2)
        self.assertIsNone(report)
        self.assertIn("UNREADABLE pddj: stripped 0x1000", err)

    def test_a_signature_that_is_no_prototype_fails_the_gate(self) -> None:
        code, report, err = run_main({0x1000: fn(INT)}, {0x1000: fn("not a prototype")})
        self.assertEqual(code, 2)
        self.assertIn("UNREADABLE pddj: stripped 0x1000", err)

    def test_a_refused_function_is_missing_and_is_no_failure(self) -> None:
        refused = fn(SIZE_T, refused={"kind": "rendering", "reason": "no body"})
        code, report, err = run_main({0x1000: fn(INT)}, {0x1000: refused})
        self.assertEqual(code, 0, err)
        # The anchor's two facts are right; the refused function's one fact is missing.
        self.assertEqual(report["facts"], {"correct": 2, "missing": 1, "marked_wrong": 0, "silently_wrong": 0})

    def test_the_header_is_the_signature_not_the_first_line_of_the_text(self) -> None:
        # A unit that defines a struct above the function opens `pdd` with the struct.
        before = "struct mixed {\n    int64_t a;\n};\n\n"
        truth = fn("void touch(struct mixed* value)", before=before)
        wrong = fn("void fcn_1000(uint64_t arg0)", before=before)
        code, report, _ = run_main({0x1000: truth}, {0x1000: wrong})
        self.assertEqual(report["functions_in_truth"], 2)
        self.assertEqual(report["facts"]["silently_wrong"], 1)
        self.assertEqual(report["silent_buckets"], {"parameter": {"pointer_as_integer": 1}})
        self.assertEqual(code, 1)


class NoPremiseAttribution(unittest.TestCase):
    """`pddj` states premises per function and no variable carries one, so no fact is attributed to a premise."""

    def test_a_closed_world_void_stays_silent_and_the_report_attributes_nothing(self) -> None:
        said = fn("void fcn_1000(void)", premises=["closed-world"])
        code, report, err = run_main({0x1000: fn(INT)}, {0x1000: said})
        self.assertEqual(code, 1, err)
        self.assertEqual(report["silent"], ["fcn.00001000 return: expected 'int', said 'void'"])
        self.assertEqual(report["silent_buckets"], {"return": {"void_vs_value": 1}})
        self.assertNotIn("premised", report)
        self.assertNotIn("marked_by", report)
        self.assertEqual(report["return_presence"]["value_to_void"], {"total": 1, "silent": 1})


class DwarfIsTheTruth(unittest.TestCase):
    """Only a function the debug build's DWARF declares has a truth; r2s's own rendering of a symbol is not one."""

    STUB = dt.Seen(proto("void", []), False)

    def test_a_runtime_function_without_dwarf_is_no_truth_and_no_presence(self) -> None:
        truth = {0x1000: dt.Seen(proto("int", []), False), 0x2000: self.STUB}
        said = {0x1000: dt.Seen(proto("int", []), False), 0x2000: self.STUB}
        report = run_gate(truth, said, declared={0x1000, 0x9000})[1]
        self.assertEqual(report["functions_in_dwarf"], 2)
        self.assertEqual(report["functions_in_truth"], 2)
        self.assertEqual(report["without_dwarf"], ["sym.f2000"])
        self.assertEqual(report["return_presence"]["void_to_void"], {"total": 0, "silent": 0})
        self.assertEqual(report["facts"]["correct"], 3)

    def test_a_runtime_function_the_engine_gets_wrong_is_not_a_silent_error(self) -> None:
        truth = {0x1000: dt.Seen(proto("int", []), False), 0x2000: dt.Seen(proto("void", []), False)}
        said = {0x1000: dt.Seen(proto("int", []), False), 0x2000: dt.Seen(proto("size_t", []), False)}
        code, report, _ = run_gate(truth, said, declared={0x1000, 0x9000})
        self.assertEqual((code, report["facts"]["silently_wrong"], report["silent"]), (0, 0, []))

    def test_a_function_dwarf_declares_and_the_engine_does_not_list_fails_the_gate(self) -> None:
        code, report, err = run_gate({0x1000: self.STUB}, {0x1000: self.STUB}, declared={0x1000, 0x9000, 0x5000})
        self.assertEqual(code, 2)
        self.assertIn("UNREADABLE aflj", err)
        self.assertIn("0x5000", err)

    def test_dwarf_that_declares_nothing_fails_the_gate(self) -> None:
        code, report, err = run_gate({0x1000: self.STUB}, {0x1000: self.STUB}, declared=set())
        self.assertEqual(code, 2)
        self.assertIn("declares no function", err)

    def test_no_readelf_fails_the_gate_and_names_it(self) -> None:
        unreadable = dt.Unreadable(pathlib.Path("debug"), "readelf", {"": "[Errno 2] No such file or directory: 'readelf'"})
        out, err = io.StringIO(), io.StringIO()
        argv = ["differential_truth.py", "--debug-build", "debug", "--stripped-build", "stripped"]
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(dt, "listing", return_value={0x1000: "sym.f"}),
            mock.patch.object(dt, "dwarf_functions", side_effect=unreadable),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            code = dt.main()
        self.assertEqual(code, 2)
        self.assertIn("UNREADABLE readelf: debug", err.getvalue())


class DeclaredFunctions(unittest.TestCase):
    """`dwarf_functions` asks the oracle side's DWARF reader, with the binutils the caller names."""

    @staticmethod
    def reading(subprograms: list[int], dies: list[SimpleNamespace] | None = None):
        dwarf = SimpleNamespace(
            subprograms=lambda: [SimpleNamespace(low_pc=pc) for pc in subprograms],
            index=dict(enumerate(dies or [])),
        )
        return mock.patch.object(dt.Dwarf, "read", return_value=dwarf)

    def test_every_subprogram_with_code_is_declared_at_its_entry(self) -> None:
        with self.reading([0x1210, 0x1220]):
            self.assertEqual(dt.dwarf_functions(pathlib.Path("debug")), {0x1210, 0x1220})

    def test_the_binutils_prefix_reaches_readelf(self) -> None:
        with self.reading([0x1210]) as read:
            dt.dwarf_functions(pathlib.Path("debug"), "g")
        self.assertEqual(read.call_args.args[1].binutils_prefix, "g")

    def test_a_function_with_ranges_and_no_entry_address_is_refused(self) -> None:
        split = SimpleNamespace(tag="DW_TAG_subprogram", offset=0x2d, attrs={"DW_AT_ranges": "0x10"})
        with self.reading([0x1210], [split]), self.assertRaises(dt.Unreadable) as raised:
            dt.dwarf_functions(pathlib.Path("debug"))
        self.assertEqual(raised.exception.command, "readelf")
        self.assertIn("die 0x2d", raised.exception.causes)

    def test_readelf_that_is_missing_or_fails_is_unreadable(self) -> None:
        for error in (FileNotFoundError(2, "No such file or directory", "readelf"), RuntimeError("readelf failed on d")):
            with self.subTest(error=error), mock.patch.object(dt.Dwarf, "read", side_effect=error):
                with self.assertRaises(dt.Unreadable) as raised:
                    dt.dwarf_functions(pathlib.Path("debug"))
                self.assertEqual(raised.exception.command, "readelf")


class Baseline(unittest.TestCase):
    """A recorded silent error is carried with its cause; any other is the failure the gate exists to catch."""

    TRUTH = {0x1000: dt.Seen(proto("int", []), False)}
    WRONG = {0x1000: dt.Seen(proto("size_t", []), False)}
    KEY = "sym.f return: expected 'int', said 'size_t'"

    def record(self, directory: str, why: dict | None) -> pathlib.Path:
        path = pathlib.Path(directory) / "baseline.json"
        path.write_text(json.dumps({"silent": [self.KEY], "why": why or {}}))
        return path

    def test_a_recorded_error_with_a_cause_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.record(directory, {self.KEY: "no sign is proven"})
            code, _, _ = run_gate(self.TRUTH, self.WRONG, "--baseline", str(path))
        self.assertEqual(code, 0)

    def test_a_new_silent_error_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "baseline.json"
            path.write_text(json.dumps({"silent": [], "why": {}}))
            code, _, err = run_gate(self.TRUTH, self.WRONG, "--baseline", str(path))
        self.assertEqual(code, 1)
        self.assertIn(f"SILENT ERROR: {self.KEY}", err)

    def test_a_recorded_error_with_no_cause_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.record(directory, None)
            code, _, err = run_gate(self.TRUTH, self.WRONG, "--baseline", str(path))
        self.assertEqual(code, 1)
        self.assertIn(f"NO CAUSE: {self.KEY}", err)

    def test_a_cause_that_says_nothing_fails_like_no_cause(self) -> None:
        for why in ("", "   ", "\n", "TODO", "todo", " TODO: look later ", "TBD", None, 5, ["a cause"]):
            with self.subTest(why=why), tempfile.TemporaryDirectory() as directory:
                path = self.record(directory, {self.KEY: why})
                code, _, err = run_gate(self.TRUTH, self.WRONG, "--baseline", str(path))
                self.assertEqual(code, 1)
                self.assertIn(f"NO CAUSE: {self.KEY}", err)

    def test_accepting_does_not_carry_a_cause_that_says_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.record(directory, {self.KEY: "TODO"})
            code, _, err = run_gate(self.TRUTH, self.WRONG, "--baseline", str(path), "--accept-baseline")
            written = json.loads(path.read_text())
        self.assertEqual(code, 1)
        self.assertIn(f"NO CAUSE: {self.KEY}", err)
        self.assertEqual(written["why"], {})

    def test_accepting_carries_the_cause_and_drops_the_fixed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.record(directory, {self.KEY: "no sign is proven", "gone": "was fixed"})
            code, _, _ = run_gate(self.TRUTH, self.WRONG, "--baseline", str(path), "--accept-baseline")
            written = json.loads(path.read_text())
        self.assertEqual(code, 0)
        self.assertEqual(written["why"], {self.KEY: "no sign is proven"})

    def test_accepting_an_error_with_no_cause_says_so(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "baseline.json"
            code, _, err = run_gate(self.TRUTH, self.WRONG, "--baseline", str(path), "--accept-baseline")
            written = json.loads(path.read_text())
        self.assertEqual(code, 1)
        self.assertIn(f"NO CAUSE: {self.KEY}", err)
        self.assertEqual(written["silent"], [self.KEY])


if __name__ == "__main__":
    unittest.main()
