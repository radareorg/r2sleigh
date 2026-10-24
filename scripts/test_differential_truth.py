#!/usr/bin/env python3
"""Unit tests for the source-gold harness: what it reads as a prototype, as a truth and as a silent error.

Pure Python; every `r2s` answer is canned and every DWARF is written from C prototypes, so no binary runs.
"""

from __future__ import annotations

import contextlib
import dataclasses
import io
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from dataclasses import dataclass
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "tests" / "equiv"))
import c_types as ct  # noqa: E402
import differential_truth as dt  # noqa: E402
import dwarf  # noqa: E402
from test_c_types import Graph  # noqa: E402

DEBUG, STRIPPED = pathlib.Path("debug"), pathlib.Path("stripped")


def declare(text: str, entry: int = 0x1000) -> dt.Declared:
    """What the source declares of the function this prototype states, read through DWARF."""
    graph = Graph()
    return dt.declared(graph.dwarf(), graph.subprogram(ct.parse_prototype(text), entry))


def seen(text: str, marked: bool = False) -> dt.Seen:
    return dt.Seen(ct.parse_prototype(text), marked)


class Source:
    """A debug build's DWARF: functions written from prototypes, and the ones it cannot place."""

    def __init__(self, protos: dict[int, str], unplaced: list[dwarf.Unplaced] | None = None) -> None:
        self.graph = Graph()
        self.placed = [self.graph.subprogram(ct.parse_prototype(text), addr) for addr, text in protos.items()]
        self.unplaced = unplaced or []

    def read(self, binary: pathlib.Path, _prefix: str):
        if binary == DEBUG:
            return self.graph.dwarf(), list(self.placed), list(self.unplaced)
        return dwarf.Dwarf([], {}), [], []


PRELUDE = "#include <stdint.h>\n\n"


@dataclass
class Fn:
    """A function as the fake shell knows it: what `pddj` prints."""

    name: str
    record: dict


def fn(signature: str, residuals: int = 0, proof_residual: int | None = None, name: str | None = None,
       addr: int = 0x1000, refused: dict | None = None, **extra: object) -> Fn:
    """One function with every field the `pddj` contract asks for.

    `residuals` is the length of the typed list, `proof_residual` the obligation count (by default the same).
    """
    definition = ct.parse_prototype(signature).name
    count = residuals if proof_residual is None else proof_residual
    record = {
        "name": name or f"fcn.{addr:08x}", "addr": addr, "language": "c", "definition": definition,
        "signature": "" if refused else signature, "refused": refused,
        "code": PRELUDE + f"{signature}\n{{\n}}\n",
        "proof": {"total": 3, "rendered": 3 - count, "elided": 0, "refused": 0, "residual": count,
                  "split": 0, "compiler_inserted": 0, "assumed": 0, "unaccounted": 0},
        "variables": [], "lines": [], "links": [],
        "residuals": [{"site": index + 1, "type": "u64", "cause": "gap", "gap": "TermNotSpelled", "line": 1}
                      for index in range(residuals)],
        "calls": [],
        **extra,
    }
    return Fn(record["name"], record)


def completed(stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], 0, stdout, stderr)


def shell(builds: dict[pathlib.Path, dict[int, Fn]], indent: int | None = None, after: str = "", stderr: str = ""):
    """A stand-in for r2s that answers `aflj`, `s` and `pddj` as r2s prints them."""

    def run(binary: pathlib.Path, commands: str, _r2s: str, **_: object):
        functions = builds[binary]
        at, out = 0, []
        for verb in (verb.strip() for verb in commands.split(";")):
            if verb == "aflj":
                out.append(json.dumps([{"addr": a, "name": f.name, "size": 10, "nbbs": 1, "confidence": "stated"}
                                       for a, f in sorted(functions.items())]) + "\n")
            elif verb.startswith("s "):
                at = int(verb.split()[1], 16)
            elif verb == "pddj":
                assert binary == STRIPPED, "the debug build's pddj is no truth and is not asked"
                out.append(json.dumps(functions[at].record, indent=indent) + "\n" + (after + "\n" if after else ""))
        return completed("".join(out), stderr)

    return mock.patch.object(dt, "r2s", side_effect=run)


def run_main(source: dict[int, str] | Source, stripped: dict[int, Fn], *extra: str, listed: set[int] | None = None,
             unplaced: list[dwarf.Unplaced] | None = None, debug_functions: dict[int, Fn] | None = None,
             **options: object) -> tuple[int, dict | None, str]:
    """Exit code, report (None when none was printed) and stderr of main over a fake shell and a written DWARF."""
    source = source if isinstance(source, Source) else Source(source, unplaced)
    debug = debug_functions or {
        sub.low_pc: Fn(f"sym.{sub.name}", {}) for sub in source.placed if listed is None or sub.low_pc in listed
    }
    argv = ["differential_truth.py", "--debug-build", str(DEBUG), "--stripped-build", str(STRIPPED), *extra]
    out, err = io.StringIO(), io.StringIO()
    with (
        mock.patch.object(sys, "argv", argv),
        shell({DEBUG: debug, STRIPPED: stripped}, **options),
        mock.patch.object(dt, "read_dwarf", side_effect=source.read),
        contextlib.redirect_stdout(out),
        contextlib.redirect_stderr(err),
    ):
        code = dt.main()
    return code, json.loads(out.getvalue()) if out.getvalue().strip() else None, err.getvalue()


def graded(source: dict[int, str], stripped: dict[int, Fn]) -> dict:
    """The report main prints."""
    return run_main(source, stripped)[1]


INT = "int32_t f(void)"
SIZE_T = "uint64_t fcn_1000(void)"
RIGHT = "int32_t fcn_1000(void)"


class ReadsPddj(unittest.TestCase):
    """The gate reads `pddj` and nothing else, through the reader the equivalence gate and DecBench share."""

    def test_the_word_residual_in_the_code_is_not_a_marker(self) -> None:
        wrong = fn(SIZE_T)
        wrong.record["code"] += "uint64_t residual_total = 0; // r2sleigh_residual\n"
        code, report, _ = run_main({0x1000: INT}, {0x1000: wrong})
        self.assertEqual(report["facts"]["silently_wrong"], 1)
        self.assertEqual(code, 1)

    def test_a_listed_residual_marks_the_function_though_the_proof_counts_none(self) -> None:
        # cmp 0x3b10: a tail transfer the renderer did not spell is a residual and stands for no obligation.
        listed = fn(SIZE_T, residuals=1, proof_residual=0)
        code, report, _ = run_main({0x1000: INT}, {0x1000: listed})
        self.assertEqual((report["facts"]["silently_wrong"], report["facts"]["marked_wrong"]), (0, 1))
        self.assertEqual(code, 0)

    def test_a_proof_count_without_a_listed_residual_marks_nothing(self) -> None:
        counted = fn(SIZE_T, residuals=0, proof_residual=2)
        code, report, _ = run_main({0x1000: INT}, {0x1000: counted})
        self.assertEqual((report["facts"]["silently_wrong"], report["facts"]["marked_wrong"]), (1, 0))
        self.assertEqual(code, 1)

    def test_pretty_printed_json_is_graded_as_the_one_line_form(self) -> None:
        # One JSON document however it is indented; read as lines, the keys spell `residuals` and mark everything.
        args = ({0x1000: INT}, {0x1000: fn(SIZE_T)})
        plain, pretty = run_main(*args), run_main(*args, indent=2)
        self.assertEqual(pretty, plain)
        self.assertEqual(plain[1]["facts"]["silently_wrong"], 1)

    def test_a_line_after_the_json_fails_the_gate_instead_of_marking_everything(self) -> None:
        code, report, err = run_main({0x1000: INT}, {0x1000: fn(SIZE_T)}, after="note: render took 3ms")
        self.assertEqual(code, 2)
        self.assertIsNone(report)
        self.assertIn("UNREADABLE pddj: stripped 0x1000", err)
        self.assertIn("refusing to score", err)

    def test_an_answer_that_breaks_the_contract_fails_the_gate(self) -> None:
        for field in ("proof", "residuals"):
            with self.subTest(field=field):
                broken = fn(SIZE_T)
                del broken.record[field]
                code, report, err = run_main({0x1000: INT}, {0x1000: broken})
                self.assertEqual(code, 2)
                self.assertIsNone(report)
                self.assertIn("UNREADABLE pddj: stripped 0x1000", err)

    def test_a_signature_that_is_no_prototype_fails_the_gate(self) -> None:
        wrong = fn(SIZE_T)
        wrong.record["signature"] = "not a prototype"
        code, report, err = run_main({0x1000: INT}, {0x1000: wrong})
        self.assertEqual(code, 2)
        self.assertIn("UNREADABLE pddj: stripped 0x1000", err)
        self.assertIn("is no prototype", err)

    def test_a_signature_that_names_another_function_than_the_definition_fails_the_gate(self) -> None:
        wrong = fn(SIZE_T)
        wrong.record["definition"] = "other"
        code, _, err = run_main({0x1000: INT}, {0x1000: wrong})
        self.assertEqual(code, 2)
        self.assertIn("signature names 'fcn_1000', the definition is 'other'", err)

    def test_a_function_returning_a_function_pointer_is_graded(self) -> None:
        pick = "int32_t(*)(int32_t, int32_t) pick(int32_t sel)"
        code, report, err = run_main({0x1000: pick}, {0x1000: fn(pick)})
        self.assertEqual((code, report["facts"]), (0, {"correct": 2, "missing": 0, "marked_wrong": 0, "silently_wrong": 0}), err)

    def test_a_function_returning_a_function_pointer_the_engine_calls_an_integer_is_a_silent_error(self) -> None:
        code, report, _ = run_main({0x1000: "int32_t(*)(int32_t, int32_t) pick(int32_t sel)"},
                                   {0x1000: fn("uint64_t pick(int32_t sel)")})
        self.assertEqual(code, 1)
        self.assertEqual(report["silent"], ["pick return: expected 'int32_t (*)(int32_t, int32_t)', said 'uint64_t'"])
        self.assertEqual(report["silent_buckets"], {"return": {"pointer_as_integer": 1}})

    def test_a_refused_function_is_missing_and_is_no_failure(self) -> None:
        refused = fn(SIZE_T, refused={"kind": "rendering", "reason": "no body"})
        code, report, err = run_main({0x1000: INT}, {0x1000: refused, 0x2000: fn(RIGHT, addr=0x2000)} if False else {0x1000: refused})
        # Nothing else is recovered, so this is the "recovered nothing" refusal; give it a neighbour that is.
        self.assertEqual(code, 2, err)
        both = run_main({0x1000: INT, 0x2000: "int32_t g(void)"},
                        {0x1000: refused, 0x2000: fn("int32_t g(void)", addr=0x2000)})
        self.assertEqual(both[0], 0, both[2])
        self.assertEqual(both[1]["facts"], {"correct": 1, "missing": 1, "marked_wrong": 0, "silently_wrong": 0})

    def test_a_function_the_stripped_build_does_not_list_is_missing_and_never_asked_for(self) -> None:
        # The fake shell raises on an address it does not list, so asking for 0x1000 would fail the test.
        code, report, err = run_main({0x1000: INT, 0x2000: "int32_t g(int32_t a)"},
                                     {0x2000: fn("int32_t g(int32_t a)", addr=0x2000)})
        self.assertEqual(code, 0, err)
        self.assertEqual(report["facts"], {"correct": 2, "missing": 1, "marked_wrong": 0, "silently_wrong": 0})
        self.assertEqual(report["functions_recovered"], 1)
        self.assertEqual(report["functions_in_truth"], 2)

    def test_a_function_the_source_does_not_define_is_not_a_recovered_function(self) -> None:
        stripped = {0x1000: fn(RIGHT), 0x5000: fn("uint64_t fcn_5000(void)", addr=0x5000)}
        code, report, err = run_main({0x1000: INT}, stripped)
        self.assertEqual((code, report["functions_recovered"], report["functions_in_truth"]), (0, 1, 1), err)

    def test_the_debug_build_is_never_asked_for_a_rendering(self) -> None:
        # `shell` raises on a pddj of the debug build: the gate passing at all is the check.
        code, _, err = run_main({0x1000: INT}, {0x1000: fn(RIGHT)})
        self.assertEqual(code, 0, err)


class Answers(unittest.TestCase):
    """The shell is run as a process: its stdout is the answer, its `r2s:` stderr lines are declines."""

    def make(self, directory: str, script: str) -> str:
        path = pathlib.Path(directory) / "r2s"
        path.write_text("#!/usr/bin/env python3\n" + textwrap.dedent(script))
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return str(path)

    def test_r2s_runs_the_shell_on_the_binary_with_the_commands(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            shell_bin = self.make(directory, """
                import sys
                print(sys.argv[1:])
                print("noise", file=sys.stderr)
            """)
            proc = dt.r2s(pathlib.Path("some binary"), "aflj; pdd", shell_bin)
        self.assertEqual(proc.stdout, "['-q', '-c', 'aflj; pdd', 'some binary']\n")
        self.assertEqual(proc.stderr, "noise\n")

    def test_the_shell_is_given_half_an_hour(self) -> None:
        with mock.patch.object(dt.subprocess, "run", return_value=completed()) as run:
            dt.r2s(pathlib.Path("b"), "aflj", "r2s")
        self.assertEqual(run.call_args.kwargs["timeout"], 1800)
        self.assertEqual(run.call_args.args[0], ["r2s", "-q", "-c", "aflj", "b"])

    def test_stderr_noise_does_not_break_a_listing_or_an_answer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            record = fn(RIGHT).record
            shell_bin = self.make(directory, f"""
                import json, sys
                print("warning: slow disk", file=sys.stderr)
                if "aflj" in sys.argv[3]:
                    print(json.dumps([{{"addr": 4096, "name": "fcn.x"}}]))
                else:
                    print(json.dumps({record!r}))
            """)
            self.assertEqual(dt.listing(pathlib.Path("b"), shell_bin), {4096: "fcn.x"})
            answer = dt.ask(pathlib.Path("b"), 0x1000, shell_bin)
        self.assertEqual(answer.kind, "output")
        self.assertEqual(answer.record["definition"], "fcn_1000")

    def test_an_r2s_line_on_stderr_is_the_decline_it_says(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            shell_bin = self.make(directory, """
                import sys
                print("r2s: cannot render 0x1000: the function is not analysed", file=sys.stderr)
            """)
            answer = dt.ask(pathlib.Path("b"), 0x1000, shell_bin)
        self.assertEqual(answer.kind, "decline")
        self.assertIn("cannot render 0x1000", answer.cause)

    def test_a_shell_that_prints_nothing_is_a_decline_not_a_refusal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            answer = dt.ask(pathlib.Path("b"), 0x1000, self.make(directory, "pass\n"))
        self.assertEqual((answer.kind, answer.refusal), ("decline", None))
        self.assertIn("r2s printed nothing", answer.cause)

    def test_a_shell_that_cannot_run_or_runs_past_its_deadline_is_a_crash(self) -> None:
        answer = dt.ask(pathlib.Path("b"), 0x1000, "/nonexistent/r2s")
        self.assertEqual(answer.kind, "crash")
        self.assertIn("cannot run /nonexistent/r2s", answer.cause)
        with mock.patch.object(dt.subprocess, "run", side_effect=subprocess.TimeoutExpired("r2s", 1800)):
            answer = dt.ask(pathlib.Path("b"), 0x1000, "r2s")
        self.assertEqual(answer.kind, "crash")
        self.assertIn("ran past its deadline", answer.cause)

    def test_a_listing_that_cannot_be_read_is_unreadable(self) -> None:
        for what, stdout in [("not json", "r2s: cannot open\n"), ("no key", '[{"name": "x"}]'), ("not a list", '"abc"'),
                             ("an address that is no number", '[{"addr": "0x10", "name": "x"}]'),
                             ("a name that is no string", '[{"addr": 16, "name": null}]'), ("empty", "")]:
            with self.subTest(what=what), mock.patch.object(dt, "r2s", return_value=completed(stdout)):
                with self.assertRaises(dt.Unreadable) as raised:
                    dt.listing(pathlib.Path("b"), "r2s")
                self.assertEqual(raised.exception.command, "aflj")

    def test_a_listing_with_no_shell_or_no_answer_in_time_is_unreadable(self) -> None:
        for error in (FileNotFoundError(2, "No such file"), subprocess.TimeoutExpired("r2s", 1800)):
            with self.subTest(error=error), mock.patch.object(dt, "r2s", side_effect=error):
                with self.assertRaises(dt.Unreadable) as raised:
                    dt.listing(pathlib.Path("b"), "r2s")
                self.assertIn("r2s did not answer", raised.exception.causes[""])

    def test_an_r2s_that_runs_past_its_deadline_fails_the_gate(self) -> None:
        def slow(binary: pathlib.Path, commands: str, r2s_bin: str):
            if "pddj" in commands:
                raise subprocess.TimeoutExpired(commands, 1800)
            return completed(json.dumps([{"addr": 0x1000, "name": "fcn.x"}]))

        source = Source({0x1000: INT})
        out, err = io.StringIO(), io.StringIO()
        argv = ["differential_truth.py", "--debug-build", "debug", "--stripped-build", "stripped"]
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(dt, "r2s", side_effect=slow),
            mock.patch.object(dt, "read_dwarf", side_effect=source.read),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            code = dt.main()
        self.assertEqual((code, out.getvalue()), (2, ""))
        self.assertIn("ran past its deadline", err.getvalue())

    def test_a_listing_that_cannot_be_read_names_the_binary_without_an_address(self) -> None:
        source = Source({0x1000: INT})
        out, err = io.StringIO(), io.StringIO()
        argv = ["differential_truth.py", "--debug-build", "debug", "--stripped-build", "stripped"]
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(dt, "r2s", return_value=completed("not a list")),
            mock.patch.object(dt, "read_dwarf", side_effect=source.read),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            code = dt.main()
        self.assertEqual(code, 2)
        self.assertTrue(err.getvalue().startswith("UNREADABLE aflj: debug: not a list of functions ("), err.getvalue())

    def test_ten_unreadable_functions_are_all_named_and_eleven_leave_one_counted(self) -> None:
        for count, more in [(10, None), (11, "... and 1 more")]:
            with self.subTest(count=count):
                source = {0x1000 + 16 * index: f"int32_t f{index}(void)" for index in range(count)}
                stripped = {addr: fn(f"int32_t fcn_{addr:x}(void)", addr=addr) for addr in source}
                for function in stripped.values():
                    del function.record["proof"]
                _, _, err = run_main(source, stripped)
                self.assertEqual(len([line for line in err.splitlines() if line.startswith("UNREADABLE")]), 10)
                self.assertEqual(more in err.splitlines() if more else "... and" in err, bool(more))

    def test_the_unreadable_functions_are_named_by_address_and_not_by_the_text_of_it(self) -> None:
        # 0xff0 sorts after 0x1000 as text; the first ten are the first ten by address.
        source = {0xFD0 + 16 * index: f"int32_t f{index}(void)" for index in range(13)}
        stripped = {addr: fn(f"int32_t fcn_{addr:x}(void)", addr=addr) for addr in source}
        for function in stripped.values():
            del function.record["proof"]
        _, _, err = run_main(source, stripped)
        named = [line.split()[3].rstrip(":") for line in err.splitlines() if line.startswith("UNREADABLE")]
        self.assertEqual(named, [f"0x{addr:x}" for addr in sorted(source)[:10]])

    def test_the_first_ten_unreadable_functions_are_named_and_the_rest_counted(self) -> None:
        source = {0x1000 + 16 * index: f"int32_t f{index}(void)" for index in range(13)}
        stripped = {addr: fn(f"int32_t fcn_{addr:x}(void)", addr=addr) for addr in source}
        for function in stripped.values():
            del function.record["proof"]
        code, _, err = run_main(source, stripped)
        self.assertEqual(code, 2)
        lines = [line for line in err.splitlines() if line.startswith("UNREADABLE")]
        self.assertEqual(len(lines), 10)
        self.assertEqual([line.split()[3].rstrip(":") for line in lines], [f"0x{addr:x}" for addr in sorted(source)[:10]])
        self.assertIn("... and 3 more", err)
        self.assertIn("no readable `pddj` answer for 13 item(s)", err)


class Crashes(unittest.TestCase):
    """CI accepts exit 0 and 1, and a Python traceback exits 1: every exception that is no verdict is exit 2."""

    def crash(self, source: dict[int, str], stripped: dict[int, Fn], *extra: str, **patched: object):
        with contextlib.ExitStack() as stack:
            for name, value in patched.items():
                stack.enter_context(mock.patch.object(dt, name, **value))
            return run_main(source, stripped, *extra)

    def test_an_exception_in_the_scoring_is_exit_2_with_the_traceback_on_stderr(self) -> None:
        code, report, err = self.crash({0x1000: INT}, {0x1000: fn(RIGHT)}, score={"side_effect": RuntimeError("boom")})
        self.assertEqual((code, report), (2, None))
        self.assertIn("Traceback (most recent call last)", err)
        self.assertIn("RuntimeError: boom", err)

    def test_an_r2s_that_lists_a_function_with_no_name_is_unreadable_and_exit_2(self) -> None:
        stripped = {0x1000: fn(RIGHT)}
        source = Source({0x1000: INT})
        debug = {0x1000: Fn(None, {})}  # type: ignore[arg-type]
        code, report, err = run_main(source, stripped, debug_functions=debug)
        self.assertEqual((code, report), (2, None))
        self.assertIn("UNREADABLE aflj: debug: not a list of functions (a name that is no string)", err)

    def test_a_baseline_that_is_no_json_is_exit_2(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            baseline = pathlib.Path(directory) / "baseline.json"
            baseline.write_text("{ not json")
            code, report, err = run_main({0x1000: INT}, {0x1000: fn(RIGHT)}, "--baseline", str(baseline))
        self.assertEqual(code, 2)
        self.assertIn("JSONDecodeError", err)

    def test_a_header_nested_five_thousand_deep_is_exit_2(self) -> None:
        deep = fn(RIGHT)
        deep.record["signature"] = "int32_t " + "(" * 5000 + "*" + ")" * 5000 + " fcn_1000(void)"
        code, report, err = run_main({0x1000: INT}, {0x1000: deep})
        self.assertEqual(code, 2)
        self.assertIn("RecursionError", err)

    def test_a_verdict_is_not_a_crash(self) -> None:
        self.assertEqual(run_main({0x1000: INT}, {0x1000: fn(RIGHT)})[0], 0)
        self.assertEqual(run_main({0x1000: INT}, {0x1000: fn(SIZE_T)})[0], 1)

    def test_a_usage_error_keeps_the_exit_code_of_argparse(self) -> None:
        with mock.patch.object(sys, "argv", ["differential_truth.py"]), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                dt.main()
        self.assertEqual(raised.exception.code, 2)


class TruthIsDwarf(unittest.TestCase):
    """The truth is what DWARF declares; the engine on the debug build is not asked and says nothing."""

    SEVEN = "void seven(int32_t a, int32_t b, int32_t c, int32_t d, int32_t e, int32_t f, int32_t g)"

    def test_a_void_function_of_seven_parameters_is_void_with_seven(self) -> None:
        # r2s recovers six register parameters; the source's seventh is missing and a `uint32_t` result is its error.
        said = fn("uint32_t seven(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4, uint32_t arg5)")
        code, report, _ = run_main({0x1000: self.SEVEN}, {0x1000: said})
        self.assertEqual(code, 1)
        self.assertEqual(report["facts"], {"correct": 0, "missing": 1, "marked_wrong": 0, "silently_wrong": 7})
        self.assertEqual(report["silent"][0], "seven return: expected 'void', said 'uint32_t'")
        self.assertEqual(report["return_presence"]["void_to_value"], {"total": 1, "silent": 1})
        self.assertEqual(report["silent_buckets"]["return"], {"void_vs_value": 1})
        self.assertEqual(report["silent_buckets"]["parameter"], {"sign": 6})

    def test_the_engine_that_agrees_with_dwarf_is_correct(self) -> None:
        said = fn("void seven(int32_t arg0, int32_t arg1, int32_t arg2, int32_t arg3, int32_t arg4, int32_t arg5)")
        code, report, _ = run_main({0x1000: self.SEVEN}, {0x1000: said})
        self.assertEqual(code, 0)
        self.assertEqual(report["facts"], {"correct": 7, "missing": 1, "marked_wrong": 0, "silently_wrong": 0})
        self.assertEqual(report["return_presence"]["void_to_void"], {"total": 1, "silent": 0})

    def test_two_spellings_of_one_type_are_right(self) -> None:
        said = fn("uint64_t fcn_1000(uint64_t arg0, int64_t arg1, uint8_t* arg2)")
        code, report, _ = run_main({0x1000: "size_t g(unsigned long a, long b, unsigned char *c)"}, {0x1000: said})
        self.assertEqual((code, report["facts"]["correct"]), (0, 4))

    def test_a_qualifier_the_machine_code_does_not_carry_is_a_silent_error(self) -> None:
        code, report, _ = run_main({0x1000: "void f(const uint8_t *p)"}, {0x1000: fn("void fcn_1000(uint8_t* arg0)")})
        self.assertEqual(code, 1)
        self.assertEqual(report["silent"], ["f parameter 0: expected 'const uint8_t*', said 'uint8_t*'"])
        self.assertEqual(report["silent_buckets"], {"parameter": {"qualifier": 1}})

    def test_a_top_level_qualifier_is_no_difference(self) -> None:
        code, report, _ = run_main({0x1000: "const int32_t f(const int32_t a, char *const b)"},
                                   {0x1000: fn("int32_t fcn_1000(int32_t arg0, char* arg1)")})
        self.assertEqual((code, report["facts"]["correct"]), (0, 3))

    def test_a_float_result_is_graded_and_a_float_parameter_is_not(self) -> None:
        said = fn("uint64_t fcn_1000(uint32_t arg0, uint64_t arg1, uint64_t arg2)")
        code, report, _ = run_main({0x1000: "double f(int32_t a, float b, int32_t c)"}, {0x1000: said})
        self.assertEqual(report["silent"], ["f return: expected 'double', said 'uint64_t'",
                                            "f parameter 0: expected 'int32_t', said 'uint32_t'"])
        self.assertEqual(report["unreadable_truth"], {dt.AFTER_ONE_NOT: 1, dt.NOT_IN_REGISTER: 1})
        self.assertEqual(list(report["unreadable_truth"]), [dt.AFTER_ONE_NOT, dt.NOT_IN_REGISTER])
        self.assertEqual(report["facts"], {"correct": 0, "missing": 0, "marked_wrong": 0, "silently_wrong": 2})

    def test_a_struct_by_value_is_no_register_parameter_and_ends_the_positions(self) -> None:
        declared = declare("int64_t f(int32_t a, struct pair p, int32_t b, void* c)")
        self.assertEqual([slot.expected for slot in declared.params],
                         [ct.integer(4, True), None, None, None])
        self.assertEqual([slot.why for slot in declared.params[1:]], [dt.NOT_IN_REGISTER, dt.AFTER_ONE_NOT, dt.AFTER_ONE_NOT])

    def test_every_parameter_that_is_an_integer_register_class_is_placed(self) -> None:
        declared = declare("void f(int8_t a, uint16_t b, int32_t c, uint64_t d, _Bool e, char* f, void (*g)(void), struct s* h)")
        self.assertTrue(all(slot.expected is not None for slot in declared.params))

    def test_a_type_the_gate_cannot_state_is_unreadable_for_a_result_and_a_parameter(self) -> None:
        graph = Graph()
        weird = graph.die("DW_TAG_base_type", name="complex", size=8, encoding="3\t(complex float)")
        ok = graph.write(ct.integer(4, True))
        sub = dwarf.Subprogram("f", 0x1000, "t.c", True, weird, [dwarf.Parameter("a", weird), dwarf.Parameter("b", ok),
                                                                   dwarf.Parameter("c", None)], False, True, False)
        declared = dt.declared(graph.dwarf(), sub)
        self.assertIsNone(declared.ret.expected)
        self.assertTrue(declared.ret.why.startswith(f"{dt.CANNOT_STATE} (base type encoding 3"))
        self.assertEqual([slot.expected for slot in declared.params], [None, None, None])
        self.assertEqual([slot.why.split(" (")[0] for slot in declared.params],
                         [dt.CANNOT_STATE, dt.AFTER_ONE_NOT, dt.CANNOT_STATE])
        self.assertEqual(declared.params[2].why, f"{dt.CANNOT_STATE} (no type)")

    def test_a_qualifier_on_a_whole_parameter_or_result_is_no_part_of_the_type(self) -> None:
        graph = Graph()
        const_int = dataclasses.replace(ct.integer(4, True), const=True)
        both = dataclasses.replace(ct.pointer(ct.integer(1, None)), const=True, volatile=True)
        array = ct.CType(ct.ARRAY, target=ct.integer(4, True), count=4)
        declared = dt.declared(graph.dwarf(), graph.subprogram(ct.Prototype("f", const_int, (const_int, both, array)), 0x1000))
        self.assertEqual(declared.ret.expected, ct.integer(4, True))
        self.assertEqual([slot.expected for slot in declared.params],
                         [ct.integer(4, True), ct.pointer(ct.integer(1, None)), ct.pointer(ct.integer(4, True))])

    def test_a_parameter_with_no_type_is_unreadable(self) -> None:
        graph = Graph()
        sub = dwarf.Subprogram("f", 0x1000, "t.c", True, None, [dwarf.Parameter("a", None)], False, True, False)
        declared = dt.declared(graph.dwarf(), sub)
        self.assertEqual(declared.params[0].why, f"{dt.CANNOT_STATE} (no type)")
        self.assertEqual(declared.ret.expected, ct.NO_VALUE)

    def test_unreadable_truth_is_counted_by_reason_and_scores_nothing(self) -> None:
        said = fn("uint64_t fcn_1000(uint64_t arg0, uint64_t arg1)")
        code, report, _ = run_main({0x1000: "int64_t f(struct pair a, int64_t b)", 0x2000: "int32_t g(void)"},
                                   {0x1000: said, 0x2000: fn(RIGHT.replace("fcn_1000", "g"), addr=0x2000)})
        self.assertEqual(report["unreadable_truth"], {dt.AFTER_ONE_NOT: 1, dt.NOT_IN_REGISTER: 1})
        self.assertEqual(report["facts"], {"correct": 1, "missing": 0, "marked_wrong": 0, "silently_wrong": 1})
        self.assertEqual(code, 1)

    def test_a_function_the_stripped_build_lacks_has_its_readable_facts_missing_and_its_unreadable_ones_counted(self) -> None:
        code, report, _ = run_main({0x1000: "int32_t f(int32_t a, double b)", 0x2000: "int32_t g(void)"},
                                   {0x2000: fn(RIGHT.replace("fcn_1000", "g"), addr=0x2000)})
        self.assertEqual(report["facts"], {"correct": 1, "missing": 2, "marked_wrong": 0, "silently_wrong": 0})
        self.assertEqual(report["unreadable_truth"], {dt.NOT_IN_REGISTER: 1})

    def test_extra_parameters_beyond_the_source_are_not_a_fact(self) -> None:
        # The source states two parameters; a third the engine adds is graded by no fact (D78 (b)).
        said = fn("int32_t fcn_1000(int32_t arg0, int32_t arg1, int32_t arg2)")
        code, report, _ = run_main({0x1000: "int32_t f(int32_t a, int32_t b)"}, {0x1000: said})
        self.assertEqual((code, report["facts"]["correct"]), (0, 3))


class Buckets(unittest.TestCase):
    """Every wrong fact lands in one bucket, so a fix can be graded by the bucket it empties."""

    def one(self, expected: str, said: str, where: str = "return", marked: bool = False) -> dict:
        if where == "return":
            source, got = f"{expected} f(void)", f"{said} fcn_1000(void)"
        else:
            source, got = f"int32_t f({expected})", f"int32_t fcn_1000({said})"
        code, report, err = run_main({0x1000: source}, {0x1000: fn(got, residuals=int(marked))})
        return report

    def test_each_kind_of_difference_has_its_bucket(self) -> None:
        cases = [
            ("return", "int32_t", "uint64_t", "width_wider"),
            ("return", "uint32_t", "uint8_t", "width_narrower"),
            ("parameter", "int8_t", "uint8_t", "sign"),
            ("parameter", "uint32_t", "int32_t", "sign"),
            ("parameter", "char", "int8_t", "other"),
            ("parameter", "const uint8_t*", "uint8_t*", "qualifier"),
            ("parameter", "int32_t (**)(int32_t)", "int32_t (* const *)(int32_t)", "qualifier"),
            ("parameter", "int32_t (*)(int32_t, int32_t)", "int32_t (*)(char*)", "pointee"),
            ("parameter", "const uint8_t*", "void*", "pointee"),
            ("parameter", "const uint8_t*", "uint64_t", "pointer_as_integer"),
            ("parameter", "uint64_t", "uint8_t*", "integer_as_pointer"),
            ("return", "void", "uint64_t", "void_vs_value"),
            ("return", "int32_t", "void", "void_vs_value"),
            ("return", "double", "uint64_t", "other"),
        ]
        for where, expected, said, bucket in cases:
            with self.subTest(where=where, expected=expected, said=said):
                report = self.one(expected, said, where)
                self.assertEqual(report["silent_buckets"], {where: {bucket: 1}})
                self.assertEqual(report["marked_buckets"], {})

    def test_a_marked_error_is_bucketed_apart_and_is_not_silent(self) -> None:
        report = self.one("const uint8_t*", "uint64_t", "parameter", marked=True)
        self.assertEqual(report["silent_buckets"], {})
        self.assertEqual(report["marked_buckets"], {"parameter": {"pointer_as_integer": 1}})
        self.assertEqual(report["facts"]["silently_wrong"], 0)
        self.assertEqual(report["silent"], [])

    def test_buckets_are_listed_in_sorted_order(self) -> None:
        said = fn("int32_t fcn_1000(char* arg0, int16_t arg1, char* arg2)")
        report = graded({0x1000: "int32_t f(const char *a, int32_t b, uint64_t c)"}, {0x1000: said})
        wrong = report["silent_buckets"]["parameter"]
        self.assertEqual(list(wrong), sorted(wrong))
        self.assertEqual(len(wrong), 3)

    def test_roles_are_listed_in_sorted_order(self) -> None:
        said = fn("uint64_t fcn_1000(uint64_t arg0)")
        report = graded({0x1000: "int32_t f(int32_t a)"}, {0x1000: said})
        self.assertEqual(list(report["silent_buckets"]), ["parameter", "return"])

    def test_the_silent_key_is_spelled_as_it_was(self) -> None:
        self.assertEqual(self.one("int32_t", "uint64_t")["silent"], ["f return: expected 'int32_t', said 'uint64_t'"])

    def test_a_marked_error_is_in_no_silent_key_and_in_no_presence_silence(self) -> None:
        report = self.one("int32_t", "void", marked=True)
        self.assertEqual(report["silent"], [])
        self.assertEqual(report["return_presence"]["value_to_void"], {"total": 1, "silent": 0})
        self.assertEqual(report["marked_buckets"], {"return": {"void_vs_value": 1}})


class Rates(unittest.TestCase):
    """The two numbers D71 and D73 gate on, from counts that tell the formulas apart."""

    def test_recovery_and_soundness(self) -> None:
        # correct 4, missing 1, marked 2, silent 4: eleven facts, eight asserted.
        stripped = {0x1000: fn("int32_t fcn_1000(int32_t a0, int32_t a1, int32_t a2)"),
                    0x2000: fn("uint64_t fcn_2000(uint64_t a0)", residuals=1, addr=0x2000),
                    0x3000: fn("uint64_t fcn_3000(uint64_t a0, uint64_t a1, uint64_t a2)", addr=0x3000)}
        source = {0x1000: "int32_t f(int32_t a, int32_t b, int32_t c, int32_t d)",
                  0x2000: "int32_t g(int32_t a)", 0x3000: "int32_t h(int32_t a, int32_t b, int32_t c)"}
        report = graded(source, stripped)
        self.assertEqual(report["facts"], {"correct": 4, "missing": 1, "marked_wrong": 2, "silently_wrong": 4})
        self.assertEqual(report["recovery_rate"], round(4 / 11, 4))
        self.assertEqual(report["soundness_rate"], 0.5)

    def test_a_run_that_asserts_nothing_is_perfectly_sound_and_recovers_nothing(self) -> None:
        # Every fact is missing or marked: nothing asserted, so nothing silent.
        stripped = {0x1000: fn("uint64_t fcn_1000(uint64_t a0)", residuals=1), 0x2000: fn(RIGHT, addr=0x2000, refused={"reason": "r"})}
        report = graded({0x1000: "int32_t f(int32_t a)", 0x2000: "int32_t g(void)"}, stripped)
        self.assertEqual(report["facts"], {"correct": 0, "missing": 1, "marked_wrong": 2, "silently_wrong": 0})
        self.assertEqual((report["recovery_rate"], report["soundness_rate"]), (0.0, 1.0))

    def test_a_run_with_no_readable_fact_recovers_nothing_and_asserts_nothing(self) -> None:
        source = Source({0x1000: "int32_t f(void)"})
        source.placed[0] = dataclasses.replace(source.placed[0], return_type=source.graph.die(
            "DW_TAG_base_type", name="c", size=8, encoding="3\t(complex)"))
        code, report, _ = run_main(source, {0x1000: fn("uint32_t f(void)")})
        self.assertEqual(report["facts"], {"correct": 0, "missing": 0, "marked_wrong": 0, "silently_wrong": 0})
        self.assertEqual((code, report["recovery_rate"], report["soundness_rate"]), (0, 0.0, 1.0))

    def test_a_run_with_no_fact_has_no_recovery(self) -> None:
        report = graded({0x1000: "void f(double a)"}, {0x1000: fn("void fcn_1000(uint64_t a0)")})
        self.assertEqual(report["facts"], {"correct": 1, "missing": 0, "marked_wrong": 0, "silently_wrong": 0})
        report = graded({0x1000: "double f(double a)"}, {0x1000: fn("void fcn_1000(uint64_t a0)")})
        self.assertEqual(report["facts"]["correct"] + report["facts"]["silently_wrong"], 1)


class Presence(unittest.TestCase):
    """Does the function return a value at all, truth to recovered, with the silent share."""

    def cells(self, source: str, said: str, marked: bool = False) -> dict:
        return graded({0x1000: source}, {0x1000: fn(said, residuals=int(marked))})["return_presence"]

    def test_the_four_cells(self) -> None:
        for source, said, cell in [("void f(void)", "void fcn_1000(void)", "void_to_void"),
                                   ("void f(void)", "uint32_t fcn_1000(void)", "void_to_value"),
                                   ("int32_t f(void)", "void fcn_1000(void)", "value_to_void"),
                                   ("int32_t f(void)", "uint32_t fcn_1000(void)", "value_to_value"),
                                   ("char* f(void)", "uint64_t fcn_1000(void)", "value_to_value")]:
            with self.subTest(cell=cell, source=source):
                cells = self.cells(source, said)
                self.assertEqual(cells[cell]["total"], 1)
                self.assertEqual(sum(c["total"] for c in cells.values()), 1)
                self.assertEqual(cells[cell]["silent"], int(cell in ("void_to_value", "value_to_void")))

    def test_a_marked_function_is_never_a_silent_presence_error(self) -> None:
        cells = self.cells("void f(void)", "uint32_t fcn_1000(void)", marked=True)
        self.assertEqual(cells["void_to_value"], {"total": 1, "silent": 0})

    def test_a_returned_value_that_agrees_is_never_silent(self) -> None:
        self.assertEqual(self.cells("int32_t f(void)", "int32_t fcn_1000(void)")["value_to_value"], {"total": 1, "silent": 0})

    def test_a_closed_world_void_stays_silent_and_the_report_attributes_nothing(self) -> None:
        said = fn("void fcn_1000(void)", premises=["closed-world"])
        code, report, err = run_main({0x1000: INT}, {0x1000: said})
        self.assertEqual(code, 1, err)
        self.assertEqual(report["silent"], ["f return: expected 'int32_t', said 'void'"])
        self.assertEqual(report["silent_buckets"], {"return": {"void_vs_value": 1}})
        self.assertNotIn("premised", report)
        self.assertNotIn("marked_by", report)
        self.assertEqual(report["return_presence"]["value_to_void"], {"total": 1, "silent": 1})

    def test_a_function_with_an_unreadable_result_has_no_presence(self) -> None:
        weird = Source({0x1000: "int32_t f(void)"})
        weird.placed[0] = weird.placed[0].__class__(**{**weird.placed[0].__dict__,
                                                      "return_type": weird.graph.die("DW_TAG_base_type", name="c", size=8,
                                                                                     encoding="3\t(complex)")})
        code, report, _ = run_main(weird, {0x1000: fn("uint32_t f(void)")})
        self.assertEqual(sum(cell["total"] for cell in report["return_presence"].values()), 0)
        self.assertEqual(report["facts"]["correct"] + report["facts"]["silently_wrong"], 0)
        self.assertEqual(list(report["unreadable_truth"].values()), [1])


class Placement(unittest.TestCase):
    """A DWARF function the gate cannot place, or the engine does not list, is named and never fails the binary."""

    def test_a_function_with_no_one_entry_is_named_and_not_graded(self) -> None:
        split = dwarf.Unplaced("sym", 0x572, "its DW_AT_ranges list has no one readable first range")
        gone = dwarf.Unplaced("never_called", 0x600, "its code was discarded by the linker (address 0x0)")
        code, report, err = run_main({0x1000: INT}, {0x1000: fn(RIGHT)}, unplaced=[split, gone])
        self.assertEqual(code, 0, err)
        self.assertEqual(report["without_entry"], ["never_called: its code was discarded by the linker (address 0x0)",
                                                   "sym: its DW_AT_ranges list has no one readable first range"])
        self.assertEqual((report["functions_in_dwarf"], report["functions_in_truth"]), (3, 1))
        self.assertEqual(report["facts"]["correct"], 1)

    def test_a_function_the_engine_does_not_list_is_named_and_not_graded(self) -> None:
        code, report, err = run_main({0x1000: INT, 0x2000: "int32_t g(void)"},
                                     {0x1000: fn(RIGHT), 0x2000: fn("uint64_t g(void)", addr=0x2000)}, listed={0x1000})
        self.assertEqual(code, 0, err)
        self.assertEqual(report["unlisted"], ["g"])
        self.assertEqual((report["functions_in_dwarf"], report["functions_in_truth"]), (2, 1))
        self.assertEqual(report["facts"], {"correct": 1, "missing": 0, "marked_wrong": 0, "silently_wrong": 0})

    def test_two_functions_at_one_entry_have_no_one_entry(self) -> None:
        code, report, err = run_main(Source({0x1000: "int32_t a(void)", 0x2000: "int32_t g(void)"}), {0x2000: fn(RIGHT, addr=0x2000)})
        self.assertEqual(code, 0, err)
        source = Source({0x1000: "int32_t a(void)", 0x2000: "int32_t g(void)"})
        source.placed.append(source.graph.subprogram(ct.parse_prototype("int32_t alias(void)"), 0x1000))
        code, report, err = run_main(source, {0x2000: fn(RIGHT, addr=0x2000), 0x1000: fn(RIGHT, addr=0x1000)})
        self.assertEqual(code, 0, err)
        self.assertEqual(report["without_entry"], ["a: it shares its entry address 0x1000 with another function",
                                                   "alias: it shares its entry address 0x1000 with another function"])
        self.assertEqual((report["functions_in_dwarf"], report["functions_in_truth"]), (3, 1))
        self.assertEqual(report["without_dwarf"], [])

    def test_the_engines_other_functions_are_listed_as_without_dwarf(self) -> None:
        debug = {0x1000: Fn("sym.f", {}), 0x2000: Fn("sym._start", {}), 0x1800: Fn("entry.fini0", {})}
        code, report, _ = run_main({0x1000: INT}, {0x1000: fn(RIGHT)}, debug_functions=debug)
        self.assertEqual(report["without_dwarf"], ["entry.fini0", "sym._start"])

    def test_dwarf_that_declares_nothing_fails_the_gate(self) -> None:
        code, report, err = run_main({}, {0x1000: fn(RIGHT)}, debug_functions={0x1000: Fn("sym.f", {})})
        self.assertEqual((code, report), (2, None))
        self.assertIn("declares no function", err)

    def test_dwarf_that_places_nothing_the_engine_lists_fails_the_gate(self) -> None:
        code, report, err = run_main({0x1000: INT}, {0x1000: fn(RIGHT)}, listed=set())
        self.assertEqual((code, report), (2, None))
        self.assertIn("no function DWARF declares has one entry the engine lists", err)
        gone = dwarf.Unplaced("f", 1, "its code was discarded by the linker (address 0x0)")
        code, report, err = run_main({}, {0x1000: fn(RIGHT)}, unplaced=[gone], debug_functions={0x1000: Fn("sym.f", {})})
        self.assertEqual((code, report), (2, None))
        self.assertIn("no function DWARF declares has one entry", err)

    def test_a_stripped_build_that_carries_dwarf_fails_the_gate(self) -> None:
        source = Source({0x1000: INT})
        for placed, unplaced in [(source.placed, []), ([], [dwarf.Unplaced("f", 1, "why")])]:
            with self.subTest(placed=bool(placed)):
                def read(binary: pathlib.Path, _prefix: str, placed=placed, unplaced=unplaced):
                    return source.graph.dwarf(), list(placed), list(unplaced)

                out, err = io.StringIO(), io.StringIO()
                argv = ["differential_truth.py", "--debug-build", "debug", "--stripped-build", "stripped"]
                with (
                    mock.patch.object(sys, "argv", argv),
                    shell({DEBUG: {0x1000: Fn("sym.f", {})}, STRIPPED: {0x1000: fn(RIGHT)}}),
                    mock.patch.object(dt, "read_dwarf", side_effect=read),
                    contextlib.redirect_stdout(out),
                    contextlib.redirect_stderr(err),
                ):
                    code = dt.main()
                self.assertEqual((code, out.getvalue()), (2, ""))
                self.assertIn("stripped build carries DWARF", err.getvalue())

    def test_an_engine_that_recovers_nothing_fails_the_gate(self) -> None:
        code, report, err = run_main({0x1000: INT}, {0x1000: fn(RIGHT, refused={"reason": "r"})})
        self.assertEqual((code, report), (2, None))
        self.assertIn("recovered no function", err)
        code, report, err = run_main({0x1000: INT}, {0x2000: fn(RIGHT, addr=0x2000)})
        self.assertEqual((code, report), (2, None))
        self.assertIn("recovered no function", err)

    def test_no_readelf_fails_the_gate_and_names_it(self) -> None:
        unreadable = dt.Unreadable(DEBUG, "readelf", {"": "[Errno 2] No such file or directory: 'readelf'"})
        out, err = io.StringIO(), io.StringIO()
        argv = ["differential_truth.py", "--debug-build", "debug", "--stripped-build", "stripped"]
        with (
            mock.patch.object(sys, "argv", argv),
            shell({DEBUG: {0x1000: Fn("sym.f", {})}, STRIPPED: {}}),
            mock.patch.object(dt, "read_dwarf", side_effect=unreadable),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            code = dt.main()
        self.assertEqual(code, 2)
        self.assertIn("UNREADABLE readelf: debug", err.getvalue())


class ReadingDwarf(unittest.TestCase):
    """`read_dwarf` asks the oracle side's DWARF reader, with the binutils the caller names."""

    def test_the_binutils_prefix_reaches_readelf_and_the_functions_come_back_placed(self) -> None:
        reading = mock.Mock(placed=lambda: (["placed"], ["unplaced"]))
        with mock.patch.object(dt.Dwarf, "read", return_value=reading) as read:
            result = dt.read_dwarf(pathlib.Path("debug"), "g")
        self.assertEqual(read.call_args.args[1].binutils_prefix, "g")
        self.assertEqual(result, (reading, ["placed"], ["unplaced"]))

    def test_readelf_that_is_missing_or_fails_is_unreadable(self) -> None:
        for error in (FileNotFoundError(2, "No such file or directory", "readelf"), RuntimeError("readelf failed on d")):
            with self.subTest(error=error), mock.patch.object(dt.Dwarf, "read", side_effect=error):
                with self.assertRaises(dt.Unreadable) as raised:
                    dt.read_dwarf(pathlib.Path("debug"), "")
                self.assertEqual(raised.exception.command, "readelf")
                self.assertIn(str(error), raised.exception.causes[""])


class Causes(unittest.TestCase):
    def test_a_cause_is_words_about_the_fact(self) -> None:
        for good in ("no sign is proven", "pointee const: a qualifier the machine code does not carry",
                     "the result is zero-extended into eax", "see D73 item three", "a b c"):
            with self.subTest(cause=good):
                self.assertTrue(dt.cause_is_stated(good))

    def test_a_blank_a_promise_or_a_shrug_is_no_cause(self) -> None:
        for bad in ("", "   ", "\n", "TODO", "todo", " TODO: look later ", "TBD later on", "- TODO", "(tbd) later on", "---",
                    "FIXME: explain the fact", "XXX fill this in", "xxx look at it", "WIP: still looking", "wip nothing yet",
                    "n/a", "none", "unknown", "wip", "no sign", "see D73", None, 5, ["a cause here"], {"a": "b c d"}):
            with self.subTest(cause=bad):
                self.assertFalse(dt.cause_is_stated(bad))

    def test_a_placeholder_is_a_placeholder_only_as_the_first_word(self) -> None:
        self.assertTrue(dt.cause_is_stated("the TODO list says nothing about it"))
        self.assertTrue(dt.cause_is_stated("a fixme tag marks it in the source"))


class Baseline(unittest.TestCase):
    """A recorded silent error is carried with its cause; any other is the failure the gate exists to catch."""

    SOURCE = {0x1000: "int32_t f(void)"}
    WRONG = {0x1000: fn("uint64_t fcn_1000(void)")}
    KEY = "f return: expected 'int32_t', said 'uint64_t'"

    def record(self, directory: str, why: dict | None, silent: list[str] | None = None) -> pathlib.Path:
        path = pathlib.Path(directory) / "baseline.json"
        path.write_text(json.dumps({"silent": [self.KEY] if silent is None else silent, "why": why or {}}))
        return path

    def run_with(self, path: pathlib.Path, *extra: str, source=None, stripped=None) -> tuple[int, dict | None, str]:
        return run_main(source or self.SOURCE, stripped or self.WRONG, "--baseline", str(path), *extra)

    def test_a_recorded_error_with_a_cause_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, _, err = self.run_with(self.record(directory, {self.KEY: "no sign is proven"}))
        self.assertEqual(code, 0, err)
        self.assertEqual(err, "")

    def test_a_new_silent_error_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, _, err = self.run_with(self.record(directory, {}, silent=[]))
        self.assertEqual(code, 1)
        self.assertIn(f"SILENT ERROR: {self.KEY}", err)

    def test_a_recorded_error_with_no_cause_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, _, err = self.run_with(self.record(directory, None))
        self.assertEqual(code, 1)
        self.assertIn(f"NO CAUSE: {self.KEY}", err)

    def test_a_cause_that_says_nothing_fails_like_no_cause(self) -> None:
        for why in ("", "   ", "TODO", " TODO: look later ", "---", "n/a", None, 5, ["a cause"]):
            with self.subTest(why=why), tempfile.TemporaryDirectory() as directory:
                code, _, err = self.run_with(self.record(directory, {self.KEY: why}))
                self.assertEqual(code, 1)
                self.assertIn(f"NO CAUSE: {self.KEY}", err)

    def test_new_and_fixed_errors_are_named_in_sorted_order(self) -> None:
        source = {0x1000: "int32_t zeta(void)", 0x1010: "int32_t alpha(void)"}
        wrong = {0x1000: fn("uint64_t zeta(void)"), 0x1010: fn("uint64_t alpha(void)", addr=0x1010)}
        gone = ["yankee return: expected 'void', said 'uint64_t'", "bravo return: expected 'void', said 'uint64_t'"]
        with tempfile.TemporaryDirectory() as directory:
            path = self.record(directory, {key: "was real once" for key in gone}, silent=gone)
            _, _, err = self.run_with(path, source=source, stripped=wrong)
        names = [line.split(":")[0] for line in err.splitlines() if line.startswith(("SILENT ERROR", "no longer silent"))]
        self.assertEqual(names, ["no longer silent", "no longer silent", "SILENT ERROR", "SILENT ERROR"])
        facts = [line.split(": ", 1)[1].split(" ")[0] for line in err.splitlines() if line.startswith(("SILENT ERROR", "no longer silent"))]
        self.assertEqual(facts, ["bravo", "yankee", "alpha", "zeta"])

    def test_a_fixed_error_asks_for_a_re_record_and_does_not_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, _, err = self.run_with(self.record(directory, {self.KEY: "no sign is proven"}),
                                         stripped={0x1000: fn(RIGHT)})
        self.assertEqual(code, 0)
        self.assertIn(f"no longer silent: {self.KEY}", err)
        self.assertIn("re-record the baseline with --accept-baseline", err)

    def test_a_fixed_error_beside_a_new_one_asks_for_no_re_record(self) -> None:
        other = "g return: expected 'int32_t', said 'uint64_t'"
        with tempfile.TemporaryDirectory() as directory:
            code, _, err = self.run_with(self.record(directory, {other: "was real now"}, silent=[other]))
        self.assertEqual(code, 1)
        self.assertIn(f"no longer silent: {other}", err)
        self.assertIn(f"SILENT ERROR: {self.KEY}", err)
        self.assertNotIn("re-record", err)

    def test_a_recorded_fact_with_no_cause_fails_though_it_is_fixed(self) -> None:
        gone = "gone return: expected 'int32_t', said 'uint64_t'"
        with tempfile.TemporaryDirectory() as directory:
            code, _, err = self.run_with(self.record(directory, {self.KEY: "no sign is proven"}, silent=[self.KEY, gone]))
        self.assertEqual(code, 1)
        self.assertIn(f"NO CAUSE: {gone}", err)
        self.assertIn(f"no longer silent: {gone}", err)

    def test_a_baseline_that_does_not_exist_gates_on_zero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, _, err = run_main(self.SOURCE, self.WRONG, "--baseline", str(pathlib.Path(directory) / "none.json"))
            ok = run_main(self.SOURCE, {0x1000: fn(RIGHT)}, "--baseline", str(pathlib.Path(directory) / "none.json"))
        self.assertEqual((code, ok[0], ok[2]), (1, 0, ""))
        self.assertEqual(err, f"SILENT ERROR: {self.KEY}\n")

    def test_two_functions_that_share_a_name_keep_one_entry_each(self) -> None:
        twice = {0x1000: "int32_t helper(void)", 0x2000: "int32_t helper(void)"}
        both = {0x1000: fn("uint64_t helper(void)"), 0x2000: fn("uint64_t helper(void)", addr=0x2000)}
        key = "helper return: expected 'int32_t', said 'uint64_t'"
        with tempfile.TemporaryDirectory() as directory:
            one_only = self.record(directory, {key: "no sign is proven"}, silent=[key])
            code, _, err = self.run_with(one_only, source=twice, stripped=both)
            self.assertEqual(code, 1)
            self.assertEqual(err.count(f"SILENT ERROR: {key}"), 1)
            both_recorded = self.record(directory, {key: "no sign is proven"}, silent=[key, key])
            code, _, err = self.run_with(both_recorded, source=twice, stripped=both)
            self.assertEqual(code, 0, err)
            code, _, err = self.run_with(both_recorded, source=self.SOURCE, stripped={0x1000: fn(RIGHT)})
            self.assertEqual(code, 0)
            self.assertEqual(err.count(f"no longer silent: {key}"), 2)

    def test_accepting_does_not_carry_a_cause_that_says_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.record(directory, {self.KEY: "TODO"})
            code, _, err = self.run_with(path, "--accept-baseline")
            written = json.loads(path.read_text())
        self.assertEqual(code, 1)
        self.assertIn(f"NO CAUSE: {self.KEY}", err)
        self.assertEqual(written["why"], {})

    def test_accepting_carries_the_cause_and_drops_the_fixed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.record(directory, {self.KEY: "no sign is proven", "gone": "this one was fixed"})
            code, _, err = self.run_with(path, "--accept-baseline")
            written = json.loads(path.read_text())
        self.assertEqual(code, 0, err)
        self.assertIn("baseline accepted", err)
        self.assertEqual(written["why"], {self.KEY: "no sign is proven"})
        self.assertEqual(written["silent"], [self.KEY])
        self.assertEqual(written["facts"]["silently_wrong"], 1)

    def test_accepting_an_error_with_no_cause_says_so(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "baseline.json"
            code, _, err = self.run_with(path, "--accept-baseline")
            written = json.loads(path.read_text())
        self.assertEqual(code, 1)
        self.assertIn(f"NO CAUSE: {self.KEY}", err)
        self.assertEqual(written["silent"], [self.KEY])

    def test_accepting_with_no_baseline_path_writes_nothing_and_gates_on_zero(self) -> None:
        code, _, _ = run_main(self.SOURCE, self.WRONG, "--accept-baseline")
        self.assertEqual(code, 1)

    def test_the_report_is_written_where_json_says(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "report.json"
            code, report, _ = run_main(self.SOURCE, self.WRONG, "--json", str(path))
            self.assertEqual(json.loads(path.read_text()), report)
            self.assertEqual(path.read_text(), json.dumps(report, indent=2) + "\n")


class ReportShape(unittest.TestCase):
    def test_the_report_names_what_it_graded(self) -> None:
        code, report, _ = run_main({0x1000: INT}, {0x1000: fn(RIGHT)})
        self.assertEqual(list(report), [
            "functions_in_dwarf", "functions_in_truth", "functions_recovered", "without_entry", "unlisted", "without_dwarf",
            "facts", "unreadable_truth", "recovery_rate", "soundness_rate", "silent", "silent_buckets", "marked_buckets",
            "return_presence"])
        self.assertEqual(list(report["return_presence"]), list(dt.PRESENCE))

    def test_every_function_dwarf_declares_is_graded_or_named(self) -> None:
        gone = [dwarf.Unplaced("g", 1, "why")]
        source = Source({0x1000: INT, 0x2000: "int32_t h(void)", 0x3000: "int32_t k(void)"}, gone)
        source.placed.append(source.graph.subprogram(ct.parse_prototype("int32_t alias(void)"), 0x1000))
        _, report, _ = run_main(source, {0x2000: fn("int32_t h(void)", addr=0x2000)}, listed={0x1000, 0x2000})
        self.assertEqual(report["functions_in_dwarf"], 5)
        self.assertEqual(report["functions_in_truth"] + len(report["without_entry"]) + len(report["unlisted"]), 5)
        self.assertEqual((report["functions_in_truth"], len(report["without_entry"]), report["unlisted"]), (1, 3, ["k"]))

    def test_every_list_in_the_report_is_sorted(self) -> None:
        names = ["zeta", "alpha", "mid"]
        source = {0x1000 + 16 * index: f"int32_t {name}(void)" for index, name in enumerate(names)}
        debug = {addr: Fn(f"sym.{name}", {}) for addr, name in zip(sorted(source), names)}
        debug[0x9000] = Fn("sym.b", {})
        debug[0x9100] = Fn("sym.a", {})
        gone = [dwarf.Unplaced("z", 1, "why"), dwarf.Unplaced("a", 2, "why")]
        stripped = {addr: fn(f"uint64_t {name}(void)", addr=addr) for addr, name in zip(source, names)}
        code, report, _ = run_main(source, stripped, debug_functions=debug, unplaced=gone)
        self.assertEqual(report["without_dwarf"], ["sym.a", "sym.b"])
        self.assertEqual(report["without_entry"], ["a: why", "z: why"])
        self.assertEqual(len(report["silent"]), 3)

    def test_the_functions_the_engine_does_not_list_are_named_in_order(self) -> None:
        source = {0x1000: "int32_t zeta(void)", 0x1010: "int32_t alpha(void)", 0x1020: "int32_t mid(void)",
                  0x1030: "int32_t zulu(void)", 0x1040: "int32_t able(void)"}
        _, report, _ = run_main(source, {0x1000: fn("int32_t zeta(void)")}, listed={0x1000, 0x1010, 0x1020})
        self.assertEqual(report["unlisted"], ["able", "zulu"])


if __name__ == "__main__":
    unittest.main()
