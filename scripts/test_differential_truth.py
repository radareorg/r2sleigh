#!/usr/bin/env python3
"""Unit tests for the source-gold harness: what it reads as a prototype, as a truth and as a silent error.

Pure Python; every `r2s` answer is canned and every DWARF is written from C prototypes, so no binary runs.
"""

from __future__ import annotations

import contextlib
import dataclasses
import functools
import io
import json
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
from test_c_types import GCC, Graph  # noqa: E402

DEBUG, STRIPPED = pathlib.Path("debug"), pathlib.Path("stripped")


def declare(text: str, entry: int = 0x1000, **states: object) -> dt.Declared:
    """What the source declares of the function this prototype states, read through DWARF."""
    graph = Graph()
    return dt.declared(graph.dwarf(), graph.subprogram(ct.parse_prototype(text), entry, **states))


def ungradable(text: str, **states: object) -> str:
    """Why the gate cannot grade the function this prototype states, as its DWARF (with `states`) says it."""
    with unittest.TestCase().assertRaises(dt.Ungradable) as raised:
        declare(text, **states)
    return raised.exception.reason


def seen(text: str, marked: bool = False) -> dt.Seen:
    return dt.Seen(ct.parse_prototype(text), marked)


class Source:
    """A debug build's DWARF: functions written from prototypes, and the ones it cannot place."""

    def __init__(self, protos: dict[int, str], unplaced: list[dwarf.Unplaced] | None = None) -> None:
        self.graph = Graph()
        self.placed = [self.graph.subprogram(ct.parse_prototype(text), addr) for addr, text in protos.items()]
        self.unplaced = unplaced or []

    def state(self, name: str, **states: object) -> "Source":
        """What DWARF says of the function `name` besides its prototype (`instance`, `prototyped`)."""
        self.placed = [dataclasses.replace(sub, **states) if sub.name == name else sub for sub in self.placed]
        return self

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
             ids: tuple[str | None, str | None] = ("1f2e", "1f2e"), **options: object) -> tuple[int, dict | None, str]:
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
        mock.patch.object(dt, "build_id", side_effect=lambda binary, _prefix: dict(zip((DEBUG, STRIPPED), ids))[binary]),
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
                             ("a name that is no string", '[{"addr": 16, "name": null}]'),
                             ("a name that is a number", '[{"addr": 16, "name": 5}]'), ("empty", "")]:
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
            mock.patch.object(dt, "build_id", return_value="6b1d"),
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

    def test_every_parameter_and_result_of_a_register_class_is_graded(self) -> None:
        declared = declare("char* f(int8_t a, uint16_t b, int32_t c, uint64_t d, _Bool e, char* f, void (*g)(void), struct s* h)")
        self.assertEqual(len(declared.params), 8)
        self.assertEqual(declared.ret, ct.pointer(ct.integer(1, None)))
        self.assertEqual(declare("void f(void)").ret, ct.NO_VALUE)

    def test_a_qualifier_on_a_whole_parameter_or_result_is_no_part_of_the_type(self) -> None:
        graph = Graph()
        const_int = dataclasses.replace(ct.integer(4, True), const=True)
        both = dataclasses.replace(ct.pointer(ct.integer(1, None)), const=True, volatile=True)
        array = ct.CType(ct.ARRAY, target=ct.integer(4, True), count=4)
        declared = dt.declared(graph.dwarf(), graph.subprogram(ct.Prototype("f", const_int, (const_int, both, array)), 0x1000))
        self.assertEqual(declared.ret, ct.integer(4, True))
        self.assertEqual(declared.params, [ct.integer(4, True), ct.pointer(ct.integer(1, None)), ct.pointer(ct.integer(4, True))])

    def test_extra_parameters_beyond_the_source_are_not_a_fact(self) -> None:
        # The source states two parameters; a third the engine adds is graded by no fact (D84).
        said = fn("int32_t fcn_1000(int32_t arg0, int32_t arg1, int32_t arg2)")
        code, report, _ = run_main({0x1000: "int32_t f(int32_t a, int32_t b)"}, {0x1000: said})
        self.assertEqual((code, report["facts"]["correct"]), (0, 3))


class Gradable(unittest.TestCase):
    """A function is graded only if it passes one predicate; every other is named with its reason (ROADMAP D70)."""

    def test_a_function_that_names_itself_and_states_a_prototype_is_graded(self) -> None:
        self.assertEqual(declare("int32_t f(int32_t a, char* b)").name, "f")

    def test_a_producer_other_than_gcc_is_not_graded(self) -> None:
        # clang drops the unused parameter of an internal function in place: `helper(int a, int unused, int c)` takes
        # (rdi, rsi), keeps its name, and its DWARF lists all three formals. Nothing in the DWARF says so.
        for producer in ("clang version 18.1.3 (1ubuntu1)", "error", "", "GNU C++17 13.3.0 -g -O2", "GNU AS 2.42",
                         "Rust 1.80", " GNU C17 13.3.0"):
            with self.subTest(producer=producer):
                self.assertEqual(ungradable("int32_t f(int32_t a)", producer=producer), dt.NOT_GCC)
        for producer in ("GNU C89 4.8.5 -g", "GNU C99 9.4.0 -g -O2", "GNU C11 7.5.0", "GNU C17 13.3.0 -mtune=generic -g -O2",
                         "GNU C23 14.1.0 -g"):
            with self.subTest(producer=producer):
                self.assertEqual(declare("int32_t f(int32_t a)", producer=producer).name, "f")

    def test_a_function_with_no_prototyped_flag_states_no_signature(self) -> None:
        # gcc -g1 emits no DW_AT_prototyped, no DW_AT_type and no formal parameter: `void f(void)` read from it is a guess.
        self.assertEqual(ungradable("void f(void)", prototyped=False), dt.NOT_PROTOTYPED)
        # K&R `int kr(a, b) char a;` with no prototype in scope has formals and no flag: its caller promotes `a` to int.
        self.assertEqual(ungradable("int32_t kr(int32_t a, char* b)", prototyped=False), dt.NOT_PROTOTYPED)

    def test_an_instance_of_an_origin_is_not_graded_though_it_reads_like_the_source(self) -> None:
        # `scale.constprop.0.isra.0` lists the source's formals in its own order and keeps the removed constant.
        self.assertEqual(ungradable("int64_t scale(int32_t k, char* p, int64_t n)", instance=True), dt.INSTANCE)
        self.assertEqual(ungradable("void f(void)", instance=True, prototyped=False), dt.INSTANCE)

    def test_no_aggregate_vector_wide_or_float_type_is_in_the_empty_class_table(self) -> None:
        graph = Graph()
        vector = graph.die("DW_TAG_array_type", (graph.child("DW_TAG_subrange_type", upper=3),),
                           type=graph.write(ct.integer(4, True)), size=16, vector=1)
        complex_double = graph.die("DW_TAG_base_type", name="complex double", size=16, encoding="3\t(complex float)")
        ok = graph.write(ct.integer(4, True))
        results = {
            "a struct result": ("struct big f(int32_t n, int64_t* p)", None),
            "a union result": ("union u16 f(int32_t n)", None),
            "a struct parameter": ("int64_t f(int32_t a, struct pair p, int32_t b)", None),
            "a union parameter": ("int64_t f(union u16 u)", None),
            "a long double result": ("long double f(int32_t a)", None),
            "a long double parameter": ("int64_t f(int32_t a, long double d, int64_t* p)", None),
            "an int128 result": ("INT128", None),
            "a double parameter": ("int32_t f(int32_t a, double d, int32_t b)", None),
            "a float parameter": ("int32_t f(float d)", None),
            "a double result": ("double f(int32_t a)", None),
            "a float result": ("float f(void)", None),
            "a pointer to a struct pair result": ("struct pair* g(void)", "ok"),
        }
        for what, (text, expected) in results.items():
            with self.subTest(what=what):
                if text == "INT128":
                    sub = graph.subprogram(ct.Prototype("f", ct.integer(16, True), ()), 0x1000)
                else:
                    sub = graph.subprogram(ct.parse_prototype(text), 0x1000)
                if expected == "ok":
                    self.assertEqual(dt.declared(graph.dwarf(), sub).name, "g")
                else:
                    with self.assertRaises(dt.Ungradable) as raised:
                        dt.declared(graph.dwarf(), sub)
                    self.assertEqual(raised.exception.reason, dt.NOT_STATED)
        for what, result, params in [("a vector parameter", ok, [ok, vector, ok]), ("a vector result", vector, [ok]),
                                     ("a complex parameter", ok, [complex_double]), ("a complex result", complex_double, []),
                                     ("a result in a type unit", dwarf.UNRESOLVED, [ok]),
                                     ("a parameter in a type unit", ok, [dwarf.UNRESOLVED]),
                                     ("a parameter with no type", ok, [None])]:
            with self.subTest(what=what):
                sub = dwarf.Subprogram("f", 0x1000, "t.c", True, result, [dwarf.Parameter("p", t) for t in params],
                                       False, GCC, True, False)
                with self.assertRaises(dt.Ungradable) as raised:
                    dt.declared(graph.dwarf(), sub)
                self.assertEqual(raised.exception.reason, dt.NOT_STATED)

    def test_a_pointer_to_a_type_the_gate_cannot_state_makes_the_function_ungradable(self) -> None:
        graph = Graph()
        vector = graph.die("DW_TAG_array_type", (graph.child("DW_TAG_subrange_type", upper=3),),
                           type=graph.write(ct.integer(4, True)), size=16, vector=1)
        pointer = graph.die("DW_TAG_pointer_type", type=vector, size=8)
        sub = dwarf.Subprogram("f", 0x1000, "t.c", True, None, [dwarf.Parameter("p", pointer)], False, GCC, True, False)
        with self.assertRaises(dt.Ungradable):
            dt.declared(graph.dwarf(), sub)

    def test_the_first_failing_check_names_the_reason(self) -> None:
        self.assertEqual(ungradable("struct big f(void)", producer="clang", prototyped=False, instance=True), dt.NOT_GCC)
        self.assertEqual(ungradable("struct big f(void)", prototyped=False, instance=True), dt.INSTANCE)
        self.assertEqual(ungradable("struct big f(void)", prototyped=False), dt.NOT_PROTOTYPED)
        self.assertEqual(ungradable("struct big f(void)"), dt.NOT_STATED)

    def test_a_function_the_gate_cannot_grade_is_counted_by_reason_in_the_report(self) -> None:
        source = Source({0x1000: "int32_t g(void)", 0x2000: "struct big mk(int32_t n)", 0x3000: "int32_t scale(int32_t k)",
                         0x4000: "void zed(void)", 0x5000: "int32_t kr(int32_t a)", 0x6000: "double d(double x)",
                         0x7000: "void h(void)", 0x8000: "void i(void)"})
        source.state("scale", instance=True).state("zed", prototyped=False).state("kr", prototyped=False)
        stripped = {0x1000: fn("int32_t g(void)")}
        code, report, err = run_main(source, stripped)
        self.assertEqual(code, 0, err)
        self.assertEqual(report["ungradable"], {dt.INSTANCE: ["scale"], dt.NOT_PROTOTYPED: ["kr", "zed"],
                                                dt.NOT_STATED: ["d", "mk"]})
        self.assertEqual(list(report["ungradable"]), sorted(report["ungradable"]))
        self.assertEqual((report["functions_in_dwarf"], report["functions_in_truth"]), (8, 3))
        self.assertEqual(report["facts"], {"correct": 1, "missing": 2, "marked_wrong": 0, "silently_wrong": 0})

    def test_the_engine_is_not_graded_on_an_ungradable_function(self) -> None:
        source = Source({0x1000: "int32_t g(void)", 0x2000: "int64_t scale(int32_t k, char* p)"}).state("scale", instance=True)
        wrong = fn("uint8_t scale(uint8_t a, uint64_t b)", addr=0x2000)
        code, report, err = run_main(source, {0x1000: fn("int32_t g(void)"), 0x2000: wrong})
        self.assertEqual((code, report["silent"], report["facts"]["correct"]), (0, [], 1), err)

    def test_a_debug_build_with_no_gradable_function_fails_the_gate(self) -> None:
        # `gcc -g1 -O2 cold.c`: every function lacks the prototyped flag. Base refused these builds, and so must this.
        source = Source({0x1000: "int32_t a(void)", 0x2000: "void b(void)"}).state("a", prototyped=False).state("b", prototyped=False)
        code, report, err = run_main(source, {0x1000: fn(RIGHT), 0x2000: fn("void fcn_2000(void)", addr=0x2000)})
        self.assertEqual((code, report), (2, None))
        self.assertIn("no function of the debug build is gradable (2 " + dt.NOT_PROTOTYPED + ")", err)

    def test_every_function_of_each_reason_is_counted_in_the_refusal(self) -> None:
        source = Source({0x1000: "int32_t a(void)", 0x2000: "struct s b(void)", 0x3000: "int32_t c(void)"})
        source.state("a", prototyped=False).state("c", instance=True)
        code, _, err = run_main(source, {0x1000: fn(RIGHT)})
        self.assertEqual(code, 2)
        self.assertIn(f"(1 {dt.NOT_STATED}; 1 {dt.INSTANCE}; 1 {dt.NOT_PROTOTYPED})", err)


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
            ("return", "_Bool", "uint8_t", "other"),
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

    def test_a_result_spelled_through_the_carrier_typedef_is_marked(self) -> None:
        # D201: `r2sleigh_result_u32` says where the machine leaves a value and claims no C type.
        cells = self.cells("void f(void)", "r2sleigh_result_u32 fcn_1000(void)")
        self.assertEqual(cells["void_to_value"], {"total": 1, "silent": 0})
        code, report, _ = run_main({0x1000: "int32_t f(void)"}, {0x1000: fn("r2sleigh_result_u32 fcn_1000(void)")})
        self.assertEqual((code, report["facts"]["silently_wrong"], report["facts"]["marked_wrong"]), (0, 0, 1))

    def test_a_hole_spelled_through_its_typedef_is_marked(self) -> None:
        # D165: `r2sleigh_unread_u64` is a slot below a read one, which claims no C type.
        code, report, _ = run_main({0x1000: "int32_t f(int32_t a, int32_t b)"},
                                   {0x1000: fn("int32_t fcn_1000(r2sleigh_unread_u64 arg0, int32_t arg1)")})
        self.assertEqual((code, report["facts"]["silently_wrong"], report["facts"]["marked_wrong"]), (0, 0, 1))

    def test_another_typedef_named_result_is_a_silent_claim(self) -> None:
        code, report, _ = run_main({0x1000: "int32_t f(void)"}, {0x1000: fn("r2sleigh_result_x fcn_1000(void)")})
        self.assertEqual((code, report["facts"]["silently_wrong"]), (1, 1))

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

    def test_a_function_with_an_ungradable_result_has_no_presence(self) -> None:
        weird = Source({0x1000: "int32_t f(void)", 0x2000: "int32_t g(void)"})
        weird.placed[0] = dataclasses.replace(weird.placed[0], return_type=weird.graph.die(
            "DW_TAG_base_type", name="c", size=8, encoding="3\t(complex)"))
        code, report, _ = run_main(weird, {0x1000: fn("uint32_t f(void)"), 0x2000: fn("int32_t g(void)", addr=0x2000)})
        self.assertEqual(sum(cell["total"] for cell in report["return_presence"].values()), 1)
        self.assertEqual(report["ungradable"], {dt.NOT_STATED: ["f"]})


class Placement(unittest.TestCase):
    """A DWARF function the gate cannot place, or the engine does not list, is named and never fails the binary."""

    def test_a_function_with_no_one_entry_is_named_and_not_graded(self) -> None:
        split = dwarf.Unplaced("sym", 0x572, "its DW_AT_ranges list has no one readable first range")
        gone = dwarf.Unplaced("never_called", 0x600, dwarf.NO_FUNC_START)
        fragment = dwarf.Unplaced("split_hot", 0x700, dwarf.NO_FUNC_START)
        code, report, err = run_main({0x1000: INT, 0x2000: "void g(void)"}, {0x1000: fn(RIGHT)},
                                     unplaced=[split, gone, fragment])
        self.assertEqual(code, 0, err)
        self.assertEqual(report["ungradable"], {"its DW_AT_ranges list has no one readable first range": ["sym"],
                                                dwarf.NO_FUNC_START: ["never_called", "split_hot"]})
        self.assertEqual((report["functions_in_dwarf"], report["functions_in_truth"]), (5, 2))
        self.assertEqual(report["facts"]["correct"], 1)

    def test_a_function_the_engine_does_not_list_is_named_and_not_graded(self) -> None:
        code, report, err = run_main({0x1000: INT, 0x2000: "int32_t g(void)"},
                                     {0x1000: fn(RIGHT), 0x2000: fn("uint64_t g(void)", addr=0x2000)}, listed={0x1000})
        self.assertEqual(code, 0, err)
        self.assertEqual(report["ungradable"], {dt.UNLISTED: ["g"]})
        self.assertEqual((report["functions_in_dwarf"], report["functions_in_truth"]), (2, 1))
        self.assertEqual(report["facts"], {"correct": 1, "missing": 0, "marked_wrong": 0, "silently_wrong": 0})

    def test_two_functions_at_an_entry_the_engine_does_not_list_are_named_for_sharing_it(self) -> None:
        source = Source({0x1000: "int32_t a(void)", 0x2000: "int32_t g(void)"})
        source.placed.append(source.graph.subprogram(ct.parse_prototype("int32_t alias(void)"), 0x1000))
        code, report, err = run_main(source, {0x2000: fn(RIGHT, addr=0x2000)}, listed={0x2000})
        self.assertEqual(report["ungradable"], {dt.SHARED: ["a", "alias"]})

    def test_two_functions_at_one_entry_have_no_one_entry(self) -> None:
        source = Source({0x1000: "int32_t a(void)", 0x2000: "int32_t g(void)"})
        source.placed.append(source.graph.subprogram(ct.parse_prototype("int32_t alias(void)"), 0x1000))
        code, report, err = run_main(source, {0x2000: fn(RIGHT, addr=0x2000), 0x1000: fn(RIGHT, addr=0x1000)})
        self.assertEqual(code, 0, err)
        self.assertEqual(report["ungradable"], {dt.SHARED: ["a", "alias"]})
        self.assertEqual((report["functions_in_dwarf"], report["functions_in_truth"]), (3, 1))
        self.assertEqual(report["without_dwarf"], [])

    def test_the_engines_other_functions_are_listed_as_without_dwarf(self) -> None:
        debug = {0x1000: Fn("sym.f", {}), 0x2000: Fn("sym._start", {}), 0x1800: Fn("entry.fini0", {})}
        code, report, _ = run_main({0x1000: INT}, {0x1000: fn(RIGHT)}, debug_functions=debug)
        self.assertEqual(report["without_dwarf"], ["entry.fini0", "sym._start"])

    def test_dwarf_that_declares_nothing_fails_the_gate(self) -> None:
        code, report, err = run_main({}, {0x1000: fn(RIGHT)}, debug_functions={0x1000: Fn("sym.f", {})})
        self.assertEqual((code, report), (2, None))
        self.assertIn("no function of the debug build is gradable (its DWARF declares no function)", err)

    def test_dwarf_that_places_nothing_the_engine_lists_fails_the_gate(self) -> None:
        code, report, err = run_main({0x1000: INT}, {0x1000: fn(RIGHT)}, listed=set())
        self.assertEqual((code, report), (2, None))
        self.assertIn(f"no function of the debug build is gradable (1 {dt.UNLISTED})", err)
        gone = dwarf.Unplaced("f", 1, dwarf.NO_FUNC_START)
        code, report, err = run_main({}, {0x1000: fn(RIGHT)}, unplaced=[gone], debug_functions={0x1000: Fn("sym.f", {})})
        self.assertEqual((code, report), (2, None))
        self.assertIn(f"no function of the debug build is gradable (1 {dwarf.NO_FUNC_START})", err)

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


# `readelf --wide --notes` of a gcc build: what `strip` keeps of it.
NOTES = ("Displaying notes found in: .note.gnu.build-id\n  Owner                Data size \tDescription\n"
         "  GNU                  0x00000014\tNT_GNU_BUILD_ID (unique build ID bitstring)\t"
         "    Build ID: 6b1d4c0f2a9e7d3b5c8a1f0e2d4b6a8c9e1f3a5b\n")


def readelf(info: str, symbols: str):
    """A stand-in for `subprocess.run` answering `readelf --debug-dump` and `--syms` with the texts.

    The stripped build named `stripped` has no DWARF or symbols.
    """

    def run(argv, **_):
        if "--notes" in argv:
            return subprocess.CompletedProcess(argv, 0, NOTES, "")
        text = "" if argv[-1] == "stripped" else symbols if "--syms" in argv else info
        return subprocess.CompletedProcess(argv, 0, text, "")

    return run


FIXTURES = HERE.parent / "tests" / "equiv" / "testdata" / "dwarf"


def fixture_texts(name: str) -> tuple[str, str]:
    """The readelf dumps kept for a build (tests/equiv/testdata/dwarf): its DWARF and symbols."""
    return tuple((FIXTURES / f"{name}{suffix}").read_text() for suffix in (".txt", ".syms.txt"))


@contextlib.contextmanager
def fixture_build(name: str):
    """readelf answering with a build's kept dumps, and its program headers read from its kept ELF head; `strip`
    keeps the program headers, so the stripped build has the same."""
    head = bytes.fromhex((FIXTURES / f"{name}.head.hex").read_text())
    with (
        mock.patch.object(dwarf.subprocess, "run", side_effect=readelf(*fixture_texts(name))),
        mock.patch.object(dt, "loaded_code", side_effect=lambda binary: dwarf.code_addresses(head, str(binary))),
    ):
        yield


class ReadingDwarf(unittest.TestCase):
    """`read_dwarf` asks the oracle side's DWARF reader, with the binutils the caller names, and places by the binary's symbols."""

    def test_the_binutils_prefix_reaches_readelf_and_the_functions_come_back_placed(self) -> None:
        reading = mock.Mock(placed=mock.Mock(return_value=(["placed"], ["unplaced"])))
        symbols, code = {0x1000: (["f"], 4)}, [range(0x1000, 0x1010)]
        with (
            mock.patch.object(dt.Dwarf, "read", return_value=reading) as read,
            mock.patch.object(dt, "function_symbols", return_value=symbols) as listed,
            mock.patch.object(dt, "loaded_code", return_value=code) as loaded,
        ):
            result = dt.read_dwarf(pathlib.Path("debug"), "g")
        self.assertEqual(read.call_args.args[1].binutils_prefix, "g")
        self.assertEqual(listed.call_args.args[1].binutils_prefix, "g")
        loaded.assert_called_once_with(pathlib.Path("debug"))
        reading.placed.assert_called_once_with(symbols, code)
        self.assertEqual(result, (reading, ["placed"], ["unplaced"]))

    def test_readelf_that_is_missing_or_fails_is_unreadable(self) -> None:
        for error in (FileNotFoundError(2, "No such file or directory", "readelf"), RuntimeError("readelf failed on d")):
            with (self.subTest(error=error), mock.patch.object(dt.Dwarf, "read", side_effect=error),
                  mock.patch.object(dt, "loaded_code", return_value=[range(0x1000, 0x1010)])):
                with self.assertRaises(dt.Unreadable) as raised:
                    dt.read_dwarf(pathlib.Path("debug"), "")
                self.assertEqual(raised.exception.command, "readelf")
                self.assertIn(str(error), raised.exception.causes[""])

    def test_a_dwarf_that_cannot_be_placed_is_unreadable(self) -> None:
        # A cycle of DW_AT_abstract_origin raises while the functions are placed, not while the dump is read.
        reading = mock.Mock(placed=mock.Mock(side_effect=RuntimeError("a cycle of DW_AT_abstract_origin at 0x40")))
        with (
            mock.patch.object(dt.Dwarf, "read", return_value=reading),
            mock.patch.object(dt, "function_symbols", return_value={}),
            mock.patch.object(dt, "loaded_code", return_value=[range(0x1000, 0x1010)]),
            self.assertRaises(dt.Unreadable) as raised,
        ):
            dt.read_dwarf(pathlib.Path("debug"), "")
        self.assertIn("a cycle", raised.exception.causes[""])

    def test_a_function_is_placed_where_a_function_symbol_starts_and_nowhere_else(self) -> None:
        for name, build, placed, unplaced in [
            ("gcc lists a split function's hot part first", "cold.gcc.O2", ["checked_div", "main", "must_alloc", "sum_bytes"], []),
            ("clang lists a basic-block-sections entry last", "cold.clang.O2.bbs", [], ["checked_div", "main", "must_alloc", "sum_bytes"]),
        ]:
            with self.subTest(name=name), fixture_build(build):
                _, found, gone = dt.read_dwarf(pathlib.Path("debug"), "")
            self.assertEqual(sorted(sub.name for sub in found), placed)
            self.assertEqual(sorted(g.name for g in gone), unplaced)

    def test_the_gate_refuses_a_build_whose_every_function_clang_split_into_sections(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        argv = ["differential_truth.py", "--debug-build", "debug", "--stripped-build", "stripped"]
        fragments = {0x11CD: Fn("loc.checked_div.__part.1", {}), 0x11C0: Fn("sym.checked_div", {})}
        with (
            mock.patch.object(sys, "argv", argv),
            shell({DEBUG: fragments, STRIPPED: {}}),
            fixture_build("cold.clang.O2.bbs"),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            code = dt.main()
        self.assertEqual((code, out.getvalue()), (2, ""))
        self.assertIn(f"no function of the debug build is gradable (4 {dwarf.NO_FUNC_START})", err.getvalue())


@functools.cache
def read_fixture(name: str):
    """`read_dwarf` over the readelf dumps kept for a build (tests/equiv/testdata/dwarf), debug build and symbols."""
    with fixture_build(name):
        return dt.read_dwarf(pathlib.Path("debug"), "")


def main_over_fixture(name: str, stripped: dict[int, Fn] | None = None) -> tuple[int, str, str]:
    """Exit code, stdout and stderr of main over a fixture's debug build, every placed function of it listed."""
    _, placed, _ = read_fixture(name)
    out, err = io.StringIO(), io.StringIO()
    argv = ["differential_truth.py", "--debug-build", "debug", "--stripped-build", "stripped"]
    functions = {sub.low_pc: Fn(f"sym.{sub.name}", {}) for sub in placed}
    with (
        mock.patch.object(sys, "argv", argv),
        shell({DEBUG: functions, STRIPPED: stripped or {}}),
        fixture_build(name),
        contextlib.redirect_stdout(out),
        contextlib.redirect_stderr(err),
    ):
        code = dt.main()
    return code, out.getvalue(), err.getvalue()


def partition_fixture(name: str):
    """The names the gate grades and the names it refuses by reason, for a build whose every function the engine lists."""
    reading, placed, unplaced = read_fixture(name)
    truth, refused = dt.partition(reading, placed, unplaced, {sub.low_pc: sub.name for sub in placed})
    return sorted(declared.name for declared in truth.values()), refused


class RealCompilers(unittest.TestCase):
    """The shapes the third review built, as gcc 13.3 left their DWARF (`tests/gold/source_gold`, the sources)."""

    def test_gcc_g1_keeps_no_signature_and_no_function_of_it_is_graded(self) -> None:
        graded, refused = partition_fixture("cold.gcc.O2.g1")
        self.assertEqual((graded, refused), ([], {dt.NOT_PROTOTYPED: ["checked_div", "main", "must_alloc", "sum_bytes"]}))
        # The gate exits 2 on it, as the base did, and not 1 with `void f(void)` for every function.
        code, out, err = main_over_fixture("cold.gcc.O2.g1")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("no function of the debug build is gradable (4 " + dt.NOT_PROTOTYPED + ")", err)

    def test_gcc_gc_sections_discards_functions_that_are_no_part_of_the_floor(self) -> None:
        # gclib.c: the linker drops 12 of 16 functions, whose DIEs keep a low_pc of 0. All 4 with code are graded.
        graded, refused = partition_fixture("gclib.gcc.O2.gc")
        self.assertEqual(graded, ["main", "used_a", "used_b", "used_c"])
        self.assertEqual(refused, {dwarf.DISCARDED: sorted(f"unused_{index}" for index in range(12))})
        _, placed, _ = read_fixture("gclib.gcc.O2.gc")
        said = {"main": "int32_t main(int32_t argc, char** argv)", "used_a": "int32_t used_a(int32_t a, int32_t b)",
                "used_b": "uint32_t used_b(uint32_t a)", "used_c": "int64_t used_c(int64_t* p, int32_t n)"}
        stripped = {sub.low_pc: fn(said[sub.name], addr=sub.low_pc) for sub in placed}
        code, out, err = main_over_fixture("gclib.gcc.O2.gc", stripped)
        self.assertEqual((code, err), (0, ""))
        report = json.loads(out)
        self.assertEqual((report["functions_in_dwarf"], report["functions_in_truth"], report["facts"]["correct"]), (16, 4, 11))

    def test_static_functions_whose_symbols_ld_x_discarded_count_in_the_floor_and_the_build_is_refused(self) -> None:
        # returns.c (x86-64 -O2) and statics.c (AArch64 -O0) linked with -Wl,-x: the static functions keep their code
        # in .text and lose their FUNC symbols, so the gate places only the global ones.
        for name, graded, total in (("returns.gcc.O2.x", 3, 12), ("statics.a64.O0.x", 3, 15)):
            with self.subTest(name=name):
                _, placed, unplaced = read_fixture(name)
                self.assertEqual((len(placed), [gone.why for gone in unplaced]), (graded, [dwarf.NO_FUNC_START] * (total - graded)))
                code, out, err = main_over_fixture(name)
                self.assertEqual((code, out), (2, ""))
                self.assertIn(f"{graded} of {total} functions are gradable, under one in 3 ({total - graded} {dwarf.NO_FUNC_START})", err)

    def test_static_functions_whose_code_lies_in_a_section_without_the_x_flag_count_in_the_floor(self) -> None:
        # fdat.c with -Wl,-x: an injected directive puts the 12 statics in `.fdat`, flags WA (or A with -DREADONLY).
        for name in ("fdat.gcc.O2.x", "fdat.gcc.O0.x", "fdat.ro.gcc.O2.x", "fdat.ro.gcc.O0.x", "fdat.a64.O0.x"):
            with self.subTest(name=name):
                _, placed, unplaced = read_fixture(name)
                self.assertEqual(sorted(sub.name for sub in placed), ["g_0", "g_1", "main"])
                self.assertEqual({(gone.why, gone.code) for gone in unplaced}, {(dwarf.NO_FUNC_START, True)})
                code, out, err = main_over_fixture(name)
                self.assertEqual((code, out), (2, ""))
                self.assertIn(f"3 of 15 functions are gradable, under one in 3 (12 {dwarf.NO_FUNC_START})", err)

    def test_a_relocatable_object_is_refused_by_name(self) -> None:
        # `gcc -g -O2 -c gclib.c`: its DWARF reads, its program header table is empty.
        head = bytes.fromhex("7f454c4602010100000000000000000001003e000100000000000000000000000000000000000000"
                             "281c0000000000000000000040000000000040001b001a00")
        out, err = io.StringIO(), io.StringIO()
        argv = ["differential_truth.py", "--debug-build", "debug", "--stripped-build", "stripped"]
        with (
            mock.patch.object(sys, "argv", argv),
            shell({DEBUG: {}, STRIPPED: {}}),
            fixture_build("gclib.gcc.O2.gc"),
            mock.patch.object(dt, "loaded_code", side_effect=lambda binary: dwarf.code_addresses(head, str(binary))),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            code = dt.main()
        self.assertEqual((code, out.getvalue()), (2, ""))
        self.assertIn(f"UNREADABLE program headers: debug: debug: {dwarf.RELOCATABLE}", err.getvalue())

    def test_a_k_and_r_definition_with_a_prototype_in_scope_is_graded_by_its_own_types(self) -> None:
        # krt.c: gcc states DW_AT_prototyped and `short c` for kr_short, whose callee converts the caller's int to
        # short; kr_bare has no prototype in scope, so its caller promotes and DWARF states no flag.
        reading, placed, unplaced = read_fixture("krt.gcc.O2")
        truth, refused = dt.partition(reading, placed, unplaced, {sub.low_pc: sub.name for sub in placed})
        spelled = {graded.name: f"{ct.spell(graded.ret)} ({', '.join(map(ct.spell, graded.params))})"
                   for graded in truth.values()}
        self.assertEqual(spelled, {"kr_short": "int32_t (int32_t, int16_t)", "main": "int32_t (int32_t, char**)"})
        self.assertEqual(refused, {dt.NOT_PROTOTYPED: ["kr_bare"]})

    def test_gcc_ipa_clones_are_instances_whose_formals_come_in_the_clones_order(self) -> None:
        # `scale(int k, char *p, long n)` became `scale.constprop.0.isra.0` taking (n, p): the DIE lists n, k, p.
        _, placed, _ = read_fixture("clones.gcc.O2")
        order = {sub.name: [param.name for param in sub.parameters] for sub in placed}
        self.assertEqual(order["scale"], ["n", "k", "p"])
        self.assertEqual(order["field_b"], ["mul", "unused", "r"])
        graded, refused = partition_fixture("clones.gcc.O2")
        self.assertEqual(refused, {dt.INSTANCE: ["field_b", "scale"]})
        self.assertEqual(graded, ["main", "part_split", "skip_first", "use_field", "use_part", "use_scale"])

    def test_no_aggregate_vector_wide_float_or_k_and_r_function_is_graded_on_either_architecture(self) -> None:
        # x86-64 passes a result over 16 bytes through the first integer register and aarch64 through x8: the gate
        # states neither, so `make_big(int n, long *p)` is graded on no architecture.
        outcomes = {name: partition_fixture(name) for name in ("abi.gcc.O2", "abi.a64.O2")}
        self.assertEqual(outcomes["abi.gcc.O2"], outcomes["abi.a64.O2"])
        graded, refused = outcomes["abi.gcc.O2"]
        self.assertEqual(refused[dt.NOT_STATED], [
            "cx_mid", "fl_mid", "fl_ret", "ld_mid", "make_big", "make_mixed", "make_small", "small_mid", "sum_big",
            "un_mid", "vec_mid", "vecf_mid", "wide_mid", "wide_ret"])
        self.assertEqual(refused[dt.NOT_PROTOTYPED], ["kr"])
        self.assertEqual(graded, ["arr_mid", "first_c", "first_sc", "first_uc", "fn_mid", "is_set", "main", "pick",
                                  "pickw", "tail", "va_sum"])

    def test_the_vector_parameters_of_gcc_are_flagged_arrays_and_no_array(self) -> None:
        reading, placed, _ = read_fixture("abi.gcc.O2")
        vec = next(sub for sub in placed if sub.name == "vec_mid")
        with self.assertRaises(ct.NotExpressible) as raised:
            ct.from_dwarf(reading, vec.parameters[1].type_offset)
        self.assertIn("vector", str(raised.exception))


    def test_an_enum_is_the_integer_gcc_states_under_it(self) -> None:
        # enums.c: `enum neg` is int, `enum big` long, `enum pos` and `enum ubig` unsigned int (gcc 13.3, DWARF 5).
        reading, placed, unplaced = read_fixture("enums.gcc.O2")
        truth, refused = dt.partition(reading, placed, unplaced, {sub.low_pc: sub.name for sub in placed})
        spelled = {graded.name: f"{ct.spell(graded.ret)} ({', '.join(map(ct.spell, graded.params))})"
                   for graded in truth.values()}
        self.assertEqual(spelled, ENUM_TRUTH)
        self.assertEqual(refused, {})

    def test_strict_dwarf_2_states_no_enum_type_and_no_function_with_one_is_graded(self) -> None:
        # `-gdwarf-2 -gstrict-dwarf` writes no DW_AT_type under an enum: its sign is stated nowhere.
        graded, refused = partition_fixture("enums.gcc.O2.strict2")
        self.assertEqual(graded, ["main"])
        self.assertEqual(refused, {dt.NOT_STATED: sorted(set(ENUM_TRUTH) - {"main"})})

    def test_a_build_with_a_type_unit_is_refused_whole(self) -> None:
        # DWARF 4 numbers .debug_types from 0, so its DIEs overwrote those of .debug_info: `main` read
        # `(int32_t, int64_t*)`; DWARF 5 leaves stubs whose enum read uint32_t. Both builds are refused whole.
        for name in ("odd.gcc.O2.dwarf4.types", "abi.gcc.O2.types"):
            out, err = io.StringIO(), io.StringIO()
            argv = ["differential_truth.py", "--debug-build", "debug", "--stripped-build", "stripped"]
            with (
                self.subTest(name=name),
                mock.patch.object(sys, "argv", argv),
                shell({DEBUG: {}, STRIPPED: {}}),
                fixture_build(name),
                contextlib.redirect_stdout(out),
                contextlib.redirect_stderr(err),
            ):
                code = dt.main()
            self.assertEqual((code, out.getvalue()), (2, ""))
            self.assertIn(dwarf.TYPE_UNIT, err.getvalue())
            self.assertNotIn("Traceback", err.getvalue())


ENUM_TRUTH = {
    "e_big": "int64_t (int64_t, int64_t)", "e_neg": "int32_t (int32_t, int32_t, int32_t)",
    "e_pos": "uint32_t (uint32_t, int64_t)", "e_ptr": "int32_t (uint32_t*)", "e_td": "int32_t (int32_t, int32_t*)",
    "e_ubig": "uint32_t (uint32_t)", "main": "int32_t (int32_t, char**)",
}


class OneProgram(unittest.TestCase):
    """The stripped build is graded only when it carries the debug build's build ID: one link, two copies."""

    def test_two_builds_whose_ids_differ_or_are_missing_are_refused(self) -> None:
        for ids in (("6b1d", "9c2e"), ("6b1d4c0f", "6b1d9e2a"), ("6b1d", "6b1d4c"), (None, "6b1d"), ("6b1d", None), (None, None)):
            with self.subTest(ids=ids):
                code, report, err = run_main({0x1000: INT}, {0x1000: fn(RIGHT)}, ids=ids)
                self.assertEqual((code, report), (2, None))
                self.assertIn("not shown to be one program", err)

    def test_one_id_is_graded(self) -> None:
        self.assertEqual(run_main({0x1000: INT}, {0x1000: fn(RIGHT)}, ids=("6b1d", "6b1d"))[0], 0)

    def test_the_id_is_the_gnu_build_id_note_and_a_build_without_one_has_none(self) -> None:
        for notes, expected in [(NOTES, "6b1d4c0f2a9e7d3b5c8a1f0e2d4b6a8c9e1f3a5b"), ("", None),
                                ("Displaying notes found in: .note.ABI-tag\n  GNU  0x10  NT_GNU_ABI_TAG\n", None)]:
            with self.subTest(expected=expected), mock.patch.object(
                    dt.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, notes, "")) as run:
                self.assertEqual(dt.build_id(pathlib.Path("debug"), "g"), expected)
            self.assertEqual(run.call_args.args[0], ["greadelf", "--wide", "--notes", "debug"])
        with mock.patch.object(dt.subprocess, "run", side_effect=FileNotFoundError(2, "No such file", "readelf")):
            with self.assertRaises(dt.Unreadable):
                dt.build_id(pathlib.Path("debug"), "")


class Coverage(unittest.TestCase):
    """A rate is printed only when the gate grades at least a third of the build's functions with code."""

    @staticmethod
    def build(graded: int, total: int) -> tuple[Source, dict[int, Fn]]:
        protos = {0x1000 + 0x10 * index: f"int32_t f{index}(int32_t a)" for index in range(total)}
        source = Source(protos)
        for index in range(graded, total):
            source.state(f"f{index}", instance=True)
        # Every graded function is wrong and marked: no fact is asserted, and the rate alone would read 1.0.
        stripped = {addr: fn(f"uint64_t fcn_{addr:x}(uint64_t arg0)", residuals=1, addr=addr) for addr in protos}
        return source, stripped

    def test_three_graded_of_twenty_is_refused_and_prints_no_rate(self) -> None:
        code, report, err = run_main(*self.build(3, 20))
        self.assertEqual((code, report), (2, None))
        self.assertIn("3 of 20 functions are gradable", err)

    def test_the_floor_is_a_third(self) -> None:
        for graded, total, code in [(6, 20, 2), (7, 20, 0), (1, 3, 0), (1, 4, 2), (11, 26, 0)]:
            with self.subTest(graded=graded, total=total):
                self.assertEqual(run_main(*self.build(graded, total))[0], code)

    def test_a_function_with_code_the_gate_cannot_place_counts_in_the_floor(self) -> None:
        # Whatever the reason, even one no code names, an unplaced function has code unless shown discarded.
        for why in (dwarf.NO_FUNC_START, "its DW_AT_entry_pc is an offset from a base, not an address", "a reason no test names"):
            with self.subTest(why=why):
                source, stripped = self.build(1, 1)
                source.unplaced = [dwarf.Unplaced(f"gone{index}", index, why) for index in range(9)]
                code, report, err = run_main(source, stripped)
                self.assertEqual((code, report), (2, None))
                self.assertIn(f"1 of 10 functions are gradable, under one in 3 (9 {why})", err)

    def test_a_function_whose_code_the_linker_discarded_is_no_part_of_the_floor(self) -> None:
        source, stripped = self.build(1, 1)
        source.unplaced = [dwarf.Unplaced(f"gone{index}", index, dwarf.DISCARDED, code=False) for index in range(9)]
        code, report, err = run_main(source, stripped)
        self.assertEqual((code, report["functions_in_dwarf"], report["functions_in_truth"]), (0, 10, 1), err)
        self.assertEqual(report["ungradable"], {dwarf.DISCARDED: [f"gone{index}" for index in range(9)]})
        # Each function with code counts: 1 graded of 2 passes, 1 of 4 does not.
        for kept, exit_code in ((1, 0), (3, 2)):
            with self.subTest(kept=kept):
                source.unplaced = [dwarf.Unplaced(f"gone{index}", index, dwarf.NO_FUNC_START, code=index < kept)
                                   for index in range(9)]
                self.assertEqual(run_main(source, stripped)[0], exit_code)

    def test_the_placed_functions_the_gate_refuses_count_beside_the_unplaced_ones(self) -> None:
        source, stripped = self.build(1, 4)
        source.unplaced = [dwarf.Unplaced(f"gone{index}", index, dwarf.NO_FUNC_START) for index in range(9)]
        code, report, err = run_main(source, stripped)
        self.assertEqual((code, report), (2, None))
        self.assertIn("1 of 13 functions are gradable", err)
        source.unplaced = [dataclasses.replace(gone, code=False) for gone in source.unplaced]
        self.assertIn("1 of 4 functions are gradable", run_main(source, stripped)[2])

    def test_functions_that_share_an_entry_count_in_the_floor(self) -> None:
        # One graded and four at two shared entries: 1 of 5 is refused, where 1 of 1 would pass.
        source, stripped = self.build(1, 1)
        twin = source.placed[0]
        source.placed += [dataclasses.replace(twin, name=f"twin{index}", low_pc=0x2000 + 0x10 * (index // 2)) for index in range(4)]
        code, report, err = run_main(source, stripped)
        self.assertEqual((code, report), (2, None))
        self.assertIn(f"1 of 5 functions are gradable, under one in 3 (4 {dt.SHARED})", err)


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
            "functions_in_dwarf", "functions_in_truth", "functions_recovered", "ungradable", "without_dwarf",
            "facts", "recovery_rate", "soundness_rate", "soundness_without_qualifier", "silent", "silent_buckets",
            "marked_buckets", "return_presence"])
        self.assertEqual(list(report["return_presence"]), list(dt.PRESENCE))

    def test_every_function_dwarf_declares_is_graded_or_named(self) -> None:
        gone = [dwarf.Unplaced("g", 1, "why")]
        source = Source({0x1000: INT, 0x2000: "int32_t h(void)", 0x3000: "int32_t k(void)", 0x4000: "int32_t m(void)",
                         0x5000: "void n(void)", 0x6000: "void o(void)"}, gone)
        source.placed.append(source.graph.subprogram(ct.parse_prototype("int32_t alias(void)"), 0x1000))
        source.state("m", instance=True)
        _, report, _ = run_main(source, {0x2000: fn("int32_t h(void)", addr=0x2000)},
                                listed={0x1000, 0x2000, 0x4000, 0x5000, 0x6000})
        named = sum(len(names) for names in report["ungradable"].values())
        self.assertEqual(report["functions_in_dwarf"], 8)
        self.assertEqual(report["functions_in_truth"] + named, 8)
        self.assertEqual(report["functions_in_truth"], 3)
        self.assertEqual(report["ungradable"], {"why": ["g"], dt.INSTANCE: ["m"], dt.SHARED: ["alias", "f"], dt.UNLISTED: ["k"]})

    def test_every_list_in_the_report_is_sorted(self) -> None:
        names = ["zeta", "alpha", "mid"]
        source = {0x1000 + 16 * index: f"int32_t {name}(void)" for index, name in enumerate(names)}
        debug = {addr: Fn(f"sym.{name}", {}) for addr, name in zip(sorted(source), names)}
        debug[0x9000] = Fn("sym.b", {})
        debug[0x9100] = Fn("sym.a", {})
        gone = [dwarf.Unplaced("z", 1, "why"), dwarf.Unplaced("a", 2, "why"), dwarf.Unplaced("m", 3, "an earlier reason")]
        stripped = {addr: fn(f"uint64_t {name}(void)", addr=addr) for addr, name in zip(source, names)}
        code, report, _ = run_main(source, stripped, debug_functions=debug, unplaced=gone)
        self.assertEqual(report["without_dwarf"], ["sym.a", "sym.b"])
        self.assertEqual(report["ungradable"], {"an earlier reason": ["m"], "why": ["a", "z"]})
        self.assertEqual(list(report["ungradable"]), ["an earlier reason", "why"])
        self.assertEqual(len(report["silent"]), 3)

    def test_the_functions_the_engine_does_not_list_are_named_in_order(self) -> None:
        source = {0x1000: "int32_t zeta(void)", 0x1010: "int32_t alpha(void)", 0x1020: "int32_t mid(void)",
                  0x1030: "int32_t zulu(void)", 0x1040: "int32_t able(void)"}
        _, report, _ = run_main(source, {0x1000: fn("int32_t zeta(void)")}, listed={0x1000, 0x1010, 0x1020})
        self.assertEqual(report["ungradable"], {dt.UNLISTED: ["able", "zulu"]})

    def test_soundness_is_reported_beside_the_same_rate_without_the_qualifier_rows(self) -> None:
        # No stripped binary states `const`: nine of fifteen silent errors in hashes.c are `const uint8_t*` said `uint8_t*`.
        source = {0x1000: "int32_t f(const uint8_t* a, const uint8_t* b, int32_t c, int32_t d)"}
        said = fn("int32_t fcn_1000(uint8_t* a0, uint8_t* a1, int32_t a2, uint64_t a3)")
        report = graded(source, {0x1000: said})
        self.assertEqual(report["silent_buckets"], {"parameter": {"qualifier": 2, "width_wider": 1}})
        # correct 2 (return, c), silent 3: asserted 5, and 2 of the 3 are qualifier rows.
        self.assertEqual(report["soundness_rate"], round(1 - 3 / 5, 4))
        self.assertEqual(report["soundness_without_qualifier"], round(1 - 1 / 3, 4))

    def test_a_run_whose_every_error_is_a_qualifier_is_perfectly_sound_without_them(self) -> None:
        report = graded({0x1000: "void f(const uint8_t* a)"}, {0x1000: fn("void fcn_1000(uint8_t* a0)")})
        self.assertEqual((report["soundness_rate"], report["soundness_without_qualifier"]), (0.5, 1.0))
        report = graded({0x1000: "void f(const uint8_t* a)"}, {0x1000: fn("void fcn_1000(uint8_t* a0)", residuals=1)})
        self.assertEqual((report["soundness_rate"], report["soundness_without_qualifier"]), (1.0, 1.0))

    def test_a_run_whose_only_asserted_fact_is_a_qualifier_asserts_nothing_without_it(self) -> None:
        report = graded({0x1000: "const char* f(void)"}, {0x1000: fn("char* fcn_1000(void)")})
        self.assertEqual((report["facts"]["correct"], report["facts"]["silently_wrong"]), (0, 1))
        self.assertEqual((report["soundness_rate"], report["soundness_without_qualifier"]), (0.0, 1.0))

    def test_a_marked_qualifier_row_is_in_neither_rate(self) -> None:
        source = {0x1000: "int32_t f(const uint8_t* a, int32_t b)"}
        said = fn("uint64_t fcn_1000(uint8_t* a0, int32_t a1)", residuals=1)
        report = graded(source, {0x1000: said})
        self.assertEqual((report["soundness_rate"], report["soundness_without_qualifier"]), (1.0, 1.0))


if __name__ == "__main__":
    unittest.main()
