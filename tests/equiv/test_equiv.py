#!/usr/bin/env python3
"""Tests of the equivalence gate itself.

    python3 -m unittest discover -s tests/equiv -p 'test_*.py'

The self-test suite is the gate's precondition and runs here too; the rest pins
the parts a gate run cannot check on itself: that r2s's every failure mode ends
as exactly one typed answer per address, that the ratchet blocks what it must,
and that the whole pipeline -- build, strip, capture, compile, run, compare --
keeps every known rendering's verdict at every level, and never grades a
rendering that hands its work back to the original as ``equal``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import build  # noqa: E402
import gate  # noqa: E402
import link  # noqa: E402
import run_equiv  # noqa: E402
import selftest  # noqa: E402
from dwarf import Dwarf  # noqa: E402
from r2s_batch import contract_problems, parse_pddj, run_batch  # noqa: E402
from spec import CallSpec, call_spec  # noqa: E402

STUB = HERE / "testdata" / "stub_r2s.py"
CAN_RUN = gate.environment_problem() is None and shutil.which("gcc") is not None


class _StubEnv:
    """Set the stub's mode and faults for one test."""

    def __init__(self, **values: str):
        self.values = values
        self.saved: dict[str, str | None] = {}

    def __enter__(self):
        for key, value in self.values.items():
            self.saved[key] = os.environ.get(key)
            os.environ[key] = value
        return self

    def __exit__(self, *exc):
        for key, value in self.saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class BatchTests(unittest.TestCase):
    """Every address comes back as exactly one typed answer."""

    ADDRESSES = [0x1000, 0x2000, 0x3000, 0x4000]

    def ask(self, timeout: float = 30.0, addresses: list[int] | None = None,
            startup: float | None = None, **env: str):
        with _StubEnv(**env), tempfile.TemporaryDirectory() as state:
            os.environ["STUB_R2S_STATE"] = state
            try:
                return run_batch(STUB, "/bin/true", addresses or self.ADDRESSES,
                                 function_timeout=timeout, startup_timeout=startup)
            finally:
                os.environ.pop("STUB_R2S_STATE", None)

    def test_a_clean_batch_is_one_process_and_one_answer_each(self):
        report = self.ask(STUB_R2S_MODE="minimal", STUB_R2S_FAULTS="")
        self.assertEqual([a.address for a in report.answers], self.ADDRESSES)
        self.assertTrue(all(a.kind == "output" for a in report.answers))
        self.assertEqual(report.processes, 1)

    def test_a_failed_statement_is_a_typed_decline_not_a_crash(self):
        # Each stdin line is a script of its own, so a failed statement costs
        # its own address only, and its message lands inside its own markers.
        report = self.ask(STUB_R2S_MODE="minimal", STUB_R2S_FAULTS="error@2000")
        kinds = [a.kind for a in report.answers]
        self.assertEqual(kinds, ["output", "decline", "output", "output"])
        self.assertEqual(report.answers[1].cause, "r2s: nothing mapped at 0x2000")
        self.assertEqual(report.processes, 1)

    def test_an_abort_costs_one_function_and_the_batch_restarts(self):
        report = self.ask(STUB_R2S_MODE="minimal", STUB_R2S_FAULTS="abort@2000")
        kinds = [a.kind for a in report.answers]
        self.assertEqual(kinds, ["output", "crash", "output", "output"])
        self.assertIn("SIGABRT", report.answers[1].cause)
        self.assertIn("0x2000", report.answers[1].cause)
        self.assertEqual(report.processes, 2)

    def test_a_hang_is_charged_to_the_function_it_hung_on(self):
        report = self.ask(timeout=2.0, STUB_R2S_MODE="minimal", STUB_R2S_FAULTS="sleep@1000")
        kinds = [a.kind for a in report.answers]
        self.assertEqual(kinds, ["crash", "output", "output", "output"])
        self.assertIn("timed out", report.answers[0].cause)

    def test_a_process_that_never_starts_declines_everything_once(self):
        report = self.ask(STUB_R2S_MODE="die-at-start", STUB_R2S_FAULTS="")
        self.assertEqual(len(report.answers), len(self.ADDRESSES))
        self.assertTrue(all(a.kind == "crash" for a in report.answers))
        self.assertEqual(len({a.cause for a in report.answers}), 1)
        self.assertEqual(report.processes, 1)

    def test_a_batch_of_any_size_is_one_process(self):
        # 3,000 addresses: as one -c script this was about 200 KiB of argv, past
        # Linux's 128 KiB cap on one argument, and Popen raised before r2s ran.
        addresses = [0x400000 + 16 * n for n in range(3000)]
        report = self.ask(addresses=addresses, STUB_R2S_MODE="minimal", STUB_R2S_FAULTS="")
        self.assertEqual([a.address for a in report.answers], addresses)
        self.assertTrue(all(a.kind == "output" for a in report.answers))
        self.assertEqual(report.processes, 1)

    def test_opening_the_binary_is_not_charged_to_the_first_function(self):
        # The open takes longer than a function may, and less than startup may.
        report = self.ask(timeout=1.0, startup=20.0, STUB_R2S_MODE="minimal",
                          STUB_R2S_FAULTS="", STUB_R2S_STARTUP_DELAY="1.5")
        self.assertEqual([a.kind for a in report.answers], ["output"] * 4)
        self.assertEqual(report.processes, 1)

    def test_a_slow_open_is_one_cause_for_every_address_once(self):
        started = time.monotonic()
        report = self.ask(timeout=30.0, startup=1.0, STUB_R2S_MODE="minimal",
                          STUB_R2S_FAULTS="", STUB_R2S_STARTUP_DELAY="20")
        self.assertLess(time.monotonic() - started, 10.0)
        self.assertEqual(len(report.answers), len(self.ADDRESSES))
        self.assertTrue(all(a.kind == "crash" for a in report.answers))
        self.assertEqual({a.cause for a in report.answers},
                         {"harness: r2s did not open the binary: timed out after 1s"})
        self.assertEqual(report.processes, 1)

    def test_a_file_r2s_will_not_open_is_its_own_decline(self):
        report = self.ask(STUB_R2S_MODE="cannot-open", STUB_R2S_FAULTS="")
        self.assertTrue(all(a.kind == "decline" for a in report.answers))
        self.assertEqual({a.cause for a in report.answers},
                         {"r2s: /bin/true: not an executable the stub reads"})
        self.assertEqual(report.processes, 1)

    def test_an_answer_without_its_newline_is_read_at_once(self):
        started = time.monotonic()
        report = self.ask(timeout=20.0, STUB_R2S_MODE="minimal",
                          STUB_R2S_FAULTS="unterminated@2000")
        self.assertLess(time.monotonic() - started, 10.0)
        self.assertEqual([a.kind for a in report.answers], ["output"] * 4)
        self.assertEqual(report.answers[1].record["addr"], 0x2000)

    def test_output_that_is_not_the_contract_is_a_harness_decline(self):
        report = self.ask(STUB_R2S_MODE="minimal",
                          STUB_R2S_FAULTS="garbage@1000,breach@2000")
        self.assertTrue(report.answers[0].cause.startswith("harness: pddj is not one JSON"))
        self.assertTrue(report.answers[1].cause.startswith("harness: pddj breaks its contract"))
        self.assertEqual(report.answers[2].kind, "output")

    def test_an_answer_about_another_address_is_never_filed_as_this_one(self):
        report = self.ask(STUB_R2S_MODE="minimal", STUB_R2S_FAULTS="elsewhere@3000")
        self.assertEqual([a.kind for a in report.answers], ["output", "output", "decline",
                                                            "output"])
        self.assertIn("`addr` is 0x3010, not the 0x3000 asked for", report.answers[2].cause)

    def test_a_refusal_keeps_its_reason(self):
        report = self.ask(STUB_R2S_MODE="refuse", STUB_R2S_FAULTS="")
        self.assertTrue(all(a.kind == "decline" for a in report.answers))
        self.assertEqual(report.answers[0].cause, "refused: stub refuses")


class ContractTests(unittest.TestCase):
    def test_a_rendering_carries_every_field(self):
        record = selftest.synthetic_pddj(selftest.CASES[0], 0x1000, {})
        self.assertEqual(contract_problems(record), [])
        del record["links"]
        record["proof"]["residual"] = "1"
        problems = contract_problems(record)
        self.assertIn("no `links`", problems)
        self.assertIn("proof.residual is not a count", problems)

    def test_an_answer_about_another_address_is_a_breach(self):
        record = selftest.synthetic_pddj(selftest.CASES[0], 0x1000, {})
        self.assertEqual(contract_problems(record, 0x1000), [])
        self.assertEqual(contract_problems(record, 0x2000),
                         ["`addr` is 0x1000, not the 0x2000 asked for"])

    def test_lines_and_variables_are_checked_entry_by_entry(self):
        record = selftest.synthetic_pddj(selftest.CASES[0], 0x1000, {})
        lines_in_code = len(record["code"].splitlines())
        record["lines"] = [{"line": lines_in_code, "addrs": [0x1000]}]
        record["variables"] = [{"name": "a", "type": "int32_t", "kind": "param",
                                "location": "rdi"}]
        self.assertEqual(contract_problems(record), [])
        for bad in ({"line": 0, "addrs": []}, {"line": lines_in_code + 1, "addrs": []},
                    {"line": 1, "addrs": ["0x1000"]}, {"line": "1", "addrs": []}, 7):
            record["lines"] = [bad]
            self.assertEqual(len(contract_problems(record)), 1, bad)
        record["lines"] = []
        for bad in ({"name": "a", "type": "int", "kind": "arg", "location": "rdi"},
                    {"name": "a", "kind": "local", "location": "stack-8"}, "a"):
            record["variables"] = [bad]
            self.assertEqual(len(contract_problems(record)), 1, bad)

    def test_a_refusal_needs_only_its_identity(self):
        self.assertEqual(
            contract_problems({"name": "f", "addr": 16, "refused": {"reason": "why"}}), []
        )


class AnswerStatusTests(unittest.TestCase):
    """Which status an answer that is not a rendering becomes, before anything runs."""

    SPEC = CallSpec(name="f", address=0x1000, params=[], ret_kind="int", ret_bytes=4,
                    ret_spelling="int")

    def status(self, answer):
        return gate.grade("k", Path("/nonexistent"), Path("/nonexistent"), None, self.SPEC,
                          answer, gate.Config(runtime=Path("/nonexistent")))

    def test_a_refusal_that_keeps_the_contract_is_refused(self):
        body = json.dumps({"name": "f", "addr": 0x1000, "refused": {"reason": "P4"}})
        record = self.status(parse_pddj(0x1000, body))
        self.assertEqual((record.status, record.evidence["cause"]), ("refused", "refused: P4"))

    def test_a_refusal_that_breaks_the_contract_is_no_record(self):
        body = json.dumps({"name": "f", "addr": 0x1000, "refused": {"reason": "P4"},
                           "links": "none"})
        record = self.status(parse_pddj(0x1000, body))
        self.assertEqual(record.status, "no-record")
        self.assertIn("breaks its contract", record.evidence["cause"])
        self.assertIn("no-record", gate.ENGINE_STATUSES)

    def test_an_address_never_asked_is_the_harness_s(self):
        self.assertEqual(self.status(None).status, "harness-error")


class RatchetTests(unittest.TestCase):
    BASELINE = {
        "schema": 1,
        "records": {
            "a::gcc-O0::f": {"status": "equal"},
            "a::gcc-O0::g": {"status": "differs", "cause": "D9: printf arguments dropped"},
            "a::gcc-O0::h": {"status": "refused", "cause": "P4: -O0 switch"},
        },
    }

    def test_holding_the_baseline_is_clean(self):
        now = {"a::gcc-O0::f": "equal", "a::gcc-O0::g": "differs", "a::gcc-O0::h": "equal"}
        self.assertEqual(gate.ratchet(self.BASELINE, now), [])

    def test_leaving_equal_blocks(self):
        now = {"a::gcc-O0::f": "residual-trap", "a::gcc-O0::g": "differs",
               "a::gcc-O0::h": "refused"}
        self.assertEqual(gate.ratchet(self.BASELINE, now),
                         ["a::gcc-O0::f: left equal (now residual-trap)"])

    def test_a_new_finding_blocks_even_where_nothing_was_equal(self):
        now = {"a::gcc-O0::f": "equal", "a::gcc-O0::g": "differs", "a::gcc-O0::h": "uninit",
               "a::gcc-O0::new": "ub"}
        problems = gate.ratchet(self.BASELINE, now)
        self.assertIn("a::gcc-O0::h: new uninit (baseline: refused)", problems)
        self.assertIn("a::gcc-O0::new: new ub (baseline: absent)", problems)

    def test_a_function_that_disappears_blocks(self):
        now = {"a::gcc-O0::g": "differs", "a::gcc-O0::h": "refused"}
        self.assertEqual(gate.ratchet(self.BASELINE, now),
                         ["a::gcc-O0::f: in the baseline but not graded by this run"])
        # Unless the run was restricted to other functions.
        self.assertEqual(gate.ratchet(self.BASELINE, now, {"a::gcc-O0::g", "a::gcc-O0::h"}), [])

    def test_a_standing_failure_needs_a_cause(self):
        baseline = json.loads(json.dumps(self.BASELINE))
        del baseline["records"]["a::gcc-O0::g"]["cause"]
        now = {"a::gcc-O0::f": "equal", "a::gcc-O0::g": "differs", "a::gcc-O0::h": "refused"}
        self.assertEqual(gate.ratchet(baseline, now),
                         ["a::gcc-O0::g: baseline status differs has no recorded cause"])


class ClassifyTests(unittest.TestCase):
    """How a vector's runs become a status, without running anything."""

    @staticmethod
    def line(index, original="return", o0=None, pairs=None, ubsan=None):
        runs = [{"run": 0, "outcome": original}, {"run": 1, "outcome": "return"},
                o0 or {"run": 2, "outcome": "return"}, {"run": 3, "outcome": "return"},
                {"run": 4, "outcome": "return"}, ubsan or {"run": 5, "outcome": "return"}]
        base = {(0, 1): True, (0, 2): True, (2, 3): True, (2, 4): True}
        base.update(pairs or {})
        return {"vector": index, "runs": runs,
                "pairs": [{"a": a, "b": b, "equal": eq, **({} if eq else {"field": "return"})}
                          for (a, b), eq in base.items()]}

    def test_outside_the_domain_is_dropped_and_nothing_left_is_untested(self):
        status, evidence, counts = gate.classify([self.line(0, original="signal")], [], 0,
                                                self.NONE)
        self.assertEqual((status, counts["dropped"]), ("untested", 1))
        self.assertIn("survived", evidence["cause"])

    def test_an_original_that_disagrees_with_itself_grades_nothing(self):
        status, _, counts = gate.classify([self.line(0, pairs={(0, 1): False})], [], 0,
                                       self.NONE)
        self.assertEqual((status, counts["unstable"]), ("untested", 1))

    HELPERS = gate.ResidualHelpers("/x/O0.so", [(0x1100, 0x1120, "r2sleigh_residual_s32")])
    NONE = gate.ResidualHelpers("", [])

    def test_a_trap_is_a_residual_only_inside_a_helper_where_one_was_counted(self):
        def trap(pc, where="/x/O0.so"):
            return {"run": 2, "outcome": "signal", "status": 4, "fault_object": where,
                    "fault_pc": hex(0x7F0000000000 + pc), "fault_base": "0x7f0000000000"}

        def status(o0, residual=1, helpers=self.HELPERS):
            line = self.line(0, o0=o0, pairs={(0, 2): False})
            return gate.classify([line], [], residual, helpers)[0]

        self.assertEqual(status(trap(0x1108)), "residual-trap")
        self.assertEqual(status(trap(0x1108), residual=0), "differs")
        self.assertEqual(status(trap(0x1108, "/y/O0.so")), "differs")
        self.assertEqual(status(trap(0x1120)), "differs")  # past the helper's end
        self.assertEqual(status({**trap(0x1108), "status": 11}), "differs")  # SIGSEGV

    def test_a_build_that_runs_out_of_time_is_slow_not_undefined_or_wrong(self):
        timeout = {"run": 2, "outcome": "timeout"}
        o0_late = self.line(0, o0=timeout, pairs={(0, 2): False, (2, 3): False, (2, 4): False})
        self.assertEqual(gate.classify([o0_late], [], 0, self.NONE)[0], "slow")
        o2_late = self.line(0, pairs={(2, 4): False})
        o2_late["runs"][4] = {"run": 4, "outcome": "timeout"}
        self.assertEqual(gate.classify([o2_late], [], 0, self.NONE)[0], "slow")
        # Both builds finished and still disagree: that stays undefined behaviour.
        disagree = self.line(0, pairs={(2, 4): False})
        self.assertEqual(gate.classify([disagree], [], 0, self.NONE)[0], "ub")
        self.assertNotIn("slow", gate.BLOCKING)

    def test_an_equal_needs_its_floor_of_graded_vectors_and_a_defect_does_not(self):
        lines = [self.line(0), self.line(1, original="signal"), self.line(2, original="signal")]
        status, evidence, counts = gate.classify(lines, [], 0, self.NONE, min_graded=2)
        self.assertEqual((status, counts["graded"]), ("untested", 1))
        self.assertIn("only 1 of 3 vectors", evidence["cause"])
        self.assertEqual(gate.classify(lines, [], 0, self.NONE, min_graded=1)[0], "equal")
        lines[0] = self.line(0, pairs={(0, 2): False})
        self.assertEqual(gate.classify(lines, [], 0, self.NONE, min_graded=2)[0], "differs")

    def test_a_vector_whose_rendering_run_was_not_made_grades_nothing(self):
        line = self.line(0)
        line["runs"][2] = {"run": 2, "outcome": "unavailable", "error": "fork: EAGAIN"}
        line["pairs"] = [p for p in line["pairs"] if p["b"] != 2 and p["a"] != 2]
        status, evidence, counts = gate.classify([line, self.line(1)], [], 0, self.NONE)
        self.assertEqual((status, counts["incomplete"], counts["graded"]),
                         ("harness-error", 1, 1))
        self.assertEqual(evidence["not_compared"], ["original-O0", "O0-pattern", "O0-O2"])
        found = self.line(1, pairs={(0, 2): False})
        self.assertEqual(gate.classify([line, found], [], 0, self.NONE)[0], "differs")

    def test_the_worst_vector_decides(self):
        lines = [self.line(0), self.line(1, pairs={(0, 2): False}),
                 self.line(2, pairs={(2, 3): False}),
                 self.line(3, ubsan={"run": 5, "outcome": "exit-raw",
                                     "stderr": "x.c:1: runtime error: signed integer overflow"})]
        status, evidence, counts = gate.classify(lines, [], 0, self.NONE)
        self.assertEqual(status, "ub")
        self.assertEqual(evidence["vector"], 3)
        self.assertEqual((counts["equal"], counts["differs"], counts["uninit"], counts["ub"]),
                         (1, 1, 1, 1))


@unittest.skipUnless(CAN_RUN, "runtime equivalence needs x86-64 Linux and gcc")
class CompilerVerdictTests(unittest.TestCase):
    def test_a_compiler_that_gives_no_verdict_is_the_harness_s_failure(self):
        # A compiler that hangs on the rendering (as gcc did for 120 s on a
        # loaded machine) must not be charged to the engine as compile-error.
        with tempfile.TemporaryDirectory() as tmp_text:
            tmp = Path(tmp_text)
            slow = tmp / "slow-cc"
            slow.write_text("#!/bin/sh\ncase \"$*\" in *rendering.c*) sleep 30;; esac\n"
                            "exec gcc \"$@\"\n")
            slow.chmod(0o755)
            binary = selftest.build_fixture("gcc", tmp)
            dwarf = Dwarf.read(binary)
            functions = [s for s in dwarf.subprograms() if s.name]
            sub = next(s for s in functions if s.name == "st_add")
            spec = call_spec(dwarf, sub, functions)
            case = next(c for c in selftest.CASES if c.name == "identity-int")
            answer = parse_pddj(sub.low_pc,
                                json.dumps(selftest.synthetic_pddj(case, sub.low_pc, {})))
            config = gate.Config(runtime=tmp / "unused", cc=str(slow), compile_timeout=1.0)
            started = time.monotonic()
            record = gate.grade("k", tmp / "work", binary, dwarf, spec, answer, config)
            self.assertLess(time.monotonic() - started, 20.0)
            self.assertEqual(record.status, "harness-error")
            self.assertIn("timed out after 1s", record.evidence["diagnostics"])
            refused = link.build_rendering("gcc", tmp / "bad", "int f(void) { return x; }\n",
                                           [], "f")[0]
            self.assertEqual({b.ran for b in refused.values()}, {True})
            self.assertEqual({b.ok for b in refused.values()}, {False})


@unittest.skipUnless(CAN_RUN, "runtime equivalence needs x86-64 Linux and gcc")
class BuildTests(unittest.TestCase):
    def test_the_shown_copy_has_a_directory_of_its_own_with_nothing_else_in_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = build.build(HERE / "selftest" / "fixture.c", "gcc", "O0", Path(tmp))
            self.assertIsNone(binary.error)
            self.assertNotEqual(binary.stripped.parent, binary.unstripped.parent)
            self.assertEqual(binary.stripped.name, binary.unstripped.name)
            self.assertEqual(sorted(p.name for p in binary.stripped.parent.iterdir()),
                             [binary.stripped.name])
            sections = subprocess.run(["readelf", "-SW", str(binary.stripped)],
                                      capture_output=True, text=True, check=True).stdout
            self.assertNotIn(".symtab", sections)
            self.assertNotIn(".debug_", sections)


@unittest.skipUnless(CAN_RUN, "runtime equivalence needs x86-64 Linux and gcc")
class DwarfTests(unittest.TestCase):
    def test_the_fixture_signatures_read_back_as_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = selftest.build_fixture("gcc", Path(tmp))
            dwarf = Dwarf.read(binary)
            functions = [s for s in dwarf.subprograms() if s.name]
            specs = {s.name: call_spec(dwarf, s, functions) for s in functions}
        self.assertEqual(specs["st_add"].describe(), "int st_add(int a@rdi, int b@rsi)")
        self.assertEqual((specs["st_mix"].ret_kind, specs["st_mix"].ret_bytes), ("int", 8))
        self.assertEqual(specs["st_scale"].ret_kind, "f64")
        self.assertEqual(specs["st_sum_list"].params[0].pointee.shape, "struct")
        self.assertEqual(specs["st_len"].params[0].pointee.shape, "string")
        many = specs["st_many"].params
        self.assertEqual([p.register for p in many[5:]], ["r9", "stack0", "stack1"])
        self.assertEqual(specs["st_many_fp"].params[-1].register, "stack0")


@unittest.skipUnless(CAN_RUN, "runtime equivalence needs x86-64 Linux and gcc")
class SelfTestSuite(unittest.TestCase):
    """The gate's precondition: every known verdict comes back."""

    def test_every_case_gets_its_known_verdict(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = link.build_runtime("gcc", HERE / "rt", Path(tmp) / "rt")
            config = gate.Config(runtime=runtime)
            outcomes = selftest.run_self_tests(config, Path(tmp) / "selftest")
        misses = [f"{o.case.name}: {o.why}" for o in outcomes if not o.ok]
        self.assertEqual(misses, [])
        self.assertEqual(len(outcomes), len(selftest.CASES))


@unittest.skipUnless(CAN_RUN, "runtime equivalence needs x86-64 Linux and gcc")
class PipelineTests(unittest.TestCase):
    """The whole gate over the self-test fixture, with r2s replaced by the stub.

    Built with GCC at -O0 and -O2 and stripped, asked through the batch runner,
    compiled, linked, run and compared: the self-test renderings keep their
    known verdicts end to end, and a rendering that hands its work back to the
    original is never equal.
    """

    FUNCTIONS = 18  # seventeen functions and main, per level

    def run_gate(self, tmp: Path, *extra: str, **env: str) -> tuple[int, dict]:
        # --out is given relative to the working directory, as a person types
        # it: the runtime runs elsewhere and must be handed absolute paths.
        tmp.mkdir(parents=True, exist_ok=True)
        argv = ["--r2s", str(STUB), "--sources", str(HERE / "selftest" / "fixture.c"),
                "--compilers", "gcc", "--opts", "O0,O2", "--out", "out", "--vectors", "24",
                *extra]
        cwd = os.getcwd()
        os.chdir(tmp)
        try:
            with _StubEnv(**env):
                code = run_equiv.main(argv)
        finally:
            os.chdir(cwd)
        records = json.loads((tmp / "out" / "records.json").read_text())["records"]
        return code, {r["key"]: r for r in records}

    @staticmethod
    def known(function: str) -> str:
        case = next((c for c in selftest.CASES
                     if c.function == function and c.expect in ("equal", "residual-trap")), None)
        return case.expect if case else "refused"

    def test_known_renderings_keep_their_verdicts_through_the_whole_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, records = self.run_gate(Path(tmp), STUB_R2S_MODE="fixture",
                                          STUB_R2S_FAULTS="")
        self.assertEqual(code, run_equiv.EXIT_OK)
        self.assertEqual(len(records), 2 * self.FUNCTIONS)
        got = {k: r["status"] for k, r in records.items()}
        want = {k: self.known(k.rsplit("::", 1)[1]) for k in records}
        self.assertEqual(got, want)
        self.assertEqual(sum(s == "equal" for s in got.values()), 2 * 15)

    def test_a_rendering_that_delegates_to_the_original_is_never_equal(self):
        # The stub's delegate calls the original's entry by its address, a
        # rendering equal to the original by construction if the original
        # still ran: every function, main included, must come out differs.
        with tempfile.TemporaryDirectory() as tmp:
            _, records = self.run_gate(Path(tmp), STUB_R2S_MODE="delegate", STUB_R2S_FAULTS="")
        self.assertEqual(len(records), 2 * self.FUNCTIONS)
        self.assertEqual({r["status"] for r in records.values()}, {"differs"})
        self.assertEqual({r["evidence"].get("guard") for r in records.values()}, {"delegated"})

    def test_two_runs_write_the_same_records(self):
        # The delegating renderings' evidence carries whole runs (their
        # faults, their registers): nothing in it may depend on timing or on
        # where the loader put a shared object.
        with tempfile.TemporaryDirectory() as tmp_text:
            tmp = Path(tmp_text)
            written = []
            for _ in range(2):
                self.run_gate(tmp, "--opts", "O2", STUB_R2S_MODE="delegate", STUB_R2S_FAULTS="")
                written.append((tmp / "out" / "records.json").read_bytes())
        self.assertEqual(written[0], written[1])
        self.assertNotIn(b"elapsed", written[0])

    def test_a_crash_is_one_record_and_the_ratchet_sees_it(self):
        with tempfile.TemporaryDirectory() as tmp_text:
            tmp = Path(tmp_text)
            code, first = self.run_gate(tmp / "first", "--opts", "O2", STUB_R2S_MODE="fixture",
                                        STUB_R2S_FAULTS="")
            clamp = next(r for k, r in first.items() if k.endswith("gcc-O2::st_clamp"))
            baseline = tmp / "baseline.json"
            baseline.write_text(json.dumps({"schema": 1, "records": {
                k: {"status": r["status"], "cause": "known" if r["status"] != "equal" else None}
                for k, r in first.items()}}))
            code, records = self.run_gate(
                tmp / "second", "--opts", "O2", "--baseline", str(baseline),
                STUB_R2S_MODE="fixture", STUB_R2S_FAULTS=f"abort@{clamp['address'][2:]}")
        self.assertEqual(code, run_equiv.EXIT_RATCHET)
        crashed = records[clamp["key"]]
        self.assertEqual(crashed["status"], "no-record")
        self.assertIn("SIGABRT", crashed["evidence"]["cause"])
        self.assertEqual({k: r["status"] for k, r in records.items() if k != clamp["key"]},
                         {k: r["status"] for k, r in first.items() if k != clamp["key"]})


if __name__ == "__main__":
    unittest.main()
