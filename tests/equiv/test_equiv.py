#!/usr/bin/env python3
"""Tests of the equivalence gate itself.

    python3 -m unittest discover -s tests/equiv -p 'test_*.py'

The self-test suite is the gate's precondition and runs here too; the rest pins
the parts a gate run cannot check on itself: that r2s's every failure mode ends
as exactly one typed answer per address, that the ratchet blocks what it must,
and that the whole pipeline -- build, strip, capture, compile, run, compare --
grades a rendering that *is* the original as ``equal`` for every function of a
real program at every level.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import gate  # noqa: E402
import link  # noqa: E402
import run_equiv  # noqa: E402
import selftest  # noqa: E402
from dwarf import Dwarf  # noqa: E402
from r2s_batch import contract_problems, run_batch  # noqa: E402
from spec import call_spec  # noqa: E402

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

    def test_a_refusal_needs_only_its_identity(self):
        self.assertEqual(
            contract_problems({"name": "f", "addr": 16, "refused": {"reason": "why"}}), []
        )


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
        status, evidence, counts = gate.classify([self.line(0, original="signal")], [], 0, "")
        self.assertEqual((status, counts["dropped"]), ("untested", 1))
        self.assertIn("survived", evidence["cause"])

    def test_an_original_that_disagrees_with_itself_grades_nothing(self):
        status, _, counts = gate.classify([self.line(0, pairs={(0, 1): False})], [], 0, "")
        self.assertEqual((status, counts["unstable"]), ("untested", 1))

    def test_a_trap_is_a_residual_only_where_one_was_counted(self):
        trap = {"run": 2, "outcome": "signal", "status": 4, "fault_object": "/x/O0.so"}
        line = self.line(0, o0=trap, pairs={(0, 2): False})
        self.assertEqual(gate.classify([line], [], 1, "/x/O0.so")[0], "residual-trap")
        self.assertEqual(gate.classify([line], [], 0, "/x/O0.so")[0], "differs")
        self.assertEqual(gate.classify([line], [], 1, "/y/O0.so")[0], "differs")

    def test_the_worst_vector_decides(self):
        lines = [self.line(0), self.line(1, pairs={(0, 2): False}),
                 self.line(2, pairs={(2, 3): False}),
                 self.line(3, ubsan={"run": 5, "outcome": "exit-raw",
                                     "stderr": "x.c:1: runtime error: signed integer overflow"})]
        status, evidence, counts = gate.classify(lines, [], 0, "")
        self.assertEqual(status, "ub")
        self.assertEqual(evidence["vector"], 3)
        self.assertEqual((counts["equal"], counts["differs"], counts["uninit"], counts["ub"]),
                         (1, 1, 1, 1))


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
    """The whole gate, with r2s replaced by a stub whose renderings are the original."""

    def run_gate(self, tmp: Path, *extra: str, **env: str) -> tuple[int, dict]:
        argv = ["--r2s", str(STUB), "--sources", str(HERE / "selftest" / "fixture.c"),
                "--compilers", "gcc", "--opts", "O0,O2", "--out", str(tmp), "--vectors", "24",
                *extra]
        with _StubEnv(**env):
            code = run_equiv.main(argv)
        records = json.loads((tmp / "records.json").read_text())["records"]
        return code, {r["key"]: r for r in records}

    def test_a_rendering_that_is_the_original_is_equal_everywhere(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, records = self.run_gate(Path(tmp), STUB_R2S_MODE="delegate",
                                          STUB_R2S_FAULTS="")
        self.assertEqual(code, run_equiv.EXIT_OK)
        self.assertEqual({r["status"] for r in records.values()}, {"equal"})
        self.assertEqual(len(records), 2 * 14)  # thirteen functions and main, at two levels

    def test_a_crash_is_one_record_and_the_ratchet_sees_it(self):
        with tempfile.TemporaryDirectory() as tmp_text:
            tmp = Path(tmp_text)
            code, records = self.run_gate(tmp / "first", STUB_R2S_MODE="delegate",
                                          STUB_R2S_FAULTS="")
            clamp = next(r for k, r in records.items() if k.endswith("gcc-O2::st_clamp"))
            baseline = tmp / "baseline.json"
            baseline.write_text(json.dumps(
                {"schema": 1, "records": {k: {"status": "equal"} for k in records}}))
            # Only -O2 is asked again: the address names one function of one build.
            code, records = self.run_gate(
                tmp / "second", "--opts", "O2", "--baseline", str(baseline),
                STUB_R2S_MODE="delegate", STUB_R2S_FAULTS=f"abort@{clamp['address'][2:]}")
        self.assertEqual(code, run_equiv.EXIT_RATCHET)
        crashed = records[clamp["key"]]
        self.assertEqual(crashed["status"], "no-record")
        self.assertIn("SIGABRT", crashed["evidence"]["cause"])
        others = {r["status"] for k, r in records.items() if k != clamp["key"]}
        self.assertEqual(others, {"equal"})


if __name__ == "__main__":
    unittest.main()
