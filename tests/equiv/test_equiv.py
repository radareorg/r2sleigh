#!/usr/bin/env python3
"""Tests of the equivalence gate itself.

    python3 -m unittest discover -s tests/equiv -p 'test_*.py'

The self-test suite is the gate's precondition and runs here too; the rest pins
the parts a gate run cannot check on itself: that r2s's every failure mode ends
as exactly one typed answer per address, that the ratchet blocks what it must,
and that the whole pipeline -- build, strip, capture, compile, run, compare --
keeps every known rendering's verdict at every level, and never grades a
rendering that hands its work back to the original as ``equal``.

The classes that build and run are written once over a target
(``target.py``): x86-64 where the host is x86-64 Linux, and AArch64 where its
cross compiler (and, to run, qemu-user) is installed. A class whose target
cannot run here is skipped with the reason.
"""

from __future__ import annotations

import dataclasses
import errno
import json
import os
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import build  # noqa: E402
import cost  # noqa: E402
import gate  # noqa: E402
import merge_shards  # noqa: E402
import link  # noqa: E402
import run_equiv  # noqa: E402
import selftest  # noqa: E402
from dwarf import (  # noqa: E402
    DISCARDED, NO_FUNC_START, RELOCATABLE, TYPE_UNIT, UNRESOLVED, Die, Dwarf, code_addresses, function_symbols, loaded_code,
    parse_ranges, parse_readelf,
)
from r2s_batch import contract_problems, parse_pddj, run_batch  # noqa: E402
from spec import CallSpec, call_spec  # noqa: E402
from target import AARCH64, WIN64, X86_64, Target  # noqa: E402
from vectors import JOB_MAGIC, Run, Vector, encode_job  # noqa: E402

STUB = HERE / "testdata" / "stub_r2s.py"
CAN_RUN = gate.environment_problem() is None and shutil.which("gcc") is not None
# Building for AArch64 needs only its cross compiler; running needs qemu-user too.
CAN_BUILD_AARCH64 = (Path("/proc/self/exe").exists()
                     and shutil.which(AARCH64.rendering_cc) is not None)
CAN_RUN_AARCH64 = AARCH64.environment_problem() is None
# Win64 needs x86-64 Linux, clang, lld-link, llvm-strip and an xwin sysroot ($EQUIV_XWIN).
CAN_RUN_WIN64 = WIN64.environment_problem() is None
_WIN64_RUN = f"Win64 runtime equivalence: {WIN64.environment_problem()}"


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
            startup: float | None = None, on_answer=None, **env: str):
        with _StubEnv(**env), tempfile.TemporaryDirectory() as state:
            os.environ["STUB_R2S_STATE"] = state
            try:
                return run_batch(STUB, "/bin/true", addresses or self.ADDRESSES,
                                 function_timeout=timeout, startup_timeout=startup,
                                 on_answer=on_answer)
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

    def test_an_answer_is_delivered_while_r2s_is_still_running(self):
        # A consumer that checkpoints from on_answer keeps what a killed run had already given:
        # the answers before a hang arrive before the hang is given up on, not after it.
        seen: list[tuple[int, float]] = []
        started = time.monotonic()
        self.ask(timeout=3.0, addresses=[0x1000, 0x2000, 0x3000], STUB_R2S_MODE="minimal",
                 STUB_R2S_FAULTS="sleep@3000",
                 on_answer=lambda a: seen.append((a.address, time.monotonic())))
        ended = time.monotonic()
        self.assertEqual([address for address, _ in seen], [0x1000, 0x2000, 0x3000])
        self.assertLess(seen[1][1] - started, 2.0)
        self.assertGreater(ended - seen[1][1], 2.0)

    def test_a_failing_consumer_stops_r2s_and_the_batch(self):
        def refuse(answer):
            raise OSError("disk full")

        started = time.monotonic()
        with self.assertRaises(OSError):
            self.ask(timeout=30.0, STUB_R2S_MODE="minimal", STUB_R2S_FAULTS="sleep@2000",
                     on_answer=refuse)
        self.assertLess(time.monotonic() - started, 10.0)

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

    def test_a_failed_survey_declines_every_function_once(self):
        # Without `aa` no rendering reads its callers, so none is graded.
        report = self.ask(STUB_R2S_MODE="aa-fails", STUB_R2S_FAULTS="")
        self.assertEqual(len(report.answers), len(self.ADDRESSES))
        self.assertTrue(all(a.kind == "decline" for a in report.answers))
        self.assertEqual({a.cause for a in report.answers},
                         {"r2s: the program could not be surveyed"})
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

    def test_a_count_is_a_number_that_is_not_a_boolean_or_negative(self):
        record = selftest.synthetic_pddj(selftest.CASES[0], 0x1000, {})
        for bad in (True, False, -1, 1.5, None, "1"):
            record["proof"]["residual"] = bad
            self.assertEqual(contract_problems(record), ["proof.residual is not a count"], bad)
        record["proof"]["residual"] = 0
        self.assertEqual(contract_problems(record), [])

    def test_the_residual_list_is_a_field_of_sites_with_causes(self):
        record = selftest.synthetic_pddj(selftest.CASES[0], 0x1000, {})
        record["residuals"] = [{"site": 1, "type": "u64", "cause": "gap", "gap": "TermNotSpelled", "line": 3}]
        self.assertEqual(contract_problems(record), [])
        del record["residuals"]
        self.assertEqual(contract_problems(record), ["no `residuals`"])
        record["residuals"] = {}
        self.assertEqual(contract_problems(record), ["`residuals` is not list"])
        for bad in ({"cause": "gap"}, {"site": 1}, {"site": "1", "cause": "gap"}, {"site": True, "cause": "gap"},
                    {"site": -1, "cause": "gap"}, {"site": 1, "cause": None}, "gap", 7):
            record["residuals"] = [{"site": 1, "cause": "gap"}, bad]
            self.assertEqual(len(contract_problems(record)), 1, bad)

    def test_the_first_bad_residual_is_the_one_reported(self):
        record = selftest.synthetic_pddj(selftest.CASES[0], 0x1000, {})
        record["residuals"] = [{"site": "a", "cause": 1}, {"site": "b", "cause": 2}]
        self.assertEqual(len(contract_problems(record)), 1)

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
        "schema": 3,
        "cost": {"measure": "time", "budget": 1000},
        "records": {
            "a::gcc-O0::f": {"status": "equal"},
            "a::gcc-O0::g": {"status": "differs", "owner": "P7", "site": "crates/r2dec/src",
                             "cause": "The printf call drops its stack-passed arguments."},
            "a::gcc-O0::h": {"status": "refused", "owner": "P4", "site": "crates/r2ssa/src",
                             "cause": "The -O0 switch table refuses on its unbounded index."},
        },
    }

    def test_holding_the_baseline_is_clean(self):
        now = {"a::gcc-O0::f": "equal", "a::gcc-O0::g": "differs", "a::gcc-O0::h": "refused"}
        self.assertEqual(gate.ratchet(self.BASELINE, now), [])

    def test_any_change_of_status_blocks_until_blessed(self):
        # An improvement the baseline does not hold is one the next change
        # could silently lose; a refusal that stops producing a record at all
        # is the departure this rule was written for.
        now = {"a::gcc-O0::f": "equal", "a::gcc-O0::g": "differs", "a::gcc-O0::h": "equal"}
        self.assertEqual(gate.ratchet(self.BASELINE, now),
                         ["a::gcc-O0::h: refused -> equal; bless it with its cause"])
        now["a::gcc-O0::h"] = "no-record"
        self.assertEqual(gate.ratchet(self.BASELINE, now),
                         ["a::gcc-O0::h: refused -> no-record; bless it with its cause"])

    def test_a_slow_blessed_under_time_is_held_by_slow_or_equal(self):
        # CPU time puts a cost near the allowance on either side by processor (ADR D341).
        baseline = json.loads(json.dumps(self.BASELINE))
        baseline["records"]["a::gcc-O0::s"] = {
            "status": "slow", "reason": "O2", "owner": "GT", "site": "tests/equiv/gate.py",
            "cause": "The -O2 build of the rendering is stopped past its allowance."}
        now = {"a::gcc-O0::f": "equal", "a::gcc-O0::g": "differs", "a::gcc-O0::h": "refused"}
        for graded in (("slow", "O2"), ("slow", "O0"), ("equal", "")):
            now["a::gcc-O0::s"] = graded
            self.assertEqual(gate.ratchet(baseline, now), [], graded)
        now["a::gcc-O0::s"] = ("differs", "rax")
        self.assertEqual(gate.ratchet(baseline, now), ["a::gcc-O0::s: new differs (baseline: slow)"])
        now["a::gcc-O0::s"] = ("residual-trap", "r2sleigh_residual_u64 unproven-return")
        self.assertEqual(gate.ratchet(baseline, now),
                         ["a::gcc-O0::s: slow -> residual-trap; bless it with its cause"])

    def test_an_equal_that_reads_slow_under_time_still_blocks(self):
        now = {"a::gcc-O0::f": ("slow", "O2"), "a::gcc-O0::g": "differs", "a::gcc-O0::h": "refused"}
        self.assertEqual(gate.ratchet(self.BASELINE, now), ["a::gcc-O0::f: left equal (now slow)"])

    def test_a_slow_blessed_under_instructions_is_exact(self):
        baseline = json.loads(json.dumps(self.BASELINE))
        baseline["cost"] = {"measure": "instructions", "budget": 4_000_000_000, "factor": 4}
        baseline["records"]["a::gcc-O0::s"] = {
            "status": "slow", "reason": "O2", "owner": "GT", "site": "tests/equiv/gate.py",
            "cause": "The -O2 build of the rendering is stopped past its allowance."}
        now = {"a::gcc-O0::f": "equal", "a::gcc-O0::g": "differs", "a::gcc-O0::h": "refused",
               "a::gcc-O0::s": ("equal", "")}
        self.assertEqual(gate.ratchet(baseline, now),
                         ["a::gcc-O0::s: slow -> equal; bless it with its cause"])
        now["a::gcc-O0::s"] = ("slow", "O0")
        self.assertIn("still slow, for another reason", gate.ratchet(baseline, now)[0])

    def test_the_same_status_for_another_reason_blocks(self):
        baseline = json.loads(json.dumps(self.BASELINE))
        baseline["records"]["a::gcc-O0::h"]["reason"] = "refused: observation journal: ConflictingWrite"
        now = {"a::gcc-O0::f": "equal", "a::gcc-O0::g": "differs",
               "a::gcc-O0::h": ("refused", "refused: observation journal: ConflictingWrite")}
        self.assertEqual(gate.ratchet(baseline, now), [])
        now["a::gcc-O0::h"] = ("refused", "refused: observation journal: ConflictingValue")
        problems = gate.ratchet(baseline, now)
        self.assertEqual(len(problems), 1)
        self.assertIn("still refused, for another reason", problems[0])

    def test_a_function_the_baseline_does_not_know_must_be_blessed(self):
        now = {"a::gcc-O0::f": "equal", "a::gcc-O0::g": "differs", "a::gcc-O0::h": "refused",
               "a::gcc-O0::new": "equal"}
        self.assertEqual(gate.ratchet(self.BASELINE, now),
                         ["a::gcc-O0::new: not in the baseline (now equal); bless it"])

    def test_a_reason_names_the_cause_and_not_where_it_landed(self):
        one = gate.reason("refused", {"cause": "r2sleigh refused fcn.401a50: missing (lowering.rs:253)"})
        two = gate.reason("refused", {"cause": "r2sleigh refused fcn.4015d0: missing (lowering.rs:261)"})
        self.assertEqual(one, two)
        self.assertEqual(gate.reason("differs", {"field": "return", "a_bytes": "00"}), "return")
        self.assertEqual(gate.reason("equal", {}), "")

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

    def test_a_cause_that_describes_nothing_blocks(self):
        # Audit T20: a placeholder, an owner the plan does not name, or a site
        # that is no path in the repository is no recorded cause.
        now = {"a::gcc-O0::f": "equal", "a::gcc-O0::g": "differs", "a::gcc-O0::h": "refused"}
        for change, problem in (
                ({"cause": "[r2dec render gap] A counted residual is reached; not yet triaged "
                           "per function."}, "has a placeholder cause"),
                ({"cause": "known"}, "has a placeholder cause"),
                ({"owner": "#122"}, "names an owner that is no ROADMAP.md item: '#122'"),
                ({"owner": None}, "names an owner that is no ROADMAP.md item: None"),
                ({"site": "crates/r2dec/src/fold/op_lower"}, "names a site that is no path"),
                ({"site": "../elsewhere"}, "names a site that is no path")):
            baseline = json.loads(json.dumps(self.BASELINE))
            baseline["records"]["a::gcc-O0::g"].update(change)
            problems = gate.ratchet(baseline, now)
            self.assertEqual(len(problems), 1, (change, problems))
            self.assertIn(problem, problems[0])

    def test_owners_are_the_items_the_roadmap_names(self):
        items = gate.roadmap_items()
        self.assertTrue({"GT", "P7", "PE", "LS"} <= items, items)
        self.assertNotIn("D30", items)

    def test_a_residual_trap_compares_what_it_compared_before(self):
        # Audit T1: a record cannot silently go back to comparing nothing.
        baseline = json.loads(json.dumps(self.BASELINE))
        baseline["records"]["a::gcc-O0::g"].update(
            status="residual-trap", reason="r2sleigh_residual_u64 unproven-return",
            compared="memory")
        trap = ("residual-trap", "r2sleigh_residual_u64 unproven-return")
        now = {"a::gcc-O0::f": "equal", "a::gcc-O0::g": (*trap, "memory"),
               "a::gcc-O0::h": "refused"}
        self.assertEqual(gate.ratchet(baseline, now), [])
        now["a::gcc-O0::g"] = (*trap, "output")
        self.assertEqual(gate.ratchet(baseline, now),
                         ["a::gcc-O0::g: compares output before its residual traps "
                          "(baseline: memory)"])
        del baseline["records"]["a::gcc-O0::g"]["compared"]
        self.assertIn("(baseline: None)", gate.ratchet(baseline, now)[0])

    def test_a_record_holds_the_least_any_trapping_vector_compared(self):
        def compared(trap_compared, trap_memory):
            counts = {"residual-trap": 3, "trap_compared": trap_compared,
                      "trap_memory": trap_memory}
            return gate.trap_comparison("residual-trap", counts)
        self.assertEqual(compared(3, 3), "memory")
        self.assertEqual(compared(3, 2), "output")
        self.assertEqual(compared(2, 2), "none")

    def test_a_bless_under_time_keeps_a_slow_entry_a_processor_reads_equal(self):
        previous = json.loads(json.dumps(self.BASELINE))
        blessed = {"status": "slow", "reason": "O2", "owner": "GT", "site": "tests/equiv/gate.py",
                   "cause": "The -O2 build of the rendering is stopped past its allowance."}
        previous["records"]["a::gcc-O0::f"] = dict(blessed)
        for record in (gate.Record("a::gcc-O0::f", "f", 0, "equal"),
                       gate.Record("a::gcc-O0::f", "f", 0, "slow", evidence={"build": "O0"})):
            self.assertEqual(gate.baseline_from([record], previous)["records"]["a::gcc-O0::f"],
                             blessed)
        previous["cost"] = {"measure": "instructions", "budget": 4_000_000_000, "factor": 4}
        entry = gate.baseline_from([gate.Record("a::gcc-O0::f", "f", 0, "equal")], previous)
        self.assertEqual(entry["records"]["a::gcc-O0::f"], {"status": "equal"})

    def test_a_bless_keeps_a_cause_only_for_the_same_reason(self):
        trap = gate.Record("a::gcc-O0::g", "g", 0, "residual-trap",
                           evidence={"helper": "r2sleigh_residual_u64",
                                     "residual_cause": "unproven-return"},
                           vectors={"residual-trap": 3, "trap_compared": 3, "trap_memory": 3})
        previous = json.loads(json.dumps(self.BASELINE))
        previous["records"]["a::gcc-O0::g"].update(
            status="residual-trap", reason="r2sleigh_residual_u64 unproven-return")
        entry = gate.baseline_from([trap], previous)["records"]["a::gcc-O0::g"]
        self.assertEqual((entry["owner"], entry["site"], entry["compared"]),
                         ("P7", "crates/r2dec/src", "memory"))
        trap.evidence["residual_cause"] = "gap:TermNotSpelled"
        entry = gate.baseline_from([trap], previous)["records"]["a::gcc-O0::g"]
        self.assertEqual((entry["cause"], entry["owner"], entry["site"], entry["reason"]),
                         (None, None, None, "r2sleigh_residual_u64 gap:TermNotSpelled"))


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

    def test_renderings_that_exhaust_their_stack_are_not_graded_on_that_vector(self):
        def fault(run, stack):
            return {"run": run, "outcome": "signal", "status": 11, "fault_addr": "0x400000000fe0",
                    **({"stack": True} if stack else {})}

        def deep(o0=True, o2=True):
            line = self.line(0, o0=fault(2, o0), pairs={(0, 2): False})
            line["runs"][4] = fault(4, o2)
            return line

        status, _, counts = gate.classify([deep(), self.line(1)], [], 0, self.NONE)
        self.assertEqual((status, counts["stack"], counts["graded"], counts["differs"]),
                         ("equal", 1, 1, 0))
        # A fault elsewhere than at the stack pointer, or in one build only, is graded.
        self.assertEqual(gate.classify([deep(o0=False)], [], 0, self.NONE)[0], "differs")
        self.assertEqual(gate.classify([deep(o2=False)], [], 0, self.NONE)[0], "differs")

    HELPERS = gate.ResidualHelpers("/x/O0.so", [(0x1100, 0x1120, "r2sleigh_residual_s32")])
    NONE = gate.ResidualHelpers("", [])

    def test_a_trap_is_a_residual_only_inside_a_helper_where_one_was_counted(self):
        def trap(pc, where="/x/O0.so"):
            return {"run": 2, "outcome": "signal", "status": 4, "fault_object": where,
                    "fault_pc": hex(0x7F0000000000 + pc), "fault_base": "0x7f0000000000"}

        def status(o0, residual=1, helpers=self.HELPERS):
            line = self.line(0, o0=o0, pairs={(0, 2): False})
            line["pairs"][1]["pre_trap"] = {"stdout": True, "stderr": True, "memory": True}
            return gate.classify([line], [], residual, helpers)[0]

        self.assertEqual(status(trap(0x1108)), "residual-trap")
        self.assertEqual(status(trap(0x1108), residual=0), "differs")
        self.assertEqual(status(trap(0x1108, "/y/O0.so")), "differs")
        self.assertEqual(status(trap(0x1120)), "differs")  # past the helper's end
        self.assertEqual(status({**trap(0x1108), "status": 11}), "differs")  # SIGSEGV

    SITES = gate.residual_sites([
        {"site": 1, "type": "s32", "cause": "unproven-return", "gap": None, "line": 4},
        {"site": 2, "type": "s32", "cause": "gap", "gap": "TermNotSpelled", "line": 6}])

    def trapped(self, index, site=1, depth="outermost", original="return", snapshot=True,
                **pre_trap):
        """A vector whose -O0 run trapped in a residual helper at ``site``."""
        o0 = {"run": 2, "outcome": "signal", "status": 4, "fault_object": "/x/O0.so",
              "fault_pc": hex(0x7F0000001108), "fault_base": "0x7f0000000000",
              "trap_site": site, "trap_depth": depth}
        line = self.line(index, original=original, o0=o0, pairs={(0, 2): False})
        primary = next(p for p in line["pairs"] if (p["a"], p["b"]) == (0, 2))
        primary["field"] = "exit"
        if snapshot:
            primary["pre_trap"] = {"stdout": True, "stderr": True, "memory": True, **pre_trap}
        return line

    def grade_traps(self, *lines, min_graded=1):
        return gate.classify(list(lines), [], 1, self.HELPERS, min_graded, self.SITES)

    WRONG_GLOBAL = {"memory": False, "field": "memory", "address": "0x404028",
                    "a_bytes": "0e", "b_bytes": "0d"}

    def test_state_before_a_returned_residual_is_the_original_s_end(self):
        status, evidence, counts = self.grade_traps(self.trapped(0, **self.WRONG_GLOBAL))
        self.assertEqual((status, evidence["field"], evidence["address"]),
                         ("differs", "memory", "0x404028"))
        self.assertEqual(gate.reason(status, evidence), "state before the residual trap memory")
        status, evidence, counts = self.grade_traps(self.trapped(0), self.trapped(1))
        self.assertEqual((status, counts["compared"], counts["trap_memory"]),
                         ("residual-trap", 2, 2))
        self.assertEqual(gate.reason(status, evidence), "r2sleigh_residual_s32 unproven-return")
        self.assertEqual(gate.trap_comparison(status, counts), "memory")

    def test_memory_is_compared_only_where_the_trap_is_the_original_s_end(self):
        # A residual inside the body, one in an inner activation, one whose
        # depth the runtime could not tell, and one where the original exited.
        for line in (self.trapped(0, site=2, **self.WRONG_GLOBAL),
                     self.trapped(0, site=7, **self.WRONG_GLOBAL),
                     self.trapped(0, depth="nested", **self.WRONG_GLOBAL),
                     self.trapped(0, depth="unknown", **self.WRONG_GLOBAL),
                     self.trapped(0, original="exit", **self.WRONG_GLOBAL)):
            status, _, counts = self.grade_traps(line)
            self.assertEqual((status, counts["trap_compared"], counts["trap_memory"]),
                             ("residual-trap", 1, 0), line)
            self.assertEqual(gate.trap_comparison(status, counts), "output")
        _, evidence, _ = self.grade_traps(self.trapped(0, site=2))
        self.assertEqual(gate.reason("residual-trap", evidence),
                         "r2sleigh_residual_s32 gap:TermNotSpelled")

    def test_output_before_any_residual_is_a_prefix_of_the_original_s(self):
        for stream in ("stdout", "stderr"):
            status, evidence, _ = self.grade_traps(self.trapped(0, site=2, **{stream: False}))
            self.assertEqual((status, evidence["field"]), ("differs", stream))

    def test_a_defect_only_where_it_traps_is_found(self):
        status, evidence, counts = self.grade_traps(
            self.line(0), self.line(1), self.trapped(2, **self.WRONG_GLOBAL))
        self.assertEqual((status, evidence["vector"], counts["equal"]), ("differs", 2, 2))

    def test_a_trap_with_no_state_to_compare_rests_on_nothing(self):
        status, evidence, counts = self.grade_traps(self.trapped(0, snapshot=False),
                                                    self.trapped(1, snapshot=False))
        self.assertEqual((status, counts["graded"], counts["compared"]), ("untested", 2, 0))
        self.assertIn("0 of 2 graded vectors were compared", evidence["cause"])
        status, _, counts = self.grade_traps(self.line(0), self.trapped(1, snapshot=False))
        self.assertEqual((status, counts["compared"]), ("residual-trap", 1))
        self.assertEqual(gate.trap_comparison(status, counts), "none")

    def test_a_build_that_runs_past_its_budget_is_slow_not_undefined_or_wrong(self):
        timeout = {"run": 2, "outcome": "budget"}
        o0_late = self.line(0, o0=timeout, pairs={(0, 2): False, (2, 3): False, (2, 4): False})
        self.assertEqual(gate.classify([o0_late], [], 0, self.NONE)[0], "slow")
        o2_late = self.line(0, pairs={(2, 4): False})
        o2_late["runs"][4] = {"run": 4, "outcome": "budget"}
        self.assertEqual(gate.classify([o2_late], [], 0, self.NONE)[0], "slow")
        # The like-for-like build is named first, whether or not an -O0 build also overran
        # (ADR D339), so the reason does not follow an -O0 build near its own allowance.
        both = self.line(0, o0=timeout, pairs={(0, 2): False, (2, 3): False, (2, 4): False})
        both["runs"][4] = {"run": 4, "outcome": "budget"}
        for line in (o2_late, both):
            evidence = gate.classify([line], [], 0, self.NONE)[1]
            self.assertEqual(gate.reason("slow", evidence), "O2")
        self.assertEqual(gate.reason("slow", gate.classify([o0_late], [], 0, self.NONE)[1]), "O0")
        # An -O0 build that sits near its own allowance may be stopped in one run and finish in
        # the next: the record is the same bytes either way.
        self.assertEqual(json.dumps(gate.classify([o2_late], [], 0, self.NONE)),
                         json.dumps(gate.classify([both], [], 0, self.NONE)))
        # Both builds finished and still disagree: that stays undefined behaviour.
        disagree = self.line(0, pairs={(2, 4): False})
        self.assertEqual(gate.classify([disagree], [], 0, self.NONE)[0], "ub")
        self.assertNotIn("slow", gate.BLOCKING)

    def test_a_run_the_wall_clock_guard_ended_says_nothing_of_cost(self):
        # `hang` is load, not cost: never slow, and with no state to compare it
        # leaves the vector ungraded for the harness to answer for.
        line = self.line(0, o0={"run": 2, "outcome": "hang"})
        line["pairs"] = [p for p in line["pairs"] if p["b"] != 2 and p["a"] != 2]
        status, evidence, counts = gate.classify([line, self.line(1)], [], 0, self.NONE)
        self.assertEqual((status, counts["incomplete"], counts["slow"]), ("harness-error", 1, 0))
        self.assertEqual(evidence["runs"], [{"run": 2, "outcome": "hang"}])
        # An original that hangs lies outside the domain, as one that overruns does.
        hung = self.line(0, original="hang")
        self.assertEqual(gate.classify([hung, self.line(1)], [], 0, self.NONE, min_graded=1)[0],
                         "equal")

    def test_a_run_s_cost_never_reaches_a_record(self):
        # A count's last digits and a CPU time vary; a record must be the same bytes on every run.
        counted = {"cost": 123456}
        late = self.line(0, o0={"run": 2, "outcome": "budget", **counted},
                         pairs={(0, 2): False, (2, 3): False, (2, 4): False})
        late["runs"][0].update(counted)
        wrong = self.line(1, o0={"run": 2, "outcome": "return", **counted}, pairs={(0, 2): False})
        wrong["runs"][0].update(counted)
        hung = self.line(2, o0={"run": 2, "outcome": "hang", **counted})
        hung["pairs"] = [p for p in hung["pairs"] if p["b"] != 2 and p["a"] != 2]
        for line in (late, wrong, hung):
            evidence = gate.classify([line], [], 0, self.NONE)[1]
            self.assertNotIn("cost", json.dumps(evidence), line["vector"])

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

    def test_where_a_run_keeps_its_files_does_not_move_a_rendering_s_data(self):
        # A rendering that reads past a literal (review.c's classify at -O2
        # reads its switch table through "\n") was graded ub under one --out
        # path and differs under another. UBSan had stored the absolute source
        # name in .rodata, so the literal moved with the path's length. Every
        # variant must place its data the same way wherever the run writes.
        code = ('#include <stdint.h>\n'
                'uint32_t f(uint32_t i) { return *(uint32_t*)((uint64_t)i * 4 + (uint64_t)"\\n"); }\n')
        with tempfile.TemporaryDirectory() as tmp_text:
            tmp = Path(tmp_text)
            short = link.build_rendering("gcc", tmp / "a", code, [], "f")[0]
            long = link.build_rendering("gcc", tmp / ("b" * 120) / "deeper", code, [], "f")[0]
            for variant in link.VARIANTS:
                self.assertTrue(short[variant].ok and long[variant].ok, variant)
                sections = []
                for built in (short[variant], long[variant]):
                    dump = subprocess.run(["objdump", "-s", "-j", ".rodata", str(built.path)],
                                          capture_output=True, text=True, check=True).stdout
                    sections.append(dump.split("Contents of section .rodata:", 1)[-1])
                self.assertEqual(sections[0], sections[1], variant)


class CostTests(unittest.TestCase):
    """What a budget counts, and when a run may be held to a baseline (ADR D38)."""

    EMULATED = dataclasses.replace(AARCH64, native_machines=())
    NATIVE = dataclasses.replace(X86_64, native_machines=(os.uname().machine,))

    @staticmethod
    def emulator(root: Path, plugins: bool) -> Path:
        """A stand-in qemu that prints a help with or without ``-plugin``."""
        (root / "bin").mkdir(parents=True)
        program = root / "bin" / "qemu-aarch64"
        shown = "-plugin              QEMU_PLUGIN" if plugins else "-seed number"
        program.write_text(f"#!/bin/sh\nprintf '%s\\n' '{shown}'\n")
        program.chmod(0o755)
        return program

    def test_an_emulator_without_plugins_cannot_count_instructions_and_says_why(self):
        with tempfile.TemporaryDirectory() as tmp:
            stub = self.emulator(Path(tmp), plugins=False)
            target = dataclasses.replace(self.EMULATED, emulator=str(stub))
            with self.assertRaises(cost.CostRefused) as refused:
                cost.resolve("instructions", target, workdir=Path(tmp) / "w",
                             counter=lambda: None)
        self.assertIn("no -plugin", str(refused.exception))
        self.assertIn("--measure time", str(refused.exception))
        # The time measure scales for the emulator, as it always did.
        self.assertEqual(cost.resolve("time", self.EMULATED, 1000).budget, 5000)

    def test_an_emulator_with_plugins_needs_the_header_it_installs(self):
        with tempfile.TemporaryDirectory() as tmp:
            stub = self.emulator(Path(tmp), plugins=True)
            target = dataclasses.replace(self.EMULATED, emulator=str(stub))
            with self.assertRaises(cost.CostRefused) as refused:
                cost.resolve("instructions", target, workdir=Path(tmp) / "w")
            self.assertIn(str(Path(tmp).resolve() / "include" / "qemu-plugin.h"),
                          str(refused.exception))

    def test_qemu_counts_under_its_own_counter_and_guard(self):
        counted = cost.Cost("instructions", 4_000_000_000, counter="qemu")
        self.assertEqual(counted.to_json()["counter"], "qemu")
        self.assertEqual(counted.guard_ticks_per_ms(), 100_000)
        # A run's wall guard grows with its allowance under qemu; perf's stays hang_ms.
        perf = cost.Cost("instructions", 4_000_000_000)
        self.assertEqual(perf.worst_vector_ms(6), 6 * perf.hang_ms)
        self.assertGreater(counted.worst_vector_ms(6),
                           6 * counted.hang_ms + counted.original_guard() // 100_000)
        # qemu reads its own options before the guest's: the plugin pair precedes every -E.
        argv = self.EMULATED.run_argv(Path("/w/prog"), ["EQUIV_JOB=/w/job"],
                                      Path("/w/qemu_count.so"))
        self.assertEqual(argv[argv.index("-plugin") + 1], "/w/qemu_count.so")
        self.assertLess(argv.index("-plugin"), argv.index("-E"))
        self.assertEqual(argv[-3:], ["-E", "EQUIV_JOB=/w/job", "/w/prog"])
        self.assertNotIn("-plugin", self.EMULATED.run_argv(Path("/w/prog"), []))

    def test_a_host_that_cannot_count_refuses_instead_of_grading_by_time(self):
        with self.assertRaises(cost.CostRefused) as refused:
            cost.resolve("instructions", self.NATIVE,
                         counter=lambda: "perf_event_open: Permission denied")
        self.assertIn("Permission denied", str(refused.exception))
        counted = cost.resolve("instructions", self.NATIVE, instructions=7, counter=lambda: None)
        self.assertEqual((counted.measure, counted.budget), ("instructions", 7))

    def test_the_probe_reads_a_counter_before_it_trusts_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            paranoid = Path(tmp) / "paranoid"
            paranoid.write_text("4\n")
            closed = []

            def denied(attr):
                raise OSError(errno.EACCES, "Permission denied")

            def opens(attr):
                return 9

            def reads(count):
                return lambda fd, size: count.to_bytes(8, "little")

            why = cost.probe(denied, paranoid=paranoid)
            self.assertIn("Permission denied", why)
            self.assertIn("perf_event_paranoid=4", why)
            self.assertIsNone(cost.probe(opens, reads(1234), closed.append))
            self.assertEqual(closed, [9])
            self.assertIn("reads zero", cost.probe(opens, reads(0), closed.append))
            self.assertEqual(closed, [9, 9])

    def test_the_event_counts_user_space_instructions_only(self):
        attr = cost.event_attr()
        kind, size, config = struct.unpack_from("<IIQ", attr)
        flags = struct.unpack_from("<Q", attr, 40)[0]
        self.assertEqual((kind, config, size), (0, 1, len(attr)))
        self.assertEqual(flags, (1 << 5) | (1 << 6))

    def test_a_baseline_is_held_to_its_own_measure_and_budget(self):
        baseline = {"cost": cost.Cost("time", 1000).to_json()}
        self.assertIsNone(cost.departure(baseline, cost.Cost("time", 1000)))
        # One graded against the absolute budget (before ADR D339) is refused, not reread.
        absolute = cost.departure({"cost": {"measure": "time", "budget": 1000}},
                                  cost.Cost("time", 1000))
        self.assertIn("factor", absolute)
        by_count = cost.departure(baseline, cost.Cost("instructions", 1000))
        self.assertIn("counts time", by_count)
        self.assertIn("counts instructions", by_count)
        self.assertIn("budget", cost.departure(baseline, cost.Cost("time", 5000)))
        # A baseline that says nothing is not one any measure may be held to.
        self.assertIsNotNone(cost.departure({}, cost.Cost("time", 1000)))
        # Instructions counted by qemu's plugin are not perf's (ADR D343); a baseline that
        # names no counter was counted by perf (baseline-win64.json).
        by_qemu = cost.Cost("instructions", 7, counter="qemu")
        self.assertIsNone(cost.departure({"cost": by_qemu.to_json()}, by_qemu))
        self.assertIn("counted by qemu", cost.departure(
            {"cost": by_qemu.to_json()}, cost.Cost("instructions", 7)))
        self.assertIn("counted by perf", cost.departure(
            {"cost": {"measure": "instructions", "budget": 7, "factor": 4}}, by_qemu))
        self.assertIsNone(cost.departure(
            {"cost": {"measure": "instructions", "budget": 7, "factor": 4}},
            cost.Cost("instructions", 7)))

    def test_shards_that_counted_differently_are_not_merged(self):
        def shard(tmp: Path, name: str, counted: dict) -> Path:
            path = tmp / name
            path.write_text(json.dumps({"config": {
                "target": "x86-64", "sources": [], "compilers": "gcc", "opts": "O0",
                "cost": counted}, "records": []}))
            return path

        with tempfile.TemporaryDirectory() as tmp_text:
            tmp = Path(tmp_text)
            time_shard = shard(tmp, "a.json", cost.Cost("time", 1000).to_json())
            same = shard(tmp, "b.json", cost.Cost("time", 1000).to_json())
            other = shard(tmp, "c.json", cost.Cost("instructions", 1000).to_json())
            absolute = shard(tmp, "d.json", {"measure": "time", "budget": 1000})
            perf = shard(tmp, "e.json", cost.Cost("instructions", 1000).to_json())
            qemu = shard(tmp, "f.json", cost.Cost("instructions", 1000, counter="qemu").to_json())
            self.assertEqual(merge_shards.load_records([qemu])[3].counter, "qemu")
            with self.assertRaises(ValueError):
                merge_shards.load_records([perf, qemu])
            self.assertEqual(merge_shards.load_records([time_shard, same])[3],
                             cost.Cost("time", 1000))
            with self.assertRaises(ValueError) as refused:
                merge_shards.load_records([time_shard, other])
            self.assertIn("different measures", str(refused.exception))
            with self.assertRaises(ValueError):
                merge_shards.load_records([time_shard, absolute])

    def test_a_record_states_the_cost_it_was_graded_by(self):
        counted = cost.Cost("instructions", 5)
        record = gate.Record(key="a::gcc-O0::f", function="f", address=0, status="equal",
                             cost=counted.to_json())
        stated = {"measure": "instructions", "budget": 5, "factor": cost.RENDERING_FACTOR,
                  "counter": "perf"}
        self.assertEqual(record.to_json()["cost"], stated)
        proposed = gate.baseline_from([record], None, None, counted)
        self.assertEqual(proposed["cost"], stated)
        self.assertEqual(proposed["schema"], 3)


class TargetTests(unittest.TestCase):
    """What each target says about its machine, without building anything."""

    def test_x86_64_keys_and_directories_are_the_ones_before_the_target_axis(self):
        self.assertEqual(X86_64.config("gcc", "O0"), "gcc-O0")
        self.assertEqual(X86_64.directory("rt"), "rt")
        self.assertEqual(AARCH64.config("clang", "O2"), "aarch64-clang-O2")
        self.assertEqual(AARCH64.directory("rt"), "rt-aarch64")
        # Budgets are native time: x86-64's are never scaled, an emulated
        # target's by its emulator's slowdown.
        self.assertEqual(X86_64.time_scale(), 1)
        self.assertEqual(cost.resolve("time", X86_64).budget, 1000)
        self.assertEqual(AARCH64.time_scale(), 5 if AARCH64.emulated() else 1)

    def test_a_narrow_argument_carries_only_the_bits_its_convention_defines(self):
        garbage = 0xDEADBEEF_CAFEBABE
        # SysV x86-64: extended to 32 bits by the type's signedness, the rest
        # the caller's.
        x86 = X86_64.abi
        self.assertEqual(x86.argument_word(0xFF, 1, True, garbage), 0xCAFEBABE_FFFFFFFF)
        self.assertEqual(x86.argument_word(0xFF, 1, False, garbage), 0xCAFEBABE_000000FF)
        self.assertEqual(x86.argument_word(0x80000000, 4, True, garbage), 0xCAFEBABE_80000000)
        self.assertEqual(x86.argument_word(7, 8, True, garbage), 7)
        # AAPCS64: every bit above the type is the caller's.
        a64 = AARCH64.abi
        self.assertEqual(a64.argument_word(0xFF, 1, True, garbage), 0xADBEEFCA_FEBABEFF)
        self.assertEqual(a64.argument_word(0x1234, 2, False, garbage), 0xBEEFCAFE_BABE1234)
        self.assertEqual(a64.argument_word(5, 4, True, garbage), 0xCAFEBABE_00000005)
        self.assertEqual(a64.argument_word(7, 8, True, garbage), 7)

    def test_a_job_vector_has_the_runtime_s_layout_of_its_machine(self):
        # struct job_vector in rt/equiv_rt.c: the seed, struct equiv_regs, and
        # two 32-bit words. equiv_regs is 320 bytes on x86-64 (six GPRs, eight
        # XMMs, rax, n_stack, sixteen stack words) and 328 on AArch64 (eight
        # GPRs, eight Q registers, n_stack, sixteen stack words); equiv_rt.c
        # asserts the same sizes.
        spec = CallSpec(name="f", address=0x1000, params=[], ret_kind="int", ret_bytes=4,
                        ret_spelling="int")
        for target, size in ((X86_64, 336), (AARCH64, 344)):
            abi = target.abi
            vector = Vector(index=0, seed=1, gpr=[0] * len(abi.int_registers),
                            fp=[bytes(16)] * len(abi.fp_registers), count=0, stack=[])
            with_vector = encode_job(spec, [], [], [vector], cost.Cost(), abi=abi)
            without = encode_job(spec, [], [], [], cost.Cost(), abi=abi)
            self.assertEqual(len(with_vector) - len(without), size, target.name)

    def test_win64_keeps_the_x86_64_job_layout_and_names_its_own_keys(self):
        # call_win64.S reads four of the six GPR words and four of the eight XMMs.
        spec = CallSpec(name="f", address=0x1000, params=[], ret_kind="int", ret_bytes=4,
                        ret_spelling="int")
        abi = WIN64.abi
        self.assertEqual(abi.regs_format(), X86_64.abi.regs_format())
        vector = Vector(index=0, seed=1, gpr=[0] * abi.int_slots(),
                        fp=[bytes(16)] * abi.fp_slots(), count=0, stack=[])
        with_vector = encode_job(spec, [], [], [vector], cost.Cost(), abi=abi)
        without = encode_job(spec, [], [], [], cost.Cost(), abi=abi)
        self.assertEqual(len(with_vector) - len(without), 336)
        self.assertEqual(WIN64.config("clang-cl", "O1"), "win64-clang-cl-O1")
        self.assertEqual(WIN64.directory("rt"), "rt-win64")
        # No Microsoft x64 caller extends a narrow argument: every bit above it is garbage.
        garbage = 0xDEADBEEF_CAFEBABE
        self.assertEqual(abi.argument_word(0xFF, 1, True, garbage), 0xADBEEFCA_FEBABEFF)

    def test_microsoft_x64_gives_each_position_one_register_of_its_class(self):
        dwarf = fixture_dwarf("abi.gcc.O2.txt")
        functions = [s for s in dwarf.subprograms() if s.name]
        specs = {s.name: call_spec(dwarf, s, functions, WIN64.abi) for s in functions}
        # `long fl_mid(long a, double d, long *p)`: d takes xmm1, so p takes r8, not rdx.
        self.assertEqual(specs["fl_mid"].describe(),
                         "long int fl_mid(long int a@rcx, double d@xmm1, long int* p@r8)")
        self.assertEqual([p.register for p in specs["pick"].params],
                         ["rcx", "rdx", "r8", "r9", "stack0"])
        self.assertIn("Microsoft x64", specs["wide_ret"].unsupported or "")

    def test_a_pe_runs_inside_the_host_program_the_runtime_maps_it_into(self):
        runtime = Path("/w/rt-win64/equiv_rt.so")
        self.assertEqual(WIN64.host_program(Path("/w/a.exe"), runtime),
                         Path("/w/rt-win64/pe_host"))
        self.assertEqual(WIN64.program_environment(Path("/w/a.exe")), ["EQUIV_PE=/w/a.exe"])
        self.assertEqual(X86_64.host_program(Path("/w/a"), runtime), Path("/w/a"))
        self.assertEqual(X86_64.program_environment(Path("/w/a")), [])

    def test_a_pe_import_link_is_the_image_s_thunk_and_an_elf_one_binds_to_libc(self):
        links = [{"ident": "fwrite", "kind": "import", "addr": 0x140003130},
                 {"ident": "puts", "kind": "import", "addr": 0}]
        win64, _ = link.shim_source(links, "sub_f", 0x140001000, WIN64)
        self.assertIn("fwrite:\n    movabs $0x140003130, %r11\n", win64)
        self.assertNotIn("puts:", win64)
        elf, _ = link.shim_source(links, "sub_f", 0x401000, X86_64)
        self.assertNotIn("fwrite:", elf)
        # r2s links an import called through `call [slot]` at the slot: the jump reads the slot.
        slot = [{"ident": "vfprintf", "kind": "function", "addr": 0x1400056D0}]
        through, _ = link.shim_source(slot, "sub_f", 0x140001000, WIN64, frozenset({0x1400056D0}))
        self.assertIn("vfprintf:\n    movabs $0x1400056d0, %r11\n    jmp *(%r11)\n", through)

    def test_the_job_header_carries_each_run_s_allowance_in_ticks(self):
        # struct job_header in rt/equiv_rt.c: 112 bytes; struct job_run's factor (ADR D339).
        spec = CallSpec(name="f", address=0x1000, params=[], ret_kind="int", ret_bytes=4,
                        ret_spelling="int")
        k = cost.RENDERING_FACTOR
        counted = cost.Cost("instructions", 3_000_000_000, hang_ms=7000, fake_original=5,
                            fake_rendering=6)
        header = encode_job(spec, [], [], [], counted)
        self.assertEqual(len(header), 112)
        self.assertEqual(header[:8], JOB_MAGIC)
        fields = struct.unpack("<8sQQQQ10IQQQQ", header)
        # The measure, its counter (perf) and the wall guard's ticks per ms (none).
        self.assertEqual((fields[8], fields[12], fields[13], fields[14]), (7000, 1, 0, 0))
        self.assertEqual(fields[15:], (k * k * 3_000_000_000, 3_000_000_000 // (k * k), 5, 6))
        by_qemu = struct.unpack("<8sQQQQ10IQQQQ", encode_job(
            spec, [], [], [], dataclasses.replace(counted, counter="qemu")))
        self.assertEqual(by_qemu[12:15], (1, 1, 100_000))
        # CPU time is carried in nanoseconds; the budget states milliseconds.
        timed = struct.unpack("<8sQQQQ10IQQQQ", encode_job(
            spec, [], [], [], cost.Cost("time", 1000, fake_original=2)))
        self.assertEqual(timed[12:15] + timed[15:],
                         (0, 0, 250_000, k * k * 10**9, 10**9 // (k * k), 2 * 10**6, 0))
        # The -O2 build and the identity get the factor; the unoptimised builds its square.
        self.assertEqual((cost.Cost.factor(True), cost.Cost.factor(False)), (k, k * k))
        run = encode_job(spec, [Run("O2", so_path="x.so", symbol="f", replaces=True,
                                    factor=k)], [], [], counted)[112:]
        self.assertEqual(struct.unpack_from("<QII", run), (0, 1, k))

    def test_function_links_jump_through_a_register_no_argument_uses(self):
        links = [{"ident": "callee", "kind": "function", "addr": 0x401234},
                 {"ident": "self", "kind": "function", "addr": 0x401000},
                 {"ident": "table", "kind": "object", "addr": 0x404010}]
        x86, _ = link.shim_source(links, "sub_f", 0x401000, X86_64)
        self.assertIn("    movabs $0x401234, %r11\n    jmp *%r11\n", x86)
        self.assertIn("self:\n    jmp sub_f\n", x86)
        a64, _ = link.shim_source(links, "sub_f", 0x401000, AARCH64)
        self.assertIn("    movz x16, #0x1234\n    movk x16, #0x40, lsl #16\n", a64)
        self.assertIn("    br x16\n", a64)
        self.assertIn("self:\n    b sub_f\n", a64)
        for text in (x86, a64):
            self.assertIn("    .set table, 0x404010\n", text)
        self.assertEqual(link.shim_objects(links, "sub_f"), [("table", 0x404010)])

    def test_immediates_are_read_in_each_machine_s_syntax(self):
        x86 = "  401000:\tcmp    $0x64,%edi\n  401003:\tmov    $0xffffffffffffffff,%rax\n"
        self.assertEqual(X86_64.asm.immediates(x86), [100, (1 << 64) - 1])
        a64 = ("  4006b0:\tldr\tw0, [sp, #12]\n"
               "  4006b4:\tcmp\tw0, #0x64\n"
               "  4006bc:\tmov\tw0, #0x3e8                 \t// #1000\n"
               "  4006c0:\tfmov\td0, #1.000000000000000000e+00\n")
        self.assertEqual(AARCH64.asm.immediates(a64), [100, 1000])

    def test_an_emulated_target_hands_its_variables_to_the_guest_only(self):
        if not AARCH64.emulated():
            self.skipTest("this host runs AArch64 natively")
        argv = AARCH64.run_argv(Path("/w/prog"), ["LD_PRELOAD=/w/rt.so", "EQUIV_JOB=/w/job"])
        self.assertEqual(argv, ["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu", "-seed", "1",
                                "-E", "LD_PRELOAD=/w/rt.so", "-E", "EQUIV_JOB=/w/job", "/w/prog"])
        with self.assertRaises(ValueError):
            AARCH64.run_argv(Path("/w/prog"), ["UBSAN_OPTIONS=a=1,b=2"])


class _OnTarget:
    """Cases written once and run per target (``TARGET``).

    Each target's class is its own ``unittest.TestCase`` with its own skip
    condition, so one target's absence never hides the other's tests.
    """

    TARGET: Target = X86_64

_AARCH64_RUN = "AArch64 runtime equivalence needs its cross compiler, sysroot and qemu-aarch64"
_AARCH64_BUILD = "building for AArch64 needs aarch64-linux-gnu-gcc"


class _BuildCases(_OnTarget):
    def test_the_shown_copy_has_a_directory_of_its_own_with_nothing_else_in_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = build.build(HERE / "selftest" / "fixture.c", "gcc", "O0", Path(tmp),
                                 self.TARGET)
            self.assertIsNone(binary.error)
            self.assertEqual(build.elf_machine(binary.stripped, self.TARGET),
                             self.TARGET.elf_machine)
            self.assertNotEqual(binary.stripped.parent, binary.unstripped.parent)
            self.assertEqual(binary.stripped.name, binary.unstripped.name)
            self.assertEqual(sorted(p.name for p in binary.stripped.parent.iterdir()),
                             [binary.stripped.name])
            sections = subprocess.run(["readelf", "-SW", str(binary.stripped)],
                                      capture_output=True, text=True, check=True).stdout
            self.assertNotIn(".symtab", sections)
            self.assertNotIn(".debug_", sections)

    def test_a_compiler_that_builds_for_another_machine_is_a_failed_build(self):
        other = AARCH64 if self.TARGET is X86_64 else X86_64
        wrong = Target(**{**self.TARGET.__dict__, "compilers": other.compilers})
        if shutil.which(other.compiler("gcc")[0]) is None:
            self.skipTest(f"no {other.name} compiler to build the wrong machine with")
        with tempfile.TemporaryDirectory() as tmp:
            binary = build.build(HERE / "selftest" / "fixture.c", "gcc", "O0", Path(tmp), wrong)
        self.assertIn(f"not {self.TARGET.elf_machine}", binary.error or "")


@unittest.skipUnless(CAN_RUN, "runtime equivalence needs x86-64 Linux and gcc")
class BuildTests(_BuildCases, unittest.TestCase):
    pass


@unittest.skipUnless(CAN_BUILD_AARCH64, _AARCH64_BUILD)
class AArch64BuildTests(_BuildCases, unittest.TestCase):
    TARGET = AARCH64


DWARF_FIXTURES = HERE / "testdata" / "dwarf"


def fixture_dwarf(name: str) -> Dwarf:
    """A DWARF from the readelf text of a gcc 13.3 build, trimmed to the DIEs a signature needs."""
    text = (DWARF_FIXTURES / name).read_text()
    units, index = parse_readelf(text)
    return Dwarf(units, index, parse_ranges(text))


class RangesTests(unittest.TestCase):
    """The first range of each list in `readelf --debug-dump=Ranges`, in DWARF 5 and DWARF 4."""

    def test_dwarf_5_lists_start_at_their_first_row(self):
        ranges = fixture_dwarf("cold.gcc.O2.txt").ranges
        # A base address row holds no range; an empty range is one (GCC lists the entry first, empty).
        self.assertEqual(ranges[0xC], (0x1380,))
        self.assertEqual(ranges[0x1C], (0x13B4,))
        # A split function lists its hot part first, its cold part second.
        self.assertEqual(ranges[0x2C], (0x13E0,))
        self.assertEqual(ranges[0x41], (0x1206,))
        self.assertEqual(ranges[0x54], (0x1370,))

    def test_dwarf_4_lists_repeat_their_offset_on_every_row(self):
        ranges = fixture_dwarf("cold.gcc.O2.dwarf4.txt").ranges
        self.assertEqual(ranges, {0x0: (0x1380,), 0x30: (0x13B4,), 0x60: (0x13E0,), 0x90: (0x1206,), 0xD0: (0x1370,)})

    def test_a_list_with_no_range_has_no_entry(self):
        text = "Contents of the .debug_rnglists section:\n\n    Offset   Begin    End\n" \
               "    0000000c 0000000000001380 (base address)\n    00000015 <End of list>\n" \
               "    00000016 <End of list>\n    00000017 0000000000002000 0000000000002010 \n    0000001a <End of list>\n"
        self.assertEqual(parse_ranges(text), {0x17: (0x2000,)})

    def test_two_sections_that_hold_one_offset_keep_both_answers(self):
        text = ("Contents of the .debug_ranges section:\n\n    Offset   Begin    End\n"
                "    00000000 0000000000001000 0000000000001010\n    00000000 <End of list>\n\n"
                "Contents of the .debug_rnglists section:\n\n    Offset   Begin    End\n"
                "    00000000 0000000000002000 0000000000002010\n    00000000 <End of list>\n")
        self.assertEqual(parse_ranges(text), {0: (0x1000, 0x2000)})

    def test_two_sections_that_agree_keep_one_answer(self):
        text = ("Contents of the .debug_ranges section:\n\n    Offset   Begin    End\n"
                "    00000000 0000000000001000 0000000000001010\n    00000000 <End of list>\n\n"
                "Contents of the .debug_rnglists section:\n\n    Offset   Begin    End\n"
                "    00000000 0000000000001000 0000000000001020\n    00000000 <End of list>\n")
        self.assertEqual(parse_ranges(text), {0: (0x1000,)})

    def test_a_32_bit_binary_prints_its_addresses_in_eight_digits(self):
        text = ("Contents of the .debug_ranges section:\n\n    Offset   Begin    End\n"
                "    00000000 00001000 00001010\n    00000000 <End of list>\n")
        self.assertEqual(parse_ranges(text), {0: (0x1000,)})

    def test_rows_outside_a_ranges_section_are_not_ranges(self):
        text = "Contents of the .debug_info section:\n    00000000 0000000000001000 0000000000001010\n"
        self.assertEqual(parse_ranges(text), {})


class ReferenceTests(unittest.TestCase):
    """A DIE's reference is a DIE of the dump, nothing, or one the dump cannot name: never void by accident."""

    def test_a_signature_reference_into_a_type_unit_is_unresolved_and_no_attribute_is_none(self):
        text = ("Contents of the .debug_info section:\n <0><c>: Abbrev Number: 1 (DW_TAG_compile_unit)\n"
                " <1><2a>: Abbrev Number: 6 (DW_TAG_subprogram)\n"
                "    <2b>   DW_AT_type        : (ref_sig8) : 0x7cbb7a52356be670\n"
                "    <2f>   DW_AT_abstract_origin: (ref4) <0x30>\n")
        _, index = parse_readelf(text)
        die = index[0x2A]
        self.assertEqual(die.ref("DW_AT_type"), UNRESOLVED)
        self.assertEqual(die.ref("DW_AT_abstract_origin"), 0x30)
        self.assertIsNone(die.ref("DW_AT_sibling"))

    def test_a_function_whose_type_is_in_another_unit_has_no_type_this_dump_can_describe(self):
        sub = Die(0x40, "DW_TAG_subprogram", 1, attrs={"DW_AT_name": "f", "DW_AT_low_pc": "0x1000", "DW_AT_prototyped": "1",
                                                      "DW_AT_type": ": 0x7cbb7a52356be670"})
        param = Die(0x50, "DW_TAG_formal_parameter", 2, attrs={"DW_AT_name": "p", "DW_AT_type": ": 0x44a62e69dcaa1ced"})
        sub.children.append(param)
        unit = Die(0x10, "DW_TAG_compile_unit", 0, attrs={"DW_AT_name": "t.c"}, children=[sub])
        dwarf = Dwarf([unit], {0x10: unit, 0x40: sub, 0x50: param})
        placed, _ = dwarf.placed(AnyAddress())
        self.assertEqual((placed[0].return_type, placed[0].parameters[0].type_offset), (UNRESOLVED, UNRESOLVED))
        self.assertEqual((dwarf.type(UNRESOLVED).kind, dwarf.canonical(UNRESOLVED)), ("unsupported", "unsupported"))


CU = "Contents of the .debug_info section:\n <0><c>: Abbrev Number: 1 (DW_TAG_compile_unit)\n"
UINT = (" <1><3b>: Abbrev Number: 2 (DW_TAG_base_type)\n    <3c>   DW_AT_byte_size   : (data1) 4\n"
        "    <3d>   DW_AT_encoding    : (data1) 7\t(unsigned)\n    <3e>   DW_AT_name        : (string) unsigned int\n")


class OneGraphTests(unittest.TestCase):
    """A dump is one graph of DIEs keyed by offset, or the reader refuses it."""

    def test_a_dwarf_4_type_unit_whose_offsets_meet_the_info_is_refused(self):
        # .debug_types numbers its DIEs from 0 as .debug_info does: its 0x3b replaced the unit's `unsigned int`.
        text = (CU + UINT + "Contents of the .debug_types section:\n  Signature:     0x3701eddaef7e0427\n"
                " <0><17>: Abbrev Number: 1 (DW_TAG_type_unit)\n <1><3b>: Abbrev Number: 3 (DW_TAG_base_type)\n"
                "    <3c>   DW_AT_byte_size   : (data1) 8\n    <3d>   DW_AT_encoding    : (data1) 5\t(signed)\n")
        with self.assertRaises(RuntimeError) as raised:
            parse_readelf(text)
        self.assertIn(TYPE_UNIT, str(raised.exception))

    def test_a_dwarf_5_type_unit_is_refused_though_no_offset_meets(self):
        text = (CU + UINT + "  Compilation Unit @ offset 0x100:\n   Unit Type:     DW_UT_type (2)\n"
                " <0><118>: Abbrev Number: 1 (DW_TAG_type_unit)\n")
        with self.assertRaises(RuntimeError) as raised:
            parse_readelf(text)
        self.assertIn(TYPE_UNIT, str(raised.exception))

    def test_two_dies_at_one_offset_are_an_error(self):
        with self.assertRaises(RuntimeError) as raised:
            parse_readelf(CU + UINT + " <0><80>: Abbrev Number: 1 (DW_TAG_compile_unit)\n" + UINT)
        self.assertIn("two DIEs at offset 0x3b", str(raised.exception))
        self.assertEqual(sorted(parse_readelf(CU + UINT)[1]), [0xC, 0x3B])

    def test_the_type_unit_builds_of_the_gold_sources_are_refused(self):
        for name in ("odd.gcc.O2.dwarf4.types.txt", "abi.gcc.O2.types.txt"):
            with self.subTest(name=name), self.assertRaises(RuntimeError) as raised:
                fixture_dwarf(name)
            self.assertIn(TYPE_UNIT, str(raised.exception))

    def test_a_split_dwarf_build_whose_dwo_readelf_follows_is_two_dies_at_one_offset(self):
        # gcc -gsplit-dwarf: the skeleton and the .dwo each start their unit at 0x14 (DWARF 5) or 0xb (DWARF 4).
        text = ("Contents of the .debug_info section (loaded from odd.split):\n   Unit Type:     DW_UT_skeleton (4)\n"
                " <0><14>: Abbrev Number: 1 (DW_TAG_skeleton_unit)\n"
                "    <25>   DW_AT_dwo_name    : (strp) (offset: 0x17): odd.split-odd.dwo\n"
                "Contents of the .debug_info.dwo section (loaded from /work/src/odd.split-odd.dwo):\n"
                "   Unit Type:     DW_UT_split_compile (5)\n <0><14>: Abbrev Number: 22 (DW_TAG_compile_unit)\n")
        with self.assertRaises(RuntimeError) as raised:
            parse_readelf(text)
        self.assertIn("two DIEs at offset 0x14", str(raised.exception))

    def test_an_instance_without_formals_takes_those_of_the_first_origin_that_lists_them(self):
        # An out-of-line copy lists no formals; its abstract origin, a declaration, does (and a second one too).
        formal = Die(0x58, "DW_TAG_formal_parameter", 2, attrs={"DW_AT_name": "n", "DW_AT_type": "<0x30>"})
        other = Die(0x68, "DW_TAG_formal_parameter", 2, attrs={"DW_AT_name": "late", "DW_AT_type": "<0x30>"})
        copy = Die(0x40, "DW_TAG_subprogram", 1, attrs={"DW_AT_low_pc": "0x1000", "DW_AT_abstract_origin": "<0x50>"})
        origin = Die(0x50, "DW_TAG_subprogram", 1, attrs={"DW_AT_name": "f", "DW_AT_specification": "<0x60>"},
                     children=[formal])
        declaration = Die(0x60, "DW_TAG_subprogram", 1, attrs={"DW_AT_name": "f"}, children=[other])
        unit = Die(0x10, "DW_TAG_compile_unit", 0, attrs={"DW_AT_name": "t.c"}, children=[copy, origin, declaration])
        dwarf = Dwarf([unit], {d.offset: d for d in (unit, copy, origin, declaration, formal, other)})
        placed, _ = dwarf.placed(AnyAddress())
        self.assertEqual([(sub.name, [p.name for p in sub.parameters]) for sub in placed], [("f", ["n"])])

    def test_a_cycle_of_origins_is_an_error_and_not_a_hang(self):
        first = Die(0x40, "DW_TAG_subprogram", 1, attrs={"DW_AT_low_pc": "0x1000", "DW_AT_abstract_origin": "<0x50>"})
        second = Die(0x50, "DW_TAG_subprogram", 1, attrs={"DW_AT_abstract_origin": "<0x40>"})
        unit = Die(0x10, "DW_TAG_compile_unit", 0, attrs={"DW_AT_name": "t.c"}, children=[first, second])
        dwarf = Dwarf([unit], {0x10: unit, 0x40: first, 0x50: second})
        previous = signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError("the walk hangs")))
        signal.alarm(5)
        try:
            with self.assertRaises(RuntimeError) as raised:
                dwarf.placed(AnyAddress())
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)
        self.assertIn("cycle", str(raised.exception))

    def test_a_number_is_a_constant_form_and_nothing_else(self):
        text = (CU + " <1><40>: Abbrev Number: 4 (DW_TAG_subrange_type)\n"
                "    <41>   DW_AT_upper_bound : (exprloc) 3 byte block: 91 68 6 \t(DW_OP_fbreg: -24; DW_OP_deref)\n"
                "    <45>   DW_AT_count       : (sdata) -1\n    <46>   DW_AT_lower_bound : 7\n"
                "    <47>   DW_AT_ranges      : (sec_offset) 0x2c\n    <48>   DW_AT_byte_size   : (implicit_const) 8\n")
        die = parse_readelf(text)[1][0x40]
        self.assertIsNone(die.number("DW_AT_upper_bound"))  # the block's length, 3, was read as the bound
        self.assertEqual(die.number("DW_AT_count"), -1)
        self.assertIsNone(die.number("DW_AT_lower_bound"))  # a value whose form readelf does not name
        self.assertIsNone(die.number("DW_AT_ranges"))
        self.assertIsNone(die.number("DW_AT_name"))
        self.assertEqual(die.number("DW_AT_byte_size"), 8)  # gcc writes the size of most types once, in the abbrev
        for form in ("data1", "data2", "data4", "data8", "udata", "sdata"):
            with self.subTest(form=form):  # an array bound or a struct size of 256 or more is no data1
                text = CU + f" <1><40>: Abbrev Number: 4 (DW_TAG_subrange_type)\n    <41>   DW_AT_upper_bound : ({form}) 299\n"
                self.assertEqual(parse_readelf(text)[1][0x40].number("DW_AT_upper_bound"), 299)

    def test_a_dwarf_2_member_offset_is_its_one_plus_uconst(self):
        text = (CU + " <1><40>: Abbrev Number: 5 (DW_TAG_structure_type)\n    <41>   DW_AT_byte_size   : (data1) 16\n"
                " <2><42>: Abbrev Number: 6 (DW_TAG_member)\n    <43>   DW_AT_name        : (string) b\n"
                "    <44>   DW_AT_data_member_location: (block1) 2 byte block: 23 8 \t(DW_OP_plus_uconst: 8)\n"
                " <2><48>: Abbrev Number: 6 (DW_TAG_member)\n    <49>   DW_AT_name        : (string) c\n"
                "    <4a>   DW_AT_data_member_location: (data1) 12\n")
        units, index = parse_readelf(text)
        self.assertEqual([member.offset for member in Dwarf(units, index).members(0x40)], [8, 12])
        for other in ("3 byte block: 23 8 6 \t(DW_OP_plus_uconst: 8; DW_OP_deref)",
                      "3 byte block: 23 8 6 \t(DW_OP_plus_uconst: 8) (DW_OP_deref)",
                      "(DW_OP_lit1) 2 byte block: 23 8 \t(DW_OP_plus_uconst: 8)"):
            with self.subTest(location=other):  # one op and nothing around it is an offset
                index[0x42].attrs["DW_AT_data_member_location"] = other
                with self.assertRaises(ValueError):
                    Dwarf(units, index).members(0x40)

    def test_an_integer_states_its_size_and_an_enum_its_underlying_type(self):
        def die(offset, tag, **attrs):
            forms = {name: "data1" for name in attrs if name in ("DW_AT_byte_size", "DW_AT_encoding")}
            return Die(offset, tag, 1, attrs=attrs, forms=forms)
        long = die(0x30, "DW_TAG_base_type", DW_AT_byte_size="8", DW_AT_encoding="5\t(signed)", DW_AT_name="long int")
        dies = [long,
                die(0x40, "DW_TAG_enumeration_type", DW_AT_byte_size="8", DW_AT_type="<0x30>"),
                die(0x50, "DW_TAG_enumeration_type", DW_AT_signature=": 0x3701eddaef7e0427"),
                die(0x60, "DW_TAG_enumeration_type", DW_AT_byte_size="4"),
                die(0x70, "DW_TAG_enumeration_type", DW_AT_type="<0x30>"),
                die(0x80, "DW_TAG_enumeration_type", DW_AT_byte_size="4", DW_AT_type="<0x30>"),
                die(0x90, "DW_TAG_enumeration_type", DW_AT_declaration="1", DW_AT_byte_size="8", DW_AT_type="<0x30>"),
                die(0xA0, "DW_TAG_base_type", DW_AT_encoding="5\t(signed)", DW_AT_name="int"),
                die(0xB0, "DW_TAG_structure_type", DW_AT_signature=": 0x986483db34619643"),
                die(0xC0, "DW_TAG_pointer_type", DW_AT_byte_size="8"),
                die(0xD0, "DW_TAG_enumeration_type", DW_AT_byte_size="8", DW_AT_type="<0xc0>")]
        dwarf = Dwarf([], {d.offset: d for d in dies})
        self.assertEqual((dwarf.type(0x40).kind, dwarf.type(0x40).size, dwarf.type(0x40).signed), ("int", 8, True))
        for offset in (0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xD0):
            with self.subTest(offset=hex(offset)):
                self.assertEqual(dwarf.type(offset).kind, "unsupported")

    def test_strict_dwarf_2_enums_are_described_as_nothing(self):
        dwarf = fixture_dwarf("enums.gcc.O2.strict2.txt")
        e_neg = next(sub for sub in dwarf.subprograms() if sub.name == "e_neg")
        self.assertEqual([dwarf.type(p.type_offset).kind for p in e_neg.parameters], ["unsupported", "int", "unsupported"])
        five = fixture_dwarf("enums.gcc.O2.txt")
        e_neg = next(sub for sub in five.subprograms() if sub.name == "e_neg")
        self.assertEqual([(five.type(p.type_offset).kind, five.type(p.type_offset).signed) for p in e_neg.parameters],
                         [("int", True)] * 3)


class AnyAddress:
    """Every address is the start of a function: the entry rule alone is under test."""

    def __contains__(self, _address: int) -> bool:
        return True


def fixture_starts(name: str) -> dict:
    """The FUNC symbols of a `readelf --wide --syms` dump kept as a fixture."""
    done = subprocess.CompletedProcess([], 0, (DWARF_FIXTURES / name).read_text(), "")
    with unittest.mock.patch.object(subprocess, "run", return_value=done):
        return function_symbols(Path("binary"))


def fixture_code(name: str) -> list[range]:
    """The loaded code of a build whose ELF header and program header table are kept as a fixture."""
    return code_addresses(bytes.fromhex((DWARF_FIXTURES / f"{name}.head.hex").read_text()), name)


def elf(kind: int = 3, loads: tuple = ((0, 0, 0x650),), wide: bool = True, order: str = "<", other: int = 0) -> bytearray:
    """An ELF header and program header table: each load is `(offset, address, file size)`, after `other` PT_NOTEs."""
    size = struct.calcsize(order + ("IIQQQQQQ" if wide else "IIIIIIII"))
    ident = b"\x7fELF" + bytes([2 if wide else 1, 1 if order == "<" else 2, 1]) + bytes(9)
    head = struct.pack(order + ("HHIQQQIHHHHHH" if wide else "HHIIIIIHHHHHH"), kind, 62, 1, 0, 64 if wide else 52, 0, 0,
                       64 if wide else 52, size, other + len(loads), 0, 0, 0)
    rows = [(4, 0x9000, 0x9000, 0x30)] * other + [(1, *load) for load in loads]
    table = b"".join(struct.pack(order + "IIQQQQQQ", kind_, 4, offset, address, address, filesz, filesz + 8, 0x1000)
                     if wide else struct.pack(order + "IIIIIIII", kind_, offset, address, address, filesz, filesz + 8, 4, 0x1000)
                     for kind_, offset, address, filesz in rows)
    return bytearray(ident + head + table)


class LoadedCodeTests(unittest.TestCase):
    TOMBSTONES = (0, 1, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF)

    def test_code_is_the_file_bytes_of_each_load_past_the_headers(self):
        # gcc 13.3 PIEs map their headers at 0: x86-64 13 entries end at 0x318, AArch64 9 at 0x238.
        self.assertEqual(fixture_code("gclib.gcc.O2.gc"),
                         [range(0x318, 0x650), range(0x1000, 0x1219), range(0x2000, 0x2134), range(0x3DB8, 0x4008)])
        self.assertEqual(fixture_code("statics.a64.O0.x"), [range(0x238, 0xE88), range(0x1FD78, 0x20010)])
        self.assertEqual(fixture_code("gclib.gcc.O2.gc.nopie")[0], range(0x400318, 0x400508))

    def test_a_tombstone_lies_in_no_loaded_code_of_a_pie_or_a_fixed_build(self):
        for name in ("gclib.gcc.O2.gc", "gclib.gcc.O2.gc.nopie", "statics.a64.O0.x", "fdat.a64.O0.x"):
            for address in self.TOMBSTONES:
                with self.subTest(name=name, address=address):
                    self.assertFalse(any(address in code for code in fixture_code(name)))

    def test_code_in_a_section_without_the_x_flag_is_loaded_code(self):
        # fdat.c: `.fdat` is WA (`"aw"`) at 0x4010 to 0x40c5 at -O2, A (`"a"`) at 0x2004 at -O0; s_0 starts in each.
        for name, s_0 in (("fdat.gcc.O2.x", 0x40C0), ("fdat.ro.gcc.O0.x", 0x2004), ("fdat.a64.O0.x", 0x20010)):
            with self.subTest(name=name):
                self.assertTrue(any(s_0 in code for code in fixture_code(name)))

    def test_only_the_file_bytes_of_a_load_hold_code(self):
        # Each load maps 8 bytes past its file size (.bss); a PT_NOTE row is no load.
        self.assertEqual(code_addresses(bytes(elf(loads=((0, 0, 0x650), (0x2DB8, 0x3DB8, 0x250)), other=2))),
                         [range(0x40 + 4 * 56, 0x650), range(0x3DB8, 0x4008)])
        self.assertEqual(code_addresses(bytes(elf(loads=((0, 0x8048000, 0x200),), wide=False, order=">"))),
                         [range(0x8048000 + 52 + 32, 0x8048200)])

    def test_a_table_that_is_no_whole_program_header_table_is_unreadable(self):
        good = elf()
        cases = {"no ELF": bytearray(b"\x7fELG") + good[4:], "class 3": good[:4] + b"\x03" + good[5:],
                 "cut": good[:-1], "short": good[:20], "no load": elf(loads=()), "empty load": elf(loads=((0, 0, 0),)),
                 "headers only": elf(loads=((0, 0, 0x78),)), "core": elf(kind=4), "none": elf(kind=0)}
        # PN_XNUM puts the count in section 0: read as 65535 rows, the second load would be code past the table.
        xnum, small = elf(loads=((0, 0, 0x650), (0x400000, 0x400000, 0x100))) + bytes(0xFFFF * 56), bytearray(good)
        struct.pack_into("<H", xnum, 56, 0xFFFF)
        struct.pack_into("<H", small, 54, 32)
        cases.update({"PN_XNUM": xnum, "entry too small": small})
        for name, data in cases.items():
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                code_addresses(bytes(data))

    def test_a_relocatable_object_is_refused_by_name(self):
        # `gcc -c gclib.c`: an object has no program headers.
        head = bytes.fromhex("7f454c4602010100000000000000000001003e000100000000000000000000000000000000000000"
                             "281c0000000000000000000040000000000040001b001a00")
        with self.assertRaises(RuntimeError) as raised:
            code_addresses(head, "gclib.o")
        self.assertEqual(str(raised.exception), f"gclib.o: {RELOCATABLE}")

    def test_the_binary_is_read_whole_from_its_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "binary"
            path.write_bytes(bytes.fromhex((DWARF_FIXTURES / "krt.gcc.O2.head.hex").read_text()))
            self.assertEqual(loaded_code(path), fixture_code("krt.gcc.O2"))


class FunctionSymbolTests(unittest.TestCase):
    def test_only_func_symbols_of_the_symtab_start_a_function(self):
        starts = fixture_starts("cold.clang.O2.bbs.syms.txt")
        # `checked_div` is a FUNC; its fragments `checked_div.__part.1` and `.2` are NOTYPE and so no function start.
        self.assertEqual(starts[0x11C0], (["checked_div"], 13))
        self.assertNotIn(0x11CD, starts)
        self.assertNotIn(0x11D3, starts)
        # `.dynsym` holds imports at address 0 and no code of the binary.
        self.assertNotIn(0, starts)

    def test_a_data_symbol_is_no_function_start(self):
        starts = fixture_starts("cold.gcc.O2.syms.txt")
        for address in (0x4028, 0x38C, 0x3D78):  # `completed.0`, `__abi_tag` and a fini_array entry are OBJECT symbols
            self.assertNotIn(address, starts)

    def test_a_function_only_the_dynamic_symbol_table_defines_is_no_function_start(self):
        text = ("Symbol table '.dynsym' contains 2 entries:\n   Num:    Value          Size Type    Bind   Vis      Ndx Name\n"
                "     1: 0000000000001000     8 FUNC    GLOBAL DEFAULT   14 exported\n\n"
                "Symbol table '.symtab' contains 2 entries:\n   Num:    Value          Size Type    Bind   Vis      Ndx Name\n"
                "     1: 0000000000002000     4 FUNC    LOCAL  DEFAULT   14 local\n")
        done = subprocess.CompletedProcess([], 0, text, "")
        with unittest.mock.patch.object(subprocess, "run", return_value=done):
            self.assertEqual(function_symbols(Path("binary")), {0x2000: (["local"], 4)})

    def test_gcc_gives_the_cold_part_of_a_split_function_a_symbol_of_its_own(self):
        starts = fixture_starts("cold.gcc.O2.syms.txt")
        self.assertEqual((starts[0x13E0][0], starts[0x1180][0]), (["must_alloc"], ["must_alloc.cold"]))


class PlacementTests(unittest.TestCase):
    """A function's address is its entry, and it is placed only where a FUNC symbol of the binary starts."""

    def test_a_split_function_is_placed_at_the_start_of_its_hot_part(self):
        # src/cold.c: `must_alloc` has DW_AT_ranges (hot 0x13e0, cold 0x1180) and no DW_AT_low_pc.
        starts = fixture_starts("cold.gcc.O2.syms.txt")
        for name in ("cold.gcc.O2.txt", "cold.gcc.O2.dwarf4.txt"):
            with self.subTest(name=name):
                placed, unplaced = fixture_dwarf(name).placed(starts)
                self.assertEqual({sub.name: sub.low_pc for sub in placed},
                                 {"main": 0x11A0, "checked_div": 0x1370, "sum_bytes": 0x13B0, "must_alloc": 0x13E0})
                self.assertEqual(unplaced, [])

    def test_clang_lists_the_entry_of_a_basic_block_section_function_last_and_no_fragment_is_placed(self):
        # `clang -O2 -fbasic-block-sections=all` on src/cold.c: the first range of each list is a fragment (NOTYPE
        # `checked_div.__part.1`) and the entry `checked_div` (FUNC, 0x11c0) is the list's last range.
        dwarf = fixture_dwarf("cold.clang.O2.bbs.txt")
        starts = fixture_starts("cold.clang.O2.bbs.syms.txt")
        self.assertEqual(dwarf.ranges[0x24], (0x11CD,))
        placed, unplaced = dwarf.placed(starts)
        self.assertEqual(placed, [])
        self.assertEqual([(gone.name, gone.why) for gone in unplaced],
                         [(name, NO_FUNC_START) for name in ("checked_div", "main", "must_alloc", "sum_bytes")])

    def test_the_rnglistx_form_of_a_range_is_read_and_still_needs_a_function_symbol(self):
        # `DW_AT_ranges : (rnglistx) (index: 0): 0x24` is the offset 0x24 of the list.
        dwarf = fixture_dwarf("cold.clang.O2.bbs.txt")
        self.assertEqual(dwarf.index[0x95].attrs["DW_AT_ranges"], "(index: 0): 0x24")
        placed, _ = dwarf.placed({0x11CD: (["checked_div"], 6)})
        self.assertEqual([(sub.name, sub.low_pc) for sub in placed], [("checked_div", 0x11CD)])

    def test_subprograms_still_lists_the_functions_that_have_a_low_pc(self):
        names = [sub.name for sub in fixture_dwarf("cold.gcc.O2.txt").subprograms()]
        self.assertEqual(names, ["main", "checked_div", "sum_bytes"])

    def test_code_a_linker_discarded_is_unplaced_because_no_function_symbol_starts_at_its_address(self):
        # src/gcsect.c with -ffunction-sections -Wl,--gc-sections: `never_called` keeps DW_AT_low_pc 0.
        placed, unplaced = fixture_dwarf("gcsect.O2.txt").placed({0x1060: (["main"], 1), 0x1180: (["used_sum"], 1)})
        self.assertEqual([(sub.name, sub.low_pc) for sub in placed], [("main", 0x1060), ("used_sum", 0x1180)])
        self.assertEqual([(gone.name, gone.why) for gone in unplaced], [("never_called", NO_FUNC_START)])
        self.assertEqual(len(fixture_dwarf("gcsect.O2.txt").subprograms()), 3)

    def graph(self, *dies: Die, ranges: dict | None = None) -> Dwarf:
        unit = Die(0x10, "DW_TAG_compile_unit", 0, attrs={"DW_AT_name": "t.c"})
        for die in dies:
            unit.children.append(die)
        index = {unit.offset: unit, **{die.offset: die for die in dies}}
        return Dwarf([unit], index, ranges or {})

    def function(self, offset: int, forms: dict[str, str] | None = None, **attrs: str) -> Die:
        """A subprogram DIE; its `DW_AT_ranges` is a `sec_offset`, as readelf names it, unless `forms` says otherwise."""
        forms = {**({"DW_AT_ranges": "sec_offset"} if "DW_AT_ranges" in attrs else {}), **(forms or {})}
        return Die(offset, "DW_TAG_subprogram", 1, attrs={"DW_AT_name": f"f{offset:x}", **attrs}, forms=forms)

    def entry_of(self, forms: dict[str, str] | None = None, starts=None, **attrs: str) -> tuple[int | None, str]:
        dwarf = self.graph(self.function(0x40, forms, **attrs),
                           ranges={0: (0x1000,), 0x2C: (0x13E0,), 0x50: (0x1000, 0x2000), 0x60: ()})
        placed, unplaced = dwarf.placed(AnyAddress() if starts is None else starts)
        return (placed[0].low_pc, "") if placed else (None, unplaced[0].why)

    def test_the_entry_pc_comes_before_the_low_pc_and_the_ranges(self):
        self.assertEqual(self.entry_of(DW_AT_entry_pc="0x1380", DW_AT_low_pc="0x1000"),
                         (None, "its DW_AT_entry_pc is an offset from a base, not an address"))
        self.assertEqual(self.entry_of({"DW_AT_entry_pc": "addr"}, DW_AT_entry_pc="0x1380", DW_AT_low_pc="0x1000",
                                       DW_AT_ranges="0x2c"), (0x1380, ""))
        self.assertEqual(self.entry_of({"DW_AT_entry_pc": "addrx"}, DW_AT_entry_pc="(index: 0x3): 0x1380", DW_AT_ranges="0x2c"),
                         (0x1380, ""))

    def test_an_entry_pc_that_is_an_offset_or_not_a_number_is_unplaced(self):
        for form in ("data1", "data8", "sec_offset"):
            with self.subTest(form=form):
                self.assertEqual(self.entry_of({"DW_AT_entry_pc": form}, DW_AT_entry_pc="4", DW_AT_low_pc="0x1000"),
                                 (None, "its DW_AT_entry_pc is an offset from a base, not an address"))
        self.assertEqual(self.entry_of({"DW_AT_entry_pc": "addr"}, DW_AT_entry_pc="zz", DW_AT_low_pc="0x1000"),
                         (None, "its DW_AT_entry_pc is not an address"))

    def test_the_low_pc_is_the_entry_of_a_function_without_an_entry_pc(self):
        self.assertEqual(self.entry_of(DW_AT_low_pc="0x1180", DW_AT_ranges="0x2c"), (0x1180, ""))
        self.assertEqual(self.entry_of(DW_AT_low_pc="(index: 0x2): 0x1190"), (0x1190, ""))
        self.assertEqual(self.entry_of(DW_AT_low_pc="zz"), (None, "its DW_AT_low_pc is not an address"))

    def test_the_first_range_is_the_entry_of_a_function_with_ranges_only(self):
        self.assertEqual(self.entry_of(DW_AT_ranges="0x2c"), (0x13E0, ""))
        for form in ("data4", "data8"):  # DWARF 2 and 3 write the offset of a range list as a constant
            with self.subTest(form=form):
                self.assertEqual(self.entry_of({"DW_AT_ranges": form}, DW_AT_ranges="0x2c"), (0x13E0, ""))
        self.assertEqual(self.entry_of(DW_AT_ranges="(index: 0x3): 0x2c"), (0x13E0, ""))
        for ranges in ("0x60", "0x99", "zz", "0x50", ""):
            with self.subTest(ranges=ranges):
                self.assertEqual(self.entry_of(DW_AT_ranges=ranges), (None, "its DW_AT_ranges list has no one readable first range"))

    def test_an_entry_from_any_attribute_is_placed_only_at_the_start_of_a_function_symbol(self):
        for forms, attrs in (({}, {"DW_AT_low_pc": "0x1180"}),
                             ({"DW_AT_entry_pc": "addr"}, {"DW_AT_entry_pc": "0x1380", "DW_AT_low_pc": "0x1000"}),
                             ({}, {"DW_AT_ranges": "0x2c"})):
            address = {"DW_AT_low_pc": 0x1180, "DW_AT_entry_pc": 0x1380, "DW_AT_ranges": 0x13E0}[next(iter(attrs))]
            with self.subTest(attrs=attrs):
                self.assertEqual(self.entry_of(forms, {address: (["f"], 1)}, **attrs), (address, ""))
                self.assertEqual(self.entry_of(forms, {address + 1: (["f"], 1)}, **attrs), (None, NO_FUNC_START))
                self.assertEqual(self.entry_of(forms, {}, **attrs), (None, NO_FUNC_START))

    def test_a_list_whose_entry_is_not_its_first_range_is_not_placed_at_the_first_range(self):
        # The entry 0x2000 is the list's last range; the first, 0x13e0, is a fragment no function symbol starts.
        self.assertEqual(self.entry_of(starts={0x2000: (["f"], 1)}, DW_AT_ranges="0x2c"), (None, NO_FUNC_START))

    def test_an_address_a_linker_discarded_is_no_function_start(self):
        for address in (0, 1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
            for forms, attrs in (({}, {"DW_AT_low_pc": hex(address)}),
                                 ({"DW_AT_entry_pc": "addr"}, {"DW_AT_entry_pc": hex(address), "DW_AT_low_pc": "0x1000"})):
                with self.subTest(address=address, attrs=attrs):
                    self.assertEqual(self.entry_of(forms, {0x1000: (["f"], 1)}, **attrs), (None, NO_FUNC_START))
        dwarf = self.graph(self.function(0x40, DW_AT_ranges="0x2c"), ranges={0x2C: (0,)})
        self.assertEqual(dwarf.placed({0x13E0: (["f"], 1)})[1][0].why, NO_FUNC_START)

    def test_an_import_is_no_function_start_so_a_tombstone_at_zero_stays_unplaced(self):
        # Every dynamic binary's .symtab lists its imports as FUNC symbols of the undefined section, at value 0.
        starts = fixture_starts("cold.gcc.O2.syms.txt")
        self.assertEqual(self.entry_of(starts=starts, DW_AT_low_pc="0"), (None, NO_FUNC_START))

    def test_an_entry_outside_the_loaded_code_is_code_the_linker_discarded_and_has_no_code(self):
        # statics.a64.O0.x: headers to 0x238, then file bytes to 0xe88; data from 0x1fd78 to 0x20010.
        code = fixture_code("statics.a64.O0.x")
        for address, why, has_code in ((0, DISCARDED, False), (0xFFFFFFFFFFFFFFFF, DISCARDED, False),
                                       (0xFFFFFFFE, DISCARDED, False), (0x237, DISCARDED, False), (0xE88, DISCARDED, False),
                                       (0x1FD77, DISCARDED, False), (0x20010, DISCARDED, False),
                                       (0x238, NO_FUNC_START, True), (0xE87, NO_FUNC_START, True),
                                       (0x1FD78, NO_FUNC_START, True), (0x2000F, NO_FUNC_START, True)):
            with self.subTest(address=address):
                _, unplaced = self.graph(self.function(0x40, DW_AT_low_pc=hex(address))).placed({}, code)
                self.assertEqual((unplaced[0].why, unplaced[0].code), (why, has_code))
        dwarf = self.graph(self.function(0x40, DW_AT_ranges="0x2c"), ranges={0x2C: (0,)})
        self.assertEqual(dwarf.placed({}, code)[1][0].code, False)

    def test_an_entry_that_starts_a_function_symbol_is_placed_whatever_the_sections_say(self):
        placed, _ = self.graph(self.function(0x40, DW_AT_low_pc="0x10")).placed({0x10: (["f"], 1)}, [range(0x700, 0xB98)])
        self.assertEqual([sub.low_pc for sub in placed], [0x10])

    def test_without_the_sections_every_unplaced_function_has_code(self):
        # No section table is no proof of discarded code: every unplaced function then counts in the floor.
        for attrs in ({"DW_AT_low_pc": "0"}, {"DW_AT_low_pc": "0x1180"}, {"DW_AT_ranges": "0x60"},
                      {"DW_AT_entry_pc": "4", "DW_AT_low_pc": "0"}):
            with self.subTest(attrs=attrs):
                _, unplaced = self.graph(self.function(0x40, **attrs), ranges={0x60: ()}).placed({})
                self.assertEqual(unplaced[0].code, True)

    def test_an_entry_the_dwarf_does_not_state_as_one_address_has_code_whatever_the_sections_say(self):
        code = [range(0x700, 0xB98)]
        for forms, attrs in (({}, {"DW_AT_ranges": "0x60"}), ({"DW_AT_entry_pc": "data1"}, {"DW_AT_entry_pc": "4", "DW_AT_low_pc": "0"}),
                             ({}, {"DW_AT_low_pc": "zz"})):
            with self.subTest(attrs=attrs):
                _, unplaced = self.graph(self.function(0x40, forms, **attrs), ranges={0x60: ()}).placed({}, code)
                self.assertNotEqual(unplaced[0].why, DISCARDED)
                self.assertEqual(unplaced[0].code, True)

    def test_a_die_without_code_is_in_neither_list(self):
        declaration = self.function(0x40, DW_AT_declaration="1")
        abstract = self.function(0x50, DW_AT_inline="3")
        placed, unplaced = self.graph(declaration, abstract).placed(AnyAddress())
        self.assertEqual((placed, unplaced), ([], []))

    def test_an_unplaced_function_takes_its_name_from_its_origin(self):
        origin = Die(0x30, "DW_TAG_subprogram", 1, attrs={"DW_AT_name": "real_name"})
        clone = Die(0x40, "DW_TAG_subprogram", 1, attrs={"DW_AT_abstract_origin": "<0x30>", "DW_AT_low_pc": "0"})
        _, unplaced = self.graph(origin, clone).placed({0x1000: (["real_name"], 1)})
        self.assertEqual([(gone.name, gone.offset) for gone in unplaced], [("real_name", 0x40)])

    def test_a_function_with_no_ranges_value_is_not_placed_by_the_list_at_offset_zero(self):
        dwarf = self.graph(Die(0x40, "DW_TAG_subprogram", 1, attrs={"DW_AT_name": "f", "DW_AT_ranges": "zz"}),
                           ranges={0: (0x1000,)})
        placed, unplaced = dwarf.placed(AnyAddress())
        self.assertEqual((placed, [gone.why for gone in unplaced]), ([], ["its DW_AT_ranges list has no one readable first range"]))

    def test_an_out_of_line_copy_takes_its_name_from_its_origin_and_is_an_instance(self):
        origin = Die(0x30, "DW_TAG_subprogram", 1, attrs={"DW_AT_name": "real_name", "DW_AT_external": "1"})
        clone = Die(0x40, "DW_TAG_subprogram", 1, attrs={"DW_AT_abstract_origin": "<0x30>", "DW_AT_low_pc": "0x1000"})
        placed, _ = self.graph(origin, clone).placed(AnyAddress())
        self.assertEqual([(sub.name, sub.low_pc, sub.instance, sub.external) for sub in placed],
                         [("real_name", 0x1000, True, True)])

    def test_a_function_carries_the_producer_of_its_unit(self):
        gcc, _ = fixture_dwarf("cold.gcc.O2.txt").placed(AnyAddress())
        self.assertTrue(all(sub.producer.startswith("GNU C17 13.3.0 -mtune=generic") for sub in gcc))
        # readelf 2.42 cannot read the strx producer of a clang DWARF 5 unit, which is not a producer to trust either.
        clang, _ = fixture_dwarf("cold.clang.O2.bbs.txt").placed(AnyAddress())
        self.assertEqual({sub.producer for sub in clang}, {"error"})
        self.assertEqual(self.graph(self.function(0x40, DW_AT_low_pc="0x1000")).placed(AnyAddress())[0][0].producer, "")

    def test_a_function_that_names_itself_is_no_instance(self):
        plain = self.function(0x40, DW_AT_low_pc="0x1000")
        placed, _ = self.graph(plain).placed(AnyAddress())
        self.assertFalse(placed[0].instance)

    def test_a_declaration_it_realises_makes_a_function_an_instance_as_well(self):
        declaration = Die(0x30, "DW_TAG_subprogram", 1, attrs={"DW_AT_name": "f", "DW_AT_declaration": "1"})
        definition = Die(0x40, "DW_TAG_subprogram", 1, attrs={"DW_AT_specification": "<0x30>", "DW_AT_low_pc": "0x1000"})
        placed, _ = self.graph(declaration, definition).placed(AnyAddress())
        self.assertEqual([(sub.name, sub.instance) for sub in placed], [("f", True)])

    def test_prototyped_is_the_flag_of_the_function_itself(self):
        yes = self.function(0x40, DW_AT_low_pc="0x1000", DW_AT_prototyped="1")
        no = self.function(0x50, DW_AT_low_pc="0x2000")
        placed, _ = self.graph(yes, no).placed(AnyAddress())
        self.assertEqual([(sub.low_pc, sub.prototyped) for sub in placed], [(0x1000, True), (0x2000, False)])

    def test_the_lists_come_back_in_address_and_name_order(self):
        dies = [self.function(0x40, DW_AT_low_pc="0x3000"), self.function(0x50, DW_AT_low_pc="0x1000"),
                self.function(0x60, DW_AT_low_pc="0"), self.function(0x70, DW_AT_low_pc="0")]
        dies[2].attrs["DW_AT_name"], dies[3].attrs["DW_AT_name"] = "zeta", "alpha"
        placed, unplaced = self.graph(*dies).placed({0x1000: (["f"], 1), 0x3000: (["f"], 1)})
        self.assertEqual([sub.low_pc for sub in placed], [0x1000, 0x3000])
        self.assertEqual([gone.name for gone in unplaced], ["alpha", "zeta"])

    def test_readelf_names_the_form_of_an_attribute(self):
        text = ("Contents of the .debug_info section:\n <0><c>: Abbrev Number: 1 (DW_TAG_compile_unit)\n"
                " <1><2a>: Abbrev Number: 6 (DW_TAG_subprogram)\n"
                "    <2b>   DW_AT_name        : (strp) (offset: 0x23): f\n"
                "    <2f>   DW_AT_entry_pc    : (addr) 0x11e3\n"
                "    <2f>   DW_AT_decl_line   : (data1) 7\n"
                "    <2f>   DW_AT_entry_pc    : (data1) 4\n"
                "    <2f>   DW_AT_external    : 1\n")
        _, index = parse_readelf(text)
        die = index[0x2A]
        self.assertEqual(die.forms, {"DW_AT_name": "strp", "DW_AT_entry_pc": "addr", "DW_AT_decl_line": "data1"})
        self.assertEqual(die.attrs["DW_AT_entry_pc"], "0x11e3")  # the first of two, with its own form
        self.assertNotIn("DW_AT_external", die.forms)

    def test_the_reader_asks_readelf_for_the_ranges_beside_the_info(self):
        completed = subprocess.CompletedProcess([], 0, (DWARF_FIXTURES / "cold.gcc.O2.txt").read_text(), "")
        with unittest.mock.patch.object(subprocess, "run", return_value=completed) as run:
            dwarf = Dwarf.read(Path("some binary"), dataclasses.replace(X86_64, binutils_prefix="g"))
        # `--debug-dump=no-follow-links` named clang's units `u clang version 18.1.3`: binutils 2.42 then reads
        # `strx` strings without the unit's offsets base, and every clang function left the equivalence population.
        self.assertEqual(run.call_args.args[0], ["greadelf", "--wide", "--debug-dump=info", "--debug-dump=Ranges",
                                                 "some binary"])
        self.assertEqual(dwarf.ranges[0x2C], (0x13E0,))
        failed = subprocess.CompletedProcess([], 1, "", "no such file")
        with unittest.mock.patch.object(subprocess, "run", return_value=failed), self.assertRaises(RuntimeError):
            Dwarf.read(Path("some binary"))

    def test_a_vector_type_is_not_an_array_to_the_type_model(self):
        vector = Die(0x30, "DW_TAG_array_type", 1, attrs={"DW_AT_GNU_vector": "1", "DW_AT_byte_size": "16"})
        array = Die(0x40, "DW_TAG_array_type", 1, attrs={"DW_AT_byte_size": "16"})
        dwarf = Dwarf([], {0x30: vector, 0x40: array})
        self.assertEqual((dwarf.type(0x30).kind, dwarf.type(0x30).reason), ("unsupported", "vector type"))
        self.assertEqual(dwarf.type(0x40).kind, "array")


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
        self.assertEqual([p.register for p in specs["st_many_int"].params[5:]],
                         ["r9", "stack0", "stack1", "stack2", "stack3"])


@unittest.skipUnless(CAN_BUILD_AARCH64, _AARCH64_BUILD)
class AArch64DwarfTests(unittest.TestCase):
    """AAPCS64: eight integer registers, eight vector registers, then stack words."""

    def test_the_fixture_signatures_read_back_under_aapcs64(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = selftest.build_fixture(AARCH64.rendering_cc, Path(tmp), AARCH64)
            dwarf = Dwarf.read(binary, AARCH64)
            functions = [s for s in dwarf.subprograms() if s.name]
            specs = {s.name: call_spec(dwarf, s, functions, AARCH64.abi) for s in functions}
        self.assertEqual(specs["st_add"].describe(), "int st_add(int a@x0, int b@x1)")
        self.assertEqual(specs["st_scale"].describe(),
                         "double st_scale(double const* v@x0, int n@x1)")
        self.assertEqual([p.register for p in specs["st_many"].params[5:]], ["x5", "x6", "x7"])
        self.assertEqual([p.register for p in specs["st_many_int"].params[6:]],
                         ["x6", "x7", "stack0", "stack1"])
        self.assertEqual([p.register for p in specs["st_many_fp"].params[7:]], ["v7", "stack0"])
        self.assertEqual(specs["st_cosine"].params[0].register, "v0")


@unittest.skipUnless(CAN_BUILD_AARCH64, _AARCH64_BUILD)
class AArch64ObjectLinkTests(unittest.TestCase):
    """AArch64's object links are bound by the loader, so what it would capture is refused."""

    def test_an_object_link_the_loader_would_bind_elsewhere_is_named(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = selftest.build_fixture(AARCH64.rendering_cc, Path(tmp), AARCH64)
            runtime = link.build_runtime(AARCH64.rendering_cc, HERE / "rt", Path(tmp) / "rt",
                                         AARCH64)
            symbols = selftest._all_symbols(binary, AARCH64)
            # The program exports stderr (copied into it from libc for st_first).
            program_stderr = next(address for name, address in symbols.items()
                                  if name.split("@", 1)[0] == "stderr")

            def conflicts(*objects):
                return link.loader_conflicts(list(objects), str(binary), str(runtime), AARCH64)

            self.assertEqual(conflicts(("st_counter", symbols["st_counter"]),
                                       ("stderr", program_stderr)), [])
            moved = conflicts(("stderr", program_stderr + 8))
            self.assertEqual(len(moved), 1)
            self.assertIn("the program's own `stderr`", moved[0])
            library = conflicts(("environ", symbols["st_counter"]))
            self.assertEqual(len(library), 1)
            self.assertIn("`environ` of libc.so.6", library[0])


class _SelfTestCases(_OnTarget):
    """The gate's precondition: every known verdict comes back."""

    def test_every_case_gets_its_known_verdict(self):
        target = self.TARGET
        with tempfile.TemporaryDirectory() as tmp:
            runtime = link.build_runtime(target.rendering_cc, HERE / "rt",
                                         Path(tmp) / target.directory("rt"), target)
            config = gate.Config(runtime=runtime, cc=target.rendering_cc, target=target)
            outcomes = selftest.run_self_tests(config, Path(tmp) / "selftest")
        misses = [f"{o.case.name}: {o.why}" for o in outcomes if not o.ok]
        self.assertEqual(misses, [])
        self.assertEqual(len(outcomes), len(selftest.CASES))


@unittest.skipUnless(CAN_RUN, "runtime equivalence needs x86-64 Linux and gcc")
class SelfTestSuite(_SelfTestCases, unittest.TestCase):
    pass


@unittest.skipUnless(CAN_RUN_AARCH64, _AARCH64_RUN)
class AArch64SelfTestSuite(_SelfTestCases, unittest.TestCase):
    TARGET = AARCH64


@unittest.skipUnless(CAN_RUN_WIN64, _WIN64_RUN)
class Win64SelfTestSuite(_SelfTestCases, unittest.TestCase):
    """The fixture as clang-cl's PE, mapped into the Linux runtime (rt/pe_win64.c)."""

    TARGET = WIN64


def _security_cookie(binary: Path) -> int | None:
    """IMAGE_LOAD_CONFIG_DIRECTORY64.SecurityCookie (offset 0x58), where the PE states one."""
    data = binary.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    sections, optional_size = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from(
        "<H", data, pe + 20)[0]
    optional = pe + 24
    base = struct.unpack_from("<Q", data, optional + 24)[0]
    rva, size = struct.unpack_from("<II", data, optional + 112 + 10 * 8)
    if size < 0x60:
        return None
    for index in range(sections):
        header = optional + optional_size + 40 * index
        vsize, start, _, raw = struct.unpack_from("<IIII", data, header + 8)
        if start <= rva + 0x58 < start + vsize:
            cookie = struct.unpack_from("<Q", data, raw + rva + 0x58 - start)[0]
            return cookie - base if cookie else None
    return None


@unittest.skipUnless(CAN_RUN_WIN64, _WIN64_RUN)
class Win64BuildTests(unittest.TestCase):
    def test_a_pe_imports_ucrt_carries_its_cookie_and_strips_to_the_same_addresses(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = build.build(HERE / "selftest" / "fixture.c", "clang-cl", "O1", Path(tmp),
                                 WIN64)
            self.assertIsNone(binary.error)
            self.assertEqual(build.machine_of(binary.stripped, WIN64), "pei-x86-64")
            headers = [subprocess.run(["objdump", "-h", str(path)], capture_output=True,
                                      text=True, check=True).stdout
                       for path in (binary.unstripped, binary.stripped)]
            private = subprocess.run(["objdump", "-p", str(binary.unstripped)],
                                     capture_output=True, text=True, check=True).stdout
            dwarf = Dwarf.read(binary.unstripped, WIN64)
            cookie = _security_cookie(binary.unstripped)
            slots = WIN64.import_slots(binary.unstripped)
        sections = [line.split()[1:4] for line in headers[1].splitlines()
                    if line.strip()[:1].isdigit()]
        self.assertTrue(sections)
        for section in sections:
            self.assertIn(" ".join(section), " ".join(headers[0].split()))
        self.assertNotIn(".debug_", headers[1])
        self.assertIn("api-ms-win-crt-stdio-l1-1-0.dll", private)
        self.assertIn("__stdio_common_vfprintf", private)
        self.assertIsNotNone(cookie)
        functions = {s.name: s for s in dwarf.subprograms() if s.name}
        self.assertGreater(functions["st_add"].size, 0)
        self.assertTrue(slots)


class _PipelineCases(_OnTarget):
    """The whole gate over the self-test fixture, with r2s replaced by the stub.

    Built with GCC at -O0 and -O2 and stripped, asked through the batch runner,
    compiled, linked, run and compared: the self-test renderings keep their
    known verdicts end to end, and a rendering that hands its work back to the
    original is never equal.
    """

    FUNCTIONS = 22  # twenty-one functions and main, per level

    def run_gate(self, tmp: Path, *extra: str, **env: str) -> tuple[int, dict]:
        # --out is given relative to the working directory, as a person types
        # it: the runtime runs elsewhere and must be handed absolute paths.
        tmp.mkdir(parents=True, exist_ok=True)
        argv = ["--r2s", str(STUB), "--sources", str(HERE / "selftest" / "fixture.c"),
                "--target", self.TARGET.name,
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
        self.assertEqual(sum(s == "equal" for s in got.values()), 2 * 17)
        configs = {key.split("::")[1] for key in records}
        self.assertEqual(configs, {self.TARGET.config("gcc", opt) for opt in ("O0", "O2")})

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

    def test_instructions_are_counted_where_the_host_can_and_refused_where_it_cannot(self):
        with tempfile.TemporaryDirectory() as tmp_text:
            tmp = Path(tmp_text)
            if self.TARGET.emulated():
                try:
                    cost.qemu_plugin(self.TARGET, tmp / "probe")
                except cost.CostRefused:
                    cwd = os.getcwd()
                    os.chdir(tmp)
                    try:
                        code = run_equiv.main(["--measure", "instructions", "--target",
                                               self.TARGET.name, "--out", "out"])
                    finally:
                        os.chdir(cwd)
                    self.assertEqual(code, run_equiv.EXIT_SETUP)
                    return
            else:
                reason = cost.probe()
                if reason:
                    self.skipTest(reason)
            written = []
            for _ in range(2):
                _, records = self.run_gate(tmp, "--opts", "O2", "--measure", "instructions",
                                           STUB_R2S_MODE="delegate", STUB_R2S_FAULTS="")
                written.append((tmp / "out" / "records.json").read_bytes())
            self.assertEqual(written[0], written[1])
            self.assertEqual({r["cost"]["measure"] for r in records.values()}, {"instructions"})
            self.assertEqual(json.loads(written[0])["config"]["cost"]["budget"],
                             cost.DEFAULT_INSTRUCTIONS)

    def test_a_crash_is_one_record_and_the_ratchet_sees_it(self):
        with tempfile.TemporaryDirectory() as tmp_text:
            tmp = Path(tmp_text)
            code, first = self.run_gate(tmp / "first", "--opts", "O2", STUB_R2S_MODE="fixture",
                                        STUB_R2S_FAULTS="")
            clamp = next(r for k, r in first.items() if k.endswith("gcc-O2::st_clamp"))
            baseline = tmp / "baseline.json"
            cause = {"owner": "GT", "site": "tests/equiv/selftest.py",
                     "cause": "The self-test rendering for this function is known to end so."}
            baseline.write_text(json.dumps({"schema": 3,
                                            "cost": cost.resolve("time", self.TARGET).to_json(),
                                            "records": {
                k: {"status": r["status"],
                    "compared": gate.trap_comparison(r["status"], r["vectors"]),
                    **(cause if r["status"] != "equal" else {})}
                for k, r in first.items()}}))
            # The baseline holds the first run, so the crash is the one departure.
            self.assertEqual(gate.ratchet(json.loads(baseline.read_text()), {
                k: (r["status"], None, gate.trap_comparison(r["status"], r["vectors"]))
                for k, r in first.items()}), [])
            code, records = self.run_gate(
                tmp / "second", "--opts", "O2", "--baseline", str(baseline),
                STUB_R2S_MODE="fixture", STUB_R2S_FAULTS=f"abort@{clamp['address'][2:]}")
        self.assertEqual(code, run_equiv.EXIT_RATCHET)
        crashed = records[clamp["key"]]
        self.assertEqual(crashed["status"], "no-record")
        self.assertIn("SIGABRT", crashed["evidence"]["cause"])
        self.assertEqual({k: r["status"] for k, r in records.items() if k != clamp["key"]},
                         {k: r["status"] for k, r in first.items() if k != clamp["key"]})


@unittest.skipUnless(CAN_RUN, "runtime equivalence needs x86-64 Linux and gcc")
class PipelineTests(_PipelineCases, unittest.TestCase):
    pass


@unittest.skipUnless(CAN_RUN_AARCH64, _AARCH64_RUN)
class AArch64PipelineTests(_PipelineCases, unittest.TestCase):
    TARGET = AARCH64


if __name__ == "__main__":
    unittest.main()
