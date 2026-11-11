#!/usr/bin/env python3
"""Unit tests for the void-soundness gate and its generator. Pure Python: no compiler, no r2s."""

from __future__ import annotations

import json
import pathlib
import re
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import gen_void_adversaries as gen  # noqa: E402
import void_soundness as gate  # noqa: E402

BUILD = gate.Build("d", "gcc", "O2")


class Types(unittest.TestCase):
    def test_the_return_type_is_what_precedes_the_name(self) -> None:
        self.assertEqual(gate.return_type("void p_d_forward(int64_t arg0)"), "void")
        self.assertEqual(gate.return_type("struct pl p_pl_compute(long x)"), "struct pl")
        self.assertEqual(gate.return_type("static double p(void)"), "double")
        self.assertIsNone(gate.return_type(None))


class Verdicts(unittest.TestCase):
    manifest = {"p_read": {"read": True}, "p_ignored": {"read": False}}

    def judged(self, rendered: dict[str, str | None]) -> list[gate.Verdict]:
        truth = {"p_read": "double", "p_ignored": "double"}
        return gate.judge(BUILD, self.manifest, truth, rendered)

    def test_a_read_result_rendered_void_is_a_false_void(self) -> None:
        verdicts = self.judged({"p_read": "void", "p_ignored": "void"})
        self.assertEqual([v.function for v in verdicts if v.false_void], ["p_read"])

    def test_an_unread_result_rendered_void_is_premised_not_false(self) -> None:
        verdicts = self.judged({"p_read": "double", "p_ignored": "void"})
        self.assertEqual([v.function for v in verdicts if v.premised_void], ["p_ignored"])
        self.assertFalse(any(v.false_void for v in verdicts))

    def test_a_source_void_is_never_a_false_void(self) -> None:
        verdict = gate.Verdict(BUILD, "p", "void", "void", True)
        self.assertFalse(verdict.false_void)

    def test_a_function_r2s_did_not_render_is_not_judged_void(self) -> None:
        verdicts = self.judged({"p_read": None})
        self.assertFalse(any(v.false_void for v in verdicts))


class Externs(unittest.TestCase):
    """A caller's declaration of a read function: `void` there is the false void the header gate misses."""
    named = {0x1379: "p_f3_chain_c", 0x138F: "c_f3_chain_c", 0x1149: "p_f3_inner"}
    code = """r2sleigh_result_u64 fcn_138f(uint64_t arg0)
{
    void fcn_1379(uint64_t);
    double fcn_1149(uint64_t);
    void* fcn_1379(uint64_t);

    /* r2dec proof: ... */
    {
        fcn_1379(arg0);
        return fcn_1379(arg0);
        r2sleigh_residual_void(1); /* r2dec gap: CallNotRendered at 0x138f:15 covering 1 op (render::values): call to fcn_1149: why */
    }
}"""

    def rows(self, read=("p_f3_chain_c", "p_f3_inner")) -> list[gate.Extern]:
        return gate.externs_of(BUILD, "c_f3_chain_c", self.code, self.named, set(read))

    def test_a_void_extern_of_a_read_function_is_a_false_void(self) -> None:
        rows = self.rows()
        self.assertEqual([(r.callee, r.rendered) for r in rows],
                         [("p_f3_chain_c", "void"), ("p_f3_inner", "double"), ("p_f3_chain_c", "void*"),
                          ("p_f3_inner", None)])
        self.assertEqual([r.callee for r in rows if r.false_void], ["p_f3_chain_c"])

    def test_a_function_no_caller_reads_is_not_graded(self) -> None:
        self.assertEqual([r.callee for r in self.rows(read=("p_f3_inner",))], ["p_f3_inner", "p_f3_inner"])

    def test_a_void_extern_fails_the_gate_and_a_refused_call_does_not(self) -> None:
        verdict = gate.Verdict(BUILD, "p_f3_chain_c", "struct f3", "r2sleigh_result_u64", True)
        void = gate.Extern(BUILD, "c_f3_chain_c", "p_f3_chain_c", "void")
        refused = gate.Extern(BUILD, "c_f3_chain_c", "p_f3_chain_c", None)
        self.assertEqual(gate.outcome([verdict], [], [], set(), [void])[1], 1)
        self.assertEqual(gate.outcome([verdict], [], [], set(), [refused])[1], 0)

    def test_too_few_extern_rows_fail(self) -> None:
        manifest = {"d.c": {f"p_{n}": {"read": True, "returns": "double"} for n in range(10)}}
        rows = [gate.Extern(BUILD, "c", f"p_{n}", "double") for n in range(9)]
        self.assertEqual(gate.extern_floors(rows, manifest, [BUILD]), [])
        self.assertEqual(len(gate.extern_floors(rows[:8], manifest, [BUILD])), 1)


class Floors(unittest.TestCase):
    manifest = {"d.c": {"p_a": {"read": True}, "p_b": {"read": True}, "p_c": {"read": False}},
                "f.c": {"p_f": {"read": True}}}

    def verdict(self, build: gate.Build, name: str) -> gate.Verdict:
        return gate.Verdict(build, name, "double", "double", name != "p_c")

    def test_a_build_with_a_function_unjudged_is_short(self) -> None:
        # p_b folded into p_a in the O2 build: one function of three has no verdict there
        o1, o2 = gate.Build("d", "gcc", "O1"), BUILD
        verdicts = [self.verdict(o1, n) for n in ("p_a", "p_b", "p_c")] + [self.verdict(o2, n) for n in ("p_a", "p_c")]
        self.assertEqual(gate.floors(verdicts, self.manifest, [o1, o2]),
                         ["d.gcc.O2: no verdict for 1 of 3 functions (p_b)"])

    def test_one_build_judging_every_function_does_not_cover_another(self) -> None:
        o1, o2 = gate.Build("d", "gcc", "O1"), BUILD
        verdicts = [self.verdict(o1, n) for n in ("p_a", "p_b", "p_c")] * 2
        self.assertEqual(len(gate.floors(verdicts, self.manifest, [o1, o2])), 1)

    def test_a_problem_names_one_build_and_not_the_build_whose_name_it_begins(self) -> None:
        jobs = [gate.Build("d", "gcc", "O2"), gate.Build("d", "gcc", "O2", "avx2"), gate.Build("f", "gcc", "O2")]
        problems = ["d.gcc.O2.avx2: does not compile"]
        self.assertEqual(gate.scored_builds(jobs, problems), [jobs[0], jobs[2]])
        self.assertEqual(gate.scored_builds(jobs, []), jobs)

    def test_a_build_is_named_by_its_isa_when_it_has_one(self) -> None:
        self.assertEqual(str(gate.Build("d", "gcc", "O2")), "d.gcc.O2")
        self.assertEqual(str(gate.Build("d", "gcc", "O2", "avx2")), "d.gcc.O2.avx2")
        self.assertEqual(gate.Build("d", "gcc", "O2", "avx2").flags(), ["-mavx2", "-mfma"])
        self.assertEqual(gate.Build("d", "gcc", "O2").flags(), [])


class Exits(unittest.TestCase):
    """Each exit of the gate's main(), by the pure functions it returns."""

    def row(self, function: str, rendered: str | None, read: bool = True, build: gate.Build = BUILD) -> gate.Verdict:
        return gate.Verdict(build, function, "double", rendered, read)

    def code(self, verdicts, problems=(), short=(), known=()) -> int:
        return gate.outcome(list(verdicts), list(problems), list(short), set(known))[1]

    def test_a_sound_run_exits_0(self) -> None:
        self.assertEqual(self.code([self.row("p_a", "double")]), 0)

    def test_a_new_false_void_exits_1(self) -> None:
        self.assertEqual(self.code([self.row("p_a", "void")]), 1)

    def test_a_known_false_void_licenses_its_build_alone(self) -> None:
        self.assertEqual(self.code([self.row("p_a", "void")], known={"d.gcc.O2/p_a"}), 0)
        other = gate.Build("d", "clang", "O2")
        self.assertEqual(self.code([self.row("p_a", "void", build=other)], known={"d.gcc.O2/p_a"}), 1)

    def test_a_stale_entry_of_a_judged_build_exits_1(self) -> None:
        self.assertEqual(self.code([self.row("p_a", "double")], known={"d.gcc.O2/p_a"}), 1)
        # An entry of a build not run says nothing.
        self.assertEqual(self.code([self.row("p_a", "double")], known={"d.clang.O3/p_a"}), 0)

    def test_more_than_a_tenth_unrendered_exits_1(self) -> None:
        rows = [self.row(f"p_{n}", "double") for n in range(9)]
        self.assertEqual(self.code(rows + [self.row("p_x", None)]), 0)
        self.assertEqual(self.code(rows + [self.row("p_x", None), self.row("p_y", None)]), 1)

    def test_a_build_with_a_function_unjudged_exits_1(self) -> None:
        self.assertEqual(self.code([self.row("p_a", "double")], short=["d.gcc.O2: no verdict"]), 1)

    def test_a_build_not_scored_exits_2(self) -> None:
        self.assertEqual(self.code([self.row("p_a", "double")], problems=["d.gcc.O3: does not compile"]), 2)

    def test_an_unread_written_result_rendered_void_exits_1(self) -> None:
        # Every `ignored` producer forwards what a call wrote: unread, never void (D202).
        self.assertEqual(self.code([self.row("p_a", "double"), self.row("p_c", "void", read=False)]), 1)
        self.assertEqual(self.code([self.row("p_a", "double"), self.row("p_c", "double", read=False)]), 0)

    def test_a_missing_compiler_exits_2_unless_allowed(self) -> None:
        self.assertEqual(gate.toolchain_exit(["gcc", "clang"], ["gcc"], True, False), 2)
        self.assertIsNone(gate.toolchain_exit(["gcc", "clang"], ["gcc"], True, True))
        self.assertIsNone(gate.toolchain_exit(["gcc", "clang"], ["gcc", "clang"], True, False))

    def test_a_host_with_no_elf_toolchain_skips(self) -> None:
        self.assertEqual(gate.toolchain_exit(["gcc"], [], True, False), 77)
        self.assertEqual(gate.toolchain_exit(["gcc"], ["gcc"], False, False), 77)


class Baseline(unittest.TestCase):
    known = json.loads((gen.OUT / "known.json").read_text())

    def test_every_known_false_void_has_a_cause_and_names_a_function_of_its_program(self) -> None:
        for key, cause in self.known["functions"].items():
            build, name = key.split("/")
            self.assertTrue(cause.strip(), key)
            self.assertIn(f" {name}(", (gen.OUT / f"{build.split('.')[0]}.c").read_text(), key)

    def test_a_known_function_is_read_by_some_caller(self) -> None:
        manifest = json.loads((gen.OUT / "manifest.json").read_text())
        for key in self.known["functions"]:
            build, name = key.split("/")
            self.assertTrue(manifest[f"{build.split('.')[0]}.c"][name]["read"], key)

    def test_a_known_function_is_named_by_one_build_and_no_more_than_once(self) -> None:
        keys = list(self.known["functions"])
        self.assertEqual(len(keys), len(set(keys)))
        build = re.compile(r"^[a-z0-9]+\.(gcc|clang)\.O[0-3](\.avx2)?/[a-z0-9_]+$")
        self.assertTrue(all(build.match(key) for key in keys), keys)


class Generator(unittest.TestCase):
    def test_the_files_are_what_the_generator_writes(self) -> None:
        for path, text in gen.generate().items():
            self.assertTrue(path.exists(), path.name)
            self.assertEqual(path.read_text(), text, f"{path.name} is stale: run gen_void_adversaries.py")

    def test_every_function_the_manifest_names_is_defined_in_its_program(self) -> None:
        manifest = json.loads((gen.OUT / "manifest.json").read_text())
        for program, functions in manifest.items():
            text = (gen.OUT / program).read_text()
            for name in functions:
                if not name.startswith("__"):
                    self.assertRegex(text, rf"\b{re.escape(name)}\(", f"{program} {name}")

    def test_each_producer_is_called_from_one_consumer(self) -> None:
        # A producer a second consumer reads directly would be read whatever the engine made of
        # the first, so the engine would not have to see it.
        for program, functions in json.loads((gen.OUT / "manifest.json").read_text()).items():
            if program == "obj.c":
                continue
            text = (gen.OUT / program).read_text()
            for name in functions:
                if name.endswith("_inner"):
                    continue
                if name.endswith("_identity"):
                    # Called with the inner function's value: the definition and one call.
                    self.assertEqual(len(re.findall(rf"\b{re.escape(name)}\(", text)), 2, name)
                    continue
                calls = re.findall(rf"\b{re.escape(name)}\(x\)", text)
                self.assertEqual(len(calls), 1, f"{program} {name}")

    def test_no_two_producers_of_a_program_have_one_body(self) -> None:
        # Alike bodies fold into one (`-fipa-icf`), and a folded producer is a row no build judges.
        for path, text in gen.generate().items():
            if path.suffix != ".c" or path.name == "obj.c":
                continue
            bodies = re.findall(r"^(?:N|NI|KEEP) [^(]*? (p_\w+)\([^)]*\) (\{.*\})$", text, re.M)
            seen: dict[str, str] = {}
            for name, rest in bodies:
                self.assertNotIn(rest, seen, f"{path.name}: {name} and {seen.get(rest)}")
                seen[rest] = name

    def test_the_hand_written_producers_write_the_registers_beside_their_result(self) -> None:
        # The footprint of an unproven result is the registers its body writes (scripts/mutants_d72.py):
        # the compilers leave them or not, so these bodies write them by hand.
        besides = {"dr": "%rax", "dz": "%rdx", "dx": "%xmm1"}
        for spec in gen.TYPES:
            if spec["tag"] in besides:
                self.assertIn(besides[spec["tag"]], spec["asm"], spec["tag"])
                self.assertIn("%xmm0", spec["asm"], spec["tag"])
                self.assertIn("indirect", spec["consumers"], spec["tag"])

    def test_the_suite_covers_every_register_a_result_comes_back_in(self) -> None:
        regs = {part for spec in gen.TYPES for part in spec["regs"].split(":")}
        self.assertTrue({"rax", "rdx", "xmm0", "xmm1", "st0", "st1", "ymm0"} <= regs)


if __name__ == "__main__":
    unittest.main()
