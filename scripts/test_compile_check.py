#!/usr/bin/env python3
"""Unit tests for the conversion gate's reading of a batch and of a compiler's answer.

Pure Python, no binary; the compiler tests need a C compiler and skip without one.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import compile_check as gate  # noqa: E402

SEP = gate.SEPARATOR

# A recursive function whose pointer parameter is handed the integer carrier it computed.
INTEGER_TO_POINTER = """#include <stdint.h>
uint64_t f(char *s, uint32_t n)
{
    uint64_t next = (uint64_t)s + 1U;
    return n ? f(next, n - 1U) : 0;
}
"""
CAST_TO_POINTER = INTEGER_TO_POINTER.replace("f(next,", "f((char*)next,")


class BatchTest(unittest.TestCase):
    def test_a_batch_is_split_at_its_separators_and_a_refusal_has_no_code(self):
        text = (
            f'noise\n{SEP}\n{{"code":"int a;","refused":null}}\n'
            f'{SEP}\n{{"code":"","refused":"why"}}\n'
            f"{SEP}\nr2s: unknown command\n"
        )
        self.assertEqual(gate.parse_batch(text), ["int a;", None, None])

    def test_diagnostics_after_the_last_answer_do_not_turn_it_into_a_refusal(self):
        text = f'{SEP}\n{{"code":"int a;","refused":null}}\nwarning: a stderr line after the answer\n'
        self.assertEqual(gate.parse_batch(text), ["int a;"])

    def test_every_error_line_is_read_and_a_constraint_anywhere_fails_the_unit(self):
        conversion = (
            "u.c:5:20: error: incompatible integer to pointer conversion passing 'uint64_t' to "
            "parameter of type 'char *' [-Wint-conversion]\n"
        )
        other = "u.c:3:10: error: conflicting types for 'g'\n"
        for order in ((other, conversion), (conversion, other)):
            self.assertEqual(gate.classify("".join(order))[0], "conversion")
        self.assertEqual(gate.classify(conversion)[1], conversion.strip())
        self.assertEqual(gate.classify(other)[0], "other")
        self.assertEqual(gate.classify("u.c:1: warning: unused\n"), (None, ""))

    def test_each_diagnostic_is_counted_under_the_warning_that_names_it(self):
        text = (
            "u.c:1:1: error: unknown type name 'x'\n"
            "u.c:2:1: error: call to undeclared function 'g' [-Wimplicit-function-declaration]\n"
            "u.c:3:1: note: declared here\n"
            "u.c:4:1: error: incompatible integer to pointer conversion [-Wint-conversion]\n"
            "u.c:5:1: error: incompatible pointer types [-Werror,-Wincompatible-pointer-types]\n"
            "u.c:6:1: error: incompatible function pointer types [-Wincompatible-function-pointer-types]\n"
            "u.c:7:1: error: passing argument 1 makes pointer from integer [-Werror=int-conversion]\n"
            "u.c:8:1: error: initializing 'char *' discards qualifiers "
            "[-Werror,-Wincompatible-pointer-types-discards-qualifiers]\n"
            "u.c:9:1: error: void function 'f' should not return a value [-Wreturn-mismatch]\n"
        )
        self.assertEqual(
            [kind for kind, _ in gate.diagnostics(text)],
            [
                "other",
                "implicit-function-declaration",
                "int-conversion",
                "incompatible-pointer-types",
                "incompatible-function-pointer-types",
                "int-conversion",
                "incompatible-pointer-types-discards-qualifiers",
                "return-mismatch",
            ],
        )


@unittest.skipUnless(shutil.which("clang"), "needs clang")
class CompilerTest(unittest.TestCase):
    def kind(self, code, cc="clang"):
        with tempfile.TemporaryDirectory() as directory:
            return gate.rejects(cc, code, directory)

    def test_an_integer_handed_to_a_pointer_parameter_is_rejected_and_a_cast_is_not(self):
        self.assertEqual(self.kind(INTEGER_TO_POINTER)[0], "conversion")
        self.assertEqual(self.kind(CAST_TO_POINTER), (None, ""))

    def test_a_conversion_fails_the_unit_wherever_the_other_errors_stand(self):
        unrelated = "unknown_t first(void);\n"
        for code in (
            unrelated + INTEGER_TO_POINTER,
            INTEGER_TO_POINTER + unrelated,
            INTEGER_TO_POINTER.replace("{\n", "{\n    unknown_t inside;\n", 1),
        ):
            kind, line = self.kind(code)
            self.assertEqual(kind, "conversion", code)
            self.assertIn("int-conversion", line)

    def test_three_errors_of_three_kinds_are_read_in_any_order(self):
        three = (
            "unknown_t first(void);\n"
            "int *pointer(long n) { return n; }\n"
            "int *mismatch(void) { long *p = 0; int *q = p; return q; }\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            seen = [kind for kind, _ in gate.diagnostics(gate.compile_unit("clang", three, directory))]
        self.assertEqual(seen, ["other", "int-conversion", "incompatible-pointer-types"])
        self.assertEqual(self.kind(three)[0], "conversion")

    def test_the_errors_past_the_compilers_default_limit_are_still_read(self):
        flood = "".join(f"unknown_{n}_t first_{n}(void);\n" for n in range(30))
        self.assertEqual(self.kind(flood + INTEGER_TO_POINTER)[0], "conversion")

    def test_a_pointer_that_loses_a_qualifier_fails_the_unit(self):
        code = "void f(const char *c) { char *d = c; (void)d; }\n"
        kind, line = self.kind(code)
        self.assertEqual(kind, "conversion")
        self.assertIn("discards-qualifiers", line)

    def test_a_return_that_disagrees_with_the_function_type_fails_the_unit_or_the_gate(self):
        if "return-mismatch" in gate.unbound("clang"):
            self.assertEqual(MainTest().status({0x1000: MainTest.CLEAN}, missing=None), 2)
            return
        for code in ("void f(int x) { return x; }\n", "int g(void) { return; }\n"):
            kind, line = self.kind(code)
            self.assertEqual(kind, "conversion", code)
            self.assertIn("return-mismatch", line)

    def test_clang_binds_every_group_it_has_had_since_clang_16(self):
        self.assertLessEqual(set(gate.unbound("clang")), {"return-mismatch"})

    def test_a_compiler_that_accepts_every_probe_binds_no_group(self):
        self.assertEqual(gate.unbound("true"), list(dict.fromkeys(kind for kind, _ in gate.PROBES)))

    def test_an_undeclared_callee_fails_the_unit(self):
        code = "int caller(void) { return undeclared(1); }\n"
        self.assertEqual(self.kind(code)[0], "conversion")

    def test_an_unrelated_error_alone_is_other_and_a_compiler_that_names_none_is_not_clean(self):
        self.assertEqual(self.kind("unknown_t only(void);\n")[0], "other")
        self.assertEqual(self.kind("int ok(void) { return 0; }\n", cc="false")[0], "other")


class MainTest(unittest.TestCase):
    """The exit status of `main`, over a stubbed binary list, `pddj` batch and compiler."""

    def status(self, answers, stderrs=None, unlisted=False, missing=()):
        """`main`'s status when each function at an address of `answers` is answered by its text
        (None: `r2s` fails) and the compiler prints `stderrs[code]` for a unit (default: accepts).
        One function to a chunk, so that one chunk can fail beside another that does not; with
        `unlisted` a second binary in the directory is one `r2s` cannot list. The compiler leaves
        the groups `missing` unbound; None asks the host's clang."""
        stderrs = stderrs or {}
        binaries = tempfile.TemporaryDirectory()
        for name in ("a", "b") if unlisted else ("a",):
            (Path(binaries.name) / name).write_text("")

        def run(command, timeout):
            address = next(a for a in answers if f"{a:#x}" in command[3])
            answer = answers[address]
            return ("", "r2s timed out") if answer is None else (answer, "")

        def functions(r2s, binary, timeout):
            if binary.name == "b":
                return [], None, "cannot list"
            return [(address, "f") for address in answers], None, None

        def compile_unit(cc, code, directory):
            return stderrs.get(code, "")

        missing = gate.unbound("clang") if missing is None else list(missing)
        patches = [
            mock.patch.object(gate, "unbound", lambda cc: missing),
            mock.patch.object(gate.gate, "run", run),
            mock.patch.object(gate.gate, "functions", functions),
            mock.patch.object(gate, "compile_unit", compile_unit),
            mock.patch.object(gate, "CHUNK", 1),
            mock.patch.object(gate.shutil, "which", lambda cc: "/usr/bin/" + cc),
            mock.patch.object(gate.gate, "opens", lambda r2s, path: True),
            mock.patch.object(sys, "argv", ["compile_check.py", "--bins", binaries.name]),
            mock.patch("builtins.print"),
        ]
        for patch in patches:
            patch.start()
        try:
            return gate.main()
        finally:
            for patch in reversed(patches):
                patch.stop()
            binaries.cleanup()

    CLEAN = f'{SEP}\n{{"code":"int a;","refused":null}}\n'
    BAD = f'{SEP}\n{{"code":"int b;","refused":null}}\n'
    REFUSED = f'{SEP}\n{{"code":"","refused":"why"}}\n'
    CONVERSION = {"int b;": "u.c:1:1: error: conversion [-Wint-conversion]\n"}

    def test_clean_units_pass(self):
        self.assertEqual(self.status({0x1000: self.CLEAN}), 0)

    def test_a_conversion_beside_a_clean_unit_fails_the_run(self):
        self.assertEqual(self.status({0x1000: self.CLEAN, 0x2000: self.BAD}, self.CONVERSION), 1)

    def test_a_chunk_r2s_never_answered_beside_a_clean_one_fails_the_run(self):
        self.assertEqual(self.status({0x1000: self.CLEAN, 0x2000: None}), 1)

    def test_a_binary_r2s_cannot_list_beside_a_clean_one_fails_the_run(self):
        self.assertEqual(self.status({0x1000: self.CLEAN}, unlisted=True), 1)

    def test_a_run_that_compiled_nothing_fails(self):
        self.assertEqual(self.status({0x1000: self.REFUSED}), 1)
        self.assertEqual(self.status({0x1000: f"{SEP}\nr2s: refused\n"}), 1)

    def test_a_refusal_beside_a_clean_unit_does_not_fail_the_run(self):
        self.assertEqual(self.status({0x1000: self.CLEAN, 0x2000: self.REFUSED}), 0)

    def test_an_empty_function_list_compiles_nothing_and_fails(self):
        self.assertEqual(self.status({}), 1)

    def test_a_compiler_that_leaves_a_group_unbound_grades_nothing(self):
        self.assertEqual(self.status({0x1000: self.CLEAN}, missing=["return-mismatch"]), 2)


if __name__ == "__main__":
    unittest.main()
