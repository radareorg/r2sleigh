#!/usr/bin/env python3
"""Unit tests for the void-row audit. Pure Python: no compiler, no headers."""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import audit_abi_rows as audit  # noqa: E402

SIGNAL = {"signal": ("void (*)(int)", "C11 7.14.1.1")}


class Rows(unittest.TestCase):
    def test_the_old_signal_row_is_an_error(self) -> None:
        _, errors = audit.audit({"types.sdb.txt": {"signal": "void"}}, SIGNAL)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("C11 7.14.1.1", errors[0])

    def test_the_fixed_signal_row_is_silent(self) -> None:
        self.assertEqual(audit.audit({"types.sdb.txt": {"signal": "void *"}}, SIGNAL), ([], []))

    def test_an_uncited_void_row_is_an_error(self) -> None:
        _, errors = audit.audit({"types.sdb.txt": {"free": "void"}}, {})
        self.assertEqual(len(errors), 1, errors)

    def test_a_cited_void_row_is_reported(self) -> None:
        report, errors = audit.audit({"t": {"free": "void"}}, {"free": ("void", "C11 7.22.3.3")})
        self.assertEqual((len(report), errors), (1, []))

    def test_a_citation_naming_no_row_is_an_error(self) -> None:
        _, errors = audit.audit({"t": {}}, {"free": ("void", "C11 7.22.3.3")})
        self.assertEqual(len(errors), 1, errors)

    def test_a_name_cited_twice_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            audit.citations_of("free | void | a\nfree | void | b\n")

    def test_the_shipped_tables_pass(self) -> None:
        rows = audit.tables(audit.DATA)
        _, errors = audit.audit(rows, audit.citations_of(audit.CITATIONS.read_text()))
        self.assertEqual(errors, [])
        self.assertEqual(rows["types.sdb.txt"]["signal"], "void *")


class Headers(unittest.TestCase):
    def test_a_function_returning_a_handler_returns_a_value(self) -> None:
        line = "/* signal.h:88:NC */ extern void (*signal (int, void (*)(int)))(int);"
        self.assertEqual(audit.declared_return(line), ("signal", False))

    def test_a_typedef_return_is_a_value(self) -> None:
        line = "extern __sighandler_t signal (int, __sighandler_t);"
        self.assertEqual(audit.declared_return(line), ("signal", False))

    def test_void_and_void_pointer_differ(self) -> None:
        self.assertEqual(audit.declared_return("extern void free (void *);"), ("free", True))
        self.assertEqual(audit.declared_return("extern void *malloc (size_t);"), ("malloc", False))

    def test_a_row_disagreeing_with_its_header_is_an_error(self) -> None:
        rows = {"types.sdb.txt": {"signal": "void", "free": "void"}}
        errors = audit.against_headers(rows, {"signal": False, "free": True})
        self.assertEqual(len(errors), 1, errors)


CITED = """
# stdio.h: ISO C17. A stream is `FILE *`.
fputs=func
func.fputs.args=2
func.fputs.arg.0=const char *,s
func.fputs.arg.1=FILE *,stream
func.fputs.ret=int
func.fputs.include=stdio.h

# fcntl.h: POSIX.1-2017.
open=func
func.open.args=3
func.open.arg.0=const char *,path
func.open.arg.1=int,oflag
func.open.arg.2=,...
func.open.ret=int
func.open.include=fcntl.h
func.open.tail=variadic

# string.h: GCC builtins.def.
__memcpy_chk=func
func.__memcpy_chk.args=0
func.__memcpy_chk.ret=void *
func.__memcpy_chk.include=string.h

# error.h: glibc, error(3).
error=func
func.error.args=2
func.error.arg.0=int,status
func.error.arg.1=,...
func.error.ret=void
func.error.include=error.h

# LSB 5.0, in the binary standard only.
__stack_chk_fail=func
func.__stack_chk_fail.args=0
func.__stack_chk_fail.ret=void
"""


class Prototypes(unittest.TestCase):
    def rows(self) -> dict[str, audit.CitedRow]:
        return {row.name: row for row in audit.cited_rows(CITED)}

    def test_a_row_spells_its_function_type(self) -> None:
        rows = self.rows()
        self.assertEqual(rows["fputs"].prototype(), "int (const char *, FILE *)")
        self.assertEqual(rows["open"].prototype(), "int (const char *, int, ...)")

    def test_a_row_is_compiled_under_the_mode_its_source_names(self) -> None:
        rows = self.rows()
        self.assertEqual(rows["fputs"].modes(), ["-std=c17"])
        self.assertEqual(rows["open"].modes(), ["-std=c17 -D_POSIX_C_SOURCE=200809L"])
        self.assertEqual(rows["error"].modes(), ["-std=gnu17 -D_GNU_SOURCE -O2 -D_FORTIFY_SOURCE=2"])
        mixed = audit.CitedRow("getrlimit", " sys/resource.h: POSIX.1-2017. The selectors are glibc's enumerations. ")
        self.assertEqual(len(mixed.modes()), 2)
        self.assertEqual(mixed.modes()[0], "-std=c17 -D_POSIX_C_SOURCE=200809L")
        self.assertIn("__typeof__(fputs)", audit.assertion(rows["fputs"]))

    def test_a_probe_includes_the_synopsis_prerequisites_first(self) -> None:
        wide = audit.CitedRow("fgetwc", " wchar.h: ISO C17. ", "wint_t", "wchar.h", {0: "FILE *,stream"})
        self.assertEqual(audit.headers_of(wide), ["stddef.h", "stdarg.h", "stdio.h", "wchar.h"])
        self.assertIn("#include <stdio.h>\n#include <wchar.h>", audit.assertion(wide))

    def test_a_fortify_header_is_reached_through_its_public_wrapper(self) -> None:
        row = audit.CitedRow("__open_2", " glibc. ", "int", "bits/fcntl2.h", {0: "const char *,path", 1: "int,oflag"})
        self.assertEqual(audit.headers_of(row)[-1], "fcntl.h")
        self.assertNotIn("bits/", audit.assertion(row))

    def test_a_redirected_name_is_probed_as_the_function_the_header_declares(self) -> None:
        row = audit.CitedRow("__isoc23_strtol", " stdlib.h: glibc. ", "long", "stdlib.h", {0: "const char *,s"})
        self.assertIn("__typeof__(strtol)", audit.assertion(row))

    def test_a_posix_type_brings_sys_types(self) -> None:
        row = audit.CitedRow("mmap64", " sys/mman.h: glibc. ", "void *", "sys/mman.h", {0: "off64_t,offset"})
        self.assertIn("sys/types.h", audit.headers_of(row))

    def test_a_row_naming_xsi_is_also_probed_under_it(self) -> None:
        row = audit.CitedRow("sigaltstack", " signal.h: POSIX.1-2017; sigaltstack is XSI. ")
        self.assertIn("-std=c17 -D_XOPEN_SOURCE=700", row.modes())

    def test_the_shipped_xsi_rows_name_xsi(self) -> None:
        rows = {row.name: row for row in audit.cited_rows((audit.DATA / "types-posix.sdb.txt").read_text())}
        for name in ("sigaltstack", "getpwent", "getgrent", "wcswidth"):
            self.assertIn("-std=c17 -D_XOPEN_SOURCE=700", rows[name].modes(), name)

    def test_a_row_citing_gccs_builtins_is_not_compiled(self) -> None:
        self.assertNotIn("__memcpy_chk", self.rows())

    def test_a_row_stands_for_the_pointer_const_and_noreturn_it_leaves_out(self) -> None:
        forms = audit.spellings("int (const char *, char **)")
        self.assertIn("int (const char *, char *const *)", forms)
        self.assertIn("__attribute__((noreturn)) int (const char *, char **)", forms)
        self.assertEqual(len(forms), 4)

    def test_a_row_with_no_header_is_not_compiled(self) -> None:
        self.assertNotIn("__stack_chk_fail", self.rows())

    def test_the_moved_rows_stay_under_the_header_return_check(self) -> None:
        self.assertTrue(set(audit.CITED_TABLES) <= set(audit.GLIBC_TABLES))


if __name__ == "__main__":
    unittest.main()
