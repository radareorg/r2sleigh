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


if __name__ == "__main__":
    unittest.main()
