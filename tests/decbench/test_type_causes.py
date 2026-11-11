#!/usr/bin/env python3
"""How a type verdict divides between parameters and locals, from the rows `type_causes.py collect` writes."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import type_causes


def var(verdict, is_arg=False, gt="int4", dec="int8"):
    return {"verdict": verdict, "is_arg": is_arg, "gt_kind": gt, "dec_kind": dec}


def row(name, vars_, dec="r2sleigh_native", value=0.5):
    return {"project": "p", "opt": "O2", "binary": "b", "function": name, "dec": dec, "value": value, "vars": vars_}


WIDTH = "fp:integer_width"


class ArgumentSplit(unittest.TestCase):
    def split(self, rows, verdict=WIDTH, dec="r2sleigh_native"):
        return type_causes.argument_split(rows, dec, verdict)

    def test_variables_divide_by_argument_and_by_width_against_the_source(self):
        rows = [
            row("a", [var(WIDTH, True, "int4", "int8"), var(WIDTH, True, "int4", "int1"), var("tp")]),
            row("b", [var(WIDTH, False, "int4", "int8"), var(WIDTH, False, "int2", "int2")]),
        ]
        split = self.split(rows)
        self.assertEqual(split["variables"], {"param": 2, "local": 2})
        self.assertEqual(split["direction"]["all"]["param"], {"wider": 1, "narrower": 1, "same": 0, "unknown": 0})
        self.assertEqual(split["direction"]["all"]["local"], {"wider": 1, "narrower": 0, "same": 1, "unknown": 0})
        # `a` has a tp beside its width errors and `b` has none: both are only-cause functions.
        self.assertEqual(split["direction"]["only_cause"], split["direction"]["all"])

    def test_direction_in_only_cause_functions_leaves_out_the_other_classes(self):
        rows = [
            row("sole", [var(WIDTH, True, "int4", "int8")]),
            row("shared", [var(WIDTH, True, "int4", "int1"), var("fp:pointer_as_integer", True)]),
        ]
        split = self.split(rows)
        self.assertEqual(split["direction"]["all"]["param"]["narrower"], 1)
        self.assertEqual(split["direction"]["only_cause"]["param"], {"wider": 1, "narrower": 0, "same": 0, "unknown": 0})

    def test_a_function_is_only_cause_when_no_other_class_is_in_it(self):
        rows = [
            row("params", [var(WIDTH, True), var("tp")]),
            row("locals", [var(WIDTH, False), var(WIDTH, False)]),
            row("mixed", [var(WIDTH, True), var(WIDTH, False)]),
            row("other_cause", [var(WIDTH, True), var("fp:pointer_as_integer", True)]),
            row("capped", [var(WIDTH, True), var("fn:unobservable")]),
            row("perfect", [var("tp")], value=1.0),
        ]
        split = self.split(rows)
        self.assertEqual(split["only_cause"], {"functions": 3, "params_only": 1, "locals_only": 1, "mixed": 1})
        self.assertEqual(split["involved"], {"functions": 5, "params_only": 3, "locals_only": 1, "mixed": 1})

    def test_only_the_named_decompiler_is_read(self):
        rows = [row("a", [var(WIDTH, True)], dec="angr"), row("b", [var(WIDTH, False)])]
        split = self.split(rows)
        self.assertEqual(split["only_cause"]["functions"], 1)
        self.assertEqual(split["variables"], {"param": 0, "local": 1})

    def test_a_kind_with_no_width_has_an_unknown_direction_and_never_the_same_one(self):
        rows = [row("a", [var(WIDTH, True, "ptr_char", "int8"), var(WIDTH, False, "int4", "float"),
                          var(WIDTH, False, "struct", "ptr_int"), var(WIDTH, False, "int4", "int4")])]
        direction = self.split(rows)["direction"]["all"]
        self.assertEqual(direction["param"], {"wider": 0, "narrower": 0, "same": 0, "unknown": 1})
        self.assertEqual(direction["local"], {"wider": 0, "narrower": 0, "same": 1, "unknown": 2})

    def test_a_perfect_function_has_no_error_to_count(self):
        rows = [row("perfect", [var(WIDTH, True)], value=1.0), row("flawed", [var(WIDTH, False)])]
        split = self.split(rows)
        self.assertEqual(split["variables"], {"param": 0, "local": 1})
        self.assertEqual(split["involved"], {"functions": 1, "params_only": 0, "locals_only": 1, "mixed": 0})
        self.assertEqual(split["direction"]["all"]["param"], {"wider": 0, "narrower": 0, "same": 0, "unknown": 0})

    def test_pointer_as_integer_has_no_width_direction(self):
        rows = [row("a", [var("fp:pointer_as_integer", True, "ptr_char", "int8")])]
        split = self.split(rows, "fp:pointer_as_integer")
        self.assertEqual(split["variables"], {"param": 1, "local": 0})
        self.assertNotIn("direction", split)


class Widths(unittest.TestCase):
    def test_the_report_states_the_shares_it_decides_on(self):
        rows = [row("a", [var(WIDTH, True)]), row("b", [var(WIDTH, False)]), row("c", [var(WIDTH, False)])]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rows.jsonl"
            path.write_text("".join(json.dumps(r) + "\n" for r in rows))
            out = io.StringIO()
            with redirect_stdout(out):
                type_causes.widths(type("Args", (), {"rows": str(path), "dec": "r2sleigh_native"})())
        text = out.getvalue()
        self.assertIn("fp:integer_width", text)
        self.assertIn("only cause 3: parameters only 1 (33.3%), locals only 2 (66.7%), mixed 0 (0.0%)", text)

    def test_the_report_gives_both_verdicts_and_the_parameter_and_local_totals(self):
        rows = [row("params", [var(WIDTH, True, "int4", "int8")]), row("locals", [var(WIDTH, False, "int4", "int1")]),
                row("mixed", [var(WIDTH, True, "int4", "int4"), var(WIDTH, False, "int2", "int8")]),
                row("pointers", [var("fp:pointer_as_integer", True, "ptr_char", "int8")])]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rows.jsonl"
            path.write_text("".join(json.dumps(r) + "\n" for r in rows))
            out = io.StringIO()
            with redirect_stdout(out):
                type_causes.widths(type("Args", (), {"rows": str(path), "dec": "r2sleigh_native"})())
        lines = out.getvalue().splitlines()
        self.assertEqual(lines[0], "== r2sleigh_native fp:integer_width: variables 4: parameters 2, locals 2")
        self.assertIn("  all        param decompiled width against source: wider 1, narrower 0, same 1, unknown 0", lines)
        self.assertIn("  all        local decompiled width against source: wider 1, narrower 1, same 0, unknown 0", lines)
        self.assertIn("  functions only cause 3: parameters only 1 (33.3%), locals only 1 (33.3%), mixed 1 (33.3%)", lines)
        self.assertIn("    parameters in 2 (66.7%), locals in 2 (66.7%)", lines)
        self.assertIn("== r2sleigh_native fp:pointer_as_integer: variables 1: parameters 1, locals 0", lines)
        self.assertIn("  functions involved 1: parameters only 1 (100.0%), locals only 0 (0.0%), mixed 0 (0.0%)", lines)

    def test_the_report_gives_the_only_cause_before_the_functions_involved(self):
        rows = [row("sole", [var(WIDTH, True)]), row("shared", [var(WIDTH, True), var("fp:pointer_as_integer", True)])]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rows.jsonl"
            path.write_text("".join(json.dumps(r) + "\n" for r in rows))
            out = io.StringIO()
            with redirect_stdout(out):
                type_causes.widths(type("Args", (), {"rows": str(path), "dec": "r2sleigh_native"})())
        lines = out.getvalue().splitlines()
        only = lines.index("  functions only cause 1: parameters only 1 (100.0%), locals only 0 (0.0%), mixed 0 (0.0%)")
        involved = lines.index("  functions involved 2: parameters only 2 (100.0%), locals only 0 (0.0%), mixed 0 (0.0%)")
        self.assertLess(only, involved)

    def test_a_share_of_no_function_is_not_a_division(self):
        self.assertEqual(type_causes.share(0, 0), "0 (n/a)")
        self.assertEqual(type_causes.share(1, 3), "1 (33.3%)")


if __name__ == "__main__":
    unittest.main()
