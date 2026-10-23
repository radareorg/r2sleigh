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


if __name__ == "__main__":
    unittest.main()
