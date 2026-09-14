#!/usr/bin/env python3
"""Check that census reconciliation preserves binary and function identity."""

import unittest

import contextlib
import io

from census_decbench import reconcile, report


class CensusReconciliationTests(unittest.TestCase):
    def test_binary_identity_prefixes_and_unmatched_names(self):
        census = [{
            "binary_path": "/run/out/O0/zlib/compiled/libz.so.1.2.13",
            "by_function": {"dbg.sym.foo": "proof missing", "sym.clone": "other cause"},
        }, {
            "binary_path": "/run/out/O2/zlib/compiled/libz.so.1.2.13",
            "by_function": {"dbg.bar": "different optimization"},
        }, {
            "binary_path": "/run/out/O0/other/compiled/libz.so.1.2.13",
            "by_function": {"dbg.baz": "different project"},
        }]
        functions = [{"function": name, "decompiled": {"r2sleigh": False, "angr": True}}
                     for name in ("foo", "bar", "baz", "clone.part.0")]
        result = {"groups": [{
            "project": "zlib", "opt_level": "O0", "binary": "libz.so.1.2",
            "functions": functions,
        }, {
            "project": "zlib", "opt_level": "O0", "binary": "absent",
            "functions": functions[:1],
        }]}
        joined = reconcile(census, [result])
        self.assertEqual(joined["totals"], {
            "angr_rendered": 5, "missed": 5, "missing_census": 1,
            "named_refusal": 1, "no_census_entry": 3, "rendered": 0, "scored": 5,
        })
        matched = [row for row in joined["misses"] if row["status"] == "named_refusal"]
        self.assertEqual(matched[0]["matches"], [{"flag": "dbg.sym.foo", "cause": "proof missing"}])
        self.assertEqual(joined, reconcile(list(reversed(census)), [result]))

    def test_colliding_flag_names_are_not_silently_overwritten(self):
        joined = reconcile([{
            "binary_path": "/run/out/O0/project/compiled/bin",
            "by_function": {"dbg.foo": "one cause", "sym.foo": "another cause"},
        }], [{"groups": [{
            "project": "project", "opt_level": "O0", "binary": "bin",
            "functions": [{"function": "foo", "decompiled": {"r2sleigh": False}}],
        }]}])
        self.assertEqual(joined["totals"]["ambiguous_census_name"], 1)
        self.assertEqual(len(joined["misses"][0]["matches"]), 2)

    def test_symbol_alias_requires_the_same_function_entry_address(self):
        binary_path = "/run/out/O2/project/compiled/bin"
        functions = [{"function": name, "decompiled": {"r2sleigh": name == "foo"}}
                     for name in ("foo", "foo.constprop.0", "foo.constprop.1", "bar.isra.0")]
        result = {"groups": [{"project": "project", "opt_level": "O2", "binary": "bin",
                              "functions": functions}]}
        discovery = [{"binary_path": binary_path, "functions": [
            {"name": "dbg.foo", "addr": 16}, {"name": "dbg.bar", "addr": 32},
        ], "symbols": [
            {"name": "foo.constprop.0", "vaddr": 16, "type": "FUNC"},
            {"name": "foo.constprop.1", "vaddr": 17, "type": "FUNC"},
            {"name": "bar.isra.0", "vaddr": 32, "type": "FUNC"},
        ]}]
        joined = reconcile([{"binary_path": binary_path, "by_function": {"dbg.bar": "refused"}}],
                           [result], discovery)
        rows = {row["function"]: row for row in joined["misses"]}
        self.assertEqual(rows["foo.constprop.0"]["status"], "rendered_alias")
        self.assertEqual(rows["foo.constprop.0"]["alias"], {"function": "foo", "address": 16})
        self.assertEqual(rows["foo.constprop.1"]["status"], "no_census_entry")
        self.assertEqual(rows["bar.isra.0"]["matches"], [{"flag": "dbg.bar", "cause": "refused"}])


class ReportAttritionTest(unittest.TestCase):
    def _report(self, payloads):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            report(payloads, top=3)
        return buffer.getvalue()

    def test_each_filter_reports_what_it_removed(self):
        text = self._report([{
            "binary_path": "/run/out/O2/project/compiled/bin",
            "rendered": 2,
            "declined": 1,
            "candidates": [
                {"stage": "discovered", "functions": 10},
                {"stage": "after skip-list", "functions": 7},
                {"stage": "after source narrowing", "functions": 3},
            ],
        }])
        self.assertIn("discovered 10 functions", text)
        self.assertIn("removed      4 after source narrowing", text)
        self.assertIn("removed      3 after skip-list", text)

    def test_a_census_without_stages_reports_no_discovery(self):
        text = self._report([{
            "binary_path": "/run/out/O0/project/compiled/bin",
            "rendered": 1,
            "declined": 0,
        }])
        self.assertNotIn("discovered", text)


if __name__ == "__main__":
    unittest.main()
