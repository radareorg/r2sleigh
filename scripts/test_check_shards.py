#!/usr/bin/env python3
"""Unit tests for the shard-coverage gate. Pure Python; the last test reads the repository."""

from __future__ import annotations

import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import check_shards  # noqa: E402

WORKFLOW = """\
jobs:
  other:
    steps:
      - run: echo
  equivalence-shard:
    strategy:
      matrix:
        part:
          - name: a
            sources: tests/corpus/a.c tests/gold/b.c
          - name: shapes
            sources: tests/corpus/shapes.c
  equivalence-shard-aarch64:
    strategy:
      matrix:
        part:
          - name: a
            sources: tests/corpus/a.c
          - name: b
            sources: tests/gold/b.c tests/corpus/shapes.c
"""
ALL = {"tests/corpus/a.c", "tests/gold/b.c", "tests/corpus/shapes.c"}


def baselines(x86=ALL, arm=ALL) -> dict[str, set[str]]:
    return {"equivalence-shard": set(x86), "equivalence-shard-aarch64": set(arm)}


class Shards(unittest.TestCase):
    def test_sources_are_read_by_job_across_parts(self) -> None:
        shards = check_shards.shards_of(WORKFLOW)
        self.assertEqual(sorted(shards), ["equivalence-shard", "equivalence-shard-aarch64"])
        self.assertEqual(set(shards["equivalence-shard-aarch64"]), ALL)

    def test_record_keys_give_their_source(self) -> None:
        records = {"records": {"tests/gold/b.c::gcc-O0::f": {}, "tests/gold/b.c::gcc-O1::g": {}}}
        self.assertEqual(check_shards.sources_of(records), {"tests/gold/b.c"})


class Problems(unittest.TestCase):
    def check(self, workflow=WORKFLOW, **kw) -> list[str]:
        return check_shards.problems(check_shards.shards_of(workflow), baselines(**kw))

    def test_consistent_tree_passes(self) -> None:
        self.assertEqual(self.check(), [])

    def test_baseline_source_in_no_shard_fails_by_name(self) -> None:
        # The #292 miss: atomics.c had baseline records and no shard.
        found = self.check(x86=ALL | {"tests/gold/atomics.c"})
        self.assertEqual(len(found), 1)
        self.assertIn("tests/gold/atomics.c", found[0])
        self.assertIn("equivalence-shard:", found[0])
        self.assertIn("no shard", found[0])

    def test_shard_source_without_records_fails(self) -> None:
        found = self.check(arm=ALL - {"tests/corpus/a.c"})
        self.assertEqual(len(found), 1)
        self.assertIn("equivalence-shard-aarch64", found[0])
        self.assertIn("tests/corpus/a.c", found[0])

    def test_each_matrix_is_graded_against_its_own_baseline(self) -> None:
        # Present in the x86-64 shards only: aarch64 records for it would be ungraded.
        workflow = WORKFLOW.replace("tests/gold/b.c tests/corpus/shapes.c", "tests/corpus/shapes.c")
        found = self.check(workflow)
        self.assertEqual(len(found), 1)
        self.assertIn("equivalence-shard-aarch64: tests/gold/b.c", found[0])

    def test_a_job_with_no_sources_line_is_red_not_vacuous(self) -> None:
        found = self.check("jobs:\n  renamed:\n    sources: tests/corpus/a.c\n")
        self.assertTrue(any("no `sources:` line" in m for m in found))

    def test_an_empty_baseline_is_red(self) -> None:
        found = self.check(x86=set())
        self.assertTrue(any("no records" in m for m in found))


class Repository(unittest.TestCase):
    def test_current_tree_is_consistent(self) -> None:
        root = check_shards.ROOT
        shards = check_shards.shards_of((root / check_shards.WORKFLOW).read_text())
        recorded = {
            job: check_shards.sources_of(json.loads((root / path).read_text()))
            for job, path in check_shards.JOBS.items()
        }
        self.assertEqual(check_shards.problems(shards, recorded), [])
        self.assertTrue(all(recorded.values()))


if __name__ == "__main__":
    unittest.main()
