#!/usr/bin/env python3
"""Unit tests for which PRs carry `full-ci`. Pure Python."""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import stack_tip  # noqa: E402


def pr(number, head, base, labels=(), **kw) -> dict:
    return {"number": number, "head": head, "base": base, "labels": list(labels), **kw}


def stack(first: int, size: int, labels=()) -> list[dict]:
    """PR first is based on master; PR first+i is based on PR first+i-1's head."""
    prs = [pr(first, f"s{first}", "master")]
    prs += [pr(first + i, f"s{first + i}", f"s{first + i - 1}") for i in range(1, size)]
    for p in prs:
        p["labels"] = [x for x in labels if p["number"] == first + size - 1]
    return prs


class Plan(unittest.TestCase):
    def test_a_stack_of_72_labels_only_its_tip(self) -> None:
        self.assertEqual(stack_tip.plan(stack(1, 72)), {"label": [72], "unlabel": []})

    def test_a_listing_order_does_not_matter(self) -> None:
        prs = list(reversed(stack(1, 72)))
        self.assertEqual(stack_tip.plan(prs), {"label": [72], "unlabel": []})

    def test_two_independent_stacks_each_have_a_tip(self) -> None:
        prs = stack(1, 5) + stack(100, 3)
        self.assertEqual(stack_tip.plan(prs), {"label": [5, 102], "unlabel": []})

    def test_a_pr_based_on_master_is_left_alone(self) -> None:
        self.assertEqual(stack_tip.plan([pr(1, "a", "master")]), {"label": [], "unlabel": []})
        labelled = [pr(1, "a", "master", ["full-ci"])]
        self.assertEqual(stack_tip.plan(labelled), {"label": [], "unlabel": []})

    def test_a_tip_that_gains_a_child_loses_the_label(self) -> None:
        prs = stack(1, 3, ["full-ci"])
        prs[1]["labels"] = ["full-ci"]
        prs.append(pr(4, "s4", "s3"))
        self.assertEqual(stack_tip.plan(prs), {"label": [4], "unlabel": [2, 3]})

    def test_a_closed_tip_hands_the_label_to_its_parent(self) -> None:
        # The tip merged or closed: it is gone from the open list, its parent is the tip.
        open_prs = stack(1, 72)[:-1]
        self.assertEqual(stack_tip.plan(open_prs), {"label": [71], "unlabel": []})
        listed_closed = stack(1, 72)
        listed_closed[-1]["state"] = "CLOSED"
        self.assertEqual(stack_tip.plan(listed_closed), {"label": [71], "unlabel": []})

    def test_a_base_merged_and_deleted_leaves_a_tip_not_a_trunk_pr(self) -> None:
        # PR 2's base `gone` is no open head and not master: it is a stacked tip.
        prs = [pr(2, "b", "gone"), pr(3, "c", "b")]
        self.assertEqual(stack_tip.plan(prs), {"label": [3], "unlabel": []})
        self.assertEqual(stack_tip.plan(prs[:1]), {"label": [2], "unlabel": []})

    def test_convergent_on_a_second_run(self) -> None:
        prs = stack(1, 6) + stack(50, 4)
        first = stack_tip.plan(prs)
        for p in prs:
            if p["number"] in first["label"]:
                p["labels"].append("full-ci")
        self.assertEqual(stack_tip.plan(prs), {"label": [], "unlabel": []})

    def test_labels_may_be_names_or_objects(self) -> None:
        prs = [pr(1, "a", "x", [{"name": "full-ci"}]), pr(2, "b", "x", ["bug"])]
        self.assertEqual(stack_tip.plan(prs), {"label": [2], "unlabel": []})

    def test_a_fork_pr_never_counts_as_a_child_or_a_tip(self) -> None:
        prs = [pr(1, "a", "x"), pr(2, "z", "a", cross=True)]
        self.assertEqual(stack_tip.plan(prs), {"label": [1], "unlabel": []})

    def test_two_prs_on_one_base_are_both_tips(self) -> None:
        prs = [pr(1, "a", "master"), pr(2, "b", "a"), pr(3, "c", "a")]
        self.assertEqual(stack_tip.plan(prs), {"label": [2, 3], "unlabel": []})


if __name__ == "__main__":
    unittest.main()
