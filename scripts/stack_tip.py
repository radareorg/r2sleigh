#!/usr/bin/env python3
"""Which open pull requests gain or lose `full-ci`: the tip of each stack carries it (ROADMAP D43).

Input: a JSON list of open PRs, `[{number, head, base, labels}]` (labels as names or `{name}`).
Output: `{"label": [numbers], "unlabel": [numbers]}`, sorted. A PR based on the trunk is
left alone (`plan` runs it in full anyway); a PR from a fork is ignored (`cross: true`).
"""

from __future__ import annotations

import argparse
import json
import sys

LABEL = "full-ci"


def names(labels: list) -> set[str]:
    return {x["name"] if isinstance(x, dict) else x for x in labels}


def plan(prs: list[dict], trunk: str = "master") -> dict[str, list[int]]:
    """A tip is an open stacked PR whose head no other open PR names as its base. O(n)."""
    own = [p for p in prs if not p.get("cross") and p.get("state", "open").lower() == "open"]
    based_on: dict[str, set[int]] = {}
    for p in own:
        based_on.setdefault(p["base"], set()).add(p["number"])
    label, unlabel = [], []
    for p in own:
        if p["base"] == trunk:
            continue
        has_child = bool(based_on.get(p["head"], set()) - {p["number"]})
        carries = LABEL in names(p.get("labels", []))
        if not has_child and not carries:
            label.append(p["number"])
        elif has_child and carries:
            unlabel.append(p["number"])
    return {"label": sorted(label), "unlabel": sorted(unlabel)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prs", help="JSON file of open PRs, or - for stdin")
    parser.add_argument("--trunk", default="master")
    args = parser.parse_args()
    raw = sys.stdin.read() if args.prs == "-" else open(args.prs).read()
    print(json.dumps(plan(json.loads(raw), args.trunk)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
