#!/usr/bin/env python3
"""Every baseline source is in an equivalence shard, and every shard source has records (ROADMAP D43).

The shards are the `sources:` lines of the two equivalence matrices in ci.yml. A source in a
baseline and in no shard is never graded; a shard source with no record grades nothing.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ".github/workflows/ci.yml"
# Job id in ci.yml -> the baseline its shards are graded against.
JOBS = {
    "equivalence-shard": "tests/equiv/baseline.json",
    "equivalence-shard-aarch64": "tests/equiv/baseline-aarch64.json",
}
JOB = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
SOURCES = re.compile(r"^\s+sources:\s*(\S.*?)\s*$")


def shards_of(workflow: str) -> dict[str, list[str]]:
    """The sources of every `sources:` line, by the job that holds it."""
    out: dict[str, list[str]] = {}
    job = None
    for line in workflow.splitlines():
        if m := JOB.match(line):
            job = m.group(1)
        elif (m := SOURCES.match(line)) and job is not None:
            out.setdefault(job, []).extend(m.group(1).split())
    return out


def sources_of(baseline: dict) -> set[str]:
    """The source of each `<source>::<config>::<function>` record key."""
    return {key.split("::", 1)[0] for key in baseline.get("records", {})}


def problems(shards: dict[str, list[str]], baselines: dict[str, set[str]]) -> list[str]:
    """One message per defect; `shards` is by job, `baselines` by job as well."""
    out = []
    for job, recorded in sorted(baselines.items()):
        listed = set(shards.get(job, []))
        if not listed:
            out.append(f"{job}: no `sources:` line found, so no shard is checked")
        if not recorded:
            out.append(f"{job}: its baseline has no records, so nothing is graded")
        for source in sorted(recorded - listed):
            out.append(f"{job}: {source} has baseline records and is in no shard")
        for source in sorted(listed - recorded):
            out.append(f"{job}: {source} is in a shard and has no baseline record")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, default=ROOT)
    args = parser.parse_args()
    shards = shards_of((args.root / WORKFLOW).read_text())
    baselines = {
        job: sources_of(json.loads((args.root / path).read_text()))
        for job, path in JOBS.items()
    }
    found = problems(shards, baselines)
    for message in found:
        print(f"check_shards: {message}", file=sys.stderr)
    if not found:
        counts = ", ".join(f"{job} {len(srcs)}" for job, srcs in baselines.items())
        print(f"check_shards: every baseline source is in a shard ({counts})")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
