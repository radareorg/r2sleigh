#!/usr/bin/env python3
"""Fold a samply profile into collapsed stacks, and report where the time goes.

    samply record --save-only --no-open --unstable-presymbolicate -o prof.json.gz \\
        target/profiling/r2s -q -c 'pdd @ 0x...' BINARY
    python3 scripts/samply_collapse.py prof.json.gz --top 30 > prof.folded
    inferno-flamegraph < prof.folded > prof.svg

stdout gets the collapsed stacks (one `a;b;c count` line per stack); stderr
gets the functions with the most inclusive and self samples.
"""

import argparse
import bisect
import collections
import gzip
import json
import re
import sys


def symbolicate(syms):
    """Per library: sorted symbol starts, and (end, name) for each."""
    names = syms["string_table"]
    tables = {}
    for lib in syms["data"]:
        rows = sorted(lib["symbol_table"], key=lambda row: row["rva"])
        starts = [row["rva"] for row in rows]
        spans = [(row["rva"] + row["size"], names[row["symbol"]]) for row in rows]
        tables[lib["debug_name"]] = (starts, spans)
    return tables


def lookup(tables, lib, address):
    starts, spans = tables.get(lib, ([], []))
    index = bisect.bisect_right(starts, address) - 1
    if index >= 0 and address < spans[index][0]:
        return spans[index][1]
    return f"{lib}+{address:#x}"


def short(name):
    """Drop generic arguments and hashes so one function is one frame."""
    name = re.sub(r"::h[0-9a-f]{16}$", "", name)
    depth, out = 0, []
    for ch in name:
        if ch == "<":
            depth += 1
            if depth == 1 and out and out[-1] != ":":
                continue
        if depth == 0 or (depth == 1 and ch == "<" and (not out or out[-1] == ":")):
            out.append(ch)
        if ch == ">":
            depth -= 1
    return "".join(out).replace(";", ",")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("profile")
    parser.add_argument("--top", type=int, default=25)
    parser.add_argument("--match", default="r2", help="report only frames containing this")
    args = parser.parse_args()
    profile = json.load(gzip.open(args.profile))
    syms_path = re.sub(r"\.gz$", "", args.profile).removesuffix(".json") + ".json.syms.json"
    tables = symbolicate(json.load(open(syms_path)))
    libs = [lib["debugName"] for lib in profile["libs"]]
    stacks = collections.Counter()
    inclusive = collections.Counter()
    self_time = collections.Counter()
    total = 0
    for thread in profile["threads"]:
        frames, funcs = thread["frameTable"], thread["funcTable"]
        resources, stack_table = thread["resourceTable"], thread["stackTable"]
        names = {}

        def frame_name(frame):
            if frame not in names:
                resource = funcs["resource"][frames["func"][frame]]
                lib = libs[resources["lib"][resource]] if resource is not None and resource >= 0 else "?"
                names[frame] = short(lookup(tables, lib, frames["address"][frame]))
            return names[frame]

        samples = thread["samples"]
        weights = samples.get("weight") or [1] * samples["length"]
        for stack, weight in zip(samples["stack"], weights):
            if stack is None:
                continue
            path = []
            while stack is not None:
                path.append(frame_name(stack_table["frame"][stack]))
                stack = stack_table["prefix"][stack]
            path.reverse()
            weight = weight or 1
            total += weight
            stacks[";".join(path)] += weight
            for name in set(path):
                inclusive[name] += weight
            self_time[path[-1]] += weight
    for stack, count in stacks.items():
        print(f"{stack} {count}")
    for title, counter in (("inclusive", inclusive), ("self", self_time)):
        print(f"== {title} (of {total} samples)", file=sys.stderr)
        rows = [(n, c) for n, c in counter.most_common() if args.match in n]
        for name, count in rows[: args.top]:
            print(f"{100 * count / total:6.1f}%  {name[:150]}", file=sys.stderr)


if __name__ == "__main__":
    main()
