#!/usr/bin/env python3
"""Whether `afv` and `pdd` name the same frame objects (ROADMAP P4, doc/adr-frame-model.md).

    scripts/frame_agree.py [--r2s R2S] [--details FILE] [BINARY...]

For every function of the census binaries, `afv` lists the frame's locals at
entry-stack offsets and `pddj` the locals the rendering declares at the same
offsets. Each offset either side names is classified:

  agree         the same locals on each side, by name and type
  name          one on each side, names differ
  type          one on each side, same name, types differ
  afv-only      `afv` lists it; the rendering declares nothing there
  pdd-only      the rendering declares it; `afv` does not list it
  afv-twice     `afv` lists the offset more than once
  pdd-twice     the rendering declares the offset more than once

P4 exits when every offset agrees.
"""

import argparse
import collections
import concurrent.futures
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from census import ROOT, corpus, r2s  # noqa: E402

AFV = re.compile(r"^var (?P<ty>.+) (?P<name>\S+) @ entry\.sp(?P<sign>[-+])0x(?P<off>[0-9a-f]+)$")


def afv_locals(text):
    found = collections.defaultdict(list)
    for line in text.splitlines():
        m = AFV.match(line.strip())
        if m:
            offset = int(m["off"], 16) * (-1 if m["sign"] == "-" else 1)
            found[offset].append((m["name"], m["ty"]))
    return found


def pdd_locals(text):
    found = collections.defaultdict(list)
    try:
        variables = json.loads(text).get("variables") or []
    except (json.JSONDecodeError, AttributeError):
        return None
    for variable in variables:
        location = variable.get("location", "")
        if variable.get("kind") == "local" and location.startswith("stack:"):
            found[int(location[len("stack:"):], 16)].append((variable["name"], variable["type"]))
    return found


def classify(afv, pdd):
    kinds = collections.Counter()
    details = []
    for offset in sorted(set(afv) | set(pdd)):
        a, p = afv.get(offset, []), pdd.get(offset, [])
        if sorted(a) == sorted(p):
            kind = "agree"
        elif len(a) > 1:
            kind = "afv-twice"
        elif len(p) > 1:
            kind = "pdd-twice"
        elif not p:
            kind = "afv-only"
        elif not a:
            kind = "pdd-only"
        elif a[0][0] != p[0][0]:
            kind = "name"
        elif a[0][1] != p[0][1]:
            kind = "type"
        else:
            kind = "agree"
        kinds[kind] += 1
        if kind != "agree":
            details.append((offset, kind, a, p))
    return kinds, details


def one_function(executable, binary, address):
    afv = afv_locals(r2s(binary, f"afv @ {address}", executable))
    pdd = pdd_locals(r2s(binary, f"pddj @ {address}", executable))
    if pdd is None:
        return address, None, []
    kinds, details = classify(afv, pdd)
    return address, kinds, details


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--r2s", default=str(ROOT / "target/debug/r2s"))
    parser.add_argument("--details", type=Path)
    parser.add_argument("binaries", nargs="*", type=Path)
    args = parser.parse_args()
    totals = collections.Counter()
    unrendered = 0
    lines = []
    for binary in args.binaries or corpus():
        listing = r2s(binary, "afl", args.r2s)
        addresses = [line.split()[0] for line in listing.splitlines() if line.startswith("0x")]
        with concurrent.futures.ThreadPoolExecutor(os.cpu_count()) as pool:
            results = list(pool.map(lambda a: one_function(args.r2s, binary, a), addresses))
        for address, kinds, details in results:
            if kinds is None:
                unrendered += 1
                continue
            totals.update(kinds)
            lines.extend(f"{binary.name} {address} {off:#x} {kind} afv={a} pdd={p}"
                         for off, kind, a, p in details)
    offsets = sum(totals.values())
    print(f"frame agreement: {totals['agree']} of {offsets} offsets agree; {unrendered} functions not rendered")
    for kind, count in totals.most_common():
        if kind != "agree":
            print(f"  {kind:10} {count}")
    if args.details:
        args.details.write_text("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
