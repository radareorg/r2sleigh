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

`afv` states each slot's fate after ` ; ` (D633): a promoted slot or a save
agrees where the rendering declares nothing; a member of `frame` agrees where
the rendering declares the array `afv` lists; `pdd reads <name>` must name a
parameter of the rendering (`reads`). `--bound` fails the run when a
disagreement count exceeds the measured one, or the parsed `afv` rows fall.

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
from census import COMMITTED, ROOT, corpus, r2s  # noqa: E402

AFV = re.compile(r"^var (?P<ty>.+) (?P<name>\S+) @ entry\.sp(?P<sign>[-+])0x(?P<off>[0-9a-f]+)"
                 r"(?: ; (?P<fate>.+))?$")
ARRAY = re.compile(r"^(?P<name>\w+)\[(?P<n>\d+)\]$")


def afv_locals(text):
    """By offset, each `afv` row's (name, type, fate); an array row reads as C's `uint8_t[568]`."""
    found = collections.defaultdict(list)
    for line in text.splitlines():
        m = AFV.match(line.strip())
        if m:
            offset = int(m["off"], 16) * (-1 if m["sign"] == "-" else 1)
            name, ty = m["name"], m["ty"]
            array = ARRAY.match(name)
            if array:
                name, ty = array["name"], f"{ty}[{array['n']}]"
            found[offset].append((name, ty, m["fate"] or ""))
    return found


def pdd_locals(text):
    found = collections.defaultdict(list)
    try:
        rendering = json.loads(text)
    except json.JSONDecodeError:
        return None
    # A refused function declares nothing; afv then lists the frame model, and nothing compares.
    if not isinstance(rendering, dict) or rendering.get("refused"):
        return None
    variables = rendering.get("variables") or []
    # The parameters a promoted slot's `pdd reads <name>` must name.
    found["params"] = {variable["name"] for variable in variables if variable.get("kind") == "param"}
    for variable in variables:
        location = variable.get("location", "")
        if variable.get("kind") == "local" and location.startswith("stack:"):
            found[int(location[len("stack:"):], 16)].append((variable["name"], variable["type"]))
    return found


def stands_alone(fate, frame):
    """A fate that agrees with the rendering declaring nothing at its offset."""
    return fate.startswith(("promoted", "save", "home")) or (fate.startswith("in frame") and frame)


def classify(afv, pdd):
    kinds = collections.Counter()
    details = []
    params = pdd.pop("params", set())
    # `promoted, pdd reads <name>` agrees only where the rendering has a parameter of that name.
    for offset, rows in afv.items():
        for name, ty, fate in rows:
            if fate.startswith("promoted, pdd reads "):
                read = fate[len("promoted, pdd reads "):]
                kinds["reads-named"] += 1
                if read not in params:
                    kinds["reads"] += 1
                    details.append((offset, "reads", [(name, ty, fate)], sorted(params)))
    # The array is compared as one row of its own, where its byte 0 may share a member's offset.
    arrays = [(o, "frame", ty) for o, rows in afv.items() for name, ty, _ in rows if name == "frame"]
    declared = [(o, name, ty) for o, rows in pdd.items() for name, ty in rows if name == "frame"]
    afv = {o: [row for row in rows if row[0] != "frame"] for o, rows in afv.items()}
    pdd = {o: [row for row in rows if row[0] != "frame"] for o, rows in pdd.items()}
    afv = {o: rows for o, rows in afv.items() if rows}
    pdd = {o: rows for o, rows in pdd.items() if rows}
    frame = bool(arrays) and arrays == declared
    if arrays or declared:
        kind = "agree" if frame else "afv-only" if not declared else "pdd-only" if not arrays else "type"
        kinds[kind] += 1
        if kind != "agree":
            details.append(("frame", kind, arrays, declared))
    for offset in sorted(set(afv) | set(pdd)):
        rows, p = afv.get(offset, []), pdd.get(offset, [])
        a = [(name, ty) for name, ty, _ in rows]
        if not p and len(rows) == 1 and stands_alone(rows[0][2], frame):
            kind = "agree"
        elif sorted(a) == sorted(p):
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
        return address, None, [], 0
    kinds, details = classify(afv, pdd)
    return address, kinds, details, sum(len(rows) for rows in afv.values())


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--r2s", default=str(ROOT / "target/debug/r2s"))
    parser.add_argument("--details", type=Path)
    parser.add_argument("--bound", action="append", default=[], metavar="KIND=N",
                        help="fail when KIND counts more than N; `rows=N` fails when fewer afv rows parse")
    parser.add_argument("--committed", action="store_true", help="the committed census only (the gate's corpus)")
    parser.add_argument("binaries", nargs="*", type=Path)
    args = parser.parse_args()
    totals = collections.Counter()
    unrendered = 0
    rows = 0
    lines = []
    for binary in args.binaries or (corpus(COMMITTED) if args.committed else corpus()):
        listing = r2s(binary, "afl", args.r2s)
        addresses = [line.split()[0] for line in listing.splitlines() if line.startswith("0x")]
        with concurrent.futures.ThreadPoolExecutor(os.cpu_count()) as pool:
            results = list(pool.map(lambda a: one_function(args.r2s, binary, a), addresses))
        for address, kinds, details, parsed in results:
            if kinds is None:
                unrendered += 1
                continue
            rows += parsed
            totals.update(kinds)
            lines.extend(f"{binary.name} {address} {off if off == 'frame' else hex(off)} {kind}"
                         f" afv={a} pdd={p}" for off, kind, a, p in details)
    named, unread = totals.pop("reads-named", 0), totals.pop("reads", 0)
    offsets = sum(totals.values())
    print(f"frame agreement: {totals['agree']} of {offsets} offsets agree; {unrendered} functions refused;"
          f" {rows} afv rows parsed")
    for kind in ("name", "type", "afv-only", "pdd-only", "afv-twice", "pdd-twice"):
        print(f"  {kind:10} {totals[kind]}")
    print(f"  reads      {unread} of {named} `pdd reads` names no parameter of the rendering")
    totals["reads"] = unread
    if args.details:
        args.details.write_text("\n".join(lines) + "\n")
    failed = []
    for bound in args.bound:
        kind, limit = bound.split("=")
        if kind == "rows":
            failed += [f"afv rows {rows} < {limit}"] if rows < int(limit) else []
        elif totals[kind] > int(limit):
            failed.append(f"{kind} {totals[kind]} > {limit}")
    for failure in failed:
        print(f"frame_agree: {failure}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
