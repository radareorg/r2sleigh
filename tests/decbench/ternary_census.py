#!/usr/bin/env python3
"""Count the `?:` of r2s renderings by what wrote them, for doc/adr-select-respelling.md.

    ternary_census.py DUMP [--without-select DUMP2]

DUMP is a `mined_set.py dump` directory. A statement is a rendering line `name = ...;`; a guard is a `?:` whose
condition compares a shift count with a width, `count >= (uintN_t)W`. Counts are `sites functions`.

* `holding`: statements that hold a `?:` anywhere in their right side; `whole`: statements whose right side is
  one `?:`; `occurrences`: every ` ? ` of every line.
* `guard`: statements holding a guard; `guard occurrences`: the guards.
* `branch-born`: statements, not holding a guard, that the build without `shape::select` (DUMP2) does not write.
* `data`: the rest, which no branch or shift guard in the text accounts for.
* `literal count`: statements that begin with a guard whose count is a literal, by shape: `single` (one cast on
  the count, `0` for the true value: what a literal count's guard folds to), `widened` (two casts on the
  count), `arithmetic` (the true value is a second `?:`, a sign fill). `literal count anywhere`: every
  `literal >= literal ?` of every line.
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from counterfactual_ged import split_ternary  # noqa: E402

CAST = r"\((?:u?int\d+_t)\)"
LITERAL = rf"(?:{CAST})*-?(?:0x[0-9a-fA-F]+|\d+)U?"
GUARD = re.compile(r">= \(u?int\d+_t\)(?:8|16|32|64|128)U \? ")
STATEMENT = re.compile(r"^\s*\w+ = (.*);$")
LITERAL_ANYWHERE = re.compile(rf"({LITERAL}) >= ({LITERAL}) \? ")
LITERAL_GUARD = re.compile(rf"^\s*\w+ = ({LITERAL}) >= ({LITERAL}) \? (.*)$")
SINGLE = re.compile(rf"^{CAST}\d+U >= {CAST}\d+U$")


def renderings(dump: Path):
    """(key, code) of every rendering a dump holds."""
    for path in sorted(dump.glob("*.json")):
        if path.name == "manifest.json":
            continue
        for name, row in json.loads(path.read_text()).items():
            if row.get("code"):
                yield (path.name, name), row["code"]


def classify(line: str, absent: collections.Counter | None) -> list[str]:
    """The classes of one rendering line; `absent` holds the lines of the build without `shape::select`."""
    classes = ["occurrences"] * line.count(" ? ")
    classes += ["literal count anywhere"] * len(LITERAL_ANYWHERE.findall(line))
    match = STATEMENT.match(line)
    if not match or " ? " not in match.group(1):
        return classes
    classes.append("holding")
    if split_ternary(match.group(1)):
        classes.append("whole")
    guards = len(GUARD.findall(line))
    classes += ["guard occurrences"] * guards
    if guards:
        classes.append("guard")
    elif absent is not None and absent[line] == 0:
        classes.append("branch-born")
    else:
        classes.append("data")
    if literal := LITERAL_GUARD.match(line):
        if " ? " in literal.group(3).split(" : ")[0]:
            shape = "arithmetic"
        elif SINGLE.match(f"{literal.group(1)} >= {literal.group(2)}"):
            shape = "single"
        else:
            shape = "widened"
        classes += ["literal count", f"literal count {shape}"]
    return classes


def census(dump: Path, without_select: Path | None = None):
    """{class: (sites, functions)} over the dump."""
    others = dict(renderings(without_select)) if without_select else {}
    sites: collections.Counter = collections.Counter()
    functions: dict[str, set] = collections.defaultdict(set)
    for key, code in renderings(dump):
        absent = collections.Counter(others[key].splitlines()) if key in others else None
        for line in code.splitlines():
            for name in classify(line, absent):
                sites[name] += 1
                functions[name].add(key)
    return {name: (sites[name], len(functions[name])) for name in sites}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dump", type=Path)
    parser.add_argument("--without-select", type=Path)
    args = parser.parse_args()
    for name, (sites, functions) in sorted(census(args.dump, args.without_select).items()):
        print(f"{name:28} {sites:6} {functions:5}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
