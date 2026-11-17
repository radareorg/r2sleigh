#!/usr/bin/env python3
"""The `<< 32` residual gate (ROADMAP D211, user ruling 2026-11-16 (a)): the set is irreducible.

Every DecBench function whose rendering holds `r2sleigh_residual_uN(n) << 32` has an entry in
`residual_shift_judged.toml` that proves the site irreducible (`proof`, with its citation and
witness addresses) or names the ROADMAP row that removes it (`row`, which must stand open). The gate
fails on a site no entry lists, on an entry whose function holds no site, on more sites than an
entry lists, and on a row ROADMAP does not hold open.

    scripts/residual_shift_gate.py --renders O2=DIR --renders O2-noinline=DIR

Each DIR holds `<project>_<binary>.json`, `{address: {"code": ...}}`, as `pddj` writes one record
per function (the DecBench runner's output).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
TABLE = pathlib.Path(__file__).resolve().parent / "residual_shift_judged.toml"
SITE = re.compile(r"r2sleigh_residual_u\d+\(\d+\) << 32")
ROW = re.compile(r"^\| (D\d+) \|.*\| ([^|]*) \|\s*$")


def load(path: pathlib.Path) -> list[dict]:
    """The judged entries of the table at `path`."""
    return tomllib.loads(path.read_text()).get("function", [])


def open_rows(roadmap: str) -> set[str]:
    """The ROADMAP rows whose status cell says open."""
    rows = set()
    for line in roadmap.splitlines():
        match = ROW.match(line)
        if match and re.search(r"\bopen\b", match.group(2)):
            rows.add(match.group(1))
    return rows


def sites(renders: dict[str, pathlib.Path]) -> dict[tuple[str, str, int], int]:
    """Each rendered function holding a site, by set, binary and address: its site count."""
    found = {}
    for name, directory in sorted(renders.items()):
        for path in sorted(pathlib.Path(directory).glob("*.json")):
            for address, record in json.loads(path.read_text()).items():
                count = len(SITE.findall(record.get("code", "")))
                if count:
                    found[(name, path.stem, int(address, 16))] = count
    return found


def failures(renders: dict[str, pathlib.Path], entries: list[dict], rows: set[str]) -> list[str]:
    """What the gate fails on, one line each; empty when every site is judged."""
    found = sites(renders)
    out = []
    listed = {}
    for row in entries:
        key = (row["set"], row["binary"], int(str(row["address"]), 16))
        listed[key] = row
        where = f"{row['set']} {row['binary']} {row['address']}"
        if ("proof" in row) == ("row" in row):
            out.append(f"{where}: an entry states a proof or a row, exactly one")
        if "row" in row and row["row"] not in rows:
            out.append(f"{where}: row {row['row']} is not open in ROADMAP")
        if key[0] in renders and key not in found:
            out.append(f"{where}: holds no site; remove the entry")
        elif key in found and found[key] > row["sites"]:
            out.append(f"{where}: {found[key]} sites, the entry lists {row['sites']}")
    for key, count in sorted(found.items()):
        if key not in listed:
            out.append(f"{key[0]} {key[1]} {key[2]:#x}: {count} sites no entry lists")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--renders", action="append", default=[], help="SET=DIR")
    parser.add_argument("--table", type=pathlib.Path, default=TABLE)
    parser.add_argument("--roadmap", type=pathlib.Path, default=ROOT / "ROADMAP.md")
    args = parser.parse_args()
    renders = dict(item.split("=", 1) for item in args.renders)
    entries = load(args.table)
    found = failures(renders, entries, open_rows(args.roadmap.read_text()))
    held = sites(renders)
    print(f"{len(held)} functions, {sum(held.values())} sites; {len(entries)} entries")
    for line in found:
        print(line)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
