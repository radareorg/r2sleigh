#!/usr/bin/env python3
"""Locate every machine-noise site the rendering gate counts.

The gate reports one number per counter per configuration, which says a
rendering is noisy without saying where.  This prints the individual sites so a
counter can be traced to the layer that emits it.
"""

from __future__ import annotations

import argparse
import collections
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import verify_rendering as V


def sites(source: str) -> list[tuple[int, str, str]]:
    """Every noise site as (line number, counter name, the text that matched)."""
    found: list[tuple[int, str, str]] = []

    def line_of(offset: int) -> int:
        return source.count("\n", 0, offset) + 1

    for match in V.FLAG_CARRIER_RE.finditer(source):
        found.append((line_of(match.start()), "flag_carriers", match.group(0)))
    for match in V.SELF_ASSIGN_RE.finditer(source):
        found.append((line_of(match.start()), "self_assignments", match.group(0).strip()))
    for match in V.LITERAL_ONLY_DECL_RE.finditer(source):
        found.append(
            (line_of(match.start()), "literal_only_declarations", match.group(0).strip())
        )
    types = V.declared_types(source)
    for match in V.CAST_OF_NAME_RE.finditer(source):
        if types.get(match.group(2)) == V.normalize_cast(match.group(1)):
            found.append((line_of(match.start()), "same_type_casts", match.group(0)))
    for run in V.CAST_RUN_RE.finditer(source):
        casts = [V.normalize_cast(c.group(0)) for c in V.CAST_RE.finditer(run.group(0))]
        for first, second in zip(casts, casts[1:]):
            if first == second:
                found.append((line_of(run.start()), "same_type_casts", run.group(0)))
        if not V.run_is_required(casts):
            found.append((line_of(run.start()), "cast_chains", run.group(0)))
    for condition in V.CONDITION_KEYWORD_RE.finditer(source):
        opening = source.index("(", condition.start())
        depth = 0
        for index in range(opening, len(source)):
            if source[index] == "(":
                depth += 1
            elif source[index] == ")":
                depth -= 1
                if depth == 0:
                    text = source[opening + 1 : index]
                    if len(V.split_top_level_commas(text)) > 1:
                        found.append((line_of(opening), "comma_conditions", text))
                    break
    for index, line in enumerate(source.splitlines(), start=1):
        if "goto " in line:
            found.append((index, "gotos", line.strip()))
    return sorted(found)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="rendered C files (default: the matrix raw artifacts)")
    parser.add_argument("--counter", help="report only this counter")
    parser.add_argument("--summary", action="store_true", help="counts per file, not sites")
    args = parser.parse_args()

    paths = [pathlib.Path(p) for p in args.paths]
    if not paths:
        paths = sorted(pathlib.Path("tests/corpus/artifacts/raw").glob("*.c"))

    totals: collections.Counter[str] = collections.Counter()
    for path in paths:
        source = path.read_text()
        found = [s for s in sites(source) if not args.counter or s[1] == args.counter]
        per_file: collections.Counter[str] = collections.Counter(kind for _, kind, _ in found)
        totals.update(per_file)
        if args.summary:
            if per_file:
                print(f"{path}: {dict(sorted(per_file.items()))}")
            continue
        for line, kind, text in found:
            flat = " ".join(text.split())
            print(f"{path}:{line}: {kind}: {flat[:160]}")
    print(f"total: {dict(sorted(totals.items()))}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
