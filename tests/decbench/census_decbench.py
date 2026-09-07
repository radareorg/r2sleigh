#!/usr/bin/env python3
"""Rank refusal causes across a sweep's per-binary censuses.

The benchmark's own results carry one boolean per function, so a sweep answers
*how many* functions were declined and never *why*.  Each binary writes a
census beside the run (``r2sleigh-refusals-*.json``); this reads a directory of
them and reports the ranking that coverage work is supposed to be planned
against.

Two distinctions the report keeps, because collapsing either one has already
misdirected a session's work:

*Harness failures are not refusals.*  A cause prefixed ``harness:`` is this
tooling saying it never got to ask -- a crashed ``r2``, a plugin that would not
load.  Counting those as the decompiler declining is how five zlib binaries
reporting zero functions read as an unusually shy decompiler while holding 68%
of the benchmark's refusals.  They are ranked separately and, being tooling
defects rather than proof gaps, ranked first.

*Causes compose multiplicatively.*  A census records only the first cause per
function, so ``P(render) = prod(1 - p_i)`` and closing the top cause unmasks
the next.  A share here is an upper bound on what closing that cause buys, and
the ranking must be retaken after each one is closed rather than planned once.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
import sys

HARNESS = "harness:"
FLAG_PREFIX = re.compile(r"^(?:(?:dbg|sym|fcn|loc|flirt)\.)+")


def _binary_key(payload: dict) -> tuple[str, str, str]:
    parts = pathlib.PurePosixPath(payload.get("binary_path", "")).parts
    if len(parts) < 4 or parts[-2] != "compiled":
        raise ValueError(f"cannot identify census binary: {payload.get('binary_path')}")
    # DecBench records Path.stem, including for versioned shared libraries.
    return parts[-3], parts[-4], pathlib.PurePosixPath(parts[-1]).stem


def reconcile(payloads: list[dict], results: list[dict], discovery: list[dict] = ()) -> dict:
    """Join scored misses to their own binary's census without borrowing causes."""
    censuses = {}
    for payload in payloads:
        key = _binary_key(payload)
        if key in censuses:
            raise ValueError(f"duplicate census binary: {key}")
        names = collections.defaultdict(list)
        for flag, cause in sorted(payload.get("by_function", {}).items()):
            name = FLAG_PREFIX.sub("", flag) or flag
            names[name].append({"flag": flag, "cause": cause})
        censuses[key] = names

    aliases = {}
    for payload in discovery:
        key = _binary_key(payload)
        if key in aliases:
            raise ValueError(f"duplicate discovery binary: {key}")
        by_address = collections.defaultdict(set)
        for function in payload["functions"]:
            by_address[function["addr"]].add(FLAG_PREFIX.sub("", function["name"]))
        symbols = collections.defaultdict(set)
        for symbol in payload["symbols"]:
            if symbol.get("type") == "FUNC" and not symbol.get("is_imported", False):
                symbols[symbol["name"]].add(symbol["vaddr"])
        aliases[key] = {}
        for name, addresses in symbols.items():
            if len(addresses) != 1:
                continue
            address = next(iter(addresses))
            owners = by_address.get(address, set())
            if len(owners) == 1:
                owner = next(iter(owners))
                if owner != name:
                    aliases[key][name] = {"function": owner, "address": address}

    totals = collections.Counter()
    binaries = {}
    misses = []
    seen = set()
    for result in results:
        for group in result.get("groups", []):
            key = tuple(group[field] for field in ("project", "opt_level", "binary"))
            census = censuses.get(key)
            counts = binaries.setdefault(key, collections.Counter())
            rendered_names = {function["function"] for function in group.get("functions", [])
                              if function.get("decompiled", {}).get("r2sleigh")}
            for function in group.get("functions", []):
                name = function["function"]
                identity = (*key, name)
                if identity in seen:
                    raise ValueError(f"duplicate scored function: {identity}")
                seen.add(identity)
                totals["scored"] += 1
                totals["rendered"] += bool(function.get("decompiled", {}).get("r2sleigh"))
                totals["angr_rendered"] += bool(function.get("decompiled", {}).get("angr"))
                if function.get("decompiled", {}).get("r2sleigh"):
                    continue
                matches = census.get(name, []) if census is not None else []
                alias = aliases.get(key, {}).get(name) if not matches else None
                if alias and census is not None:
                    matches = census.get(alias["function"], [])
                if census is None:
                    status = "missing_census"
                elif len(matches) > 1:
                    status = "ambiguous_census_name"
                elif matches:
                    status = "named_refusal"
                elif alias and alias["function"] in rendered_names:
                    status = "rendered_alias"
                else:
                    status = "no_census_entry"
                totals["missed"] += 1
                totals[status] += 1
                counts[status] += 1
                misses.append(dict(zip(("project", "opt_level", "binary"), key)) | {
                    "function": name, "status": status, "matches": matches, "alias": alias,
                })

    return {
        "totals": dict(sorted(totals.items())),
        "by_binary": [dict(zip(("project", "opt_level", "binary"), key)) | dict(counts)
                      for key, counts in sorted(binaries.items())],
        "misses": sorted(misses, key=lambda row: tuple(
            row[field] for field in ("project", "opt_level", "binary", "function")
        )),
    }


def _cell(payload: dict) -> str:
    """The project/optimization cell a census belongs to.

    Derived from the recorded build path rather than asked for, because the
    adapter is handed a path and nothing else.  decbench lays binaries out as
    ``<out>/<opt>/<project>/compiled/<binary>``; when the path does not have
    that shape the cell is reported as unknown rather than guessed.
    """
    raw = payload.get("binary_path")
    if not raw:
        return "unknown"
    parts = pathlib.PurePosixPath(raw).parts
    if len(parts) >= 4 and parts[-2] == "compiled":
        return f"{parts[-3]}/{parts[-4]}"
    return "unknown"


def load(directory: pathlib.Path) -> list[dict]:
    payloads = []
    for path in sorted(directory.rglob("r2sleigh-refusals-*.json")):
        try:
            payloads.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError) as exc:
            print(f"skipped {path.name}: {exc}", file=sys.stderr)
    return payloads


def report(payloads: list[dict], top: int) -> None:
    rendered = sum(p.get("rendered", 0) for p in payloads)
    declined = sum(p.get("declined", 0) for p in payloads)
    observed = rendered + declined
    if observed == 0:
        print("no functions observed in any census", file=sys.stderr)
        return

    by_cell: dict[str, list[int]] = collections.defaultdict(lambda: [0, 0, 0])
    causes: collections.Counter[str] = collections.Counter()
    gap_causes: collections.Counter[str] = collections.Counter()
    gapped = 0
    gap_ops = 0
    for payload in payloads:
        cell = by_cell[_cell(payload)]
        cell[0] += payload.get("rendered", 0)
        cell[1] += payload.get("declined", 0)
        cell[2] += payload.get("gapped", 0)
        causes.update(payload.get("causes", {}))
        gap_causes.update(payload.get("gap_causes", {}))
        gapped += payload.get("gapped", 0)
        gap_ops += payload.get("gap_ops", 0)

    print(f"binaries   {len(payloads)}")
    print(f"observed   {observed} functions")
    print(f"coverage   {rendered}/{observed} = {rendered / observed:.3f}")
    # A gapped function is rendered but not proven, so both are printed:
    # coverage bought entirely with gaps is not progress.
    proven = rendered - gapped
    print(f"proven     {proven}/{observed} = {proven / observed:.3f}"
          f"  ({gapped} gapped, {gap_ops} ops)")
    print()

    print("by cell")
    for name in sorted(by_cell):
        rend, decl, gaps = by_cell[name]
        total = rend + decl
        share = rend / total if total else 0.0
        suffix = f"  {gaps} gapped" if gaps else ""
        print(f"  {name:<24} {rend:>5}/{total:<5} = {share:.3f}{suffix}")
    print()

    harness = [(c, n) for c, n in causes.items() if c.startswith(HARNESS)]
    proof = [(c, n) for c, n in causes.items() if not c.startswith(HARNESS)]

    gap_rows = list(gap_causes.items())
    for title, rows in (
        ("harness failures", harness),
        ("refusal causes", proof),
        ("gap causes", gap_rows),
    ):
        lost = sum(n for _, n in rows)
        unit = "gaps" if title == "gap causes" else "functions"
        print(f"{title}: {lost} {unit}, {lost / observed:.3f} of all observed")
        for cause, count in sorted(rows, key=lambda kv: (-kv[1], kv[0]))[:top]:
            print(f"  {count:>5}  {count / observed:.3f}  {cause}")
        if not rows:
            print("  none")
        print()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=pathlib.Path,
                        help="directory holding r2sleigh-refusals-*.json")
    parser.add_argument("--top", type=int, default=20,
                        help="how many causes to list per category")
    parser.add_argument("--results", type=pathlib.Path, nargs="+",
                        help="reconcile scored JSON files and print the join as JSON")
    parser.add_argument("--discovery", type=pathlib.Path,
                        help="JSON list of binary_path, functions (aflj), and symbols (isj) records")
    args = parser.parse_args()
    if args.discovery and not args.results:
        parser.error("--discovery requires --results")
    payloads = load(args.directory)
    if not payloads:
        print(f"no census files under {args.directory}", file=sys.stderr)
        return 1
    if args.results:
        try:
            results = [json.loads(path.read_text(encoding="utf-8")) for path in args.results]
            discovery = json.loads(args.discovery.read_text(encoding="utf-8")) if args.discovery else []
            print(json.dumps(reconcile(payloads, results, discovery), indent=2))
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
    else:
        report(payloads, args.top)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
