#!/usr/bin/env python3
"""Hold the records of several gate shards to one baseline.

    tests/equiv/merge_shards.py --baseline tests/equiv/baseline.json \\
        --out merged shard-*/records.json

Continuous integration grades the population in shards, one per compiler and
optimisation level, so the gate fits in minutes. Each shard writes its
``records.json`` without a ratchet; this joins them, holds the union to the
baseline exactly as ``run_equiv.py --baseline`` would, and writes the joined
records and a proposed baseline beside them. The proposed baseline keeps every
cause the current one records for the same status and reason, so blessing a
run is reading it, filling in the causes it leaves empty, and committing it.

Every baseline record must be graded by some shard: a shard missing from the
matrix would otherwise drop its records unseen. ``--partial`` holds only the
configurations the given shards ran, for a local run over part of the
population. A shard built with another toolchain than the baseline's is
refused, as in the gate, and so are shards of two targets (a shard's
``config.target``; a file written before the target axis is x86-64's).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import gate  # noqa: E402
from target import by_name  # noqa: E402
from run_equiv import EXIT_OK, EXIT_RATCHET, EXIT_SETUP, summarize  # noqa: E402


def load_records(paths: list[Path]) -> tuple[list[gate.Record], set[tuple[str, str]], dict]:
    records: list[gate.Record] = []
    ran: set[tuple[str, str]] = set()
    toolchain: dict[str, str] = {}
    targets: set[str] = set()
    for path in paths:
        payload = json.loads(path.read_text(encoding="utf-8"))
        config = payload["config"]
        target = by_name(config.get("target", "x86-64"))
        targets.add(target.name)
        if len(targets) > 1:
            raise ValueError(f"{path}: shards of {' and '.join(sorted(targets))} cannot be "
                             "held to one baseline")
        for name, version in (config.get("toolchain") or {}).items():
            if toolchain.setdefault(name, version) != version:
                raise ValueError(f"{path}: {name} is {version}, another shard has "
                                 f"{toolchain[name]}")
        for source in config["sources"]:
            for compiler in config["compilers"].split(","):
                for opt in config["opts"].split(","):
                    ran.add((source, target.config(compiler, opt)))
        for raw in payload["records"]:
            records.append(gate.Record(
                key=raw["key"], function=raw["function"], address=int(raw["address"], 16),
                status=raw["status"], evidence=raw.get("evidence", {}),
                signature=raw.get("signature", ""), definition=raw.get("definition", ""),
                proof=raw.get("proof", {}), vectors=raw.get("vectors", {}),
                strict=raw.get("strict", ""),
            ))
    return records, ran, toolchain


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--partial", action="store_true",
                        help="hold only the configurations these shards ran")
    parser.add_argument("records", type=Path, nargs="+")
    args = parser.parse_args(argv)

    try:
        records, ran, toolchain = load_records(args.records)
    except (ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"merge: {error}", file=sys.stderr)
        return EXIT_SETUP
    baseline = gate.load_baseline(args.baseline)
    blessed = baseline.get("toolchain")
    if blessed is not None and any(blessed.get(name) != version
                                   for name, version in toolchain.items()):
        print(f"ratchet: the baseline was blessed on {blessed}, the shards built with "
              f"{toolchain}; the statuses are not comparable")
        return EXIT_RATCHET

    keys = [record.key for record in records]
    duplicated = sorted({key for key in keys if keys.count(key) > 1})
    if duplicated:
        print(f"merge: graded by two shards: {', '.join(duplicated[:5])}", file=sys.stderr)
        return EXIT_SETUP
    records.sort(key=lambda record: record.key)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "records.json").write_text(json.dumps(
        {"schema": 1, "toolchain": toolchain,
         "records": [record.to_json() for record in records]}, indent=1) + "\n",
        encoding="utf-8")
    proposed = gate.baseline_from(records, baseline, toolchain)
    (args.out / "baseline.proposed.json").write_text(
        json.dumps(proposed, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(summarize(records))

    def held(key: str) -> bool:
        parts = key.split("::")
        return len(parts) == 3 and (parts[0], parts[1]) in ran

    selected = {key for key in baseline["records"] if not args.partial or held(key)}
    graded = {r.key: (r.status, gate.reason(r.status, r.evidence)) for r in records}
    problems = gate.ratchet(baseline, graded, selected)
    for line in problems:
        print(f"ratchet: {line}")
    if problems:
        print(f"ratchet: to bless, read {args.out / 'records.json'}, fill in every empty "
              f"cause in {args.out / 'baseline.proposed.json'} and commit it as the baseline")
        return EXIT_RATCHET
    print(f"ratchet: {len(selected)} baseline records held")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
