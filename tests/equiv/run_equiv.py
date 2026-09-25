#!/usr/bin/env python3
"""The compile-and-diff equivalence gate over r2s.

    tests/equiv/run_equiv.py [--r2s target/debug/r2s] [--baseline tests/equiv/baseline.json]

For every source in ``tests/corpus`` and ``tests/gold`` (or ``--sources``),
built with GCC and Clang at ``-O0``, ``-O1`` and ``-O2``, non-PIE:

1. r2s is shown only the ``strip --strip-all`` copy, and asked ``pddj`` at
   every function the unstripped build's DWARF names;
2. each rendering is compiled into a shared object whose link-map shim
   resolves its external identifiers to the original image;
3. inside the original image, the original function and the rendering are
   called from the same forked state through one register-level thunk, on
   boundary and random vectors, comparing the return (at the source's class
   and width), the arena its pointers point into, the program's writable
   segments, stdout, stderr and how the call ended;
4. uninitialised reads (``-ftrivial-auto-var-init=zero`` vs ``=pattern``) and
   undefined behaviour (UBSan, ``-O0`` vs ``-O2``) are graded separately.

Every function yields exactly one record (see ``gate.py`` for the statuses).
The self-tests in ``selftest.py`` run first; if any fails, nothing is graded
and the gate exits 2. With ``--baseline`` the run is held to the ratchet: no
function may leave ``equal``, and any new ``differs``, ``uninit`` or ``ub``
blocks (exit 1). The baseline is written only on request, with
``--write-baseline``, and every non-equal record in it needs a recorded cause
before the ratchet accepts it.

Runtime equivalence needs x86-64 Linux; elsewhere the gate says so and exits 3.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import build  # noqa: E402
import gate  # noqa: E402
import link  # noqa: E402
import selftest  # noqa: E402
from dwarf import Dwarf, code_constants, function_symbols  # noqa: E402
from r2s_batch import Answer, run_batch  # noqa: E402
from spec import call_spec  # noqa: E402

EXIT_OK, EXIT_RATCHET, EXIT_SELF_TEST, EXIT_SETUP = 0, 1, 2, 3


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--r2s", type=Path, default=build.REPO / "target" / "debug" / "r2s")
    parser.add_argument("--sources", type=Path, nargs="+", default=None,
                        help="C sources to build (default: tests/corpus/*.c tests/gold/*.c)")
    parser.add_argument("--compilers", default=",".join(build.COMPILERS))
    parser.add_argument("--opts", default=",".join(build.OPT_LEVELS))
    parser.add_argument("--only", default=None,
                        help="grade only record keys matching this regular expression")
    parser.add_argument("--out", type=Path, default=HERE / "artifacts")
    parser.add_argument("--cc", default="gcc", help="compiler for the renderings")
    parser.add_argument("--vectors", type=int, default=48)
    parser.add_argument("--timeout-ms", type=int, default=1000,
                        help="the original's budget per call; a rendering gets four times it")
    parser.add_argument("--function-timeout", type=float, default=300.0,
                        help="seconds r2s may spend on one function before it is restarted")
    parser.add_argument("--startup-timeout", type=float, default=600.0,
                        help="seconds r2s may spend opening a binary before its first function")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--baseline", type=Path, default=None)
    parser.add_argument("--write-baseline", type=Path, default=None)
    parser.add_argument("--self-test-only", action="store_true")
    parser.add_argument("--keep", action="store_true", help="keep every work directory")
    return parser.parse_args(argv)


def run_self_tests(config: gate.Config, out: Path) -> bool:
    outcomes = selftest.run_self_tests(config, out / "selftest")
    failed = [o for o in outcomes if not o.ok]
    for outcome in outcomes:
        mark = "ok  " if outcome.ok else "FAIL"
        print(f"self-test {mark} {outcome.case.name}: {outcome.record.status}"
              + (f" ({outcome.why})" if outcome.why else ""))
    if failed:
        print(f"{len(failed)} of {len(outcomes)} self-tests failed: the gate may not grade.")
    return not failed


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def functions_of(binary: build.Binary) -> tuple[Dwarf, list]:
    """The source's own functions in this build, from its DWARF, in address order."""
    dwarf = Dwarf.read(binary.unstripped)
    unit = binary.source.name
    subs = [s for s in dwarf.subprograms()
            if s.name and Path(s.unit).name == unit]
    seen: set[int] = set()
    unique = []
    for sub in subs:
        if sub.low_pc in seen:
            continue
        seen.add(sub.low_pc)
        unique.append(sub)
    return dwarf, unique


def grade_binary(binary: build.Binary, args: argparse.Namespace, config: gate.Config,
                 only: re.Pattern | None, pool: concurrent.futures.Executor) -> list[gate.Record]:
    dwarf, subs = functions_of(binary)
    symbols = function_symbols(binary.unstripped)
    all_functions = [s for s in dwarf.subprograms() if s.name]
    names_used: dict[str, int] = {}
    wanted = []
    for sub in subs:
        count = names_used.get(sub.name, 0)
        names_used[sub.name] = count + 1
        suffix = "" if count == 0 else f"@0x{sub.low_pc:x}"
        key = f"{binary.source_key}::{binary.config}::{sub.name}{suffix}"
        if only is not None and not only.search(key):
            continue
        wanted.append((key, sub))
    if not wanted:
        return []
    addresses = [sub.low_pc for _, sub in wanted]
    report = run_batch(args.r2s, binary.stripped, addresses,
                       function_timeout=args.function_timeout,
                       startup_timeout=args.startup_timeout)
    answers = report.by_address()
    futures = []
    for key, sub in wanted:
        spec = call_spec(dwarf, sub, all_functions)
        names, size = symbols.get(sub.low_pc, ([], 0))
        if names and sub.name not in names and not spec.unsupported:
            spec.unsupported = (
                f"the symbol at 0x{sub.low_pc:x} is {names[0]}, a compiler copy whose "
                "prototype is not the source's"
            )
        spec.constants = code_constants(binary.unstripped, sub.low_pc, size)
        spec.extent = size
        workdir = args.out / "work" / binary.source.stem / binary.config / re.sub(
            r"[^A-Za-z0-9_.@-]", "_", sub.name + ("" if names_used[sub.name] == 1
                                                  else f"@{sub.low_pc:x}"))
        answer: Answer | None = answers.get(sub.low_pc)
        futures.append(pool.submit(gate.grade, key, workdir, binary.unstripped, dwarf, spec,
                                   answer, config))
    return [future.result() for future in futures]


def build_failure_record(binary: build.Binary) -> gate.Record:
    return gate.Record(
        key=f"{binary.source_key}::{binary.config}::<build>",
        function="<build>",
        address=0,
        status="harness-error",
        evidence={"cause": binary.error or "unknown build failure"},
    )


def selected_predicate(args: argparse.Namespace, sources: list[Path]):
    source_keys = {build.Binary(s, "", "", s, s).source_key for s in sources}
    compilers = set(args.compilers.split(","))
    opts = set(args.opts.split(","))
    only = re.compile(args.only) if args.only else None

    def selected(key: str) -> bool:
        parts = key.split("::")
        if len(parts) != 3:
            return False
        source, config, _ = parts
        compiler, _, opt = config.partition("-")
        return (source in source_keys and compiler in compilers and opt in opts
                and (only is None or bool(only.search(key))))

    return selected


def summarize(records: list[gate.Record]) -> str:
    by_status: dict[str, int] = {}
    by_config: dict[str, dict[str, int]] = {}
    for record in records:
        by_status[record.status] = by_status.get(record.status, 0) + 1
        config = record.key.split("::")[1] if record.key.count("::") == 2 else "?"
        row = by_config.setdefault(config, {})
        row[record.status] = row.get(record.status, 0) + 1
    lines = [f"{len(records)} records: " + ", ".join(
        f"{status} {by_status[status]}" for status in gate.STATUSES if status in by_status)]
    for config in sorted(by_config):
        row = by_config[config]
        lines.append(f"  {config:10} " + ", ".join(
            f"{status} {row[status]}" for status in gate.STATUSES if status in row))
    for record in records:
        if record.status in ("equal",):
            continue
        cause = record.evidence.get("cause") or record.evidence.get("field") or \
            record.evidence.get("detector") or record.evidence.get("variant") or ""
        lines.append(f"  {record.status:13} {record.key}: {str(cause)[:160]}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    # The runtime runs with its work directory as cwd: every path it is handed
    # must be absolute.
    args.out = args.out.resolve()
    args.r2s = args.r2s.resolve()
    problem = gate.environment_problem()
    if problem:
        print(f"equiv: {problem}; the gate cannot run here", file=sys.stderr)
        return EXIT_SETUP
    args.out.mkdir(parents=True, exist_ok=True)
    try:
        runtime = link.build_runtime(args.cc, HERE / "rt", args.out / "rt")
    except RuntimeError as error:
        print(f"equiv: {error}", file=sys.stderr)
        return EXIT_SETUP
    config = gate.Config(runtime=runtime, cc=args.cc, vectors=args.vectors,
                         timeout_ms=args.timeout_ms, keep=args.keep)

    if args.baseline is not None and not args.baseline.exists():
        print(f"equiv: no baseline at {args.baseline}; measure without --baseline, read "
              "records.json, and bless one with --write-baseline (a cause for every record "
              "that is not equal)", file=sys.stderr)
        return EXIT_SETUP

    started = time.monotonic()
    if not run_self_tests(config, args.out):
        return EXIT_SELF_TEST
    if args.self_test_only:
        return EXIT_OK
    if not args.r2s.exists():
        print(f"equiv: no r2s at {args.r2s}; build it with "
              "`cargo build -p r2s --features sleigh`", file=sys.stderr)
        return EXIT_SETUP

    sources = [s.resolve() for s in (args.sources or build.default_sources())]
    binaries = build.build_all(sources, args.compilers.split(","), args.opts.split(","),
                               args.out / "build")
    only = re.compile(args.only) if args.only else None
    records: list[gate.Record] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        for binary in binaries:
            if binary.error:
                records.append(build_failure_record(binary))
                continue
            records.extend(grade_binary(binary, args, config, only, pool))
    records.sort(key=lambda r: r.key)

    # Nothing in the file depends on when or how fast it ran: two runs over the
    # same inputs write the same bytes.
    payload = {
        "schema": 1,
        "r2s": str(args.r2s),
        "r2s_sha256": sha256(args.r2s),
        "config": {"vectors": args.vectors, "timeout_ms": args.timeout_ms, "cc": args.cc,
                   "compilers": args.compilers, "opts": args.opts, "only": args.only,
                   "sources": [build.Binary(s, "", "", s, s).source_key for s in sources],
                   "fixed_layout": bool(gate.fixed_layout_prefix())},
        "records": [record.to_json() for record in records],
    }
    (args.out / "records.json").write_text(json.dumps(payload, indent=1) + "\n",
                                           encoding="utf-8")
    summary = summarize(records)
    (args.out / "summary.txt").write_text(summary + "\n", encoding="utf-8")
    print(summary)
    print(f"records: {args.out / 'records.json'} ({time.monotonic() - started:.1f}s)")

    status = EXIT_OK
    if args.baseline is not None:
        baseline = gate.load_baseline(args.baseline)
        selected = selected_predicate(args, sources)
        held = {key for key in baseline["records"] if selected(key)}
        problems = gate.ratchet(baseline, {r.key: r.status for r in records}, held)
        for line in problems:
            print(f"ratchet: {line}")
        if problems:
            status = EXIT_RATCHET
        else:
            print(f"ratchet: {len(held)} baseline records held")
    if args.write_baseline is not None:
        previous = gate.load_baseline(args.write_baseline) if args.write_baseline.exists() else None
        args.write_baseline.write_text(
            json.dumps(gate.baseline_from(records, previous), indent=1, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"baseline written: {args.write_baseline} (fill in a cause for every non-equal "
              "record before gating on it)")
    return status


if __name__ == "__main__":
    sys.exit(main())
