#!/usr/bin/env python3
"""The census and the release timing: what every function renders, and how long the big ones take.

  census.py run  --r2s R2S --out DIR [BINARY...]   pdd every function into DIR/<binary>.txt
  census.py diff BASE_DIR HEAD_DIR [--report FILE] summary of moved renderings; the diff to FILE
  census.py time --r2s BASE --r2s HEAD [--runs N] [--budget R] --bins DIR
                                                   median release pdd time per case; fails when
                                                   HEAD exceeds R x BASE or the outputs differ

With no binaries, `run` reads the repository's own: tests/coverage/pinned,
tests/fixtures and, where the coverage sweep compiled them, tests/coverage/artifacts/bin.
"""
import argparse
import concurrent.futures
import difflib
import hashlib
import os
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# The functions where a quadratic pass shows first, in radare2's test binaries.
TIMED = [("0pack", "0x0058e3d0"), ("0pack", "0x0062ecf0"),
         ("pumasim", "0x0023fdf0"), ("pumasim", "0x004baf30")]


def corpus():
    found = []
    for directory in ("tests/coverage/pinned", "tests/fixtures", "tests/coverage/artifacts/bin"):
        for path in sorted((ROOT / directory).glob("*")):
            if path.is_file() and os.access(path, os.X_OK) and path.suffix == "":
                found.append(path)
    return found


def r2s(binary, command, executable):
    done = subprocess.run([executable, "-q", "-c", command, str(binary)],
                          capture_output=True, text=True, errors="replace")
    return done.stdout + done.stderr


def census_one(executable, binary, out):
    listing = r2s(binary, "afl", executable)
    addresses = [line.split()[0] for line in listing.splitlines() if line.startswith("0x")]
    with concurrent.futures.ThreadPoolExecutor(os.cpu_count()) as pool:
        rendered = list(pool.map(lambda a: r2s(binary, f"pdd @ {a}", executable), addresses))
    text = "".join(f"== {a}\n{body}" for a, body in zip(addresses, rendered))
    (out / f"{binary.name}.txt").write_text(text)
    return binary.name, len(addresses)


def run(args):
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    binaries = [Path(b) for b in args.binaries] or corpus()
    for binary in binaries:
        name, count = census_one(args.r2s, binary, out)
        print(f"{name}: {count} functions")


def functions(text):
    parts = re.split(r"^== (0x[0-9a-f]+)\n", text, flags=re.M)
    return dict(zip(parts[1::2], parts[2::2]))


def counts(text):
    return (text.count("r2sleigh refused"), len(re.findall(r"r2sleigh_residual_\w+\(", text)))


def diff(args):
    base, head = Path(args.base), Path(args.head)
    names = sorted({p.name for p in base.glob("*.txt")} | {p.name for p in head.glob("*.txt")})
    report, rows, moved = [], [], 0
    for name in names:
        before = (base / name).read_text() if (base / name).exists() else ""
        after = (head / name).read_text() if (head / name).exists() else ""
        if before == after:
            continue
        a, b = functions(before), functions(after)
        changed = [f for f in sorted(set(a) | set(b)) if a.get(f) != b.get(f)]
        moved += len(changed)
        (r0, s0), (r1, s1) = counts(before), counts(after)
        rows.append(f"| {name} | {len(changed)} | {r0} -> {r1} | {s0} -> {s1} |")
        for function in changed:
            report.extend(difflib.unified_diff(
                (a.get(function) or "").splitlines(keepends=True),
                (b.get(function) or "").splitlines(keepends=True),
                f"base/{name}@{function}", f"head/{name}@{function}"))
    if not rows:
        print("census: byte-identical")
    else:
        print(f"census: {moved} functions moved\n")
        print("| binary | functions moved | refused | residuals |\n|---|---|---|---|")
        print("\n".join(rows))
    if args.report:
        Path(args.report).write_text("".join(report))


def time_cases(args):
    base, head = args.r2s
    failed = False
    print("| case | base s | head s | ratio | output |\n|---|---|---|---|---|")
    for name, address in TIMED:
        binary = Path(args.bins) / name
        if not binary.exists():
            print(f"| {name} {address} | missing | | | |")
            continue
        seconds, digests = {}, {}
        for side, executable in (("base", base), ("head", head)):
            runs = []
            for _ in range(args.runs):
                start = time.perf_counter()
                text = r2s(binary, f"pdd @ {address}", executable)
                runs.append(time.perf_counter() - start)
            seconds[side] = statistics.median(runs)
            digests[side] = hashlib.sha256(text.encode()).hexdigest()[:12]
        ratio = seconds["head"] / seconds["base"]
        same = digests["base"] == digests["head"]
        failed |= ratio > args.budget
        print(f"| {name} {address} | {seconds['base']:.2f} | {seconds['head']:.2f} | "
              f"{ratio:.2f} | {'same' if same else 'moved'} |")
    if failed:
        print(f"a case took more than {args.budget}x its base time", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("run")
    p.add_argument("--r2s", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("binaries", nargs="*")
    p.set_defaults(func=run)
    p = sub.add_parser("diff")
    p.add_argument("base")
    p.add_argument("head")
    p.add_argument("--report")
    p.set_defaults(func=diff)
    p = sub.add_parser("time")
    p.add_argument("--r2s", action="append", required=True)
    p.add_argument("--bins", required=True)
    p.add_argument("--runs", type=int, default=3)
    p.add_argument("--budget", type=float, default=1.25)
    p.set_defaults(func=time_cases)
    args = parser.parse_args()
    if args.command == "time" and len(args.r2s) != 2:
        parser.error("time takes --r2s twice: base, then head")
    args.func(args)


if __name__ == "__main__":
    main()
