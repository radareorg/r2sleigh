#!/usr/bin/env python3
"""The census and the release timing: what every function renders, and how long the big ones take.

  census.py run  --r2s R2S --out DIR [BINARY...]   pdd every function into DIR/<binary>.txt
  census.py diff BASE_DIR HEAD_DIR [--report FILE] summary of moved renderings; the diff to FILE
  census.py sites DIR                              each staged function whose proof line counts a
                                                   residual its text holds no site for; fails on any
  census.py time --r2s BASE --r2s HEAD [--runs N] [--budget R] [--rss-budget R]
                 [--count-r2s BASE --count-r2s HEAD] [--alloc-budget R] --bins DIR
                                                   median release time and peak RSS per case, and
                                                   the allocation count from alloc-count builds;
                                                   fails when HEAD exceeds a budget x BASE
  census.py exponent --r2s R2S [--min-instructions N] [--sample N] [--out FILE] BINARY...
                                                   how `pdd` cost and peak RSS grow with a
                                                   function's instructions (ROADMAP LX's exit):
                                                   instructions retired by `afl; pdd @ f` less
                                                   `afl`'s, under `perf stat` (Linux)

With no binaries, `run` reads the repository's own: tests/coverage/pinned,
tests/fixtures and, where the coverage sweep compiled them, tests/coverage/artifacts/bin.
"""
import argparse
import concurrent.futures
import difflib
import hashlib
import math
import os
import re
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# The functions where a quadratic pass shows first, and the two largest listings, in radare2's test binaries.
TIMED = [("0pack", "pdd @ 0x0058e3d0"), ("0pack", "pdd @ 0x0062ecf0"),
         ("pumasim", "pdd @ 0x0023fdf0"), ("pumasim", "pdd @ 0x004baf30"),
         ("pumasim", "afl"), ("0pack", "afl")]
ALLOCATIONS = re.compile(r"^r2s: allocations: (\d+)$", re.MULTILINE)
INFO = re.compile(r"^addr: (0x[0-9a-f]+)\n(?:.*\n)*?num-instrs: (\d+)$", re.MULTILINE)


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


PROOF = re.compile(r"r2dec proof: (?:(no individual construct is marked)|(\d+) constructs? (?:is|are) marked"
                   r"|rendering produced no statements)(.*?)\*/")


def residual_sites(body):
    """The proof line's marked count, residual and unaccounted columns, and the sites the text holds."""
    found = PROOF.search(body)
    if not found:
        return None
    marked = int(found.group(2) or 0)
    column = lambda name: int(m.group(1)) if (m := re.search(rf"(\d+) {name}\b", found.group(3))) else 0
    sites = len(re.findall(r"r2sleigh_residual_\w+\(", body[found.end():]))
    return marked, column("residual"), column("unaccounted"), sites


def unsited(body):
    """The proof line's residuals it states have no site, by the cause it names."""
    return {cause: int(n) for n, cause in re.findall(r"\((\d+) without a site: ([a-z ]+)\)", body)}


REFUSED_UNACCOUNTED = re.compile(r"r2sleigh refused (\S+): .*?(\d+) unaccounted \(([^)]*)\)")


def site_mismatches(body):
    """Why a function's proof line counts a residual its text holds no site for; empty when none."""
    counted = residual_sites(body)
    if counted is None:
        return []
    marked, residual, unaccounted, found = counted
    named = sum(unsited(body).values())
    return [reason for reason, wrong in (
        (f"{residual - named} residual, no site", residual > named and found == 0),
        (f"{unaccounted} unaccounted", unaccounted > 0),
        (f"{marked} marked, {found} in the text", marked != found)) if wrong]


def sites(args):
    """A counted residual needs a site: a residual call or gap marker in the text (ledger.rs, Outcome::Gapped).
    A residual the proof line names a cause for (`UnsitedReason`), and a refusal, are listed, not failed."""
    mismatches, refused, named = 0, [], []
    for path in sorted(Path(args.dir).glob("*.txt")):
        for address, body in functions(path.read_text()).items():
            if reasons := site_mismatches(body):
                mismatches += 1
                print(f"{path.stem} {address}: {'; '.join(reasons)}")
            for cause, count in unsited(body).items():
                named.append(f"{path.stem} {address}: {count} residual, no site: {cause}")
            if found := REFUSED_UNACCOUNTED.search(body):
                refused.append(f"{path.stem} {address} {found[1]}: {found[2]} unaccounted ({found[3]})")
    for line in named:
        print(f"named cause: {line}")
    for line in refused:
        print(f"refused, unaccounted: {line}")
    print(f"sites: {mismatches} mismatches, {len(named)} residuals without a site under a named cause,"
          f" {len(refused)} refused for unaccounted obligations")
    if mismatches:
        sys.exit(1)


def measured(binary, command, executable):
    """Wall seconds, this child's own peak RSS in MB, its output, and the allocations it reported."""
    with tempfile.TemporaryFile() as out:
        start = time.perf_counter()
        child = subprocess.Popen([executable, "-q", "-c", command, str(binary)],
                                 stdout=out, stderr=subprocess.STDOUT,
                                 env={**os.environ, "R2S_ALLOCATIONS": "1"})
        # wait4 reaps this child alone, so its rusage is this run's and no other's.
        _, _, usage = os.wait4(child.pid, 0)
        seconds = time.perf_counter() - start
        child.returncode = 0
        out.seek(0)
        text = out.read().decode(errors="replace")
    # ru_maxrss is bytes on macOS and KiB on Linux.
    peak = usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024) / (1 << 20)
    found = ALLOCATIONS.search(text)
    return seconds, peak, ALLOCATIONS.sub("", text), int(found.group(1)) if found else None


def time_cases(args):
    failed = []
    print("| case | base s | head s | ratio | base MB | head MB | ratio | allocations | output |\n"
          "|---|---|---|---|---|---|---|---|---|")
    for name, command in TIMED:
        binary = Path(args.bins) / name
        if not binary.exists():
            print(f"| {name} {command} | missing | | | | | | | |")
            continue
        seconds, peaks, digests, counts = {}, {}, {}, {}
        for side, executable in zip(("base", "head"), args.r2s):
            runs = [measured(binary, command, executable) for _ in range(args.runs)]
            seconds[side] = statistics.median(run[0] for run in runs)
            peaks[side] = max(run[1] for run in runs)
            digests[side] = hashlib.sha256(runs[-1][2].encode()).hexdigest()[:12]
        # A base built before the count existed has no counting build; head's count stands alone.
        for side, executable in zip(("base", "head"), args.count_r2s or ()):
            if Path(executable).exists():
                counts[side] = measured(binary, command, executable)[3]
        ratio = seconds["head"] / seconds["base"]
        rss = peaks["head"] / peaks["base"]
        allocations = ""
        if counts.get("base") and counts.get("head"):
            allocated = counts["head"] / counts["base"]
            allocations = f"{counts['base']:,} -> {counts['head']:,} ({allocated:.2f})"
            if allocated > args.alloc_budget:
                failed.append(f"{name} {command}: {allocated:.2f}x the base's allocations")
        elif counts.get("head"):
            allocations = f"{counts['head']:,}"
        if ratio > args.budget:
            failed.append(f"{name} {command}: {ratio:.2f}x the base's time")
        if rss > args.rss_budget:
            failed.append(f"{name} {command}: {rss:.2f}x the base's peak RSS")
        same = digests["base"] == digests["head"]
        print(f"| {name} {command} | {seconds['base']:.2f} | {seconds['head']:.2f} | {ratio:.2f} | "
              f"{peaks['base']:.0f} | {peaks['head']:.0f} | {rss:.2f} | {allocations} | "
              f"{'same' if same else 'moved'} |")
    for line in failed:
        print(line, file=sys.stderr)
    if failed:
        sys.exit(1)


def retired(binary, command, executable):
    """User-space instructions retired by one run, and its peak RSS in MB; `perf` is Linux's."""
    with tempfile.NamedTemporaryFile() as counts:
        child = subprocess.Popen(["perf", "stat", "-x,", "-e", "instructions:u", "-o", counts.name,
                                  executable, "-q", "-c", command, str(binary)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # wait4 reports the largest resident set among the child and what it reaped.
        _, _, usage = os.wait4(child.pid, 0)
        text = Path(counts.name).read_text()
    count = next((int(line.split(",")[0]) for line in text.splitlines() if "instructions" in line), None)
    if count is None:
        sys.exit(f"perf counted no instructions: {text.strip()[:200]}")
    return count, usage.ru_maxrss / 1024


def instruction_counts(binary, executable):
    """Each function's instruction count, by address, from `afi` in batches of 256."""
    listing = r2s(binary, "afl", executable)
    addresses = [line.split()[0] for line in listing.splitlines() if line.startswith("0x")]
    found = {}
    for start in range(0, len(addresses), 256):
        text = r2s(binary, "; ".join(f"afi @ {a}" for a in addresses[start:start + 256]), executable)
        found.update((int(a, 16), int(n)) for a, n in INFO.findall(text))
    return found


def fit(points):
    """Least squares of log y on log x: the slope and R squared."""
    xs = [math.log(x) for x, _ in points]
    ys = [math.log(y) for _, y in points]
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    syy = sum((y - my) ** 2 for y in ys)
    return sxy / sxx, (sxy * sxy) / (sxx * syy) if syy else 1.0


def evenly(rows, count):
    """`count` rows evenly spaced by instruction count, so a fit sees the whole range."""
    by_size = sorted(rows, key=lambda row: (row[1], row[0]))
    if len(by_size) <= count or count < 2:
        return sorted(rows)
    step = (len(by_size) - 1) / (count - 1)
    return sorted({by_size[round(i * step)] for i in range(count)})


def exponent(args):
    rows = []
    for binary in map(Path, args.binaries):
        large = [row for row in instruction_counts(binary, args.r2s).items() if row[1] >= args.min_instructions]
        print(f"{binary.name}: {len(large)} functions of {args.min_instructions}+ instructions", flush=True)
        if not large:
            continue
        base_cost, base_peak = retired(binary, "afl", args.r2s)
        for address, count in evenly(large, args.sample):
            cost, peak = retired(binary, f"afl; pdd @ {address:#x}", args.r2s)
            rows.append((binary.name, address, count, max(cost - base_cost, 1), peak - base_peak))
            print(f"  {address:#x} {count} {(cost - base_cost) / 1e6:.1f}M {peak - base_peak:.0f}MB", flush=True)
    if args.out:
        Path(args.out).write_text("".join(f"{b}\t{a:#x}\t{n}\t{c}\t{p:.1f}\n" for b, a, n, c, p in rows))
    if len(rows) < 3:
        sys.exit("fewer than three functions: no fit")
    slope, r2 = fit([(n, c) for _, _, n, c, _ in rows])
    print(f"cost: instructions^{slope:.2f} (R^2 {r2:.2f}) over {len(rows)} functions")
    grown = [(n, p) for _, _, n, _, p in rows if p > 1]
    if len(grown) >= 3:
        slope, r2 = fit(grown)
        print(f"peak RSS above afl's: instructions^{slope:.2f} (R^2 {r2:.2f}) over {len(grown)} functions")


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
    p = sub.add_parser("sites")
    p.add_argument("dir")
    p.set_defaults(func=sites)
    p = sub.add_parser("time")
    p.add_argument("--r2s", action="append", required=True)
    p.add_argument("--bins", required=True)
    p.add_argument("--runs", type=int, default=3)
    p.add_argument("--budget", type=float, default=1.25)
    p.add_argument("--rss-budget", type=float, default=1.3)
    p.add_argument("--count-r2s", action="append")
    p.add_argument("--alloc-budget", type=float, default=1.3)
    p.set_defaults(func=time_cases)
    p = sub.add_parser("exponent")
    p.add_argument("--r2s", required=True)
    p.add_argument("--min-instructions", type=int, default=300)
    p.add_argument("--sample", type=int, default=40)
    p.add_argument("--out")
    p.add_argument("binaries", nargs="+")
    p.set_defaults(func=exponent)
    args = parser.parse_args()
    if args.command == "time" and len(args.r2s) != 2:
        parser.error("time takes --r2s twice: base, then head")
    if args.command == "time" and args.count_r2s and len(args.count_r2s) != 2:
        parser.error("time takes --count-r2s twice: base, then head")
    args.func(args)


if __name__ == "__main__":
    main()
