#!/usr/bin/env python3
"""The census and the release timing: what every function renders, and how long the big ones take.

  census.py run  --r2s R2S --out DIR [BINARY...]   pdd every function into DIR/<binary>.txt
  census.py diff BASE_DIR HEAD_DIR [--report FILE] summary of moved renderings; the diff to FILE
  census.py golden --r2s R2S                       write tests/db/census/<binary>, one r2r test per
                                                   function of each committed binary, expectations
                                                   empty for `R2S_BLESS=1` to fill (tests/db/README.md)
  census.py sites DIR                              each staged function whose proof line counts a
                                                   residual its text holds no site for; fails on any
  census.py time --r2s BASE --r2s HEAD [--runs N] [--budget R] [--rss-budget R]
                 [--count-r2s BASE --count-r2s HEAD] [--alloc-budget R] [--heap-budget R]
                 [--causes FILE] --bins DIR       median release time and peak RSS per case, and
                                                   the allocation count and heap peak from
                                                   alloc-count builds; fails when HEAD exceeds a
                                                   budget x BASE, an allocation rise only without
                                                   a cause line for its base count, or a case's
                                                   binary is missing
  census.py count --r2s BASE --r2s HEAD --qemu QEMU [--runs N] [--budget R] [--causes FILE] --bins DIR
                                                   every guest instruction of an `r2s` process per
                                                   counted case under a `--enable-plugins`
                                                   qemu-user; fails as `time` does for allocations
  census.py exponent --r2s R2S [--min-instructions N] [--sample N] [--max-exponent X]
                    [--out FILE] BINARY...         how `pdd` instructions retired, CPU time and
                                                   peak RSS grow with a function's instructions
                                                   (ROADMAP LX's exit): `afl; pdd @ f` less `afl`,
                                                   under `perf stat` (Linux); fails above X
  census.py orders --r2s R2S [--out DIR] [--reuse] [--min-live N] BINARY...
                                                   pddj of every function under the write orders of a
                                                   `--features placement_mutants` build (natural, then
                                                   o1: no exit inlined, o2: exits reversed, o3: merges
                                                   reversed); fails when a verdict differs from
                                                   natural's (ROADMAP D58) or an order moves no text
  census.py heap [--top N] [INSTRUCTIONS=]PROFILE...
                                                   bytes live at each dhat profile's heap peak by
                                                   allocation site (a `--features dhat-heap` build
                                                   run with R2S_HEAP_PROFILE=1 writes dhat-heap.json);
                                                   given each profile's
                                                   instruction count, how fast each site grows

With no binaries, `run` reads the repository's own: tests/coverage/pinned,
tests/fixtures and, where the coverage sweep compiled them, tests/coverage/artifacts/bin.
"""
import argparse
import collections
import concurrent.futures
import difflib
import hashlib
import json
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
# One session over pumasim's largest functions and a sample down to its smallest: what a session holds
# between requests (doc/adr-memory-model.md, Gates).
SESSION = (
    0x23fdf0, 0x1fafb0, 0x2312c0, 0x4baf30, 0x213a60, 0x22a010, 0x1f61b0, 0x23da20,
    0x452a80, 0x421360, 0x4501a0, 0x414ca0, 0x26a7b0, 0x46a470, 0x41d770, 0x44e290,
    0x23ba50, 0x4ad0b0, 0x1e5fc0, 0x2690b0, 0x275e80, 0x274900, 0x273380, 0x1f4aa0,
    0x1f3390, 0x32b4b0, 0x523800, 0x4fea20, 0x5a42f0, 0x20e340, 0x38f3c0, 0x437a40,
    0x54cfd0, 0x57f2a0, 0x2e9a10, 0x529360, 0x37a6b0, 0x4ed1f0, 0x43c7c0, 0x5ac4f0,
    0x2d0fe0, 0x2f6e30, 0x4bff00, 0x3954c0, 0x42acd0, 0x2cfc20, 0x42af90, 0x1c4dc0,
    0x529df0, 0x4d7650,
)
TIMED = [("0pack", "pdd @ 0x0058e3d0"), ("0pack", "pdd @ 0x0062ecf0"),
         ("pumasim", "pdd @ 0x0023fdf0"), ("pumasim", "pdd @ 0x004baf30"),
         ("pumasim", "afl"), ("0pack", "afl"),
         ("pumasim", "; ".join(f"pdd @ {address:#x}" for address in SESSION), "session: pdd of 50 functions"),
         # The chain's analysed cases (D402): `aa` walks every body, so a per-body cost shows here first.
         ("pumasim", "aa; pdd @ 0x3b6b20"), ("bash", "aa; pdd @ 0x2e630")]
# The four cases the stack's timing table grades, counted whole-process under qemu (D343).
COUNTED = [("pumasim", "pdd @ 0x0023fdf0"), ("0pack", "pdd @ 0x0062ecf0"),
           ("bash", "aa; pdd @ 0x2e630"), ("pumasim", "aa; pdd @ 0x3b6b20")]
# A counted rise past its budget stands only on a line naming its row and cause for that exact
# base count, so the line excuses no later rise (D401).
CAUSES = ROOT / "scripts/cost_causes.txt"
CAUSE = re.compile(r"^(allocations|instructions) \| (.+?) \| (\d+) \| (\d+) \| (D\d+) \| (\S.*)$")
ALLOCATIONS = re.compile(r"^r2s: allocations: (\d+)$", re.MULTILINE)
HEAP_PEAK = re.compile(r"^r2s: heap peak: (\d+)$", re.MULTILINE)
INFO = re.compile(r"^addr: (0x[0-9a-f]+)\n(?:.*\n)*?num-instrs: (\d+)$", re.MULTILINE)
# A dhat frame the project does not own: the allocator, the standard library and its collections.
LIBRARY_FRAME = re.compile(r": <?(alloc|core|std|hashbrown)::|\((\?\?\?|dhat-|alloc/|core/|std/|hashbrown|smallvec"
                           r"|collections/|iter/|r2s/src/allocator"
                           r"|src/(raw_vec|vec|boxed|collections|alloc|ops|panic|iter|slice|str|string|fmt"
                           r"|hash|sync|rc|option|result|cell|ptr|mem|array|btree|clone|raw)/)")


COMMITTED = ("tests/coverage/pinned", "tests/fixtures")


def corpus(directories=(*COMMITTED, "tests/coverage/artifacts/bin")):
    found = []
    for directory in directories:
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
        # `aa` first: each rendering reads its callers, as an analysed session's does.
        rendered = list(pool.map(lambda a: r2s(binary, f"aa; pdd @ {a}", executable), addresses))
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


def golden(args):
    """One r2r file per committed binary: its `afl`, then `aa; pdd` of each function it lists."""
    out = ROOT / "tests/db/census"
    out.mkdir(parents=True, exist_ok=True)
    for binary in corpus(COMMITTED):
        listing = r2s(binary, "afl", args.r2s)
        addresses = [line.split()[0] for line in listing.splitlines() if line.startswith("0x")]
        relative = binary.relative_to(ROOT).as_posix()
        test = (lambda name, commands: f"NAME={name}\nFILE={relative}\nCMDS={commands}\n"
                "EXPECT=<<EOF\nEOF\nEXPECT_ERR=<<EOF\nEOF\nRUN\n")
        header = (f"# The census of {binary.name}: what `aa; pdd` renders for each function `afl` lists.\n"
                  "# Regenerate with `scripts/census.py golden` when `afl` moves, then bless.\n")
        tests = [test("afl", "afl")] + [test(address, f"aa; pdd @ {address}") for address in addresses]
        (out / binary.name).write_text(header + "\n" + "\n".join(tests))
        print(f"{binary.name}: {len(addresses)} functions")


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


def causes(path=CAUSES):
    """Each cause line by (metric, case, base count): the head count it allows, its row and cause."""
    entries = {}
    for number, line in enumerate(Path(path).read_text().splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        found = CAUSE.match(line)
        if not found:
            sys.exit(f"{path}:{number}: not `metric | case | base | head ceiling | Dnnn | cause`")
        metric, case, base, ceiling, row, cause = found.groups()
        entries[(metric, case, int(base))] = (int(ceiling), row, cause)
    return entries


def counted_rise(metric, case, base, head, budget, entries):
    """Why HEAD's count fails against BASE's, or None: above budget x BASE with no cause line for
    this base count whose ceiling holds HEAD."""
    ratio = head / base
    if ratio <= budget:
        return None
    ceiling, *_ = entries.get((metric, case, base), (0,))
    if head <= ceiling:
        return None
    return (f"{case}: {metric} {base:,} -> {head:,} ({ratio:.4f}x, budget {budget}); a rise stands only "
            f"on a line in {CAUSES.relative_to(ROOT)}: `{metric} | {case} | {base} | {head} | Dnnn | <cause>`")


def measured(binary, command, executable):
    """Wall seconds, this child's own peak RSS in MB, its output, and the allocations and heap peak
    in MB it reported."""
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
    heap = HEAP_PEAK.search(text)
    output = HEAP_PEAK.sub("", ALLOCATIONS.sub("", text))
    return (seconds, peak, output, int(found.group(1)) if found else None,
            int(heap.group(1)) / (1 << 20) if heap else None)


def time_cases(args):
    failed, entries = [], causes(args.causes)
    print("| case | base s | head s | ratio | base MB | head MB | ratio | base heap MB | head heap MB "
          "| ratio | allocations | output |\n|---|---|---|---|---|---|---|---|---|---|---|---|")
    for name, command, *label in TIMED:
        case = f"{name} {label[0] if label else command}"
        binary = Path(args.bins) / name
        if not binary.exists():
            failed.append(f"{case}: no {binary}; every timed case runs (D402)")
            continue
        seconds, peaks, digests, counts, heaps = {}, {}, {}, {}, {}
        for side, executable in zip(("base", "head"), args.r2s):
            runs = [measured(binary, command, executable) for _ in range(args.runs)]
            seconds[side] = statistics.median(run[0] for run in runs)
            peaks[side] = max(run[1] for run in runs)
            digests[side] = hashlib.sha256(runs[-1][2].encode()).hexdigest()[:12]
        # A base built before the count existed has no counting build; head's count stands alone.
        for side, executable in zip(("base", "head"), args.count_r2s or ()):
            if Path(executable).exists():
                counted = measured(binary, command, executable)
                counts[side], heaps[side] = counted[3], counted[4]
        ratio = seconds["head"] / seconds["base"]
        rss = peaks["head"] / peaks["base"]
        allocations = ""
        if counts.get("base") and counts.get("head"):
            allocated = counts["head"] / counts["base"]
            allocations = f"{counts['base']:,} -> {counts['head']:,} ({allocated:.4f})"
            if rise := counted_rise("allocations", case, counts["base"], counts["head"], args.alloc_budget, entries):
                failed.append(rise)
        elif counts.get("head"):
            allocations = f"{counts['head']:,}"
        heap = ["", "", ""]
        # A base from before the count may print none; the head's counting build must print its peak.
        if len(args.count_r2s or ()) == 2 and Path(args.count_r2s[1]).exists() and not heaps.get("head"):
            failed.append(f"{case}: the head's counting run printed no heap peak")
        if heaps.get("head"):
            heap[1] = f"{heaps['head']:.1f}"
        if heaps.get("base") and heaps.get("head"):
            grown = heaps["head"] / heaps["base"]
            heap = [f"{heaps['base']:.1f}", heap[1], f"{grown:.2f}"]
            if grown > args.heap_budget:
                failed.append(f"{case}: {grown:.2f}x the base's heap peak")
        if ratio > args.budget:
            failed.append(f"{case}: {ratio:.2f}x the base's time")
        if rss > args.rss_budget:
            failed.append(f"{case}: {rss:.2f}x the base's peak RSS")
        same = digests["base"] == digests["head"]
        print(f"| {case} | {seconds['base']:.2f} | {seconds['head']:.2f} | {ratio:.2f} | "
              f"{peaks['base']:.0f} | {peaks['head']:.0f} | {rss:.2f} | {' | '.join(heap)} | "
              f"{allocations} | {'same' if same else 'moved'} |")
    for line in failed:
        print(line, file=sys.stderr)
    if failed:
        sys.exit(1)


def qemu_plugin(qemu, workdir):
    """scripts/qemu_insns.c built against the header a `--enable-plugins` qemu installs beside its bin."""
    header = Path(qemu).resolve().parent.parent / "include" / "qemu-plugin.h"
    if not header.exists():
        sys.exit(f"{qemu} has no {header}: build qemu with --enable-plugins (D343)")
    plugin = Path(workdir) / "qemu_insns.so"
    subprocess.run(["cc", "-O2", "-Wall", "-Werror", "-shared", "-fPIC", f"-I{header.parent}",
                    str(ROOT / "scripts/qemu_insns.c"), "-o", str(plugin)], check=True)
    return plugin


def guest_instructions(qemu, plugin, binary, command, executable, workdir):
    """Every instruction one `r2s -q -c COMMAND BINARY` process retires under qemu-user."""
    out = Path(workdir) / "count"
    out.unlink(missing_ok=True)
    done = subprocess.run([qemu, "-plugin", f"{plugin},out={out}", executable, "-q", "-c", command,
                           str(binary)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if done.returncode != 0 or not out.exists():
        sys.exit(f"{binary.name}: `{command}` under qemu exited {done.returncode}; no count")
    return int(out.read_text())


def count_cases(args):
    """Whole-process guest instructions of base and head per counted case; a rise past the budget
    fails unless a cause line names its base count (D343, D401)."""
    failed, entries = [], causes(args.causes)
    print("| case | base | head | ratio |\n|---|---|---|---|")
    with tempfile.TemporaryDirectory() as workdir:
        plugin = qemu_plugin(args.qemu, workdir)
        for name, command in COUNTED:
            case = f"{name} {command}"
            binary = Path(args.bins) / name
            if not binary.exists():
                failed.append(f"{case}: no {binary}; every counted case runs")
                continue
            base, head = (statistics.median_low(
                guest_instructions(args.qemu, plugin, binary, command, executable, workdir)
                for _ in range(args.runs)) for executable in args.r2s)
            print(f"| {case} | {base:,} | {head:,} | {head / base:.4f} |", flush=True)
            if rise := counted_rise("instructions", case, base, head, args.budget, entries):
                failed.append(rise)
    for line in failed:
        print(line, file=sys.stderr)
    if failed:
        sys.exit(1)


def retired(binary, command, executable):
    """User-space instructions retired, CPU milliseconds and peak RSS in MB of one run that
    exited cleanly; `perf` is Linux's."""
    with tempfile.NamedTemporaryFile() as counts:
        child = subprocess.Popen(["perf", "stat", "-x,", "-e", "instructions:u,task-clock",
                                  "-o", counts.name, executable, "-q", "-c", command, str(binary)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # wait4 reports the largest resident set among the child and what it reaped.
        _, status, usage = os.wait4(child.pid, 0)
        text = Path(counts.name).read_text()
    if os.waitstatus_to_exitcode(status) != 0:
        sys.exit(f"{binary.name}: `{command}` exited {os.waitstatus_to_exitcode(status)}; no row")
    counted = {line.split(",")[2].split(":")[0]: float(line.split(",")[0])
               for line in text.splitlines() if line.count(",") >= 2 and line.split(",")[0][:1].isdigit()}
    if "instructions" not in counted or "task-clock" not in counted:
        sys.exit(f"perf counted no instructions or task-clock: {text.strip()[:200]}")
    return int(counted["instructions"]), counted["task-clock"], usage.ru_maxrss / 1024


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
        base_cost, base_ms, base_peak = retired(binary, "afl", args.r2s)
        for address, count in evenly(large, args.sample):
            cost, ms, peak = retired(binary, f"afl; pdd @ {address:#x}", args.r2s)
            row = (count, max(cost - base_cost, 1), max(ms - base_ms, 0.1), peak - base_peak)
            rows.append((binary.name, address, *row))
            print(f"  {address:#x} {count} {row[1] / 1e6:.1f}M {row[2]:.0f}ms {row[3]:.0f}MB", flush=True)
    if args.out:
        Path(args.out).write_text("".join(f"{b}\t{a:#x}\t{n}\t{c}\t{t:.1f}\t{p:.1f}\n"
                                          for b, a, n, c, t, p in rows))
    if len(rows) < 3:
        sys.exit("fewer than three functions: no fit")
    over = []
    for label, column in (("instructions retired", 3), ("CPU time", 4), ("peak RSS above afl's", 5)):
        points = [(row[2], row[column]) for row in rows if row[column] > (1 if column == 5 else 0)]
        if len(points) < 3:
            continue
        slope, r2 = fit(points)
        print(f"{label}: instructions^{slope:.2f} (R^2 {r2:.2f}) over {len(points)} functions")
        if args.max_exponent is not None and slope > args.max_exponent:
            over.append(f"{label} grows as instructions^{slope:.2f}, above {args.max_exponent}")
    for line in over:
        print(line, file=sys.stderr)
    if over:
        sys.exit(1)


def heap_sites(profile):
    """Bytes live at a dhat profile's global peak, by the first two frames the project owns."""
    frames = profile["ftbl"]
    sites = collections.Counter()
    for point in profile["pps"]:
        if not point["gb"]:
            continue
        own = [frames[i].split(": ", 1)[-1] for i in point["fs"]
               if frames[i] != "[root]" and not LIBRARY_FRAME.search(frames[i])]
        sites[" <- ".join(own[:2]) or "?"] += point["gb"]
    return sites


def heap(args):
    runs = []
    for spec in args.profiles:
        size, _, path = spec.rpartition("=")
        runs.append((int(size) if size else None, heap_sites(json.loads(Path(path).read_text()))))
    print("heap peak MB: " + "  ".join(f"{sum(sites.values()) / 1e6:.1f}" for _, sites in runs))
    total = collections.Counter()
    for _, sites in runs:
        total.update(sites)
    for site, _ in total.most_common(args.top):
        points = [(size, sites[site]) for size, sites in runs if size and sites.get(site)]
        growth = f"{fit(points)[0]:5.2f}" if len({size for size, _ in points}) >= 2 else "    -"
        cells = " ".join(f"{sites.get(site, 0) / 1e6:7.2f}" for _, sites in runs)
        print(f"{growth} {cells}  {' <- '.join(frame[:70] for frame in site.split(' <- '))}")


WRITE_ORDERS = ("natural", "o1", "o2", "o3")
NEVER_ASSIGNED = re.compile(r"never assigned, read as residuals \(([^)]*)\)")
RESIDUAL_CALL = re.compile(r"(r2sleigh_residual_\w+)\(\d+\)")
TRAILING_COMMENT = re.compile(r"\s*/\*.*?\*/\s*$")
LABEL = re.compile(r"^\w+:(\s*;)?$")
CONTROL = ("goto ", "continue;", "break;", "if (", "} else", "else", "for (", "while (", "} while (", "do {",
           "switch (", "case ", "default:", "/*")


def never_assigned(code):
    """The names the proof line says were read as residuals for want of a value."""
    found = NEVER_ASSIGNED.search(code)
    return sorted(name.strip() for name in found[1].split(",")) if found else []


def leaf_statements(code):
    """The set of statement lines of a rendering, apart from its control (a label, a jump, a brace) and
    the numbering of its residual sites: what no block write order may change. A set, since a tail is
    written once per jump to it."""
    leaves = set()
    for line in code.splitlines():
        line = line.strip()
        without_comment = TRAILING_COMMENT.sub("", line)
        if not without_comment.endswith(";") or line.startswith(CONTROL) or LABEL.match(line):
            continue
        leaves.add(RESIDUAL_CALL.sub(r"\1(N)", line))
    return sorted(leaves)


def fingerprint(record):
    """What a rendering says that no write order may change: the ledger's columns, the values read as
    never assigned, the residual sites by (instruction address, cause, gap kind, callee, reason), the
    names it declares and links, and its leaf statements. A refused function has one too, its refusal
    (the kind and the reason, which counts the obligations and names the first unaccounted one) and
    its ledger, since a verdict can move inside a refusal (ROADMAP D68)."""
    refused = record.get("refused")
    addrs = {line["line"]: sorted(line["addrs"]) for line in record["lines"]}
    return {
        "refusal": json.dumps(refused, sort_keys=True) if refused else None,
        "proof": record["proof"],
        "never_assigned": never_assigned(record["code"]),
        "sites": sorted(json.dumps([addrs.get(site["line"], []), site["cause"], site["gap"], site["callee"],
                                    site["reason"], site["type"]]) for site in record["residuals"]),
        "variables": sorted(json.dumps(variable, sort_keys=True) for variable in record["variables"]),
        "links": sorted(json.dumps(link, sort_keys=True) for link in record["links"]),
        "statements": leaf_statements(record["code"]),
    }


ASSIGNMENT = re.compile(r"^(\S+) = (.*);$")


def selection_only(natural, mutant):
    """Whether two leaf-statement sets differ only where the structurer's selection pass chose differently:
    each variable they disagree on is assigned on both sides, and a conditional expression is one of the
    assignments (`if (c) x = a; else x = b;` against `x = c ? a : b;`). That pass reads the layout, so it is
    no verdict of D2's; any other difference is."""
    only = [line for line in set(natural) ^ set(mutant)]
    targets = collections.defaultdict(lambda: [0, 0, False])
    for line in only:
        found = ASSIGNMENT.match(line)
        if not found:
            return False
        side = targets[found[1]]
        side[0 if line in natural else 1] += 1
        side[2] |= " ? " in found[2]
    return all(n and m and ternary for n, m, ternary in targets.values())


def verdict_moves(natural, mutant):
    """The parts of two fingerprints that differ, and how the pair is refused (`None` where both or
    neither are). A function without an answer on a side (a crash) has no fingerprint. A difference in
    the statements that only the selection pass explains is no move (`selection_only`)."""
    if natural is None or mutant is None:
        return ([], "refused only under the mutant" if natural is not None else
                "refused only at natural" if mutant is not None else None)
    if bool(natural["refusal"]) != bool(mutant["refusal"]):
        return ([], "refused only under the mutant" if mutant["refusal"] else "refused only at natural")
    moved = [part for part in natural if natural[part] != mutant[part]]
    if "statements" in moved and selection_only(natural["statements"], mutant["statements"]):
        moved.remove("statements")
    return moved, None


def order_answers(args, order, binary):
    """`{address: (fingerprint or refusal, code hash)}` for every function of `binary` under `order`."""
    sys.path.insert(0, str(ROOT / "tests" / "equiv"))
    import r2s_batch

    listing = r2s(binary, "aa; afl", args.r2s)
    addresses = [int(line.split()[0], 16) for line in listing.splitlines()
                 if line.startswith("0x") and not line.split()[3].startswith(("sym.imp", "sym._"))]
    env = {**os.environ, "R2SLEIGH_WRITE_ORDER": order}
    report = r2s_batch.run_batch(args.r2s, binary, addresses, function_timeout=120, startup_timeout=600, env=env)
    answers = {}
    for answer in report.answers:
        if answer.ok:
            record = answer.record
            answers[hex(answer.address)] = {"fingerprint": fingerprint(record),
                                            "text": hashlib.sha256(record["code"].encode()).hexdigest()}
        else:
            answers[hex(answer.address)] = {"fingerprint": None, "text": None, "cause": (answer.cause or "")[:120]}
    return answers


def orders(args):
    """Every function under each write order, against natural: its verdicts must not move, and the order
    must (a knob that moves no text proves nothing)."""
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    binaries = [Path(b) for b in args.binaries]
    results = {}
    for order in WRITE_ORDERS:
        cached = out / f"{order}.json"
        if args.reuse and cached.exists():
            results[order] = json.loads(cached.read_text())
            continue
        with concurrent.futures.ThreadPoolExecutor(min(3, len(binaries))) as pool:
            done = list(pool.map(lambda binary: order_answers(args, order, binary), binaries))
        results[order] = {binary.name: answers for binary, answers in zip(binaries, done)}
        cached.write_text(json.dumps(results[order]))
    failed = False
    total = sum(len(answers) for answers in results["natural"].values())
    print(f"orders: {total} functions in {', '.join(b.name for b in binaries)}")
    for order in WRITE_ORDERS[1:]:
        differ, live, selected, parity, shown = 0, 0, 0, collections.Counter(), []
        for name, natural in results["natural"].items():
            for address, was in natural.items():
                now = results[order][name].get(address, {"fingerprint": None, "text": None})
                moved, refusal = verdict_moves(was["fingerprint"], now["fingerprint"])
                live += was["text"] != now["text"]
                if was["fingerprint"] and now["fingerprint"] and not moved:
                    selected += was["fingerprint"]["statements"] != now["fingerprint"]["statements"]
                if refusal:
                    parity[refusal] += 1
                if moved or refusal:
                    differ += 1
                    shown.append(f"  {name} {address}: {', '.join(moved) or refusal}")
        print(f"{order}: {differ} differ, {live} change text, {selected} differ only in a selection, {dict(parity)}")
        print("\n".join(shown[:args.show]))
        failed |= differ > 0 or live < args.min_live
    if failed:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("run")
    p.add_argument("--r2s", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("binaries", nargs="*")
    p.set_defaults(func=run)
    p = sub.add_parser("golden")
    p.add_argument("--r2s", required=True)
    p.set_defaults(func=golden)
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
    p.add_argument("--alloc-budget", type=float, default=1.02)
    p.add_argument("--heap-budget", type=float, default=1.05)
    p.add_argument("--causes", default=str(CAUSES))
    p.set_defaults(func=time_cases)
    p = sub.add_parser("count")
    p.add_argument("--r2s", action="append", required=True)
    p.add_argument("--qemu", required=True)
    p.add_argument("--bins", required=True)
    p.add_argument("--runs", type=int, default=1)
    p.add_argument("--budget", type=float, default=1.01)
    p.add_argument("--causes", default=str(CAUSES))
    p.set_defaults(func=count_cases)
    p = sub.add_parser("exponent")
    p.add_argument("--r2s", required=True)
    p.add_argument("--min-instructions", type=int, default=300)
    p.add_argument("--sample", type=int, default=40)
    p.add_argument("--max-exponent", type=float)
    p.add_argument("--out")
    p.add_argument("binaries", nargs="+")
    p.set_defaults(func=exponent)
    p = sub.add_parser("orders")
    p.add_argument("--r2s", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--reuse", action="store_true", help="read an order's answers from OUT where it has them")
    p.add_argument("--min-live", type=int, default=50, help="the fewest functions each order must change the text of")
    p.add_argument("--show", type=int, default=20)
    p.add_argument("binaries", nargs="+")
    p.set_defaults(func=orders)
    p = sub.add_parser("heap")
    p.add_argument("--top", type=int, default=30)
    p.add_argument("profiles", nargs="+")
    p.set_defaults(func=heap)
    args = parser.parse_args()
    if args.command in ("time", "count") and len(args.r2s) != 2:
        parser.error(f"{args.command} takes --r2s twice: base, then head")
    if args.command == "time" and args.count_r2s and len(args.count_r2s) != 2:
        parser.error("time takes --count-r2s twice: base, then head")
    args.func(args)


if __name__ == "__main__":
    main()
