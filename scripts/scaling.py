#!/usr/bin/env python3
"""The scaling bench (ROADMAP D404): how `aa; pdd` of one generated function grows along each dimension.

  scaling.py [--r2s R2S] [--meter R2S] [--n N] [--budget R] [--only DIM] [--out DIR]

Each dimension generates the same function at sizes 0, N and 2N, builds it with `cc`, and counts
`r2s -q -c "aa; pdd @ f"` under callgrind. The size-0 count is the fixed cost (startup, the
Sleigh load, the rest of the binary), so a linear pass reads (Ir(2N) - Ir(0)) / (Ir(N) - Ir(0)) = 2
and a quadratic one 4; the budget is 2.3. A dimension another row owns that fails today is held
in OPEN: it fails until that row lands, and then once it passes.

`--meter` grades a `work-meter` build the same way by its element visits (`r2s: stats: scans`,
D417): P whole passes visit P*n elements and a rescan adds n^2, so the ratio is exact where Ir
is noisy and a rescan reads above SCAN_BUDGET at sizes callgrind cannot see.
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

BUDGET = 2.3
# Element visits: a linear generator reads 2 exactly but for its constant terms (D417).
SCAN_BUDGET = 2.1
# A dimension that fails today, by the row that owns its cost; held exactly both ways.
OPEN = {}
SCAN_OPEN = {}
START = "_start:\n    call f\n    mov $60, %eax\n    xor %edi, %edi\n    syscall\n"


def calls_in_one_block(n):
    """n calls to one walked callee in one block: a per-call scan of the block is O(n^2) (1cd65fdcc)."""
    body = "".join(f"    mov ${i}, %edi\n    call g\n" for i in range(n))
    return "s", f".text\n.globl _start\n{START}g:\n    ret\nf:\n    push %rbx\n{body}    pop %rbx\n    ret\n"


def unproven_returns(n):
    """n returns whose stack pointer a dynamic adjust leaves unproven: a per-return walk of the
    function is O(n * (I + B)) (c67924d1a)."""
    tests = "".join(f"    cmp ${i}, %edi\n    je .Lr{i}\n" for i in range(n))
    arms = "".join(f".Lr{i}:\n    mov ${i}, %eax\n    add %rsi, %rsp\n    ret\n" for i in range(n))
    return "s", f".text\n.globl _start\n{START}f:\n{tests}    xor %eax, %eax\n    ret\n{arms}"


def struct_parameter_accesses(n):
    """n declared struct-pointer parameters, each read once: grouping accesses per parameter by a
    rescan is O(params * accesses) (adee2bc73)."""
    params = ", ".join(f"struct s *p{i}" for i in range(max(n, 1)))
    reads = " + ".join(f"p{i}->m{i % 4}" for i in range(n)) or "0"
    args = ", ".join("&v" for _ in range(max(n, 1)))
    return "c", (f"struct s {{ long m0, m1, m2, m3; }};\n"
                 f"__attribute__((noipa)) long f({params}) {{ return {reads}; }}\n"
                 f"int main(void) {{ struct s v = {{0}}; return (int)f({args}); }}\n")


def halting_calls(n):
    """n calls to a stub that halts on one argument value: a walker per call is O(n * body) (604ce3cb7)."""
    calls = "".join(f"    error(0, 0, \"%d\", {i});\n" for i in range(n))
    return "c", (f"#include <error.h>\n__attribute__((noipa)) void f(void) {{\n{calls}}}\n"
                 "int main(void) { f(); return 0; }\n")


def escaped_locals(n):
    """n locals whose addresses an unknown call takes, each read after: a scan of every opaque point
    per read is O(n^2) (D397, close_upward)."""
    decls = "".join(f"    long x{i} = {i};\n    g(&x{i});\n" for i in range(n))
    total = " + ".join(f"x{i}" for i in range(n)) or "0"
    return "c", (f"__attribute__((noipa)) void g(long *p) {{ (void)p; }}\n"
                 f"__attribute__((noipa)) long f(void) {{\n{decls}    return {total};\n}}\n"
                 "int main(void) { return (int)f(); }\n")


DIMENSIONS = {
    "calls_in_one_block": calls_in_one_block,
    "unproven_returns": unproven_returns,
    "struct_parameter_accesses": struct_parameter_accesses,
    "halting_calls": halting_calls,
    "escaped_locals": escaped_locals,
}


def build(kind, source, out):
    """The generated function as a linked x86-64 ELF at `out`."""
    path = out.with_suffix("." + kind)
    path.write_text(source)
    flags = ["-nostdlib", "-static", "-no-pie"] if kind == "s" else ["-O1", "-g", "-fno-inline", "-no-pie"]
    subprocess.run(["cc", *flags, str(path), "-o", str(out)], check=True)
    symbols = subprocess.run(["nm", str(out)], capture_output=True, text=True, check=True).stdout
    address = re.search(r"^([0-9a-f]+) [Tt] f$", symbols, re.MULTILINE)
    if not address:
        sys.exit(f"{out}: no symbol f")
    return f"0x{int(address.group(1), 16):x}"


def instructions(r2s, binary, address, work):
    """Instructions callgrind counts for one `aa; pdd @ address` process."""
    out = Path(work) / "callgrind.out"
    subprocess.run(["valgrind", "--tool=callgrind", f"--callgrind-out-file={out}", r2s, "-q", "-c",
                    f"aa; pdd @ {address}", str(binary)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    totals = re.search(r"^(?:summary|totals): (\d+)", out.read_text(), re.MULTILINE)
    if not totals:
        sys.exit(f"{out}: no totals line")
    return int(totals.group(1))


def scans(r2s, binary, address):
    """Element visits a `work-meter` build counts for one `aa; pdd @ address` process."""
    done = subprocess.run([r2s, "-q", "-c", f"aa; pdd @ {address}", str(binary)],
                          env={**os.environ, "R2S_STATS": "1"}, capture_output=True, text=True)
    found = re.search(r"^r2s: stats: scans (\d+)$", done.stderr, re.MULTILINE)
    if done.returncode != 0 or not found:
        sys.exit(f"{binary}: exited {done.returncode} with no scans line; is {r2s} a work-meter build?")
    return int(found.group(1))


def growth(fixed, one, two):
    """Ir(2N) over Ir(N), each less the size-0 run: 2 for a linear pass, 4 for a quadratic one."""
    if one <= fixed:
        return None
    return (two - fixed) / (one - fixed)


def verdict(name, ratio, budget, open_rows=OPEN):
    """Why the dimension fails, or None: over budget and not open, or open and within it."""
    owner = open_rows.get(name)
    if ratio is None:
        return f"{name}: size N cost no more than size 0; the generator does not reach the engine"
    if ratio > budget and owner is None:
        return f"{name}: grows {ratio:.2f}x from N to 2N, above {budget}"
    if ratio <= budget and owner is not None:
        return f"{name}: grows {ratio:.2f}x, within {budget}; delete its OPEN entry ({owner})"
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--r2s", help="a build to count under callgrind")
    parser.add_argument("--meter", help="a work-meter build to count by element visits")
    parser.add_argument("--n", type=int, default=64)
    parser.add_argument("--budget", type=float, default=BUDGET)
    parser.add_argument("--scan-budget", type=float, default=SCAN_BUDGET)
    parser.add_argument("--only", action="append", choices=sorted(DIMENSIONS))
    parser.add_argument("--out", help="keep the generated binaries here")
    args = parser.parse_args()
    if not (args.r2s or args.meter):
        parser.error("give --r2s, --meter or both")
    grades = []
    if args.r2s:
        grades.append(("Ir", lambda binary, address, work: instructions(args.r2s, binary, address, work),
                       args.budget, OPEN))
    if args.meter:
        grades.append(("scans", lambda binary, address, work: scans(args.meter, binary, address),
                       args.scan_budget, SCAN_OPEN))
    failed = []
    print("| dimension | count | size 0 | N | 2N | growth |\n|---|---|---|---|---|---|")
    with tempfile.TemporaryDirectory() as work:
        out = Path(args.out or work)
        out.mkdir(parents=True, exist_ok=True)
        for name in args.only or DIMENSIONS:
            built = []
            for size in (0, args.n, 2 * args.n):
                binary = out / f"{name}-{size}"
                kind, source = DIMENSIONS[name](size)
                built.append((binary, build(kind, source, binary)))
            for label, count, budget, open_rows in grades:
                counts = [count(binary, address, work) for binary, address in built]
                ratio = growth(*counts)
                shown = "n/a" if ratio is None else f"{ratio:.3f}"
                print(f"| {name} | {label} | {counts[0]:,} | {counts[1]:,} | {counts[2]:,} | {shown} |",
                      flush=True)
                if reason := verdict(name, ratio, budget, open_rows):
                    failed.append(f"{label}: {reason}")
    for line in failed:
        print(line, file=sys.stderr)
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
