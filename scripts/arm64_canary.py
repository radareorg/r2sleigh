#!/usr/bin/env python3
"""gcc's arm64 stack-guard check, measured on debug builds (ROADMAP D248, doc/adr-scratch-result.md).

    arm64_canary.py [--binutils-prefix P] DEBUG...

For each function that calls `__stack_chk_fail`, the check is the run from the last `adrp` before the `b.ne` that
jumps to that call, through the `b.ne`. It prints the registers the check writes, counted over functions, and the
source-void functions (DWARF, the gate's `truth`) whose X0 at the `ret` after the check was last written by the
check: the functions whose only result byte is the check's. Linear in instructions; objdump's text, no engine.
"""

from __future__ import annotations

import argparse
import collections
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scratch_void  # noqa: E402

FUNC = re.compile(r"^([0-9a-f]+) <([^>]+)>:$")
INSN = re.compile(r"^\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+(\S+)\s*([^/]*)")
NO_DEST = ("str", "stp", "strb", "strh", "stur", "cmp", "cmn", "tst", "b", "bl", "br", "blr", "ret", "cbz", "cbnz",
           "tbz", "tbnz", "nop")


@dataclass
class Function:
    name: str
    entry: int
    insns: list[tuple[int, str, list[str]]] = field(default_factory=list)


def functions(debug: Path, prefix: str) -> list[Function]:
    out = subprocess.run([prefix + "objdump", "-d", str(debug)], capture_output=True, text=True, check=True).stdout
    found, current = [], None
    for line in out.splitlines():
        head = FUNC.match(line)
        if head:
            current = Function(head.group(2), int(head.group(1), 16))
            found.append(current)
            continue
        insn = INSN.match(line)
        if insn and current is not None:
            ops = [op.strip() for op in insn.group(3).split(",") if op.strip()]
            current.insns.append((int(insn.group(1), 16), insn.group(2), ops))
    return found


def written(mnemonic: str, ops: list[str]) -> str | None:
    """The 64-bit register an instruction writes first, as `xN` (`wN` widened), or None."""
    if mnemonic.startswith("b.") or mnemonic in NO_DEST or not ops:
        return None
    reg = ops[0]
    return "x" + reg[1:] if re.fullmatch(r"[wx]\d+", reg) else None


def check(fn: Function, fail: set[int]) -> tuple[set[str], bool] | None:
    """(registers the check writes, whether X0 at the following `ret` is the check's) or None without a check."""
    for at, (_, mnemonic, ops) in enumerate(fn.insns):
        if not (mnemonic == "b.ne" and ops and int(ops[0].split()[0], 16) in fail):
            continue
        start = max((i for i in range(at) if fn.insns[i][1] == "adrp"), default=None)
        if start is None:
            return None
        regs = {r for _, m, o in fn.insns[start:at + 1] if (r := written(m, o))}
        last_x0 = "check" if "x0" in regs else None
        for _, m, o in fn.insns[at + 1:]:
            if m == "ret":
                return regs, last_x0 == "check"
            if written(m, o) == "x0":
                last_x0 = "after"
        return regs, False
    return None


def measure(debug: Path, prefix: str) -> tuple[collections.Counter, int, list[str]]:
    fns = functions(debug, prefix)
    calls = {fn.entry for fn in fns if fn.name == "__stack_chk_fail@plt"}
    # the block that calls `__stack_chk_fail`: its first instruction is the `b.ne` target
    fail = {a for fn in fns for a, m, o in fn.insns if m == "bl" and o and int(o[0].split()[0], 16) in calls}
    target = scratch_void.target_of("aarch64", prefix or None)
    void = {src.name for src in scratch_void.truth(debug, target).values() if not src.value}
    regs: collections.Counter = collections.Counter()
    checked, only = 0, []
    for fn in fns:
        found = check(fn, fail)
        if found is None:
            continue
        checked += 1
        regs.update(found[0])
        if found[1] and fn.name in void:
            only.append(fn.name)
    return regs, checked, only


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binutils-prefix", default="aarch64-linux-gnu-")
    parser.add_argument("debug", nargs="+", type=Path)
    args = parser.parse_args(argv)
    total: collections.Counter = collections.Counter()
    checked, only = 0, []
    for debug in args.debug:
        regs, n, names = measure(debug, args.binutils_prefix)
        total.update(regs)
        checked += n
        only += [f"{debug.name} {name}" for name in names]
    print(f"{checked} functions with a guard check; registers it writes: "
          + ", ".join(f"{r} {n}" for r, n in sorted(total.items(), key=lambda kv: (-kv[1], kv[0]))))
    print(f"{len(only)} source-void functions whose X0 at the return is the check's")
    for line in only:
        print(f"  {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
