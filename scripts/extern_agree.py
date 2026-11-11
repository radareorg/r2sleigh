#!/usr/bin/env python3
"""Whether each caller's extern of a function spells that function's own header (W46, D166).

    scripts/extern_agree.py [--r2s R2S] [--json FILE] [--max N] [BINARY...]

`aa`, then `pddj` of every function `afl` lists. Each extern a rendering declares for a function the
same run renders is compared with that function's header: the result type and the parameter types,
names dropped. Without binaries, the census binaries (doc/adr-call-boundary.md, "S16 as built").
Exit 1 where more than `--max` pairs differ.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests/equiv"))
import r2s_batch  # noqa: E402

CENSUS = [
    "tests/coverage/pinned/branchy_gcc_x64_O0",
    "tests/coverage/pinned/hashes_gcc_x64_O2",
    "tests/coverage/pinned/shapes_gcc_x64_O0",
    "tests/fixtures/code_pointer_table_O0",
    "tests/fixtures/float_calls_zig_aarch64_O2g",
    "tests/fixtures/float_calls_zig_x86_64_O2g",
    "tests/fixtures/float_compares_zig_aarch64_O2g",
    "tests/fixtures/float_compares_zig_x86_64_O2g",
    "tests/fixtures/float_moves_zig_aarch64_O2g",
    "tests/fixtures/float_moves_zig_x86_64_O2g",
    "tests/fixtures/float_returns_zig_aarch64_O2g",
    "tests/fixtures/float_returns_zig_x86_64_O2g",
    "tests/fixtures/frame_pointer_locals_clang_O0g",
    "tests/fixtures/hashes_gcc_x64_O2_stripped",
    "tests/fixtures/loop_exits_gcc_x64_O2",
    "tests/fixtures/manual_limits_O0",
    "tests/fixtures/manual_limits_O2",
    "tests/fixtures/rv_O0g",
    "tests/fixtures/rv_O0g_stripped",
    "tests/fixtures/rv_O2",
    "tests/fixtures/shapes_zig_riscv64_O0",
    "tests/fixtures/syscalls_static_O2",
    "tests/fixtures/two_units_O0g",
]
HEADER = re.compile(r"^(?:static\s+)?(.+?)\b([A-Za-z_][\w.]*)\((.*)\)\s*$")
EXTERN = re.compile(r"^\s+(?:__attribute__\(\(noreturn\)\)\s+)?(.+?)\b([A-Za-z_][\w.]*)\((.*)\);\s*$")


def split(params: str) -> list[str]:
    """`int (*f)(int, int), int` -> two parameters: commas inside parentheses stay."""
    out, depth, current = [], 0, ""
    for ch in params:
        depth += (ch == "(") - (ch == ")")
        if ch == "," and depth == 0:
            out.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        out.append(current.strip())
    return out


def unnamed(param: str) -> str:
    """`uint32_t arg0` -> `uint32_t`; `int32_t (*fn)(int32_t)` -> `int32_t(*)(int32_t)`."""
    param = re.sub(r"\(\s*\*\s*[A-Za-z_]\w*\s*\)", "(*)", param)
    if not param.endswith(("*", ")")):
        param = re.sub(r"\s+[A-Za-z_]\w*$", "", param)
    return re.sub(r"\s+", "", param)


def shape(ret: str, params: str) -> tuple[str, tuple[str, ...]]:
    found = split(params)
    found = [] if found in ([], ["void"]) else found
    return re.sub(r"\s+", "", ret), tuple(unnamed(param) for param in found)


def pairs(r2s: str, binary: str) -> tuple[int, list[dict]]:
    """How many extern pairs `binary` holds, and those that differ."""
    run = subprocess.run([r2s, "-q", "-c", "aa; afl", binary], capture_output=True, text=True, timeout=3600)
    addrs = sorted({int(line.split()[0], 16) for line in run.stdout.splitlines() if line.startswith("0x")})
    report = r2s_batch.run_batch(r2s, binary, addrs, function_timeout=300, startup_timeout=3600)
    headers, externs = {}, []
    for answer in report.answers:
        record = answer.record or {}
        signature, code = record.get("signature"), record.get("code") or ""
        found = signature and HEADER.match(signature.strip())
        if not found:
            continue
        caller = found.group(2)
        headers[caller] = shape(found.group(1), found.group(3))
        lines = code.splitlines()
        start = next((at for at, line in enumerate(lines) if line.strip() == signature.strip()), None)
        for line in lines[start + 2 :] if start is not None else []:
            if not line.startswith("    ") or line.strip() == "{":
                break
            if declared := EXTERN.match(line):
                externs.append((caller, declared.group(2), shape(declared.group(1), declared.group(3))))
    total, differ = 0, []
    for caller, callee, extern in externs:
        if callee not in headers or callee == caller:
            continue
        total += 1
        if extern != headers[callee]:
            differ.append({"caller": caller, "callee": callee, "extern": extern, "header": headers[callee]})
    return total, differ


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--r2s", default=str(ROOT / "target/release/r2s"))
    parser.add_argument("--json", type=Path)
    parser.add_argument("--max", type=int)
    parser.add_argument("binaries", nargs="*")
    args = parser.parse_args()
    total, report = 0, {}
    for binary in args.binaries or [str(ROOT / path) for path in CENSUS]:
        count, differ = pairs(args.r2s, binary)
        total += count
        if differ:
            report[Path(binary).name] = differ
    differ = sum(len(found) for found in report.values())
    for binary, found in report.items():
        for pair in found:
            print(f"{binary} {pair['caller']} -> {pair['callee']}: {pair['extern']} | {pair['header']}")
    print(f"{differ} of {total} differ")
    if args.json:
        args.json.write_text(json.dumps(report, indent=1) + "\n")
    return 1 if args.max is not None and differ > args.max else 0


if __name__ == "__main__":
    sys.exit(main())
