#!/usr/bin/env python3
"""Whether each caller's extern of a function spells that function's own header (W46, D166).

    scripts/extern_agree.py [--r2s R2S] [--json FILE] [--max N] [BINARY...]

`aa`, then `pddj` of every function `afl` lists. Each extern a rendering declares for a function the
same run renders is compared with that function's header: the result type and the parameter types,
names dropped. Without binaries, the census binaries (doc/adr-call-boundary.md, "S16 as built").
Exit 1 where more than `--max` pairs differ, 2 where analysis failed: `aa; afl` exits nonzero or
lists no function, or a function's `pddj` crashed, so no comparison stands in for it.

Each binary is keyed by its DecBench set (`O2`, `O2-noinline`) and its name, so the two builds of one
name stay apart; a binary under no set is keyed by its name. Calls refused for their callee's declaration are counted by tag (D350). A callee is
matched by name: two static functions of one name (census two_units `helper`) read as one.
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


class AnalysisFailed(Exception):
    """A binary or function the comparison could not read; exit 2."""


# Each refusal's tag and the texts `CallRefusal` spells it with (r2dec `ast.rs`).
REFUSALS = {
    "declaration-disagrees": ("another call disagrees with its declaration",),
}


def key(binary: str) -> str:
    """`.../O2/grep/stripped/grep` -> `O2/grep`: the set's name where the path has one."""
    parts = Path(binary).parts
    sets = [part for part in parts if part in ("O2", "O2-noinline")]
    return f"{sets[-1]}/{parts[-1]}" if sets else parts[-1]


def pairs(r2s: str, binary: str, refused: dict[str, int]) -> tuple[int, list[dict], list[str]]:
    """How many extern pairs `binary` holds, those that differ, and each callee two callers declare
    differently (D350), counting refused calls into `refused`; raises where analysis failed."""
    run = subprocess.run([r2s, "-q", "-c", "aa; afl", binary], capture_output=True, text=True, timeout=3600)
    addrs = sorted({int(line.split()[0], 16) for line in run.stdout.splitlines() if line.startswith("0x")})
    if run.returncode != 0 or not addrs:
        raise AnalysisFailed(f"{binary}: `aa; afl` exited {run.returncode} with {len(addrs)} functions")
    report = r2s_batch.run_batch(r2s, binary, addrs, function_timeout=300, startup_timeout=3600)
    crashed = [answer for answer in report.answers if answer.kind == "crash"]
    if crashed:
        first = crashed[0]
        raise AnalysisFailed(f"{binary}: {len(crashed)} functions crashed, first {first.address:#x}: {first.cause[:200]}")
    headers, externs = {}, []
    for answer in report.answers:
        record = answer.record or {}
        signature, code = record.get("signature"), record.get("code") or ""
        for tag, texts in REFUSALS.items():
            refused[tag] = refused.get(tag, 0) + sum(code.count(text) for text in texts)
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
    spelled: dict[str, set] = {}
    for _, callee, extern in externs:
        spelled.setdefault(callee, set()).add(extern)
    split = sorted(callee for callee, found in spelled.items() if len(found) > 1)
    total, differ = 0, []
    for caller, callee, extern in externs:
        if callee not in headers or callee == caller:
            continue
        total += 1
        if extern != headers[callee]:
            differ.append({"caller": caller, "callee": callee, "extern": extern, "header": headers[callee]})
    return total, differ, split


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--r2s", default=str(ROOT / "target/release/r2s"))
    parser.add_argument("--json", type=Path)
    parser.add_argument("--max", type=int)
    parser.add_argument("binaries", nargs="*")
    args = parser.parse_args()
    total, report, splits, refused = 0, {}, {}, {}
    for binary in args.binaries or [str(ROOT / path) for path in CENSUS]:
        try:
            count, differ, split = pairs(args.r2s, binary, refused)
        except AnalysisFailed as failed:
            print(f"analysis failed: {failed}", file=sys.stderr)
            return 2
        total += count
        if split:
            splits[key(binary)] = split
        if differ:
            report[key(binary)] = differ
    differ = sum(len(found) for found in report.values())
    for binary, found in report.items():
        for pair in found:
            print(f"{binary} {pair['caller']} -> {pair['callee']}: {pair['extern']} | {pair['header']}")
    for binary, split in splits.items():
        print(f"{binary}: more than one extern for {', '.join(split)}")
    two_ways = sum(map(len, splits.values()))
    causes = ", ".join(f"{refused.get(tag, 0)} {tag}" for tag in REFUSALS)
    print(f"{differ} of {total} differ; {two_ways} callees declared two ways; refused: {causes}")
    if args.json:
        args.json.write_text(json.dumps(report, indent=1) + "\n")
    return 1 if args.max is not None and differ > args.max else 0


if __name__ == "__main__":
    sys.exit(main())
