#!/usr/bin/env python3
"""Score every rendering of a binary with DecBench's own `byte_match`, locally.

`byte_match` is the one metric that measures what a rendering *computes*
rather than what it looks like, and until now it could only be read from a
remote sweep that takes hours. This runs the real metric on one binary, on this
machine, in minutes.

It is the upstream implementation, not a lookalike: the disassembly, the
operand normalisation, the line diff and the compile-with-fixup repair all come
from a DecBench checkout, so a number here is the number the sweep would
report for the same function. Reimplementing them would have produced a
plausible score that moved for reasons of its own.

    tests/decbench/byte_match_census.py <binary built with -g> \\
        [--r2s target/release/r2s] [--decbench DIR] [--python PY] [--limit N] [--json OUT]

The binary is the oracle's copy: its DWARF names each function and its
address, and its bytes are what a rendering is scored against. r2s is shown
only a `strip --strip-all` copy and asked `pddj` at each address, as the
official driver does (`renderings.py`). The code is scored exactly as `pddj`
printed it; a rendering DecBench's fixup had to repair is counted, since a
self-contained unit should need none.

`--decbench` defaults to `$R2SLEIGH_DECBENCH_SRC`, and the interpreter has to
be one DecBench supports (3.10 or newer) with `capstone`, `diff_match_patch`
and `pydantic` available. Without those it says so and exits rather than
falling back to something that would score differently.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

from renderings import DEFAULT_R2S, render_binary  # noqa: E402

_WORKER = r'''
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from decbench.utils import binfmt
from decbench.metrics.byte_match import _disassemble_bytes, _compute_jaccard_similarity
from decbench.metrics.fixup import compile_with_fixup

request = json.load(sys.stdin)
binary = Path(request["binary"])
info = binfmt.detect(binary)
if info is None:
    print(json.dumps({"fatal": f"{binary} is not a binary DecBench recognises"}))
    raise SystemExit(0)
flags = binfmt.producer_flags(binary)
arch_mode = binfmt.capstone_arch_mode(info)
compiler = request.get("compiler") or binfmt.recompiler_for(info) or "cc"
flags = request.get("flags") or flags
# `compile_with_fixup` only adds `-c` to its own default flag set, so a caller
# that supplies flags has to ask for an object itself or clang tries to link,
# which on a cross target fails for a reason that has nothing to do with the
# rendering.
if "-c" not in flags:
    flags = [*flags, "-c"]

out = []
for item in request["functions"]:
    original = binfmt.function_bytes(binary, item["original"], item["address"])
    if not original:
        out.append({**item, "status": "no-original-bytes"})
        continue
    fix = compile_with_fixup(item["code"], item["rendered"], compiler, flags)
    if fix.obj_path is None:
        out.append({
            **item, "status": "not-compilable", "score": 0.0,
            "fixups": fix.iterations, "error": (fix.error or "")[:200],
        })
        continue
    recompiled = binfmt.object_text_bytes(fix.obj_path, item["rendered"])
    if not recompiled:
        out.append({**item, "status": "no-recompiled-bytes", "score": 0.0})
        continue
    if recompiled == original:
        out.append({
            **item, "status": "exact", "score": 1.0, "fixups": fix.iterations,
            "original_bytes": len(original), "recompiled_bytes": len(recompiled),
        })
        continue
    a = _disassemble_bytes(original, item["address"], arch_mode)
    b = _disassemble_bytes(recompiled, 0, arch_mode)
    score, changed = _compute_jaccard_similarity(a, b)
    out.append({
        **item, "status": "scored", "score": score, "changed_lines": changed,
        "fixups": fix.iterations, "original_asm": len(a), "recompiled_asm": len(b),
        "original_bytes": len(original), "recompiled_bytes": len(recompiled),
    })

print(json.dumps({
    "compiler": compiler, "flags": flags,
    "preferred": binfmt.recompiler_for(info) or "",
    "arch": f"{info.arch}/{info.bits}", "results": out,
}))
'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("binary", help="the binary, built with -g (its DWARF names the targets)")
    parser.add_argument("--r2s", type=Path, default=DEFAULT_R2S)
    parser.add_argument(
        "--decbench",
        default=os.environ.get("R2SLEIGH_DECBENCH_SRC", ""),
        help="a DecBench checkout (default: $R2SLEIGH_DECBENCH_SRC)",
    )
    parser.add_argument(
        "--python",
        default=os.environ.get("R2SLEIGH_DECBENCH_PYTHON", sys.executable),
        help="interpreter with DecBench's dependencies (3.10 or newer)",
    )
    parser.add_argument(
        "--compiler",
        default=os.environ.get("R2SLEIGH_DECBENCH_CC", ""),
        help="override the recompiler DecBench picks from the binary; on a host "
        "without the producer's cross toolchain, clang targets it directly "
        "(only an object is needed, never a link)",
    )
    parser.add_argument(
        "--flag",
        action="append",
        default=[],
        help="extra compiler flag, repeatable; used when the binary records none",
    )
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--json", default="")
    parser.add_argument("--show", type=int, default=10, help="worst N to list")
    args = parser.parse_args()

    if not args.decbench or not Path(args.decbench, "decbench").is_dir():
        print(
            "a DecBench checkout is required: pass --decbench or set "
            "R2SLEIGH_DECBENCH_SRC. The metric is run, never reimplemented, so "
            "that a number here is the number a sweep would report.",
            file=sys.stderr,
        )
        return 2

    binary = Path(args.binary).resolve()
    requests = []
    declined: dict[str, str] = {}
    for rendering in render_binary(binary, args.r2s, limit=args.limit):
        answer = rendering.answer
        label = rendering.name or f"0x{rendering.address:x}"
        if not answer.ok or answer.record is None:
            declined[label] = answer.cause
            continue
        if rendering.name is None:
            # Without the source's name DecBench cannot find the original bytes.
            declined[label] = "harness: the binary names no source function at this address"
            continue
        requests.append({
            "rendered": str(answer.record.get("definition", "")),
            "original": rendering.name,
            "address": rendering.address,
            "code": str(answer.record.get("code", "")),
        })

    if not requests:
        print(f"no function rendered ({len(declined)} declined)", file=sys.stderr)
        for label, cause in sorted(declined.items())[: args.show]:
            print(f"  {label}: {cause[:160]}", file=sys.stderr)
        return 1

    run = subprocess.run(
        [args.python, "-c", _WORKER, str(Path(args.decbench).resolve())],
        input=json.dumps(
            {
                "binary": str(binary),
                "functions": requests,
                "compiler": args.compiler,
                "flags": args.flag,
            }
        ),
        capture_output=True,
        text=True,
        check=False,
    )
    if run.returncode != 0 or not run.stdout.strip():
        print(run.stderr.strip()[-2000:] or "the scorer produced nothing", file=sys.stderr)
        return 1
    report = json.loads(run.stdout)
    if "fatal" in report:
        print(report["fatal"], file=sys.stderr)
        return 1

    results = report["results"]
    scored = [r for r in results if "score" in r]
    print(f"{binary.name}  {report['arch']}  {report['compiler']} {' '.join(report['flags'])}")
    if "clang" in report["compiler"] and "gcc" in (report.get("preferred") or ""):
        print(
            f"  note: the binary's producer was {report['preferred']}, which is not on this "
            "host. Recompiling with clang gives different codegen, so treat these as "
            "comparable between local runs, not against a remote sweep."
        )
    if not scored:
        reasons: dict[str, int] = {}
        for r in results:
            reasons[r.get("status", "?")] = reasons.get(r.get("status", "?"), 0) + 1
        print(f"nothing scored over {len(results)} renderings: {reasons}")
        for r in results[:3]:
            if r.get("error"):
                print(f"  {r['original']}: {r['error']}")
        return 1
    mean = sum(r["score"] for r in scored) / len(scored)
    perfect = sum(1 for r in scored if r["score"] >= 1.0)
    repaired = sum(1 for r in scored if r.get("fixups", 0) > 0)
    print(
        f"scored {len(scored)} of {len(results)} renderings"
        f"  mean byte_match {mean:.4f}  perfect {perfect}"
        f" ({100 * perfect / len(scored):.1f}%)  repaired by fixup {repaired}"
    )
    if declined:
        print(f"  declined by r2s, scoring nothing: {len(declined)}")
        for label, cause in sorted(declined.items())[: args.show]:
            print(f"    {label}: {cause[:160]}")
    failures = sum(1 for r in results if r.get("status") == "not-compilable")
    if failures:
        print(f"  {failures} did not compile even after fixup, scoring zero")

    if args.show:
        worst = sorted(scored, key=lambda r: r["score"])[: args.show]
        for r in worst:
            print(f"  {r['score']:.4f}  {r['original']}  ({r['status']})")

    if args.json:
        Path(args.json).write_text(json.dumps({**report, "declined": declined}, indent=2))
        print(f"  wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
