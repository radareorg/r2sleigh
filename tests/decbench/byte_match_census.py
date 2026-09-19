#!/usr/bin/env python3
"""Score a control census with DecBench's own `byte_match`, locally.

`byte_match` is the one metric that measures what a rendering *computes*
rather than what it looks like, and until now it could only be read from a
remote sweep that takes hours. Every change had to be argued for instead of
priced, and this project has already reported a gain four times that turned out
to be a semantic regression. This runs the real metric against the output of
`tests/corpus/control_census.sh` on one binary, on this machine, in minutes.

It is the upstream implementation, not a lookalike: the disassembly, the
operand normalisation, the line diff and the compile-with-fixup repair all come
from a DecBench checkout, so a number here is the number the sweep would
report for the same function. Reimplementing them would have produced a
plausible score that moved for reasons of its own.

    tests/decbench/byte_match_census.py <census.txt> <original-binary> \
        [--decbench DIR] [--python PY] [--limit N] [--json OUT]

`--decbench` defaults to `$R2SLEIGH_DECBENCH_SRC`, and the interpreter has to
be one DecBench supports (3.10 or newer) with `capstone`, `diff_match_patch`
and `pydantic` available. Without those it says so and exits rather than
falling back to something that would score differently.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

from compile_census import renderings  # noqa: E402

# The engine prefixes every rendered function with the debug marker; the
# original symbol is what the binary calls it.
# `pd:s` renders a body function as `dbg_<name>` and an import thunk as
# `sym_imp_<name>`; radare2 spells the same symbols with dots.
_RENDER_PREFIXES = ("dbg_", "sym_imp_", "sym_")
_SIGNATURE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_NOT_A_NAME = frozenset({"if", "while", "for", "switch", "return", "sizeof", "__attribute__"})


def rendered_name(source: str) -> str | None:
    """The function this rendering defines, as its own C spells it.

    The definition line is at column zero and does not end in a semicolon,
    which separates it from the extern prototypes indented inside the body and
    from the typedefs and aggregate definitions above it. Cutting at the first
    brace does not work: that brace now opens a `struct` the rendering
    defines, not the function.
    """
    for line in source.splitlines():
        if not line or line[0].isspace() or line.lstrip().startswith(("/*", "//", "#")):
            continue
        if line.rstrip().endswith(";"):
            continue
        for match in _SIGNATURE.finditer(line):
            name = match.group(1)
            if name not in _NOT_A_NAME:
                return name
    return None


def original_name(name: str) -> str:
    for prefix in _RENDER_PREFIXES:
        if name.startswith(prefix):
            return name[len(prefix) :]
    return name


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


def function_addresses(binary: Path) -> dict[str, int]:
    """Every function radare2 finds, by the name the binary gives it.

    The census marks each rendering by address; `binfmt.function_bytes` wants
    a name and an address, and this is the one table that has both.
    """
    listing = subprocess.run(
        ["r2", "-e", "scr.color=0", "-q", "-c", "aaa; afl", str(binary)],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    found: dict[str, int] = {}
    for line in listing.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[0].startswith("0x"):
            try:
                found[fields[3]] = int(fields[0], 16)
            except ValueError:
                continue
    return found


def strip_symbol_prefix(name: str) -> str:
    for prefix in ("sym.", "sym.imp.", "fcn.", "dbg."):
        if name.startswith(prefix):
            name = name[len(prefix) :]
    return name.lstrip("_")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("census", help="output of tests/corpus/control_census.sh")
    parser.add_argument("binary", help="the binary that census was taken from")
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
    addresses = {
        strip_symbol_prefix(name): addr for name, addr in function_addresses(binary).items()
    }

    requests = []
    skipped_unnamed = 0
    skipped_unplaced = []
    for _marker, source in renderings(Path(args.census).read_text()):
        name = rendered_name(source)
        if name is None:
            skipped_unnamed += 1
            continue
        original = original_name(name)
        address = addresses.get(original) or addresses.get(original.lstrip("_"))
        if address is None:
            skipped_unplaced.append(original)
            continue
        requests.append(
            {"rendered": name, "original": original, "address": address, "code": source}
        )
        if args.limit and len(requests) >= args.limit:
            break

    if not requests:
        print("no rendering could be matched to a function in the binary", file=sys.stderr)
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
    if all(r.get("status") == "not-compilable" for r in scored):
        for r in scored[:3]:
            print(f"  {r['original']}: {r.get('error', '')}")
        return 1
    mean = sum(r["score"] for r in scored) / len(scored)
    perfect = sum(1 for r in scored if r["score"] >= 1.0)
    repaired = sum(1 for r in scored if r.get("fixups", 0) > 0)
    print(
        f"scored {len(scored)} of {len(results)} renderings"
        f"  mean byte_match {mean:.4f}  perfect {perfect}"
        f" ({100 * perfect / len(scored):.1f}%)  repaired by fixup {repaired}"
    )
    if skipped_unnamed or skipped_unplaced:
        print(
            f"  skipped: {skipped_unnamed} without a definition line,"
            f" {len(skipped_unplaced)} not found in the binary"
        )
    failures = sum(1 for r in results if r.get("status") == "not-compilable")
    if failures:
        print(f"  {failures} did not compile even after fixup, scoring zero")

    if args.show:
        worst = sorted(scored, key=lambda r: r["score"])[: args.show]
        for r in worst:
            print(f"  {r['score']:.4f}  {r['original']}  ({r['status']})")

    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2))
        print(f"  wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
