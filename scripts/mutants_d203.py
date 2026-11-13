#!/usr/bin/env python3
"""D203's mutation target: each mutant breaks one fact a `void` result rests on, r2s is rebuilt, and the scratch-void
gate must fail on the builds it is given (doc/adr-scratch-result.md, S4). A mutant that survives is expected to, and says
why.

  mutants_d203.py [--check] [--only NAME]... GATE_ARGS...

GATE_ARGS go to scripts/scratch_void.py (`--target`, `--build`, `--manifest`, `--known`, `--baseline`,
`--binutils-prefix`); the shapes in tests/gold/source_gold/scratch.c kill each mutant. Under `--target` only the mutants
graded on that machine run (ROADMAP D246). The unmutated tree must pass the gate first. Run from the
repository root with the files below unmodified; exit 1 where a mutant lives that should die, or dies that should live.
"""

from __future__ import annotations

import os
import subprocess
import sys

BUILD = "cargo build --release -p r2s --features sleigh"
R2S = "target/release/r2s"
RECOVER = "crates/r2ssa/src/recover_interface.rs"
PORTABLE = "crates/r2abi/data/types-posix.sdb.txt"
LANES = "crates/r2ssa/src/lanes.rs"

ALL = ("x86-64", "aarch64")
# The x86 corpus grades every mutant; arm64 grades `entry-byte` alone until a run on it measures the rest (D246).
X86 = ("x86-64",)

# (name, edits, whether it must die, why it may live, targets graded)
MUTANTS = [
    # A void call's leftover on one path decides every path: `some_path` returns a value on the other.
    ("some-path-join", [(RECOVER, "ReturnedByCall::Void => {\n                every_path_writes = false;\n                continue;\n            }",
                         "ReturnedByCall::Void => return RecoveredFunctionResult::Void,")], True, "", X86),
    # `puts` stated void: `tail_puts` forwards its result.
    ("void-row", [(PORTABLE, "func.puts.ret=int\n", "func.puts.ret=void\n")], True, "", X86),
    # Any entry byte defines nothing: `identity` returns its argument, an input's entry byte.
    ("entry-byte", [(LANES, "Fill::Entry(from) => own(at, from),", "Fill::Entry(_) => true,")], True, "", ALL),
    # The canary's residue is a write like any other: `canary_void` returns it (D200 case 3).
    ("inserted-write-unread", [(LANES, "_ if inserted.contains(id) || function.is_checked_difference(*dst) => {",
                                "_ if false => {")], True, "", X86),
]


def sh(command: str) -> subprocess.CompletedProcess:
    return subprocess.run(command, shell=True, capture_output=True, text=True)


# The gate's own failure lines: only these grade a mutant killed.
DIAGNOSTICS = ("FALSE VOID", "VOID LOST", "FLOOR")


def gate(gate_args: list[str]) -> tuple[str, subprocess.CompletedProcess]:
    """`("build", result)` where cargo failed, else `("gate", result)`."""
    built = sh(BUILD)
    if built.returncode != 0:
        return "build", built
    return "gate", subprocess.run([sys.executable, "scripts/scratch_void.py", "--r2s", R2S, *gate_args],
                                  capture_output=True, text=True)


def verdict(stage: str, done: subprocess.CompletedProcess) -> tuple[str, bool | None]:
    """What the run says of the mutant: killed (True), survived (False), or no grade (None) with the reason."""
    if stage == "build" or done.returncode not in (0, 1):
        return f"the {stage} failed (exit {done.returncode}): {done.stderr.strip()[-300:]}", None
    caught = [line for line in done.stderr.splitlines() if line.startswith(DIAGNOSTICS)]
    if done.returncode == 1 and not caught:
        return f"the gate exited 1 with no failure line of its own: {done.stderr.strip()[-300:]}", None
    return (f"killed: {'; '.join(caught[:3])}", True) if caught else ("survived the gate", False)


def target_of(gate_args: list[str]) -> str:
    """The `--target` the gate is given, x86-64 when absent."""
    for i, arg in enumerate(gate_args):
        if arg == "--target" and i + 1 < len(gate_args):
            return gate_args[i + 1]
        if arg.startswith("--target="):
            return arg.split("=", 1)[1]
    return "x86-64"


def run(name, edits, must_die, why, check, gate_args):
    files = {path for path, _, _ in edits}
    originals = {path: open(path).read() for path in files}
    for path, old, _ in edits:
        if originals[path].count(old) != 1:
            return f"{name}: the edit's old text occurs {originals[path].count(old)} times in {path}", False
    if check:
        return f"{name}: applies", True
    text = dict(originals)
    for path, old, new in edits:
        text[path] = text[path].replace(old, new, 1)
    try:
        for path in files:
            open(path, "w").write(text[path])
        stage, done = gate(gate_args)
    finally:
        for path in files:
            open(path, "w").write(originals[path])
    said, died = verdict(stage, done)
    if died is None:
        return f"{name}: {said}", False
    return f"{name}: {said}" + (f" ({why})" if why and not died else ""), died == must_die


def main(argv: list[str]) -> int:
    check = "--check" in argv
    only = [argv[i + 1] for i, a in enumerate(argv) if a == "--only"]
    gate_args = [a for i, a in enumerate(argv) if a != "--check" and a != "--only" and (i == 0 or argv[i - 1] != "--only")]
    target = target_of(gate_args)
    if target not in ALL:
        sys.exit(f"no mutant is graded on {target}")
    paths = sorted({path for _, edits, *_ in MUTANTS for path, _, _ in edits})
    if not check:
        if subprocess.run(["git", "diff", "--quiet", "--", *paths]).returncode:
            sys.exit("a file a mutant edits has changes: commit or restore them first")
        _, green = gate(gate_args)
        if green.returncode != 0:
            print(green.stdout + green.stderr[-2000:])
            sys.exit("the unmutated tree fails the gate: no mutant can be graded against it")
        print("ok    unmutated: the gate passes", flush=True)
    bad = 0
    for name, edits, must_die, why, targets in MUTANTS:
        if (only and name not in only) or target not in targets:
            continue
        line, ok = run(name, edits, must_die, why, check, gate_args)
        print(("ok   " if ok else "WRONG"), line, flush=True)
        bad += not ok
    if not check:
        sh(BUILD)  # leave target/release/r2s built from the tree as it is
    return 1 if bad else 0


if __name__ == "__main__":
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    sys.exit(main(sys.argv[1:]))
