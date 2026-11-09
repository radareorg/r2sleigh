#!/usr/bin/env python3
"""D75's mutation target: each mutant of the noreturn guard and of the `never_returns` predicate's readers is applied to
the tree, the tests that should kill it run, and the file is restored (doc/adr-structure-dominator-tree.md, "the
noreturn guard").

  mutants_d75.py [--check] [NAME...]    run (or only --check that every edit applies once) the named mutants, else all

Run from the repository root with the files below unmodified. A mutant dies only when every test command builds and one
reports a failing test; one that does not build, or a command that fails without a failing test, is WRONG. Exit 1 where
a mutant is not killed."""

import os
import re
import subprocess
import sys

R2DEC = "cargo test -p r2dec --lib --all-features"
ENGINE = "cargo test -p r2engine --test engine structure::"

SHAPE = "crates/r2dec/src/structure/shape.rs"
TAILS = "crates/r2dec/src/structure/tails.rs"
GUARD = "crates/r2dec/src/structure/guard.rs"
RENDER = "crates/r2dec/src/render/mod.rs"

# The predicate's lookup and its call pattern.
LOOKUP = "if self.never_return.contains(name)))"
PREDICATE = "matches!(stmt, CStmt::Expr(CExpr::Call { func, .. })\n            if matches!("

# Every reader of the predicate: the file, its text, and that text reading `{call}` as the predicate's verdict.
READERS = [
    ("tail-run", TAILS, "CStmt::Expr(_) if ev.never_returns(stmt) => Some(Ended::Terminal),",
     "CStmt::Expr(_) if {call} => Some(Ended::Terminal),"),
    ("completes", TAILS, "CStmt::Expr(_) => !ev.never_returns(stmt),", "CStmt::Expr(_) => !({call}),"),
    ("falling-ends", TAILS, "CStmt::Expr(_) => Some(usize::from(!ev.never_returns(stmt))),",
     "CStmt::Expr(_) => Some(usize::from(!({call}))),"),
    ("arm-end", GUARD, "CStmt::Expr(_) => return ev.never_returns(stmt),", "CStmt::Expr(_) => return {call},"),
    ("role", RENDER, "false => (traps(stmt) || evidence.never_returns(stmt)).into(),",
     "false => (traps(stmt) || {call}).into(),"),
]

# Argument counts a reader may cut at: two (`err(1, fmt)`), four, past the six x86-64 and eight AArch64 registers.
CUTS = (2, 4, 7, 9, 16)


def counted(reader, cut):
    """`reader` ignoring a call with `cut` or more arguments."""
    name, path, old, new = next(r for r in READERS if r[0] == reader)
    ev = "evidence" if path == RENDER else "ev"
    verdict = (f"{ev}.never_returns(stmt) && !matches!(stmt, crate::ast::CStmt::Expr(crate::ast::CExpr::Call {{ args, .. }})"
               f" if args.len() >= {cut})")
    return (f"{name}-ignores-{cut}-args", [(path, old, new.replace("{call}", verdict))])


def name_as(spelled):
    """The predicate reading the name as `spelled` (a Rust expression over `name`) before the lookup."""
    return (SHAPE, LOOKUP, f"if self.never_return.contains({spelled})))")


FREED = "stmts.push(stmt);\n            todo.extend(freed.into_iter().flat_map(Vec::into_iter).rev());"

# (name, edits, tests that run in order). Every mutant must die.
MUTANTS = [
    # The guard puts what it frees before its test; the certificate does not read it (D80).
    ("freed-before-test", [(GUARD, FREED, "stmts.extend(freed.into_iter().flatten());\n            stmts.push(stmt);")],
     [ENGINE, R2DEC]),
    ("freed-after-sequence", [(GUARD, FREED, "stmts.push(stmt);\n            todo.splice(0..0, freed.into_iter().flatten());")],
     [ENGINE, R2DEC]),
    # A name read through a cut, a trim or a digit strip.
    ("name-cut-at-dot", [name_as("name.split('.').next().unwrap_or(name)")], [R2DEC]),
    ("name-cut-at-at", [name_as("name.split('@').next().unwrap_or(name)")], [R2DEC]),
    ("name-cut-at-dollar", [name_as("name.split('$').next().unwrap_or(name)")], [R2DEC]),
    ("name-trimmed", [name_as("name.trim()")], [R2DEC]),
    ("name-cut-at-colon", [name_as("name.split(':').next().unwrap_or(name)")], [R2DEC]),
    ("name-digits-stripped", [name_as("name.trim_end_matches(|c: char| c.is_ascii_digit())")], [R2DEC]),
    ("name-after-last-colon", [name_as("name.rsplit(':').next().unwrap_or(name)")], [R2DEC]),
    ("name-by-prefix", [(SHAPE, LOOKUP, "if self.never_return.iter().any(|n| name.starts_with(n.as_str()))))")], [R2DEC]),
    ("name-lowercased", [name_as("&name.to_lowercase()")], [R2DEC]),
] + [
    # The predicate itself cut at an argument count.
    (f"predicate-ignores-{cut}-args",
     [(SHAPE, PREDICATE, f"matches!(stmt, CStmt::Expr(CExpr::Call {{ func, args, .. }})\n            if args.len() < {cut} && matches!(")],
     [R2DEC, ENGINE])
    for cut in CUTS
] + [
    # Each reader cut at an argument count.
    (*counted(reader, cut), [R2DEC, ENGINE])
    for reader, *_ in READERS for cut in CUTS
]


def failing_test(output):
    """The first failing test's name, or None when the output reports none."""
    if "test result: FAILED" not in output:
        return None
    found = re.search(r"^---- (\S+) stdout ----$", output, re.M)
    return found.group(1) if found else "?"


def run(name, edits, tests, check):
    files = {path for path, _, _ in edits}
    originals = {path: open(path).read() for path in files}
    for path, old, new in edits:
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
        for command in tests:
            if subprocess.run(f"{command} --no-run", shell=True, capture_output=True).returncode:
                return f"{name}: does not build under `{command}`", False
        for command in tests:
            done = subprocess.run(command, shell=True, capture_output=True, text=True)
            if done.returncode == 0:
                continue
            test = failing_test(done.stdout)
            if test is None:
                return f"{name}: `{command}` exits {done.returncode} with no failing test", False
            return f"{name}: killed by {test} (`{command}`)", True
    finally:
        for path in files:
            open(path, "w").write(originals[path])
    return f"{name}: survived {len(tests)} test commands", False


def main():
    args = sys.argv[1:]
    check = "--check" in args
    names = [a for a in args if not a.startswith("--")]
    if not check and subprocess.run(["git", "diff", "--quiet", "--"] + sorted({p for _, e, _ in MUTANTS for p, _, _ in e})).returncode:
        sys.exit("a file a mutant edits has changes: commit or restore them first")
    bad = 0
    for name, edits, tests in MUTANTS:
        if names and name not in names:
            continue
        line, ok = run(name, edits, tests, check)
        print(("ok   " if ok else "WRONG"), line, flush=True)
        bad += not ok
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    main()
