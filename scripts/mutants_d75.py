#!/usr/bin/env python3
"""D75's mutation target: each mutant of the noreturn guard and of the `never_returns` predicate's readers is applied to
the tree, the tests that should kill it run, and the file is restored (doc/adr-structure-dominator-tree.md, "the
noreturn guard").

  mutants_d75.py [--check] [NAME...]    run (or only --check that every edit applies once) the named mutants, else all

Run from the repository root with the files below unmodified. Exit 1 where a mutant lives."""

import os
import subprocess
import sys

R2DEC = "cargo test -p r2dec --lib --all-features"
ENGINE = "cargo test -p r2engine --test engine structure::"

SHAPE = "crates/r2dec/src/structure/shape.rs"
TAILS = "crates/r2dec/src/structure/tails.rs"
GUARD = "crates/r2dec/src/structure/guard.rs"

# The predicate's lookup, and a call's arguments where a reader asks for them.
LOOKUP = "if self.never_return.contains(name)))"
TWO_ARGS = "matches!(stmt, CStmt::Expr(CExpr::Call { args, .. }) if args.len() >= 2)"


def name_as(spelled):
    """The predicate reading the name as `spelled` (a Rust expression over `name`) before the lookup."""
    return (SHAPE, LOOKUP, f"if self.never_return.contains({spelled})))")


# (name, edits, tests that run in order). Every mutant must die.
MUTANTS = [
    # The guard puts what it frees before its test (B1 of the fourth review); the certificate does not read it.
    ("freed-before-test", [(GUARD, "stmts.push(stmt);\n            todo.extend(freed.into_iter().flat_map(Vec::into_iter).rev());",
                            "stmts.extend(freed.into_iter().flatten());\n            stmts.push(stmt);")], [ENGINE, R2DEC]),
    ("freed-after-sequence", [(GUARD, "stmts.push(stmt);\n            todo.extend(freed.into_iter().flat_map(Vec::into_iter).rev());",
                               "stmts.push(stmt);\n            todo.splice(0..0, freed.into_iter().flatten());")], [ENGINE, R2DEC]),
    # A name read through a cut, a trim or a digit strip (S41 to S48 of the fourth review).
    ("name-cut-at-dot", [name_as("name.split('.').next().unwrap_or(name)")], [R2DEC]),
    ("name-cut-at-at", [name_as("name.split('@').next().unwrap_or(name)")], [R2DEC]),
    ("name-trimmed", [name_as("name.trim()")], [R2DEC]),
    ("name-cut-at-colon", [name_as("name.split(':').next().unwrap_or(name)")], [R2DEC]),
    ("name-digits-stripped", [name_as("name.trim_end_matches(|c: char| c.is_ascii_digit())")], [R2DEC]),
    ("name-after-last-colon", [name_as("name.rsplit(':').next().unwrap_or(name)")], [R2DEC]),
    ("name-by-prefix", [(SHAPE, LOOKUP, "if self.never_return.iter().any(|n| name.starts_with(n.as_str()))))")], [R2DEC]),
    ("name-lowercased", [name_as("&name.to_lowercase()")], [R2DEC]),
    # A reader that ignores a call with two or more arguments (F14 to F16 of the fourth review).
    ("completes-two-args", [(TAILS, "CStmt::Expr(_) => !ev.never_returns(stmt),",
                             f"CStmt::Expr(_) => !ev.never_returns(stmt) || {TWO_ARGS},")], [R2DEC, ENGINE]),
    ("falling-ends-two-args", [(TAILS, "CStmt::Expr(_) => Some(usize::from(!ev.never_returns(stmt))),",
                                f"CStmt::Expr(_) => Some(usize::from(!ev.never_returns(stmt) || {TWO_ARGS})),")], [R2DEC, ENGINE]),
    ("arm-end-two-args", [(GUARD, "CStmt::Expr(_) => return ev.never_returns(stmt),",
                           f"CStmt::Expr(_) => return ev.never_returns(stmt) && !{TWO_ARGS},")], [R2DEC, ENGINE]),
    ("tail-run-two-args", [(TAILS, "CStmt::Expr(_) if ev.never_returns(stmt) => Some(Ended::Terminal),",
                            f"CStmt::Expr(_) if ev.never_returns(stmt) && !{TWO_ARGS} => Some(Ended::Terminal),")], [R2DEC, ENGINE]),
]


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
        killer = None
        for command in tests:
            done = subprocess.run(command, shell=True, capture_output=True, text=True)
            if done.returncode != 0:
                killer = command
                break
    finally:
        for path in files:
            open(path, "w").write(originals[path])
    if killer is None:
        return f"{name}: survived {len(tests)} test commands", False
    return f"{name}: killed by `{killer}`", True


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
