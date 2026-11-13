#!/usr/bin/env python3
"""S31a's mutation target: one mutant per way into a function the closed world reads (doc/adr-result-side.md,
"The closed world"), each dropping that way from `Escapes` or `only_called`, and one that lets a `CallBoundary`
reach a closed seal (the no-cycle test, section 5). Each is applied, the tests that should kill it run, and the
file is restored.

  mutants_s31a.py [--check] [NAME...]    run (or only --check that every edit applies once) the named mutants, else all

Run from the repository root with the files below unmodified; the rules are mutants_d213.py's."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mutants_d75 import baseline, shell  # noqa: E402
from mutants_d213 import run  # noqa: E402

WAYS = "cargo test -p r2engine --test engine call_boundary::every_way_in"
COUNT = "cargo test -p r2engine --lib program::reads"  # the predicates no fixture isolates
CYCLE = "cargo test -p r2engine --test engine call_boundary::a_call_boundary_reaches"

READS = "crates/r2engine/src/program/reads.rs"
INDEX = "crates/r2engine/src/query/references.rs"
FATES = "crates/r2engine/src/program/fates.rs"
RECOVER = "crates/r2ssa/src/recover_interface.rs"

MUTANTS = [
    ("an-export-is-no-way-in", [(READS, ".filter(|symbol| exported(container.format, symbol))", ".filter(|_| false)")],
     [WAYS]),
    ("an-entry-is-no-way-in", [(READS, "None => escaped.push(entry.vaddr),", "None => {}")], [WAYS]),
    ("a-non-call-reference-is-no-way-in", [(READS, "if fact.role != Role::Call && !looping && !slot {",
                                            "if fact.role != Role::Call && !looping && !slot && false {")], [WAYS]),
    # Below 4 GiB a 4-byte window holds every 8-byte word's entry, so the 8-byte width is read above it.
    ("an-8-byte-word-is-no-way-in", [(READS, "64 => &[8, 4],", "64 => &[4],")], [COUNT]),
    ("a-4-byte-word-is-no-way-in", [(READS, "64 => &[8, 4],", "64 => &[8],")], [WAYS]),
    ("a-thumb-bit-hides-a-way-in", [(READS, "for value in [word, word & !1] {", "for value in [word] {")], [WAYS]),
    ("a-relative-loader-write-is-no-way-in", [(INDEX, "Some(value) => value,", "Some(_) => continue,")], [WAYS]),
    ("a-resolver-write-is-no-way-in", [(INDEX, "(_, WriteKind::Resolver(resolver)) => *resolver,",
                                        "(_, WriteKind::Resolver(_)) => continue,")], [WAYS]),
    ("an-unknown-write-is-no-way-in", [(READS, "if let Some(at) = index.coverage.unstated.first() {",
                                        "if let Some(at) = index.coverage.unstated.first().filter(|_| false) {")],
     [WAYS]),
    ("an-unread-body-is-no-way-in", [(READS, "if !index.coverage.unread.is_empty() {", "if false {")], [WAYS]),
    ("unaccounted-code-is-no-way-in", [(READS, "if let Some(at) = unaccounted_code(db, &survey, &mut escaped) {",
                                        "if let Some(at) = unaccounted_code(db, &survey, &mut escaped).filter(|_| false) {")],
     [WAYS]),
    ("any-language-is-closed", [(READS, "    if !matches!(\n        language,", "    if false && !matches!(\n        language,")],
     [WAYS]),
    ("a-call-count-one-short-is-every-call", [(READS, "usize::try_from(calls).is_ok_and(|calls| calls == claimed)",
                                               "usize::try_from(calls).is_ok_and(|calls| calls + 1 >= claimed)")],
     [COUNT]),
    # Default-deny: a decided void never overrules a lane the seal's walk finds written (S36).
    ("a-closed-void-overrules-a-written-lane", [(RECOVER, "Some(r2source::SourceClosedResult::Void) if unheld.is_some() => {",
                                                 "Some(r2source::SourceClosedResult::Void) if false => {")],
     ["cargo test -p r2engine --test engine call_boundary::a_written_x87"]),
    # A decision that reads a closed seal: the database's cycle the ADR traced none of.
    ("a-boundary-reads-a-closed-seal", [(FATES, "                let forwarding = (*db.get::<ComponentForwarding>(&entry).ok()?).clone()?;",
                                         "                let _ = db.get::<super::resolved::Resolved>(&((entry, view.thumb_at(entry)), super::resolved::Demand::Arity));\n                let forwarding = (*db.get::<ComponentForwarding>(&entry).ok()?).clone()?;")],
     [CYCLE]),
]


def main(args, sh=shell):
    check = "--check" in args
    names = [a for a in args if not a.startswith("--")]
    chosen = [m for m in MUTANTS if not names or m[0] in names]
    passed = {}
    if not check:
        if sh("git diff --quiet -- " + " ".join(sorted({p for _, e, _ in MUTANTS for p, _, _ in e})))[0]:
            return "a file a mutant edits has changes: commit or restore them first"
        passed, reason = baseline(sorted({c for _, _, tests in chosen for c in tests}), sh)
        if passed is None:
            return reason
    bad = 0
    for name, edits, tests in chosen:
        line, ok = run(name, edits, tests, check, passed, sh)
        print(("ok   " if ok else "WRONG"), line, flush=True)
        bad += not ok
    return 1 if bad else 0


if __name__ == "__main__":
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    sys.exit(main(sys.argv[1:]))
