#!/usr/bin/env python3
"""D213's mutation target: each mutant of the closed world's result decision (r2engine `program/fates.rs`), the
carrier fact it reads (r2ssa `integer_undefined`), the padding the every-way-in check accepts and the call
boundary's byte liveness is applied to the tree, the tests that should kill it run, and the file is restored
(doc/adr-call-boundary.md, "S7 as built").

  mutants_d213.py [--check] [NAME...]    run (or only --check that every edit applies once) the named mutants, else all

Run from the repository root with the files below unmodified. Each test command first runs once on the unmutated
tree, and any failure there stops the script (exit 1). A mutant dies only when every test command builds and a test
that passed on that baseline fails; one that does not build, or that fails no baseline test, is WRONG. Exit 1 where
a mutant is not killed."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mutants_d75 import baseline, outcomes, shell  # noqa: E402

BOUNDARY = "cargo test -p r2engine --test engine call_boundary"
READS = "cargo test -p r2engine --test engine result_reads"
UNIT = "cargo test -p r2engine --lib program::fates"
SITES = "cargo test -p r2ssa --lib site_boundary"

FATES = "crates/r2engine/src/program/fates.rs"
ESCAPES = "crates/r2engine/src/program/reads.rs"
RECOVER = "crates/r2ssa/src/recover_interface.rs"
LIVENESS = "crates/r2ssa/src/site_boundary.rs"

EXEMPT = "&& (at == usize::from(LaneId::INTEGER.0) || at == usize::from(LaneId::SECOND.0)))"

# (name, edits, tests that run in order). Every mutant must die.
MUTANTS = [
    # Which lanes a void needs dead at every call.
    ("integer-never-exempt", [(FATES, "let undefined = carriers.is_some_and(|carriers| carriers.integer_undefined);",
                               "let undefined = false;")], [BOUNDARY]),
    ("second-never-exempt", [(FATES, EXEMPT, "&& at == usize::from(LaneId::INTEGER.0))")], [BOUNDARY]),
    ("integer-only-exempt", [(FATES, EXEMPT, "&& at == usize::from(LaneId::SECOND.0))")], [BOUNDARY]),
    ("an-integer-read-counts-though-undefined", [(FATES, "let integer_read = integer.read && !undefined;",
                                                  "let integer_read = integer.read;")], [BOUNDARY]),
    ("unheld-lanes-must-die", [(FATES, "lanes[at].held\n            && !(undefined", "true\n            && !(undefined")],
     [BOUNDARY, READS]),
    # Whether the calls are every way in.
    ("every-way-in-assumed", [(FATES, "let mut answer = !unread && super::reads::only_called(db, callee, *calls);",
                               "let mut answer = true;")], [BOUNDARY, READS]),
    ("forwarders-assumed", [(FATES, "for caller in forwarders.iter() {", "for caller in forwarders.iter().take(0) {")],
     [READS]),
    ("a-dead-forwarder-is-unknown", [(FATES, "lane if lane.dead => Forwarded::DeadIfEveryWayIn,",
                                      "lane if lane.dead => Forwarded::Fate(LaneFate::Unknown),")], [BOUNDARY]),
    ("nothing-called-is-never-decided", [(FATES, "if (*calls > 0 || handed_back) && all_dead() {",
                                          "if *calls > 0 && all_dead() {")], [BOUNDARY]),
    ("a-written-result-is-void", [(FATES, "true => SourceClosedResult::Void,\n                    false => SourceClosedResult::Unread,",
                                   "true | false => SourceClosedResult::Void,")], [BOUNDARY]),
    # The fact r2ssa states.
    ("integer-undefined-never-stated", [(RECOVER, "                float: Some(float),\n                second: None,\n                integer_undefined: true,",
                                         "                float: Some(float),\n                second: None,\n                integer_undefined: false,")],
     [BOUNDARY]),
    # The padding no way in hides behind.
    ("hlt-is-code", [(ESCAPES, "|| (!transfer.call && transfer.target.offset == address))", ")")], [BOUNDARY]),
    ("a-multi-byte-nop-is-code", [(ESCAPES, "lifted.ops.iter().all(none)", "lifted.ops.is_empty()")], [BOUNDARY]),
    # The disputes the authority order leaves.
    ("a-dispute-ignores-the-overwrite", [(FATES, ".filter(|lane| lanes[usize::from(lane.0)].read && overwritten(*lane))",
                                          ".filter(|lane| lanes[usize::from(lane.0)].read)")], [UNIT]),
    ("no-dispute", [(FATES, ".filter(|lane| lanes[usize::from(lane.0)].read && overwritten(*lane))",
                     ".filter(|_| false)")], [UNIT]),
    ("the-body-outranks-the-declaration", [(FATES, "true => Authority::Declared,\n        false => Authority::Body,",
                                            "true => Authority::Body,\n        false => Authority::Declared,")], [UNIT]),
    # The byte liveness after a call.
    ("call-takes-ignored", [(LIVENESS, "merge(&mut live.open, call.takes.0);", "let _ = call.takes.0;")], [SITES, BOUNDARY]),
    ("return-hands-nothing-back", [(LIVENESS, "merge(&mut live.returned, self.lanes.every());",
                                    "let _ = self.lanes.every();")], [SITES, READS]),
    ("unstated-reads-leave-the-lanes-closed", [(LIVENESS, "if operation.reads_unstated() {\n            merge(&mut live.open, self.lanes.every());\n        }", "")],
     [SITES]),
]


def run(name, edits, tests, check, passed, sh):
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
            if sh(f"{command} --no-run")[0]:
                return f"{name}: does not build under `{command}`", False
        for command in tests:
            code, out = sh(command)
            killers = sorted(outcomes(out)[1] & passed[command])
            if killers:
                return f"{name}: killed by {killers[0]} (`{command}`)", True
            if code:
                return f"{name}: `{command}` exits {code} with no baseline test failing", False
    finally:
        for path in files:
            open(path, "w").write(originals[path])
    return f"{name}: survived {len(tests)} test commands", False


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
