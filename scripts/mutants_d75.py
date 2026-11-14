#!/usr/bin/env python3
"""D75's mutation target: each mutant of the noreturn guard and of the `never_returns` predicate's readers is applied to
the tree, the tests that should kill it run, and the file is restored (doc/adr-structure-dominator-tree.md, "the
noreturn guard"). The predicate takes the call's site alone (D384), so a mutant of it reading a call's arguments must
not build.

  mutants_d75.py [--check] [NAME...]    run (or only --check that every edit applies once) the named mutants, else all

Run from the repository root with the files below unmodified. Each test command first runs once on the unmutated tree,
and any failure there stops the script (exit 1). A mutant dies only when every test command builds and a test that
passed on that baseline fails; one that does not build, or that fails no baseline test, is WRONG. An UNBUILT mutant
dies only when the build fails naming a value out of scope (E0425). Exit 1 where a mutant is not killed."""

import os
import re
import signal
import subprocess
import sys

R2DEC = "cargo test -p r2dec --lib --all-features"
ARCH = "cargo test -p r2dec --all-features --test architecture"
ENGINE = "cargo test -p r2engine --test engine structure::"

SHAPE = "crates/r2dec/src/structure/shape.rs"
TAILS = "crates/r2dec/src/structure/tails.rs"
GUARD = "crates/r2dec/src/structure/guard.rs"
RENDER = "crates/r2dec/src/render/mod.rs"

# The predicate's lookup, over the call's site alone (D384).
LOOKUP = "site.is_some_and(|site| self.never_return.contains(site))"

# The one place a call's site is read off a statement.
EXTRACT = "CStmt::Expr(CExpr::Call { func, site, .. }) => match &**func {"
NAMED = "CExpr::External { .. } => *site,\n            _ => None,"

# Every reader of the predicate: the file, its text, and that text reading `{call}` as the predicate's verdict.
READERS = [
    ("tail-run", TAILS, "CStmt::Expr(_) if ev.never_returns(site_of(stmt)) => Some(Ended::Terminal),",
     "CStmt::Expr(_) if {call} => Some(Ended::Terminal),"),
    ("completes", TAILS, "CStmt::Expr(_) => !ev.never_returns(site_of(stmt)),", "CStmt::Expr(_) => !({call}),"),
    ("falling-ends", TAILS, "CStmt::Expr(_) => Some(usize::from(!ev.never_returns(site_of(stmt)))),",
     "CStmt::Expr(_) => Some(usize::from(!({call}))),"),
    ("arm-end", GUARD, "CStmt::Expr(_) => return ev.never_returns(site_of(stmt)),",
     "CStmt::Expr(_) => return {call},"),
    ("role", RENDER, "false => (traps(stmt) || evidence.never_returns(site_of(stmt))).into(),",
     "false => (traps(stmt) || {call}).into(),"),
]

# Argument counts a reader may cut at: two (`err(1, fmt)`), four, past the six x86-64 and eight AArch64 registers.
CUTS = (2, 4, 7, 9, 16)


def counted(reader, cut):
    """`reader` ignoring a call with `cut` or more arguments."""
    name, path, old, new = next(r for r in READERS if r[0] == reader)
    ev = "evidence" if path == RENDER else "ev"
    verdict = (f"{ev}.never_returns(site_of(stmt)) && !matches!(stmt, crate::ast::CStmt::Expr(crate::ast::CExpr::Call"
               f" {{ args, .. }}) if args.len() >= {cut})")
    return (f"{name}-ignores-{cut}-args", [(path, old, new.replace("{call}", verdict))])


# One pattern per `CExpr` form an argument may take (crates/r2dec/src/ast.rs).
FORMS = [
    ("observed", "Observed { .. }"), ("int", "IntLit(_)"), ("uint", "UIntLit(_)"), ("float", "FloatLit(..)"),
    ("string", "StringLit(_)"), ("char", "CharLit(_)"), ("var", "Var(_)"), ("external", "External { .. }"),
    ("data", "DataObject { .. }"), ("unary", "Unary { .. }"), ("binary", "Binary { .. }"), ("ternary", "Ternary { .. }"),
    ("cast", "Cast { .. }"), ("call", "Call { .. }"), ("subscript", "Subscript { .. }"), ("member", "Member { .. }"),
    ("ptr-member", "PtrMember { .. }"), ("sizeof", "Sizeof(_)"), ("sizeof-type", "SizeofType(_)"),
    ("addr-of", "AddrOf(_)"), ("deref", "Deref(_)"), ("comma", "Comma(_)"), ("paren", "Paren(_)"),
]
E = "crate::ast::CExpr"
ANY_FORM = "args.iter().any(|a| matches!(a, " + E + "::{}))"
# Argument shapes a reader may wrongly read: a register, anything not a literal, a cast of a value.
SHAPES = [
    ("var", ANY_FORM.format("Var(_)")),
    ("nonlit", f"args.iter().any(|a| !matches!(a, {E}::IntLit(_) | {E}::UIntLit(_) | {E}::StringLit(_) | {E}::Cast {{ .. }}))"),
    ("cast-nonlit", f"args.iter().any(|a| matches!(a, {E}::Cast {{ expr, .. }} if !matches!(**expr, {E}::IntLit(_) | {E}::UIntLit(_))))"),
]


def predicate_unless(condition):
    """The predicate false for a call whose `args` meet `condition`: it must not build, as no call is in scope."""
    return [(SHAPE, LOOKUP, f"!({condition}) && {LOOKUP}")]


def reader_unless(reader, condition):
    """`reader` reading a call whose `args` meet `condition` as returning."""
    _, path, old, new = next(r for r in READERS if r[0] == reader)
    ev = "evidence" if path == RENDER else "ev"
    verdict = (f"{ev}.never_returns(site_of(stmt)) && !matches!(stmt, crate::ast::CStmt::Expr({E}::Call {{ args, .. }})"
               f" if {condition})")
    return [(path, old, new.replace("{call}", verdict))]


# What an argument may be read for, past its form: a value, a symbol, a site, a nested form, the depth (round 6).
UNOB = "(match {x} {{ " + E + "::Observed {{ expr, .. }} => &**expr, e => e }})"


def inner(form, field, pattern):
    """An argument of `form` whose `field`, seen through an observation, matches `pattern`."""
    return f"matches!(a, {E}::{form} if matches!({UNOB.format(x='&**' + field)}, {E}::{pattern}))"


DEPTH = ("{ fn depth(e: &" + E + ") -> usize { use " + E + " as X; match e { "
         "X::Observed { expr, .. } | X::Cast { expr, .. } | X::Sizeof(expr) | X::AddrOf(expr) | X::Deref(expr) "
         "| X::Paren(expr) | X::Unary { operand: expr, .. } | X::Member { base: expr, .. } "
         "| X::PtrMember { base: expr, .. } => 1 + depth(expr), "
         "X::Binary { left, right, .. } | X::Subscript { base: left, index: right } => 1 + depth(left).max(depth(right)), "
         "X::Ternary { cond, then_expr, else_expr } => 1 + depth(cond).max(depth(then_expr)).max(depth(else_expr)), "
         "X::Call { args, .. } | X::Comma(args) => 1 + args.iter().map(depth).max().unwrap_or(0), "
         "_ => 0 } } depth(a) >= 3 }")
ARGUMENT = [
    ("int0", f"matches!(a, {E}::IntLit(0))"), ("intnot1", f"matches!(a, {E}::IntLit(v) if *v != 1)"),
    ("uintnot1", f"matches!(a, {E}::UIntLit(v) if *v != 1)"), ("uint0", f"matches!(a, {E}::UIntLit(0))"),
    ("cast-deref", inner("Cast { expr, .. }", "expr", "Deref(_)")),
    ("cast-binary", inner("Cast { expr, .. }", "expr", "Binary { .. }")),
    ("cast-call", inner("Cast { expr, .. }", "expr", "Call { .. }")),
    ("cast-observed", f"matches!(a, {E}::Cast {{ expr, .. }} if matches!(**expr, {E}::Observed {{ .. }}))"),
    ("cast-role-step", f"matches!(a, {E}::Cast {{ role: crate::ast::CastRole::PointerWidthStep, .. }})"),
    ("cast-not-int32", f"matches!(a, {E}::Cast {{ ty, .. }} if !matches!(ty, crate::ast::CType::Int {{ bits: 32, .. }}))"),
    ("deref-binary", inner("Deref(e)", "e", "Binary { .. }")), ("deref-cast", inner("Deref(e)", "e", "Cast { .. }")),
    ("binary-not-add", f"matches!(a, {E}::Binary {{ op, .. }} if *op != crate::ast::BinaryOp::Add)"),
    ("binary-lit-left", f"matches!(a, {E}::Binary {{ left, .. }} if !matches!({UNOB.format(x='&**left')}, {E}::Var(_)))"),
    ("string-long", f"matches!(a, {E}::StringLit(s) if s.len() > 1)"),
    ("string-percent", f"matches!(a, {E}::StringLit(s) if s.contains('%'))"),
    ("var-not-first", f"matches!(a, {E}::Var(id) if id.index() != 0)"),
    ("observed-not-var", f"matches!(a, {E}::Observed {{ expr, .. }} if !matches!(**expr, {E}::Var(_)))"),
    ("call-noargs", f"matches!(a, {E}::Call {{ args, .. }} if args.is_empty())"),
    ("call-sited", f"matches!(a, {E}::Call {{ site: Some(_), .. }})"),
    ("external-not-global", f"matches!(a, {E}::External {{ kind, .. }} if *kind != crate::symbol::ExternalKind::Global)"),
    ("depth3", DEPTH), ("char-not-c", f"matches!(a, {E}::CharLit(c) if *c != 'c')"),
    ("unary-not-neg", f"matches!(a, {E}::Unary {{ op, .. }} if *op != crate::ast::UnaryOp::Neg)"),
    ("subscript-lit", inner("Subscript { index, .. }", "index", "IntLit(_) | " + E + "::UIntLit(_)")),
    ("ternary-cond-not-var", f"matches!(a, {E}::Ternary {{ cond, .. }} if !matches!({UNOB.format(x='&**cond')}, {E}::Var(_)))"),
    ("comma-not-2", f"matches!(a, {E}::Comma(v) if v.len() != 2)"),
    ("data-not-40", f"matches!(a, {E}::DataObject {{ address, .. }} if *address != 0x40)"),
    ("addrof-not-var", f"matches!(a, {E}::AddrOf(e) if !matches!({UNOB.format(x='&**e')}, {E}::Var(_)))"),
    ("paren-not-var", f"matches!(a, {E}::Paren(e) if !matches!({UNOB.format(x='&**e')}, {E}::Var(_)))"),
]
SITED = "matches!(stmt, crate::ast::CStmt::Expr(" + E + "::Call {{ site: {}, .. }}))"
# Conditions over the whole call: any argument above, its count past the AArch64 registers, its site.
CONTENT = [(what, f"args.iter().any(|a| {cond})") for what, cond in ARGUMENT] + [
    ("args17", "args.len() >= 17"), ("stmt-sited", SITED.format("Some(_)")), ("stmt-unsited", SITED.format("None")),
]
# The readers' share: one value, one nested form, the depth, a second symbol, a site.
READ_CONTENT = ("int0", "cast-binary", "depth3", "var-not-first", "stmt-sited")

ROLE = "false => (traps(stmt) || evidence.never_returns(site_of(stmt))).into(),"

# The build a predicate mutant must fail, and the error naming a value out of the predicate's scope.
UNBUILT = ("cargo build -p r2dec --lib --all-features 2>&1", "error[E0425]")

FREED = "stmts.push(stmt);\n            todo.extend(freed.into_iter().flat_map(Vec::into_iter).rev());"

# (name, edits, tests that run in order). Every mutant must die.
MUTANTS = [
    # The guard puts what it frees before its test; the certificate does not read it (D80).
    ("freed-before-test", [(GUARD, FREED, "stmts.extend(freed.into_iter().flatten());\n            stmts.push(stmt);")],
     [ENGINE, R2DEC]),
    ("freed-after-sequence", [(GUARD, FREED, "stmts.push(stmt);\n            todo.splice(0..0, freed.into_iter().flatten());")],
     [ENGINE, R2DEC]),
    # The site read loosely: any proven site, an unsited call, a neighbouring instruction (D384 replaced the name key,
    # whose nine name-cut mutants have no text to edit).
    ("site-any-proven", [(SHAPE, LOOKUP, "site.is_some() && !self.never_return.is_empty()")], [R2DEC]),
    ("site-unsited-ends", [(SHAPE, LOOKUP, "site.is_none_or(|site| self.never_return.contains(site))")], [R2DEC]),
    ("site-neighbour",
     [(SHAPE, LOOKUP, LOOKUP.replace("contains(site))",
                                     "contains(site) || self.never_return.contains(r2ssa::InstId(site.0.saturating_sub(1))))"))],
     [R2DEC]),
    # A call through a pointer read as a named callee's site.
    ("site-of-any-callee", [(SHAPE, NAMED, "_ => *site,")], [R2DEC]),
] + [
    # The predicate cut at an argument count, reading an argument's form, the order `err(value, fmt)` passes them in,
    # or what a call passes: no call is in its scope, so none builds.
    (f"predicate-ignores-{cut}-args", predicate_unless(f"args.len() >= {cut}"), UNBUILT) for cut in CUTS
] + [
    (f"predicate-ignores-{form}-arg", predicate_unless(ANY_FORM.format(pattern)), UNBUILT) for form, pattern in FORMS
] + [
    ("predicate-ignores-var-then-string",
     predicate_unless(f"matches!(args.as_slice(), [{E}::Var(_), {E}::StringLit(_), ..])"), UNBUILT),
] + [
    (f"predicate-reads-{what}", predicate_unless(condition), UNBUILT) for what, condition in CONTENT
] + [
    # Each reader cut at an argument count, reading an argument's shape, or reading what a call passes; the
    # architecture test finds the call read in a function deciding the predicate.
    (*counted(reader, cut), [ARCH, R2DEC, ENGINE])
    for reader, *_ in READERS for cut in CUTS
] + [
    (f"{reader}-ignores-{shape}-arg", reader_unless(reader, condition), [ARCH, R2DEC, ENGINE])
    for reader, *_ in READERS for shape, condition in SHAPES
] + [
    (f"{reader}-reads-{what}", reader_unless(reader, dict(CONTENT)[what]), [ARCH, R2DEC])
    for reader, *_ in READERS for what in READ_CONTENT
] + [
    # The site read off a call only when the call's arguments allow it.
    ("site-of-reads-args",
     [(SHAPE, EXTRACT, EXTRACT.replace("{ func, site, .. })", "{ func, site, args, .. }) if args.len() < 21"))],
     [ARCH, R2DEC])
] + [
    # The role reading whether the stage selected anything, in place of the call.
    ("role-when-nothing-selected",
     [(RENDER, ROLE,
       "false => (traps(stmt) || (selections.is_empty() && evidence.never_returns(site_of(stmt)))).into(),")],
     [R2DEC, ENGINE]),
    ("role-when-anything-selected",
     [(RENDER, ROLE,
       "false => (traps(stmt) || !selections.is_empty() || evidence.never_returns(site_of(stmt))).into(),")],
     [R2DEC, ENGINE]),
]


def outcomes(output):
    """The tests the output reports passed, and those it reports failed."""
    passed = set(re.findall(r"^test (\S+) \.\.\. ok$", output, re.M))
    failed = set(re.findall(r"^test (\S+) \.\.\. FAILED$", output, re.M))
    return passed, failed


def shell(command, timeout=3600):
    """`command` run in a shell: its exit code and standard output; past `timeout` seconds its process group is killed
    and the code is 124, so a mutant that loops is WRONG and the script finishes."""
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            start_new_session=True)
    try:
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        return 124, proc.communicate()[0]
    return proc.returncode, out


def baseline(commands, sh):
    """The tests each command passes on the unmutated tree; None, with the reason, if any command fails there."""
    passed = {}
    for command in commands:
        code, out = sh(command)
        ok, failed = outcomes(out)
        if code or failed:
            return None, f"`{command}` fails on the unmutated tree (exit {code}, failing {sorted(failed)})"
        passed[command] = ok
    return passed, None


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
        if tests == UNBUILT:
            return refused(name, sh)
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


def refused(name, sh):
    """An UNBUILT mutant dies when its build fails naming a value out of scope."""
    code, out = sh(UNBUILT[0])
    if code and UNBUILT[1] in out:
        return f"{name}: does not build ({UNBUILT[1]}), the predicate's type kills it", True
    return f"{name}: `{UNBUILT[0]}` exits {code} without {UNBUILT[1]}", False


def commands(tests):
    """The commands a mutant's baseline runs."""
    return [UNBUILT[0]] if tests == UNBUILT else tests


def main(args, sh=shell):
    check = "--check" in args
    names = [a for a in args if not a.startswith("--")]
    chosen = [m for m in MUTANTS if not names or m[0] in names]
    passed = {}
    if not check:
        if sh("git diff --quiet -- " + " ".join(sorted({p for _, e, _ in MUTANTS for p, _, _ in e})))[0]:
            return "a file a mutant edits has changes: commit or restore them first"
        passed, reason = baseline(sorted({c for _, _, tests in chosen for c in commands(tests)}), sh)
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
