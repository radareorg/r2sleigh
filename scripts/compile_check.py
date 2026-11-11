#!/usr/bin/env python3
"""Conversion gate: compile every rendering as a C compiler that enforces C's conversion rules reads it.

gcc 13 only warns where an integer is passed to a pointer parameter, and clang 15 and gcc 14 reject
the unit; a rendering that needs the lenient compiler is ill typed on its own terms. The unit is the
`code` field of `pddj` (helpers included), checked by clang with `-fsyntax-only`, no error limit and
the conversion, undeclared-callee and return-mismatch diagnostics as errors; the flags are clang's
and gcc refuses them. `-w` is not used: it hides a warning that `-Werror=` promotes, as
`incompatible-pointer-types`.
The gate reads every error line and fails a unit when any of them is one of those, wherever it
stands; other errors are counted and reported and do not fail it. A compiler that does not bind every
promoted group (clang 18 has no `return-mismatch`, and `-Wno-everything` hides the unknown option)
grades nothing: the gate compiles one probe per group first and exits 2 when one is accepted.

Usage:
  scripts/compile_check.py BINARY
  scripts/compile_check.py --bins DIR --limit 5 --functions 200
"""

import argparse
import itertools
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

import certify_render as gate

FLAGS = [
    "-fsyntax-only",
    "-std=gnu11",
    "-Wno-everything",
    "-Werror=int-conversion",
    "-Werror=incompatible-pointer-types",
    "-Werror=incompatible-function-pointer-types",
    "-Werror=implicit-function-declaration",
    "-Werror=return-mismatch",
    "-ferror-limit=0",
]
CONSTRAINT = re.compile(
    r"\[(?:-Werror[=,])?(?:-W)?(int-conversion|incompatible-pointer-types(?:-discards-qualifiers)?"
    r"|incompatible-function-pointer-types|implicit-function-declaration|return-mismatch)\]"
)
# Units a compiler binding the named group rejects under it, one diagnostic each.
PROBES = [
    ("int-conversion", "int *f(long n) { return n; }\n"),
    ("incompatible-pointer-types", "int *f(long *p) { return p; }\n"),
    ("incompatible-pointer-types-discards-qualifiers", "char *f(const char *c) { return c; }\n"),
    ("incompatible-function-pointer-types", "void g(int);\nvoid (*f(void))(long) { return g; }\n"),
    ("implicit-function-declaration", "int f(void) { return undeclared(1); }\n"),
    ("return-mismatch", "void f(int x) { return x; }\n"),
    ("return-mismatch", "int g(void) { return; }\n"),
]
SEPARATOR = "==r2s-compile=="
CHUNK = 100


def parse_batch(text):
    """The `code` of each function in a batch of `pddj` answers, by position; None where refused.

    An answer that is not JSON (a refusal printed as an error) has no code.
    """
    answers = []
    for part in text.split(SEPARATOR)[1:]:
        body = part.strip()
        try:
            # raw_decode stops at the JSON value's end, so stderr after it cannot hide an answer.
            answer = json.JSONDecoder().raw_decode(body, body.index("{"))[0] if "{" in body else None
        except json.JSONDecodeError:
            answer = None
        code = answer.get("code") if isinstance(answer, dict) and not answer.get("refused") else None
        answers.append(code or None)
    return answers


def diagnostics(stderr):
    """Each error line as (kind, line): the warning that names the constraint, else `other`."""
    found = []
    for line in stderr.splitlines():
        if "error:" in line:
            match = CONSTRAINT.search(line)
            found.append((match.group(1) if match else "other", line.strip()))
    return found


def classify(stderr):
    """`conversion` where any error is a constraint the gate checks, else `other`; None if clean.

    The line is the first of that kind.
    """
    found = diagnostics(stderr)
    for kind, line in found:
        if kind != "other":
            return "conversion", line
    return ("other", found[0][1]) if found else (None, "")


def compile_unit(cc, code, directory):
    """The compiler's stderr for `code`; empty if it accepts the unit.

    A failure that names no error is given one, so that it is never read as clean.
    """
    path = pathlib.Path(directory) / "unit.c"
    path.write_text(code)
    done = subprocess.run([cc, *FLAGS, str(path)], capture_output=True, text=True, check=False)
    if not done.returncode:
        return ""
    if "error:" in done.stderr:
        return done.stderr
    return f"{done.stderr}{cc}: error: exited {done.returncode} and named no error\n"


def rejects(cc, code, directory):
    """How the compiler reads `code`: (None, "") if it accepts it, else (kind, first error of that kind)."""
    return classify(compile_unit(cc, code, directory))


def unbound(cc):
    """The promoted groups `cc` accepts a probe of; empty if it binds them all."""
    missing = []
    with tempfile.TemporaryDirectory() as directory:
        for kind, code in PROBES:
            labels = [label for label, _ in diagnostics(compile_unit(cc, code, directory))]
            if labels != [kind] and kind not in missing:
                missing.append(kind)
    return missing


def check_chunk(args, binary, addresses):
    script = "aa; " + "; ".join(f"?e {SEPARATOR}; pddj @ {a:#x}" for a in addresses)
    text, error = gate.run([args.r2s, "-q", "-c", script, str(binary)], args.timeout * len(addresses))
    if error:
        return [("unanswered", f"{error}", [])]
    results = []
    with tempfile.TemporaryDirectory() as directory:
        for code in parse_batch(text):
            if code is None:
                results.append(("refused", "", []))
            else:
                stderr = compile_unit(args.cc, code, directory)
                kind, first = classify(stderr)
                results.append((kind or "compiled", first, diagnostics(stderr)))
    return results


def main():
    here = pathlib.Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?")
    parser.add_argument("--bins")
    parser.add_argument("--r2s", default=str(here / "target/debug/r2s"))
    parser.add_argument("--cc", default="clang")
    parser.add_argument("--limit", type=int, default=5, help="binaries")
    parser.add_argument("--functions", type=int, default=None, help="per binary (default all)")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    if shutil.which(args.cc) is None:
        print(f"no C compiler `{args.cc}`: the gate graded nothing")
        return 2
    missing = unbound(args.cc)
    if missing:
        print(f"`{args.cc}` does not reject under {', '.join(missing)}: the gate graded nothing")
        return 2
    if args.binary:
        binaries = [pathlib.Path(args.binary)]
    elif args.bins:
        files = sorted(p for p in pathlib.Path(args.bins).iterdir() if p.is_file())
        binaries = list(itertools.islice((p for p in files if gate.opens(args.r2s, p)), args.limit))
    else:
        parser.error("pass a binary or --bins")

    totals, seen, others = {}, {}, {}
    for binary in binaries:
        found, _, error = gate.functions(args.r2s, binary, args.timeout)
        if error:
            totals["unlisted"] = totals.get("unlisted", 0) + 1
            print(f"{binary.name}: {error}")
            continue
        chosen = found if args.functions is None else found[: args.functions]
        addresses = [address for address, _ in chosen]
        chunks = [addresses[i : i + CHUNK] for i in range(0, len(addresses), CHUNK)]
        with ThreadPoolExecutor(args.jobs) as pool:
            for results in pool.map(lambda chunk: check_chunk(args, binary, chunk), chunks):
                for kind, _, diagnosed in results:
                    totals[kind] = totals.get(kind, 0) + 1
                    for label, line in diagnosed:
                        seen[label] = seen.get(label, 0) + 1
                        if label != "other":
                            print(f"{binary.name}: {line}")
                        else:
                            text = line.split("error:", 1)[1].strip()
                            others[text] = others.get(text, 0) + 1
        print(binary.name, {k: v for k, v in totals.items()})
    print()
    for key in ("compiled", "refused", "conversion", "other", "unanswered", "unlisted"):
        print(f"{key:12} {totals.get(key, 0)}")
    print("diagnostics  " + ", ".join(f"{label} {count}" for label, count in sorted(seen.items())))
    for text, count in sorted(others.items(), key=lambda item: -item[1])[:5]:
        print(f"  {count:4} {text[:140]}")
    if not totals.get("compiled"):
        print("nothing compiled: the gate graded nothing")
        return 1
    return 1 if any(totals.get(key, 0) for key in ("conversion", "unanswered", "unlisted")) else 0


if __name__ == "__main__":
    sys.exit(main())
