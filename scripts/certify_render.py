#!/usr/bin/env python3
"""Certification gate: render every named function and read the proof.

radare2 is not run. A rendering that reads a value nothing wrote is a claim
about the program the program does not make, and it is wrong on its own terms
with nothing to compare against -- which is why this gate outlived the two-sided
capture comparison it grew out of. The engine is graded against the source a
binary was compiled from, not against another route into the same renderer.

Usage:
  scripts/certify_render.py BINARY                 # every named function
  scripts/certify_render.py BINARY --at 0x1000     # one function
  scripts/certify_render.py --bins DIR --limit 24 --functions 8
"""

import argparse
import pathlib
import re
import subprocess
import sys

NOISE = re.compile(r"^\s*(INFO|WARN|ERROR|DEBUG):")
PROOF = re.compile(r"^\s*/\* r2dec proof:.*\*/\s*$")


def run(argv, timeout):
    try:
        done = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return "", "timeout"
    except OSError as error:
        return "", str(error)
    return done.stdout, ""


def clean(text):
    lines = []
    for line in text.splitlines():
        if NOISE.match(line):
            continue
        if not line.strip():
            continue
        lines.append(line.rstrip())
    return lines


def functions(r2s, binary, timeout):
    """Every defined function the binary names, as (address, name)."""
    text, error = run([str(r2s), "-q", "-c", "is", str(binary)], timeout)
    if error:
        return [], error
    found = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5 or not parts[1].startswith("0x"):
            continue
        if parts[3] != "FUNC":
            continue
        address = int(parts[1], 16)
        name = parts[4]
        if name.endswith("_header"):
            continue
        found.append((address, name))
    return found, ""


def native_render(r2s, binary, address, timeout):
    script = f"s {address:#x}; pdd"
    text, error = run([str(r2s), "-q", "-c", script, str(binary)], timeout)
    return text, error


def refused(lines):
    # An error the shell printed instead of a rendering is a refusal too: a
    # function nothing rendered must not be counted as rendered.
    return any("r2sleigh refused" in line or line.startswith("r2s:") for line in lines)


# A declaration names its variable last: `const int8_t* name;`. The name is an
# identifier, which is what keeps an array bound from being read as one. A
# statement that opens with a keyword has the same shape -- `return x;`,
# `goto L2;` -- and declares nothing: taking `return x;` for a declaration
# listed `x` once more for every return of it.
DECLARATION = re.compile(
    r"^\s*(?!(?:return|goto|else|case|do)\b)(?:const\s+)?"
    r"[A-Za-z_][\w*\s]*?\b([A-Za-z_]\w*)\s*;\s*$"
)
PROOF_REFUSED = re.compile(r"(\d+) refused")
# What the rendering says it could not spell: a value the function entered
# holding is declared and never assigned because C has no other way to name it.
# The proof line names each one; a count alone cannot say which of the
# unassigned reads it excuses, so a count with no names excuses none.
PROOF_ENTRY_HELD = re.compile(r"(\d+) held from entry \(([^)]*)\)")
# An argument slot no recovered parameter admits. It is named so a reader can
# find it, and never excused: the signature says the function was not given it.
PROOF_UNADMITTED = re.compile(r"(\d+) argument slots? read with no parameter \(([^)]*)\)")
# `==`, `!=`, `<=`, `>=` and `!` are comparisons; an assignment is a lone `=`.
ASSIGNMENT = re.compile(r"(?<![=!<>+\-*/%&|^])=(?!=)")


def assigns(line, name):
    """Whether this line writes `name`, however it spells the destination.

    A write reaches its variable through casts, indices and address-of:
    `((uint32_t*)&slot)[3] = 0` assigns `slot` as surely as `slot = 0` does.
    So the test is whether the name stands left of the assignment, not whether
    it is the whole of it. Taking its address counts too: whoever holds the
    pointer may write through it.
    """
    if re.search(r"&\s*{}\b".format(re.escape(name)), line):
        return True
    found = ASSIGNMENT.search(line)
    if not found:
        return False
    return re.search(r"\b{}\b".format(re.escape(name)), line[: found.start()]) is not None


def undefined_reads(lines):
    """Names a rendering declares, never assigns, and then reads.

    A read of a value nothing wrote is not a quality complaint: it is a claim
    about the program that the program does not make. Reported beside what the
    proof line says was refused, because the pair is the interesting part --
    an undefined read under `0 refused` says the accounting is wrong, not just
    the output.
    """
    found = []
    for line in lines:
        declared = DECLARATION.match(line)
        if not declared:
            continue
        name = declared.group(1)
        if name in ("return", "else", "struct", "union") or name in found:
            continue
        if any(assigns(other, name) for other in lines):
            continue
        # Declared, never written. A read anywhere else is a read of nothing.
        uses = sum(
            len(re.findall(r"\b{}\b".format(re.escape(name)), other)) for other in lines
        )
        if uses > 1:
            found.append(name)
    return found


def proof_names(lines, pattern):
    """The names one clause of the proof line lists, or none.

    The clause states its count beside its names. A count the names do not
    match is an accounting the line cannot stand behind, so it lists nothing.
    """
    for line in lines:
        if "r2dec proof:" in line:
            found = pattern.search(line)
            if not found:
                return set()
            names = {name.strip() for name in found.group(2).split(",") if name.strip()}
            return names if len(names) == int(found.group(1)) else set()
    return set()


def proof_entry_held(lines):
    """The values the proof line says the function entered holding."""
    return proof_names(lines, PROOF_ENTRY_HELD)


def proof_unadmitted(lines):
    """The argument slots the proof line says no parameter admits."""
    return proof_names(lines, PROOF_UNADMITTED)


def proof_refusals(lines):
    for line in lines:
        if "r2dec proof:" in line:
            found = PROOF_REFUSED.search(line)
            return int(found.group(1)) if found else None
    return None


def lint(args, binary, found):
    """Report what the rendering claims it proved and did not."""
    tally = {"rendered": 0, "refused": 0, "undefined reads": 0}
    for address, name in found[: args.functions]:
        native, error = native_render(args.r2s, binary, address, args.timeout)
        if error:
            print(f"  {name}: {error}")
            continue
        lines = clean(native)
        if refused(lines):
            tally["refused"] += 1
            continue
        tally["rendered"] += 1
        report = uncertified_reads(lines)
        if report:
            tally["undefined reads"] += 1
            print(f"  {name}: {report}")
    return tally


def uncertified_reads(lines):
    """What a rendering reads that nothing assigns and the proof does not excuse.

    A value held from entry is declared and never assigned on purpose, and the
    proof line names each one. Exactly those names are excused -- by name, not
    by count, so an excuse can never land on a different read. Everything else
    is a read of something the program never produced, and an argument slot
    the proof says no parameter admits is one of them.
    """
    held = proof_entry_held(lines)
    unadmitted = proof_unadmitted(lines)
    undefined = [name for name in undefined_reads(lines) if name not in held]
    if not undefined:
        return ""
    parts = []
    missing = [name for name in undefined if name in unadmitted]
    unwritten = [name for name in undefined if name not in unadmitted]
    if unwritten:
        parts.append("reads {} which nothing assigns".format(", ".join(unwritten)))
    if missing:
        parts.append(
            "reads {} from an argument slot no parameter admits".format(
                ", ".join(missing)
            )
        )
    parts.append("proof says {} refused".format(proof_refusals(lines)))
    return ", ".join(parts)



def main():
    here = pathlib.Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?")
    parser.add_argument("--bins")
    parser.add_argument("--r2s", default=str(here / "target/debug/r2s"))
    parser.add_argument("--at", type=lambda value: int(value, 0))
    parser.add_argument("--limit", type=int, default=5, help="binaries")
    parser.add_argument("--functions", type=int, default=20, help="per binary")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="measure whatever binary is already there",
    )
    args = parser.parse_args()

    # Build before measuring. The default binary is the debug one, which a
    # plain `cargo build --release` does not touch, so a measurement taken
    # after one reported the tree as it was several changes ago -- including a
    # whole class of undefined reads that a fix had already closed.
    if not args.no_build and args.r2s == str(here / "target/debug/r2s"):
        subprocess.run(
            ["cargo", "build", "-p", "r2s", "--features", "sleigh"],
            cwd=here,
            check=True,
        )

    if args.binary:
        binaries = [pathlib.Path(args.binary)]
    elif args.bins:
        binaries = sorted(p for p in pathlib.Path(args.bins).iterdir() if p.is_file())[
            : args.limit
        ]
    else:
        parser.error("pass a binary or --bins")

    totals = {}
    for binary in binaries:
        print(binary.name)
        found, error = functions(args.r2s, binary, args.timeout)
        if error:
            print(f"  {error}")
            continue
        if args.at is not None:
            found = [(address, name) for address, name in found if address == args.at]
            if not found:
                found = [(args.at, f"fcn.{args.at:x}")]
        for key, value in lint(args, binary, found).items():
            totals[key] = totals.get(key, 0) + value

    print()
    for key in ("rendered", "refused", "undefined reads"):
        print(f"{key:16} {totals.get(key, 0)}")
    # An uncertified rendering is a defect on its own terms.
    return 1 if totals.get("undefined reads", 0) else 0


if __name__ == "__main__":
    sys.exit(main())
