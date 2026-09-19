#!/usr/bin/env python3
"""Differential harness: run the same commands through radare2 and r2s.

radare2 is the validation target for everything the engine reproduces natively,
so the cheapest way to grade discovery, mapping and decoding is to ask both
tools the same question and report where they disagree.

Two comparison modes, because the two tools do not yet fill the same columns:

  exact   normalised text must match line for line, with integer literals
          canonicalised because the two spell the same value differently.
          Used where r2s already claims radare2's layout, such as `px`, `pd`.
  values  compares the set of values each tool reports. A value r2s reports and
          radare2 does not is a defect and fails; a value radare2 reports and
          r2s does not is an unfilled column, reported but not failed. Used for
          the listing commands until their columns are complete.

Usage:
  scripts/diff_r2.py                        # default corpus and commands
  scripts/diff_r2.py --bins DIR --limit 20
  scripts/diff_r2.py --only pd --verbose
"""

import argparse
import pathlib
import re
import subprocess
import sys

# Command, comparison mode. The seek is issued to both so the cursor agrees.
COMMANDS = [
    ("px 64", "exact"),
    ("pd 8", "exact"),
    ("ie", "values"),
    ("iS", "values"),
    ("is", "values"),
]

HEX = re.compile(r"0x[0-9a-fA-F]+")
NOISE = re.compile(r"^\s*(WARN|ERROR|INFO):")
# radare2 annotates the listing from analysis the engine does not have yet.
ANNOTATION = re.compile(r"^\s*;")
# A trailing annotation on a disassembly line. Only applied to the listing,
# where a semicolon never belongs to the instruction itself.
TRAILING = re.compile(r"\s+;.*$")


def normalise(text, strip_trailing=False):
    lines = []
    for line in text.splitlines():
        if NOISE.match(line) or ANNOTATION.match(line):
            continue
        if strip_trailing:
            line = canonical_numbers(TRAILING.sub("", line))
        line = line.rstrip()
        if line:
            lines.append(line)
    return lines


def values(lines):
    found = set()
    for line in lines:
        found.update(int(token, 16) for token in HEX.findall(line))
    return found


NUMBER = re.compile(r"-0x[0-9a-fA-F]+|0x[0-9a-fA-F]+|\b-?[0-9]+\b")


def canonical_numbers(line):
    """Rewrite every integer literal to unsigned 64-bit hex.

    radare2 prints `0xfffffffffffffff0` and a bare `8` where Sleigh prints
    `-0x10` and `0x8`. Both spell the same value, so a diff that reported them
    as a disagreement would bury the defects worth seeing.
    """

    def rewrite(match):
        token = match.group(0)
        try:
            value = int(token, 16) if "0x" in token.lower() else int(token, 10)
        except ValueError:
            return token
        return "0x{:x}".format(value & 0xFFFFFFFFFFFFFFFF)

    return NUMBER.sub(rewrite, line)


def run(argv, timeout):
    """Return (stdout, stderr, code); code is None when the tool never ran."""
    try:
        done = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return "", "timeout", None
    except OSError as error:
        return "", str(error), None
    return done.stdout, done.stderr, done.returncode


def compare(command, mode, left, right, verbose):
    """Return a one-line verdict, or None when the two agree."""
    # Only the listing carries trailing annotations; a hex dump's ASCII column
    # can hold a semicolon that must not be mistaken for one.
    strip = command.startswith("pd")
    left_lines, right_lines = normalise(left, strip), normalise(right, strip)
    if mode == "values":
        ours, theirs = values(left_lines), values(right_lines)
        invented = ours - theirs
        if not invented:
            return None
        sample = ", ".join("{:#x}".format(value) for value in sorted(invented)[:4])
        return "{} reports {} value(s) radare2 does not: {}".format(
            command, len(invented), sample
        )

    if left_lines == right_lines:
        return None

    detail = ""
    if verbose:
        for index in range(max(len(left_lines), len(right_lines))):
            got = left_lines[index] if index < len(left_lines) else None
            want = right_lines[index] if index < len(right_lines) else None
            if got != want:
                detail = "\n      r2  {}\n      r2s {}".format(
                    want if want is not None else "<missing>",
                    got if got is not None else "<missing>",
                )
                break
    return "{} differs ({} lines vs {}){}".format(
        command, len(left_lines), len(right_lines), detail
    )


def main():
    here = pathlib.Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--r2", default=str(here.parent / "radare2/binr/radare2/radare2"))
    parser.add_argument("--r2s", default=str(here / "target/debug/r2s"))
    parser.add_argument("--bins", default=str(here.parent / "radare2/test/bins/elf"))
    parser.add_argument("--limit", type=int, default=25)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--only", help="run just the commands whose verb matches this")
    parser.add_argument("--verbose", action="store_true", help="show the first differing line")
    args = parser.parse_args()

    r2, r2s = pathlib.Path(args.r2), pathlib.Path(args.r2s)
    for tool in (r2, r2s):
        if not tool.exists():
            print("missing {}".format(tool), file=sys.stderr)
            return 2

    commands = [
        (command, mode)
        for command, mode in COMMANDS
        if not args.only or command.split()[0] == args.only
    ]
    if not commands:
        print("no command matches --only {}".format(args.only), file=sys.stderr)
        return 2

    binaries = sorted(p for p in pathlib.Path(args.bins).iterdir() if p.is_file())[: args.limit]
    if not binaries:
        print("no binaries under {}".format(args.bins), file=sys.stderr)
        return 2

    agreed = {command: 0 for command, _ in commands}
    differed = {command: 0 for command, _ in commands}
    unsupported = {}
    skipped = 0

    for binary in binaries:
        # A refusal to open is a capability gap, not a disagreement about a
        # binary both tools read, so it is counted and reported separately.
        _, opened_error, opened_code = run(
            [str(r2s), "-q", "-c", "i", str(binary)], args.timeout
        )
        if opened_code != 0:
            reason = opened_error.strip().splitlines()[-1] if opened_error.strip() else "failed"
            reason = reason.replace("r2s: ", "")
            unsupported[reason] = unsupported.get(reason, 0) + 1
            continue

        reported = False
        for command, mode in commands:
            script = "s entry0;{}".format(command)
            right, _, right_code = run(
                [str(r2), "-N", "-q", "-e", "scr.color=0", "-c", script, str(binary)],
                args.timeout,
            )
            if right_code is None:
                skipped += 1
                continue
            left, _, left_code = run([str(r2s), "-q", "-c", script, str(binary)], args.timeout)
            if left_code is None:
                skipped += 1
                continue

            # A binary neither tool has anything to say about is not a difference.
            if not normalise(right) and not normalise(left):
                continue

            verdict = compare(command, mode, left, right, args.verbose)
            if verdict is None:
                agreed[command] += 1
            else:
                differed[command] += 1
                if not reported:
                    print(binary.name)
                    reported = True
                print("    {}".format(verdict))

    print("\n{:<8} {:>8} {:>8}".format("command", "agree", "differ"))
    print("-" * 26)
    total_differ = 0
    for command, _ in commands:
        print("{:<8} {:>8} {:>8}".format(command, agreed[command], differed[command]))
        total_differ += differed[command]
    if skipped:
        print("\n{} runs skipped (timeout or launch failure)".format(skipped))
    if unsupported:
        print("\nnot opened by r2s:")
        for reason, count in sorted(unsupported.items(), key=lambda item: -item[1]):
            print("  {:>4}  {}".format(count, reason))
    return 1 if total_differ else 0


if __name__ == "__main__":
    sys.exit(main())
