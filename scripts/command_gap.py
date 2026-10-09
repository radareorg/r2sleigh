#!/usr/bin/env python3
"""Measure radare2's command surface against r2s' verb table.

Three numbers feed doc/command-gap.md: radare2's help triples, r2s' verbs, and
how often radare2's own test corpus checks a command's output.
"""

import argparse
import collections
import os
import re
import sys

HELP_ARRAY = re.compile(
    r"RCoreHelpMessage\s+help_msg_(\w+)\s*=\s*\{(.*?)\n\};", re.S
)
TRIPLE = re.compile(
    r'"((?:[^"\\]|\\.)*)"\s*,\s*"((?:[^"\\]|\\.)*)"\s*,\s*"((?:[^"\\]|\\.)*)"'
)
VERB = re.compile(r"verb!\(\s*\[(.*?)\]", re.S)
BLOCK = re.compile(r"^CMDS=<<(\w+)\n(.*?)^\1\n", re.S | re.M)
INLINE = re.compile(r"^CMDS=(?!<<)(.*)$", re.M)
COMMAND = re.compile(r"^([a-zA-Z/?!][a-zA-Z0-9_/?*.+-]*)")
# These print nothing, so a block ending in one is checked on the line above.
SILENT = re.compile(r"^(q|\?e|echo|exit)\b")


def help_triples(root):
    for name in sorted(os.listdir(os.path.join(root, "libr/core"))):
        if not (name.startswith("cmd_") and name.endswith(".c")):
            continue
        path = os.path.join(root, "libr/core", name)
        with open(path, errors="replace") as handle:
            source = handle.read()
        for array in HELP_ARRAY.finditer(source):
            for command, args, text in TRIPLE.findall(array.group(2)):
                yield name, array.group(1), command, args, text


def verbs(path):
    with open(path) as handle:
        source = handle.read()
    found = set()
    for macro in VERB.finditer(source):
        found.update(re.findall(r'"([^"]+)"', macro.group(1)))
    return found


def under_test(line):
    match = COMMAND.match(line)
    return match.group(1) if match else None


def checked(lines):
    """The command whose output EXPECT checks: the last one that prints."""
    for line in reversed(lines):
        if not SILENT.match(line):
            return line
    return None


def tested(root):
    counts = collections.Counter()
    for directory, _, files in os.walk(os.path.join(root, "test/db")):
        for name in files:
            try:
                with open(os.path.join(directory, name), errors="replace") as handle:
                    text = handle.read()
            except OSError:
                continue
            runs = [body for _, body in BLOCK.findall(text)]
            commands = [
                [line.strip() for line in body.splitlines() if line.strip()]
                for body in runs
            ]
            commands += [
                [part.strip() for part in run.group(1).strip("\"'").split(";") if part.strip()]
                for run in INLINE.finditer(text)
            ]
            for lines in commands:
                last = checked(lines)
                if last and (name := under_test(last)):
                    counts[name] += 1
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--radare2", default="../radare2")
    parser.add_argument("--verbs", default="crates/r2s/src/commands.rs")
    parser.add_argument("--what", choices=["help", "verbs", "tested"], default="tested")
    options = parser.parse_args()
    if options.what == "help":
        rows = list(help_triples(options.radare2))
        for row in rows:
            print("\t".join(row))
        print(f"{len(rows)} triples", file=sys.stderr)
    elif options.what == "verbs":
        print("\n".join(sorted(verbs(options.verbs))))
    else:
        for command, count in tested(options.radare2).most_common():
            print(f"{count}\t{command}")


if __name__ == "__main__":
    main()
