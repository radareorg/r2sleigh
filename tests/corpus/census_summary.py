#!/usr/bin/env python3
"""Summarise control_census outputs.

Prints the rendered count, the refusal classes behind the rest, and -- given a
second directory -- which functions the two runs disagree about.

usage: tests/corpus/census_summary.py <census-dir> [baseline-census-dir]
"""
import collections
import os
import re
import sys


def load(directory):
    out = {}
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".txt"):
            continue
        binary = name[:-4]
        current = certificate = refusal = None
        skip = False
        for line in open(os.path.join(directory, name), errors="replace"):
            if line.startswith("==MARK"):
                if current and not skip:
                    out[(binary, current)] = (certificate, refusal)
                current = line.split()[1]
                certificate = refusal = None
                skip = False
            elif line.startswith("control-certificate "):
                certificate = line.strip()
            elif line.startswith("/* r2sleigh refused"):
                refusal = line.strip()[:160]
            # A cold partition is a label inside a function this run already
            # decompiled under its owner's name. It is neither rendered nor
            # refused; counting it either way measures the same code twice.
            # The phrase appears in the note and in the older refusal alike.
            elif "is a cold partition of" in line:
                skip = True
            # A declared address has no body and therefore no control proof;
            # the declaration is the whole rendering.
            elif line.startswith("/* r2sleigh: "):
                certificate = "declaration ok "
        if current and not skip:
            out[(binary, current)] = (certificate, refusal)
    return out


def rendered_set(census):
    # A refusal comment can follow an ok control certificate: the control proof
    # is not the rendering. A function counts as rendered only with neither.
    return {
        key
        for key, (certificate, refusal) in census.items()
        if certificate and " ok " in certificate and not refusal
    }


def main():
    census = load(sys.argv[1])
    baseline = load(sys.argv[2]) if len(sys.argv) > 2 else {}
    rendered = rendered_set(census)
    print("functions", len(census), "rendered", len(rendered))

    classes = collections.Counter()
    for key, (certificate, refusal) in census.items():
        if key in rendered:
            continue
        match = re.search(r"refused [^:]*: ?(.*)", refusal) if refusal else None
        label = match.group(1)[:90] if match else (certificate[:90] if certificate else "no-output")
        label = re.sub(r"0x[0-9a-f]+", "0x", label)
        label = re.sub(r"\d+", "N", label)
        classes[label] += 1
    for label, count in classes.most_common(25):
        print(f"{count:4} {label}")

    if baseline:
        was = rendered_set(baseline)
        print("gained", sorted(rendered - was))
        print("lost", sorted(was - rendered))


if __name__ == "__main__":
    main()
