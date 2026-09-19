#!/usr/bin/env python3
"""Differential harness: one function, two captures, the same renderer.

`scripts/diff_r2.py` grades the decoder against radare2. Nothing graded the
capture, so whether the native route loses facts the plugin's capture carries
was a matter of opinion. This answers it: the same function is rendered from
radare2's capture through the plugin (`pd:s`) and from the engine's own capture
through `r2s pdd`, and the two renderings are diffed.

Both sides run the same decompiler. A difference is therefore a difference in
what the capture carried, which is exactly the question.

Usage:
  scripts/diff_capture.py BINARY                 # every named function
  scripts/diff_capture.py BINARY --at 0x1000     # one function
  scripts/diff_capture.py --bins DIR --limit 5
  scripts/diff_capture.py BINARY --verbose
"""

import argparse
import difflib
import pathlib
import re
import subprocess
import sys

NOISE = re.compile(r"^\s*(INFO|WARN|ERROR|DEBUG):")
# radare2 flags a function `sym.name` and spells that `sym_name` in C, where the
# engine uses the symbol's own name. The body is what is being compared.
# radare2 flags a function `sym.name` and the renderer spells that `sym_name`,
# where the engine uses the symbol's own name. Which name a function has is not
# what this harness is asking about.
FLAGGED = re.compile(r"\bsym[._]")
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


def clean(text, keep_proof):
    lines = []
    for line in text.splitlines():
        if NOISE.match(line):
            continue
        if not keep_proof and PROOF.match(line):
            continue
        if not line.strip():
            continue
        lines.append(line.rstrip())
    return lines


def spellings(name):
    """Every way the two sides spell one function's name."""
    bare = name.lstrip("_")
    return sorted(
        {
            name,
            bare,
            f"sym_{name}",
            f"sym_{bare}",
            f"sym.{name}",
            f"sym.{bare}",
        },
        key=len,
        reverse=True,
    )


def rendered(lines, name):
    """Strip the names the two sides legitimately spell differently."""
    out = []
    for line in lines:
        for spelling in spellings(name):
            line = line.replace(spelling, "FN")
        out.append(FLAGGED.sub("", line))
    return out


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


def plugin_render(r2, binary, address, timeout):
    script = f"aaa; s {address:#x}; pd:s"
    text, error = run([str(r2), "-q", "-c", script, str(binary)], timeout)
    return text, error


def native_render(r2s, binary, address, timeout):
    script = f"s {address:#x}; pdd"
    text, error = run([str(r2s), "-q", "-c", script, str(binary)], timeout)
    return text, error


def refused(lines):
    return any("r2sleigh refused" in line for line in lines)


DECLARATION = re.compile(r"^\s*(?:const\s+)?[A-Za-z_][\w*\s]*?\b(\w+)\s*;\s*$")
ASSIGNED = re.compile(r"\b{}\s*(?:=[^=]|\+\+|--)")
PROOF_REFUSED = re.compile(r"(\d+) refused")


def undefined_reads(lines):
    """Names a rendering declares, never assigns, and then reads.

    A read of a value nothing wrote is not a quality complaint: it is a claim
    about the program that the program does not make. Reported beside what the
    proof line says was refused, because the pair is the interesting part --
    an undefined read under `0 refused` says the accounting is wrong, not just
    the output.
    """
    body = "\n".join(lines)
    found = []
    for line in lines:
        declared = DECLARATION.match(line)
        if not declared:
            continue
        name = declared.group(1)
        if name in ("return", "else", "struct", "union"):
            continue
        if re.search(ASSIGNED.pattern.format(re.escape(name)), body):
            continue
        # Declared, never written. Read anywhere else is a read of nothing.
        uses = len(re.findall(r"\b{}\b".format(re.escape(name)), body))
        if uses > 1:
            found.append(name)
    return found


def proof_refusals(lines):
    for line in lines:
        if "r2dec proof:" in line:
            found = PROOF_REFUSED.search(line)
            return int(found.group(1)) if found else None
    return None


def compare(args, binary):
    found, error = functions(args.r2s, binary, args.timeout)
    if error:
        print(f"{binary.name}: {error}")
        return {}
    if args.at is not None:
        found = [(address, name) for address, name in found if address == args.at]
        if not found:
            found = [(args.at, f"fcn.{args.at:x}")]

    tally = {
        "same": 0,
        "differ": 0,
        "native refused": 0,
        "plugin refused": 0,
        "both refused": 0,
        "undefined reads": 0,
    }
    for address, name in found[: args.functions]:
        plugin, plugin_error = plugin_render(args.r2, binary, address, args.timeout)
        native, native_error = native_render(args.r2s, binary, address, args.timeout)
        if plugin_error or native_error:
            print(f"  {name}: {plugin_error or native_error}")
            continue

        left = rendered(clean(plugin, args.proof), name)
        right = rendered(clean(native, args.proof), name)

        # A read of a value nothing assigned, under a proof line that refused
        # nothing, is a certification defect and outranks any difference.
        undefined = undefined_reads(clean(native, True))
        if undefined:
            tally["undefined reads"] = tally.get("undefined reads", 0) + 1
            print(
                "  {}: reads {} which nothing assigns, proof says {} refused".format(
                    name,
                    ", ".join(undefined),
                    proof_refusals(clean(native, True)),
                )
            )
        if refused(left) and refused(right):
            tally["both refused"] += 1
            continue
        if refused(right):
            tally["native refused"] += 1
            print(f"  {name}: native refused, plugin rendered")
            if args.verbose:
                print("\n".join(f"      {line}" for line in right))
            continue
        if refused(left):
            tally["plugin refused"] += 1
            continue
        if left == right:
            tally["same"] += 1
            continue

        tally["differ"] += 1
        print(f"  {name}: {len(left)} lines vs {len(right)}")
        if args.verbose:
            for line in difflib.unified_diff(left, right, "plugin", "native", lineterm="", n=1):
                print(f"      {line}")
    return tally


def main():
    here = pathlib.Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?")
    parser.add_argument("--bins")
    parser.add_argument("--r2", default="radare2")
    parser.add_argument("--r2s", default=str(here / "target/debug/r2s"))
    parser.add_argument("--at", type=lambda value: int(value, 0))
    parser.add_argument("--limit", type=int, default=5, help="binaries")
    parser.add_argument("--functions", type=int, default=20, help="per binary")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--proof", action="store_true", help="compare proof lines too")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

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
        for key, value in compare(args, binary).items():
            totals[key] = totals.get(key, 0) + value

    print()
    for key in (
        "same",
        "differ",
        "native refused",
        "plugin refused",
        "both refused",
        "undefined reads",
    ):
        print(f"{key:16} {totals.get(key, 0)}")
    return 1 if totals.get("differ", 0) or totals.get("native refused", 0) else 0



if __name__ == "__main__":
    sys.exit(main())
