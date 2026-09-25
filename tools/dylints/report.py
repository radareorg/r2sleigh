#!/usr/bin/env python3
"""Lint the workspace with r2sleigh_lints and hold every slice to its baseline.

A slice is one lint in one crate. Most slices are clean, and a clean slice is
strict: one finding there fails. A slice with standing debt -- a seam another
phase is rewriting -- is recorded in `baseline.txt` with its count and may
fall but never rise, the way `scripts/structure-report.sh` holds the
structural lints. Nothing is allowed silently: every non-zero slice is named
in the baseline, so the debt stays visible and so does its owner.

    tools/dylints/report.py            lint, compare against the baseline
    tools/dylints/report.py --bless    lint, write the current counts
    tools/dylints/report.py --from F   compare the JSON messages in F instead
                                       of running cargo dylint (for tests)

A finding is identified by lint, file, line and column, so the same finding
reported twice -- once for the library and once for its test harness under
`--all-targets` -- counts once.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
LIBRARY = HERE / "r2sleigh_lints"
BASELINE = HERE / "baseline.txt"


def declared_lints() -> set[str]:
    """Every lint the library declares, spelled as rustc reports it."""
    source = "\n".join(path.read_text() for path in sorted((LIBRARY / "src").rglob("*.rs")))
    names = re.findall(r"declare_lint!\(\s*(?:///[^\n]*\n\s*)*pub ([A-Z0-9_]+),", source)
    if not names:
        raise SystemExit("no lints declared under r2sleigh_lints/src")
    return {name.lower() for name in names}


def run_dylint() -> list[str]:
    command = [
        "cargo",
        "dylint",
        "--path",
        str(LIBRARY.relative_to(ROOT)),
        "--workspace",
        "--",
        "--all-targets",
        "--all-features",
        "--message-format=json",
    ]
    print("+", " ".join(command), file=sys.stderr)
    completed = subprocess.run(
        command, cwd=ROOT, stdout=subprocess.PIPE, text=True, check=False
    )
    if completed.returncode != 0:
        # A lint at `Warn` never fails the build, so a failure here is a
        # compile error or a broken toolchain, and the counts would be a
        # reading of whatever compiled before it.
        sys.stderr.write(completed.stdout[-4000:])
        raise SystemExit(f"cargo dylint failed with exit status {completed.returncode}")
    return completed.stdout.splitlines()


def crate_of(message: dict) -> str:
    target = message.get("target") or {}
    name = target.get("name")
    if name:
        return name.replace("-", "_")
    package = message.get("package_id", "")
    match = re.search(r"#([A-Za-z0-9_-]+)@", package) or re.search(r"/([A-Za-z0-9_-]+)#", package)
    return (match.group(1) if match else package).replace("-", "_")


def findings(lines: list[str], lints: set[str]) -> dict[tuple[str, str], set[tuple]]:
    """Each (lint, crate) slice's distinct findings."""
    slices: dict[tuple[str, str], set[tuple]] = {}
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if message.get("reason") != "compiler-message":
            continue
        diagnostic = message.get("message") or {}
        code = (diagnostic.get("code") or {}).get("code")
        if code not in lints:
            continue
        spans = [span for span in diagnostic.get("spans", []) if span.get("is_primary")]
        span = spans[0] if spans else {}
        crate = crate_of(message)
        # A crate's test harness is the same crate: `r2dec` and its unit
        # tests share one slice.
        slices.setdefault((code, crate), set()).add(
            (span.get("file_name"), span.get("line_start"), span.get("column_start"))
        )
    return slices


def read_baseline() -> Counter:
    counts: Counter = Counter()
    if not BASELINE.exists():
        return counts
    for raw in BASELINE.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        lint, crate, count = line.split()
        counts[(lint, crate)] = int(count)
    return counts


HEADER = """\
# r2sleigh_lints debt, one line per (lint, crate) slice that is not clean.
#
# Every slice not listed here is clean and strict: one finding fails
# tools/dylints/report.py. A listed slice may fall, never rise. Lower a count
# when you have lowered it in the tree (or rerun with --bless); never raise
# one, and never add a line to make a new finding pass -- fix the finding.
#
# lint crate count
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bless", action="store_true", help="write the current counts")
    parser.add_argument("--from", dest="source", type=Path, help="read JSON messages from a file")
    arguments = parser.parse_args()

    lints = declared_lints()
    lines = arguments.source.read_text().splitlines() if arguments.source else run_dylint()
    current = Counter({key: len(found) for key, found in findings(lines, lints).items()})

    for (lint, crate), count in sorted(current.items()):
        print(f"{lint} {crate} {count}")
    print(f"{sum(current.values())} findings in {len(current)} slices", file=sys.stderr)

    if arguments.bless:
        body = "".join(f"{lint} {crate} {count}\n" for (lint, crate), count in sorted(current.items()))
        BASELINE.write_text(HEADER + body)
        print(f"baseline written: {BASELINE.relative_to(ROOT)}", file=sys.stderr)
        return 0

    baseline = read_baseline()
    status = 0
    for key in sorted(set(current) | set(baseline)):
        lint, crate = key
        was, now = baseline.get(key, 0), current.get(key, 0)
        if key not in baseline and now:
            print(f"{lint} in {crate}: {now} finding(s) in a clean slice", file=sys.stderr)
            for file_name, line, column in sorted(findings_for(lines, lints, key)):
                print(f"  {file_name}:{line}:{column}", file=sys.stderr)
            status = 1
        elif now > was:
            print(f"{lint} in {crate} rose from {was} to {now}", file=sys.stderr)
            status = 1
        elif now < was:
            print(f"{lint} in {crate} fell from {was} to {now} -- lower the baseline")
    for key in sorted(baseline):
        if key[0] not in lints:
            print(f"baseline names {key[0]}, which the library no longer declares", file=sys.stderr)
            status = 1
    return status


def findings_for(lines: list[str], lints: set[str], key: tuple[str, str]) -> set[tuple]:
    return findings(lines, lints).get(key, set())


if __name__ == "__main__":
    sys.exit(main())
