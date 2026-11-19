#!/usr/bin/env python3
"""Differential harness: run the same commands through radare2 and r2s.

radare2 is the validation target for everything the engine reproduces natively,
so the cheapest way to grade discovery, mapping and decoding is to ask both
tools the same question and report where they disagree.

Two comparison modes, because the two tools do not yet fill the same columns:

  exact   normalised text must match line for line, with integer literals
          canonicalised because the two spell the same value differently.
          Used where r2s already claims radare2's layout, such as `px`, `pd`.
  registers  `aoj`: each sampled instruction's size and bytes, and the registers
          it reads and writes. r2s states them from the lifted IL; radare2's
          `aoj` has no register field, so its side is `aeaj 1` (ESIL's `I`, the
          registers read before written, and `W`) after `aei; aeim`, without
          which ESIL stops at the first stack access and drops the rest. The sample is bounded and deterministic:
          each entry point `ie` states and SAMPLED_FUNCTIONS FUNC symbols `is`
          states, evenly spaced by address, and SAMPLED_INSTRUCTIONS instructions
          from each: where the container says code begins, with no discovery. One disagreement
          per register one side names and the other does not; a size or bytes
          disagreement is one, and its registers are not compared.
  pairs   compares the `key value` rows of `i` that r2s states (POSTURE_KEYS): a key both print
          with two values is a disagreement; a key radare2 prints and r2s does not is unfilled,
          counted and ratcheted with the values.
  values  compares the values each tool reports, column by column where both
          headers name the column. A value r2s reports and radare2 does not is
          a disagreement; a value radare2 reports and r2s does not is unfilled,
          counted per corpus and command and ratcheted (`diff_r2_baseline.json`):
          the count may fall, never rise. A value a `[[missed]]` entry lists, with
          radare2's line or an open row, is judged and leaves the count (D541).
          Used for the listings.

The analysis verbs (ROADMAP D490) run after one `aa` per file per tool, in one session each,
on the corpora ANALYSED_CORPORA names and the architectures GRADED_ARCHES names (`i`'s arch):

  entries     `afl`: the set of function entries. One r2s lists alone is a disagreement; one
              radare2 lists alone is unfilled, counted and ratcheted, and judged by class.
  blocks      `afb`: each sampled function's set of (address, size), both directions.
  noreturn    `afi`: the noreturn bit. r2s `true` against radare2 `false`, and radare2 `true`
              against r2s not `true` (`unproven`, or no line), are disagreements.
  frame       `afv`: frame offsets from the stack pointer at entry, and argument registers by
              their whole register (ARGUMENT_REGISTERS). radare2's offset is its own var delta
              (radare2 6.2.4 var.c: `afvj` sp offset minus `afi`'s stackframe; a bp var's delta
              from `afvf`, its bp offset fixed by the function's other vars), both directions.
  references  `axt`: each referencing address, for each sampled function and SAMPLED_FUNCTIONS
              import slots `is` states. r2s-only is a disagreement; radare2-only is unfilled.

The sample is `aoj`'s: each entry point `ie` states and SAMPLED_FUNCTIONS of the entries both
tools list, evenly spaced by address. A session may run ANALYSIS_TIMEOUT seconds (or --timeout, if longer):
pumasim's takes 32 s on an M-series Mac and about 90 s on a 4-core x86-64 host. A file either session
times out on is skipped and counted.

Every disagreement is either judged in `diff_r2_judged.toml` (who is right,
and why) or fails the run; a judgment nothing matches any more is reported, so
the table cannot outlive what it judged (ROADMAP P11). The judgments were made
against one radare2 release, which the table names and the run refuses any other,
as an x86-64 host runs it: radare2 picks a fat file's slice, and the architecture
of a machine it does not know, by its host's, so the run fixes both to x86-64
(CI's runner) and gives the file back its own architecture once it is loaded.
The corpora are radare2-testbins at CI's TESTBINS_REF; a newer checkout holds
binaries no judgment has seen.

Usage:
  scripts/diff_r2.py                        # default corpus and commands
  scripts/diff_r2.py --bins DIR --limit 20
  scripts/diff_r2.py --bins ELF MACH0 PE --bless   # whole corpora; rewrite the baseline
  scripts/diff_r2.py --only pd --verbose
"""

import argparse
import bisect
import concurrent.futures
import os
import fnmatch
import json
import pathlib
import re
import signal
import subprocess
import sys
import threading
import time
import tomllib

VERDICTS = ("r2s-right", "r2-right", "unfilled", "deliberate")
# A judged radare2-only value names radare2's line (6.2.4) when radare2 is wrong, an open row otherwise.
MISSED_WITNESS = {"r2s-right": "r2_line", "r2-right": "row", "unfilled": "row"}
R2_LINE = re.compile(r"[\w./-]+\.\w+:\d+(-\d+)?")
ROW = re.compile(r"[A-Z]+\d+(\.\d+)*[a-z]?")
VALUE = re.compile(r"0x[0-9a-f]+|[a-z]+")

# The analysis verbs, each with its mode; the corpora and architectures they grade.
ANALYSIS = [("afl", "entries"), ("afb", "blocks"), ("afi", "noreturn"), ("afv", "frame"), ("axt", "references")]
ANALYSED_CORPORA = ("elf",)
ANALYSIS_TIMEOUT = 300
GRADED_ARCHES = ("x86-64", "AArch64")
# Frame facts with no stated entry offset: r2s's `fp-`, `realigned.sp-` and offsetless stack formals,
# radare2's bp var two bp offsets explain. Counted, not compared (ROADMAP D490, D507).
UNPLACED = ("base", "formal", "unstated")
# Fences a session's answers: `<FENCE> <verb> <address>` before each.
SESSION_FENCE = "diff-r2"

# A part of a register by its whole register: x86-64's 32, 16 and 8-bit names, AArch64's w.
ARGUMENT_REGISTERS = {
    **{
        part: "r" + whole
        for whole in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp")
        for part in ("e" + whole, whole)
    },
    **{low: "r" + whole for whole, low in (("ax", "al"), ("bx", "bl"), ("cx", "cl"), ("dx", "dl"))},
    **{low: "r" + whole for whole, low in (("si", "sil"), ("di", "dil"), ("bp", "bpl"), ("sp", "spl"))},
    **{"r{}{}".format(n, s): "r{}".format(n) for n in range(8, 16) for s in "dwb"},
    **{"w{}".format(n): "x{}".format(n) for n in range(31)},
    # Sleigh's low quadword and doubleword lanes of an SSE register (a double or float argument).
    **{"xmm{}_{}".format(n, lane): "xmm{}".format(n) for n in range(16) for lane in ("qa", "da")},
}

# The bytes a C type r2s's `afv` spells occupies, where the spelling alone states it: the extent
# `frame_witness` measures an offset radare2 lists inside an r2s object against.
TYPE_BYTES = {
    **{name: 1 for name in ("char", "bool", "_Bool", "int8_t", "uint8_t")},
    **{name: 2 for name in ("short", "int16_t", "uint16_t")},
    **{name: 4 for name in ("int", "float", "int32_t", "uint32_t", "__uint32_t", "unsigned int")},
    **{name: 8 for name in ("long", "double", "size_t", "int64_t", "uint64_t", "__uint64_t", "long long")},
    **{name: 16 for name in ("__int128_t", "__uint128_t")},
}

# Command, comparison mode. The seek is issued to both so the cursor agrees.
COMMANDS = [
    ("px 64", "exact"),
    ("pd 8", "exact"),
    ("i", "pairs"),
    ("ie", "values"),
    ("iS", "values"),
    ("is", "values"),
    ("aoj", "registers"),
    *ANALYSIS,
]

# The keys of `i` that pairs mode grades: the container's posture, under radare2's names.
POSTURE_KEYS = ("intrp", "nx", "pic", "relro", "static")

# The `aoj` sample: this many FUNC symbols beside the entry points, and this many instructions from each.
SAMPLED_FUNCTIONS = 4
SAMPLED_INSTRUCTIONS = 8
# Printed before each instruction's pair of radare2 answers.
FENCE = "aoj-fence"

HEX = re.compile(r"0x[0-9a-fA-F]+")
NOISE = re.compile(r"^\s*(WARN|ERROR|INFO):")
# radare2 annotates the listing from analysis the engine does not have yet; a note row may follow
# the rails and flow lanes either tool draws (doc/adr-display.md, D581).
ANNOTATION = re.compile(r"^[\s│┌└├┐┘─<>|,`+]*;")
# A trailing annotation on a disassembly line. Only applied to the listing,
# where a semicolon never belongs to the instruction itself.
TRAILING = re.compile(r"\s+;.*$")


def instruction(line):
    """One listing line from its address on, or nothing when it has none.

    radare2 draws the control flow in a gutter left of the address -- `,=<`
    for a jump, `:` for the column it passes through -- and a line that is
    only gutter carries no instruction at all. The drawing is analysis made
    visible, not disassembly, so it is dropped for the same reason the
    trailing annotations are.
    """
    start = line.find("0x")
    return line[start:] if start >= 0 else ""


def normalise(text, strip_trailing=False):
    lines = []
    for line in text.splitlines():
        if NOISE.match(line) or ANNOTATION.match(line):
            continue
        if strip_trailing:
            line = canonical_numbers(TRAILING.sub("", instruction(line)))
        line = line.rstrip()
        if line:
            lines.append(line)
    return lines


def values(lines):
    found = set()
    for line in lines:
        found.update(int(token, 16) for token in HEX.findall(line))
    return found


def pairs(lines):
    """Each posture key `i` prints, with its value."""
    found = {}
    for line in lines:
        key, _, value = line.strip().partition(" ")
        if key in POSTURE_KEYS:
            found[key] = value.strip()
    return found


def header_of(lines):
    """The column names of a listing's header, or None when it prints none."""
    return next((line.split() for line in lines if "vaddr" in line.split()), None)


def columns(lines):
    """Each value with every (column, row) it appears at; the column is the header's name for it."""
    header = header_of(lines)
    found = {}
    for line in lines:
        for index, token in enumerate(line.split()):
            if not HEX.fullmatch(token):
                continue
            column = header[index] if header and index < len(header) else None
            found.setdefault(int(token, 16), []).append((column, line))
    return found


def by_column(lines):
    """Each column a header names, with the values printed in it."""
    found = {}
    for value, places in columns(lines).items():
        for column, _ in places:
            if column is not None:
                found.setdefault(column, set()).add(value)
    return found


def absent(value, column, named, everywhere):
    """Whether the other tool lacks this value: in the same column when it names one, else anywhere."""
    if column in named:
        return value not in named[column]
    return value not in everywhere


def cells(header, row):
    """A row's values by the column its header names."""
    found = {}
    for index, token in enumerate(row.split()):
        if header and index < len(header) and HEX.fullmatch(token):
            found.setdefault(header[index], int(token, 16))
    return found


class Listing:
    """radare2's rows of one values listing, found by a value they hold or by a column's value."""

    def __init__(self, lines):
        self.header, self.lines = header_of(lines), lines
        self.held, self.keys = None, {}

    def holding(self, value):
        if self.held is None:
            self.held = {}
            for found, places in columns(self.lines).items():
                self.held[found] = sorted({" ".join(row.split()) for _, row in places})
        return self.held.get(value, [])

    def keyed(self, column, value):
        if column not in self.keys:
            self.keys[column] = {}
            for line in self.lines:
                row = cells(self.header, line)
                if column in row:
                    self.keys[column].setdefault(row[column], []).append(row)
        return self.keys[column].get(value, [])


def rounded(value, other):
    """Whether `other` is `value` rounded up to a power-of-two alignment from 0x200 to 0x10000."""
    return other > value and any(other == -(-value // align) * align for align in (1 << n for n in range(9, 17)))


def radare2_only(left_lines, right_lines):
    """Each (column, value) radare2 reports and r2s does not: what r2s leaves unfilled."""
    ours, theirs = values(left_lines), columns(right_lines)
    named = by_column(left_lines) if header_of(left_lines) else {}
    return sorted(
        {
            (column or "", value)
            for value, places in theirs.items()
            for column, _ in places
            if absent(value, column, named, ours)
        }
    )


# `\b` never matches before a minus, so a negative decimal used to lose its
# sign: radare2's `[sp, -4]` normalised to `-0x4` while Sleigh's `[sp, -0x4]`
# normalised to the unsigned word, and the same displacement read as two.
NUMBER = re.compile(r"-?0x[0-9a-fA-F]+|(?<![0-9A-Za-z_])-?[0-9]+\b")


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
        # A listing of a non-text byte is not UTF-8: each invalid byte keeps its value, so two
        # different ones still compare different.
        done = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            errors="surrogateescape",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "", "timeout", None
    except OSError as error:
        return "", str(error), None
    return done.stdout, done.stderr, done.returncode


def differences(command, mode, left, right):
    """Every disagreement of one command on one binary.

    A listing pairs its lines by position, each pair one disagreement, with
    `None` for a line one tool did not print; a values listing gives each
    value r2s reports and radare2 does not.
    """
    if mode == "registers":
        return register_differences(left, right)
    if mode == "pairs":
        ours, theirs = pairs(left.splitlines()), pairs(right.splitlines())
        return [
            ("lines", (None if key not in theirs else "{} {}".format(key, theirs[key]), "{} {}".format(key, ours[key])))
            for key in POSTURE_KEYS
            if key in ours and ours[key] != theirs.get(key)
        ]
    # Only the listing carries trailing annotations; a hex dump's ASCII column
    # can hold a semicolon that must not be mistaken for one.
    strip = command.startswith("pd")
    left_lines, right_lines = normalise(left, strip), normalise(right, strip)
    if mode == "values":
        theirs, ours = values(right_lines), columns(left_lines)
        named = by_column(right_lines) if header_of(right_lines) else {}
        # One disagreement per occurrence: a judgment of one column must not hide another, and a
        # value in a column both name is compared with that column alone, so a swap is seen.
        # A value inside a word (no column of its own) is compared with every value radare2 prints.
        inside = {value: [(None, "")] for value in values(left_lines) if value not in ours}
        listing, header = Listing(right_lines), header_of(left_lines)
        return [
            ("value", (value, column, " ".join(row.split()), {"ours": cells(header, row), "theirs": listing}))
            for value, places in sorted({**ours, **inside}.items())
            for column, row in places
            if absent(value, column, named, theirs)
        ]
    found = []
    for index in range(max(len(left_lines), len(right_lines))):
        ours = left_lines[index] if index < len(left_lines) else None
        theirs = right_lines[index] if index < len(right_lines) else None
        if ours != theirs:
            found.append(("lines", (theirs, ours)))
    return found


def register_differences(left, right):
    """Each instruction both tools read at one address: a disagreement about which instruction it
    is, else each register one side's read or written set names and the other's does not.

    `left` is r2s's sample (`arch` and its `aoj` rows), `right` radare2's rows (`aoj 1` with
    `aeaj 1`'s `I`, `W` and memory accesses added), both JSON. A detail is (address, field,
    register or None, side lacking it or None, r2s's opcode, radare2's opcode, context).
    """
    sample = json.loads(left or "{}")
    ours = {row["addr"]: row for row in sample.get("rows", [])}
    theirs = {row["addr"]: row for row in json.loads(right or "[]")}
    found = []
    for address in sorted(ours):
        mine, other = ours[address], theirs.get(address)
        spelled = (mine.get("opcode", ""), "<missing>" if other is None else other.get("opcode", ""))
        context = {
            "arch": sample.get("arch", ""),
            "refused": mine.get("refused", ""),
            "ours": "",
            "theirs": "",
        }

        def instruction(field):
            found.append(("instruction", (address, field, None, None) + spelled + (context,)))

        if other is None:
            instruction("missing")
            continue
        if (mine["size"], mine["bytes"]) != (other.get("size"), other.get("bytes")):
            instruction("size")
            continue
        if spelled == ("invalid", "invalid"):
            continue
        # One instruction spelled two ways, or two instructions: either way no sets are compared.
        if mine.get("mnemonic") != other.get("mnemonic"):
            instruction("decode")
            continue
        if "refused" in mine:
            instruction("refused")
            continue
        # ESIL that never reached the memory the IL accesses stopped there and dropped the rest,
        # so what its sets hold or lack says nothing.
        memory = any(op.startswith("STORE") or " LOAD " in op for op in mine.get("il", []))
        if memory and not (other.get("@R") or other.get("@W")):
            instruction("halted")
            continue
        for field, key in (("reads", "I"), ("writes", "W")):
            have, want = set(mine[field]), set(other.get(key, []))
            context = dict(context, ours=" ".join(sorted(have)), theirs=" ".join(sorted(want)))
            for register in sorted(have - want):
                found.append(("register", (address, field, register, "r2") + spelled + (context,)))
            for register in sorted(want - have):
                found.append(("register", (address, field, register, "r2s") + spelled + (context,)))
    return found


def load_table(path):
    """The radare2 release the table was judged against, and its judged disagreements."""
    if not path.exists():
        return None, []
    table = tomllib.loads(path.read_text())
    return table.get("radare2"), load_judgments(path, table)


def load_judgments(path, table=None):
    """The judged disagreements: each a class of them, with its verdict and reason."""
    if table is None:
        if not path.exists():
            return []
        table = tomllib.loads(path.read_text())
    judged = table["judged"]
    for judgment in judged:
        if judgment["verdict"] not in VERDICTS:
            raise ValueError("unknown verdict {!r}".format(judgment["verdict"]))
        judgment["values"] = {int(value, 16) for value in judgment.get("values", [])}
        judgment["columns"] = set(judgment.get("columns", []))
        judgment["registers"] = set(judgment.get("registers", []))
        judgment["fields"] = set(judgment.get("fields", []))
        judgment["matched"] = 0
    return judged


def load_missed(path, table=None):
    """The judged radare2-only values (`[[missed]]`), indexed by binary, verb and value."""
    if table is None:
        if not path.exists():
            return Misses({})
        table = tomllib.loads(path.read_text())
    index = {}
    for entry in table.get("missed", []):
        witness = MISSED_WITNESS.get(entry.get("verdict"))
        if witness is None:
            raise ValueError("a missed value's verdict is one of {}: {!r}".format(sorted(MISSED_WITNESS), entry))
        pattern = R2_LINE if witness == "r2_line" else ROW
        if not entry.get("reason") or pattern.fullmatch(entry.get(witness, "")) is None:
            raise ValueError("a {} missed value states its reason and `{}`: {!r}".format(entry["verdict"], witness, entry))
        verbs, binaries = entry["command"], entry["binaries"]
        for verb, binary, value in (
            (verb, binary, value)
            for verb in ([verbs] if isinstance(verbs, str) else verbs)
            for binary in ([binaries] if isinstance(binaries, str) else binaries)
            for value in entry["values"]
        ):
            if VALUE.fullmatch(value) is None or any(c in binary for c in "*?["):
                raise ValueError("a missed value is listed, never a pattern: {} {}".format(binary, value))
            key = (verb, binary, int(value, 16) if value.startswith("0x") else value)
            if key in index:
                raise ValueError("a missed value is judged once: {} {} {}".format(*key))
            index[key] = entry
    return Misses(index)


class Misses:
    """The judged radare2-only values, the ones a run reported, and the binaries and verbs it graded."""

    def __init__(self, index):
        self.index, self.matched, self.ran = index, set(), set()

    def __len__(self):
        return len(self.index)

    def judged(self, binary, command, item):
        """Whether an entry lists this radare2-only value; O(1)."""
        column, value = item
        key = (command.split()[0], binary, column if value is None else value)
        if key not in self.index:
            return False
        self.matched.add(key)
        return True


def unmatched_misses(misses):
    """Each listed value of a graded binary and verb that its run did not report."""
    return sorted((key for key in misses.index if key[:2] in misses.ran and key not in misses.matched), key=str)


def release(banner):
    """The release `radare2 -v` names on its first line, or None."""
    words = banner.split()
    return words[1] if len(words) > 1 and words[0] == "radare2" else None


def dumped(verb, line):
    """The address and hex bytes a `px` or `pd` line shows, or None."""
    if line is None or not line.startswith("0x"):
        return None
    address, _, rest = line.partition(" ")
    if verb == "px":
        # Eight groups of four digits after two spaces; the ASCII column after them may look hex.
        return address, rest[1:40].replace(" ", "").lower()
    # radare2 marks a line that starts inside the previous instruction with `~`.
    words = [word for word in rest.split() if word != "~"]
    return (address, words[0].lower()) if words and re.fullmatch("[0-9a-fA-F]+", words[0]) else None


def filled(verb, theirs, ours, byte):
    """Whether radare2's line is r2s's (or nothing) followed only by `byte`: a fill past the mapping."""
    shown, prefix = dumped(verb, theirs), dumped(verb, ours) if ours is not None else None
    if shown is None or (ours is not None and (prefix is None or prefix[0] != shown[0])):
        return False
    head = prefix[1] if prefix else ""
    tail = shown[1][len(head) :]
    return shown[1].startswith(head) and tail != "" and tail == byte * (len(tail) // len(byte))


def aligned(key, column, value, context):
    """Whether radare2's row with r2s's `key` holds, in this column, r2s's value rounded up."""
    ours = context["ours"].get(key)
    return any(
        column in row and rounded(value, row[column]) for row in context["theirs"].keyed(key, ours)
    )


def judgment_for(judgments, binary, command, difference, corpus=None):
    """The first judgment that covers this disagreement, or None."""
    verb = command.split()[0]
    kind, detail = difference
    for judgment in judgments:
        patterns = judgment["binaries"]
        patterns = [patterns] if isinstance(patterns, str) else patterns
        verbs = judgment["command"]
        verbs = [verbs] if isinstance(verbs, str) else verbs
        if verb not in verbs or not any(fnmatch.fnmatchcase(binary, p) for p in patterns):
            continue
        if judgment.get("corpus", corpus) != corpus:
            continue
        if kind in ("register", "instruction"):
            _, field, register, lacking, mine, other, context = detail
            # `{register}` in a pattern is the register judged, `{suffix}` it without its first letter.
            def pattern(key):
                text = judgment.get(key, "")
                if register is not None:
                    text = text.replace("{register}", re.escape(register)).replace("{suffix}", re.escape(register[1:]))
                return text

            covered = (
                (not judgment["fields"] or field in judgment["fields"])
                and (not judgment["registers"] or register in judgment["registers"])
                and ("register" not in judgment or re.fullmatch(judgment["register"], register or "") is not None)
                and judgment.get("lacking", lacking) == lacking
                and re.search(pattern("r2s"), mine) is not None
                and re.search(pattern("r2"), other) is not None
                and all(
                    re.search(pattern(key), context[key]) is not None
                    for key in ("arch", "refused", "ours", "theirs")
                )
            )
        elif kind == "fact":
            _, _, _, lacking, mine, other, context = detail
            covered = (
                judgment.get("lacking", lacking) == lacking
                and re.search(judgment.get("r2s", ""), mine) is not None
                and re.search(judgment.get("r2", ""), other) is not None
                and all(re.search(judgment.get(key, ""), context[key]) is not None for key in ("arch", "function"))
            )
        elif kind == "value":
            # No values listed covers every value of those binaries; columns listed cover only values
            # r2s prints in them; `r2s` matches r2s's row and `r2` a radare2 row holding the value.
            value, column, row, context = (detail + (None,))[:4]
            theirs = context["theirs"].holding(value) if context else []
            covered = (
                (not judgment["values"] or value in judgment["values"])
                and (not judgment["columns"] or column in judgment["columns"])
                and re.search(judgment.get("r2s", ""), row) is not None
                and ("r2" not in judgment or any(re.search(judgment["r2"], line) for line in theirs or ["<missing>"]))
                and ("key" not in judgment or (context is not None and aligned(judgment["key"], column, value, context)))
            )
        else:
            theirs, ours = detail
            covered = not judgment["values"] and all(
                re.search(judgment[side], line if line is not None else "<missing>")
                for side, line in (("r2", theirs), ("r2s", ours))
                if side in judgment
            )
            if "fill" in judgment:
                covered = covered and filled(verb, theirs, ours, judgment["fill"])
        if covered:
            judgment["matched"] += 1
            judgment.setdefault("instance", (binary, command, difference))
            return judgment
    return None


def spelled(difference):
    """One disagreement as the report prints it, indented under its command."""
    kind, detail = difference
    if kind in ("register", "instruction"):
        address, field, register, lacking, mine, other, context = detail
        what = field if register is None else "{} {} (not in {}'s)".format(field, register, lacking)
        return "      {:#x} {}  r2s `{}`  r2 `{}`  [{}] r2s {{{}}} r2 {{{}}}{}".format(
            address, what, mine, other, context["arch"], context["ours"], context["theirs"],
            "  ({})".format(context["refused"]) if context["refused"] else "",
        )
    if kind == "fact":
        verb, function, key, lacking, mine, other, context = detail
        key = " ".join(map(str, key)) if isinstance(key, tuple) else "{:#x}".format(key)
        return "      {:#x} {} not in {}'s  r2s `{}`  r2 `{}`  [{}] {}".format(
            function, key, lacking, mine, other, context["arch"], context["function"])
    if kind == "value":
        value, column, row = detail[:3]
        return "      {:#x}{}  {}".format(value, " ({})".format(column) if column else "", row)
    theirs, ours = detail
    return "      r2  {}\n      r2s {}".format(
        theirs if theirs is not None else "<missing>", ours if ours is not None else "<missing>"
    )


# `-e` holds through the load, so the file's own architecture and bits are put back after it.
RESTORE = "e asm.arch=`i~^arch[1]`;e asm.bits=`i~^bits[1]`"


def radare2_argv(r2, script, binary):
    """radare2 answering `script`, loading `binary` as an x86-64 host does; with no script, a
    session that reads its commands on stdin, RESTORE first. Names stay flag spellings
    (demangling off), so every name count compares flags (ROADMAP D574)."""
    script = [] if script is None else ["-c", RESTORE + ";" + script]
    return [str(r2), "-N", "-q", "-e", "asm.arch=x86", "-e", "asm.bits=64", "-e", "scr.color=0",
            "-e", "asm.demangle=false", "-e", "bin.demangle=false", *script, str(binary)]


def r2s_argv(r2s, script, binary):
    """r2s answering `script` on `binary`, its names flag spellings as radare2's are; with no
    script, a session that reads its commands on stdin."""
    script = [] if script is None else ["-c", script]
    return [str(r2s), "-e", "asm.demangle=false", "-q", *script, str(binary)]


ANALYSIS_MODES = {mode for _, mode in ANALYSIS}


def answers(binary, commands, r2, r2s, timeout, corpus=None):
    """Both tools' output for each command on one binary, or r2s's refusal to open it. The
    analysis verbs share one session per tool, on a graded corpus and architecture only."""
    # A refusal to open is a capability gap, not a disagreement about a
    # binary both tools read, so it is counted and reported separately.
    opened, opened_error, opened_code = run(r2s_argv(r2s, "i", binary), timeout)
    if opened_code != 0:
        reason = opened_error.strip().splitlines()[-1] if opened_error.strip() else "failed"
        return reason.replace("r2s: ", ""), {}
    said = {}
    arch = next((line.split()[1] for line in opened.splitlines() if line.split()[:1] == ["arch"]), "")
    if corpus in ANALYSED_CORPORA and arch in GRADED_ARCHES and any(m in ANALYSIS_MODES for _, m in commands):
        both, ended = analysed(binary, r2, r2s, max(timeout, ANALYSIS_TIMEOUT))
        said["aa"] = ended
        if both is not None:
            both[0][("arch", 0)] = [arch]
            said.update({command: both for command, mode in commands if mode in ANALYSIS_MODES})
    for command, mode in commands:
        if mode in ANALYSIS_MODES:
            continue
        # Every command seeks first, so a seek that timed out once times out each time.
        if None in said.values():
            said[command] = None
            continue
        if mode == "registers":
            said[command] = sampled_instructions(binary, r2, r2s, timeout)
            continue
        script = "s entry0;{}".format(command)
        right, _, right_code = run(radare2_argv(r2, script, binary), timeout)
        left, _, left_code = run(r2s_argv(r2s, script, binary), timeout)
        said[command] = None if right_code is None or left_code is None else (left, right)
    return None, said


def sampled_instructions(binary, r2, r2s, timeout):
    """(r2s's sample, radare2's rows for the same addresses) as JSON; (None, None) where r2s lists
    no function to sample; None on a timeout."""
    listed, _, code = run(r2s_argv(r2s, "i~^arch;ie;is", binary), timeout)
    if code is None:
        return None
    entries = sampled_entries(listed.splitlines())
    if not entries:
        return None, None
    arch = next((line.split()[1] for line in listed.splitlines() if line.split()[:1] == ["arch"]), "")
    script = ";".join("aoj {} @ {:#x}".format(SAMPLED_INSTRUCTIONS, entry) for entry in entries)
    left, _, code = run(r2s_argv(r2s, script, binary), timeout)
    if code is None:
        return None
    ours = [row for line in left.splitlines() if line.startswith("[") for row in json.loads(line)]
    addresses = sorted({row["addr"] for row in ours})
    if not addresses:
        return None, None
    # Each address's pair is fenced, so a command that prints nothing cannot shift the rest.
    asked = ";".join("?e {};aoj 1 @ {:#x};aeaj 1 @ {:#x}".format(FENCE, a, a) for a in addresses)
    right, _, code = run(radare2_argv(r2, "aei;aeim;" + asked, binary), timeout)
    if code is None:
        return None
    return json.dumps({"arch": arch, "rows": ours}), json.dumps(radare2_rows(right))


def sampled_entries(lines):
    """The entry points `ie` states, then SAMPLED_FUNCTIONS of the FUNC symbols `is` states, evenly
    spaced over them by address: where the container says code begins, with no discovery run."""
    entries, functions, lib = set(), set(), None
    for line in lines:
        words = line.split()
        if words[:1] == ["nth"] and "lib" in words:
            lib = (line.index(" lib ") + 1, line.index(" name") + 1)
        if len(words) == 5 and words[-1] == "program" and HEX.fullmatch(words[1]):
            entries.add(int(words[1], 16))
        elif len(words) >= 5 and words[4] == "FUNC" and HEX.fullmatch(words[2]) and int(words[2], 16):
            # A symbol a library defines names the slot the loader fills (a PE import), not code.
            if lib is None or not line[lib[0] : lib[1]].strip():
                functions.add(int(words[2], 16))
    return sorted(entries) + spaced(functions - entries)


def spaced(addresses):
    """SAMPLED_FUNCTIONS of these addresses, evenly spaced over them in address order."""
    addresses = sorted(addresses)
    return addresses[:: max(1, len(addresses) // SAMPLED_FUNCTIONS)][:SAMPLED_FUNCTIONS]


def radare2_rows(text):
    """radare2's fenced `aoj 1` and `aeaj 1` answers, one row per address with `I`, `W` and the
    memory `@R` and `@W` added: `I` is what ESIL reads before writing, as r2s's reads are."""
    rows, blocks = [], [[]]
    for line in text.splitlines():
        if line == FENCE:
            blocks.append([])
        elif line.startswith(("[", "{")):
            blocks[-1].append(line)
    for lines in blocks[1:]:
        try:
            decoded = json.loads(lines[0])[0] if lines else None
            accessed = json.loads(lines[1]) if len(lines) > 1 else {}
        except (ValueError, IndexError):
            continue
        if decoded is None:
            continue
        for key in ("I", "W", "@R", "@W"):
            decoded[key] = accessed.get(key, [])
        rows.append(decoded)
    return rows


def fenced(text):
    """A session's answers by the fence before each: (verb, address) to its lines."""
    found, current = {}, None
    for line in text.splitlines():
        words = line.split()
        if len(words) == 3 and words[0] == SESSION_FENCE and HEX.fullmatch(words[2]):
            current = (words[1], int(words[2], 16))
            found[current] = []
        elif current is not None:
            found[current].append(line)
    return found


def fence(verb, address=0):
    return "?e {} {} {:#x}".format(SESSION_FENCE, verb, address)


def listed(lines):
    """Each function `afl` lists: its entry to its row."""
    found = {}
    for line in lines:
        words = line.split()
        if len(words) >= 4 and HEX.fullmatch(words[0]):
            found.setdefault(int(words[0], 16), " ".join(words))
    return found


FDE = re.compile(r"FDE cie=\S+ pc=([0-9a-f]+)\.\.\.?([0-9a-f]+)")


def frame_descriptions(binary, timeout):
    """Each `.eh_frame` FDE's code range, `objdump --dwarf=frames`'s rows: the container's statement a
    judgment of an entry cites. Empty where objdump is missing or fails."""
    out, _, _ = run(["objdump", "--dwarf=frames", str(binary)], timeout)
    return ["{} {}".format(*match.groups()) for match in FDE.finditer(out)]


def sections(lines):
    """`iS`'s sections that hold bytes in memory, (vaddr, vsize, `name:perm`), sorted by address."""
    header = header_of(lines)
    found = []
    for line in lines:
        row, words = cells(header, line), line.split()
        if header and "vaddr" in row and "vsize" in row and row["vsize"] and words[-1].startswith("."):
            perm = next((word for word in words if re.fullmatch(r"[-a-z][-r][-w][-x]", word)), "")
            # A section with no permission is not loaded: its vaddr 0 places nothing.
            if perm != "----":
                found.append((row["vaddr"], row["vsize"], "{}:{}".format(words[-1], perm)))
    return sorted(found)


def section_of(address, spans):
    """The name of the section holding this address, or None; the spans are sorted by address."""
    index = bisect.bisect_right(spans, (address, float("inf"), "")) - 1
    return spans[index][2] if index >= 0 and address < spans[index][0] + spans[index][1] else None


def entry_rows(said):
    """`afl`'s rows, each with the section `iS` places it in, the basis `aflj` states and the FDE
    that starts there, if any: the statements a judgment of an entry cites."""
    fdes = {int(low, 16): int(high, 16) for low, high in map(str.split, said.get(("fde", 0), []))}
    spans = sections(said.get(("iS", 0), []))
    rows = {}
    for entry, row in listed(said.get(("afl", 0), [])).items():
        where = section_of(entry, spans) if spans else None
        row = row if where is None else "{} in={}".format(row, where.split(":")[0])
        rows[entry] = row if entry not in fdes else "{} fde={:#x}-{:#x}".format(row, entry, fdes[entry])
    try:
        basis = {row["addr"]: row.get("confidence") for row in json.loads("".join(said.get(("aflj", 0), [])) or "[]")}
    except (ValueError, TypeError, KeyError):
        basis = {}
    return {
        entry: row if basis.get(entry) is None else row.replace(" fde=", " basis={} fde=".format(basis[entry]))
        if " fde=" in row else "{} basis={}".format(row, basis[entry])
        for entry, row in rows.items()
    }


def referenced_by(lines):
    """The kinds and mnemonics of the references `axt` lists, sorted: `CALL:call,JUMP:je`, or `none`."""
    kinds = set()
    for words in map(str.split, lines):
        if len(words) >= 4 and HEX.fullmatch(words[1]) and words[2].startswith("["):
            kinds.add("{}:{}".format(words[2].strip("[]").split(":")[0], words[3]))
    return ",".join(sorted(kinds)) or "none"


def stated_entries(lines):
    """The program entry points `ie` states."""
    return {
        int(words[1], 16)
        for words in map(str.split, lines)
        if len(words) == 5 and words[-1] == "program" and HEX.fullmatch(words[1])
    }


def import_slots(lines):
    """The address `is` states for each import that has one: where a call to the import goes."""
    return {
        int(words[2], 16)
        for words in map(str.split, lines)
        if len(words) >= 5 and words[4] == "FUNC" and HEX.fullmatch(words[2]) and int(words[2], 16)
        and words[-1].startswith("imp.")
    }


def analysis_sample(entries, ours, theirs):
    """The stated entry points both tools list, then SAMPLED_FUNCTIONS of the other entries both list."""
    common = set(ours) & set(theirs)
    return sorted(common & entries) + spaced(common - entries)


def block_rows(lines):
    """`afb`'s blocks, (address, size) to the row; the size is the row's end less its start."""
    found = {}
    for words in map(str.split, lines):
        if len(words) >= 2 and HEX.fullmatch(words[0]) and HEX.fullmatch(words[1]):
            start = int(words[0], 16)
            found[(start, int(words[1], 16) - start)] = " ".join(words)
    return found


def noreturn_row(lines):
    """`afi`'s noreturn row, `<absent>` where it prints none, or its refusal."""
    for line in lines:
        if line.startswith(("noreturn:", "refused:")):
            return " ".join(line.split())
    return "<absent>"


def signed(value):
    return value - (1 << 64) if value >= 1 << 63 else value


def frame_key(at):
    """A variable's place as a fact: an offset from the stack pointer at entry, a whole register,
    or a base no entry offset is stated for (`fp`, `realigned.sp`)."""
    based = re.fullmatch(r"entry\.sp([+-])0x([0-9a-f]+)", at)
    if based:
        return ("offset", int(based.group(2), 16) * (-1 if based.group(1) == "-" else 1))
    if re.search(r"[+-]", at):
        return ("base", at)
    return ("register", ARGUMENT_REGISTERS.get(at, at))


def our_frame(lines):
    """r2s's `afv`: each fact to its row; a refusal is one fact of its own."""
    found = {}
    for line in lines:
        words = line.split()
        if line.startswith("refused:"):
            found[("refused", " ".join(words))] = " ".join(words)
        elif words[:1] in (["arg"], ["var"]) and len(words) >= 3 and words[-2] == "@":
            found.setdefault(frame_key(words[-1]), " ".join(words))
        elif words[:1] == ["arg"] and len(words) >= 3:
            found.setdefault(("formal", words[-1]), " ".join(words))
    return found


def their_frame(variables, frame, stackframe, unstated=None):
    """radare2's `afv` as facts, each to its row, from `afvj`, `afvf` and `afi`'s stackframe.

    A var's delta is its offset from the stack pointer at entry (6.2.4 var.c:1389-1396). `afvj`
    prints an sp var's delta plus the stackframe (var.c:641-646) and a bp var's plus the bp's own
    offset, which nothing prints. `afvf` prints -delta for a var at or below 0 and delta - 0x6a
    for an argument or a var at or above 0 (cmd_anal.inc.c:2005-2033), so a bp var's delta is the
    candidate that gives every bp var of the function one bp offset; with none or two it is unstated,
    and `unstated`, where given, takes each such var's candidate offsets.
    """
    try:
        table = json.loads(variables) if variables else {}
    except ValueError:
        table = {}
    if not isinstance(table, dict):
        table = {}
    found = {}
    for var in table.get("reg", []):
        found.setdefault(("register", ARGUMENT_REGISTERS.get(var["ref"], var["ref"])), "arg {} {} @ {}".format(
            var["type"], var["name"], var["ref"]))
    for var in table.get("sp", []):
        delta = var["ref"]["offset"] - stackframe
        found.setdefault(("offset", delta), "{} {} {} @ {}{:+#x}".format(
            var["kind"], var["type"], var["name"], var["ref"]["base"], var["ref"]["offset"]))
    printed = {}
    for words in map(str.split, frame):
        if len(words) >= 2 and HEX.fullmatch(words[0]):
            printed.setdefault(words[1].rstrip(":"), []).append(int(words[0], 16))
    candidates = []
    for var in table.get("bp", []):
        deltas = None
        for value in printed.get(var["name"], []):
            above, below = signed((value + 0x6A) & ((1 << 64) - 1)), -signed(value)
            each = {above} if var["kind"] == "arg" or above >= 0 else set()
            each |= {below} if var["kind"] != "arg" and below <= 0 else set()
            deltas = each if deltas is None else deltas & each
        candidates.append((var, deltas or set()))
    offsets = None
    for var, deltas in candidates:
        each = {var["ref"]["offset"] - delta for delta in deltas}
        offsets = each if offsets is None else offsets & each
    for var, deltas in candidates:
        row = "{} {} {} @ {}{:+#x}".format(
            var["kind"], var["type"], var["name"], var["ref"]["base"], var["ref"]["offset"])
        key = ("offset", var["ref"]["offset"] - next(iter(offsets))) if offsets and len(offsets) == 1 else (
            "unstated", var["name"])
        found.setdefault(key, row)
        if key[0] == "unstated" and unstated is not None:
            unstated.update(deltas)
    return found


def type_bytes(spelled):
    """The bytes a C type spelling occupies, or None where the spelling does not state it."""
    spelled = spelled.strip()
    array = re.fullmatch(r"(.+)\[(\d+)\]", spelled)
    if array:
        element = type_bytes(array.group(1))
        return element * int(array.group(2)) if element else None
    if spelled.endswith("*"):
        return 8
    sized = re.fullmatch(r"(?:struct )?r2sleigh_(?:bits_|word_u|unread_u)(\d+)", spelled)
    if sized:
        return int(sized.group(1)) // 8
    return TYPE_BYTES.get(spelled)


def extents_of(rows):
    """Each frame object's (start, end, name, type) where its spelled type states its bytes."""
    found = []
    for key, row in rows.items():
        typed = re.fullmatch(r"(?:var|arg) (.+) (\S+) @ \S+", row)
        if key[0] == "offset" and typed and type_bytes(typed.group(1)):
            found.append((key[1], key[1] + type_bytes(typed.group(1)), typed.group(2), typed.group(1)))
    return sorted(found)


def frame_witness(facts, function, mine, their, unstated):
    """What each side states where it lacks the other's frame fact, and the r2s offsets radare2 may hold.

    A radare2 frame fact r2s lacks shows r2s's refusal, the r2s object whose extent (by its spelled
    type) holds the offset, or, above the entry stack pointer, the stack formals r2s spells with no
    offset. An r2s offset radare2 lacks shows the radare2 var whose extent holds it, or the radare2
    vars inside the r2s object. An r2s offset an unstated radare2 bp var may hold is not compared."""
    refused = next((row for key, row in mine.items() if key[0] == "refused"), None)
    extents, theirs = extents_of(mine), extents_of(their)
    unplaced = sum(1 for key in mine if key[0] == "formal")
    for (place, key), (shown_ours, shown_theirs, side) in list(facts.items()):
        if place != function or not isinstance(key, tuple):
            continue
        if side == "r2s" and key[0] == "offset" and key[1] in unstated:
            facts[(place, key)] = (shown_ours, shown_theirs, "unplaced")
        elif side == "r2s" and key[0] == "offset":
            holder = next((e for e in theirs if e[0] < key[1] < e[1]), None)
            own = next((e for e in extents if e[0] == key[1]), None)
            held = [e[2] for e in theirs if own is not None and own[0] < e[0] < own[1]]
            said = "<missing>"
            if holder is not None:
                said += " within={} {}".format(holder[2], holder[3])
            elif held:
                said += " holds={}".format(",".join(held))
            facts[(place, key)] = (shown_ours, said, side)
        elif side == "r2" and refused is not None:
            facts[(place, key)] = ("<missing> " + refused, shown_theirs, side)
        elif side == "r2" and key[0] == "offset":
            holder = next((e for e in extents if e[0] < key[1] < e[1]), None)
            said = "<missing>"
            if holder is not None:
                said += " inside={} {}".format(holder[2], holder[3])
            elif key[1] >= 0:
                said += " above formals={}".format(unplaced)
            facts[(place, key)] = (said, shown_theirs, side)


def stackframe_of(lines):
    return next((int(line.split()[1]) for line in lines if line.startswith("stackframe:")), 0)


def reference_rows(lines):
    """`axt`'s rows, each referencing address to its row. A demangled function name may hold
    spaces, so the address is the first hex word followed by the `[KIND:perm]` word."""
    found = {}
    for words in map(str.split, lines):
        at = next(
            (i for i in range(1, len(words) - 1) if HEX.fullmatch(words[i]) and words[i + 1].startswith("[")), None
        )
        if at is not None:
            found.setdefault(int(words[at], 16), " ".join(words))
    return found


def order(key):
    """A fact's sort key: numbers by value, before words, so the report keeps address order."""
    if isinstance(key, tuple):
        return tuple(order(part) for part in key)
    return (0, key, "") if isinstance(key, int) else (1, 0, str(key))


def analysis_facts(verb, ours, theirs):
    """Every fact of one analysis verb either session states: (function, key) to (r2s's row, radare2's
    row, side) where side is `equal`, `r2s` (r2s alone states it) or `r2` (radare2 alone)."""
    facts = {}

    def add(function, mine, other, near=lambda key: key):
        places = {}
        for side, rows in ((0, mine), (1, other)):
            for key, row in rows.items():
                places.setdefault((side, near(key)), row)
        for key in sorted(set(mine) | set(other), key=order):
            here = (mine.get(key), other.get(key))
            side = "equal" if None not in here else "r2s" if here[1] is None else "r2"
            # A frame offset from a base no entry offset is stated for is not compared (UNPLACED).
            side = "unplaced" if isinstance(key, tuple) and key[0] in UNPLACED else side
            shown = tuple(
                here[index] or places.get((index, near(key)), "<missing>") for index in (0, 1)
            )
            facts[(function, key)] = shown + (side,)

    if verb == "afl":
        mine, other = entry_rows(ours), entry_rows(theirs)
        add(0, mine, other)
        # An entry one side lacks shows what that side records referencing it, and an entry
        # radare2 lists alone the r2s function whose extent (`afl`'s address and size) holds it.
        extents = sorted((entry, entry + int(row.split()[2])) for entry, row in mine.items())
        spans = sections(ours.get(("iS", 0), []))
        for (_, entry), (shown_ours, shown_theirs, side) in list(facts.items()):
            if side != "equal":
                lacking = ours if side == "r2" else theirs
                said = "<missing> refs={}".format(referenced_by(lacking.get(("refs", entry), [])))
                index = bisect.bisect_right(extents, (entry, float("inf"))) - 1
                if side == "r2" and index >= 0 and entry < extents[index][1]:
                    said += " inside={:#x}".format(extents[index][0])
                if side == "r2" and spans:
                    said += " in={}".format(section_of(entry, spans) or "none")
                facts[(0, entry)] = (said, shown_theirs, side) if side == "r2" else (shown_ours, said, side)
        return facts
    if verb == "axt":
        extents = sorted((entry, entry + int(row.split()[2])) for entry, row in listed(ours.get(("afl", 0), [])).items())
        listed_theirs = set(listed(theirs.get(("afl", 0), [])))

        def holder(address):
            index = bisect.bisect_right(extents, (address, float("inf"))) - 1
            return extents[index][0] if index >= 0 and address < extents[index][1] else None

    for (asked, function), lines in sorted(ours.items()):
        if asked != verb:
            continue
        other = theirs.get((verb, function), [])
        if verb == "afb":
            add(function, block_rows(lines), block_rows(other), near=lambda key: key[0])
        elif verb == "afi":
            mine, their = noreturn_row(lines), noreturn_row(other)
            ours_true, theirs_true = mine.startswith("noreturn: true"), their == "noreturn: true"
            side = "equal" if ours_true == theirs_true else "r2s" if ours_true else "r2"
            facts[(function, ("noreturn",))] = (mine, their, side)
        elif verb == "afv":
            stackframe = stackframe_of(theirs.get(("afi", function), []))
            variables = "".join(theirs.get(("afvj", function), []))
            unstated = set()
            their = their_frame(variables, theirs.get(("afvf", function), []), stackframe, unstated)
            mine = our_frame(lines)
            add(function, mine, their)
            frame_witness(facts, function, mine, their, unstated)
        elif verb == "axt":
            add(function, reference_rows(lines), reference_rows(other))
            # A reference r2s states alone names the r2s function it lies in, and whether radare2 lists it.
            for (_, place), (mine, their, side) in [item for item in facts.items() if item[0][0] == function]:
                if side == "r2s":
                    # The extent misses a function laid out in pieces; r2s's row then names it.
                    named = re.match(r"fcn\.([0-9a-f]+) ", mine)
                    caller = holder(place) if named is None else int(named.group(1), 16)
                    facts[(function, place)] = (mine, "<missing> from={} listed={}".format(
                        "none" if caller is None else "{:#x}".format(caller),
                        "yes" if caller in listed_theirs else "no"), side)
    return facts


def fact_differences(verb, ours, theirs, context):
    """Each fact the two sessions disagree on, as `fact` disagreements; radare2-only `axt`
    references are unfilled, returned apart and not judged."""
    found, missed = [], []
    for (function, key), (mine, other, side) in sorted(analysis_facts(verb, ours, theirs).items(), key=order):
        if side in ("equal", "unplaced"):
            continue
        # An `afl` fact is an entry: the function it names.
        function = key if verb == "afl" else function
        detail = (verb, function, key, "r2" if side == "r2s" else "r2s", mine, other, context(function))
        if verb == "axt" and side == "r2":
            missed.append((verb, key))
        else:
            found.append(("fact", detail))
        if verb == "afl" and side == "r2":
            missed.append((verb, key))
    return found, missed


class Session:
    """One tool answering on stdin for one file, killed at its deadline."""

    def __init__(self, argv, timeout):
        self.started, self.timeout = time.monotonic(), timeout
        self.process = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, errors="surrogateescape",
        )
        self.lock, self.reaped = threading.Lock(), False
        self.timer = threading.Timer(timeout, self.kill)
        self.timer.start()

    def kill(self):
        """The deadline: SIGKILL while end() has not reaped the child, so its pid is still this child's."""
        with self.lock:
            if not self.reaped:
                os.kill(self.process.pid, signal.SIGKILL)

    def send(self, lines):
        """Write on a thread of its own: a tool answering while its pipe is full blocks the writer."""
        script = "\n".join(lines + [fence("end")]) + "\n"

        def write():
            try:
                self.process.stdin.write(script)
                self.process.stdin.flush()
            except (OSError, ValueError):
                pass

        self.writer = threading.Thread(target=write, daemon=True)
        self.writer.start()

    def receive(self):
        """The answers up to the closing fence; None once the session died."""
        closing, out = "{} end 0x0".format(SESSION_FENCE), []
        while True:
            line = self.process.stdout.readline()
            if not line:
                return None
            if line.rstrip("\n") == closing:
                return "\n".join(out)
            out.append(line.rstrip("\n"))

    def end(self):
        """(seconds, peak resident KiB, how it ended): `done`, `timeout` or `died`."""
        self.writer.join()
        try:
            self.process.stdin.close()
        except OSError:
            pass
        self.process.stdout.read()
        # Exited, still a zombie (WNOWAIT): the deadline may signal it until the flag is set.
        # macOS has waitid from Python 3.13; before it the deadline ends at stdout's close.
        if hasattr(os, "waitid"):
            os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOWAIT)
        with self.lock:
            self.reaped = True
        self.timer.cancel()
        _, status, usage = os.wait4(self.process.pid, 0)
        self.process.returncode = status
        took = time.monotonic() - self.started
        ended = "done" if status == 0 else "timeout" if took >= self.timeout else "died"
        return took, usage.ru_maxrss, ended


def analysed(binary, r2, r2s, timeout):
    """Both sessions' fenced answers after one `aa` each, or None, and each session's end."""
    ours = Session(r2s_argv(r2s, None, binary), timeout)
    theirs = Session(radare2_argv(r2, None, binary), timeout)
    ours.send([fence("ie"), "ie", fence("is"), "is", fence("iS"), "iS", "aa", fence("afl"), "afl", fence("aflj"), "aflj"])
    theirs.send([RESTORE, "aa", fence("afl"), "afl"])
    mine, other = ours.receive(), theirs.receive()
    if mine is not None and other is not None:
        mine, other = fenced(mine), fenced(other)
        mine[("fde", 0)] = frame_descriptions(binary, timeout)
        entries = stated_entries(mine.get(("ie", 0), []))
        listed_ours, listed_theirs = listed(mine.get(("afl", 0), [])), listed(other.get(("afl", 0), []))
        sample = analysis_sample(entries, listed_ours, listed_theirs)
        asked_ours, asked_theirs = [], []
        # An entry one side lists alone: what the other side records referencing it.
        for address in sorted(set(listed_theirs) - set(listed_ours)):
            asked_ours += [fence("refs", address), "axt @ {:#x}".format(address)]
        for address in sorted(set(listed_ours) - set(listed_theirs)):
            asked_theirs += [fence("refs", address), "axt @ {:#x}".format(address)]
        for address in sample:
            for verb in ("afb", "afi", "afv", "axt"):
                asked_ours += [fence(verb, address), "{} @ {:#x}".format(verb, address)]
            for verb in ("afb", "afi", "afvj", "afvf", "axt"):
                asked_theirs += [fence(verb, address), "{} @ {:#x}".format(verb, address)]
        for address in spaced(import_slots(mine.get(("is", 0), [])) - set(sample)):
            asked_ours += [fence("axt", address), "axt @ {:#x}".format(address)]
            asked_theirs += [fence("axt", address), "axt @ {:#x}".format(address)]
        ours.send(asked_ours)
        theirs.send(asked_theirs)
        second, third = ours.receive(), theirs.receive()
        if second is not None and third is not None:
            mine.update(fenced(second))
            other.update(fenced(third))
        else:
            mine = None
    ended = ours.end(), theirs.end()
    if mine is None or other is None or any(end[2] != "done" for end in ended):
        return None, ended
    return (mine, other), ended


def context_of(ours, theirs):
    """The context a fact judgment reads: the architecture, and the function's `afl` row."""
    arch = (ours.get(("arch", 0)) or [""])[0]
    rows = {**listed(theirs.get(("afl", 0), [])), **listed(ours.get(("afl", 0), []))}
    return lambda function: {"arch": arch, "function": rows.get(function, "{:#x}".format(function))}


def compare(name, command, mode, left, right, judgments, corpus=None):
    """Every disagreement, those no judgment covers, and the values only radare2 reports."""
    if mode in ANALYSIS_MODES:
        found, missed = fact_differences(command, left, right, context_of(left, right))
        unjudged = [item for item in found if judgment_for(judgments, name, command, item, corpus) is None]
        return found, unjudged, missed
    found = differences(command, mode, left, right)
    unjudged = [item for item in found if judgment_for(judgments, name, command, item, corpus) is None]
    missed = radare2_only(normalise(left), normalise(right)) if mode == "values" else []
    if mode == "pairs":
        ours, theirs = pairs(left.splitlines()), pairs(right.splitlines())
        missed = [(key, None) for key in POSTURE_KEYS if key in theirs and key not in ours]
    return found, unjudged, missed


def grade(corpus, binaries, commands, r2, r2s, judgments, args, misses=None):
    """One corpus: per command, binaries agreeing, judged, unjudged, and radare2-only values,
    unjudged (`r2-only`, ratcheted) and listed in `[[missed]]` (`r2-judged`)."""
    misses = Misses({}) if misses is None else misses
    tally = {
        command: {"agree": 0, "judged": 0, "unjudged": 0, "r2-only": 0, "r2-judged": 0} for command, _ in commands
    }
    unsupported, skipped = {}, []
    facts = {
        command: {"files": 0, "equal": 0, "r2s": 0, "r2": 0, "unplaced": 0}
        for command, mode in commands
        if mode in ANALYSIS_MODES
    }
    # The tools run in parallel; judging stays in name order, so the report and the matches do not move.
    with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
        ran = pool.map(lambda binary: answers(binary, commands, r2, r2s, args.timeout, corpus), binaries)
        for binary, (refused, said) in zip(binaries, ran):
            if refused is not None:
                unsupported[refused] = unsupported.get(refused, 0) + 1
                continue
            reported = False
            ended = said.get("aa")
            if ended is not None:
                if args.verbose:
                    print("{} aa: r2s {:.1f}s {} MiB {}, radare2 {:.1f}s {} MiB {}".format(
                        binary.name, ended[0][0], ended[0][1] // 1024, ended[0][2],
                        ended[1][0], ended[1][1] // 1024, ended[1][2]))
                if any(end[2] != "done" for end in ended):
                    skipped.append("{} aa".format(binary.name))
            for command, mode in commands:
                if mode in ANALYSIS_MODES and command not in said:
                    continue
                if said[command] is None:
                    skipped.append("{} {}".format(binary.name, command))
                    continue
                left, right = said[command]
                # A binary neither tool has anything to say about is not a difference.
                if mode == "registers" and left is None:
                    continue
                if mode in ANALYSIS_MODES:
                    for _, (_, _, side) in analysis_facts(command, left, right).items():
                        facts[command][side] += 1
                    facts[command]["files"] += 1
                elif mode != "registers" and not normalise(right) and not normalise(left):
                    continue

                found, unjudged, missed = compare(binary.name, command, mode, left, right, judgments, corpus)
                misses.ran.add((command.split()[0], binary.name))
                judged = [item for item in missed if misses.judged(binary.name, command, item)]
                missed = [item for item in missed if item not in judged]
                tally[command]["r2-only"] += len(missed)
                tally[command]["r2-judged"] += len(judged)
                if not found:
                    tally[command]["agree"] += 1
                elif not unjudged:
                    tally[command]["judged"] += 1
                else:
                    tally[command]["unjudged"] += 1
                if not unjudged and not (missed and args.verbose):
                    continue
                if not reported:
                    print(binary.name)
                    reported = True
                if unjudged:
                    print("    {} differs: {} unjudged of {}".format(command, len(unjudged), len(found)))
                    for difference in unjudged if args.verbose else unjudged[:1]:
                        print(spelled(difference))
                if missed and args.verbose:
                    print("    {} radare2 only: {}".format(command, len(missed)))
                    shown = [c if v is None else "{}={:#x}".format(c, v) if c else "{:#x}".format(v) for c, v in missed[:8]]
                    print("      " + " ".join(shown + (["..."] if len(missed) > 8 else [])))
    return tally, unsupported, skipped, facts


def ratchet(baseline, measured):
    """Each (corpus, count, before, now) that moved: radare2-only values per command, refusals."""
    moved = []
    for corpus, counts in sorted(measured.items()):
        for command, count in sorted(counts.items()):
            before = baseline.get(corpus, {}).get(command)
            if before != count:
                moved.append((corpus, command, before, count))
    return moved


def main():
    # A line holding an invalid byte prints as its escape.
    sys.stdout.reconfigure(errors="backslashreplace")
    here = pathlib.Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--r2", default=str(here.parent / "radare2/binr/radare2/radare2"))
    parser.add_argument("--r2s", default=str(here / "target/debug/r2s"))
    parser.add_argument(
        "--bins",
        nargs="+",
        default=[str(here.parent / "radare2/test/bins/elf")],
        help="corpus directories, each graded and ratcheted by its name",
    )
    parser.add_argument("--limit", type=int, help="the first N binaries of each corpus; no ratchet")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--jobs", type=int, default=os.cpu_count(), help="binaries run at once")
    parser.add_argument("--only", help="run just the commands whose verb matches this")
    parser.add_argument("--verbose", action="store_true", help="show each unjudged disagreement")
    parser.add_argument(
        "--judged",
        default=str(here / "scripts/diff_r2_judged.toml"),
        help="the judged disagreements",
    )
    parser.add_argument(
        "--baseline",
        default=str(here / "scripts/diff_r2_baseline.json"),
        help="radare2-only values per corpus and command, which may not rise",
    )
    parser.add_argument("--bless", action="store_true", help="write this run's counts as the baseline")
    parser.add_argument(
        "--upstream", action="store_true", help="list each judged radare2 defect with one instance it matched"
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="measure whatever binary is already there",
    )
    args = parser.parse_args()
    if args.bless and args.limit is not None:
        print("--bless needs whole corpora: drop --limit", file=sys.stderr)
        return 2

    # Build before measuring. The default binary is the debug one, which a
    # plain `cargo build --release` does not touch, so a run taken after one
    # reported the tree as it was several changes ago.
    if not args.no_build and args.r2s == str(here / "target/debug/r2s"):
        subprocess.run(
            ["cargo", "build", "-p", "r2s", "--features", "sleigh"],
            cwd=here,
            check=True,
        )

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

    corpora = {}
    for directory in map(pathlib.Path, args.bins):
        binaries = sorted(p for p in directory.iterdir() if p.is_file())[: args.limit]
        if not binaries:
            print("no binaries under {}".format(directory), file=sys.stderr)
            return 2
        corpora[directory.name] = binaries

    pinned, judgments = load_table(pathlib.Path(args.judged))
    misses = load_missed(pathlib.Path(args.judged))
    banner, _, _ = run([str(r2), "-v"], args.timeout)
    if pinned and release(banner) != pinned:
        print(
            "{} is radare2 {}; the judgments are against {} (build its tag, or CI's .deb)".format(
                r2, release(banner), pinned
            ),
            file=sys.stderr,
        )
        return 2

    unjudged, measured = 0, {}
    for corpus, binaries in corpora.items():
        print("== {} ({} binaries)".format(corpus, len(binaries)))
        tally, unsupported, skipped, facts = grade(corpus, binaries, commands, r2, r2s, judgments, args, misses)
        print("\n{:<8} {:>8} {:>8} {:>8} {:>8} {:>9}".format("command", "agree", "judged", "unjudged", "r2-only", "r2-judged"))
        print("-" * 54)
        for command, _ in commands:
            row = tally[command]
            print(
                "{:<8} {:>8} {:>8} {:>8} {:>8} {:>9}".format(
                    command, row["agree"], row["judged"], row["unjudged"], row["r2-only"], row["r2-judged"]
                )
            )
            unjudged += row["unjudged"]
        if any(row["files"] for row in facts.values()):
            print("\n{:<8} {:>8} {:>8} {:>8} {:>8} {:>8}".format("facts", "files", "equal", "r2s-only", "r2-only", "unplaced"))
            print("-" * 53)
            for command, row in facts.items():
                print("{:<8} {:>8} {:>8} {:>8} {:>8} {:>8}".format(
                    command, row["files"], row["equal"], row["r2s"], row["r2"], row["unplaced"]))
            print("{} files skipped by the aa sessions".format(sum(1 for s in skipped if s.endswith(" aa"))))
        # A binary r2s stops opening, or a run that times out, hides its values: both are ratcheted.
        ratcheted = ("values", "pairs", "entries", "references")
        measured[corpus] = {
            command.split()[0]: tally[command]["r2-only"] for command, mode in commands if mode in ratcheted
            and (mode not in ANALYSIS_MODES or corpus in ANALYSED_CORPORA)
        }
        measured[corpus]["refused"] = sum(unsupported.values())
        measured[corpus]["skipped"] = len(skipped)
        if skipped:
            print("\n{} runs skipped (timeout or launch failure): {}".format(len(skipped), ", ".join(skipped)))
        if unsupported:
            print("\nnot opened by r2s:")
            for reason, count in sorted(unsupported.items(), key=lambda item: -item[1]):
                print("  {:>4}  {}".format(count, reason))
        print()

    if args.upstream:
        # One idea per line: judgments naming the same upstream line are one entry, their matches summed.
        ideas = {}
        for judgment in judgments:
            if "upstream" in judgment and "instance" in judgment:
                ideas.setdefault(judgment["upstream"], []).append(judgment)
        print("radare2 defects (r2s-right with an upstream line), one instance each:")
        for idea, judged in ideas.items():
            binary, command, difference = judged[0]["instance"]
            print("  {} ({} matched)\n    {} {}".format(idea, sum(j["matched"] for j in judged), binary, command))
            print(spelled(difference))
        print()

    stale = [judgment for judgment in judgments if judgment["matched"] == 0]
    if stale:
        print("judgments nothing matched (stale, or outside these corpora):")
        for judgment in stale:
            print("  {} {}: {}".format(judgment["command"], judgment["binaries"], judgment["reason"]))
        print()

    # A listed radare2-only value its graded run no longer reports fails, so the table cannot outlive it.
    gone = unmatched_misses(misses)
    for verb, binary, value in gone:
        print("missed value nothing reported: {} {} {}".format(verb, binary, value if isinstance(value, str) else hex(value)))

    # A partial corpus says nothing about the whole one's count.
    risen = []
    if args.limit is None:
        path = pathlib.Path(args.baseline)
        baseline = json.loads(path.read_text()) if path.exists() else {}
        if args.bless:
            # A count is blessed upward only beside a refused binary r2s now opens (its misses arrive).
            for corpus, command, before, now in ratchet(baseline, measured):
                fell = measured[corpus]["refused"] < baseline.get(corpus, {}).get("refused", 0)
                if before is not None and now > before and command != "refused" and not fell:
                    print("{} {}: {} rose to {}; a rise is judged in [[missed]], never blessed".format(corpus, command, before, now))
                    return 1
            for corpus, counts in measured.items():
                baseline.setdefault(corpus, {}).update(counts)
            path.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n")
            print("blessed {}".format(path))
        else:
            for corpus, command, before, now in ratchet(baseline, measured):
                if before is None:
                    risen.append((corpus, command))
                    print("{} {}: {} with no baseline; --bless to start one".format(corpus, command, now))
                elif now > before:
                    risen.append((corpus, command))
                    # Opening a refused binary adds its misses: that rise is blessed with the fall.
                    refused = baseline.get(corpus, {}).get("refused"), measured[corpus]["refused"]
                    print("{} {}: {} rose to {} (refused {} to {})".format(corpus, command, before, now, *refused))
                else:
                    print("{} {}: {} fell to {}; --bless to keep it".format(corpus, command, before, now))
    return 1 if unjudged or risen or gone else 0


if __name__ == "__main__":
    sys.exit(main())
