#!/usr/bin/env python3
"""Count the casts in rendered C: doc/phase1-design.md section 1.

usage: tests/corpus/cast_census.py <file of rendered C>
  tests/coverage/sweep_binary.sh ./binary > sweep.txt; tests/corpus/cast_census.py sweep.txt

statements: lines ending in ';'. casts: every '(type)' applied to an operand,
split into those on a bare name and those on a parenthesised expression.
narrowing: a name cast to fewer bits than the name is declared with. never-at
declared width: declared names every read of which is a narrowing cast.
"""
import re
import sys
from collections import defaultdict

TYPE = r"(?:const\s+)?(?:unsigned\s+|signed\s+)?(?:u?int(?:8|16|32|64|128)_t|size_t|ssize_t|char|short|int|long|bool|float|double|void|struct\s+\w+|\w+_t)(?:\s*\*+)?"
CAST = re.compile(r"\((" + TYPE + r")\)\s*(\(|[A-Za-z_]\w*)")
DECL = re.compile(r"^\s*(" + TYPE + r")\s+([A-Za-z_]\w*)(?:\s*=|;)")
NAME = re.compile(r"\b([A-Za-z_]\w*)\b")
WIDTH = {"int8_t": 8, "uint8_t": 8, "char": 8, "bool": 8, "int16_t": 16, "uint16_t": 16, "short": 16,
         "int32_t": 32, "uint32_t": 32, "int": 32, "float": 32, "int64_t": 64, "uint64_t": 64,
         "size_t": 64, "ssize_t": 64, "long": 64, "double": 64}


def width_of(ty):
    ty = ty.replace("const ", "").strip()
    if "*" in ty:
        return 64
    return WIDTH.get(ty)


def main(path):
    text = open(path, errors="replace").read().splitlines()
    statements = sum(1 for line in text if line.rstrip().endswith(";"))
    declared = {}
    for line in text:
        m = DECL.match(line)
        if m and width_of(m.group(1)):
            declared[m.group(2)] = width_of(m.group(1))
    casts = on_name = on_expr = narrowing = 0
    reads = defaultdict(lambda: [0, 0])  # name -> [narrowing casts, other reads]
    for line in text:
        if DECL.match(line) and "=" not in line:
            continue
        cast_names = set()
        for m in CAST.finditer(line):
            casts += 1
            if m.group(2) == "(":
                on_expr += 1
                continue
            on_name += 1
            name = m.group(2)
            to = width_of(m.group(1))
            frm = declared.get(name)
            if to and frm and to < frm:
                narrowing += 1
                reads[name][0] += 1
                cast_names.add((name, m.start(2)))
        # every other mention of a declared name is a read at its declared
        # width, except the name being assigned or declared on this line.
        body = line
        m = DECL.match(line)
        if m:
            body = line[m.end():]
        elif "=" in line and not re.search(r"[=!<>]=", line.split("=", 1)[0] + "="):
            body = line.split("=", 1)[1]
        shift = len(line) - len(body)
        for m in NAME.finditer(body):
            name = m.group(1)
            if name in declared and (name, m.start(1) + shift) not in cast_names:
                reads[name][1] += 1
    never = {n: r[0] for n, r in reads.items() if r[0] and r[1] == 0}
    print(f"statements={statements} casts={casts} on_name={on_name} on_expr={on_expr} "
          f"narrowing_name_casts={narrowing} names_never_read_at_declared_width={len(never)} "
          f"their_casts={sum(never.values())}")


if __name__ == "__main__":
    main(sys.argv[1])
