#!/usr/bin/env python3
"""Per-function parameter count, and the longest identifiers in the tree.

A long parameter list is a group of values that always travel together and have
not been named; a long identifier is usually a sentence where a word would do.
"""
import re, sys, pathlib

FN = re.compile(r'^\s*(pub(\([a-z()]+\))?\s+)?(const\s+|async\s+|unsafe\s+)*fn (\w+)\s*(<[^>]*>)?\s*\(', re.M)

def params(text, i):
    depth, buf = 0, []
    for ch in text[i:]:
        if ch == '(':
            depth += 1
            if depth == 1:
                continue
        elif ch == ')':
            depth -= 1
            if depth == 0:
                break
        if depth >= 1:
            buf.append(ch)
    sig = ''.join(buf)
    out, d = [], 0
    cur = ''
    for ch in sig:
        if ch in '<([': d += 1
        elif ch in '>)]': d -= 1
        if ch == ',' and d == 0:
            out.append(cur); cur = ''
        else:
            cur += ch
    if cur.strip(): out.append(cur)
    return [p.strip() for p in out if p.strip() and p.strip() != '&self' and p.strip() != 'self' and p.strip() != '&mut self']

rows, names = [], {}
for path in sorted(pathlib.Path('crates').rglob('*.rs')):
    if 'tests' in path.parts or path.name == 'tests.rs':
        continue
    text = path.read_text()
    for m in FN.finditer(text):
        n = len(params(text, m.end() - 1))
        line = text[:m.start()].count('\n') + 1
        rows.append((n, str(path), m.group(4), line))
    for ident in re.findall(r'\b[a-z_][a-z0-9_]{24,}\b', text):
        names[ident] = names.get(ident, 0) + 1

mode = sys.argv[1] if len(sys.argv) > 1 else 'args'
if mode == 'args':
    rows.sort(key=lambda r: -r[0])
    print(f"{'args':>4}  location")
    for n, p, f, l in rows[:20]:
        print(f"{n:4d}  {p}:{l} {f}")
else:
    for ident, count in sorted(names.items(), key=lambda kv: (-len(kv[0]), -kv[1]))[:20]:
        print(f"{len(ident):3d} x{count:<4d} {ident}")
