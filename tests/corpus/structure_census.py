#!/usr/bin/env python3
"""Per-function branch count and true loop-nesting depth, by brace depth.

Sequential loops are not nesting: a function with eleven `for` blocks one after
another is a list of rules, while one `for` inside another is where cost and
confusion actually compound. Depth is measured by tracking the brace depth each
loop opened at and counting how many are still open.
"""
import re, sys, pathlib

LOOP = re.compile(r'^(for |while |loop\s*\{)')
BRANCH = re.compile(r'^(\}\s*)?(else\s+if|if|match)\b')

def scan(path):
    out = []
    depth = 0
    fn = None
    for i, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.split('//')[0]
        stripped = line.strip()
        if fn is None and re.match(r'^\s*(pub(\([a-z()]+\))?\s+)?(const\s+|async\s+|unsafe\s+)*fn \w+', line):
            fn = {'name': re.search(r'fn (\w+)', line).group(1), 'line': i,
                  'base': depth, 'branches': 0, 'loops': [], 'maxdepth': 0}
        if fn:
            if BRANCH.match(stripped):
                fn['branches'] += 1
            if LOOP.match(stripped):
                fn['loops'].append(depth)
                fn['maxdepth'] = max(fn['maxdepth'], len(fn['loops']))
        depth += line.count('{') - line.count('}')
        if fn:
            fn['loops'] = [d for d in fn['loops'] if d < depth]
            if depth <= fn['base']:
                out.append((fn['maxdepth'], fn['branches'], i - fn['line'], str(path), fn['name'], fn['line']))
                fn = None
    return out

rows = []
for path in sorted(pathlib.Path('crates').rglob('*.rs')):
    if 'tests' in path.parts or path.name == 'tests.rs':
        continue
    rows += scan(path)
want = sys.argv[1:] 
if want:
    rows = [r for r in rows if r[4] in want]
else:
    rows.sort(key=lambda r: (-r[0], -r[1]))
    rows = rows[:20]
print(f"{'nest':>4} {'branch':>6} {'lines':>5}  location")
for d, b, n, p, f, fl in rows:
    print(f"{d:4d} {b:6d} {n:5d}  {p}:{fl} {f}")
