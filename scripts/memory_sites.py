#!/usr/bin/env python3
"""Memory sites in `pddj` records: the round 18 output counters (ROADMAP D640, doc/adr-memory-places.md).

  memory_sites.py count DIR... [--bins BINDIR...]      every counter, summed, and the address class table
  memory_sites.py diff BASE HEAD [BASE HEAD ...] [--bins BINDIR...]
                                                       each counter base to head and the functions it
                                                       moved; exit 1 when a "down" counter rises or a
                                                       "typed" counter falls

DIR holds `<project>_<binary>.json` files mapping an address to a `pddj` record, or to
`{"record": ...}` as `designs/memtypes/tools/dump.py` writes. A site is one call of
`r2sleigh_load_uN` or `r2sleigh_store_uN` in the body; a `static inline` prelude definition is
no site. `--bins` names one binary root per DIR (or per pair), searched as `ROOT/<project>/stripped/
<binary>`, `ROOT/<project>/<binary>` and `ROOT/<binary>`; without it the constant address classes
report as one. Cost: O(code bytes) per function, the class chase memoised per function.
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import struct
import sys
from pathlib import Path

CALL = re.compile(r"r2sleigh_(load|store)_u(\d+)\(")
RESIDUAL = re.compile(r"r2sleigh_residual_\w+\(\d+\)")
PROOF = "/* r2dec proof"
EXTERN = re.compile(r"^\s*extern\s+(.*?)\s*\b([A-Za-z_]\w*)\s*(\[\s*\])?\s*;\s*$", re.M)
NARROW = re.compile(r"^(u?int(8|16|32)_t)$")
NARROW_PARAM = re.compile(r"^(u?int(8|16|32)_t|r2sleigh_word_u(8|16|32))$")
PTRLIKE = ("param", "stack", "gsym", "gconst", "call", "loaded", "residual", "pfield")
ASSIGN = re.compile(r"^\s*(?:(?:const\s+)?[A-Za-z_]\w*\s+\**)?([A-Za-z_]\w*) = (.*);\s*$")
TOKEN = re.compile(
    r"\s*(0x[0-9a-fA-F]+[uUlL]*|\d+[uUlL]*|[A-Za-z_]\w*|->|<<|>>|<=|>=|==|!=|&&|\|\||[-+*/%&|^~!<>()?:,.\[\]=;{}])"
)
TYPEWORDS = re.compile(
    r"^(u?int(8|16|32|64)_t|void|char|short|int|long|unsigned|signed|float|double|_Bool|bool|size_t"
    r"|struct|union|const|r2sleigh_\w+|[A-Za-z_]\w*_t)$"
)
LITERALS = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)
BINARY = {"||": 1, "&&": 2, "|": 3, "^": 4, "&": 5, "==": 6, "!=": 6, "<": 7, ">": 7, "<=": 7, ">=": 7,
          "<<": 8, ">>": 8, "+": 9, "-": 9, "*": 10, "/": 10, "%": 10}

# The counters; "down" ones fail `diff` on a rise, "typed" ones on a fall.
DOWN = ("loads", "stores", "residual_sites")
TYPED = ("typed_address_sites", "lvalue_sites", "named_frame_objects", "typed_pointer_locals")
COUNTERS = DOWN + TYPED + ("unparsed",)


def tokens(text):
    out, i = [], 0
    while i < len(text):
        m = TOKEN.match(text, i)
        if not m:
            if text[i:].strip() == "":
                break
            raise ValueError("token " + text[i:i + 20])
        out.append(m.group(1))
        i = m.end()
    return out


class Parser:
    """The C subset `pdd` prints in an address argument."""

    def __init__(self, toks):
        self.t, self.i = toks, 0

    def peek(self, k=0):
        return self.t[self.i + k] if self.i + k < len(self.t) else None

    def eat(self, want=None):
        v = self.peek()
        if v is None or (want is not None and v != want):
            raise ValueError(f"want {want} got {v}")
        self.i += 1
        return v

    def is_cast(self):
        if self.peek() != "(":
            return False
        j, seen = self.i + 1, False
        while j < len(self.t) and self.t[j] != ")":
            w = self.t[j]
            if w == "*" or TYPEWORDS.match(w) or self.t[j - 1] in ("struct", "union"):
                seen, j = True, j + 1
                continue
            return False
        return seen and j < len(self.t)

    def expr(self, prec=0):
        left = self.unary()
        while True:
            op = self.peek()
            if op == "?" and prec == 0:
                self.eat()
                a = self.expr()
                self.eat(":")
                left = ("?", left, a, self.expr())
                continue
            if op not in BINARY or BINARY[op] < prec:
                return left
            self.eat()
            left = ("bin", op, left, self.expr(BINARY[op] + 1))

    def unary(self):
        v = self.peek()
        if self.is_cast():
            self.eat("(")
            ty = []
            while self.peek() != ")":
                ty.append(self.eat())
            self.eat(")")
            return ("cast", " ".join(ty), self.unary())
        if v in ("&", "*", "-", "~", "!"):
            self.eat()
            return ("un", v, self.unary())
        return self.postfix()

    def postfix(self):
        e = self.primary()
        while True:
            v = self.peek()
            if v == "(":
                self.eat()
                args = []
                if self.peek() != ")":
                    args.append(self.expr())
                    while self.peek() == ",":
                        self.eat()
                        args.append(self.expr())
                self.eat(")")
                e = ("call", e, args)
            elif v in ("->", "."):
                self.eat()
                e = ("mem", v, e, self.eat())
            elif v == "[":
                self.eat()
                ix = self.expr()
                self.eat("]")
                e = ("idx", e, ix)
            else:
                return e

    def primary(self):
        v = self.eat()
        if v == "(":
            e = self.expr()
            self.eat(")")
            return e
        m = re.match(r"^(0x[0-9a-fA-F]+|\d+)", v)
        if m:
            return ("num", int(m.group(1), 0))
        if re.match(r"^[A-Za-z_]\w*$", v):
            return ("id", v)
        raise ValueError("primary " + v)


def parse(text):
    p = Parser(tokens(text))
    e = p.expr()
    if p.i != len(p.t):
        raise ValueError("trailing " + " ".join(p.t[p.i:p.i + 5]))
    return e


def args_at(code, i):
    """The top-level arguments of the call whose `(` ends just before `i`."""
    depth, start, out = 0, i, []
    for j in range(i, len(code)):
        ch = code[j]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                out.append(code[start:j].strip())
                return out
            depth -= 1
        elif ch == "," and depth == 0:
            out.append(code[start:j].strip())
            start = j + 1
    return out


def body_of(code):
    """The function body: from the proof comment on, or the text without `static inline` definitions."""
    at = code.find(PROOF)
    if at >= 0:
        return code[at:]
    return re.sub(r"^static inline [^\n]*\n\{\n.*?^\}\n", "", code, flags=re.S | re.M)


def elf_sections(path):
    """Allocated ELF64 little-endian sections as sorted (start, end, name); () for anything else."""
    b = Path(path).read_bytes()
    if b[:4] != b"\x7fELF" or b[4] != 2 or b[5] != 1:
        return ()
    shoff, = struct.unpack_from("<Q", b, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", b, 0x3a)
    hdr = [struct.unpack_from("<IIQQQQIIQQ", b, shoff + i * shentsize) for i in range(shnum)]
    names = hdr[shstrndx][4]
    out = []
    for name, _, flags, addr, _, size, *_ in hdr:
        if addr and flags & 2:
            end = b.index(b"\0", names + name)
            out.append((addr, addr + size, b[names + name:end].decode()))
    return tuple(sorted(out))


def where(secs, addr):
    for start, end, name in secs:
        if start <= addr < end:
            return name
    return None


def const(e):
    while e[0] == "cast":
        e = e[2]
    if e[0] == "num":
        return e[1]
    if e[0] == "bin" and e[1] == "*":
        a, b = const(e[2]), const(e[3])
        if a is not None and b is not None:
            return a * b
    return None


def terms(e, sign=1, out=None):
    out = [] if out is None else out
    while e[0] == "cast" and not NARROW.match(e[1]):
        e = e[2]
    if e[0] == "bin" and e[1] in "+-":
        terms(e[2], sign, out)
        terms(e[3], sign if e[1] == "+" else -sign, out)
        return out
    out.append((sign, e))
    return out


def scaled(e):
    while e[0] == "cast" and not NARROW.match(e[1]):
        e = e[2]
    return e[0] == "bin" and e[1] in ("*", "<<") and (const(e[2]) is not None or const(e[3]) is not None)


def norm(origins):
    o = {x for x in origins if not x.startswith("undef")} or origins
    p = [x for x in ("stack", "param", "pfield", "gsym", "gconst", "call", "loaded", "residual") if x in o]
    if len(p) == 1:
        return p[0]
    if len(p) > 1:
        return "mixed:" + "+".join(p)
    return "int/other:" + "+".join(sorted(o))


class Function:
    """One body's assignments, chased from an address's base to its roots (memoised per name)."""

    def __init__(self, body, params, secs):
        self.defs = collections.defaultdict(list)
        for line in body.split("\n"):
            m = ASSIGN.match(line)
            if m:
                try:
                    self.defs[m.group(1)].append(parse(m.group(2)))
                except (ValueError, IndexError):
                    self.defs[m.group(1)].append(("bad",))
        self.params, self.secs, self.memo, self.tag = params, secs, {}, False

    def origin(self, e, stack=()):
        k = e[0]
        if k == "cast":
            return {"int"} if NARROW.match(e[1]) else self.origin(e[2], stack)
        if k == "num":
            return {"gconst"} if where(self.secs, e[1]) else {"int"}
        if k == "id":
            return self.name_origin(e[1], stack)
        if k == "un":
            if e[1] != "&":
                return {"int"}
            t = e[2]
            if t[0] == "mem":
                o = self.origin(t[2], stack)
                return {"pfield"} if "param" in o else {"field:" + "/".join(sorted(o))}
            return {"gsym"} if t[0] == "id" else {"addr"}
        if k == "call":
            f = e[1][1] if e[1][0] == "id" else "?"
            if f.startswith("r2sleigh_load"):
                # The inner chase runs untagged too: its memo entries fix the measure's table.
                inner = norm(self.origin(e[2][0], stack)) if e[2] else "?"
                return {"loaded<" + inner.split(":")[0] + ">"} if self.tag else {"loaded"}
            if f.startswith("r2sleigh_residual"):
                return {"residual"}
            if f.startswith("r2sleigh_carrier"):
                return self.origin(e[2][0], stack)
            return {"int"} if f.startswith("r2sleigh_") else {"call"}
        if k == "bin":
            return self.sum_origin(e, stack) if e[1] in ("+", "-") else {"int"}
        if k == "?":
            return self.origin(e[2], stack) | self.origin(e[3], stack)
        return {"other"}

    def name_origin(self, n, stack):
        if n in self.params or re.match(r"^arg\d+$", n):
            return {"int"} if NARROW_PARAM.match(self.params.get(n, "")) else {"param"}
        if n == "frame":
            return {"stack"}
        if (n, self.tag) in self.memo:
            return self.memo[(n, self.tag)]
        if n in stack:
            return set()
        if len(stack) > 64:
            return {"deep"}
        if n not in self.defs:
            return {"undef:global"}
        o = set()
        for d in self.defs[n]:
            o |= self.origin(d, stack + (n,))
        self.memo[(n, self.tag)] = o
        return o

    def sum_origin(self, e, stack):
        ca, cb = const(e[2]), const(e[3])
        if ca is not None or cb is not None:
            if ca is not None and cb is not None:
                return {"gconst"} if where(self.secs, ca + cb) else {"int"}
            other, k = (e[3], ca) if ca is not None else (e[2], cb)
            o = self.origin(other, stack)
            ptr = {x for x in o if x in PTRLIKE}
            if ptr:
                return ptr
            return {"gconst"} if e[1] == "+" and where(self.secs, k) else o
        a = self.origin(e[2], stack)
        b = self.origin(e[3], stack) if e[1] == "+" else {"int"}
        ptr = {x for x in a | b if x in PTRLIKE}
        return ptr or (a | b)


def shape_of(fn, e, secs):
    """The address's shape: (kind, base[, loaded-from])."""
    ts = terms(e)
    rest = [t for _, t in ts if const(t) is None]
    idx = [t for t in rest if scaled(t)]
    bases = [t for t in rest if not scaled(t)]
    off = sum(sg * c for sg, t in ts if (c := const(t)) is not None)
    if not rest:
        return ("global-const", where(secs, off) or "none")
    for b in bases:
        while b[0] == "cast":
            b = b[2]
        if b[0] == "un" and b[1] == "&":
            if b[2][0] == "mem":
                return ("typed-field", norm(fn.origin(b[2][2])))
            if b[2][0] == "id":
                return ("global-sym", "indexed" if idx or len(bases) > 1 else "const")
    origins = [norm(fn.origin(b)) for b in bases]
    ptr = [o for o in origins if not o.startswith("int/other")]
    shape = "indexed" if idx or len(bases) > 1 else "const"
    if "stack" in ptr or any(o.startswith("mixed") and "stack" in o for o in ptr):
        return ("stack", shape)
    if len(set(ptr)) == 1:
        base = ptr[0]
    elif ptr:
        base = "mixed:" + "+".join(sorted(set(ptr)))
    elif where(secs, off):
        return ("global-indexed", where(secs, off))
    else:
        base = "none:" + ("+".join(sorted(set(origins))) if origins else "index-only")
    if base in ("gconst", "gsym"):
        return ("global-derived", shape)
    if base == "loaded":
        fn.tag = True
        sub = set()
        for b in bases:
            sub |= {x for x in fn.origin(b) if x.startswith("loaded<")}
        fn.tag = False
        return ("ptr-" + shape, "loaded", sorted(sub)[0] if len(sub) == 1 else "loaded<mixed>")
    return ("ptr-" + shape, base)


def class_of(shape, have_bins):
    """The measure's class name (designs/memtypes/measure-r2s.md section 2) for a shape."""
    k, base = shape[0], shape[1]
    if k == "stack":
        return "A1 stack, frame + K" if base == "const" else "A2 stack, frame + K + i"
    if k == "global-sym":
        return "B1 global, named symbol"
    if not have_bins and k in ("global-const", "global-indexed", "global-derived"):
        return "B2-B4 global, constant address (no --bins)"
    if k == "global-const":
        return "B2 global, constant address, " + (".bss" if base == ".bss" else "data/ro/got")
    if k == "global-indexed":
        return "B3 global, constant base + integer index"
    if k == "global-derived":
        return "B4 global, pointer arithmetic on a global"
    if k == "typed-field":
        return "C1 parameter field, typed" if base == "param" else "C1b typed field, base " + base
    if k == "ptr-const" and base == "param":
        return "C2 parameter + constant, byte arithmetic"
    if k == "ptr-indexed" and base != "residual" and not base.startswith(("mixed", "none")):
        return "D pointer + index, base " + base
    if k == "ptr-const" and base == "call":
        return "E call result + constant"
    if k == "ptr-const" and base == "loaded":
        return "F loaded pointer + constant"
    if base == "residual":
        return "G residual base"
    if base.startswith("mixed"):
        return "G merge of origins"
    return "G integer-derived, unresolved"


def declared_objects(code):
    """Names an `extern` line declares with a type; `char name[]` is the untyped byte placeholder."""
    out = set()
    for m in EXTERN.finditer(code):
        ty, name, array = m.group(1), m.group(2), m.group(3)
        if "(" in ty:
            continue
        if not (array and ty == "char"):
            out.add(name)
    return out


def typed_address(e, declared):
    while e[0] == "cast":
        e = e[2]
    if e[0] != "un" or e[1] != "&":
        return False
    t = e[2]
    if t[0] in ("mem", "idx"):
        return True
    return t[0] == "id" and t[1] in declared


def lvalue_sites(body, names):
    """Member chains, declared objects and named frame objects spelled outside `&` and outside a helper."""
    count = 0
    for line in LITERALS.sub(" ", body).split("\n"):
        if CALL.search(line) is None and ("->" not in line and "." not in line) and not names:
            continue
        try:
            toks = tokens(line)
        except ValueError:
            continue
        i = 0
        while i < len(toks):
            tok = toks[i]
            if not re.match(r"^[A-Za-z_]\w*$", tok) or (i > 0 and toks[i - 1] in ("->", ".")):
                i += 1
                continue
            j, member = i + 1, False
            while j < len(toks) and toks[j] in ("->", ".", "["):
                if toks[j] == "[":
                    depth = 0
                    while j < len(toks):
                        depth += toks[j] == "["
                        depth -= toks[j] == "]"
                        j += 1
                        if depth == 0:
                            break
                else:
                    member, j = True, j + 2
            addressed = i > 0 and toks[i - 1] == "&"
            if not addressed and (member or tok in names) and not tok.startswith("r2sleigh_"):
                count += 1
            i = max(j, i + 1)
    return count


def find_binary(root, key):
    project, _, binary = key.partition("_")
    for path in (root / project / "stripped" / binary, root / project / binary, root / binary):
        if path.is_file():
            return path
    return None


def records(directory):
    for path in sorted(Path(directory).glob("*.json")):
        for address, value in json.loads(path.read_text()).items():
            yield path.stem, address, value.get("record") or value


def measure(record, secs, have_bins):
    """One function's counters and its sites' classes."""
    code = record.get("code") or ""
    body = body_of(code)
    variables = record.get("variables")
    params = {v["name"]: v["type"] for v in variables or [] if v.get("kind") == "param"}
    frame_objects = {v["name"] for v in variables or []
                     if (v.get("location") or "").startswith("stack") and v["name"] != "frame"}
    declared = declared_objects(code)
    fn = Function(body, params, secs)
    c = collections.Counter()
    classes = collections.Counter()
    for m in CALL.finditer(body):
        kind = m.group(1)
        c[kind + "s"] += 1
        args = args_at(body, m.end())
        try:
            e = parse(args[0] if args else "")
        except (ValueError, IndexError):
            c["unparsed"] += 1
            classes[("unparsed", kind)] += 1
            continue
        c["typed_address_sites"] += typed_address(e, declared)
        classes[(class_of(shape_of(fn, e, secs), have_bins), kind)] += 1
    c["residual_sites"] = len(RESIDUAL.findall(body))
    if "residuals" in record and c["residual_sites"] != len(record["residuals"]):
        raise SystemExit(f"{record.get('name')}: {c['residual_sites']} residual sites, "
                         f"{len(record['residuals'])} residuals listed")
    if variables is not None:
        c["lvalue_sites"] = lvalue_sites(body, declared | frame_objects)
        c["named_frame_objects"] = len(frame_objects)
        c["typed_pointer_locals"] = sum(1 for v in variables
                                        if v.get("kind") == "local" and (v.get("type") or "").endswith("*"))
    return c, classes


def collect(dirs, bins):
    """Per function counters keyed by (set, file, address), and the class table."""
    per, table = {}, collections.Counter()
    for n, directory in enumerate(dirs):
        root = Path(bins[n]) if n < len(bins) else None
        secs_of = {}
        for key, address, record in records(directory):
            if key not in secs_of:
                path = find_binary(root, key) if root else None
                secs_of[key] = elf_sections(path) if path else ()
            c, classes = measure(record, secs_of[key], root is not None)
            per[(Path(directory).name, key, address)] = c
            table.update(classes)
            for k in {k[0] for k in classes}:
                table[(k, "fns")] += 1
    return per, table


def totals(per):
    out = collections.Counter()
    for c in per.values():
        out.update(c)
    return out


def print_table(table, out):
    loads = sum(v for (k, kind), v in table.items() if kind == "load")
    stores = sum(v for (k, kind), v in table.items() if kind == "store")
    names = sorted({k for (k, kind) in table if kind in ("load", "store")})
    out.append(f"{'class':48} {'loads':>7} {'stores':>7} {'fns':>5}")
    for k in names:
        out.append(f"{k:48} {table[(k, 'load')]:7} {table[(k, 'store')]:7} {table[(k, 'fns')]:5}")
    out.append(f"{'sum':48} {loads:7} {stores:7}")


def count(args):
    per, table = collect(args.dirs, args.bins or [])
    t = totals(per)
    out = [f"functions {len(per)}"] + [f"{k} {t[k]}" for k in COUNTERS]
    print_table(table, out)
    print("\n".join(out))
    return 0


def diff(args):
    if len(args.dirs) % 2:
        raise SystemExit("diff takes BASE HEAD pairs")
    bins = args.bins or []
    base, head = {}, {}
    for n in range(0, len(args.dirs), 2):
        pair_bins = bins[n // 2:n // 2 + 1]
        b, _ = collect([args.dirs[n]], pair_bins)
        h, _ = collect([args.dirs[n + 1]], pair_bins)
        base.update({(n,) + k[1:]: v for k, v in b.items()})
        head.update({(n,) + k[1:]: v for k, v in h.items()})
    tb, th = totals(base), totals(head)
    failed = False
    for k in COUNTERS:
        bad = (k in DOWN and th[k] > tb[k]) or (k in TYPED and th[k] < tb[k])
        failed |= bad
        print(f"{k} {tb[k]} -> {th[k]}{'  FAIL' if bad else ''}")
        moved = sorted(f for f in base.keys() & head.keys() if base[f][k] != head[f][k])
        for f in moved[:args.show]:
            print(f"  {f[1]} {f[2]}: {base[f][k]} -> {head[f][k]}")
    missing = sorted(base.keys() ^ head.keys())
    if missing:
        print(f"functions in one side only: {len(missing)}")
    return 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("count")
    p.add_argument("dirs", nargs="+")
    p.add_argument("--bins", nargs="+")
    p.set_defaults(func=count)
    p = sub.add_parser("diff")
    p.add_argument("dirs", nargs="+")
    p.add_argument("--bins", nargs="+")
    p.add_argument("--show", type=int, default=20)
    p.set_defaults(func=diff)
    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
