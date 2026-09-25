"""The gate's self-tests: renderings whose verdict is known before the gate runs.

A gate that cannot tell a right rendering from a wrong one grades nothing, so
these run before any engine rendering is graded, and a single miss refuses the
run. Each case is a hand-written rendering of a function in
``selftest/fixture.c``, wrapped in the same ``pddj`` shape r2s prints, and
graded through the same path an engine rendering takes:

* the identities (a source-equivalent, UB-free rendering of every fixture
  function) must be ``equal``: the harness produces no false positive for
  integer, 64-bit, float, pointer, string, linked-struct, global-writing,
  buffer-writing, printing, libm-calling or stack-argument functions;
* one flipped operator, one off-by-one, two swapped stack-passed arguments and a
  32-bit parameter read as 64 bits must be ``differs`` (return);
* a read of an uninitialised local must be ``uninit``;
* a write to the wrong global and a wrong value written to the right global
  must be ``differs`` (memory);
* a wrong byte written through a pointer must be ``differs`` (arena);
* swapped arguments of a printf must be ``differs`` (stdout), and a dropped
  one ``differs``;
* a signed overflow must be ``ub``;
* a reached residual must be ``residual-trap``, also where the function prints
  on every vector and traps on some only; a trap outside every residual helper
  must be ``differs`` even when the proof counts a residual;
* a function that writes to stderr and then faults on its NULL vector must be
  ``equal`` on most of its vectors: a dropped vector's output is not carried
  into the next;
* a recursion through a link to the function's own entry, and one through a
  program function that calls it back, must be ``equal``: the rendering
  replaced the function in the image;
* a rendering that calls the original function's own entry must be
  ``differs``, delegation named; a link into the original's body must be
  ``compile-error``;
* an identifier missing from the link map must be ``compile-error``;
* a refusal must be ``refused``.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import gate
from dwarf import Dwarf, code_constants, function_symbols
from r2s_batch import Answer
from spec import call_spec

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "selftest" / "fixture.c"

_RESIDUAL_S32 = (
    "static inline int32_t r2sleigh_residual_s32(uint32_t site)\n"
    "{\n    (void)site;\n    __builtin_trap();\n}\n"
)
_NODE = "struct st_node { int32_t key; struct st_node *next; };\n"


@dataclass
class Case:
    name: str
    function: str
    expect: str
    code: str
    # (ident, kind), or (ident, kind, offset) for an address that many bytes
    # past the graded function's entry.
    links: list[tuple] = field(default_factory=list)
    expect_field: str | None = None
    residual: int = 0
    refused: str | None = None
    expect_guard: str | None = None


def _tu(body: str, headers: str = "#include <stdint.h>\n#include <stddef.h>\n") -> str:
    return headers + body


CASES = [
    # Identities: no false positives.
    Case("identity-int", "st_add", "equal", _tu(
        "int32_t sub_add(int32_t a, int32_t b)\n{\n"
        "    return (int32_t)((uint32_t)a + (uint32_t)b);\n}\n")),
    Case("identity-u64", "st_mix", "equal", _tu(
        "uint64_t sub_mix(uint64_t a, uint32_t b)\n{\n"
        "    return (a ^ (uint64_t)b) * 0x9e3779b97f4a7c15ull;\n}\n")),
    Case("identity-branches", "st_clamp", "equal", _tu(
        "int32_t sub_clamp(int32_t x)\n{\n    if (x < 0)\n        return 0;\n"
        "    if (x > 100)\n        return 100;\n    return x;\n}\n")),
    Case("identity-double", "st_scale", "equal", _tu(
        "double sub_scale(const double *v, int32_t n)\n{\n    double s = 0.0;\n"
        "    for (int32_t i = 0; i < n && i < 64; i++)\n        s += v[i];\n"
        "    return s * 0.5;\n}\n")),
    Case("identity-global", "st_bump", "equal", _tu(
        "extern int32_t st_counter;\nvoid sub_bump(int32_t by)\n{\n"
        "    st_counter = (int32_t)((uint32_t)st_counter + (uint32_t)by);\n}\n"),
        links=[("st_counter", "object")]),
    Case("identity-printf", "st_print", "equal", _tu(
        "int32_t sub_print(int32_t x, int32_t y)\n{\n"
        "    return printf(\"%d %d\\n\", x, y);\n}\n",
        "#include <stdint.h>\n#include <stdio.h>\n"),
        links=[("printf", "import")]),
    Case("identity-string", "st_len", "equal", _tu(
        "size_t sub_len(const char *s)\n{\n    size_t n = 0;\n"
        "    while (s[n])\n        n++;\n    return n;\n}\n")),
    Case("identity-list", "st_sum_list", "equal", _tu(
        _NODE + "int32_t sub_sum_list(const struct st_node *n)\n{\n    uint32_t total = 0;\n"
        "    while (n) {\n        total += (uint32_t)n->key;\n        n = n->next;\n    }\n"
        "    return (int32_t)total;\n}\n")),
    Case("identity-buffer-write", "st_fill", "equal", _tu(
        "void sub_fill(uint8_t *dst, size_t n, uint8_t v)\n{\n"
        "    for (size_t i = 0; i < n && i < 4096; i++)\n"
        "        dst[i] = (uint8_t)(v + i);\n}\n")),
    Case("identity-stack-arguments", "st_many", "equal", _tu(
        "int64_t sub_many(int64_t a, int64_t b, int64_t c, int64_t d, int64_t e, int64_t f,\n"
        "                 int32_t g, int64_t h)\n{\n"
        "    return (int64_t)((uint64_t)a + 3u * (uint64_t)b + 5u * (uint64_t)c\n"
        "        + 7u * (uint64_t)d + 11u * (uint64_t)e + 13u * (uint64_t)f\n"
        "        + 17u * (uint64_t)(int64_t)g + 19u * (uint64_t)h);\n}\n")),
    # stderr is written before the NULL vector faults: the dropped vector must
    # not shift what the original's later vectors are compared on.
    Case("identity-stderr-then-fault", "st_first", "equal", _tu(
        "int32_t sub_first(const char *p)\n{\n    fputs(\"first\\n\", stderr);\n"
        "    return (int32_t)(int8_t)p[0];\n}\n",
        "#include <stdint.h>\n#include <stdio.h>\n"),
        links=[("fputs", "import"), ("stderr", "import")]),
    # cos is libm's: the rendering links against what the original needs.
    Case("identity-libm-import", "st_cosine", "equal", _tu(
        "double sub_cosine(double x)\n{\n    return cos(x) * 2.0;\n}\n",
        "#include <math.h>\n"), links=[("cos", "import")]),
    Case("identity-stack-floats", "st_many_fp", "equal", _tu(
        "double sub_many_fp(double a, double b, double c, double d, double e, double f,\n"
        "                   double g, double h, double i)\n{\n"
        "    return a - b + c - d + e - f + g - h + 2.0 * i;\n}\n")),
    # Wrong renderings, each wrong in one way.
    Case("mutation-operator", "st_add", "differs", _tu(
        "int32_t sub_add(int32_t a, int32_t b)\n{\n"
        "    return (int32_t)((uint32_t)a - (uint32_t)b);\n}\n"), expect_field="return"),
    Case("mutation-off-by-one", "st_clamp", "differs", _tu(
        "int32_t sub_clamp(int32_t x)\n{\n    if (x < 0)\n        return 0;\n"
        "    if (x > 101)\n        return 100;\n    return x;\n}\n"), expect_field="return"),
    # The seventh and eighth integer arguments swapped: only the stack word and
    # the last register differ.
    Case("stack-argument-swapped", "st_many", "differs", _tu(
        "int64_t sub_many(int64_t a, int64_t b, int64_t c, int64_t d, int64_t e, int64_t f,\n"
        "                 int32_t g, int64_t h)\n{\n"
        "    return (int64_t)((uint64_t)a + 3u * (uint64_t)b + 5u * (uint64_t)c\n"
        "        + 7u * (uint64_t)d + 11u * (uint64_t)e + 13u * (uint64_t)f\n"
        "        + 19u * (uint64_t)(int64_t)g + 17u * (uint64_t)h);\n}\n"), expect_field="return"),
    # A 32-bit parameter read as 64 bits: the ABI leaves bits 32..63 to the caller.
    Case("narrow-parameter-read-wide", "st_mix", "differs", _tu(
        "uint64_t sub_mix(uint64_t a, uint64_t b)\n{\n"
        "    return (a ^ b) * 0x9e3779b97f4a7c15ull;\n}\n"), expect_field="return"),
    Case("uninitialised-read", "st_add", "uninit", _tu(
        "int32_t sub_add(int32_t a, int32_t b)\n{\n    uint32_t t;\n"
        "    if (a == 123456789)\n        t = 0;\n"
        "    return (int32_t)((uint32_t)a + (uint32_t)b + t);\n}\n")),
    Case("wrong-global", "st_bump", "differs", _tu(
        "extern int32_t st_other;\nvoid sub_bump(int32_t by)\n{\n"
        "    st_other = (int32_t)((uint32_t)st_other + (uint32_t)by);\n}\n"),
        links=[("st_other", "object")], expect_field="memory"),
    Case("wrong-global-value", "st_bump", "differs", _tu(
        "extern int32_t st_counter;\nvoid sub_bump(int32_t by)\n{\n"
        "    st_counter = (int32_t)((uint32_t)st_counter + (uint32_t)by + 1u);\n}\n"),
        links=[("st_counter", "object")], expect_field="memory"),
    Case("wrong-byte-through-pointer", "st_fill", "differs", _tu(
        "void sub_fill(uint8_t *dst, size_t n, uint8_t v)\n{\n"
        "    for (size_t i = 0; i < n && i < 4096; i++)\n"
        "        dst[i] = (uint8_t)(v + i + (i == 3));\n}\n"), expect_field="arena"),
    # The same characters in the other order: the count printf returns agrees,
    # so only the comparison of what reached fd 1 can see it.
    Case("printf-swapped-arguments", "st_print", "differs", _tu(
        "int32_t sub_print(int32_t x, int32_t y)\n{\n"
        "    return printf(\"%d %d\\n\", y, x);\n}\n",
        "#include <stdint.h>\n#include <stdio.h>\n"),
        links=[("printf", "import")], expect_field="stdout"),
    Case("printf-dropped-argument", "st_print", "differs", _tu(
        "int32_t sub_print(int32_t x, int32_t y)\n{\n    (void)y;\n"
        "    return printf(\"%d\\n\", x);\n}\n",
        "#include <stdint.h>\n#include <stdio.h>\n"),
        links=[("printf", "import")]),
    Case("signed-overflow", "st_add", "ub", _tu(
        "int32_t sub_add(int32_t a, int32_t b)\n{\n    return a + b;\n}\n")),
    Case("residual-reached", "st_clamp", "residual-trap", _tu(
        _RESIDUAL_S32 + "int32_t sub_clamp(int32_t x)\n{\n    if (x < 0)\n"
        "        return r2sleigh_residual_s32(1);\n    if (x > 100)\n        return 100;\n"
        "    return x;\n}\n"), residual=1),
    # Prints on every vector and traps on some: a vector the rendering trapped
    # on (its buffered output lost) must not skew the stdout of the next.
    Case("residual-reached-after-printing", "st_say", "residual-trap", _tu(
        _RESIDUAL_S32 + "int32_t sub_say(int32_t x)\n{\n    printf(\"%d\\n\", x);\n"
        "    if (x > 5)\n        return r2sleigh_residual_s32(1);\n    return x;\n}\n",
        "#include <stdint.h>\n#include <stdio.h>\n"),
        links=[("printf", "import")], residual=1),
    # A trap the rendering wrote itself is not a residual, whatever the proof
    # counters claim: only a trap inside a residual helper is.
    Case("trap-outside-a-residual", "st_clamp", "differs", _tu(
        "int32_t sub_clamp(int32_t x)\n{\n    if (x < 0)\n        __builtin_trap();\n"
        "    if (x > 100)\n        return 100;\n    return x;\n}\n"), residual=1,
        expect_field="exit"),
    # The function being graded is the rendering. Recursion spelled through a
    # link to its own entry reaches the rendering; a program function that
    # calls it back reaches the rendering; a rendering that hands its work to
    # the original's own code is never equal, and a link into the original's
    # body is refused.
    Case("recursion-through-its-own-link", "st_rsum", "equal", _tu(
        _NODE + "extern int32_t st_rsum(const struct st_node *);\n"
        "int32_t sub_rsum(const struct st_node *n)\n{\n"
        "    return n ? (int32_t)((uint32_t)n->key + (uint32_t)st_rsum(n->next)) : 0;\n}\n"),
        links=[("st_rsum", "function")]),
    Case("recursion-through-the-program", "st_ping", "equal", _tu(
        _NODE + "extern int32_t st_pong(const struct st_node *);\n"
        "int32_t sub_ping(const struct st_node *n)\n{\n"
        "    return n ? (int32_t)(1u + 2u * (uint32_t)st_pong(n->next)) : 0;\n}\n"),
        links=[("st_pong", "function")]),
    # Wrong only where the program calls it back (depth > 1): only a gate
    # whose rendering replaced the function in the image can see it.
    Case("wrong-only-when-called-back", "st_ping", "differs", _tu(
        _NODE + "extern int32_t st_pong(const struct st_node *);\n"
        "static int32_t depth;\n"
        "int32_t sub_ping(const struct st_node *n)\n{\n    int32_t r;\n    depth++;\n"
        "    if (!n)\n        r = depth > 1 ? 1000 : 0;\n    else\n"
        "        r = (int32_t)(1u + 2u * (uint32_t)st_pong(n->next));\n"
        "    depth--;\n    return r;\n}\n"),
        links=[("st_pong", "function")], expect_field="return"),
    Case("delegation-to-the-original", "st_add", "differs", _tu(
        "typedef int32_t (*st_add_fn)(int32_t, int32_t);\n"
        "int32_t sub_add(int32_t a, int32_t b)\n{\n"
        "    return ((st_add_fn){entry})(a, b);\n}\n"), expect_field="exit",
        expect_guard="delegated"),
    Case("link-into-its-own-body", "st_clamp", "compile-error", _tu(
        "extern int32_t st_clamp_tail(int32_t);\n"
        "int32_t sub_clamp(int32_t x)\n{\n    return st_clamp_tail(x);\n}\n"),
        links=[("st_clamp_tail", "function", 1)]),
    Case("link-map-gap", "st_bump", "compile-error", _tu(
        "extern int32_t st_counter;\nvoid sub_bump(int32_t by)\n{\n"
        "    st_counter = (int32_t)((uint32_t)st_counter + (uint32_t)by);\n}\n")),
    Case("refusal", "st_add", "refused", "", refused="the case says so"),
]


def build_fixture(cc: str, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = out_dir / "fixture"
    proc = subprocess.run(
        [cc, "-g", "-O2", "-no-pie", "-fno-pie", str(FIXTURE), "-o", str(binary), "-lm"],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"cannot build the self-test fixture:\n{proc.stderr}")
    return binary


def synthetic_pddj(case: Case, address: int, symbols: dict[str, int]) -> dict:
    definition = "sub_" + case.function[len("st_"):]
    links = []
    for ident, kind, *offset in case.links:
        where = address + offset[0] if offset else symbols.get(ident, 0)
        links.append({"ident": ident, "kind": kind, "addr": where, "size": None})
    return {
        "name": case.function,
        "addr": address,
        "definition": definition,
        "signature": "",
        "refused": {"reason": case.refused} if case.refused else None,
        "code": case.code.replace("{entry}", f"0x{address:x}"),
        "proof": {"rendered": 1, "elided": 0, "refused": 0, "residual": case.residual,
                  "split": 0, "compiler_inserted": 0, "assumed": 0},
        "variables": [],
        "lines": [],
        "links": links,
    }


@dataclass
class Outcome:
    case: Case
    record: gate.Record
    ok: bool
    why: str


def run_self_tests(config: gate.Config, workdir: Path,
                   only: list[str] | None = None) -> list[Outcome]:
    binary = build_fixture(config.cc, workdir)
    dwarf = Dwarf.read(binary)
    functions = [s for s in dwarf.subprograms() if s.name]
    by_name = {s.name: s for s in functions}
    symbols = _all_symbols(binary)
    extents = function_symbols(binary)
    outcomes: list[Outcome] = []
    for case in CASES:
        if only and case.name not in only:
            continue
        sub = by_name[case.function]
        spec = call_spec(dwarf, sub, functions)
        spec.extent = extents.get(sub.low_pc, ([], 0))[1]
        spec.constants = code_constants(binary, sub.low_pc, spec.extent)
        record = synthetic_pddj(case, sub.low_pc, symbols)
        if case.refused:
            answer = Answer(sub.low_pc, "decline", record=record, cause=f"refused: {case.refused}",
                            refusal=case.refused)
        else:
            answer = Answer(sub.low_pc, "output", record=record)
        graded = gate.grade(f"selftest::{case.name}", workdir / case.name, binary, dwarf, spec,
                            answer, config)
        ok = graded.status == case.expect
        why = f"expected {case.expect}, got {graded.status}"
        if ok and case.expect_field:
            got_field = graded.evidence.get("field")
            ok = got_field == case.expect_field
            why = f"expected field {case.expect_field}, got {got_field}"
        if ok and case.expect_guard:
            got_guard = graded.evidence.get("guard")
            ok = got_guard == case.expect_guard
            why = f"expected guard {case.expect_guard}, got {got_guard}"
        if ok and case.expect == "equal" and graded.vectors.get("graded", 0) < config.vectors // 2:
            ok = False
            why = f"only {graded.vectors.get('graded')} of {config.vectors} vectors were graded"
        outcomes.append(Outcome(case, graded, ok, "" if ok else why))
    return outcomes


def _all_symbols(binary: Path) -> dict[str, int]:
    proc = subprocess.run(["nm", str(binary)], capture_output=True, text=True, check=False)
    out: dict[str, int] = {}
    for line in proc.stdout.splitlines():
        fields = line.split()
        if len(fields) == 3:
            try:
                out.setdefault(fields[2], int(fields[0], 16))
            except ValueError:
                continue
    return out


if __name__ == "__main__":  # pragma: no cover - manual entry point
    import sys

    sys.exit("run tests/equiv/run_equiv.py --self-test-only")
