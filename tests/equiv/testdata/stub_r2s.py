#!/usr/bin/env python3
"""A stand-in for r2s that answers ``pddj`` the way the contract says r2s does.

It exists to test the harnesses that talk to r2s -- the batch runner, the
equivalence gate's orchestration and the DecBench adapter -- without the
engine, and in particular to make r2s fail in each of the ways a harness has
to survive. It is never a rendering source for a real measurement.

    stub_r2s.py -q -c '<statements>' <binary>
    stub_r2s.py -q <binary>          # one script per stdin line, like r2s

``?e`` prints its text, ``s`` seeks, ``pddj`` answers for the current address,
``afl`` lists ``$STUB_R2S_AFL`` (``0x1000 main,0x2000 -``), anything else is an
unknown command. ``STUB_R2S_MODE`` picks the answer:

* ``minimal``   a valid record with an empty body (the default);
* ``fixture``   for a function of the gate's own fixture
                (``selftest/fixture.c``), the self-test rendering whose verdict
                is known (its first ``equal`` or ``residual-trap`` case); a
                refusal for any other function;
* ``delegate``  a rendering that calls the original function through its
                address, spelled from the unstripped twin's DWARF: what a
                rendering that hands its work back to the original looks like,
                which the gate must never grade ``equal``;
* ``refuse``    a record whose ``refused`` is set.

The unstripped twin of the binary r2s is shown is the binary path minus
``.stripped``: only this stand-in, never r2s, looks there.

``STUB_R2S_FAULTS`` is a comma list of ``<kind>@<hex address>`` applied when
``pddj`` runs there: ``abort`` (SIGABRT), ``sleep`` (hang for a minute),
``error`` (a ``r2s: ...`` line to stderr and a failed statement), ``garbage``
(text that is not JSON), ``breach`` (JSON missing contract fields),
``unterminated`` (the answer without its trailing newline), ``elsewhere`` (an
answer about another address). A fault named ``once-<kind>`` fires only in the
first process that reaches it (tracked in ``$STUB_R2S_STATE``), so a restart
can be told from a retry. As the whole mode, ``die-at-start`` makes the
process abort before it runs any statement and ``cannot-open`` makes it say
``r2s: ...`` and exit 1 the way r2s does on a file it cannot open.
``STUB_R2S_STARTUP_DELAY`` seconds pass before the first statement.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path


def _faults() -> dict[int, str]:
    faults: dict[int, str] = {}
    for item in filter(None, os.environ.get("STUB_R2S_FAULTS", "").split(",")):
        kind, _, address = item.partition("@")
        faults[int(address, 16)] = kind
    return faults


def _fired(kind: str, address: int) -> bool:
    state = os.environ.get("STUB_R2S_STATE")
    if not state:
        return False
    marker = Path(state) / f"{kind}-{address:x}"
    if marker.exists():
        return True
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("fired")
    return False


def _c_type(dwarf, offset) -> str:
    info = dwarf.type(offset)
    if info.kind == "void":
        return "void"
    if info.kind == "bool":
        return "_Bool"
    if info.kind == "int":
        return f"{'' if info.signed else 'u'}int{info.size * 8}_t"
    if info.kind == "float":
        return "float" if info.size == 4 else "double"
    return "void *"


def _delegate(binary: Path, address: int) -> dict:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from dwarf import Dwarf  # noqa: PLC0415

    unstripped = Path(str(binary).removesuffix(".stripped"))
    dwarf = Dwarf.read(unstripped)
    sub = next(s for s in dwarf.subprograms() if s.low_pc == address)
    ret = _c_type(dwarf, sub.return_type)
    params = [_c_type(dwarf, p.type_offset) for p in sub.parameters]
    formals = ", ".join(f"{t} a{i}" for i, t in enumerate(params)) or "void"
    actuals = ", ".join(f"a{i}" for i in range(len(params)))
    name = f"fcn_{address:08x}"
    call = f"((equiv_fn)0x{address:x}ULL)({actuals})"
    body = f"    {call};\n" if ret == "void" else f"    return {call};\n"
    code = (
        "#include <stdint.h>\n"
        f"typedef {ret} (*equiv_fn)({', '.join(params) or 'void'});\n"
        f"{ret} {name}({formals})\n{{\n{body}}}\n"
    )
    return _record(address, name, code)


def _fixture(binary: Path, address: int) -> dict:
    here = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(here))
    import selftest  # noqa: PLC0415
    from dwarf import Dwarf  # noqa: PLC0415

    unstripped = Path(str(binary).removesuffix(".stripped"))
    name = next(s.name for s in Dwarf.read(unstripped).subprograms() if s.low_pc == address)
    case = next((c for c in selftest.CASES
                 if c.function == name and c.expect in ("equal", "residual-trap")), None)
    if case is None:
        return _record(address, name, "", refused="no known rendering in the fixture")
    return selftest.synthetic_pddj(case, address, selftest._all_symbols(unstripped))


def _record(address: int, name: str, code: str, refused: str | None = None) -> dict:
    lines = [{"line": n + 1, "addrs": [address]} for n, text in enumerate(code.splitlines())
             if "return" in text]
    return {
        "name": name,
        "addr": address,
        "definition": name,
        "signature": code.splitlines()[2] if code.count("\n") > 2 else "",
        "refused": {"reason": refused} if refused else None,
        "code": code,
        "proof": {"rendered": 1, "elided": 0, "refused": 0, "residual": 0, "split": 0,
                  "compiler_inserted": 0, "assumed": 0},
        "variables": [{"name": "a0", "type": "int32_t", "kind": "param", "location": "rdi"},
                      {"name": "i", "type": "int32_t", "kind": "local",
                       "location": "stack-0x14"}],
        "lines": lines,
        "links": [],
    }


class Shell:
    """One stub process: the current address, and whether a statement failed."""

    def __init__(self, binary: Path, mode: str):
        self.binary = binary
        self.mode = mode
        self.faults = _faults()
        self.address = 0
        self.failed = False

    def run(self, script: str) -> None:
        for statement in (s.strip() for s in script.split(";")):
            if statement:
                self.statement(statement)

    def statement(self, statement: str) -> None:
        address = self.address
        if statement.startswith("?e "):
            print(statement[3:], flush=True)
        elif statement.startswith("s "):
            self.address = int(statement[2:], 0)
        elif statement == "afl":
            # radare2's headerless layout: addr nbbs size name.
            for item in filter(None, os.environ.get("STUB_R2S_AFL", "").split(",")):
                where, _, name = item.partition(" ")
                print(f"{where} 1 16 {name or '-'}", flush=True)
        elif statement == "pddj":
            fault = self.faults.get(address, "")
            if fault.startswith("once-"):
                fault = "" if _fired(fault, address) else fault[len("once-"):]
            if fault == "abort":
                sys.stdout.flush()
                os.abort()
            if fault == "sleep":
                time.sleep(60)
            if fault == "error":
                print(f"r2s: nothing mapped at 0x{address:x}", file=sys.stderr, flush=True)
                self.failed = True
                return
            if fault == "garbage":
                print("uint64_t fcn(void) { not json }", flush=True)
                return
            if fault == "breach":
                print(json.dumps({"name": "x", "addr": address}), flush=True)
                return
            if self.mode == "delegate":
                record = _delegate(self.binary, address)
            elif self.mode == "fixture":
                record = _fixture(self.binary, address)
            elif self.mode == "refuse":
                record = _record(address, f"fcn_{address:08x}", "", refused="stub refuses")
            else:
                record = _record(address, f"fcn_{address:08x}",
                                 f"#include <stdint.h>\n\nvoid fcn_{address:08x}(void)\n{{\n}}\n")
            if fault == "elsewhere":
                record["addr"] = address + 16
            # ``unterminated``: the answer has no newline of its own, so the
            # END marker after it lands on the same line.
            print(json.dumps(record), end="" if fault == "unterminated" else "\n", flush=True)
        else:
            print(f"r2s: unknown command '{statement}'", file=sys.stderr, flush=True)
            self.failed = True


def main() -> int:
    argv = sys.argv[1:]
    binary = Path(argv[-1])
    mode = os.environ.get("STUB_R2S_MODE", "minimal")
    if mode == "die-at-start":
        os.abort()
    if mode == "cannot-open":
        print(f"r2s: {binary}: not an executable the stub reads", file=sys.stderr, flush=True)
        return 1
    time.sleep(float(os.environ.get("STUB_R2S_STARTUP_DELAY", "0")))
    shell = Shell(binary, mode)
    if "-c" in argv:
        shell.run(argv[argv.index("-c") + 1])
        return 1 if shell.failed else 0
    # Like r2s: each stdin line is a script of its own, and the end of input
    # ends the session with status 0.
    for line in sys.stdin:
        shell.run(line.rstrip("\n"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
