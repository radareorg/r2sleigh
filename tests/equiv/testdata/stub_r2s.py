#!/usr/bin/env python3
"""A stand-in for r2s that answers ``pddj`` the way the contract says r2s does.

It exists to test the harnesses that talk to r2s -- the batch runner, the
equivalence gate's orchestration and the DecBench adapter -- without the
engine, and in particular to make r2s fail in each of the ways a harness has
to survive. It is never a rendering source for a real measurement.

    stub_r2s.py -q -c '<statements>' <binary>

``?e`` prints its text, ``s`` seeks, ``pddj`` answers for the current address,
anything else is an unknown command. ``STUB_R2S_MODE`` picks the answer:

* ``minimal``   a valid record with an empty body (the default);
* ``delegate``  a rendering that calls the original function through its
                address, spelled from the unstripped twin's DWARF (the binary
                path minus ``.stripped``): equal to the original by construction;
* ``refuse``    a record whose ``refused`` is set.

``STUB_R2S_FAULTS`` is a comma list of ``<kind>@<hex address>`` applied when
``pddj`` runs there: ``abort`` (SIGABRT), ``sleep`` (hang for a minute),
``error`` (a ``r2s: ...`` line to stderr and a failed statement), ``garbage``
(text that is not JSON), ``breach`` (JSON missing contract fields). A fault
named ``once-<kind>`` fires only in the first process that reaches it (tracked
in ``$STUB_R2S_STATE``), so a restart can be told from a retry. ``die-at-start``
as the whole mode makes the process abort before it runs any statement.
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


def main() -> int:
    argv = sys.argv[1:]
    script = argv[argv.index("-c") + 1]
    binary = Path(argv[-1])
    mode = os.environ.get("STUB_R2S_MODE", "minimal")
    if mode == "die-at-start":
        os.abort()
    faults = _faults()
    address = 0
    failed = False
    for statement in (s.strip() for s in script.split(";")):
        if statement.startswith("?e "):
            print(statement[3:], flush=True)
        elif statement.startswith("s "):
            address = int(statement[2:], 0)
        elif statement == "pddj":
            fault = faults.get(address, "")
            if fault.startswith("once-"):
                fault = "" if _fired(fault, address) else fault[len("once-"):]
            if fault == "abort":
                sys.stdout.flush()
                os.abort()
            if fault == "sleep":
                time.sleep(60)
            if fault == "error":
                print(f"r2s: nothing mapped at 0x{address:x}", file=sys.stderr, flush=True)
                failed = True
                continue
            if fault == "garbage":
                print("uint64_t fcn(void) { not json }", flush=True)
                continue
            if fault == "breach":
                print(json.dumps({"name": "x", "addr": address}), flush=True)
                continue
            if mode == "delegate":
                record = _delegate(binary, address)
            elif mode == "refuse":
                record = _record(address, f"fcn_{address:08x}", "", refused="stub refuses")
            else:
                record = _record(address, f"fcn_{address:08x}",
                                 f"#include <stdint.h>\n\nvoid fcn_{address:08x}(void)\n{{\n}}\n")
            print(json.dumps(record), flush=True)
        else:
            print(f"r2s: unknown command '{statement}'", file=sys.stderr, flush=True)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
