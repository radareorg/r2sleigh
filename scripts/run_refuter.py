#!/usr/bin/env python3
"""The run refuter, step 1 (ROADMAP D467): a leaf function's run under qemu-user beside
`r2il::eval` of the lift `pdd` reads, from one recorded entry state.

    scripts/run_refuter.py record --bins DIR --r2s PATH [--qemu qemu-x86_64]
    scripts/run_refuter.py check [RECORDING ...] [--bins DIR] [--r2s PATH]

`record` (Linux x86-64) runs each DecBench binary's command under `qemu-x86_64 -g`, stops at the
entry of each leaf it picks (out-degree 0, no supervisor call, no indirect jump), reads the
registers, then asks `r2s pdie` to run the lift and reads each memory cell the run names as
unrecorded, until the run ends. It then runs the machine to the return and records RAX, XMM0 and
the bytes at every address the lift wrote. With a plugin-enabled qemu, `scripts/qemu_refute.c`
also logs the machine's own stores; without one a recording states `store_trace: false`.

`check` replays the committed recordings in tests/refuter/ through `pdie`: offline and
deterministic. A function is refuted when its return value differs, a stored byte differs, the
machine stores where the lift does not (store trace only), or the lift leaves its body. A value
the lift computes in the image's file-space range that equals the machine's less the load bias is
`slid`, not refuted. A recording whose binary is absent or differs from its sha256 is counted,
never passed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RECORDINGS = ROOT / "tests/refuter"
INPUTS = RECORDINGS / "inputs"

# The bytes a recorder reads for one unrecorded address, aligned to their size.
CELL = 64
# The cells one recording may hold; a run that names more refuses the recording.
CELL_BUDGET = 512
# How many leaves step 1 records.
FUNCTIONS = 10
RESULTS = ["RAX", "XMM0"]

# What each DecBench binary is run with, inputs from tests/refuter/inputs copied into its directory.
COMMANDS = {
    "bzip2": ["-c", "-k", "text.txt"],
    "cmp": ["text.txt", "other.txt"],
    "diff": ["text.txt", "other.txt"],
    "diff3": ["text.txt", "other.txt", "text.txt"],
    "find": [".", "-name", "*.txt"],
    "grep": ["-n", "refute", "text.txt"],
    "gzip": ["-c", "text.txt"],
    "sdiff": ["text.txt", "other.txt"],
    "xmlwf": ["doc.xml"],
}

# gdb's x86-64 register names as Sleigh's x86-64 specification spells them.
GENERAL = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"] + [f"r{n}" for n in range(8, 16)]
FLAGS = {"CF": 0, "PF": 2, "AF": 4, "ZF": 6, "SF": 7, "TF": 8, "IF": 9, "DF": 10, "OF": 11}
SEGMENT_BASES = {"fs_base": "FS_OFFSET", "gs_base": "GS_OFFSET"}


# ── The ELF facts the refuter reads ─────────────────────────────────────


def elf_facts(path: Path) -> dict:
    """`e_type`, `e_entry` and the file-space range the PT_LOAD segments span."""
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError(f"{path}: not a little-endian ELF64")
    e_type, _, _, e_entry, e_phoff = struct.unpack_from("<HHIQQ", data, 16)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    loads = []
    for index in range(e_phnum):
        p_type, _, _, p_vaddr, _, _, p_memsz, _ = struct.unpack_from(
            "<IIQQQQQQ", data, e_phoff + index * e_phentsize
        )
        if p_type == 1 and p_memsz:
            loads.append((p_vaddr, p_vaddr + p_memsz))
    start = min(lo for lo, _ in loads)
    end = max(hi for _, hi in loads)
    return {"type": e_type, "entry": e_entry, "image": (start, end)}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ── The comparison ──────────────────────────────────────────────────────


def judge(recording: dict, answer: dict, image: tuple[int, int]) -> dict:
    """What one replay says against the machine: `refuted` with each reason, and `slid` counts."""
    bias = int(recording["bias"], 16)
    machine = recording["machine"]
    inside = lambda value: image[0] <= value < image[1]
    reasons, slid = [], 0
    stop = answer["stop"]
    if stop["kind"] == "left-body":
        reasons.append(f"the lift leaves its body at {stop['at']} for {stop['to']}")
    elif stop["kind"] != "returned":
        return {"refuted": [], "slid": 0, "unreplayed": f"{stop['kind']} {json.dumps(stop)}"}
    elif int(stop["to"], 16) != int(machine["returned_to"], 16):
        reasons.append(f"the lift returns to {stop['to']}, the machine to {machine['returned_to']}")
    for name, value in machine["results"].items():
        ours = answer["results"].get(name)
        if ours is None:
            reasons.append(f"{name}: the lift states no value, the machine {value}")
            continue
        ours, theirs = int(ours, 16), int(value, 16)
        if ours == theirs:
            continue
        if inside(ours) and (ours + bias) & (2**64 - 1) == theirs:
            slid += 1
            continue
        reasons.append(f"{name}: the lift {ours:#x}, the machine {theirs:#x}")
    stored = {int(write["address"], 16): write["bytes"] for write in machine["writes"]}
    for write in answer["writes"]:
        address = int(write["address"], 16)
        at = address + bias if inside(address) else address
        theirs = stored.get(at)
        if theirs is None:
            reasons.append(f"the lift writes {address:#x}, which the recording never read back")
            continue
        if write["bytes"] == theirs:
            continue
        ours = bytes.fromhex(write["bytes"])
        if len(ours) == 8:
            value = int.from_bytes(ours, "little")
            if inside(value) and (value + bias).to_bytes(8, "little") == bytes.fromhex(theirs):
                slid += 1
                continue
        reasons.append(f"[{at:#x}]: the lift stores {write['bytes']}, the machine holds {theirs}")
    if machine.get("store_trace"):
        ours = {
            (int(write["address"], 16) + bias if inside(int(write["address"], 16)) else int(write["address"], 16))
            for write in answer["writes"]
        }
        for address in machine.get("stores", []):
            if int(address, 16) not in ours:
                reasons.append(f"the machine stores at {address}, the lift does not")
    return {"refuted": reasons, "slid": slid, "unreplayed": None}


def pdie(r2s: Path, binary: Path, recording: Path) -> dict:
    """`r2s pdie RECORDING` on BINARY, as the object it prints."""
    done = subprocess.run(
        [str(r2s), "-q", "-c", f"pdie {recording}", str(binary)],
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode != 0:
        raise RuntimeError(f"pdie {recording}: {done.stderr.strip() or done.stdout.strip()}")
    return json.loads(done.stdout)


def located(recording: dict, bins: Path | None) -> Path | None:
    """The binary a recording names, where its bytes are the ones recorded."""
    named = ROOT / recording["binary"]
    candidates = [named] if named.is_file() else []
    if bins is not None:
        candidates += sorted(bins.rglob(Path(recording["binary"]).name))
    for candidate in candidates:
        if candidate.is_file() and sha256(candidate) == recording["sha256"]:
            return candidate
    return None


def check(args: argparse.Namespace) -> int:
    recordings = [Path(p) for p in args.recordings] or sorted(RECORDINGS.glob("*.json"))
    tally = {"recorded": 0, "refuted": 0, "slid": 0, "absent": 0, "unreplayed": 0}
    for path in recordings:
        recording = json.loads(path.read_text())
        binary = located(recording, args.bins)
        if binary is None:
            tally["absent"] += 1
            print(f"{path.name}: absent: no {recording['binary']} with sha256 {recording['sha256'][:12]}")
            continue
        tally["recorded"] += 1
        verdict = judge(recording, pdie(args.r2s, binary, path), tuple(elf_facts(binary)["image"]))
        tally["slid"] += verdict["slid"]
        if verdict["unreplayed"]:
            tally["unreplayed"] += 1
            print(f"{path.name}: unreplayed: {verdict['unreplayed']}")
        elif verdict["refuted"]:
            tally["refuted"] += 1
            print(f"{path.name}: refuted: " + "; ".join(verdict["refuted"]))
        else:
            print(f"{path.name}: agrees ({verdict['slid']} slid)")
    print(" ".join(f"{key} {value}" for key, value in tally.items()))
    return 0 if tally["refuted"] == tally["absent"] == tally["unreplayed"] == 0 else 1


# ── The gdb remote protocol, as qemu-user's stub speaks it ──────────────


def framed(payload: str) -> bytes:
    return f"${payload}#{sum(payload.encode()) % 256:02x}".encode()


def unescaped(body: bytes) -> bytes:
    """A reply's body with `}` escapes and `*` run lengths undone."""
    out, at = bytearray(), 0
    while at < len(body):
        byte = body[at]
        if byte == 0x7D:
            out.append(body[at + 1] ^ 0x20)
            at += 2
        elif byte == 0x2A and out:
            out.extend(out[-1:] * (body[at + 1] - 29))
            at += 2
        else:
            out.append(byte)
            at += 1
    return bytes(out)


class Remote:
    """One gdb remote connection: each request waits for its one reply."""

    def __init__(self, port: int):
        for _ in range(200):
            try:
                self.sock = socket.create_connection(("127.0.0.1", port), timeout=30)
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError(f"no gdb stub on port {port}")
        # A continue waits as long as the program runs to its next stop.
        self.sock.settimeout(None)
        self.buffer = b""

    def _byte(self) -> int:
        while not self.buffer:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise RuntimeError("the stub closed the connection")
            self.buffer += chunk
        byte, self.buffer = self.buffer[0], self.buffer[1:]
        return byte

    def ask(self, payload: str) -> bytes:
        self.sock.sendall(framed(payload))
        while True:
            byte = self._byte()
            if byte == ord("$"):
                break
        body = bytearray()
        while (byte := self._byte()) != ord("#"):
            body.append(byte)
        self._byte(), self._byte()
        self.sock.sendall(b"+")
        return unescaped(bytes(body))

    def memory(self, address: int, length: int) -> bytes | None:
        reply = self.ask(f"m{address:x},{length:x}")
        return None if reply.startswith(b"E") or len(reply) != 2 * length else bytes.fromhex(reply.decode())

    def xfer(self, kind: str, annex: str) -> bytes:
        data, offset = b"", 0
        while True:
            reply = self.ask(f"qXfer:{kind}:read:{annex}:{offset:x},fff")
            data += reply[1:]
            offset += len(reply) - 1
            if reply[:1] == b"l":
                return data
            if reply[:1] != b"m":
                raise RuntimeError(f"qXfer:{kind}:{annex}: {reply[:40]!r}")


def register_numbers(remote: Remote) -> dict[str, tuple[int, int]]:
    """Each register the stub's target description names: its number and its width in bytes."""
    numbers, pending, number = {}, ["target.xml"], 0
    while pending:
        xml = remote.xfer("features", pending.pop(0)).decode()
        pending += re.findall(r'<xi:include href="([^"]+)"', xml)
        for attributes in re.findall(r"<reg ([^>]*)>", xml):
            fields = dict(re.findall(r'(\w+)="([^"]*)"', attributes))
            number = int(fields.get("regnum", number))
            numbers[fields["name"]] = (number, int(fields["bitsize"]) // 8)
            number += 1
    return numbers


def stub_register(remote: Remote, numbers: dict, name: str) -> int | None:
    """A register's value, or `None` where the stub answers an error (qemu 8.2 refuses `mxcsr`)."""
    if name not in numbers:
        return None
    number, width = numbers[name]
    reply = remote.ask(f"p{number:x}").decode()
    if reply.startswith("E") or not reply:
        return None
    return int.from_bytes(bytes.fromhex(reply)[:width], "little")


def read_register(remote: Remote, numbers: dict, name: str) -> int:
    value = stub_register(remote, numbers, name)
    if value is None:
        raise RuntimeError(f"the stub does not read {name}")
    return value


def entry_registers(remote: Remote, numbers: dict) -> dict[str, int]:
    """The machine's registers, by Sleigh's names; one the stub does not read is left unstated."""
    held = {name.upper(): read_register(remote, numbers, name) for name in GENERAL}
    eflags = read_register(remote, numbers, "eflags")
    held.update({flag: (eflags >> bit) & 1 for flag, bit in FLAGS.items()})
    optional = {**SEGMENT_BASES, **{f"xmm{n}": f"XMM{n}" for n in range(16)}, "mxcsr": "MXCSR"}
    for gdb, sleigh in optional.items():
        value = stub_register(remote, numbers, gdb)
        if value is not None:
            held[sleigh] = value
    return held


def auxv_entry(remote: Remote) -> int:
    data = remote.xfer("auxv", "")
    for at in range(0, len(data) - 15, 16):
        kind, value = struct.unpack_from("<QQ", data, at)
        if kind == 9:  # AT_ENTRY
            return value
    raise RuntimeError("the auxiliary vector states no AT_ENTRY")


# ── Picking and recording leaves ────────────────────────────────────────


def leaves(r2s: Path, binary: Path) -> list[int]:
    """Functions `afi` says call nothing whose listing holds no call, no supervisor call and no indirect jump."""
    listed = subprocess.run([str(r2s), "-q", "-c", "aa; afl", str(binary)], capture_output=True, text=True).stdout
    entries = [int(line.split()[0], 16) for line in listed.splitlines() if line.startswith("0x")]
    script = "aa\n" + "".join(f"?e ==F {e:#x}\nafi @ {e:#x}\npdf @ {e:#x}\n" for e in entries)
    out = subprocess.run([str(r2s), "-q", str(binary)], input=script, capture_output=True, text=True).stdout
    picked = []
    for chunk in out.split("==F ")[1:]:
        entry, _, body = chunk.partition("\n")
        name = re.search(r"^name: (.*)$", body, re.M)
        if name and name.group(1).startswith("sym.imp."):
            continue
        if not re.search(r"^out-degree: 0$", body, re.M):
            continue
        if re.search(r"\b(syscall|sysenter|int|call)\b", body):
            continue
        if re.search(r"\b(notrack )?jmp (?!0x|sym\.|fcn\.|loc\.)", body):
            continue
        picked.append(int(entry, 16))
    return sorted(picked)


def extent(r2s: Path, binary: Path, entry: int) -> int:
    """The address after the function's last block, as `afi` states it."""
    info = subprocess.run([str(r2s), "-q", "-c", f"afi @ {entry:#x}", str(binary)], capture_output=True, text=True)
    return int(re.search(r"^maxaddr: (0x[0-9a-f]+)$", info.stdout, re.M).group(1), 16)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def plugin(qemu: str, scratch: Path) -> Path | None:
    """scripts/qemu_refute.c built against the header a `--enable-plugins` qemu installs beside its bin."""
    found = shutil.which(qemu) or qemu
    header = Path(found).resolve().parent.parent / "include" / "qemu-plugin.h"
    if not header.exists():
        return None
    built = scratch / "qemu_refute.so"
    subprocess.run(["cc", "-O2", "-Wall", "-Werror", "-shared", "-fPIC", f"-I{header.parent}",
                    str(ROOT / "scripts/qemu_refute.c"), "-o", str(built)], check=True)
    return built


def stores(log: Path, entry: int) -> list[str]:
    """The machine addresses the first activation of `entry` stored to, from the plugin's log."""
    found, inside = [], False
    for line in log.read_text().splitlines():
        words = line.split()
        if words[0] == "enter":
            inside = int(words[1], 16) == entry and words[2] == "1"
        elif words[0] == "leave":
            inside = False
        elif words[0] == "store" and inside:
            found += [f"{int(words[1], 16) + at:#x}" for at in range(int(words[2]))]
    return found


class Run:
    """One run of a binary's command under `qemu-x86_64 -g`, stopped at its first instruction."""

    def __init__(self, qemu: str, binary: Path, workdir: Path, traced: list[str] | None = None):
        port = free_port()
        self.process = subprocess.Popen(
            [qemu, *(traced or []), "-g", str(port), str(binary), *COMMANDS[binary.name]],
            cwd=workdir, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            # The guest sees no host environment: its stack holds nothing of the recording host's.
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        self.remote = Remote(port)
        self.remote.ask("?")
        self.numbers = register_numbers(self.remote)
        facts = elf_facts(binary)
        self.bias = auxv_entry(self.remote) - facts["entry"] if facts["type"] == 3 else 0
        self.image = facts["image"]

    def pc(self) -> int:
        return read_register(self.remote, self.numbers, "rip")

    def resume(self) -> bool:
        """Run to the next breakpoint: false where the process ended."""
        reply = self.remote.ask("c")
        return reply[:1] in (b"T", b"S")

    def close(self):
        try:
            self.remote.ask("k")
        except (OSError, RuntimeError):
            pass
        self.process.kill()
        self.process.wait()


def workdir() -> Path:
    path = Path(tempfile.mkdtemp(prefix="refuter-"))
    for source in INPUTS.iterdir():
        shutil.copy(source, path / source.name)
    return path


def executed(qemu: str, binary: Path, candidates: list[int]) -> list[int]:
    """The candidates the command enters, in address order."""
    where = workdir()
    run = Run(qemu, binary, where)
    try:
        for entry in candidates:
            run.remote.ask(f"Z0,{entry + run.bias:x},1")
        hit = set()
        while run.resume():
            at = run.pc() - run.bias
            if at in candidates and at not in hit:
                hit.add(at)
                run.remote.ask(f"z0,{at + run.bias:x},1")
        return sorted(hit)
    finally:
        run.close()
        shutil.rmtree(where)


def spelled(recording: dict) -> dict:
    """A recording's request as `pdie` reads it, numbers in hex."""
    return {
        **recording,
        "registers": {name: f"{value:#x}" for name, value in recording["registers"].items()},
        "cells": {f"{at:#x}": data.hex() for at, data in sorted(recording["cells"].items())},
    }


def record_one(run: Run, r2s: Path, binary: Path, entry: int, scratch: Path) -> dict:
    """At the entry stop: the registers, the cells the lift reads, then the machine run to return."""
    remote = run.remote
    registers = entry_registers(remote, run.numbers)
    recording = {
        "binary": f"{binary.parent.parent.name}/{binary.name}",
        "sha256": sha256(binary),
        "function": f"{entry:#x}",
        "command": [binary.name, *COMMANDS[binary.name]],
        "entry": f"{entry:#x}",
        "bias": f"{run.bias:#x}",
        "registers": registers,
        "cells": {},
        "results": RESULTS,
    }
    inside = lambda address: run.image[0] <= address < run.image[1]
    while True:
        (scratch / "request.json").write_text(json.dumps(spelled(recording)))
        answer = pdie(r2s, binary, scratch / "request.json")
        if answer["stop"]["kind"] != "unrecorded":
            break
        if len(recording["cells"]) >= CELL_BUDGET:
            raise RuntimeError(f"{entry:#x}: the lift reads more than {CELL_BUDGET} cells")
        start = int(answer["stop"]["address"], 16) & ~(CELL - 1)
        data = remote.memory(start, CELL)
        if data is None:
            raise RuntimeError(f"{entry:#x}: the machine maps no byte at {start:#x}")
        recording["cells"][start] = data
    rsp = registers["RSP"]
    returned_to = int.from_bytes(remote.memory(rsp, 8), "little")
    remote.ask(f"Z0,{returned_to:x},1")
    # The return lands at the caller's address with the return address popped; a leaf calls none.
    while True:
        if not run.resume():
            raise RuntimeError(f"{entry:#x}: the process ended before the function returned")
        if run.pc() == returned_to and read_register(remote, run.numbers, "rsp") == rsp + 8:
            break
    remote.ask(f"z0,{returned_to:x},1")
    writes = []
    for write in answer["writes"]:
        address = int(write["address"], 16)
        at = address + run.bias if inside(address) else address
        held = remote.memory(at, len(write["bytes"]) // 2)
        writes.append({"address": f"{at:#x}", "bytes": held.hex() if held else ""})
    recording["machine"] = {
        "results": {
            name: f"{value:#x}"
            for name in RESULTS
            if (value := stub_register(remote, run.numbers, name.lower())) is not None
        },
        "writes": writes,
        "returned_to": f"{returned_to:#x}",
        "store_trace": False,
    }
    return spelled(recording)


def record(args: argparse.Namespace) -> int:
    binaries = sorted(
        (path for path in args.bins.rglob("*") if path.is_file() and path.name in COMMANDS),
        key=lambda path: path.name,
    )
    chosen: list[tuple[Path, int]] = []
    for binary in binaries:
        if len(chosen) >= FUNCTIONS:
            break
        hit = executed(args.qemu, binary, leaves(args.r2s, binary))
        chosen += [(binary, entry) for entry in hit[: FUNCTIONS - len(chosen)]]
        print(f"{binary.name}: {len(hit)} leaves entered")
    scratch = Path(tempfile.mkdtemp(prefix="refuter-plugin-"))
    built = plugin(args.qemu, scratch)
    print(f"store trace: {'qemu_refute.so' if built else 'none (no qemu-plugin.h beside qemu)'}")
    for binary, entry in chosen:
        where = workdir()
        log = scratch / "log.txt"
        traced = None
        if built is not None:
            end = extent(args.r2s, binary, entry)
            options = f"entry={elf_facts(binary)['entry']:x},out={log},fn={entry:x}:{end:x}"
            traced = ["-plugin", f"{built},{options}"]
        run = Run(args.qemu, binary, where, traced)
        try:
            run.remote.ask(f"Z0,{entry + run.bias:x},1")
            if not run.resume() or run.pc() != entry + run.bias:
                raise RuntimeError(f"{binary.name} {entry:#x}: not entered")
            run.remote.ask(f"z0,{entry + run.bias:x},1")
            recording = record_one(run, args.r2s, binary, entry, where)
        finally:
            run.close()
            shutil.rmtree(where)
        if built is not None:
            recording["machine"]["store_trace"] = True
            recording["machine"]["stores"] = stores(log, entry)
        out = RECORDINGS / f"{binary.name}_{entry:x}.json"
        out.write_text(json.dumps(recording, indent=1, sort_keys=True) + "\n")
        print(f"{out.relative_to(ROOT)}: {len(recording['cells'])} cells")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="verb", required=True)
    rec = sub.add_parser("record", help="record leaves under qemu-user (Linux x86-64)")
    rec.add_argument("--bins", type=Path, required=True, help="the DecBench O2 binaries")
    rec.add_argument("--r2s", type=Path, default=ROOT / "target/release/r2s")
    rec.add_argument("--qemu", default="qemu-x86_64")
    chk = sub.add_parser("check", help="replay the committed recordings")
    chk.add_argument("recordings", nargs="*")
    chk.add_argument("--bins", type=Path, help="where the recorded binaries are")
    chk.add_argument("--r2s", type=Path, default=ROOT / "target/release/r2s")
    args = parser.parse_args()
    return record(args) if args.verb == "record" else check(args)


if __name__ == "__main__":
    sys.exit(main())
