#!/usr/bin/env python3
"""Differential ESIL check: r2sleigh's lifting against radare2's own.

radare2 decodes the instruction window with its native architecture plugin
and steps each instruction in its ESIL virtual machine (`aes`). The r2sleigh
side is the ESIL the `r2sleigh` CLI prints for the same bytes
(`r2sleigh disasm --file <binary> --addr <start> -n <count> --format esil`),
evaluated in the same virtual machine (`ae`) with the program counter already
advanced past the instruction, as `aes` does. Both start from identical
register state, and the machine state afterwards is compared.

radare2 is the reference here, not an oracle: a divergence means the two
disagree and one of them is wrong. Triage tells you which. The r2sleigh plugin
that used to supply the second side inside radare2 is deleted; the CLI is the
lift's own surface.

    scripts/esil_differential.py --binary /bin/ls --arch arm --count 200
    scripts/esil_differential.py --binary /tmp/x86 --arch x86 --bits 64 --json \
        --r2sleigh target/release/r2sleigh

Exit status is non-zero when any instruction diverges, so the script can gate.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# Seeds are fixed so a run is reproducible and a regression is bisectable. The
# values straddle the sign boundary of every width because that is where
# comparison and overflow lifting goes wrong.
SEED_VALUES = [
    0x0000000000000001,
    0x00000000FFFFFFFF,
    0x000000007FFFFFFF,
    0x0000000080000000,
    0xFFFFFFFFFFFFFFFF,
    0x0000000000000080,
    0x123456789ABCDEF0,
]

# Registers seeded before each step.
SEED_REGISTERS = {
    "x86": ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"],
    "arm": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9"],
}

# Every step starts from the same machine, so a divergence is attributable to
# the instruction under test rather than to drift left by an earlier one. The
# stack registers are pinned inside the map `aeim` creates so that memory
# operands stay addressable.
STACK_ANCHOR = 0x170000
STACK_REGISTERS = {"x86": ["rsp", "rbp"], "arm": ["sp"]}

# Registers whose post-state is compared. Everything the seeds touch, plus the
# flags and the program counter, which is what a mis-lifted branch corrupts.
# These are read one at a time: `aerj` reports a different subset per plugin,
# so intersecting its keys silently compares almost nothing.
COMPARE_REGISTERS = {
    "x86": SEED_REGISTERS["x86"] + ["rbp", "rsp", "rip", "zf", "cf", "sf", "of", "pf"],
    "arm": SEED_REGISTERS["arm"] + ["sp", "pc", "zf", "cf", "nf", "vf"],
}

PC_REGISTER = {"x86": "rip", "arm": "pc"}

MARKER = "==ESILDIFF=="


@dataclass
class Instruction:
    addr: int
    size: int
    opcode: str
    bytes: str


@dataclass
class Divergence:
    instruction: Instruction
    trial: int
    native_esil: str
    sleigh_esil: str
    differing: dict[str, tuple[str, str]] = field(default_factory=dict)


def run_r2(binary: str, arch: str | None, bits: int, commands: list[str]) -> str:
    """Run one radare2 session over a command script and return its stdout."""
    with tempfile.NamedTemporaryFile("w", suffix=".r2", delete=False) as handle:
        handle.write("\n".join(commands) + "\n")
        script = handle.name
    argv = ["r2", "-e", "scr.color=false", "-e", "log.level=0", "-q"]
    if arch:
        argv += ["-a", arch]
    argv += ["-b", str(bits), "-i", script, binary]
    try:
        completed = subprocess.run(
            argv, capture_output=True, text=True, timeout=600, check=False
        )
    finally:
        Path(script).unlink(missing_ok=True)
    return completed.stdout


def list_instructions(binary: str, arch: str, bits: int, start: str, count: int) -> list[Instruction]:
    """Decode the instruction window once, with the native plugin."""
    out = run_r2(binary, arch, bits, [f"s {start}", f'"aoj {count}"'])
    payload = out[out.index("[") :] if "[" in out else "[]"
    decoded = json.loads(payload)
    # Bytes the reference plugin cannot decode say nothing about lifting: the
    # two sides are being asked different questions.
    return [
        Instruction(
            addr=item["addr"],
            size=item["size"],
            opcode=item.get("opcode", ""),
            bytes=item.get("bytes", ""),
        )
        for item in decoded
        if item.get("size", 0) > 0
        and item.get("type") not in {"ill", "invalid", "unk"}
        and item.get("opcode", "") not in {"invalid", "unaligned"}
    ]


def emulation_script(
    instructions: list[Instruction], family: str, trials: int,
    sleigh: dict[int, list[str]] | None = None,
) -> list[str]:
    """One session that steps every instruction once per seed, resetting between.

    With ``sleigh`` (ESIL lines per address) each instruction is evaluated from
    those lines instead of stepped with radare2's own lift; the program counter
    is set past the instruction first, which is what `aes` does before it
    evaluates.
    """
    commands = ["aei", "aeim", "aeip"]
    for trial in range(trials):
        for inst in instructions:
            commands.append(f"?e {MARKER}")
            for index, reg in enumerate(SEED_REGISTERS[family]):
                value = SEED_VALUES[(index + trial) % len(SEED_VALUES)]
                commands.append(f"aer {reg}={value:#x}")
            for reg in STACK_REGISTERS[family]:
                commands.append(f"aer {reg}={STACK_ANCHOR:#x}")
            for flag in ("zf", "cf", "sf", "of", "pf", "nf", "vf"):
                commands.append(f"aer {flag}=0")
            commands.append(f"s {inst.addr:#x}")
            if sleigh is None:
                commands.append(f"aer {PC_REGISTER[family]}={inst.addr:#x}")
                commands.append("aes")
            else:
                commands.append(f"aer {PC_REGISTER[family]}={inst.addr + inst.size:#x}")
                for line in sleigh.get(inst.addr, []):
                    # Quoted, so no character of the expression is a command operator.
                    commands.append(f'"ae {line}"')
            for reg in COMPARE_REGISTERS[family]:
                commands.append(f"aer {reg}")
    return commands


def parse_states(output: str, family: str) -> list[dict]:
    """Split a session's stdout into one register dictionary per step."""
    watched = COMPARE_REGISTERS[family]
    states: list[dict] = []
    for chunk in output.split(MARKER)[1:]:
        values = [line.strip() for line in chunk.splitlines() if line.strip().startswith("0x")]
        if len(values) < len(watched):
            states.append({})
            continue
        states.append(
            {reg: int(value, 16) for reg, value in zip(watched, values[: len(watched)])}
        )
    return states


_SLEIGH_HEADER = re.compile(r"^# 0x([0-9a-fA-F]+): .*\(size=(\d+)\)\s*$")


def parse_sleigh_esil(output: str) -> dict[int, list[str]]:
    """``address -> ESIL lines`` from ``r2sleigh disasm --format esil``.

    Each instruction is a ``# 0x<addr>: <mnemonic> (size=<n>)`` header followed
    by its ESIL lines. A window can print an address twice; the first wins.
    """
    found: dict[int, list[str]] = {}
    current: int | None = None
    for line in output.splitlines():
        header = _SLEIGH_HEADER.match(line.strip())
        if header:
            address = int(header.group(1), 16)
            current = address if address not in found else None
            if current is not None:
                found[current] = []
            continue
        if current is not None and line.strip():
            found[current].append(line.strip())
    return found


def sleigh_esil(r2sleigh: str, binary: str, instructions: list[Instruction]) -> dict[int, list[str]]:
    """The r2sleigh CLI's ESIL for the window, by address."""
    argv = [r2sleigh, "disasm", "--file", binary, "--addr", f"{instructions[0].addr:#x}",
            "-n", str(len(instructions)), "--format", "esil"]
    completed = subprocess.run(argv, capture_output=True, text=True, timeout=600, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"r2sleigh disasm failed: {completed.stderr.strip()[:400]}")
    return parse_sleigh_esil(completed.stdout)


def default_r2sleigh() -> str:
    root = Path(__file__).resolve().parents[1]
    target = Path(os.environ.get("CARGO_TARGET_DIR", root / "target"))
    for candidate in (target / "release" / "r2sleigh", target / "debug" / "r2sleigh"):
        if candidate.exists():
            return str(candidate)
    return shutil.which("r2sleigh") or "r2sleigh"


def esil_strings(binary: str, arch: str | None, bits: int, instructions: list[Instruction]) -> list[str]:
    """The ESIL radare2's native plugin produces, kept for triage of a divergence."""
    commands = []
    for inst in instructions:
        commands.append(f"?e {MARKER}")
        commands.append(f's {inst.addr:#x}')
        commands.append('"aoj 1"')
    out = run_r2(binary, arch, bits, commands)
    results = []
    for chunk in out.split(MARKER)[1:]:
        bracket = chunk.find("[")
        if bracket < 0:
            results.append("")
            continue
        # A long ESIL string can be wrapped, so rejoin before decoding.
        text = " ".join(chunk[bracket:].strip().splitlines())
        try:
            results.append(json.loads(text)[0].get("esil", ""))
        except (json.JSONDecodeError, IndexError, KeyError):
            try:
                results.append(json.loads(text.split("][")[0] + "]")[0].get("esil", ""))
            except (json.JSONDecodeError, IndexError, KeyError):
                results.append("")
    # One entry per instruction even when a decode produced nothing printable.
    results.extend([""] * (len(instructions) - len(results)))
    return results[: len(instructions)]


def compare(
    instructions: list[Instruction],
    native: list[dict],
    sleigh: list[dict],
    family: str,
    trials: int,
    native_esil: list[str],
    sleigh_esil: list[str],
) -> tuple[int, list[Divergence]]:
    compared = 0
    divergences: list[Divergence] = []
    watched = COMPARE_REGISTERS[family]
    for step, (before, after) in enumerate(zip(native, sleigh)):
        if not before or not after:
            continue
        index = step % len(instructions)
        trial = step // len(instructions)
        differing = {
            reg: (hex(before[reg]), hex(after[reg]))
            for reg in watched
            if reg in before and reg in after and before[reg] != after[reg]
        }
        compared += 1
        if differing:
            divergences.append(
                Divergence(
                    instruction=instructions[index],
                    trial=trial,
                    native_esil=native_esil[index],
                    sleigh_esil=sleigh_esil[index],
                    differing=differing,
                )
            )
    return compared, divergences


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--arch", required=True, choices=sorted(SEED_REGISTERS))
    parser.add_argument("--bits", type=int, default=64)
    parser.add_argument("--start", default="entry0")
    parser.add_argument("--count", type=int, default=64)
    parser.add_argument("--trials", type=int, default=len(SEED_VALUES))
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--show", type=int, default=10, help="how many divergences to print"
    )
    parser.add_argument(
        "--r2sleigh", default=default_r2sleigh(),
        help="the r2sleigh CLI (cargo build -p r2sleigh-cli --bin r2sleigh --features x86)",
    )
    args = parser.parse_args()

    instructions = list_instructions(args.binary, args.arch, args.bits, args.start, args.count)
    if not instructions:
        print(f"no instructions decoded at {args.start} in {args.binary}", file=sys.stderr)
        return 2

    lifted = sleigh_esil(args.r2sleigh, args.binary, instructions)
    missing = [inst for inst in instructions if not lifted.get(inst.addr)]
    if missing:
        print(f"r2sleigh printed no ESIL for {len(missing)} of {len(instructions)} "
              f"instructions (first at {missing[0].addr:#x}); they are not compared",
              file=sys.stderr)
        instructions = [inst for inst in instructions if lifted.get(inst.addr)]
        if not instructions:
            return 2
    script = emulation_script(instructions, args.arch, args.trials)
    native = parse_states(run_r2(args.binary, args.arch, args.bits, script), args.arch)
    lifted_script = emulation_script(instructions, args.arch, args.trials, lifted)
    sleigh = parse_states(run_r2(args.binary, args.arch, args.bits, lifted_script), args.arch)
    native_esil = esil_strings(args.binary, args.arch, args.bits, instructions)
    sleigh_esil = [",".join(lifted.get(inst.addr, [])) for inst in instructions]

    compared, divergences = compare(
        instructions, native, sleigh, args.arch, args.trials, native_esil, sleigh_esil
    )

    diverging_instructions = {d.instruction.addr for d in divergences}
    report = {
        "binary": args.binary,
        "arch": args.arch,
        "instructions": len(instructions),
        "steps_compared": compared,
        "steps_diverged": len(divergences),
        "instructions_diverged": len(diverging_instructions),
        "agreement": round(1 - len(divergences) / compared, 4) if compared else 0.0,
    }

    if args.json:
        report["divergences"] = [
            {
                "addr": hex(d.instruction.addr),
                "opcode": d.instruction.opcode,
                "trial": d.trial,
                "registers": d.differing,
                "native_esil": d.native_esil,
                "sleigh_esil": d.sleigh_esil,
            }
            for d in divergences[: args.show]
        ]
        print(json.dumps(report, indent=2))
    else:
        print(
            f"{report['instructions']} instructions, {compared} steps, "
            f"{len(divergences)} diverged "
            f"({len(diverging_instructions)} distinct instructions), "
            f"agreement {report['agreement']:.2%}"
        )
        seen: set[int] = set()
        for d in divergences:
            if d.instruction.addr in seen or len(seen) >= args.show:
                continue
            seen.add(d.instruction.addr)
            print(f"\n{d.instruction.addr:#x}  {d.instruction.opcode}  [{d.instruction.bytes}]")
            for reg, (want, got) in sorted(d.differing.items()):
                print(f"    {reg:<5} native={want:<20} sleigh={got}")
            print(f"    native: {d.native_esil}")
            print(f"    sleigh: {d.sleigh_esil}")

    return 1 if divergences else 0


if __name__ == "__main__":
    sys.exit(main())
