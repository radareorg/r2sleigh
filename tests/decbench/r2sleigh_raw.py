"""DecBench backend for r2sleigh, driven through its own shell, ``r2s``.

r2sleigh (https://github.com/radareorg/r2sleigh) is a refusal-first
decompiler: Ghidra Sleigh lift, its own IL, SSA, a sealed binding plan, C. It
renders a function it can account for and refuses one it cannot, with the
reason. ``r2s`` is its shell; this backend asks it one question per function,

    r2s -q -c '?e BEGIN i; s <addr>; pddj; ?e END i; ...' <stripped binary>

and reads the structured answer ``pddj`` prints: the C translation unit, the
identifier the function is defined as, its variables, which instruction
addresses each line came from, and the proof counters. The streaming, the
restart after a crash and the reading of an answer live in ``r2s_batch.py``,
shared with the repository's equivalence gate so the two cannot read r2s
differently.

What this backend guarantees, against the official driver
(``scripts/run_benchmark.py``), which hands it a ``strip --strip-all`` copy
and the DWARF ``low_pc`` of every source function:

* It renders exactly the addresses it was given (``function_names`` and
  ``functions``), with no symbol lookup; with no targets at all it renders
  what ``afl`` (the engine's own discovery) finds, through DecBench's shared
  skip rule.
* Addresses pass through unchanged. r2s reports ELF link addresses, which are
  DecBench's ELF-file-space for PIE and non-PIE alike; nothing is rebased.
* ``FunctionDecompilation.name`` is the identifier the rendering itself
  defines (``pddj.definition``), so DecBench's relabel to the DWARF name
  rewrites the code and the key together. When the caller named the function,
  the definition is renamed to that name the same way.
* Every requested function is either rendered or declined with a typed cause:
  ``refused: <reason>`` (r2s's own), ``r2s: <message>`` (a failed statement),
  or ``harness: <how r2s ended> while rendering <addr>`` (a crash or a
  deadline, after which r2s is restarted at the next function).
  ``rendered + declined == requested`` is checked before returning.
* After every function the partial result is pickled to ``progress_path``, so
  the driver's hard kill loses nothing already answered.
* It fails closed on a binary carrying ``.debug_info`` or ``.symtab``: r2s
  reads the declarations of the file it opens, and DecBench scores types
  against that same DWARF. Such a binary is declined whole with the reason.
* ``variables`` and ``line_mappings`` come from ``pddj``, never from parsing C.

Locate the shell with ``$R2SLEIGH_R2S_BIN`` or ``r2s`` on ``$PATH``.
Per-function deadline: ``$R2SLEIGH_FUNCTION_TIMEOUT`` seconds (default 300).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

from decbench.decompilers.base import Decompiler, DecompilerConfig
from decbench.decompilers.raw import common
from decbench.decompilers.registry import register_decompiler
from decbench.models.decompilation import (
    DecompilationResult,
    DecompilerMetadata,
    FunctionDecompilation,
    LineMapping,
    VariableInfo,
)

try:  # installed beside this file inside DecBench's tree
    from decbench.decompilers.raw import r2s_batch  # type: ignore[attr-defined]
except ImportError:  # loaded from the r2sleigh tree: tests/equiv owns the runner
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "equiv"))
    import r2s_batch  # type: ignore[no-redef]

log = logging.getLogger(__name__)

BACKEND = "r2sleigh_native"

# Sections whose presence means r2s would read facts DecBench grades against.
FAIL_CLOSED_SECTIONS = (".debug_info", ".symtab")

_STACK_OFFSET = re.compile(r"([+-])\s*(0x[0-9a-fA-F]+|\d+)\s*\]?\s*$")


def r2s_bin() -> Path | None:
    explicit = os.environ.get("R2SLEIGH_R2S_BIN")
    if explicit:
        candidate = Path(explicit)
        return candidate if candidate.exists() else None
    found = shutil.which("r2s")
    return Path(found) if found else None


def elf_section_names(binary: Path) -> list[str] | None:
    """The section names of an ELF file, or None when it is not one we can read."""
    try:
        data = binary.read_bytes()
    except OSError:
        return None
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None
    is64 = data[4] == 2
    order = "<" if data[5] == 1 else ">"
    try:
        if is64:
            shoff, = struct.unpack_from(order + "Q", data, 0x28)
            shentsize, shnum, shstrndx = struct.unpack_from(order + "HHH", data, 0x3A)
        else:
            shoff, = struct.unpack_from(order + "I", data, 0x20)
            shentsize, shnum, shstrndx = struct.unpack_from(order + "HHH", data, 0x2E)
        if shoff == 0 or shnum == 0 or shstrndx >= shnum:
            return []

        def header(index: int) -> tuple[int, int, int]:
            base = shoff + index * shentsize
            if is64:
                name, _, _, _, offset, size = struct.unpack_from(order + "IIQQQQ", data, base)
            else:
                name, _, _, _, offset, size = struct.unpack_from(order + "IIIIII", data, base)
            return name, offset, size

        _, str_offset, str_size = header(shstrndx)
        strings = data[str_offset:str_offset + str_size]
        names: list[str] = []
        for index in range(shnum):
            name_offset, _, _ = header(index)
            end = strings.find(b"\0", name_offset)
            names.append(strings[name_offset:end if end >= 0 else None].decode("latin-1"))
        return names
    except struct.error:
        return None


def leaked_sections(binary: Path) -> list[str]:
    names = elf_section_names(binary) or []
    return [name for name in FAIL_CLOSED_SECTIONS if name in names]


def discover(executable: Path, binary: Path, timeout: float) -> tuple[list[tuple[str, int]], str]:
    """What ``afl`` lists: ``(name, address)``, with a placeholder for an unnamed one."""
    try:
        proc = subprocess.run(  # noqa: S603
            [str(executable), "-q", "-c", "afl", str(binary)],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return [], f"harness: r2s afl timed out after {timeout:g}s"
    functions: list[tuple[str, int]] = []
    for line in proc.stdout.splitlines():
        fields = line.split()
        if not fields or not fields[0].startswith("0x"):
            continue
        try:
            address = int(fields[0], 16)
        except ValueError:
            continue
        name = fields[-1] if len(fields) > 1 else "-"
        functions.append((f"sub_{address:x}" if name == "-" else name, address))
    ending = "" if proc.returncode == 0 else f"r2s afl exited {proc.returncode}"
    return functions, ending


def stack_offset(location: str) -> int | None:
    """``stack-0x14``, ``[rbp-0x14]`` or ``sp+8`` -> the signed offset."""
    found = _STACK_OFFSET.search(location.strip())
    if not found:
        return None
    value = int(found.group(2), 0)
    return -value if found.group(1) == "-" else value


def to_function(record: dict, address: int, requested: str | None) -> FunctionDecompilation:
    """A pddj record as DecBench's function record, filed under ``requested`` if given."""
    definition = str(record.get("definition") or "")
    code = str(record.get("code") or "")
    name = definition or f"sub_{address:x}"
    if requested and requested != definition and definition:
        # The caller knows the function by a name; the definition takes it, in
        # the code and in the key, exactly as DecBench's own relabel does.
        code = re.sub(rf"\b{re.escape(definition)}\b", requested, code)
        name = requested
    elif requested and not definition:
        name = requested
    code_lines = code.splitlines()
    mappings = [
        LineMapping(line_number=int(entry["line"]),
                    addresses=sorted({int(a) for a in entry.get("addrs", [])}))
        for entry in record.get("lines", [])
        if isinstance(entry, dict) and entry.get("addrs")
    ]
    variables: list[VariableInfo] = []
    arg_index = 0
    for entry in record.get("variables", []):
        if not isinstance(entry, dict) or entry.get("kind") not in ("param", "local"):
            continue
        var_name = str(entry.get("name", ""))
        pattern = re.compile(rf"\b{re.escape(var_name)}\b") if var_name else None
        line_numbers = [n + 1 for n, text in enumerate(code_lines)
                        if pattern is not None and pattern.search(text)]
        if entry["kind"] == "param":
            variables.append(VariableInfo(
                name=var_name, type=str(entry.get("type", "")), kind="arg",
                arg_index=arg_index, line_numbers=line_numbers,
            ))
            arg_index += 1
        else:
            variables.append(VariableInfo(
                name=var_name, type=str(entry.get("type", "")), kind="stack",
                stack_offset=stack_offset(str(entry.get("location", ""))),
                line_numbers=line_numbers,
            ))
    proof = record.get("proof") if isinstance(record.get("proof"), dict) else {}
    metadata = dict(common.extract_metrics(code))
    metadata.update({
        "definition": definition,
        "signature": record.get("signature", ""),
        "proof": proof,
        "residual": int(proof.get("residual", 0) or 0),
    })
    return FunctionDecompilation(
        name=name,
        address=address,
        decompiled_code=code,
        line_count=len(code_lines),
        line_mappings=mappings,
        variables=variables,
        metadata=metadata,
    )


@register_decompiler(BACKEND)
class R2sDecompiler(Decompiler):
    """r2sleigh through ``r2s pddj``: typed declines, pass-through addresses."""

    name = BACKEND
    display_name = "r2sleigh (r2s)"

    def __init__(self, config: DecompilerConfig | None = None):
        super().__init__(config)
        self._version: str | None = None

    def is_available(self) -> bool:
        executable = r2s_bin()
        if executable is None or not os.access(executable, os.X_OK):
            return False
        shell = shutil.which("sh") or "/bin/sh"
        try:
            proc = subprocess.run(  # noqa: S603
                [str(executable), "-q", "-c", "?e r2s-alive", shell],
                capture_output=True, text=True, timeout=60, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return "r2s-alive" in proc.stdout

    def get_version(self) -> str | None:
        """The exact build: a result names the r2s that produced it."""
        if self._version is None:
            executable = r2s_bin()
            if executable is None:
                return None
            digest = hashlib.sha256(executable.read_bytes()).hexdigest()[:16]
            self._version = f"r2s sha256:{digest}"
        return self._version

    def decompile_binary(
        self,
        binary_path: Path,
        functions: list[tuple[str, int]] | None = None,
        output_dir: Path | None = None,
        function_names: set[int] | None = None,
        progress_path: Path | None = None,
    ) -> DecompilationResult:
        started = time.time()
        binary_path = Path(binary_path)
        executable = r2s_bin()
        timeout = float(os.environ.get("R2SLEIGH_FUNCTION_TIMEOUT", "300"))

        # What was asked, by address, with the caller's name when it gave one.
        requested: dict[int, str | None] = {}
        for name, address in functions or []:
            requested.setdefault(int(address), name or None)
        for address in sorted(common.addr_targets_of(function_names)):
            requested.setdefault(address, None)
        source = "targets" if requested else "afl"

        declined: dict[str, str] = {}
        rendered: dict[str, FunctionDecompilation] = {}
        extra: dict = {"requested_from": source}

        def result() -> DecompilationResult:
            extra.update({
                "requested": len(requested),
                "rendered": len(rendered),
                "declined": len(declined),
                "decline_causes": dict(sorted(declined.items())),
            })
            return DecompilationResult(
                binary_path=binary_path,
                binary_name=binary_path.stem,
                decompiler=DecompilerMetadata(
                    decompiler_name=self.id,
                    decompiler_version=self.get_version(),
                    total_time_seconds=time.time() - started,
                    failed_functions=sorted(declined),
                    extra=dict(extra),
                ),
                functions=dict(rendered),
                output_dir=output_dir,
            )

        leaked = leaked_sections(binary_path)
        if leaked:
            # Fail closed: nothing r2s says about this file is admissible.
            cause = (f"harness: the binary carries {' and '.join(leaked)}; r2s would read the "
                     "declarations DecBench scores against (strip --strip-all it, as "
                     "scripts/run_benchmark.py does)")
            for address, name in requested.items() or [(0, None)]:
                declined[name or (f"0x{address:x}" if address else binary_path.name)] = cause
            extra["fail_closed"] = leaked
            return result()
        if executable is None:
            cause = "harness: no r2s ($R2SLEIGH_R2S_BIN unset and r2s not on PATH)"
            for address, name in requested.items() or [(0, None)]:
                declined[name or (f"0x{address:x}" if address else binary_path.name)] = cause
            return result()

        if not requested:
            found, ending = discover(executable, binary_path, timeout)
            text = common.elf_text_ranges(binary_path)
            kept = [(n, a) for n, a in found
                    if not common.should_skip_function(n, a, text, set())]
            for _, address in kept:
                requested.setdefault(address, None)
            extra["discovered"] = len(found)
            if not requested:
                declined[binary_path.name] = (
                    "harness: afl found no function to render"
                    + (f" ({ending})" if ending else "")
                )
                return result()

        def file_answer(answer: "r2s_batch.Answer") -> None:
            name = requested.get(answer.address)
            key = name or f"0x{answer.address:x}"
            if answer.ok and answer.record is not None:
                function = to_function(answer.record, answer.address, name)
                if function.name in rendered:
                    function.name = f"{function.name}_{answer.address:x}"
                rendered[function.name] = function
            else:
                declined[key] = answer.cause or "harness: no answer"
            common.dump_progress(progress_path, result())

        report = r2s_batch.run_batch(
            executable, binary_path, list(requested), function_timeout=timeout,
            on_answer=file_answer,
        )
        extra["processes"] = report.processes
        extra["process_endings"] = report.endings
        if len(rendered) + len(declined) != len(requested):
            raise RuntimeError(
                f"{binary_path.name}: {len(rendered)} rendered + {len(declined)} declined "
                f"!= {len(requested)} requested"
            )
        _write_census(output_dir, binary_path, declined, rendered)
        return result()


def _write_census(output_dir: Path | None, binary_path: Path, declined: dict[str, str],
                  rendered: dict[str, FunctionDecompilation]) -> None:
    """Why each function was declined and how much of each rendering is residual.

    DecBench keeps one ``decompiled`` boolean per function, so a sweep says how
    many were declined and never why. This file, beside the run, is the why.
    Failure to write is deliberately silent: it is measurement about a
    measurement and must never fail a sweep.
    """
    override = os.environ.get("R2SLEIGH_REFUSAL_CENSUS_DIR")
    target = Path(override) if override else Path(output_dir) if output_dir else binary_path.parent
    try:
        counts: dict[str, int] = {}
        for cause in declined.values():
            counts[cause] = counts.get(cause, 0) + 1
        residual = {name: f.metadata.get("residual", 0) for name, f in rendered.items()
                    if f.metadata.get("residual", 0)}
        payload = {
            "schema_version": 4,
            "backend": BACKEND,
            "binary": binary_path.name,
            "binary_path": str(binary_path),
            "rendered": len(rendered),
            "declined": len(declined),
            "causes": dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))),
            "by_function": dict(sorted(declined.items())),
            "with_residual": len(residual),
            "fully_proven": len(rendered) - len(residual),
            "residual_by_function": dict(sorted(residual.items())),
        }
        stem = str(binary_path).strip("/").replace("/", "_")
        path = target / f"r2sleigh-refusals-{stem}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    except OSError:
        return
