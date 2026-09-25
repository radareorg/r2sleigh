"""Grade one rendering against its original, and hold the population to a ratchet.

One function yields exactly one record, whatever happened on the way. Its
status is one of:

========================  ====================================================
``equal``                 every vector inside the original's domain agreed
``residual-trap``         agreed wherever it ran; on some vectors execution
                          reached a counted ``r2sleigh_residual_*`` trap
``differs``               some vector returned, wrote, printed or ended
                          differently; the evidence names the vector and field
``uninit``                the ``=zero`` and ``=pattern`` builds disagree: the
                          rendering read a local nothing wrote
``ub``                    UBSan reported, or the ``-O0`` and ``-O2`` builds
                          disagree
``compile-error``         a build or its load failed; the diagnostic is kept
``refused``               r2s refused the function, with its reason
``no-record``             r2s printed no usable ``pddj`` (crash, timeout,
                          unknown command, broken contract), with the cause
``unsupported``           the thunk cannot call this signature (aggregate by
                          value, variadic definition, ...); the reason is kept
``untested``              no vector survived the original (all dropped) or the
                          harness could not reproduce the original
``harness-error``         the runtime itself failed
========================  ====================================================

The first seven grade the engine; the last four say the gate could not. A
vector the original does not return or exit from is dropped as outside its
domain. A vector on which the original, called twice (directly and through a
trampoline in a loaded object), does not agree with itself is ``unstable`` and
dropped too, so nondeterminism in the program can never read as a defect of
the rendering.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import link
from dwarf import Dwarf
from r2s_batch import Answer
from spec import CallSpec
from vectors import Run, build_vectors, encode_job

RUN_LABELS = ("original", "identity", "O0", "pattern", "O2", "ubsan")
ORIGINAL, IDENTITY, O0, PATTERN, O2, UBSAN = range(6)
PAIRS = ((ORIGINAL, IDENTITY), (ORIGINAL, O0), (O0, PATTERN), (O0, O2))

ENGINE_STATUSES = ("equal", "residual-trap", "differs", "uninit", "ub", "compile-error",
                   "refused")
HARNESS_STATUSES = ("no-record", "unsupported", "untested", "harness-error")
STATUSES = ENGINE_STATUSES + HARNESS_STATUSES
# Worst first, among the statuses a vector can have.
_VECTOR_SEVERITY = ("ub", "uninit", "differs", "residual-trap", "equal")
# Findings that block a landing whenever they are new.
BLOCKING = frozenset({"differs", "uninit", "ub"})


@dataclass
class Config:
    runtime: Path
    cc: str = "gcc"
    vectors: int = 48
    timeout_ms: int = 1000
    keep: bool = False


@dataclass
class Record:
    key: str
    function: str
    address: int
    status: str
    evidence: dict = field(default_factory=dict)
    signature: str = ""
    definition: str = ""
    proof: dict = field(default_factory=dict)
    vectors: dict = field(default_factory=dict)
    strict: str = ""

    def to_json(self) -> dict:
        return {
            "key": self.key,
            "function": self.function,
            "address": f"0x{self.address:x}",
            "status": self.status,
            "evidence": self.evidence,
            "signature": self.signature,
            "definition": self.definition,
            "proof": self.proof,
            "vectors": self.vectors,
            "strict": self.strict,
        }


def grade(key: str, workdir: Path, binary: Path, dwarf: Dwarf, spec: CallSpec,
          answer: Answer | None, config: Config) -> Record:
    record = Record(key=key, function=spec.name, address=spec.address, status="harness-error",
                    signature=spec.describe())
    if answer is None:
        record.status = "no-record"
        record.evidence = {"cause": "harness: r2s was not asked for this address"}
        return record
    if answer.record is not None:
        record.definition = str(answer.record.get("definition", ""))
        proof = answer.record.get("proof")
        record.proof = proof if isinstance(proof, dict) else {}
    if answer.kind == "decline" and answer.record is not None and answer.record.get("refused"):
        record.status = "refused"
        record.evidence = {"cause": answer.cause}
        return record
    if not answer.ok:
        record.status = "no-record"
        record.evidence = {"cause": answer.cause}
        return record
    if spec.unsupported:
        record.status = "unsupported"
        record.evidence = {"cause": spec.unsupported}
        return record
    pddj = answer.record or {}
    code = str(pddj.get("code", ""))
    definition = str(pddj.get("definition", ""))
    links = [entry for entry in pddj.get("links", []) if isinstance(entry, dict)]
    return grade_code(record, workdir, binary, dwarf, spec, code, definition, links, config)


def grade_code(record: Record, workdir: Path, binary: Path, dwarf: Dwarf, spec: CallSpec,
               code: str, definition: str, links: list[dict], config: Config) -> Record:
    workdir.mkdir(parents=True, exist_ok=True)
    identity = link.build_trampoline(config.cc, workdir, spec.address)
    builds, strict, skipped = link.build_rendering(config.cc, workdir, code, links, definition)
    record.strict = strict
    if not identity.ok:
        record.status = "harness-error"
        record.evidence = {"cause": "cannot build the identity trampoline",
                           "diagnostics": identity.diagnostics[:2000]}
        return record
    failed = [build for build in builds.values() if not build.ok]
    if failed:
        record.status = "compile-error"
        record.evidence = {
            "variant": failed[0].variant,
            "diagnostics": _clip(failed[0].diagnostics, 40),
            "skipped_links": skipped,
        }
        return record

    runs = [
        Run("original", address=spec.address),
        Run("identity", so_path=str(identity.path), symbol="equiv_identity"),
        *(Run(variant, so_path=str(builds[variant].path), symbol=definition)
          for variant in ("O0", "pattern", "O2", "ubsan")),
    ]
    vectors = build_vectors(spec, dwarf, config.vectors, record.key)
    job = workdir / "job.bin"
    job.write_bytes(encode_job(spec, runs, list(PAIRS), vectors, config.timeout_ms))
    out = workdir / "result.jsonl"
    ok, cause, lines = run_driver(binary, job, out, config, len(vectors))
    if not ok:
        record.status = "harness-error"
        record.evidence = {"cause": cause}
        return record
    header, vector_lines = lines[0], lines[1:]
    load_errors = [run for run in header.get("runs", []) if run.get("error")]
    if load_errors:
        record.status = "compile-error"
        record.evidence = {
            "variant": load_errors[0].get("label"),
            "diagnostics": "load: " + str(load_errors[0].get("error")),
        }
        return record
    residual = int(record.proof.get("residual", 0) or 0)
    status, evidence, counts = classify(vector_lines, vectors, residual,
                                        str(builds["O0"].path))
    record.status = status
    record.evidence = evidence
    record.vectors = counts
    if not config.keep and status == "equal":
        for path in workdir.glob("*.so"):
            path.unlink(missing_ok=True)
        job.unlink(missing_ok=True)
    return record


def run_driver(binary: Path, job: Path, out: Path, config: Config,
               vector_count: int) -> tuple[bool, str, list[dict]]:
    env = {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "LD_PRELOAD": str(config.runtime),
        "LD_BIND_NOW": "1",
        "EQUIV_JOB": str(job),
        "EQUIV_OUT": str(out),
        "UBSAN_OPTIONS": "print_stacktrace=0:halt_on_error=1:exitcode=86",
    }
    budget = max(120.0, vector_count * config.timeout_ms * 22 / 1000.0 + 60.0)
    out.unlink(missing_ok=True)
    try:
        proc = subprocess.run(
            [str(binary)], env=env, cwd=str(out.parent), capture_output=True, timeout=budget,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, f"the runtime ran past {budget:g}s", []
    lines: list[dict] = []
    if out.exists():
        for raw in out.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                lines.append(json.loads(raw))
            except json.JSONDecodeError:
                return False, f"the runtime wrote a line that is not JSON: {raw[:200]}", []
    stderr = proc.stderr.decode("utf-8", "replace").strip()
    if proc.returncode != 0 or not lines or not lines[-1].get("done"):
        errors = [line.get("error") for line in lines if line.get("error")]
        how = (f"killed by {signal.Signals(-proc.returncode).name}" if proc.returncode < 0
               else f"exited {proc.returncode}")
        cause = f"the runtime {how}"
        if errors:
            cause += f": {errors[0]}"
        elif stderr:
            cause += f": {stderr.splitlines()[-1][:300]}"
        return False, cause, lines
    return True, "", lines[:-1]


def classify(vector_lines: list[dict], vectors: list, residual: int,
             o0_object: str) -> tuple[str, dict, dict]:
    counts = {"total": len(vector_lines), "dropped": 0, "unstable": 0, "graded": 0,
              "equal": 0, "residual-trap": 0, "differs": 0, "uninit": 0, "ub": 0}
    first: dict[str, dict] = {}
    unstable_example: dict | None = None
    for line in vector_lines:
        index = int(line.get("vector", -1))
        runs = line.get("runs", [])
        pairs = {(p["a"], p["b"]): p for p in line.get("pairs", [])}
        shown = vectors[index].shown if 0 <= index < len(vectors) else []
        if not runs or runs[ORIGINAL].get("outcome") not in ("return", "exit"):
            counts["dropped"] += 1
            continue
        identity = pairs.get((ORIGINAL, IDENTITY))
        if identity is None or not identity.get("equal"):
            counts["unstable"] += 1
            if unstable_example is None:
                unstable_example = {"vector": index, "inputs": shown, **_pair_evidence(identity)}
            continue
        counts["graded"] += 1
        found: dict[str, dict] = {}
        ubsan = runs[UBSAN] if len(runs) > UBSAN else {}
        if "runtime error" in str(ubsan.get("stderr", "")):
            found["ub"] = {"detector": "ubsan", "report": _clip(str(ubsan.get("stderr")), 8)}
        primary = pairs.get((ORIGINAL, O0))
        if primary is not None and not primary.get("equal"):
            o0 = runs[O0] if len(runs) > O0 else {}
            trapped = (
                o0.get("outcome") == "signal"
                and o0.get("status") == signal.SIGILL
                and str(o0.get("fault_object", "")) == o0_object
            )
            if trapped and residual > 0:
                found["residual-trap"] = {"fault_pc": o0.get("fault_pc")}
            else:
                found["differs"] = {**_pair_evidence(primary), "original": runs[ORIGINAL],
                                    "rendering": o0}
        uninit = pairs.get((O0, PATTERN))
        if uninit is not None and not uninit.get("equal"):
            found["uninit"] = {"detector": "auto-var-init zero vs pattern",
                               **_pair_evidence(uninit)}
        optimised = pairs.get((O0, O2))
        if optimised is not None and not optimised.get("equal") and "ub" not in found:
            found["ub"] = {"detector": "-O0 and -O2 builds disagree", **_pair_evidence(optimised)}
        status = next((s for s in _VECTOR_SEVERITY if s in found), "equal")
        counts[status] += 1
        if status != "equal" and status not in first:
            first[status] = {"vector": index, "inputs": shown, **found[status]}
    if counts["graded"] == 0:
        cause = "no vector survived the original" if counts["dropped"] else "no vectors"
        if counts["unstable"]:
            cause = "the original does not agree with itself on any surviving vector"
        evidence = {"cause": cause}
        if unstable_example:
            evidence["unstable"] = unstable_example
        return "untested", evidence, counts
    status = next((s for s in _VECTOR_SEVERITY if counts[s]), "equal")
    evidence = dict(first.get(status, {}))
    if unstable_example is not None:
        evidence["unstable_example"] = unstable_example
    return status, evidence, counts


def _pair_evidence(pair: dict | None) -> dict:
    if not pair:
        return {"field": "not compared"}
    return {key: pair[key] for key in ("field", "address", "a_bytes", "b_bytes") if key in pair}


def _clip(text: str, lines: int) -> str:
    kept = text.splitlines()[:lines]
    return "\n".join(line[:300] for line in kept)


# ------------------------------------------------------------------ ratchet


def load_baseline(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != 1 or not isinstance(payload.get("records"), dict):
        raise ValueError(f"{path}: not an equivalence baseline (schema 1)")
    return payload


def ratchet(baseline: dict, records: dict[str, str], selected: set[str] | None = None) -> list[str]:
    """Every way ``records`` (key -> status) falls short of ``baseline``.

    * a function the baseline holds ``equal`` must still be ``equal``;
    * a ``differs``, ``uninit`` or ``ub`` the baseline does not already record
      for that function blocks;
    * a function the baseline knows must still be graded (when ``selected`` is
      given, only the selected keys are held);
    * every non-``equal`` baseline record carries a recorded cause.
    """
    problems: list[str] = []
    held = baseline["records"]
    for key, entry in sorted(held.items()):
        if selected is not None and key not in selected:
            continue
        before = entry.get("status")
        if before != "equal" and not entry.get("cause"):
            problems.append(f"{key}: baseline status {before} has no recorded cause")
        now = records.get(key)
        if now is None:
            problems.append(f"{key}: in the baseline but not graded by this run")
            continue
        if before == "equal" and now != "equal":
            problems.append(f"{key}: left equal (now {now})")
    for key, now in sorted(records.items()):
        before = held.get(key, {}).get("status")
        if now in BLOCKING and now != before:
            problems.append(f"{key}: new {now} (baseline: {before or 'absent'})")
    return problems


def baseline_from(records: list[Record], previous: dict | None = None) -> dict:
    """A baseline holding this run, keeping every cause a previous one recorded."""
    old = (previous or {}).get("records", {})
    out: dict[str, dict] = {}
    for record in sorted(records, key=lambda r: r.key):
        entry = {"status": record.status}
        cause = old.get(record.key, {}).get("cause")
        if record.status != "equal":
            entry["cause"] = cause if cause and old.get(record.key, {}).get("status") == record.status else None
        out[record.key] = entry
    return {
        "schema": 1,
        "note": (
            "Blessed by the integrator after reading records.json. A non-equal record needs a "
            "cause before the ratchet accepts this file."
        ),
        "records": out,
    }


def environment_problem() -> str | None:
    """Why this machine cannot run the gate, or None."""
    if os.uname().machine not in ("x86_64", "amd64"):
        return f"runtime equivalence needs x86-64 (this is {os.uname().machine})"
    if not Path("/proc/self/exe").exists():
        return "runtime equivalence needs Linux"
    return None
