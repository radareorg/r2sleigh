"""Grade one rendering against its original, and hold the population to a ratchet.

One function yields exactly one record, whatever happened on the way. Its
status is one of:

========================  ====================================================
``equal``                 every vector inside the original's domain agreed
``residual-trap``         agreed wherever it ran; on some vectors execution
                          reached a counted ``r2sleigh_residual_*`` trap
``differs``               some vector returned, wrote, printed or ended
                          differently; the evidence names the vector and field.
                          A rendering that passes control to the original's
                          own code (delegation) ends differently by
                          construction, and the evidence says so
``uninit``                the ``=zero`` and ``=pattern`` builds disagree: the
                          rendering read a local nothing wrote
``ub``                    UBSan reported, or the ``-O0`` and ``-O2`` builds
                          disagree on a vector both finished
``slow``                  every finished run agreed, but a rendering build ran
                          out of its time budget on some vector: not evidence
                          of a wrong answer, and not ``equal`` either
``compile-error``         the compiler or the loader rejected a build; the
                          diagnostic is kept (a compiler that timed out or
                          could not run is the harness's: ``harness-error``)
``refused``               r2s refused the function, with its reason, in a
                          ``pddj`` that keeps the contract
``no-record``             r2s printed no usable ``pddj`` (crash, timeout,
                          unknown command, broken contract), with the cause
``unsupported``           the thunk cannot call this signature (aggregate by
                          value, variadic definition, ...); the reason is kept
``untested``              too few vectors survived the original to rest an
                          ``equal`` on (fewer than a quarter of them, see
                          :meth:`Config.floor`), or the harness could not
                          reproduce the original
``harness-error``         the runtime itself failed, or r2s was never asked
========================  ====================================================

The first eight grade the engine -- a crash, a deadline or a broken contract
is r2s failing to answer, which is the engine's to fix -- and the last three
say the gate could not. A
vector the original does not return or exit from is dropped as outside its
domain. A vector on which the original, called twice (directly and through a
trampoline in a loaded object), does not agree with itself is ``unstable`` and
dropped too, so nondeterminism in the program can never read as a defect of
the rendering. A vector counts as graded only when every comparison it needs
was made; one a rendering run could not be made on (a failed fork, a failed
capture reset) leaves the record ``harness-error`` unless another vector
already found a defect.
"""

from __future__ import annotations

import functools
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

ENGINE_STATUSES = ("equal", "residual-trap", "slow", "differs", "uninit", "ub", "compile-error",
                   "refused", "no-record")
HARNESS_STATUSES = ("unsupported", "untested", "harness-error")
STATUSES = ENGINE_STATUSES + HARNESS_STATUSES
# Worst first, among the statuses a vector can have.
_VECTOR_SEVERITY = ("ub", "uninit", "differs", "residual-trap", "slow", "equal")
# Findings that block a landing whenever they are new.
BLOCKING = frozenset({"differs", "uninit", "ub"})


@dataclass
class Config:
    runtime: Path
    cc: str = "gcc"
    vectors: int = 48
    timeout_ms: int = 1000
    keep: bool = False
    min_graded: int | None = None
    compile_timeout: float = link.COMPILE_TIMEOUT

    def floor(self) -> int:
        """How many graded vectors an ``equal`` or ``residual-trap`` must rest on.

        A quarter of the vectors: every function of the default population
        grades at least 13 of 48 (an index past a pointer table is outside the
        original's domain), and a verdict on one or two survivors says nothing.
        """
        return self.min_graded if self.min_graded is not None else max(1, self.vectors // 4)


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
        record.status = "harness-error"
        record.evidence = {"cause": "harness: r2s was not asked for this address"}
        return record
    if answer.record is not None:
        record.definition = str(answer.record.get("definition", ""))
        proof = answer.record.get("proof")
        record.proof = proof if isinstance(proof, dict) else {}
    if answer.refusal is not None:
        record.status = "refused"
        record.evidence = {"cause": answer.cause}
        return record
    if not answer.ok:
        # A crash, a deadline, a failed statement or a record that breaks the
        # contract -- including one that also says it refuses.
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
    inside = link.links_into_body(links, spec.guard())
    if inside:
        record.status = "compile-error"
        record.evidence = {"variant": "link", "diagnostics": "\n".join(inside)}
        return record
    identity = link.build_trampoline(config.cc, workdir, spec.address)
    builds, strict, skipped = link.build_rendering(config.cc, workdir, code, links, definition,
                                                   link.needed_libraries(str(binary)),
                                                   spec.address, config.compile_timeout)
    record.strict = strict
    if not identity.ok:
        record.status = "harness-error"
        record.evidence = {"cause": "cannot build the identity trampoline",
                           "diagnostics": identity.diagnostics[:2000]}
        return record
    failed = [build for build in builds.values() if not build.ok]
    unrun = [build for build in failed if not build.ran]
    if failed:
        # A compiler that gave no verdict (a timeout on a loaded machine, a
        # missing compiler) says nothing about the rendering.
        record.status = "harness-error" if unrun else "compile-error"
        shown = (unrun or failed)[0]
        record.evidence = {
            "variant": shown.variant,
            "diagnostics": _clip(shown.diagnostics, 40),
            "skipped_links": skipped,
        }
        return record

    runs = [
        Run("original", address=spec.address),
        Run("identity", so_path=str(identity.path), symbol="equiv_identity"),
        *(Run(variant, so_path=str(builds[variant].path), symbol=definition, replaces=True)
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
    helpers = ResidualHelpers(str(builds["O0"].path), link.residual_helpers(builds["O0"].path))
    status, evidence, counts = classify(vector_lines, vectors, residual, helpers,
                                        config.floor())
    record.status = status
    record.evidence = evidence
    record.vectors = counts
    if not config.keep and status == "equal":
        for path in workdir.glob("*.so"):
            path.unlink(missing_ok=True)
        job.unlink(missing_ok=True)
    return record


@functools.lru_cache(maxsize=None)
def fixed_layout_prefix() -> tuple[str, ...]:
    """The command prefix that runs a program with address randomisation off.

    With it, every address a record's evidence carries -- a fault in a loaded
    rendering, a pointer a function returned, the stack -- is the same on
    every run, so two runs of the gate write the same records. Empty where the
    personality cannot be set (some container sandboxes refuse it); the run
    then says so in its config.
    """
    prefix = ("setarch", os.uname().machine, "-R")
    try:
        proc = subprocess.run([*prefix, "/bin/true"], capture_output=True, check=False)
    except FileNotFoundError:
        return ()
    return prefix if proc.returncode == 0 else ()


def run_driver(binary: Path, job: Path, out: Path, config: Config,
               vector_count: int) -> tuple[bool, str, list[dict]]:
    # The runtime's variables are set by env(1), the last program before the
    # binary: setarch, which runs first, must not load the runtime itself.
    assignments = [
        f"LD_PRELOAD={config.runtime}",
        "LD_BIND_NOW=1",
        f"EQUIV_JOB={job}",
        f"EQUIV_OUT={out}",
        "UBSAN_OPTIONS=print_stacktrace=0:halt_on_error=1:exitcode=86",
    ]
    argv = [*fixed_layout_prefix(), "/usr/bin/env", *assignments, str(binary)]
    budget = max(120.0, vector_count * config.timeout_ms * 22 / 1000.0 + 60.0)
    out.unlink(missing_ok=True)
    try:
        proc = subprocess.run(
            argv, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, cwd=str(out.parent),
            capture_output=True, timeout=budget, check=False, stdin=subprocess.DEVNULL,
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


@dataclass
class ResidualHelpers:
    """The ``-O0`` build's ``r2sleigh_residual_*`` functions: where a residual traps."""

    object_path: str
    ranges: list[tuple[int, int, str]] = field(default_factory=list)

    def reached(self, run: dict) -> str | None:
        """The helper a run died of SIGILL inside, or None.

        A trap is a reached residual only at a program counter inside one of
        these helpers of this object: a ``__builtin_trap`` anywhere else, or a
        stray illegal instruction, is the rendering ending differently.
        """
        if run.get("outcome") != "signal" or run.get("status") != signal.SIGILL:
            return None
        if str(run.get("fault_object", "")) != self.object_path:
            return None
        try:
            offset = int(str(run.get("fault_pc")), 16) - int(str(run.get("fault_base")), 16)
        except ValueError:
            return None
        for start, end, name in self.ranges:
            if start <= offset < end:
                return name
        return None


def classify(vector_lines: list[dict], vectors: list, residual: int,
             helpers: ResidualHelpers, min_graded: int = 1) -> tuple[str, dict, dict]:
    counts = {"total": len(vector_lines), "dropped": 0, "unstable": 0, "incomplete": 0,
              "graded": 0, "equal": 0, "residual-trap": 0, "slow": 0, "differs": 0, "uninit": 0,
              "ub": 0}
    first: dict[str, dict] = {}
    unstable_example: dict | None = None
    incomplete_example: dict | None = None
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
        missing = [pair for pair in PAIRS[1:] if pair not in pairs]
        if missing:
            # A rendering run that could not be made: nothing was compared.
            counts["incomplete"] += 1
            if incomplete_example is None:
                incomplete_example = {
                    "vector": index, "inputs": shown,
                    "not_compared": [f"{RUN_LABELS[a]}-{RUN_LABELS[b]}" for a, b in missing],
                    "runs": [run for run in runs if run.get("outcome") == "unavailable"],
                }
            continue
        counts["graded"] += 1
        found: dict[str, dict] = {}
        ubsan = runs[UBSAN] if len(runs) > UBSAN else {}
        if "runtime error" in str(ubsan.get("stderr", "")):
            found["ub"] = {"detector": "ubsan", "report": _clip(str(ubsan.get("stderr")), 8)}
        primary = pairs.get((ORIGINAL, O0))
        if primary is not None and not primary.get("equal"):
            o0 = runs[O0] if len(runs) > O0 else {}
            helper = helpers.reached(o0) if residual > 0 else None
            if helper is not None:
                found["residual-trap"] = {"helper": helper,
                                          "fault_offset": _run_evidence(o0).get("fault_offset")}
            elif _timed_out(o0):
                # Running out of time is a cost, not an answer: nothing it
                # computed can be compared.
                found["slow"] = {"build": "O0", "original": _run_evidence(runs[ORIGINAL])}
            else:
                found["differs"] = {**_pair_evidence(primary),
                                    "original": _run_evidence(runs[ORIGINAL]),
                                    "rendering": _run_evidence(o0)}
                if o0.get("guard") == "delegated":
                    found["differs"]["guard"] = "delegated"
                    found["differs"]["cause"] = (
                        "the rendering passed control to the original function's own entry "
                        "instead of computing the result itself")
                elif o0.get("guard") == "body":
                    found["differs"]["guard"] = "body"
                    found["differs"]["cause"] = (
                        f"control reached the original function's body at {o0.get('fault_pc')}")
        uninit = pairs.get((O0, PATTERN))
        if uninit is not None and not uninit.get("equal"):
            late = [RUN_LABELS[i] for i in (O0, PATTERN) if len(runs) > i and _timed_out(runs[i])]
            if late:
                found.setdefault("slow", {"build": ", ".join(late)})
            else:
                found["uninit"] = {"detector": "auto-var-init zero vs pattern",
                                   **_pair_evidence(uninit)}
        optimised = pairs.get((O0, O2))
        if optimised is not None and not optimised.get("equal") and "ub" not in found:
            late = [RUN_LABELS[i] for i in (O0, O2) if len(runs) > i and _timed_out(runs[i])]
            if late:
                found.setdefault("slow", {"build": ", ".join(late)})
            else:
                found["ub"] = {"detector": "-O0 and -O2 builds disagree",
                               **_pair_evidence(optimised)}
        status = next((s for s in _VECTOR_SEVERITY if s in found), "equal")
        counts[status] += 1
        if status != "equal" and status not in first:
            first[status] = {"vector": index, "inputs": shown, **found[status]}
    status = next((s for s in _VECTOR_SEVERITY if counts[s]), "equal")
    if status in BLOCKING:
        # A defect one vector showed stands however few vectors were graded.
        evidence = dict(first[status])
        if unstable_example is not None:
            evidence["unstable_example"] = unstable_example
        return status, evidence, counts
    if incomplete_example is not None:
        return "harness-error", {"cause": "a rendering run could not be made",
                                 **incomplete_example}, counts
    if counts["graded"] < min_graded:
        if counts["graded"] == 0:
            cause = "no vector survived the original" if counts["dropped"] else "no vectors"
            if counts["unstable"]:
                cause = "the original does not agree with itself on any surviving vector"
        else:
            cause = (f"only {counts['graded']} of {counts['total']} vectors survived the "
                     f"original; an {status} verdict needs {min_graded}")
        evidence = {"cause": cause}
        if unstable_example:
            evidence["unstable"] = unstable_example
        return "untested", evidence, counts
    evidence = dict(first.get(status, {}))
    if unstable_example is not None:
        evidence["unstable_example"] = unstable_example
    return status, evidence, counts


def _run_evidence(run: dict) -> dict:
    """A run as a record keeps it: a fault as an offset into its object."""
    kept = {key: value for key, value in run.items() if key not in ("fault_pc", "fault_base")}
    try:
        kept["fault_offset"] = hex(int(str(run["fault_pc"]), 16) - int(str(run["fault_base"]), 16))
    except (KeyError, ValueError):
        pass
    return kept


def _timed_out(run: dict) -> bool:
    return run.get("outcome") == "timeout"


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
