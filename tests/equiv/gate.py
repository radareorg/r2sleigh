"""Grade one rendering against its original, and hold the population to a ratchet.

One function yields exactly one record, whatever happened on the way. Its
status is one of:

========================  ====================================================
``equal``                 every vector inside the original's domain agreed
``residual-trap``         agreed wherever it ran; on some vectors execution
                          reached a counted ``r2sleigh_residual_*`` trap, and
                          what it printed before the trap (and, for a residual
                          the rendering returns, the memory it wrote) agreed
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
                          past its budget on some vector (:mod:`cost`): not
                          evidence of a wrong answer, and not ``equal`` either
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
``harness-error``         the runtime itself failed, r2s was never asked, or
                          the target's loader would bind an object link
                          elsewhere (``link.loader_conflicts``)
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
import re
import signal
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import link
from cost import Cost
from dwarf import Dwarf
from r2s_batch import Answer
from spec import CallSpec
from target import X86_64, Target
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
    cost: Cost = field(default_factory=Cost)
    keep: bool = False
    min_graded: int | None = None
    compile_timeout: float = link.COMPILE_TIMEOUT
    # The machine the graded binaries are built for, and how to run them.
    target: Target = X86_64

    def driver_ceiling(self, vector_count: int) -> float:
        """Seconds the runtime may take for these vectors before it is presumed stuck:
        every run of every vector ending at its guard."""
        per_vector_ms = (self.cost.budget * 22 if self.cost.measure == "time"
                         else self.cost.hang_ms * 6)
        return max(120.0, vector_count * per_vector_ms / 1000.0 + 60.0)

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
    # The measure and budget the run counted by (cost.Cost.to_json).
    cost: dict = field(default_factory=dict)

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
            "cost": self.cost,
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
    sites = residual_sites(pddj.get("residuals"))
    return grade_code(record, workdir, binary, dwarf, spec, code, definition, links, config,
                      sites)


def residual_sites(residuals) -> dict[int, dict]:
    """``pddj``'s residuals by site number: what the rendering states each one stands for."""
    if not isinstance(residuals, list):
        return {}
    return {entry["site"]: entry for entry in residuals
            if isinstance(entry, dict) and isinstance(entry.get("site"), int)}


def grade_code(record: Record, workdir: Path, binary: Path, dwarf: Dwarf, spec: CallSpec,
               code: str, definition: str, links: list[dict], config: Config,
               sites: dict[int, dict] | None = None) -> Record:
    workdir.mkdir(parents=True, exist_ok=True)
    inside = link.links_into_body(links, spec.guard())
    if inside:
        record.status = "compile-error"
        record.evidence = {"variant": "link", "diagnostics": "\n".join(inside)}
        return record
    target = config.target
    if target.objects_through_loader:
        conflicts = link.loader_conflicts(link.shim_objects(links, definition), str(binary),
                                          str(config.runtime), target)
        if conflicts:
            # The rendering cannot be run against the objects it names here.
            record.status = "harness-error"
            record.evidence = {"cause": "; ".join(conflicts)}
            return record
    identity = link.build_trampoline(config.cc, workdir, spec.address, target)
    builds, strict, skipped = link.build_rendering(config.cc, workdir, code, links, definition,
                                                   link.needed_libraries(str(binary), target),
                                                   spec.address, config.compile_timeout, target)
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
    vectors = build_vectors(spec, dwarf, config.vectors, record.key, target.abi)
    job = workdir / "job.bin"
    job.write_bytes(encode_job(spec, runs, list(PAIRS), vectors, config.cost, abi=target.abi))
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
    helpers = ResidualHelpers(str(builds["O0"].path),
                              link.residual_helpers(builds["O0"].path, target),
                              target.trap_signal)
    status, evidence, counts = classify(vector_lines, vectors, residual, helpers,
                                        config.floor(), sites)
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

    An emulated target runs under the same prefix. qemu-user gives its guest
    no address randomisation of its own: it places the guest's image, stack
    and mappings by a first-fit search from fixed bases, so the guest layout
    is a function of the host addresses qemu's own mappings took, and with the
    host's randomisation off those are fixed too.
    """
    prefix = ("setarch", os.uname().machine, "-R")
    try:
        proc = subprocess.run([*prefix, "/bin/true"], capture_output=True, check=False)
    except FileNotFoundError:
        return ()
    return prefix if proc.returncode == 0 else ()


def run_driver(binary: Path, job: Path, out: Path, config: Config,
               vector_count: int) -> tuple[bool, str, list[dict]]:
    # The runtime's variables reach the binary alone (Target.run_argv):
    # setarch, which runs first, and an emulator must not load it themselves.
    assignments = [
        f"LD_PRELOAD={config.runtime}",
        "LD_BIND_NOW=1",
        f"EQUIV_JOB={job}",
        f"EQUIV_OUT={out}",
        "UBSAN_OPTIONS=print_stacktrace=0:halt_on_error=1:exitcode=86",
    ]
    argv = [*fixed_layout_prefix(), *config.target.run_argv(binary, assignments)]
    budget = config.driver_ceiling(vector_count)
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
    # What __builtin_trap raises on the target: SIGILL (ud2) on x86-64,
    # SIGTRAP (brk) on AArch64.
    trap_signal: int = signal.SIGILL

    def reached(self, run: dict) -> str | None:
        """The helper a run died of the trap signal inside, or None.

        A trap is a reached residual only at a program counter inside one of
        these helpers of this object: a ``__builtin_trap`` anywhere else, or a
        stray illegal instruction, is the rendering ending differently.
        """
        if run.get("outcome") != "signal" or run.get("status") != self.trap_signal:
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


# A residual of this cause is a whole return statement (r2dec render/control.rs), so the
# state at its trap is the state the original returns with.
RETURN_POSITION = frozenset({"unproven-return"})
# The statuses that rest on a floor of vectors compared with the original.
_FLOORED = ("equal", "residual-trap")


def classify(vector_lines: list[dict], vectors: list, residual: int,
             helpers: ResidualHelpers, min_graded: int = 1,
             sites: dict[int, dict] | None = None) -> tuple[str, dict, dict]:
    """A record's status from its vectors.

    ``compared`` counts the vectors whose rendering was compared with the
    original: every pair agreed, or the run trapped at a residual and what it
    had done by then was compared. Of the trapping ones, ``trap_compared``
    counts those, and ``trap_memory`` those whose memory was compared too.
    """
    counts = {"total": len(vector_lines), "dropped": 0, "unstable": 0, "incomplete": 0,
              "graded": 0, "compared": 0, "trap_compared": 0, "trap_memory": 0, "equal": 0,
              "residual-trap": 0, "slow": 0, "differs": 0, "uninit": 0, "ub": 0}
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
                    "runs": [_run_evidence(run) for run in runs
                             if run.get("outcome") in ("unavailable", "hang")],
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
                verdict, at_trap, compared = _at_trap(primary, runs[ORIGINAL], o0, helper,
                                                      sites or {})
                found[verdict] = at_trap
                counts["trap_compared"] += bool(compared)
                counts["trap_memory"] += compared == "memory"
            elif _over_budget(o0):
                # Running past the budget is a cost, not an answer: nothing it
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
            late = [RUN_LABELS[i] for i in (O0, PATTERN) if len(runs) > i and _over_budget(runs[i])]
            if late:
                found.setdefault("slow", {"build": ", ".join(late)})
            else:
                found["uninit"] = {"detector": "auto-var-init zero vs pattern",
                                   **_pair_evidence(uninit)}
        optimised = pairs.get((O0, O2))
        if optimised is not None and not optimised.get("equal") and "ub" not in found:
            late = [RUN_LABELS[i] for i in (O0, O2) if len(runs) > i and _over_budget(runs[i])]
            if late:
                found.setdefault("slow", {"build": ", ".join(late)})
            else:
                found["ub"] = {"detector": "-O0 and -O2 builds disagree",
                               **_pair_evidence(optimised)}
        status = next((s for s in _VECTOR_SEVERITY if s in found), "equal")
        counts[status] += 1
        if status == "equal" or (status == "residual-trap" and primary.get("pre_trap")):
            counts["compared"] += 1
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
    rested = counts["compared"] if status in _FLOORED else counts["graded"]
    if rested < min_graded:
        if counts["graded"] == 0:
            cause = "no vector survived the original" if counts["dropped"] else "no vectors"
            if counts["unstable"]:
                cause = "the original does not agree with itself on any surviving vector"
        elif rested < counts["graded"]:
            cause = (f"only {rested} of {counts['graded']} graded vectors were compared with "
                     f"the original; an {status} verdict needs {min_graded}")
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


def residual_cause(entry: dict | None) -> str:
    """What a residual site stands for, as ``pddj`` states it: its cause, and a gap's kind."""
    if not entry:
        return "unstated"
    cause = str(entry.get("cause") or "unstated")
    return f"{cause}:{entry['gap']}" if cause == "gap" and entry.get("gap") else cause


def _at_trap(primary: dict, original: dict, o0: dict, helper: str,
             sites: dict[int, dict]) -> tuple[str, dict, str]:
    """A vector whose rendering trapped at a residual, graded on what it did before.

    Its output so far must be a prefix of the original's. Its memory is held to
    the original's final state only where the trap stands for the return of the
    call the gate made: a return-position residual in the outermost activation.
    Returns the vector's status, its evidence and what was compared (``""``,
    ``"output"`` or ``"memory"``).
    """
    site = o0.get("trap_site")
    entry = sites.get(site) if isinstance(site, int) else None
    evidence = {"helper": helper, "site": site, "residual_cause": residual_cause(entry),
                "fault_offset": _run_evidence(o0).get("fault_offset")}
    snapshot = primary.get("pre_trap")
    if not snapshot:
        return "residual-trap", evidence, ""
    detector = "state before the residual trap"
    for stream in ("stdout", "stderr"):
        if not snapshot.get(stream):
            return "differs", {"detector": detector, "field": stream, **evidence,
                               "original": _run_evidence(original),
                               "rendering": _run_evidence(o0)}, "output"
    if not (evidence["residual_cause"] in RETURN_POSITION and o0.get("trap_depth") == "outermost"
            and original.get("outcome") == "return"):
        return "residual-trap", evidence, "output"
    if not snapshot.get("memory"):
        return "differs", {"detector": detector, **_pair_evidence(snapshot), **evidence}, "memory"
    return "residual-trap", evidence, "memory"


def trap_comparison(status: str, counts: dict) -> str | None:
    """What every trapping vector of a ``residual-trap`` record compared before its trap, the
    weakest of them: ``memory``, ``output`` or ``none``; None for any other status. One vector
    losing its snapshot weakens the record, so the ratchet sees it."""
    if status != "residual-trap":
        return None
    trapped = counts.get("residual-trap", 0)
    compared = counts.get("trap_compared", 0)
    if not compared or compared < trapped:
        return "none"
    return "memory" if counts.get("trap_memory", 0) >= compared else "output"


def _run_evidence(run: dict) -> dict:
    """A run as a record keeps it: a fault as an offset into its object."""
    # `insns` is a count the counter may vary in its last digits: no record keeps it.
    kept = {key: value for key, value in run.items()
            if key not in ("fault_pc", "fault_base", "insns")}
    try:
        kept["fault_offset"] = hex(int(str(run["fault_pc"]), 16) - int(str(run["fault_base"]), 16))
    except (KeyError, ValueError):
        pass
    return kept


def _over_budget(run: dict) -> bool:
    """Only a run the budget stopped is slow; ``hang`` is the wall-clock guard, which
    load moves and which therefore never grades cost."""
    return run.get("outcome") == "budget"


def _pair_evidence(pair: dict | None) -> dict:
    if not pair:
        return {"field": "not compared"}
    return {key: pair[key] for key in ("field", "address", "a_bytes", "b_bytes") if key in pair}


def _clip(text: str, lines: int) -> str:
    kept = text.splitlines()[:lines]
    return "\n".join(line[:300] for line in kept)


# ------------------------------------------------------------------ ratchet


REPO = Path(__file__).resolve().parents[2]
BASELINE_SCHEMA = 3
# Causes that say nothing about their record, which the ratchet refuses (audit T20).
PLACEHOLDER_CAUSES = (
    re.compile(r"not (?:yet )?triaged", re.I),
    re.compile(r"\b(?:todo|tbd|fixme|xxx)\b", re.I),
    re.compile(r"placeholder", re.I),
    re.compile(r"the run reaches a counted residual", re.I),
)


def load_baseline(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != BASELINE_SCHEMA or not isinstance(payload.get("records"), dict):
        raise ValueError(f"{path}: not an equivalence baseline (schema {BASELINE_SCHEMA})")
    return payload


@functools.lru_cache(maxsize=None)
def roadmap_items(roadmap: Path = REPO / "ROADMAP.md") -> frozenset[str]:
    """The items ROADMAP.md's plan tables name (``| **P7** ...``): the owners a cause may name."""
    return frozenset(re.findall(r"^\| \*\*([A-Z][A-Z0-9]*)\*\*", roadmap.read_text("utf-8"),
                                re.M))


def cause_problems(entry: dict, repo: Path = REPO) -> list[str]:
    """Why a non-equal baseline entry's cause does not stand: it is missing or a
    placeholder, its owner is no ROADMAP.md item, or its site no repository path."""
    cause = str(entry.get("cause") or "").strip()
    if not cause:
        return ["has no recorded cause"]
    problems = []
    if len(cause.split()) < 6 or any(pattern.search(cause) for pattern in PLACEHOLDER_CAUSES):
        problems.append(f"has a placeholder cause: {cause[:60]!r}")
    owner = entry.get("owner")
    if owner not in roadmap_items(repo / "ROADMAP.md"):
        problems.append(f"names an owner that is no ROADMAP.md item: {owner!r}")
    site = entry.get("site")
    if (not isinstance(site, str) or not site or Path(site).is_absolute()
            or ".." in Path(site).parts or not (repo / site).exists()):
        problems.append(f"names a site that is no path in the repository: {site!r}")
    return problems


def reason(status: str, evidence: dict) -> str:
    """Why a record has its status, normalised so the same cause reads the same.

    The ratchet holds this beside the status: a refusal that keeps its status
    for another cause is a different defect, and so is a disagreement in
    another field. Addresses, generated names and source line numbers move with
    every build and every edit, so they are erased; what is left names the
    cause, not where it happened to land.
    """
    if status == "equal":
        return ""
    if status == "residual-trap":
        text = " ".join(str(evidence.get(key, "")) for key in ("helper", "residual_cause"))
    elif status in ("differs", "ub", "uninit"):
        text = " ".join(str(evidence.get(key, "")) for key in ("detector", "field")).strip()
    elif status == "compile-error":
        errors = [line.split("error:", 1)[1] for line in str(evidence.get("diagnostics", "")).splitlines()
                  if "error:" in line]
        text = errors[0] if errors else ""
    elif status == "slow":
        text = str(evidence.get("build", ""))
    else:
        text = str(evidence.get("cause", ""))
    text = re.sub(r"\b(?:fcn|sub)[._][0-9a-f]+\b", "fcn", text)
    text = re.sub(r"0x[0-9a-fA-F]+", "0x", text)
    text = re.sub(r"(?<=0x):(?:op:)?\d+", "", text)
    text = re.sub(r"\b([A-Za-z_][\w/]*\.rs):\d+(?::\d+)?", r"\1", text)
    return " ".join(text.split())


def graded(record: Record) -> tuple[str, str, str | None]:
    """What the ratchet holds of a record: its status, its reason, and what a
    ``residual-trap`` compared before its traps."""
    return (record.status, reason(record.status, record.evidence),
            trap_comparison(record.status, record.vectors))


def ratchet(baseline: dict, records: dict[str, "str | tuple"],
            selected: set[str] | None = None) -> list[str]:
    """Every way ``records`` departs from ``baseline``.

    The baseline is exact, so it only moves by a bless:

    * a record's status must be the baseline's -- falling short blocks, and so
      does improving, because an improvement the baseline does not hold is one
      the next change may silently lose;
    * a ``differs``, ``uninit`` or ``ub`` the baseline does not record blocks
      under its own message, as the worst departure;
    * a non-``equal`` record must fail for the reason the baseline records,
      where it records one;
    * a ``residual-trap`` must compare what the baseline says it compared
      before its traps (``memory``, ``output`` or ``none``), so a record cannot
      silently go back to comparing nothing;
    * a function the baseline knows must still be graded, and one it does not
      know must be blessed (when ``selected`` is given, only the selected keys
      are held);
    * every non-``equal`` baseline record carries a cause that stands
      (:func:`cause_problems`): no placeholder, an owner, a site.

    ``records`` maps a key to its status, or to :func:`graded`'s tuple (or its
    first two members).
    """
    problems: list[str] = []
    held = baseline["records"]

    def split(graded):
        return (*graded, None, None)[:3] if isinstance(graded, tuple) else (graded, None, None)

    for key, entry in sorted(held.items()):
        if selected is not None and key not in selected:
            continue
        before = entry.get("status")
        if before != "equal":
            problems.extend(f"{key}: baseline status {before} {why}"
                            for why in cause_problems(entry))
        if key not in records:
            problems.append(f"{key}: in the baseline but not graded by this run")
            continue
        now, why, compared = split(records[key])
        if now in BLOCKING and now != before:
            problems.append(f"{key}: new {now} (baseline: {before})")
        elif before == "equal" and now != "equal":
            problems.append(f"{key}: left equal (now {now})")
        elif now != before:
            problems.append(f"{key}: {before} -> {now}; bless it with its cause")
        elif why is not None and entry.get("reason") is not None and why != entry["reason"]:
            problems.append(f"{key}: still {now}, for another reason: {why!r} "
                            f"(baseline: {entry['reason']!r})")
        elif compared is not None and compared != entry.get("compared"):
            problems.append(f"{key}: compares {compared} before its residual traps "
                            f"(baseline: {entry.get('compared')})")
    for key, graded in sorted(records.items()):
        if key in held:
            continue
        now, _, _ = split(graded)
        if now in BLOCKING:
            problems.append(f"{key}: new {now} (baseline: absent)")
        else:
            problems.append(f"{key}: not in the baseline (now {now}); bless it")
    return problems


def baseline_from(records: list[Record], previous: dict | None = None,
                  toolchain: dict[str, str] | None = None,
                  cost: Cost | None = None) -> dict:
    """A baseline holding this run, keeping every cause, owner and site a
    previous one recorded for the same status and reason. It names the measure
    and budget the run counted by (:func:`cost.departure` holds later runs to them)."""
    old = (previous or {}).get("records", {})
    out: dict[str, dict] = {}
    for record in sorted(records, key=lambda r: r.key):
        entry: dict = {"status": record.status}
        if record.status != "equal":
            status, why, compared = graded(record)
            kept = old.get(record.key, {})
            same = kept.get("status") == status and kept.get("reason", why) == why
            for name in ("cause", "owner", "site"):
                entry[name] = kept.get(name) if same else None
            entry["reason"] = why
            if compared is not None:
                entry["compared"] = compared
        out[record.key] = entry
    return {
        "schema": BASELINE_SCHEMA,
        "toolchain": toolchain if toolchain is not None else (previous or {}).get("toolchain"),
        "cost": cost.to_json() if cost is not None else (previous or {}).get("cost"),
        "note": (previous or {}).get("note") or (
            "Blessed by the integrator after reading records.json. A non-equal record needs a "
            "cause, its ROADMAP.md owner and its site before the ratchet accepts this file."
        ),
        "records": out,
    }


def environment_problem(target: Target = X86_64) -> str | None:
    """Why this machine cannot run the gate for ``target``, or None."""
    return target.environment_problem()
