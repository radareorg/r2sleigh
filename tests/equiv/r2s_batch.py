"""Ask one r2s process about many addresses, and account for every one.

Both consumers of a rendering -- the equivalence gate (``tests/equiv``) and the
DecBench adapter (``tests/decbench/r2sleigh_raw.py``) -- ask the same question
of the same shell: for each address, ``s <addr>; pddj``. This module is the one
place that asks it, so the two cannot drift on how an answer is read.

The contract it keeps is that every requested address comes back with exactly
one :class:`Answer`, whatever happened to the process:

* ``output``  -- the command printed an answer (for ``pddj`` a JSON object);
* ``decline`` -- r2s said no: a ``r2s: <message>`` line (stderr is merged into
  stdout, so the message lands inside the markers it belongs to), or a
  ``pddj`` whose ``refused`` field is set;
* ``crash``   -- the process died, or ran past its deadline, while this address
  was being answered. The cause names how it ended and carries the last lines
  it printed, and the batch restarts at the next address, so one crash costs
  one function rather than the rest of the binary.

r2s exits 1 when any statement failed. With every marker present that is a
completed batch with declines, never a crash. Only a signal, a deadline, or a
missing END marker is a process failure.

Rust's stdout is line-buffered and ``eprintln!`` is unbuffered, so with
``stderr=STDOUT`` a statement's error line arrives between the markers of the
statement that caused it.
"""

from __future__ import annotations

import json
import os
import queue
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

BEGIN = "R2S_BATCH_BEGIN__"
END = "R2S_BATCH_END__"
ERROR_PREFIX = "r2s: "


@dataclass
class Answer:
    """One address's answer. ``kind`` is ``output``, ``decline`` or ``crash``."""

    address: int
    kind: str
    text: str = ""
    cause: str = ""
    record: dict | None = None
    seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return self.kind == "output"


@dataclass
class BatchReport:
    answers: list[Answer] = field(default_factory=list)
    processes: int = 0
    endings: list[str] = field(default_factory=list)

    def by_address(self) -> dict[int, Answer]:
        return {answer.address: answer for answer in self.answers}


def signal_name(number: int) -> str:
    try:
        return signal.Signals(number).name
    except ValueError:
        return f"signal {number}"


def ending_of(returncode: int | None, timed_out: bool, deadline: float) -> str:
    if timed_out:
        return f"timed out after {deadline:g}s"
    if returncode is None:
        return "ended without a status"
    if returncode < 0:
        return f"killed by signal {-returncode} ({signal_name(-returncode)})"
    return f"exited {returncode}"


def _script(addresses: list[int], command: str, first_index: int) -> str:
    parts: list[str] = []
    for offset, address in enumerate(addresses):
        index = first_index + offset
        parts.append(f"?e {BEGIN}{index}")
        parts.append(f"s 0x{address:x}")
        parts.append(command)
        parts.append(f"?e {END}{index}")
    return "; ".join(parts)


def parse_pddj(address: int, body: str) -> Answer:
    """Read one address's slice of a ``pddj`` batch."""
    errors = [line[len(ERROR_PREFIX):].strip() for line in body.splitlines()
              if line.startswith(ERROR_PREFIX)]
    payload = "\n".join(line for line in body.splitlines()
                        if not line.startswith(ERROR_PREFIX)).strip()
    if not payload:
        cause = "; ".join(errors) if errors else "r2s printed nothing"
        return Answer(address, "decline", text=body, cause=f"r2s: {cause}")
    try:
        record = json.loads(payload)
    except json.JSONDecodeError as error:
        first = payload.splitlines()[0][:160]
        return Answer(
            address, "decline", text=body,
            cause=f"harness: pddj is not one JSON object ({error.msg}): {first}",
        )
    if not isinstance(record, dict):
        return Answer(address, "decline", text=body,
                      cause="harness: pddj printed JSON that is not an object")
    problems = contract_problems(record)
    if problems:
        return Answer(address, "decline", text=body, record=record,
                      cause="harness: pddj breaks its contract: " + "; ".join(problems))
    refused = record.get("refused")
    if refused:
        reason = refused.get("reason") if isinstance(refused, dict) else str(refused)
        return Answer(address, "decline", text=body, record=record,
                      cause=f"refused: {reason or 'no reason given'}")
    return Answer(address, "output", text=body, record=record)


# The fields every pddj record carries. A missing field is a contract breach,
# reported as a harness decline rather than guessed around.
PDDJ_FIELDS = {
    "name": str,
    "addr": int,
    "definition": str,
    "signature": str,
    "code": str,
    "proof": dict,
    "variables": list,
    "lines": list,
    "links": list,
}
PROOF_COUNTERS = ("rendered", "elided", "refused", "residual", "split",
                  "compiler_inserted", "assumed")


def contract_problems(record: dict) -> list[str]:
    problems: list[str] = []
    refused = record.get("refused")
    for name, kind in PDDJ_FIELDS.items():
        if name not in record:
            # A refused function need not carry the rendering's fields.
            if refused and name not in ("name", "addr"):
                continue
            problems.append(f"no `{name}`")
        elif not isinstance(record[name], kind) or (kind is int and isinstance(record[name], bool)):
            problems.append(f"`{name}` is not {kind.__name__}")
    if refused is not None and not isinstance(refused, dict):
        problems.append("`refused` is neither null nor an object")
    proof = record.get("proof")
    if isinstance(proof, dict) and not refused:
        for counter in PROOF_COUNTERS:
            if not isinstance(proof.get(counter), int):
                problems.append(f"proof.{counter} is not a count")
    for link in record.get("links") or []:
        if not isinstance(link, dict) or not isinstance(link.get("ident"), str):
            problems.append("a link has no `ident`")
            break
        if link.get("kind") not in ("function", "object", "import"):
            problems.append(f"link `{link.get('ident')}` has kind {link.get('kind')!r}")
            break
    return problems


def run_batch(
    r2s: Path | str,
    binary: Path | str,
    addresses: Iterable[int],
    *,
    command: str = "pddj",
    parse: Callable[[int, str], Answer] = parse_pddj,
    function_timeout: float = 300.0,
    on_answer: Callable[[Answer], None] | None = None,
    env: dict[str, str] | None = None,
) -> BatchReport:
    """Answer every address, restarting r2s after a crash or a deadline.

    ``function_timeout`` bounds each address, measured from its BEGIN marker (or
    from the process start for the first one). ``on_answer`` is called once per
    address, in request order, as soon as its answer is final -- the adapter
    uses it to checkpoint after every function.
    """
    pending = list(addresses)
    report = BatchReport()
    index = 0
    while pending:
        answers, consumed, ending = _one_process(
            r2s, binary, pending, index, command, parse, function_timeout, env
        )
        report.processes += 1
        report.endings.append(ending)
        for answer in answers:
            report.answers.append(answer)
            if on_answer is not None:
                on_answer(answer)
        if consumed == 0:
            # The process died before it started on the first address: every
            # restart would do the same, so the rest share this one cause.
            cause = f"harness: r2s {ending} before answering"
            for address in pending:
                answer = Answer(address, "crash", cause=cause)
                report.answers.append(answer)
                if on_answer is not None:
                    on_answer(answer)
            break
        pending = pending[consumed:]
        index += consumed
    return report


def _one_process(r2s, binary, addresses, first_index, command, parse, function_timeout, env):
    """Run one r2s over ``addresses`` until it finishes or dies.

    Returns the answers it produced, how many addresses they cover (a crash
    counts the address it died on), and how the process ended.
    """
    argv = [str(r2s), "-q", "-c", _script(addresses, command, first_index), str(binary)]
    process_env = dict(os.environ)
    process_env.setdefault("RUST_BACKTRACE", "0")
    if env:
        process_env.update(env)
    proc = subprocess.Popen(  # noqa: S603
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        env=process_env,
        start_new_session=True,
    )
    lines: queue.Queue[str | None] = queue.Queue()

    def reader() -> None:
        assert proc.stdout is not None
        for raw in iter(proc.stdout.readline, b""):
            lines.put(raw.decode("utf-8", "replace"))
        lines.put(None)

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()

    answers: list[Answer] = []
    current: int | None = None
    body: list[str] = []
    started = time.monotonic()
    tail: list[str] = []
    timed_out = False
    finished = False
    while not finished:
        remaining = function_timeout - (time.monotonic() - started)
        if remaining <= 0:
            timed_out = True
            break
        try:
            line = lines.get(timeout=remaining)
        except queue.Empty:
            timed_out = True
            break
        if line is None:
            finished = True
            break
        stripped = line.rstrip("\n")
        tail = (tail + [stripped])[-6:]
        if stripped.startswith(BEGIN):
            try:
                current = int(stripped[len(BEGIN):]) - first_index
            except ValueError:
                current = None
            body = []
            started = time.monotonic()
            continue
        if stripped.startswith(END):
            if current is not None and 0 <= current < len(addresses) and current == len(answers):
                answer = parse(addresses[current], "\n".join(body))
                answer.seconds = time.monotonic() - started
                answers.append(answer)
            current = None
            body = []
            started = time.monotonic()
            if len(answers) == len(addresses):
                # Every address answered; the rest is the process exiting.
                pass
            continue
        if current is not None:
            body.append(stripped)

    if timed_out:
        _kill(proc)
    try:
        returncode = proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        _kill(proc)
        returncode = proc.wait()
    thread.join(timeout=5)
    if proc.stdout is not None:
        proc.stdout.close()
    ending = ending_of(returncode, timed_out, function_timeout)

    consumed = len(answers)
    if consumed < len(addresses):
        # The address the process was on when it stopped, if it had begun one.
        # The markers are printed in order, so a stop before the next BEGIN is
        # a stop between statements: nothing to charge, restart from there.
        if current is not None or timed_out:
            address = addresses[consumed]
            last = " | ".join(line for line in tail if line and not line.startswith(BEGIN))
            cause = f"harness: r2s {ending} while rendering 0x{address:x}"
            if last:
                cause += f" (last output: {last[:400]})"
            answers.append(Answer(address, "crash", text="\n".join(body), cause=cause,
                                  seconds=time.monotonic() - started))
            consumed += 1
    return answers, consumed, ending


def _kill(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass
