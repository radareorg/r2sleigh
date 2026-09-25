"""Ask one r2s process about many addresses, and account for every one.

Both consumers of a rendering -- the equivalence gate (``tests/equiv``) and the
DecBench adapter (``tests/decbench/r2sleigh_raw.py``) -- ask the same question
of the same shell: for each address, ``s <addr>; pddj``. This module is the one
place that asks it, so the two cannot drift on how an answer is read.

r2s is started once, ``r2s -q <binary>``, and fed one line per address on its
stdin, ``?e BEGIN<i>; s <addr>; pddj; ?e END<i>``, the next line only after the
previous one's END marker has come back. r2s reads each stdin line as a script
of its own, so one address's failed statement never touches the next, and the
batch has no size limit: nothing grows with the address count but the time.
(A ``-c`` script would carry every address in one argv string, which Linux
caps at 128 KiB, about 1,950 addresses.)

The contract it keeps is that every requested address comes back with exactly
one :class:`Answer`, whatever happened to the process:

* ``output``  -- the command printed an answer (for ``pddj`` a JSON object);
* ``decline`` -- r2s said no: a ``r2s: <message>`` line (stderr is merged into
  stdout, so the message lands inside the markers it belongs to), a ``pddj``
  whose ``refused`` field is set, or one that breaks the ``pddj`` contract;
* ``crash``   -- the process died, or ran past its deadline, while this address
  was being answered. The cause names how it ended and carries the last lines
  it printed, and the batch restarts at the next address, so one crash costs
  one function rather than the rest of the binary.

Deadlines are per phase. Opening the binary, up to the first BEGIN marker, has
its own budget (``startup_timeout``); a process that cannot open it in time,
or exits before it starts, answers every remaining address with that one
cause, once, rather than once per address. Each address then has
``function_timeout`` from its BEGIN marker.

Rust's stdout is line-buffered and ``eprintln!`` is unbuffered, so with
``stderr=STDOUT`` a statement's error line arrives between the markers of the
statement that caused it. A marker is found wherever it sits on its line: an
answer printed without a trailing newline runs into the END marker after it.
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


def statement_line(address: int, command: str, index: int) -> str:
    """The one stdin line that asks about one address, between its markers."""
    return f"?e {BEGIN}{index}; s 0x{address:x}; {command}; ?e {END}{index}\n"


def split_marker(line: str, marker: str) -> tuple[str, int] | None:
    """``(text before, index)`` when ``line`` ends in ``marker<index>``, else None.

    ``?e`` ends its line after the marker, so the marker is always the end of
    its line; what comes before it is output that had no newline of its own.
    """
    before, found, after = line.rpartition(marker)
    if not found or not after.isdigit():
        return None
    return before, int(after)


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
    startup_timeout: float | None = None,
    on_answer: Callable[[Answer], None] | None = None,
    env: dict[str, str] | None = None,
) -> BatchReport:
    """Answer every address, restarting r2s after a crash or a deadline.

    ``function_timeout`` bounds each address from its BEGIN marker;
    ``startup_timeout`` (default: ``function_timeout``) bounds a process from
    its start to its first BEGIN marker. ``on_answer`` is called once per
    address, in request order, as soon as its answer is final -- the adapter
    uses it to checkpoint after every function.
    """
    pending = list(addresses)
    startup = function_timeout if startup_timeout is None else startup_timeout
    report = BatchReport()
    index = 0
    while pending:
        answers, consumed, ending, before = _one_process(
            r2s, binary, pending, index, command, parse, function_timeout, startup, env
        )
        report.processes += 1
        report.endings.append(ending)
        for answer in answers:
            report.answers.append(answer)
            if on_answer is not None:
                on_answer(answer)
        if consumed == 0:
            # The process ended, or ran out of its startup budget, before it
            # began the first address: every restart would do the same, so the
            # rest share this one cause.
            for address in pending:
                answer = Answer(address, before.kind, cause=before.cause, text=before.text)
                report.answers.append(answer)
                if on_answer is not None:
                    on_answer(answer)
            break
        pending = pending[consumed:]
        index += consumed
    return report


def _one_process(r2s, binary, addresses, first_index, command, parse, function_timeout,
                 startup_timeout, env):
    """Run one r2s over ``addresses``, one stdin line each, until it finishes or dies.

    Returns the answers it produced, how many addresses they cover (a crash
    counts the address it died on), how the process ended, and -- for a
    process that never began an address -- the answer every remaining address
    shares.
    """
    argv = [str(r2s), "-q", str(binary)]
    process_env = dict(os.environ)
    process_env.setdefault("RUST_BACKTRACE", "0")
    if env:
        process_env.update(env)
    proc = subprocess.Popen(  # noqa: S603
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
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

    def send(text: str) -> bool:
        assert proc.stdin is not None
        try:
            proc.stdin.write(text.encode())
            proc.stdin.flush()
            return True
        except (BrokenPipeError, OSError):
            return False

    answers: list[Answer] = []
    tail: list[str] = []
    body: list[str] = []
    began = False          # the current address's BEGIN marker has come back
    timed_out = False
    deadline_used = startup_timeout
    ended = False
    started = time.monotonic()
    for offset, address in enumerate(addresses):
        index = first_index + offset
        began = False
        body = []
        budget = startup_timeout if offset == 0 else function_timeout
        deadline_used = budget
        started = time.monotonic()
        if not send(statement_line(address, command, index)):
            ended = True
            break
        answered = False
        while not answered:
            remaining = budget - (time.monotonic() - started)
            if remaining <= 0:
                timed_out = True
                break
            try:
                line = lines.get(timeout=remaining)
            except queue.Empty:
                timed_out = True
                break
            if line is None:
                ended = True
                break
            stripped = line.rstrip("\n")
            tail = (tail + [stripped])[-6:]
            end = split_marker(stripped, END)
            if end is not None and began and end[1] == index:
                if end[0]:
                    body.append(end[0])
                answer = parse(address, "\n".join(body))
                answer.seconds = time.monotonic() - started
                answers.append(answer)
                answered = True
                continue
            begin = split_marker(stripped, BEGIN)
            if begin is not None and begin[1] == index:
                # Anything before the marker belongs to no address.
                began = True
                body = []
                budget = function_timeout
                deadline_used = budget
                started = time.monotonic()
                continue
            if began:
                body.append(stripped)
        if not answered:
            break

    if timed_out:
        _kill(proc)
    if proc.stdin is not None:
        try:
            proc.stdin.close()
        except (BrokenPipeError, OSError):
            pass
    try:
        returncode = proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        _kill(proc)
        returncode = proc.wait()
    thread.join(timeout=5)
    if proc.stdout is not None:
        proc.stdout.close()
    # Whatever the process printed after the point it stopped being read.
    while True:
        try:
            late = lines.get_nowait()
        except queue.Empty:
            break
        if late is not None:
            tail = (tail + [late.rstrip("\n")])[-6:]
    ending = ending_of(returncode, timed_out, deadline_used)
    last = " | ".join(line for line in tail
                      if line and split_marker(line, BEGIN) is None
                      and split_marker(line, END) is None)

    consumed = len(answers)
    before = Answer(0, "crash")
    if consumed < len(addresses) and (timed_out or ended):
        address = addresses[consumed]
        if began:
            # It died, or ran out of time, on this address: charge it, and the
            # batch restarts at the next one.
            cause = f"harness: r2s {ending} while rendering 0x{address:x}"
            if last:
                cause += f" (last output: {last[:400]})"
            answers.append(Answer(address, "crash", text="\n".join(body), cause=cause,
                                  seconds=time.monotonic() - started))
            consumed += 1
        elif consumed == 0:
            before = _before_answer(ending, timed_out, returncode, tail, last)
        # Otherwise it stopped between two addresses: nothing to charge, and
        # the next process starts at the address it never began.
    return answers, consumed, ending, before


def _before_answer(ending: str, timed_out: bool, returncode: int | None, tail: list[str],
                   last: str) -> Answer:
    """What a process that never began an address says about every one of them."""
    errors = [line[len(ERROR_PREFIX):].strip() for line in tail if line.startswith(ERROR_PREFIX)]
    if errors and not timed_out and returncode is not None and returncode >= 0:
        # r2s said why it would not open the binary: its own decline.
        return Answer(0, "decline", text="\n".join(tail), cause="r2s: " + "; ".join(errors))
    cause = f"harness: r2s {ending} before answering"
    if timed_out:
        cause = f"harness: r2s did not open the binary: {ending}"
    if last:
        cause += f" (last output: {last[:400]})"
    return Answer(0, "crash", text="\n".join(tail), cause=cause)


def _kill(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass
