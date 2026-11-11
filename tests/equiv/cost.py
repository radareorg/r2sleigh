"""What a run's cost counts, what each run may spend, and whether this host can count it.

A cost is a number of one measure (ADR D38). ``time`` is the CPU time the call
uses; ``instructions`` is the user-space instructions it retires, counted by
``perf_event_open`` in the runtime. A rendering is graded against its original
on the same vector and runner (ADR D339): its allowance is a factor times the
original's cost, so a faster or slower runner moves both. Every record and every
baseline states its measure, budget and factor, and the ratchet never compares
across them (:func:`departure`).
"""

from __future__ import annotations

import ctypes
import errno
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from target import Target

MEASURES = ("time", "instructions")
# A like-for-like run (the identity, the -O2 build) may cost this many times the original
# (ADR D339); an unoptimised build (-O0, pattern, UBSan) this many times that.
RENDERING_FACTOR = 4
DEFAULT_TIME_MS = 1000
# About a second of this corpus's loops (README, Cost).
DEFAULT_INSTRUCTIONS = 4_000_000_000
# The wall clock only ends a run that does not run (a blocked call), so it is long enough that a
# loaded host does not reach it; the loaded legs of D38's gate ran at 120 s.
DEFAULT_HANG_MS = 120_000


@dataclass(frozen=True)
class Cost:
    """A budget ``B`` in one measure, and what each run may spend against it (ADR D339).

    With ``k`` = :data:`RENDERING_FACTOR`, an original may cost ``k*k*B``; past that the vector
    is outside its domain. A like-for-like run may cost ``k * max(c, B/(k*k))``, ``c`` the
    original's cost on the vector, and an unoptimised build ``k`` times that. Below ``B/(k*k)``
    a cost is too small to compare, so ``B/k`` and ``B`` are the floors.
    """

    measure: str = "time"
    budget: int = DEFAULT_TIME_MS
    hang_ms: int = DEFAULT_HANG_MS
    # Tests only: the costs the original and every rendering report in place of the measure.
    fake_original: int = 0
    fake_rendering: int = 0

    def to_json(self) -> dict:
        return {"measure": self.measure, "budget": self.budget, "factor": RENDERING_FACTOR}

    def ticks(self, amount: int) -> int:
        """``amount`` of this measure in the runtime's ticks: instructions, or CPU nanoseconds."""
        return amount * 1_000_000 if self.measure == "time" else amount

    def original_guard(self) -> int:
        return self.ticks(RENDERING_FACTOR * RENDERING_FACTOR * self.budget)

    def floor(self) -> int:
        return self.ticks(self.budget) // (RENDERING_FACTOR * RENDERING_FACTOR)

    @staticmethod
    def factor(optimised: bool) -> int:
        """A run's allowance over its original's cost: an unoptimised build's -O0 code is the
        compiler's cost, not the rendering's (ADR D339)."""
        return RENDERING_FACTOR if optimised else RENDERING_FACTOR * RENDERING_FACTOR

    def worst_vector_ms(self, runs: int) -> int:
        """Wall milliseconds one vector of ``runs`` runs may take with every run at its guard."""
        if self.measure != "time":
            return runs * self.hang_ms
        k, b = RENDERING_FACTOR, self.budget
        cpu = [k * k * b] + [k * k * k * k * b] * (runs - 1)
        return sum(self.hang_ms + 5 * ms for ms in cpu)


class CostRefused(Exception):
    """This host or target cannot grade by the requested measure."""


def resolve(measure: str, target: Target, timeout_ms: int = DEFAULT_TIME_MS,
            instructions: int = DEFAULT_INSTRUCTIONS, hang_ms: int = DEFAULT_HANG_MS,
            counter: Callable[[], str | None] | None = None) -> Cost:
    """The cost a run grades by, or :class:`CostRefused` saying why it cannot.

    ``time`` is native CPU milliseconds, scaled for an emulated target
    (:meth:`target.Target.time_scale`). ``instructions`` needs a counter the
    host runs natively: an emulated guest has none (qemu-user answers ENOSYS to
    ``perf_event_open`` and the packaged qemu has no ``-plugin``).
    """
    if measure == "time":
        return Cost("time", timeout_ms * target.time_scale(), hang_ms)
    if measure != "instructions":
        raise CostRefused(f"no measure named {measure!r} (known: {', '.join(MEASURES)})")
    if target.emulated():
        raise CostRefused(
            f"{target.name} runs under {target.emulator} here, which cannot count the guest's "
            "instructions (no perf_event_open in the guest, no -plugin in the packaged qemu): "
            "use --measure time")
    reason = (counter or probe)()
    if reason:
        raise CostRefused(f"this host cannot count instructions: {reason}; use --measure time")
    return Cost("instructions", instructions, hang_ms)


def departure(baseline: dict, cost: Cost) -> str | None:
    """Why a run by ``cost`` may not be held to ``baseline``, or None."""
    held = baseline.get("cost") or {}
    if held and held.get("factor") != RENDERING_FACTOR:
        return (f"the baseline graded cost with factor {held.get('factor')}, this run with "
                f"{RENDERING_FACTOR} against each vector's original (ADR D339); re-bless it")
    if held.get("measure") != cost.measure:
        return (f"the baseline counts {held.get('measure')}, this run counts {cost.measure}; "
                "the verdicts are not comparable. Run with --measure "
                f"{held.get('measure')}, or bless a baseline for this measure")
    if held.get("budget") != cost.budget:
        return (f"the baseline's budget is {held.get('budget')} {cost.measure}, this run's is "
                f"{cost.budget}; a different budget moves which vectors are slow or dropped")
    return None


# ------------------------------------------------------------------- probe

_SYSCALL = {"x86_64": 298, "amd64": 298, "aarch64": 241, "arm64": 241}
_PERF_TYPE_HARDWARE = 0
_PERF_COUNT_HW_INSTRUCTIONS = 1
_EXCLUDE_KERNEL = 1 << 5
_EXCLUDE_HV = 1 << 6
_ATTR_SIZE = 112  # PERF_ATTR_SIZE_VER5, enough for these fields on every kernel since 3.19


def event_attr() -> bytes:
    """A ``perf_event_attr`` counting user-space retired instructions, as the runtime opens one."""
    attr = bytearray(_ATTR_SIZE)
    struct.pack_into("<IIQ", attr, 0, _PERF_TYPE_HARDWARE, _ATTR_SIZE,
                     _PERF_COUNT_HW_INSTRUCTIONS)
    struct.pack_into("<Q", attr, 40, _EXCLUDE_KERNEL | _EXCLUDE_HV)
    return bytes(attr)


def open_event(attr: bytes) -> int:
    """``perf_event_open`` on this thread; an OSError names why not."""
    number = _SYSCALL.get(os.uname().machine)
    if number is None:
        raise OSError(errno.ENOSYS, f"no perf_event_open number for {os.uname().machine}")
    libc = ctypes.CDLL(None, use_errno=True)
    buffer = ctypes.create_string_buffer(attr, len(attr))
    fd = libc.syscall(number, buffer, 0, -1, -1, 0)
    if fd < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return fd


def probe(opener: Callable[[bytes], int] = open_event,
          reader: Callable[[int, int], bytes] = os.read,
          closer: Callable[[int], None] = os.close,
          paranoid: Path = Path("/proc/sys/kernel/perf_event_paranoid")) -> str | None:
    """None when this host counts retired instructions, else why not.

    A counter that opens is not yet one that counts: some virtual machines hand
    out an event that reads zero, so the probe retires instructions and reads.
    """
    try:
        fd = opener(event_attr())
    except OSError as error:
        level = ""
        if error.errno in (errno.EACCES, errno.EPERM):
            try:
                level = f" (kernel.perf_event_paranoid={paranoid.read_text().strip()})"
            except OSError:
                pass
        return f"perf_event_open: {error.strerror or error}{level}"
    try:
        sum(range(20_000))
        count = int.from_bytes(reader(fd, 8), "little")
    except OSError as error:
        return f"reading the counter: {error.strerror or error}"
    finally:
        closer(fd)
    # The loop above retires thousands of instructions on any machine that counts.
    return None if count > 0 else "the counter opened but reads zero (no virtual PMU?)"
