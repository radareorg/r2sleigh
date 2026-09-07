"""Record DecBench phase intervals without changing worker scheduling."""

from __future__ import annotations

import os
import sys
import time
from contextlib import contextmanager
from functools import wraps
from pathlib import Path


@contextmanager
def record_phase(phase):
    path = os.environ["R2SLEIGH_DECBENCH_PHASE_LOG"]
    started = time.monotonic_ns()
    try:
        yield
    finally:
        ended = time.monotonic_ns()
        row = f"{phase}\t{started}\t{ended}\n".encode()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, row)
        finally:
            os.close(fd)


def timed_decompile_binary(binary_path, decompiler_name, *args, **kwargs):
    # Keep the wrapper importable by multiprocessing's spawned workers.
    from decbench.pipeline.decompile import decompile_binary

    phase = "reference" if decompiler_name == "angr" else "decompile"
    with record_phase(phase):
        return decompile_binary.__wrapped__(
            binary_path, decompiler_name, *args, **kwargs
        )


def install_phase_timing():
    """Instrument workers and evaluation only when the harness requests it."""
    if "R2SLEIGH_DECBENCH_PHASE_LOG" not in os.environ:
        return
    from decbench.pipeline import decompile, executor

    if decompile.decompile_binary is timed_decompile_binary:
        return
    timed_decompile_binary.__wrapped__ = decompile.decompile_binary
    decompile.decompile_binary = timed_decompile_binary
    evaluate_projects = executor.evaluate_projects

    @wraps(evaluate_projects)
    def timed_evaluate(*args, **kwargs):
        with record_phase("evaluate"):
            return evaluate_projects(*args, **kwargs)

    executor.evaluate_projects = timed_evaluate


def phase_seconds(path):
    """Return elapsed busy time per phase, merging concurrent worker intervals."""
    intervals = {phase: [] for phase in ("decompile", "reference", "evaluate")}
    for row in Path(path).read_text().splitlines():
        phase, started, ended = row.split("\t")
        intervals[phase].append((int(started), int(ended)))
    totals = {}
    for phase, spans in intervals.items():
        total = 0
        end = 0
        for started, ended in sorted(spans):
            total += max(0, ended - max(started, end))
            end = max(end, ended)
        totals[phase] = total / 1_000_000_000
    return totals


if __name__ == "__main__":
    print("\t".join(f"{value:.3f}" for value in phase_seconds(sys.argv[1]).values()))
