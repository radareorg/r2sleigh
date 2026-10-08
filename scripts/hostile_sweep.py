#!/usr/bin/env python3
"""Run r2s over hostile inputs with a time and memory budget, and report every overrun or crash.

    python3 scripts/hostile_sweep.py --r2s target/release/r2s DIR... [--command afl] [--seconds 30] [--mb 512]

A file that exceeds the time budget is killed; one that exceeds the memory budget is reported
with its peak; one whose run exits other than 0 (success) or 1 (a refusal) crashed. Exit status
is 1 when anything overran or crashed, so it can gate.
"""

import argparse
import os
import subprocess
import sys
import time


def run(r2s, path, command, seconds):
    """The exit status (or "timeout"), the wall time and this child's own peak RSS in MB."""
    start = time.monotonic()
    child = subprocess.Popen(
        [r2s, "-q", "-c", command, path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    status = None
    usage = None
    while status is None:
        pid, raw, usage = os.wait4(child.pid, os.WNOHANG)
        if pid:
            status = os.waitstatus_to_exitcode(raw)
        elif time.monotonic() - start > seconds:
            child.kill()
            _, _, usage = os.wait4(child.pid, 0)
            status = "timeout"
        else:
            time.sleep(0.02)
    # ru_maxrss is bytes on macOS and KiB on Linux.
    scale = 1 if sys.platform == "darwin" else 1024
    return status, time.monotonic() - start, usage.ru_maxrss * scale / (1 << 20)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--r2s", required=True)
    parser.add_argument("--command", default="afl")
    parser.add_argument("--seconds", type=float, default=30)
    parser.add_argument("--mb", type=float, default=512)
    parser.add_argument("dirs", nargs="+")
    args = parser.parse_args()
    over = []
    count = 0
    for directory in args.dirs:
        for name in sorted(os.listdir(directory)):
            path = os.path.join(directory, name)
            if not os.path.isfile(path):
                continue
            count += 1
            # Each file in its own process group of one, so the peak is this file's.
            status, elapsed, peak = run(args.r2s, path, args.command, args.seconds)
            # r2s exits 0 on success and 1 on a refusal; a panic exits 101 and a signal is negative.
            if status not in (0, 1) or peak > args.mb:
                over.append((path, status, elapsed, peak))
                print(f"{path}: {status} after {elapsed:.1f} s, peak {peak:.0f} MB", flush=True)
    print(f"{count} files, {len(over)} over budget ({args.seconds:.0f} s, {args.mb:.0f} MB)")
    return 1 if over else 0


if __name__ == "__main__":
    sys.exit(main())
