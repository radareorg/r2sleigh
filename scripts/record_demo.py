#!/usr/bin/env python3
"""Drive an interactive r2s session in a pty and write the README demo's asciinema v2 cast.

usage: record_demo.py R2S BINARY OUT.cast [--cols N --rows N --snapshots FILE]
Needs pyte, whose screen answers the line editor's cursor-position queries.
"""
import argparse
import codecs
import fcntl
import json
import os
import pty
import random
import select
import struct
import tempfile
import termios
import threading
import time

import pyte

ap = argparse.ArgumentParser()
ap.add_argument("r2s")
ap.add_argument("binary")
ap.add_argument("out")
ap.add_argument("--cols", type=int, default=120)
ap.add_argument("--rows", type=int, default=34)
ap.add_argument("--snapshots", help="write the screen after each step to this file")
args = ap.parse_args()

# (kind, payload, seconds to hold the result). "cmd" types a line at the r2s prompt, "key" sends one key.
SCRIPT = [
    ("cmd", "i~format,arch,bits,lang,pic", 2.0),
    ("cmd", "aa;afl", 2.2),
    ("cmd", "e scr.color.grep=true;e asm.rails=false", 0.2),
    ("cmd", "pdf @ sym.count~:0..30", 3.8),
    ("cmd", "ao @ 0x1226~:8..34", 3.0),
    ("cmd", "axt @ sym.count", 2.5),
    ("cmd", "pdd @ sym.main~obligations", 3.0),
    ("cmd", "e asm.rails=true", 0.2),
    ("cmd", "pdd @ sym.main~:31..62", 4.2),
    ("cmd", "pd?", 2.8),
    ("cmd", "s sym.count", 0.2),
    ("cmd", "V", 0.8),
    ("key", "\\", 2.8),
    ("key", "V", 2.8),
    ("key", "q", 0.5),
    ("cmd", "q", 0.2),
]

random.seed(7)
events, lock = [], threading.Lock()
screen = pyte.Screen(args.cols, args.rows)
stream = pyte.Stream(screen)
t0 = time.monotonic()


def emit(data):
    with lock:
        events.append([round(time.monotonic() - t0, 4), "o", data])
        stream.feed(data)


pid, fd = pty.fork()
if pid == 0:
    fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", args.rows, args.cols, 0, 0))
    # A fresh HOME keeps host history and rc files out of the cast.
    env = {"PATH": "/usr/bin:/bin", "TERM": "xterm-256color", "LANG": "en_US.UTF-8",
           "HOME": tempfile.mkdtemp(prefix="r2s-demo-home."),
           "COLUMNS": str(args.cols), "LINES": str(args.rows)}
    os.chdir(os.path.dirname(os.path.abspath(args.binary)))
    os.execve(args.r2s, ["r2s", os.path.basename(args.binary)], env)

fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", args.rows, args.cols, 0, 0))
screen.write_process_input = lambda data: os.write(fd, data.encode())
last_out = [time.monotonic()]
done = threading.Event()


def reader():
    dec = codecs.getincrementaldecoder("utf-8")("replace")
    while True:
        try:
            ready, _, _ = select.select([fd], [], [], 0.05)
            if fd in ready:
                data = os.read(fd, 65536)
                if not data:
                    break
                last_out[0] = time.monotonic()
                emit(dec.decode(data))
        except OSError:
            break
    done.set()


def settle(quiet=0.4, cap=20.0):
    start = time.monotonic()
    while time.monotonic() - start < cap and time.monotonic() - last_out[0] <= quiet:
        time.sleep(0.05)


def keystroke_delay():
    return 0.04 + random.random() * 0.05


# The shell line is written into the cast by hand, so no host prompt or path reaches it.
emit("$ ")
time.sleep(0.8)
for ch in "r2s " + os.path.basename(args.binary):
    emit(ch)
    time.sleep(keystroke_delay())
time.sleep(0.3)
emit("\r\n")
threading.Thread(target=reader, daemon=True).start()
settle(0.8)
time.sleep(0.8)
snaps, marks = [], []
for kind, payload, hold in SCRIPT:
    marks.append((round(time.monotonic() - t0, 1), payload))
    if kind == "cmd":
        for ch in payload:
            os.write(fd, ch.encode())
            time.sleep(keystroke_delay())
        time.sleep(0.3)
        os.write(fd, b"\r")
    else:
        os.write(fd, payload.encode())
    settle()
    with lock:
        snaps.append(f"=== {kind} {payload!r}\n" + "\n".join(line.rstrip() for line in screen.display))
    time.sleep(hold)
    if done.is_set():
        break
done.wait(3)
try:
    os.kill(pid, 15)
except OSError:
    pass
os.waitpid(pid, 0)
emit("$ ")
time.sleep(1.0)
emit("")

with open(args.out, "w") as f:
    f.write(json.dumps({"version": 2, "width": args.cols, "height": args.rows, "timestamp": 0,
                        "env": {"TERM": "xterm-256color", "SHELL": "/bin/sh"}, "title": "r2s"}) + "\n")
    for e in events:
        f.write(json.dumps(e, ensure_ascii=False) + "\n")
if args.snapshots:
    with open(args.snapshots, "w") as f:
        f.write("\n".join(snaps) + "\n")
for at, payload in marks:
    print(f"{at:6.1f}s  {payload}")
print(f"{len(events)} events, {events[-1][0]:.1f}s")
