#!/usr/bin/env bash
# Sample one r2 command against a symbolised build of this tree's plugin and
# name the hot frames.
#
# A release build is stripped, so `sample` of the shipped plugin is hex. The
# `probe` profile keeps symbols and line tables; this installs that build over
# the release one under the install lock, samples the run, and symbolicates
# every plugin frame with `atos` so the call graph reads as function names and
# source lines.
#
# usage: tests/corpus/locked_sample.sh <binary> <r2 command> [seconds] [env=value ...]
#   tests/corpus/locked_sample.sh ./minigzip_O2 'aaa; s 0x7120; pd:s' 60
#
# SAMPLE_DELAY waits that many seconds before sampling, so a run that analyses
# first can be sampled over the render rather than over the analysis.
set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "usage: $0 <binary> <r2 command> [seconds] [env=value ...]" >&2
    exit 64
fi

binary=$1
command=$2
seconds=${3:-60}
shift 2
[[ $# -gt 0 ]] && shift 1

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
out=${SAMPLE_OUT:-${CLAUDE_JOB_DIR:-/tmp}/tmp/sample-$$}
# Seconds to wait before sampling starts. A command that analyses first spends
# most of its wall clock before the part worth sampling, and a sample taken from
# the start reports the analysis instead of the render.
delay=${SAMPLE_DELAY:-0.5}
mkdir -p "$out"

exec "$root/tests/locked_run.sh" bash -c '
    set -euo pipefail
    root=$1; binary=$2; command=$3; seconds=$4; out=$5; delay=$6
    shift 6
    make -C "$root/r2plugin" RUST_FEATURES=all-archs install >&2
    (cd "$root" && cargo build --profile probe --features all-archs -p r2sleigh-plugin >&2)
    dylib="$root/target/probe/libr2sleigh_plugin.dylib"
    installed="$HOME/.local/share/radare2/plugins/r2sleigh/libr2sleigh_plugin.dylib"
    cp "$dylib" "$installed"
    codesign -f -s - "$installed" 2>/dev/null
    dsym="$dylib.dSYM"
    if [[ ! -e "$dsym" || "$dylib" -nt "$dsym" ]]; then
        dsymutil "$dylib" -o "$dsym" >&2
    fi
    dwarf="$dsym/Contents/Resources/DWARF/libr2sleigh_plugin.dylib"

    env "$@" r2 -e scr.color=0 -q -c "$command" "$binary" > "$out/render.txt" 2> "$out/render.err" &
    pid=$!
    sleep "$delay"
    sample "$pid" "$seconds" -mayDie -file "$out/sample.txt" >/dev/null 2>&1 || true
    wait "$pid" || true

    load=$(grep -E "libr2sleigh_plugin.dylib" "$out/sample.txt" | grep -oE "^ *0x[0-9a-f]+" | head -1 | tr -d " ")
    if [[ -z "$load" ]]; then
        load=$(grep -oE "load address 0x[0-9a-f]+" "$out/sample.txt" | head -1 | awk "{print \$3}")
    fi
    grep -oE "libr2sleigh_plugin.dylib\)  load address 0x[0-9a-f]+ \+ 0x[0-9a-f]+" "$out/sample.txt" \
        | awk "{print \$6}" | sort -u > "$out/offsets.txt"
    python3 - "$out" "$dwarf" "$load" <<'"'"'PY'"'"'
import subprocess, sys, re, collections
out, dwarf, load = sys.argv[1:4]
offsets = [line.strip() for line in open(f"{out}/offsets.txt") if line.strip()]
load_int = int(load, 16)
names = {}
if offsets:
    addrs = [hex(load_int + int(o, 16)) for o in offsets]
    for i in range(0, len(addrs), 200):
        chunk = addrs[i:i+200]
        res = subprocess.run(["atos", "-o", dwarf, "-l", load] + chunk, capture_output=True, text=True).stdout.splitlines()
        for o, line in zip(offsets[i:i+200], res):
            line = re.sub(r" \(in libr2sleigh_plugin.dylib\)", "", line)
            names[o] = line
text = open(f"{out}/sample.txt").read()
def sub(m):
    return names.get(m.group(1), m.group(0))
text = re.sub(r"\?\?\?  \(in libr2sleigh_plugin.dylib\)  load address 0x[0-9a-f]+ \+ (0x[0-9a-f]+)", sub, text)
open(f"{out}/sample.sym.txt", "w").write(text)
# leaf frames by count
top = []
in_top = False
for line in text.splitlines():
    if line.startswith("Sort by top of stack"):
        in_top = True; continue
    if in_top:
        if not line.strip():
            if top: break
            continue
        top.append(line)
print("== leaf frames ==")
for line in top[:25]:
    print(line[:200])
# hottest path through the call graph: walk the deepest chain of max-count children
print("== hottest path ==")
lines = text.splitlines()
start = next((i for i, l in enumerate(lines) if l.startswith("Call graph")), None)
if start is not None:
    path = []
    prev_depth = -1
    for l in lines[start+1:]:
        if not l.strip() or l.startswith("Total number"):
            break
        m = re.match(r"^( *)([+|! ]*)(\d+) (.*)$", l)
        if not m: continue
        depth = len(m.group(1)) + len(m.group(2))
        count = int(m.group(3)); rest = m.group(4)
        if depth <= prev_depth and path and count < path[-1][1] * 0.6:
            continue
        if depth > prev_depth or not path or count >= path[-1][1] * 0.6:
            path.append((depth, count, rest)); prev_depth = depth
    for depth, count, rest in path[:80]:
        if "r2sleigh" in rest or "radare2" in rest or "libr_" in rest:
            print(f"{count:6d} {rest[:170]}")
PY
    echo "sample: $out/sample.sym.txt" >&2
' locked-sample "$root" "$binary" "$command" "$seconds" "$out" "$delay" "$@"
