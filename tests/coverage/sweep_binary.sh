#!/bin/bash
# Decompile every function the engine finds in one binary, with markers.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <binary>" >&2
    exit 64
fi

binary=$1
if [[ ! -r "$binary" ]]; then
    echo "binary is not readable: $binary" >&2
    exit 66
fi

r2s_bin=${R2SLEIGH_R2S:-}
if [[ -z "$r2s_bin" ]]; then
    script_dir=$(cd "$(dirname "$0")" && pwd)
    r2s_bin="$script_dir/../../target/release/r2s"
fi
if [[ ! -x "$r2s_bin" ]]; then
    echo "r2s executable not found at $r2s_bin" >&2
    exit 69
fi

# The function list goes to a temporary file rather than beside the binary.
# Writing `$binary.functions` works for a corpus binary this harness compiled
# into its own artifact directory and fails for anything under a system path,
# which is exactly the input the harness most needs to sweep.
functions=$(mktemp -t r2sleigh-coverage-functions)
trap 'rm -f "$functions"' EXIT

# `afl` is read from the same build that renders, so the function set and the
# renderings cannot come from different analyses. A discovered function the
# binary has no name for is keyed by its address, so two of them are two cells
# rather than one.
{ "$r2s_bin" -q -c 'afl' "$binary" 2>/dev/null || true; } \
    | awk '$1 ~ /^0x/ { print $1, ($NF == "-" ? $1 : $NF) }' > "$functions"

command_text=""
while read -r addr name; do
    # The marker is text: every character the shell's line reads as an
    # operator (SPECIAL in crates/r2s/src/line.rs) is escaped, so a name such
    # as `f#1` or `g;h` prints as itself rather than cutting the script, and
    # so is a backslash, which `?e` would otherwise read as an escape.
    marker=$(printf '%s' "$name" | sed 's/[\\@;~$#|`"'"'"'()<>]/\\&/g')
    command_text+="?e R2SLEIGH_COV_BEGIN__${marker}"
    command_text+="; s ${addr}"
    command_text+="; pdd"
    command_text+="; ?e R2SLEIGH_COV_END__${marker}; "
done < "$functions"

# A refusal is what this sweep measures, and the shell reports one by exiting
# non-zero, so a failing command must not end the run: the whole point is to
# record which functions refused and why.
echo "R2SLEIGH_COV_BINARY__$binary"
# What the sweep set out to measure. A run that is cut short -- the shell
# killed, the machine loaded, a decoder hanging -- otherwise looks exactly like
# a binary with fewer functions, and the report believed it.
echo "R2SLEIGH_COV_ASKED__$(wc -l < "$functions" | tr -d ' ')"
"$r2s_bin" -q -c "${command_text%; }" "$binary" 2>&1 || true
