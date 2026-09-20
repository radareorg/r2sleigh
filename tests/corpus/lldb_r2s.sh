#!/usr/bin/env bash
# Stop `r2s` at one source line and dump the frame there.
#
# The lldb-mcp backend in lldb_mcp.sh targets radare2 and the plugin, which is
# the right target for a `pd:s` refusal. A native `pdd` refusal happens inside
# `r2s` itself, with no plugin involved, so it needs its own target. Debug info
# is in the dev profile already, so no special build is needed.
#
#   tests/corpus/lldb_r2s.sh crates/r2ssa/src/machine.rs:3300 0x2e368 <binary>
#
# Extra lldb commands to run at the stop come from LLDB_AT_STOP, newline
# separated; the default prints the frame and its variables.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
lldb_bin=${LLDB_BIN:-$(command -v rust-lldb || echo /opt/homebrew/opt/lldb/bin/lldb)}
r2s=${R2S:-$root/target/probe/r2s}
where=${1:?file:line}
address=${2:?address}
binary=${3:?binary}
at_stop=${LLDB_AT_STOP:-$'frame info\nframe variable\nbt 12'}

[[ -x $lldb_bin ]] || { echo "missing $lldb_bin; brew install lldb" >&2; exit 69; }
[[ -x $r2s ]] || {
    echo "missing $r2s; cargo build --profile probe -p r2s --features sleigh" >&2
    exit 69
}

script=$(mktemp -t r2sleigh-lldb-r2s)
trap 'rm -f "$script"' EXIT
{
    echo "breakpoint set --file ${where%:*} --line ${where##*:}"
    echo "run -q -c \"s $address; pdd\" $binary"
    echo "$at_stop"
    echo "quit"
} >"$script"

"$lldb_bin" --batch --source "$script" -- "$r2s" 2>&1
