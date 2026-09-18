#!/usr/bin/env bash
# Stop radare2 inside the plugin this tree built, at the predicate that refuses.
#
# The evidence channel says where a refusal was decided; this shows what the
# predicate saw, in one stop, instead of a rerun per operand. It builds the
# plugin with symbols (`[profile.probe]`), swaps it into the r2r plugin
# directory for the run, and restores the release build afterwards.
#
# usage: tests/corpus/lldb_probe.sh <binary> <r2 command> <file.rs:line> [file.rs:line ...]
#   tests/corpus/lldb_probe.sh tests/r2r/bins/stress_test_opt \
#       'a:sla; aaa; s sym._fp_interpolate; pd:s' machine.rs:2614
#
# At every stop it prints the frame's variables and eight frames of backtrace,
# then continues. R2_BIN names the radare2 (default: the fork's build tree),
# PLUGIN_DIR the plugin directory (default: the r2r one), LLDB_STOP extra lldb
# commands to run at each stop, LLDB_STOPS how many stops to report (default
# 4), RUST_FEATURES the plugin features.
set -euo pipefail

if [[ $# -lt 3 ]]; then
    echo "usage: $0 <binary> <r2 command> <file.rs:line> [file.rs:line ...]" >&2
    exit 64
fi
binary=$1
command=$2
shift 2

root=$(cd "$(dirname "$0")/../.." && pwd)
r2_bin=${R2_BIN:-$root/../radare2/binr/radare2/radare2}
plugin_dir=${PLUGIN_DIR:-/tmp/r2sleigh-r2r-tmp/plugins}
features=${RUST_FEATURES:-all-archs}
installed=$plugin_dir/r2sleigh/libr2sleigh_plugin.dylib
[[ -x $r2_bin ]] || { echo "radare2 not found: $r2_bin" >&2; exit 69; }
[[ -f $installed ]] || { echo "no installed plugin at $installed; run make -C tests/r2r install-plugin" >&2; exit 69; }

(cd "$root" && cargo build --profile probe --features "$features" -p r2sleigh-plugin >&2)
probe=$root/target/probe/libr2sleigh_plugin.dylib
backup=$(mktemp -t r2sleigh-release-plugin)
cp "$installed" "$backup"
trap 'cp "$backup" "$installed"; codesign -f -s - "$installed" 2>/dev/null; rm -f "$backup"' EXIT
cp "$probe" "$installed"
codesign -f -s - "$installed" 2>/dev/null
dsymutil "$installed" -o "$installed.dSYM" >/dev/null 2>&1 || true

libs=""
if [[ $r2_bin == */binr/radare2/radare2 ]]; then
    libs=$(ls -d "${r2_bin%/binr/radare2/radare2}"/libr/*/ | tr '\n' ':')
fi
commands=$(mktemp -t r2sleigh-lldb)
trap 'cp "$backup" "$installed"; codesign -f -s - "$installed" 2>/dev/null; rm -f "$backup" "$commands"' EXIT
{
    echo "settings set target.env-vars DYLD_LIBRARY_PATH=$libs R2_LIBR_PLUGINS=$plugin_dir XDG_DATA_HOME=${XDG_DATA_HOME:-/tmp/r2sleigh-probe-xdg} TMPDIR=${TMPDIR:-/tmp}"
    for stop in "$@"; do
        echo "breakpoint set --file ${stop%%:*} --line ${stop##*:}"
    done
    echo "run"
    for ((i = 0; i < ${LLDB_STOPS:-4}; i++)); do
        echo "frame variable"
        echo "bt 8"
        if [[ -n ${LLDB_STOP:-} ]]; then
            echo "$LLDB_STOP"
        fi
        echo "continue"
    done
    echo "quit"
} >"$commands"
lldb --batch -s "$commands" -- "$r2_bin" -e scr.color=0 -e bin.relocs.apply=true -q -c "$command" "$binary"
