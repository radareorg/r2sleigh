#!/usr/bin/env bash
# Serve lldb to an MCP client over stdio, with radare2 and the plugin tree
# already known to the debugger.
#
# `lldb-mcp` (Homebrew `lldb`, 23.1.1) multiplexes lldb sessions that register
# under ~/.lldb. Its own spawn of an lldb backend gives that lldb no stdin, and
# lldb quits on EOF before it registers, so this starts the backend itself with
# stdin held open, waits for the registration and then hands stdio to lldb-mcp.
# The backend dies with the multiplexer.
#
# The session starts with the fork's radare2 as its target and the environment
# the probe scripts use, with refusal tracing on so evidence lines run and can
# be stopped at. Run tests/corpus/probe_plugin.sh install first so the plugin
# radare2 loads carries symbols; `restore` puts the release build back. Then,
# through the `command` tool:
#   breakpoint set --shlib libr2sleigh_plugin.dylib --file function.rs --line N
#   breakpoint set -n r2ssa::function::promote_private_stack_slots
#   process launch -i /dev/null -o /tmp/out.txt -e /tmp/err.txt -- -q -c "a:sla; aaa; s <addr>; pd:s" <binary>
#   process status            (the session is asynchronous: poll until stopped)
#   frame variable / bt / expression / continue / process kill
# A pending file breakpoint needs `--shlib`, the plugin is loaded at run time.
# The inferior must not inherit the backend's stdio (`-i`, `-o`, `-e` above),
# and `script` is not to be run through the session: both take the backend down.
#
# Configured for Claude Code by .mcp.json at the repository root. R2_BIN and
# PLUGIN_DIR override the radare2 and the plugin directory.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
lldb_bin=${LLDB_BIN:-/opt/homebrew/opt/lldb/bin/lldb}
lldb_mcp=${LLDB_MCP:-/opt/homebrew/opt/lldb/bin/lldb-mcp}
r2_bin=${R2_BIN:-$root/../radare2/binr/radare2/radare2}
plugin_dir=${PLUGIN_DIR:-/tmp/r2sleigh-r2r-tmp/plugins}
for tool in "$lldb_bin" "$lldb_mcp"; do
    [[ -x $tool ]] || { echo "missing $tool; brew install lldb" >&2; exit 69; }
done

libs=""
if [[ $r2_bin == */binr/radare2/radare2 && -d ${r2_bin%/binr/radare2/radare2}/libr ]]; then
    libs=$(ls -d "${r2_bin%/binr/radare2/radare2}"/libr/*/ | tr '\n' ':')
fi
env_vars="DYLD_LIBRARY_PATH=$libs R2_LIBR_PLUGINS=$plugin_dir XDG_DATA_HOME=${XDG_DATA_HOME:-/tmp/r2sleigh-probe-xdg} TMPDIR=${TMPDIR:-/tmp} R2DEC_TRACE_REFUSAL=1"

hold=$(mktemp -u -t r2sleigh-lldb-mcp)
mkfifo "$hold"
log=${LLDB_MCP_BACKEND_LOG:-/tmp/r2sleigh-lldb-mcp-backend.log}
"$lldb_bin" \
    -O "settings set target.env-vars $env_vars" \
    -O "settings set target.disable-aslr false" \
    -O "settings set target.load-cwd-lldbinit false" \
    -o "protocol start MCP" \
    -- "$r2_bin" \
    <"$hold" >"$log" 2>&1 &
backend=$!
exec 3>"$hold"
trap 'exec 3>&-; kill $backend 2>/dev/null; wait $backend 2>/dev/null; rm -f "$hold"' EXIT

registry=$HOME/.lldb/lldb-mcp-$backend.json
for _ in $(seq 1 200); do
    [[ -s $registry ]] && break
    kill -0 $backend 2>/dev/null || { echo "lldb backend exited; see $log" >&2; exit 70; }
    sleep 0.05
done
[[ -s $registry ]] || { echo "lldb backend did not register; see $log" >&2; exit 70; }

"$lldb_mcp"
