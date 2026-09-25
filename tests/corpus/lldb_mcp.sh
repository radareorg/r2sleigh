#!/usr/bin/env bash
# Serve lldb to an MCP client over stdio, with r2s already its target.
#
# `lldb-mcp` (Homebrew `lldb`, 23.1.1) multiplexes lldb sessions that register
# under ~/.lldb. Its own spawn of an lldb backend gives that lldb no stdin, and
# lldb quits on EOF before it registers, so this starts the backend itself with
# stdin held open, waits for the registration and then hands stdio to lldb-mcp.
# The backend dies with the multiplexer.
#
# The session's target is the dev-profile r2s (debug info is in the dev profile
# already; `cargo build -p r2s --features sleigh`), with refusal tracing on so
# evidence lines run and can be stopped at. Then, through the `command` tool:
#   breakpoint set --file function.rs --line N
#   breakpoint set -n r2ssa::function::promote_private_stack_slots
#   process launch -i /dev/null -o /tmp/out.txt -e /tmp/err.txt -- -q -c "s <addr>; pdd" <binary>
#   process status            (the session is asynchronous: poll until stopped)
#   frame variable / bt / expression / continue / process kill
# The inferior must not inherit the backend's stdio (`-i`, `-o`, `-e` above),
# and `script` is not to be run through the session: both take the backend down.
# For one stop in batch, tests/corpus/lldb_r2s.sh does the same without MCP.
#
# Configured for Claude Code by .mcp.json at the repository root. R2S overrides
# the r2s the session targets.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
lldb_bin=${LLDB_BIN:-$(command -v lldb || echo /opt/homebrew/opt/lldb/bin/lldb)}
lldb_mcp=${LLDB_MCP:-$(command -v lldb-mcp || echo /opt/homebrew/opt/lldb/bin/lldb-mcp)}
r2s=${R2S:-${CARGO_TARGET_DIR:-$root/target}/debug/r2s}
for tool in "$lldb_bin" "$lldb_mcp"; do
    [[ -x $tool ]] || { echo "missing $tool; install lldb (brew install lldb)" >&2; exit 69; }
done
# A fresh checkout has no r2s yet. The server still starts, with no target,
# so the MCP client does not fail at launch; build r2s and then
# `target create <path to r2s>` through the `command` tool.
target=(-- "$r2s")
if [[ ! -x $r2s ]]; then
    echo "lldb_mcp: no $r2s yet (cargo build -p r2s --features sleigh);" \
        "starting with no target" >&2
    target=()
fi

env_vars="TMPDIR=${TMPDIR:-/tmp} R2DEC_TRACE_REFUSAL=1"

hold=$(mktemp -u -t r2sleigh-lldb-mcp.XXXXXX)
mkfifo "$hold"
log=${LLDB_MCP_BACKEND_LOG:-/tmp/r2sleigh-lldb-mcp-backend.log}
"$lldb_bin" \
    -O "settings set target.env-vars $env_vars" \
    -O "settings set target.disable-aslr false" \
    -O "settings set target.load-cwd-lldbinit false" \
    -o "protocol start MCP" \
    ${target[@]+"${target[@]}"} \
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
