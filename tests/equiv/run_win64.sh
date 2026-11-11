#!/bin/bash
# The Win64 equivalence target on an x86-64 Linux host (doc/testing.md): bash run_win64.sh R2S [ARGS].
# Needs $EQUIV_XWIN, an `xwin splat` output; extra arguments go to run_equiv.py.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
r2s=${1:?usage: run_win64.sh <r2s> [run_equiv.py arguments]}
shift
: "${EQUIV_XWIN:?set EQUIV_XWIN to an xwin splat output}"
exec python3 "$here/run_equiv.py" --target win64 --r2s "$r2s" \
    --measure instructions --baseline "$here/baseline-win64.json" "$@"
