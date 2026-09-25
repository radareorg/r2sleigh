#!/usr/bin/env bash
# Measure r2s on DecBench through DecBench's own driver, on stripped input.
#
# The official protocol is DecBench's scripts/run_benchmark.py: it hands every
# decompiler a `strip --strip-all` copy of each binary and the DWARF low_pc of
# each source function, relabels the answers to DWARF names afterwards, and
# scores against the unstripped build. This script runs exactly that, with the
# r2s this tree builds:
#
#   1. build target/release/r2s (or take --r2s) and record its sha256;
#   2. install this tree's backend into the DecBench checkout
#      (install_backend.py), so the per-binary decompile_one.py subprocess the
#      driver starts registers r2sleigh_native;
#   3. check the backend reports the same sha256 before anything is measured --
#      a stale r2s on PATH must not be scored as this tree;
#   4. optionally compile the projects (DecBench's compile_all.py);
#   5. run scripts/run_benchmark.py through decbench_cli.py, which registers
#      the vj_ged metric when DecBench does not;
#   6. check every r2sleigh_native result names that sha256, then report
#      against baseline.json (report_decbench.py).
#
# The driver needs cgroup v2 and a user systemd manager (`systemd-run --user`)
# for its per-binary limits; it says so and stops when they are missing.
# GED needs Joern (pyjoern downloads it from github.com releases).
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
decbench=${R2SLEIGH_DECBENCH_SRC:-$root/../decbench}
python=${R2SLEIGH_DECBENCH_PYTHON:-python3}
out=
r2s=
compile=0
accept=0
plan=0
decompilers=r2sleigh_native,angr
metrics=byte_match,ged,vj_ged,type_match
workers=${R2SLEIGH_DECBENCH_WORKERS:-4}
declare -a projects=()
declare -a opts=()

usage() {
    cat <<'EOF'
usage: tests/decbench/run_decbench.sh [options]

  --decbench DIR       DecBench checkout, installed with `pip install -e`
                       (default: $R2SLEIGH_DECBENCH_SRC or ../decbench)
  --python PY          interpreter DecBench is installed in
                       (default: $R2SLEIGH_DECBENCH_PYTHON or python3)
  --out DIR            results tree (default: tests/decbench/artifacts/run-<time>)
  --project NAME       a sailr project; repeatable (default: every project)
  --opt-level OPT      O0, O2 or O2_noinline; repeatable (default: O0 O2)
  --decompilers LIST   (default: r2sleigh_native,angr)
  --metrics LIST       (default: byte_match,ged,vj_ged,type_match)
  --workers N          DecBench workers (default: 4)
  --r2s PATH           measure this r2s instead of building target/release/r2s
  --compile            compile the projects first (DecBench's compile_all.py)
  --accept-baseline    start or extend baseline.json with this run
  --plan               print what would run, and run nothing
EOF
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --decbench) decbench=$2; shift 2 ;;
        --python) python=$2; shift 2 ;;
        --out) out=$2; shift 2 ;;
        --project) projects+=("$2"); shift 2 ;;
        --opt-level) opts+=("$2"); shift 2 ;;
        --decompilers) decompilers=$2; shift 2 ;;
        --metrics) metrics=$2; shift 2 ;;
        --workers) workers=$2; shift 2 ;;
        --r2s) r2s=$2; shift 2 ;;
        --compile) compile=1; shift ;;
        --accept-baseline) accept=1; shift ;;
        --plan) plan=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 64 ;;
    esac
done
(( ${#opts[@]} )) || opts=(O0 O2)
out=${out:-$root/tests/decbench/artifacts/run-$(date -u +%Y%m%dT%H%M%SZ)}
opt_list=$(IFS=,; echo "${opts[*]}")

run() {
    printf '+'
    printf ' %q' "$@"
    printf '\n'
    (( plan )) || "$@"
}

if [[ -z $r2s ]]; then
    run cargo build --release -p r2s --features sleigh --manifest-path "$root/Cargo.toml"
    r2s=${CARGO_TARGET_DIR:-$root/target}/release/r2s
fi
run python3 "$root/tests/decbench/install_backend.py" "$decbench"

witness=
if (( ! plan )); then
    [[ -x $r2s ]] || { echo "no r2s at $r2s" >&2; exit 69; }
    witness="r2s sha256:$(sha256sum "$r2s" | cut -c1-16)"
    reported=$(R2SLEIGH_R2S_BIN=$r2s "$python" -c '
import decbench.decompilers
from decbench.decompilers.registry import DecompilerRegistry
backend = DecompilerRegistry.get("r2sleigh_native")
print(backend.get_version() if backend.is_available() else "unavailable")')
    if [[ $reported != "$witness" ]]; then
        echo "the installed backend reports '$reported', not the r2s being measured ($witness)" >&2
        exit 70
    fi
    echo "measuring $witness ($r2s)"
fi

export R2SLEIGH_R2S_BIN=$r2s
export R2SLEIGH_REFUSAL_CENSUS_DIR=$out/refusals
if (( compile )); then
    run env -C "$decbench" "$python" scripts/compile_all.py "$out" "$workers" "${projects[@]}"
fi
declare -a only=()
(( ${#projects[@]} )) && only=(-- "${projects[@]}")
run env -C "$decbench" \
    DECBENCH_DECOMPILERS="$decompilers" \
    DECBENCH_OPT_LEVELS="$opt_list" \
    DECBENCH_METRICS="$metrics" \
    DECBENCH_WORKERS="$workers" \
    R2SLEIGH_DECBENCH_PHASE_LOG="$out/phases.tsv" \
    "$python" "$root/tests/decbench/decbench_cli.py" run-benchmark "$out" "${only[@]}"

(( plan )) && exit 0
results=$out/function_results.json
python3 - "$results" "$witness" <<'PY'
import json, sys
results, witness = json.load(open(sys.argv[1])), sys.argv[2]
seen = (results.get("decompiler_versions") or {}).get("r2sleigh_native")
if seen != witness:
    sys.exit(f"the results name {seen!r} for r2sleigh_native, not {witness!r}")
print(f"results measured {witness}")
PY
declare -a report=(python3 "$root/tests/decbench/report_decbench.py" --results "$results"
    --baseline "$root/tests/decbench/baseline.json")
(( accept )) && report+=(--accept-baseline)
run "${report[@]}"
