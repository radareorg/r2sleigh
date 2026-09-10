#!/usr/bin/env bash
# Run `pd:s` over every function radare2 finds in one binary and tally the
# control certificate (doc/adr-structure-dominator-tree.md §3) per function.
#
# usage: tests/corpus/control_census.sh <binary> [out-file]
#
# The invocation per function is the harness's own -- `a:sla; aaa; s <addr>;
# pd:s` -- so a number here is a number the gates would see. The plugin that
# is installed is the plugin measured; build and install first.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "usage: $0 <binary> [out-file]" >&2
    exit 64
fi
binary=$1
out=${2:-${CLAUDE_JOB_DIR:-/tmp}/control-census-$(basename "$binary").txt}
mkdir -p "$(dirname "$out")"

r2_bin=$(command -v r2) || {
    echo "radare2 executable not found" >&2
    exit 69
}

fns=$("$r2_bin" -e scr.color=0 -q -c 'a:sla; aaa; afl' "$binary" 2>/dev/null | awk '$1 ~ /^0x/ {print $1}')
if [[ -z "$fns" ]]; then
    echo "no functions found in $binary" >&2
    exit 70
fi
cmd="a:sla; aaa"
for a in $fns; do
    cmd+="; ?e ==MARK $a; s $a; pd:s"
done
R2DEC_CONTROL_CERTIFICATE=1 "$r2_bin" -e scr.color=0 -q -c "$cmd" "$binary" >"$out" 2>&1

# A function is structured once per gap attempt and certified each time; the
# last line under its marker is the body that was kept.
final=$(awk '/^==MARK/ { if (last != "") print last; last = "" }
             /^control-certificate [^ ]*: (ok|FAIL)/ { last = $0 }
             END { if (last != "") print last }' "$out")
functions=$(grep -c '^==MARK' "$out" || true)
certified=$(printf '%s\n' "$final" | grep -c '^control-certificate' || true)
ok=$(printf '%s\n' "$final" | grep -c ': ok' || true)
fail=$(printf '%s\n' "$final" | grep -c ': FAIL' || true)
inverted=$(printf '%s\n' "$final" | grep -vc 'inversions=0' || true)
# The register-identity census (doc/adr-register-identity.md, S0): functions
# whose graph still carries alias temporaries or a family entered twice.
identity=$(awk '/^==MARK/ { if (last != "") print last; last = "" }
                /^register-identity / { last = $0 }
                END { if (last != "") print last }' "$out")
regalias=$(printf '%s\n' "$identity" | grep -vc 'regalias=0 ' || true)
split=$(printf '%s\n' "$identity" | grep -vc 'split_entries=0$' || true)
echo "$(basename "$binary"): functions=$functions certified=$certified ok=$ok fail=$fail with-inversions=$inverted regalias=$regalias split-entries=$split out=$out"
# Clauses, by the number of functions whose final certificate names each.
printf '%s\n' "$final" | grep ': FAIL' \
    | sed -E 's/^control-certificate [^ ]*: FAIL [0-9]+ //; s/ occurrences=.*$//' \
    | tr ',' '\n' | sed -E 's/=[0-9]+$//' | sort | uniq -c | sort -rn
