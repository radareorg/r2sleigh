#!/usr/bin/env bash
# Count the structural lints, and refuse to let the counts rise.
#
# The standing definition of good structure is few branches, fewer nested
# loops, few parameters and short names. There is more of that debt in the
# tree than one change can clear, so denying the lints outright would stop all
# work; allowing them silently would let the debt grow. This does neither: it
# holds the counts in `structure-baseline.txt` and fails when any of them goes
# up, so every change either leaves the debt alone or pays some of it off.
#
# Lower a number in the baseline when you have lowered it in the tree. Never
# raise one.
#
#   scripts/structure-report.sh            compare against the baseline
#   scripts/structure-report.sh --bless    write the current counts
set -Eeuo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
baseline="$root/scripts/structure-baseline.txt"
cd "$root"

lints=(
    too_many_arguments
    too_many_lines
    cognitive_complexity
    excessive_nesting
    redundant_clone
    assigning_clones
    needless_pass_by_ref_mut
    clone_on_ref_ptr
    mut_mut
)

flags=(-A clippy::all)
for lint in "${lints[@]}"; do
    flags+=(-W "clippy::$lint")
done

findings=$(cargo clippy --workspace --all-targets --all-features \
    --message-format=short -- "${flags[@]}" 2>&1 |
    grep -E '^[^ ]+\.rs:[0-9]+' || true)

# The message each lint prints. Naming the lint itself takes the long output
# format, and running them one at a time would be nine builds.
#
# Defined out here because bash 3.2, which is what macOS ships, mis-parses a
# `case` inside a command substitution.
pattern_for() {
    case "$1" in
    too_many_arguments) echo 'this function has too many arguments' ;;
    too_many_lines) echo 'this function has too many lines' ;;
    cognitive_complexity) echo 'cognitive complexity of' ;;
    excessive_nesting) echo 'this block is too nested' ;;
    redundant_clone) echo 'redundant clone' ;;
    assigning_clones) echo 'assigning the result of' ;;
    needless_pass_by_ref_mut) echo 'but not used mutably' ;;
    clone_on_ref_ptr) echo 'on a ref-counted pointer' ;;
    mut_mut) echo 'you want to avoid' ;;
    esac
}

current=""
for lint in "${lints[@]}"; do
    pattern=$(pattern_for "$lint")
    count=$(grep -cF "$pattern" <<<"$findings" || true)
    current="${current}${lint} ${count}
"
done
current=${current%$'\n'}

if [ "${1:-}" = "--bless" ]; then
    printf '%s\n' "$current" >"$baseline"
    echo "baseline written:"
    printf '%s\n' "$current"
    exit 0
fi

if [ ! -f "$baseline" ]; then
    echo "no baseline; run scripts/structure-report.sh --bless" >&2
    exit 2
fi

status=0
while read -r lint count; do
    was=$(awk -v l="$lint" '$1 == l {print $2}' "$baseline")
    was=${was:-0}
    if [ "$count" -gt "$was" ]; then
        echo "$lint rose from $was to $count" >&2
        status=1
    elif [ "$count" -lt "$was" ]; then
        echo "$lint fell from $was to $count -- bless the baseline"
    fi
done <<<"$current"

exit "$status"
