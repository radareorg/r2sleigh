#!/bin/bash
cd /root/r2s-stack && git checkout -q -f p7-float-carrier && git log --oneline -1
export CARGO_TARGET_DIR=/root/r2s-target
cargo dylint --path tools/dylints/r2sleigh_lints --workspace -- --all-features --lib --bins 2>&1 | grep -E "^(error|warning)(\[|:)|-->" | grep -v "warning: unused" | head -40
echo "DYLINT_EXIT ${PIPESTATUS[0]}"
echo EXIT
