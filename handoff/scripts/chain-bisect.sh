#!/bin/bash
cd /root/r2s-stack
B=/root/r2s-logs/equiv-p9-a64/build/shapes/aarch64-gcc-O2/oracle/shapes
export CARGO_TARGET_DIR=/root/r2s-target CARGO_INCREMENTAL=0
for b in h-macho-bind-repeat q3-retention tui-no-cache k-fixpoint-moves q1-exhausted-refuses q7-reads-every-call; do
  git checkout -q -f $b
  cargo build -q --release -p r2s --features sleigh 2>&1 | grep -E "^error" | head -3
  out=$(/root/r2s-target/release/r2s -q -c "aa; pdd @ 0x401580" $B 2>&1)
  echo "$b $(git log --oneline -1 | cut -c1-60) | u64=$(echo "$out" | grep -c 'r2sleigh_residual_u64(') void=$(echo "$out" | grep -c 'r2sleigh_residual_void(') entry=$(echo "$out" | grep -o 'read as residuals ([^)]*)' | head -1)"
done
echo EXIT
