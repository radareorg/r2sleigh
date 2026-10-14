#!/bin/bash
cd /root/r2s-stack && git checkout -q -f golden-files && git log --oneline -1
export CARGO_TARGET_DIR=/root/r2s-target CARGO_INCREMENTAL=0
cargo build -q -p r2s --all-features 2>&1 | grep -E "^error" | head -3
python3 scripts/census.py golden --r2s /root/r2s-target/debug/r2s 2>&1 | tail -2
R2S_BLESS=1 cargo test -q -p r2s --all-features --test golden 2>&1 | grep -E "test result|FAILED" | tail -3
echo "--- verify"
cargo test -q -p r2s --all-features --test golden 2>&1 | grep -E "test result|FAILED" | tail -3
git status --short | wc -l
git diff --stat | tail -1
echo EXIT
