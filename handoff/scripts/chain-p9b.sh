#!/bin/bash
L=/root/r2s-logs
cd /root/r2s-stack && git checkout -q -f p9b-members && git log --oneline -1
export CARGO_TARGET_DIR=/root/r2s-target CARGO_INCREMENTAL=0
cargo build -q --release -p r2s --features sleigh 2>&1 | grep -E "^error" | head -3
cp /root/r2s-target/release/r2s /root/r2s-p9b
rm -rf $L/equiv-p9b-x86 $L/equiv-p9b-a64
python3 tests/equiv/run_equiv.py --r2s /root/r2s-p9b --baseline tests/equiv/baseline.json --jobs 4 --out $L/equiv-p9b-x86 > $L/equiv-p9b-x86.log 2>&1; echo "EXIT $?" >> $L/equiv-p9b-x86.log
python3 tests/equiv/run_equiv.py --r2s /root/r2s-p9b --target aarch64 --baseline tests/equiv/baseline-aarch64.json --jobs 4 --out $L/equiv-p9b-a64 > $L/equiv-p9b-a64.log 2>&1; echo "EXIT $?" >> $L/equiv-p9b-a64.log
cargo test -q --workspace --all-features --no-fail-fast 2>&1 | grep -E "^test result|FAILED|panicked|^error" | awk '/test result/{split($0,a," "); p+=a[4]; f+=a[6]} /FAILED|panicked|^error/{print} END{print "passed",p,"failed",f}'
echo EXIT
