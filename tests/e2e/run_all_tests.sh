#!/bin/bash
# Comprehensive end-to-end tests for r2sleigh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
R2SLEIGH_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=========================================="
echo "r2sleigh Comprehensive End-to-End Tests"
echo "=========================================="
echo ""

# Build everything if needed
echo "--- Building r2sleigh plugin (release) ---"
cd "$R2SLEIGH_ROOT"
cargo build --release -p r2sleigh-plugin 2>&1 | tail -3
echo ""

# Build test binary
echo "--- Building test binary ---"
cd "$SCRIPT_DIR"
if [ ! -f test_func ]; then
    gcc -O0 -g -o test_func test_func.c
    echo "Built test_func"
else
    echo "test_func already exists"
fi
echo ""

# Build e2e test binary
echo "--- Building e2e test binary ---"
cargo build --release 2>&1 | tail -3
echo ""

# Run radare2 tests
echo "=========================================="
echo "Part 1: radare2 Analysis Tests"
echo "=========================================="
./run_e2e_tests.sh
echo ""

# Run plugin tests
echo "=========================================="
echo "Part 2: r2sleigh Plugin Tests"
echo "=========================================="
./target/release/e2e_test
echo ""

# Run unit tests
echo "=========================================="
echo "Part 3: Unit Tests"
echo "=========================================="
cd "$R2SLEIGH_ROOT"
cargo test -p r2ssa -p r2sym -p r2dec --release 2>&1 | grep -E "(^running|^test |PASSED|FAILED|ok\.|test result)"
echo ""

echo "=========================================="
echo "All Tests Completed!"
echo "=========================================="
