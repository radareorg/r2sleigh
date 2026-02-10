# E2E Tests for r2sleigh

Rust-based integration tests for the r2sleigh plugin.

## Prerequisites

1. Build the test binaries:
   ```bash
   cd tests/e2e
   gcc -O0 -g -o vuln_test vuln_test.c
   gcc -O0 -g -o test_func test_func.c
   # optional stress corpus binaries used by regression tests
   gcc -O0 -g -o stress_test stress_test.c
   gcc -O2 -g -o stress_test_opt stress_test.c
   ```

2. Build the plugin:
   ```bash
   cargo build --release -p r2plugin
   ```

3. Ensure `r2` is in your PATH with the plugin loaded.

## Running Tests

From the `tests/e2e` directory:

```bash
cargo test
```

Run specific test module:

```bash
cargo test plugin_status
cargo test symbolic
cargo test decompilation
```

Run with output:

```bash
cargo test -- --nocapture
```

## Test Structure

| Module | Description |
|--------|-------------|
| `plugin_status` | Basic plugin loading and arch detection |
| `instruction_analysis` | Per-instruction analysis (JSON, regs, mem, SSA) |
| `function_ssa` | Function-level SSA form |
| `cfg` | Control flow graph and dominators |
| `slicing` | Backward slicing |
| `taint` | Taint analysis |
| `symbolic` | Symbolic execution |
| `paths` | Path exploration and solving |
| `merging` | State merging options |
| `decompilation` | C decompilation output |
| `ffi` | Direct FFI tests against plugin library |
