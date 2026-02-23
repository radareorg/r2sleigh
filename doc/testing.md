Testing Strategy
================

Overview
--------

r2sleigh has approximately 200 tests across 7 crates plus an end-to-end
integration test suite. All new features require tests.

Test Levels
-----------

### Unit Tests

Each crate has inline test modules:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_my_feature() {
        // ...
    }
}
```

Run with:

```bash
cargo test --all-features
```

### Integration Tests (tests/e2e/)

End-to-end tests run radare2 with the plugin installed and validate output.
Located in tests/e2e/integration_tests.rs.

Run with:

```bash
cd tests/e2e
cargo test
```

### Advisory Semantic Metadata Benchmark

Use the benchmark script to compare semantic output and `aaaa` timing with
semantic metadata enabled vs disabled:

```bash
python3 scripts/bench_semantic_metadata.py \
  --runs 7 \
  --max-overhead-pct 5 \
  --json-out /tmp/semantic-bench.json
```

Default behavior is advisory (always exits `0`) and reports PASS/FAIL in the
output JSON. Use `--strict` to return non-zero on threshold failures.

Test Harness
------------

The e2e harness (tests/e2e/lib.rs) provides:

### r2_cmd(binary, cmd)

Run a radare2 command on a binary. Returns R2Result.

### r2_at_func(binary, func, cmd)

Seek to a function then run a command:

```rust
let result = r2_at_func(vuln_test_binary(), "main", "a:sla.dec");
result.assert_ok();
assert!(result.contains("int"));
```

### r2_at_addr(binary, addr, cmd)

Seek to an address then run a command.

### R2Result

```rust
pub struct R2Result {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub crashed: bool,
    pub panicked: bool,
}
```

Methods:
- assert_ok() -- panics if crashed or panicked
- contains(pattern) -- check stdout/stderr for string
- contains_all(patterns) -- all patterns present
- contains_any(patterns) -- any pattern present
- parse_json::<T>() -- deserialize stdout as JSON

Test Binaries
-------------

### vuln_test.c

Located at tests/e2e/vuln_test.c. Contains test functions exercising
specific patterns. Each function is a numbered test case selected via
main()'s switch statement.

Compile:

```bash
gcc -O0 -g -fno-stack-protector -no-pie -o vuln_test vuln_test.c
```

### Adding a Test Pattern

1. Add a function to vuln_test.c:

```c
int test_my_pattern(int x) {
    // Pattern that exercises the feature
    return x * 2;
}
```

2. Add to main() switch:

```c
case N:
    result = test_my_pattern(atoi(argv[2]));
    break;
```

3. Recompile the binary.

4. Add integration test:

```rust
#[test]
fn test_my_pattern() {
    let result = r2_at_func(vuln_test_binary(), "test_my_pattern", "a:sla.dec");
    result.assert_ok();
    assert!(result.contains("expected_output"));
}
```

What to Test for Each Feature
-----------------------------

New opcode:
  - Unit test in crate
  - e2e test via a:sla.json checking the opcode appears

New plugin command:
  - e2e test that the command runs without crash
  - e2e test checking expected output format

New optimization pass:
  - Unit test in r2ssa with before/after SSA
  - e2e test via a:sla.ssa.func.opt

Bug fix:
  - Regression test reproducing the original bug

Decompiler change:
  - e2e test via a:sla.dec checking output

Test Coverage Checklist
-----------------------

Before committing:

1. cargo build --features x86 succeeds
2. cargo test --features x86 passes
3. cd tests/e2e && cargo test passes (for plugin changes)
4. New feature has at least one test
5. Edge cases are covered (empty input, large input, error paths)
