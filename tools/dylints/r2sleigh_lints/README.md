# template

### What it does

### Why is this bad?

### Known problems

Remove if none.

### Example

```rust
// example code where a warning is issued
```

Use instead:

```rust
// example code that does not raise a warning
```

## name_decides_fact (D460)

### What it does

Denies a call of `r2abi::SymbolName::text` in r2engine, r2ssa, r2types and r2dec outside an item that allows
`name_decides_fact` with one of `NAME_READ_REASONS`: printed, handed to an output contract, or a
table lookup by C identifier.

### Why is this bad?

A symbol name is a hint, never proof (AGENTS.md, Non-Negotiable 6). Reading its text to decide a
fact makes a name the owner of that fact.

### Example

```rust
if name.text() == "exit" { /* a noreturn decided by a name */ }
```

Use instead a cited row looked up by the name, in an item stating that reason, or a fact from the
code.
