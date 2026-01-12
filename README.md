# r2sleigh

A Sleigh-to-r2il compiler for radare2.

## Overview

r2sleigh compiles Ghidra Sleigh processor specifications (`.slaspec` files) into a compact binary intermediate language format (`.r2il`) that can be consumed by radare2 for instruction lifting and analysis.

## Features

- Pure Rust implementation (edition 2024) using `libsla` (Ghidra native bindings)
- Strongly-typed intermediate language (r2il)
- Compact binary serialization with `bincode`
- CLI tool for compiling and testing Sleigh specs
- Register name resolution for human-readable output
- Multiple output formats: text, JSON, ESIL
- Pre-compiled processor specs via `sleigh-config`

## Project Structure

```
r2sleigh/
├── crates/
│   ├── r2il/              # Core IL definitions
│   ├── r2sleigh-lift/     # Sleigh -> r2il translator
│   └── r2sleigh-cli/      # CLI tool
└── r2plugin/              # C-ABI for radare2 integration
```

## Building

```bash
# Basic build
cargo build --release

# Build with x86 architecture support
cargo build --release -p r2sleigh-cli --features x86

# Build with ARM architecture support
cargo build --release -p r2sleigh-cli --features arm
```

## Usage

```bash
# Compile a Sleigh spec to r2il binary
r2sleigh compile path/to/x86-64.slaspec -o x86-64.r2il

# Disassemble bytes using pre-compiled SLA data
r2sleigh disasm --arch x86-64 --bytes "4889e5"

# Output in different formats
r2sleigh disasm --arch x86-64 --bytes "4889e5" --format json
r2sleigh disasm --arch x86-64 --bytes "4889e5" --format esil

# Show architecture info
r2sleigh info x86-64.r2il
```

## Example Output

```
$ r2sleigh disasm --arch x86-64 --bytes "4889e500000000000000000000000000"
0x1000  MOV RBP,RSP  (size=3)
P-code (1 ops):
  0: Copy { dst: RBP, src: RSP }
```

## Requirements

- Rust 1.85+ (for edition 2024 support)
- For architecture features: `sleigh-config` with corresponding arch feature

## License

LGPL-3.0-only
