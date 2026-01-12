# r2sleigh

A Sleigh-to-r2il compiler for radare2.

## Overview

r2sleigh compiles Ghidra Sleigh processor specifications (`.slaspec` files) into a compact binary intermediate language format (`.r2il`) that can be consumed by radare2 for instruction lifting and analysis.

## Features

- Pure Rust implementation using `sleigh-rs`
- Strongly-typed intermediate language (r2il)
- Compact binary serialization with `bincode`
- CLI tool for compiling and testing Sleigh specs

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
cargo build --release
```

## Usage

```bash
# Compile a Sleigh spec to r2il binary
r2sleigh compile path/to/x86-64.slaspec -o x86-64.r2il

# Disassemble bytes using the compiled spec
r2sleigh disasm x86-64.r2il --bytes "554889e5"
```

## License

LGPL-3.0-only
