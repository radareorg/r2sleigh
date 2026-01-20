# r2sleigh

A Sleigh-to-r2il compiler and radare2 analysis plugin.

## Overview

r2sleigh compiles Ghidra Sleigh processor specifications into a typed intermediate language (r2il) and provides a radare2 plugin for instruction lifting and ESIL generation.

## Features

- Pure Rust implementation (edition 2024) using `libsla` (Ghidra native bindings)
- Strongly-typed intermediate language (r2il)
- **SSA (Static Single Assignment)** transformation with def-use analysis
- Compact binary serialization with `bincode`
- CLI tool for compiling and testing Sleigh specs
- **radare2 plugin** for analysis with ESIL output
- Register name resolution for human-readable output
- Multiple output formats: text, JSON, ESIL
- Pre-compiled processor specs via `sleigh-config`

## Project Structure

```
r2sleigh/
├── crates/
│   ├── r2il/              # Core IL definitions
│   ├── r2sleigh-lift/     # Sleigh -> r2il translator + ESIL
│   ├── r2sleigh-cli/      # CLI tool
│   └── r2ssa/             # SSA transformation and analysis
└── r2plugin/              # radare2 plugin (Rust cdylib + C wrapper)
    ├── src/lib.rs         # Rust FFI exports
    ├── r_anal_sleigh.c    # C RAnalPlugin wrapper
    └── Makefile           # Plugin build system
```

## Building

### CLI Tool

```bash
# Build with x86 architecture support
cargo build --release -p r2sleigh-cli --features x86

# Build with ARM architecture support
cargo build --release -p r2sleigh-cli --features arm

# Build with all architectures
cargo build --release -p r2sleigh-cli --features all-archs
```

### radare2 Plugin

```bash
cd r2plugin

# Build release (default: x86 support)
make

# Build with all architectures
make RUST_FEATURES=all-archs

# Build debug version
make RUST_TARGET=debug
```

## Installation

### Plugin Installation

```bash
# From the repo root
cargo install-plugin

# Or directly
cd r2plugin
make install
```

This installs:
- `anal_sleigh.so` - The radare2 plugin
- `libr2sleigh_plugin.so` - The Rust library

To `~/.local/share/radare2/plugins/`

### Uninstall

```bash
cd r2plugin
make uninstall
```

## Usage

### CLI Tool

```bash
# Compile a Sleigh spec to r2il binary
r2sleigh compile path/to/x86-64.slaspec -o x86-64.r2il

# Disassemble bytes using pre-compiled SLA data
r2sleigh disasm --arch x86-64 --bytes "4889e5"

# Output in different formats
r2sleigh disasm --arch x86-64 --bytes "4889e5" --format json
r2sleigh disasm --arch x86-64 --bytes "4889e5" --format esil

JSON output uses structured ops with register varnode names (field: `name`).

Example JSON (truncated):
```json
{
  "addr": "0x1000",
  "size": 3,
  "mnemonic": "mov rbp, rsp",
  "ops": [
    { "Copy": { "dst": { "space": "register", "offset": 32, "size": 8, "name": "RBP" }, "src": { "space": "register", "offset": 24, "size": 8, "name": "RSP" } } }
  ]
}
```

# Show architecture info
r2sleigh info x86-64.r2il
```

### radare2 Plugin

```bash
# Use sleigh for analysis
r2 -e anal.arch=sleigh /bin/ls

# Or set interactively
[0x00001000]> e anal.arch=sleigh
```

#### Disassembly with ESIL

```bash
# Show disassembly
r2 -qc 'e anal.arch=sleigh; pd 5' /bin/ls

# Show ESIL
r2 -qc 'e anal.arch=sleigh; e asm.esil=true; pd 5' /bin/ls
```

#### Plugin Commands

```
a:sleigh        - Show r2sleigh status
a:sleigh.info   - Show current architecture info
a:sleigh.json   - Dump r2il ops as JSON for current instruction
a:sleigh.regs   - Show registers read/written by instruction
a:sleigh.mem    - Show memory accesses by instruction
a:sleigh.vars   - Show all varnodes used by instruction
a:sleigh.ssa    - Show SSA form of instruction
a:sleigh.defuse - Show def-use analysis of instruction
```

Example:

```bash
$ r2 -qc 'a:sleigh.info' /bin/ls
r2sleigh: loaded architecture 'x86-64'

$ r2 -qc 's entry0+4; a:sleigh.ssa' /bin/ls
[
  {"op": "Copy", "dst": "cf_1", "sources": ["0x0_0"]},
  {"op": "IntXor", "dst": "ebp_1", "sources": ["ebp_0", "ebp_0"]},
  {"op": "IntZExt", "dst": "rbp_1", "sources": ["ebp_1"]},
  ...
]

$ r2 -qc 's entry0+4; a:sleigh.defuse' /bin/ls
{
  "inputs": ["0x0_0", "ebp_0"],
  "outputs": ["rbp_1", "cf_1", "zf_1", "sf_1", "pf_1", "of_1"],
  "live": ["ebp_1", "tmp:0x2c200_1", "tmp:0x2c280_1", "tmp:0x2c300_1"]
}
```

## Example Output

### CLI

```
$ r2sleigh disasm --arch x86-64 --bytes "4889e500000000000000000000000000"
0x1000  MOV RBP,RSP  (size=3)
P-code (1 ops):
  0: Copy { dst: RBP, src: RSP }
```

```
$ r2sleigh disasm --arch x86-64 --bytes "31c00fa2c3ffffffffffffffffffffffff" --format esil
# 0x1000: XOR EAX,EAX (size=2)
eax,eax,^,eax,=
# 0x1002: CPUID (size=2)
eax,CALLOTHER(44:cpuid),tmp:0x40800,=
```

### radare2 Plugin

```
$ r2 -qc 'e anal.arch=sleigh; pd 3' /tmp/test.bin
            0x00000000      55             push rbp
            0x00000001      4889e5         mov rbp, rsp
            0x00000004      c3             ret

$ r2 -qc 'e anal.arch=sleigh; e asm.esil=true; pd 3' /tmp/test.bin
            0x00000000      55             rbp,8,rsp,-,=[8],8,rsp,-=
            0x00000001      4889e5         rsp,rbp,=
            0x00000004      c3             rsp,[8],rip,=,8,rsp,+=
```

## Supported Architectures

| Architecture | Feature Flag | Status |
|--------------|--------------|--------|
| x86-64       | `x86`        | ✓ Working |
| x86 (32-bit) | `x86`        | ✓ Working |
| ARM          | `arm`        | ✓ Available |

## Troubleshooting

### Plugin not loading

**Symptom**: `LA` doesn't show `sleigh` plugin

**Check**:
```bash
# Verify plugin files exist
ls ~/.local/share/radare2/plugins/anal_sleigh.so
ls ~/.local/share/radare2/plugins/libr2sleigh_plugin.so

# Check library dependencies
ldd ~/.local/share/radare2/plugins/anal_sleigh.so
```

**Fix**: Ensure both `.so` files are in the plugins directory.

### "unsupported architecture" error

**Symptom**: Plugin loads but fails to analyze

**Check**: The plugin was built with the required architecture feature.

**Fix**: Rebuild with the needed feature:
```bash
cd r2plugin
make RUST_FEATURES=all-archs
make install
```

### Short instruction decode failures

**Note**: The Sleigh disassembler requires at least 16 bytes of input for x86-64 (variable-length instructions). The plugin handles this automatically by padding, but if you see decode errors, ensure sufficient bytes are available.

## Requirements

- Rust 1.85+ (for edition 2024 support)
- radare2 (for plugin)
- pkg-config (for plugin build)
- For architecture features: `sleigh-config` with corresponding arch feature

## License

LGPL-3.0-only
