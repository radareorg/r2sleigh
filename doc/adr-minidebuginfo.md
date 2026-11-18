# ADR: `.gnu_debugdata` as a second symbol source (MiniDebugInfo)

Status: built in round 15 (ROADMAP D572).

## Problem

Stripped distribution binaries keep the names of their local functions in a
`.gnu_debugdata` section. r2image did not read it, so ls-toybox (AArch64)
listed 321 named functions where radare2 lists 1,133, and `perror_msg` at
0x30da8 printed as `fcn.00030da8`.

## What the container states

GDB 15.2's manual, node "MiniDebugInfo", section "Debugging information in a
special section" (`gdb/doc/gdb.texinfo` at tag `gdb-15.2-release`):

> Some systems ship pre-built executables and libraries that have a special
> `.gnu_debugdata` section. This feature is called MiniDebugInfo. This section
> holds an LZMA-compressed object and is used to supply extra symbols for
> backtraces.
>
> The intent of this section is to provide extra minimal debugging
> information for use in simple backtraces. It is not intended to be a
> replacement for full separate debugging information (see Separate Debug
> Files). The example below shows the intended use; however, GDB does not
> currently put restrictions on what sort of debugging information might be
> included in the section.

The manual's recipe keeps the `T`, `t` and `D` symbols `nm` lists that the
dynamic table lacks, copies them with `objcopy --only-keep-debug` and
`objcopy -S --keep-symbols`, compresses the result with `xz` and adds it with
`objcopy --add-section .gnu_debugdata=mini_debuginfo.xz`.
`tests/fixtures/minidebug_gcc_x64_O2` is built by that recipe.

## Decision

- Owner: r2image `loader/minidebug.rs`. The section's bytes are one xz stream
  (xz file format 1.2.1). Its stated uncompressed size is read from the index
  the footer points at, before any block is decoded.
- Budget, refusing: a stated size over 64 MiB, a stream that decodes past or
  short of its stated size, a failed check, or an inner file `object` does not
  read refuses the whole source. The refusal is `MiniDebugRefusal` (kind and
  reason) on the `Image`, printed by `i` as `minidebug refused: <reason>`.
  Nothing is truncated and no partial symbol list is kept.
- Decoder: `lzma-rs` 0.3.0 (pure Rust, MIT, `forbid(unsafe_code)`; it pulls
  `byteorder` and `crc`): xz with the LZMA2 filter and CRC32 or CRC64 checks;
  a SHA-256 check or a BCJ filter is its error, so a refusal. ls-toybox's
  stream is LZMA2 with a 32 KiB dictionary and CRC32; fedora_32_bin_ls's
  LZMA2, 8 MiB and CRC64. No C library.
- The budget holds while decoding: lzma-rs decodes a block whole into memory
  before any size check, so every LZMA2 chunk header is walked first (no
  decoding, O(compressed / 64 KiB)). lzma-rs decodes a chunk to exactly its
  stated size, so chunks stating more or less than the index refuse the
  stream before it allocates; decoding then holds at most twice the stated
  size (its block buffer and ours).
- Precedence: an address `.symtab` or `.dynsym` names keeps that name; every
  other defined symbol of the inner `.symtab` is added where `Image` collects
  symbols, with `SymbolOrigin::minidebug` set, read as the container states it
  (Stated). Its section index is the outer section of the same name. A symbol
  outside the image's mapped ranges is kept and listed as placeless, as a
  `.symtab` symbol there is.
- Discovery reads FUNC symbols as starts; these are starts on the same basis.

## Costs

O(compressed + uncompressed bytes) once at open, within the budget; symbols
merged by sorted address, O(n log n). A file with no such section pays one
section lookup.
