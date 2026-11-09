`readelf --wide --debug-dump=info --debug-dump=Ranges` of x86-64 PIE builds (gcc 13.3.0, `-g`), the DIEs below depth 2
cut away and the build directory renamed to `/work/src`; `odd` holds the info only. The sources are in
`tests/gold/source_gold/`: `cold.c` (`-O2`, DWARF 5 and `-gdwarf-4`), `gcsect.c`
(`-O2 -ffunction-sections -Wl,--gc-sections`) and `odd.c` (`-O2`).

`cold.clang.O2.bbs.txt` is the same dump of `cold.c` built by clang 18.1.3 with `-g -O2 -fbasic-block-sections=all`:
the entry of each function is the last range of its list. The `*.syms.txt` files are `readelf --wide --syms` of
`cold.c` built by gcc (`-g -O2`) and by that clang, the symbol tables a function's entry is checked against.

`clones.gcc.O2`, `abi.gcc.O2`, `abi.a64.O2` (gcc 13.3 for AArch64, `-std=gnu17`) and `cold.gcc.O2.g1` (`gcc -g1`) are the
same dumps, each with its `.syms.txt`, of `clones.c`, `abi.c` and `cold.c` in `tests/gold/source_gold/`.

`enums.gcc.O2` (`-g -O2`) and `enums.gcc.O2.strict2` (`-gdwarf-2 -gstrict-dwarf`, whose enums have no `DW_AT_type`) are
`enums.c`. `odd.gcc.O2.dwarf4.types` (`-gdwarf-4 -fdebug-types-section`: `.debug_types` reuses the offsets of
`.debug_info`) and `abi.gcc.O2.types` (`-std=gnu17 -gdwarf-5 -fdebug-types-section`: type units and the stubs that
name them) are the builds the reader refuses whole.
