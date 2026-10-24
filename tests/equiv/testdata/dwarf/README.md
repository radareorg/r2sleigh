`readelf --wide --debug-dump=info --debug-dump=Ranges` of x86-64 PIE builds (gcc 13.3.0, `-g`), the DIEs below depth 2
cut away and the build directory renamed to `/work/src`; `odd` holds the info only. The sources are in
`tests/gold/source_gold/`: `cold.c` (`-O2`, DWARF 5 and `-gdwarf-4`), `gcsect.c`
(`-O2 -ffunction-sections -Wl,--gc-sections`) and `odd.c` (`-O2`).

`cold.clang.O2.bbs.txt` is the same dump of `cold.c` built by clang 18.1.3 with `-g -O2 -fbasic-block-sections=all`:
the entry of each function is the last range of its list. The `*.syms.txt` files are `readelf --wide --syms` of
`cold.c` built by gcc (`-g -O2`) and by that clang, the symbol tables a function's entry is checked against.
