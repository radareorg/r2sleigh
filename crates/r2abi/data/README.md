# Where this data comes from

Copied verbatim from radare2's `libr/anal/d/`:

- `cc-*.sdb.txt` — what each calling convention does with arguments, results,
  and saved registers.
- `types.sdb.txt` — what five hundred and seventy-seven library functions take
  and return.

radare2 is LGPL-3.0, as is this tree.

## Refreshing

Nothing here is edited locally, so a refresh is a copy:

    cp ../radare2/libr/anal/d/cc-{x86-64,x86-32,arm-64,arm-32,riscv-64}.sdb.txt \
       ../radare2/libr/anal/d/types.sdb.txt \
       crates/r2abi/data/

Then run `cargo test -p r2abi`: the tests read the embedded copies and assert
what the data says about `amd64`, `ms`, `arm64`, `printf` and `__strcpy_chk`, so
a refresh that changes those facts fails rather than passing silently.

Refresh when radare2's own copies change. They rarely do: the two commits that
last touched them are `39b18895dc` and `1a9c2698f8`, both upstream.
