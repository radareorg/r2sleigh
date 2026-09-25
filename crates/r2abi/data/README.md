# r2abi's tables

These are r2abi's own tables. They began as copies of radare2's
`libr/anal/d/` and are kept in its `sdb` text form, but they are not a mirror
of it: they are keyed differently, scoped differently, and carry records
radare2 does not. Each difference is listed below, so a refresh from radare2
is a merge that keeps them rather than a copy that drops them.

- `cc-*.sdb.txt`: what each calling convention does with arguments, results
  and saved registers.
- `types.sdb.txt`: the portable table, what a library function takes and
  returns wherever it is linked. A record belongs here only when every C
  library r2abi scopes (glibc, bionic, Darwin's libSystem) declares that
  interface alike.
- `types-linux.sdb.txt`: what the GNU C library declares for itself.
- `types-android.sdb.txt`: what bionic, Android's C library, declares for
  itself.
- `types-darwin.sdb.txt`: what Darwin's libSystem declares for itself.

radare2 is LGPL-3.0, as is this tree.

## Keys are C identifiers

A record is keyed by the C identifier a program links against: `__memcpy_chk`,
`__libc_start_main`, `_Exit`. `Prototypes::get` is an exact lookup. Nothing is
stripped to make a name match, because a name that differs names another
function: `__memcpy_chk` takes one argument more than `memcpy`, and a
program's own `_strlen` is not the library's `strlen`.

A linked name's decoration is not part of the identifier, and it is the
loader's to drop, once, when it states the import: Mach-O writes every C name
with one leading underscore, so r2image states the `___memcpy_chk` a Mach-O
binds as `__memcpy_chk`. ELF writes the identifier itself.

radare2 keys the same records the other way: it drops every leading
underscore from both the record and the name it looks up
(`type_func_try_guess` and `trim_lodashes`), so its key for `__memcpy_chk` is
`memcpy_chk`. radare2#26743 proposed identifier keys upstream and is being
reworked to keep radare2's normalized keys, so the two stay different. A
refresh translates radare2's keys through this table, never by adding or
stripping underscores at lookup:

| radare2 key       | r2abi key           | r2abi table |
|-------------------|---------------------|-------------|
| `strcpy_chk`      | `__strcpy_chk`      | portable    |
| `snprintf_chk`    | `__snprintf_chk`    | portable    |
| `sprintf_chk`     | `__sprintf_chk`     | portable    |
| `vsprintf_chk`    | `__vsprintf_chk`    | portable    |
| `vsnprintf_chk`   | `__vsnprintf_chk`   | portable    |
| `memcpy_chk`      | `__memcpy_chk`      | portable    |
| `memmove_chk`     | `__memmove_chk`     | portable    |
| `memset_chk`      | `__memset_chk`      | portable    |
| `strncpy_chk`     | `__strncpy_chk`     | portable    |
| `strcat_chk`      | `__strcat_chk`      | portable    |
| `strncat_chk`     | `__strncat_chk`     | portable    |
| `printf_chk`      | `__printf_chk`      | linux       |
| `fprintf_chk`     | `__fprintf_chk`     | linux       |
| `vprintf_chk`     | `__vprintf_chk`     | linux       |
| `vfprintf_chk`    | `__vfprintf_chk`    | linux       |
| `fgets_chk`       | `__fgets_chk`       | linux       |
| `fread_chk`       | `__fread_chk`       | linux       |
| `read_chk`        | `__read_chk`        | linux       |
| `realpath_chk`    | `__realpath_chk`    | linux       |
| `longjmp_chk`     | `__longjmp_chk`     | linux       |
| `fdelt_chk`       | `__fdelt_chk`       | linux       |
| `libc_start_main` | `__libc_start_main` | linux (kept beside radare2's key) |

A radare2 record whose key is not an identifier any program links, and that
this table does not translate, is unreachable here and stays as radare2 has
it: `libc_init`, `libc_init_array` and `errno_location` in
`types-linux.sdb.txt`, for instance.

## Records are scoped per C library

A name two libraries export is not one interface. glibc's `__fgets_chk` is
`(char *s, size_t size, int n, FILE *stream)`; bionic's is
`(char *s, int n, FILE *stream, size_t size)`. So each library's own records
are in its own table, and the engine layers a table over the portable one only
when the container states which library the program runs against: ELF's
`PT_INTERP`, the notes its start files leave, and `EI_OSABI` (r2image reads
them; r2engine selects). With no such statement only the portable table
applies, and a call to `__fgets_chk` has no prototype rather than one read in
the wrong library's order.

Where radare2 scopes differently:

- The eight fortified functions glibc, bionic and Darwin declare alike --
  `__memcpy_chk`, `__memmove_chk`, `__memset_chk`, `__strncpy_chk`,
  `__strcat_chk`, `__strncat_chk`, `__vsprintf_chk`, `__vsnprintf_chk` -- are
  in the portable table; radare2 has them in `types-linux` only, so Darwin gets
  none of them. This is the move the maintainer's rework of #26743 proposes.
- The ten that are glibc's alone are in `types-linux.sdb.txt`, as radare2 has
  them.
- `types-android.sdb.txt` declares bionic's `__fgets_chk` and `__fread_chk` in
  bionic's order, which radare2 does not declare at all, and leaves out
  radare2's `android_log_*` (liblog's `__android_log_*` under a key with the
  underscores dropped, with arities that are not `<android/log.h>`'s) and
  `xalloc_die` (gnulib's, not bionic's).

## Other local edits

- `types-linux.sdb.txt` declares `__libc_start_main`, the name glibc exports,
  beside radare2's `libc_start_main`.
- `cc-arm-64.sdb.txt` spells the arm64 vector clobbers `q0..q7,q16..q31` and
  preserves only `d8..d15`, the low halves AAPCS64 keeps.
- The x86 conventions with a `preserve` list end it with `df`, since every x86
  ABI requires the direction flag clear on entry and on return.

## Refreshing

Diff radare2's `libr/anal/d/` against these files, and take a change only
through the rules above: translate its keys through the table, put a record in
the table of the C library that declares it, and keep the local edits. Then
run `cargo test -p r2abi`: the tests read the embedded tables and assert what
they say about `amd64`, `ms`, `arm64`, `printf`, `__strcpy_chk` and each
library's `__fgets_chk`, so a refresh that changes those facts fails rather
than passing silently.
