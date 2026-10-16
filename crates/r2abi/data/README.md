# r2abi's tables

These are r2abi's own tables. They began as copies of radare2's
`libr/anal/d/` and are kept in its `sdb` text form, but they are not a mirror
of it: they are keyed differently, scoped differently, and carry records
radare2 does not. Each difference is listed below, so a refresh from radare2
is a merge that keeps them rather than a copy that drops them.

- `types.sdb.txt`: the portable table, what a library function takes and
  returns wherever it is linked. A record belongs here only when every C
  library r2abi scopes (glibc, bionic, Darwin's libSystem) declares that
  interface alike.
- `types-cxx.sdb.txt`: the C++ runtime, portable as well: operator new and
  delete, the Itanium C++ ABI's `__cxa_*`, `__dynamic_cast` and
  `_Unwind_Resume`, `std::terminate` and libstdc++'s `std::__throw_*`. None
  of it is radare2's, so a refresh leaves it alone; each block cites its
  source.
- `types-linux.sdb.txt`: what the GNU C library declares for itself.
- `types-android.sdb.txt`: what bionic, Android's C library, declares for
  itself.
- `types-darwin.sdb.txt`: what Darwin's libSystem declares for itself.
- `syscalls-linux-*.txt`: the Linux kernel's system call numbers, generated
  from its UAPI headers by `scripts/gen_syscalls.py` and never edited by
  hand. These are not radare2's `libr/syscall/d/` tables, which are kept by
  hand and carry the OABI numbering for arm-32.

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
| `cxa_throw`       | `__cxa_throw`       | cxx (radare2's record kept under its key) |
| `cxa_finalize`    | `__cxa_finalize`    | cxx (radare2's record kept under its key) |

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

## The C++ runtime is portable

`types-cxx.sdb.txt` is read on every platform, beside the portable table,
rather than selected by a C++ runtime the container names (`DT_NEEDED`
libstdc++ or libc++, `LC_LOAD_DYLIB`), because its keys cannot collide the
way `__fgets_chk` does:

- A mangled key states its parameter types. Two runtimes cannot export
  `_Znwm` with two interfaces, and the data models' forms are already two
  keys: `_Znwm` takes an `unsigned long` (LP64), `_Znwj` an `unsigned int`
  (ILP32). A scope would be a second owner of what the key already says.
- The Itanium C++ ABI's `extern "C"` routines are declared alike by
  libsupc++ and libc++abi; `__cxa_atexit` and `__cxa_finalize` by glibc,
  bionic and libSystem; `_Unwind_Resume` by libgcc_s and libunwind.
- A row is read only for an import, which has no body here, and importing
  `_Znwm` is itself the container's statement that the program links a C++
  runtime. A program's own function of that name has its body, and the body
  is what states its interface.

Microsoft's runtime mangles differently (`??2@YAPEAX_K@Z`), so none of these
keys reaches a PE that links it.

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
- `types-darwin.sdb.txt` declares `__bzero`, which radare2 does not.
  libsystem_platform exports `___bzero` at the address of
  `__platform_bzero`, the function libsystem_c re-exports as `_bzero`
  (`dyld_info -exports` on both), so it is `bzero` under a second name, and
  clang emits calls to it for `bzero` and zeroing `memset` on x86-64.

- `types-darwin.sdb.txt` declares libSystem's own imports `ls` calls, each block
  citing the SDK header it reads (`__assert_rtn`, `__maskrune`, `__tolower`, `__error`,
  `wcwidth`, `fts_*`, `acl_get_*`, `getxattr`, `fflagstostr`, `uuid_unparse_upper`), and
  `__assert_rtn` replaces radare2's `assert_rtn`, whose key no Mach-O binds and whose
  arguments were glibc's order. `mbr_identifier_translate` is in no public SDK header, so
  it stays undeclared.

- The portable table declares POSIX `<dlfcn.h>`'s `dlopen`, `dlsym`,
  `dlclose` and `dlerror`, which radare2 does not; glibc, bionic and
  libSystem declare them alike. Without them a call to one has no arity
  but the stub's, a floor (ROADMAP P7).
- The Objective-C runtime's records are objc4's (`objc/message.h`,
  `objc/objc-internal.h`), in the Darwin table only (GNUstep's libobjc2
  differs: its `objc_storeStrong` returns the object), where radare2's are not: `objc_msgSend` and
  `objc_msgSendSuper2` are variadic after `self` and `op`;
  `objc_storeStrong` is `void (id *location, id obj)`, not `(void *, int)`
  returning `void *`; `objc_retain` and
  `objc_retainAutoreleasedReturnValue` return the object.

## Refreshing

Diff radare2's `libr/anal/d/` against these files, and take a change only
through the rules above: translate its keys through the table, put a record in
the table of the C library that declares it, and keep the local edits. Then
run `cargo test -p r2abi`: the tests read the embedded tables and assert what
they say about `printf`, `__strcpy_chk` and each
library's `__fgets_chk`, so a refresh that changes those facts fails rather
than passing silently.
