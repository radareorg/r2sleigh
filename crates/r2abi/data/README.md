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
- `types-posix.sdb.txt`: ISO C17, POSIX and 4.4BSD rows that carry the header they are read
  from, portable like `types.sdb.txt`, each with its tail stated (see "Cited rows").
- `types-linux.sdb.txt`: what the GNU C library declares for itself.
- `types-glibc.sdb.txt`: the GNU C library's rows that carry their header, read with
  `types-linux.sdb.txt` and on the same terms as `types-posix.sdb.txt`.
- `types-android.sdb.txt`: what bionic, Android's C library, declares for
  itself.
- `types-bionic.sdb.txt`: bionic's rows that carry their header, read with
  `types-android.sdb.txt` and on the same terms as `types-posix.sdb.txt`.
- `types-musl.sdb.txt`: musl's rows that carry their header, read beside the portable tables on
  the same terms as `types-posix.sdb.txt`.
- `types-kernel32.sdb.txt` and `types-ucrt.sdb.txt`: what KERNEL32.dll and the
  Universal C Runtime export, each row citing Microsoft's reference page (or
  header) and the minimum version it states; read only for a PE import that
  names that DLL.
- `cxx-objects.txt`: for a mangled member whose name does not say whether it
  takes `this`, the header that does (see "Mangled names").
- `types-darwin.sdb.txt`: what Darwin's libSystem declares for itself.
- `types-objc.sdb.txt`: what objc4's `libobjc.A.dylib` exports; read only for an import whose
  two-level namespace ordinal names that dylib.
- `uncited-rows.txt`: why each row of `types.sdb.txt` and `types-linux.sdb.txt` is still
  radare2's (see "Cited rows").
- `void-rows.txt`: the source that states each `ret=void` row returns
  nothing, and the rows found spelled `void` that return a value.
  `scripts/audit_abi_rows.py` fails on an uncited `void` row (ROADMAP D204).
- `syscalls-linux-*.txt`: the Linux kernel's system call numbers, generated
  from its UAPI headers by `scripts/gen_syscalls.py` and never edited by
  hand. These are not radare2's `libr/syscall/d/` tables, which are kept by
  hand and carry the OABI numbering for arm-32.

radare2 is LGPL-3.0, as is this tree.

## Keys are C identifiers

A record is keyed by the C identifier a program links against: `__memcpy_chk`,
`__libc_start_main`, `_Exit`. `LibraryRows::row` is an exact lookup. Nothing is
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
| `libc_start_main` | `__libc_start_main` | glibc (cited, LSB) |
| `cxa_throw`       | `__cxa_throw`       | cxx |
| `cxa_finalize`    | `__cxa_finalize`    | cxx |
| `assert_fail`     | `__assert_fail`     | glibc (cited) |
| `errno_location`  | `__errno_location`  | glibc (cited) |

A radare2 record whose key is not an identifier any program links is deleted, not kept: one
fact has one key. `libc_init`, `libc_init_array` and `uClibc_main` went with the keys above, and
`tests/cited_rows.rs` fails if one returns.

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

## Cited rows

Every row of `types-posix.sdb.txt` and `types-glibc.sdb.txt` names the header it is read from on
a `func.<name>.include=` line and sits under a comment naming its source (`r2abi::library::SOURCES`:
ISO C17, POSIX.1-2017, POSIX.1-2024, 4.4BSD, glibc, LSB 5.0, GCC, bionic, musl or Microsoft). The bionic,
KERNEL32 and UCRT tables are cited the same way; a Microsoft row adds `func.<name>.cite=`, the
reference page and its minimum supported client. A binary-only LSB 5.0 interface
(`__stack_chk_fail`) has no header: it cites its LSB section on `func.<name>.cite=` instead, under
a comment saying it is in the binary standard only. A row that spells `...`
states its tail on `func.<name>.tail=`: `variadic`, `format(printf|scanf|wprintf|wscanf,<index>)`
or `va_list(<index>)`, the index counting fixed parameters from zero. A row with no `...` and no
`.tail=` states a fixed prototype (`Tail::None`). Every row of the other tables is
`Tail::Unstated`: its fixed list is radare2's and only a lower bound of what a call reads
(doc/adr-call-boundary.md, "Lower bounds and upper bounds"). `tests/cited_rows.rs` fails a cited
row without its header, source or tail, a tail its prototype does not have, a `.tail=` in an
uncited table, and a row declared in two tables.

S18 (ROADMAP D242) moved 418 rows of `types.sdb.txt` and `types-linux.sdb.txt` that a glibc 2.39
header declares into the cited tables, each respelled from the header's declaration under
the mode its source names (`-std=c17`, `_POSIX_C_SOURCE=200809L`, `_XOPEN_SOURCE=700`,
`_GNU_SOURCE`). A portable row keeps its scope in `types-posix.sdb.txt`, a glibc row in
`types-glibc.sdb.txt`. `scripts/audit_abi_rows.py --cc gcc` compiles each cited row that names a
header against it in CI; a row citing GCC's `builtins.def` is not compiled. `uncited-rows.txt`
names each row left behind and why (61 of them glibc declares), and that list only falls.
The fortified string functions (`__memcpy_chk` and 8 more) cite GCC's `builtins.def`.

A Microsoft row states a handle its page names by what it refers to: `func.<name>.yields=current-process`
where the result is the calling process's handle (`GetCurrentProcess`), and
`func.<name>.halts_on=<index>,current-process` where the page says the call does not return when that
parameter is it (`TerminateProcess`: "When a process terminates itself, TerminateProcess stops
execution of the calling thread and does not return").

The printf and scanf families, `err`, `syslog`, `error` and the fortified `__*printf_chk` moved
here from radare2's tables to state `Tail::Format`, which replaced the engine's guess of a format
from a parameter called `format`.

A pointer's own qualifiers (`restrict`, a `const` after the star) are not part of a
prototype's type, so the rows leave them out.

## Mangled names

An import whose name is an Itanium C++ ABI mangling states its parameter types
in the name (5.1.5), so r2abi reads its row from the name when no table states
one (`r2abi::mangled`, `LibraryRows::read_mangled`). A reference is its pointer.
A class or enum passed by value stays a named opaque type: the name does not
say whether it is trivially copyable, so the convention cannot place it. The
row states no result (the return type is refused), and its tail is `None`, or
`Variadic` for a `z`. A name that encodes no result (any non-template function)
may still return in memory through a hidden pointer in the first argument
register, and a base-object constructor or destructor (C2, D2) may take a VTT,
so such a row (`Passing::HiddenResultUnstated`, `Passing::VttUnstated`) places
no argument on SysV x86-64 or Microsoft x64; AAPCS64 passes the pointer in x8
and places it.

The name says whether the function takes `this` only for a constructor, a
destructor, a cv- or ref-qualified member, a conversion, and an operator of a
scope the name proves a class (template arguments, or `So`, `Si`, `Sd`, `Ss`,
`Sa`, `Sb`). Anything else nested could be a namespace function, a static
member or a non-static one, so `cxx-objects.txt` states it from the header that
declares it, and a name it does not list gets no row.

## Handles

`FILE` and `DIR` are typedefs of tags the C library's header names. `spelling.rs` states the tag
per library: glibc's `struct _IO_FILE` (`bits/types/FILE.h`) and `struct __dirstream`
(`dirent.h`), libSystem's `struct __sFILE` (`_stdio.h`), bionic's `struct __sFILE` (`stdio.h`)
and `struct DIR` (`dirent.h`). libSystem's `DIR` is a typedef of an anonymous struct, so it states
none and the name stays an opaque typedef.

## Binding

A row applies only to an import, never to a body by its name (doc/adr-call-boundary.md, Refusals
"A library row"). r2engine's `imports::Imports` binds a versioned ELF import to the library its
version names (`GLIBC_*` to glibc, bionic's `LIBC*`, `GLIBCXX_*`, `CXXABI_*` and `GCC_*` to the
C++ runtime rows) and an unversioned one only where `DT_NEEDED` names exactly one C library. A PE
import that names KERNEL32.dll reads only `types-kernel32.sdb.txt`; one that names
`ucrtbase.dll` or an `api-ms-win-crt-*` set reads `types-ucrt.sdb.txt` first, then the C++ and
portable rows as every other PE import does.

## Other local edits

- `fopen`, `fdopen`, `freopen`, `popen`, `tmpfile` and glibc's `fopen64` return `FILE *`, where
  radare2 spells their result `file*`, a name no header has.

- `types-glibc.sdb.txt` declares `__libc_start_main`, the name glibc exports, from LSB 5.0 Core.
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

- The portable table declares `signal` returning `void *` (C11 7.14.1.1:
  the previous handler; radare2#27403), `aligned_alloc` under its own name
  returning `void *` where radare2 keys `*aligned_alloc` returning `void`
  (C11 7.22.3.1), and `srandom` returning `void` where radare2 says
  `uint32_t` (POSIX `<stdlib.h>`). The spelling for `signal` is `void *`
  because a function-pointer spelling reads as refused here.

- The portable table declares POSIX `<dlfcn.h>`'s `dlopen`, `dlsym`,
  `dlclose` and `dlerror`, which radare2 does not; glibc, bionic and
  libSystem declare them alike. Without them a call to one has no arity
  but the stub's, a floor (ROADMAP P7).
- The Objective-C runtime's records are objc4's (`objc/message.h`,
  `objc/objc-internal.h`), in `types-objc.sdb.txt` only (GNUstep's libobjc2
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
