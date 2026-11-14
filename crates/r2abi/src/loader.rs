//! How a loader calls the functions a container names (doc/adr-call-boundary.md, "Ga as built").
//! Keyed by the container's statement and its C library, never by a symbol's name.

use crate::library::CLibrary;
use crate::statement::{EntryKind, Format};

/// One call the loader makes to a function the container names: what it reads of the result, and
/// the documents that state it. What it passes is no row's: a passed register stays a parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoaderCall {
    pub reads_result: ResultRead,
    pub citation: &'static str,
}

/// What the loader reads of what a function leaves in the result registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultRead {
    /// Nothing: the call is a statement, its value discarded.
    Nothing,
    /// The low `bytes` of the integer result register, and no other lane.
    Integer { bytes: u8 },
}

const ELF_TERMINATION: LoaderCall = LoaderCall {
    reads_result: ResultRead::Nothing,
    citation: "System V gABI, chapter 5, \"Initialization and Termination Functions\": \
               termination functions \"are executed with the atexit(BA_OS) mechanism\", and the \
               dynamic linker may register \"the executable file's termination function with \
               atexit(BA_OS)\"; ISO C17 7.22.4.2: `int atexit(void (*func)(void))`",
};

const GLIBC_INITIALISER: LoaderCall = LoaderCall {
    reads_result: ResultRead::Nothing,
    citation: "glibc elf/dl-init.c `call_init`: `DL_CALL_DT_INIT(l, ..., argc, argv, env)` and \
               `((dl_init_t) addrs[j]) (argc, argv, env)`, `_dl_init` the same for \
               DT_PREINIT_ARRAY; csu/libc-start.c `call_init` (2.34 on), static: \
               `(*__preinit_array_start [i]) (argc, argv, envp)`, `_init ()`, \
               `(*__init_array_start [i]) (argc, argv, envp)`; csu/elf-init.c \
               `__libc_csu_init` (before 2.34) likewise: each a statement, its value discarded",
};

const MUSL_INITIALISER: LoaderCall = LoaderCall {
    reads_result: ResultRead::Nothing,
    citation: "musl ldso/dynlink.c `do_init_fini`: `fpaddr(p, dyn[DT_INIT])()` and \
               `((void (*)(void))*fn++)()`; src/env/__libc_start_main.c `libc_start_init`: \
               `_init()` and `(*(void (**)(void))a)()`: each a statement, its value discarded. \
               Neither reads DT_PREINIT_ARRAY",
};

const DYLD_MAIN: LoaderCall = LoaderCall {
    reads_result: ResultRead::Integer { bytes: 4 },
    citation: "Apple dyld dyld/dyldMain.cpp `start`: \"call main() and if it returns, call exit() \
               with the result\", `int result = appMain(argc, argv, envp, apple)` then \
               `libSystemHelpers.exit(result)`; ISO C17 5.1.2.2.1 and 5.1.2.2.3; `int` is four \
               bytes (System V AMD64 psABI 3.1.2, Figure 3.1; AAPCS64 \"Arithmetic Types\", a \
               signed word)",
};

/// The loader's call to a function the container names as `kind`, where a document states it for
/// the program's C library. Bionic, an unknown library and a Mach-O initialiser have none.
pub fn loader_call(
    format: Format,
    library: CLibrary,
    kind: EntryKind,
) -> Option<&'static LoaderCall> {
    use EntryKind::{CMain, Fini, FiniHook, Init, InitHook, Preinit};
    match (format, library, kind) {
        (Format::Elf, _, FiniHook | Fini) => Some(&ELF_TERMINATION),
        (Format::Elf, CLibrary::Glibc, Init | InitHook | Preinit) => Some(&GLIBC_INITIALISER),
        (Format::Elf, CLibrary::Musl, Init | InitHook) => Some(&MUSL_INITIALISER),
        (Format::MachO, CLibrary::LibSystem, CMain) => Some(&DYLD_MAIN),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `DT_FINI`'s function and each fini array entry are called as `atexit` handlers, whatever
    /// the library; a Mach-O terminator and an ELF entry point are not stated by any row.
    #[test]
    fn an_elf_termination_function_reads_nothing_under_every_library() {
        for library in [CLibrary::Glibc, CLibrary::Bionic, CLibrary::Unknown] {
            let fini = loader_call(Format::Elf, library, EntryKind::FiniHook).expect("a row");
            assert_eq!(fini.reads_result, ResultRead::Nothing);
            assert!(fini.citation.contains("atexit"));
            assert_eq!(
                loader_call(Format::Elf, library, EntryKind::Fini),
                Some(fini)
            );
        }
        let none = |format, kind| loader_call(format, CLibrary::Glibc, kind);
        assert_eq!(none(Format::MachO, EntryKind::Fini), None);
        assert_eq!(none(Format::Elf, EntryKind::Symbol), None);
        assert_eq!(none(Format::Elf, EntryKind::Main), None);
    }

    /// glibc and musl call constructors as statements; bionic's linker is uncited, and musl
    /// never runs a preinit array.
    #[test]
    fn an_initialiser_row_is_keyed_by_the_c_library() {
        let call = |library, kind| loader_call(Format::Elf, library, kind);
        for kind in [EntryKind::Init, EntryKind::InitHook, EntryKind::Preinit] {
            let row = call(CLibrary::Glibc, kind).expect("glibc states it");
            assert_eq!(row.reads_result, ResultRead::Nothing);
            assert!(row.citation.contains("dl-init.c"));
            assert_eq!(call(CLibrary::Bionic, kind), None);
            assert_eq!(call(CLibrary::Unknown, kind), None);
        }
        let musl = call(CLibrary::Musl, EntryKind::Init).expect("musl states it");
        assert!(musl.citation.contains("do_init_fini"));
        assert_eq!(call(CLibrary::Musl, EntryKind::Preinit), None);
        let mach_o = loader_call(Format::MachO, CLibrary::LibSystem, EntryKind::Init);
        assert_eq!(mach_o, None);
    }

    /// dyld hands `main`'s `int` to `exit`: the integer lane's low four bytes, nothing else.
    #[test]
    fn dyld_reads_the_int_main_returns() {
        let main = loader_call(Format::MachO, CLibrary::LibSystem, EntryKind::CMain);
        let main = main.expect("dyld states it");
        assert_eq!(main.reads_result, ResultRead::Integer { bytes: 4 });
        assert!(main.citation.contains("dyldMain.cpp"));
        assert_eq!(
            loader_call(Format::Elf, CLibrary::Glibc, EntryKind::CMain),
            None
        );
    }
}
