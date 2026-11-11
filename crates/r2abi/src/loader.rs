//! How a loader calls the functions a container names for it to call (doc/adr-call-boundary.md,
//! "S22 as built"). Keyed by the container's statement, never by a symbol's name.

use crate::statement::{EntryKind, Format};

/// One call the loader makes to a function the container names: what it passes, and whether it
/// reads what the function leaves in the result registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoaderCall {
    /// How many arguments the loader passes.
    pub arguments: u8,
    /// Whether the loader reads the result.
    pub reads_result: bool,
    pub citation: &'static str,
}

impl LoaderCall {
    /// A call that passes nothing and reads nothing: a way in no caller's reading needs to count.
    pub const fn adds_no_read(&self) -> bool {
        self.arguments == 0 && !self.reads_result
    }
}

const ELF_TERMINATION: LoaderCall = LoaderCall {
    arguments: 0,
    reads_result: false,
    citation: "System V gABI, chapter 5, \"Initialization and Termination Functions\": \
               termination functions \"are executed with the atexit(BA_OS) mechanism\", and the \
               dynamic linker may register \"the executable file's termination function with \
               atexit(BA_OS)\"; ISO C17 7.22.4.2: `int atexit(void (*func)(void))`",
};

/// The loader's call to a function the container names as `kind`, where a document states it.
/// Initialisers have none: glibc passes `argc, argv, envp`, musl nothing (D240).
pub fn loader_call(format: Format, kind: EntryKind) -> Option<&'static LoaderCall> {
    match (format, kind) {
        (Format::Elf, EntryKind::FiniHook | EntryKind::Fini) => Some(&ELF_TERMINATION),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `DT_FINI`'s function and each fini array entry are called as `atexit` handlers; an
    /// initialiser and a Mach-O terminator are not stated by this row.
    #[test]
    fn only_an_elf_termination_function_has_a_cited_loader_call() {
        let fini = loader_call(Format::Elf, EntryKind::FiniHook).expect("a row");
        assert!(fini.adds_no_read());
        assert!(fini.citation.contains("atexit"));
        assert_eq!(loader_call(Format::Elf, EntryKind::Fini), Some(fini));
        assert_eq!(loader_call(Format::Elf, EntryKind::InitHook), None);
        assert_eq!(loader_call(Format::Elf, EntryKind::Init), None);
        assert_eq!(loader_call(Format::MachO, EntryKind::Fini), None);
        assert_eq!(loader_call(Format::Elf, EntryKind::Symbol), None);
    }
}
