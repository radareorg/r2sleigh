//! What a platform's ABI and its C library state, read natively: library
//! rows by linked name (`library`), system calls, types and the cited ABI rows (`platform`). Where a
//! call's arguments arrive is the compiler specification's (`r2sleigh_lift::profile`).
#![cfg_attr(dylint_lib = "r2sleigh_lints", deny(entity_keyed_map))]

pub mod convention;
pub mod data_model;
pub mod declarations;
pub mod frames;
pub mod library;
pub mod loader;
pub mod mangled;
pub mod platform;
pub mod prototypes;
pub mod runtime;
mod spelling;
pub mod statement;
pub mod syscalls;
pub mod types;

pub use convention::{
    ConventionId, ConventionRow, Cspec, Extension, HomeArea, RegName, ResultSet, Side, SlotClass,
    SpecOverride, Toolchain,
};
pub use data_model::{CDataModel, KERNEL_MODE_CITATION};
pub use declarations::{DataObject, Declarations};
pub use library::{
    CLibrary, Dll, FlagBits, FlagTest, FormatKind, Handle, Kernel, LibraryId, LibraryRow,
    LibraryRows, PrototypeId, RowResult, Tail,
};
pub use loader::{LoaderCall, ResultRead, loader_call};
pub use mangled::Passing;
pub use platform::{
    CookieCheck, EntryStack, GuardRow, LinkedGuard, PlatformRegister, RegisterDuty,
    RegisterSaveArea, SaveAreaAnchor, StackGuard, architecture_registers, guard_row,
    platform_registers,
};
pub use prototypes::{Arrival, FrameBase, Local, Parameter, Prototype, Spelled, StatedConvention};
pub use syscalls::Syscalls;
pub use types::{
    Keyword, Member, Qualifiers, Record, RecordKind, Refusal, Scalar, ScalarKind, Signature, Type,
    TypeGraph, TypeId, Width,
};

/// The file family an architecture name belongs to.
///
/// One table: the same question was answered again in the engine, and the two
/// had already drifted apart by two spellings.
pub fn family(arch: &str) -> Option<&'static str> {
    let arch = arch.to_ascii_lowercase();
    let arch = arch.as_str();
    match arch {
        "x86" | "x86-32" | "x86-64" | "x86_64" | "x64" | "amd64" | "i386" | "i686" => Some("x86"),
        "arm" | "arm32" | "arm64" | "arm64e" | "aarch64" | "thumb" => Some("arm"),
        "riscv" | "riscv32" | "riscv64" => Some("riscv"),
        _ => None,
    }
}
