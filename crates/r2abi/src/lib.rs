//! What a platform's ABI and its C library state, read natively: library
//! prototypes, system calls, types and the cited ABI rows (`platform`). Where a
//! call's arguments arrive is the compiler specification's (`r2sleigh_lift::profile`).

pub mod declarations;
pub mod frames;
pub mod platform;
pub mod prototypes;
mod spelling;
pub mod statement;
pub mod syscalls;
pub mod types;

pub use declarations::{DataObject, Declarations};
pub use platform::{
    CallingConvention, PlatformRegister, RegisterDuty, StackGuard, architecture_registers,
    calling_convention, platform_registers, stack_guard,
};
pub use prototypes::{
    Arrival, FrameBase, Local, Parameter, Platform, Prototype, Prototypes, Spelled,
};
pub use syscalls::Syscalls;
pub use types::{
    DataModel, Keyword, Member, Qualifiers, Record, RecordKind, Refusal, Scalar, ScalarKind,
    Signature, Type, TypeGraph, TypeId, Width,
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
