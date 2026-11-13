//! What a platform's ABI says about registers that no calling convention list does.
//!
//! radare2's `cc` data names the registers a call destroys and the ones it
//! restores. Two more duties exist in the processor supplements and are not in
//! that data: a register the platform reserves to the system, which conforming
//! code never writes, so one value survives every call; and a control register
//! the supplement makes callee-saved. The `cc` files stay as radare2 ships them,
//! and this table carries the rest, one row per statement, each with the
//! document that makes it.
//!
//! Registers are spelled as radare2 spells them (`fs_base`, `cwd`, `mxcsr`);
//! placing a spelling in the lifted architecture is the lifter's job.

use crate::convention::RegName;
use crate::{CLibrary, Kernel};

/// What a call does to a register the platform ABI speaks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegisterDuty {
    /// Reserved to the system. Conforming code never writes it, so a callee
    /// leaves it holding the value it held when the call was made. The
    /// thread pointer is the case every platform has.
    SystemReserved,
    /// Callee-saved: a callee may change it, and restores it before it returns.
    CalleeSaved,
}

/// One register a platform ABI assigns a duty to, and where it says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformRegister {
    /// The register, spelled as radare2 spells it.
    pub register: &'static str,
    pub duty: RegisterDuty,
    /// The bits the duty covers, where the document gives it only some of the
    /// register: MXCSR's control bits are callee-saved and its status bits are
    /// not. `None` is the whole register.
    pub bits: Option<u64>,
    /// The document, section and words that state the duty.
    pub citation: &'static str,
}

impl PlatformRegister {
    /// The bytes, counted from the register's least significant one, that the
    /// duty covers whole.
    ///
    /// A byte shared between a covered bit and an uncovered one is not
    /// covered: a storage model that places whole bytes can claim no more.
    pub fn covered_bytes(&self, size_bytes: u32) -> impl Iterator<Item = u32> + '_ {
        (0..size_bytes).filter(move |byte| match self.bits {
            None => true,
            Some(bits) => {
                let Some(mask) = 0xffu64.checked_shl(byte * 8) else {
                    return false;
                };
                bits & mask == mask
            }
        })
    }
}

/// System V AMD64 psABI 1.0, §3.2.1 "Registers", and its Figure 3.4.
const X86_64_SYSV_CONTROL: [PlatformRegister; 2] = [
    PlatformRegister {
        register: "cwd",
        duty: RegisterDuty::CalleeSaved,
        bits: None,
        citation: "System V AMD64 psABI 1.0, section 3.2.1: \"the x87 control word is \
                   callee-saved\"",
    },
    PlatformRegister {
        register: "mxcsr",
        duty: RegisterDuty::CalleeSaved,
        // DAZ (bit 6), the six exception masks (7-12), RC (13-14) and FZ (15).
        bits: Some(0xffc0),
        citation: "System V AMD64 psABI 1.0, section 3.2.1: \"The control bits of the MXCSR \
                   register are callee-saved (preserved across calls), while the status bits \
                   are caller-saved\"",
    },
];

const X86_64_SYSV_LINUX: [PlatformRegister; 3] = [
    PlatformRegister {
        register: "fs_base",
        duty: RegisterDuty::SystemReserved,
        bits: None,
        citation: "System V AMD64 psABI 1.0, section 3.2.1, Figure 3.4: %fs is \"Reserved for \
                   system (as thread specific data register)\"",
    },
    X86_64_SYSV_CONTROL[0],
    X86_64_SYSV_CONTROL[1],
];

const I386_SYSV_LINUX: [PlatformRegister; 1] = [PlatformRegister {
    register: "gs_base",
    duty: RegisterDuty::SystemReserved,
    bits: None,
    citation: "U. Drepper, \"ELF Handling For Thread-Local Storage\", IA-32 (variant II): the \
               thread pointer is the base of the segment %gs selects, which the system sets \
               and the program does not",
}];

const AARCH64_ELF: [PlatformRegister; 1] = [PlatformRegister {
    register: "tpidr_el0",
    duty: RegisterDuty::SystemReserved,
    bits: None,
    citation: "ELF for the Arm 64-bit Architecture (AAELF64), thread-local storage: the thread \
               pointer is TPIDR_EL0, set by the system for each thread",
}];

const AARCH64_DARWIN: [PlatformRegister; 1] = [PlatformRegister {
    register: "x18",
    duty: RegisterDuty::SystemReserved,
    bits: None,
    citation: "Apple, \"Writing ARM64 code for Apple platforms\": \"The platform reserves \
               register x18. Don't use this register.\"",
}];

/// A word a compiler-inserted stack check reads at a constant offset from a register no call
/// changes: a platform's canary beside a reserved register, or a runtime's lowest stack pointer
/// beside the register its convention fixes (Go's `g.stackguard0`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackGuard {
    /// The reserved register.
    pub register: RegName,
    pub offset: u64,
    pub width: u32,
    pub citation: &'static str,
}

const X86_64_LINUX_GUARD: StackGuard = StackGuard {
    register: RegName("fs_base"),
    offset: 0x28,
    width: 8,
    citation: "glibc sysdeps/x86_64/nptl/tls.h, tcbhead_t: stack_guard at %fs:0x28; GCC \
               gcc/config/i386/gnu-user64.h: TARGET_THREAD_SSP_OFFSET 0x28 (musl agrees)",
};

const I386_LINUX_GUARD: StackGuard = StackGuard {
    register: RegName("gs_base"),
    offset: 0x14,
    width: 4,
    citation: "glibc sysdeps/i386/nptl/tls.h, tcbhead_t: stack_guard at %gs:0x14; GCC \
               gcc/config/i386/gnu-user.h: TARGET_THREAD_SSP_OFFSET 0x14",
};

/// Where a C library keeps the stack protector's canary (doc/adr-call-boundary.md, `GuardRow`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardRow {
    /// A word at a constant offset from the thread pointer.
    ThreadSlot(StackGuard),
    /// A global the library defines; only a binding the container states places it.
    LinkedGlobal(LinkedGuard),
    /// The word the PE load configuration's `SecurityCookie` names (Microsoft PE format,
    /// "Load Configuration Layout"); its address is the container's.
    LoadConfigCookie(CookieCheck),
}

/// The register `__security_check_cookie` takes the saved cookie in, as the CRT source states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CookieCheck {
    pub argument: RegName,
    pub citation: &'static str,
}

/// A stack protector's global word, by the symbol a C library defines it under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkedGuard {
    pub symbol: &'static str,
    pub width: u32,
    pub citation: &'static str,
}

/// GCC AArch64 reads the global (`-mstack-protector-guard=global`, its default), LLVM too except on
/// Android, where it reads `tpidr_el0 + 0x28` (no row yet; doc/adr-call-boundary.md, S27).
const AARCH64_GLIBC_GUARD: GuardRow = GuardRow::LinkedGlobal(LinkedGuard {
    symbol: "__stack_chk_guard",
    width: 8,
    citation: "glibc elf/rtld.c: `uintptr_t __stack_chk_guard attribute_relro` where the thread \
        control block keeps no guard (sysdeps/aarch64/nptl/tls.h); ld.so exports it at \
        GLIBC_2.17; GCC gcc/config/aarch64/aarch64.opt: -mstack-protector-guard=global",
});
const AARCH64_MUSL_GUARD: GuardRow = GuardRow::LinkedGlobal(LinkedGuard {
    symbol: "__stack_chk_guard",
    width: 8,
    citation: "musl src/env/__stack_chk_fail.c: `uintptr_t __stack_chk_guard`; GCC \
        gcc/config/aarch64/aarch64.opt: -mstack-protector-guard=global",
});
const AARCH64_BIONIC_GUARD: GuardRow = GuardRow::LinkedGlobal(LinkedGuard {
    symbol: "__stack_chk_guard",
    width: 8,
    citation: "bionic libc/bionic/__libc_init_main_thread.cpp: `uintptr_t __stack_chk_guard`, \
        which libc.so exports; GCC gcc/config/aarch64/aarch64.opt: \
        -mstack-protector-guard=global",
});

const X86_64_GLIBC_GUARD: GuardRow = GuardRow::ThreadSlot(X86_64_LINUX_GUARD);
const I386_GLIBC_GUARD: GuardRow = GuardRow::ThreadSlot(I386_LINUX_GUARD);

/// Bionic's x86 canary: slot 5 of the thread's TLS words, one pointer each from the segment base.
const BIONIC_GUARD_CITATION: &str = "bionic libc/platform/bionic/tls_defines.h: \
    `TLS_SLOT_STACK_GUARD 5` on x86, used for -fstack-protector, a slot one pointer wide from \
    %fs:0 or %gs:0; LLVM X86ISelLoweringCall.cpp, getIRStackGuard: %fs:0x28, gs:0x14 on i386, \
    for Android from API 17 (hasStackGuardSlotTLS)";
const X86_64_BIONIC_GUARD: GuardRow = GuardRow::ThreadSlot(StackGuard {
    citation: BIONIC_GUARD_CITATION,
    ..X86_64_LINUX_GUARD
});
const I386_BIONIC_GUARD: GuardRow = GuardRow::ThreadSlot(StackGuard {
    citation: BIONIC_GUARD_CITATION,
    ..I386_LINUX_GUARD
});
const UCRT_X86_64_GUARD: GuardRow = GuardRow::LoadConfigCookie(CookieCheck {
    argument: RegName("rcx"),
    citation: "MSVC CRT amdsecgs.asm (x64): `__security_check_cookie` compares rcx, Microsoft \
        x64's first integer argument, with `__security_cookie`",
});
const UCRT_I386_GUARD: GuardRow = GuardRow::LoadConfigCookie(CookieCheck {
    argument: RegName("ecx"),
    citation: "MSVC CRT secchk.c (x86): `void __declspec(naked) __fastcall \
        __security_check_cookie(UINT_PTR cookie)`, `cmp ecx, __security_cookie`",
});

/// The C library's guard row for an architecture; a library no row cites states none.
pub fn guard_row(arch: &str, bits: u32, library: CLibrary) -> Option<&'static GuardRow> {
    match (crate::family(arch), bits, library) {
        (Some("x86"), 64, CLibrary::Glibc | CLibrary::Musl) => Some(&X86_64_GLIBC_GUARD),
        (Some("x86"), 32, CLibrary::Glibc) => Some(&I386_GLIBC_GUARD),
        (Some("x86"), 64, CLibrary::Bionic) => Some(&X86_64_BIONIC_GUARD),
        (Some("x86"), 32, CLibrary::Bionic) => Some(&I386_BIONIC_GUARD),
        (Some("x86"), 64, CLibrary::Ucrt) => Some(&UCRT_X86_64_GUARD),
        (Some("x86"), 32, CLibrary::Ucrt) => Some(&UCRT_I386_GUARD),
        (Some("arm"), 64, CLibrary::Glibc) => Some(&AARCH64_GLIBC_GUARD),
        (Some("arm"), 64, CLibrary::Musl) => Some(&AARCH64_MUSL_GUARD),
        (Some("arm"), 64, CLibrary::Bionic) => Some(&AARCH64_BIONIC_GUARD),
        _ => None,
    }
}

/// What a `va_list` holds of the general register save area (doc/adr-resolved-bodies.md, "Variadic
/// tail"): a bound of it, and a field `va_start` sets to the first unnamed slot's distance from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterSaveArea {
    pub anchor: SaveAreaAnchor,
    /// The offset field's distance in bytes from the bound's own field in the `va_list`.
    pub offset_field: i64,
    /// The offset field's width in bytes.
    pub offset_width: u32,
    /// The pointer `va_arg` fetches stack arguments through, as its distance in bytes from the
    /// bound's own field.
    pub stack_field: i64,
}

/// The bound of the general register save area a `va_list` holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveAreaAnchor {
    /// Its start: System V AMD64's `reg_save_area`.
    Base,
    /// The byte past its end: AAPCS64's `__gr_top`.
    End,
}

/// `sp % alignment == residue` at a function's first instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryStack {
    pub alignment: u32,
    pub residue: u32,
}

/// The direction flag, which every x86 psABI requires clear on entry to and
/// return from a function: a conforming callee hands it back as it found it.
const X86_DIRECTION_FLAG: [PlatformRegister; 1] = [PlatformRegister {
    register: "df",
    duty: RegisterDuty::CalleeSaved,
    bits: None,
    citation: "System V AMD64 psABI 1.0, section 3.2.1: \"The direction flag DF in the \
               %rFLAGS register must be clear (set to \u{201c}forward\u{201d} direction) on \
               function entry and return\"; System V i386 ABI 1.1, section 2.2.1, the same of \
               %eflags; Microsoft x64 software conventions: \"On function exit and on \
               function entry ... the direction flag in the CPU flags register is expected \
               to be cleared\"",
}];

/// The duties an architecture's ABIs assign on every platform alike.
pub fn architecture_registers(arch: &str) -> &'static [PlatformRegister] {
    match crate::family(arch) {
        Some("x86") => &X86_DIRECTION_FLAG,
        _ => &[],
    }
}

/// The duties a platform's ABI assigns beyond its calling convention's lists.
///
/// The architecture is named as the engine names it; `bits` is the width the
/// program runs at. A platform the table does not know gets nothing, which
/// costs precision -- a reserved register reads as clobbered by every call --
/// and never soundness.
pub fn platform_registers(arch: &str, bits: u32, kernel: Kernel) -> &'static [PlatformRegister] {
    match (crate::family(arch), bits, kernel) {
        (Some("x86"), 64, Kernel::Linux) => &X86_64_SYSV_LINUX,
        // Darwin follows the psABI for x86-64 but keeps its thread pointer in
        // %gs, which no document this table can cite states.
        (Some("x86"), 64, Kernel::Darwin) => &X86_64_SYSV_CONTROL,
        (Some("x86"), 32, Kernel::Linux) => &I386_SYSV_LINUX,
        (Some("arm"), 64, Kernel::Linux) => &AARCH64_ELF,
        (Some("arm"), 64, Kernel::Darwin) => &AARCH64_DARWIN,
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn duty(arch: &str, bits: u32, kernel: Kernel, register: &str) -> Option<RegisterDuty> {
        platform_registers(arch, bits, kernel)
            .iter()
            .find(|row| row.register == register)
            .map(|row| row.duty)
    }

    /// Each platform names the register its thread pointer lives in, and no other platform's.
    #[test]
    fn each_platform_reserves_its_own_thread_pointer() {
        assert_eq!(
            duty("x86-64", 64, Kernel::Linux, "fs_base"),
            Some(RegisterDuty::SystemReserved)
        );
        assert_eq!(
            duty("x86", 32, Kernel::Linux, "gs_base"),
            Some(RegisterDuty::SystemReserved)
        );
        assert_eq!(
            duty("aarch64", 64, Kernel::Linux, "tpidr_el0"),
            Some(RegisterDuty::SystemReserved)
        );
        assert_eq!(
            duty("arm64", 64, Kernel::Darwin, "x18"),
            Some(RegisterDuty::SystemReserved)
        );
        // x18 is an ordinary temporary on Linux, and fs means nothing on i386.
        assert_eq!(duty("aarch64", 64, Kernel::Linux, "x18"), None);
        assert_eq!(duty("x86", 32, Kernel::Linux, "fs_base"), None);
        assert!(platform_registers("x86-64", 64, Kernel::Unknown).is_empty());
        assert!(
            platform_registers("x86-64", 64, Kernel::Linux)
                .iter()
                .all(|row| !row.citation.is_empty())
        );
    }

    /// Bionic's x86 canary sits where glibc's does, under its own citation; its AArch64 one is a global.
    #[test]
    fn bionic_states_its_x86_guard_slot() {
        let slot = |arch: &str, bits: u32| match guard_row(arch, bits, CLibrary::Bionic) {
            Some(GuardRow::ThreadSlot(guard)) => Some(*guard),
            _ => None,
        };
        let wide = slot("x86-64", 64).expect("bionic x86-64 states a slot");
        assert_eq!(
            (wide.register.0, wide.offset, wide.width),
            ("fs_base", 0x28, 8)
        );
        let narrow = slot("x86", 32).expect("bionic i386 states a slot");
        assert_eq!(
            (narrow.register.0, narrow.offset, narrow.width),
            ("gs_base", 0x14, 4)
        );
        assert!(wide.citation.contains("bionic") && narrow.citation.contains("bionic"));
        assert_eq!(slot("aarch64", 64), None);
    }

    /// AArch64 glibc, musl and bionic keep the canary in a global the container must bind.
    #[test]
    fn aarch64_states_a_linked_guard() {
        for library in [CLibrary::Glibc, CLibrary::Musl, CLibrary::Bionic] {
            let Some(GuardRow::LinkedGlobal(guard)) = guard_row("aarch64", 64, library) else {
                panic!("{library:?} states a linked guard");
            };
            assert_eq!((guard.symbol, guard.width), ("__stack_chk_guard", 8));
            assert!(!guard.citation.is_empty());
        }
        assert_eq!(guard_row("aarch64", 64, CLibrary::Unknown), None);
        assert_eq!(guard_row("arm", 32, CLibrary::Glibc), None);
    }

    /// MXCSR's control bits are callee-saved and its status bits are not, so of
    /// its four bytes only the one holding nothing but control bits is claimed.
    #[test]
    fn a_partly_callee_saved_register_claims_only_its_whole_bytes() {
        let mxcsr = platform_registers("x86-64", 64, Kernel::Linux)
            .iter()
            .find(|row| row.register == "mxcsr")
            .expect("mxcsr row");
        assert_eq!(mxcsr.duty, RegisterDuty::CalleeSaved);
        assert_eq!(mxcsr.covered_bytes(4).collect::<Vec<_>>(), [1]);
        let cwd = platform_registers("x86-64", 64, Kernel::Linux)
            .iter()
            .find(|row| row.register == "cwd")
            .expect("cwd row");
        assert_eq!(cwd.covered_bytes(2).collect::<Vec<_>>(), [0, 1]);
    }
}
