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

use crate::Platform;

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

/// The duties a platform's ABI assigns beyond its calling convention's lists.
///
/// The architecture is named as the engine names it; `bits` is the width the
/// program runs at. A platform the table does not know gets nothing, which
/// costs precision -- a reserved register reads as clobbered by every call --
/// and never soundness.
pub fn platform_registers(
    arch: &str,
    bits: u32,
    platform: Platform,
) -> &'static [PlatformRegister] {
    match (crate::family(arch), bits, platform) {
        (Some("x86"), 64, Platform::Linux) => &X86_64_SYSV_LINUX,
        // Darwin follows the psABI for x86-64 but keeps its thread pointer in
        // %gs, which no document this table can cite states.
        (Some("x86"), 64, Platform::Darwin) => &X86_64_SYSV_CONTROL,
        (Some("x86"), 32, Platform::Linux) => &I386_SYSV_LINUX,
        (Some("arm"), 64, Platform::Linux) => &AARCH64_ELF,
        (Some("arm"), 64, Platform::Darwin) => &AARCH64_DARWIN,
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn duty(arch: &str, bits: u32, platform: Platform, register: &str) -> Option<RegisterDuty> {
        platform_registers(arch, bits, platform)
            .iter()
            .find(|row| row.register == register)
            .map(|row| row.duty)
    }

    /// Each platform names the register its thread pointer lives in, and no other platform's.
    #[test]
    fn each_platform_reserves_its_own_thread_pointer() {
        assert_eq!(
            duty("x86-64", 64, Platform::Linux, "fs_base"),
            Some(RegisterDuty::SystemReserved)
        );
        assert_eq!(
            duty("x86", 32, Platform::Linux, "gs_base"),
            Some(RegisterDuty::SystemReserved)
        );
        assert_eq!(
            duty("aarch64", 64, Platform::Linux, "tpidr_el0"),
            Some(RegisterDuty::SystemReserved)
        );
        assert_eq!(
            duty("arm64", 64, Platform::Darwin, "x18"),
            Some(RegisterDuty::SystemReserved)
        );
        // x18 is an ordinary temporary on Linux, and fs means nothing on i386.
        assert_eq!(duty("aarch64", 64, Platform::Linux, "x18"), None);
        assert_eq!(duty("x86", 32, Platform::Linux, "fs_base"), None);
        assert!(platform_registers("x86-64", 64, Platform::Unknown).is_empty());
        assert!(
            platform_registers("x86-64", 64, Platform::Linux)
                .iter()
                .all(|row| !row.citation.is_empty())
        );
    }

    /// MXCSR's control bits are callee-saved and its status bits are not, so of
    /// its four bytes only the one holding nothing but control bits is claimed.
    #[test]
    fn a_partly_callee_saved_register_claims_only_its_whole_bytes() {
        let mxcsr = platform_registers("x86-64", 64, Platform::Linux)
            .iter()
            .find(|row| row.register == "mxcsr")
            .expect("mxcsr row");
        assert_eq!(mxcsr.duty, RegisterDuty::CalleeSaved);
        assert_eq!(mxcsr.covered_bytes(4).collect::<Vec<_>>(), [1]);
        let cwd = platform_registers("x86-64", 64, Platform::Linux)
            .iter()
            .find(|row| row.register == "cwd")
            .expect("cwd row");
        assert_eq!(cwd.covered_bytes(2).collect::<Vec<_>>(), [0, 1]);
    }
}
