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

/// What a platform's ABI says of its default calling convention that no
/// compiler specification in the Sleigh bundle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallingConvention {
    /// The convention's name as radare2 spells it, which is what `afi`
    /// prints and what radare2's output is diffed against.
    pub name: &'static str,
    /// How many bytes past the stack pointer a function may use without
    /// moving it.
    pub red_zone_bytes: u32,
    /// Whether every variadic argument travels on the stack from the first
    /// slot, whatever registers the fixed arguments leave free.
    pub variadic_tail_on_stack: bool,
    /// The register a call passes a variadic callee's count of vector
    /// arguments in, which every call may therefore read.
    pub variadic_count_register: Option<&'static str>,
    /// The documents that state these.
    pub citation: &'static str,
}

const SYSTEM_V_AMD64: CallingConvention = CallingConvention {
    name: "amd64",
    red_zone_bytes: 128,
    variadic_tail_on_stack: false,
    variadic_count_register: Some("al"),
    citation: "System V AMD64 psABI 1.0, section 3.2.2: \"The 128-byte area beyond the \
               location pointed to by %rsp is considered to be reserved and shall not be \
               modified by signal or interrupt handlers\"; section 3.5.7: \"%al is used as \
               hidden argument to specify the number of vector registers used\"",
};

const MICROSOFT_X64: CallingConvention = CallingConvention {
    name: "ms",
    red_zone_bytes: 0,
    variadic_tail_on_stack: false,
    variadic_count_register: None,
    citation: "Microsoft x64 software conventions, \"Stack usage\": the convention \
               defines no red zone",
};

const I386_CDECL: CallingConvention = CallingConvention {
    name: "cdecl",
    red_zone_bytes: 0,
    variadic_tail_on_stack: false,
    variadic_count_register: None,
    citation: "System V i386 ABI 1.1, \"Function Calling Sequence\": the convention \
               defines no red zone",
};

const AAPCS64: CallingConvention = CallingConvention {
    name: "arm64",
    red_zone_bytes: 0,
    variadic_tail_on_stack: false,
    variadic_count_register: None,
    citation: "AAPCS64, \"Universal stack constraints\": \"A process may only access \
               (for reading or writing) the closed interval of the entire stack delimited \
               by [SP, stack-base - 1]\"",
};

const AAPCS64_DARWIN: CallingConvention = CallingConvention {
    variadic_tail_on_stack: true,
    variadic_count_register: None,
    citation: "Apple, \"Writing ARM64 code for Apple platforms\": \"the caller places \
               the arguments for the variadic portion of a function on the stack\"",
    ..AAPCS64
};

const AAPCS32: CallingConvention = CallingConvention {
    name: "arm32",
    red_zone_bytes: 0,
    variadic_tail_on_stack: false,
    variadic_count_register: None,
    citation: "AAPCS32, \"Universal stack constraints\": \"A process may only access \
               (for reading or writing) the closed interval of the entire stack delimited \
               by [SP, stack-base - 1]\"",
};

const RISCV_LP64: CallingConvention = CallingConvention {
    name: "rvg",
    red_zone_bytes: 0,
    variadic_tail_on_stack: false,
    variadic_count_register: None,
    citation: "RISC-V ELF psABI, \"Integer Calling Convention\": the convention defines \
               no red zone",
};

/// The default calling convention a program for this architecture and
/// platform runs under.
pub fn calling_convention(
    arch: &str,
    bits: u32,
    platform: Platform,
) -> Option<&'static CallingConvention> {
    match (crate::family(arch), bits, platform) {
        (Some("x86"), 64, Platform::Windows) => Some(&MICROSOFT_X64),
        (Some("x86"), 64, _) => Some(&SYSTEM_V_AMD64),
        (Some("x86"), 32, _) => Some(&I386_CDECL),
        (Some("arm"), 64, Platform::Darwin) => Some(&AAPCS64_DARWIN),
        (Some("arm"), 64, _) => Some(&AAPCS64),
        (Some("arm"), 32, _) => Some(&AAPCS32),
        (Some("riscv"), 64, _) => Some(&RISCV_LP64),
        _ => None,
    }
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

    /// What no compiler specification states is the platform's: the red
    /// zone is System V's alone among x86-64 ABIs, and only Apple's arm64 ABI
    /// passes a variadic tail on the stack from its first argument.
    #[test]
    fn each_platform_states_its_own_convention() {
        let x64 = |platform| calling_convention("x86-64", 64, platform).expect("a convention");
        assert_eq!(x64(Platform::Linux).name, "amd64");
        assert_eq!(x64(Platform::Linux).red_zone_bytes, 128);
        assert_eq!(x64(Platform::Darwin).red_zone_bytes, 128);
        assert_eq!(x64(Platform::Windows).name, "ms");
        assert_eq!(x64(Platform::Windows).red_zone_bytes, 0);
        let arm64 = |platform| calling_convention("aarch64", 64, platform).expect("a convention");
        assert!(arm64(Platform::Darwin).variadic_tail_on_stack);
        assert!(!arm64(Platform::Linux).variadic_tail_on_stack);
        assert_eq!(arm64(Platform::Darwin).name, "arm64");
        assert!(calling_convention("mips", 32, Platform::Linux).is_none());
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
