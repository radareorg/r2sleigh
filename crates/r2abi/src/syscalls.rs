//! What a platform's kernel calls each system call number, and where a
//! program puts the number.
//!
//! The tables are the kernel's own: `scripts/gen_syscalls.py` expands each
//! architecture's UAPI header with the C preprocessor, the way a program built
//! for it includes it. The register is the one syscall(2)'s "Architecture
//! calling conventions" table names for the instruction that enters the
//! kernel, per architecture and kernel -- not one register per architecture,
//! since two kernels on one architecture disagree (Linux arm64 reads `x8`,
//! Darwin's `x16`).

use std::collections::BTreeMap;

use crate::Kernel;

/// One platform's system calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Syscalls {
    number_register: &'static str,
    names: BTreeMap<u64, String>,
}

impl Syscalls {
    /// The table for a kernel on an architecture, where r2abi keeps one. Android runs the
    /// Linux kernel, so it reads Linux's.
    pub fn for_kernel(kernel: Kernel, arch: &str, bits: u32) -> Option<Self> {
        let family = crate::family(arch)?;
        let (number_register, text) = match (kernel, family, bits) {
            (Kernel::Linux, "x86", 64) => ("rax", LINUX_X86_64),
            (Kernel::Linux, "x86", 32) => ("eax", LINUX_X86_32),
            (Kernel::Linux, "arm", 64) => ("x8", LINUX_ARM_64),
            // Linux arm (EABI) reads r7, but its table is
            // arch/arm/tools/syscall.tbl, which no installed header carries;
            // radare2's is the obsolete OABI numbering. No table, rather than
            // that one.
            _ => return None,
        };
        Some(Self {
            number_register,
            names: parse(text),
        })
    }

    /// The register the number travels in, spelled as the lifter spells it.
    pub const fn number_register(&self) -> &'static str {
        self.number_register
    }

    /// The kernel's name for a number, where it gives one.
    pub fn name(&self, number: u64) -> Option<&str> {
        self.names.get(&number).map(String::as_str)
    }

    /// Whether control comes back from the call. `exit` ends the thread and
    /// `exit_group` the process; no other number in these tables ends the
    /// caller unconditionally.
    pub fn returns(&self, number: u64) -> bool {
        !matches!(self.name(number), Some("exit" | "exit_group"))
    }
}

/// Why an interrupt `vector` on `arch` under `kernel` never comes back, where a document states it
/// (D229). x86 only: `int n`'s vector is the operand Sleigh's `swi` reads.
pub fn interrupt_never_returns(kernel: Kernel, arch: &str, vector: u64) -> Option<&'static str> {
    match (kernel, crate::family(arch)?, vector) {
        (Kernel::Windows, "x86", 0x29) => Some(FASTFAIL),
        _ => None,
    }
}

const FASTFAIL: &str = "Microsoft Learn, \"__fastfail\": \"The __fastfail intrinsic does not return\"; \
                        x86 and x64: `int 0x29`, the failure code in ecx (rcx)";

const LINUX_X86_64: &str = include_str!("../data/syscalls-linux-x86-64.txt");
const LINUX_X86_32: &str = include_str!("../data/syscalls-linux-x86-32.txt");
const LINUX_ARM_64: &str = include_str!("../data/syscalls-linux-arm-64.txt");

/// `number name` per line; `#` starts a comment.
fn parse(text: &str) -> BTreeMap<u64, String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let (number, name) = line.split_once(' ')?;
            Some((number.parse().ok()?, name.trim().to_owned()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_windows_fastfail_is_an_interrupt_that_never_returns() {
        let cited = interrupt_never_returns(Kernel::Windows, "x86-64", 0x29).expect("a row");
        assert!(cited.contains("does not return"));
        assert!(interrupt_never_returns(Kernel::Windows, "x86", 0x29).is_some());
        assert_eq!(interrupt_never_returns(Kernel::Linux, "x86-64", 0x29), None);
        assert_eq!(
            interrupt_never_returns(Kernel::Windows, "x86-64", 0x80),
            None
        );
        assert_eq!(
            interrupt_never_returns(Kernel::Windows, "aarch64", 0x29),
            None
        );
    }

    #[test]
    fn one_number_names_different_calls_on_different_architectures() {
        let x86_64 = Syscalls::for_kernel(Kernel::Linux, "x86-64", 64).expect("a table");
        let arm64 = Syscalls::for_kernel(Kernel::Linux, "aarch64", 64).expect("a table");
        let i386 = Syscalls::for_kernel(Kernel::Linux, "x86", 32).expect("a table");
        assert_eq!(
            (x86_64.name(1), x86_64.name(60)),
            (Some("write"), Some("exit"))
        );
        assert_eq!(
            (arm64.name(64), arm64.name(93)),
            (Some("write"), Some("exit"))
        );
        assert_eq!(
            (i386.name(4), i386.name(252)),
            (Some("write"), Some("exit_group"))
        );
        assert_eq!(
            (
                x86_64.number_register(),
                arm64.number_register(),
                i386.number_register()
            ),
            ("rax", "x8", "eax")
        );
        assert!(!x86_64.returns(231) && !arm64.returns(94) && x86_64.returns(1));
        // A number the kernel does not assign has no name, and is not exit.
        assert_eq!(x86_64.name(100_000), None);
        assert!(x86_64.returns(100_000));
    }

    #[test]
    fn a_platform_without_a_kernel_table_has_none() {
        assert_eq!(Syscalls::for_kernel(Kernel::Darwin, "x86-64", 64), None);
        assert_eq!(Syscalls::for_kernel(Kernel::Unknown, "x86-64", 64), None);
        assert_eq!(Syscalls::for_kernel(Kernel::Linux, "arm", 32), None);
    }
}
