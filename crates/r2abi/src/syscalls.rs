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
    /// The numbers a kernel document says never return, each with its citation (D505).
    never: &'static [(u64, &'static str)],
}

impl Syscalls {
    /// The table for a kernel on an architecture, where r2abi keeps one. Android runs the
    /// Linux kernel, so it reads Linux's.
    pub fn for_kernel(kernel: Kernel, arch: &str, bits: u32) -> Option<Self> {
        let family = crate::family(arch)?;
        let (number_register, text, never) = match (kernel, family, bits) {
            (Kernel::Linux, "x86", 64) => ("rax", LINUX_X86_64, LINUX_X86_64_EXITS),
            (Kernel::Linux, "x86", 32) => ("eax", LINUX_X86_32, &[][..]),
            (Kernel::Linux, "arm", 64) => ("x8", LINUX_ARM_64, LINUX_GENERIC_EXITS),
            // Linux arm (EABI) reads r7, but its table is
            // arch/arm/tools/syscall.tbl, which no installed header carries;
            // radare2's is the obsolete OABI numbering. No table, rather than
            // that one.
            _ => return None,
        };
        Some(Self {
            number_register,
            names: parse(text),
            never,
        })
    }

    /// The register the number travels in, spelled as the lifter spells it.
    pub const fn number_register(&self) -> &'static str {
        self.number_register
    }

    /// Why system call `number` never comes back, where the kernel's source states it (D505).
    pub fn never_returns(&self, number: u64) -> Option<&'static str> {
        let row = self.never.iter().find(|(held, _)| *held == number);
        row.map(|(_, cited)| *cited)
    }

    /// The kernel's name for a number, where it gives one.
    pub fn name(&self, number: u64) -> Option<&str> {
        self.names.get(&number).map(String::as_str)
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

/// Why system call `number` on `arch` under `kernel` never comes back, where the kernel's source
/// states it (D505); the number is the table's, read by no name.
pub fn syscall_never_returns(
    kernel: Kernel,
    arch: &str,
    bits: u32,
    number: u64,
) -> Option<&'static str> {
    Syscalls::for_kernel(kernel, arch, bits)?.never_returns(number)
}

/// Linux v6.8 `kernel/exit.c`: `void __noreturn do_exit(long code)` (:811); `SYSCALL_DEFINE1(exit, ..)`
/// calls `do_exit` (:985-988); `exit_group` calls `void __noreturn do_group_exit(..)`, `/* NOTREACHED */` (:995, :1029-1033).
const EXIT: &str = "Linux v6.8 kernel/exit.c:985-988 sys_exit calls do_exit, `void __noreturn do_exit(long code)` (:811)";
const EXIT_GROUP: &str = "Linux v6.8 kernel/exit.c:1029-1033 sys_exit_group calls `void __noreturn do_group_exit` (:995-996), `/* NOTREACHED */`";
/// `arch/x86/entry/syscalls/syscall_64.tbl:71` `60 common exit sys_exit`, `:242` `231 common exit_group sys_exit_group`.
const LINUX_X86_64_EXITS: &[(u64, &str)] = &[(60, EXIT), (231, EXIT_GROUP)];
/// `include/uapi/asm-generic/unistd.h:258` `#define __NR_exit 93`, `:260` `#define __NR_exit_group 94`.
const LINUX_GENERIC_EXITS: &[(u64, &str)] = &[(93, EXIT), (94, EXIT_GROUP)];

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
    fn only_the_exit_numbers_the_kernel_states_never_return() {
        let exits = |arch, bits, numbers: &[u64]| {
            (numbers.iter())
                .map(|number| syscall_never_returns(Kernel::Linux, arch, bits, *number).is_some())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            exits("x86-64", 64, &[60, 231, 39, 93]),
            [true, true, false, false]
        );
        assert_eq!(
            exits("aarch64", 64, &[93, 94, 60, 231]),
            [true, true, false, false]
        );
        // The i386 table states no exit row yet; Darwin no table.
        assert_eq!(exits("x86", 32, &[1, 252]), [false, false]);
        assert_eq!(
            syscall_never_returns(Kernel::Darwin, "x86-64", 64, 60),
            None
        );
        let cited = syscall_never_returns(Kernel::Linux, "x86-64", 64, 231).expect("a row");
        assert!(cited.contains("kernel/exit.c") && cited.contains("__noreturn"));
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
        // A number the kernel does not assign has no name.
        assert_eq!(x86_64.name(100_000), None);
    }

    #[test]
    fn a_platform_without_a_kernel_table_has_none() {
        assert_eq!(Syscalls::for_kernel(Kernel::Darwin, "x86-64", 64), None);
        assert_eq!(Syscalls::for_kernel(Kernel::Unknown, "x86-64", 64), None);
        assert_eq!(Syscalls::for_kernel(Kernel::Linux, "arm", 32), None);
    }
}
