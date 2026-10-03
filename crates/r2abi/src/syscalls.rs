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

use crate::Platform;

/// One platform's system calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Syscalls {
    number_register: &'static str,
    names: BTreeMap<u64, String>,
}

impl Syscalls {
    /// The table for a platform's kernel on an architecture, where r2abi
    /// keeps one. Android runs the Linux kernel, so it reads Linux's.
    pub fn for_platform(platform: Platform, arch: &str, bits: u32) -> Option<Self> {
        let family = crate::family(arch)?;
        let (number_register, text) = match (platform, family, bits) {
            (Platform::Linux | Platform::Android, "x86", 64) => ("rax", LINUX_X86_64),
            (Platform::Linux | Platform::Android, "x86", 32) => ("eax", LINUX_X86_32),
            (Platform::Linux | Platform::Android, "arm", 64) => ("x8", LINUX_ARM_64),
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
    fn one_number_names_different_calls_on_different_architectures() {
        let x86_64 = Syscalls::for_platform(Platform::Linux, "x86-64", 64).expect("a table");
        let arm64 = Syscalls::for_platform(Platform::Linux, "aarch64", 64).expect("a table");
        let i386 = Syscalls::for_platform(Platform::Android, "x86", 32).expect("a table");
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
        assert_eq!(Syscalls::for_platform(Platform::Darwin, "x86-64", 64), None);
        assert_eq!(
            Syscalls::for_platform(Platform::Unknown, "x86-64", 64),
            None
        );
        assert_eq!(Syscalls::for_platform(Platform::Linux, "arm", 32), None);
    }
}
