//! Calling conventions, read natively.
//!
//! radare2 answers `r_anal_cc_arg` and its eleven siblings out of `sdb` files
//! that ship as text beside its analysis library. The data is good and hard
//! won; the lookup code is what had no business crossing an FFI boundary. The
//! files are vendored here and parsed directly, so the engine can say where a
//! function's arguments arrive with no radare2 present.
//!
//! The text is `sdb`'s dump format: one `key=value` per line, `#` comments, and
//! a `<name>=cc` line declaring that `<name>` is a convention. Every fact about
//! a convention is spelled `cc.<name>.<what>`.

pub mod compiler_spec;
pub mod prototypes;

pub use compiler_spec::CompilerSpec;
pub use prototypes::{
    FrameBase, FrameRole, Local, Parameter, Platform, Prototype, Prototypes, Spelled,
    dwarf_frame_register,
};

use std::collections::BTreeMap;

/// One location, and the register names that spell it.
///
/// arm64's data writes a floating-point slot as `{d0,s0,v0,q0}`: one place,
/// named by whichever width the instruction uses. A caller that wants a single
/// spelling takes `name`; one matching a register the code actually touched
/// tests `spells`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Slot {
    names: Vec<String>,
}

impl Slot {
    /// Parse one value: a bare register, or a `{a,b,c}` alias group.
    fn parse(value: &str) -> Self {
        let inner = value
            .strip_prefix('{')
            .and_then(|rest| rest.strip_suffix('}'))
            .unwrap_or(value);
        Self { names: list(inner) }
    }

    /// The first spelling, which is the widest the data names.
    pub fn name(&self) -> &str {
        self.names.first().map_or("", String::as_str)
    }

    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Whether this location is what `register` names, in any width.
    pub fn spells(&self, register: &str) -> bool {
        self.names
            .iter()
            .any(|name| name.eq_ignore_ascii_case(register))
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

/// Where arguments go once the register slots run out.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ArgumentTail {
    /// The convention states none, so it has no tail.
    #[default]
    None,
    /// Pushed in declaration order.
    Stack,
    /// Pushed in reverse, so the last argument is nearest the return address.
    StackReversed,
}

/// The conventions one architecture and width declare.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Conventions {
    default: Option<String>,
    by_name: BTreeMap<String, Convention>,
}

/// Where one convention puts arguments, results and saved registers.
///
/// Registers are spelled as radare2 spells them, which is lower case; a
/// consumer matching against Sleigh's register names compares without case.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Convention {
    pub name: String,
    /// Integer argument registers, in order. An argument past the end of this
    /// list goes where `tail` says.
    pub args: Vec<Slot>,
    /// Floating-point argument registers, in order, where the convention
    /// passes them separately.
    pub float_args: Vec<Slot>,
    /// Where arguments past the register slots are passed.
    pub tail: ArgumentTail,
    /// Result registers as the data spells them, `ret0` first. How many of
    /// them the convention actually uses is `result_count`.
    pub returns: Vec<Slot>,
    /// `retn`: how many result registers this convention uses. Absent means
    /// one, which is every convention but D's.
    pub declared_result_count: Option<u32>,
    /// Floating-point result register.
    pub float_return: Option<Slot>,
    /// Where the object pointer arrives, for conventions that name one.
    pub self_register: Option<Slot>,
    /// Where an error is returned, for conventions that name one.
    pub error_register: Option<Slot>,
    /// Registers the callee may destroy.
    pub clobbered: Vec<String>,
    /// Registers the callee must restore.
    pub preserved: Vec<String>,
    /// Who removes the arguments from the stack.
    pub pop: Option<Pop>,
    /// Which way the stack grows as arguments are placed.
    pub stack_allocation: Option<StackAllocation>,
    /// Bytes the caller reserves above the return address for the callee to
    /// spill its register arguments into.
    pub shadow_bytes: u64,
    /// Bytes below the stack pointer a leaf function may use without moving it.
    pub redzone_bytes: u64,
    /// Arguments are placed in reverse order.
    pub reversed_arguments: bool,
    /// How a result too large for a register comes back, verbatim from the
    /// data: radare2 spells the only one it carries `stack:0:8:8`.
    pub return_mechanism: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pop {
    Caller,
    Callee,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackAllocation {
    /// Arguments are placed at descending addresses.
    Lower,
    /// Arguments are placed at ascending addresses.
    Higher,
}

/// The vendored files, keyed as radare2 names them.
const EMBEDDED: &[(&str, u32, &str)] = &[
    ("x86", 64, include_str!("../data/cc-x86-64.sdb.txt")),
    ("x86", 32, include_str!("../data/cc-x86-32.sdb.txt")),
    ("arm", 64, include_str!("../data/cc-arm-64.sdb.txt")),
    ("arm", 32, include_str!("../data/cc-arm-32.sdb.txt")),
    ("riscv", 64, include_str!("../data/cc-riscv-64.sdb.txt")),
];

impl Conventions {
    /// The conventions declared for an architecture at a width.
    ///
    /// The architecture is named as the engine names it, so `x86-64`, `amd64`
    /// and `x86` all reach the same file once the width is known.
    pub fn for_arch(arch: &str, bits: u32) -> Option<Self> {
        let family = family(arch)?;
        EMBEDDED
            .iter()
            .find(|(name, width, _)| *name == family && *width == bits)
            .map(|(_, _, text)| Self::parse(text))
    }

    /// Parse one `sdb` dump.
    pub fn parse(text: &str) -> Self {
        let mut conventions = Self::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            conventions.take(key.trim(), value.trim());
        }
        conventions
    }

    /// The convention a function uses when nothing else says.
    pub fn default_name(&self) -> Option<&str> {
        self.default.as_deref()
    }

    /// The convention nothing else names, already looked up.
    pub fn default_convention(&self) -> Option<&Convention> {
        self.get(self.default_name()?)
    }

    pub fn get(&self, name: &str) -> Option<&Convention> {
        self.by_name.get(name)
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.by_name.keys().map(String::as_str)
    }

    fn take(&mut self, key: &str, value: &str) {
        if key == "default.cc" {
            self.default = Some(value.to_owned());
            return;
        }
        // `<name>=cc` declares a convention and carries nothing else.
        let Some(rest) = key.strip_prefix("cc.") else {
            if value == "cc" {
                self.entry(key);
            }
            return;
        };
        let Some((name, what)) = rest.split_once('.') else {
            return;
        };
        self.entry(name).take(what, value);
    }

    fn entry(&mut self, name: &str) -> &mut Convention {
        self.by_name
            .entry(name.to_owned())
            .or_insert_with(|| Convention {
                name: name.to_owned(),
                ..Convention::default()
            })
    }
}

impl Convention {
    /// Where the argument at `index` arrives, or `None` when it is on the
    /// stack or the convention does not reach that far.
    pub fn argument(&self, index: usize) -> Option<&Slot> {
        self.args.get(index)
    }

    /// Where the floating-point argument at `index` arrives.
    pub fn float_argument(&self, index: usize) -> Option<&Slot> {
        self.float_args.get(index)
    }

    /// The result slots this convention uses, which is one unless the data
    /// declares more.
    pub fn results(&self) -> &[Slot] {
        let count = self.declared_result_count.unwrap_or(1) as usize;
        &self.returns[..count.min(self.returns.len())]
    }

    /// The result register, where there is one.
    pub fn return_register(&self) -> Option<&Slot> {
        self.results().first()
    }

    fn take(&mut self, what: &str, value: &str) {
        match what {
            "argn" => {
                self.tail = match value {
                    "stack" => ArgumentTail::Stack,
                    "stack_rev" => ArgumentTail::StackReversed,
                    _ => ArgumentTail::None,
                }
            }
            "fpret0" => self.float_return = Some(Slot::parse(value)),
            "self" => self.self_register = Some(Slot::parse(value)),
            "error" => self.error_register = Some(Slot::parse(value)),
            "clobber" => self.clobbered = list(value),
            "preserve" => self.preserved = list(value),
            "pop" => {
                self.pop = match value {
                    "caller" => Some(Pop::Caller),
                    "callee" => Some(Pop::Callee),
                    _ => None,
                }
            }
            "stackalloc" => {
                self.stack_allocation = match value {
                    "lower" => Some(StackAllocation::Lower),
                    "higher" => Some(StackAllocation::Higher),
                    _ => None,
                }
            }
            "shadow" => self.shadow_bytes = value.parse().unwrap_or(0),
            "redzone" => self.redzone_bytes = value.parse().unwrap_or(0),
            "retn" => self.declared_result_count = value.parse().ok(),
            "revarg" => self.reversed_arguments = value != "0",
            "retmech" => self.return_mechanism = Some(value.to_owned()),
            _ => self.take_indexed(what, value),
        }
    }

    /// The keys that carry a position: `arg3`, `fparg1`, `ret0`.
    fn take_indexed(&mut self, what: &str, value: &str) {
        let Some((prefix, index)) = split_index(what) else {
            return;
        };
        let slot: &mut Vec<Slot> = match prefix {
            "arg" => &mut self.args,
            "fparg" => &mut self.float_args,
            "ret" => &mut self.returns,
            _ => return,
        };
        if slot.len() <= index {
            slot.resize(index + 1, Slot::default());
        }
        slot[index] = Slot::parse(value);
    }
}

/// Split `arg12` into `("arg", 12)`.
fn split_index(what: &str) -> Option<(&str, usize)> {
    let digits = what.len() - what.trim_end_matches(|c: char| c.is_ascii_digit()).len();
    (digits > 0).then(|| {
        let split = what.len() - digits;
        Some((&what[..split], what[split..].parse().ok()?))
    })?
}

fn list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_v_convention_reads_whole() {
        let conventions = Conventions::for_arch("x86-64", 64).expect("x86-64 conventions");
        assert_eq!(conventions.default_name(), Some("amd64"));
        let amd64 = conventions.default_convention().expect("amd64");
        let args: Vec<&str> = amd64.args.iter().map(Slot::name).collect();
        assert_eq!(args, ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]);
        assert_eq!(amd64.float_args.len(), 8);
        assert_eq!(amd64.return_register().map(Slot::name), Some("rax"));
        assert_eq!(amd64.tail, ArgumentTail::Stack);
        assert_eq!(amd64.pop, Some(Pop::Caller));
        assert_eq!(amd64.stack_allocation, Some(StackAllocation::Lower));
        assert_eq!(amd64.redzone_bytes, 128);
        assert_eq!(amd64.return_mechanism.as_deref(), Some("stack:0:8:8"));
        assert!(amd64.preserved.iter().any(|reg| reg == "rbx"));
    }

    #[test]
    fn the_windows_convention_carries_its_shadow_space() {
        let conventions = Conventions::for_arch("amd64", 64).expect("x86-64 conventions");
        let ms = conventions.get("ms").expect("ms");
        let args: Vec<&str> = ms.args.iter().map(Slot::name).collect();
        assert_eq!(args, ["rcx", "rdx", "r8", "r9"]);
        assert_eq!(ms.shadow_bytes, 32);
        // win64 passes one sequence with per-type homes, so there is no
        // separate float argument sequence to read.
        assert!(ms.float_args.is_empty());
    }

    #[test]
    fn aarch64_arguments_are_the_first_eight_registers() {
        let conventions = Conventions::for_arch("aarch64", 64).expect("arm-64 conventions");
        let default = conventions.default_convention().expect("default");
        let args: Vec<&str> = default.args.iter().map(Slot::name).collect();
        assert_eq!(args, ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]);
        assert_eq!(default.return_register().map(Slot::name), Some("x0"));
    }

    #[test]
    fn a_float_slot_keeps_every_width_that_spells_it() {
        let conventions = Conventions::for_arch("aarch64", 64).expect("arm-64 conventions");
        let default = conventions.default_convention().expect("default");
        let first = default.float_argument(0).expect("fparg0");
        assert!(first.spells("d0"), "{:?}", first.names());
        assert!(first.spells("S0"), "{:?}", first.names());
        assert!(!first.spells("d1"));
    }

    #[test]
    fn only_a_convention_that_declares_two_results_has_two() {
        let x86 = Conventions::for_arch("x86-64", 64).expect("x86-64 conventions");
        let dlang = x86.get("dlang").expect("dlang");
        assert_eq!(dlang.declared_result_count, Some(2));
        assert_eq!(dlang.results().len(), 2);
        // amd64 parses no `retn`, so one result register is all it claims.
        assert_eq!(x86.get("amd64").expect("amd64").results().len(), 1);
    }

    #[test]
    fn a_reversed_stack_tail_is_still_a_stack_tail() {
        let x86 = Conventions::for_arch("x86", 32).expect("x86-32 conventions");
        let pascal = x86.get("pascal").expect("pascal");
        assert_eq!(pascal.tail, ArgumentTail::StackReversed);
        assert_eq!(x86.get("cdecl").expect("cdecl").tail, ArgumentTail::Stack);
    }

    #[test]
    fn a_convention_naming_a_self_register_keeps_it() {
        let conventions = Conventions::for_arch("aarch64", 64).expect("arm-64 conventions");
        let swift = conventions.get("swift").expect("swift");
        assert_eq!(swift.self_register.as_ref().map(Slot::name), Some("x20"));
        assert_eq!(swift.error_register.as_ref().map(Slot::name), Some("x21"));
    }

    #[test]
    fn an_unknown_architecture_has_no_conventions() {
        assert!(Conventions::for_arch("sparc", 32).is_none());
        assert!(Conventions::for_arch("x86", 16).is_none());
    }

    #[test]
    fn comments_and_declarations_are_not_facts() {
        let conventions = Conventions::parse("# a comment\nfoo=cc\ncc.foo.arg0=r0\n");
        let foo = conventions.get("foo").expect("foo");
        assert_eq!(foo.args.len(), 1);
        assert_eq!(foo.args[0].name(), "r0");
        assert_eq!(conventions.names().count(), 1);
    }
}
