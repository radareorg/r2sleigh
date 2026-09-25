//! r2sleigh-lift - Sleigh to r2il translator
//!
//! This crate provides functionality to work with Ghidra Sleigh specifications
//! and translate P-code into r2il intermediate language.
//!
//! # Architecture
//!
//! The lifting process uses `libsla` (Ghidra's native Sleigh library) with
//! pre-compiled `.sla` files from `sleigh-config` for disassembly and P-code
//! generation.
//!
//! # Example
//!
//! ```rust,ignore
//! use r2sleigh_lift::{Lifter, sleigh::build_arch_spec};
//!
//! // Build an architecture spec from pre-compiled SLA data
//! let spec = build_arch_spec(
//!     sleigh_config::processor_x86::SLA_X86_64,
//!     sleigh_config::processor_x86::PSPEC_X86_64,
//!     "x86-64"
//! )?;
//! r2il::serialize::save(&spec, "x86-64.r2il")?;
//! ```

pub mod context;
pub mod disasm;
pub mod esil;
mod internal_control;
pub mod sleigh;
pub mod translate;

use thiserror::Error;

pub use context::LiftContext;
pub use disasm::syntax::{NumberSpan, Syntax};
pub use disasm::{
    Continuation, Decoded, Disassembler, GENUINE_LIFT_PROVENANCE_SCHEMA_VERSION,
    GenuineInstructionSpan, GenuineLiftAuthority, GenuineLiftedBlock, GenuineLiftedFunction,
    GenuineLiftedFunctionAuthority, TrustedLiftedFunction, TrustedSleighProfile,
};
pub use disasm::{
    EmbeddedMachine, embedded_arch_and_disassembler, embedded_machine, embedded_thumb_machine,
};
pub use esil::{OpEsil, block_to_esil, format_op, op_esil, op_to_esil};
use r2il::ArchSpec;
use r2il::Endianness;
pub use sleigh::{SleighInfo, build_arch_spec, extract_arch_spec, get_sleigh_info};

/// Errors that can occur during lifting.
#[derive(Debug, Error)]
pub enum LiftError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Unsupported feature: {0}")]
    Unsupported(String),
}

/// Result type for lifting operations.
pub type Result<T> = std::result::Result<T, LiftError>;

/// Main lifter for converting Sleigh specs to r2il.
pub struct Lifter {
    /// The architecture context being built
    ctx: LiftContext,
}

impl Lifter {
    /// Create a new lifter for the given architecture name.
    pub fn new(arch_name: impl Into<String>) -> Self {
        Self {
            ctx: LiftContext::new(arch_name),
        }
    }

    /// Create a lifter from an existing ArchSpec.
    ///
    /// This is the preferred way to create a Lifter when you have
    /// pre-compiled SLA data available via `sleigh-config`.
    ///
    /// # Arguments
    ///
    /// * `spec` - An `ArchSpec` built from `build_arch_spec()`
    ///
    /// # Returns
    ///
    /// A `Lifter` with the architecture context.
    pub fn from_spec(spec: ArchSpec) -> Self {
        let ctx = LiftContext::from_arch_spec(spec);
        Self { ctx }
    }

    /// Create a lifter from pre-compiled SLA data.
    ///
    /// # Arguments
    ///
    /// * `sla_data` - Compiled SLA specification bytes
    /// * `pspec_data` - Processor specification string
    /// * `arch_name` - Name for the architecture
    ///
    /// # Returns
    ///
    /// A `Lifter` with the parsed architecture context, or an error if loading fails.
    pub fn from_sla(sla_data: &[u8], pspec_data: &str, arch_name: &str) -> Result<Self> {
        let spec = sleigh::build_arch_spec(sla_data, pspec_data, arch_name)?;
        Ok(Self::from_spec(spec))
    }

    /// Get mutable access to the lift context.
    pub fn context_mut(&mut self) -> &mut LiftContext {
        &mut self.ctx
    }

    /// Get read access to the lift context.
    pub fn context(&self) -> &LiftContext {
        &self.ctx
    }

    /// Set instruction endianness.
    pub fn set_instruction_endianness(&mut self, endianness: Endianness) -> &mut Self {
        self.ctx.set_instruction_endianness(endianness);
        self
    }

    /// Set memory endianness.
    pub fn set_memory_endianness(&mut self, endianness: Endianness) -> &mut Self {
        self.ctx.set_memory_endianness(endianness);
        self
    }

    /// Set the address size.
    pub fn set_addr_size(&mut self, size: u32) -> &mut Self {
        self.ctx.set_addr_size(size);
        self
    }

    /// Add a register definition.
    pub fn add_register(&mut self, name: &str, offset: u64, size: u32) -> &mut Self {
        self.ctx.add_register(name, offset, size);
        self
    }

    /// Compile the specification and return the architecture spec.
    pub fn compile(self) -> Result<ArchSpec> {
        Ok(self.ctx.finish())
    }
}

/// Create a basic x86-64 architecture specification for testing.
///
/// This provides a minimal x86-64 spec with common registers.
pub fn create_x86_64_spec() -> ArchSpec {
    let mut ctx = LiftContext::new("x86-64");
    ctx.set_instruction_endianness(Endianness::Little);
    ctx.set_memory_endianness(Endianness::Little);
    ctx.set_addr_size(8);

    // Add standard address spaces
    ctx.add_space("ram", 8, true);
    ctx.add_space("register", 4, false);
    ctx.add_space("unique", 4, false);

    // General purpose registers (64-bit)
    ctx.add_register("RAX", 0x00, 8);
    ctx.add_register("RCX", 0x08, 8);
    ctx.add_register("RDX", 0x10, 8);
    ctx.add_register("RBX", 0x18, 8);
    ctx.add_register("RSP", 0x20, 8);
    ctx.add_register("RBP", 0x28, 8);
    ctx.add_register("RSI", 0x30, 8);
    ctx.add_register("RDI", 0x38, 8);
    ctx.add_register("R8", 0x80, 8);
    ctx.add_register("R9", 0x88, 8);
    ctx.add_register("R10", 0x90, 8);
    ctx.add_register("R11", 0x98, 8);
    ctx.add_register("R12", 0xa0, 8);
    ctx.add_register("R13", 0xa8, 8);
    ctx.add_register("R14", 0xb0, 8);
    ctx.add_register("R15", 0xb8, 8);

    // 32-bit sub-registers
    ctx.add_sub_register("EAX", 0x00, 4, "RAX");
    ctx.add_sub_register("ECX", 0x08, 4, "RCX");
    ctx.add_sub_register("EDX", 0x10, 4, "RDX");
    ctx.add_sub_register("EBX", 0x18, 4, "RBX");
    ctx.add_sub_register("ESP", 0x20, 4, "RSP");
    ctx.add_sub_register("EBP", 0x28, 4, "RBP");
    ctx.add_sub_register("ESI", 0x30, 4, "RSI");
    ctx.add_sub_register("EDI", 0x38, 4, "RDI");

    // Instruction pointer
    ctx.add_register("RIP", 0x280, 8);
    ctx.add_sub_register("EIP", 0x280, 4, "RIP");

    // Flags register
    ctx.add_register("rflags", 0x288, 8);
    ctx.add_sub_register("eflags", 0x288, 4, "rflags");

    // Individual flags
    ctx.add_register("CF", 0x200, 1);
    ctx.add_register("PF", 0x202, 1);
    ctx.add_register("AF", 0x204, 1);
    ctx.add_register("ZF", 0x206, 1);
    ctx.add_register("SF", 0x207, 1);
    ctx.add_register("OF", 0x20b, 1);

    ctx.finish()
}

/// Create a basic ARM architecture specification for testing.
pub fn create_arm_spec() -> ArchSpec {
    let mut ctx = LiftContext::new("ARM");
    ctx.set_instruction_endianness(Endianness::Little);
    ctx.set_memory_endianness(Endianness::Little);
    ctx.set_addr_size(4);

    // Add standard address spaces
    ctx.add_space("ram", 4, true);
    ctx.add_space("register", 4, false);
    ctx.add_space("unique", 4, false);

    // General purpose registers
    for i in 0..=12 {
        ctx.add_register(&format!("r{}", i), (i * 4) as u64, 4);
    }

    // Special registers
    ctx.add_register("sp", 0x34, 4); // r13
    ctx.add_register("lr", 0x38, 4); // r14
    ctx.add_register("pc", 0x3c, 4); // r15

    // Status register
    ctx.add_register("cpsr", 0x40, 4);

    // Condition flags
    ctx.add_register("NG", 0x44, 1); // Negative
    ctx.add_register("ZR", 0x45, 1); // Zero
    ctx.add_register("CY", 0x46, 1); // Carry
    ctx.add_register("OV", 0x47, 1); // Overflow

    ctx.finish()
}

fn create_riscv_spec(name: &str, addr_size: u32) -> ArchSpec {
    let mut ctx = LiftContext::new(name);
    ctx.set_instruction_endianness(Endianness::Little);
    ctx.set_memory_endianness(Endianness::Little);
    ctx.set_addr_size(addr_size);

    // Add standard address spaces
    ctx.add_space("ram", addr_size, true);
    ctx.add_space("register", 4, false);
    ctx.add_space("unique", 4, false);

    let reg_size = addr_size;
    let base = 0x2000u64;
    let stride = u64::from(addr_size);
    let integer_regs = [
        "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
        "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
        "t5", "t6",
    ];
    for (idx, reg) in integer_regs.iter().enumerate() {
        ctx.add_register(reg, base + (idx as u64 * stride), reg_size);
    }

    // Common aliases used by downstream analysis.
    ctx.add_sub_register("fp", base + 8 * stride, reg_size, "s0");
    ctx.add_register("pc", 0x1000, reg_size);

    ctx.finish()
}

/// Create a basic RISC-V RV64 architecture specification for testing.
pub fn create_riscv64_spec() -> ArchSpec {
    create_riscv_spec("riscv64", 8)
}

/// Create a basic RISC-V RV32 architecture specification for testing.
pub fn create_riscv32_spec() -> ArchSpec {
    create_riscv_spec("riscv32", 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifter_creation() {
        let lifter = Lifter::new("test-arch");
        assert_eq!(lifter.context().arch.name, "test-arch");
    }

    #[test]
    fn test_x86_64_spec() {
        let spec = create_x86_64_spec();
        assert_eq!(spec.name, "x86-64");
        assert_eq!(spec.instruction_endianness, Endianness::Little);
        assert_eq!(spec.memory_endianness, Endianness::Little);
        assert_eq!(spec.addr_size, 8);

        // Check some registers exist
        assert!(spec.get_register("RAX").is_some());
        assert!(spec.get_register("RSP").is_some());
        assert!(spec.get_register("RIP").is_some());
    }

    /// The processor specification's own program-counter role reaches the
    /// architecture, in the specification's own spelling.
    ///
    /// AArch64 writes it `pc` and x86-64 writes it `RIP`, which is exactly why
    /// it is read rather than guessed: a list of spellings has to know both, and
    /// every architecture nobody thought of gets no answer or a wrong one.
    #[test]
    fn processor_specifications_name_their_own_program_counter() {
        for (sla, pspec, arch, expected) in [
            (
                sleigh_config::processor_aarch64::SLA_AARCH64,
                sleigh_config::processor_aarch64::PSPEC_AARCH64,
                "aarch64",
                "pc",
            ),
            (
                sleigh_config::processor_x86::SLA_X86_64,
                sleigh_config::processor_x86::PSPEC_X86_64,
                "x86-64",
                "RIP",
            ),
        ] {
            let spec = build_arch_spec(sla, pspec, arch).expect("sleigh specification");
            assert_eq!(
                spec.program_counter.as_deref(),
                Some(expected),
                "{arch} states its program counter"
            );
            assert!(
                spec.get_register(expected).is_some(),
                "the named register must exist in {arch}"
            );
        }
    }

    /// The specification's own user-operation table reaches the architecture.
    ///
    /// A `CallOther` states only an index, and the index is assigned by the
    /// compiled specification, so this table is the only thing that can say
    /// which operation an instruction invoked. `NEON_ext`, `NEON_ushl` and `NEON_rev64` are
    /// the ones the corpus needs; asserting a name resolves back through its own
    /// index is the property a consumer depends on.
    #[test]
    fn aarch64_user_operation_names_reach_the_arch_spec() {
        let spec = build_arch_spec(
            sleigh_config::processor_aarch64::SLA_AARCH64,
            sleigh_config::processor_aarch64::PSPEC_AARCH64,
            "aarch64",
        )
        .expect("aarch64 sleigh specification");

        assert!(
            !spec.user_ops.is_empty(),
            "AARCH64 declares user-defined operations"
        );
        for name in [
            "NEON_ext",
            "NEON_ushl",
            "NEON_rev64",
            "NEON_umax",
            "NEON_umin",
            "NEON_umaxv",
            "NEON_uminv",
            "a64_TBL",
        ] {
            let index = spec
                .user_ops
                .iter()
                .position(|declared| declared == name)
                .unwrap_or_else(|| panic!("AARCH64 declares {name}"));
            assert_eq!(spec.user_ops[index], name);
        }
    }

    /// Every x86 packed-extension operation the lift models is declared, under
    /// exactly that name, by both x86 specifications, and resolves through its
    /// own index to the operation the name spells.
    ///
    /// The expected operation is read off the name here, independently of the
    /// table: `vpmovsxbd_avx2` is a sign extension of bytes to doublewords in
    /// the 256-bit VEX encoding. A specification upgrade that renames one of
    /// these, or gives it real p-code, fails this rather than silently leaving
    /// its `CallOther` unmodelled.
    #[test]
    fn x86_packed_extension_names_reach_both_x86_specs() {
        use crate::disasm::user_operation::{
            EncodingForm, Extension, ModelledUserOperation, PackedExtension,
            modelled_user_operations, resolve_modelled_user_operations,
        };

        fn element_bytes(letter: char) -> u32 {
            match letter {
                'b' => 1,
                'w' => 2,
                'd' => 4,
                'q' => 8,
                other => panic!("no element width {other}"),
            }
        }

        fn spelled_by(name: &str) -> ModelledUserOperation {
            let (core, form) = match name.split_once('_') {
                None => (name, EncodingForm::Legacy),
                Some((core, "avx")) => (core, EncodingForm::Vex128),
                Some((core, "avx2")) => (core, EncodingForm::Vex256),
                Some((core, "avx512vl")) => (core, EncodingForm::EvexVl),
                Some((core, "avx512f" | "avx512bw")) => (core, EncodingForm::Evex512),
                Some((_, suffix)) => panic!("{name}: no encoding {suffix}"),
            };
            let core = core.strip_prefix('v').unwrap_or(core);
            let letters = core
                .strip_prefix("pmov")
                .unwrap_or_else(|| panic!("{name} is not a packed move"))
                .chars()
                .collect::<Vec<_>>();
            let [kind, 'x', from, to] = letters[..] else {
                panic!("{name} does not spell a packed extension");
            };
            ModelledUserOperation::PackedExtension(PackedExtension {
                from_bytes: element_bytes(from),
                to_bytes: element_bytes(to),
                extension: match kind {
                    's' => Extension::Sign,
                    'z' => Extension::Zero,
                    other => panic!("{name}: no extension {other}"),
                },
                form,
            })
        }

        let packed = modelled_user_operations()
            .filter(|(_, operation)| matches!(operation, ModelledUserOperation::PackedExtension(_)))
            .collect::<Vec<_>>();
        assert_eq!(packed.len(), 60, "twelve operations in five encodings");
        for (sla, pspec, arch) in [
            (
                sleigh_config::processor_x86::SLA_X86_64,
                sleigh_config::processor_x86::PSPEC_X86_64,
                "x86-64",
            ),
            (
                sleigh_config::processor_x86::SLA_X86,
                sleigh_config::processor_x86::PSPEC_X86,
                "x86",
            ),
        ] {
            let spec = build_arch_spec(sla, pspec, arch).expect("x86 sleigh specification");
            let resolved = resolve_modelled_user_operations(&spec.user_ops);
            for (name, operation) in &packed {
                let index = spec
                    .user_ops
                    .iter()
                    .position(|declared| declared == name)
                    .unwrap_or_else(|| panic!("{arch} declares {name}"));
                assert_eq!(resolved[index], Some(*operation), "{arch} {name}");
                assert_eq!(*operation, spelled_by(name), "{name}");
            }
        }
    }

    #[test]
    fn test_arm_spec() {
        let spec = create_arm_spec();
        assert_eq!(spec.name, "ARM");
        assert_eq!(spec.instruction_endianness, Endianness::Little);
        assert_eq!(spec.memory_endianness, Endianness::Little);
        assert_eq!(spec.addr_size, 4);

        // Check some registers exist
        assert!(spec.get_register("r0").is_some());
        assert!(spec.get_register("sp").is_some());
        assert!(spec.get_register("pc").is_some());
    }

    #[test]
    fn test_riscv64_spec() {
        let spec = create_riscv64_spec();
        assert_eq!(spec.name, "riscv64");
        assert_eq!(spec.instruction_endianness, Endianness::Little);
        assert_eq!(spec.memory_endianness, Endianness::Little);
        assert_eq!(spec.addr_size, 8);
        assert!(spec.get_register("a0").is_some());
        assert!(spec.get_register("sp").is_some());
        assert!(spec.get_register("pc").is_some());
    }

    #[test]
    fn test_riscv32_spec() {
        let spec = create_riscv32_spec();
        assert_eq!(spec.name, "riscv32");
        assert_eq!(spec.instruction_endianness, Endianness::Little);
        assert_eq!(spec.memory_endianness, Endianness::Little);
        assert_eq!(spec.addr_size, 4);
        assert!(spec.get_register("a0").is_some());
        assert!(spec.get_register("sp").is_some());
        assert!(spec.get_register("pc").is_some());
    }
}
