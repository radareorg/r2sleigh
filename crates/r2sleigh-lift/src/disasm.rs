//! Disassembly and P-code lifting using libsla.
//!
//! This module provides runtime disassembly of instruction bytes to P-code
//! and translation to r2il using Ghidra's libsla library.

use libsla::{
    Address, AddressSpace, AddressSpaceType, BoolOp, FloatOp, GhidraSleigh, InstructionLoader,
    IntOp, IntSign, OpCode, PcodeDisassembly, PcodeInstruction, PseudoOp, Sleigh, VarnodeData,
};
use r2il::{R2ILBlock, R2ILOp, SpaceId, Varnode};

use crate::translate::{self, PcodeSource};
use crate::{LiftError, Result};

/// A disassembler that uses libsla to lift instructions to r2il.
pub struct Disassembler {
    /// The underlying Ghidra Sleigh instance
    sleigh: GhidraSleigh,
    /// Architecture name
    arch_name: String,
}

/// Wrapper for libsla PcodeInstruction that implements PcodeSource.
struct DisasmInstructionWrapper<'a> {
    instr: &'a PcodeInstruction,
    disasm: &'a Disassembler,
}

impl<'a> PcodeSource for DisasmInstructionWrapper<'a> {
    fn output(&self) -> Option<Varnode> {
        self.instr
            .output
            .as_ref()
            .map(|v| self.disasm.translate_varnode(v))
    }

    fn input(&self, idx: usize) -> Option<Varnode> {
        self.instr
            .inputs
            .get(idx)
            .map(|v| self.disasm.translate_varnode(v))
    }

    fn input_raw_offset(&self, idx: usize) -> Option<u64> {
        self.instr.inputs.get(idx).map(|v| v.address.offset)
    }

    fn input_count(&self) -> usize {
        self.instr.inputs.len()
    }

    fn space_from_index(&self, idx: u64) -> SpaceId {
        let spaces = self.disasm.sleigh.address_spaces();
        if let Some(space) = spaces.get(idx as usize) {
            self.disasm.translate_space(space)
        } else {
            SpaceId::Custom(idx as u32)
        }
    }
}

fn translate_err(e: translate::TranslateError) -> LiftError {
    match e {
        translate::TranslateError::MissingOutput(op) => {
            LiftError::Parse(format!("{} requires output", op))
        }
        translate::TranslateError::MissingInput(op, idx) => {
            LiftError::Parse(format!("{} requires input at index {}", op, idx))
        }
        translate::TranslateError::InvalidSpace(idx) => {
            LiftError::Parse(format!("Invalid space index: {}", idx))
        }
    }
}

impl Disassembler {
    /// Create a new disassembler from a precompiled .sla file and processor specification.
    ///
    /// # Arguments
    ///
    /// * `sla_bytes` - The compiled .sla file contents
    /// * `pspec` - The processor specification XML string
    /// * `arch_name` - Name of the architecture
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use r2sleigh_lift::disasm::Disassembler;
    ///
    /// // Using sleigh-config precompiled data
    /// let disasm = Disassembler::from_sla(
    ///     include_bytes!("x86-64.sla"),
    ///     include_str!("x86-64.pspec"),
    ///     "x86-64"
    /// )?;
    /// ```
    pub fn from_sla(sla_bytes: &[u8], pspec: &str, arch_name: &str) -> Result<Self> {
        let sleigh = GhidraSleigh::builder()
            .processor_spec(pspec)
            .map_err(|e| LiftError::Parse(format!("Invalid processor spec: {}", e)))?
            .build(sla_bytes)
            .map_err(|e| LiftError::Parse(format!("Failed to load .sla: {}", e)))?;

        Ok(Self {
            sleigh,
            arch_name: arch_name.to_string(),
        })
    }

    /// Get the architecture name.
    pub fn arch_name(&self) -> &str {
        &self.arch_name
    }

    /// Get the default code address space.
    pub fn default_code_space(&self) -> AddressSpace {
        self.sleigh.default_code_space()
    }

    /// List all address spaces.
    pub fn address_spaces(&self) -> Vec<AddressSpace> {
        self.sleigh.address_spaces()
    }

    /// Get a register's varnode data by name.
    pub fn register(&self, name: &str) -> Result<VarnodeData> {
        self.sleigh
            .register_from_name(name)
            .map_err(|e| LiftError::Parse(format!("Unknown register '{}': {}", name, e)))
    }

    /// Get the register name for a varnode in the register space.
    ///
    /// Returns `None` if the varnode is not in the register space or if
    /// no register name is found for the given offset and size.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let vn = Varnode::register(0x20, 8); // RSP on x86-64
    /// let name = disasm.register_name(&vn);
    /// assert_eq!(name, Some("RSP".to_string()));
    /// ```
    pub fn register_name(&self, vn: &Varnode) -> Option<String> {
        if vn.space != SpaceId::Register {
            return None;
        }

        // Get the register address space
        let reg_space = self.sleigh.address_space_by_name("register")?;

        // Create a VarnodeData to query libsla
        let varnode_data = VarnodeData::new(Address::new(reg_space, vn.offset), vn.size as usize);

        self.sleigh.register_name(&varnode_data)
    }

    /// Format a varnode as a human-readable string, resolving register names.
    ///
    /// This is useful for pretty-printing P-code operations.
    pub fn format_varnode(&self, vn: &Varnode) -> String {
        match vn.space {
            SpaceId::Const => format!("0x{:x}", vn.offset),
            SpaceId::Register => {
                // Try to resolve the register name
                if let Some(name) = self.register_name(vn) {
                    name
                } else {
                    format!("reg:0x{:x}:{}", vn.offset, vn.size)
                }
            }
            SpaceId::Unique => format!("tmp:0x{:x}", vn.offset),
            SpaceId::Ram => format!("[0x{:x}]:{}", vn.offset, vn.size),
            SpaceId::Custom(n) => format!("space{}:0x{:x}", n, vn.offset),
        }
    }

    /// Disassemble instruction bytes at a given address and return r2il.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Instruction bytes to disassemble
    /// * `addr` - Address where the instruction is located
    ///
    /// # Returns
    ///
    /// An `R2ILBlock` containing the translated operations, or an error.
    ///
    /// Note: This lifts a **single instruction**. Use `lift_block` to lift
    /// multiple instructions within a basic block.
    pub fn lift(&self, bytes: &[u8], addr: u64) -> Result<R2ILBlock> {
        let code_space = self.sleigh.default_code_space();
        let address = Address::new(code_space, addr);

        // Create an instruction loader from the bytes
        let loader = ByteLoader::new(bytes, addr);

        // Disassemble to P-code
        let pcode = self
            .sleigh
            .disassemble_pcode(&loader, address)
            .map_err(|e| {
                LiftError::Pcode(crate::pcode::PcodeError::InvalidOpcode(format!(
                    "Disassembly failed: {}",
                    e
                )))
            })?;

        // Translate P-code to r2il
        self.translate_pcode(pcode, addr)
    }

    /// Minimum bytes required by libsla for disassembly.
    const MIN_BYTES: usize = 16;

    /// Lift an entire basic block (multiple instructions) to r2il.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Instruction bytes for the entire block (should be at least 16 bytes for libsla)
    /// * `addr` - Starting address of the block
    /// * `block_size` - Size of the block in bytes
    ///
    /// # Returns
    ///
    /// An `R2ILBlock` containing operations from all instructions in the block.
    pub fn lift_block(&self, bytes: &[u8], addr: u64, block_size: usize) -> Result<R2ILBlock> {
        let mut combined_block = R2ILBlock::new(addr, block_size as u32);
        let mut offset = 0usize;

        while offset < block_size {
            let remaining = &bytes[offset..];
            if remaining.is_empty() {
                break;
            }

            let instr_addr = addr + offset as u64;

            // libsla requires at least 16 bytes; pad if necessary
            let lift_bytes: Vec<u8> = if remaining.len() < Self::MIN_BYTES {
                let mut padded = remaining.to_vec();
                padded.resize(Self::MIN_BYTES, 0);
                padded
            } else {
                remaining.to_vec()
            };

            // Lift single instruction
            match self.lift(&lift_bytes, instr_addr) {
                Ok(instr_block) => {
                    let instr_size = instr_block.size as usize;
                    if instr_size == 0 {
                        // Prevent infinite loop on zero-size instruction
                        break;
                    }

                    // Append all ops from this instruction
                    for op in instr_block.ops {
                        combined_block.push(op);
                    }

                    offset += instr_size;
                }
                Err(_) => {
                    // Stop on disassembly error (e.g., invalid instruction)
                    break;
                }
            }
        }

        // Update the block size to reflect actual bytes consumed
        combined_block.size = offset as u32;

        Ok(combined_block)
    }

    /// Disassemble and get native assembly mnemonic.
    pub fn disasm_native(&self, bytes: &[u8], addr: u64) -> Result<(String, usize)> {
        let code_space = self.sleigh.default_code_space();
        let address = Address::new(code_space, addr);
        let loader = ByteLoader::new(bytes, addr);

        let native = self
            .sleigh
            .disassemble_native(&loader, address)
            .map_err(|e| LiftError::Parse(format!("Disassembly failed: {}", e)))?;

        let mnemonic = format!(
            "{} {}",
            native.instruction.mnemonic, native.instruction.body
        );
        let size = native.origin.size;

        Ok((mnemonic.trim().to_string(), size))
    }

    /// Translate a P-code disassembly to an r2il block.
    fn translate_pcode(&self, pcode: PcodeDisassembly, addr: u64) -> Result<R2ILBlock> {
        let instr_size = pcode.origin.size as u32;
        let mut block = R2ILBlock::new(addr, instr_size);

        for pcode_instr in pcode.instructions {
            if let Some(op) = self.translate_pcode_op(&pcode_instr)? {
                block.push(op);
            }
        }

        Ok(block)
    }

    /// Translate a single P-code instruction to an r2il operation.
    fn translate_pcode_op(&self, instr: &PcodeInstruction) -> Result<Option<R2ILOp>> {
        let source = DisasmInstructionWrapper {
            instr,
            disasm: self,
        };

        // Helpers for common patterns
        let unary = |name, f: fn(Varnode, Varnode) -> R2ILOp| {
            translate::translate_unary(&source, name, f)
                .map(Some)
                .map_err(translate_err)
        };

        let binary = |name, f: fn(Varnode, Varnode, Varnode) -> R2ILOp| {
            translate::translate_binary(&source, name, f)
                .map(Some)
                .map_err(translate_err)
        };

        match &instr.op_code {
            // Data movement
            OpCode::Copy => unary("COPY", |dst, src| R2ILOp::Copy { dst, src }),

            OpCode::Load => translate::translate_load(&source)
                .map(Some)
                .map_err(translate_err),

            OpCode::Store => translate::translate_store(&source)
                .map(Some)
                .map_err(translate_err),

            // Control flow
            OpCode::Branch => {
                let target =
                    translate::require_input(&source, 0, "BRANCH").map_err(translate_err)?;
                Ok(Some(R2ILOp::Branch { target }))
            }

            OpCode::BranchConditional => translate::translate_cbranch(&source)
                .map(Some)
                .map_err(translate_err),

            OpCode::BranchIndirect => {
                let target =
                    translate::require_input(&source, 0, "BRANCHIND").map_err(translate_err)?;
                Ok(Some(R2ILOp::BranchInd { target }))
            }

            OpCode::Call => {
                let target = translate::require_input(&source, 0, "CALL").map_err(translate_err)?;
                Ok(Some(R2ILOp::Call { target }))
            }

            OpCode::CallIndirect => {
                let target =
                    translate::require_input(&source, 0, "CALLIND").map_err(translate_err)?;
                Ok(Some(R2ILOp::CallInd { target }))
            }

            OpCode::Return => {
                let target =
                    translate::require_input(&source, 0, "RETURN").map_err(translate_err)?;
                Ok(Some(R2ILOp::Return { target }))
            }

            // Integer arithmetic
            // Integer arithmetic
            OpCode::Int(IntOp::Add) => binary("INT_ADD", |dst, a, b| R2ILOp::IntAdd { dst, a, b }),
            OpCode::Int(IntOp::Subtract) => {
                binary("INT_SUB", |dst, a, b| R2ILOp::IntSub { dst, a, b })
            }
            OpCode::Int(IntOp::Multiply) => {
                binary("INT_MULT", |dst, a, b| R2ILOp::IntMult { dst, a, b })
            }
            OpCode::Int(IntOp::Divide(IntSign::Unsigned)) => {
                binary("INT_DIV", |dst, a, b| R2ILOp::IntDiv { dst, a, b })
            }
            OpCode::Int(IntOp::Divide(IntSign::Signed)) => {
                binary("INT_SDIV", |dst, a, b| R2ILOp::IntSDiv { dst, a, b })
            }
            OpCode::Int(IntOp::Remainder(IntSign::Unsigned)) => {
                binary("INT_REM", |dst, a, b| R2ILOp::IntRem { dst, a, b })
            }
            OpCode::Int(IntOp::Remainder(IntSign::Signed)) => {
                binary("INT_SREM", |dst, a, b| R2ILOp::IntSRem { dst, a, b })
            }
            OpCode::Int(IntOp::Negate) => {
                unary("INT_2COMP", |dst, src| R2ILOp::IntNegate { dst, src })
            }

            // Bitwise operations
            OpCode::Int(IntOp::Bitwise(BoolOp::And)) => {
                binary("INT_AND", |dst, a, b| R2ILOp::IntAnd { dst, a, b })
            }
            OpCode::Int(IntOp::Bitwise(BoolOp::Or)) => {
                binary("INT_OR", |dst, a, b| R2ILOp::IntOr { dst, a, b })
            }
            OpCode::Int(IntOp::Bitwise(BoolOp::Xor)) => {
                binary("INT_XOR", |dst, a, b| R2ILOp::IntXor { dst, a, b })
            }
            OpCode::Int(IntOp::Bitwise(BoolOp::Negate)) => {
                unary("INT_NEGATE", |dst, src| R2ILOp::IntNot { dst, src })
            }

            // Shift operations
            OpCode::Int(IntOp::ShiftLeft) => {
                binary("INT_LEFT", |dst, a, b| R2ILOp::IntLeft { dst, a, b })
            }
            OpCode::Int(IntOp::ShiftRight(IntSign::Unsigned)) => {
                binary("INT_RIGHT", |dst, a, b| R2ILOp::IntRight { dst, a, b })
            }
            OpCode::Int(IntOp::ShiftRight(IntSign::Signed)) => {
                binary("INT_SRIGHT", |dst, a, b| R2ILOp::IntSRight { dst, a, b })
            }

            // Comparison operations
            OpCode::Int(IntOp::Equal) => {
                binary("INT_EQUAL", |dst, a, b| R2ILOp::IntEqual { dst, a, b })
            }
            OpCode::Int(IntOp::NotEqual) => binary("INT_NOTEQUAL", |dst, a, b| {
                R2ILOp::IntNotEqual { dst, a, b }
            }),
            OpCode::Int(IntOp::LessThan(IntSign::Unsigned)) => {
                binary("INT_LESS", |dst, a, b| R2ILOp::IntLess { dst, a, b })
            }
            OpCode::Int(IntOp::LessThan(IntSign::Signed)) => {
                binary("INT_SLESS", |dst, a, b| R2ILOp::IntSLess { dst, a, b })
            }

            OpCode::Int(IntOp::LessThanOrEqual(IntSign::Unsigned)) => {
                binary("INT_LESSEQUAL", |dst, a, b| R2ILOp::IntLessEqual {
                    dst,
                    a,
                    b,
                })
            }

            OpCode::Int(IntOp::LessThanOrEqual(IntSign::Signed)) => {
                binary("INT_SLESSEQUAL", |dst, a, b| R2ILOp::IntSLessEqual {
                    dst,
                    a,
                    b,
                })
            }

            // Extension operations
            OpCode::Int(IntOp::Extension(IntSign::Unsigned)) => {
                unary("INT_ZEXT", |dst, src| R2ILOp::IntZExt { dst, src })
            }

            OpCode::Int(IntOp::Extension(IntSign::Signed)) => {
                unary("INT_SEXT", |dst, src| R2ILOp::IntSExt { dst, src })
            }

            // Carry/Borrow
            OpCode::Int(IntOp::Carry(IntSign::Unsigned)) => {
                binary("INT_CARRY", |dst, a, b| R2ILOp::IntCarry { dst, a, b })
            }

            OpCode::Int(IntOp::Carry(IntSign::Signed)) => {
                binary("INT_SCARRY", |dst, a, b| R2ILOp::IntSCarry { dst, a, b })
            }

            OpCode::Int(IntOp::Borrow) => {
                binary("INT_SBORROW", |dst, a, b| R2ILOp::IntSBorrow { dst, a, b })
            }

            // Boolean operations
            OpCode::Bool(BoolOp::And) => {
                binary("BOOL_AND", |dst, a, b| R2ILOp::BoolAnd { dst, a, b })
            }

            OpCode::Bool(BoolOp::Or) => binary("BOOL_OR", |dst, a, b| R2ILOp::BoolOr { dst, a, b }),

            OpCode::Bool(BoolOp::Xor) => {
                binary("BOOL_XOR", |dst, a, b| R2ILOp::BoolXor { dst, a, b })
            }

            OpCode::Bool(BoolOp::Negate) => {
                unary("BOOL_NEGATE", |dst, src| R2ILOp::BoolNot { dst, src })
            }

            // Piece/Subpiece
            // Piece/Subpiece
            OpCode::Piece => binary("PIECE", |dst, hi, lo| R2ILOp::Piece { dst, hi, lo }),

            OpCode::Subpiece => translate::translate_subpiece(&source)
                .map(Some)
                .map_err(translate_err),

            // Popcount/LzCount
            OpCode::Popcount => unary("POPCOUNT", |dst, src| R2ILOp::PopCount { dst, src }),

            OpCode::LzCount => unary("LZCOUNT", |dst, src| R2ILOp::Lzcount { dst, src }),

            // Floating point operations
            OpCode::Float(FloatOp::Add) => {
                binary("FLOAT_ADD", |dst, a, b| R2ILOp::FloatAdd { dst, a, b })
            }

            OpCode::Float(FloatOp::Subtract) => {
                binary("FLOAT_SUB", |dst, a, b| R2ILOp::FloatSub { dst, a, b })
            }

            OpCode::Float(FloatOp::Multiply) => {
                binary("FLOAT_MULT", |dst, a, b| R2ILOp::FloatMult { dst, a, b })
            }

            OpCode::Float(FloatOp::Divide) => {
                binary("FLOAT_DIV", |dst, a, b| R2ILOp::FloatDiv { dst, a, b })
            }

            OpCode::Float(FloatOp::Negate) => {
                unary("FLOAT_NEG", |dst, src| R2ILOp::FloatNeg { dst, src })
            }

            OpCode::Float(FloatOp::AbsoluteValue) => {
                unary("FLOAT_ABS", |dst, src| R2ILOp::FloatAbs { dst, src })
            }

            OpCode::Float(FloatOp::SquareRoot) => {
                unary("FLOAT_SQRT", |dst, src| R2ILOp::FloatSqrt { dst, src })
            }

            OpCode::Float(FloatOp::Equal) => {
                binary("FLOAT_EQUAL", |dst, a, b| R2ILOp::FloatEqual { dst, a, b })
            }

            OpCode::Float(FloatOp::NotEqual) => binary("FLOAT_NOTEQUAL", |dst, a, b| {
                R2ILOp::FloatNotEqual { dst, a, b }
            }),

            OpCode::Float(FloatOp::LessThan) => {
                binary("FLOAT_LESS", |dst, a, b| R2ILOp::FloatLess { dst, a, b })
            }

            OpCode::Float(FloatOp::LessThanOrEqual) => binary("FLOAT_LESSEQUAL", |dst, a, b| {
                R2ILOp::FloatLessEqual { dst, a, b }
            }),

            OpCode::Float(FloatOp::IsNaN) => {
                unary("FLOAT_NAN", |dst, src| R2ILOp::FloatNaN { dst, src })
            }

            OpCode::Float(FloatOp::IntToFloat) => {
                unary("INT2FLOAT", |dst, src| R2ILOp::Int2Float { dst, src })
            }

            OpCode::Float(FloatOp::FloatToFloat) => {
                unary("FLOAT_FLOAT", |dst, src| R2ILOp::FloatFloat { dst, src })
            }

            OpCode::Float(FloatOp::Truncate) => {
                unary("TRUNC", |dst, src| R2ILOp::Trunc { dst, src })
            }

            OpCode::Float(FloatOp::Ceiling) => {
                unary("FLOAT_CEIL", |dst, src| R2ILOp::FloatCeil { dst, src })
            }

            OpCode::Float(FloatOp::Floor) => {
                unary("FLOAT_FLOOR", |dst, src| R2ILOp::FloatFloor { dst, src })
            }

            OpCode::Float(FloatOp::Round) => {
                unary("FLOAT_ROUND", |dst, src| R2ILOp::FloatRound { dst, src })
            }

            // Pseudo operations
            OpCode::Pseudo(PseudoOp::CallOther) => {
                // CALLOTHER: first input is userop index, rest are arguments
                let userop_vn =
                    translate::require_input(&source, 0, "CALLOTHER").map_err(translate_err)?;
                let userop = userop_vn.offset as u32;
                let output = source.output();

                // Collect remaining inputs (args)
                let mut inputs = Vec::new();
                for i in 1..source.input_count() {
                    if let Some(input) = source.input(i) {
                        inputs.push(input);
                    }
                }

                Ok(Some(R2ILOp::CallOther {
                    userop,
                    output,
                    inputs,
                }))
            }

            // Analysis ops and unknowns - emit as Nop or unsupported marker
            OpCode::Analysis(_) | OpCode::Pseudo(_) | OpCode::Unknown(_) => {
                // Skip analysis-only operations
                Ok(None)
            }
        }
    }

    /// Convert a libsla VarnodeData to our Varnode type.
    fn translate_varnode(&self, vn: &VarnodeData) -> Varnode {
        let space = self.translate_space(&vn.address.address_space);
        Varnode {
            space,
            offset: vn.address.offset,
            size: vn.size as u32,
        }
    }

    /// Convert a libsla AddressSpace to our SpaceId.
    fn translate_space(&self, space: &AddressSpace) -> SpaceId {
        match space.space_type {
            AddressSpaceType::Processor => {
                // Check if this is the register space
                if space.name.contains("register") || space.name == "register" {
                    SpaceId::Register
                } else {
                    SpaceId::Ram
                }
            }
            AddressSpaceType::Constant => SpaceId::Const,
            AddressSpaceType::Internal => SpaceId::Unique,
            _ => {
                // Use custom space with a hash of the name for unknown space types
                let hash = space
                    .name
                    .bytes()
                    .fold(0u32, |acc, b| acc.wrapping_add(b as u32));
                SpaceId::Custom(hash)
            }
        }
    }
}

/// Simple byte loader for instruction bytes.
struct ByteLoader<'a> {
    bytes: &'a [u8],
    base_addr: u64,
}

impl<'a> ByteLoader<'a> {
    fn new(bytes: &'a [u8], base_addr: u64) -> Self {
        Self { bytes, base_addr }
    }
}

impl<'a> InstructionLoader for ByteLoader<'a> {
    fn load_instruction_bytes(
        &self,
        varnode: &VarnodeData,
    ) -> std::result::Result<Vec<u8>, String> {
        let offset = varnode
            .address
            .offset
            .checked_sub(self.base_addr)
            .ok_or_else(|| "Address underflow".to_string())?;
        let start = offset as usize;
        let end = start
            .checked_add(varnode.size)
            .ok_or_else(|| "Size overflow".to_string())?;

        if end <= self.bytes.len() {
            Ok(self.bytes[start..end].to_vec())
        } else {
            Err(format!(
                "Out of bounds: requested {}..{}, have {}",
                start,
                end,
                self.bytes.len()
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    // Tests require sleigh-config feature flags to be enabled
    // They are skipped by default

    #[test]
    #[ignore = "Requires sleigh-config with x86 feature"]
    fn test_x86_disasm() {
        // This test would require:
        // sleigh-config = { version = "1.0", features = ["x86"] }
        // Then use sleigh_config::processor_x86::SLA_X86_64 and PSPEC_X86_64
    }
}
