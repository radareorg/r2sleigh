//! Disassembly and P-code lifting using libsla.
//!
//! This module provides runtime disassembly of instruction bytes to P-code
//! and translation to r2il using Ghidra's libsla library.

use libsla::{
    Address, AddressSpace, AddressSpaceType, BoolOp, FloatOp, GhidraSleigh, InstructionLoader,
    IntOp, IntSign, OpCode, PcodeDisassembly, PcodeInstruction, PseudoOp, Sleigh, VarnodeData,
};
use r2il::{R2ILBlock, R2ILOp, SpaceId, Varnode};

use crate::{LiftError, Result};

/// A disassembler that uses libsla to lift instructions to r2il.
pub struct Disassembler {
    /// The underlying Ghidra Sleigh instance
    sleigh: GhidraSleigh,
    /// Architecture name
    arch_name: String,
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
        let output = instr.output.as_ref().map(|v| self.translate_varnode(v));
        let inputs: Vec<Varnode> = instr
            .inputs
            .iter()
            .map(|v| self.translate_varnode(v))
            .collect();

        let op = match &instr.op_code {
            // Data movement
            OpCode::Copy => {
                let dst = output.ok_or_else(|| missing_output("COPY"))?;
                let src = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("COPY", 0))?;
                Some(R2ILOp::Copy { dst, src })
            }

            OpCode::Load => {
                let dst = output.ok_or_else(|| missing_output("LOAD"))?;
                // First input is space ID (constant), second is address
                let space_id = inputs.first().ok_or_else(|| missing_input("LOAD", 0))?;
                let addr_varnode = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("LOAD", 1))?;
                let space = self.space_from_constant(space_id);
                Some(R2ILOp::Load {
                    dst,
                    space,
                    addr: addr_varnode,
                })
            }

            OpCode::Store => {
                // First input is space ID, second is address, third is value
                let space_id = inputs.first().ok_or_else(|| missing_input("STORE", 0))?;
                let addr_varnode = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("STORE", 1))?;
                let val = inputs
                    .get(2)
                    .cloned()
                    .ok_or_else(|| missing_input("STORE", 2))?;
                let space = self.space_from_constant(space_id);
                Some(R2ILOp::Store {
                    space,
                    addr: addr_varnode,
                    val,
                })
            }

            // Control flow
            OpCode::Branch => {
                let target = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("BRANCH", 0))?;
                Some(R2ILOp::Branch { target })
            }

            OpCode::BranchConditional => {
                let cond = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("CBRANCH", 0))?;
                let target = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("CBRANCH", 1))?;
                Some(R2ILOp::CBranch { cond, target })
            }

            OpCode::BranchIndirect => {
                let target = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("BRANCHIND", 0))?;
                Some(R2ILOp::BranchInd { target })
            }

            OpCode::Call => {
                let target = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("CALL", 0))?;
                Some(R2ILOp::Call { target })
            }

            OpCode::CallIndirect => {
                let target = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("CALLIND", 0))?;
                Some(R2ILOp::CallInd { target })
            }

            OpCode::Return => {
                let target = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("RETURN", 0))?;
                Some(R2ILOp::Return { target })
            }

            // Integer arithmetic
            OpCode::Int(IntOp::Add) => {
                let dst = output.ok_or_else(|| missing_output("INT_ADD"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_ADD", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("INT_ADD", 1))?;
                Some(R2ILOp::IntAdd { dst, a, b })
            }

            OpCode::Int(IntOp::Subtract) => {
                let dst = output.ok_or_else(|| missing_output("INT_SUB"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_SUB", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("INT_SUB", 1))?;
                Some(R2ILOp::IntSub { dst, a, b })
            }

            OpCode::Int(IntOp::Multiply) => {
                let dst = output.ok_or_else(|| missing_output("INT_MULT"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_MULT", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("INT_MULT", 1))?;
                Some(R2ILOp::IntMult { dst, a, b })
            }

            OpCode::Int(IntOp::Divide(IntSign::Unsigned)) => {
                let dst = output.ok_or_else(|| missing_output("INT_DIV"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_DIV", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("INT_DIV", 1))?;
                Some(R2ILOp::IntDiv { dst, a, b })
            }

            OpCode::Int(IntOp::Divide(IntSign::Signed)) => {
                let dst = output.ok_or_else(|| missing_output("INT_SDIV"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_SDIV", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("INT_SDIV", 1))?;
                Some(R2ILOp::IntSDiv { dst, a, b })
            }

            OpCode::Int(IntOp::Remainder(IntSign::Unsigned)) => {
                let dst = output.ok_or_else(|| missing_output("INT_REM"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_REM", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("INT_REM", 1))?;
                Some(R2ILOp::IntRem { dst, a, b })
            }

            OpCode::Int(IntOp::Remainder(IntSign::Signed)) => {
                let dst = output.ok_or_else(|| missing_output("INT_SREM"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_SREM", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("INT_SREM", 1))?;
                Some(R2ILOp::IntSRem { dst, a, b })
            }

            OpCode::Int(IntOp::Negate) => {
                let dst = output.ok_or_else(|| missing_output("INT_2COMP"))?;
                let src = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_2COMP", 0))?;
                Some(R2ILOp::IntNegate { dst, src })
            }

            // Bitwise operations
            OpCode::Int(IntOp::Bitwise(BoolOp::And)) => {
                let dst = output.ok_or_else(|| missing_output("INT_AND"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_AND", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("INT_AND", 1))?;
                Some(R2ILOp::IntAnd { dst, a, b })
            }

            OpCode::Int(IntOp::Bitwise(BoolOp::Or)) => {
                let dst = output.ok_or_else(|| missing_output("INT_OR"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_OR", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("INT_OR", 1))?;
                Some(R2ILOp::IntOr { dst, a, b })
            }

            OpCode::Int(IntOp::Bitwise(BoolOp::Xor)) => {
                let dst = output.ok_or_else(|| missing_output("INT_XOR"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_XOR", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("INT_XOR", 1))?;
                Some(R2ILOp::IntXor { dst, a, b })
            }

            OpCode::Int(IntOp::Bitwise(BoolOp::Negate)) => {
                let dst = output.ok_or_else(|| missing_output("INT_NEGATE"))?;
                let src = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_NEGATE", 0))?;
                Some(R2ILOp::IntNot { dst, src })
            }

            // Shift operations
            OpCode::Int(IntOp::ShiftLeft) => {
                let dst = output.ok_or_else(|| missing_output("INT_LEFT"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_LEFT", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("INT_LEFT", 1))?;
                Some(R2ILOp::IntLeft { dst, a, b })
            }

            OpCode::Int(IntOp::ShiftRight(IntSign::Unsigned)) => {
                let dst = output.ok_or_else(|| missing_output("INT_RIGHT"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_RIGHT", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("INT_RIGHT", 1))?;
                Some(R2ILOp::IntRight { dst, a, b })
            }

            OpCode::Int(IntOp::ShiftRight(IntSign::Signed)) => {
                let dst = output.ok_or_else(|| missing_output("INT_SRIGHT"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_SRIGHT", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("INT_SRIGHT", 1))?;
                Some(R2ILOp::IntSRight { dst, a, b })
            }

            // Comparison operations
            OpCode::Int(IntOp::Equal) => {
                let dst = output.ok_or_else(|| missing_output("INT_EQUAL"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_EQUAL", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("INT_EQUAL", 1))?;
                Some(R2ILOp::IntEqual { dst, a, b })
            }

            OpCode::Int(IntOp::NotEqual) => {
                let dst = output.ok_or_else(|| missing_output("INT_NOTEQUAL"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_NOTEQUAL", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("INT_NOTEQUAL", 1))?;
                Some(R2ILOp::IntNotEqual { dst, a, b })
            }

            OpCode::Int(IntOp::LessThan(IntSign::Unsigned)) => {
                let dst = output.ok_or_else(|| missing_output("INT_LESS"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_LESS", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("INT_LESS", 1))?;
                Some(R2ILOp::IntLess { dst, a, b })
            }

            OpCode::Int(IntOp::LessThan(IntSign::Signed)) => {
                let dst = output.ok_or_else(|| missing_output("INT_SLESS"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_SLESS", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("INT_SLESS", 1))?;
                Some(R2ILOp::IntSLess { dst, a, b })
            }

            OpCode::Int(IntOp::LessThanOrEqual(IntSign::Unsigned)) => {
                let dst = output.ok_or_else(|| missing_output("INT_LESSEQUAL"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_LESSEQUAL", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("INT_LESSEQUAL", 1))?;
                Some(R2ILOp::IntLessEqual { dst, a, b })
            }

            OpCode::Int(IntOp::LessThanOrEqual(IntSign::Signed)) => {
                let dst = output.ok_or_else(|| missing_output("INT_SLESSEQUAL"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_SLESSEQUAL", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("INT_SLESSEQUAL", 1))?;
                Some(R2ILOp::IntSLessEqual { dst, a, b })
            }

            // Extension operations
            OpCode::Int(IntOp::Extension(IntSign::Unsigned)) => {
                let dst = output.ok_or_else(|| missing_output("INT_ZEXT"))?;
                let src = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_ZEXT", 0))?;
                Some(R2ILOp::IntZExt { dst, src })
            }

            OpCode::Int(IntOp::Extension(IntSign::Signed)) => {
                let dst = output.ok_or_else(|| missing_output("INT_SEXT"))?;
                let src = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_SEXT", 0))?;
                Some(R2ILOp::IntSExt { dst, src })
            }

            // Carry/Borrow
            OpCode::Int(IntOp::Carry(IntSign::Unsigned)) => {
                let dst = output.ok_or_else(|| missing_output("INT_CARRY"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_CARRY", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("INT_CARRY", 1))?;
                Some(R2ILOp::IntCarry { dst, a, b })
            }

            OpCode::Int(IntOp::Carry(IntSign::Signed)) => {
                let dst = output.ok_or_else(|| missing_output("INT_SCARRY"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_SCARRY", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("INT_SCARRY", 1))?;
                Some(R2ILOp::IntSCarry { dst, a, b })
            }

            OpCode::Int(IntOp::Borrow) => {
                let dst = output.ok_or_else(|| missing_output("INT_SBORROW"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("INT_SBORROW", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("INT_SBORROW", 1))?;
                Some(R2ILOp::IntSBorrow { dst, a, b })
            }

            // Boolean operations
            OpCode::Bool(BoolOp::And) => {
                let dst = output.ok_or_else(|| missing_output("BOOL_AND"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("BOOL_AND", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("BOOL_AND", 1))?;
                Some(R2ILOp::BoolAnd { dst, a, b })
            }

            OpCode::Bool(BoolOp::Or) => {
                let dst = output.ok_or_else(|| missing_output("BOOL_OR"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("BOOL_OR", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("BOOL_OR", 1))?;
                Some(R2ILOp::BoolOr { dst, a, b })
            }

            OpCode::Bool(BoolOp::Xor) => {
                let dst = output.ok_or_else(|| missing_output("BOOL_XOR"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("BOOL_XOR", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("BOOL_XOR", 1))?;
                Some(R2ILOp::BoolXor { dst, a, b })
            }

            OpCode::Bool(BoolOp::Negate) => {
                let dst = output.ok_or_else(|| missing_output("BOOL_NEGATE"))?;
                let src = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("BOOL_NEGATE", 0))?;
                Some(R2ILOp::BoolNot { dst, src })
            }

            // Piece/Subpiece
            OpCode::Piece => {
                let dst = output.ok_or_else(|| missing_output("PIECE"))?;
                let hi = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("PIECE", 0))?;
                let lo = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("PIECE", 1))?;
                Some(R2ILOp::Piece { dst, hi, lo })
            }

            OpCode::Subpiece => {
                let dst = output.ok_or_else(|| missing_output("SUBPIECE"))?;
                let src = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("SUBPIECE", 0))?;
                let offset_vn = inputs.get(1).ok_or_else(|| missing_input("SUBPIECE", 1))?;
                // The offset is a constant - extract the value
                let offset = offset_vn.offset as u32;
                Some(R2ILOp::Subpiece { dst, src, offset })
            }

            // Popcount/LzCount
            OpCode::Popcount => {
                let dst = output.ok_or_else(|| missing_output("POPCOUNT"))?;
                let src = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("POPCOUNT", 0))?;
                Some(R2ILOp::PopCount { dst, src })
            }

            OpCode::LzCount => {
                let dst = output.ok_or_else(|| missing_output("LZCOUNT"))?;
                let src = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("LZCOUNT", 0))?;
                Some(R2ILOp::Lzcount { dst, src })
            }

            // Floating point operations
            OpCode::Float(FloatOp::Add) => {
                let dst = output.ok_or_else(|| missing_output("FLOAT_ADD"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_ADD", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_ADD", 1))?;
                Some(R2ILOp::FloatAdd { dst, a, b })
            }

            OpCode::Float(FloatOp::Subtract) => {
                let dst = output.ok_or_else(|| missing_output("FLOAT_SUB"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_SUB", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_SUB", 1))?;
                Some(R2ILOp::FloatSub { dst, a, b })
            }

            OpCode::Float(FloatOp::Multiply) => {
                let dst = output.ok_or_else(|| missing_output("FLOAT_MULT"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_MULT", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_MULT", 1))?;
                Some(R2ILOp::FloatMult { dst, a, b })
            }

            OpCode::Float(FloatOp::Divide) => {
                let dst = output.ok_or_else(|| missing_output("FLOAT_DIV"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_DIV", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_DIV", 1))?;
                Some(R2ILOp::FloatDiv { dst, a, b })
            }

            OpCode::Float(FloatOp::Negate) => {
                let dst = output.ok_or_else(|| missing_output("FLOAT_NEG"))?;
                let src = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_NEG", 0))?;
                Some(R2ILOp::FloatNeg { dst, src })
            }

            OpCode::Float(FloatOp::AbsoluteValue) => {
                let dst = output.ok_or_else(|| missing_output("FLOAT_ABS"))?;
                let src = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_ABS", 0))?;
                Some(R2ILOp::FloatAbs { dst, src })
            }

            OpCode::Float(FloatOp::SquareRoot) => {
                let dst = output.ok_or_else(|| missing_output("FLOAT_SQRT"))?;
                let src = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_SQRT", 0))?;
                Some(R2ILOp::FloatSqrt { dst, src })
            }

            OpCode::Float(FloatOp::Equal) => {
                let dst = output.ok_or_else(|| missing_output("FLOAT_EQUAL"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_EQUAL", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_EQUAL", 1))?;
                Some(R2ILOp::FloatEqual { dst, a, b })
            }

            OpCode::Float(FloatOp::NotEqual) => {
                let dst = output.ok_or_else(|| missing_output("FLOAT_NOTEQUAL"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_NOTEQUAL", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_NOTEQUAL", 1))?;
                Some(R2ILOp::FloatNotEqual { dst, a, b })
            }

            OpCode::Float(FloatOp::LessThan) => {
                let dst = output.ok_or_else(|| missing_output("FLOAT_LESS"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_LESS", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_LESS", 1))?;
                Some(R2ILOp::FloatLess { dst, a, b })
            }

            OpCode::Float(FloatOp::LessThanOrEqual) => {
                let dst = output.ok_or_else(|| missing_output("FLOAT_LESSEQUAL"))?;
                let a = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_LESSEQUAL", 0))?;
                let b = inputs
                    .get(1)
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_LESSEQUAL", 1))?;
                Some(R2ILOp::FloatLessEqual { dst, a, b })
            }

            OpCode::Float(FloatOp::IsNaN) => {
                let dst = output.ok_or_else(|| missing_output("FLOAT_NAN"))?;
                let src = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_NAN", 0))?;
                Some(R2ILOp::FloatNaN { dst, src })
            }

            OpCode::Float(FloatOp::IntToFloat) => {
                let dst = output.ok_or_else(|| missing_output("FLOAT_INT2FLOAT"))?;
                let src = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_INT2FLOAT", 0))?;
                Some(R2ILOp::Int2Float { dst, src })
            }

            OpCode::Float(FloatOp::FloatToFloat) => {
                let dst = output.ok_or_else(|| missing_output("FLOAT_FLOAT2FLOAT"))?;
                let src = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_FLOAT2FLOAT", 0))?;
                Some(R2ILOp::FloatFloat { dst, src })
            }

            OpCode::Float(FloatOp::Truncate) => {
                let dst = output.ok_or_else(|| missing_output("FLOAT_TRUNC"))?;
                let src = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_TRUNC", 0))?;
                Some(R2ILOp::Trunc { dst, src })
            }

            OpCode::Float(FloatOp::Ceiling) => {
                let dst = output.ok_or_else(|| missing_output("FLOAT_CEIL"))?;
                let src = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_CEIL", 0))?;
                Some(R2ILOp::FloatCeil { dst, src })
            }

            OpCode::Float(FloatOp::Floor) => {
                let dst = output.ok_or_else(|| missing_output("FLOAT_FLOOR"))?;
                let src = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_FLOOR", 0))?;
                Some(R2ILOp::FloatFloor { dst, src })
            }

            OpCode::Float(FloatOp::Round) => {
                let dst = output.ok_or_else(|| missing_output("FLOAT_ROUND"))?;
                let src = inputs
                    .first()
                    .cloned()
                    .ok_or_else(|| missing_input("FLOAT_ROUND", 0))?;
                Some(R2ILOp::FloatRound { dst, src })
            }

            // Pseudo operations
            OpCode::Pseudo(PseudoOp::CallOther) => {
                // CALLOTHER: first input is userop index, rest are arguments
                let userop_id = inputs
                    .first()
                    .ok_or_else(|| missing_input("CALLOTHER", 0))?;
                let args: Vec<Varnode> = inputs.iter().skip(1).cloned().collect();
                Some(R2ILOp::CallOther {
                    userop: userop_id.offset as u32,
                    output,
                    inputs: args,
                })
            }

            // Analysis ops and unknowns - emit as Nop or unsupported marker
            OpCode::Analysis(_) | OpCode::Pseudo(_) | OpCode::Unknown(_) => {
                // Skip analysis-only operations
                None
            }
        };

        Ok(op)
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

    /// Extract a space ID from a constant varnode (used in LOAD/STORE).
    fn space_from_constant(&self, vn: &Varnode) -> SpaceId {
        // In P-code, LOAD/STORE use a constant varnode with the space index as the offset
        // We map it to our space types
        match vn.offset {
            0 => SpaceId::Ram,
            1 => SpaceId::Register,
            2 => SpaceId::Unique,
            n => SpaceId::Custom(n as u32),
        }
    }
}

/// Simple byte loader for instruction bytes.
struct ByteLoader {
    bytes: Vec<u8>,
    base_addr: u64,
}

impl ByteLoader {
    fn new(bytes: &[u8], base_addr: u64) -> Self {
        Self {
            bytes: bytes.to_vec(),
            base_addr,
        }
    }
}

impl InstructionLoader for ByteLoader {
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

/// Helper for missing output error.
fn missing_output(op: &str) -> LiftError {
    LiftError::Pcode(crate::pcode::PcodeError::InvalidOpcode(format!(
        "{} requires an output",
        op
    )))
}

/// Helper for missing input error.
fn missing_input(op: &str, index: usize) -> LiftError {
    LiftError::Pcode(crate::pcode::PcodeError::InvalidOpcode(format!(
        "{} requires input at index {}",
        op, index
    )))
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
