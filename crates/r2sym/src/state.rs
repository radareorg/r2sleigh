//! Symbolic execution state.
//!
//! This module provides the `SymState` type which represents the state
//! of the program during symbolic execution.

use std::collections::HashMap;

use z3::ast::{Ast, Bool, BV};
use z3::Context;

use crate::memory::SymMemory;
use crate::value::SymValue;

/// A tracked symbolic memory region (usually an input buffer).
#[derive(Debug, Clone)]
pub struct SymbolicMemoryRegion<'ctx> {
    /// Name of the symbolic buffer.
    pub name: String,
    /// Concrete address of the buffer.
    pub addr: u64,
    /// Size in bytes.
    pub size: u32,
    /// Symbolic value representing the buffer contents.
    pub value: SymValue<'ctx>,
}

/// The state of a symbolic execution.
///
/// Contains registers, memory, path constraints, and program counter.
pub struct SymState<'ctx> {
    /// The Z3 context.
    ctx: &'ctx Context,
    /// Register values (register name -> value).
    registers: HashMap<String, SymValue<'ctx>>,
    /// Memory state.
    pub memory: SymMemory<'ctx>,
    /// Path constraints (conditions that must be true for this path).
    constraints: Vec<Bool<'ctx>>,
    /// Current program counter.
    pub pc: u64,
    /// Whether this state is still active (not terminated).
    pub active: bool,
    /// Exit status (if terminated).
    pub exit_status: Option<ExitStatus>,
    /// Execution depth (number of steps taken).
    pub depth: usize,
    /// Named symbolic inputs (registers or buffers).
    symbolic_inputs: HashMap<String, SymValue<'ctx>>,
    /// Tracked symbolic memory regions.
    symbolic_memory: Vec<SymbolicMemoryRegion<'ctx>>,
}

/// Exit status of a symbolic execution path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitStatus {
    /// Normal return.
    Return,
    /// Hit an error/exception.
    Error(String),
    /// Hit an unimplemented operation.
    Unimplemented,
    /// Reached maximum depth.
    MaxDepth,
    /// Path is infeasible (constraints unsatisfiable).
    Infeasible,
}

impl<'ctx> SymState<'ctx> {
    /// Create a new symbolic state.
    pub fn new(ctx: &'ctx Context, entry_pc: u64) -> Self {
        Self {
            ctx,
            registers: HashMap::new(),
            memory: SymMemory::new(ctx),
            constraints: Vec::new(),
            pc: entry_pc,
            active: true,
            exit_status: None,
            depth: 0,
            symbolic_inputs: HashMap::new(),
            symbolic_memory: Vec::new(),
        }
    }

    /// Create a new state with symbolic memory.
    pub fn new_symbolic(ctx: &'ctx Context, entry_pc: u64) -> Self {
        Self {
            ctx,
            registers: HashMap::new(),
            memory: SymMemory::new_symbolic(ctx),
            constraints: Vec::new(),
            pc: entry_pc,
            active: true,
            exit_status: None,
            depth: 0,
            symbolic_inputs: HashMap::new(),
            symbolic_memory: Vec::new(),
        }
    }

    /// Get the Z3 context.
    pub fn context(&self) -> &'ctx Context {
        self.ctx
    }

    /// Get a register value.
    pub fn get_register(&self, name: &str) -> SymValue<'ctx> {
        self.get_register_sized(name, 64)
    }

    /// Get a register value with an expected bit width.
    pub fn get_register_sized(&self, name: &str, bits: u32) -> SymValue<'ctx> {
        self.registers
            .get(name)
            .cloned()
            .unwrap_or_else(|| SymValue::unknown(bits))
    }

    /// Set a register value.
    pub fn set_register(&mut self, name: &str, value: SymValue<'ctx>) {
        self.registers.insert(name.to_string(), value);
    }

    /// Make a register symbolic with a given name.
    pub fn make_symbolic(&mut self, reg_name: &str, bits: u32) {
        let sym_name = format!("sym_{}", reg_name);
        self.make_symbolic_named(reg_name, &sym_name, bits);
    }

    /// Make a register symbolic with an explicit symbol name.
    pub fn make_symbolic_named(&mut self, reg_name: &str, sym_name: &str, bits: u32) {
        let value = SymValue::new_symbolic(self.ctx, sym_name, bits);
        self.registers.insert(reg_name.to_string(), value.clone());
        self.symbolic_inputs.insert(sym_name.to_string(), value);
    }

    /// Set a register to a concrete value.
    pub fn set_concrete(&mut self, reg_name: &str, value: u64, bits: u32) {
        self.registers
            .insert(reg_name.to_string(), SymValue::concrete(value, bits));
    }

    /// Get all register names.
    pub fn register_names(&self) -> impl Iterator<Item = &String> {
        self.registers.keys()
    }

    /// Get all registers.
    pub fn registers(&self) -> &HashMap<String, SymValue<'ctx>> {
        &self.registers
    }

    /// Get tracked symbolic inputs.
    pub fn symbolic_inputs(&self) -> &HashMap<String, SymValue<'ctx>> {
        &self.symbolic_inputs
    }

    /// Get tracked symbolic memory regions.
    pub fn symbolic_memory(&self) -> &[SymbolicMemoryRegion<'ctx>] {
        &self.symbolic_memory
    }

    /// Read from memory.
    pub fn mem_read(&self, addr: &SymValue<'ctx>, size: u32) -> SymValue<'ctx> {
        self.memory.read(addr, size)
    }

    /// Write to memory.
    pub fn mem_write(&mut self, addr: &SymValue<'ctx>, value: &SymValue<'ctx>, size: u32) {
        self.memory.write(addr, value, size);
    }

    /// Add a path constraint.
    pub fn add_constraint(&mut self, constraint: Bool<'ctx>) {
        self.constraints.push(constraint);
    }

    /// Constrain a value to equal a concrete constant.
    pub fn constrain_eq(&mut self, value: &SymValue<'ctx>, rhs: u64) {
        let bv = value.to_bv(self.ctx);
        let rhs_bv = BV::from_u64(self.ctx, rhs, value.bits());
        self.add_constraint(bv._eq(&rhs_bv));
    }

    /// Constrain a value to not equal a concrete constant.
    pub fn constrain_ne(&mut self, value: &SymValue<'ctx>, rhs: u64) {
        let bv = value.to_bv(self.ctx);
        let rhs_bv = BV::from_u64(self.ctx, rhs, value.bits());
        self.add_constraint(bv._eq(&rhs_bv).not());
    }

    /// Constrain a value to be within an unsigned range [min, max].
    pub fn constrain_range(&mut self, value: &SymValue<'ctx>, min: u64, max: u64) {
        let bv = value.to_bv(self.ctx);
        let min_bv = BV::from_u64(self.ctx, min, value.bits());
        let max_bv = BV::from_u64(self.ctx, max, value.bits());
        let ge = bv.bvuge(&min_bv);
        let le = bv.bvule(&max_bv);
        self.add_constraint(ge & le);
    }

    /// Constrain bytes of a bitvector to an exact string or a simple pattern.
    ///
    /// Patterns use the form "[A-Za-z0-9]" and apply to every byte.
    pub fn constrain_bytes(&mut self, value: &SymValue<'ctx>, pattern: &str) {
        let bits = value.bits();
        if bits < 8 {
            return;
        }

        let bv = value.to_bv(self.ctx);
        let bytes = (bits / 8) as usize;

        let is_pattern = pattern.starts_with('[') && pattern.ends_with(']');
        if !is_pattern {
            let pat_bytes = pattern.as_bytes();
            let limit = std::cmp::min(bytes, pat_bytes.len());
            for i in 0..limit {
                let byte_bv = bv.extract((i as u32 + 1) * 8 - 1, (i as u32) * 8);
                let expected = BV::from_u64(self.ctx, pat_bytes[i] as u64, 8);
                self.add_constraint(byte_bv._eq(&expected));
            }
            return;
        }

        let content = &pattern[1..pattern.len() - 1];
        let ranges = parse_byte_ranges(content);
        if ranges.is_empty() {
            return;
        }

        for i in 0..bytes {
            let byte_bv = bv.extract((i as u32 + 1) * 8 - 1, (i as u32) * 8);
            let mut ors = Vec::with_capacity(ranges.len());
            for (lo, hi) in &ranges {
                let lo_bv = BV::from_u64(self.ctx, *lo as u64, 8);
                let hi_bv = BV::from_u64(self.ctx, *hi as u64, 8);
                if lo == hi {
                    ors.push(byte_bv._eq(&lo_bv));
                } else {
                    ors.push(byte_bv.bvuge(&lo_bv) & byte_bv.bvule(&hi_bv));
                }
            }
            self.add_constraint(or_all(self.ctx, &ors));
        }
    }

    /// Constrain a value to contain a substring.
    pub fn constrain_contains(&mut self, value: &SymValue<'ctx>, needle: &str) {
        self.constrain_contains_inner(value, needle, true);
    }

    /// Constrain a value to not contain a substring.
    pub fn constrain_not_contains(&mut self, value: &SymValue<'ctx>, needle: &str) {
        self.constrain_contains_inner(value, needle, false);
    }

    fn constrain_contains_inner(
        &mut self,
        value: &SymValue<'ctx>,
        needle: &str,
        must_contain: bool,
    ) {
        let needle_bytes = needle.as_bytes();
        if needle_bytes.is_empty() {
            return;
        }

        let total_bytes = (value.bits() / 8) as usize;
        if total_bytes < needle_bytes.len() {
            if must_contain {
                let false_bool = Bool::from_bool(self.ctx, false);
                self.add_constraint(false_bool);
            }
            return;
        }

        let bv = value.to_bv(self.ctx);
        let mut matches = Vec::new();
        for offset in 0..=total_bytes - needle_bytes.len() {
            let mut ands = Vec::with_capacity(needle_bytes.len());
            for (i, byte) in needle_bytes.iter().enumerate() {
                let low = ((offset + i) as u32) * 8;
                let high = low + 7;
                let byte_bv = bv.extract(high, low);
                let expected = BV::from_u64(self.ctx, *byte as u64, 8);
                ands.push(byte_bv._eq(&expected));
            }
            matches.push(and_all(self.ctx, &ands));
        }

        let contains = or_all(self.ctx, &matches);
        if must_contain {
            self.add_constraint(contains);
        } else {
            self.add_constraint(contains.not());
        }
    }

    /// Add a constraint that a value is true (non-zero).
    pub fn add_true_constraint(&mut self, value: &SymValue<'ctx>) {
        let bv = value.to_bv(self.ctx);
        let zero = BV::from_u64(self.ctx, 0, value.bits());
        let cond = bv._eq(&zero).not();
        self.constraints.push(cond);
    }

    /// Add a constraint that a value is false (zero).
    pub fn add_false_constraint(&mut self, value: &SymValue<'ctx>) {
        let bv = value.to_bv(self.ctx);
        let zero = BV::from_u64(self.ctx, 0, value.bits());
        let cond = bv._eq(&zero);
        self.constraints.push(cond);
    }

    /// Get all path constraints.
    pub fn constraints(&self) -> &[Bool<'ctx>] {
        &self.constraints
    }

    /// Get the number of constraints.
    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    /// Terminate this state with the given status.
    pub fn terminate(&mut self, status: ExitStatus) {
        self.active = false;
        self.exit_status = Some(status);
    }

    /// Check if this state has terminated.
    pub fn is_terminated(&self) -> bool {
        !self.active
    }

    /// Increment the execution depth.
    pub fn step(&mut self) {
        self.depth += 1;
    }

    /// Fork this state (for branching).
    pub fn fork(&self) -> Self {
        Self {
            ctx: self.ctx,
            registers: self.registers.clone(),
            memory: self.memory.fork(),
            constraints: self.constraints.clone(),
            pc: self.pc,
            active: self.active,
            exit_status: self.exit_status.clone(),
            depth: self.depth,
            symbolic_inputs: self.symbolic_inputs.clone(),
            symbolic_memory: self.symbolic_memory.clone(),
        }
    }

    /// Create a forked state with an additional constraint.
    pub fn fork_with_constraint(&self, constraint: Bool<'ctx>) -> Self {
        let mut forked = self.fork();
        forked.add_constraint(constraint);
        forked
    }

    /// Create a named symbolic input value.
    pub fn new_symbolic_input(&mut self, name: &str, bits: u32) -> SymValue<'ctx> {
        let value = SymValue::new_symbolic(self.ctx, name, bits);
        self.symbolic_inputs.insert(name.to_string(), value.clone());
        value
    }

    /// Create a named symbolic input value with taint.
    pub fn new_symbolic_input_tainted(
        &mut self,
        name: &str,
        bits: u32,
        taint: u64,
    ) -> SymValue<'ctx> {
        let value = SymValue::new_symbolic_tainted(self.ctx, name, bits, taint);
        self.symbolic_inputs.insert(name.to_string(), value.clone());
        value
    }

    /// Create a symbolic buffer at a concrete address and track it.
    pub fn make_symbolic_memory(&mut self, addr: u64, size: u32, name: &str) -> SymValue<'ctx> {
        self.make_symbolic_memory_tainted(addr, size, name, 0)
    }

    /// Create a tainted symbolic buffer at a concrete address and track it.
    pub fn make_symbolic_memory_tainted(
        &mut self,
        addr: u64,
        size: u32,
        name: &str,
        taint: u64,
    ) -> SymValue<'ctx> {
        let value = if taint == 0 {
            SymValue::new_symbolic(self.ctx, name, size * 8)
        } else {
            SymValue::new_symbolic_tainted(self.ctx, name, size * 8, taint)
        };
        let addr_val = SymValue::concrete(addr, 64);
        self.mem_write(&addr_val, &value, size);
        self.symbolic_inputs.insert(name.to_string(), value.clone());
        self.symbolic_memory.push(SymbolicMemoryRegion {
            name: name.to_string(),
            addr,
            size,
            value: value.clone(),
        });
        value
    }
}

fn parse_byte_ranges(pattern: &str) -> Vec<(u8, u8)> {
    let bytes = pattern.as_bytes();
    let mut ranges = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let start = bytes[i];
        if i + 2 < bytes.len() && bytes[i + 1] == b'-' {
            let end = bytes[i + 2];
            ranges.push((start, end));
            i += 3;
        } else {
            ranges.push((start, start));
            i += 1;
        }
    }
    ranges
}

fn and_all<'ctx>(ctx: &'ctx Context, values: &[Bool<'ctx>]) -> Bool<'ctx> {
    if values.is_empty() {
        return Bool::from_bool(ctx, true);
    }
    let mut iter = values.iter();
    let mut acc = iter.next().unwrap().clone();
    for val in iter {
        acc = acc & val;
    }
    acc
}

fn or_all<'ctx>(ctx: &'ctx Context, values: &[Bool<'ctx>]) -> Bool<'ctx> {
    if values.is_empty() {
        return Bool::from_bool(ctx, false);
    }
    let mut iter = values.iter();
    let mut acc = iter.next().unwrap().clone();
    for val in iter {
        acc = acc | val;
    }
    acc
}

impl<'ctx> std::fmt::Debug for SymState<'ctx> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymState")
            .field("pc", &format!("0x{:x}", self.pc))
            .field("registers", &self.registers.len())
            .field("constraints", &self.constraints.len())
            .field("depth", &self.depth)
            .field("symbolic_inputs", &self.symbolic_inputs.len())
            .field("symbolic_memory", &self.symbolic_memory.len())
            .field("active", &self.active)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::Config;

    #[test]
    fn test_state_creation() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        let state = SymState::new(&ctx, 0x1000);
        assert_eq!(state.pc, 0x1000);
        assert!(state.active);
        assert_eq!(state.depth, 0);
    }

    #[test]
    fn test_register_access() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        let mut state = SymState::new(&ctx, 0x1000);

        state.set_concrete("rax", 42, 64);
        let rax = state.get_register("rax");
        assert_eq!(rax.as_concrete(), Some(42));

        state.make_symbolic("rbx", 64);
        let rbx = state.get_register("rbx");
        assert!(rbx.is_symbolic());
    }

    #[test]
    fn test_memory_access() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        let mut state = SymState::new(&ctx, 0x1000);

        let addr = SymValue::concrete(0x2000, 64);
        let value = SymValue::concrete(0xDEADBEEF, 32);

        state.mem_write(&addr, &value, 4);
        let read = state.mem_read(&addr, 4);
        assert_eq!(read.as_concrete(), Some(0xDEADBEEF));
    }

    #[test]
    fn test_fork() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        let mut state = SymState::new(&ctx, 0x1000);
        state.set_concrete("rax", 42, 64);
        state.pc = 0x2000;

        let forked = state.fork();
        assert_eq!(forked.pc, 0x2000);
        assert_eq!(forked.get_register("rax").as_concrete(), Some(42));
    }

    #[test]
    fn test_constraints() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        let mut state = SymState::new(&ctx, 0x1000);
        state.make_symbolic("rax", 64);

        let rax = state.get_register("rax");
        state.add_true_constraint(&rax);

        assert_eq!(state.num_constraints(), 1);
    }

    #[test]
    fn test_symbolic_memory_tracking() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        let mut state = SymState::new(&ctx, 0x1000);
        let sym = state.make_symbolic_memory(0x3000, 4, "input_buf");

        assert!(sym.is_symbolic());
        assert_eq!(state.symbolic_memory().len(), 1);
        assert!(state.symbolic_inputs().contains_key("input_buf"));
    }

    #[test]
    fn test_constrain_bytes_pattern() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);

        let mut state = SymState::new(&ctx, 0x1000);
        let sym = state.new_symbolic_input("sym", 16);
        state.constrain_bytes(&sym, "[A-Z]");

        assert_eq!(state.num_constraints(), 2);
    }
}
