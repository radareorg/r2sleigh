//! Symbolic execution state.
//!
//! This module provides the `SymState` type which represents the state
//! of the program during symbolic execution.

use std::collections::HashMap;

use z3::ast::{Ast, Bool, BV};
use z3::Context;

use crate::memory::SymMemory;
use crate::value::SymValue;

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
        }
    }

    /// Get the Z3 context.
    pub fn context(&self) -> &'ctx Context {
        self.ctx
    }

    /// Get a register value.
    pub fn get_register(&self, name: &str) -> SymValue<'ctx> {
        self.registers
            .get(name)
            .cloned()
            .unwrap_or_else(|| SymValue::unknown(64))
    }

    /// Set a register value.
    pub fn set_register(&mut self, name: &str, value: SymValue<'ctx>) {
        self.registers.insert(name.to_string(), value);
    }

    /// Make a register symbolic with a given name.
    pub fn make_symbolic(&mut self, reg_name: &str, bits: u32) {
        let sym_name = format!("sym_{}", reg_name);
        let value = SymValue::new_symbolic(self.ctx, &sym_name, bits);
        self.registers.insert(reg_name.to_string(), value);
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
        }
    }

    /// Create a forked state with an additional constraint.
    pub fn fork_with_constraint(&self, constraint: Bool<'ctx>) -> Self {
        let mut forked = self.fork();
        forked.add_constraint(constraint);
        forked
    }
}

impl<'ctx> std::fmt::Debug for SymState<'ctx> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymState")
            .field("pc", &format!("0x{:x}", self.pc))
            .field("registers", &self.registers.len())
            .field("constraints", &self.constraints.len())
            .field("depth", &self.depth)
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
}
