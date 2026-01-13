//! Symbolic memory model for symbolic execution.
//!
//! This module provides a sparse memory model that can handle both
//! concrete and symbolic addresses and values.

use std::collections::HashMap;

use z3::Context;

use crate::value::SymValue;

/// A symbolic memory model.
///
/// Memory is modeled as a sparse map from addresses to byte values.
/// For symbolic addresses, we use Z3's array theory.
pub struct SymMemory<'ctx> {
    /// The Z3 context.
    ctx: &'ctx Context,
    /// Concrete memory (address -> byte value).
    concrete: HashMap<u64, u8>,
    /// Symbolic memory regions (for symbolic writes).
    /// Each entry represents a write: (address, value, size).
    symbolic_writes: Vec<(SymValue<'ctx>, SymValue<'ctx>, u32)>,
    /// Default value for uninitialized memory (0 or symbolic).
    default_symbolic: bool,
}

impl<'ctx> SymMemory<'ctx> {
    /// Create a new empty memory.
    pub fn new(ctx: &'ctx Context) -> Self {
        Self {
            ctx,
            concrete: HashMap::new(),
            symbolic_writes: Vec::new(),
            default_symbolic: false,
        }
    }

    /// Create memory with symbolic default values.
    pub fn new_symbolic(ctx: &'ctx Context) -> Self {
        Self {
            ctx,
            concrete: HashMap::new(),
            symbolic_writes: Vec::new(),
            default_symbolic: true,
        }
    }

    /// Read a value from memory.
    ///
    /// # Arguments
    /// * `addr` - The address to read from
    /// * `size` - The size in bytes to read
    pub fn read(&self, addr: &SymValue<'ctx>, size: u32) -> SymValue<'ctx> {
        // Check if address is concrete
        if let Some(concrete_addr) = addr.as_concrete() {
            // Check if all bytes are in concrete memory
            let mut all_concrete = true;
            let mut value: u64 = 0;

            for i in 0..size {
                let byte_addr = concrete_addr.wrapping_add(i as u64);
                if let Some(&byte) = self.concrete.get(&byte_addr) {
                    value |= (byte as u64) << (i * 8);
                } else {
                    all_concrete = false;
                    break;
                }
            }

            if all_concrete {
                return SymValue::concrete(value, size * 8);
            }

            // Check symbolic writes for this address
            for (write_addr, write_val, write_size) in self.symbolic_writes.iter().rev() {
                if let Some(wa) = write_addr.as_concrete() {
                    // Check if this write covers our read
                    if wa <= concrete_addr
                        && wa + (*write_size as u64) >= concrete_addr + (size as u64)
                    {
                        let offset = concrete_addr - wa;
                        if offset == 0 && *write_size == size {
                            return write_val.clone();
                        }
                        // Extract the relevant bytes
                        let low_bit = (offset * 8) as u32;
                        let high_bit = low_bit + (size * 8) - 1;
                        return write_val.extract(self.ctx, high_bit, low_bit);
                    }
                }
            }

            // Return default value
            if self.default_symbolic {
                SymValue::new_symbolic(self.ctx, &format!("mem_{:x}", concrete_addr), size * 8)
            } else {
                SymValue::concrete(0, size * 8)
            }
        } else {
            // Symbolic address - need to model with Z3
            // For now, return a fresh symbolic value
            let ast = z3::ast::BV::fresh_const("mem_sym", size * 8);
            SymValue::symbolic(ast, size * 8)
        }
    }

    /// Write a value to memory.
    ///
    /// # Arguments
    /// * `addr` - The address to write to
    /// * `value` - The value to write
    /// * `size` - The size in bytes to write
    pub fn write(&mut self, addr: &SymValue<'ctx>, value: &SymValue<'ctx>, size: u32) {
        if let (Some(concrete_addr), Some(concrete_value)) =
            (addr.as_concrete(), value.as_concrete())
        {
            // Concrete write
            for i in 0..size {
                let byte_addr = concrete_addr.wrapping_add(i as u64);
                let byte_value = ((concrete_value >> (i * 8)) & 0xFF) as u8;
                self.concrete.insert(byte_addr, byte_value);
            }
        } else {
            // Symbolic write - record it
            self.symbolic_writes
                .push((addr.clone(), value.clone(), size));
        }
    }

    /// Write concrete bytes to memory.
    pub fn write_bytes(&mut self, addr: u64, bytes: &[u8]) {
        for (i, &byte) in bytes.iter().enumerate() {
            self.concrete.insert(addr + i as u64, byte);
        }
    }

    /// Read concrete bytes from memory.
    pub fn read_bytes(&self, addr: u64, size: usize) -> Option<Vec<u8>> {
        let mut bytes = Vec::with_capacity(size);
        for i in 0..size {
            if let Some(&byte) = self.concrete.get(&(addr + i as u64)) {
                bytes.push(byte);
            } else {
                return None;
            }
        }
        Some(bytes)
    }

    /// Check if an address range is fully concrete.
    pub fn is_concrete_range(&self, addr: u64, size: u32) -> bool {
        for i in 0..size {
            if !self.concrete.contains_key(&(addr + i as u64)) {
                return false;
            }
        }
        true
    }

    /// Get the number of concrete bytes stored.
    pub fn concrete_size(&self) -> usize {
        self.concrete.len()
    }

    /// Get the number of symbolic writes.
    pub fn symbolic_writes_count(&self) -> usize {
        self.symbolic_writes.len()
    }

    /// Clone the memory state (for forking).
    pub fn fork(&self) -> Self {
        Self {
            ctx: self.ctx,
            concrete: self.concrete.clone(),
            symbolic_writes: self.symbolic_writes.clone(),
            default_symbolic: self.default_symbolic,
        }
    }

    /// Clear all memory.
    pub fn clear(&mut self) {
        self.concrete.clear();
        self.symbolic_writes.clear();
    }
}

impl<'ctx> std::fmt::Debug for SymMemory<'ctx> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymMemory")
            .field("concrete_bytes", &self.concrete.len())
            .field("symbolic_writes", &self.symbolic_writes.len())
            .field("default_symbolic", &self.default_symbolic)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_concrete_read_write() {
        let ctx = Context::thread_local();
        let mut mem = SymMemory::new(&ctx);

        let addr = SymValue::concrete(0x1000, 64);
        let value = SymValue::concrete(0xDEADBEEF, 32);

        mem.write(&addr, &value, 4);

        let read_value = mem.read(&addr, 4);
        assert_eq!(read_value.as_concrete(), Some(0xDEADBEEF));
    }

    #[test]
    fn test_byte_access() {
        let ctx = Context::thread_local();
        let mut mem = SymMemory::new(&ctx);

        mem.write_bytes(0x1000, &[0x11, 0x22, 0x33, 0x44]);

        let bytes = mem.read_bytes(0x1000, 4).unwrap();
        assert_eq!(bytes, vec![0x11, 0x22, 0x33, 0x44]);

        let addr = SymValue::concrete(0x1000, 64);
        let value = mem.read(&addr, 4);
        assert_eq!(value.as_concrete(), Some(0x44332211)); // Little-endian
    }

    #[test]
    fn test_uninitialized_read() {
        let ctx = Context::thread_local();
        let mem = SymMemory::new(&ctx);

        let addr = SymValue::concrete(0x2000, 64);
        let value = mem.read(&addr, 4);
        // Default is concrete 0
        assert_eq!(value.as_concrete(), Some(0));
    }

    #[test]
    fn test_symbolic_default() {
        let ctx = Context::thread_local();
        let mem = SymMemory::new_symbolic(&ctx);

        let addr = SymValue::concrete(0x2000, 64);
        let value = mem.read(&addr, 4);
        // Default is symbolic
        assert!(value.is_symbolic());
    }
}
