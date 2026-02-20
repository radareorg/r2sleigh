//! Structural validation for r2il types.
//!
//! This module provides lightweight structural invariants for architecture
//! specifications and lifted blocks. The checks are intentionally conservative
//! and avoid deep semantic/type reasoning.

use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::opcode::{R2ILBlock, R2ILOp};
use crate::serialize::ArchSpec;
use crate::{SpaceId, Varnode};

/// A single validation issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationIssue {
    /// Stable machine-readable issue code.
    pub code: &'static str,
    /// Path-like location for the issue.
    pub path: String,
    /// Human-readable description.
    pub message: String,
}

impl ValidationIssue {
    fn new(code: &'static str, path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code,
            path: path.into(),
            message: message.into(),
        }
    }
}

/// Aggregated validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    /// All issues discovered during validation.
    pub issues: Vec<ValidationIssue>,
}

impl ValidationError {
    fn from_issues(issues: Vec<ValidationIssue>) -> Self {
        Self { issues }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "r2il validation failed with {} issue(s):",
            self.issues.len()
        )?;
        for issue in &self.issues {
            writeln!(f, "  - [{}] {}: {}", issue.code, issue.path, issue.message)?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationError {}

/// Validate an architecture specification.
pub fn validate_archspec(arch: &ArchSpec) -> Result<(), ValidationError> {
    let mut issues = Vec::new();

    if arch.name.trim().is_empty() {
        issues.push(ValidationIssue::new(
            "arch.name.empty",
            "arch.name",
            "architecture name must not be empty",
        ));
    }
    if arch.addr_size == 0 {
        issues.push(ValidationIssue::new(
            "arch.addr_size.zero",
            "arch.addr_size",
            "address size must be > 0",
        ));
    }
    if arch.alignment == 0 {
        issues.push(ValidationIssue::new(
            "arch.alignment.zero",
            "arch.alignment",
            "alignment must be > 0",
        ));
    }

    if arch.spaces.is_empty() {
        issues.push(ValidationIssue::new(
            "arch.spaces.empty",
            "arch.spaces",
            "at least one address space is required",
        ));
    }

    let default_count = arch.spaces.iter().filter(|s| s.is_default).count();
    if default_count != 1 {
        issues.push(ValidationIssue::new(
            "arch.spaces.default_count",
            "arch.spaces",
            format!(
                "exactly one default address space is required (found {})",
                default_count
            ),
        ));
    }

    let mut seen_space_ids = HashSet::new();
    let mut seen_space_names = HashSet::new();
    for (i, space) in arch.spaces.iter().enumerate() {
        if !seen_space_ids.insert(space.id) {
            issues.push(ValidationIssue::new(
                "arch.spaces.duplicate_id",
                format!("arch.spaces[{i}].id"),
                format!("duplicate space id '{}'", space.id),
            ));
        }
        if !seen_space_names.insert(space.name.clone()) {
            issues.push(ValidationIssue::new(
                "arch.spaces.duplicate_name",
                format!("arch.spaces[{i}].name"),
                format!("duplicate space name '{}'", space.name),
            ));
        }
    }

    let mut seen_reg_names = HashSet::new();
    let mut reg_by_name = HashMap::new();
    for (i, reg) in arch.registers.iter().enumerate() {
        if reg.size == 0 {
            issues.push(ValidationIssue::new(
                "arch.registers.size.zero",
                format!("arch.registers[{i}].size"),
                "register size must be > 0",
            ));
        }
        if !seen_reg_names.insert(reg.name.clone()) {
            issues.push(ValidationIssue::new(
                "arch.registers.duplicate_name",
                format!("arch.registers[{i}].name"),
                format!("duplicate register name '{}'", reg.name),
            ));
        }
        reg_by_name.insert(reg.name.as_str(), reg.offset);
    }

    for (name, offset) in &arch.register_map {
        match reg_by_name.get(name.as_str()) {
            None => issues.push(ValidationIssue::new(
                "arch.register_map.unknown_register",
                format!("arch.register_map[{name}]"),
                format!("register_map entry references unknown register '{}'", name),
            )),
            Some(reg_offset) if reg_offset != offset => issues.push(ValidationIssue::new(
                "arch.register_map.offset_mismatch",
                format!("arch.register_map[{name}]"),
                format!(
                    "register_map offset {} does not match register offset {}",
                    offset, reg_offset
                ),
            )),
            Some(_) => {}
        }
    }

    for (i, reg) in arch.registers.iter().enumerate() {
        match arch.register_map.get(&reg.name) {
            None => issues.push(ValidationIssue::new(
                "arch.register_map.missing_entry",
                format!("arch.registers[{i}]"),
                format!("missing register_map entry for '{}'", reg.name),
            )),
            Some(offset) if *offset != reg.offset => issues.push(ValidationIssue::new(
                "arch.register_map.offset_mismatch",
                format!("arch.registers[{i}]"),
                format!(
                    "register '{}' offset {} mismatches register_map offset {}",
                    reg.name, reg.offset, offset
                ),
            )),
            Some(_) => {}
        }
    }

    let mut seen_userops = HashSet::new();
    for (i, op) in arch.userops.iter().enumerate() {
        if !seen_userops.insert(op.index) {
            issues.push(ValidationIssue::new(
                "arch.userops.duplicate_index",
                format!("arch.userops[{i}].index"),
                format!("duplicate userop index {}", op.index),
            ));
        }
    }

    if issues.is_empty() {
        Ok(())
    } else {
        Err(ValidationError::from_issues(issues))
    }
}

/// Validate a single operation at a given index.
pub fn validate_op(op: &R2ILOp, op_index: usize) -> Result<(), ValidationError> {
    let mut issues = Vec::new();

    for (input_index, input) in op.inputs().iter().enumerate() {
        validate_varnode(
            &mut issues,
            input,
            format!("block.ops[{op_index}].inputs[{input_index}]"),
            false,
        );
    }

    if let Some(output) = op.output() {
        validate_varnode(
            &mut issues,
            output,
            format!("block.ops[{op_index}].output"),
            true,
        );
    }

    match op {
        R2ILOp::Load { space, .. } if *space == SpaceId::Const => {
            issues.push(ValidationIssue::new(
                "op.load.space_const",
                format!("block.ops[{op_index}].space"),
                "load space must not be const",
            ));
        }
        R2ILOp::Store { space, .. } if *space == SpaceId::Const => {
            issues.push(ValidationIssue::new(
                "op.store.space_const",
                format!("block.ops[{op_index}].space"),
                "store space must not be const",
            ));
        }
        R2ILOp::PtrAdd { element_size, .. } if *element_size == 0 => {
            issues.push(ValidationIssue::new(
                "op.ptradd.element_size_zero",
                format!("block.ops[{op_index}].element_size"),
                "PtrAdd element_size must be > 0",
            ));
        }
        R2ILOp::PtrSub { element_size, .. } if *element_size == 0 => {
            issues.push(ValidationIssue::new(
                "op.ptrsub.element_size_zero",
                format!("block.ops[{op_index}].element_size"),
                "PtrSub element_size must be > 0",
            ));
        }
        R2ILOp::Multiequal { inputs, .. } if inputs.is_empty() => {
            issues.push(ValidationIssue::new(
                "op.multiequal.inputs_empty",
                format!("block.ops[{op_index}].inputs"),
                "Multiequal inputs must not be empty",
            ));
        }
        R2ILOp::CallOther {
            output: Some(output),
            ..
        } if output.space == SpaceId::Const => {
            issues.push(ValidationIssue::new(
                "op.callother.output_const",
                format!("block.ops[{op_index}].output"),
                "CallOther output must not be const space",
            ));
        }
        _ => {}
    }

    if issues.is_empty() {
        Ok(())
    } else {
        Err(ValidationError::from_issues(issues))
    }
}

/// Validate a full lifted block.
pub fn validate_block(block: &R2ILBlock) -> Result<(), ValidationError> {
    let mut issues = Vec::new();

    if block.size == 0 {
        issues.push(ValidationIssue::new(
            "block.size.zero",
            "block.size",
            "block size must be > 0",
        ));
    }

    for (i, op) in block.ops.iter().enumerate() {
        if let Err(err) = validate_op(op, i) {
            issues.extend(err.issues);
        }
    }

    if let Some(sw) = &block.switch_info {
        if sw.min_val > sw.max_val {
            issues.push(ValidationIssue::new(
                "block.switch.range_invalid",
                "block.switch_info",
                format!(
                    "switch min_val ({}) must be <= max_val ({})",
                    sw.min_val, sw.max_val
                ),
            ));
        }

        let mut seen_case_values = HashSet::new();
        for (i, case) in sw.cases.iter().enumerate() {
            if case.value < sw.min_val || case.value > sw.max_val {
                issues.push(ValidationIssue::new(
                    "block.switch.case_out_of_range",
                    format!("block.switch_info.cases[{i}].value"),
                    format!(
                        "case value {} is outside switch range [{}, {}]",
                        case.value, sw.min_val, sw.max_val
                    ),
                ));
            }
            if !seen_case_values.insert(case.value) {
                issues.push(ValidationIssue::new(
                    "block.switch.duplicate_case_value",
                    format!("block.switch_info.cases[{i}].value"),
                    format!("duplicate switch case value {}", case.value),
                ));
            }
        }
    }

    if issues.is_empty() {
        Ok(())
    } else {
        Err(ValidationError::from_issues(issues))
    }
}

fn validate_varnode(
    issues: &mut Vec<ValidationIssue>,
    vn: &Varnode,
    path: String,
    is_output: bool,
) {
    if vn.size == 0 {
        issues.push(ValidationIssue::new(
            "varnode.size.zero",
            format!("{path}.size"),
            "varnode size must be > 0",
        ));
    }
    if is_output && vn.space == SpaceId::Const {
        issues.push(ValidationIssue::new(
            "varnode.output_const_space",
            format!("{path}.space"),
            "output/destination varnode must not be const space",
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcode::{SwitchCase, SwitchInfo};
    use crate::serialize::{RegisterDef, UserOpDef};
    use crate::{AddressSpace, R2ILOp};

    fn valid_archspec() -> ArchSpec {
        let mut arch = ArchSpec::new("test-arch");
        arch.addr_size = 8;
        arch.alignment = 1;
        arch.add_space(AddressSpace::ram(8));
        arch.add_space(AddressSpace::register());
        arch.add_register(RegisterDef::new("RAX", 0, 8));
        arch.userops.push(UserOpDef {
            index: 0,
            name: "u0".to_string(),
        });
        arch
    }

    fn valid_block() -> R2ILBlock {
        let mut block = R2ILBlock::new(0x1000, 1);
        block.push(R2ILOp::Copy {
            dst: Varnode::register(0, 8),
            src: Varnode::constant(1, 8),
        });
        block
    }

    #[test]
    fn valid_minimal_block_passes() {
        let block = valid_block();
        assert!(validate_block(&block).is_ok());
    }

    #[test]
    fn zero_size_varnode_fails() {
        let mut block = R2ILBlock::new(0x1000, 1);
        block.push(R2ILOp::Copy {
            dst: Varnode::register(0, 8),
            src: Varnode::new(SpaceId::Const, 1, 0),
        });
        let err = validate_block(&block).expect_err("block should fail");
        assert!(err.issues.iter().any(|i| i.code == "varnode.size.zero"));
    }

    #[test]
    fn const_space_destination_fails() {
        let mut block = R2ILBlock::new(0x1000, 1);
        block.push(R2ILOp::Copy {
            dst: Varnode::new(SpaceId::Const, 0, 8),
            src: Varnode::register(0, 8),
        });
        let err = validate_block(&block).expect_err("block should fail");
        assert!(
            err.issues
                .iter()
                .any(|i| i.code == "varnode.output_const_space")
        );
    }

    #[test]
    fn invalid_load_store_space_fails() {
        let mut block = R2ILBlock::new(0x1000, 1);
        block.push(R2ILOp::Load {
            dst: Varnode::register(0, 8),
            space: SpaceId::Const,
            addr: Varnode::ram(0x2000, 8),
        });
        block.push(R2ILOp::Store {
            space: SpaceId::Const,
            addr: Varnode::ram(0x2000, 8),
            val: Varnode::register(0, 8),
        });
        let err = validate_block(&block).expect_err("block should fail");
        assert!(err.issues.iter().any(|i| i.code == "op.load.space_const"));
        assert!(err.issues.iter().any(|i| i.code == "op.store.space_const"));
    }

    #[test]
    fn zero_element_size_in_ptr_ops_fails() {
        let mut block = R2ILBlock::new(0x1000, 1);
        block.push(R2ILOp::PtrAdd {
            dst: Varnode::register(0, 8),
            base: Varnode::register(8, 8),
            index: Varnode::register(16, 8),
            element_size: 0,
        });
        block.push(R2ILOp::PtrSub {
            dst: Varnode::register(0, 8),
            base: Varnode::register(8, 8),
            index: Varnode::register(16, 8),
            element_size: 0,
        });
        let err = validate_block(&block).expect_err("block should fail");
        assert!(
            err.issues
                .iter()
                .any(|i| i.code == "op.ptradd.element_size_zero")
        );
        assert!(
            err.issues
                .iter()
                .any(|i| i.code == "op.ptrsub.element_size_zero")
        );
    }

    #[test]
    fn multiequal_inputs_empty_fails() {
        let mut block = R2ILBlock::new(0x1000, 1);
        block.push(R2ILOp::Multiequal {
            dst: Varnode::register(0, 8),
            inputs: Vec::new(),
        });
        let err = validate_block(&block).expect_err("block should fail");
        assert!(
            err.issues
                .iter()
                .any(|i| i.code == "op.multiequal.inputs_empty")
        );
    }

    #[test]
    fn callother_output_const_fails() {
        let mut block = R2ILBlock::new(0x1000, 1);
        block.push(R2ILOp::CallOther {
            output: Some(Varnode::new(SpaceId::Const, 0, 8)),
            userop: 1,
            inputs: vec![Varnode::register(0, 8)],
        });
        let err = validate_block(&block).expect_err("block should fail");
        assert!(
            err.issues
                .iter()
                .any(|i| i.code == "op.callother.output_const")
        );
    }

    #[test]
    fn invalid_switch_metadata_fails() {
        let mut block = valid_block();
        block.switch_info = Some(SwitchInfo {
            switch_addr: 0x1000,
            min_val: 10,
            max_val: 5,
            default_target: Some(0x1200),
            cases: vec![
                SwitchCase {
                    value: 11,
                    target: 0x1300,
                },
                SwitchCase {
                    value: 11,
                    target: 0x1400,
                },
            ],
        });

        let err = validate_block(&block).expect_err("block should fail");
        assert!(
            err.issues
                .iter()
                .any(|i| i.code == "block.switch.range_invalid")
        );
        assert!(
            err.issues
                .iter()
                .any(|i| i.code == "block.switch.case_out_of_range")
        );
        assert!(
            err.issues
                .iter()
                .any(|i| i.code == "block.switch.duplicate_case_value")
        );
    }

    #[test]
    fn invalid_archspec_duplicate_default_and_register_map_mismatch_fails() {
        let mut arch = valid_archspec();

        arch.spaces.push(AddressSpace::new(SpaceId::Ram, "ram2", 8));
        if let Some(space) = arch.spaces.last_mut() {
            space.is_default = true;
        }

        arch.registers.push(RegisterDef::new("RAX", 8, 8));
        arch.register_map.insert("RAX".to_string(), 0xdeadbeef);
        arch.register_map.insert("MISSING".to_string(), 0x10);
        arch.userops.push(UserOpDef {
            index: 0,
            name: "u0_duplicate".to_string(),
        });

        let err = validate_archspec(&arch).expect_err("arch should fail");
        assert!(
            err.issues
                .iter()
                .any(|i| i.code == "arch.spaces.default_count")
        );
        assert!(
            err.issues
                .iter()
                .any(|i| i.code == "arch.registers.duplicate_name")
        );
        assert!(
            err.issues
                .iter()
                .any(|i| i.code == "arch.register_map.offset_mismatch")
        );
        assert!(
            err.issues
                .iter()
                .any(|i| i.code == "arch.register_map.unknown_register")
        );
        assert!(
            err.issues
                .iter()
                .any(|i| i.code == "arch.userops.duplicate_index")
        );
    }
}
