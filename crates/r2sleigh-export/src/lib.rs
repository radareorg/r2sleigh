//! Unified instruction export pipeline for r2sleigh.

use std::collections::HashSet;
use std::fmt;

use r2dec::{CStmt, CodeGenConfig, CodeGenerator, lower_ssa_ops_to_stmts};
use r2il::{ArchSpec, R2ILBlock, R2ILOp, SpaceId, Varnode, validate_block_full};
use r2sleigh_lift::{Disassembler, format_op, op_to_esil_named};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionAction {
    Lift,
    Ssa,
    Defuse,
    Dec,
}

impl InstructionAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lift => "lift",
            Self::Ssa => "ssa",
            Self::Defuse => "defuse",
            Self::Dec => "dec",
        }
    }
}

impl fmt::Display for InstructionAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Text,
    Esil,
    CLike,
    R2Cmd,
}

impl ExportFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Text => "text",
            Self::Esil => "esil",
            Self::CLike => "c_like",
            Self::R2Cmd => "r2cmd",
        }
    }
}

impl fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub struct InstructionExportInput<'a> {
    pub disasm: &'a Disassembler,
    pub arch: &'a ArchSpec,
    pub block: &'a R2ILBlock,
    pub addr: u64,
    pub mnemonic: &'a str,
    pub native_size: usize,
}

#[derive(Debug, Error)]
pub enum ExportError {
    #[error(
        "unsupported action/format combination: action={action} format={format}. Supported formats for {action}: {supported}"
    )]
    UnsupportedCombination {
        action: InstructionAction,
        format: ExportFormat,
        supported: String,
    },
    #[error("validation failed: {0}")]
    ValidationFailed(String),
    #[error("serialization failed: {0}")]
    SerializeError(String),
    #[error("render failed: {0}")]
    RenderError(String),
}

pub fn export_instruction(
    input: &InstructionExportInput<'_>,
    action: InstructionAction,
    format: ExportFormat,
) -> Result<String, ExportError> {
    validate_block_full(input.block, input.arch)
        .map_err(|e| ExportError::ValidationFailed(e.to_string()))?;
    ensure_supported(action, format)?;

    match action {
        InstructionAction::Lift => export_lift(input, format),
        InstructionAction::Ssa => export_ssa(input, format),
        InstructionAction::Defuse => export_defuse(input, format),
        InstructionAction::Dec => export_dec(input, format),
    }
}

pub fn op_json_named(disasm: &Disassembler, op: &R2ILOp) -> Result<String, ExportError> {
    let mut value =
        serde_json::to_value(op).map_err(|e| ExportError::SerializeError(e.to_string()))?;
    annotate_register_names(&mut value, disasm);
    annotate_userop_names(&mut value, disasm);
    serde_json::to_string(&value).map_err(|e| ExportError::SerializeError(e.to_string()))
}

fn ensure_supported(action: InstructionAction, format: ExportFormat) -> Result<(), ExportError> {
    let supported = supported_formats(action);
    if supported.contains(&format) {
        return Ok(());
    }
    let supported = supported
        .iter()
        .map(|f| f.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    Err(ExportError::UnsupportedCombination {
        action,
        format,
        supported,
    })
}

fn supported_formats(action: InstructionAction) -> &'static [ExportFormat] {
    use ExportFormat::*;
    match action {
        InstructionAction::Lift => &[Json, Text, Esil, R2Cmd],
        InstructionAction::Ssa => &[Json, Text],
        InstructionAction::Defuse => &[Json, Text],
        InstructionAction::Dec => &[CLike, Json, Text],
    }
}

fn export_lift(
    input: &InstructionExportInput<'_>,
    format: ExportFormat,
) -> Result<String, ExportError> {
    match format {
        ExportFormat::Json => {
            let value = lift_json_value(input)?;
            serde_json::to_string_pretty(&value)
                .map_err(|e| ExportError::SerializeError(e.to_string()))
        }
        ExportFormat::Text => {
            let mut out = format!(
                "0x{:x}  {}  (size={})\nP-code ({} ops):",
                input.addr,
                input.mnemonic,
                input.native_size,
                input.block.ops.len()
            );
            for (i, op) in input.block.ops.iter().enumerate() {
                out.push_str(&format!("\n  {}: {}", i, format_op(input.disasm, op)));
            }
            Ok(out)
        }
        ExportFormat::Esil => {
            let lines = input
                .block
                .ops
                .iter()
                .map(|op| op_to_esil_named(input.disasm, op))
                .collect::<Vec<_>>();
            Ok(lines.join("\n"))
        }
        ExportFormat::R2Cmd => {
            let mut out = Vec::new();
            for (idx, op) in input.block.ops.iter().enumerate() {
                let op_json = op_json_named(input.disasm, op)?;
                let op_value: Value = serde_json::from_str(&op_json)
                    .map_err(|e| ExportError::SerializeError(e.to_string()))?;

                let op_name =
                    op_name_from_value(&op_value).unwrap_or_else(|| "unknown".to_string());
                let mut sidecar = serde_json::Map::new();
                sidecar.insert("op_index".to_string(), serde_json::json!(idx));
                sidecar.insert("op".to_string(), Value::String(op_name));
                sidecar.insert("op_json".to_string(), op_value);
                if let Some(meta) = input.block.op_metadata.get(&idx) {
                    sidecar.insert(
                        "meta".to_string(),
                        serde_json::to_value(meta)
                            .map_err(|e| ExportError::SerializeError(e.to_string()))?,
                    );
                }
                out.push(format!("# {}", Value::Object(sidecar)));
                out.push(format!("ae {}", op_to_esil_named(input.disasm, op)));
            }
            Ok(out.join("\n"))
        }
        ExportFormat::CLike => Err(ExportError::UnsupportedCombination {
            action: InstructionAction::Lift,
            format,
            supported: "json, text, esil, r2cmd".to_string(),
        }),
    }
}

fn lift_json_value(input: &InstructionExportInput<'_>) -> Result<Value, ExportError> {
    let mut ops = Vec::new();
    for op in &input.block.ops {
        let op_json = op_json_named(input.disasm, op)?;
        let op_value: Value = serde_json::from_str(&op_json)
            .map_err(|e| ExportError::SerializeError(e.to_string()))?;
        ops.push(op_value);
    }

    let mut out = serde_json::json!({
        "addr": format!("0x{:x}", input.block.addr),
        "size": input.native_size,
        "mnemonic": input.mnemonic,
        "ops": ops,
    });
    if !input.block.op_metadata.is_empty() {
        out["op_metadata"] = serde_json::to_value(&input.block.op_metadata)
            .map_err(|e| ExportError::SerializeError(e.to_string()))?;
    }
    Ok(out)
}

fn export_ssa(
    input: &InstructionExportInput<'_>,
    format: ExportFormat,
) -> Result<String, ExportError> {
    let ssa_block = r2ssa::block::to_ssa(input.block, input.disasm);
    let ops_info: Vec<SSAOpInfo> = ssa_block.ops.iter().map(ssa_op_to_info).collect();

    match format {
        ExportFormat::Json => serde_json::to_string_pretty(&ops_info)
            .map_err(|e| ExportError::SerializeError(e.to_string())),
        ExportFormat::Text => {
            let mut lines = Vec::new();
            for (idx, info) in ops_info.iter().enumerate() {
                let dst = info.dst.as_deref().unwrap_or("-");
                let sources = if info.sources.is_empty() {
                    String::new()
                } else {
                    info.sources.join(", ")
                };
                lines.push(format!(
                    "{}: {} dst={} src=[{}]",
                    idx, info.op, dst, sources
                ));
            }
            Ok(lines.join("\n"))
        }
        _ => Err(ExportError::UnsupportedCombination {
            action: InstructionAction::Ssa,
            format,
            supported: "json, text".to_string(),
        }),
    }
}

fn export_defuse(
    input: &InstructionExportInput<'_>,
    format: ExportFormat,
) -> Result<String, ExportError> {
    let ssa_block = r2ssa::block::to_ssa(input.block, input.disasm);
    let info = r2ssa::def_use(&ssa_block);
    let json_info = DefUseInfoJson {
        inputs: sorted_set(&info.inputs),
        outputs: sorted_set(&info.outputs),
        live: sorted_set(&info.live),
    };

    match format {
        ExportFormat::Json => serde_json::to_string_pretty(&json_info)
            .map_err(|e| ExportError::SerializeError(e.to_string())),
        ExportFormat::Text => Ok(format!(
            "inputs: {}\noutputs: {}\nlive: {}",
            json_info.inputs.join(", "),
            json_info.outputs.join(", "),
            json_info.live.join(", ")
        )),
        _ => Err(ExportError::UnsupportedCombination {
            action: InstructionAction::Defuse,
            format,
            supported: "json, text".to_string(),
        }),
    }
}

fn export_dec(
    input: &InstructionExportInput<'_>,
    format: ExportFormat,
) -> Result<String, ExportError> {
    let ssa_block = r2ssa::block::to_ssa(input.block, input.disasm);
    let ptr_size = input.arch.addr_size.saturating_mul(8);
    let stmts: Vec<CStmt> = lower_ssa_ops_to_stmts(ptr_size, &ssa_block.ops);

    match format {
        ExportFormat::Json => serde_json::to_string_pretty(&stmts)
            .map_err(|e| ExportError::SerializeError(e.to_string())),
        ExportFormat::Text | ExportFormat::CLike => {
            let mut codegen = CodeGenerator::new(CodeGenConfig::default());
            let mut output = String::new();
            for stmt in &stmts {
                output.push_str(&codegen.generate_stmt(stmt));
                output.push('\n');
            }
            Ok(output.trim_end_matches('\n').to_string())
        }
        _ => Err(ExportError::UnsupportedCombination {
            action: InstructionAction::Dec,
            format,
            supported: "c_like, json, text".to_string(),
        }),
    }
}

fn sorted_set(values: &HashSet<String>) -> Vec<String> {
    let mut out: Vec<String> = values.iter().cloned().collect();
    out.sort();
    out
}

fn annotate_register_names(value: &mut Value, disasm: &Disassembler) {
    match value {
        Value::Object(map) => {
            let is_varnode =
                map.contains_key("space") && map.contains_key("offset") && map.contains_key("size");
            if is_varnode {
                let space = map.get("space").and_then(Value::as_str);
                if let Some(space_str) = space
                    && space_str.eq_ignore_ascii_case("register")
                {
                    let offset = map.get("offset").and_then(Value::as_u64);
                    let size = map.get("size").and_then(Value::as_u64);
                    if let (Some(offset), Some(size)) = (offset, size)
                        && let Ok(size32) = u32::try_from(size)
                    {
                        let vn = Varnode {
                            space: SpaceId::Register,
                            offset,
                            size: size32,
                            meta: None,
                        };
                        if let Some(name) = disasm.register_name(&vn) {
                            map.insert("name".to_string(), Value::String(name));
                        }
                    }
                }
            }

            for value in map.values_mut() {
                annotate_register_names(value, disasm);
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                annotate_register_names(item, disasm);
            }
        }
        _ => {}
    }
}

fn annotate_userop_names(value: &mut Value, disasm: &Disassembler) {
    match value {
        Value::Object(map) => {
            if let Some(callother) = map.get_mut("CallOther")
                && let Value::Object(call_map) = callother
            {
                let userop = call_map.get("userop").and_then(Value::as_u64);
                if let Some(userop) = userop
                    && let Some(name) = disasm.userop_name(userop as u32)
                {
                    call_map.insert("userop_name".to_string(), Value::String(name.to_string()));
                }
            }

            for value in map.values_mut() {
                annotate_userop_names(value, disasm);
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                annotate_userop_names(item, disasm);
            }
        }
        _ => {}
    }
}

fn op_name_from_value(value: &Value) -> Option<String> {
    let map = value.as_object()?;
    map.keys().next().cloned()
}

#[derive(Serialize)]
struct SSAOpInfo {
    op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    dst: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sources: Vec<String>,
}

fn ssa_op_to_info(op: &r2ssa::SSAOp) -> SSAOpInfo {
    let op_name = serde_json::to_value(op)
        .ok()
        .and_then(|v| op_name_from_value(&v))
        .unwrap_or_else(|| "Unknown".to_string());
    SSAOpInfo {
        op: op_name,
        dst: op.dst().map(|v| v.display_name()),
        sources: op.sources().iter().map(|v| v.display_name()).collect(),
    }
}

#[derive(Serialize)]
struct DefUseInfoJson {
    inputs: Vec<String>,
    outputs: Vec<String>,
    live: Vec<String>,
}

#[cfg(all(test, feature = "x86"))]
mod tests {
    use super::*;
    use r2il::{MemoryClass, OpMetadata, ScalarKind, VarnodeMetadata};
    use r2sleigh_lift::{build_arch_spec, userop_map_for_arch};

    fn x86_disasm_and_spec() -> (Disassembler, ArchSpec) {
        let spec = build_arch_spec(
            sleigh_config::processor_x86::SLA_X86_64,
            sleigh_config::processor_x86::PSPEC_X86_64,
            "x86-64",
        )
        .expect("arch spec");
        let mut disasm = Disassembler::from_sla(
            sleigh_config::processor_x86::SLA_X86_64,
            sleigh_config::processor_x86::PSPEC_X86_64,
            "x86-64",
        )
        .expect("disasm");
        disasm.set_userop_map(userop_map_for_arch("x86-64"));
        (disasm, spec)
    }

    fn lift_input(bytes_hex: &str, addr: u64) -> InstructionExportInput<'static> {
        let (disasm, spec) = x86_disasm_and_spec();
        let bytes = hex::decode(bytes_hex).expect("hex");
        let block = disasm.lift(&bytes, addr).expect("lift");
        let (mnemonic, native_size) = disasm.disasm_native(&bytes, addr).expect("disasm");

        let disasm = Box::leak(Box::new(disasm));
        let spec = Box::leak(Box::new(spec));
        let block = Box::leak(Box::new(block));
        let mnemonic = Box::leak(Box::new(mnemonic));

        InstructionExportInput {
            disasm,
            arch: spec,
            block,
            addr,
            mnemonic,
            native_size,
        }
    }

    #[test]
    fn lift_json_includes_op_and_varnode_metadata() {
        let (disasm, spec) = x86_disasm_and_spec();
        let mut block = R2ILBlock::new(0x1000, 1);
        let vn_meta = VarnodeMetadata {
            scalar_kind: Some(ScalarKind::UnsignedInt),
            ..Default::default()
        };
        block.push_with_metadata(
            R2ILOp::Copy {
                dst: Varnode::register(0, 8).with_meta(vn_meta),
                src: Varnode::constant(1, 8),
            },
            Some(OpMetadata {
                memory_class: Some(MemoryClass::Stack),
                endianness: None,
                memory_ordering: None,
                permissions: None,
                valid_range: None,
                bank_id: None,
                segment_id: None,
                atomic_kind: None,
            }),
        );
        let input = InstructionExportInput {
            disasm: &disasm,
            arch: &spec,
            block: &block,
            addr: 0x1000,
            mnemonic: "mov",
            native_size: 1,
        };

        let out = export_instruction(&input, InstructionAction::Lift, ExportFormat::Json)
            .expect("lift json");
        let parsed: Value = serde_json::from_str(&out).expect("json");

        assert!(parsed.get("op_metadata").is_some(), "expected op metadata");
        assert!(
            parsed.to_string().contains("\"meta\""),
            "expected varnode metadata in output: {}",
            parsed
        );
    }

    #[test]
    fn lift_r2cmd_emits_comment_then_ae_per_op() {
        let input = lift_input("31c00000000000000000000000000000", 0x1000);
        let out = export_instruction(&input, InstructionAction::Lift, ExportFormat::R2Cmd)
            .expect("lift r2cmd");
        let lines: Vec<&str> = out.lines().collect();
        assert!(!lines.is_empty(), "expected output lines");
        assert!(
            lines[0].starts_with("# "),
            "first line must be sidecar comment"
        );
        assert!(
            lines.get(1).is_some_and(|l| l.starts_with("ae ")),
            "second line must be an ae replay line"
        );
    }

    #[test]
    fn ssa_json_is_valid_and_nonempty() {
        let input = lift_input("31c00000000000000000000000000000", 0x1000);
        let out = export_instruction(&input, InstructionAction::Ssa, ExportFormat::Json)
            .expect("ssa json");
        let parsed: Value = serde_json::from_str(&out).expect("json");
        let arr = parsed.as_array().expect("array");
        assert!(!arr.is_empty(), "expected non-empty ssa ops");
    }

    #[test]
    fn defuse_json_contains_inputs_outputs_live() {
        let input = lift_input("31c00000000000000000000000000000", 0x1000);
        let out = export_instruction(&input, InstructionAction::Defuse, ExportFormat::Json)
            .expect("defuse json");
        let parsed: Value = serde_json::from_str(&out).expect("json");
        assert!(parsed.get("inputs").is_some());
        assert!(parsed.get("outputs").is_some());
        assert!(parsed.get("live").is_some());
    }

    #[test]
    fn dec_c_like_nonempty_for_simple_block() {
        let input = lift_input("31c00000000000000000000000000000", 0x1000);
        let out = export_instruction(&input, InstructionAction::Dec, ExportFormat::CLike)
            .expect("dec c-like");
        assert!(!out.trim().is_empty(), "expected non-empty c-like output");
    }

    #[test]
    fn unsupported_combo_returns_error() {
        let input = lift_input("31c00000000000000000000000000000", 0x1000);
        let err = export_instruction(&input, InstructionAction::Ssa, ExportFormat::Esil)
            .expect_err("unsupported combo must fail");
        assert!(
            matches!(err, ExportError::UnsupportedCombination { .. }),
            "unexpected error kind: {}",
            err
        );
    }

    #[test]
    fn validation_failure_propagates() {
        let (disasm, arch) = x86_disasm_and_spec();
        let mut block = R2ILBlock::new(0x1000, 1);
        block.push(R2ILOp::Copy {
            dst: Varnode::register(0, 8),
            src: Varnode::register(8, 4),
        });

        let input = InstructionExportInput {
            disasm: &disasm,
            arch: &arch,
            block: &block,
            addr: 0x1000,
            mnemonic: "copy",
            native_size: 1,
        };

        let err = export_instruction(&input, InstructionAction::Lift, ExportFormat::Json)
            .expect_err("invalid block must fail");
        assert!(
            matches!(err, ExportError::ValidationFailed(_)),
            "unexpected error kind: {}",
            err
        );
    }
}
