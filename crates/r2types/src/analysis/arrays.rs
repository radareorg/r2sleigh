//! Which accesses certify an array, and what its elements are.

use super::*;

pub(crate) struct ScalarArrayMachineProfile<'a> {
    pub(crate) architecture: r2ssa::MachineArchitectureFamily,
    pub(crate) pointer_arg_slots: Option<&'a HashMap<String, usize>>,
    pub(crate) ptr_bits: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScalarPointerValue {
    pub(crate) slot: usize,
    pub(crate) base: ArrayIndexBase,
    pub(crate) element_stride: u64,
    pub(crate) confidence: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScalarArrayAddrExpr {
    pub(crate) pointer: ScalarPointerValue,
    pub(crate) field_offset: u64,
    pub(crate) confidence: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ScalarArrayAccessCertificates {
    pub(crate) array_index: Vec<ArrayIndexCertificate>,
    pub(crate) field_access: Vec<crate::FieldAccessCertificate>,
    pub(crate) render_candidates: Vec<ScalarArrayRenderCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternalLayoutFieldAccess {
    pub(crate) name: String,
    pub(crate) ty: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AffineIndexFactor {
    pub(crate) root: Option<String>,
    pub(crate) scale: i128,
}

pub(crate) struct ScalarArrayInferenceCtx<'a> {
    pub(crate) parsed_context: &'a ParsedExternalContext,
    pub(crate) type_db: &'a ExternalTypeDb,
    pub(crate) merged_signature: Option<&'a FunctionSignatureSpec>,
    pub(crate) ptr_bits: u32,
    pub(crate) pointer_arg_slot_map: &'a HashMap<String, usize>,
    pub(crate) local_element_strides: &'a HashMap<usize, u64>,
    pub(crate) pointer_values: &'a HashMap<String, ScalarPointerValue>,
    pub(crate) pointer_value_names: &'a HashMap<String, Option<ScalarPointerValue>>,
    pub(crate) array_addr_exprs: &'a HashMap<String, ScalarArrayAddrExpr>,
    pub(crate) array_addr_expr_names: &'a HashMap<String, Option<ScalarArrayAddrExpr>>,
    pub(crate) stack_addr_offsets: &'a HashMap<String, i64>,
    pub(crate) stack_addr_offset_names: &'a HashMap<String, Option<i64>>,
    pub(crate) block_ops: &'a HashMap<u64, HashMap<String, SSAOp>>,
    pub(crate) value_ops: &'a HashMap<String, SSAOp>,
}

pub(crate) fn collect_pointer_arg_slot_map(
    architecture: r2ssa::MachineArchitectureFamily,
    ptr_bits: u32,
) -> HashMap<String, usize> {
    let (arg_regs, _, _) = recover_vars_arch_profile(architecture);
    let is_arm64 = matches!(architecture, r2ssa::MachineArchitectureFamily::AArch64);
    let is_x86_64 = matches!(architecture, r2ssa::MachineArchitectureFamily::X86_64);
    let is_riscv64 = matches!(architecture, r2ssa::MachineArchitectureFamily::RiscV64);

    let mut out = HashMap::new();
    for (idx, (canonical, aliases)) in arg_regs.iter().enumerate() {
        let include_alias = |alias: &str| -> bool {
            if ptr_bits <= 32 {
                return true;
            }
            let alias = alias.to_ascii_lowercase();
            if is_arm64 {
                return alias.starts_with('x');
            }
            if is_x86_64 {
                return alias.starts_with('r');
            }
            if is_riscv64 {
                return alias.starts_with('x') || alias.starts_with('a');
            }
            alias == (*canonical).to_ascii_lowercase()
        };

        if include_alias(canonical) {
            out.insert((*canonical).to_string(), idx);
        }
        for alias in *aliases {
            if include_alias(alias) {
                out.insert((*alias).to_string(), idx);
            }
        }
    }
    out
}

pub(crate) fn scalar_array_access_certificates_from_ssa(
    ssa_blocks: &[SSABlock],
    parsed_context: &ParsedExternalContext,
    type_db: &ExternalTypeDb,
    merged_signature: Option<&FunctionSignatureSpec>,
    local_element_strides: &HashMap<usize, u64>,
    machine: ScalarArrayMachineProfile<'_>,
) -> ScalarArrayAccessCertificates {
    let architecture = machine.architecture;
    let detached_pointer_arg_slots;
    let pointer_arg_slot_map = match machine.pointer_arg_slots {
        Some(slots) => slots,
        None => {
            detached_pointer_arg_slots =
                collect_pointer_arg_slot_map(architecture, machine.ptr_bits);
            &detached_pointer_arg_slots
        }
    };
    let (_, stack_bases, frame_bases) = recover_vars_arch_profile(architecture);
    let ptr_bits = machine.ptr_bits;
    let mut stack_addr_offsets: HashMap<String, i64> = HashMap::new();
    let mut stack_addr_offset_names: HashMap<String, Option<i64>> = HashMap::new();
    let mut pointer_values: HashMap<String, ScalarPointerValue> = HashMap::new();
    let mut pointer_value_names: HashMap<String, Option<ScalarPointerValue>> = HashMap::new();
    let mut array_addr_exprs: HashMap<String, ScalarArrayAddrExpr> = HashMap::new();
    let mut array_addr_expr_names: HashMap<String, Option<ScalarArrayAddrExpr>> = HashMap::new();
    let mut certificates = ScalarArrayAccessCertificates::default();

    let block_ops: HashMap<u64, HashMap<String, SSAOp>> = ssa_blocks
        .iter()
        .map(|block| {
            let ops = block
                .ops
                .iter()
                .filter_map(|op| {
                    op.dst()
                        .map(|dst| (ssa_var_block_key(block.addr, dst), op.clone()))
                })
                .collect::<HashMap<_, _>>();
            (block.addr, ops)
        })
        .collect();
    let value_ops: HashMap<String, SSAOp> = ssa_blocks
        .iter()
        .flat_map(|block| {
            block
                .ops
                .iter()
                .filter_map(|op| op.dst().map(|dst| (dst.display_name(), op.clone())))
        })
        .collect();

    let is_stack_base = |name: &str| stack_bases.contains(&name) || frame_bases.contains(&name);

    for _ in 0..6 {
        let mut changed = false;
        for block in ssa_blocks {
            for op in &block.ops {
                match op {
                    SSAOp::Copy { dst, src }
                    | SSAOp::Cast { dst, src }
                    | SSAOp::New { dst, src }
                    | SSAOp::IntZExt { dst, src }
                    | SSAOp::IntSExt { dst, src }
                    | SSAOp::Trunc { dst, src }
                    | SSAOp::Subpiece { dst, src, .. } => {
                        let ctx = ScalarArrayInferenceCtx {
                            parsed_context,
                            type_db,
                            merged_signature,
                            ptr_bits,
                            pointer_arg_slot_map,
                            local_element_strides,
                            pointer_values: &pointer_values,
                            pointer_value_names: &pointer_value_names,
                            array_addr_exprs: &array_addr_exprs,
                            array_addr_expr_names: &array_addr_expr_names,
                            stack_addr_offsets: &stack_addr_offsets,
                            stack_addr_offset_names: &stack_addr_offset_names,
                            block_ops: &block_ops,
                            value_ops: &value_ops,
                        };
                        if let Some(mut pointer) =
                            scalar_pointer_value_for_var(block.addr, src, &ctx)
                        {
                            pointer.confidence = pointer.confidence.saturating_sub(2);
                            changed |= set_scalar_pointer_value(
                                block.addr,
                                dst,
                                pointer,
                                &mut pointer_values,
                                &mut pointer_value_names,
                            );
                        }
                        if let Some(mut expr) = scalar_array_addr_expr_for_var(
                            block.addr,
                            src,
                            &array_addr_exprs,
                            &array_addr_expr_names,
                        ) {
                            expr.confidence = expr.confidence.saturating_sub(2);
                            changed |= set_scalar_array_addr_expr(
                                block.addr,
                                dst,
                                expr,
                                &mut array_addr_exprs,
                                &mut array_addr_expr_names,
                            );
                        }
                        if let Some(offset) = stack_addr_offset_for_var(
                            block.addr,
                            src,
                            &stack_addr_offsets,
                            &stack_addr_offset_names,
                        ) {
                            changed |= set_stack_addr_offset(
                                block.addr,
                                dst,
                                offset,
                                &mut stack_addr_offsets,
                                &mut stack_addr_offset_names,
                            );
                        }
                    }
                    SSAOp::Phi { dst, sources } => {
                        let ctx = ScalarArrayInferenceCtx {
                            parsed_context,
                            type_db,
                            merged_signature,
                            ptr_bits,
                            pointer_arg_slot_map,
                            local_element_strides,
                            pointer_values: &pointer_values,
                            pointer_value_names: &pointer_value_names,
                            array_addr_exprs: &array_addr_exprs,
                            array_addr_expr_names: &array_addr_expr_names,
                            stack_addr_offsets: &stack_addr_offsets,
                            stack_addr_offset_names: &stack_addr_offset_names,
                            block_ops: &block_ops,
                            value_ops: &value_ops,
                        };
                        if let Some(mut pointer) =
                            phi_scalar_pointer_value(block.addr, dst, sources, &ctx)
                        {
                            pointer.confidence = pointer.confidence.saturating_sub(3);
                            changed |= set_scalar_pointer_value(
                                block.addr,
                                dst,
                                pointer,
                                &mut pointer_values,
                                &mut pointer_value_names,
                            );
                        }
                        if let Some(mut expr) = phi_scalar_array_addr_expr(
                            block.addr,
                            sources,
                            &array_addr_exprs,
                            &array_addr_expr_names,
                        ) {
                            expr.confidence = expr.confidence.saturating_sub(3);
                            changed |= set_scalar_array_addr_expr(
                                block.addr,
                                dst,
                                expr,
                                &mut array_addr_exprs,
                                &mut array_addr_expr_names,
                            );
                        }
                    }
                    SSAOp::IntAdd { dst, a, b } => {
                        if let Some(off) = exact_ssa_const_offset(b, ptr_bits)
                            && is_stack_base(a.name().to_ascii_lowercase().as_str())
                        {
                            changed |= set_stack_addr_offset(
                                block.addr,
                                dst,
                                off,
                                &mut stack_addr_offsets,
                                &mut stack_addr_offset_names,
                            );
                        }
                        if let Some(off) = exact_ssa_const_offset(a, ptr_bits)
                            && is_stack_base(b.name().to_ascii_lowercase().as_str())
                        {
                            changed |= set_stack_addr_offset(
                                block.addr,
                                dst,
                                off,
                                &mut stack_addr_offsets,
                                &mut stack_addr_offset_names,
                            );
                        }
                        let expr = {
                            let ctx = ScalarArrayInferenceCtx {
                                parsed_context,
                                type_db,
                                merged_signature,
                                ptr_bits,
                                pointer_arg_slot_map,
                                local_element_strides,
                                pointer_values: &pointer_values,
                                pointer_value_names: &pointer_value_names,
                                array_addr_exprs: &array_addr_exprs,
                                array_addr_expr_names: &array_addr_expr_names,
                                stack_addr_offsets: &stack_addr_offsets,
                                stack_addr_offset_names: &stack_addr_offset_names,
                                block_ops: &block_ops,
                                value_ops: &value_ops,
                            };
                            scalar_array_expr_for_addend_pair(block.addr, a, b, &ctx)
                        };
                        if let Some(expr) = expr {
                            changed |= set_scalar_array_addr_expr(
                                block.addr,
                                dst,
                                expr,
                                &mut array_addr_exprs,
                                &mut array_addr_expr_names,
                            );
                        }
                        let pointer = {
                            let ctx = ScalarArrayInferenceCtx {
                                parsed_context,
                                type_db,
                                merged_signature,
                                ptr_bits,
                                pointer_arg_slot_map,
                                local_element_strides,
                                pointer_values: &pointer_values,
                                pointer_value_names: &pointer_value_names,
                                array_addr_exprs: &array_addr_exprs,
                                array_addr_expr_names: &array_addr_expr_names,
                                stack_addr_offsets: &stack_addr_offsets,
                                stack_addr_offset_names: &stack_addr_offset_names,
                                block_ops: &block_ops,
                                value_ops: &value_ops,
                            };
                            scalar_pointer_plus_const(block.addr, a, b, &ctx)
                                .or_else(|| scalar_pointer_plus_const(block.addr, b, a, &ctx))
                        };
                        if let Some(pointer) = pointer {
                            changed |= set_scalar_pointer_value(
                                block.addr,
                                dst,
                                pointer,
                                &mut pointer_values,
                                &mut pointer_value_names,
                            );
                        }
                    }
                    SSAOp::IntSub { dst, a, b } => {
                        if let Some(delta) = exact_ssa_const_offset(b, ptr_bits)
                            && is_stack_base(a.name().to_ascii_lowercase().as_str())
                        {
                            changed |= set_stack_addr_offset(
                                block.addr,
                                dst,
                                delta.saturating_neg(),
                                &mut stack_addr_offsets,
                                &mut stack_addr_offset_names,
                            );
                        }
                        let pointer_expr = {
                            let ctx = ScalarArrayInferenceCtx {
                                parsed_context,
                                type_db,
                                merged_signature,
                                ptr_bits,
                                pointer_arg_slot_map,
                                local_element_strides,
                                pointer_values: &pointer_values,
                                pointer_value_names: &pointer_value_names,
                                array_addr_exprs: &array_addr_exprs,
                                array_addr_expr_names: &array_addr_expr_names,
                                stack_addr_offsets: &stack_addr_offsets,
                                stack_addr_offset_names: &stack_addr_offset_names,
                                block_ops: &block_ops,
                                value_ops: &value_ops,
                            };
                            scalar_pointer_value_for_var(block.addr, a, &ctx).filter(|pointer| {
                                scalar_index_matches_stride(
                                    block.addr,
                                    b,
                                    pointer.element_stride,
                                    &ctx,
                                    0,
                                )
                            })
                        };
                        if let Some(pointer) = pointer_expr {
                            let expr = ScalarArrayAddrExpr {
                                confidence: pointer.confidence.saturating_sub(4),
                                pointer,
                                field_offset: 0,
                            };
                            changed |= set_scalar_array_addr_expr(
                                block.addr,
                                dst,
                                expr,
                                &mut array_addr_exprs,
                                &mut array_addr_expr_names,
                            );
                        }
                        let pointer = {
                            let ctx = ScalarArrayInferenceCtx {
                                parsed_context,
                                type_db,
                                merged_signature,
                                ptr_bits,
                                pointer_arg_slot_map,
                                local_element_strides,
                                pointer_values: &pointer_values,
                                pointer_value_names: &pointer_value_names,
                                array_addr_exprs: &array_addr_exprs,
                                array_addr_expr_names: &array_addr_expr_names,
                                stack_addr_offsets: &stack_addr_offsets,
                                stack_addr_offset_names: &stack_addr_offset_names,
                                block_ops: &block_ops,
                                value_ops: &value_ops,
                            };
                            scalar_pointer_minus_const(block.addr, a, b, &ctx)
                        };
                        if let Some(pointer) = pointer {
                            changed |= set_scalar_pointer_value(
                                block.addr,
                                dst,
                                pointer,
                                &mut pointer_values,
                                &mut pointer_value_names,
                            );
                        }
                    }
                    SSAOp::Load {
                        dst,
                        space: r2il::SpaceId::Ram,
                        addr,
                    } => {
                        if let Some(offset) = stack_addr_offset_for_var(
                            block.addr,
                            addr,
                            &stack_addr_offsets,
                            &stack_addr_offset_names,
                        ) {
                            let pointer = scalar_pointer_value_for_stack_slot(
                                parsed_context,
                                type_db,
                                offset,
                                ptr_bits,
                            );
                            if let Some(mut pointer) = pointer {
                                pointer.confidence = pointer.confidence.saturating_sub(1);
                                changed |= set_scalar_pointer_value(
                                    block.addr,
                                    dst,
                                    pointer,
                                    &mut pointer_values,
                                    &mut pointer_value_names,
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        if !changed {
            break;
        }
    }

    for block in ssa_blocks {
        for (op_index, op) in block.ops.iter().enumerate() {
            match op {
                SSAOp::Load {
                    dst,
                    space: r2il::SpaceId::Ram,
                    addr,
                } => {
                    let ctx = ScalarArrayInferenceCtx {
                        parsed_context,
                        type_db,
                        merged_signature,
                        ptr_bits,
                        pointer_arg_slot_map,
                        local_element_strides,
                        pointer_values: &pointer_values,
                        pointer_value_names: &pointer_value_names,
                        array_addr_exprs: &array_addr_exprs,
                        array_addr_expr_names: &array_addr_expr_names,
                        stack_addr_offsets: &stack_addr_offsets,
                        stack_addr_offset_names: &stack_addr_offset_names,
                        block_ops: &block_ops,
                        value_ops: &value_ops,
                    };
                    if let Some(expr) = scalar_array_addr_expr_for_var(
                        block.addr,
                        addr,
                        &array_addr_exprs,
                        &array_addr_expr_names,
                    )
                    .or_else(|| direct_scalar_pointer_array_expr(block.addr, addr, &ctx))
                    {
                        let access_width = dst.size;
                        if push_scalar_array_access_certificates(
                            &mut certificates,
                            &expr,
                            u64::from(access_width),
                            parsed_context,
                            type_db,
                            merged_signature,
                            ptr_bits,
                        ) {
                            certificates
                                .render_candidates
                                .push(ScalarArrayRenderCandidate {
                                    slot: expr.pointer.slot,
                                    block_addr: block.addr,
                                    op_index,
                                    is_write: false,
                                    field_offset: expr.field_offset,
                                    element_stride: expr.pointer.element_stride,
                                    access_width,
                                    index_value: None,
                                });
                        }
                    }
                }
                SSAOp::Store {
                    space: r2il::SpaceId::Ram,
                    addr,
                    val,
                } => {
                    let ctx = ScalarArrayInferenceCtx {
                        parsed_context,
                        type_db,
                        merged_signature,
                        ptr_bits,
                        pointer_arg_slot_map,
                        local_element_strides,
                        pointer_values: &pointer_values,
                        pointer_value_names: &pointer_value_names,
                        array_addr_exprs: &array_addr_exprs,
                        array_addr_expr_names: &array_addr_expr_names,
                        stack_addr_offsets: &stack_addr_offsets,
                        stack_addr_offset_names: &stack_addr_offset_names,
                        block_ops: &block_ops,
                        value_ops: &value_ops,
                    };
                    if let Some(expr) = scalar_array_addr_expr_for_var(
                        block.addr,
                        addr,
                        &array_addr_exprs,
                        &array_addr_expr_names,
                    )
                    .or_else(|| direct_scalar_pointer_array_expr(block.addr, addr, &ctx))
                    {
                        let access_width = val.size;
                        if push_scalar_array_access_certificates(
                            &mut certificates,
                            &expr,
                            u64::from(access_width),
                            parsed_context,
                            type_db,
                            merged_signature,
                            ptr_bits,
                        ) {
                            certificates
                                .render_candidates
                                .push(ScalarArrayRenderCandidate {
                                    slot: expr.pointer.slot,
                                    block_addr: block.addr,
                                    op_index,
                                    is_write: true,
                                    field_offset: expr.field_offset,
                                    element_stride: expr.pointer.element_stride,
                                    access_width,
                                    index_value: None,
                                });
                        }
                    }
                }
                _ => {}
            }
        }
    }

    certificates.array_index.sort();
    certificates.array_index.dedup();
    certificates.field_access.sort();
    certificates.field_access.dedup();
    certificates.render_candidates.sort();
    certificates.render_candidates.dedup();
    certificates
}

pub(crate) fn push_scalar_array_access_certificates(
    certificates: &mut ScalarArrayAccessCertificates,
    expr: &ScalarArrayAddrExpr,
    access_width: u64,
    parsed_context: &ParsedExternalContext,
    type_db: &ExternalTypeDb,
    merged_signature: Option<&FunctionSignatureSpec>,
    ptr_bits: u32,
) -> bool {
    let full_element_access = expr.field_offset == 0 && access_width == expr.pointer.element_stride;
    let field_layout = external_layout_field_access_for_scalar_expr(
        expr,
        access_width,
        parsed_context,
        type_db,
        merged_signature,
        ptr_bits,
    );

    if !full_element_access && field_layout.is_none() {
        return false;
    }

    certificates.array_index.push(ArrayIndexCertificate {
        slot: expr.pointer.slot,
        base: Some(expr.pointer.base.clone()),
        field_offset: expr.field_offset,
        element_stride: expr.pointer.element_stride,
    });

    if let Some(field) = field_layout {
        certificates
            .field_access
            .push(crate::FieldAccessCertificate {
                slot: expr.pointer.slot,
                field_offset: expr.field_offset,
                field_name: field.name,
                field_type: field.ty,
            });
    }

    true
}

pub(crate) fn external_layout_field_access_for_scalar_expr(
    expr: &ScalarArrayAddrExpr,
    access_width: u64,
    parsed_context: &ParsedExternalContext,
    type_db: &ExternalTypeDb,
    merged_signature: Option<&FunctionSignatureSpec>,
    ptr_bits: u32,
) -> Option<ExternalLayoutFieldAccess> {
    aggregate_pointee_type_names_for_scalar_pointer(&expr.pointer, parsed_context, merged_signature)
        .into_iter()
        .find_map(|type_name| {
            external_layout_field_access_for_offset(
                type_db,
                &type_name,
                expr.field_offset,
                access_width,
                ptr_bits,
            )
        })
}

pub(crate) fn aggregate_pointee_type_names_for_scalar_pointer(
    pointer: &ScalarPointerValue,
    parsed_context: &ParsedExternalContext,
    merged_signature: Option<&FunctionSignatureSpec>,
) -> Vec<String> {
    let names: Vec<String> = match &pointer.base {
        ArrayIndexBase::Param { index } => parsed_context
            .register_params
            .get(*index)
            .and_then(|param| param.ty.as_ref())
            .into_iter()
            .chain(
                merged_signature
                    .and_then(|signature| signature.params.get(*index))
                    .and_then(|param| param.ty.as_ref()),
            )
            .flat_map(aggregate_pointee_type_names_from_type)
            .collect(),
        ArrayIndexBase::StackSlot { slot } => parsed_context
            .stack_slots
            .get(slot)
            .and_then(|spec| spec.ty.as_ref())
            .into_iter()
            .flat_map(aggregate_pointee_type_names_from_type)
            .collect(),
    };
    names.into_iter().fold(Vec::new(), |mut out, name| {
        push_unique_type_name(&mut out, &name);
        out
    })
}

pub(crate) fn external_layout_field_access_for_offset(
    type_db: &ExternalTypeDb,
    type_name: &str,
    offset: u64,
    access_width: u64,
    ptr_bits: u32,
) -> Option<ExternalLayoutFieldAccess> {
    for key in aggregate_lookup_keys(type_name) {
        if let Some(st) = type_db.structs.get(&key)
            && let Some(field) =
                external_struct_field_access_for_offset(st, offset, access_width, ptr_bits)
        {
            return Some(field);
        }
        if let Some(un) = type_db.unions.get(&key)
            && let Some(field) =
                external_union_field_access_for_offset(un, offset, access_width, ptr_bits)
        {
            return Some(field);
        }
    }
    None
}

pub(crate) fn external_struct_field_access_for_offset(
    st: &ExternalStruct,
    offset: u64,
    access_width: u64,
    ptr_bits: u32,
) -> Option<ExternalLayoutFieldAccess> {
    st.fields
        .range(..=offset)
        .next_back()
        .and_then(|(_, field)| {
            external_field_access_for_offset(field, offset, access_width, ptr_bits)
        })
}

pub(crate) fn external_union_field_access_for_offset(
    un: &ExternalUnion,
    offset: u64,
    access_width: u64,
    ptr_bits: u32,
) -> Option<ExternalLayoutFieldAccess> {
    if offset != 0 {
        return None;
    }
    un.fields
        .values()
        .find_map(|field| external_field_access_for_offset(field, offset, access_width, ptr_bits))
}

pub(crate) fn external_field_access_for_offset(
    field: &ExternalField,
    offset: u64,
    access_width: u64,
    ptr_bits: u32,
) -> Option<ExternalLayoutFieldAccess> {
    if offset < field.offset {
        return None;
    }
    let rel = offset - field.offset;
    let field_ty = field.ty.as_deref();
    if let Some(CTypeLike::Array(inner, len)) =
        field_ty.and_then(|ty| parse_c_type_like(ty, ptr_bits))
    {
        let elem_size = estimate_type_like_size_bytes(&inner, ptr_bits)?;
        if elem_size == 0 || !rel.is_multiple_of(elem_size) || access_width > elem_size {
            return None;
        }
        let index = rel / elem_size;
        if len.is_some_and(|count| index >= count as u64) {
            return None;
        }
        return Some(ExternalLayoutFieldAccess {
            name: format!("{}[{index}]", field.name),
            ty: Some(render_signature_type(&inner, ptr_bits)),
        });
    }

    if rel == 0 {
        return Some(ExternalLayoutFieldAccess {
            name: field.name.clone(),
            ty: field.ty.clone(),
        });
    }

    None
}

pub(crate) fn scalar_pointer_value_for_var(
    block_addr: u64,
    var: &SSAVar,
    ctx: &ScalarArrayInferenceCtx<'_>,
) -> Option<ScalarPointerValue> {
    let lower = var.name().to_ascii_lowercase();
    if let Some(param_index) = ctx.pointer_arg_slot_map.get(lower.as_str()).copied() {
        let has_local_def = ctx.value_ops.contains_key(&var.display_name())
            || ctx
                .block_ops
                .get(&block_addr)
                .is_some_and(|ops| ops.contains_key(&ssa_var_block_key(block_addr, var)));
        if var.version == 0 || !has_local_def {
            let element_stride = ctx
                .local_element_strides
                .get(&param_index)
                .copied()
                .or_else(|| {
                    ctx.parsed_context
                        .register_params
                        .iter()
                        .find(|param| param.reg.eq_ignore_ascii_case(var.name()))
                        .and_then(|param| param.ty.as_ref())
                        .into_iter()
                        .chain(
                            ctx.merged_signature
                                .and_then(|signature| signature.params.get(param_index))
                                .and_then(|param| param.ty.as_ref()),
                        )
                        .find_map(|ty| pointer_element_stride(ty, ctx.type_db, ctx.ptr_bits))
                });
            if let Some(element_stride) = element_stride {
                return Some(ScalarPointerValue {
                    slot: param_index,
                    base: ArrayIndexBase::Param { index: param_index },
                    element_stride,
                    confidence: if var.version == 0 { 94 } else { 82 },
                });
            }
        }
    }
    ctx.pointer_values
        .get(&ssa_var_block_key(block_addr, var))
        .cloned()
        .or_else(|| {
            ctx.pointer_value_names
                .get(&var.display_name())
                .and_then(Clone::clone)
        })
}

pub(crate) fn scalar_pointer_value_for_stack_slot(
    parsed_context: &ParsedExternalContext,
    type_db: &ExternalTypeDb,
    offset: i64,
    ptr_bits: u32,
) -> Option<ScalarPointerValue> {
    parsed_context
        .stack_slots
        .iter()
        .filter(|(key, _)| key.offset == offset)
        .filter_map(|(key, spec)| {
            let element_stride = spec
                .ty
                .as_ref()
                .and_then(|ty| pointer_element_stride(ty, type_db, ptr_bits))?;
            Some(ScalarPointerValue {
                slot: legacy_array_slot_for_stack_slot(key),
                base: ArrayIndexBase::StackSlot { slot: *key },
                element_stride,
                confidence: 94,
            })
        })
        .next()
}

pub(crate) fn legacy_array_slot_for_stack_slot(key: &StackSlotKey) -> usize {
    // Retain the legacy numeric slot while the exact owner is carried by
    // ArrayIndexBase::StackSlot.
    1_000_000usize.saturating_add(key.offset.unsigned_abs() as usize)
}

pub(crate) fn pointer_element_stride(
    ty: &CTypeLike,
    type_db: &ExternalTypeDb,
    ptr_bits: u32,
) -> Option<u64> {
    match ty {
        CTypeLike::Pointer(inner) | CTypeLike::Array(inner, _) => {
            scalar_element_stride(inner, ptr_bits).or_else(|| {
                aggregate_pointee_type_names_from_type(ty)
                    .into_iter()
                    .find_map(|name| external_aggregate_size(type_db, &name, ptr_bits))
            })
        }
        _ => None,
    }
}

pub(crate) fn scalar_element_stride(ty: &CTypeLike, ptr_bits: u32) -> Option<u64> {
    match ty {
        CTypeLike::Const(inner) => scalar_element_stride(inner, ptr_bits),
        CTypeLike::Bool | CTypeLike::Int { .. } | CTypeLike::Float(_) => {
            estimate_type_like_size_bytes(ty, ptr_bits).filter(|size| *size > 0)
        }
        CTypeLike::Typedef { name, .. } => {
            let normalized = normalize_external_type_name(name);
            parse_c_type_like(&normalized, ptr_bits).and_then(|parsed| match parsed {
                CTypeLike::Bool | CTypeLike::Int { .. } | CTypeLike::Float(_) => {
                    estimate_type_like_size_bytes(&parsed, ptr_bits).filter(|size| *size > 0)
                }
                _ => None,
            })
        }
        CTypeLike::Void
        | CTypeLike::Unknown
        | CTypeLike::Array(_, _)
        | CTypeLike::Struct(_)
        | CTypeLike::Union(_)
        | CTypeLike::Enum(_)
        | CTypeLike::BitVector(_)
        | CTypeLike::Function { .. } => None,
        CTypeLike::Pointer(_) => Some((ptr_bits / 8).max(1) as u64),
    }
}

pub(crate) fn set_scalar_pointer_value(
    block_addr: u64,
    dst: &SSAVar,
    pointer: ScalarPointerValue,
    pointer_values: &mut HashMap<String, ScalarPointerValue>,
    pointer_value_names: &mut HashMap<String, Option<ScalarPointerValue>>,
) -> bool {
    let key = ssa_var_block_key(block_addr, dst);
    match pointer_values.get(&key) {
        Some(prev) if prev.confidence >= pointer.confidence => false,
        _ => {
            pointer_values.insert(key, pointer.clone());
            merge_named_scalar_pointer_value(dst, pointer, pointer_value_names);
            true
        }
    }
}

pub(crate) fn set_scalar_array_addr_expr(
    block_addr: u64,
    dst: &SSAVar,
    expr: ScalarArrayAddrExpr,
    array_addr_exprs: &mut HashMap<String, ScalarArrayAddrExpr>,
    array_addr_expr_names: &mut HashMap<String, Option<ScalarArrayAddrExpr>>,
) -> bool {
    let key = ssa_var_block_key(block_addr, dst);
    match array_addr_exprs.get(&key) {
        Some(prev) if prev.confidence >= expr.confidence => false,
        _ => {
            array_addr_exprs.insert(key, expr.clone());
            merge_named_scalar_array_addr_expr(dst, expr, array_addr_expr_names);
            true
        }
    }
}

pub(crate) fn set_stack_addr_offset(
    block_addr: u64,
    dst: &SSAVar,
    offset: i64,
    stack_addr_offsets: &mut HashMap<String, i64>,
    stack_addr_offset_names: &mut HashMap<String, Option<i64>>,
) -> bool {
    let key = ssa_var_block_key(block_addr, dst);
    match stack_addr_offsets.get(&key).copied() {
        Some(prev) if prev == offset => false,
        _ => {
            stack_addr_offsets.insert(key, offset);
            merge_named_stack_addr_offset(dst, offset, stack_addr_offset_names);
            true
        }
    }
}

pub(crate) fn merge_named_scalar_pointer_value(
    dst: &SSAVar,
    pointer: ScalarPointerValue,
    pointer_value_names: &mut HashMap<String, Option<ScalarPointerValue>>,
) {
    merge_named_fact(dst, pointer, pointer_value_names);
}

pub(crate) fn merge_named_scalar_array_addr_expr(
    dst: &SSAVar,
    expr: ScalarArrayAddrExpr,
    array_addr_expr_names: &mut HashMap<String, Option<ScalarArrayAddrExpr>>,
) {
    merge_named_fact(dst, expr, array_addr_expr_names);
}

pub(crate) fn merge_named_stack_addr_offset(
    dst: &SSAVar,
    offset: i64,
    stack_addr_offset_names: &mut HashMap<String, Option<i64>>,
) {
    merge_named_fact(dst, offset, stack_addr_offset_names);
}

pub(crate) fn merge_named_fact<T: Clone + PartialEq>(
    dst: &SSAVar,
    fact: T,
    named_facts: &mut HashMap<String, Option<T>>,
) {
    let key = dst.display_name();
    match named_facts.get(&key) {
        None => {
            named_facts.insert(key, Some(fact));
        }
        Some(Some(prev)) if prev == &fact => {}
        Some(_) => {
            named_facts.insert(key, None);
        }
    }
}

pub(crate) fn stack_addr_offset_for_var(
    block_addr: u64,
    var: &SSAVar,
    stack_addr_offsets: &HashMap<String, i64>,
    stack_addr_offset_names: &HashMap<String, Option<i64>>,
) -> Option<i64> {
    stack_addr_offsets
        .get(&ssa_var_block_key(block_addr, var))
        .copied()
        .or_else(|| {
            stack_addr_offset_names
                .get(&var.display_name())
                .and_then(|value| *value)
        })
}

pub(crate) fn scalar_array_addr_expr_for_var(
    block_addr: u64,
    var: &SSAVar,
    array_addr_exprs: &HashMap<String, ScalarArrayAddrExpr>,
    array_addr_expr_names: &HashMap<String, Option<ScalarArrayAddrExpr>>,
) -> Option<ScalarArrayAddrExpr> {
    array_addr_exprs
        .get(&ssa_var_block_key(block_addr, var))
        .cloned()
        .or_else(|| {
            array_addr_expr_names
                .get(&var.display_name())
                .and_then(Clone::clone)
        })
}

pub(crate) fn phi_scalar_pointer_value(
    block_addr: u64,
    dst: &SSAVar,
    sources: &[SSAVar],
    ctx: &ScalarArrayInferenceCtx<'_>,
) -> Option<ScalarPointerValue> {
    let mut selected: Option<ScalarPointerValue> = None;
    let mut unknown_sources = Vec::new();
    for src in sources {
        let Some(pointer) = scalar_pointer_value_for_var(block_addr, src, ctx) else {
            unknown_sources.push(src);
            continue;
        };
        selected = match selected {
            None => Some(pointer),
            Some(prev)
                if prev.base == pointer.base && prev.element_stride == pointer.element_stride =>
            {
                Some(ScalarPointerValue {
                    confidence: prev.confidence.max(pointer.confidence),
                    ..prev
                })
            }
            _ => return None,
        };
    }
    let mut selected = selected?;
    for src in unknown_sources {
        if !phi_source_is_const_stride_pointer_recurrence(dst, src, &selected, ctx, 0) {
            return None;
        }
        selected.confidence = selected.confidence.saturating_sub(4);
    }
    Some(selected)
}

pub(crate) fn phi_source_is_const_stride_pointer_recurrence(
    phi_dst: &SSAVar,
    src: &SSAVar,
    pointer: &ScalarPointerValue,
    ctx: &ScalarArrayInferenceCtx<'_>,
    depth: u32,
) -> bool {
    if depth > 4 {
        return false;
    }
    let Some(op) = ctx.value_ops.get(&src.display_name()) else {
        return false;
    };
    match op {
        SSAOp::Copy { src, .. }
        | SSAOp::Cast { src, .. }
        | SSAOp::New { src, .. }
        | SSAOp::IntZExt { src, .. }
        | SSAOp::IntSExt { src, .. }
        | SSAOp::Trunc { src, .. }
        | SSAOp::Subpiece { src, .. } => {
            src == phi_dst
                || phi_source_is_const_stride_pointer_recurrence(
                    phi_dst,
                    src,
                    pointer,
                    ctx,
                    depth + 1,
                )
        }
        SSAOp::IntAdd { a, b, .. } => {
            phi_pointer_step_matches(phi_dst, a, b, pointer, ctx)
                || phi_pointer_step_matches(phi_dst, b, a, pointer, ctx)
        }
        SSAOp::IntSub { a, b, .. } => phi_pointer_step_matches(phi_dst, a, b, pointer, ctx),
        _ => false,
    }
}

pub(crate) fn phi_pointer_step_matches(
    phi_dst: &SSAVar,
    pointer_term: &SSAVar,
    offset_term: &SSAVar,
    pointer: &ScalarPointerValue,
    ctx: &ScalarArrayInferenceCtx<'_>,
) -> bool {
    if pointer_term != phi_dst {
        return false;
    }
    let Some(offset) = exact_ssa_const_offset(offset_term, ctx.ptr_bits) else {
        return false;
    };
    offset
        .unsigned_abs()
        .is_multiple_of(pointer.element_stride.max(1))
}

pub(crate) fn phi_scalar_array_addr_expr(
    block_addr: u64,
    sources: &[SSAVar],
    array_addr_exprs: &HashMap<String, ScalarArrayAddrExpr>,
    array_addr_expr_names: &HashMap<String, Option<ScalarArrayAddrExpr>>,
) -> Option<ScalarArrayAddrExpr> {
    let mut selected: Option<ScalarArrayAddrExpr> = None;
    for src in sources {
        let expr = scalar_array_addr_expr_for_var(
            block_addr,
            src,
            array_addr_exprs,
            array_addr_expr_names,
        )?;
        selected = match selected {
            None => Some(expr),
            Some(prev)
                if prev.pointer.base == expr.pointer.base
                    && prev.pointer.element_stride == expr.pointer.element_stride
                    && prev.field_offset == expr.field_offset =>
            {
                Some(ScalarArrayAddrExpr {
                    confidence: prev.confidence.max(expr.confidence),
                    ..prev
                })
            }
            _ => return None,
        };
    }
    selected
}

pub(crate) fn scalar_array_expr_for_addend_pair(
    block_addr: u64,
    a: &SSAVar,
    b: &SSAVar,
    ctx: &ScalarArrayInferenceCtx<'_>,
) -> Option<ScalarArrayAddrExpr> {
    if let Some(expr) = scalar_array_plus_const(block_addr, a, b, ctx) {
        return Some(expr);
    }
    if let Some(expr) = scalar_array_plus_const(block_addr, b, a, ctx) {
        return Some(expr);
    }
    if let Some(expr) = scalar_pointer_plus_index(block_addr, a, b, ctx) {
        return Some(expr);
    }
    scalar_pointer_plus_index(block_addr, b, a, ctx)
}

pub(crate) fn direct_scalar_pointer_array_expr(
    block_addr: u64,
    var: &SSAVar,
    ctx: &ScalarArrayInferenceCtx<'_>,
) -> Option<ScalarArrayAddrExpr> {
    let pointer = scalar_pointer_value_for_var(block_addr, var, ctx)?;
    Some(ScalarArrayAddrExpr {
        confidence: pointer.confidence.saturating_sub(2),
        pointer,
        field_offset: 0,
    })
}

pub(crate) fn scalar_pointer_plus_const(
    block_addr: u64,
    pointer_var: &SSAVar,
    const_var: &SSAVar,
    ctx: &ScalarArrayInferenceCtx<'_>,
) -> Option<ScalarPointerValue> {
    let offset = exact_ssa_const_offset(const_var, ctx.ptr_bits)?;
    scalar_pointer_offset_by_const(block_addr, pointer_var, offset, ctx)
}

pub(crate) fn scalar_pointer_minus_const(
    block_addr: u64,
    pointer_var: &SSAVar,
    const_var: &SSAVar,
    ctx: &ScalarArrayInferenceCtx<'_>,
) -> Option<ScalarPointerValue> {
    let offset = exact_ssa_const_offset(const_var, ctx.ptr_bits)?;
    scalar_pointer_offset_by_const(block_addr, pointer_var, offset.saturating_neg(), ctx)
}

pub(crate) fn scalar_pointer_offset_by_const(
    block_addr: u64,
    pointer_var: &SSAVar,
    offset: i64,
    ctx: &ScalarArrayInferenceCtx<'_>,
) -> Option<ScalarPointerValue> {
    let mut pointer = scalar_pointer_value_for_var(block_addr, pointer_var, ctx)?;
    let stride = pointer.element_stride.max(1);
    if !offset.unsigned_abs().is_multiple_of(stride) {
        return None;
    }
    pointer.confidence = pointer.confidence.saturating_sub(3);
    Some(pointer)
}

pub(crate) fn scalar_array_plus_const(
    block_addr: u64,
    array_var: &SSAVar,
    const_var: &SSAVar,
    ctx: &ScalarArrayInferenceCtx<'_>,
) -> Option<ScalarArrayAddrExpr> {
    let offset = exact_ssa_const_offset(const_var, ctx.ptr_bits)?;
    let mut expr = scalar_array_addr_expr_for_var(
        block_addr,
        array_var,
        ctx.array_addr_exprs,
        ctx.array_addr_expr_names,
    )?;
    if offset < 0 {
        return None;
    }
    expr.field_offset = expr.field_offset.checked_add(offset as u64)?;
    expr.confidence = expr.confidence.saturating_sub(1);
    Some(expr)
}

pub(crate) fn scalar_pointer_plus_index(
    block_addr: u64,
    pointer_var: &SSAVar,
    index_var: &SSAVar,
    ctx: &ScalarArrayInferenceCtx<'_>,
) -> Option<ScalarArrayAddrExpr> {
    let pointer = scalar_pointer_value_for_var(block_addr, pointer_var, ctx)?;
    if !scalar_index_matches_stride(block_addr, index_var, pointer.element_stride, ctx, 0) {
        return None;
    }
    Some(ScalarArrayAddrExpr {
        confidence: pointer.confidence.saturating_sub(4),
        pointer,
        field_offset: 0,
    })
}

pub(crate) fn scalar_index_matches_stride(
    block_addr: u64,
    var: &SSAVar,
    stride: u64,
    ctx: &ScalarArrayInferenceCtx<'_>,
    depth: u32,
) -> bool {
    if depth > 8 {
        return false;
    }
    let key = ssa_var_block_key(block_addr, var);
    if ctx.pointer_values.contains_key(&key)
        || ctx.array_addr_exprs.contains_key(&key)
        || ctx.stack_addr_offsets.contains_key(&key)
        || ctx
            .pointer_value_names
            .get(&var.display_name())
            .and_then(Clone::clone)
            .is_some()
        || ctx
            .array_addr_expr_names
            .get(&var.display_name())
            .and_then(Clone::clone)
            .is_some()
        || ctx
            .stack_addr_offset_names
            .get(&var.display_name())
            .and_then(|value| *value)
            .is_some()
    {
        return false;
    }
    if let Some(offset) = exact_ssa_const_offset(var, 64) {
        return offset >= 0 && (offset as u64).is_multiple_of(stride.max(1));
    }
    if let Some(factor) = scalar_index_affine_factor(block_addr, var, ctx, depth)
        && factor.root.is_some()
        && factor.scale.unsigned_abs() == u128::from(stride)
    {
        return true;
    }
    if stride == 1 && var.version == 0 {
        return true;
    }
    let Some(op) = ctx.block_ops.get(&block_addr).and_then(|ops| ops.get(&key)) else {
        return stride == 1;
    };
    match op {
        SSAOp::Copy { src, .. }
        | SSAOp::Cast { src, .. }
        | SSAOp::New { src, .. }
        | SSAOp::IntZExt { src, .. }
        | SSAOp::IntSExt { src, .. }
        | SSAOp::Trunc { src, .. }
        | SSAOp::Subpiece { src, .. } => {
            scalar_index_matches_stride(block_addr, src, stride, ctx, depth + 1)
        }
        SSAOp::Load {
            space: r2il::SpaceId::Ram,
            ..
        }
        | SSAOp::Phi { .. } => stride == 1,
        SSAOp::IntMult { a, b, .. } => {
            scaled_index_term_matches_stride(block_addr, a, b, stride, ctx, depth + 1)
        }
        SSAOp::IntLeft { a, b, .. } => {
            exact_ssa_const_offset(b, 64)
                .and_then(|shift| (shift >= 0).then_some(1u64.checked_shl(shift as u32)?))
                == Some(stride)
                && scalar_index_matches_stride(block_addr, a, 1, ctx, depth + 1)
        }
        SSAOp::IntAdd { a, b, .. } | SSAOp::IntSub { a, b, .. } => {
            stride == 1
                && scalar_index_matches_stride(block_addr, a, stride, ctx, depth + 1)
                && scalar_index_matches_stride(block_addr, b, stride, ctx, depth + 1)
        }
        _ => false,
    }
}

pub(crate) fn scalar_index_affine_factor(
    block_addr: u64,
    var: &SSAVar,
    ctx: &ScalarArrayInferenceCtx<'_>,
    depth: u32,
) -> Option<AffineIndexFactor> {
    if depth > 8 {
        return None;
    }
    let key = ssa_var_block_key(block_addr, var);
    if ctx.pointer_values.contains_key(&key)
        || ctx.array_addr_exprs.contains_key(&key)
        || ctx.stack_addr_offsets.contains_key(&key)
        || ctx
            .pointer_value_names
            .get(&var.display_name())
            .and_then(Clone::clone)
            .is_some()
        || ctx
            .array_addr_expr_names
            .get(&var.display_name())
            .and_then(Clone::clone)
            .is_some()
        || ctx
            .stack_addr_offset_names
            .get(&var.display_name())
            .and_then(|value| *value)
            .is_some()
    {
        return None;
    }
    if exact_ssa_const_offset(var, 64).is_some() {
        return Some(AffineIndexFactor {
            root: None,
            scale: 0,
        });
    }
    if var.version == 0 {
        return Some(AffineIndexFactor {
            root: Some(var.name().to_ascii_lowercase()),
            scale: 1,
        });
    }

    let op = ctx
        .block_ops
        .get(&block_addr)
        .and_then(|ops| ops.get(&key))?;
    match op {
        SSAOp::Copy { src, .. }
        | SSAOp::Cast { src, .. }
        | SSAOp::New { src, .. }
        | SSAOp::IntZExt { src, .. }
        | SSAOp::IntSExt { src, .. }
        | SSAOp::Trunc { src, .. }
        | SSAOp::Subpiece { src, .. } => {
            scalar_index_affine_factor(block_addr, src, ctx, depth + 1)
        }
        SSAOp::IntMult { a, b, .. } => affine_scaled_term(block_addr, a, b, ctx, depth + 1)
            .or_else(|| affine_scaled_term(block_addr, b, a, ctx, depth + 1)),
        SSAOp::IntLeft { a, b, .. } => {
            let shift = exact_ssa_const_offset(b, 64)?;
            if shift < 0 {
                return None;
            }
            let factor = scalar_index_affine_factor(block_addr, a, ctx, depth + 1)?;
            let multiplier = 1i128.checked_shl(shift as u32)?;
            Some(AffineIndexFactor {
                root: factor.root,
                scale: factor.scale.checked_mul(multiplier)?,
            })
        }
        SSAOp::IntAdd { a, b, .. } => {
            let left = scalar_index_affine_factor(block_addr, a, ctx, depth + 1)?;
            let right = scalar_index_affine_factor(block_addr, b, ctx, depth + 1)?;
            combine_affine_terms(left, right, 1)
        }
        SSAOp::IntSub { a, b, .. } => {
            let left = scalar_index_affine_factor(block_addr, a, ctx, depth + 1)?;
            let right = scalar_index_affine_factor(block_addr, b, ctx, depth + 1)?;
            combine_affine_terms(left, right, -1)
        }
        SSAOp::Load {
            space: r2il::SpaceId::Ram,
            addr,
            ..
        } => {
            let offset = stack_addr_offset_for_var(
                block_addr,
                addr,
                ctx.stack_addr_offsets,
                ctx.stack_addr_offset_names,
            )?;
            Some(AffineIndexFactor {
                root: Some(format!("stack:{offset}")),
                scale: 1,
            })
        }
        _ => None,
    }
}

pub(crate) fn affine_scaled_term(
    block_addr: u64,
    term: &SSAVar,
    multiplier: &SSAVar,
    ctx: &ScalarArrayInferenceCtx<'_>,
    depth: u32,
) -> Option<AffineIndexFactor> {
    let multiplier = exact_ssa_const_offset(multiplier, 64)?;
    let factor = scalar_index_affine_factor(block_addr, term, ctx, depth)?;
    Some(AffineIndexFactor {
        root: factor.root,
        scale: factor.scale.checked_mul(i128::from(multiplier))?,
    })
}

pub(crate) fn combine_affine_terms(
    left: AffineIndexFactor,
    right: AffineIndexFactor,
    right_sign: i128,
) -> Option<AffineIndexFactor> {
    let root = match (left.root, right.root) {
        (Some(left_root), Some(right_root)) if left_root == right_root => Some(left_root),
        (Some(left_root), None) => Some(left_root),
        (None, Some(right_root)) => Some(right_root),
        (None, None) => None,
        _ => return None,
    };
    Some(AffineIndexFactor {
        root,
        scale: left
            .scale
            .checked_add(right.scale.checked_mul(right_sign)?)?,
    })
}

pub(crate) fn scaled_index_term_matches_stride(
    block_addr: u64,
    a: &SSAVar,
    b: &SSAVar,
    stride: u64,
    ctx: &ScalarArrayInferenceCtx<'_>,
    depth: u32,
) -> bool {
    if exact_ssa_const_offset(a, 64).is_some_and(|value| value >= 0 && value as u64 == stride) {
        return scalar_index_matches_stride(block_addr, b, 1, ctx, depth + 1);
    }
    if exact_ssa_const_offset(b, 64).is_some_and(|value| value >= 0 && value as u64 == stride) {
        return scalar_index_matches_stride(block_addr, a, 1, ctx, depth + 1);
    }
    false
}

pub(crate) fn aggregate_pointee_type_names_from_type(ty: &CTypeLike) -> Vec<String> {
    let mut out = Vec::new();
    if let CTypeLike::Pointer(inner) | CTypeLike::Array(inner, _) = ty {
        collect_aggregate_type_names(inner, &mut out);
    }
    out
}

pub(crate) fn collect_aggregate_type_names(ty: &CTypeLike, out: &mut Vec<String>) {
    match ty {
        CTypeLike::Const(inner) => collect_aggregate_type_names(inner, out),
        CTypeLike::Struct(name) | CTypeLike::Union(name) | CTypeLike::Enum(name) => {
            push_unique_type_name(out, name);
        }
        CTypeLike::Typedef { name, .. } => {
            push_unique_type_name(out, name);
            push_unique_type_name(out, &format!("struct {name}"));
            push_unique_type_name(out, &format!("union {name}"));
        }
        CTypeLike::Pointer(inner) | CTypeLike::Array(inner, _) => {
            collect_aggregate_type_names(inner, out);
        }
        CTypeLike::Void
        | CTypeLike::Unknown
        | CTypeLike::Bool
        | CTypeLike::Int { .. }
        | CTypeLike::Float(_)
        | CTypeLike::BitVector(_)
        | CTypeLike::Function { .. } => {}
    }
}

pub(crate) fn push_unique_type_name(out: &mut Vec<String>, name: &str) {
    let trimmed = name.trim();
    if !trimmed.is_empty() && !out.iter().any(|existing| existing == trimmed) {
        out.push(trimmed.to_string());
    }
}

pub(crate) fn external_aggregate_size(
    type_db: &ExternalTypeDb,
    name: &str,
    ptr_bits: u32,
) -> Option<u64> {
    for key in aggregate_lookup_keys(name) {
        if let Some(st) = type_db.structs.get(&key)
            && let Some(size) = external_struct_size(st, ptr_bits)
        {
            return Some(size);
        }
        if let Some(un) = type_db.unions.get(&key) {
            let size = un
                .fields
                .values()
                .filter_map(|field| {
                    field
                        .ty
                        .as_deref()
                        .map(|ty| estimate_c_type_size_bytes(ty, ptr_bits))
                })
                .max()
                .unwrap_or(1);
            return Some(size);
        }
    }
    None
}

pub(crate) fn external_struct_size(st: &ExternalStruct, ptr_bits: u32) -> Option<u64> {
    st.fields
        .values()
        .filter_map(|field| {
            let ty = field.ty.as_deref().unwrap_or("uint8_t");
            let width = estimate_c_type_size_bytes(ty, ptr_bits).max(1);
            field.offset.checked_add(width)
        })
        .max()
}
