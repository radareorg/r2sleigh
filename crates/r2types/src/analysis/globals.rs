//! What a global address is, read off the accesses that reach it.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GlobalTypeLinkCandidate {
    pub addr: u64,
    /// The type this address is linked to, as a type.
    ///
    /// Rendered only where it leaves for radare2 or a JSON payload. It used to
    /// be built here with `format!("struct {} *", ..)` and taken apart again
    /// downstream with `strip_prefix`/`strip_suffix`, which is what made the
    /// pointer's spacing something three components each had an opinion about.
    pub target_type: CTypeLike,
    pub confidence: u8,
    pub source: TypeFactSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GlobalAddrExpr {
    pub(crate) base: u64,
    pub(crate) offset: i64,
    pub(crate) confidence: u8,
}

pub(crate) fn score_global_type_links(
    ssa_blocks: &[SSABlock],
    struct_decls: &[StructDeclCandidate],
    var_type_candidates: &[VarTypeCandidate],
    ptr_bits: u32,
    extents: &crate::ProgramExtents,
) -> Vec<GlobalTypeLinkCandidate> {
    let per_addr_profiles = infer_global_field_profiles(ssa_blocks, ptr_bits, extents);
    if per_addr_profiles.is_empty() {
        return Vec::new();
    }

    let mut per_type_weight: BTreeMap<CTypeLike, i32> = BTreeMap::new();
    let mut decl_profiles: BTreeMap<CTypeLike, BTreeMap<u64, String>> = BTreeMap::new();
    for decl in struct_decls {
        // Genericity here is a property of the struct's own name, which is what
        // the placeholder test actually inspects once it has stripped the
        // `struct` keyword and the star back off a rendered spelling.
        if type_name_is_opaque_placeholder(&decl.name) {
            continue;
        }
        let key = CTypeLike::Pointer(Box::new(CTypeLike::Struct(decl.name.clone())));
        let source_boost = if decl.source == StructDeclSource::ExternalTypeDb {
            12
        } else {
            0
        };
        per_type_weight.insert(
            key.clone(),
            32 + source_boost + (decl.confidence as i32 / 6) + (decl.fields.len() as i32).min(16),
        );
        decl_profiles.insert(
            key,
            decl.fields
                .iter()
                .map(|field| {
                    (
                        field.offset,
                        render_signature_type(&field.field_type, ptr_bits).to_ascii_lowercase(),
                    )
                })
                .collect(),
        );
    }
    for var in var_type_candidates {
        let parsed = var.var_type.clone();
        if matches!(&parsed, CTypeLike::Pointer(inner) if matches!(inner.as_ref(), CTypeLike::Struct(name) if !type_name_is_opaque_placeholder(name)))
        {
            *per_type_weight.entry(parsed).or_insert(30) += 4 + (var.confidence as i32 / 12);
        }
    }
    if per_type_weight.is_empty() {
        return Vec::new();
    }

    let mut per_addr_best: BTreeMap<u64, (CTypeLike, i32)> = BTreeMap::new();
    for (addr, profile) in per_addr_profiles {
        if profile.is_empty() {
            continue;
        }
        let observed_fields = profile.len();
        let mut best: Option<(CTypeLike, i32)> = None;
        for (ty, base_score) in &per_type_weight {
            let Some(decl_profile) = decl_profiles.get(ty) else {
                continue;
            };
            if observed_fields == 1 && decl_profile.len() > 1 {
                continue;
            }

            let mut exact_matches = 0i32;
            let mut declared_offsets = 0i32;
            let mut evidence_weight = 0i32;
            for (offset, evidence) in &profile {
                let Some(decl_ty) = decl_profile.get(offset) else {
                    continue;
                };
                declared_offsets += 1;
                let observed = evidence
                    .field_type
                    .as_deref()
                    .map(normalize_external_type_name);
                if observed.is_some_and(|observed| observed.eq_ignore_ascii_case(decl_ty)) {
                    exact_matches += 1;
                    evidence_weight +=
                        1 + evidence.reads.min(4) as i32 + evidence.writes.min(4) as i32;
                }
            }
            if exact_matches == 0 {
                continue;
            }
            if observed_fields > 1 && exact_matches < observed_fields.min(2) as i32 {
                continue;
            }

            let score =
                *base_score + exact_matches * 18 + declared_offsets * 6 + evidence_weight.min(18);
            match best {
                Some((ref prev_ty, prev_score))
                    if prev_score > score || (prev_score == score && prev_ty <= ty) => {}
                _ => best = Some((ty.clone(), score)),
            }
        }
        if let Some(candidate) = best {
            per_addr_best.insert(addr, candidate);
        }
    }

    per_addr_best
        .into_iter()
        .map(|(addr, (target_type, score))| GlobalTypeLinkCandidate {
            addr,
            target_type,
            confidence: score.clamp(1, 99) as u8,
            source: TypeFactSource::DataflowRanked,
        })
        .collect()
}

/// Every global a body accesses, by base, with what each offset from it was read and written as.
///
/// A base is a constant a section the program loads holds; this cannot see
/// whether the number moved with the program, so the engine's test for an
/// absolute number decides it.
pub(crate) fn infer_global_field_profiles(
    ssa_blocks: &[SSABlock],
    ptr_bits: u32,
    extents: &crate::ProgramExtents,
) -> BTreeMap<u64, BTreeMap<u64, InferredGlobalFieldEvidence>> {
    let mut addr_exprs: HashMap<(u64, SSAVar), GlobalAddrExpr> = HashMap::new();
    let mut field_evidence: BTreeMap<u64, BTreeMap<u64, InferredGlobalFieldEvidence>> =
        BTreeMap::new();
    let offset_bound = 0x4000i64;

    for _ in 0..6 {
        let mut changed = false;
        for block in ssa_blocks {
            for op in &block.ops {
                let addr_of = |var: &SSAVar, map: &HashMap<(u64, SSAVar), GlobalAddrExpr>| {
                    var.constant_bits()
                        .filter(|base| extents.holds(*base))
                        .map(|base| GlobalAddrExpr {
                            base,
                            offset: 0,
                            confidence: 92,
                        })
                        .or_else(|| map.get(&(block.addr, var.clone())).copied())
                };
                let set_expr =
                    |dst: &SSAVar,
                     expr: GlobalAddrExpr,
                     map: &mut HashMap<(u64, SSAVar), GlobalAddrExpr>| {
                        let key = (block.addr, dst.clone());
                        match map.get(&key).copied() {
                            Some(prev) if prev.confidence >= expr.confidence => false,
                            _ => {
                                map.insert(key, expr);
                                true
                            }
                        }
                    };
                match op {
                    SSAOp::Copy { dst, src }
                    | SSAOp::Cast { dst, src }
                    | SSAOp::New { dst, src }
                    | SSAOp::IntZExt { dst, src }
                    | SSAOp::IntSExt { dst, src } => {
                        if let Some(mut expr) = addr_of(src, &addr_exprs) {
                            expr.confidence = expr.confidence.saturating_sub(2);
                            changed |= set_expr(dst, expr, &mut addr_exprs);
                        }
                    }
                    SSAOp::Phi { dst, sources } => {
                        let mut selected = None;
                        for src in sources {
                            let Some(expr) = addr_of(src, &addr_exprs) else {
                                selected = None;
                                break;
                            };
                            selected = match selected {
                                None => Some(expr),
                                Some(prev)
                                    if prev.base == expr.base && prev.offset == expr.offset =>
                                {
                                    Some(GlobalAddrExpr {
                                        base: prev.base,
                                        offset: prev.offset,
                                        confidence: prev.confidence.max(expr.confidence),
                                    })
                                }
                                _ => None,
                            };
                            if selected.is_none() {
                                break;
                            }
                        }
                        if let Some(mut expr) = selected {
                            expr.confidence = expr.confidence.saturating_sub(3);
                            changed |= set_expr(dst, expr, &mut addr_exprs);
                        }
                    }
                    SSAOp::IntAdd { dst, a, b } => {
                        if let Some(base) = addr_of(a, &addr_exprs)
                            && let Some(raw) = b.constant_bits()
                        {
                            let off = base
                                .offset
                                .saturating_add(signed_offset_from_const(raw, ptr_bits));
                            if (-offset_bound..=offset_bound).contains(&off) {
                                changed |= set_expr(
                                    dst,
                                    GlobalAddrExpr {
                                        base: base.base,
                                        offset: off,
                                        confidence: base.confidence.saturating_sub(1),
                                    },
                                    &mut addr_exprs,
                                );
                            }
                        } else if let Some(base) = addr_of(b, &addr_exprs)
                            && let Some(raw) = a.constant_bits()
                        {
                            let off = base
                                .offset
                                .saturating_add(signed_offset_from_const(raw, ptr_bits));
                            if (-offset_bound..=offset_bound).contains(&off) {
                                changed |= set_expr(
                                    dst,
                                    GlobalAddrExpr {
                                        base: base.base,
                                        offset: off,
                                        confidence: base.confidence.saturating_sub(1),
                                    },
                                    &mut addr_exprs,
                                );
                            }
                        }
                    }
                    SSAOp::IntSub { dst, a, b } => {
                        if let Some(base) = addr_of(a, &addr_exprs)
                            && let Some(raw) = b.constant_bits()
                        {
                            let off = base
                                .offset
                                .saturating_sub(signed_offset_from_const(raw, ptr_bits));
                            if (-offset_bound..=offset_bound).contains(&off) {
                                changed |= set_expr(
                                    dst,
                                    GlobalAddrExpr {
                                        base: base.base,
                                        offset: off,
                                        confidence: base.confidence.saturating_sub(1),
                                    },
                                    &mut addr_exprs,
                                );
                            }
                        }
                    }
                    SSAOp::PtrAdd {
                        dst,
                        base,
                        index,
                        element_size,
                    } => {
                        if let Some(base_expr) = addr_of(base, &addr_exprs)
                            && let Some(raw) = index.constant_bits()
                        {
                            let scaled = signed_offset_from_const(raw, ptr_bits)
                                .saturating_mul((*element_size).into());
                            let off = base_expr.offset.saturating_add(scaled);
                            if (-offset_bound..=offset_bound).contains(&off) {
                                changed |= set_expr(
                                    dst,
                                    GlobalAddrExpr {
                                        base: base_expr.base,
                                        offset: off,
                                        confidence: base_expr.confidence.saturating_sub(1),
                                    },
                                    &mut addr_exprs,
                                );
                            }
                        }
                    }
                    SSAOp::PtrSub {
                        dst,
                        base,
                        index,
                        element_size,
                    } => {
                        if let Some(base_expr) = addr_of(base, &addr_exprs)
                            && let Some(raw) = index.constant_bits()
                        {
                            let scaled = signed_offset_from_const(raw, ptr_bits)
                                .saturating_mul((*element_size).into());
                            let off = base_expr.offset.saturating_sub(scaled);
                            if (-offset_bound..=offset_bound).contains(&off) {
                                changed |= set_expr(
                                    dst,
                                    GlobalAddrExpr {
                                        base: base_expr.base,
                                        offset: off,
                                        confidence: base_expr.confidence.saturating_sub(1),
                                    },
                                    &mut addr_exprs,
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
        for op in &block.ops {
            let resolve_addr = |addr: &SSAVar| -> Option<GlobalAddrExpr> {
                addr.constant_bits()
                    .filter(|base| extents.holds(*base))
                    .map(|base| GlobalAddrExpr {
                        base,
                        offset: 0,
                        confidence: 92,
                    })
                    .or_else(|| addr_exprs.get(&(block.addr, addr.clone())).copied())
            };
            match op {
                SSAOp::Load {
                    dst,
                    space: r2il::SpaceId::Ram,
                    addr,
                } => {
                    if let Some(expr) = resolve_addr(addr)
                        && (0..=offset_bound).contains(&expr.offset)
                    {
                        let entry = field_evidence
                            .entry(expr.base)
                            .or_default()
                            .entry(expr.offset as u64)
                            .or_default();
                        entry.reads = entry.reads.saturating_add(1);
                        entry.field_type = storage_type_spelling(dst.size, Signedness::Signed);
                    }
                }
                SSAOp::Store {
                    space: r2il::SpaceId::Ram,
                    addr,
                    val,
                } => {
                    if let Some(expr) = resolve_addr(addr)
                        && (0..=offset_bound).contains(&expr.offset)
                    {
                        let entry = field_evidence
                            .entry(expr.base)
                            .or_default()
                            .entry(expr.offset as u64)
                            .or_default();
                        entry.writes = entry.writes.saturating_add(1);
                        entry.field_type = storage_type_spelling(val.size, Signedness::Signed);
                    }
                }
                _ => {}
            }
        }
    }

    field_evidence
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct InferredGlobalFieldEvidence {
    pub(crate) reads: u32,
    pub(crate) writes: u32,
    pub(crate) field_type: Option<String>,
}
