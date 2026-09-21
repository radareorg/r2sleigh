//! Aggregates the frame proves, and how they meet the declared ones.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalAddrExpr {
    pub(crate) slot: usize,
    pub(crate) offset: i64,
    pub(crate) index: Option<LocalIndexExpr>,
    pub(crate) confidence: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalIndexExpr {
    pub(crate) root: SSAVar,
    pub(crate) scale: i128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalAffineValue {
    pub(crate) root: Option<SSAVar>,
    pub(crate) scale: i128,
    pub(crate) constant: i128,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct LocalMemoryVersionFacts {
    pub(crate) stores_by_site: HashMap<(u64, usize), Vec<MemoryVersion>>,
    pub(crate) loads_by_site: HashMap<(u64, usize), Vec<MemoryVersion>>,
    pub(crate) phi_inputs: HashMap<MemoryVersion, Vec<MemoryVersion>>,
    pub(crate) value_ids: HashMap<SSAVar, r2ssa::ValueId>,
}

impl LocalMemoryVersionFacts {
    fn from_prepared(prepared: &SsaArtifact) -> Self {
        let is_stack = |version: MemoryVersion| {
            prepared
                .objects()
                .object(version.object)
                .is_some_and(|object| {
                    matches!(
                        object.kind,
                        ObjectKind::StackSlot {
                            space: r2il::SpaceId::Ram,
                            ..
                        } | ObjectKind::FrameObject {
                            space: r2il::SpaceId::Ram,
                            ..
                        }
                    )
                })
        };
        let mut facts = Self::default();
        facts.value_ids.extend(
            prepared
                .graph()
                .values
                .iter()
                .map(|value| (value.var.clone(), value.id)),
        );
        for block in prepared.function().blocks() {
            for (op_index, op) in block.ops.iter().enumerate() {
                if !matches!(
                    op,
                    SSAOp::Load {
                        space: r2il::SpaceId::Ram,
                        ..
                    } | SSAOp::Store {
                        space: r2il::SpaceId::Ram,
                        ..
                    }
                ) {
                    continue;
                }
                let store_versions = prepared
                    .memory_defs_for_op_site(block.addr, op_index)
                    .into_iter()
                    .flatten()
                    .map(|fact| fact.next_version)
                    .filter(|version| is_stack(*version))
                    .collect::<Vec<_>>();
                if !store_versions.is_empty() {
                    facts
                        .stores_by_site
                        .insert((block.addr, op_index), store_versions);
                }
                let load_versions = prepared
                    .memory_uses_for_op_site(block.addr, op_index)
                    .into_iter()
                    .flatten()
                    .map(|fact| fact.version)
                    .filter(|version| is_stack(*version))
                    .collect::<Vec<_>>();
                if !load_versions.is_empty() {
                    facts
                        .loads_by_site
                        .insert((block.addr, op_index), load_versions);
                }
            }
        }
        for phis in prepared.memory().phis_by_block.values() {
            for phi in phis {
                if is_stack(phi.output_version) {
                    facts.phi_inputs.insert(
                        phi.output_version,
                        phi.inputs.iter().map(|(_, version)| *version).collect(),
                    );
                }
            }
        }
        facts
    }
}

#[derive(Default)]
pub(crate) struct LocalTypeEquivalence {
    pub(crate) ids: HashMap<SSAVar, usize>,
    pub(crate) vars: Vec<SSAVar>,
    pub(crate) parents: Vec<usize>,
    pub(crate) ranks: Vec<u8>,
}

impl LocalTypeEquivalence {
    fn id_for_var(&mut self, var: &SSAVar) -> Option<usize> {
        if var.is_const() {
            return None;
        }
        if let Some(id) = self.ids.get(var).copied() {
            return Some(id);
        }
        let id = self.parents.len();
        self.ids.insert(var.clone(), id);
        self.vars.push(var.clone());
        self.parents.push(id);
        self.ranks.push(0);
        Some(id)
    }

    fn find(&mut self, id: usize) -> usize {
        let parent = self.parents[id];
        if parent != id {
            self.parents[id] = self.find(parent);
        }
        self.parents[id]
    }

    fn union_vars(&mut self, lhs: &SSAVar, rhs: &SSAVar, ptr_bytes: u32) {
        if lhs.size != ptr_bytes || rhs.size != ptr_bytes {
            return;
        }
        let (Some(lhs), Some(rhs)) = (self.id_for_var(lhs), self.id_for_var(rhs)) else {
            return;
        };
        let lhs = self.find(lhs);
        let rhs = self.find(rhs);
        if lhs == rhs {
            return;
        }
        let (root, child) = if self.ranks[lhs] < self.ranks[rhs] {
            (rhs, lhs)
        } else {
            (lhs, rhs)
        };
        self.parents[child] = root;
        if self.ranks[lhs] == self.ranks[rhs] {
            self.ranks[root] = self.ranks[root].saturating_add(1);
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct InferredLocalFieldEvidence {
    pub(crate) reads: u32,
    pub(crate) writes: u32,
    pub(crate) widths: BTreeMap<u32, u32>,
    pub(crate) type_votes: BTreeMap<String, u32>,
    pub(crate) recursive_pointer_reads: u32,
    pub(crate) pointee_types: BTreeMap<String, u32>,
}

pub(crate) type LocalFieldEvidenceMap = HashMap<usize, BTreeMap<u64, InferredLocalFieldEvidence>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InferredLocalFieldType {
    Concrete(String),
    SelfPointer,
}

impl InferredLocalFieldType {
    fn shape_key(&self) -> &str {
        match self {
            Self::Concrete(ty) => ty,
            Self::SelfPointer => "self *",
        }
    }

    fn render(&self, struct_name: &str) -> String {
        match self {
            Self::Concrete(ty) => ty.clone(),
            Self::SelfPointer => format!("struct {struct_name} *"),
        }
    }
}

pub(crate) fn collect_prepared_pointer_arg_slot_map(
    prepared: &SsaArtifact,
) -> HashMap<String, usize> {
    let context = prepared.machine_context();
    let abi = context.abi_model();
    if !abi.is_available() || !abi.argument_placement_is_coherent() {
        return HashMap::new();
    }

    let mut out = HashMap::new();
    for slot in abi.argument_registers() {
        let Ok(index) = usize::try_from(slot.index()) else {
            continue;
        };
        for (name, storage) in context.register_storages_by_name() {
            if *storage == slot.storage() {
                out.insert(name.to_ascii_lowercase(), index);
            }
        }
    }
    out
}

pub(crate) fn local_struct_type_slots(
    blocks: &[SSABlock],
    pointer_arg_slot_map: &HashMap<String, usize>,
    ptr_bits: u32,
) -> HashMap<SSAVar, usize> {
    let ptr_bytes = (ptr_bits / 8).max(1);
    let mut classes = LocalTypeEquivalence::default();
    let mut seeds = Vec::new();

    let remember_seed =
        |classes: &mut LocalTypeEquivalence, seeds: &mut Vec<(usize, usize)>, var: &SSAVar| {
            if var.size != ptr_bytes || var.version != 0 {
                return;
            }
            let Some(slot) = pointer_arg_slot_map
                .get(var.name().to_ascii_lowercase().as_str())
                .copied()
            else {
                return;
            };
            if let Some(id) = classes.id_for_var(var) {
                seeds.push((id, slot));
            }
        };

    for block in blocks {
        for phi in &block.phis {
            remember_seed(&mut classes, &mut seeds, &phi.dst);
            for (_, source) in &phi.sources {
                remember_seed(&mut classes, &mut seeds, source);
                classes.union_vars(&phi.dst, source, ptr_bytes);
            }
        }
        for op in &block.ops {
            if let Some(dst) = op.dst() {
                remember_seed(&mut classes, &mut seeds, dst);
            }
            op.for_each_source(&mut |source| {
                remember_seed(&mut classes, &mut seeds, source);
            });
            match op {
                SSAOp::Copy { dst, src }
                | SSAOp::Cast { dst, src }
                | SSAOp::New { dst, src }
                | SSAOp::IntZExt { dst, src }
                | SSAOp::IntSExt { dst, src } => classes.union_vars(dst, src, ptr_bytes),
                _ => {}
            }
        }
    }

    let mut slots_by_root: HashMap<usize, BTreeSet<usize>> = HashMap::new();
    for (id, slot) in seeds {
        let root = classes.find(id);
        slots_by_root.entry(root).or_default().insert(slot);
    }
    let named_ids = classes.vars.iter().cloned().enumerate().collect::<Vec<_>>();
    let mut slots = HashMap::new();
    for (id, var) in named_ids {
        let root = classes.find(id);
        let Some(root_slots) = slots_by_root.get(&root) else {
            continue;
        };
        if root_slots.len() == 1
            && let Some(slot) = root_slots.first().copied()
        {
            slots.insert(var, slot);
        }
    }
    slots
}

/// Compute exact pointee-type evidence for SSA values in one reverse flow.
///
/// Edges point from a derived pointer back to its source. Starting at every
/// memory address operand lets dereference types flow through transparent
/// aliases, phis, and constant pointer arithmetic without rescanning the
/// function once per candidate field.
pub(crate) fn local_pointer_pointee_types(
    blocks: &[SSABlock],
    ptr_bits: u32,
    scalar_signedness: &HashMap<SSAVar, BTreeSet<ScalarSignednessEvidence>>,
) -> HashMap<SSAVar, BTreeSet<String>> {
    let ptr_bytes = (ptr_bits / 8).max(1);
    let mut reverse_edges = HashMap::<SSAVar, BTreeSet<SSAVar>>::new();
    let mut types = HashMap::<SSAVar, BTreeSet<String>>::new();
    let mut link = |source: &SSAVar, derived: &SSAVar| {
        if source.size == ptr_bytes && derived.size == ptr_bytes {
            reverse_edges
                .entry(derived.clone())
                .or_default()
                .insert(source.clone());
        }
    };

    for block in blocks {
        for phi in &block.phis {
            for (_, source) in &phi.sources {
                link(source, &phi.dst);
            }
        }
        for op in &block.ops {
            match op {
                SSAOp::Copy { dst, src }
                | SSAOp::Cast { dst, src }
                | SSAOp::New { dst, src }
                | SSAOp::IntZExt { dst, src }
                | SSAOp::IntSExt { dst, src }
                | SSAOp::Trunc { dst, src } => link(src, dst),
                SSAOp::Subpiece {
                    dst,
                    src,
                    offset: 0,
                } => link(src, dst),
                SSAOp::Phi { dst, sources } => {
                    for source in sources {
                        link(source, dst);
                    }
                }
                SSAOp::IntAdd { dst, a, b } => {
                    if a.is_const() {
                        link(b, dst);
                    } else if b.is_const() {
                        link(a, dst);
                    }
                }
                SSAOp::IntSub { dst, a, b } if b.is_const() => link(a, dst),
                SSAOp::Load {
                    dst,
                    space: r2il::SpaceId::Ram,
                    addr,
                } => {
                    types
                        .entry(addr.clone())
                        .or_default()
                        .extend(local_scalar_type_names(dst, scalar_signedness));
                }
                SSAOp::Store {
                    space: r2il::SpaceId::Ram,
                    addr,
                    val,
                } => {
                    types
                        .entry(addr.clone())
                        .or_default()
                        .extend(local_scalar_type_names(val, scalar_signedness));
                }
                _ => {}
            }
        }
    }

    let mut ready = types.keys().cloned().collect::<VecDeque<_>>();
    while let Some(derived) = ready.pop_front() {
        let Some(observed) = types.get(&derived).cloned() else {
            continue;
        };
        let Some(sources) = reverse_edges.get(&derived) else {
            continue;
        };
        for source in sources {
            let entry = types.entry(source.clone()).or_default();
            let before = entry.len();
            entry.extend(observed.iter().cloned());
            if entry.len() != before {
                ready.push_back(source.clone());
            }
        }
    }
    types
}

pub(crate) fn local_scalar_type_names(
    var: &SSAVar,
    signedness: &HashMap<SSAVar, BTreeSet<ScalarSignednessEvidence>>,
) -> BTreeSet<String> {
    let observed = signedness.get(var);
    if observed.is_none_or(BTreeSet::is_empty) {
        return BTreeSet::from([size_to_type(var.size)]);
    }
    observed
        .into_iter()
        .flatten()
        .map(|value| match value {
            ScalarSignednessEvidence::Signed => size_to_type(var.size),
            ScalarSignednessEvidence::Unsigned => size_to_unsigned_type(var.size),
        })
        .collect()
}

pub(crate) fn add_local_scalar_type_votes(
    votes: &mut BTreeMap<String, u32>,
    var: &SSAVar,
    signedness: &HashMap<SSAVar, BTreeSet<ScalarSignednessEvidence>>,
) {
    for ty in local_scalar_type_names(var, signedness) {
        *votes.entry(ty).or_insert(0) += 1;
    }
}

pub(crate) fn combine_local_affine_values(
    left: LocalAffineValue,
    right: LocalAffineValue,
    right_sign: i128,
) -> Option<LocalAffineValue> {
    let root = match (&left.root, &right.root) {
        (Some(left), Some(right)) if left == right => Some(left.clone()),
        (Some(left), None) => Some(left.clone()),
        (None, Some(right)) => Some(right.clone()),
        (None, None) => None,
        _ => return None,
    };
    let scale = left
        .scale
        .checked_add(right.scale.checked_mul(right_sign)?)?;
    let constant = left
        .constant
        .checked_add(right.constant.checked_mul(right_sign)?)?;
    Some(LocalAffineValue {
        root: (scale != 0).then_some(root).flatten(),
        scale,
        constant,
    })
}

pub(crate) fn multiply_local_affine_value(
    value: LocalAffineValue,
    multiplier: i128,
) -> Option<LocalAffineValue> {
    Some(LocalAffineValue {
        root: value.root,
        scale: value.scale.checked_mul(multiplier)?,
        constant: value.constant.checked_mul(multiplier)?,
    })
}

pub(crate) fn local_affine_value(
    var: &SSAVar,
    definitions: &HashMap<SSAVar, SSAOp>,
    ptr_bits: u32,
    memo: &mut HashMap<SSAVar, Option<LocalAffineValue>>,
    visiting: &mut HashSet<SSAVar>,
) -> Option<LocalAffineValue> {
    if let Some(value) = memo.get(var) {
        return value.clone();
    }
    if let Some(constant) = exact_ssa_const_offset(var, ptr_bits) {
        return Some(LocalAffineValue {
            root: None,
            scale: 0,
            constant: i128::from(constant),
        });
    }
    if !visiting.insert(var.clone()) {
        return None;
    }
    let result = (|| match definitions.get(var) {
        None
        | Some(SSAOp::Load {
            space: r2il::SpaceId::Ram,
            ..
        })
        | Some(SSAOp::Phi { .. }) => Some(LocalAffineValue {
            root: Some(var.clone()),
            scale: 1,
            constant: 0,
        }),
        Some(
            SSAOp::Copy { src, .. }
            | SSAOp::Cast { src, .. }
            | SSAOp::New { src, .. }
            | SSAOp::IntZExt { src, .. }
            | SSAOp::IntSExt { src, .. }
            | SSAOp::Trunc { src, .. }
            | SSAOp::Subpiece { src, .. },
        ) => local_affine_value(src, definitions, ptr_bits, memo, visiting),
        Some(SSAOp::IntNegate { src, .. }) => {
            let value = local_affine_value(src, definitions, ptr_bits, memo, visiting)?;
            multiply_local_affine_value(value, -1)
        }
        Some(SSAOp::IntAdd { a, b, .. }) => {
            let left = local_affine_value(a, definitions, ptr_bits, memo, visiting)?;
            let right = local_affine_value(b, definitions, ptr_bits, memo, visiting)?;
            combine_local_affine_values(left, right, 1)
        }
        Some(SSAOp::IntSub { a, b, .. }) => {
            let left = local_affine_value(a, definitions, ptr_bits, memo, visiting)?;
            let right = local_affine_value(b, definitions, ptr_bits, memo, visiting)?;
            combine_local_affine_values(left, right, -1)
        }
        Some(SSAOp::IntMult { a, b, .. }) => {
            let left = local_affine_value(a, definitions, ptr_bits, memo, visiting)?;
            let right = local_affine_value(b, definitions, ptr_bits, memo, visiting)?;
            if left.root.is_none() && left.scale == 0 {
                multiply_local_affine_value(right, left.constant)
            } else if right.root.is_none() && right.scale == 0 {
                multiply_local_affine_value(left, right.constant)
            } else {
                None
            }
        }
        Some(SSAOp::IntLeft { a, b, .. }) => {
            let shift = exact_ssa_const_offset(b, ptr_bits)?;
            let shift = u32::try_from(shift).ok()?;
            let multiplier = 1i128.checked_shl(shift)?;
            let value = local_affine_value(a, definitions, ptr_bits, memo, visiting)?;
            multiply_local_affine_value(value, multiplier)
        }
        Some(_) => None,
    })();
    visiting.remove(var);
    memo.insert(var.clone(), result.clone());
    result
}

pub(crate) fn record_local_index_stride(
    expr: &LocalAddrExpr,
    access_size: u32,
    evidence: &mut HashMap<usize, BTreeSet<u64>>,
    diagnostics: &mut TypeAnalysisDiagnostics,
) -> bool {
    let Some(index) = &expr.index else {
        return true;
    };
    let Ok(stride) = u64::try_from(index.scale) else {
        return false;
    };
    let Some(end_offset) = u64::try_from(expr.offset)
        .ok()
        .and_then(|offset| offset.checked_add(u64::from(access_size)))
    else {
        return false;
    };
    if stride == 0 || access_size == 0 || end_offset > stride {
        diagnostics.warnings.push(format!(
            "slot {} indexed access +0x{:x}/{} exceeds stride 0x{stride:x}",
            expr.slot, expr.offset, access_size
        ));
        return false;
    }
    evidence.entry(expr.slot).or_default().insert(stride);
    true
}

pub(crate) fn local_expr_for_memory_version(
    version: MemoryVersion,
    values: &HashMap<MemoryVersion, LocalAddrExpr>,
    phi_inputs: &HashMap<MemoryVersion, Vec<MemoryVersion>>,
    visiting: &mut HashSet<MemoryVersion>,
) -> Option<LocalAddrExpr> {
    if let Some(value) = values.get(&version) {
        return Some(value.clone());
    }
    if !visiting.insert(version) {
        return None;
    }
    let result = (|| {
        let sources = phi_inputs.get(&version)?;
        let mut selected: Option<LocalAddrExpr> = None;
        for source in sources {
            let value = local_expr_for_memory_version(*source, values, phi_inputs, visiting)?;
            selected = match selected {
                None => Some(value),
                Some(previous)
                    if previous.slot == value.slot
                        && previous.offset == value.offset
                        && previous.index == value.index =>
                {
                    Some(LocalAddrExpr {
                        slot: previous.slot,
                        offset: previous.offset,
                        index: previous.index,
                        confidence: previous.confidence.min(value.confidence),
                    })
                }
                _ => return None,
            };
        }
        selected
    })();
    visiting.remove(&version);
    result
}

pub(crate) fn local_expr_for_memory_versions(
    versions: &[MemoryVersion],
    values: &HashMap<MemoryVersion, LocalAddrExpr>,
    phi_inputs: &HashMap<MemoryVersion, Vec<MemoryVersion>>,
) -> Option<LocalAddrExpr> {
    let mut selected: Option<LocalAddrExpr> = None;
    for version in versions {
        let value =
            local_expr_for_memory_version(*version, values, phi_inputs, &mut HashSet::new())?;
        selected = match selected {
            None => Some(value),
            Some(previous)
                if previous.slot == value.slot
                    && previous.offset == value.offset
                    && previous.index == value.index =>
            {
                Some(LocalAddrExpr {
                    slot: previous.slot,
                    offset: previous.offset,
                    index: previous.index,
                    confidence: previous.confidence.min(value.confidence),
                })
            }
            _ => return None,
        };
    }
    selected
}

pub(crate) fn infer_local_struct_artifacts_from_prepared_ssa(
    prepared: &SsaArtifact,
    arch_name: Option<&str>,
    ptr_bits: u32,
    diagnostics: &mut TypeAnalysisDiagnostics,
) -> LocalStructArtifacts {
    let blocks = prepared.function().blocks();
    let memory_versions = LocalMemoryVersionFacts::from_prepared(prepared);
    let architecture = prepared.machine_context().architecture_family();
    let pointer_arg_slots = collect_prepared_pointer_arg_slot_map(prepared);
    let mut artifacts = infer_local_struct_artifacts_from_blocks(
        blocks,
        Some(&memory_versions),
        arch_name,
        architecture,
        &pointer_arg_slots,
        ptr_bits,
        diagnostics,
    );
    artifacts.indexed_accesses = prepared_parameter_indexed_accesses(prepared);
    artifacts
}

pub(crate) fn prepared_parameter_indexed_accesses(
    prepared: &SsaArtifact,
) -> Vec<ScalarArrayRenderCandidate> {
    let mut candidates = Vec::new();
    for access in prepared.certificates().memory_accesses.values() {
        if access.space != r2il::SpaceId::Ram {
            continue;
        }
        let Some(address) = prepared.addresses().parameter_expression(access.address) else {
            continue;
        };
        let [index] = address.terms.as_slice() else {
            continue;
        };
        let Ok(element_stride) = u64::try_from(index.coefficient) else {
            continue;
        };
        let Ok(field_offset) = u64::try_from(address.offset) else {
            continue;
        };
        if element_stride == 0
            || field_offset >= element_stride
            || u64::from(access.width) > element_stride - field_offset
            || !prepared
                .certificates()
                .expressions
                .get(&index.value)
                .is_some_and(|certificate| certificate.renderable)
        {
            continue;
        }
        candidates.push(ScalarArrayRenderCandidate {
            slot: address.parameter,
            block_addr: access.block_addr,
            op_index: access.op_index,
            is_write: access.is_write,
            field_offset,
            element_stride,
            access_width: access.width,
            index_value: Some(index.value),
        });
    }
    candidates.sort();
    candidates.dedup();
    candidates
}

pub(crate) fn infer_local_struct_artifacts_from_blocks(
    ssa_blocks: &[SSABlock],
    memory_versions: Option<&LocalMemoryVersionFacts>,
    arch_name: Option<&str>,
    architecture: r2ssa::MachineArchitectureFamily,
    pointer_arg_slot_map: &HashMap<String, usize>,
    ptr_bits: u32,
    diagnostics: &mut TypeAnalysisDiagnostics,
) -> LocalStructArtifacts {
    let type_slots = local_struct_type_slots(ssa_blocks, pointer_arg_slot_map, ptr_bits);
    let scalar_signedness = infer_scalar_signedness(
        ssa_blocks.iter().flat_map(|block| block.ops.iter()),
        ssa_blocks.iter().flat_map(|block| {
            block
                .phis
                .iter()
                .flat_map(|phi| phi.sources.iter().map(|(_, source)| (source, &phi.dst)))
        }),
        arch_name,
    );
    let pointer_pointee_types =
        local_pointer_pointee_types(ssa_blocks, ptr_bits, &scalar_signedness);
    let (_, stack_bases, frame_bases) = recover_vars_arch_profile(architecture);
    let mut addr_exprs: HashMap<SSAVar, LocalAddrExpr> = HashMap::new();
    let mut stack_addr_offsets: HashMap<SSAVar, i64> = HashMap::new();
    let mut stack_slot_values: HashMap<(u64, i64), LocalAddrExpr> = HashMap::new();
    let mut memory_version_values = HashMap::<MemoryVersion, LocalAddrExpr>::new();
    let mut slot_field_evidence: LocalFieldEvidenceMap = HashMap::new();
    let mut slot_stride_evidence = HashMap::<usize, BTreeSet<u64>>::new();
    let mut indexed_accesses = Vec::new();
    let offset_bound = 0x4000i64;
    let definitions = ssa_blocks
        .iter()
        .flat_map(|block| block.ops.iter())
        .filter_map(|op| op.dst().map(|dst| (dst.clone(), op.clone())))
        .collect::<HashMap<_, _>>();
    let mut affine_memo = HashMap::<SSAVar, Option<LocalAffineValue>>::new();

    for block in ssa_blocks {
        let mut seed_var = |var: &SSAVar| {
            if let Some(slot) = type_slots.get(var).copied() {
                addr_exprs.entry(var.clone()).or_insert(LocalAddrExpr {
                    slot,
                    offset: 0,
                    index: None,
                    confidence: if var.version == 0 { 92 } else { 86 },
                });
            }
        };
        for phi in &block.phis {
            seed_var(&phi.dst);
            for (_, source) in &phi.sources {
                seed_var(source);
            }
        }
        for op in &block.ops {
            if let Some(dst) = op.dst() {
                seed_var(dst);
            }
            op.for_each_source(&mut seed_var);
        }
    }

    let is_stack_base = |name: &str| stack_bases.contains(&name) || frame_bases.contains(&name);

    loop {
        let mut changed = false;
        for block in ssa_blocks {
            for (op_index, op) in block.ops.iter().enumerate() {
                let addr_of = |var: &SSAVar, map: &HashMap<SSAVar, LocalAddrExpr>| {
                    if var.version == 0 {
                        let key = var.name().to_ascii_lowercase();
                        if let Some(slot) = pointer_arg_slot_map.get(key.as_str()).copied() {
                            return Some(LocalAddrExpr {
                                slot,
                                offset: 0,
                                index: None,
                                confidence: 92,
                            });
                        }
                    }
                    map.get(var).cloned()
                };
                let stack_slot_of =
                    |var: &SSAVar, stack_map: &HashMap<SSAVar, i64>| stack_map.get(var).copied();
                let set_expr =
                    |dst: &SSAVar,
                     expr: LocalAddrExpr,
                     map: &mut HashMap<SSAVar, LocalAddrExpr>| {
                        match map.get(dst) {
                            Some(prev) if prev.confidence >= expr.confidence => false,
                            _ => {
                                map.insert(dst.clone(), expr);
                                true
                            }
                        }
                    };
                let set_stack_slot =
                    |dst: &SSAVar, offset: i64, map: &mut HashMap<SSAVar, i64>| match map
                        .get(dst)
                        .copied()
                    {
                        Some(prev) if prev == offset => false,
                        _ => {
                            map.insert(dst.clone(), offset);
                            true
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
                        if let Some(offset) = stack_slot_of(src, &stack_addr_offsets) {
                            changed |= set_stack_slot(dst, offset, &mut stack_addr_offsets);
                        }
                    }
                    SSAOp::Phi { dst, sources } => {
                        let mut selected = None;
                        let mut selected_slot = None;
                        for src in sources {
                            let Some(expr) = addr_of(src, &addr_exprs) else {
                                selected = None;
                                break;
                            };
                            selected = match selected {
                                None => Some(expr),
                                Some(prev)
                                    if prev.slot == expr.slot
                                        && prev.offset == expr.offset
                                        && prev.index == expr.index =>
                                {
                                    Some(LocalAddrExpr {
                                        slot: prev.slot,
                                        offset: prev.offset,
                                        index: prev.index,
                                        confidence: prev.confidence.max(expr.confidence),
                                    })
                                }
                                _ => None,
                            };
                            let Some(slot) = stack_slot_of(src, &stack_addr_offsets) else {
                                selected_slot = None;
                                break;
                            };
                            selected_slot = match selected_slot {
                                None => Some(slot),
                                Some(prev) if prev == slot => Some(prev),
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
                        if let Some(slot) = selected_slot {
                            changed |= set_stack_slot(dst, slot, &mut stack_addr_offsets);
                        }
                    }
                    SSAOp::IntAdd { dst, a, b } => {
                        if let Some(off) = exact_ssa_const_offset(b, ptr_bits) {
                            let a_lower = a.name().to_ascii_lowercase();
                            if is_stack_base(a_lower.as_str()) {
                                changed |= set_stack_slot(dst, off, &mut stack_addr_offsets);
                            }
                        }
                        if let Some(off) = exact_ssa_const_offset(a, ptr_bits) {
                            let b_lower = b.name().to_ascii_lowercase();
                            if is_stack_base(b_lower.as_str()) {
                                changed |= set_stack_slot(dst, off, &mut stack_addr_offsets);
                            }
                        }
                        if let Some(base) = addr_of(a, &addr_exprs)
                            && let Some(delta) = exact_ssa_const_offset(b, ptr_bits)
                        {
                            let off = base.offset.saturating_add(delta);
                            if (-offset_bound..=offset_bound).contains(&off) {
                                changed |= set_expr(
                                    dst,
                                    LocalAddrExpr {
                                        slot: base.slot,
                                        offset: off,
                                        index: base.index,
                                        confidence: base.confidence.saturating_sub(1),
                                    },
                                    &mut addr_exprs,
                                );
                            }
                        } else if let Some(base) = addr_of(a, &addr_exprs)
                            && base.index.is_none()
                            && let Some(affine) = local_affine_value(
                                b,
                                &definitions,
                                ptr_bits,
                                &mut affine_memo,
                                &mut HashSet::new(),
                            )
                            && let Some(root) = affine.root
                            && affine.scale > 0
                            && let (Ok(delta), Ok(scale)) =
                                (i64::try_from(affine.constant), u64::try_from(affine.scale))
                        {
                            let off = base.offset.saturating_add(delta);
                            if (-offset_bound..=offset_bound).contains(&off) {
                                changed |= set_expr(
                                    dst,
                                    LocalAddrExpr {
                                        slot: base.slot,
                                        offset: off,
                                        index: Some(LocalIndexExpr {
                                            root,
                                            scale: i128::from(scale),
                                        }),
                                        confidence: base.confidence.saturating_sub(2),
                                    },
                                    &mut addr_exprs,
                                );
                            }
                        } else if let Some(base) = addr_of(b, &addr_exprs)
                            && let Some(delta) = exact_ssa_const_offset(a, ptr_bits)
                        {
                            let off = base.offset.saturating_add(delta);
                            if (-offset_bound..=offset_bound).contains(&off) {
                                changed |= set_expr(
                                    dst,
                                    LocalAddrExpr {
                                        slot: base.slot,
                                        offset: off,
                                        index: base.index,
                                        confidence: base.confidence.saturating_sub(1),
                                    },
                                    &mut addr_exprs,
                                );
                            }
                        } else if let Some(base) = addr_of(b, &addr_exprs)
                            && base.index.is_none()
                            && let Some(affine) = local_affine_value(
                                a,
                                &definitions,
                                ptr_bits,
                                &mut affine_memo,
                                &mut HashSet::new(),
                            )
                            && let Some(root) = affine.root
                            && affine.scale > 0
                            && let (Ok(delta), Ok(scale)) =
                                (i64::try_from(affine.constant), u64::try_from(affine.scale))
                        {
                            let off = base.offset.saturating_add(delta);
                            if (-offset_bound..=offset_bound).contains(&off) {
                                changed |= set_expr(
                                    dst,
                                    LocalAddrExpr {
                                        slot: base.slot,
                                        offset: off,
                                        index: Some(LocalIndexExpr {
                                            root,
                                            scale: i128::from(scale),
                                        }),
                                        confidence: base.confidence.saturating_sub(2),
                                    },
                                    &mut addr_exprs,
                                );
                            }
                        }
                    }
                    SSAOp::IntSub { dst, a, b } => {
                        if let Some(delta) = exact_ssa_const_offset(b, ptr_bits) {
                            let a_lower = a.name().to_ascii_lowercase();
                            if is_stack_base(a_lower.as_str()) {
                                changed |= set_stack_slot(
                                    dst,
                                    delta.saturating_neg(),
                                    &mut stack_addr_offsets,
                                );
                            }
                        }
                        if let Some(base) = addr_of(a, &addr_exprs)
                            && let Some(delta) = exact_ssa_const_offset(b, ptr_bits)
                        {
                            let off = base.offset.saturating_sub(delta);
                            if (-offset_bound..=offset_bound).contains(&off) {
                                changed |= set_expr(
                                    dst,
                                    LocalAddrExpr {
                                        slot: base.slot,
                                        offset: off,
                                        index: base.index,
                                        confidence: base.confidence.saturating_sub(1),
                                    },
                                    &mut addr_exprs,
                                );
                            }
                        } else if let Some(base) = addr_of(a, &addr_exprs)
                            && base.index.is_none()
                            && let Some(affine) = local_affine_value(
                                b,
                                &definitions,
                                ptr_bits,
                                &mut affine_memo,
                                &mut HashSet::new(),
                            )
                            && let Some(root) = affine.root
                            && affine.scale < 0
                            && let (Some(delta), Some(scale)) =
                                (affine.constant.checked_neg(), affine.scale.checked_neg())
                            && let (Ok(delta), Ok(scale)) =
                                (i64::try_from(delta), u64::try_from(scale))
                        {
                            let off = base.offset.saturating_add(delta);
                            if (-offset_bound..=offset_bound).contains(&off) {
                                changed |= set_expr(
                                    dst,
                                    LocalAddrExpr {
                                        slot: base.slot,
                                        offset: off,
                                        index: Some(LocalIndexExpr {
                                            root,
                                            scale: i128::from(scale),
                                        }),
                                        confidence: base.confidence.saturating_sub(2),
                                    },
                                    &mut addr_exprs,
                                );
                            }
                        }
                    }
                    SSAOp::Store {
                        space: r2il::SpaceId::Ram,
                        addr,
                        val,
                    } => {
                        if let Some(offset) = stack_slot_of(addr, &stack_addr_offsets)
                            && let Some(mut expr) = addr_of(val, &addr_exprs)
                        {
                            expr.confidence = expr.confidence.saturating_sub(2);
                            if let Some(versions) = memory_versions
                                .and_then(|facts| facts.stores_by_site.get(&(block.addr, op_index)))
                            {
                                for version in versions {
                                    match memory_version_values.get(version) {
                                        Some(previous)
                                            if previous.confidence >= expr.confidence => {}
                                        _ => {
                                            memory_version_values.insert(*version, expr.clone());
                                            changed = true;
                                        }
                                    }
                                }
                            } else if memory_versions.is_none() {
                                let key = (block.addr, offset);
                                match stack_slot_values.get(&key) {
                                    Some(previous) if previous.confidence >= expr.confidence => {}
                                    _ => {
                                        stack_slot_values.insert(key, expr);
                                        changed = true;
                                    }
                                }
                            }
                        }
                    }
                    SSAOp::Load {
                        dst,
                        space: r2il::SpaceId::Ram,
                        addr,
                    } => {
                        let exact_expr = memory_versions
                            .and_then(|facts| facts.loads_by_site.get(&(block.addr, op_index)))
                            .and_then(|versions| {
                                let facts = memory_versions?;
                                local_expr_for_memory_versions(
                                    versions,
                                    &memory_version_values,
                                    &facts.phi_inputs,
                                )
                            });
                        let fallback_expr = (memory_versions.is_none())
                            .then(|| stack_slot_of(addr, &stack_addr_offsets))
                            .flatten()
                            .and_then(|offset| {
                                stack_slot_values.get(&(block.addr, offset)).cloned()
                            });
                        if let Some(mut expr) = exact_expr.or(fallback_expr) {
                            expr.confidence = expr.confidence.saturating_sub(3);
                            changed |= set_expr(dst, expr, &mut addr_exprs);
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
            let resolve_addr = |addr: &SSAVar| -> Option<LocalAddrExpr> {
                if addr.version == 0 {
                    let key = addr.name().to_ascii_lowercase();
                    if let Some(slot) = pointer_arg_slot_map.get(key.as_str()).copied() {
                        return Some(LocalAddrExpr {
                            slot,
                            offset: 0,
                            index: None,
                            confidence: 92,
                        });
                    }
                }
                addr_exprs.get(addr).cloned()
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
                        let recursive_pointer = addr_exprs.get(dst).is_some_and(|value| {
                            value.slot == expr.slot && value.offset == 0 && value.index.is_none()
                        });
                        if !record_local_index_stride(
                            &expr,
                            dst.size,
                            &mut slot_stride_evidence,
                            diagnostics,
                        ) {
                            continue;
                        }
                        if let Some(index) = &expr.index
                            && let Ok(element_stride) = u64::try_from(index.scale)
                        {
                            indexed_accesses.push(ScalarArrayRenderCandidate {
                                slot: expr.slot,
                                block_addr: block.addr,
                                op_index,
                                is_write: false,
                                field_offset: expr.offset as u64,
                                element_stride,
                                access_width: dst.size,
                                index_value: memory_versions
                                    .and_then(|facts| facts.value_ids.get(&index.root).copied()),
                            });
                        }
                        let entry = slot_field_evidence
                            .entry(expr.slot)
                            .or_default()
                            .entry(expr.offset as u64)
                            .or_default();
                        entry.reads = entry.reads.saturating_add(1);
                        *entry.widths.entry(dst.size).or_insert(0) += 1;
                        add_local_scalar_type_votes(&mut entry.type_votes, dst, &scalar_signedness);
                        if recursive_pointer {
                            entry.recursive_pointer_reads =
                                entry.recursive_pointer_reads.saturating_add(1);
                        } else if let Some(types) = pointer_pointee_types.get(dst) {
                            for ty in types {
                                *entry.pointee_types.entry(ty.clone()).or_insert(0) += 1;
                            }
                        }
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
                        let recursive_pointer = addr_exprs.get(val).is_some_and(|value| {
                            value.slot == expr.slot && value.offset == 0 && value.index.is_none()
                        });
                        if !record_local_index_stride(
                            &expr,
                            val.size,
                            &mut slot_stride_evidence,
                            diagnostics,
                        ) {
                            continue;
                        }
                        if let Some(index) = &expr.index
                            && let Ok(element_stride) = u64::try_from(index.scale)
                        {
                            indexed_accesses.push(ScalarArrayRenderCandidate {
                                slot: expr.slot,
                                block_addr: block.addr,
                                op_index,
                                is_write: true,
                                field_offset: expr.offset as u64,
                                element_stride,
                                access_width: val.size,
                                index_value: memory_versions
                                    .and_then(|facts| facts.value_ids.get(&index.root).copied()),
                            });
                        }
                        let entry = slot_field_evidence
                            .entry(expr.slot)
                            .or_default()
                            .entry(expr.offset as u64)
                            .or_default();
                        entry.writes = entry.writes.saturating_add(1);
                        *entry.widths.entry(val.size).or_insert(0) += 1;
                        add_local_scalar_type_votes(&mut entry.type_votes, val, &scalar_signedness);
                        if recursive_pointer {
                            entry.recursive_pointer_reads =
                                entry.recursive_pointer_reads.saturating_add(1);
                        } else if let Some(types) = pointer_pointee_types.get(val) {
                            for ty in types {
                                *entry.pointee_types.entry(ty.clone()).or_insert(0) += 1;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    indexed_accesses.sort();
    indexed_accesses.dedup();

    let mut struct_decls = Vec::new();
    let mut slot_type_overrides = HashMap::new();
    let mut slot_field_profiles = HashMap::new();
    let mut slot_element_strides = HashMap::new();
    let mut slots: Vec<usize> = slot_field_evidence.keys().copied().collect();
    slots.sort_unstable();

    for slot in slots {
        let Some(fields_map) = slot_field_evidence.get(&slot) else {
            continue;
        };
        if fields_map.is_empty() {
            continue;
        }
        let mut shape = String::new();
        let element_stride = match slot_stride_evidence.get(&slot) {
            Some(strides) if strides.len() == 1 => strides.first().copied(),
            Some(strides) if !strides.is_empty() => {
                diagnostics.conflicts.push(format!(
                    "slot {slot} has conflicting indexed element strides {strides:?}"
                ));
                None
            }
            _ => None,
        };
        if let Some(stride) = element_stride {
            shape.push_str(&format!("stride:{stride:x};"));
        }
        let mut selected_fields = Vec::new();
        let mut confidence_acc = 0u32;
        for (offset, evidence) in fields_map {
            if evidence.type_votes.len() > 1 {
                diagnostics.conflicts.push(format!(
                    "slot {slot} field +0x{offset:x} conflicting type votes {:?}",
                    evidence.type_votes
                ));
            }
            let (field_type, total_votes, field_votes) = if evidence.recursive_pointer_reads > 0 {
                (
                    InferredLocalFieldType::SelfPointer,
                    evidence.recursive_pointer_reads,
                    evidence.recursive_pointer_reads,
                )
            } else if !evidence.pointee_types.is_empty() {
                let total_votes = evidence.pointee_types.values().copied().sum();
                let field_votes = evidence
                    .pointee_types
                    .values()
                    .copied()
                    .max()
                    .unwrap_or_default();
                let ty = if evidence.pointee_types.len() == 1 {
                    let pointee = evidence
                        .pointee_types
                        .first_key_value()
                        .expect("non-empty pointee types")
                        .0;
                    format!("{pointee} *")
                } else {
                    diagnostics.conflicts.push(format!(
                        "slot {slot} field +0x{offset:x} conflicting pointee types {:?}",
                        evidence.pointee_types
                    ));
                    "void *".to_string()
                };
                (
                    InferredLocalFieldType::Concrete(ty),
                    total_votes,
                    field_votes,
                )
            } else {
                let total_votes = evidence.type_votes.values().copied().sum();
                let Some((field_type, field_votes)) = evidence
                    .type_votes
                    .iter()
                    .max_by_key(|(_, count)| **count)
                    .map(|(ty, count)| (ty.clone(), *count))
                else {
                    continue;
                };
                (
                    InferredLocalFieldType::Concrete(field_type),
                    total_votes,
                    field_votes,
                )
            };
            let strength = ((field_votes.saturating_mul(100)) / total_votes.max(1)) as u8;
            let rw_bonus = if evidence.reads > 0 && evidence.writes > 0 {
                10
            } else {
                0
            };
            let field_conf = 70u8.saturating_add(strength / 3).saturating_add(rw_bonus);
            confidence_acc = confidence_acc.saturating_add(field_conf as u32);
            shape.push_str(&format!("{offset:x}:{};", field_type.shape_key()));
            selected_fields.push((*offset, field_type, field_conf));
        }
        if selected_fields.is_empty() {
            continue;
        }
        let avg_conf = (confidence_acc / selected_fields.len() as u32).clamp(1, 100) as u8;
        let allow_single_field =
            element_stride.is_none() && selected_fields.len() == 1 && avg_conf >= 94;
        if selected_fields.len() < 2 && !allow_single_field {
            continue;
        }
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        shape.hash(&mut hasher);
        let struct_name = format!("sla_struct_{:016x}", hasher.finish());
        let Some(fields) = selected_fields
            .into_iter()
            .map(|(offset, field_type, confidence)| {
                Some(StructFieldCandidate {
                    name: format!("f_{offset:x}"),
                    offset,
                    field_type: parse_c_type_like(&field_type.render(&struct_name), ptr_bits)?,
                    confidence,
                })
            })
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        let normalized_fields = fields
            .iter()
            // The profile is still keyed by spelling; render at that boundary
            // rather than keeping the candidate's type as text.
            .map(|field| {
                (
                    field.offset,
                    crate::signature_infer::render_type_spelling(&field.field_type, ptr_bits),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let Some(decl) =
            build_struct_decl_with_size(&struct_name, &fields, ptr_bits, element_stride)
        else {
            diagnostics.conflicts.push(format!(
                "slot {slot} inferred fields exceed indexed element stride {element_stride:?}"
            ));
            continue;
        };
        struct_decls.push(StructDeclCandidate {
            name: struct_name.clone(),
            decl,
            confidence: avg_conf.max(84),
            source: StructDeclSource::LocalInferred,
            fields,
        });
        slot_field_profiles.insert(slot, normalized_fields);
        slot_type_overrides.insert(slot, format!("struct {struct_name} *"));
        if let Some(stride) = element_stride {
            slot_element_strides.insert(slot, stride);
        }
    }

    LocalStructArtifacts {
        struct_decls,
        slot_type_overrides,
        slot_field_profiles,
        slot_element_strides,
        indexed_accesses,
    }
}

pub(crate) fn augment_local_struct_artifacts_with_projection(
    local_structs: &mut LocalStructArtifacts,
    projection: &SemanticTypeProjection,
    ptr_bits: u32,
) {
    for (slot, projected) in &projection.slot_field_profiles {
        let profile = local_structs.slot_field_profiles.entry(*slot).or_default();
        for (offset, field_type) in projected {
            profile.entry(*offset).or_insert(field_type.clone());
        }
        if profile.is_empty() || local_structs.slot_type_overrides.contains_key(slot) {
            continue;
        }
        let struct_name = format!("sla_struct_symbolic_arg{}", slot + 1);
        let Some(fields) = profile
            .iter()
            .map(|(offset, field_type)| {
                Some(StructFieldCandidate {
                    name: format!("f_{offset:x}"),
                    offset: *offset,
                    field_type: parse_c_type_like(field_type, ptr_bits)?,
                    confidence: 84,
                })
            })
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        let Some(decl) = build_struct_decl(&struct_name, &fields, ptr_bits) else {
            continue;
        };
        if !local_structs
            .struct_decls
            .iter()
            .any(|candidate| candidate.name.eq_ignore_ascii_case(&struct_name))
        {
            local_structs.struct_decls.push(StructDeclCandidate {
                name: struct_name.clone(),
                decl,
                confidence: 84,
                source: StructDeclSource::LocalInferred,
                fields,
            });
        }
        local_structs
            .slot_type_overrides
            .insert(*slot, format!("struct {struct_name} *"));
    }
}

pub(crate) fn augment_local_struct_artifacts_with_local_field_accesses(
    local_structs: &mut LocalStructArtifacts,
    local_field_accesses: &[LocalFieldAccessFact],
    ptr_bits: u32,
) {
    let mut projected_profiles = BTreeMap::<usize, BTreeMap<u64, String>>::new();
    for access in local_field_accesses {
        let field_type = access
            .field_type
            .clone()
            .unwrap_or_else(|| access.field_name.clone());
        projected_profiles
            .entry(access.slot)
            .or_default()
            .entry(access.field_offset)
            .or_insert(field_type);
    }

    for (slot, projected) in projected_profiles {
        let profile = local_structs.slot_field_profiles.entry(slot).or_default();
        for (offset, field_type) in projected {
            profile.entry(offset).or_insert(field_type);
        }
        if profile.is_empty() || local_structs.slot_type_overrides.contains_key(&slot) {
            continue;
        }

        let allow_single_field = profile.len() == 1;
        if profile.len() < 2 && !allow_single_field {
            continue;
        }
        let mut shape = String::new();
        let Some(fields) = profile
            .iter()
            .map(|(offset, field_type)| {
                shape.push_str(&format!("{offset:x}:{field_type};"));
                Some(StructFieldCandidate {
                    name: format!("f_{offset:x}"),
                    offset: *offset,
                    field_type: parse_c_type_like(field_type, ptr_bits)?,
                    confidence: 90,
                })
            })
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        shape.hash(&mut hasher);
        let struct_name = format!("sla_struct_{:016x}", hasher.finish());
        let Some(decl) = build_struct_decl(&struct_name, &fields, ptr_bits) else {
            continue;
        };
        if !local_structs
            .struct_decls
            .iter()
            .any(|candidate| candidate.name.eq_ignore_ascii_case(&struct_name))
        {
            local_structs.struct_decls.push(StructDeclCandidate {
                name: struct_name.clone(),
                decl,
                confidence: 90,
                source: StructDeclSource::LocalInferred,
                fields,
            });
        }
        local_structs
            .slot_type_overrides
            .insert(slot, format!("struct {struct_name} *"));
    }
}

pub(crate) fn signature_param_blocks_local_struct_override(
    signature: &Option<FunctionSignatureSpec>,
    slot: usize,
    raw_ty: &str,
    type_db: &ExternalTypeDb,
    ptr_bits: u32,
) -> bool {
    signature_param_blocks_generated_local_struct_override(
        signature.as_ref().and_then(|sig| sig.params.get(slot)),
        raw_ty,
        type_db,
        ptr_bits,
    )
}

pub(crate) fn prune_conflicting_local_struct_overrides(
    merged_signature: &Option<FunctionSignatureSpec>,
    struct_decls: &mut Vec<StructDeclCandidate>,
    slot_type_overrides: &mut HashMap<usize, String>,
    slot_field_profiles: &mut HashMap<usize, BTreeMap<u64, String>>,
    indexed_local_struct_refinement_slots: &HashSet<usize>,
    type_db: &ExternalTypeDb,
    ptr_bits: u32,
) {
    let blocked_slots = slot_type_overrides
        .iter()
        .filter_map(|(slot, raw_ty)| {
            (!indexed_local_struct_refinement_slots.contains(slot)
                && signature_param_blocks_local_struct_override(
                    merged_signature,
                    *slot,
                    raw_ty,
                    type_db,
                    ptr_bits,
                ))
            .then_some(*slot)
        })
        .collect::<Vec<_>>();
    if blocked_slots.is_empty() {
        return;
    }

    for slot in &blocked_slots {
        slot_type_overrides.remove(slot);
        slot_field_profiles.remove(slot);
    }

    let referenced_local_names = slot_type_overrides
        .values()
        .filter_map(|ty| ty.trim().strip_prefix("struct "))
        .filter_map(|rest| rest.trim_end().strip_suffix(" *"))
        .map(|name| name.to_ascii_lowercase())
        .collect::<HashSet<_>>();

    struct_decls.retain(|decl| {
        decl.source != StructDeclSource::LocalInferred
            || referenced_local_names.contains(&decl.name.to_ascii_lowercase())
    });
}

pub(crate) fn collect_external_struct_candidates_from_db(
    db: &ExternalTypeDb,
    ptr_bits: u32,
) -> Vec<StructDeclCandidate> {
    let mut keys: Vec<String> = db.structs.keys().cloned().collect();
    keys.sort();

    let mut out = Vec::new();
    'structs: for key in keys {
        let Some(st) = db.structs.get(&key) else {
            continue;
        };
        if type_name_is_opaque_placeholder(&st.name)
            || st.fields.is_empty()
            || db.is_aggregate_typedef(&st.name)
        {
            continue;
        }
        let mut fields = Vec::new();
        for (offset, field) in &st.fields {
            let raw_ty = field.ty.clone().unwrap_or_else(|| "uint8_t".to_string());
            let Some(field_type) = parse_c_type_like(&raw_ty, ptr_bits) else {
                continue 'structs;
            };
            fields.push(StructFieldCandidate {
                name: field.name.clone(),
                offset: *offset,
                field_type,
                confidence: 95,
            });
        }
        let Some(decl) = build_struct_decl(&st.name, &fields, ptr_bits) else {
            continue;
        };
        out.push(StructDeclCandidate {
            name: st.name.clone(),
            decl,
            confidence: 95,
            source: StructDeclSource::ExternalTypeDb,
            fields,
        });
    }
    out
}

pub(crate) fn merge_local_structs_into_type_db(
    db: &mut ExternalTypeDb,
    struct_decls: &[StructDeclCandidate],
    ptr_bits: u32,
) {
    for decl in struct_decls {
        let key = decl.name.to_ascii_lowercase();
        let mut fields = BTreeMap::new();
        for field in &decl.fields {
            fields.insert(
                field.offset,
                ExternalField {
                    name: field.name.clone(),
                    offset: field.offset,
                    ty: Some(render_signature_type(&field.field_type, ptr_bits)),
                },
            );
        }
        let candidate = ExternalStruct {
            name: decl.name.clone(),
            fields,
        };
        match db.structs.entry(key) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(candidate);
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if decl.source == StructDeclSource::LocalInferred
                    && (is_generated_local_struct_name(&decl.name) || entry.get().fields.is_empty())
                {
                    entry.insert(candidate);
                }
            }
        }
    }
}

pub(crate) fn canonical_field_type_key(ty: &str, ptr_bits: u32) -> String {
    let normalized = normalize_external_type_name(ty);
    parse_c_type_like(&normalized, ptr_bits)
        .map(|parsed| render_signature_type(&parsed, ptr_bits).to_ascii_lowercase())
        .unwrap_or_else(|| normalized.to_ascii_lowercase())
}

pub(crate) fn struct_fields_signature(
    fields: &[StructFieldCandidate],
    ptr_bits: u32,
) -> Vec<(u64, String)> {
    let mut out: Vec<(u64, String)> = fields
        .iter()
        .map(|f| {
            (
                f.offset,
                canonical_field_type_key(&render_signature_type(&f.field_type, ptr_bits), ptr_bits),
            )
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    out
}

pub(crate) fn local_struct_profile_score(
    decl: &StructDeclCandidate,
    profile: &BTreeMap<u64, String>,
    ptr_bits: u32,
) -> Option<(usize, usize, usize, i32)> {
    if decl.source != StructDeclSource::LocalInferred || profile.is_empty() {
        return None;
    }

    let field_map = decl
        .fields
        .iter()
        .map(|field| {
            (
                field.offset,
                canonical_field_type_key(
                    &render_signature_type(&field.field_type, ptr_bits),
                    ptr_bits,
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut offset_matches = 0usize;
    let mut typed_matches = 0usize;
    for (offset, ty) in profile {
        let Some(field_ty) = field_map.get(offset) else {
            continue;
        };
        offset_matches += 1;
        if field_ty == &canonical_field_type_key(ty, ptr_bits) {
            typed_matches += 1;
        }
    }

    (offset_matches > 0).then_some((
        offset_matches,
        typed_matches,
        decl.fields.len(),
        i32::from(decl.confidence),
    ))
}

pub(crate) fn prefer_stronger_local_struct_overrides(
    struct_decls: &[StructDeclCandidate],
    slot_type_overrides: &mut HashMap<usize, String>,
    slot_field_profiles: &HashMap<usize, BTreeMap<u64, String>>,
    ptr_bits: u32,
) {
    for (slot, ty) in slot_type_overrides.iter_mut() {
        let Some(profile) = slot_field_profiles.get(slot) else {
            continue;
        };
        if profile.is_empty() {
            continue;
        }

        let current_name = parse_struct_ptr_type_name(ty);
        let current_decl = current_name.as_ref().and_then(|name| {
            struct_decls
                .iter()
                .find(|decl| decl.name.eq_ignore_ascii_case(name))
        });
        if current_decl.is_some_and(|decl| decl.source == StructDeclSource::ExternalTypeDb)
            || current_name.is_some() && current_decl.is_none()
        {
            continue;
        }

        let current_score =
            current_decl.and_then(|decl| local_struct_profile_score(decl, profile, ptr_bits));
        let best_local = struct_decls
            .iter()
            .filter_map(|decl| {
                local_struct_profile_score(decl, profile, ptr_bits)
                    .map(|score| (score, decl.name.clone()))
            })
            .max_by(|(left_score, left_name), (right_score, right_name)| {
                left_score
                    .cmp(right_score)
                    .then_with(|| left_name.cmp(right_name))
            });

        let Some((best_score, best_name)) = best_local else {
            continue;
        };
        if current_score.is_none_or(|score| best_score > score) {
            *ty = format!("struct {} *", best_name);
        }
    }
}

pub(crate) fn structurally_compatible(
    local_fields: &[(u64, String)],
    ext_fields: &[(u64, String)],
) -> bool {
    if local_fields.is_empty() || ext_fields.is_empty() {
        return false;
    }
    let mut matches = 0usize;
    for (off, ty) in local_fields {
        if ext_fields
            .iter()
            .any(|(eoff, ety)| eoff == off && ety == ty)
        {
            matches += 1;
        }
    }
    matches >= local_fields.len().min(2)
}

pub(crate) fn align_local_structs_with_external(
    struct_decls: &mut [StructDeclCandidate],
    slot_type_overrides: &mut HashMap<usize, String>,
    slot_field_profiles: &HashMap<usize, BTreeMap<u64, String>>,
    external_structs: &[StructDeclCandidate],
    ptr_bits: u32,
) {
    let mut local_to_external: HashMap<String, String> = HashMap::new();
    for local in struct_decls.iter_mut() {
        if local.source != StructDeclSource::LocalInferred {
            continue;
        }
        let local_sig = struct_fields_signature(&local.fields, ptr_bits);
        for ext in external_structs {
            let ext_sig = struct_fields_signature(&ext.fields, ptr_bits);
            if structurally_compatible(&local_sig, &ext_sig) {
                local_to_external.insert(local.name.clone(), ext.name.clone());
                local.confidence = local.confidence.max(92);
                break;
            }
        }
    }

    for (slot, ty) in slot_type_overrides.iter_mut() {
        let Some(profile) = slot_field_profiles.get(slot) else {
            continue;
        };
        if profile.is_empty() {
            continue;
        }
        let replacement = external_structs.iter().find_map(|ext| {
            let ext_sig = struct_fields_signature(&ext.fields, ptr_bits);
            let local_sig: Vec<(u64, String)> = profile
                .iter()
                .map(|(off, ty)| (*off, canonical_field_type_key(ty, ptr_bits)))
                .collect();
            if structurally_compatible(&local_sig, &ext_sig) {
                Some(ext.name.clone())
            } else {
                None
            }
        });
        if let Some(ext_name) = replacement {
            *ty = format!("struct {} *", ext_name);
            continue;
        }
        if let Some(local_name) = ty
            .strip_prefix("struct ")
            .and_then(|s| s.strip_suffix(" *"))
            .map(str::to_string)
            && let Some(ext_name) = local_to_external.get(&local_name)
        {
            *ty = format!("struct {} *", ext_name);
        }
    }
}

pub(crate) fn build_struct_decl(
    struct_name: &str,
    fields: &[StructFieldCandidate],
    ptr_bits: u32,
) -> Option<String> {
    build_struct_decl_with_size(struct_name, fields, ptr_bits, None)
}

pub(crate) fn build_struct_decl_with_size(
    struct_name: &str,
    fields: &[StructFieldCandidate],
    ptr_bits: u32,
    exact_size: Option<u64>,
) -> Option<String> {
    if fields.is_empty() {
        return None;
    }
    let mut sorted_fields = fields.iter().collect::<Vec<_>>();
    sorted_fields.sort_by_key(|field| (field.offset, field.name.as_str()));

    let mut cursor = 0u64;
    let mut lines = Vec::new();
    for field in sorted_fields {
        if field.offset > cursor {
            let gap = field.offset - cursor;
            lines.push(format!("    uint8_t _pad_{cursor:x}[{gap}];"));
            cursor = field.offset;
        }

        let field_type = render_signature_type(&field.field_type, ptr_bits);
        lines.push(format!("    {} {};", field_type, field.name));
        cursor = cursor.saturating_add(estimate_c_type_size_bytes(&field_type, ptr_bits));
    }
    if let Some(exact_size) = exact_size {
        if cursor > exact_size {
            return None;
        }
        if cursor < exact_size {
            let gap = exact_size - cursor;
            lines.push(format!("    uint8_t _pad_{cursor:x}[{gap}];"));
        }
    }

    let body = lines.join("\n");
    Some(format!("struct {struct_name} {{\n{body}\n}};"))
}
