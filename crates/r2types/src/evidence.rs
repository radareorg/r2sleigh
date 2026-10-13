//! Types recovered from what the code does, for binaries that carry no types.
//!
//! With debug info the prototype is read; without it every type has to be
//! earned. This module gathers the evidence a prepared function already proves
//! -- the prototype of each callee at each call site, the width of every
//! certified memory access, the identities the SSA form guarantees -- and hands
//! the whole set to the type solver at once. Nothing here decides a type on its
//! own: a value keeps whatever the solved constraint system says, and a value no
//! constraint reaches stays unresolved.
//!
//! The nodes are the values and the memory objects of the prepared artifact
//! rather than SSA variables, because the evidence lives there: a call result is
//! a value, a stack home is an object, and the same solver runs over both.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::constraint::SolverNode;
use crate::context::{ExternalStackBase, StackSlotKey};
use crate::convert::{CTypeLike, to_c_type_like};
use crate::facts::FunctionType;
use crate::model::{Signedness, Type, TypeArena, TypeId};

use crate::signedness::ScalarSignednessEvidence;
use crate::solver::IncrementalSolver;
use r2ssa::dense::IdMap;

/// A node of the recovered type graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceNode {
    /// One SSA value of the prepared graph.
    Value(r2ssa::ValueId),
    /// One memory object: a stack home, a frame object, a heap block.
    Object(r2ssa::ObjectId),
}

impl SolverNode for EvidenceNode {
    fn solver_label(&self) -> String {
        match self {
            Self::Value(value) => format!("value{}", value.0),
            Self::Object(object) => format!("object{}", object.0),
        }
    }
}

/// What the solver concluded, spelled the way the evidence spelled it.
#[derive(Debug, Clone, Default)]
pub struct EvidenceTypes {
    value_types: r2ssa::dense::IdMap<r2ssa::ValueId, CTypeLike>,
    slot_types: BTreeMap<StackSlotKey, CTypeLike>,
}

impl EvidenceTypes {
    pub fn is_empty(&self) -> bool {
        self.value_types.is_empty() && self.slot_types.is_empty()
    }

    pub fn value_type(&self, value: r2ssa::ValueId) -> Option<&CTypeLike> {
        self.value_types.get(value)
    }

    pub fn stack_slot_types(&self) -> impl Iterator<Item = (&StackSlotKey, &CTypeLike)> {
        self.slot_types.iter()
    }
}

/// Solve the recovered types of one prepared function.
///
/// `callsite_signatures` supplies the prototype of the callee reached from each
/// call site; call sites without one contribute no type evidence rather than a
/// default prototype, because a guessed arity would type arguments that no
/// callee declares.
pub fn solve_evidence_types(
    source: &r2ssa::SsaArtifact,
    callsite_signatures: &BTreeMap<r2ssa::CallSiteId, FunctionType>,
    signedness: &IdMap<r2ssa::ValueId, BTreeSet<ScalarSignednessEvidence>>,
    ptr_bits: u32,
) -> EvidenceTypes {
    let mut builder = EvidenceBuilder::new(source, ptr_bits);
    builder.gather_ssa_identities();
    builder.gather_scalar_signedness(signedness);
    builder.gather_callee_prototypes(callsite_signatures);
    builder.gather_memory_widths();
    builder.gather_allocation_element_widths(callsite_signatures);

    builder.gather_indexed_pointer_bases();
    builder.read_back()
}

/// Interning that keeps the lattice structural and the spelling intact.
///
/// `size_t` and `unsigned long` are one type to the lattice and two names to a
/// reader, and `void *` is the pointer that any object pointer refines, which is
/// the arena's `Top` rather than a distinct pointee. Interning resolves both;
/// the spelling is remembered per assertion so the reader still sees the name
/// the evidence used.
struct SpelledType {
    ty: TypeId,
    spelling: CTypeLike,
}

struct EvidenceBuilder<'a> {
    source: &'a r2ssa::SsaArtifact,
    ptr_bits: u32,
    /// The classes and their types as the evidence arrives; its arena interns every type.
    solver: IncrementalSolver<EvidenceNode>,
    /// Spellings asserted on a node, kept to name the solved type.
    spellings: Vec<(EvidenceNode, TypeId, CTypeLike)>,
    /// Bounds already asserted, so a refinement round can tell what is new.
    asserted: HashSet<(EvidenceNode, TypeId)>,
}

impl<'a> EvidenceBuilder<'a> {
    fn new(source: &'a r2ssa::SsaArtifact, ptr_bits: u32) -> Self {
        Self {
            source,
            ptr_bits,
            solver: IncrementalSolver::new(TypeArena::default()),
            spellings: Vec::new(),
            asserted: HashSet::new(),
        }
    }

    fn value_size(&self, value: r2ssa::ValueId) -> Option<u32> {
        self.source.value_var(value).map(|var| var.size)
    }

    fn value_is_constant(&self, value: r2ssa::ValueId) -> bool {
        self.source.graph().value(value).is_some_and(|graph_value| {
            let Some(bits) = graph_value.var.constant_bits() else {
                return false;
            };
            graph_value.canonical_storage.is_some_and(|storage| {
                storage.space == r2ssa::CanonicalStorageSpace::Constant
                    && storage.offset == bits
                    && storage.size == graph_value.var.size
            })
        })
    }

    fn equate(&mut self, a: r2ssa::ValueId, b: r2ssa::ValueId) {
        // A constant is compatible with every type, and one constant value is
        // shared by every use of that literal. Merging through it would fuse
        // unrelated variables into one class.
        if self.value_is_constant(a) || self.value_is_constant(b) {
            return;
        }
        if self.value_size(a) != self.value_size(b) {
            return;
        }
        self.solver
            .equal(&EvidenceNode::Value(a), &EvidenceNode::Value(b));
    }

    fn equate_nodes(&mut self, a: EvidenceNode, b: EvidenceNode) {
        self.solver.equal(&a, &b);
    }

    /// Record an upper bound, and report whether it was not already recorded.
    fn bound(&mut self, node: EvidenceNode, spelled: SpelledType) -> bool {
        if !self.asserted.insert((node, spelled.ty)) {
            return false;
        }
        self.spellings.push((node, spelled.ty, spelled.spelling));
        // An upper bound, not an assignment: two prototypes that both describe
        // one value must intersect, so the more specific one survives whatever
        // order the evidence reaches them in.
        self.solver.bound(&node, spelled.ty);
        true
    }

    /// Values the SSA form proves are the same value.
    ///
    /// A merge no observation reads (`SsaArtifact::unobserved_merges`) is
    /// left out: it carries no value the program uses, so it is no evidence
    /// that its sources share a type. A register reused for an index on one
    /// path and a pointer on the other merges both at the join, and equating
    /// through that merge typed the index a pointer.
    fn gather_ssa_identities(&mut self) {
        let graph = self.source.graph();
        let unobserved = self.source.unobserved_merges();
        let mut pairs = Vec::new();
        for inst in &graph.insts {
            let Some(output) = inst.output else {
                continue;
            };
            match &inst.payload {
                r2ssa::InstPayload::Phi { .. } if unobserved.contains(output) => {}
                r2ssa::InstPayload::Phi { .. } => {
                    for input in graph.inputs(inst.id) {
                        pairs.push((output, *input));
                    }
                }
                r2ssa::InstPayload::Op(r2ssa::SSAOp::Copy { .. } | r2ssa::SSAOp::New { .. }) => {
                    if let Some(input) = graph.inputs(inst.id).first() {
                        pairs.push((output, *input));
                    }
                }
                r2ssa::InstPayload::Op(_) => {}
            }
        }
        for (a, b) in pairs {
            self.equate(a, b);
        }
    }

    /// Signed and unsigned machine operations type the values they consume.
    ///
    /// The signedness pass already follows transparent same-width operations.
    /// SSA phi/cell identities are constraints in this builder, so a seed on
    /// either side reaches the same solver class without a second alias model.
    /// Conflicting signed and unsigned uses are both asserted: their meet is
    /// `Bottom`, and readback refuses only that value.
    fn gather_scalar_signedness(
        &mut self,
        inferred: &IdMap<r2ssa::ValueId, BTreeSet<ScalarSignednessEvidence>>,
    ) {
        for (value, evidence) in inferred {
            let Some(var) = self.source.graph().value(value).map(|value| &value.var) else {
                continue;
            };
            let Some(bits) = var.size.checked_mul(8) else {
                continue;
            };
            if !CTypeLike::is_integer_width(bits) {
                continue;
            }
            for evidence in evidence {
                let signedness = match evidence {
                    ScalarSignednessEvidence::Signed => Signedness::Signed,
                    ScalarSignednessEvidence::Unsigned => Signedness::Unsigned,
                };
                let ty = CTypeLike::Int { bits, signedness };
                let Some(spelled) = self.intern_spelled(&ty) else {
                    continue;
                };
                self.bound(EvidenceNode::Value(value), spelled);
            }
        }
    }

    /// What each callee declares about the values it is handed and returns.
    fn gather_callee_prototypes(
        &mut self,
        callsite_signatures: &BTreeMap<r2ssa::CallSiteId, FunctionType>,
    ) {
        let certificates = self.source.certificates();
        let mut bounds = Vec::new();

        for (call_site, certificate) in &certificates.callsites {
            let Some(signature) = callsite_signatures.get(call_site) else {
                continue;
            };
            for argument in &certificate.argument_certificates {
                let Some(declared) = signature.params.get(argument.index) else {
                    continue;
                };
                if self.value_is_constant(argument.value) {
                    continue;
                }
                bounds.push((EvidenceNode::Value(argument.value), declared.clone()));
            }
        }

        for (value, certificate) in &certificates.call_results {
            let Some(signature) = callsite_signatures.get(&certificate.call_site) else {
                continue;
            };
            // A derived result is some function of the returned value, not the
            // returned value, so the callee's return type does not describe it.
            if !certificate.relation.is_identity() {
                continue;
            }
            bounds.push((EvidenceNode::Value(value), signature.return_type.clone()));
        }

        for (node, declared) in bounds {
            let Some(spelled) = self.intern_spelled(&declared) else {
                continue;
            };
            self.bound(node, spelled);
        }
    }

    /// Every certified access says its address is a pointer and how wide the
    /// thing it points at is, and ties a whole-cell home to the value it holds.
    fn gather_memory_widths(&mut self) {
        let certificates = self.source.certificates();
        let mut address_bounds = Vec::new();
        let mut cell_pairs = Vec::new();

        let scalar_cells = self.scalar_memory_cells();

        for access in certificates.memory_accesses.values() {
            if access.space != r2il::SpaceId::Ram {
                continue;
            }
            if !self.value_is_constant(access.address)
                && let Some(elem) = pointee_type_for_width(access.width)
            {
                let elem = self.pointee_with_loaded_signedness(access, elem);
                address_bounds.push((EvidenceNode::Value(access.address), elem.clone()));
                if let Some(parameter) = self.provenance_parameter_value(access) {
                    address_bounds.push((EvidenceNode::Value(parameter), elem));
                }
            }
            let Some(value) = access.value else {
                continue;
            };
            if !scalar_cells.contains(&access.object) || self.value_is_constant(value) {
                continue;
            }
            cell_pairs.push((
                EvidenceNode::Value(value),
                EvidenceNode::Object(access.object),
            ));
        }

        for (node, elem) in address_bounds {
            let Some(spelled) = self.intern_spelled(&elem) else {
                continue;
            };
            self.bound(node, spelled);
        }
        for (value, object) in cell_pairs {
            self.equate_nodes(value, object);
        }
    }

    /// The exact formal parameter at the base of one certified RAM address.
    ///
    /// Affine provenance is the owner of base identity across arithmetic and
    /// proven stack spills. Matching its retained storage back to the source
    /// boundary keeps this keyed by `ValueId`; a positional index alone is not
    /// enough to assert a type on a graph value.
    fn provenance_parameter_value(
        &self,
        access: &r2ssa::MemoryAccessCertificate,
    ) -> Option<r2ssa::ValueId> {
        if access.space != r2il::SpaceId::Ram {
            return None;
        }
        let address = self
            .source
            .addresses()
            .parameter_expression(access.address)?;
        let slot = u32::try_from(address.parameter).ok()?;
        let parameter = self.source.facts().boundaries.parameters.get(&slot)?;
        (parameter.index == slot
            && parameter.index as usize == address.parameter
            && address.parameter_storage == Some(parameter.graph_storage))
        .then_some(parameter.value)
    }

    /// The element width of a block the function allocated.
    ///
    /// An allocator declares `void *` because it cannot know; the accesses the
    /// caller makes to the block do know, and a block reached only at one width
    /// is a pointer to that width.
    fn gather_allocation_element_widths(
        &mut self,
        callsite_signatures: &BTreeMap<r2ssa::CallSiteId, FunctionType>,
    ) {
        let certificates = self.source.certificates();
        let mut widths: BTreeMap<r2ssa::CallSiteId, BTreeSet<u32>> = BTreeMap::new();
        for access in certificates.memory_accesses.values() {
            let Some(object) = self.source.objects().object(access.object) else {
                continue;
            };
            if let r2ssa::ObjectKind::HeapAlloc { call_site, .. } = object.kind {
                widths.entry(call_site).or_default().insert(access.width);
            }
        }

        let mut bounds = Vec::new();
        for (value, certificate) in &certificates.call_results {
            if !certificate.relation.is_identity() {
                continue;
            }
            // Only refine what the callee itself declared as a pointer: a call
            // whose prototype is unknown has not been shown to return one.
            let declares_pointer = callsite_signatures
                .get(&certificate.call_site)
                .is_some_and(|signature| matches!(signature.return_type, CTypeLike::Pointer(_)));
            if !declares_pointer {
                continue;
            }
            let Some(widths) = widths.get(&certificate.call_site) else {
                continue;
            };
            let [width] = widths.iter().copied().collect::<Vec<_>>()[..] else {
                continue;
            };
            let Some(elem) = pointee_type_for_width(width) else {
                continue;
            };
            bounds.push((EvidenceNode::Value(value), elem));
        }

        for (node, elem) in bounds {
            let Some(spelled) = self.intern_spelled(&elem) else {
                continue;
            };
            self.bound(node, spelled);
        }
    }

    /// The element each `base + index` access's base points at, once one operand is a pointer: a
    /// worklist over the accesses (doc/types.md, "Indexed bases").
    fn gather_indexed_pointer_bases(&mut self) {
        let source = self.source;
        let mut sums = Vec::new();
        for access in source.certificates().memory_accesses.values() {
            if access.space != r2il::SpaceId::Ram {
                continue;
            }
            let Some(elem) = pointee_type_for_width(access.width) else {
                continue;
            };
            let Some((left, right)) = self.address_sum_operands(access.address) else {
                continue;
            };
            sums.push((left, right, elem));
        }
        let mut readers = HashMap::<usize, Vec<usize>>::new();
        for (at, (left, right, _)) in sums.iter().enumerate() {
            for operand in [left, right] {
                let class = self.solver.class_seeing(&EvidenceNode::Value(*operand));
                readers.entry(class).or_default().push(at);
            }
        }
        let mut queued = vec![true; sums.len()];
        let mut queue = (0..sums.len()).collect::<std::collections::VecDeque<_>>();
        while let Some(at) = queue.pop_front() {
            queued[at] = false;
            let (left, right, ref elem) = sums[at];
            // Exactly one side has been shown to be a pointer; the other is the
            // index. Two pointers, or none, decides nothing.
            let base = match (self.solved_is_pointer(left), self.solved_is_pointer(right)) {
                (true, false) => left,
                (false, true) => right,
                _ => continue,
            };
            let index = if base == left { right } else { left };
            if self.value_is_constant(index) {
                continue;
            }
            let Some(spelled) = self.intern_spelled(elem) else {
                continue;
            };
            let node = EvidenceNode::Value(base);
            if !self.bound(node, spelled) {
                continue;
            }
            let class = self.solver.class_seeing(&node);
            for &reader in readers.get(&class).into_iter().flatten() {
                if !std::mem::replace(&mut queued[reader], true) {
                    queue.push_back(reader);
                }
            }
        }
    }

    /// The two operands of an address that is one value plus another.
    #[cfg_attr(
        dylint_lib = "r2sleigh_lints",
        allow(
            entity_keyed_map,
            reason = "a walk guard of one query: the few ids one walk visits, where a bitset would cost O(values) per query"
        )
    )]
    fn address_sum_operands(
        &self,
        address: r2ssa::ValueId,
    ) -> Option<(r2ssa::ValueId, r2ssa::ValueId)> {
        let graph = self.source.graph();
        let mut current = address;
        let mut seen = HashSet::new();
        while seen.insert(current) {
            let inst = graph.inst(graph.def_inst(current)?)?;
            match &inst.payload {
                r2ssa::InstPayload::Op(r2ssa::SSAOp::Copy { .. } | r2ssa::SSAOp::New { .. }) => {
                    current = *graph.inputs(inst.id).first()?;
                }
                r2ssa::InstPayload::Op(
                    r2ssa::SSAOp::IntAdd { .. } | r2ssa::SSAOp::PtrAdd { .. },
                ) => {
                    let [left, right] = graph.inputs(inst.id)[..] else {
                        return None;
                    };
                    return Some((left, right));
                }
                _ => return None,
            }
        }
        None
    }

    fn solved_is_pointer(&mut self, value: r2ssa::ValueId) -> bool {
        let ty = self.solver.type_of(&EvidenceNode::Value(value));
        ty.is_some_and(|ty| matches!(self.solver.arena().get(ty), Type::Ptr(_)))
    }

    /// Memory objects that hold exactly one value of one width.
    ///
    /// A home that is only ever read and written whole is the storage of one
    /// variable, so its type and the type of every value that passes through it
    /// are the same type. An object touched at more than one width, or narrower
    /// than itself, is an aggregate and is left alone.
    fn scalar_memory_cells(&self) -> HashSet<r2ssa::ObjectId> {
        let certificates = self.source.certificates();
        let mut widths: BTreeMap<r2ssa::ObjectId, BTreeSet<u32>> = BTreeMap::new();
        for access in certificates.memory_accesses.values() {
            if access.space != r2il::SpaceId::Ram {
                continue;
            }
            widths
                .entry(access.object)
                .or_default()
                .insert(access.width);
        }

        let mut cells = HashSet::new();
        for (object, widths) in widths {
            let [width] = widths.iter().copied().collect::<Vec<_>>()[..] else {
                continue;
            };
            let Some(fact) = self.source.objects().object(object) else {
                continue;
            };
            let identified = match fact.kind {
                r2ssa::ObjectKind::StackSlot {
                    space: r2il::SpaceId::Ram,
                    ..
                }
                | r2ssa::ObjectKind::FrameObject {
                    space: r2il::SpaceId::Ram,
                    ..
                } => true,
                // An unidentified region is a bucket, and two addresses that
                // landed in the same bucket are not the same storage. One
                // address expression over one set of SSA values is, so a bucket
                // reached only that way is still one cell.
                r2ssa::ObjectKind::EscapedUnknown {
                    space: r2il::SpaceId::Ram,
                } => self.object_has_single_address_identity(object),
                _ => false,
            };
            if !identified {
                continue;
            }
            if certificates
                .stack_slots
                .get(&object)
                .and_then(|slot| slot.size)
                .is_some_and(|size| size != width)
            {
                continue;
            }
            cells.insert(object);
        }
        cells
    }

    /// Whether every certified access to an object goes through one address.
    fn object_has_single_address_identity(&self, object: r2ssa::ObjectId) -> bool {
        let mut identity: Option<AddressIdentity> = None;
        for access in self.source.certificates().memory_accesses.values() {
            if access.object != object {
                continue;
            }
            let Some(current) = self.address_identity(access.address) else {
                return false;
            };
            match &identity {
                None => identity = Some(current),
                Some(existing) if *existing == current => {}
                Some(_) => return false,
            }
        }
        identity.is_some()
    }

    /// The address expression a value computes, as its operator and operands.
    fn address_identity(&self, address: r2ssa::ValueId) -> Option<AddressIdentity> {
        let graph = self.source.graph();
        let Some(inst) = graph.def_inst(address).and_then(|inst| graph.inst(inst)) else {
            return Some(AddressIdentity::Value(address));
        };
        match &inst.payload {
            r2ssa::InstPayload::Op(op) => Some(AddressIdentity::Computed {
                op: std::mem::discriminant(op),
                inputs: graph.inputs(inst.id).to_vec(),
            }),
            r2ssa::InstPayload::Phi { .. } => None,
        }
    }

    fn intern_spelled(&mut self, ty: &CTypeLike) -> Option<SpelledType> {
        let id = self.intern_structural(ty)?;
        Some(SpelledType {
            ty: id,
            spelling: ty.clone(),
        })
    }

    fn intern_structural(&mut self, ty: &CTypeLike) -> Option<TypeId> {
        match ty {
            CTypeLike::Const(inner) => self.intern_structural(inner),
            // `void` as a value type says nothing; as a pointee it is the top of
            // the pointee lattice, which is what `Top` already means.
            CTypeLike::Void
            | CTypeLike::Unknown
            | CTypeLike::BitVector(_)
            | CTypeLike::Function { .. }
            | CTypeLike::UnprototypedFunction(_) => None,
            CTypeLike::Bool => Some(self.solver.arena().bool_ty()),
            CTypeLike::Int { bits, signedness } => {
                Some(self.solver.arena_mut().int(*bits, *signedness))
            }
            CTypeLike::Float(bits) => Some(self.solver.arena_mut().float(*bits)),
            CTypeLike::Pointer(inner) => {
                let inner = match self.intern_structural(inner) {
                    Some(inner) => inner,
                    None => self.solver.arena().top(),
                };
                Some(self.solver.arena_mut().ptr(inner))
            }
            CTypeLike::Array(inner, len) => {
                let inner = self.intern_structural(inner)?;
                Some(self.solver.arena_mut().array(inner, *len, None))
            }
            CTypeLike::Struct(name) => Some(
                self.solver
                    .arena_mut()
                    .unknown_alias(format!("struct {name}")),
            ),
            CTypeLike::Union(name) => Some(
                self.solver
                    .arena_mut()
                    .unknown_alias(format!("union {name}")),
            ),
            CTypeLike::Enum(name) => Some(
                self.solver
                    .arena_mut()
                    .unknown_alias(format!("enum {name}")),
            ),
            CTypeLike::Typedef { name, .. } => {
                let resolved = crate::parse_c_type_like(name, self.ptr_bits)?;
                if matches!(resolved, CTypeLike::Typedef { .. }) {
                    return Some(self.solver.arena_mut().unknown_alias(name.clone()));
                }
                self.intern_structural(&resolved)
            }
        }
    }

    fn read_back(&mut self) -> EvidenceTypes {
        // A spelling names the solved type only when it is that type. The class
        // carries it because every member of an equality class is one variable.
        let mut class_spellings: HashMap<usize, CTypeLike> = HashMap::new();
        for (node, ty, spelling) in std::mem::take(&mut self.spellings) {
            if self.solver.type_of(&node) != Some(ty) {
                continue;
            }
            let Some(root) = self.solver.class_of(&node) else {
                continue;
            };
            match class_spellings.get(&root) {
                None => {
                    class_spellings.insert(root, spelling);
                }
                Some(existing) if *existing == spelling => {}
                Some(_) => {
                    // Two names for one type is not a conflict about the type,
                    // but it is no longer evidence for either name.
                    class_spellings.insert(root, CTypeLike::Unknown);
                }
            }
        }

        let mut types = EvidenceTypes::default();
        let mut object_types: HashMap<r2ssa::ObjectId, CTypeLike> = HashMap::new();
        for (node, ty) in self.solver.typed() {
            let Some(resolved) = self.spell(&class_spellings, node, ty) else {
                continue;
            };
            match node {
                EvidenceNode::Value(value) => {
                    types.value_types.insert(value, resolved);
                }
                EvidenceNode::Object(object) => {
                    object_types.insert(object, resolved);
                }
            }
        }

        for (object, ty) in object_types {
            let Some(fact) = self.source.objects().object(object) else {
                continue;
            };
            let (base, offset) = match fact.kind {
                r2ssa::ObjectKind::StackSlot { base, offset, .. }
                | r2ssa::ObjectKind::FrameObject { base, offset, .. } => (base, offset),
                _ => continue,
            };
            types.slot_types.insert(
                StackSlotKey {
                    base: match base {
                        r2ssa::StackAddressBase::FramePointer => ExternalStackBase::FramePointer,
                        r2ssa::StackAddressBase::StackPointer => ExternalStackBase::StackPointer,
                        r2ssa::StackAddressBase::Realigned => ExternalStackBase::Realigned,
                    },
                    offset,
                },
                ty,
            );
        }

        types
    }

    fn spell(
        &mut self,
        class_spellings: &HashMap<usize, CTypeLike>,
        node: EvidenceNode,
        ty: TypeId,
    ) -> Option<CTypeLike> {
        // A `Bottom` anywhere is contradictory evidence, which is not a type.
        if type_is_unresolved(self.solver.arena(), ty) {
            return None;
        }
        let root = self.solver.class_of(&node);
        if let Some(spelling) = root.and_then(|root| class_spellings.get(&root))
            && !matches!(spelling, CTypeLike::Unknown)
        {
            return Some(spelling.clone());
        }
        let structural = structural_type_like(self.solver.arena(), ty);
        (!matches!(structural, CTypeLike::Unknown)).then_some(structural)
    }
}

/// How an address was computed, independent of the name of the result.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AddressIdentity {
    Value(r2ssa::ValueId),
    Computed {
        op: std::mem::Discriminant<r2ssa::SSAOp<r2ssa::ValueId>>,
        inputs: Vec<r2ssa::ValueId>,
    },
}

/// The arena's `Top` pointee is `void`, which is how C spells "points at
/// something this has not been shown to know".
fn structural_type_like(arena: &TypeArena, ty: TypeId) -> CTypeLike {
    match arena.get(ty) {
        Type::Ptr(inner) => {
            let inner = match arena.get(*inner) {
                Type::Top | Type::Bottom => CTypeLike::Void,
                _ => structural_type_like(arena, *inner),
            };
            CTypeLike::Pointer(Box::new(inner))
        }
        _ => to_c_type_like(arena, ty),
    }
}

/// Whether a solved type carries no conclusion, at the top level or inside.
///
/// `Top` is "nothing was learned" and `Bottom` is "two things were learned that
/// cannot both hold"; neither is a type, and a pointer to either is not one.
fn type_is_unresolved(arena: &TypeArena, ty: TypeId) -> bool {
    match arena.get(ty) {
        Type::Top | Type::Bottom => true,
        Type::Ptr(inner) => matches!(arena.get(*inner), Type::Bottom),
        _ => false,
    }
}

/// A pointee known only by the width of the accesses made through it.
impl EvidenceBuilder<'_> {
    /// Refine a pointee's signedness by how the loaded value is widened.
    ///
    /// The access width says how many bits are read and nothing about what
    /// they mean, so a pointee derived from it alone is `Signedness::Unknown`
    /// and spells `int8_t *` -- a signed pointee asserted from not knowing.
    /// The instruction after the load says which it is: the machine widens a
    /// byte it means as unsigned with a zero extension and one it means as
    /// signed with a sign extension, and that is a fact about the pointee
    /// rather than a reading of the C.
    fn pointee_with_loaded_signedness(
        &self,
        access: &r2ssa::MemoryAccessCertificate,
        elem: CTypeLike,
    ) -> CTypeLike {
        let CTypeLike::Pointer(pointee) = &elem else {
            return elem;
        };
        let CTypeLike::Int {
            bits,
            signedness: Signedness::Unknown,
        } = pointee.as_ref()
        else {
            return elem;
        };
        let Some(value) = access.value else {
            return elem;
        };
        let graph = self.source.graph();
        let mut signedness = None;
        for site in graph.use_sites(value) {
            let Some(inst) = graph.inst(site.inst) else {
                return elem;
            };
            let widened = match &inst.payload {
                r2ssa::InstPayload::Op(r2ssa::SSAOp::IntZExt { .. }) => Signedness::Unsigned,
                r2ssa::InstPayload::Op(r2ssa::SSAOp::IntSExt { .. }) => Signedness::Signed,
                _ => continue,
            };
            match signedness {
                None => signedness = Some(widened),
                // Widened both ways, so the bits are not one or the other.
                Some(seen) if seen != widened => return elem,
                Some(_) => {}
            }
        }
        let Some(signedness) = signedness else {
            return elem;
        };
        CTypeLike::Pointer(Box::new(CTypeLike::Int {
            bits: *bits,
            signedness,
        }))
    }
}

fn pointee_type_for_width(width: u32) -> Option<CTypeLike> {
    let bits = width.checked_mul(8)?;
    matches!(bits, 8 | 16 | 32 | 64).then(|| {
        CTypeLike::Pointer(Box::new(CTypeLike::Int {
            bits,
            signedness: Signedness::Unknown,
        }))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointee_width_maps_to_addressable_integer_widths() {
        assert_eq!(
            pointee_type_for_width(1),
            Some(CTypeLike::Pointer(Box::new(CTypeLike::Int {
                bits: 8,
                signedness: Signedness::Unknown
            })))
        );
        assert_eq!(pointee_type_for_width(3), None);
        assert_eq!(pointee_type_for_width(0), None);
    }

    fn empty_artifact() -> r2ssa::SsaArtifact {
        r2ssa::SsaArtifact::raw(
            &[r2il::R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: Vec::new(),
                ..Default::default()
            }],
            None,
        )
        .expect("an empty block prepares")
    }

    #[test]
    fn interning_resolves_a_typedef_to_its_structure() {
        let source = empty_artifact();
        let mut builder = EvidenceBuilder::new(&source, 64);
        let size_t = builder
            .intern_structural(&CTypeLike::typedef("size_t"))
            .expect("size_t resolves");
        let unsigned_long = builder
            .intern_structural(&CTypeLike::Int {
                bits: 64,
                signedness: Signedness::Unsigned,
            })
            .expect("uint64 resolves");
        assert_eq!(size_t, unsigned_long);
    }

    #[test]
    fn a_void_pointee_interns_as_the_pointee_top() {
        let source = empty_artifact();
        let mut builder = EvidenceBuilder::new(&source, 64);
        let void_ptr = builder
            .intern_structural(&CTypeLike::Pointer(Box::new(CTypeLike::Void)))
            .expect("void* resolves");
        let top = builder.solver.arena().top();
        let expected = builder.solver.arena_mut().ptr(top);
        assert_eq!(void_ptr, expected);
        assert_eq!(
            structural_type_like(builder.solver.arena(), void_ptr),
            CTypeLike::Pointer(Box::new(CTypeLike::Void))
        );
    }

    #[test]
    fn contradictory_bounds_leave_a_value_unresolved() {
        let mut arena = TypeArena::default();
        let byte = arena.int(8, Signedness::Unknown);
        let byte_ptr = arena.ptr(byte);
        let word = arena.int(64, Signedness::Unsigned);
        let node = EvidenceNode::Value(r2ssa::ValueId(1));

        let constraints = [byte_ptr, word]
            .into_iter()
            .map(|ty| crate::Constraint::Subtype {
                var: node,
                ty,
                source: crate::ConstraintSource::SignatureRegistry,
            })
            .collect::<Vec<_>>();
        let solved = crate::solve_constraints(arena, &constraints);
        let solved_ty = solved.var_types.get(&node).copied().expect("node visited");
        assert!(type_is_unresolved(&solved.arena, solved_ty));
    }

    #[test]
    fn a_tighter_bound_survives_a_looser_one_whatever_the_order() {
        let mut arena = TypeArena::default();
        let top = arena.top();
        let void_ptr = arena.ptr(top);
        let byte = arena.int(8, Signedness::Unknown);
        let byte_ptr = arena.ptr(byte);
        let node = EvidenceNode::Value(r2ssa::ValueId(1));

        for order in [[void_ptr, byte_ptr], [byte_ptr, void_ptr]] {
            let constraints = order
                .into_iter()
                .map(|ty| crate::Constraint::Subtype {
                    var: node,
                    ty,
                    source: crate::ConstraintSource::SignatureRegistry,
                })
                .collect::<Vec<_>>();
            let solved = crate::solve_constraints(arena.clone(), &constraints);
            let solved_ty = solved.var_types.get(&node).copied().expect("node typed");
            assert_eq!(
                structural_type_like(&solved.arena, solved_ty),
                CTypeLike::Pointer(Box::new(CTypeLike::Int {
                    bits: 8,
                    signedness: Signedness::Unknown
                }))
            );
        }
    }

    #[test]
    fn memory_and_ssa_evidence_solve_without_callee_signatures() {
        let mut arch = r2il::ArchSpec::new("x86-64");
        arch.add_register(r2il::RegisterDef::new("rdi", 0, 8));
        arch.add_register(r2il::RegisterDef::new("rsp", 8, 8));
        arch.add_register(r2il::RegisterDef::new("rip", 16, 8));
        let register = |offset| r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset,
            size: 8,
        };
        let interface = r2ssa::SourceFunctionInterface::new_exact(
            b"evidence-without-callee-signatures".to_vec(),
            "sysv64",
            [r2ssa::SourceAbiParameterSpec::new(0, register(0))],
            r2ssa::SourceFunctionReturn::Void,
            [],
        )
        .and_then(|interface| interface.with_stack_pointer_storage(register(8)))
        .and_then(|interface| interface.with_return_address_storage(register(16)))
        .expect("exact source interface");
        let mut block = r2il::R2ILBlock::new(0x1000, 4);
        block.push(r2il::R2ILOp::Copy {
            dst: r2il::Varnode::unique(0x100, 8),
            src: r2il::Varnode::register(0, 8),
        });
        block.push(r2il::R2ILOp::Load {
            dst: r2il::Varnode::unique(0x200, 4),
            space: r2il::SpaceId::Ram,
            addr: r2il::Varnode::unique(0x100, 8),
        });
        let source = r2ssa::SsaArtifact::for_decompile_with_interface(
            &[block],
            Some(&r2ssa::Arch::from(arch.clone())),
            interface,
        )
        .expect("prepared source");
        let parameter = source
            .facts()
            .boundaries
            .parameters
            .get(&0)
            .expect("exact parameter")
            .value;
        let address = source
            .certificates()
            .memory_accesses
            .values()
            .next()
            .expect("certified load")
            .address;

        let solved =
            crate::function_facts::SolvedFunction::of(&source, &BTreeMap::new(), 64).evidence;
        let expected = CTypeLike::Pointer(Box::new(CTypeLike::Int {
            bits: 32,
            signedness: Signedness::Unknown,
        }));
        assert_eq!(solved.value_type(address), Some(&expected));
        assert_eq!(
            solved.value_type(parameter),
            Some(&expected),
            "copy identity must carry memory evidence to the exact entry value"
        );
    }

    #[test]
    fn affine_address_provenance_bootstraps_the_indexed_parameter_base() {
        let mut arch = r2il::ArchSpec::new("x86-64");
        arch.add_register(r2il::RegisterDef::new("rdi", 0, 8));
        arch.add_register(r2il::RegisterDef::new("rsi", 8, 8));
        arch.add_register(r2il::RegisterDef::new("rsp", 16, 8));
        arch.add_register(r2il::RegisterDef::new("rip", 24, 8));
        let register = |offset| r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset,
            size: 8,
        };
        let interface = r2ssa::SourceFunctionInterface::new_exact(
            b"indexed-parameter-evidence".to_vec(),
            "sysv64",
            [
                r2ssa::SourceAbiParameterSpec::new(0, register(0)),
                r2ssa::SourceAbiParameterSpec::new(1, register(8)),
            ],
            r2ssa::SourceFunctionReturn::Void,
            [],
        )
        .and_then(|interface| interface.with_stack_pointer_storage(register(16)))
        .and_then(|interface| interface.with_return_address_storage(register(24)))
        .expect("exact source interface");
        let mut block = r2il::R2ILBlock::new(0x1000, 4);
        block.push(r2il::R2ILOp::IntMult {
            dst: r2il::Varnode::unique(0x100, 8),
            a: r2il::Varnode::register(8, 8),
            b: r2il::Varnode::constant(4, 8),
        });
        block.push(r2il::R2ILOp::IntAdd {
            dst: r2il::Varnode::unique(0x108, 8),
            a: r2il::Varnode::register(0, 8),
            b: r2il::Varnode::unique(0x100, 8),
        });
        block.push(r2il::R2ILOp::Load {
            dst: r2il::Varnode::unique(0x200, 4),
            space: r2il::SpaceId::Ram,
            addr: r2il::Varnode::unique(0x108, 8),
        });
        let source = r2ssa::SsaArtifact::for_decompile_with_interface(
            &[block],
            Some(&r2ssa::Arch::from(arch.clone())),
            interface,
        )
        .expect("prepared source");
        let parameter = source.facts().boundaries.parameters[&0].value;
        let index = source.facts().boundaries.parameters[&1].value;
        let access = source
            .certificates()
            .memory_accesses
            .values()
            .next()
            .expect("certified indexed load");
        assert_eq!(
            source
                .addresses()
                .parameter_expression(access.address)
                .map(|address| address.parameter),
            Some(0)
        );

        let solved =
            crate::function_facts::SolvedFunction::of(&source, &BTreeMap::new(), 64).evidence;
        let expected = CTypeLike::Pointer(Box::new(CTypeLike::Int {
            bits: 32,
            signedness: Signedness::Unknown,
        }));
        assert_eq!(solved.value_type(parameter), Some(&expected));
        assert_eq!(
            solved.value_type(index),
            None,
            "the affine index is not a second pointer base"
        );
    }

    /// A function of a pointer in `rdi` and an index in `rsi`, with `rdx` free.
    fn pointer_and_index_source(blocks: &[r2il::R2ILBlock]) -> r2ssa::SsaArtifact {
        let mut arch = r2il::ArchSpec::new("x86-64");
        arch.add_register(r2il::RegisterDef::new("rdi", 0, 8));
        arch.add_register(r2il::RegisterDef::new("rsi", 8, 8));
        arch.add_register(r2il::RegisterDef::new("rsp", 16, 8));
        arch.add_register(r2il::RegisterDef::new("rip", 24, 8));
        arch.add_register(r2il::RegisterDef::new("rdx", 32, 8));
        let register = |offset| r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset,
            size: 8,
        };
        let interface = r2ssa::SourceFunctionInterface::new_exact(
            b"unobserved-merge-evidence".to_vec(),
            "sysv64",
            [
                r2ssa::SourceAbiParameterSpec::new(0, register(0)),
                r2ssa::SourceAbiParameterSpec::new(1, register(8)),
            ],
            r2ssa::SourceFunctionReturn::Void,
            [],
        )
        .and_then(|interface| interface.with_stack_pointer_storage(register(16)))
        .and_then(|interface| interface.with_return_address_storage(register(24)))
        .expect("exact source interface");
        r2ssa::SsaArtifact::for_decompile_with_interface(
            blocks,
            Some(&r2ssa::Arch::from(arch.clone())),
            interface,
        )
        .expect("prepared source")
    }

    /// `rdx` holds the index on one path and the pointer on the other, and
    /// the join merges them; nothing the program observes reads that merge.
    /// It is no evidence that the index and the pointer share a type, and
    /// equating through it typed the index a pointer
    /// (manual_limits.c `out_param_parse`, gcc -O0).
    #[test]
    fn an_unobserved_merge_of_an_index_and_a_pointer_types_neither_as_the_other() {
        let rdx = r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset: 32,
            size: 8,
        };
        let mut entry = r2il::R2ILBlock::new(0x1000, 4);
        entry.push(r2il::R2ILOp::Load {
            dst: r2il::Varnode::unique(0x200, 4),
            space: r2il::SpaceId::Ram,
            addr: r2il::Varnode::register(0, 8),
        });
        entry.push(r2il::R2ILOp::CBranch {
            target: r2il::Varnode::constant(0x1008, 8),
            cond: r2il::Varnode::unique(0x200, 1),
        });
        let mut index = r2il::R2ILBlock::new(0x1004, 4);
        index.push(r2il::R2ILOp::Copy {
            dst: r2il::Varnode::register(32, 8),
            src: r2il::Varnode::register(8, 8),
        });
        index.push(r2il::R2ILOp::Branch {
            target: r2il::Varnode::constant(0x100c, 8),
        });
        let mut pointer = r2il::R2ILBlock::new(0x1008, 4);
        pointer.push(r2il::R2ILOp::Copy {
            dst: r2il::Varnode::register(32, 8),
            src: r2il::Varnode::register(0, 8),
        });
        let mut join = r2il::R2ILBlock::new(0x100c, 4);
        join.push(r2il::R2ILOp::IntAdd {
            dst: r2il::Varnode::register(32, 8),
            a: r2il::Varnode::register(32, 8),
            b: r2il::Varnode::constant(1, 8),
        });
        join.push(r2il::R2ILOp::Return {
            target: r2il::Varnode::register(24, 8),
        });
        let source = pointer_and_index_source(&[entry, index, pointer, join]);
        let merged = source
            .graph()
            .insts
            .iter()
            .filter(|inst| matches!(inst.payload, r2ssa::InstPayload::Phi { .. }))
            .filter_map(|inst| inst.output)
            .find(|value| {
                source
                    .graph()
                    .value(*value)
                    .is_some_and(|value| value.canonical_storage == Some(rdx))
            })
            .expect("rdx merges at the join");
        assert!(
            source.unobserved_merges().contains(merged),
            "the merge is read only by an increment nothing observes"
        );
        let index = source.facts().boundaries.parameters[&1].value;
        let solved =
            crate::function_facts::SolvedFunction::of(&source, &BTreeMap::new(), 64).evidence;
        assert!(
            !matches!(solved.value_type(index), Some(CTypeLike::Pointer(_))),
            "{:?}",
            solved.value_type(index)
        );
    }

    #[test]
    fn signed_comparison_types_only_its_exact_parameter_value() {
        let mut arch = r2il::ArchSpec::new("x86-64");
        arch.add_register(r2il::RegisterDef::new("rdi", 0, 8));
        arch.add_register(r2il::RegisterDef::new("rsi", 8, 8));
        arch.add_register(r2il::RegisterDef::new("rsp", 16, 8));
        arch.add_register(r2il::RegisterDef::new("rip", 24, 8));
        let register = |offset| r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset,
            size: 8,
        };
        let interface = r2ssa::SourceFunctionInterface::new_exact(
            b"signed-parameter-evidence".to_vec(),
            "sysv64",
            [
                r2ssa::SourceAbiParameterSpec::new(0, register(0)),
                r2ssa::SourceAbiParameterSpec::new(1, register(8)),
            ],
            r2ssa::SourceFunctionReturn::Void,
            [],
        )
        .and_then(|interface| interface.with_stack_pointer_storage(register(16)))
        .and_then(|interface| interface.with_return_address_storage(register(24)))
        .expect("exact source interface");
        let mut entry = r2il::R2ILBlock::new(0x1000, 4);
        entry.push(r2il::R2ILOp::IntSLess {
            dst: r2il::Varnode::unique(0x100, 1),
            a: r2il::Varnode::register(0, 8),
            b: r2il::Varnode::constant(10, 8),
        });
        entry.push(r2il::R2ILOp::IntEqual {
            dst: r2il::Varnode::unique(0x108, 1),
            a: r2il::Varnode::register(8, 8),
            b: r2il::Varnode::constant(0, 8),
        });
        entry.push(r2il::R2ILOp::BoolAnd {
            dst: r2il::Varnode::unique(0x110, 1),
            a: r2il::Varnode::unique(0x100, 1),
            b: r2il::Varnode::unique(0x108, 1),
        });
        entry.push(r2il::R2ILOp::CBranch {
            target: r2il::Varnode::constant(0x1008, 8),
            cond: r2il::Varnode::unique(0x110, 1),
        });
        let fallthrough = r2il::R2ILBlock::new(0x1004, 4);
        let taken = r2il::R2ILBlock::new(0x1008, 4);
        let source = r2ssa::SsaArtifact::for_decompile_with_interface(
            &[entry, fallthrough, taken],
            Some(&r2ssa::Arch::from(arch.clone())),
            interface,
        )
        .expect("prepared source");
        let signed = source.facts().boundaries.parameters[&0].value;
        let untouched = source.facts().boundaries.parameters[&1].value;

        let solved =
            crate::function_facts::SolvedFunction::of(&source, &BTreeMap::new(), 64).evidence;
        assert_eq!(
            solved.value_type(signed),
            Some(&CTypeLike::Int {
                bits: 64,
                signedness: Signedness::Signed,
            })
        );
        assert_eq!(solved.value_type(untouched), None);

        let machine = CTypeLike::u64();
        let signature = crate::FunctionSignatureSpec {
            ret_type: Some(CTypeLike::Void),
            params: vec![
                crate::FunctionParamSpec {
                    name: "lhs".to_string(),
                    ty: Some(machine.clone()),
                },
                crate::FunctionParamSpec {
                    name: "rhs".to_string(),
                    ty: Some(machine.clone()),
                },
            ],
        };
        let mut facts = crate::FunctionFacts::new(crate::FunctionTypeFacts {
            signature_certificate: crate::SignatureCertificate::from_signature(
                &signature,
                [crate::SignatureCertificateSource::LocalInference],
            ),
            merged_signature: Some(signature),
            ..crate::FunctionTypeFacts::default()
        });
        let solved =
            crate::function_facts::SolvedFunction::of(&source, &BTreeMap::new(), 64).evidence;
        facts.apply_recovered_evidence_types(&source, &solved, 64);
        let written = facts
            .type_facts()
            .render_authorized_signature()
            .expect("recovered parameter signature remains render-authorized");
        assert_eq!(
            written.params[0].ty,
            Some(CTypeLike::Int {
                bits: 64,
                signedness: Signedness::Signed,
            })
        );
        assert_eq!(written.params[1].ty, Some(machine));
    }

    #[test]
    fn unsigned_use_after_a_stack_spill_types_the_parameter_and_home() {
        let mut arch = r2il::ArchSpec::new("aarch64");
        arch.add_register(r2il::RegisterDef::new("x1", 8, 8));
        arch.add_register(r2il::RegisterDef::new("sp", 16, 8));
        arch.add_register(r2il::RegisterDef::new("lr", 24, 8));
        let register = |offset| r2ssa::CanonicalStorageId {
            space: r2ssa::CanonicalStorageSpace::Register,
            offset,
            size: 8,
        };
        let interface = r2ssa::SourceFunctionInterface::new_exact(
            b"unsigned-spilled-parameter".to_vec(),
            "aapcs64",
            [r2ssa::SourceAbiParameterSpec::new(0, register(8))],
            r2ssa::SourceFunctionReturn::Void,
            [r2ssa::SourceStackSlotSpec::new_local(
                r2ssa::StackAddressBase::StackPointer,
                register(16),
                -8,
                8,
            )],
        )
        .and_then(|interface| interface.with_stack_pointer_storage(register(16)))
        .and_then(|interface| interface.with_return_address_storage(register(24)))
        .expect("exact source interface");

        let mut entry = r2il::R2ILBlock::new(0x1000, 4);
        entry.push(r2il::R2ILOp::IntSub {
            dst: r2il::Varnode::unique(0x100, 8),
            a: r2il::Varnode::register(16, 8),
            b: r2il::Varnode::constant(8, 8),
        });
        entry.push(r2il::R2ILOp::Store {
            space: r2il::SpaceId::Ram,
            addr: r2il::Varnode::unique(0x100, 8),
            val: r2il::Varnode::register(8, 8),
        });
        entry.push(r2il::R2ILOp::Load {
            dst: r2il::Varnode::unique(0x108, 8),
            space: r2il::SpaceId::Ram,
            addr: r2il::Varnode::unique(0x100, 8),
        });
        entry.push(r2il::R2ILOp::IntLess {
            dst: r2il::Varnode::unique(0x110, 1),
            a: r2il::Varnode::unique(0x108, 8),
            b: r2il::Varnode::constant(10, 8),
        });
        entry.push(r2il::R2ILOp::CBranch {
            target: r2il::Varnode::constant(0x1008, 8),
            cond: r2il::Varnode::unique(0x110, 1),
        });
        let fallthrough = r2il::R2ILBlock::new(0x1004, 4);
        let taken = r2il::R2ILBlock::new(0x1008, 4);
        let source = r2ssa::SsaArtifact::for_decompile_with_interface(
            &[entry, fallthrough, taken],
            Some(&r2ssa::Arch::from(arch.clone())),
            interface,
        )
        .expect("prepared source");
        let parameter = source.facts().boundaries.parameters[&0].value;
        let solved =
            crate::function_facts::SolvedFunction::of(&source, &BTreeMap::new(), 64).evidence;
        let unsigned = CTypeLike::Int {
            bits: 64,
            signedness: Signedness::Unsigned,
        };

        assert_eq!(solved.value_type(parameter), Some(&unsigned));
        assert_eq!(
            solved
                .stack_slot_types()
                .find(|(slot, _)| slot.offset == -8)
                .map(|(_, ty)| ty),
            Some(&unsigned),
            "one scalar memory cell must carry the use-proven type both ways"
        );

        let signed = CTypeLike::typedef("int64_t");
        let signature = crate::FunctionSignatureSpec {
            ret_type: Some(CTypeLike::Void),
            params: vec![crate::FunctionParamSpec {
                name: "length".to_string(),
                ty: Some(signed),
            }],
        };
        let mut facts = crate::FunctionFacts::new(crate::FunctionTypeFacts {
            signature_certificate: crate::SignatureCertificate::from_signature(
                &signature,
                [crate::SignatureCertificateSource::LocalInference],
            ),
            merged_signature: Some(signature),
            ..crate::FunctionTypeFacts::default()
        });
        let solved =
            crate::function_facts::SolvedFunction::of(&source, &BTreeMap::new(), 64).evidence;
        facts.apply_recovered_evidence_types(&source, &solved, 64);

        let type_facts = facts.type_facts();
        assert_eq!(
            type_facts
                .merged_signature
                .as_ref()
                .and_then(|signature| signature.params[0].ty.as_ref()),
            Some(&unsigned)
        );
    }
}
