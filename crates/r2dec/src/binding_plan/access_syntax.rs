//! How each memory access is spelled, decided once from the facts.
//!
//! The renderer used to find the spelling by a ladder over rendered
//! expressions; it is decided here once, from the facts, and the renderer
//! asks. See `doc/adr-access-syntax.md`.

use std::collections::BTreeMap;

use r2rewrite::{TermArena, TermId, TermKind};
use r2ssa::{MachineExprKind, ObjectId, StructuredAccessId, ValueId};
use r2types::function_facts::{
    ArrayAccessRenderFact, FunctionRenderFacts, MemberAccessRenderFact, MemoryAccessRenderFact,
};

use super::{Binding, BindingId, MachineProjection, StackObjectDisposition, ValueDisposition};

/// The spelling of one memory access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AccessSyntax {
    /// The declared slot's own name: the access is at its base.
    SlotName { binding: BindingId },
    /// A declared member of the slot at the access's offset.
    SlotMember { binding: BindingId, field: Box<str> },
    /// Bytes of the slot at an offset, at the access's own width: a slot read
    /// at several widths, or narrower than it is declared, or inside it.
    SlotBytes { binding: BindingId, offset: i64 },
    /// An element of an array a parameter points at, optionally a member of it.
    ParamArray {
        base: ValueId,
        index: ValueId,
        field: Option<Box<str>>,
    },
    /// A declared member of the aggregate a pointer parameter points at.
    PtrMember { base: ValueId, field: Box<str> },
    /// The rewriter's proven `base[index]`.
    Subscript { term: TermId },
    /// The address itself, dereferenced or decomposed; either way it is rendered.
    Address { address: ValueId },
}

pub(super) struct AccessSyntaxInputs<'a> {
    pub render: &'a FunctionRenderFacts,
    pub objects: &'a r2ssa::ObjectModel,
    pub canonical: &'a r2rewrite::CanonicalRoots,
    pub projection: &'a MachineProjection,
    pub dispositions: &'a [ValueDisposition],
    pub stack_objects: &'a BTreeMap<ObjectId, StackObjectDisposition>,
    pub bindings: &'a [Binding],
    /// The source's own type graph, for asking whether a tag can be defined.
    pub type_graph: Option<&'a r2ssa::SourceTypeGraph>,
    pub ptr_bits: u32,
}

/// Every RAM access the render facts know, with its spelling. The spelling is
/// total: an access no structured shape fits is spelled by its address, so a
/// renderer can never meet a RAM access the plan did not answer for.
pub(super) fn derive(
    inputs: &AccessSyntaxInputs<'_>,
) -> BTreeMap<StructuredAccessId, AccessSyntax> {
    let mut out = BTreeMap::new();
    for fact in inputs.render.memory_accesses() {
        if fact.space != r2il::SpaceId::Ram {
            continue;
        }
        out.insert(fact.access, syntax_for(inputs, fact));
    }
    out
}

fn syntax_for(inputs: &AccessSyntaxInputs<'_>, fact: &MemoryAccessRenderFact) -> AccessSyntax {
    let member = member_fact(inputs.render, fact);
    let array = array_fact(inputs.render, fact);
    if let Some(array) = array
        && (array.base.is_some() || array.index.is_some())
        && let Some(syntax) = param_array(inputs, fact, array, member)
    {
        // An array certificate whose shape is spellable spells the access.
        // Where it is not, the address stands: claiming no shape is always
        // true, and the alternative is refusing a function over a spelling.
        return syntax;
    }
    // A member the source's own type graph named, on a base the plan can spell.
    if let Some(member) = member
        && let Some(base) = declared_member_base(inputs, fact, member)
    {
        return AccessSyntax::PtrMember {
            base,
            field: member.field_name.clone().into_boxed_str(),
        };
    }
    if member.is_none()
        && let Some(term) = subscript(inputs, fact)
    {
        return AccessSyntax::Subscript { term };
    }
    let indexed = inputs.objects.address_is_indexed(fact.address);
    let declared = inputs.render.stack_slot_offset(fact.object).is_some();
    let bound = bound_stack_object(inputs, fact.object);
    if fact.width > 0
        && !indexed
        && let Some(offset) = fact.object_offset.filter(|offset| *offset >= 0)
        && let Some(member) = member
        && i64::try_from(member.field_offset).ok() == Some(offset)
        && declared
        && let Some(binding) = bound
        // Only when the slot is actually declared as that aggregate. The plan
        // falls back to the slot's bytes for a tag the rendering cannot
        // define, and spelling `.st_mode` against a byte array is a rendering
        // that does not compile -- which scores nothing at all.
        && inputs
            .bindings
            .get(binding.index())
            .is_some_and(|binding| binding.declaration_type().is_aggregate())
    {
        return AccessSyntax::SlotMember {
            binding,
            field: member.field_name.clone().into_boxed_str(),
        };
    }
    if fact.width > 0
        && !indexed
        && declared
        && let Some(binding) = bound
    {
        // The name stands for the whole slot: only an access at its base, as
        // wide as it is declared, and of a scalar; an array would decay and an
        // aggregate cannot be assigned the integer the machine moved.
        let declared_type = inputs
            .bindings
            .get(binding.index())
            .map(|binding| binding.declaration_type().unaliased());
        let whole = fact.object_offset.is_none_or(|offset| offset == 0)
            && declared_type.is_none_or(|ty| {
                !matches!(
                    ty,
                    r2types::CTypeLike::Array(..)
                        | r2types::CTypeLike::Struct(..)
                        | r2types::CTypeLike::Union(..)
                ) && ty
                    .bits(inputs.ptr_bits)
                    .is_none_or(|bits| bits == fact.width * 8)
            });
        if whole {
            return AccessSyntax::SlotName { binding };
        }
        if let Some(offset) = fact.object_offset.filter(|offset| *offset >= 0) {
            return AccessSyntax::SlotBytes { binding, offset };
        }
    }
    // A member fact blocks the subscript spelling above, because `s.field`
    // beats `s[3]` when a slot arm can spell it. Where none could -- the base
    // is a pointer parameter rather than a bound stack object -- the rewriter's
    // own `base[index]` is still a better answer than casting the whole
    // address to the pointee's pointer, which applies a byte displacement to a
    // typed pointer and advances whole objects. `state + 120` reached here
    // with `Subscript { base, index }` already proven and unused.
    if let Some(term) = subscript(inputs, fact) {
        return AccessSyntax::Subscript { term };
    }
    AccessSyntax::Address {
        address: fact.address,
    }
}

fn param_array(
    inputs: &AccessSyntaxInputs<'_>,
    fact: &MemoryAccessRenderFact,
    array: &ArrayAccessRenderFact,
    member: Option<&MemberAccessRenderFact>,
) -> Option<AccessSyntax> {
    let (Some(r2ssa::SemanticId::Parameter(slot)), Some(r2ssa::SemanticId::Expression(index))) =
        (array.base, array.index)
    else {
        return None;
    };
    let slot = usize::try_from(slot).ok()?;
    let base = inputs.render.parameter_values(slot).next()?;
    if !inputs
        .render
        .certified_expr_for_value(index)
        .is_some_and(|expr| expr.fact.renderable)
    {
        return None;
    }
    if !value_has_expression(inputs, base) || !value_has_expression(inputs, index) {
        return None;
    }
    if !name_may_be_subscripted(inputs, base) {
        return None;
    }
    let field = match member {
        Some(member)
            if member.field_offset == array.field_offset && member.access == array.access =>
        {
            Some(member.field_name.clone().into_boxed_str())
        }
        None if array.field_offset == 0 => None,
        _ => return None,
    };
    let _ = fact;
    Some(AccessSyntax::ParamArray { base, index, field })
}

/// The parameter a declared member is reached through, proven as `param_array` proves its own.
///
/// Only a name the source's type graph gave: an external layout matched a
/// spelling rather than a declaration, and its label must not replace the
/// address the plan bound.
fn declared_member_base(
    inputs: &AccessSyntaxInputs<'_>,
    fact: &MemoryAccessRenderFact,
    member: &MemberAccessRenderFact,
) -> Option<ValueId> {
    if member.source != r2types::MemberAccessSource::DeclaredType {
        return None;
    }
    let r2ssa::SemanticId::Parameter(slot) = member.base? else {
        return None;
    };
    let base = inputs
        .render
        .parameter_values(usize::try_from(slot).ok()?)
        .next()?;
    if !value_has_expression(inputs, base) || !name_may_be_subscripted(inputs, base) {
        return None;
    }
    // And only where the rendering can define the aggregate: `p->field` against a
    // tag it only forward-declares is `incomplete definition of type`.
    let ValueDisposition::Bound { binding } = inputs.dispositions.get(base.0 as usize)? else {
        return None;
    };
    // An address bound to another name is read there too, and `p->field` would hide it.
    if let Some(ValueDisposition::Bound { binding: address }) =
        inputs.dispositions.get(fact.address.0 as usize)
        && address != binding
    {
        return None;
    }
    let declared = inputs.bindings.get(binding.index())?.declaration_type();
    let r2types::CTypeLike::Pointer(pointee) = declared.unaliased() else {
        return None;
    };
    let tag = pointee.aggregate_tag()?;
    inputs
        .type_graph
        .is_some_and(|graph| r2types::aggregate_is_definable(graph, tag))
        .then_some(base)
}

/// The rendered name's declared type admits `name[i]`: a pointer, an array,
/// or a name whose type the symbol table does not know. An inlined
/// expression is not a name and is never refused on this ground.
fn name_may_be_subscripted(inputs: &AccessSyntaxInputs<'_>, value: ValueId) -> bool {
    match inputs.dispositions.get(value.0 as usize) {
        Some(ValueDisposition::Bound { binding }) => {
            let Some(binding) = inputs.bindings.get(binding.index()) else {
                return true;
            };
            binding.declaration_type().may_be_subscripted()
        }
        _ => true,
    }
}

fn value_has_expression(inputs: &AccessSyntaxInputs<'_>, value: ValueId) -> bool {
    matches!(
        inputs.dispositions.get(value.0 as usize),
        Some(ValueDisposition::Bound { .. } | ValueDisposition::Inline { .. })
    )
}

fn bound_stack_object(inputs: &AccessSyntaxInputs<'_>, object: ObjectId) -> Option<BindingId> {
    match inputs.stack_objects.get(&object)? {
        StackObjectDisposition::Bound { binding } => Some(*binding),
        _ => None,
    }
}

fn subscript(inputs: &AccessSyntaxInputs<'_>, fact: &MemoryAccessRenderFact) -> Option<TermId> {
    let access = inputs.canonical.access(fact.access)?;
    let arena = inputs.canonical.arena();
    let TermKind::Subscript { base, index } = arena.term(access.canonical).kind else {
        return None;
    };
    (term_renderable(inputs, arena, base) && term_renderable(inputs, arena, index))
        .then_some(access.canonical)
}

/// Whether every leaf and operator of the term has a C spelling, mirroring
/// what the subscript renderer accepts.
fn term_renderable(inputs: &AccessSyntaxInputs<'_>, arena: &TermArena, term: TermId) -> bool {
    let child = |child: TermId| term_renderable(inputs, arena, child);
    match arena.term(term).kind {
        TermKind::Leaf(read) => match inputs.projection.expr(read.expr).map(|expr| expr.kind()) {
            Some(MachineExprKind::Source { binding, .. }) => matches!(
                inputs.dispositions.get(binding.value().0 as usize),
                Some(ValueDisposition::Bound { .. })
            ),
            Some(MachineExprKind::Constant { .. }) => true,
            _ => false,
        },
        TermKind::Literal(_) => true,
        TermKind::ObjectAddress(object) => bound_stack_object(inputs, object).is_some(),
        TermKind::Arithmetic { left, right, .. }
        | TermKind::Bitwise { left, right, .. }
        | TermKind::Boolean { left, right, .. }
        | TermKind::Compare { left, right, .. } => child(left) && child(right),
        TermKind::Shift { value, count, .. } => child(value) && child(count),
        TermKind::Negate(input)
        | TermKind::BitwiseNot(input)
        | TermKind::BooleanNot(input)
        | TermKind::Extract { input, .. } => child(input),
        TermKind::Cast { kind, input } => {
            matches!(
                kind,
                r2ssa::MachineCastKind::ZeroExtend
                    | r2ssa::MachineCastKind::SignExtend
                    | r2ssa::MachineCastKind::BitReinterpret
            ) && child(input)
        }
        TermKind::Select {
            condition,
            if_true,
            if_false,
        } => child(condition) && child(if_true) && child(if_false),
        TermKind::Opaque(_)
        | TermKind::Variable(_)
        | TermKind::Flag { .. }
        | TermKind::Concat { .. }
        | TermKind::Load { .. }
        | TermKind::Subscript { .. }
        | TermKind::FloatCast { .. }
        | TermKind::FloatArithmetic { .. }
        | TermKind::FloatUnary { .. }
        | TermKind::FloatCompare { .. } => false,
    }
}

fn member_fact<'a>(
    render: &'a FunctionRenderFacts,
    memory: &MemoryAccessRenderFact,
) -> Option<&'a MemberAccessRenderFact> {
    let facts =
        render
            .member_accesses_by_op
            .get(&(memory.block_addr, memory.op_index, memory.is_write))?;
    let mut matching = facts.iter().filter(|fact| {
        fact.access == memory.access
            && fact.object == memory.object
            && fact.access_width == memory.width
    });
    let first = matching.next()?;
    matching.next().is_none().then_some(first)
}

fn array_fact<'a>(
    render: &'a FunctionRenderFacts,
    memory: &MemoryAccessRenderFact,
) -> Option<&'a ArrayAccessRenderFact> {
    let facts =
        render
            .array_accesses_by_op
            .get(&(memory.block_addr, memory.op_index, memory.is_write))?;
    let mut matching = facts.iter().filter(|fact| {
        fact.access == memory.access
            && fact.object == memory.object
            && fact.access_width == memory.width
            && fact.element_stride > 0
    });
    let first = matching.next()?;
    matching.next().is_none().then_some(first)
}
