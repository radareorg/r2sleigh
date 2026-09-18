//! Where the renderer's types come from.
//!
//! Every conversion the renderer spells is made from two facts: what the
//! expression has and what the boundary requires. Both are read from the
//! typed boundaries the binding plan derives over the arena, keyed by the
//! value read or by the operation lowered and the operand's position, and
//! neither is ever read off the rendered text.

use r2rewrite::{CValue, TypedBoundaries};
use r2ssa::{MachineExprId, ValueId};

use super::{FoldingContext, LowerFrame};
use crate::ast::{CExpr, CType};

impl FoldingContext<'_> {
    /// The typed boundaries of the function being rendered, where a plan
    /// exists to derive them from.
    pub(super) fn typed_boundaries(&self) -> Option<&TypedBoundaries> {
        Some(self.inputs.binding_names?.plan().typed_boundaries())
    }

    /// The width of an address on the target, in bits.
    ///
    /// From the memory model, which is the source-owned answer. The fold
    /// configuration's `ptr_size` is the fallback for a context built
    /// without prepared SSA, and it is already a width in bits -- 64 or 32,
    /// as `FoldArchConfig::for_ptr_size` and `DecompilerConfig` both spell
    /// it. Two callers used to multiply it by eight on their way to a bit
    /// width, which made a sixty-four bit target's addresses five hundred
    /// and twelve bits wide wherever that fallback was reached.
    pub(super) fn pointer_bits(&self) -> u32 {
        self.inputs
            .prepared_ssa
            .map(|prepared| {
                prepared
                    .machine_context()
                    .memory_model()
                    .default_address_bits()
            })
            .unwrap_or(self.inputs.arch.ptr_size)
    }

    /// Convert `expr`, which has `from`, to `to`. The one emitter.
    pub(super) fn convert(&self, expr: CExpr, from: &CValue, to: &CType) -> CExpr {
        super::convert::convert(expr, from, to, self.pointer_bits())
    }

    /// Convert where what the expression has may be unrecorded.
    ///
    /// Nothing is recorded only where there is no plan to record it, and
    /// then the one conversion that is still certain is the one C never
    /// performs on its own: an integer does not become a pointer unless the
    /// program says so.
    ///
    /// `Unknown` is that absence wearing a type's clothes. A callee with no
    /// recovered prototype has `CType::Unknown` for its return, and passing
    /// that on as a recorded fact says "this expression has a type, and the
    /// type is one nothing can convert" -- which silenced the conversion
    /// instead of leaving it to the rule above. A call whose result is
    /// assigned to a pointer-declared object rendered
    /// `uint8_t *X0_9 = sym__rotl32(...)` on exactly that path.
    #[track_caller]
    pub(super) fn convert_from(&self, expr: CExpr, from: Option<&CValue>, to: &CType) -> CExpr {
        // A constant address is named here, where the requirement is stated.
        // Asked of the literal itself: an address the lift folded into a load
        // arrives typed as the carrier and is still the number it spells.
        if (matches!(from, Some(CValue::Constant)) || crate::literal_value(&expr).is_some())
            && let Some((named, named_type)) = crate::name_of_constant_address(
                &expr,
                self.inputs.function_facts.display_names().strings(),
                self.inputs.function_facts.display_names().symbols(),
                &self.inputs.function_facts.type_facts().program_data_objects,
                &mut self.named_data_objects.borrow_mut(),
                crate::string_literal_serves(to, self.pointer_bits()),
            )
        {
            return super::convert::convert(
                named,
                &CValue::Typed(named_type),
                to,
                self.pointer_bits(),
            );
        }
        // A bare name converts from what it is declared as, whatever the
        // boundary believed its value to be: the declaration is what C reads.
        // A lossless conversion already spelled over the name is peeled first,
        // so `(uint32_t)(uint64_t)x` on a `uint32_t` is `x`.
        let (expr, declared) = self.name_under_lossless_conversions(expr);
        let declared = declared.map(CValue::Typed);
        let from = declared.as_ref().or(from);
        super::convert::convert_optional(expr, from, to, self.pointer_bits())
    }

    /// The name an expression is, through integer conversions that lose no
    /// value, with its declared type; or the expression itself and nothing.
    fn name_under_lossless_conversions(&self, expr: CExpr) -> (CExpr, Option<CType>) {
        let declared_name = |expr: &CExpr| match expr.unobserved() {
            CExpr::Var(symbol) => Some(self.symbols.borrow().ty(*symbol).clone())
                .filter(|ty| !matches!(ty, CType::Unknown)),
            _ => None,
        };
        if let Some(declared) = declared_name(&expr) {
            return (expr, Some(declared));
        }
        let CExpr::Cast {
            ty: mid,
            expr: inner,
            role: crate::ast::CastRole::Conversion,
        } = expr.unobserved()
        else {
            return (expr, None);
        };
        let Some(declared) = declared_name(inner) else {
            return (expr, None);
        };
        let lossless = match (
            super::convert::integer_meta(&declared, self.pointer_bits()),
            super::convert::integer_meta(mid, self.pointer_bits()),
        ) {
            (Some((from_signed, from_bits)), Some((mid_signed, mid_bits))) => {
                (from_bits < mid_bits && (!from_signed || mid_signed))
                    || (from_bits == mid_bits && from_signed == mid_signed)
            }
            _ => false,
        };
        if lossless {
            (
                Self::under_observations(&expr, &|_| (**inner).clone()),
                Some(declared),
            )
        } else {
            (expr, None)
        }
    }

    /// `expr` with what sits under its observation markers replaced, the
    /// markers kept: a read stays recorded where it was recorded.
    fn under_observations(expr: &CExpr, replace: &dyn Fn(&CExpr) -> CExpr) -> CExpr {
        match expr {
            CExpr::Observed { id, expr } => CExpr::Observed {
                id: *id,
                expr: Box::new(Self::under_observations(expr, replace)),
            },
            other => replace(other),
        }
    }

    /// What a read of `value` renders as, before any use projection.
    pub(super) fn value_type(&self, value: ValueId) -> Option<CValue> {
        self.typed_boundaries()?.value_type(value).cloned()
    }

    /// The arena root of the value the operation at `frame` defines.
    pub(super) fn root_at(&self, frame: &LowerFrame) -> Option<MachineExprId> {
        let site = frame.normalized_site?;
        let output = self.normalized_output_projection(site).ok()?;
        let names = self.inputs.binding_names?;
        Some(
            names
                .plan()
                .machine_projection()
                .entity_for_output(output.value)?
                .root(),
        )
    }

    /// What the operation at `frame` requires of its operand at `index`.
    pub(super) fn required_at(&self, frame: &LowerFrame, index: usize) -> Option<CType> {
        let root = self.root_at(frame)?;
        self.typed_boundaries()?.required(root, index).cloned()
    }

    /// What the expression the operation at `frame` renders has.
    pub(super) fn produced_at(&self, frame: &LowerFrame) -> Option<CValue> {
        let root = self.root_at(frame)?;
        self.typed_boundaries()?.produced(root).cloned()
    }
}
