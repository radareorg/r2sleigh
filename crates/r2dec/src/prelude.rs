//! The one statement of every scalar helper a rendering may call.
//!
//! C has no operator for a P-code flag (`INT_CARRY`, `INT_SCARRY`,
//! `INT_SBORROW`), for reinterpreting an integer's bits as a float, or for a
//! value the rendering could not prove. Each of those is a call to a helper
//! named here, and a rendering that calls one defines it, `static inline`,
//! above the function: the translation unit a rendering hands out compiles on
//! its own, with nothing but `<stdint.h>`, and there is no header beside it
//! that could say something different.
//!
//! A helper is a typed value, not a name. The lowering builds the call from
//! [`Helper::call`], which is what puts [`ExternalKind::Helper`] on it, or,
//! for a residual, from [`residual`], which puts [`ExternalKind::Residual`] on
//! it with the residual's cause; the prelude is read back off those kinds
//! ([`helpers_called`]), and nothing parses a spelling to find out what a
//! rendering needs.
//!
//! Every definition is exact for the P-code operation it stands for and has no
//! undefined behaviour: arithmetic is done in an unsigned type at least as wide
//! as `unsigned int`, so no operand is promoted to a signed `int`, and every
//! shift count is below the width it shifts. Two things are not ISO C and are
//! used on purpose: `__uint128_t`, which is the only spelling of a 128-bit
//! integer the rendering already uses, and the compiler builtins for the
//! square root, the roundings and the trap, which need no header. A header
//! would declare library functions the rendering may itself declare with the
//! machine's types, and the two declarations would contradict each other.
//!
//! [`ExternalKind::Helper`]: crate::symbol::ExternalKind::Helper
//! [`ExternalKind::Residual`]: crate::symbol::ExternalKind::Residual

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::ast::{CExpr, CFunction, CStmt, CType};

/// One P-code flag computed from two operands of one width.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FlagOp {
    /// `INT_CARRY`: the unsigned sum does not fit.
    Carry,
    /// `INT_SCARRY`: the signed sum does not fit.
    SignedCarry,
    /// `INT_SBORROW`: the signed difference does not fit.
    SignedBorrow,
}

impl FlagOp {
    /// The flag the machine projection names.
    pub(crate) const fn of(op: r2ssa::MachineArithmeticFlagOp) -> Self {
        match op {
            r2ssa::MachineArithmeticFlagOp::UnsignedCarry => Self::Carry,
            r2ssa::MachineArithmeticFlagOp::SignedCarry => Self::SignedCarry,
            r2ssa::MachineArithmeticFlagOp::SignedBorrow => Self::SignedBorrow,
        }
    }

    const fn spelling(self) -> &'static str {
        match self {
            Self::Carry => "carry",
            Self::SignedCarry => "scarry",
            Self::SignedBorrow => "sborrow",
        }
    }
}

/// One P-code unary floating-point operation C has no operator for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FloatOp {
    /// `FLOAT_ABS`: the operand with its sign bit clear.
    Absolute,
    /// `FLOAT_SQRT`.
    SquareRoot,
    /// `FLOAT_CEIL`.
    Ceiling,
    /// `FLOAT_FLOOR`.
    Floor,
    /// `FLOAT_ROUND`, which P-code defines as `floor(x + 0.5)`.
    Round,
    /// `FLOAT_NAN`: whether the operand is a NaN, as a byte.
    IsNan,
}

impl FloatOp {
    /// The helper the machine projection's operation is, or none for
    /// negation, which is C's own operator.
    pub(crate) const fn of(op: r2ssa::MachineFloatUnaryOp) -> Option<Self> {
        Some(match op {
            r2ssa::MachineFloatUnaryOp::Negate => return None,
            r2ssa::MachineFloatUnaryOp::Absolute => Self::Absolute,
            r2ssa::MachineFloatUnaryOp::SquareRoot => Self::SquareRoot,
            r2ssa::MachineFloatUnaryOp::Ceiling => Self::Ceiling,
            r2ssa::MachineFloatUnaryOp::Floor => Self::Floor,
            r2ssa::MachineFloatUnaryOp::Round => Self::Round,
            r2ssa::MachineFloatUnaryOp::IsNan => Self::IsNan,
        })
    }

    const fn spelling(self) -> &'static str {
        match self {
            Self::Absolute => "abs",
            Self::SquareRoot => "sqrt",
            Self::Ceiling => "ceil",
            Self::Floor => "floor",
            Self::Round => "round",
            Self::IsNan => "isnan",
        }
    }
}

/// The C type a residual stands in for, which its helper returns.
///
/// A residual is a construct the rendering could not prove, spelled as a call
/// that traps if it is ever executed. It has to be an expression of the type
/// the construct would have had, so the rest of the function still compiles
/// around it; this is that type, as one of the scalars C can return.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ResidualType {
    /// A statement: nothing is produced.
    Void,
    /// `_Bool`.
    Bool,
    /// An unsigned integer of 8, 16, 32, 64 or 128 bits.
    Unsigned(u32),
    /// A signed integer of 8, 16, 32, 64 or 128 bits.
    Signed(u32),
    /// A `float` (32) or a `double` (64).
    Float(u32),
    /// `void *`, which converts to every object pointer; a use is cast to the
    /// pointer type it stands for.
    Pointer,
}

impl ResidualType {
    /// The residual a value of `ty` is spelled with, when `ty` is a scalar C
    /// can return. An aggregate, an array, a carrier wider than any integer or
    /// a type nothing states has no residual.
    pub fn of(ty: &CType) -> Option<Self> {
        match ty {
            CType::Void => Some(Self::Void),
            CType::Bool => Some(Self::Bool),
            CType::Int {
                bits,
                signedness: r2types::Signedness::Unsigned,
            } if CType::is_integer_width(*bits) => Some(Self::Unsigned(*bits)),
            CType::Int { bits, .. } if CType::is_integer_width(*bits) => Some(Self::Signed(*bits)),
            CType::Float(bits @ (32 | 64)) => Some(Self::Float(*bits)),
            CType::Pointer(_) => Some(Self::Pointer),
            CType::Typedef { ty, .. } | CType::Const(ty) => Self::of(ty),
            _ => None,
        }
    }

    /// The tag in the helper's name.
    pub fn tag(self) -> String {
        match self {
            Self::Void => "void".to_owned(),
            Self::Bool => "bool".to_owned(),
            Self::Unsigned(bits) => format!("u{bits}"),
            Self::Signed(bits) => format!("i{bits}"),
            Self::Float(bits) => format!("f{bits}"),
            Self::Pointer => "ptr".to_owned(),
        }
    }

    /// The C type the helper returns.
    fn spelled(self) -> String {
        match self {
            Self::Void => "void".to_owned(),
            Self::Bool => "_Bool".to_owned(),
            Self::Unsigned(128) => "__uint128_t".to_owned(),
            Self::Signed(128) => "__int128_t".to_owned(),
            Self::Unsigned(bits) => format!("uint{bits}_t"),
            Self::Signed(bits) => format!("int{bits}_t"),
            Self::Float(32) => "float".to_owned(),
            Self::Float(_) => "double".to_owned(),
            Self::Pointer => "void*".to_owned(),
        }
    }
}

/// A scalar operation spelled as a call to a helper the rendering defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Helper {
    /// A P-code flag of two operands of `bits` each: 8, 16, 32, 64 or 128.
    Flag { op: FlagOp, bits: u32 },
    /// A unary float operation at `bits`: 32 or 64.
    Float { op: FloatOp, bits: u32 },
    /// The float whose bits are this integer.
    FloatFromBits { bits: u32 },
    /// The integer whose bits are this float.
    FloatToBits { bits: u32 },
    /// A construct the rendering could not prove: it traps if executed.
    Residual(ResidualType),
}

impl Helper {
    /// A flag helper, where the width is a C integer's.
    pub fn flag(op: FlagOp, bits: u32) -> Option<Self> {
        CType::is_integer_width(bits).then_some(Self::Flag { op, bits })
    }

    /// A unary float helper, where the width is `float`'s or `double`'s.
    pub fn float(op: FloatOp, bits: u32) -> Option<Self> {
        matches!(bits, 32 | 64).then_some(Self::Float { op, bits })
    }

    /// The reinterpretation of an integer's bits as a float of `bits`.
    pub fn float_from_bits(bits: u32) -> Option<Self> {
        matches!(bits, 32 | 64).then_some(Self::FloatFromBits { bits })
    }

    /// The reinterpretation of a float's bits as an integer of `bits`.
    pub fn float_to_bits(bits: u32) -> Option<Self> {
        matches!(bits, 32 | 64).then_some(Self::FloatToBits { bits })
    }

    /// The helper's name.
    pub fn name(self) -> String {
        match self {
            Self::Flag { op, bits } => format!("r2sleigh_int_{}_{bits}", op.spelling()),
            Self::Float { op, bits } => format!("r2sleigh_float_{}_{bits}", op.spelling()),
            Self::FloatFromBits { bits } => format!("r2sleigh_float_from_bits_{bits}"),
            Self::FloatToBits { bits } => format!("r2sleigh_float_to_bits_{bits}"),
            Self::Residual(ty) => format!("r2sleigh_residual_{}", ty.tag()),
        }
    }

    /// The name, as the expression a call is made through.
    pub(crate) fn callee(self) -> CExpr {
        CExpr::External {
            name: self.name(),
            kind: crate::symbol::ExternalKind::Helper(self),
        }
    }

    /// A call to the helper.
    pub(crate) fn call(self, args: Vec<CExpr>) -> CExpr {
        CExpr::call(self.callee(), args)
    }

    /// The helper's C definition.
    pub fn definition(self) -> String {
        let name = self.name();
        match self {
            Self::Flag { op, bits } => flag_definition(&name, op, bits),
            Self::Float { op, bits } => float_definition(&name, op, bits),
            Self::FloatFromBits { bits } => {
                let (float, int) = float_and_bits(bits);
                format!(
                    "static inline {float} {name}({int} bits)\n\
                     {{\n\
                     \x20   union {{ {int} bits; {float} value; }} pun;\n\
                     \x20   pun.bits = bits;\n\
                     \x20   return pun.value;\n\
                     }}\n"
                )
            }
            Self::FloatToBits { bits } => {
                let (float, int) = float_and_bits(bits);
                format!(
                    "static inline {int} {name}({float} value)\n\
                     {{\n\
                     \x20   union {{ {float} value; {int} bits; }} pun;\n\
                     \x20   pun.value = value;\n\
                     \x20   return pun.bits;\n\
                     }}\n"
                )
            }
            Self::Residual(ty) => format!(
                "static inline {} {name}(uint32_t site)\n\
                 {{\n\
                 \x20   (void)site;\n\
                 \x20   __builtin_trap();\n\
                 }}\n",
                ty.spelled()
            ),
        }
    }
}

/// `float` and its bits, or `double` and its bits.
fn float_and_bits(bits: u32) -> (&'static str, &'static str) {
    if bits == 32 {
        ("float", "uint32_t")
    } else {
        ("double", "uint64_t")
    }
}

/// A flag of two `bits`-wide operands.
///
/// The operands are widened into an unsigned type no narrower than
/// `unsigned int` before any arithmetic, so no operation is on a promoted
/// signed `int`. Below that type's width the sum keeps its carry in the next
/// bit and the result is masked back to `bits`; at that width the carry is the
/// wrapped sum being smaller than an operand.
fn flag_definition(name: &str, op: FlagOp, bits: u32) -> String {
    let operand = match bits {
        128 => "__uint128_t".to_owned(),
        bits => format!("uint{bits}_t"),
    };
    let (wide, wide_bits) = match bits {
        128 => ("__uint128_t", 128),
        64 => ("uint64_t", 64),
        _ => ("uint32_t", 32),
    };
    let top = bits - 1;
    let masked = |expr: &str| {
        if bits == wide_bits {
            format!("({wide})({expr})")
        } else {
            format!("({wide})(({expr}) & ((({wide})1 << {bits}) - 1u))")
        }
    };
    let body = match op {
        FlagOp::Carry if bits == wide_bits => "    return (uint8_t)((a + b) < a);\n".to_owned(),
        FlagOp::Carry => format!("    return (uint8_t)(((a + b) >> {bits}) & 1u);\n"),
        FlagOp::SignedCarry => format!(
            "    const {wide} result = {};\n\
             \x20   return (uint8_t)(((~(a ^ b) & (a ^ result)) >> {top}) & 1u);\n",
            masked("a + b")
        ),
        FlagOp::SignedBorrow => format!(
            "    const {wide} result = {};\n\
             \x20   return (uint8_t)((((a ^ b) & (a ^ result)) >> {top}) & 1u);\n",
            masked("a - b")
        ),
    };
    format!(
        "static inline uint8_t {name}({operand} left, {operand} right)\n\
         {{\n\
         \x20   const {wide} a = left;\n\
         \x20   const {wide} b = right;\n\
         {body}\
         }}\n"
    )
}

/// A unary float operation on a `bits`-wide float.
fn float_definition(name: &str, op: FloatOp, bits: u32) -> String {
    let (float, int) = float_and_bits(bits);
    let suffix = if bits == 32 { "f" } else { "" };
    match op {
        // The sign bit cleared, so a NaN keeps its payload and `-0.0` is
        // `0.0`, which is what the operation is defined to do.
        FloatOp::Absolute => format!(
            "static inline {float} {name}({float} x)\n\
             {{\n\
             \x20   union {{ {float} value; {int} bits; }} pun;\n\
             \x20   pun.value = x;\n\
             \x20   pun.bits &= ~(({int})1 << {top});\n\
             \x20   return pun.value;\n\
             }}\n",
            top = bits - 1
        ),
        FloatOp::IsNan => format!(
            "static inline uint8_t {name}({float} x)\n\
             {{\n\
             \x20   return (uint8_t)(x != x);\n\
             }}\n"
        ),
        FloatOp::SquareRoot | FloatOp::Ceiling | FloatOp::Floor | FloatOp::Round => {
            let expr = match op {
                FloatOp::SquareRoot => format!("__builtin_sqrt{suffix}(x)"),
                FloatOp::Ceiling => format!("__builtin_ceil{suffix}(x)"),
                FloatOp::Floor => format!("__builtin_floor{suffix}(x)"),
                // P-code's FLOAT_ROUND is `floor(x + 0.5)` evaluated in double
                // at every width, and so is this: in float, `0.49999997f + 0.5f`
                // rounds up to 1 before the floor sees it. The floor of a float
                // plus a half is a float again, so the conversion back is exact.
                _ if bits == 32 => "(float)__builtin_floor((double)x + 0.5)".to_owned(),
                _ => "__builtin_floor(x + 0.5)".to_owned(),
            };
            format!(
                "static inline {float} {name}({float} x)\n\
                 {{\n\
                 \x20   return {expr};\n\
                 }}\n"
            )
        }
    }
}

/// Why a residual stands where it does: which construct the rendering could
/// not prove.
///
/// Carried on the residual's callee from where it is made to where the
/// emitter numbers it, so a consumer of the unit reads each site's cause
/// rather than guessing it from the text around the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ResidualCause {
    /// The interface proves no result, and this return hands one back.
    UnprovenReturn,
    /// A read of a value the function entered holding, in storage no
    /// convention argument slot delivers.
    HeldFromEntry,
    /// A read of an argument slot no recovered parameter admits.
    UnadmittedArgument,
    /// A read of an object nothing assigns and no entry supplies: a result a
    /// call left that nothing claimed, for one.
    NeverAssigned,
    /// A conversion to or from a float C has no type for.
    UnrepresentableFloat,
    /// A marked gap: an operation, or a branch or dispatch test, the renderer
    /// could not lower. The gap's own marker says which.
    Gap,
}

impl ResidualCause {
    /// The cause as a consumer of the unit reads it.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::UnprovenReturn => "unproven-return",
            Self::HeldFromEntry => "held-from-entry",
            Self::UnadmittedArgument => "unadmitted-argument",
            Self::NeverAssigned => "never-assigned",
            Self::UnrepresentableFloat => "unrepresentable-float",
            Self::Gap => "gap",
        }
    }
}

/// A residual of `ty`: an expression of that type which traps if evaluated,
/// standing for a construct unproven for `cause`.
///
/// The site is the emitter's to number, so the call carries no argument until
/// it is written: the number is where the residual stands in the text, and
/// only the text knows that.
pub(crate) fn residual(ty: &CType, cause: ResidualCause) -> Option<CExpr> {
    let residual = ResidualType::of(ty)?;
    let call = CExpr::call(
        CExpr::External {
            name: Helper::Residual(residual).name(),
            kind: crate::symbol::ExternalKind::Residual(residual, cause),
        },
        Vec::new(),
    );
    // A `void *` converts to an object pointer on assignment and nowhere else,
    // so a pointer residual is cast to the pointer it stands for.
    Some(if residual == ResidualType::Pointer {
        CExpr::cast(ty.clone(), call)
    } else {
        call
    })
}

/// Whether this expression node is a residual call's callee.
pub(crate) fn is_residual_callee(expr: &CExpr) -> Option<ResidualType> {
    residual_callee(expr).map(|(ty, _)| ty)
}

/// The type and the cause of the residual this callee names, if it names one.
pub(crate) fn residual_callee(expr: &CExpr) -> Option<(ResidualType, ResidualCause)> {
    match expr.unobserved() {
        CExpr::External {
            kind: crate::symbol::ExternalKind::Residual(ty, cause),
            ..
        } => Some((*ty, *cause)),
        _ => None,
    }
}

/// Every helper a function calls, and the trap a marked gap stands for, in the
/// order their definitions are emitted.
pub(crate) fn helpers_called(function: &CFunction) -> BTreeSet<Helper> {
    let mut helpers = BTreeSet::new();
    function.visit_body_exprs(&mut |expr| match expr {
        CExpr::External {
            kind: crate::symbol::ExternalKind::Helper(helper),
            ..
        } => {
            helpers.insert(*helper);
        }
        // One definition per type, whatever each site's cause.
        CExpr::External {
            kind: crate::symbol::ExternalKind::Residual(ty, _),
            ..
        } => {
            helpers.insert(Helper::Residual(*ty));
        }
        _ => {}
    });
    if function.body.iter().any(stmt_holds_gap) {
        helpers.insert(Helper::Residual(ResidualType::Void));
    }
    helpers
}

/// How many residuals a function holds: one for each residual call and each
/// marked gap, which is exactly how many sites the emitter numbers.
pub(crate) fn count_residuals(function: &CFunction) -> usize {
    let mut calls = 0usize;
    function.visit_body_exprs(&mut |expr| {
        if let CExpr::Call { func, .. } = expr
            && is_residual_callee(func).is_some()
        {
            calls += 1;
        }
    });
    calls + function.body.iter().map(count_gaps).sum::<usize>()
}

/// Every marker standing over a residual the occurrence it marks evaluates.
///
/// A marker on an expression covers the residuals inside that expression. A
/// marker on a statement covers the residuals in the statement's own
/// expressions -- its value, its test, its header -- and not those in the
/// statements it nests: an `if` whose arm traps still performs its test. A
/// marked gap is a residual where it stands, covered by the markers of the
/// statements it is the value of. One walk, the markers above the current
/// node kept on a stack.
pub(crate) fn markers_over_residuals(body: &[CStmt]) -> BTreeSet<crate::ast::RenderObservationId> {
    let mut found = BTreeSet::new();
    let mut over = Vec::new();
    for stmt in body {
        stmt_markers_over_residuals(stmt, &mut over, &mut found);
    }
    found
}

fn stmt_markers_over_residuals(
    stmt: &CStmt,
    over: &mut Vec<crate::ast::RenderObservationId>,
    found: &mut BTreeSet<crate::ast::RenderObservationId>,
) {
    // A nested statement starts with nothing over it: what marks the
    // statement holding it is not discharged by the nested one's residuals.
    let nested = |stmt: &CStmt, found: &mut BTreeSet<_>| {
        stmt_markers_over_residuals(stmt, &mut Vec::new(), found);
    };
    match stmt {
        CStmt::Observed { ids, stmt } => {
            let depth = over.len();
            over.extend(ids.iter());
            stmt_markers_over_residuals(stmt, over, found);
            over.truncate(depth);
        }
        CStmt::StructuredRegion { stmt, .. } => stmt_markers_over_residuals(stmt, over, found),
        CStmt::Expr(expr)
        | CStmt::Decl {
            init: Some(expr), ..
        }
        | CStmt::Return(Some(expr)) => expr_markers_over_residuals(expr, over, found),
        CStmt::Gap(_) => found.extend(over.iter().copied()),
        CStmt::Block(body) => {
            for stmt in body {
                nested(stmt, found);
            }
        }
        CStmt::If {
            cond,
            then_body,
            else_body,
        } => {
            expr_markers_over_residuals(cond, over, found);
            nested(then_body, found);
            if let Some(else_body) = else_body {
                nested(else_body, found);
            }
        }
        CStmt::While { cond, body } | CStmt::DoWhile { body, cond } => {
            expr_markers_over_residuals(cond, over, found);
            nested(body, found);
        }
        CStmt::For {
            init,
            cond,
            update,
            body,
        } => {
            if let Some(init) = init {
                stmt_markers_over_residuals(init, over, found);
            }
            for expr in cond.iter().chain(update) {
                expr_markers_over_residuals(expr, over, found);
            }
            nested(body, found);
        }
        CStmt::Switch {
            expr,
            cases,
            default,
        } => {
            expr_markers_over_residuals(expr, over, found);
            for stmt in cases
                .iter()
                .flat_map(|case| &case.body)
                .chain(default.iter().flatten())
            {
                nested(stmt, found);
            }
        }
        CStmt::Empty
        | CStmt::Decl { init: None, .. }
        | CStmt::Return(None)
        | CStmt::Break
        | CStmt::Continue
        | CStmt::Goto(_)
        | CStmt::Label(_)
        | CStmt::Comment(_) => {}
    }
}

fn expr_markers_over_residuals(
    expr: &CExpr,
    over: &mut Vec<crate::ast::RenderObservationId>,
    found: &mut BTreeSet<crate::ast::RenderObservationId>,
) {
    let depth = over.len();
    over.extend(expr.observation_ids().iter().copied());
    let expr = expr.unobserved();
    if let CExpr::Call { func, .. } = expr
        && is_residual_callee(func).is_some()
    {
        found.extend(over.iter().copied());
    }
    for child in expr.children() {
        expr_markers_over_residuals(child, over, found);
    }
    over.truncate(depth);
}

fn stmt_holds_gap(stmt: &CStmt) -> bool {
    count_gaps(stmt) > 0
}

/// Marked gaps in a statement and the statements inside it.
fn count_gaps(stmt: &CStmt) -> usize {
    let each = |stmts: &[CStmt]| stmts.iter().map(count_gaps).sum::<usize>();
    match stmt.unobserved() {
        CStmt::Gap(_) => 1,
        CStmt::StructuredRegion { stmt, .. } => count_gaps(stmt),
        CStmt::Block(body) => each(body),
        CStmt::If {
            then_body,
            else_body,
            ..
        } => count_gaps(then_body) + else_body.as_deref().map_or(0, count_gaps),
        CStmt::While { body, .. } | CStmt::DoWhile { body, .. } => count_gaps(body),
        CStmt::For { init, body, .. } => init.as_deref().map_or(0, count_gaps) + count_gaps(body),
        CStmt::Switch { cases, default, .. } => {
            cases.iter().map(|case| each(&case.body)).sum::<usize>()
                + default.as_deref().map_or(0, each)
        }
        _ => 0,
    }
}

/// The headers a translation unit includes.
///
/// Only `<stdint.h>`: the rendering spells every integer at a fixed width, and
/// no helper here needs a library declaration.
pub(crate) const INCLUDES: &[&str] = &["#include <stdint.h>"];

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::ast::RenderObservationId;

    /// A marker covers the residuals its own occurrence evaluates -- inside
    /// its expression, in its statement's test, in a gap it stands on -- and
    /// not those in a statement it nests: an `if` whose arm traps has still
    /// performed its test.
    #[test]
    fn a_marker_covers_the_residuals_its_occurrence_evaluates() {
        let [test, arm, value, gap, clean] = [0, 1, 2, 3, 4].map(RenderObservationId::from_index);
        let trap = || {
            residual(&CType::uint(64), ResidualCause::NeverAssigned)
                .expect("a residual of an integer")
        };
        let body = vec![
            CStmt::observe_all(
                [test],
                CStmt::If {
                    cond: CExpr::binary(crate::ast::BinaryOp::Eq, trap(), CExpr::IntLit(0)),
                    then_body: Box::new(CStmt::observe_all(
                        [arm],
                        CStmt::Return(Some(CExpr::observe_all([value], trap()))),
                    )),
                    else_body: None,
                },
            ),
            CStmt::observe_all(
                [gap],
                CStmt::Gap(crate::ast::GapMarker {
                    kind: "UnresolvedBranchCondition".to_owned(),
                    origin: "structure".to_owned(),
                    block_addr: 0x1000,
                    op_idx: 0,
                    ops: 0,
                }),
            ),
            CStmt::observe_all(
                [clean],
                CStmt::If {
                    cond: CExpr::IntLit(1),
                    then_body: Box::new(CStmt::Return(Some(trap()))),
                    else_body: None,
                },
            ),
        ];
        assert_eq!(
            markers_over_residuals(&body),
            BTreeSet::from([test, arm, value, gap])
        );
    }

    /// Every helper at every width it is made for.
    fn every_helper() -> BTreeSet<Helper> {
        let mut helpers = BTreeSet::new();
        for bits in [8, 16, 32, 64, 128] {
            for op in [FlagOp::Carry, FlagOp::SignedCarry, FlagOp::SignedBorrow] {
                helpers.insert(Helper::flag(op, bits).expect("integer width"));
            }
        }
        for bits in [32, 64] {
            for op in [
                FloatOp::Absolute,
                FloatOp::SquareRoot,
                FloatOp::Ceiling,
                FloatOp::Floor,
                FloatOp::Round,
                FloatOp::IsNan,
            ] {
                helpers.insert(Helper::float(op, bits).expect("float width"));
            }
            helpers.insert(Helper::float_from_bits(bits).expect("float width"));
            helpers.insert(Helper::float_to_bits(bits).expect("float width"));
        }
        for ty in [
            ResidualType::Void,
            ResidualType::Bool,
            ResidualType::Unsigned(64),
            ResidualType::Signed(32),
            ResidualType::Float(64),
            ResidualType::Pointer,
        ] {
            helpers.insert(Helper::Residual(ty));
        }
        helpers
    }

    /// Checks of each helper against its P-code definition, at the values
    /// where the definition turns; `main` returns the failing line.
    const CHECKS: &str = r#"
#define CHECK(c) do { if (!(c)) return __LINE__; } while (0)
int main(void)
{
    CHECK(r2sleigh_int_carry_8(0xff, 1) == 1 && r2sleigh_int_carry_8(0xfe, 1) == 0);
    CHECK(r2sleigh_int_carry_16(0xffff, 0xffff) == 1 && r2sleigh_int_carry_16(1, 2) == 0);
    CHECK(r2sleigh_int_carry_32(0xffffffffu, 1) == 1 && r2sleigh_int_carry_32(7, 9) == 0);
    CHECK(r2sleigh_int_carry_64(~(uint64_t)0, 1) == 1 && r2sleigh_int_carry_64(1, 1) == 0);
    CHECK(r2sleigh_int_carry_128(~(__uint128_t)0, 1) == 1 && r2sleigh_int_carry_128(1, 1) == 0);
    CHECK(r2sleigh_int_scarry_8(0x7f, 1) == 1 && r2sleigh_int_scarry_8(0x80, 0xff) == 1);
    CHECK(r2sleigh_int_scarry_8(0x7f, 0xff) == 0 && r2sleigh_int_scarry_8(1, 1) == 0);
    CHECK(r2sleigh_int_scarry_16(0x7fff, 1) == 1 && r2sleigh_int_scarry_16(0xffff, 1) == 0);
    CHECK(r2sleigh_int_scarry_32(0x7fffffffu, 1) == 1 && r2sleigh_int_scarry_32(0x80000000u, 0x80000000u) == 1);
    CHECK(r2sleigh_int_scarry_32(0xffffffffu, 1) == 0);
    CHECK(r2sleigh_int_scarry_64(0x7fffffffffffffffull, 1) == 1 && r2sleigh_int_scarry_64(2, 3) == 0);
    CHECK(r2sleigh_int_scarry_128(~(__uint128_t)0 >> 1, 1) == 1 && r2sleigh_int_scarry_128(2, 3) == 0);
    CHECK(r2sleigh_int_sborrow_8(0x80, 1) == 1 && r2sleigh_int_sborrow_8(0x7f, 0xff) == 1);
    CHECK(r2sleigh_int_sborrow_8(0, 1) == 0 && r2sleigh_int_sborrow_8(0x80, 0x80) == 0);
    CHECK(r2sleigh_int_sborrow_16(0x8000, 1) == 1 && r2sleigh_int_sborrow_16(5, 7) == 0);
    CHECK(r2sleigh_int_sborrow_32(0x80000000u, 1) == 1 && r2sleigh_int_sborrow_32(0, 0x80000000u) == 1);
    CHECK(r2sleigh_int_sborrow_32(2, 2) == 0);
    CHECK(r2sleigh_int_sborrow_64(0x8000000000000000ull, 1) == 1 && r2sleigh_int_sborrow_64(9, 3) == 0);
    CHECK(r2sleigh_int_sborrow_128((__uint128_t)1 << 127, 1) == 1 && r2sleigh_int_sborrow_128(9, 3) == 0);
    CHECK(r2sleigh_float_to_bits_64(r2sleigh_float_from_bits_64(0x400921fb54442d18ull)) == 0x400921fb54442d18ull);
    CHECK(r2sleigh_float_from_bits_64(0x3ff0000000000000ull) == 1.0);
    CHECK(r2sleigh_float_from_bits_32(0x3f800000u) == 1.0f && r2sleigh_float_to_bits_32(-0.0f) == 0x80000000u);
    CHECK(r2sleigh_float_to_bits_64(r2sleigh_float_abs_64(-0.0)) == 0);
    CHECK(r2sleigh_float_to_bits_32(r2sleigh_float_abs_32(r2sleigh_float_from_bits_32(0xffc00001u))) == 0x7fc00001u);
    CHECK(r2sleigh_float_abs_64(-2.5) == 2.5 && r2sleigh_float_abs_32(-2.5f) == 2.5f);
    CHECK(r2sleigh_float_sqrt_64(9.0) == 3.0 && r2sleigh_float_sqrt_32(16.0f) == 4.0f);
    CHECK(r2sleigh_float_ceil_64(-1.5) == -1.0 && r2sleigh_float_ceil_32(1.25f) == 2.0f);
    CHECK(r2sleigh_float_floor_64(-1.5) == -2.0 && r2sleigh_float_floor_32(1.75f) == 1.0f);
    CHECK(r2sleigh_float_round_64(2.5) == 3.0 && r2sleigh_float_round_64(-2.5) == -2.0);
    CHECK(r2sleigh_float_round_32(0.25f) == 0.0f);
    CHECK(r2sleigh_float_round_32(0.49999997f) == 0.0f && r2sleigh_float_round_32(-2.5f) == -2.0f);
    CHECK(r2sleigh_float_isnan_64(r2sleigh_float_from_bits_64(0x7ff8000000000000ull)) == 1);
    CHECK(r2sleigh_float_isnan_32(1.0f) == 0);
    return 0;
}
"#;

    /// Every helper at every width it is made for, defined in one translation
    /// unit and exercised on the values where each operation's definition
    /// turns: a carry out of the top bit, a sign change, a NaN, a negative
    /// zero and a halfway rounding. The compiled program checks each answer
    /// against the P-code definition and exits non-zero on the first wrong
    /// one. Skipped where no C compiler is installed.
    #[test]
    fn every_helper_compiles_strictly_and_computes_its_pcode_operation() {
        let Some(cc) = compiler() else {
            return;
        };
        let helpers = every_helper();
        let mut unit = INCLUDES.join("\n");
        unit.push('\n');
        for helper in &helpers {
            unit.push_str(&helper.definition());
        }
        unit.push_str(CHECKS);
        let dir = std::env::temp_dir().join(format!(
            "r2dec-prelude-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("temporary directory");
        let source = dir.join("prelude.c");
        let binary = dir.join("prelude");
        std::fs::write(&source, &unit).expect("write the unit");
        let compiled = std::process::Command::new(&cc)
            .args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-O1", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
            .expect("run the compiler");
        assert!(
            compiled.status.success(),
            "{}\n{unit}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let ran = std::process::Command::new(&binary)
            .status()
            .expect("run the checks");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            ran.code(),
            Some(0),
            "the check at that line failed:\n{unit}"
        );
    }

    /// The C compiler a test may use, when one is installed.
    pub(crate) fn compiler() -> Option<String> {
        ["cc", "gcc", "clang"]
            .into_iter()
            .find(|cc| {
                std::process::Command::new(cc)
                    .arg("--version")
                    .output()
                    .is_ok_and(|out| out.status.success())
            })
            .map(str::to_owned)
    }

    /// A residual's type is the scalar it stands in for, and nothing that is
    /// not one has a residual.
    #[test]
    fn a_residual_is_typed_by_the_scalar_it_stands_for() {
        assert_eq!(
            ResidualType::of(&CType::uint(64)),
            Some(ResidualType::Unsigned(64))
        );
        assert_eq!(
            ResidualType::of(&CType::int(16)),
            Some(ResidualType::Signed(16))
        );
        assert_eq!(
            ResidualType::of(&CType::Pointer(Box::new(CType::Float(64)))),
            Some(ResidualType::Pointer)
        );
        assert_eq!(ResidualType::of(&CType::BitVector(256)), None);
        assert_eq!(ResidualType::of(&CType::Struct("s".into())), None);
        assert_eq!(ResidualType::of(&CType::Unknown), None);
        assert_eq!(
            Helper::Residual(ResidualType::Unsigned(64)).name(),
            "r2sleigh_residual_u64"
        );
    }
}
