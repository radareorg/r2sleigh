//! C Abstract Syntax Tree representation.
//!
//! This module defines the AST types used to represent decompiled C code.

use serde::{Deserialize, Serialize};

/// The C type model.
///
/// This was a second type enum with its own renderer, and the two had already
/// disagreed once -- about how to spell a 128-bit integer -- with nothing to
/// catch it. It is now the shared model, so there is one set of variants and
/// one spelling for each of them.
pub use r2types::CTypeLike as CType;
/// Why a cast is in the rendered tree.
///
/// The distinction cannot be recovered from the types: a pointer converted to
/// a `uint64_t` and a `uint32_t` widened to a `uint64_t` are the same cast to
/// look at, and only the site that emitted one knows which it made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CastRole {
    /// A conversion the program performs.
    Conversion,
    /// The address-width step C requires between a pointer and an integer
    /// that is not the pointer's own width.
    PointerWidthStep,
}

/// The width of an integer cast target, or `None` for anything else.
fn integer_cast_width(ty: &CType) -> Option<u32> {
    match ty {
        CType::Int { bits, .. } => Some(*bits),
        CType::Bool => Some(8),
        _ => None,
    }
}

fn is_signed_integer(ty: &CType) -> bool {
    matches!(
        ty,
        CType::Int {
            signedness: r2types::Signedness::Signed,
            ..
        }
    )
}

/// A C expression.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CExpr {
    /// Internal marker attached to one exact rendered expression occurrence.
    ///
    /// This is transparent to C rendering and must be stripped before a
    /// `CFunction` leaves the decompiler. Every observation the occurrence
    /// carries is in `ids`, and `expr` is never itself `Observed`: build it
    /// with [`CExpr::observe_one`] or [`CExpr::observe_all`], which fuse.
    #[doc(hidden)]
    #[serde(skip)]
    Observed {
        ids: ObservationSet,
        expr: Box<CExpr>,
    },
    /// Integer literal.
    IntLit(i64),
    /// Unsigned integer literal.
    UIntLit(u64),
    /// Float literal.
    /// A floating literal and the width it is spelled at, 32 or 64.
    FloatLit(f64, u32),
    /// String literal.
    StringLit(String),
    /// Character literal.
    CharLit(char),
    /// Reference to a name this function declares.
    Var(crate::symbol::SymbolId),
    /// A name for something the function does not own, and what kind of thing it is.
    ///
    /// `Var` is for values this function has. An intrinsic the target defines, or
    /// a marker the lowering emits where it has nothing to say, is neither a value
    /// nor something a declaration could give it, and spelling it as a variable is
    /// what let a machine name look exactly like a local.
    External {
        name: String,
        kind: crate::symbol::ExternalKind,
    },
    /// A program-scope data object. Its address is the identity; `name` is
    /// presentation only.
    DataObject { address: u64, name: String },
    /// Unary operation.
    Unary { op: UnaryOp, operand: Box<CExpr> },
    /// Binary operation.
    Binary {
        op: BinaryOp,
        left: Box<CExpr>,
        right: Box<CExpr>,
    },
    /// Ternary conditional: cond ? then : else.
    Ternary {
        cond: Box<CExpr>,
        then_expr: Box<CExpr>,
        else_expr: Box<CExpr>,
    },
    /// Type cast: (type)expr.
    Cast {
        ty: CType,
        expr: Box<CExpr>,
        role: CastRole,
    },
    /// Function call.
    /// A call, and the site that makes it when one is known.
    ///
    /// Two layers build an expression for one call and nothing downstream could
    /// tell they were the same call, because the only handle either offered was
    /// the shape of the expression and the shapes differ. The site is an
    /// identity that does not change when the rendering does.
    Call {
        func: Box<CExpr>,
        args: Vec<CExpr>,
        /// Boxed: the site is present on a minority of calls and a call is a
        /// minority of expressions, but an inline `Option<(u64, usize)>` is
        /// twenty-four bytes and so set the width of every expression node in
        /// a rendered function.
        site: Option<Box<(u64, usize)>>,
    },
    /// Array/pointer subscript: `arr[index]`.
    Subscript { base: Box<CExpr>, index: Box<CExpr> },
    /// Member access: obj.member.
    Member { base: Box<CExpr>, member: String },
    /// Pointer member access: ptr->member.
    PtrMember { base: Box<CExpr>, member: String },
    /// Sizeof expression.
    Sizeof(Box<CExpr>),
    /// Sizeof type.
    SizeofType(CType),
    /// Address-of: &expr.
    AddrOf(Box<CExpr>),
    /// Dereference: *expr.
    Deref(Box<CExpr>),
    /// Comma expression: (a, b, c).
    Comma(Vec<CExpr>),
    /// Parenthesized expression.
    Paren(Box<CExpr>),
}

/// Unary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnaryOp {
    /// Logical NOT: !x
    Not,
    /// Bitwise NOT: ~x
    BitNot,
    /// Negation: -x
    Neg,
    /// Pre-increment: ++x
    PreInc,
    /// Pre-decrement: --x
    PreDec,
    /// Post-increment: x++
    PostInc,
    /// Post-decrement: x--
    PostDec,
}

/// Binary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryOp {
    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Mod,

    // Bitwise
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,

    // Comparison
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,

    // Logical
    And,
    Or,

    // Assignment
    Assign,
    AddAssign,
    SubAssign,
    MulAssign,
    DivAssign,
    ModAssign,
    BitAndAssign,
    BitOrAssign,
    BitXorAssign,
    ShlAssign,
    ShrAssign,
}

impl CExpr {
    /// Attach one observation to this exact occurrence, outside any it
    /// already carries.
    pub(crate) fn observe_one(id: RenderObservationId, expr: CExpr) -> Self {
        Self::observe_all([id], expr)
    }

    /// Attach observations, given outermost first, to this exact occurrence.
    ///
    /// They go outside any the occurrence already carries, and into the same
    /// node: an occurrence has one observation set however many cells it
    /// answers for. No ids leaves the expression as it is.
    pub(crate) fn observe_all(
        outer_to_inner: impl IntoIterator<Item = RenderObservationId>,
        expr: CExpr,
    ) -> Self {
        match ObservationSet::new(outer_to_inner.into_iter().collect()) {
            Some(outer) => Self::observe_set(outer, expr),
            None => expr,
        }
    }

    /// Attach a whole set outside any the occurrence already carries.
    fn observe_set(outer: ObservationSet, expr: CExpr) -> Self {
        match expr {
            Self::Observed { ids: inner, expr } => Self::Observed {
                ids: outer.join(inner),
                expr,
            },
            expr => Self::Observed {
                ids: outer,
                expr: Box::new(expr),
            },
        }
    }

    /// The observations this occurrence carries, outermost first.
    ///
    /// Every id on the sets stacked over [`Self::unobserved`], so the two are
    /// one decomposition: a walk or a rebuild that takes the semantic
    /// expression from one and the ids from the other neither misses nor
    /// drops an id. On a canonical tree that is the one set, borrowed. See
    /// [`Self::unobserved`] for a tree some pass left nested.
    pub(crate) fn observation_ids(&self) -> std::borrow::Cow<'_, [RenderObservationId]> {
        stacked_observation_ids(self, |expr| match expr {
            Self::Observed { ids, expr } => Some((ids, expr.as_ref())),
            _ => None,
        })
    }

    /// Separate this occurrence's observations, outermost first, from the
    /// semantic expression beneath them. Observations inside it stay put.
    ///
    /// The by-value form of [`Self::observation_ids`] and
    /// [`Self::unobserved`]: the ids of every set stacked on the occurrence
    /// and the expression beneath them all. One step on a canonical tree.
    pub(crate) fn into_semantic_with_observations(self) -> (Self, Vec<RenderObservationId>) {
        let mut semantic = self;
        let mut outer_to_inner = Vec::new();
        while let Self::Observed { ids, expr } = semantic {
            if outer_to_inner.is_empty() {
                outer_to_inner = ids.into_ids();
            } else {
                outer_to_inner.extend(ids);
            }
            semantic = *expr;
        }
        (semantic, outer_to_inner)
    }

    /// Visit the opaque proof markers nested in this expression.
    ///
    /// Semantic visitors deliberately skip wrappers. The observation journal
    /// needs the complementary view when it composes an outer replacement
    /// with an already-finalized inner one, so it can require that the inner
    /// value has its own occurrence instead of marking it twice.
    pub(crate) fn visit_render_observations(&self, visit: &mut impl FnMut(RenderObservationId)) {
        visit_expr_observations(self, &mut |id| {
            visit(id);
            Ok::<(), ()>(())
        })
        .expect("an infallible render-observation visitor cannot refuse");
    }

    /// Borrow the semantic expression beneath this occurrence's observations.
    ///
    /// One step: an occurrence carries all of its observations on one node.
    /// A tree some pass left nested is still seen through, and
    /// [`Self::observation_ids`] joins every set this steps over, so no pair
    /// of the two loses an id on it. A rebuild from such a pair puts the ids
    /// back as one set, canonical again. A read-only walk leaves the nesting
    /// standing, and the seal refuses it as `NestedObservation`.
    pub(crate) fn unobserved(&self) -> &Self {
        let mut expr = self;
        while let Self::Observed { expr: inner, .. } = expr {
            expr = inner;
        }
        expr
    }

    /// Structural equality that treats observation wrappers as metadata at
    /// every depth, not only at the root.
    pub(crate) fn transparently_eq(&self, other: &Self) -> bool {
        let left = self.unobserved();
        let right = other.unobserved();
        match (left, right) {
            (Self::IntLit(left), Self::IntLit(right)) => left == right,
            (Self::UIntLit(left), Self::UIntLit(right)) => left == right,
            (Self::FloatLit(left, lw), Self::FloatLit(right, rw)) => {
                left.to_bits() == right.to_bits() && lw == rw
            }
            (Self::StringLit(left), Self::StringLit(right)) => left == right,
            (Self::CharLit(left), Self::CharLit(right)) => left == right,
            (Self::Var(left), Self::Var(right)) => left == right,
            (
                Self::External {
                    name: left_name,
                    kind: left_kind,
                },
                Self::External {
                    name: right_name,
                    kind: right_kind,
                },
            ) => left_name == right_name && left_kind == right_kind,
            (
                Self::DataObject {
                    address: left_address,
                    name: left_name,
                },
                Self::DataObject {
                    address: right_address,
                    name: right_name,
                },
            ) => left_address == right_address && left_name == right_name,
            (
                Self::Unary {
                    op: left_op,
                    operand: left_operand,
                },
                Self::Unary {
                    op: right_op,
                    operand: right_operand,
                },
            ) => left_op == right_op && left_operand.transparently_eq(right_operand),
            (
                Self::Binary {
                    op: left_op,
                    left: left_left,
                    right: left_right,
                },
                Self::Binary {
                    op: right_op,
                    left: right_left,
                    right: right_right,
                },
            ) => {
                left_op == right_op
                    && left_left.transparently_eq(right_left)
                    && left_right.transparently_eq(right_right)
            }
            (
                Self::Ternary {
                    cond: left_cond,
                    then_expr: left_then,
                    else_expr: left_else,
                },
                Self::Ternary {
                    cond: right_cond,
                    then_expr: right_then,
                    else_expr: right_else,
                },
            ) => {
                left_cond.transparently_eq(right_cond)
                    && left_then.transparently_eq(right_then)
                    && left_else.transparently_eq(right_else)
            }
            (
                Self::Cast {
                    ty: left_ty,
                    expr: left_expr,
                    ..
                },
                Self::Cast {
                    ty: right_ty,
                    expr: right_expr,
                    ..
                },
            ) => left_ty == right_ty && left_expr.transparently_eq(right_expr),
            (
                Self::Call {
                    func: left_func,
                    args: left_args,
                    site: left_site,
                },
                Self::Call {
                    func: right_func,
                    args: right_args,
                    site: right_site,
                },
            ) => {
                left_site == right_site
                    && left_func.transparently_eq(right_func)
                    && transparent_expr_slices_eq(left_args, right_args)
            }
            (
                Self::Subscript {
                    base: left_base,
                    index: left_index,
                },
                Self::Subscript {
                    base: right_base,
                    index: right_index,
                },
            ) => left_base.transparently_eq(right_base) && left_index.transparently_eq(right_index),
            (
                Self::Member {
                    base: left_base,
                    member: left_member,
                },
                Self::Member {
                    base: right_base,
                    member: right_member,
                },
            )
            | (
                Self::PtrMember {
                    base: left_base,
                    member: left_member,
                },
                Self::PtrMember {
                    base: right_base,
                    member: right_member,
                },
            ) => left_member == right_member && left_base.transparently_eq(right_base),
            (Self::Sizeof(left), Self::Sizeof(right))
            | (Self::AddrOf(left), Self::AddrOf(right))
            | (Self::Deref(left), Self::Deref(right))
            | (Self::Paren(left), Self::Paren(right)) => left.transparently_eq(right),
            (Self::SizeofType(left), Self::SizeofType(right)) => left == right,
            (Self::Comma(left), Self::Comma(right)) => transparent_expr_slices_eq(left, right),
            _ => false,
        }
    }

    /// Clone semantic expression structure without copying occurrence-owned
    /// observation IDs into a second location.
    pub(crate) fn clone_without_render_observations(&self) -> Self {
        fn strip(expr: CExpr) -> CExpr {
            match expr {
                CExpr::Observed { expr, .. } => strip(*expr),
                other => other.map_children(&mut strip),
            }
        }

        strip(self.clone())
    }

    /// Create an integer literal.
    pub fn int(value: i64) -> Self {
        Self::IntLit(value)
    }

    /// Create an unsigned integer literal.
    pub fn uint(value: u64) -> Self {
        Self::UIntLit(value)
    }

    /// Create a variable reference to an already declared name.
    pub fn var(name: crate::symbol::SymbolId) -> Self {
        Self::Var(name)
    }

    /// Create a binary operation.
    pub fn binary(op: BinaryOp, left: CExpr, right: CExpr) -> Self {
        Self::Binary {
            op,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// Create a unary operation.
    pub fn unary(op: UnaryOp, operand: CExpr) -> Self {
        Self::Unary {
            op,
            operand: Box::new(operand),
        }
    }

    /// Create a function call.
    pub fn call(func: CExpr, args: Vec<CExpr>) -> Self {
        Self::Call {
            func: Box::new(func),
            args,
            site: None,
        }
    }

    /// A call that knows which site makes it.
    pub fn call_at(site: (u64, usize), func: CExpr, args: Vec<CExpr>) -> Self {
        Self::Call {
            func: Box::new(func),
            args,
            site: Some(Box::new(site)),
        }
    }

    /// Create a cast expression.
    /// Create a cast, which never nests directly inside itself.
    ///
    /// Converting to a type a value has already been converted to converts
    /// nothing: `(uint32_t)(uint32_t)x` and `(uint32_t)x` are the same value,
    /// the same type and the same bits, for every type C can spell. Casting
    /// is idempotent, so the constructor states it once.
    ///
    /// This is where the rule belongs rather than at each caller. A cast is
    /// applied at a type boundary, and a projection, an operand rule and an
    /// assignment policy each state their own boundary without being able to
    /// see what the others already said; twenty-six sites in operation
    /// lowering alone call this, and asking each of them to check first is
    /// twenty-six chances to forget. The nesting the renderer does need --
    /// a narrowing inside a widening, or the pointer-width step before a
    /// pointer becomes a smaller integer -- is between two *different* types
    /// and is untouched.
    /// Create a conversion the program performs.
    ///
    /// Adjacent conversions that say one thing twice are said once; see
    /// [`CExpr::cast_with_role`] for the rules and their side conditions.
    pub fn cast(ty: CType, expr: CExpr) -> Self {
        Self::cast_with_role(ty, expr, CastRole::Conversion)
    }

    /// Create the address-width step C requires beside a pointer conversion.
    ///
    /// Only a site that is converting a pointer to or from its own
    /// address-width integer calls this, and it knows that at the moment it
    /// emits. Nothing downstream can tell such a step from an ordinary
    /// widening by looking at the types, which is exactly why it is recorded
    /// here rather than re-derived later by inspecting the expression.
    pub fn pointer_width_cast(ty: CType, expr: CExpr) -> Self {
        Self::cast_with_role(ty, expr, CastRole::PointerWidthStep)
    }

    /// The collapse rules for adjacent casts.
    ///
    /// Each rule is an equality between two spellings of one conversion, and
    /// each is stated over the cast types alone, never over the operand's
    /// text. `w(T)` is T's width in bits.
    ///
    /// - **Same type.** `(T)(T)e` is `(T)e`. Converting to a type a value has
    ///   already been converted to converts nothing.
    /// - **A narrowing absorbs the conversion beneath it.** `(A)(B)e` is
    ///   `(A)e` when both are integers and `w(A) <= w(B)`: `(B)e` has the low
    ///   `w(B)` bits of `e`, and the low `w(A) <= w(B)` of those are the low
    ///   `w(A)` bits of `e`. B's signedness cannot matter because only the bit
    ///   pattern survives the second truncation.
    /// - **Transitive widening.** `(A)(B)(C)e` is `(A)(C)e` when
    ///   `w(C) <= w(B) <= w(A)` and C's signedness implies B's: widening a
    ///   value twice widens it once. The signedness condition is load-bearing.
    ///   `(uint64_t)(uint32_t)(int8_t)e` is **not** `(uint64_t)(int8_t)e`,
    ///   because the first stops sign-extending at thirty-two bits.
    /// - **Pointer round trip.** `(P)(I)(P)e` is `(P)e` when `I` is a recorded
    ///   address-width step: a pointer converted to its own address integer
    ///   and back is the pointer.
    ///
    /// The middle two never look through a recorded address-width step.
    /// `(uint32_t)(uint64_t)p` is a pointer narrowed to a smaller integer
    /// through its own width, and dropping the step leaves
    /// `-Wpointer-to-int-cast`, which is a hard error under the corpus flags.
    /// That is the whole reason the step is recorded.
    pub fn cast_with_role(ty: CType, expr: CExpr, role: CastRole) -> Self {
        // Through the render markers, which are metadata: the cast the
        // renderer already spelled is the one under them. A marker on a cast
        // that goes away moves onto what replaces it, at the same depth, so
        // the occurrence it records is still in the sealed tree. `carried` is
        // every id `bare` sits beneath, however many sets they stand in.
        let (carried, bare) = (expr.observation_ids(), expr.unobserved());
        if let CExpr::Cast {
            ty: inner_ty,
            expr: inner_expr,
            role: inner_role,
        } = bare
        {
            if *inner_ty == ty {
                return expr;
            }
            let surviving =
                |inner: &CExpr| CExpr::observe_all(carried.iter().copied(), inner.clone());
            // Two pointer conversions in a row are one. C11 6.3.2.3p1 and p7
            // make a conversion to `void *` and back the same pointer, and an
            // object pointer converted twice lands where converting once would
            // have: `(char *)(void *)p` is `(char *)p`. Function pointers are
            // left alone -- only object pointers carry that guarantee.
            if matches!(ty, CType::Pointer(_))
                && matches!(inner_ty, CType::Pointer(_))
                && !matches!(&ty, CType::Pointer(inner) if matches!(**inner, CType::Function { .. }))
                && !matches!(inner_ty, CType::Pointer(inner) if matches!(**inner, CType::Function { .. }))
            {
                return Self::cast_with_role(ty, surviving(inner_expr), role);
            }
            // A conversion sitting directly on a pointer is the address-width
            // step whether or not the site that emitted it said so, and
            // dropping it leaves a pointer converted straight to a narrower
            // integer. The recorded role catches the step over a pointer the
            // AST cannot see into, such as a bare name; this catches the step
            // over a pointer the AST can.
            let over_a_pointer = matches!(
                inner_expr.unobserved(),
                CExpr::Cast {
                    ty: CType::Pointer(_),
                    ..
                }
            );
            if *inner_role == CastRole::Conversion
                && !over_a_pointer
                && let (Some(outer_bits), Some(inner_bits)) =
                    (integer_cast_width(&ty), integer_cast_width(inner_ty))
            {
                if outer_bits <= inner_bits {
                    return Self::cast_with_role(ty, surviving(inner_expr), role);
                }
                if let CExpr::Cast {
                    ty: innermost_ty, ..
                } = inner_expr.unobserved()
                    && let Some(innermost_bits) = integer_cast_width(innermost_ty)
                    && innermost_bits <= inner_bits
                    && (!is_signed_integer(innermost_ty) || is_signed_integer(inner_ty))
                {
                    return Self::cast_with_role(ty, surviving(inner_expr), role);
                }
            }
            if matches!(ty, CType::Pointer(_))
                && *inner_role == CastRole::PointerWidthStep
                && let CExpr::Cast {
                    ty: innermost_ty, ..
                } = inner_expr.unobserved()
                && *innermost_ty == ty
            {
                return surviving(inner_expr);
            }
        }
        Self::Cast {
            ty,
            expr: Box::new(expr),
            role,
        }
    }

    /// Create an assignment.
    pub fn assign(target: CExpr, value: CExpr) -> Self {
        Self::binary(BinaryOp::Assign, target, value)
    }

    /// Create a dereference.
    pub fn deref(expr: CExpr) -> Self {
        Self::Deref(Box::new(expr))
    }

    /// Create an address-of.
    pub fn addr_of(expr: CExpr) -> Self {
        Self::AddrOf(Box::new(expr))
    }

    /// Create a subscript.
    pub fn subscript(base: CExpr, index: CExpr) -> Self {
        Self::Subscript {
            base: Box::new(base),
            index: Box::new(index),
        }
    }

    /// Get operator precedence (higher = binds tighter).
    pub fn precedence(&self) -> u8 {
        match self {
            Self::Observed { expr, .. } => expr.precedence(),
            Self::Comma(_) => 1,
            Self::Binary {
                op:
                    BinaryOp::Assign
                    | BinaryOp::AddAssign
                    | BinaryOp::SubAssign
                    | BinaryOp::MulAssign
                    | BinaryOp::DivAssign
                    | BinaryOp::ModAssign
                    | BinaryOp::BitAndAssign
                    | BinaryOp::BitOrAssign
                    | BinaryOp::BitXorAssign
                    | BinaryOp::ShlAssign
                    | BinaryOp::ShrAssign,
                ..
            } => 2,
            Self::Ternary { .. } => 3,
            Self::Binary {
                op: BinaryOp::Or, ..
            } => 4,
            Self::Binary {
                op: BinaryOp::And, ..
            } => 5,
            Self::Binary {
                op: BinaryOp::BitOr,
                ..
            } => 6,
            Self::Binary {
                op: BinaryOp::BitXor,
                ..
            } => 7,
            Self::Binary {
                op: BinaryOp::BitAnd,
                ..
            } => 8,
            Self::Binary {
                op: BinaryOp::Eq | BinaryOp::Ne,
                ..
            } => 9,
            Self::Binary {
                op: BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge,
                ..
            } => 10,
            Self::Binary {
                op: BinaryOp::Shl | BinaryOp::Shr,
                ..
            } => 11,
            Self::Binary {
                op: BinaryOp::Add | BinaryOp::Sub,
                ..
            } => 12,
            Self::Binary {
                op: BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod,
                ..
            } => 13,
            Self::Unary { .. }
            | Self::Cast { .. }
            | Self::Sizeof(_)
            | Self::SizeofType(_)
            | Self::AddrOf(_)
            | Self::Deref(_) => 14,
            Self::Subscript { .. }
            | Self::Member { .. }
            | Self::PtrMember { .. }
            | Self::Call { .. } => 15,
            _ => 16, // Literals, variables, parenthesized
        }
    }

    /// Apply a transformation to immediate child expressions.
    pub fn map_children(self, f: &mut impl FnMut(CExpr) -> CExpr) -> Self {
        match self {
            // Through the fusing constructor: the rewritten child may carry
            // observations of its own, and they join this occurrence's.
            Self::Observed { ids, expr } => Self::observe_all(ids, f(*expr)),
            Self::Unary { op, operand } => Self::Unary {
                op,
                operand: Box::new(f(*operand)),
            },
            Self::Binary { op, left, right } => Self::Binary {
                op,
                left: Box::new(f(*left)),
                right: Box::new(f(*right)),
            },
            Self::Ternary {
                cond,
                then_expr,
                else_expr,
            } => Self::Ternary {
                cond: Box::new(f(*cond)),
                then_expr: Box::new(f(*then_expr)),
                else_expr: Box::new(f(*else_expr)),
            },
            Self::Cast { ty, expr, role } => Self::Cast {
                ty,
                expr: Box::new(f(*expr)),
                role,
            },
            Self::Call { func, args, site } => Self::Call {
                func: Box::new(f(*func)),
                args: args.into_iter().map(f).collect(),
                site,
            },
            Self::Subscript { base, index } => Self::Subscript {
                base: Box::new(f(*base)),
                index: Box::new(f(*index)),
            },
            Self::Member { base, member } => Self::Member {
                base: Box::new(f(*base)),
                member,
            },
            Self::PtrMember { base, member } => Self::PtrMember {
                base: Box::new(f(*base)),
                member,
            },
            Self::Sizeof(inner) => Self::Sizeof(Box::new(f(*inner))),
            Self::AddrOf(inner) => Self::AddrOf(Box::new(f(*inner))),
            Self::Deref(inner) => Self::Deref(Box::new(f(*inner))),
            Self::Comma(items) => Self::Comma(items.into_iter().map(f).collect()),
            Self::Paren(inner) => Self::Paren(Box::new(f(*inner))),
            leaf => leaf,
        }
    }

    /// The immediate child expressions, in the order they are written.
    ///
    /// The borrowing twin of [`Self::map_children`], for a walk that has to
    /// carry state down the tree and cannot rebuild it on the way back.
    pub fn children(&self) -> Vec<&CExpr> {
        match self {
            Self::Observed { expr, .. }
            | Self::Unary { operand: expr, .. }
            | Self::Cast { expr, .. }
            | Self::Sizeof(expr)
            | Self::AddrOf(expr)
            | Self::Deref(expr)
            | Self::Paren(expr)
            | Self::Member { base: expr, .. }
            | Self::PtrMember { base: expr, .. } => vec![expr],
            Self::Binary { left, right, .. }
            | Self::Subscript {
                base: left,
                index: right,
            } => vec![left, right],
            Self::Ternary {
                cond,
                then_expr,
                else_expr,
            } => vec![cond, then_expr, else_expr],
            Self::Call { func, args, .. } => std::iter::once(&**func).chain(args.iter()).collect(),
            Self::Comma(items) => items.iter().collect(),
            _ => Vec::new(),
        }
    }

    /// Visit this expression and all descendants in pre-order.
    pub fn visit(&self, f: &mut impl FnMut(&CExpr)) {
        if let Self::Observed { expr, .. } = self {
            expr.visit(f);
            return;
        }
        f(self);
        match self {
            Self::Unary { operand, .. }
            | Self::Cast { expr: operand, .. }
            | Self::Sizeof(operand)
            | Self::AddrOf(operand)
            | Self::Deref(operand)
            | Self::Paren(operand) => operand.visit(f),
            Self::Binary { left, right, .. } => {
                left.visit(f);
                right.visit(f);
            }
            Self::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                cond.visit(f);
                then_expr.visit(f);
                else_expr.visit(f);
            }
            Self::Call { func, args, .. } => {
                func.visit(f);
                for arg in args {
                    arg.visit(f);
                }
            }
            Self::Subscript { base, index } => {
                base.visit(f);
                index.visit(f);
            }
            Self::Member { base, .. } | Self::PtrMember { base, .. } => base.visit(f),
            Self::Comma(items) => {
                for item in items {
                    item.visit(f);
                }
            }
            Self::IntLit(_)
            | Self::UIntLit(_)
            | Self::FloatLit(..)
            | Self::StringLit(_)
            | Self::CharLit(_)
            | Self::Var(_)
            | Self::External { .. }
            | Self::DataObject { .. }
            | Self::SizeofType(_) => {}
            Self::Observed { .. } => unreachable!("handled before visiting semantic nodes"),
        }
    }
}

impl CExpr {
    /// Every type this expression spells, in pre-order.
    ///
    /// A cast and a `sizeof` write a type into the page just as a declaration
    /// does, so any question about what the rendering names has to ask them
    /// too. Answering it from the tree rather than from the emitted text is
    /// what keeps the answer stable when the spelling changes.
    pub fn visit_types(&self, f: &mut impl FnMut(&CType)) {
        self.visit(&mut |expr| match expr {
            Self::Cast { ty, .. } | Self::SizeofType(ty) => f(ty),
            _ => {}
        });
    }
}

impl CExpr {
    /// Every type this expression spells, for rewriting one in place.
    pub fn visit_types_mut(&mut self, f: &mut impl FnMut(&mut CType)) {
        match self {
            Self::Cast { ty, expr, .. } => {
                f(ty);
                expr.visit_types_mut(f);
            }
            Self::SizeofType(ty) => f(ty),
            Self::Unary { operand, .. } => operand.visit_types_mut(f),
            Self::Sizeof(operand)
            | Self::AddrOf(operand)
            | Self::Deref(operand)
            | Self::Paren(operand) => operand.visit_types_mut(f),
            Self::Observed { expr, .. } => expr.visit_types_mut(f),
            Self::Binary { left, right, .. } => {
                left.visit_types_mut(f);
                right.visit_types_mut(f);
            }
            Self::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                cond.visit_types_mut(f);
                then_expr.visit_types_mut(f);
                else_expr.visit_types_mut(f);
            }
            Self::Call { func, args, .. } => {
                func.visit_types_mut(f);
                args.iter_mut().for_each(|arg| arg.visit_types_mut(f));
            }
            Self::Subscript { base, index } => {
                base.visit_types_mut(f);
                index.visit_types_mut(f);
            }
            Self::Member { base, .. } | Self::PtrMember { base, .. } => base.visit_types_mut(f),
            Self::Comma(items) => items.iter_mut().for_each(|item| item.visit_types_mut(f)),
            Self::IntLit(_)
            | Self::UIntLit(_)
            | Self::FloatLit(..)
            | Self::StringLit(_)
            | Self::CharLit(_)
            | Self::Var(_)
            | Self::External { .. }
            | Self::DataObject { .. } => {}
        }
    }
}

impl CStmt {
    /// Every type this statement and its descendants spell, for rewriting.
    pub fn visit_types_mut(&mut self, f: &mut impl FnMut(&mut CType)) {
        match self {
            Self::Observed { stmt, .. } | Self::StructuredRegion { stmt, .. } => {
                stmt.visit_types_mut(f);
            }
            Self::Decl { ty, init, .. } => {
                f(ty);
                if let Some(init) = init {
                    init.visit_types_mut(f);
                }
            }
            Self::Expr(expr) => expr.visit_types_mut(f),
            Self::Block(stmts) => stmts.iter_mut().for_each(|stmt| stmt.visit_types_mut(f)),
            Self::If {
                cond,
                then_body,
                else_body,
            } => {
                cond.visit_types_mut(f);
                then_body.visit_types_mut(f);
                if let Some(body) = else_body {
                    body.visit_types_mut(f);
                }
            }
            Self::While { cond, body } | Self::DoWhile { body, cond } => {
                cond.visit_types_mut(f);
                body.visit_types_mut(f);
            }
            Self::For {
                init,
                cond,
                update,
                body,
            } => {
                if let Some(init) = init {
                    init.visit_types_mut(f);
                }
                if let Some(cond) = cond {
                    cond.visit_types_mut(f);
                }
                if let Some(update) = update {
                    update.visit_types_mut(f);
                }
                body.visit_types_mut(f);
            }
            Self::Switch {
                expr,
                cases,
                default,
            } => {
                expr.visit_types_mut(f);
                for case in cases {
                    case.body
                        .iter_mut()
                        .for_each(|stmt| stmt.visit_types_mut(f));
                }
                if let Some(default) = default {
                    default.iter_mut().for_each(|stmt| stmt.visit_types_mut(f));
                }
            }
            Self::Return(expr) => {
                if let Some(expr) = expr {
                    expr.visit_types_mut(f);
                }
            }
            Self::Empty
            | Self::Break
            | Self::Continue
            | Self::Goto(_)
            | Self::Label(_)
            | Self::Comment(_)
            | Self::Gap(_) => {}
        }
    }
}

impl CStmt {
    /// Every expression this statement and its descendants hold at the top,
    /// in pre-order; [`CExpr::visit`] reaches what is inside each.
    pub fn visit_exprs(&self, f: &mut impl FnMut(&CExpr)) {
        match self {
            Self::Observed { stmt, .. } | Self::StructuredRegion { stmt, .. } => {
                stmt.visit_exprs(f);
            }
            Self::Decl { init, .. } => {
                if let Some(init) = init {
                    f(init);
                }
            }
            Self::Expr(expr) => f(expr),
            Self::Block(stmts) => stmts.iter().for_each(|stmt| stmt.visit_exprs(f)),
            Self::If {
                cond,
                then_body,
                else_body,
            } => {
                f(cond);
                then_body.visit_exprs(f);
                if let Some(body) = else_body {
                    body.visit_exprs(f);
                }
            }
            Self::While { cond, body } | Self::DoWhile { body, cond } => {
                f(cond);
                body.visit_exprs(f);
            }
            Self::For {
                init,
                cond,
                update,
                body,
            } => {
                if let Some(init) = init {
                    init.visit_exprs(f);
                }
                if let Some(cond) = cond {
                    f(cond);
                }
                if let Some(update) = update {
                    f(update);
                }
                body.visit_exprs(f);
            }
            Self::Switch {
                expr,
                cases,
                default,
            } => {
                f(expr);
                for case in cases {
                    f(&case.value);
                    case.body.iter().for_each(|stmt| stmt.visit_exprs(f));
                }
                if let Some(default) = default {
                    default.iter().for_each(|stmt| stmt.visit_exprs(f));
                }
            }
            Self::Return(expr) => {
                if let Some(expr) = expr {
                    f(expr);
                }
            }
            Self::Empty
            | Self::Break
            | Self::Continue
            | Self::Goto(_)
            | Self::Label(_)
            | Self::Comment(_)
            | Self::Gap(_) => {}
        }
    }

    /// Every root expression of this statement and its descendants, for
    /// rewriting in place, in the order [`Self::visit_exprs`] visits them.
    pub(crate) fn visit_exprs_mut(&mut self, f: &mut impl FnMut(&mut CExpr)) {
        match self {
            Self::Observed { stmt, .. } | Self::StructuredRegion { stmt, .. } => {
                stmt.visit_exprs_mut(f);
            }
            Self::Decl { init, .. } => {
                if let Some(init) = init {
                    f(init);
                }
            }
            Self::Expr(expr) => f(expr),
            Self::Block(stmts) => stmts.iter_mut().for_each(|stmt| stmt.visit_exprs_mut(f)),
            Self::If {
                cond,
                then_body,
                else_body,
            } => {
                f(cond);
                then_body.visit_exprs_mut(f);
                if let Some(body) = else_body {
                    body.visit_exprs_mut(f);
                }
            }
            Self::While { cond, body } | Self::DoWhile { body, cond } => {
                f(cond);
                body.visit_exprs_mut(f);
            }
            Self::For {
                init,
                cond,
                update,
                body,
            } => {
                if let Some(init) = init {
                    init.visit_exprs_mut(f);
                }
                if let Some(cond) = cond {
                    f(cond);
                }
                if let Some(update) = update {
                    f(update);
                }
                body.visit_exprs_mut(f);
            }
            Self::Switch {
                expr,
                cases,
                default,
            } => {
                f(expr);
                for case in cases {
                    f(&mut case.value);
                    case.body
                        .iter_mut()
                        .for_each(|stmt| stmt.visit_exprs_mut(f));
                }
                if let Some(default) = default {
                    default.iter_mut().for_each(|stmt| stmt.visit_exprs_mut(f));
                }
            }
            Self::Return(expr) => {
                if let Some(expr) = expr {
                    f(expr);
                }
            }
            Self::Empty
            | Self::Break
            | Self::Continue
            | Self::Goto(_)
            | Self::Label(_)
            | Self::Comment(_)
            | Self::Gap(_) => {}
        }
    }

    /// Every statement this one holds, itself first, for rewriting in place.
    ///
    /// Observation and region markers are stepped through, so a statement
    /// replaced here stays under the markers it stood under.
    pub(crate) fn visit_stmts_mut(&mut self, f: &mut impl FnMut(&mut CStmt)) {
        if let Self::Observed { stmt, .. } | Self::StructuredRegion { stmt, .. } = self {
            stmt.visit_stmts_mut(f);
            return;
        }
        f(self);
        match self {
            Self::Block(stmts) => stmts.iter_mut().for_each(|stmt| stmt.visit_stmts_mut(f)),
            Self::If {
                then_body,
                else_body,
                ..
            } => {
                then_body.visit_stmts_mut(f);
                if let Some(body) = else_body {
                    body.visit_stmts_mut(f);
                }
            }
            Self::While { body, .. } | Self::DoWhile { body, .. } => body.visit_stmts_mut(f),
            Self::For { init, body, .. } => {
                if let Some(init) = init {
                    init.visit_stmts_mut(f);
                }
                body.visit_stmts_mut(f);
            }
            Self::Switch { cases, default, .. } => {
                for case in cases {
                    case.body
                        .iter_mut()
                        .for_each(|stmt| stmt.visit_stmts_mut(f));
                }
                if let Some(default) = default {
                    default.iter_mut().for_each(|stmt| stmt.visit_stmts_mut(f));
                }
            }
            _ => {}
        }
    }

    /// Every type this statement and its descendants spell, in pre-order.
    pub fn visit_types(&self, f: &mut impl FnMut(&CType)) {
        match self {
            Self::Observed { stmt, .. } | Self::StructuredRegion { stmt, .. } => {
                stmt.visit_types(f);
            }
            Self::Decl { ty, init, .. } => {
                f(ty);
                if let Some(init) = init {
                    init.visit_types(f);
                }
            }
            Self::Expr(expr) => expr.visit_types(f),
            Self::Block(stmts) => stmts.iter().for_each(|stmt| stmt.visit_types(f)),
            Self::If {
                cond,
                then_body,
                else_body,
            } => {
                cond.visit_types(f);
                then_body.visit_types(f);
                if let Some(body) = else_body {
                    body.visit_types(f);
                }
            }
            Self::While { cond, body } | Self::DoWhile { body, cond } => {
                cond.visit_types(f);
                body.visit_types(f);
            }
            Self::For {
                init,
                cond,
                update,
                body,
            } => {
                if let Some(init) = init {
                    init.visit_types(f);
                }
                if let Some(cond) = cond {
                    cond.visit_types(f);
                }
                if let Some(update) = update {
                    update.visit_types(f);
                }
                body.visit_types(f);
            }
            Self::Switch {
                expr,
                cases,
                default,
            } => {
                expr.visit_types(f);
                for case in cases {
                    case.body.iter().for_each(|stmt| stmt.visit_types(f));
                }
                if let Some(default) = default {
                    default.iter().for_each(|stmt| stmt.visit_types(f));
                }
            }
            Self::Return(expr) => {
                if let Some(expr) = expr {
                    expr.visit_types(f);
                }
            }
            Self::Empty
            | Self::Break
            | Self::Continue
            | Self::Goto(_)
            | Self::Label(_)
            | Self::Comment(_)
            | Self::Gap(_) => {}
        }
    }
}

impl CFunction {
    /// Every expression node in the body, in pre-order, through markers.
    pub(crate) fn visit_body_exprs(&self, f: &mut impl FnMut(&CExpr)) {
        for stmt in &self.body {
            stmt.visit_exprs(&mut |root| root.visit(f));
        }
    }

    /// Every statement in the body, for rewriting one in place.
    pub(crate) fn visit_body_stmts_mut(&mut self, f: &mut impl FnMut(&mut CStmt)) {
        for stmt in &mut self.body {
            stmt.visit_stmts_mut(f);
        }
    }

    /// Every type this rendering spells, for rewriting one in place.
    pub fn visit_types_mut(&mut self, f: &mut impl FnMut(&mut CType)) {
        f(&mut self.ret_type);
        for param in &mut self.params {
            f(&mut param.ty);
        }
        for local in &mut self.locals {
            f(&mut local.ty);
        }
        for decl in &mut self.externs {
            f(&mut decl.ret_type);
            for param in decl.params.iter_mut().flatten() {
                f(param);
            }
        }
        for aggregate in &mut self.aggregates {
            for (ty, _) in &mut aggregate.members {
                f(ty);
            }
        }
        for typedef in &mut self.typedefs {
            f(&mut typedef.target);
        }
        self.body
            .iter_mut()
            .for_each(|stmt| stmt.visit_types_mut(f));
    }

    pub fn visit_types(&self, f: &mut impl FnMut(&CType)) {
        f(&self.ret_type);
        for param in &self.params {
            f(&param.ty);
        }
        for local in &self.locals {
            f(&local.ty);
        }
        for decl in &self.externs {
            f(&decl.ret_type);
            for param in decl.params.iter().flatten() {
                f(param);
            }
        }
        for aggregate in &self.aggregates {
            for (ty, _) in &aggregate.members {
                f(ty);
            }
        }
        for typedef in &self.typedefs {
            f(&typedef.target);
        }
        self.body.iter().for_each(|stmt| stmt.visit_types(f));
    }
}

fn transparent_expr_slices_eq(left: &[CExpr], right: &[CExpr]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.transparently_eq(right))
}

pub use crate::observation_journal::RenderObservationId;

/// Test-only marker allocator. Production IDs are owned by the sealed journal.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct RenderObservationOwner {
    next: u32,
}

/// Allocation failed before an observation could be attached.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RenderObservationAllocationError {
    IdSpaceExhausted,
}

#[cfg(test)]
impl RenderObservationOwner {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn allocate(&mut self) -> Result<RenderObservationId, RenderObservationAllocationError> {
        let next = self
            .next
            .checked_add(1)
            .ok_or(RenderObservationAllocationError::IdSpaceExhausted)?;
        let id = crate::observation_journal::test_render_observation_id(self.next);
        self.next = next;
        Ok(id)
    }

    pub(crate) fn observe_expr(
        &mut self,
        expr: CExpr,
    ) -> Result<(RenderObservationId, CExpr), RenderObservationAllocationError> {
        let id = self.allocate()?;
        Ok((id, CExpr::observe_one(id, expr)))
    }

    pub(crate) fn observe_stmt(
        &mut self,
        stmt: CStmt,
    ) -> Result<(RenderObservationId, CStmt), RenderObservationAllocationError> {
        let id = self.allocate()?;
        Ok((id, CStmt::observe_one(id, stmt)))
    }

    pub(crate) fn expected_count(&self) -> usize {
        usize::try_from(self.next).unwrap_or(usize::MAX)
    }
}

impl BinaryOp {
    /// True for the operators whose left operand is written, not read.
    pub const fn writes_left_operand(self) -> bool {
        matches!(
            self,
            Self::Assign
                | Self::AddAssign
                | Self::SubAssign
                | Self::MulAssign
                | Self::DivAssign
                | Self::ModAssign
                | Self::BitAndAssign
                | Self::BitOrAssign
                | Self::BitXorAssign
                | Self::ShlAssign
                | Self::ShrAssign
        )
    }

    /// Get the C operator string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
            Self::Mod => "%",
            Self::BitAnd => "&",
            Self::BitOr => "|",
            Self::BitXor => "^",
            Self::Shl => "<<",
            Self::Shr => ">>",
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::And => "&&",
            Self::Or => "||",
            Self::Assign => "=",
            Self::AddAssign => "+=",
            Self::SubAssign => "-=",
            Self::MulAssign => "*=",
            Self::DivAssign => "/=",
            Self::ModAssign => "%=",
            Self::BitAndAssign => "&=",
            Self::BitOrAssign => "|=",
            Self::BitXorAssign => "^=",
            Self::ShlAssign => "<<=",
            Self::ShrAssign => ">>=",
        }
    }
}

impl UnaryOp {
    /// Get the C operator string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Not => "!",
            Self::BitNot => "~",
            Self::Neg => "-",
            Self::PreInc => "++",
            Self::PreDec => "--",
            Self::PostInc => "++",
            Self::PostDec => "--",
        }
    }

    /// Check if this is a postfix operator.
    pub fn is_postfix(&self) -> bool {
        matches!(self, Self::PostInc | Self::PostDec)
    }
}

/// A C statement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CStmt {
    /// Internal lexical-region marker attached to one exact statement occurrence.
    ///
    /// The marker is transparent to C semantics.  It is minted and sealed by
    /// the control-flow structurer so later lowering phases can recover exact
    /// lexical ancestry without rebuilding it from block addresses.
    #[doc(hidden)]
    #[serde(skip)]
    StructuredRegion {
        marker: crate::structured_region::StructuredRegionMarker,
        stmt: Box<CStmt>,
    },
    /// Internal marker attached to one exact rendered statement occurrence.
    ///
    /// This is transparent to C rendering and must be stripped before a
    /// `CFunction` leaves the decompiler. Every observation the occurrence
    /// carries is in `ids`, and `stmt` is never itself `Observed`: build it
    /// with [`CStmt::observe_one`] or [`CStmt::observe_all`], which fuse.
    #[doc(hidden)]
    #[serde(skip)]
    Observed {
        ids: ObservationSet,
        stmt: Box<CStmt>,
    },
    /// Empty statement.
    Empty,
    /// Expression statement.
    Expr(CExpr),
    /// Variable declaration.
    Decl {
        ty: CType,
        name: crate::symbol::SymbolId,
        init: Option<CExpr>,
    },
    /// Block of statements.
    Block(Vec<CStmt>),
    /// If statement.
    If {
        cond: CExpr,
        then_body: Box<CStmt>,
        else_body: Option<Box<CStmt>>,
    },
    /// While loop.
    While { cond: CExpr, body: Box<CStmt> },
    /// Do-while loop.
    DoWhile { body: Box<CStmt>, cond: CExpr },
    /// For loop.
    For {
        init: Option<Box<CStmt>>,
        cond: Option<CExpr>,
        update: Option<CExpr>,
        body: Box<CStmt>,
    },
    /// Switch statement.
    Switch {
        expr: CExpr,
        cases: Vec<SwitchCase>,
        default: Option<Vec<CStmt>>,
    },
    /// Return statement.
    Return(Option<CExpr>),
    /// Break statement.
    Break,
    /// Continue statement.
    Continue,
    /// Goto statement.
    Goto(String),
    /// Label.
    Label(String),
    /// Comment.
    Comment(String),
    /// A cell the renderer could not prove, marked where it stands.
    ///
    /// The gap is the honest alternative to refusing the whole function: the
    /// operations it covers are accounted for in the obligation ledger under
    /// [`crate::ledger::Outcome::Gapped`], the reader and the compiler both
    /// see that something is missing here, and nothing downstream may treat
    /// the function as fully proven.
    Gap(GapMarker),
}

/// What one marked gap covers and why it is there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GapMarker {
    /// The refusal that opened the gap, in its diagnostic spelling.
    pub kind: String,
    /// Where in the decompiler the refusal was decided, as `file.rs:line`.
    pub origin: String,
    /// The block whose operation could not be proven.
    pub block_addr: u64,
    /// The index of that operation within the block.
    pub op_idx: usize,
    /// How many graph instructions this one marker accounts for.
    pub ops: usize,
}

impl std::fmt::Display for GapMarker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A gap over no operation marks control the text could not state.
        if self.ops == 0 {
            return write!(
                f,
                "r2dec gap: {} at {:#x} ({})",
                self.kind, self.block_addr, self.origin
            );
        }
        write!(
            f,
            "r2dec gap: {} at {:#x}:{} covering {} op{} ({})",
            self.kind,
            self.block_addr,
            self.op_idx,
            self.ops,
            if self.ops == 1 { "" } else { "s" },
            self.origin
        )
    }
}

/// Every observation one rendered occurrence carries, outermost first.
///
/// An observation set is an attribute of one occurrence. It used to be one
/// wrapper per id, and an occurrence answers for as many cells as it stands
/// for -- a gap claims every cell of its closure, tens of thousands in one
/// function -- so the depth of the render tree grew with that count, and every
/// recursive pass over the tree overflowed the stack on it. One node holding
/// the whole set keeps the depth independent of the count and makes reaching
/// the semantic node beneath it one step.
///
/// Never empty, and constructed only here: an occurrence with no observations
/// has no `Observed` node, and one that gains more fuses them into the node it
/// has. The one constructor answers `None` for no ids and the one combinator
/// joins two sets, so no path builds an empty set in any build profile.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationSet {
    outer_to_inner: Box<[RenderObservationId]>,
}

impl ObservationSet {
    /// The set of these ids, outermost first; none for no ids.
    fn new(outer_to_inner: Vec<RenderObservationId>) -> Option<Self> {
        (!outer_to_inner.is_empty()).then(|| Self {
            outer_to_inner: outer_to_inner.into_boxed_slice(),
        })
    }

    /// This set outside `inner`: one occurrence's ids, this set's first.
    fn join(self, inner: Self) -> Self {
        let mut outer_to_inner = self.outer_to_inner.into_vec();
        outer_to_inner.extend_from_slice(&inner.outer_to_inner);
        Self {
            outer_to_inner: outer_to_inner.into_boxed_slice(),
        }
    }

    /// The ids, outermost first.
    pub(crate) fn ids(&self) -> &[RenderObservationId] {
        &self.outer_to_inner
    }

    /// The ids, outermost first, by value.
    pub(crate) fn iter(&self) -> impl DoubleEndedIterator<Item = RenderObservationId> + '_ {
        self.outer_to_inner.iter().copied()
    }

    /// The ids, outermost first, as a vector of their own.
    fn into_ids(self) -> Vec<RenderObservationId> {
        self.outer_to_inner.into_vec()
    }
}

impl IntoIterator for ObservationSet {
    type Item = RenderObservationId;
    type IntoIter = std::vec::IntoIter<RenderObservationId>;

    fn into_iter(self) -> Self::IntoIter {
        self.into_ids().into_iter()
    }
}

/// Every id on the observation sets stacked from `node` down, outermost
/// first, where `layer` answers a node's set and the node beneath it.
///
/// On a canonical tree there is at most one set, which is borrowed. A tree
/// some pass left nested has its sets joined in the order they stand, which is
/// the order the one-box-per-id chains met them.
fn stacked_observation_ids<'a, T: 'a>(
    node: &'a T,
    layer: impl Fn(&'a T) -> Option<(&'a ObservationSet, &'a T)>,
) -> std::borrow::Cow<'a, [RenderObservationId]> {
    use std::borrow::Cow;
    let mut sets =
        std::iter::successors(layer(node), |(_, beneath)| layer(beneath)).map(|(set, _)| set.ids());
    match (sets.next(), sets.next()) {
        (None, _) => Cow::Borrowed(&[]),
        (Some(only), None) => Cow::Borrowed(only),
        (Some(outer), Some(next)) => Cow::Owned(
            outer
                .iter()
                .chain(next)
                .chain(sets.flatten())
                .copied()
                .collect(),
        ),
    }
}

/// Ordered observation metadata peeled from the outside of one statement.
///
/// Shape-changing passes may need to inspect or decompose the semantic
/// statement, but the observation IDs still belong to the same source
/// position. This chain is the single owner of that temporary separation: it
/// is the statement's [`ObservationSet`] taken off -- every set stacked on it,
/// joined, should a pass have left them nested -- or nothing when the
/// statement carried none, and it is put back as that same set, so neither the
/// order nor the cardinality can drift.
#[derive(Debug, Default)]
pub(crate) struct StmtObservationChain {
    set: Option<ObservationSet>,
}

impl StmtObservationChain {
    /// Take on another chain's markers, innermost last.
    ///
    /// Two statements the text replaces with one still owe every cell they
    /// owned, so the survivor carries both chains.
    pub(crate) fn extend(&mut self, other: Self) {
        self.set = match (self.set.take(), other.set) {
            (Some(outer), Some(inner)) => Some(outer.join(inner)),
            (outer, inner) => outer.or(inner),
        };
    }

    /// Split the markers this predicate selects out of the chain, keeping both
    /// sides in order.
    pub(crate) fn split_out(
        self,
        select: &dyn Fn(RenderObservationId) -> bool,
    ) -> (Vec<RenderObservationId>, Self) {
        let (selected, rest) = self
            .into_ids()
            .into_iter()
            .partition::<Vec<_>, _>(|id| select(*id));
        (
            selected,
            Self {
                set: ObservationSet::new(rest),
            },
        )
    }

    /// The markers themselves, outermost first, for a rewrite that has to put
    /// them somewhere other than around one statement.
    pub(crate) fn into_ids(self) -> Vec<RenderObservationId> {
        self.set.map_or_else(Vec::new, ObservationSet::into_ids)
    }

    /// Reattach this chain to the semantic statement at the same position.
    pub(crate) fn reapply(self, stmt: CStmt) -> CStmt {
        match self.set {
            Some(set) => CStmt::observe_set(set, stmt),
            None => stmt,
        }
    }

    /// Move the exact statement occurrence into an expression-valued header
    /// position without dropping its observation ownership.
    pub(crate) fn reapply_expr(self, expr: CExpr) -> CExpr {
        match self.set {
            Some(set) => CExpr::observe_set(set, expr),
            None => expr,
        }
    }

    /// Reattach this chain when decomposition has one exact surviving statement.
    ///
    /// Returning `false` means the semantic position was deleted or split into
    /// multiple statements, so no single final occurrence owns the IDs.
    /// Callers must leave that coverage unaccounted rather than choosing a
    /// child merely to keep the chain reachable.
    pub(crate) fn reapply_to_unique(self, stmts: &mut [CStmt]) -> bool {
        if stmts.len() != 1 {
            return false;
        }
        let semantic = std::mem::replace(&mut stmts[0], CStmt::Empty);
        stmts[0] = self.reapply(semantic);
        true
    }
}

/// A case in a switch statement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwitchCase {
    /// Case value.
    pub value: CExpr,
    /// Case body.
    pub body: Vec<CStmt>,
}

impl CStmt {
    /// Attach an unsealed lexical-region marker to this statement occurrence.
    pub(crate) fn structured_region(
        marker: crate::structured_region::StructuredRegionMarker,
        stmt: CStmt,
    ) -> Self {
        Self::StructuredRegion {
            marker,
            stmt: Box::new(stmt),
        }
    }

    /// Attach one observation to this exact occurrence, outside any it
    /// already carries.
    #[cfg(test)]
    pub(crate) fn observe_one(id: RenderObservationId, stmt: CStmt) -> Self {
        Self::observe_all([id], stmt)
    }

    /// Attach observations, given outermost first, to this exact occurrence.
    ///
    /// They go outside any the occurrence already carries, and into the same
    /// node: an occurrence has one observation set however many cells it
    /// answers for. No ids leaves the statement as it is.
    pub(crate) fn observe_all(
        outer_to_inner: impl IntoIterator<Item = RenderObservationId>,
        stmt: CStmt,
    ) -> Self {
        match ObservationSet::new(outer_to_inner.into_iter().collect()) {
            Some(outer) => Self::observe_set(outer, stmt),
            None => stmt,
        }
    }

    /// Attach a whole set outside any the occurrence already carries.
    fn observe_set(outer: ObservationSet, stmt: CStmt) -> Self {
        match stmt {
            Self::Observed { ids: inner, stmt } => Self::Observed {
                ids: outer.join(inner),
                stmt,
            },
            stmt => Self::Observed {
                ids: outer,
                stmt: Box::new(stmt),
            },
        }
    }

    /// Restore one occurrence after a pass rewrote its statement in place.
    ///
    /// A pass that descends through an observation and replaces what it finds
    /// there -- a block collapsing to its only statement, a conditional
    /// rewritten into an assignment that carries markers of its own -- can
    /// leave an observed statement directly under this one. Both sets belong
    /// to the one occurrence, so the inner set joins this one as its innermost
    /// ids. Constant time when there is nothing to join.
    pub(crate) fn rejoin_observations(&mut self) {
        if let Self::Observed { stmt, .. } = self
            && matches!(stmt.as_ref(), Self::Observed { .. })
            && let Self::Observed { ids, stmt } = std::mem::replace(self, Self::Empty)
        {
            *self = Self::observe_set(ids, *stmt);
        }
    }

    /// The observations this occurrence carries, outermost first.
    ///
    /// Every id on the sets stacked over [`Self::unobserved`], so the two are
    /// one decomposition: a walk or a rebuild that takes the semantic
    /// statement from one and the ids from the other neither misses nor drops
    /// an id. On a canonical tree that is the one set, borrowed. See
    /// [`Self::unobserved`] for a tree some pass left nested.
    pub(crate) fn observation_ids(&self) -> std::borrow::Cow<'_, [RenderObservationId]> {
        stacked_observation_ids(self, |stmt| match stmt {
            Self::Observed { ids, stmt } => Some((ids, stmt.as_ref())),
            _ => None,
        })
    }

    /// Separate only the leading statement-observation chain from its semantic
    /// node. Nested child observations remain in place.
    ///
    /// The by-value form of [`Self::observation_ids`] and
    /// [`Self::unobserved`]: the ids of every set stacked on the occurrence
    /// and the statement beneath them all. One step on a canonical tree.
    pub(crate) fn into_semantic_with_observations(self) -> (Self, StmtObservationChain) {
        let mut semantic = self;
        let mut outer_to_inner = Vec::new();
        while let Self::Observed { ids, stmt } = semantic {
            if outer_to_inner.is_empty() {
                outer_to_inner = ids.into_ids();
            } else {
                outer_to_inner.extend(ids);
            }
            semantic = *stmt;
        }
        let set = ObservationSet::new(outer_to_inner);
        (semantic, StmtObservationChain { set })
    }

    /// Borrow the semantic statement beneath this occurrence's observations.
    ///
    /// One step: an occurrence carries all of its observations on one node.
    /// A tree some pass left nested is still seen through, and
    /// [`Self::observation_ids`] joins every set this steps over, so no pair
    /// of the two loses an id on it. A rebuild from such a pair puts the ids
    /// back as one set, canonical again. A read-only walk leaves the nesting
    /// standing, and the seal refuses it as `NestedObservation`.
    pub(crate) fn unobserved(&self) -> &Self {
        let mut stmt = self;
        while let Self::Observed { stmt: inner, .. } = stmt {
            stmt = inner;
        }
        stmt
    }

    /// Clone semantic statement data while omitting every observation wrapper.
    pub(crate) fn clone_without_render_observations(&self) -> Self {
        let mut clone = self.clone();
        strip_stmt_observations(&mut clone);
        clone
    }

    /// Create an expression statement.
    pub fn expr(e: CExpr) -> Self {
        Self::Expr(e)
    }

    /// Create a return statement.
    pub fn ret(value: Option<CExpr>) -> Self {
        Self::Return(value)
    }

    /// Create an if statement.
    pub fn if_stmt(cond: CExpr, then_body: CStmt, else_body: Option<CStmt>) -> Self {
        Self::If {
            cond,
            then_body: Box::new(then_body),
            else_body: else_body.map(Box::new),
        }
    }

    /// Create a while loop.
    pub fn while_loop(cond: CExpr, body: CStmt) -> Self {
        Self::While {
            cond,
            body: Box::new(body),
        }
    }

    /// Create a block.
    pub fn block(stmts: Vec<CStmt>) -> Self {
        Self::Block(stmts)
    }

    /// Create a declaration.
    pub fn decl(ty: CType, name: crate::symbol::SymbolId, init: Option<CExpr>) -> Self {
        Self::Decl { ty, name, init }
    }

    /// Create a comment.
    pub fn comment(text: impl Into<String>) -> Self {
        Self::Comment(text.into())
    }
}

/// A C function definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CFunction {
    /// Every name this function declares.
    ///
    /// Owned here because every pass that runs after folding already takes
    /// `&mut CFunction`, so none of them needs the table threaded to it.
    /// The names this function declares, shared with everything that renders
    /// it. Handing a copy over instead would give the renderer identifiers the
    /// copy never issued.
    pub symbols: std::rc::Rc<std::cell::RefCell<crate::symbol::SymbolTable>>,
    /// Function name.
    pub name: String,
    /// Return type.
    pub ret_type: CType,
    /// Parameters.
    pub params: Vec<CParam>,
    /// Local variables.
    pub locals: Vec<CLocal>,
    /// Function body.
    pub body: Vec<CStmt>,
    /// False when the parameter list was never recovered, as opposed to being
    /// recovered and found empty. An empty list prints as `(void)`, which
    /// asserts the function takes no arguments; a function whose interface is
    /// unknown must not make that claim.
    pub params_known: bool,
    /// The functions this one calls, in the order their names sort.
    ///
    /// C requires a declaration before a call, and a decompiled function that
    /// calls another is not readable, compilable or checkable without one.
    /// These are emitted above the definition.
    pub externs: Vec<CExternDecl>,
    /// Why this function is declared rather than defined, when it is.
    ///
    /// A PLT stub for a variadic import forwards the caller's variadic tail,
    /// and C has no syntax for that, so the honest rendering names what the
    /// address resolves to and defines nothing.
    pub declaration_only: Option<String>,
    /// Named types the rendering spells, declared so the names resolve.
    ///
    /// Emitted above the aggregates: a typedef may name a tag defined below it,
    /// and an aggregate member may be declared at a typedef name.
    pub typedefs: Vec<CTypedefDef>,
    /// Aggregate definitions the rendering declares a value of.
    ///
    /// A pointer to an undefined tag is legal C; a value of one is not. The
    /// layout comes from the same type graph the declaration's type did, so
    /// defining it here costs nothing the declaration did not already claim.
    pub aggregates: Vec<CAggregateDef>,
    /// The wide-carrier helpers the body calls, defined above the function.
    ///
    /// A carrier wider than any C integer has no operators, so every
    /// operation on one is a call; the rendering defines what it calls, so it
    /// compiles on its own. `crate::bitvector` is their one definition.
    pub bitvector_helpers: Vec<crate::bitvector::BitVectorHelper>,
    /// Named data objects the body refers to, declared so the rendering stays a
    /// self-contained translation unit.
    ///
    /// An accepted type remains marked with its radare2 provenance. Without
    /// one, the emitter keeps the honest incomplete-byte-array declaration.
    pub extern_objects: Vec<CExternObject>,
}

/// One named type this rendering declares, so the name it spells resolves.
///
/// A pointer to an undeclared *tag* is legal C; a pointer to an undeclared
/// *typedef name* is not, so a rendering that writes `UInt16 *p` has to say
/// what `UInt16` is. The target comes from the same type database that
/// admitted the name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CTypedefDef {
    pub name: String,
    pub target: CType,
    /// The text to declare the name with, where the type model has no spelling
    /// for it. A name the C implementation owns is defined by the
    /// implementation's own words -- `size_t` is `unsigned long` on a machine
    /// whose long is its address width -- and those are not fixed-width names.
    pub spelling: Option<String>,
}

/// One aggregate this rendering defines, so a value of it can be declared.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CAggregateDef {
    /// `struct` or `union`, as the tag was introduced.
    pub is_union: bool,
    pub name: String,
    /// Each member's declared type and name, in offset order.
    pub members: Vec<(CType, String)>,
}

/// One program data object used by this function's rendered body.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CExternObject {
    pub name: String,
    pub address: u64,
    pub type_fact: Option<r2types::DataObjectTypeFact>,
    pub type_refusal: Option<r2types::DataObjectTypeRefusal>,
}

/// The name a linker knows an import by, with radare2's flag namespace removed.
fn import_namespace_stripped(name: &str) -> &str {
    for space in ["sym.imp.", "imp.", "reloc.imp.", "sym.func.imp."] {
        if let Some(stripped) = name.strip_prefix(space) {
            return stripped;
        }
    }
    name
}

/// A machine symbol spelled as a C identifier.
///
/// radare2 names a symbol `sym._rotl32`, and a decompiler that puts that in its
/// output has written something no C compiler will parse -- it reads as a
/// member access on an undeclared `sym`. The name still has to be recognisable,
/// so every character C does not allow becomes an underscore and nothing else
/// changes.
///
/// An import is the exception, because it is the one name here that a linker
/// has to resolve. `sym.imp.__stack_chk_fail` spelled with its namespace
/// intact is `sym_imp___stack_chk_fail`, which nothing defines, and every
/// stack-protected rendering failed to link on that symbol. The namespace is
/// radare2's, not the program's, so an import carries the name the program
/// was linked against. A defined symbol keeps its namespace: its definition
/// is rendered here under the same spelling, and stripping `sym.` from
/// `sym._rotl32` would make the rendering collide with the real `_rotl32`.
pub fn c_identifier(name: &str) -> String {
    let name = import_namespace_stripped(name);
    let mut identifier = String::with_capacity(name.len());
    for character in name.chars() {
        if character.is_ascii_alphanumeric() || character == '_' {
            identifier.push(character);
        } else {
            identifier.push('_');
        }
    }
    if identifier.is_empty() {
        return "_".to_string();
    }
    if identifier.starts_with(|character: char| character.is_ascii_digit()) {
        identifier.insert(0, '_');
    }
    identifier
}

/// A prototype for a function this one calls.
///
/// Only what the call needs to be well formed: the name, what it returns, and
/// the types of the arguments the call passes. Where the callee's interface is
/// not recovered the parameter list is left unspecified rather than asserted
/// empty, for the same reason `params_known` exists.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CExternDecl {
    /// The callee's name, as the call spells it.
    pub name: String,
    /// What the callee returns.
    pub ret_type: CType,
    /// The callee's parameter types, or `None` when they are unknown.
    pub params: Option<Vec<CType>>,
    /// Whether the callee takes a variadic tail.
    ///
    /// One declaration has to describe every call to the callee in this
    /// function, and a fixed parameter list cannot describe two calls that
    /// pass different numbers of arguments. Declaring the ellipsis is what
    /// makes both of them legal C rather than a call the declaration
    /// contradicts.
    pub variadic: bool,
    /// Whether the source says the callee never returns: the block that
    /// calls it has no successor, and the prototype has to say so too.
    pub noreturn: bool,
    /// Where in the program the name resolves: the entry a direct call
    /// reaches, which is the stub for an import. `None` for a machine
    /// operation, which is no place in the program at all.
    pub address: Option<u64>,
}

/// A function parameter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CParam {
    /// Parameter type.
    pub ty: CType,
    /// Parameter name.
    pub name: crate::symbol::SymbolId,
}

/// A local variable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CLocal {
    /// Variable type.
    pub ty: CType,
    /// Variable name.
    pub name: crate::symbol::SymbolId,
    /// Stack offset (if known).
    pub stack_offset: Option<i64>,
}

impl CFunction {
    /// Create a new function.
    pub fn new(name: impl Into<String>, ret_type: CType) -> Self {
        Self {
            symbols: std::rc::Rc::new(std::cell::RefCell::new(crate::symbol::SymbolTable::new())),
            name: name.into(),
            ret_type,
            externs: Vec::new(),
            typedefs: Vec::new(),
            aggregates: Vec::new(),
            bitvector_helpers: Vec::new(),
            extern_objects: Vec::new(),
            params: Vec::new(),
            locals: Vec::new(),
            body: Vec::new(),
            params_known: true,
            declaration_only: None,
        }
    }

    /// Declare what this address resolves to instead of defining it.
    pub fn as_declaration_only(mut self, reason: impl Into<String>) -> Self {
        self.declaration_only = Some(reason.into());
        self
    }

    /// Mark the parameter list as unrecovered, so it is not rendered as a
    /// proven-empty `(void)` list.
    pub fn with_unknown_params(mut self) -> Self {
        self.params_known = false;
        self
    }

    /// Add a parameter.
    pub fn with_param(mut self, ty: CType, name: crate::symbol::SymbolId) -> Self {
        self.params.push(CParam { ty, name });
        self
    }

    /// Set the body.
    pub fn with_body(mut self, body: Vec<CStmt>) -> Self {
        self.body = body;
        self
    }
}

/// Validated reachability for one owner's fixed observation-ID domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReachableObservations {
    reachable: Vec<bool>,
}

impl ReachableObservations {
    #[cfg(test)]
    pub(crate) fn contains(&self, id: RenderObservationId) -> bool {
        usize::try_from(id.index())
            .ok()
            .and_then(|index| self.reachable.get(index))
            .copied()
            .unwrap_or(false)
    }

    #[cfg(test)]
    pub(crate) fn ids(&self) -> impl Iterator<Item = RenderObservationId> + '_ {
        self.reachable
            .iter()
            .enumerate()
            .filter_map(|(index, reachable)| {
                if *reachable {
                    u32::try_from(index)
                        .ok()
                        .map(crate::observation_journal::test_render_observation_id)
                } else {
                    None
                }
            })
    }
}

/// A marked AST did not belong to the supplied dense observation-ID domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RenderObservationStripError {
    DomainTooLarge {
        expected_count: usize,
    },
    CapacityUnavailable {
        expected_count: usize,
    },
    OutOfRange {
        id: RenderObservationId,
        expected_count: usize,
    },
    Duplicate {
        id: RenderObservationId,
    },
    /// An observed occurrence directly inside another: one occurrence's ids
    /// split over two nodes. Every constructor fuses them, so this is a pass
    /// that built the node by hand or rewrote a child without rejoining.
    NestedObservation {
        id: RenderObservationId,
    },
}

impl std::fmt::Display for RenderObservationStripError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DomainTooLarge { expected_count } => write!(
                f,
                "observation domain of size {expected_count} exceeds the ID space"
            ),
            Self::CapacityUnavailable { expected_count } => {
                write!(
                    f,
                    "cannot allocate observation domain of size {expected_count}"
                )
            }
            Self::OutOfRange { id, expected_count } => write!(
                f,
                "observation {} is outside expected domain 0..{expected_count}",
                id.index()
            ),
            Self::Duplicate { id } => {
                write!(f, "observation {} occurs more than once", id.index())
            }
            Self::NestedObservation { id } => write!(
                f,
                "observation {} wraps another observed node instead of sharing its set",
                id.index()
            ),
        }
    }
}

impl std::error::Error for RenderObservationStripError {}

/// Final AST node carried by one validated observation marker.
///
/// The node is borrowed from inside the wrapper, after every render rewrite
/// has completed.  Consumers therefore inspect what survived, rather than
/// treating marker reachability as a proxy for the final disposition.
#[derive(Debug, Clone, Copy)]
pub(crate) enum RenderObservationNode<'a> {
    Expr(&'a CExpr),
    Stmt(&'a CStmt),
}

/// Failure while transactionally inspecting a fixed observation domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RenderObservationInspectError<E> {
    Markers(RenderObservationStripError),
    Observer(E),
}

fn validate_render_observations(
    function: &CFunction,
    expected_count: usize,
) -> Result<ReachableObservations, RenderObservationStripError> {
    if expected_count > usize::try_from(u32::MAX).unwrap_or(usize::MAX) {
        return Err(RenderObservationStripError::DomainTooLarge { expected_count });
    }
    let mut reachable = Vec::new();
    reachable
        .try_reserve_exact(expected_count)
        .map_err(|_| RenderObservationStripError::CapacityUnavailable { expected_count })?;
    reachable.resize(expected_count, false);
    let mut observations = ReachableObservations { reachable };
    // Through the inspecting walk, which hands over the node beneath each
    // set: canonical form is checked there in constant time per id, at the
    // first node that breaks it, without following the chain it starts.
    for stmt in &function.body {
        inspect_stmt_observations(stmt, &mut |id, node| {
            let nested = match node {
                RenderObservationNode::Expr(expr) => matches!(expr, CExpr::Observed { .. }),
                RenderObservationNode::Stmt(stmt) => matches!(stmt, CStmt::Observed { .. }),
            };
            if nested {
                return Err(RenderObservationStripError::NestedObservation { id });
            }
            observations.record(id)
        })?;
    }
    Ok(observations)
}

/// Whether a function still contains any internal render observation marker.
pub(crate) fn has_render_observations(function: &CFunction) -> bool {
    validate_render_observations(function, 0).is_err()
}

/// Whether one expression subtree contains any render observation marker.
pub(crate) fn expr_has_render_observations(expr: &CExpr) -> bool {
    let mut found = false;
    let never = visit_expr_observations(expr, &mut |_| {
        found = true;
        Ok::<_, std::convert::Infallible>(())
    });
    match never {
        Ok(()) => found,
        Err(never) => match never {},
    }
}

/// Whether one statement subtree contains any render observation marker.
#[cfg(test)]
pub(crate) fn stmt_has_render_observations(stmt: &CStmt) -> bool {
    let mut found = false;
    let never = visit_stmt_observations(stmt, &mut |_| {
        found = true;
        Ok::<_, std::convert::Infallible>(())
    });
    match never {
        Ok(()) => found,
        Err(never) => match never {},
    }
}

/// Validate every marker before exposing any final wrapped node to `inspect`.
///
/// Marker-domain errors invoke no callback.  Callers can likewise accumulate
/// observations in temporary storage and commit it only after this function
/// succeeds, making conflict handling transactional as well.
pub(crate) fn inspect_render_observations<E>(
    function: &CFunction,
    expected_count: usize,
    mut inspect: impl FnMut(RenderObservationId, RenderObservationNode<'_>) -> Result<(), E>,
) -> Result<ReachableObservations, RenderObservationInspectError<E>> {
    let observations = validate_render_observations(function, expected_count)
        .map_err(RenderObservationInspectError::Markers)?;
    for stmt in &function.body {
        inspect_stmt_observations(stmt, &mut inspect)
            .map_err(RenderObservationInspectError::Observer)?;
    }
    Ok(observations)
}

/// Transactionally inspect final wrapped nodes and then remove all markers.
///
/// Marker validation and observer callbacks both complete before mutation.
/// On success the already-validated AST is stripped without a redundant
/// validation pass.
#[cfg(test)]
pub(crate) fn inspect_and_strip_render_observations<E>(
    function: &mut CFunction,
    expected_count: usize,
    inspect: impl FnMut(RenderObservationId, RenderObservationNode<'_>) -> Result<(), E>,
) -> Result<ReachableObservations, RenderObservationInspectError<E>> {
    let observations = inspect_render_observations(function, expected_count, inspect)?;
    for stmt in &mut function.body {
        strip_stmt_observations(stmt);
    }
    Ok(observations)
}

/// Validate and remove every internal render observation before a `CFunction`
/// is exposed or serialized.
///
/// Validation is a read-only linear pass over a fixed-size dense bitset. The
/// AST is stripped only after every reachable marker is proven unique and in
/// range, so an error leaves the input unchanged.
#[cfg(test)]
pub(crate) fn strip_render_observations(
    function: &mut CFunction,
    expected_count: usize,
) -> Result<ReachableObservations, RenderObservationStripError> {
    let observations = validate_render_observations(function, expected_count)?;
    for stmt in &mut function.body {
        strip_stmt_observations(stmt);
    }
    Ok(observations)
}

/// Remove every internal observation wrapper after the audit path has failed.
///
/// This deliberately performs no validation: the observation journal owns the
/// authority to report that failure, while native rendering must still emit the
/// same marker-free AST it would have emitted without the shadow audit.
pub(crate) fn discard_render_observations(function: &mut CFunction) {
    for stmt in &mut function.body {
        strip_stmt_observations(stmt);
    }
}

/// Collect the observation identities already carried by one statement tree.
///
/// Composite constructs use this before claiming implicit source effects: a
/// child statement that already owns an effect is the concrete occurrence, so
/// attaching the same cell to the parent would create two accounting markers
/// for one rendering.
pub(crate) fn stmt_render_observation_ids(stmt: &CStmt) -> Vec<RenderObservationId> {
    let mut ids = Vec::new();
    let never = visit_stmt_observations(stmt, &mut |id| {
        ids.push(id);
        Ok::<_, std::convert::Infallible>(())
    });
    match never {
        Ok(()) => ids,
        Err(never) => match never {},
    }
}

/// Give every marker in a cloned statement tree a fresh occurrence identity.
///
/// A semantic block may be emitted in more than one certified region. Its
/// cached AST is the authoritative fold result, but observation IDs belong to
/// concrete AST occurrences and therefore cannot be copied with that cache.
pub(crate) fn remap_render_observation_ids<E>(
    stmts: &mut [CStmt],
    remap: &mut impl FnMut(RenderObservationId) -> Result<RenderObservationId, E>,
) -> Result<(), E> {
    fn remap_expr<E>(
        expr: &mut CExpr,
        remap: &mut impl FnMut(RenderObservationId) -> Result<RenderObservationId, E>,
    ) -> Result<(), E> {
        if let CExpr::Observed { ids, expr } = expr {
            for id in ids.outer_to_inner.iter_mut() {
                *id = remap(*id)?;
            }
            return remap_expr(expr, remap);
        }
        match expr {
            CExpr::Observed { .. } => unreachable!("handled before semantic expression"),
            CExpr::Unary { operand, .. }
            | CExpr::Cast { expr: operand, .. }
            | CExpr::Sizeof(operand)
            | CExpr::AddrOf(operand)
            | CExpr::Deref(operand)
            | CExpr::Paren(operand) => remap_expr(operand, remap)?,
            CExpr::Binary { left, right, .. } => {
                remap_expr(left, remap)?;
                remap_expr(right, remap)?;
            }
            CExpr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                remap_expr(cond, remap)?;
                remap_expr(then_expr, remap)?;
                remap_expr(else_expr, remap)?;
            }
            CExpr::Call { func, args, .. } => {
                remap_expr(func, remap)?;
                for arg in args {
                    remap_expr(arg, remap)?;
                }
            }
            CExpr::Subscript { base, index } => {
                remap_expr(base, remap)?;
                remap_expr(index, remap)?;
            }
            CExpr::Member { base, .. } | CExpr::PtrMember { base, .. } => {
                remap_expr(base, remap)?;
            }
            CExpr::Comma(items) => {
                for item in items {
                    remap_expr(item, remap)?;
                }
            }
            CExpr::IntLit(_)
            | CExpr::UIntLit(_)
            | CExpr::FloatLit(..)
            | CExpr::StringLit(_)
            | CExpr::CharLit(_)
            | CExpr::Var(_)
            | CExpr::External { .. }
            | CExpr::DataObject { .. }
            | CExpr::SizeofType(_) => {}
        }
        Ok(())
    }

    fn remap_stmt<E>(
        stmt: &mut CStmt,
        remap: &mut impl FnMut(RenderObservationId) -> Result<RenderObservationId, E>,
    ) -> Result<(), E> {
        if let CStmt::Observed { ids, stmt } = stmt {
            for id in ids.outer_to_inner.iter_mut() {
                *id = remap(*id)?;
            }
            return remap_stmt(stmt, remap);
        }
        match stmt {
            CStmt::StructuredRegion { stmt, .. } => remap_stmt(stmt, remap)?,
            CStmt::Observed { .. } => unreachable!("handled before semantic statement"),
            CStmt::Expr(expr) => remap_expr(expr, remap)?,
            CStmt::Decl { init, .. } | CStmt::Return(init) => {
                if let Some(expr) = init {
                    remap_expr(expr, remap)?;
                }
            }
            CStmt::Block(stmts) => {
                for stmt in stmts {
                    remap_stmt(stmt, remap)?;
                }
            }
            CStmt::If {
                cond,
                then_body,
                else_body,
            } => {
                remap_expr(cond, remap)?;
                remap_stmt(then_body, remap)?;
                if let Some(else_body) = else_body {
                    remap_stmt(else_body, remap)?;
                }
            }
            CStmt::While { cond, body } => {
                remap_expr(cond, remap)?;
                remap_stmt(body, remap)?;
            }
            CStmt::DoWhile { body, cond } => {
                remap_stmt(body, remap)?;
                remap_expr(cond, remap)?;
            }
            CStmt::For {
                init,
                cond,
                update,
                body,
            } => {
                if let Some(init) = init {
                    remap_stmt(init, remap)?;
                }
                if let Some(cond) = cond {
                    remap_expr(cond, remap)?;
                }
                if let Some(update) = update {
                    remap_expr(update, remap)?;
                }
                remap_stmt(body, remap)?;
            }
            CStmt::Switch {
                expr,
                cases,
                default,
            } => {
                remap_expr(expr, remap)?;
                for case in cases {
                    remap_expr(&mut case.value, remap)?;
                    for stmt in &mut case.body {
                        remap_stmt(stmt, remap)?;
                    }
                }
                if let Some(default) = default {
                    for stmt in default {
                        remap_stmt(stmt, remap)?;
                    }
                }
            }
            CStmt::Empty
            | CStmt::Break
            | CStmt::Continue
            | CStmt::Goto(_)
            | CStmt::Label(_)
            | CStmt::Comment(_)
            | CStmt::Gap(_) => {}
        }
        Ok(())
    }

    for stmt in stmts {
        remap_stmt(stmt, remap)?;
    }
    Ok(())
}

fn inspect_expr_observations<E>(
    expr: &CExpr,
    inspect: &mut impl FnMut(RenderObservationId, RenderObservationNode<'_>) -> Result<(), E>,
) -> Result<(), E> {
    if let CExpr::Observed { ids, expr } = expr {
        for id in ids.iter() {
            inspect(id, RenderObservationNode::Expr(expr))?;
        }
        return inspect_expr_observations(expr, inspect);
    }
    match expr {
        CExpr::Observed { .. } => unreachable!("handled before semantic expression"),
        CExpr::Unary { operand, .. }
        | CExpr::Cast { expr: operand, .. }
        | CExpr::Sizeof(operand)
        | CExpr::AddrOf(operand)
        | CExpr::Deref(operand)
        | CExpr::Paren(operand) => inspect_expr_observations(operand, inspect)?,
        CExpr::Binary { left, right, .. } => {
            inspect_expr_observations(left, inspect)?;
            inspect_expr_observations(right, inspect)?;
        }
        CExpr::Ternary {
            cond,
            then_expr,
            else_expr,
        } => {
            inspect_expr_observations(cond, inspect)?;
            inspect_expr_observations(then_expr, inspect)?;
            inspect_expr_observations(else_expr, inspect)?;
        }
        CExpr::Call { func, args, .. } => {
            inspect_expr_observations(func, inspect)?;
            for arg in args {
                inspect_expr_observations(arg, inspect)?;
            }
        }
        CExpr::Subscript { base, index } => {
            inspect_expr_observations(base, inspect)?;
            inspect_expr_observations(index, inspect)?;
        }
        CExpr::Member { base, .. } | CExpr::PtrMember { base, .. } => {
            inspect_expr_observations(base, inspect)?;
        }
        CExpr::Comma(items) => {
            for item in items {
                inspect_expr_observations(item, inspect)?;
            }
        }
        CExpr::IntLit(_)
        | CExpr::UIntLit(_)
        | CExpr::FloatLit(..)
        | CExpr::StringLit(_)
        | CExpr::CharLit(_)
        | CExpr::Var(_)
        | CExpr::External { .. }
        | CExpr::DataObject { .. }
        | CExpr::SizeofType(_) => {}
    }
    Ok(())
}

impl ReachableObservations {
    fn record(&mut self, id: RenderObservationId) -> Result<(), RenderObservationStripError> {
        let Ok(index) = usize::try_from(id.index()) else {
            return Err(RenderObservationStripError::OutOfRange {
                id,
                expected_count: self.reachable.len(),
            });
        };
        let Some(reachable) = self.reachable.get_mut(index) else {
            return Err(RenderObservationStripError::OutOfRange {
                id,
                expected_count: self.reachable.len(),
            });
        };
        // A marker met twice is not refused here. Two occurrences of one cell
        // are a duplicate only if both can happen, and that is a question about
        // the structure this walk cannot see: a return specialised into the
        // arms of a conditional is written twice and performed once. The seal
        // asks it, over the same tree, where the region tree is in hand.
        if *reachable {
            return Ok(());
        }
        *reachable = true;
        Ok(())
    }
}

fn visit_expr_observations<E>(
    expr: &CExpr,
    visit: &mut impl FnMut(RenderObservationId) -> Result<(), E>,
) -> Result<(), E> {
    if let CExpr::Observed { ids, expr } = expr {
        for id in ids.iter() {
            visit(id)?;
        }
        return visit_expr_observations(expr, visit);
    }
    match expr {
        CExpr::Observed { .. } => unreachable!("handled before semantic expression"),
        CExpr::Unary { operand, .. }
        | CExpr::Cast { expr: operand, .. }
        | CExpr::Sizeof(operand)
        | CExpr::AddrOf(operand)
        | CExpr::Deref(operand)
        | CExpr::Paren(operand) => visit_expr_observations(operand, visit)?,
        CExpr::Binary { left, right, .. } => {
            visit_expr_observations(left, visit)?;
            visit_expr_observations(right, visit)?;
        }
        CExpr::Ternary {
            cond,
            then_expr,
            else_expr,
        } => {
            visit_expr_observations(cond, visit)?;
            visit_expr_observations(then_expr, visit)?;
            visit_expr_observations(else_expr, visit)?;
        }
        CExpr::Call { func, args, .. } => {
            visit_expr_observations(func, visit)?;
            for arg in args {
                visit_expr_observations(arg, visit)?;
            }
        }
        CExpr::Subscript { base, index } => {
            visit_expr_observations(base, visit)?;
            visit_expr_observations(index, visit)?;
        }
        CExpr::Member { base, .. } | CExpr::PtrMember { base, .. } => {
            visit_expr_observations(base, visit)?;
        }
        CExpr::Comma(items) => {
            for item in items {
                visit_expr_observations(item, visit)?;
            }
        }
        CExpr::IntLit(_)
        | CExpr::UIntLit(_)
        | CExpr::FloatLit(..)
        | CExpr::StringLit(_)
        | CExpr::CharLit(_)
        | CExpr::Var(_)
        | CExpr::External { .. }
        | CExpr::DataObject { .. }
        | CExpr::SizeofType(_) => {}
    }
    Ok(())
}

fn strip_expr_observations(expr: &mut CExpr) {
    // A loop rather than one step: this also strips an audit that failed,
    // whose tree is not known to be canonical.
    while let CExpr::Observed { expr: inner, .. } = expr {
        *expr = std::mem::replace(inner.as_mut(), CExpr::IntLit(0));
    }
    match expr {
        CExpr::Observed { .. } => unreachable!("all leading observations were stripped"),
        CExpr::Unary { operand, .. }
        | CExpr::Cast { expr: operand, .. }
        | CExpr::Sizeof(operand)
        | CExpr::AddrOf(operand)
        | CExpr::Deref(operand)
        | CExpr::Paren(operand) => strip_expr_observations(operand),
        CExpr::Binary { left, right, .. } => {
            strip_expr_observations(left);
            strip_expr_observations(right);
        }
        CExpr::Ternary {
            cond,
            then_expr,
            else_expr,
        } => {
            strip_expr_observations(cond);
            strip_expr_observations(then_expr);
            strip_expr_observations(else_expr);
        }
        CExpr::Call { func, args, .. } => {
            strip_expr_observations(func);
            for arg in args {
                strip_expr_observations(arg);
            }
        }
        CExpr::Subscript { base, index } => {
            strip_expr_observations(base);
            strip_expr_observations(index);
        }
        CExpr::Member { base, .. } | CExpr::PtrMember { base, .. } => {
            strip_expr_observations(base);
        }
        CExpr::Comma(items) => {
            for item in items {
                strip_expr_observations(item);
            }
        }
        CExpr::IntLit(_)
        | CExpr::UIntLit(_)
        | CExpr::FloatLit(..)
        | CExpr::StringLit(_)
        | CExpr::CharLit(_)
        | CExpr::Var(_)
        | CExpr::External { .. }
        | CExpr::DataObject { .. }
        | CExpr::SizeofType(_) => {}
    }
}

fn visit_stmt_observations<E>(
    stmt: &CStmt,
    visit: &mut impl FnMut(RenderObservationId) -> Result<(), E>,
) -> Result<(), E> {
    if let CStmt::Observed { ids, stmt } = stmt {
        for id in ids.iter() {
            visit(id)?;
        }
        return visit_stmt_observations(stmt, visit);
    }
    match stmt {
        CStmt::StructuredRegion { stmt, .. } => visit_stmt_observations(stmt, visit)?,
        CStmt::Observed { .. } => unreachable!("handled before semantic statement"),
        CStmt::Expr(expr) => visit_expr_observations(expr, visit)?,
        CStmt::Decl { init, .. } | CStmt::Return(init) => {
            if let Some(expr) = init {
                visit_expr_observations(expr, visit)?;
            }
        }
        CStmt::Block(stmts) => {
            for stmt in stmts {
                visit_stmt_observations(stmt, visit)?;
            }
        }
        CStmt::If {
            cond,
            then_body,
            else_body,
        } => {
            visit_expr_observations(cond, visit)?;
            visit_stmt_observations(then_body, visit)?;
            if let Some(else_body) = else_body {
                visit_stmt_observations(else_body, visit)?;
            }
        }
        CStmt::While { cond, body } => {
            visit_expr_observations(cond, visit)?;
            visit_stmt_observations(body, visit)?;
        }
        CStmt::DoWhile { body, cond } => {
            visit_stmt_observations(body, visit)?;
            visit_expr_observations(cond, visit)?;
        }
        CStmt::For {
            init,
            cond,
            update,
            body,
        } => {
            if let Some(init) = init {
                visit_stmt_observations(init, visit)?;
            }
            if let Some(cond) = cond {
                visit_expr_observations(cond, visit)?;
            }
            if let Some(update) = update {
                visit_expr_observations(update, visit)?;
            }
            visit_stmt_observations(body, visit)?;
        }
        CStmt::Switch {
            expr,
            cases,
            default,
        } => {
            visit_expr_observations(expr, visit)?;
            for case in cases {
                visit_expr_observations(&case.value, visit)?;
                for stmt in &case.body {
                    visit_stmt_observations(stmt, visit)?;
                }
            }
            if let Some(default) = default {
                for stmt in default {
                    visit_stmt_observations(stmt, visit)?;
                }
            }
        }
        CStmt::Empty
        | CStmt::Break
        | CStmt::Continue
        | CStmt::Goto(_)
        | CStmt::Label(_)
        | CStmt::Comment(_)
        | CStmt::Gap(_) => {}
    }
    Ok(())
}

fn inspect_stmt_observations<E>(
    stmt: &CStmt,
    inspect: &mut impl FnMut(RenderObservationId, RenderObservationNode<'_>) -> Result<(), E>,
) -> Result<(), E> {
    if let CStmt::Observed { ids, stmt } = stmt {
        for id in ids.iter() {
            inspect(id, RenderObservationNode::Stmt(stmt))?;
        }
        return inspect_stmt_observations(stmt, inspect);
    }
    match stmt {
        CStmt::StructuredRegion { stmt, .. } => inspect_stmt_observations(stmt, inspect)?,
        CStmt::Observed { .. } => unreachable!("handled before semantic statement"),
        CStmt::Expr(expr) => inspect_expr_observations(expr, inspect)?,
        CStmt::Decl { init, .. } | CStmt::Return(init) => {
            if let Some(expr) = init {
                inspect_expr_observations(expr, inspect)?;
            }
        }
        CStmt::Block(stmts) => {
            for stmt in stmts {
                inspect_stmt_observations(stmt, inspect)?;
            }
        }
        CStmt::If {
            cond,
            then_body,
            else_body,
        } => {
            inspect_expr_observations(cond, inspect)?;
            inspect_stmt_observations(then_body, inspect)?;
            if let Some(else_body) = else_body {
                inspect_stmt_observations(else_body, inspect)?;
            }
        }
        CStmt::While { cond, body } => {
            inspect_expr_observations(cond, inspect)?;
            inspect_stmt_observations(body, inspect)?;
        }
        CStmt::DoWhile { body, cond } => {
            inspect_stmt_observations(body, inspect)?;
            inspect_expr_observations(cond, inspect)?;
        }
        CStmt::For {
            init,
            cond,
            update,
            body,
        } => {
            if let Some(init) = init {
                inspect_stmt_observations(init, inspect)?;
            }
            if let Some(cond) = cond {
                inspect_expr_observations(cond, inspect)?;
            }
            if let Some(update) = update {
                inspect_expr_observations(update, inspect)?;
            }
            inspect_stmt_observations(body, inspect)?;
        }
        CStmt::Switch {
            expr,
            cases,
            default,
        } => {
            inspect_expr_observations(expr, inspect)?;
            for case in cases {
                inspect_expr_observations(&case.value, inspect)?;
                for stmt in &case.body {
                    inspect_stmt_observations(stmt, inspect)?;
                }
            }
            if let Some(default) = default {
                for stmt in default {
                    inspect_stmt_observations(stmt, inspect)?;
                }
            }
        }
        CStmt::Empty
        | CStmt::Break
        | CStmt::Continue
        | CStmt::Goto(_)
        | CStmt::Label(_)
        | CStmt::Comment(_)
        | CStmt::Gap(_) => {}
    }
    Ok(())
}

/// Move only a source expression's leading observations onto a replacement
/// for that same occurrence.
pub(crate) fn carry_outer_expr_observations(source: &CExpr, replacement: CExpr) -> CExpr {
    CExpr::observe_all(source.observation_ids().iter().copied(), replacement)
}

/// Every observation in an expression, in pre-order and each occurrence's
/// ids outermost first: the order a walk of the old one-wrapper-per-id chains
/// met them.
///
/// An explicit stack over borrowed nodes. The walk this replaces cloned the
/// subtree at every level to reach its children, which is quadratic in the
/// height of the expression. Each node takes the ids of every set stacked on
/// it before the walk descends from beneath them all.
fn expr_observation_ids_in_preorder(expr: &CExpr) -> Vec<RenderObservationId> {
    let mut ids = Vec::new();
    let mut pending = vec![expr];
    while let Some(expr) = pending.pop() {
        ids.extend_from_slice(&expr.observation_ids());
        pending.extend(expr.unobserved().children().into_iter().rev());
    }
    ids
}

/// Move every observation in a source expression onto a replacement that
/// stands for the whole of it.
///
/// `carry_outer_expr_observations` is right when the replacement keeps the
/// source's subtrees, since the markers inside them travel with those
/// subtrees. It is wrong when the replacement discards them: folding
/// `(uint64_t)(int32_t)0xcc9e2d51` down to one literal, or turning an address
/// into `&name`, throws away whatever the collapsed nodes were marked with,
/// and the accounting then reports an effect that was rendered as refused.
///
/// The replacement renders everything the source rendered, so it owns every
/// occurrence the source owned. Order is preserved outermost-first so the
/// rebuilt set reads the same way round as the ones it replaces.
pub(crate) fn carry_all_expr_observations(source: &CExpr, replacement: CExpr) -> CExpr {
    CExpr::observe_all(expr_observation_ids_in_preorder(source), replacement)
}

/// Move every marker in `source` onto its replacement, each at its own kind of position.
pub(crate) fn carry_all_stmt_observations(source: &[CStmt], replacement: CStmt) -> CStmt {
    let mut statement_ids = Vec::new();
    let mut expression_ids = Vec::new();
    for stmt in source {
        statement_ids.extend_from_slice(&stmt.observation_ids());
        let _ = visit_stmt_observations::<std::convert::Infallible>(stmt.unobserved(), &mut |id| {
            expression_ids.push(id);
            Ok(())
        });
    }
    let replacement = match (replacement, expression_ids.is_empty()) {
        (CStmt::Expr(expr), false) => CStmt::Expr(CExpr::observe_all(expression_ids, expr)),
        (replacement, _) => {
            statement_ids.extend(expression_ids);
            replacement
        }
    };
    CStmt::observe_all(statement_ids, replacement)
}

fn strip_stmt_observations(stmt: &mut CStmt) {
    // A loop rather than one step: this also strips an audit that failed,
    // whose tree is not known to be canonical.
    while let CStmt::Observed { stmt: inner, .. } = stmt {
        *stmt = std::mem::replace(inner.as_mut(), CStmt::Empty);
    }
    match stmt {
        CStmt::StructuredRegion { stmt, .. } => strip_stmt_observations(stmt),
        CStmt::Observed { .. } => unreachable!("all leading observations were stripped"),
        CStmt::Expr(expr) => strip_expr_observations(expr),
        CStmt::Decl { init, .. } | CStmt::Return(init) => {
            if let Some(expr) = init {
                strip_expr_observations(expr);
            }
        }
        CStmt::Block(stmts) => {
            for stmt in stmts {
                strip_stmt_observations(stmt);
            }
        }
        CStmt::If {
            cond,
            then_body,
            else_body,
        } => {
            strip_expr_observations(cond);
            strip_stmt_observations(then_body);
            if let Some(else_body) = else_body {
                strip_stmt_observations(else_body);
            }
        }
        CStmt::While { cond, body } => {
            strip_expr_observations(cond);
            strip_stmt_observations(body);
        }
        CStmt::DoWhile { body, cond } => {
            strip_stmt_observations(body);
            strip_expr_observations(cond);
        }
        CStmt::For {
            init,
            cond,
            update,
            body,
        } => {
            if let Some(init) = init {
                strip_stmt_observations(init);
            }
            if let Some(cond) = cond {
                strip_expr_observations(cond);
            }
            if let Some(update) = update {
                strip_expr_observations(update);
            }
            strip_stmt_observations(body);
        }
        CStmt::Switch {
            expr,
            cases,
            default,
        } => {
            strip_expr_observations(expr);
            for case in cases {
                strip_expr_observations(&mut case.value);
                for stmt in &mut case.body {
                    strip_stmt_observations(stmt);
                }
            }
            if let Some(default) = default {
                for stmt in default {
                    strip_stmt_observations(stmt);
                }
            }
        }
        CStmt::Empty
        | CStmt::Break
        | CStmt::Continue
        | CStmt::Goto(_)
        | CStmt::Label(_)
        | CStmt::Comment(_)
        | CStmt::Gap(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The names a fixture in this module declares.
    fn test_table() -> std::cell::RefCell<crate::symbol::SymbolTable> {
        std::cell::RefCell::new(crate::symbol::SymbolTable::new())
    }

    /// An import is spelled the way the linker knows it; a defined symbol is
    /// not, because its definition is rendered here under the same spelling.
    #[test]
    fn an_import_loses_the_flag_namespace_and_a_defined_symbol_keeps_it() {
        assert_eq!(c_identifier("sym.imp.__stack_chk_fail"), "__stack_chk_fail");
        assert_eq!(c_identifier("imp.__memcpy_chk"), "__memcpy_chk");
        assert_eq!(c_identifier("sym._rotl32"), "sym__rotl32");
        assert_eq!(c_identifier("sym.imp."), "_");
        assert_eq!(c_identifier("7up"), "_7up");
    }

    #[test]
    fn test_type_display() {
        assert_eq!(CType::Void.to_string(), "void");
        assert_eq!(CType::i32().to_string(), "int32_t");
        assert_eq!(CType::u64().to_string(), "uint64_t");
        assert_eq!(CType::ptr(CType::i32()).to_string(), "int32_t*");
    }

    #[test]
    fn test_expr_creation() {
        let symbols = test_table();
        let a = CExpr::var(crate::symbol::declare(&symbols, "a"));
        let b = CExpr::var(crate::symbol::declare(&symbols, "b"));
        let sum = CExpr::binary(BinaryOp::Add, a, b);

        if let CExpr::Binary { op, left, right } = sum {
            assert_eq!(op, BinaryOp::Add);
            assert_eq!(*left, CExpr::var(crate::symbol::declare(&symbols, "a")));
            assert_eq!(*right, CExpr::var(crate::symbol::declare(&symbols, "b")));
        } else {
            panic!("Expected Binary expression");
        }
    }

    #[test]
    fn test_stmt_creation() {
        let symbols = test_table();
        let stmt = CStmt::if_stmt(
            CExpr::var(crate::symbol::declare(&symbols, "x")),
            CStmt::ret(Some(CExpr::int(1))),
            Some(CStmt::ret(Some(CExpr::int(0)))),
        );

        if let CStmt::If {
            cond,
            then_body: _,
            else_body,
        } = stmt
        {
            assert_eq!(cond, CExpr::var(crate::symbol::declare(&symbols, "x")));
            assert!(else_body.is_some());
        } else {
            panic!("Expected If statement");
        }
    }

    #[test]
    fn test_expr_visit_traverses_all_nodes() {
        let symbols = test_table();
        let expr = CExpr::binary(
            BinaryOp::Add,
            CExpr::var(crate::symbol::declare(&symbols, "a")),
            CExpr::call(
                CExpr::var(crate::symbol::declare(&symbols, "f")),
                vec![
                    CExpr::int(1),
                    CExpr::var(crate::symbol::declare(&symbols, "b")),
                ],
            ),
        );
        let mut vars = Vec::new();
        expr.visit(&mut |node| {
            if let CExpr::Var(name) = node {
                vars.push(*name);
            }
        });
        assert!(vars.iter().any(|v| symbols.borrow().name(*v) == "a"));
        assert!(vars.iter().any(|v| symbols.borrow().name(*v) == "f"));
        assert!(vars.iter().any(|v| symbols.borrow().name(*v) == "b"));
    }

    #[test]
    fn test_expr_map_children_updates_direct_children() {
        let symbols = test_table();
        let expr = CExpr::binary(
            BinaryOp::Add,
            CExpr::var(crate::symbol::declare(&symbols, "a")),
            CExpr::int(1),
        );
        let mut mapper = |child: CExpr| match child {
            CExpr::Var(name) if name == crate::symbol::declare(&symbols, "a") => {
                CExpr::var(crate::symbol::declare(&symbols, "x"))
            }
            other => other,
        };
        let rewritten = expr.map_children(&mut mapper);
        let CExpr::Binary { left, .. } = rewritten else {
            panic!("expected binary expression");
        };
        assert_eq!(*left, CExpr::var(crate::symbol::declare(&symbols, "x")));
    }

    #[test]
    fn observations_survive_recursive_expression_rewrites() {
        fn rewrite(expr: CExpr) -> CExpr {
            let expr = expr.map_children(&mut rewrite);
            match expr {
                CExpr::IntLit(1) => CExpr::IntLit(2),
                other => other,
            }
        }

        let mut owner = RenderObservationOwner::new();
        let (id, observed_one) = owner
            .observe_expr(CExpr::IntLit(1))
            .expect("allocate observation");
        let rewritten = rewrite(CExpr::binary(BinaryOp::Add, observed_one, CExpr::IntLit(1)));
        assert_eq!(
            rewritten,
            CExpr::binary(
                BinaryOp::Add,
                CExpr::observe_one(id, CExpr::IntLit(2)),
                CExpr::IntLit(2),
            )
        );
    }

    #[test]
    fn statement_observation_chain_round_trips_in_nesting_order_once() {
        let semantic = CStmt::Expr(CExpr::IntLit(7));
        let mut owner = RenderObservationOwner::new();
        let (inner_id, inner) = owner
            .observe_stmt(semantic.clone())
            .expect("inner statement observation");
        let (outer_id, wrapped) = owner
            .observe_stmt(inner)
            .expect("outer statement observation");

        let (peeled, observations) = wrapped.clone().into_semantic_with_observations();
        assert_eq!(peeled, semantic);
        let rebuilt = observations.reapply(peeled);
        assert_eq!(rebuilt, wrapped, "outer and inner IDs must not reorder");

        let mut function = CFunction::new("stmt_chain", CType::Void).with_body(vec![rebuilt]);
        let reachable = strip_render_observations(&mut function, owner.expected_count())
            .expect("recomposition must retain every ID exactly once");
        assert!(reachable.contains(inner_id));
        assert!(reachable.contains(outer_id));
        assert_eq!(function.body, vec![semantic]);
    }

    #[test]
    fn final_node_inspection_visits_subscript_markers_once() {
        let mut owner = RenderObservationOwner::new();
        let (base_id, base) = owner
            .observe_expr(CExpr::IntLit(1))
            .expect("base observation");
        let (index_id, index) = owner
            .observe_expr(CExpr::IntLit(2))
            .expect("index observation");
        let function =
            CFunction::new("inspect", CType::Void).with_body(vec![CStmt::Expr(CExpr::Subscript {
                base: Box::new(base),
                index: Box::new(index),
            })]);
        let mut visited = Vec::new();
        inspect_render_observations(
            &function,
            owner.expected_count(),
            |id, node| -> Result<(), std::convert::Infallible> {
                assert!(matches!(
                    node,
                    RenderObservationNode::Expr(CExpr::IntLit(_))
                ));
                visited.push(id);
                Ok(())
            },
        )
        .expect("valid marker inspection");
        assert_eq!(visited, vec![base_id, index_id]);
    }

    #[test]
    fn semantic_clones_drop_occurrence_owned_observations() {
        let mut owner = RenderObservationOwner::new();
        let (_, left) = owner
            .observe_expr(CExpr::IntLit(1))
            .expect("left observation");
        let (_, right) = owner
            .observe_expr(CExpr::IntLit(2))
            .expect("right observation");
        let source = CExpr::binary(BinaryOp::Add, left, right);
        assert_eq!(
            source.clone_without_render_observations(),
            CExpr::binary(BinaryOp::Add, CExpr::IntLit(1), CExpr::IntLit(2))
        );
        let mut function =
            CFunction::new("fold", CType::Void).with_body(vec![CStmt::Expr(CExpr::IntLit(3))]);
        let reachable = strip_render_observations(&mut function, owner.expected_count())
            .expect("eliminated observations remain unaccounted");
        assert_eq!(reachable.ids().count(), 0);
        assert_eq!(function.body, vec![CStmt::Expr(CExpr::IntLit(3))]);
    }

    #[test]
    fn stripping_reports_only_reachable_observations_and_restores_the_ast() {
        let mut plain = CFunction::new(
            "observed",
            CType::Int {
                bits: 32,
                signedness: r2types::Signedness::Signed,
            },
        )
        .with_body(vec![CStmt::Block(vec![CStmt::Expr(CExpr::binary(
            BinaryOp::Add,
            CExpr::IntLit(1),
            CExpr::IntLit(2),
        ))])]);
        let expected = plain.clone();
        let mut owner = RenderObservationOwner::new();
        let (nested_expr_id, nested_expr) = owner
            .observe_expr(CExpr::IntLit(1))
            .expect("allocate nested expression observation");
        let (expr_id, expr) = owner
            .observe_expr(CExpr::binary(BinaryOp::Add, nested_expr, CExpr::IntLit(2)))
            .expect("allocate expression observation");
        let (stmt_id, stmt) = owner
            .observe_stmt(CStmt::Block(vec![CStmt::Expr(expr)]))
            .expect("allocate statement observation");
        let (dropped_id, dropped_stmt) = owner
            .observe_stmt(CStmt::Expr(CExpr::IntLit(99)))
            .expect("allocate dropped observation");
        plain.body = vec![stmt, dropped_stmt];

        plain.body.pop();
        let reachable = strip_render_observations(&mut plain, owner.expected_count())
            .expect("valid observation domain");

        assert_eq!(
            reachable.ids().collect::<Vec<_>>(),
            vec![nested_expr_id, expr_id, stmt_id],
            "dense-ID order is independent of AST traversal order"
        );
        assert!(!reachable.contains(dropped_id));
        assert_eq!(plain, expected);
        assert_eq!(expr_id.index(), 1);
    }

    #[test]
    fn observations_are_rejected_by_serde_until_the_boundary_strips_them() {
        let mut owner = RenderObservationOwner::new();
        let (id, stmt) = owner
            .observe_stmt(CStmt::Expr(CExpr::IntLit(1)))
            .expect("allocate observation");
        let mut function = CFunction::new("observed", CType::Void).with_body(vec![stmt]);

        assert!(serde_json::to_string(&function).is_err());
        assert!(
            serde_json::from_str::<CStmt>(
                r#"{"Observed":{"ids":[0],"stmt":{"Expr":{"IntLit":1}}}}"#,
            )
            .is_err()
        );

        let reachable = strip_render_observations(&mut function, owner.expected_count())
            .expect("valid observation domain");
        assert_eq!(reachable.ids().collect::<Vec<_>>(), vec![id]);
        let stripped = serde_json::to_string(&function).expect("serialize stripped AST");
        assert!(!stripped.contains("Observed"));
    }

    /// A marker written twice is not refused here.
    ///
    /// Two occurrences of one cell are a duplicate only when both can happen,
    /// and that is a question about the structure the walk cannot see. The
    /// seal asks it, where the region tree is in hand.
    #[test]
    fn stripping_admits_a_repeated_observation_for_the_seal_to_judge() {
        let duplicate = RenderObservationId::from_index(0);
        let mut duplicate_function =
            CFunction::new("duplicate", CType::Void).with_body(vec![CStmt::observe_one(
                duplicate,
                CStmt::Expr(CExpr::observe_one(duplicate, CExpr::IntLit(1))),
            )]);
        let reachable = strip_render_observations(&mut duplicate_function, 1)
            .expect("a repeat is not a strip failure");
        assert_eq!(reachable.ids().collect::<Vec<_>>(), vec![duplicate]);
    }

    #[test]
    fn stripping_rejects_out_of_range_observations_without_mutation() {
        let out_of_range = RenderObservationId::from_index(1);
        let mut out_of_range_function = CFunction::new("range", CType::Void)
            .with_body(vec![CStmt::observe_one(out_of_range, CStmt::Empty)]);
        let out_of_range_before = out_of_range_function.clone();
        assert_eq!(
            strip_render_observations(&mut out_of_range_function, 1),
            Err(RenderObservationStripError::OutOfRange {
                id: out_of_range,
                expected_count: 1,
            })
        );
        assert_eq!(out_of_range_function, out_of_range_before);

        #[cfg(target_pointer_width = "64")]
        {
            let mut empty = CFunction::new("large", CType::Void);
            let expected_count = usize::try_from(u64::from(u32::MAX) + 1).unwrap();
            assert_eq!(
                strip_render_observations(&mut empty, expected_count),
                Err(RenderObservationStripError::DomainTooLarge { expected_count })
            );
        }
    }

    /// An observed node directly inside another splits one occurrence's set.
    ///
    /// The constructors fuse, and a node built by hand around another -- the
    /// only way to get one -- is refused by the seal with its own error and
    /// the tree left as it was, found at the first layer rather than by
    /// following the chain. A pass that rewrote a child in place puts the two
    /// back together as one set, outer ids first.
    #[test]
    fn a_nested_observation_is_refused_and_rejoins_as_one_set() {
        let outer = RenderObservationId::from_index(0);
        let inner = RenderObservationId::from_index(1);
        let nested = CStmt::Observed {
            ids: ObservationSet::new(vec![outer]).expect("one id"),
            stmt: Box::new(CStmt::observe_one(inner, CStmt::Empty)),
        };
        let mut function = CFunction::new("nested", CType::Void).with_body(vec![nested.clone()]);
        assert_eq!(
            strip_render_observations(&mut function, 2),
            Err(RenderObservationStripError::NestedObservation { id: outer })
        );
        assert_eq!(function.body, vec![nested.clone()]);

        let mut rejoined = nested;
        rejoined.rejoin_observations();
        assert!(matches!(
            rejoined.observation_ids(),
            std::borrow::Cow::Borrowed(ids) if ids == [outer, inner]
        ));
        assert_eq!(rejoined.unobserved(), &CStmt::Empty);
        assert_eq!(
            rejoined,
            CStmt::observe_all([outer], CStmt::observe_one(inner, CStmt::Empty))
        );
        let mut function = CFunction::new("rejoined", CType::Void).with_body(vec![rejoined]);
        let reachable = strip_render_observations(&mut function, 2).expect("one set");
        assert_eq!(reachable.ids().collect::<Vec<_>>(), vec![outer, inner]);
    }

    /// A rebuild from a nested occurrence carries every set it stands in.
    ///
    /// The rebuilders take the semantic node from beneath every stacked set,
    /// so they have to take the ids of every one of those sets too: an id
    /// left behind with a discarded layer is a cell nothing answers, and the
    /// seal would report it as unaccounted instead of naming the nesting.
    /// Each rebuild comes out canonical, the sets joined outer first.
    #[test]
    fn a_rebuild_from_a_nested_occurrence_carries_every_set() {
        let [outer, inner, child] = [0, 1, 2].map(RenderObservationId::from_index);
        let nested_expr = |semantic: CExpr| CExpr::Observed {
            ids: ObservationSet::new(vec![outer]).expect("one id"),
            expr: Box::new(CExpr::observe_one(inner, semantic)),
        };
        let one_set = |semantic: CExpr| CExpr::observe_all([outer, inner], semantic);

        assert_eq!(
            *nested_expr(CExpr::IntLit(1)).observation_ids(),
            [outer, inner]
        );
        assert_eq!(
            carry_all_expr_observations(&nested_expr(CExpr::IntLit(1)), CExpr::IntLit(2)),
            one_set(CExpr::IntLit(2))
        );
        assert_eq!(
            carry_outer_expr_observations(&nested_expr(CExpr::IntLit(1)), CExpr::IntLit(2)),
            one_set(CExpr::IntLit(2))
        );
        assert_eq!(
            nested_expr(CExpr::IntLit(1)).into_semantic_with_observations(),
            (CExpr::IntLit(1), vec![outer, inner])
        );

        // `(uint8_t)(uint32_t)7` narrows once; the markers on the dropped
        // conversion land on what it converted.
        let int = |bits| CType::Int {
            bits,
            signedness: r2types::Signedness::Unsigned,
        };
        let x = CExpr::UIntLit(7);
        let widened = CExpr::Cast {
            ty: int(32),
            expr: Box::new(x.clone()),
            role: CastRole::Conversion,
        };
        assert_eq!(
            CExpr::cast_with_role(int(8), nested_expr(widened), CastRole::Conversion),
            CExpr::Cast {
                ty: int(8),
                expr: Box::new(one_set(x)),
                role: CastRole::Conversion,
            }
        );

        let nested_stmt = CStmt::Observed {
            ids: ObservationSet::new(vec![outer]).expect("one id"),
            stmt: Box::new(CStmt::observe_one(
                inner,
                CStmt::Expr(CExpr::observe_one(child, CExpr::IntLit(1))),
            )),
        };
        assert_eq!(*nested_stmt.observation_ids(), [outer, inner]);
        let (semantic, chain) = nested_stmt.clone().into_semantic_with_observations();
        assert_eq!(
            semantic,
            CStmt::Expr(CExpr::observe_one(child, CExpr::IntLit(1)))
        );
        assert_eq!(
            chain.reapply(CStmt::Empty),
            CStmt::observe_all([outer, inner], CStmt::Empty)
        );
        assert_eq!(
            carry_all_stmt_observations(&[nested_stmt], CStmt::Expr(CExpr::IntLit(2))),
            CStmt::observe_all(
                [outer, inner],
                CStmt::Expr(CExpr::observe_one(child, CExpr::IntLit(2)))
            )
        );
    }

    #[test]
    fn transparent_equality_ignores_nested_observations() {
        let mut owner = RenderObservationOwner::new();
        let (_, nested) = owner
            .observe_expr(CExpr::IntLit(1))
            .expect("allocate nested observation");
        let plain = CExpr::binary(BinaryOp::Add, CExpr::IntLit(1), CExpr::IntLit(2));
        let wrapped = CExpr::binary(BinaryOp::Add, nested, CExpr::IntLit(2));
        assert!(plain.transparently_eq(&wrapped));
        assert!(wrapped.transparently_eq(&plain));
    }
}

#[cfg(test)]
mod cast_collapse {
    use super::*;

    fn u(bits: u32) -> CType {
        CType::Int {
            bits,
            signedness: r2types::Signedness::Unsigned,
        }
    }

    fn i(bits: u32) -> CType {
        CType::Int {
            bits,
            signedness: r2types::Signedness::Signed,
        }
    }

    fn ptr() -> CType {
        CType::Pointer(Box::new(u(8)))
    }

    fn leaf() -> CExpr {
        CExpr::UIntLit(0)
    }

    /// Build a chain without any collapsing, outermost type first.
    fn raw(types: &[(CType, CastRole)]) -> CExpr {
        types
            .iter()
            .rev()
            .fold(leaf(), |acc, (ty, role)| CExpr::Cast {
                ty: ty.clone(),
                expr: Box::new(acc),
                role: *role,
            })
    }

    /// Build a chain through the constructor, outermost type last applied.
    fn built(types: &[(CType, CastRole)]) -> CExpr {
        types.iter().rev().fold(leaf(), |acc, (ty, role)| {
            CExpr::cast_with_role(ty.clone(), acc, *role)
        })
    }

    /// The cast types of a chain, outermost first.
    fn spine(expr: &CExpr) -> Vec<CType> {
        let mut out = Vec::new();
        let mut cursor = expr;
        while let CExpr::Cast {
            ty, expr: inner, ..
        } = cursor.unobserved()
        {
            out.push(ty.clone());
            cursor = inner;
        }
        out
    }

    fn conv(types: &[CType]) -> Vec<(CType, CastRole)> {
        types
            .iter()
            .cloned()
            .map(|t| (t, CastRole::Conversion))
            .collect()
    }

    /// Apply one C conversion to a value held at `width` bits with `signed`
    /// interpretation, returning the new bits and type.
    fn convert(bits: u128, width: u32, signed: bool, to: &CType) -> (u128, u32, bool) {
        let (to_bits, to_signed) = match to {
            CType::Int { bits, signedness } => (*bits, *signedness == r2types::Signedness::Signed),
            _ => unreachable!("only integer conversions are evaluated"),
        };
        let mask = |w: u32| {
            if w >= 128 {
                u128::MAX
            } else {
                (1u128 << w) - 1
            }
        };
        let value = if to_bits <= width {
            bits & mask(to_bits)
        } else if signed && (bits >> (width - 1)) & 1 == 1 {
            (bits | !mask(width)) & mask(to_bits)
        } else {
            bits & mask(width)
        };
        (value, to_bits, to_signed)
    }

    /// Evaluate a chain over one input, innermost cast first.
    fn eval(chain: &[CType], input: u128, source: &CType) -> u128 {
        let (mut bits, mut width, mut signed) = match source {
            CType::Int {
                bits: w,
                signedness,
            } => (input, *w, *signedness == r2types::Signedness::Signed),
            _ => unreachable!(),
        };
        for ty in chain.iter().rev() {
            let (b, w, s) = convert(bits, width, signed, ty);
            bits = b;
            width = w;
            signed = s;
        }
        bits
    }

    /// Every input of the source width agrees between the two chains.
    fn agrees(before: &[CType], after: &[CType], source: &CType) {
        let width = match source {
            CType::Int { bits, .. } => *bits,
            _ => unreachable!(),
        };
        for input in 0..(1u128 << width) {
            let a = eval(before, input, source);
            let b = eval(after, input, source);
            assert_eq!(
                a, b,
                "chains disagree on input {input:#x} of {source:?}: {before:?} gave {a:#x}, {after:?} gave {b:#x}"
            );
        }
    }

    #[test]
    fn same_type_says_it_once() {
        let collapsed = built(&conv(&[u(32), u(32)]));
        assert_eq!(spine(&collapsed), vec![u(32)]);
    }

    #[test]
    fn a_narrowing_absorbs_the_conversion_beneath_it() {
        for (outer, inner) in [
            (u(32), u(64)),
            (u(16), u(32)),
            (u(32), u(32)),
            (i(32), u(32)),
            (u(32), i(64)),
            (u(8), u(64)),
        ] {
            let collapsed = built(&conv(&[outer.clone(), inner.clone()]));
            assert_eq!(
                spine(&collapsed),
                vec![outer.clone()],
                "({outer:?})({inner:?}) should be one conversion"
            );
            for source in [u(8), i(8)] {
                agrees(
                    &[outer.clone(), inner.clone()],
                    std::slice::from_ref(&outer),
                    &source,
                );
            }
        }
    }

    #[test]
    fn widening_is_transitive() {
        let before = [u(64), u(32), u(8)];
        let collapsed = built(&conv(&before));
        assert_eq!(spine(&collapsed), vec![u(64), u(8)]);
        for source in [u(8), i(8)] {
            agrees(&before, &[u(64), u(8)], &source);
        }
        let signed = [i(64), i(32), i(8)];
        assert_eq!(spine(&built(&conv(&signed))), vec![i(64), i(8)]);
        for source in [u(8), i(8)] {
            agrees(&signed, &[i(64), i(8)], &source);
        }
    }

    #[test]
    fn a_pointer_round_trip_is_the_pointer() {
        let chain = built(&[
            (ptr(), CastRole::PointerWidthStep),
            (u(64), CastRole::PointerWidthStep),
            (ptr(), CastRole::PointerWidthStep),
        ]);
        assert_eq!(spine(&chain), vec![ptr()]);
    }

    // ---- the shapes that must not collapse ----

    #[test]
    fn a_widening_of_a_narrowing_stays_two() {
        // `(uint64_t)(uint32_t)x` truncates and then widens. It is not
        // `(uint64_t)x`, and it is how a thirty-two bit machine write reaches
        // the C.
        let before = [u(64), u(32)];
        assert_eq!(spine(&built(&conv(&before))), vec![u(64), u(32)]);
        // A signed source exhibits it: `(uint32_t)` of a negative `int16_t`
        // keeps the sign bits only up to thirty-two, and the widening then
        // zero-fills, where converting straight to `uint64_t` sign-fills.
        let mut differs = false;
        for input in 0..(1u128 << 16) {
            if eval(&before, input, &i(16)) != eval(&[u(64)], input, &i(16)) {
                differs = true;
                break;
            }
        }
        assert!(differs, "the rule would have been sound after all");
        // With an unsigned source narrower than the inner cast the two do
        // agree, which is why the collapse needs the operand's type and is
        // not stated on the cast types alone.
        agrees(&before, &[u(64)], &u(8));
    }

    #[test]
    fn a_widening_over_a_signed_narrowing_keeps_its_middle_step() {
        // `(uint64_t)(uint32_t)(int8_t)e` is not `(uint64_t)(int8_t)e`: the
        // first stops sign-extending at thirty-two bits.
        let before = [u(64), u(32), i(8)];
        assert_eq!(spine(&built(&conv(&before))), vec![u(64), u(32), i(8)]);
        let mut differs = false;
        for input in 0..(1u128 << 8) {
            if eval(&before, input, &u(8)) != eval(&[u(64), i(8)], input, &u(8)) {
                differs = true;
                break;
            }
        }
        assert!(
            differs,
            "the signedness condition would have been unnecessary"
        );
    }

    #[test]
    fn a_recorded_address_width_step_is_never_dropped() {
        // `(uint32_t)(uint64_t)p` narrows a pointer through its own width.
        // Dropping the step leaves `-Wpointer-to-int-cast`, a hard error under
        // the corpus flags, which is the whole reason the step is recorded.
        let chain = built(&[
            (u(32), CastRole::Conversion),
            (u(64), CastRole::PointerWidthStep),
            (ptr(), CastRole::PointerWidthStep),
        ]);
        assert_eq!(spine(&chain), vec![u(32), u(64), ptr()]);
        // The same widths with an ordinary conversion in the middle do
        // collapse, so it is the recording that makes the difference.
        let unmarked = built(&[
            (u(32), CastRole::Conversion),
            (u(64), CastRole::Conversion),
            (u(32), CastRole::Conversion),
        ]);
        assert_eq!(spine(&unmarked), vec![u(32)]);
    }

    #[test]
    fn collapsing_is_idempotent() {
        for types in [
            vec![u(64), u(32), u(64), u(32)],
            vec![u(64), u(32), u(8)],
            vec![u(64), i(64), i(32), u(32)],
        ] {
            let once = built(&conv(&types));
            let twice = built(&conv(&spine(&once)));
            assert_eq!(
                spine(&once),
                spine(&twice),
                "{types:?} is not a fixed point"
            );
            let raw_chain = raw(&conv(&types));
            assert_eq!(
                spine(&raw_chain),
                types,
                "the raw builder must not collapse"
            );
            for source in [u(8), i(8)] {
                agrees(&types, &spine(&once), &source);
            }
        }
    }
}
