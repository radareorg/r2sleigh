Type Inference (r2types)
========================

Background
----------

The r2types crate implements constraint-based type inference for SSA
variables. It collects type constraints from SSA operations and solves
them using a fixed-point iteration algorithm.

Type System
-----------

### TypeArena

Types are interned in a TypeArena. Each type gets a unique TypeId:

```rust
pub struct TypeArena {
    types: Vec<Type>,
    top: TypeId,     // unknown / unconstrained
    bottom: TypeId,  // conflicting constraints
    bool_ty: TypeId,
}
```

### Type Variants

```rust
pub enum Type {
    Top,                          // Unknown
    Bottom,                       // Conflict
    Bool,                         // Boolean (1-bit)
    Int { bits: u32, signedness: Signedness },
    Float { bits: u32 },
    Ptr(TypeId),                  // Pointer to another type
    Array { elem: TypeId, len: Option<usize>, stride: Option<u32> },
    Struct(StructShape),          // Struct with field offsets
    Function { params: Vec<TypeId>, ret: TypeId, variadic: bool },
    UnknownAlias(String),         // Named but unresolved type
}
```

Signedness is Signed, Unsigned, or Unknown.

### StructShape

```rust
pub struct StructShape {
    pub name: Option<String>,
    pub fields: BTreeMap<u64, StructField>,  // offset -> field
}
```

Constraints
-----------

Type constraints are gathered from a prepared function's evidence
(`r2types::evidence`): SSA identities, callee prototypes at each call site,
and certified memory access widths.

```rust
pub enum Constraint<K> {
    Equal { a, b, source },    // a and b are one variable
    Subtype { var, ty, source }, // var's type lies below ty
}
```

Every constraint only tightens. A constraint that would loosen a type -- a
join, a priority override, a rewrite of a field already typed -- cannot be
written, because meets and joins over one variable do not settle.

### Constraint Sources

`Inferred`, `SignatureRegistry` and `External` record where a bound came from.
They carry no priority: every bound holds at once, and two that cannot both
hold meet at `Bottom`, which refuses that variable's type.

Solver
------

```rust
pub fn solve_constraints<K>(arena: TypeArena, constraints: &[Constraint<K>]) -> SolvedTypes<K>
```

1. `Equal` constraints merge nodes into classes (union-find).
2. Each class's type is the left fold of `TypeLattice::meet` over the bounds
   on its members, in constraint order.

There are no rounds and nothing to converge: after the fold has met a bound,
the class type lies below it, and `meet(x, b)` is `x` whenever `x` already lies
below `b`, so the folded type satisfies every bound. Cost: O(C α(N)) plus one
memoised meet per bound.

### Output

```rust
pub struct SolvedTypes<K> {
    pub arena: TypeArena,
    pub var_types: HashMap<K, TypeId>, // present iff the class carries a bound
}
```

Integration with Decompiler
---------------------------

The decompiler uses solved types to:
- Choose correct C types for variables (int vs unsigned vs pointer)
- Determine signedness for comparison operators
- Generate struct field access expressions
- Produce typed function signatures

Type information flows from r2types into r2dec's FoldingContext and
CodeGenerator for the final C output.
