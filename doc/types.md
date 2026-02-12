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

Type constraints are collected from SSA operations:

```rust
pub enum Constraint {
    SetType { var, ty, source },
    Equal { a, b, source },
    Subtype { var, ty, source },
    HasCapability { ptr, capability, elem_ty, source },
    CallSig { target, args, params, ret, source },
    FieldAccess { base_ptr, offset, field_ty, field_name, source },
}
```

### Constraint Sources

Each constraint has a priority based on its source:

- Inferred (priority 1): from SSA operations
- SignatureRegistry (priority 2): from built-in function signatures
- External (priority 3): from radare2 type info (highest priority)

Higher-priority constraints override lower ones when conflicting.

Solver
------

```rust
pub struct TypeSolver {
    config: SolverConfig,  // max_iterations: 64
}
```

The solver:
1. Rewrites Equal constraints into equivalence classes
2. Iterates over constraints, applying each to the type state
3. Uses TypeLattice for meet/join operations
4. Stops when no changes occur or iteration cap is reached

### Output

```rust
pub struct SolvedTypes {
    pub arena: TypeArena,
    pub var_types: HashMap<SSAVar, TypeId>,
    pub diagnostics: SolverDiagnostics,
}
```

Diagnostics include warnings, conflicts, iteration count, and convergence.

Integration with Decompiler
---------------------------

The decompiler uses solved types to:
- Choose correct C types for variables (int vs unsigned vs pointer)
- Determine signedness for comparison operators
- Generate struct field access expressions
- Produce typed function signatures

Type information flows from r2types into r2dec's FoldingContext and
CodeGenerator for the final C output.
