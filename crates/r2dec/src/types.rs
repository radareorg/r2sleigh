//! Type inference and representation.
//!
//! This module provides type inference for decompiled code,
//! mapping SSA variables to C types.

use std::collections::{HashMap, HashSet};

use r2ssa::{SSAFunction, SSAOp, SSAVar};
use r2types::{
    CTypeLike, Constraint, ConstraintSource, ExternalTypeDb, MemoryCapability, ResolvedSignature,
    SignatureRegistry, Signedness, SolvedTypes, SolverConfig, TypeArena, TypeId, TypeOracle,
    TypeSolver, to_c_type_like,
};

use crate::ast::CType;
use crate::{ExternalFunctionSignature, ExternalStackVar};

/// Type inference context.
pub struct TypeInference {
    /// Inferred types for variables.
    var_types: HashMap<SSAVar, CType>,
    /// User-provided function signatures.
    func_types: HashMap<String, FunctionType>,
    /// Function names by address (injected from external context).
    function_names: HashMap<u64, String>,
    /// Pointer size in bits.
    ptr_size: u32,
    /// Calling-convention argument registers for the active architecture.
    arg_regs: Vec<String>,
    /// Return-value registers for the active architecture.
    ret_regs: Vec<String>,
    /// Embedded signature registry.
    signature_registry: SignatureRegistry,
    /// Optional externally recovered function signature.
    external_signature: Option<ExternalFunctionSignature>,
    /// Optional externally recovered stack variables.
    external_stack_vars: HashMap<i64, ExternalStackVar>,
    /// Optional external host type database.
    external_type_db: ExternalTypeDb,
    /// Last solver output for this function inference pass.
    solved_types: Option<SolvedTypes>,
}

/// Function type signature.
#[derive(Debug, Clone)]
pub struct FunctionType {
    pub return_type: CType,
    pub params: Vec<CType>,
    pub variadic: bool,
}

impl TypeInference {
    /// Create a new type inference context.
    pub fn new(ptr_size: u32) -> Self {
        Self {
            var_types: HashMap::new(),
            func_types: HashMap::new(),
            function_names: HashMap::new(),
            ptr_size,
            arg_regs: if ptr_size == 64 {
                vec![
                    "rdi".to_string(),
                    "rsi".to_string(),
                    "rdx".to_string(),
                    "rcx".to_string(),
                    "r8".to_string(),
                    "r9".to_string(),
                ]
            } else {
                vec![]
            },
            ret_regs: if ptr_size == 64 {
                vec!["rax".to_string(), "eax".to_string()]
            } else {
                vec!["eax".to_string()]
            },
            signature_registry: SignatureRegistry::from_embedded_json(),
            external_signature: None,
            external_stack_vars: HashMap::new(),
            external_type_db: ExternalTypeDb::default(),
            solved_types: None,
        }
    }

    /// Set externally-resolved function names (address -> symbol).
    pub fn set_function_names(&mut self, names: HashMap<u64, String>) {
        self.function_names = names;
    }

    /// Set externally recovered function signature.
    pub fn set_external_signature(&mut self, signature: Option<ExternalFunctionSignature>) {
        self.external_signature = signature;
    }

    /// Set externally recovered stack variables.
    pub fn set_external_stack_vars(&mut self, stack_vars: HashMap<i64, ExternalStackVar>) {
        self.external_stack_vars = stack_vars;
    }

    /// Set externally recovered type database (from tsj payload).
    pub fn set_external_type_db(&mut self, db: ExternalTypeDb) {
        self.external_type_db = db;
    }

    /// Infer types for all variables in a function.
    pub fn infer_function(&mut self, func: &SSAFunction) {
        let mut arena = TypeArena::default();
        let mut constraints = Vec::new();

        let defs = build_def_map(func);
        let mut struct_hints: HashMap<SSAVar, String> = HashMap::new();

        self.emit_inferred_constraints(
            func,
            &defs,
            &mut arena,
            &mut constraints,
            &mut struct_hints,
        );
        self.emit_external_function_constraints(
            func,
            &mut arena,
            &mut constraints,
            &mut struct_hints,
        );
        self.emit_call_signature_constraints(func, &mut arena, &mut constraints, &mut struct_hints);

        let solver = TypeSolver::new(SolverConfig::default());
        let solved = solver.solve(arena, &constraints);

        self.var_types.clear();
        let vars = collect_vars(func);
        for var in vars {
            let ty_id = solved.type_of(&var);
            let hinted = self.type_id_to_ctype(&solved.arena, ty_id, var.size);
            self.var_types.insert(var, hinted);
        }
        self.solved_types = Some(solved);
    }

    fn emit_inferred_constraints(
        &self,
        func: &SSAFunction,
        defs: &HashMap<String, SSAOp>,
        arena: &mut TypeArena,
        constraints: &mut Vec<Constraint>,
        struct_hints: &mut HashMap<SSAVar, String>,
    ) {
        for block in func.blocks() {
            for phi in &block.phis {
                for src in &phi.sources {
                    constraints.push(Constraint::Equal {
                        a: phi.dst.clone(),
                        b: src.1.clone(),
                        source: ConstraintSource::Inferred,
                    });
                }
            }

            for op in &block.ops {
                match op {
                    SSAOp::Copy { dst, src } | SSAOp::Cast { dst, src } => {
                        constraints.push(Constraint::Equal {
                            a: dst.clone(),
                            b: src.clone(),
                            source: ConstraintSource::Inferred,
                        });
                    }
                    SSAOp::Phi { dst, sources } => {
                        for src in sources {
                            constraints.push(Constraint::Equal {
                                a: dst.clone(),
                                b: src.clone(),
                                source: ConstraintSource::Inferred,
                            });
                        }
                    }
                    SSAOp::Load { dst, addr, .. } => {
                        let elem = self.integer_type_id(dst.size, Signedness::Unknown, arena);
                        constraints.push(Constraint::HasCapability {
                            ptr: addr.clone(),
                            capability: MemoryCapability::Load,
                            elem_ty: elem,
                            source: ConstraintSource::Inferred,
                        });
                        constraints.push(Constraint::SetType {
                            var: dst.clone(),
                            ty: elem,
                            source: ConstraintSource::Inferred,
                        });

                        if let Some((base, offset, stride)) = self.detect_addr_pattern(addr, defs) {
                            let field_name =
                                self.lookup_field_name(offset, struct_hints.get(&base));
                            constraints.push(Constraint::FieldAccess {
                                base_ptr: base.clone(),
                                offset,
                                field_ty: elem,
                                field_name,
                                source: ConstraintSource::Inferred,
                            });
                            if let Some(element_size) = stride {
                                let array_elem =
                                    self.integer_type_id(element_size, Signedness::Unknown, arena);
                                let arr_ty = arena.array(array_elem, None, Some(element_size * 8));
                                let arr_ptr = arena.ptr(arr_ty);
                                constraints.push(Constraint::SetType {
                                    var: base,
                                    ty: arr_ptr,
                                    source: ConstraintSource::Inferred,
                                });
                            }
                        }
                    }
                    SSAOp::Store { addr, val, .. } => {
                        let elem = self.integer_type_id(val.size, Signedness::Unknown, arena);
                        constraints.push(Constraint::HasCapability {
                            ptr: addr.clone(),
                            capability: MemoryCapability::Store,
                            elem_ty: elem,
                            source: ConstraintSource::Inferred,
                        });

                        if let Some((base, offset, stride)) = self.detect_addr_pattern(addr, defs) {
                            let field_name =
                                self.lookup_field_name(offset, struct_hints.get(&base));
                            constraints.push(Constraint::FieldAccess {
                                base_ptr: base.clone(),
                                offset,
                                field_ty: elem,
                                field_name,
                                source: ConstraintSource::Inferred,
                            });
                            if let Some(element_size) = stride {
                                let array_elem =
                                    self.integer_type_id(element_size, Signedness::Unknown, arena);
                                let arr_ty = arena.array(array_elem, None, Some(element_size * 8));
                                let arr_ptr = arena.ptr(arr_ty);
                                constraints.push(Constraint::SetType {
                                    var: base,
                                    ty: arr_ptr,
                                    source: ConstraintSource::Inferred,
                                });
                            }
                        }
                    }
                    SSAOp::IntAdd { dst, a, b }
                    | SSAOp::IntSub { dst, a, b }
                    | SSAOp::IntMult { dst, a, b }
                    | SSAOp::IntAnd { dst, a, b }
                    | SSAOp::IntOr { dst, a, b }
                    | SSAOp::IntXor { dst, a, b }
                    | SSAOp::IntLeft { dst, a, b }
                    | SSAOp::IntRight { dst, a, b }
                    | SSAOp::IntSRight { dst, a, b } => {
                        let ty = self.integer_type_id(dst.size, Signedness::Unknown, arena);
                        constraints.push(Constraint::SetType {
                            var: dst.clone(),
                            ty,
                            source: ConstraintSource::Inferred,
                        });
                        constraints.push(Constraint::SetType {
                            var: a.clone(),
                            ty,
                            source: ConstraintSource::Inferred,
                        });
                        constraints.push(Constraint::SetType {
                            var: b.clone(),
                            ty,
                            source: ConstraintSource::Inferred,
                        });
                    }
                    SSAOp::IntDiv { dst, a, b } | SSAOp::IntRem { dst, a, b } => {
                        let ty = self.integer_type_id(dst.size, Signedness::Unsigned, arena);
                        constraints.push(Constraint::SetType {
                            var: dst.clone(),
                            ty,
                            source: ConstraintSource::Inferred,
                        });
                        constraints.push(Constraint::SetType {
                            var: a.clone(),
                            ty,
                            source: ConstraintSource::Inferred,
                        });
                        constraints.push(Constraint::SetType {
                            var: b.clone(),
                            ty,
                            source: ConstraintSource::Inferred,
                        });
                    }
                    SSAOp::IntSDiv { dst, a, b } | SSAOp::IntSRem { dst, a, b } => {
                        let ty = self.integer_type_id(dst.size, Signedness::Signed, arena);
                        constraints.push(Constraint::SetType {
                            var: dst.clone(),
                            ty,
                            source: ConstraintSource::Inferred,
                        });
                        constraints.push(Constraint::SetType {
                            var: a.clone(),
                            ty,
                            source: ConstraintSource::Inferred,
                        });
                        constraints.push(Constraint::SetType {
                            var: b.clone(),
                            ty,
                            source: ConstraintSource::Inferred,
                        });
                    }
                    SSAOp::IntEqual { dst, a, b }
                    | SSAOp::IntNotEqual { dst, a, b }
                    | SSAOp::IntLess { dst, a, b }
                    | SSAOp::IntLessEqual { dst, a, b } => {
                        constraints.push(Constraint::SetType {
                            var: dst.clone(),
                            ty: arena.bool_ty(),
                            source: ConstraintSource::Inferred,
                        });
                        let ty = self.integer_type_id(a.size, Signedness::Unknown, arena);
                        constraints.push(Constraint::SetType {
                            var: a.clone(),
                            ty,
                            source: ConstraintSource::Inferred,
                        });
                        constraints.push(Constraint::SetType {
                            var: b.clone(),
                            ty,
                            source: ConstraintSource::Inferred,
                        });
                    }
                    SSAOp::IntSLess { dst, a, b } | SSAOp::IntSLessEqual { dst, a, b } => {
                        constraints.push(Constraint::SetType {
                            var: dst.clone(),
                            ty: arena.bool_ty(),
                            source: ConstraintSource::Inferred,
                        });
                        let ty = self.integer_type_id(a.size, Signedness::Signed, arena);
                        constraints.push(Constraint::SetType {
                            var: a.clone(),
                            ty,
                            source: ConstraintSource::Inferred,
                        });
                        constraints.push(Constraint::SetType {
                            var: b.clone(),
                            ty,
                            source: ConstraintSource::Inferred,
                        });
                    }
                    SSAOp::IntZExt { dst, src } => {
                        constraints.push(Constraint::SetType {
                            var: src.clone(),
                            ty: self.integer_type_id(src.size, Signedness::Unsigned, arena),
                            source: ConstraintSource::Inferred,
                        });
                        constraints.push(Constraint::SetType {
                            var: dst.clone(),
                            ty: self.integer_type_id(dst.size, Signedness::Unsigned, arena),
                            source: ConstraintSource::Inferred,
                        });
                    }
                    SSAOp::IntSExt { dst, src } => {
                        constraints.push(Constraint::SetType {
                            var: src.clone(),
                            ty: self.integer_type_id(src.size, Signedness::Signed, arena),
                            source: ConstraintSource::Inferred,
                        });
                        constraints.push(Constraint::SetType {
                            var: dst.clone(),
                            ty: self.integer_type_id(dst.size, Signedness::Signed, arena),
                            source: ConstraintSource::Inferred,
                        });
                    }
                    SSAOp::BoolAnd { dst, a, b }
                    | SSAOp::BoolOr { dst, a, b }
                    | SSAOp::BoolXor { dst, a, b } => {
                        let bool_ty = arena.bool_ty();
                        for var in [dst, a, b] {
                            constraints.push(Constraint::SetType {
                                var: var.clone(),
                                ty: bool_ty,
                                source: ConstraintSource::Inferred,
                            });
                        }
                    }
                    SSAOp::BoolNot { dst, src } => {
                        let bool_ty = arena.bool_ty();
                        constraints.push(Constraint::SetType {
                            var: dst.clone(),
                            ty: bool_ty,
                            source: ConstraintSource::Inferred,
                        });
                        constraints.push(Constraint::SetType {
                            var: src.clone(),
                            ty: bool_ty,
                            source: ConstraintSource::Inferred,
                        });
                    }
                    SSAOp::FloatAdd { dst, a, b }
                    | SSAOp::FloatSub { dst, a, b }
                    | SSAOp::FloatMult { dst, a, b }
                    | SSAOp::FloatDiv { dst, a, b } => {
                        let ty = arena.float(dst.size.saturating_mul(8));
                        for var in [dst, a, b] {
                            constraints.push(Constraint::SetType {
                                var: var.clone(),
                                ty,
                                source: ConstraintSource::Inferred,
                            });
                        }
                    }
                    SSAOp::FloatNeg { dst, src }
                    | SSAOp::FloatAbs { dst, src }
                    | SSAOp::FloatSqrt { dst, src } => {
                        let ty = arena.float(dst.size.saturating_mul(8));
                        constraints.push(Constraint::SetType {
                            var: dst.clone(),
                            ty,
                            source: ConstraintSource::Inferred,
                        });
                        constraints.push(Constraint::SetType {
                            var: src.clone(),
                            ty,
                            source: ConstraintSource::Inferred,
                        });
                    }
                    SSAOp::FloatLess { dst, a, b }
                    | SSAOp::FloatLessEqual { dst, a, b }
                    | SSAOp::FloatEqual { dst, a, b }
                    | SSAOp::FloatNotEqual { dst, a, b } => {
                        constraints.push(Constraint::SetType {
                            var: dst.clone(),
                            ty: arena.bool_ty(),
                            source: ConstraintSource::Inferred,
                        });
                        let ty = arena.float(a.size.saturating_mul(8));
                        constraints.push(Constraint::SetType {
                            var: a.clone(),
                            ty,
                            source: ConstraintSource::Inferred,
                        });
                        constraints.push(Constraint::SetType {
                            var: b.clone(),
                            ty,
                            source: ConstraintSource::Inferred,
                        });
                    }
                    SSAOp::PtrAdd {
                        dst,
                        base,
                        index,
                        element_size,
                    }
                    | SSAOp::PtrSub {
                        dst,
                        base,
                        index,
                        element_size,
                    } => {
                        let elem = self.integer_type_id(*element_size, Signedness::Unknown, arena);
                        let ptr = arena.ptr(elem);
                        constraints.push(Constraint::SetType {
                            var: base.clone(),
                            ty: ptr,
                            source: ConstraintSource::Inferred,
                        });
                        constraints.push(Constraint::SetType {
                            var: dst.clone(),
                            ty: ptr,
                            source: ConstraintSource::Inferred,
                        });
                        constraints.push(Constraint::SetType {
                            var: index.clone(),
                            ty: self.integer_type_id(index.size, Signedness::Unknown, arena),
                            source: ConstraintSource::Inferred,
                        });
                    }
                    _ => {}
                }
            }
        }
    }

    fn emit_external_function_constraints(
        &self,
        func: &SSAFunction,
        arena: &mut TypeArena,
        constraints: &mut Vec<Constraint>,
        struct_hints: &mut HashMap<SSAVar, String>,
    ) {
        let Some(signature) = &self.external_signature else {
            return;
        };
        if signature.params.is_empty() {
            return;
        }

        let vars = collect_vars(func);
        let mut reg0_map: HashMap<String, SSAVar> = HashMap::new();
        for var in vars {
            if var.version == 0 {
                reg0_map.entry(var.name.to_ascii_lowercase()).or_insert(var);
            }
        }

        for (idx, ext) in signature.params.iter().enumerate() {
            let Some(raw_ty) = &ext.ty else {
                continue;
            };
            let Some(reg_name) = self.arg_regs.get(idx) else {
                continue;
            };
            let Some(reg_var) = reg0_map.get(reg_name).cloned() else {
                continue;
            };
            let (ty_id, struct_name) = self.ctype_to_typeid(raw_ty, arena);
            constraints.push(Constraint::SetType {
                var: reg_var.clone(),
                ty: ty_id,
                source: ConstraintSource::External,
            });
            if let Some(name) = struct_name {
                struct_hints.insert(reg_var, name);
            }
        }

        for stack_var in self.external_stack_vars.values() {
            let Some(ty) = &stack_var.ty else {
                continue;
            };
            let key = stack_var.name.to_ascii_lowercase();
            let Some(var) = reg0_map.get(&key).cloned() else {
                continue;
            };
            let (ty_id, struct_name) = self.ctype_to_typeid(ty, arena);
            constraints.push(Constraint::SetType {
                var: var.clone(),
                ty: ty_id,
                source: ConstraintSource::External,
            });
            if let Some(name) = struct_name {
                struct_hints.insert(var, name);
            }
        }
    }

    fn emit_call_signature_constraints(
        &self,
        func: &SSAFunction,
        arena: &mut TypeArena,
        constraints: &mut Vec<Constraint>,
        struct_hints: &mut HashMap<SSAVar, String>,
    ) {
        for block in func.blocks() {
            for (call_idx, op) in block.ops.iter().enumerate() {
                let target = match op {
                    SSAOp::Call { target } | SSAOp::CallInd { target } => target,
                    _ => continue,
                };

                let Some(sig) = self.resolve_call_signature(target, arena) else {
                    continue;
                };

                let args = collect_call_args(&block.ops, call_idx, &self.arg_regs);
                for (idx, arg_var) in args.iter().enumerate() {
                    if idx >= sig.params.len() {
                        break;
                    }
                    let ty = sig.params[idx];
                    constraints.push(Constraint::SetType {
                        var: arg_var.clone(),
                        ty,
                        source: ConstraintSource::SignatureRegistry,
                    });
                    if let Some(name) = struct_name_from_type(arena, ty) {
                        struct_hints.insert(arg_var.clone(), name.to_string());
                    }
                }

                let ret = collect_call_return(&block.ops, call_idx, &self.ret_regs)
                    .map(|ret_var| (ret_var, sig.ret));
                constraints.push(Constraint::CallSig {
                    target: target.clone(),
                    args,
                    params: sig.params,
                    ret,
                    source: ConstraintSource::SignatureRegistry,
                });
            }
        }
    }

    fn resolve_call_signature(
        &self,
        target: &SSAVar,
        arena: &mut TypeArena,
    ) -> Option<ResolvedSignature> {
        let mut candidates = Vec::new();
        candidates.push(target.name.clone());

        if let Some(addr) = parse_const_addr(&target.name)
            && let Some(name) = self.function_names.get(&addr)
        {
            candidates.push(name.clone());
        }

        for candidate in candidates {
            if let Some(sig) = self.func_types.get(&candidate) {
                let params = sig
                    .params
                    .iter()
                    .map(|ty| self.ctype_to_typeid(ty, arena).0)
                    .collect();
                let ret = self.ctype_to_typeid(&sig.return_type, arena).0;
                return Some(ResolvedSignature {
                    ret,
                    params,
                    variadic: sig.variadic,
                });
            }
            if let Some(sig) = self
                .signature_registry
                .resolve(&candidate, arena, self.ptr_size)
            {
                return Some(sig);
            }
        }

        None
    }

    fn lookup_field_name(&self, offset: u64, struct_name_hint: Option<&String>) -> Option<String> {
        if let Some(name) = struct_name_hint {
            let key = name.to_ascii_lowercase();
            if let Some(st) = self.external_type_db.structs.get(&key)
                && let Some(field) = st.fields.get(&offset)
            {
                return Some(field.name.clone());
            }
        }

        let mut found: Option<String> = None;
        for st in self.external_type_db.structs.values() {
            if let Some(field) = st.fields.get(&offset) {
                if let Some(existing) = &found {
                    if existing != &field.name {
                        return None;
                    }
                } else {
                    found = Some(field.name.clone());
                }
            }
        }

        found
    }

    fn detect_addr_pattern(
        &self,
        addr: &SSAVar,
        defs: &HashMap<String, SSAOp>,
    ) -> Option<(SSAVar, u64, Option<u32>)> {
        let op = defs.get(&addr.display_name())?;

        match op {
            SSAOp::PtrAdd {
                base,
                index: _,
                element_size,
                ..
            }
            | SSAOp::PtrSub {
                base,
                index: _,
                element_size,
                ..
            } => Some((base.clone(), 0, Some(*element_size))),
            SSAOp::IntAdd { a, b, .. } => {
                if a.is_const()
                    && let Some(offset) = parse_const_addr(&a.name)
                {
                    return Some((b.clone(), offset, None));
                }
                if b.is_const()
                    && let Some(offset) = parse_const_addr(&b.name)
                {
                    return Some((a.clone(), offset, None));
                }

                if let Some((base, stride)) = self.match_base_plus_scaled_index(a, b, defs) {
                    return Some((base, 0, Some(stride)));
                }
                if let Some((base, stride)) = self.match_base_plus_scaled_index(b, a, defs) {
                    return Some((base, 0, Some(stride)));
                }
                None
            }
            SSAOp::IntSub { a, b, .. } => {
                if b.is_const()
                    && let Some(offset) = parse_const_addr(&b.name)
                {
                    return Some((a.clone(), offset, None));
                }
                None
            }
            _ => None,
        }
    }

    fn match_base_plus_scaled_index(
        &self,
        base: &SSAVar,
        candidate: &SSAVar,
        defs: &HashMap<String, SSAOp>,
    ) -> Option<(SSAVar, u32)> {
        let mul = defs.get(&candidate.display_name())?;
        match mul {
            SSAOp::IntMult { a, b, .. } => {
                if let Some(scale) = parse_const_addr(&a.name) {
                    return Some((base.clone(), scale as u32));
                }
                if let Some(scale) = parse_const_addr(&b.name) {
                    return Some((base.clone(), scale as u32));
                }
                None
            }
            SSAOp::IntLeft { b, .. } => {
                let shift = parse_const_addr(&b.name)?;
                let scale = 1u32.checked_shl(shift as u32)?;
                Some((base.clone(), scale))
            }
            _ => None,
        }
    }

    fn ctype_to_typeid(&self, ty: &CType, arena: &mut TypeArena) -> (TypeId, Option<String>) {
        match ty {
            CType::Void => (arena.unknown_alias("void"), None),
            CType::Bool => (arena.bool_ty(), None),
            CType::Int(bits) => (arena.int(*bits, Signedness::Signed), None),
            CType::UInt(bits) => (arena.int(*bits, Signedness::Unsigned), None),
            CType::Float(bits) => (arena.float(*bits), None),
            CType::Pointer(inner) => {
                let (inner_ty, struct_name) = self.ctype_to_typeid(inner, arena);
                (arena.ptr(inner_ty), struct_name)
            }
            CType::Array(inner, len) => {
                let (elem_ty, struct_name) = self.ctype_to_typeid(inner, arena);
                (arena.array(elem_ty, *len, None), struct_name)
            }
            CType::Struct(name) => (
                arena.struct_named_or_existing(name.clone()),
                Some(name.clone()),
            ),
            CType::Union(name) | CType::Enum(name) | CType::Typedef(name) => {
                (arena.unknown_alias(name.clone()), None)
            }
            CType::Function { params, ret } => {
                let param_ids = params
                    .iter()
                    .map(|param| self.ctype_to_typeid(param, arena).0)
                    .collect();
                let (ret_id, _) = self.ctype_to_typeid(ret, arena);
                (arena.function(param_ids, ret_id, false), None)
            }
            CType::Unknown => (arena.top(), None),
        }
    }

    fn type_id_to_ctype(&self, arena: &TypeArena, ty_id: TypeId, fallback_size: u32) -> CType {
        match to_c_type_like(arena, ty_id) {
            CTypeLike::Void => CType::Void,
            CTypeLike::Bool => CType::Bool,
            CTypeLike::Int { bits, signedness } => match signedness {
                Signedness::Unsigned => CType::UInt(bits),
                Signedness::Signed | Signedness::Unknown => CType::Int(bits),
            },
            CTypeLike::Float(bits) => CType::Float(bits),
            CTypeLike::Pointer(inner) => CType::Pointer(Box::new(self.ctype_like_to_ctype(*inner))),
            CTypeLike::Array(inner, len) => {
                CType::Array(Box::new(self.ctype_like_to_ctype(*inner)), len)
            }
            CTypeLike::Struct(name) => CType::Struct(name),
            CTypeLike::Function => CType::Unknown,
            CTypeLike::Unknown => self.type_from_size(fallback_size),
        }
    }

    fn ctype_like_to_ctype(&self, ty: CTypeLike) -> CType {
        match ty {
            CTypeLike::Void => CType::Void,
            CTypeLike::Bool => CType::Bool,
            CTypeLike::Int { bits, signedness } => match signedness {
                Signedness::Unsigned => CType::UInt(bits),
                Signedness::Signed | Signedness::Unknown => CType::Int(bits),
            },
            CTypeLike::Float(bits) => CType::Float(bits),
            CTypeLike::Pointer(inner) => CType::Pointer(Box::new(self.ctype_like_to_ctype(*inner))),
            CTypeLike::Array(inner, len) => {
                CType::Array(Box::new(self.ctype_like_to_ctype(*inner)), len)
            }
            CTypeLike::Struct(name) => CType::Struct(name),
            CTypeLike::Function | CTypeLike::Unknown => CType::Unknown,
        }
    }

    fn integer_type_id(
        &self,
        size_bytes: u32,
        signedness: Signedness,
        arena: &mut TypeArena,
    ) -> TypeId {
        let bits = match size_bytes {
            0 => 1,
            _ => size_bytes.saturating_mul(8),
        };
        arena.int(bits, signedness)
    }

    /// Get the type of a variable.
    pub fn get_type(&self, var: &SSAVar) -> CType {
        self.var_types
            .get(var)
            .cloned()
            .unwrap_or_else(|| self.type_from_size(var.size))
    }

    /// Get a type from a size.
    pub fn type_from_size(&self, size: u32) -> CType {
        match size {
            0 => CType::Unknown,
            1 => CType::Int(8),
            2 => CType::Int(16),
            4 => CType::Int(32),
            8 => CType::Int(64),
            _ => CType::Int(size.saturating_mul(8)),
        }
    }

    /// Export inferred types keyed by variable display/lowered names.
    pub fn var_type_hints(&self) -> HashMap<String, CType> {
        let mut out = HashMap::new();
        for (var, ty) in &self.var_types {
            let key = var.display_name();
            out.insert(key.clone(), ty.clone());
            out.insert(key.to_lowercase(), ty.clone());

            let base = var.name.to_lowercase();
            out.insert(base.clone(), ty.clone());
            out.insert(format!("{}_{}", base, var.version), ty.clone());
        }
        out
    }

    /// Register a function type.
    pub fn add_function_type(&mut self, name: &str, func_type: FunctionType) {
        self.func_types.insert(name.to_string(), func_type);
    }

    /// Get a function type.
    pub fn get_function_type(&self, name: &str) -> Option<&FunctionType> {
        self.func_types.get(name)
    }

    /// Get the last solved type lattice for oracle-based consumers.
    pub fn solved_types(&self) -> Option<&SolvedTypes> {
        self.solved_types.as_ref()
    }
}

fn build_def_map(func: &SSAFunction) -> HashMap<String, SSAOp> {
    let mut defs = HashMap::new();
    for block in func.blocks() {
        for op in &block.ops {
            if let Some(dst) = op.dst() {
                defs.insert(dst.display_name(), op.clone());
            }
        }
        for phi in &block.phis {
            defs.insert(
                phi.dst.display_name(),
                SSAOp::Phi {
                    dst: phi.dst.clone(),
                    sources: phi.sources.iter().map(|(_, src)| src.clone()).collect(),
                },
            );
        }
    }
    defs
}

fn collect_vars(func: &SSAFunction) -> Vec<SSAVar> {
    let mut seen = HashSet::new();
    let mut vars = Vec::new();

    let push = |v: &SSAVar, vars: &mut Vec<SSAVar>, seen: &mut HashSet<SSAVar>| {
        if seen.insert(v.clone()) {
            vars.push(v.clone());
        }
    };

    for block in func.blocks() {
        for phi in &block.phis {
            push(&phi.dst, &mut vars, &mut seen);
            for (_, src) in &phi.sources {
                push(src, &mut vars, &mut seen);
            }
        }
        for op in &block.ops {
            if let Some(dst) = op.dst() {
                push(dst, &mut vars, &mut seen);
            }
            for src in op.sources() {
                push(src, &mut vars, &mut seen);
            }
        }
    }

    vars
}

fn parse_const_addr(name: &str) -> Option<u64> {
    if let Some(val_str) = name.strip_prefix("const:") {
        let val_str = val_str.split('_').next().unwrap_or(val_str);
        if let Some(dec) = val_str
            .strip_prefix("0d")
            .or_else(|| val_str.strip_prefix("0D"))
        {
            return dec.parse().ok();
        }
        if let Some(hex) = val_str
            .strip_prefix("0x")
            .or_else(|| val_str.strip_prefix("0X"))
        {
            return u64::from_str_radix(hex, 16).ok();
        }
        u64::from_str_radix(val_str, 16).ok()
    } else if let Some(val_str) = name.strip_prefix("ram:") {
        let val_str = val_str.split('_').next().unwrap_or(val_str);
        u64::from_str_radix(val_str, 16).ok()
    } else {
        None
    }
}

fn collect_call_args(ops: &[SSAOp], call_idx: usize, arg_regs: &[String]) -> Vec<SSAVar> {
    if arg_regs.is_empty() {
        return Vec::new();
    }

    let mut found: HashMap<String, SSAVar> = HashMap::new();
    let mut idx = call_idx;
    while idx > 0 {
        idx -= 1;
        let prev = &ops[idx];

        if matches!(prev, SSAOp::Call { .. } | SSAOp::CallInd { .. }) {
            break;
        }

        let (dst, src) = match prev {
            SSAOp::Copy { dst, src }
            | SSAOp::IntZExt { dst, src }
            | SSAOp::IntSExt { dst, src }
            | SSAOp::Cast { dst, src } => (dst, src),
            _ => continue,
        };

        let dst_name = dst.name.to_ascii_lowercase();
        if arg_regs.iter().any(|reg| reg == &dst_name) && !found.contains_key(&dst_name) {
            found.insert(dst_name, src.clone());
        }
    }

    let mut ordered = Vec::new();
    for reg in arg_regs {
        if let Some(var) = found.remove(reg) {
            ordered.push(var);
        } else {
            break;
        }
    }

    ordered
}

fn collect_call_return(ops: &[SSAOp], call_idx: usize, ret_regs: &[String]) -> Option<SSAVar> {
    let mut idx = call_idx + 1;
    while idx < ops.len() {
        let next = &ops[idx];

        if matches!(next, SSAOp::Call { .. } | SSAOp::CallInd { .. }) {
            break;
        }

        match next {
            SSAOp::Copy { dst, src }
            | SSAOp::IntZExt { dst, src }
            | SSAOp::IntSExt { dst, src }
            | SSAOp::Cast { dst, src } => {
                let src_name = src.name.to_ascii_lowercase();
                if ret_regs.iter().any(|reg| reg == &src_name) {
                    return Some(dst.clone());
                }
            }
            _ => {}
        }

        idx += 1;
    }

    None
}

fn struct_name_from_type(arena: &TypeArena, ty: TypeId) -> Option<&str> {
    match arena.get(ty) {
        r2types::Type::Struct(shape) => shape.name.as_deref(),
        r2types::Type::Ptr(inner) => match arena.get(*inner) {
            r2types::Type::Struct(shape) => shape.name.as_deref(),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_from_size() {
        let ti = TypeInference::new(64);

        assert_eq!(ti.type_from_size(1), CType::Int(8));
        assert_eq!(ti.type_from_size(2), CType::Int(16));
        assert_eq!(ti.type_from_size(4), CType::Int(32));
        assert_eq!(ti.type_from_size(8), CType::Int(64));
    }

    #[test]
    fn test_parse_const_addr() {
        assert_eq!(parse_const_addr("const:0x40_0"), Some(0x40));
        assert_eq!(parse_const_addr("const:40"), Some(0x40));
        assert_eq!(parse_const_addr("const:0d40"), Some(40));
        assert_eq!(parse_const_addr("ram:401000_0"), Some(0x401000));
        assert_eq!(parse_const_addr("RAX_1"), None);
    }
}
