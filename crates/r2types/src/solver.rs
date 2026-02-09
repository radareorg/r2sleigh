use std::collections::HashMap;

use r2ssa::SSAVar;

use crate::constraint::Constraint;
use crate::lattice::TypeLattice;
use crate::model::{Type, TypeArena, TypeId};

#[derive(Debug, Clone)]
pub struct SolverConfig {
    pub max_iterations: usize,
}

impl Default for SolverConfig {
    fn default() -> Self {
        Self { max_iterations: 64 }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SolverDiagnostics {
    pub warnings: Vec<String>,
    pub conflicts: Vec<String>,
    pub iterations: usize,
    pub converged: bool,
}

#[derive(Debug, Clone)]
pub struct SolvedTypes {
    pub arena: TypeArena,
    pub var_types: HashMap<SSAVar, TypeId>,
    pub diagnostics: SolverDiagnostics,
    pub top_id: TypeId,
}

#[derive(Debug, Clone, Copy)]
struct Assignment {
    ty: TypeId,
    priority: u8,
}

#[derive(Debug, Default)]
pub struct TypeSolver {
    config: SolverConfig,
}

impl TypeSolver {
    pub fn new(config: SolverConfig) -> Self {
        Self { config }
    }

    pub fn solve(&self, mut arena: TypeArena, constraints: &[Constraint]) -> SolvedTypes {
        let mut diagnostics = SolverDiagnostics::default();
        let mut state: HashMap<SSAVar, Assignment> = HashMap::new();
        let (rewritten_constraints, class_members) = rewrite_equal_constraints(constraints);

        let mut converged = false;
        for iter in 0..self.config.max_iterations {
            let mut changed = false;
            for constraint in &rewritten_constraints {
                changed |= apply_constraint(constraint, &mut arena, &mut state, &mut diagnostics);
            }
            diagnostics.iterations = iter + 1;
            if !changed {
                converged = true;
                break;
            }
        }

        diagnostics.converged = converged;
        if !converged {
            diagnostics.warnings.push(format!(
                "type solver reached iteration cap ({})",
                self.config.max_iterations
            ));
        }

        let mut var_types: HashMap<SSAVar, TypeId> = HashMap::new();
        for (representative, assignment) in state {
            if let Some(members) = class_members.get(&representative) {
                for member in members {
                    var_types.insert(member.clone(), assignment.ty);
                }
            } else {
                var_types.insert(representative, assignment.ty);
            }
        }
        let top_id = arena.top();

        SolvedTypes {
            arena,
            var_types,
            diagnostics,
            top_id,
        }
    }
}

#[derive(Debug, Default)]
struct VarDsu {
    parent: HashMap<SSAVar, SSAVar>,
}

impl VarDsu {
    fn ensure(&mut self, var: &SSAVar) {
        self.parent
            .entry(var.clone())
            .or_insert_with(|| var.clone());
    }

    fn find(&mut self, var: &SSAVar) -> SSAVar {
        self.ensure(var);
        let parent = self.parent.get(var).cloned().unwrap_or_else(|| var.clone());
        if parent == *var {
            return parent;
        }
        let root = self.find(&parent);
        self.parent.insert(var.clone(), root.clone());
        root
    }

    fn union(&mut self, a: &SSAVar, b: &SSAVar) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra != rb {
            self.parent.insert(ra, rb);
        }
    }
}

fn rewrite_equal_constraints(
    constraints: &[Constraint],
) -> (Vec<Constraint>, HashMap<SSAVar, Vec<SSAVar>>) {
    let mut dsu = VarDsu::default();

    for constraint in constraints {
        match constraint {
            Constraint::SetType { var, .. } | Constraint::Subtype { var, .. } => dsu.ensure(var),
            Constraint::HasCapability { ptr, .. } => dsu.ensure(ptr),
            Constraint::FieldAccess { base_ptr, .. } => dsu.ensure(base_ptr),
            Constraint::CallSig {
                target, args, ret, ..
            } => {
                dsu.ensure(target);
                for arg in args {
                    dsu.ensure(arg);
                }
                if let Some((ret_var, _)) = ret {
                    dsu.ensure(ret_var);
                }
            }
            Constraint::Equal { a, b, .. } => {
                dsu.union(a, b);
            }
        }
    }

    let vars: Vec<SSAVar> = dsu.parent.keys().cloned().collect();
    let mut class_members: HashMap<SSAVar, Vec<SSAVar>> = HashMap::new();
    for var in &vars {
        let rep = dsu.find(var);
        class_members.entry(rep).or_default().push(var.clone());
    }

    let mut rewritten = Vec::with_capacity(constraints.len());
    for constraint in constraints {
        match constraint {
            Constraint::Equal { .. } => {}
            Constraint::SetType { var, ty, source } => rewritten.push(Constraint::SetType {
                var: dsu.find(var),
                ty: *ty,
                source: *source,
            }),
            Constraint::Subtype { var, ty, source } => rewritten.push(Constraint::Subtype {
                var: dsu.find(var),
                ty: *ty,
                source: *source,
            }),
            Constraint::HasCapability {
                ptr,
                capability,
                elem_ty,
                source,
            } => rewritten.push(Constraint::HasCapability {
                ptr: dsu.find(ptr),
                capability: *capability,
                elem_ty: *elem_ty,
                source: *source,
            }),
            Constraint::FieldAccess {
                base_ptr,
                offset,
                field_ty,
                field_name,
                source,
            } => rewritten.push(Constraint::FieldAccess {
                base_ptr: dsu.find(base_ptr),
                offset: *offset,
                field_ty: *field_ty,
                field_name: field_name.clone(),
                source: *source,
            }),
            Constraint::CallSig {
                target,
                args,
                params,
                ret,
                source,
            } => rewritten.push(Constraint::CallSig {
                target: dsu.find(target),
                args: args.iter().map(|v| dsu.find(v)).collect(),
                params: params.clone(),
                ret: ret.as_ref().map(|(var, ty)| (dsu.find(var), *ty)),
                source: *source,
            }),
        }
    }

    (rewritten, class_members)
}

fn apply_constraint(
    constraint: &Constraint,
    arena: &mut TypeArena,
    state: &mut HashMap<SSAVar, Assignment>,
    diagnostics: &mut SolverDiagnostics,
) -> bool {
    let source_priority = constraint.source().priority();

    match constraint {
        Constraint::SetType { var, ty, .. } => {
            assign(var, *ty, source_priority, arena, state, diagnostics)
        }
        Constraint::Equal { a, b, .. } => {
            let mut changed = false;
            if let Some(a_ty) = state.get(a).copied() {
                changed |= assign(
                    b,
                    a_ty.ty,
                    source_priority.max(a_ty.priority),
                    arena,
                    state,
                    diagnostics,
                );
            }
            if let Some(b_ty) = state.get(b).copied() {
                changed |= assign(
                    a,
                    b_ty.ty,
                    source_priority.max(b_ty.priority),
                    arena,
                    state,
                    diagnostics,
                );
            }
            changed
        }
        Constraint::Subtype { var, ty, .. } => {
            if let Some(existing) = state.get(var).copied() {
                let tightened = TypeLattice::meet(arena, existing.ty, *ty);
                assign(
                    var,
                    tightened,
                    source_priority.max(existing.priority),
                    arena,
                    state,
                    diagnostics,
                )
            } else {
                assign(var, *ty, source_priority, arena, state, diagnostics)
            }
        }
        Constraint::HasCapability { ptr, elem_ty, .. } => {
            let ptr_ty = arena.ptr(*elem_ty);
            assign(ptr, ptr_ty, source_priority, arena, state, diagnostics)
        }
        Constraint::FieldAccess {
            base_ptr,
            offset,
            field_ty,
            field_name,
            ..
        } => {
            let mut struct_ty = state
                .get(base_ptr)
                .and_then(|assignment| match arena.get(assignment.ty) {
                    Type::Ptr(inner) => match arena.get(*inner) {
                        Type::Struct(_) => Some(*inner),
                        _ => None,
                    },
                    Type::Struct(_) => Some(assignment.ty),
                    _ => None,
                })
                .unwrap_or_else(|| arena.struct_anon());
            struct_ty = arena.struct_with_field(struct_ty, *offset, field_name.clone(), *field_ty);
            let ptr_ty = arena.ptr(struct_ty);
            if let Some(existing) = state.get(base_ptr).copied()
                && existing.priority == source_priority
            {
                if existing.ty != ptr_ty {
                    state.insert(
                        base_ptr.clone(),
                        Assignment {
                            ty: ptr_ty,
                            priority: existing.priority,
                        },
                    );
                    return true;
                }
                return false;
            }
            assign(base_ptr, ptr_ty, source_priority, arena, state, diagnostics)
        }
        Constraint::CallSig {
            args, params, ret, ..
        } => {
            let mut changed = false;
            for (arg, param_ty) in args.iter().zip(params.iter()) {
                changed |= assign(arg, *param_ty, source_priority, arena, state, diagnostics);
            }
            if let Some((ret_var, ret_ty)) = ret {
                changed |= assign(ret_var, *ret_ty, source_priority, arena, state, diagnostics);
            }
            changed
        }
    }
}

fn assign(
    var: &SSAVar,
    ty: TypeId,
    priority: u8,
    arena: &mut TypeArena,
    state: &mut HashMap<SSAVar, Assignment>,
    diagnostics: &mut SolverDiagnostics,
) -> bool {
    match state.get(var).copied() {
        None => {
            state.insert(var.clone(), Assignment { ty, priority });
            true
        }
        Some(existing) if priority > existing.priority => {
            if existing.ty != ty {
                diagnostics.conflicts.push(format!(
                    "{} overridden by higher-priority source ({})",
                    var.display_name(),
                    priority
                ));
            }
            state.insert(var.clone(), Assignment { ty, priority });
            true
        }
        Some(existing) if priority < existing.priority => false,
        Some(existing) => {
            let joined = TypeLattice::join(arena, existing.ty, ty);
            if joined != existing.ty {
                state.insert(
                    var.clone(),
                    Assignment {
                        ty: joined,
                        priority,
                    },
                );
                true
            } else {
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraint::{Constraint, ConstraintSource};
    use crate::model::Signedness;

    #[test]
    fn external_constraints_override_inferred() {
        let mut arena = TypeArena::default();
        let inferred = arena.int(32, Signedness::Unsigned);
        let void_ty = arena.unknown_alias("void");
        let external = arena.ptr(void_ty);
        let var = SSAVar::new("RAX", 1, 8);

        let constraints = vec![
            Constraint::SetType {
                var: var.clone(),
                ty: inferred,
                source: ConstraintSource::Inferred,
            },
            Constraint::SetType {
                var: var.clone(),
                ty: external,
                source: ConstraintSource::External,
            },
        ];

        let solved = TypeSolver::new(SolverConfig::default()).solve(arena, &constraints);
        let ty = solved.var_types.get(&var).copied().expect("missing type");
        assert_eq!(solved.arena.get(ty), solved.arena.get(external));
    }

    #[test]
    fn field_access_enriches_named_struct_pointer() {
        let mut arena = TypeArena::default();
        let base = SSAVar::new("obj", 0, 8);
        let field_ty = arena.int(32, Signedness::Signed);
        let named = arena.struct_named_or_existing("DemoStruct");
        let named_ptr = arena.ptr(named);

        let constraints = vec![
            Constraint::SetType {
                var: base.clone(),
                ty: named_ptr,
                source: ConstraintSource::Inferred,
            },
            Constraint::FieldAccess {
                base_ptr: base.clone(),
                offset: 48,
                field_ty,
                field_name: Some("thirteenth".to_string()),
                source: ConstraintSource::Inferred,
            },
        ];

        let solved = TypeSolver::new(SolverConfig::default()).solve(arena, &constraints);
        let ty = solved
            .var_types
            .get(&base)
            .copied()
            .expect("missing base type");
        let Type::Ptr(inner) = solved.arena.get(ty) else {
            panic!("base should remain a pointer");
        };
        let Type::Struct(shape) = solved.arena.get(*inner) else {
            panic!("pointee should be struct");
        };
        assert_eq!(shape.name.as_deref(), Some("DemoStruct"));
        let field = shape.fields.get(&48).expect("offset 48 field missing");
        assert_eq!(field.name.as_deref(), Some("thirteenth"));
    }

    #[test]
    fn equal_chain_closure_propagates_with_low_iteration_cap() {
        let mut arena = TypeArena::default();
        let v0 = SSAVar::new("tmp:0", 0, 8);
        let v1 = SSAVar::new("tmp:1", 0, 8);
        let v2 = SSAVar::new("tmp:2", 0, 8);
        let v3 = SSAVar::new("tmp:3", 0, 8);
        let void_ty = arena.unknown_alias("void");
        let ptr_ty = arena.ptr(void_ty);

        let constraints = vec![
            Constraint::SetType {
                var: v0.clone(),
                ty: ptr_ty,
                source: ConstraintSource::Inferred,
            },
            Constraint::Equal {
                a: v0.clone(),
                b: v1.clone(),
                source: ConstraintSource::Inferred,
            },
            Constraint::Equal {
                a: v1.clone(),
                b: v2.clone(),
                source: ConstraintSource::Inferred,
            },
            Constraint::Equal {
                a: v2.clone(),
                b: v3.clone(),
                source: ConstraintSource::Inferred,
            },
        ];

        let solved = TypeSolver::new(SolverConfig { max_iterations: 1 }).solve(arena, &constraints);
        let t3 = solved
            .var_types
            .get(&v3)
            .copied()
            .expect("v3 should be typed");
        assert_eq!(solved.arena.get(t3), solved.arena.get(ptr_ty));
    }

    #[test]
    fn external_type_pins_equal_class() {
        let mut arena = TypeArena::default();
        let a = SSAVar::new("RAX", 1, 8);
        let b = SSAVar::new("tmp:9", 2, 8);
        let inferred = arena.int(64, Signedness::Unsigned);
        let void_ty = arena.unknown_alias("void");
        let ext = arena.ptr(void_ty);

        let constraints = vec![
            Constraint::SetType {
                var: a.clone(),
                ty: ext,
                source: ConstraintSource::External,
            },
            Constraint::SetType {
                var: b.clone(),
                ty: inferred,
                source: ConstraintSource::Inferred,
            },
            Constraint::Equal {
                a: a.clone(),
                b: b.clone(),
                source: ConstraintSource::Inferred,
            },
        ];

        let solved = TypeSolver::new(SolverConfig::default()).solve(arena, &constraints);
        let ta = solved.var_types.get(&a).copied().expect("a typed");
        let tb = solved.var_types.get(&b).copied().expect("b typed");
        assert_eq!(solved.arena.get(ta), solved.arena.get(ext));
        assert_eq!(solved.arena.get(tb), solved.arena.get(ext));
    }
}
