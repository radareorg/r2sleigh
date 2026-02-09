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

        let mut converged = false;
        for iter in 0..self.config.max_iterations {
            let mut changed = false;
            for constraint in constraints {
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

        let var_types = state
            .into_iter()
            .map(|(var, assignment)| (var, assignment.ty))
            .collect();
        let top_id = arena.top();

        SolvedTypes {
            arena,
            var_types,
            diagnostics,
            top_id,
        }
    }
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
}
