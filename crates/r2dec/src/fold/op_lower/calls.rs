use super::*;

impl<'a> FoldingContext<'a> {
    fn lookup_known_signature(&self, callee_name: &str) -> Option<&FunctionType> {
        let normalized = normalize_callee_name(callee_name);
        self.inputs.known_function_signatures.get(&normalized)
    }

    fn extract_callee_name(expr: &CExpr) -> Option<&str> {
        match expr {
            CExpr::Var(name) => Some(name.as_str()),
            CExpr::Deref(inner) | CExpr::Paren(inner) | CExpr::AddrOf(inner) => {
                Self::extract_callee_name(inner)
            }
            CExpr::Cast { expr: inner, .. } => Self::extract_callee_name(inner),
            _ => None,
        }
    }

    pub(super) fn non_variadic_call_arity(&self, callee: &CExpr) -> Option<usize> {
        let name = Self::extract_callee_name(callee)?;

        let known_arity = self
            .lookup_known_signature(name)
            .and_then(|sig| (!sig.variadic).then_some(sig.params.len()));

        let normalized = normalize_callee_name(name);
        let mut arena = TypeArena::default();
        let mut registry_arity = None;
        for candidate in [name, normalized.as_str()] {
            if let Some(resolved) =
                self.signature_registry
                    .resolve(candidate, &mut arena, self.inputs.arch.ptr_size)
            {
                registry_arity = (!resolved.variadic).then_some(resolved.params.len());
                break;
            }
        }

        match (known_arity, registry_arity) {
            (Some(known), Some(registry)) => Some(known.min(registry)),
            (Some(known), None) => Some(known),
            (None, Some(registry)) => Some(registry),
            (None, None) => None,
        }
    }

    pub(super) fn resolve_call_target(&self, target: &SSAVar) -> CExpr {
        if let Some(addr) = extract_call_address(&target.name) {
            if let Some(name) = self.lookup_function(addr) {
                return CExpr::Var(name.clone());
            }
            if let Some(name) = self.lookup_symbol(addr) {
                return CExpr::Var(name.clone());
            }
        } else if target.is_const()
            && let Some(addr) = parse_const_value(&target.name)
        {
            if let Some(name) = self.lookup_function(addr) {
                return CExpr::Var(name.clone());
            }
            if let Some(name) = self.lookup_symbol(addr) {
                return CExpr::Var(name.clone());
            }
        }
        self.get_expr(target)
    }

    /// Convert an SSA operation to a C statement.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn op_to_stmt(&self, op: &SSAOp) -> Option<CStmt> {
        let mut frame = LowerFrame::for_stmt(0, 0, false);
        self.lowered_to_stmt(self.lower_op(op, &mut frame))
    }
}
