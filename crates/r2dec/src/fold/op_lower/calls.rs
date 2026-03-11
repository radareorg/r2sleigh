use super::*;
use r2types::FunctionType;

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

    pub(super) fn render_call_arg_for_callee(
        &self,
        callee: &CExpr,
        arg: analysis::SemanticCallArg,
    ) -> CExpr {
        if self.is_imported_call_target(callee) {
            return self.render_imported_call_arg(arg);
        }

        match arg {
            analysis::SemanticCallArg::Semantic(value) => {
                let mut visited = HashSet::new();
                let expr = self
                    .render_semantic_value(&value, 0, &mut visited)
                    .unwrap_or_else(|| self.expr_for_semantic_call_arg_fallback(&value));
                self.normalize_call_arg_expr_for_callee(callee, expr)
            }
            analysis::SemanticCallArg::StringAddr(addr) => self
                .lookup_string(addr)
                .map(|s| CExpr::StringLit(s.clone()))
                .or_else(|| {
                    self.lookup_symbol(addr)
                        .map(|name| CExpr::Var(name.clone()))
                })
                .unwrap_or(CExpr::UIntLit(addr)),
            analysis::SemanticCallArg::FallbackExpr(expr) => {
                self.normalize_call_arg_expr_for_callee(callee, expr)
            }
        }
    }

    fn render_imported_call_arg(&self, arg: analysis::SemanticCallArg) -> CExpr {
        match arg {
            analysis::SemanticCallArg::Semantic(value) => {
                let mut visited = HashSet::new();
                let expr = self
                    .render_semantic_value(&value, 0, &mut visited)
                    .unwrap_or_else(|| self.expr_for_semantic_call_arg_fallback(&value));
                self.finalize_authoritative_imported_call_arg_expr(expr)
            }
            analysis::SemanticCallArg::StringAddr(addr) => self
                .lookup_string(addr)
                .map(|s| CExpr::StringLit(s.clone()))
                .or_else(|| {
                    self.lookup_symbol(addr)
                        .map(|name| CExpr::Var(name.clone()))
                })
                .unwrap_or(CExpr::UIntLit(addr)),
            analysis::SemanticCallArg::FallbackExpr(expr) => {
                self.normalize_imported_call_arg_expr(expr)
            }
        }
    }

    fn expr_for_semantic_call_arg_fallback(&self, value: &analysis::SemanticValue) -> CExpr {
        match value {
            analysis::SemanticValue::Scalar(analysis::ScalarValue::Expr(expr)) => expr.clone(),
            analysis::SemanticValue::Scalar(analysis::ScalarValue::Root(value_ref)) => {
                if value_ref.var.is_const() {
                    self.const_to_expr(&value_ref.var)
                } else {
                    let rendered = self.var_name(&value_ref.var);
                    self.arg_alias_for_rendered_name(&rendered)
                        .map(CExpr::Var)
                        .unwrap_or_else(|| CExpr::Var(rendered))
                }
            }
            analysis::SemanticValue::Address(addr) => {
                let mut visited = HashSet::new();
                self.render_address_expr_from_addr(addr, 0, &mut visited)
                    .or_else(|| self.render_base_ref_expr(&addr.base, true, 0, &mut visited))
                    .unwrap_or(CExpr::UIntLit(0))
            }
            analysis::SemanticValue::Load { addr, size } => {
                let mut visited = HashSet::new();
                self.render_load_from_addr(addr, *size, 0, &mut visited)
                    .or_else(|| {
                        let addr_expr =
                            self.render_address_expr_from_addr(addr, 0, &mut visited)?;
                        Some(CExpr::Deref(Box::new(addr_expr)))
                    })
                    .unwrap_or(CExpr::UIntLit(0))
            }
            analysis::SemanticValue::Unknown => CExpr::UIntLit(0),
        }
    }

    fn normalize_imported_call_arg_expr(&self, expr: CExpr) -> CExpr {
        let rewritten = self.rewrite_stack_expr(expr);
        let mut best = Some(rewritten.clone());

        let mut expanded_visited = HashSet::new();
        let expanded = self.expand_call_arg_expr(&rewritten, 0, &mut expanded_visited);
        best = self.choose_preferred_call_arg_expr(best, Some(expanded.clone()), true);

        let mut semantic_visited = HashSet::new();
        let semanticized = self.semanticize_visible_expr(&expanded, 0, &mut semantic_visited);
        best = self.choose_preferred_call_arg_expr(best, Some(semanticized.clone()), true);

        let memoryized = match &semanticized {
            CExpr::Deref(inner) => {
                let mut memory_visited = HashSet::new();
                self.render_memory_access_from_visible_expr(
                    inner,
                    self.inputs.arch.ptr_size.max(1),
                    0,
                    &mut memory_visited,
                )
                .or_else(|| self.promote_constant_indexed_call_arg(inner))
                .unwrap_or_else(|| semanticized.clone())
            }
            _ => semanticized.clone(),
        };
        best = self.choose_preferred_call_arg_expr(best, Some(memoryized.clone()), true);

        let literalized = self
            .resolve_literalish_call_arg_expr(&memoryized)
            .unwrap_or(memoryized);
        best = self.choose_preferred_call_arg_expr(best, Some(literalized.clone()), true);

        let mut string_visited = HashSet::new();
        let stringy =
            self.resolve_string_like_imported_call_arg_expr(&literalized, 0, &mut string_visited);
        best = self.choose_preferred_call_arg_expr(best, stringy, true);

        let best = best.unwrap_or(rewritten);
        let best = if let CExpr::Var(name) = &best {
            let name = name.clone();
            if self.should_force_imported_call_resolution_name(&name) {
                let mut semantic_visited = HashSet::new();
                let semantic = self
                    .render_semantic_value_by_name(&name, 0, &mut semantic_visited)
                    .or_else(|| {
                        self.render_authoritative_memory_access_by_name(
                            &name,
                            self.inputs.arch.ptr_size.max(1),
                            0,
                            &mut semantic_visited,
                        )
                    });
                let best = self
                    .choose_preferred_call_arg_expr(Some(best.clone()), semantic, true)
                    .unwrap_or_else(|| best.clone());
                let mut force_visited = HashSet::new();
                self.force_resolve_imported_call_arg_var(&name, 0, &mut force_visited)
                    .and_then(|candidate| {
                        (!matches!(&candidate, CExpr::Var(inner) if inner.eq_ignore_ascii_case(&name)))
                            .then_some(candidate)
                    })
                    .map(|candidate| {
                        self.choose_preferred_call_arg_expr(Some(best.clone()), Some(candidate), true)
                            .unwrap_or(best.clone())
                    })
                    .unwrap_or(best)
            } else {
                best
            }
        } else {
            best
        };
        let rewritten_best = self.rewrite_stack_expr(best.clone());
        self.choose_preferred_call_arg_expr(Some(best.clone()), Some(rewritten_best), true)
            .unwrap_or(best)
    }

    fn finalize_authoritative_imported_call_arg_expr(&self, expr: CExpr) -> CExpr {
        let rewritten = self.rewrite_stack_expr(expr);
        let memoryized = match &rewritten {
            CExpr::Deref(inner) => {
                let mut memory_visited = HashSet::new();
                self.render_memory_access_from_visible_expr(
                    inner,
                    self.inputs.arch.ptr_size.max(1),
                    0,
                    &mut memory_visited,
                )
                .or_else(|| self.promote_constant_indexed_call_arg(inner))
                .unwrap_or_else(|| rewritten.clone())
            }
            _ => rewritten.clone(),
        };
        let literalized = self
            .resolve_literalish_call_arg_expr(&memoryized)
            .unwrap_or(memoryized);
        let mut string_visited = HashSet::new();
        self.resolve_string_like_imported_call_arg_expr(&literalized, 0, &mut string_visited)
            .unwrap_or(literalized)
    }

    /// Convert an SSA operation to a C statement.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn op_to_stmt(&self, op: &SSAOp) -> Option<CStmt> {
        let mut frame = LowerFrame::for_stmt(0, 0, false);
        self.lowered_to_stmt(self.lower_op(op, &mut frame))
    }
}
