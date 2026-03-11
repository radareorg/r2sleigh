use super::*;

impl<'a> FoldingContext<'a> {
    fn semanticized_raw_definition_candidate(&self, name: &str) -> Option<CExpr> {
        let raw = self.lookup_definition_raw(name)?;
        let mut semantic_visited = HashSet::new();
        let semanticized = self.semanticize_visible_expr(&raw, 0, &mut semantic_visited);
        self.choose_preferred_visible_expr(Some(raw), Some(semanticized))
    }

    pub(crate) fn expr_contains_generic_stack_alias(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Var(name) => should_replace_preserved_stack_alias(name),
            CExpr::Paren(inner) => self.expr_contains_generic_stack_alias(inner),
            CExpr::Cast { expr: inner, .. } => self.expr_contains_generic_stack_alias(inner),
            CExpr::Unary { operand, .. } => self.expr_contains_generic_stack_alias(operand),
            CExpr::Binary { left, right, .. } => {
                self.expr_contains_generic_stack_alias(left)
                    || self.expr_contains_generic_stack_alias(right)
            }
            CExpr::Deref(inner) | CExpr::AddrOf(inner) => {
                self.expr_contains_generic_stack_alias(inner)
            }
            CExpr::Subscript { base, index } => {
                self.expr_contains_generic_stack_alias(base)
                    || self.expr_contains_generic_stack_alias(index)
            }
            CExpr::Member { base, .. } | CExpr::PtrMember { base, .. } => {
                self.expr_contains_generic_stack_alias(base)
            }
            CExpr::Call { func, args } => {
                self.expr_contains_generic_stack_alias(func)
                    || args
                        .iter()
                        .any(|arg| self.expr_contains_generic_stack_alias(arg))
            }
            _ => false,
        }
    }

    fn predicate_return_candidate(
        &self,
        expr: &CExpr,
        depth: u32,
        visited: &mut HashSet<String>,
    ) -> Option<CExpr> {
        if depth > MAX_PREDICATE_OPERAND_DEPTH {
            return None;
        }

        match expr {
            CExpr::Var(name) => {
                if self.is_transient_visible_name(name) || self.is_low_signal_visible_name(name) {
                    return None;
                }
                if !visited.insert(name.clone()) {
                    return None;
                }

                let candidate = self
                    .lookup_predicate_expr(name)
                    .map(|pred| self.simplify_condition_expr(pred))
                    .or_else(|| {
                        self.lookup_definition_raw(name).and_then(|def| {
                            self.predicate_return_candidate(&def, depth + 1, visited)
                                .or_else(|| {
                                    self.is_assignment_predicate_expr(&def)
                                        .then(|| self.simplify_condition_expr(def))
                                })
                        })
                    });

                visited.remove(name);
                candidate
            }
            CExpr::Paren(inner) => self
                .predicate_return_candidate(inner, depth + 1, visited)
                .map(|resolved| CExpr::Paren(Box::new(resolved))),
            CExpr::Cast { ty, expr: inner } => self
                .predicate_return_candidate(inner, depth + 1, visited)
                .map(|resolved| CExpr::cast(ty.clone(), resolved)),
            _ => self
                .is_assignment_predicate_expr(expr)
                .then(|| self.simplify_condition_expr(expr.clone())),
        }
    }

    pub(super) fn resolve_return_candidate(&self, expr: &CExpr) -> CExpr {
        let mut best = expr.clone();
        let mut has_semantic_root = false;
        if let CExpr::Var(name) = expr {
            let mut semantic_visited = HashSet::new();
            if let Some(semantic) =
                self.render_semantic_value_by_name(name, 0, &mut semantic_visited)
            {
                has_semantic_root = true;
                if self.prefers_visible_expr(&best, &semantic) {
                    best = semantic;
                }
            }
        }
        let mut visited = HashSet::new();
        if let Some(predicate) = self.predicate_return_candidate(expr, 0, &mut visited)
            && self.prefers_visible_expr(&best, &predicate)
        {
            best = predicate;
        }

        visited.clear();
        if let Some(resolved) = self.resolve_return_expr_from_defs(expr, 0, &mut visited)
            && self.prefers_visible_expr(&best, &resolved)
        {
            best = resolved;
        }

        if let CExpr::Var(name) = expr
            && let Some(candidate) = self.semanticized_raw_definition_candidate(name)
            && self.prefers_visible_expr(&best, &candidate)
        {
            best = candidate;
        }

        if !has_semantic_root
            && let CExpr::Var(name) = expr
            && let Some(def) = self.lookup_definition(name)
            && self.prefers_visible_expr(&best, &def)
        {
            best = def;
        }

        if !has_semantic_root
            && let CExpr::Var(name) = expr
            && let Some(def) = self.best_visible_definition(name)
            && self.prefers_visible_expr(&best, &def)
        {
            best = def;
        }

        best
    }

    pub(super) fn preferred_return_candidate(
        &self,
        current: Option<CExpr>,
        candidate: Option<CExpr>,
    ) -> Option<CExpr> {
        match (current, candidate) {
            (None, other) => other,
            (some @ Some(_), None) => some,
            (Some(current_expr), Some(candidate_expr)) => {
                let current_expr = self.resolve_return_candidate(&current_expr);
                let candidate_expr = self.resolve_return_candidate(&candidate_expr);
                let current_bad = self.expr_contains_generic_stack_alias(&current_expr)
                    || self.is_uninitialized_return_reg(&current_expr)
                    || self.expr_is_transient_return_artifact(&current_expr);
                let candidate_bad = self.expr_contains_generic_stack_alias(&candidate_expr)
                    || self.is_uninitialized_return_reg(&candidate_expr)
                    || self.expr_is_transient_return_artifact(&candidate_expr);
                if current_bad && !candidate_bad {
                    return Some(candidate_expr);
                }
                if candidate_bad && !current_bad {
                    return Some(current_expr);
                }
                self.choose_preferred_visible_expr(Some(current_expr), Some(candidate_expr))
            }
        }
    }

    pub(crate) fn merged_return_candidate_for_block_slot(
        &self,
        block_addr: u64,
        slot_offset: i64,
    ) -> Option<CExpr> {
        let mut best = None;
        for summary in self.frame_slot_merges_map().values() {
            if summary.slot_offset != slot_offset {
                continue;
            }
            let Some(value) = summary.incoming.get(&block_addr) else {
                continue;
            };
            let mut visited = HashSet::new();
            let rendered = self.render_semantic_value(value, 0, &mut visited);
            best = self.preferred_return_candidate(best, rendered);
        }
        best
    }

    fn expr_is_transient_return_artifact(&self, expr: &CExpr) -> bool {
        match expr {
            CExpr::Var(name) => {
                self.is_transient_visible_name(name) || self.is_low_signal_visible_name(name)
            }
            CExpr::Paren(inner) | CExpr::Cast { expr: inner, .. } => {
                self.expr_is_transient_return_artifact(inner)
            }
            _ => false,
        }
    }

    pub(super) fn semantic_deref_candidate_for_name(&self, name: &str) -> Option<CExpr> {
        let mut visited = HashSet::new();
        self.render_authoritative_memory_access_by_name(name, 0, 0, &mut visited)
    }

    fn should_inline_in_return(&self, var_name: &str, depth: u32) -> bool {
        if depth > MAX_RETURN_INLINE_DEPTH {
            return false;
        }

        let lower = var_name.to_lowercase();
        if lower.starts_with("const:") || lower.starts_with("tmp:") {
            return true;
        }
        if self.inputs.arch.is_return_register_name(&lower) {
            return true;
        }

        let is_pinned = self.pinned_set().contains(var_name)
            || self.pinned_set().contains(&lower)
            || var_name
                .rsplit_once('_')
                .map(|(base, ver)| {
                    self.pinned_set()
                        .contains(&format!("{}_{}", base.to_lowercase(), ver))
                        || self
                            .pinned_set()
                            .contains(&format!("{}_{}", base.to_uppercase(), ver))
                })
                .unwrap_or(false);
        if is_pinned {
            return false;
        }

        let use_count = self
            .use_counts_map()
            .get(var_name)
            .copied()
            .or_else(|| self.use_counts_map().get(&lower).copied())
            .or_else(|| {
                var_name.rsplit_once('_').and_then(|(base, ver)| {
                    self.use_counts_map()
                        .get(&format!("{}_{}", base.to_lowercase(), ver))
                        .copied()
                        .or_else(|| {
                            self.use_counts_map()
                                .get(&format!("{}_{}", base.to_uppercase(), ver))
                                .copied()
                        })
                })
            })
            .unwrap_or(0);
        if use_count == 0 || use_count > 3 {
            return false;
        }

        self.lookup_definition(var_name)
            .map(|expr| self.is_return_inline_candidate(&expr, 0))
            .unwrap_or(false)
    }

    fn is_return_inline_candidate(&self, expr: &CExpr, depth: u32) -> bool {
        if depth > MAX_RETURN_INLINE_CANDIDATE_DEPTH {
            return false;
        }

        match expr {
            CExpr::IntLit(_)
            | CExpr::UIntLit(_)
            | CExpr::FloatLit(_)
            | CExpr::StringLit(_)
            | CExpr::CharLit(_) => true,
            CExpr::Var(_) => true,
            CExpr::Paren(inner) | CExpr::Cast { expr: inner, .. } => {
                self.is_return_inline_candidate(inner, depth + 1)
            }
            CExpr::Unary { operand, .. } => self.is_return_inline_candidate(operand, depth + 1),
            CExpr::Binary { op, left, right } => {
                matches!(
                    op,
                    BinaryOp::Add
                        | BinaryOp::Sub
                        | BinaryOp::Mul
                        | BinaryOp::Div
                        | BinaryOp::Mod
                        | BinaryOp::Shl
                        | BinaryOp::Shr
                        | BinaryOp::BitAnd
                        | BinaryOp::BitOr
                        | BinaryOp::BitXor
                        | BinaryOp::And
                        | BinaryOp::Or
                        | BinaryOp::Eq
                        | BinaryOp::Ne
                        | BinaryOp::Lt
                        | BinaryOp::Le
                        | BinaryOp::Gt
                        | BinaryOp::Ge
                ) && self.is_return_inline_candidate(left, depth + 1)
                    && self.is_return_inline_candidate(right, depth + 1)
            }
            CExpr::Deref(inner) => self
                .resolve_stack_alias_from_addr_expr(inner, 0)
                .filter(|alias| !should_replace_preserved_stack_alias(alias))
                .is_some(),
            _ => false,
        }
    }

    pub(crate) fn stack_alias_from_deref_expr(&self, expr: &CExpr) -> Option<String> {
        match expr {
            CExpr::Deref(inner) => self
                .resolve_stack_alias_from_addr_expr(inner, 0)
                .filter(|alias| !should_replace_preserved_stack_alias(alias)),
            CExpr::Paren(inner) => self.stack_alias_from_deref_expr(inner),
            CExpr::Cast { expr: inner, .. } => self.stack_alias_from_deref_expr(inner),
            _ => None,
        }
    }

    pub(super) fn expand_return_expr(
        &self,
        expr: &CExpr,
        depth: u32,
        visited: &mut HashSet<String>,
    ) -> CExpr {
        if depth > MAX_RETURN_EXPR_DEPTH {
            return expr.clone();
        }

        match expr {
            CExpr::Var(name) => {
                if let Some(val) = parse_const_value(name) {
                    return if val > 0x7fffffff {
                        CExpr::UIntLit(val)
                    } else {
                        CExpr::IntLit(val as i64)
                    };
                }
                if let Some(alias) = self.arg_alias_for_rendered_name(name) {
                    return CExpr::Var(alias);
                }
                if self.lookup_predicate_expr(name).is_some() {
                    return self.simplify_condition_expr(CExpr::Var(name.clone()));
                }

                let mut semantic_visited = HashSet::new();
                if let Some(semantic) =
                    self.render_semantic_value_by_name(name, 0, &mut semantic_visited)
                    && self.prefers_visible_expr(&CExpr::Var(name.clone()), &semantic)
                {
                    if !visited.insert(name.clone()) {
                        return semantic;
                    }
                    let resolved = self.expand_return_expr(&semantic, depth + 1, visited);
                    visited.remove(name);
                    return if self.is_predicate_like_expr(&resolved) {
                        self.simplify_condition_expr(resolved)
                    } else {
                        resolved
                    };
                }

                if let Some(candidate) = self.semanticized_raw_definition_candidate(name)
                    && self.prefers_visible_expr(&CExpr::Var(name.clone()), &candidate)
                {
                    if !visited.insert(name.clone()) {
                        return candidate;
                    }
                    let resolved = self.expand_return_expr(&candidate, depth + 1, visited);
                    visited.remove(name);
                    return if self.is_predicate_like_expr(&resolved) {
                        self.simplify_condition_expr(resolved)
                    } else {
                        resolved
                    };
                }

                if !self.should_inline_in_return(name, depth) || !visited.insert(name.clone()) {
                    return CExpr::Var(name.clone());
                }

                let resolved = self
                    .choose_preferred_visible_expr(
                        self.lookup_definition(name),
                        self.choose_preferred_visible_expr(
                            self.semanticized_raw_definition_candidate(name),
                            self.best_visible_definition(name),
                        ),
                    )
                    .map(|inner| self.expand_return_expr(&inner, depth + 1, visited))
                    .unwrap_or_else(|| CExpr::Var(name.clone()));

                visited.remove(name);
                if self.is_predicate_like_expr(&resolved) {
                    self.simplify_condition_expr(resolved)
                } else {
                    resolved
                }
            }
            CExpr::Deref(inner) => {
                if let CExpr::Var(name) = inner.as_ref()
                    && let Some(candidate) = self.semantic_deref_candidate_for_name(name)
                {
                    return candidate;
                }
                if let Some(stack_var) = self
                    .resolve_stack_alias_from_addr_expr(inner, 0)
                    .filter(|alias| !should_replace_preserved_stack_alias(alias))
                {
                    CExpr::Var(stack_var)
                } else {
                    let expanded_inner = self.expand_return_expr(inner, depth + 1, visited);
                    let mut semantic_visited = HashSet::new();
                    self.render_memory_access_from_visible_expr(
                        &expanded_inner,
                        0,
                        depth + 1,
                        &mut semantic_visited,
                    )
                    .unwrap_or_else(|| CExpr::Deref(Box::new(expanded_inner)))
                }
            }
            CExpr::Binary { op, left, right } => {
                let rebuilt = CExpr::binary(
                    *op,
                    self.expand_return_expr(left, depth + 1, visited),
                    self.expand_return_expr(right, depth + 1, visited),
                );
                if self.is_predicate_like_expr(&rebuilt) {
                    self.simplify_condition_expr(rebuilt)
                } else {
                    rebuilt
                }
            }
            CExpr::Paren(inner) => {
                CExpr::Paren(Box::new(self.expand_return_expr(inner, depth + 1, visited)))
            }
            CExpr::Cast { ty, expr: inner } => {
                let expanded_inner = self.expand_return_expr(inner, depth + 1, visited);
                let simplified_inner = if self.is_predicate_like_expr(&expanded_inner) {
                    self.simplify_condition_expr(expanded_inner)
                } else {
                    expanded_inner
                };
                CExpr::Cast {
                    ty: ty.clone(),
                    expr: Box::new(simplified_inner),
                }
            }
            _ => expr
                .clone()
                .map_children(&mut |child| self.expand_return_expr(&child, depth + 1, visited)),
        }
    }

    pub(super) fn get_return_expr(&self, var: &SSAVar) -> CExpr {
        if var.is_const() {
            return self.const_to_expr(var);
        }

        let mut visited = HashSet::new();
        let root_name = var.display_name();
        let unresolved = CExpr::Var(self.var_name(var));
        let mut semantic_visited = HashSet::new();
        let semantic_root = self
            .preferred_return_candidate(
                self.render_semantic_value_by_name(&root_name, 0, &mut semantic_visited),
                self.lookup_definition(&root_name),
            )
            .and_then(|expr| {
                self.preferred_return_candidate(
                    Some(expr),
                    self.semanticized_raw_definition_candidate(&root_name),
                )
            })
            .and_then(|expr| {
                self.preferred_return_candidate(
                    Some(expr),
                    self.best_visible_definition(&root_name),
                )
            })
            .or_else(|| self.lookup_definition(&root_name))
            .or_else(|| self.best_visible_definition(&root_name))
            .unwrap_or_else(|| unresolved.clone());
        let base_root = self
            .preferred_return_candidate(Some(semantic_root), Some(unresolved.clone()))
            .unwrap_or_else(|| unresolved.clone());
        let predicate_root = self.predicate_return_candidate(&unresolved, 0, &mut visited);
        let root = self
            .preferred_return_candidate(
                self.choose_preferred_visible_expr(
                    self.predicate_candidate_for_var(var),
                    predicate_root,
                ),
                Some(base_root),
            )
            .unwrap_or_else(|| unresolved.clone());
        let root = self.resolve_predicate_rhs_for_var(var, root);
        let raw = self.expand_return_expr(&root, 0, &mut visited);
        let mut semantic_visited = HashSet::new();
        let raw = self.semanticize_visible_expr(&raw, 0, &mut semantic_visited);
        let simplified = if self.is_predicate_like_expr(&raw) {
            self.simplify_condition_expr(raw)
        } else {
            raw
        };
        self.sanitize_return_expr(simplified, root, unresolved)
    }

    #[cfg(test)]
    pub(crate) fn debug_return_expr_stages(&self, var: &SSAVar) -> (CExpr, CExpr, CExpr) {
        let mut visited = HashSet::new();
        let root_name = var.display_name();
        let unresolved = CExpr::Var(self.var_name(var));
        let mut semantic_visited = HashSet::new();
        let semantic_root = self
            .preferred_return_candidate(
                self.render_semantic_value_by_name(&root_name, 0, &mut semantic_visited),
                self.lookup_definition(&root_name),
            )
            .and_then(|expr| {
                self.preferred_return_candidate(
                    Some(expr),
                    self.semanticized_raw_definition_candidate(&root_name),
                )
            })
            .and_then(|expr| {
                self.preferred_return_candidate(
                    Some(expr),
                    self.best_visible_definition(&root_name),
                )
            })
            .or_else(|| self.lookup_definition(&root_name))
            .or_else(|| self.best_visible_definition(&root_name))
            .unwrap_or_else(|| unresolved.clone());
        let base_root = self
            .preferred_return_candidate(Some(semantic_root), Some(unresolved.clone()))
            .unwrap_or_else(|| unresolved.clone());
        let predicate_root = self.predicate_return_candidate(&unresolved, 0, &mut visited);
        let root = self
            .preferred_return_candidate(
                self.choose_preferred_visible_expr(
                    self.predicate_candidate_for_var(var),
                    predicate_root,
                ),
                Some(base_root),
            )
            .unwrap_or_else(|| unresolved.clone());
        let root = self.resolve_predicate_rhs_for_var(var, root);
        let raw = self.expand_return_expr(&root, 0, &mut visited);
        let mut semantic_visited = HashSet::new();
        let semanticized = self.semanticize_visible_expr(&raw, 0, &mut semantic_visited);
        (root, raw, semanticized)
    }

    fn sanitize_return_expr(&self, expr: CExpr, fallback: CExpr, unresolved: CExpr) -> CExpr {
        self.preferred_return_candidate(
            self.preferred_return_candidate(Some(unresolved.clone()), Some(fallback)),
            Some(expr),
        )
        .unwrap_or(unresolved)
    }

    pub(super) fn sanitize_final_return_expr(&self, expr: CExpr, fallback: CExpr) -> CExpr {
        self.preferred_return_candidate(
            Some(self.resolve_return_candidate(&fallback)),
            Some(self.resolve_return_candidate(&expr)),
        )
        .unwrap_or_else(|| CExpr::Var("return".to_string()))
    }

    /// Convert an SSA variable to a C variable name.
    pub fn var_name(&self, var: &SSAVar) -> String {
        if var.is_const() {
            // Return the constant value directly
            let val = parse_const_value(&var.name).unwrap_or(0);
            if val > 0xffff {
                return format!("0x{:x}", val);
            } else {
                return format!("{}", val);
            }
        }

        if let Some(addr) = extract_call_address(&var.name) {
            if let Some(sym) = self.lookup_symbol(addr) {
                return sym.clone();
            }
            if let Some(name) = self.lookup_function(addr) {
                return name.clone();
            }
        }

        // Check if coalescing mapped this SSA name to a merged name
        let display = var.display_name();
        if let Some(alias) = self.var_aliases_map().get(&display) {
            return self
                .canonicalize_stack_name(alias)
                .unwrap_or_else(|| alias.clone());
        }

        if var.version == 0
            && let Some(alias) = self.arg_alias_for_register_name(&var.name)
        {
            return alias;
        }

        let base = if var.name.starts_with("reg:") {
            let reg = var.name.trim_start_matches("reg:");
            if is_hex_name(reg) {
                format!("r{}", reg)
            } else {
                reg.to_string()
            }
        } else if var.name.starts_with("tmp:") {
            format!("t{}", var.name.trim_start_matches("tmp:"))
        } else {
            var.name.to_lowercase()
        };

        if var.version > 0 {
            format!("{}_{}", base, var.version)
        } else {
            base
        }
    }

    /// Convert a constant variable to a C expression.
    pub(crate) fn const_to_expr(&self, var: &SSAVar) -> CExpr {
        let val = parse_const_value(&var.name).unwrap_or(0);

        // Only resolve addresses that are plausibly code/data (not small literals)
        if val > 0xff {
            // Check if this is a function address (e.g., for lea rdi, [main])
            if let Some(name) = self.lookup_function(val) {
                return CExpr::Var(name.clone());
            }

            // Check if this is a string address
            if let Some(s) = self.lookup_string(val) {
                return CExpr::StringLit(s.clone());
            }

            // Check if this is a symbol address
            if let Some(s) = self.lookup_symbol(val) {
                return CExpr::Var(s.clone());
            }
        }

        if val > 0x7fffffff {
            CExpr::UIntLit(val)
        } else {
            CExpr::IntLit(val as i64)
        }
    }
}
