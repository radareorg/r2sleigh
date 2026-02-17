use super::*;

impl<'a> FoldingContext<'a> {
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
            CExpr::Deref(inner) => self.resolve_stack_alias_from_addr_expr(inner, 0).is_some(),
            _ => false,
        }
    }

    pub(crate) fn stack_alias_from_deref_expr(&self, expr: &CExpr) -> Option<String> {
        match expr {
            CExpr::Deref(inner) => self.resolve_stack_alias_from_addr_expr(inner, 0),
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
                if let Some(inner) = self
                    .lookup_definition(name)
                    .or_else(|| self.formatted_defs_map().get(name).cloned())
                    && let CExpr::Var(inner_name) = inner
                {
                    if inner_name.starts_with("arg") {
                        return CExpr::Var(inner_name);
                    }
                    if let Some(alias) = self.arg_alias_for_rendered_name(&inner_name) {
                        return CExpr::Var(alias);
                    }
                }

                if !self.should_inline_in_return(name, depth) || !visited.insert(name.clone()) {
                    return CExpr::Var(name.clone());
                }

                let resolved = self
                    .lookup_definition(name)
                    .or_else(|| self.formatted_defs_map().get(name).cloned())
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
                if let Some(stack_var) = self.resolve_stack_alias_from_addr_expr(inner, 0) {
                    CExpr::Var(stack_var)
                } else {
                    let expanded_inner = self.expand_return_expr(inner, depth + 1, visited);
                    if let Some(sub) = self.try_subscript_from_addr_expr(&expanded_inner) {
                        sub
                    } else if let Some(member) =
                        self.try_member_access_from_addr_expr(None, &expanded_inner)
                    {
                        member
                    } else {
                        CExpr::Deref(Box::new(expanded_inner))
                    }
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
        let root = self
            .lookup_definition(&root_name)
            .unwrap_or(CExpr::Var(root_name));
        let raw = self.expand_return_expr(&root, 0, &mut visited);
        if self.is_predicate_like_expr(&raw) {
            self.simplify_condition_expr(raw)
        } else {
            raw
        }
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

        let base = if var.name.starts_with("reg:") {
            let reg = var.name.trim_start_matches("reg:");
            if is_hex_name(reg) {
                format!("r{}", reg)
            } else {
                reg.to_string()
            }
        } else if var.name.starts_with("tmp:") {
            format!("t{}", var.version)
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
