#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    use crate::{ExternalStackVar, FoldArchConfig, FoldInputs};
    use r2il::{R2ILBlock, R2ILOp, Varnode};
    use r2types::{
        ExternalField, ExternalStruct, ExternalTypeDb, Signedness, SolvedTypes,
        SolverDiagnostics, TypeArena,
    };

    fn make_var(name: &str, version: u32, size: u32) -> SSAVar {
        SSAVar::new(name, version, size)
    }

    fn make_block(ops: Vec<SSAOp>) -> SSABlock {
        SSABlock {
            addr: 0x1000,
            size: 4,
            ops,
            phis: Vec::new(),
        }
    }

    fn make_oracle_for_member(base: SSAVar, offset: u64, field_name: &str) -> SolvedTypes {
        let mut arena = TypeArena::default();
        let i32_ty = arena.int(32, Signedness::Signed);
        let st = arena.struct_named_or_existing("DemoStruct");
        let st = arena.struct_with_field(st, offset, Some(field_name.to_string()), i32_ty);
        let ptr = arena.ptr(st);
        let mut var_types = HashMap::new();
        var_types.insert(base, ptr);
        let top_id = arena.top();
        SolvedTypes {
            arena,
            var_types,
            diagnostics: SolverDiagnostics::default(),
            top_id,
        }
    }

    #[allow(dead_code)]
    fn make_oracle_for_members(base: SSAVar, fields: &[(u64, &str)]) -> SolvedTypes {
        let mut arena = TypeArena::default();
        let i32_ty = arena.int(32, Signedness::Signed);
        let mut st = arena.struct_named_or_existing("DemoStruct");
        for (offset, field_name) in fields {
            st = arena.struct_with_field(st, *offset, Some((*field_name).to_string()), i32_ty);
        }
        let ptr = arena.ptr(st);
        let mut var_types = HashMap::new();
        var_types.insert(base, ptr);
        let top_id = arena.top();
        SolvedTypes {
            arena,
            var_types,
            diagnostics: SolverDiagnostics::default(),
            top_id,
        }
    }

    fn make_aarch64_ctx<'a>() -> FoldingContext<'a> {
        let arch = Box::leak(Box::new(FoldArchConfig {
            ptr_size: 8,
            sp_name: "sp".to_string(),
            fp_name: "x29".to_string(),
            ret_reg_name: "x0".to_string(),
            arg_regs: vec![
                "x0".to_string(),
                "x1".to_string(),
                "x2".to_string(),
                "x3".to_string(),
                "x4".to_string(),
                "x5".to_string(),
                "x6".to_string(),
                "x7".to_string(),
            ],
            caller_saved_regs: HashSet::new(),
        }));
        let empty_u64 = Box::leak(Box::new(HashMap::new()));
        let empty_stack = Box::leak(Box::new(HashMap::new()));
        let empty_str = Box::leak(Box::new(HashMap::new()));
        let empty_fn = Box::leak(Box::new(HashMap::new()));
        let empty_ty = Box::leak(Box::new(HashMap::new()));
        FoldingContext::from_inputs(FoldInputs {
            arch,
            function_names: empty_u64,
            strings: empty_u64,
            symbols: empty_u64,
            known_function_signatures: empty_fn,
            external_stack_vars: empty_stack,
            external_type_db: Box::leak(Box::new(r2types::ExternalTypeDb::default())),
            param_register_aliases: empty_str,
            type_hints: empty_ty,
            type_oracle: None,
        })
    }

    fn expr_contains_binary_op(expr: &CExpr, target: BinaryOp) -> bool {
        match expr {
            CExpr::Binary { op, left, right } => {
                *op == target
                    || expr_contains_binary_op(left, target)
                    || expr_contains_binary_op(right, target)
            }
            CExpr::Unary { operand, .. } => expr_contains_binary_op(operand, target),
            CExpr::Paren(inner) => expr_contains_binary_op(inner, target),
            CExpr::Cast { expr: inner, .. } => expr_contains_binary_op(inner, target),
            _ => false,
        }
    }

    fn expr_contains_flag_artifact(expr: &CExpr) -> bool {
        match expr {
            CExpr::Var(name) => {
                let lower = name.to_lowercase();
                lower.starts_with("of_")
                    || lower.starts_with("zf_")
                    || lower.starts_with("sf_")
                    || lower.starts_with("cf_")
            }
            CExpr::Binary { left, right, .. } => {
                expr_contains_flag_artifact(left) || expr_contains_flag_artifact(right)
            }
            CExpr::Unary { operand, .. } => expr_contains_flag_artifact(operand),
            CExpr::Paren(inner) => expr_contains_flag_artifact(inner),
            CExpr::Cast { expr: inner, .. } => expr_contains_flag_artifact(inner),
            CExpr::Deref(inner) => expr_contains_flag_artifact(inner),
            CExpr::Subscript { base, index } => {
                expr_contains_flag_artifact(base) || expr_contains_flag_artifact(index)
            }
            CExpr::Member { base, .. } => expr_contains_flag_artifact(base),
            CExpr::PtrMember { base, .. } => expr_contains_flag_artifact(base),
            CExpr::Call { func, args } => {
                expr_contains_flag_artifact(func) || args.iter().any(expr_contains_flag_artifact)
            }
            _ => false,
        }
    }

    fn expr_contains_sub_zero_cmp_scaffold(expr: &CExpr) -> bool {
        fn is_zero(expr: &CExpr) -> bool {
            matches!(expr, CExpr::IntLit(0) | CExpr::UIntLit(0))
        }

        fn is_sub_zero(expr: &CExpr) -> bool {
            matches!(
                expr,
                CExpr::Binary {
                    op: BinaryOp::Sub,
                    right,
                    ..
                } if is_zero(right)
            )
        }

        match expr {
            CExpr::Binary { op, left, right } => {
                ((*op == BinaryOp::Eq || *op == BinaryOp::Ne)
                    && ((is_sub_zero(left) && is_zero(right))
                        || (is_sub_zero(right) && is_zero(left))))
                    || expr_contains_sub_zero_cmp_scaffold(left)
                    || expr_contains_sub_zero_cmp_scaffold(right)
            }
            CExpr::Unary { operand, .. } => expr_contains_sub_zero_cmp_scaffold(operand),
            CExpr::Paren(inner) => expr_contains_sub_zero_cmp_scaffold(inner),
            CExpr::Cast { expr: inner, .. } => expr_contains_sub_zero_cmp_scaffold(inner),
            CExpr::Deref(inner) => expr_contains_sub_zero_cmp_scaffold(inner),
            CExpr::Subscript { base, index } => {
                expr_contains_sub_zero_cmp_scaffold(base)
                    || expr_contains_sub_zero_cmp_scaffold(index)
            }
            CExpr::Member { base, .. } => expr_contains_sub_zero_cmp_scaffold(base),
            CExpr::PtrMember { base, .. } => expr_contains_sub_zero_cmp_scaffold(base),
            CExpr::Call { func, args } => {
                expr_contains_sub_zero_cmp_scaffold(func)
                    || args.iter().any(expr_contains_sub_zero_cmp_scaffold)
            }
            _ => false,
        }
    }

    #[test]
    fn test_constant_parsing() {
        assert_eq!(parse_const_value("const:0x42"), Some(0x42));
        assert_eq!(parse_const_value("const:42"), Some(42));
        assert_eq!(parse_const_value("const:fffffffc"), Some(0xfffffffc));
        assert_eq!(parse_const_value("const:0x42_0"), Some(0x42));
    }

    #[test]
    fn test_call_args_clamp_non_variadic_signature() {
        let mut ctx = FoldingContext::new(64);
        let mut names = HashMap::new();
        names.insert(0x401000, "sym.imp.memcpy".to_string());
        ctx.set_function_names(names);
        let mut sigs = HashMap::new();
        sigs.insert(
            "sym.imp.memcpy".to_string(),
            FunctionType {
                return_type: CType::void_ptr(),
                params: vec![CType::void_ptr(), CType::void_ptr(), CType::u64()],
                variadic: false,
            },
        );
        ctx.set_known_function_signatures(sigs);
        ctx.state.analysis_ctx.use_info.call_args.insert(
            (0x1000, 0),
            vec![
                CExpr::Var("a".to_string()),
                CExpr::Var("b".to_string()),
                CExpr::Var("c".to_string()),
                CExpr::Var("d".to_string()),
            ],
        );

        let stmt = ctx
            .op_to_stmt_with_args(
                &SSAOp::Call {
                    target: make_var("const:401000", 0, 8),
                },
                0x1000,
                0,
            )
            .expect("call should emit statement");

        let CStmt::Expr(CExpr::Call { args, .. }) = stmt else {
            panic!("expected call expression");
        };
        assert_eq!(args.len(), 3, "non-variadic call should clamp to arity");
    }

    #[test]
    fn test_call_args_do_not_clamp_variadic_signature() {
        let mut ctx = FoldingContext::new(64);
        let mut names = HashMap::new();
        names.insert(0x401010, "sym.imp.printf".to_string());
        ctx.set_function_names(names);
        let mut sigs = HashMap::new();
        sigs.insert(
            "sym.imp.printf".to_string(),
            FunctionType {
                return_type: CType::Int(32),
                params: vec![CType::ptr(CType::Int(8))],
                variadic: true,
            },
        );
        ctx.set_known_function_signatures(sigs);
        ctx.state.analysis_ctx.use_info.call_args.insert(
            (0x1000, 0),
            vec![
                CExpr::Var("fmt".to_string()),
                CExpr::Var("x".to_string()),
                CExpr::Var("y".to_string()),
            ],
        );

        let stmt = ctx
            .op_to_stmt_with_args(
                &SSAOp::Call {
                    target: make_var("const:401010", 0, 8),
                },
                0x1000,
                0,
            )
            .expect("call should emit statement");

        let CStmt::Expr(CExpr::Call { args, .. }) = stmt else {
            panic!("expected call expression");
        };
        assert_eq!(
            args.len(),
            3,
            "variadic call should keep all discovered call arguments"
        );
    }

    #[test]
    fn test_registry_arity_resolution_handles_prefixed_and_ssa_suffixed_names() {
        let ctx = FoldingContext::new(64);
        assert_eq!(
            ctx.non_variadic_call_arity(&CExpr::Var("sym.imp.strcmp".to_string())),
            Some(2)
        );
        assert_eq!(
            ctx.non_variadic_call_arity(&CExpr::Var("sym.imp.strcmp_0".to_string())),
            Some(2)
        );
    }

    #[test]
    fn test_registry_arity_can_cap_broken_known_signature_arity() {
        let mut ctx = FoldingContext::new(64);
        let mut sigs = HashMap::new();
        sigs.insert(
            "sym.imp.strcmp".to_string(),
            FunctionType {
                return_type: CType::Int(32),
                params: vec![CType::void_ptr(), CType::void_ptr(), CType::void_ptr()],
                variadic: false,
            },
        );
        ctx.set_known_function_signatures(sigs);

        assert_eq!(
            ctx.non_variadic_call_arity(&CExpr::Var("sym.imp.strcmp".to_string())),
            Some(2),
            "embedded registry should cap malformed known signature arity for common libc calls"
        );
    }

    #[test]
    fn test_is_cpu_flag() {
        assert!(is_cpu_flag("cf"));
        assert!(is_cpu_flag("zf"));
        assert!(is_cpu_flag("sf"));
        assert!(is_cpu_flag("cf_1"));
        assert!(!is_cpu_flag("rax"));
        assert!(!is_cpu_flag("rbp"));
    }

    #[test]
    fn test_dead_flag_elimination() {
        let rax_0 = make_var("RAX", 0, 8);
        let rax_1 = make_var("RAX", 1, 8);
        let zf_1 = make_var("ZF", 1, 1);
        let const_1 = make_var("const:1", 0, 8);

        let block = make_block(vec![
            // RAX_1 = RAX_0 + 1 (used)
            SSAOp::IntAdd {
                dst: rax_1.clone(),
                a: rax_0.clone(),
                b: const_1.clone(),
            },
            // ZF_1 = RAX_1 == 0 (not used - should be eliminated)
            SSAOp::IntEqual {
                dst: zf_1.clone(),
                a: rax_1.clone(),
                b: make_var("const:0", 0, 8),
            },
            // Store RAX_1 (uses RAX_1)
            SSAOp::Store {
                space: "ram".to_string(),
                addr: make_var("const:0x1000", 0, 8),
                val: rax_1,
            },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);

        // ZF_1 should be dead (flag, not used)
        assert!(ctx.is_dead(&zf_1));
    }

    #[test]
    fn test_single_use_inlining() {
        let rax_0 = make_var("RAX", 0, 8);
        let rbx_0 = make_var("RBX", 0, 8);
        let t0 = make_var("tmp:100", 0, 8);
        let t1 = make_var("tmp:100", 1, 8);

        let block = make_block(vec![
            // t0 = rax_0 + rbx_0 (single use)
            SSAOp::IntAdd {
                dst: t0.clone(),
                a: rax_0.clone(),
                b: rbx_0.clone(),
            },
            // t1 = t0 * 2
            SSAOp::IntMult {
                dst: t1.clone(),
                a: t0.clone(),
                b: make_var("const:2", 0, 8),
            },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);

        // t0 should be inlined (single use, temp)
        assert!(ctx.should_inline(&t0.display_name()));
    }

    #[test]
    fn test_multi_use_simple_temp_inlining() {
        let rax_0 = make_var("RAX", 0, 8);
        let t0 = make_var("tmp:200", 1, 8);
        let t1 = make_var("tmp:201", 1, 8);
        let t2 = make_var("tmp:202", 1, 8);

        let block = make_block(vec![
            SSAOp::IntAdd {
                dst: t0.clone(),
                a: rax_0,
                b: make_var("const:1", 0, 8),
            },
            SSAOp::IntAdd {
                dst: t1.clone(),
                a: t0.clone(),
                b: t0.clone(),
            },
            SSAOp::IntAdd {
                dst: t2,
                a: t1,
                b: t0.clone(),
            },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);

        // t0 has 3 uses but remains simple enough to inline.
        assert!(ctx.should_inline(&t0.display_name()));
    }

    #[test]
    fn test_fold_block() {
        let rax_0 = make_var("RAX", 0, 8);
        let rax_1 = make_var("RAX", 1, 8);
        let zf_1 = make_var("ZF", 1, 1);
        let const_1 = make_var("const:1", 0, 8);

        let block = make_block(vec![
            // RAX_1 = RAX_0 + 1
            SSAOp::IntAdd {
                dst: rax_1.clone(),
                a: rax_0.clone(),
                b: const_1.clone(),
            },
            // ZF_1 = RAX_1 == 0 (unused flag)
            SSAOp::IntEqual {
                dst: zf_1.clone(),
                a: rax_1.clone(),
                b: make_var("const:0", 0, 8),
            },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);
        let stmts = ctx.fold_block(&block, block.addr);

        // RAX_1 is used only once (in the dead ZF_1 expression), so with stronger
        // inlining it gets inlined into the dead expression, which is then eliminated.
        // Both statements should be eliminated.
        assert_eq!(stmts.len(), 0);
    }

    #[test]
    fn test_member_access_uses_oracle_field_name() {
        let base = make_var("arg1", 0, 8);
        let addr = make_var("tmp:9100", 1, 8);
        let dst = make_var("tmp:9101", 1, 4);
        let block = make_block(vec![
            SSAOp::IntAdd {
                dst: addr.clone(),
                a: base.clone(),
                b: make_var("const:0x30", 0, 8),
            },
            SSAOp::Load {
                dst: dst.clone(),
                space: "ram".to_string(),
                addr: addr.clone(),
            },
        ]);

        let mut ctx = FoldingContext::new(64);
        let mut hints = HashMap::new();
        hints.insert(base.display_name(), CType::ptr(CType::Int(32)));
        ctx.set_type_hints(hints);
        let oracle = make_oracle_for_member(base, 0x30, "thirteenth");
        ctx.set_type_oracle(Some(&oracle));
        ctx.analyze_block(&block);

        let expr = ctx.op_to_expr(&SSAOp::Load {
            dst,
            space: "ram".to_string(),
            addr,
        });
        let CExpr::PtrMember { member, .. } = expr else {
            panic!("expected pointer member access");
        };
        assert_eq!(member, "thirteenth");
    }

    #[test]
    fn test_member_access_falls_back_without_oracle_name() {
        let base = make_var("arg1", 0, 8);
        let addr = make_var("tmp:9200", 1, 8);
        let dst = make_var("tmp:9201", 1, 4);
        let block = make_block(vec![
            SSAOp::IntAdd {
                dst: addr.clone(),
                a: base.clone(),
                b: make_var("const:0x30", 0, 8),
            },
            SSAOp::Load {
                dst: dst.clone(),
                space: "ram".to_string(),
                addr: addr.clone(),
            },
        ]);

        let mut ctx = FoldingContext::new(64);
        let mut hints = HashMap::new();
        hints.insert(base.display_name(), CType::ptr(CType::Int(32)));
        ctx.set_type_hints(hints);
        ctx.analyze_block(&block);

        let expr = ctx.op_to_expr(&SSAOp::Load {
            dst,
            space: "ram".to_string(),
            addr,
        });
        assert!(
            !matches!(expr, CExpr::PtrMember { .. } | CExpr::Member { .. }),
            "member syntax should not be invented without oracle-backed field names"
        );
    }

    #[test]
    fn test_get_return_expr_semanticizes_raw_member_derefs_from_typed_base() {
        let base = make_var("arg1", 0, 8);
        let ret = make_var("tmp:9300", 1, 8);
        let mut arena = TypeArena::default();
        let i32_ty = arena.int(32, Signedness::Signed);
        let st = arena.struct_named_or_existing("DemoStruct");
        let st = arena.struct_with_field(st, 0, Some("first".to_string()), i32_ty);
        let st = arena.struct_with_field(st, 0x30, Some("thirteenth".to_string()), i32_ty);
        let ptr = arena.ptr(st);
        let mut var_types = HashMap::new();
        var_types.insert(base.clone(), ptr);
        let top_id = arena.top();
        let oracle = SolvedTypes {
            arena,
            var_types,
            diagnostics: SolverDiagnostics::default(),
            top_id,
        };

        let mut ctx = FoldingContext::new(64);
        ctx.set_type_oracle(Some(&oracle));
        ctx.state.analysis_ctx.use_info.definitions.insert(
            ret.display_name(),
            CExpr::binary(
                BinaryOp::Add,
                CExpr::Deref(Box::new(CExpr::binary(
                    BinaryOp::Add,
                    CExpr::Var(base.display_name()),
                    CExpr::IntLit(0x30),
                ))),
                CExpr::Deref(Box::new(CExpr::Var(base.display_name()))),
            ),
        );

        let expr = ctx.get_return_expr(&ret);
        let CExpr::Binary { left, right, .. } = expr else {
            panic!("expected semanticized binary return");
        };
        assert!(
            matches!(left.as_ref(), CExpr::PtrMember { member, .. } if member == "thirteenth"),
            "expected left side to resolve to thirteenth field, got {left:?}"
        );
        assert!(
            matches!(right.as_ref(), CExpr::PtrMember { member, .. } if member == "first"),
            "expected right side to resolve to first field, got {right:?}"
        );
    }

    #[test]
    fn test_get_return_expr_semanticizes_raw_member_derefs_from_visible_arg_alias() {
        let base_ssa = make_var("X0", 0, 8);
        let ret = make_var("tmp:9301", 1, 8);
        let mut arena = TypeArena::default();
        let i32_ty = arena.int(32, Signedness::Signed);
        let st = arena.struct_named_or_existing("DemoStruct");
        let st = arena.struct_with_field(st, 0, Some("first".to_string()), i32_ty);
        let st = arena.struct_with_field(st, 0x30, Some("thirteenth".to_string()), i32_ty);
        let ptr = arena.ptr(st);
        let mut var_types = HashMap::new();
        var_types.insert(base_ssa, ptr);
        let top_id = arena.top();
        let oracle = SolvedTypes {
            arena,
            var_types,
            diagnostics: SolverDiagnostics::default(),
            top_id,
        };

        let mut ctx = FoldingContext::new(64);
        ctx.set_type_oracle(Some(&oracle));
        ctx.state.analysis_ctx.use_info.definitions.insert(
            ret.display_name(),
            CExpr::binary(
                BinaryOp::Add,
                CExpr::Deref(Box::new(CExpr::binary(
                    BinaryOp::Add,
                    CExpr::Var("arg1".to_string()),
                    CExpr::IntLit(0x30),
                ))),
                CExpr::Deref(Box::new(CExpr::Var("arg1".to_string()))),
            ),
        );

        let expr = ctx.get_return_expr(&ret);
        let CExpr::Binary { left, right, .. } = expr else {
            panic!("expected semanticized binary return");
        };
        assert!(
            matches!(left.as_ref(), CExpr::PtrMember { member, .. } if member == "thirteenth"),
            "expected left side to resolve visible arg alias back to the SSA-backed field, got {left:?}"
        );
        assert!(
            matches!(right.as_ref(), CExpr::PtrMember { member, .. } if member == "first"),
            "expected right side to resolve visible arg alias back to the SSA-backed field, got {right:?}"
        );
    }

    #[test]
    fn test_subscript_rejects_pointer_typed_local_as_index_and_uses_scalar_index() {
        let arr = make_var("arg1", 0, 8);
        let addr = make_var("tmp:9300", 1, 8);
        let load = make_var("tmp:9301", 1, 4);
        let bogus_index = make_var("tmp:9302", 1, 8);
        let real_index = make_var("tmp:9303", 1, 4);

        let mut ctx = FoldingContext::new(64);
        ctx.state.analysis_ctx.use_info.ptr_arith.insert(
            addr.display_name(),
            PtrArith {
                base: arr.clone(),
                index: bogus_index.clone(),
                element_size: 4,
                is_sub: false,
            },
        );
        ctx.state.analysis_ctx.use_info.definitions.insert(
            bogus_index.display_name(),
            CExpr::Var("local_8".to_string()),
        );
        ctx.state.analysis_ctx.use_info.definitions.insert(
            addr.display_name(),
            CExpr::binary(
                BinaryOp::Add,
                CExpr::Var("arg1".to_string()),
                CExpr::binary(
                    BinaryOp::Mul,
                    CExpr::Var("local_c".to_string()),
                    CExpr::IntLit(4),
                ),
            ),
        );
        ctx.state
            .analysis_ctx
            .use_info
            .type_hints
            .insert("local_8".to_string(), CType::ptr(CType::Int(32)));
        ctx.state
            .analysis_ctx
            .use_info
            .type_hints
            .insert("local_c".to_string(), CType::Int(32));
        ctx.state.analysis_ctx.use_info.definitions.insert(
            real_index.display_name(),
            CExpr::Var("local_c".to_string()),
        );
        ctx.state.analysis_ctx.use_info.semantic_values.insert(
            real_index.display_name(),
            crate::analysis::SemanticValue::Scalar(crate::analysis::ScalarValue::Expr(
                CExpr::Var("local_c".to_string()),
            )),
        );
        ctx.state.analysis_ctx.use_info.semantic_values.insert(
            load.display_name(),
            crate::analysis::SemanticValue::Load {
                addr: crate::analysis::NormalizedAddr {
                    base: crate::analysis::BaseRef::Value(crate::analysis::ValueRef::from(
                        arr.clone(),
                    )),
                    index: Some(crate::analysis::ValueRef::from(real_index.clone())),
                    scale_bytes: 4,
                    offset_bytes: 0,
                },
                size: 4,
            },
        );

        let mut visited = HashSet::new();
        let expr = ctx
            .render_semantic_value(
                ctx.state
                    .analysis_ctx
                    .use_info
                    .semantic_values
                    .get(&load.display_name())
                    .expect("semantic load should exist"),
                0,
                &mut visited,
            )
            .expect("semantic load should render");
        let CExpr::Subscript { ref index, .. } = expr else {
            panic!("expected subscript expression, got {expr:?}");
        };
        assert!(
            matches!(index.as_ref(), CExpr::Var(name) if name == "local_c"),
            "typed pointer locals must not survive as subscript indices, got {expr:?}"
        );
    }

    #[test]
    fn test_member_access_uses_subscript_base_when_base_has_generic_ptr_arith_definition() {
        let idx = make_var("arg2", 0, 4);
        let base = make_var("tmp:9400", 1, 8);
        let addr = make_var("tmp:9401", 1, 8);
        let dst = make_var("tmp:9402", 1, 4);
        let mut ctx = FoldingContext::new(64);
        ctx.state.analysis_ctx.use_info.ptr_members.insert(
            addr.display_name(),
            (base.clone(), 8),
        );
        ctx.state.analysis_ctx.use_info.definitions.insert(
            base.display_name(),
            CExpr::binary(
                BinaryOp::Add,
                CExpr::Var("arg1".to_string()),
                CExpr::binary(
                    BinaryOp::Mul,
                    CExpr::Var("arg2".to_string()),
                    CExpr::IntLit(56),
                ),
            ),
        );
        ctx.state.analysis_ctx.use_info.type_hints.insert(
            base.display_name(),
            CType::ptr(CType::Struct("DemoStruct".to_string())),
        );
        ctx.state.analysis_ctx.use_info.semantic_values.insert(
            dst.display_name(),
            crate::analysis::SemanticValue::Load {
                addr: crate::analysis::NormalizedAddr {
                    base: crate::analysis::BaseRef::Value(crate::analysis::ValueRef::from(
                        make_var("arg1", 0, 8),
                    )),
                    index: Some(crate::analysis::ValueRef::from(idx.clone())),
                    scale_bytes: 56,
                    offset_bytes: 8,
                },
                size: 4,
            },
        );
        let oracle = make_oracle_for_member(base.clone(), 8, "third");
        ctx.set_type_oracle(Some(&oracle));

        let semantic = ctx
            .state
            .analysis_ctx
            .use_info
            .semantic_values
            .get(&dst.display_name())
            .expect("semantic member load should exist");
        let crate::analysis::SemanticValue::Load { addr, .. } = semantic
        else {
            panic!("expected semantic member load, got {semantic:?}");
        };
        assert_eq!(addr.offset_bytes, 8);
        assert!(
            addr.index.is_some() && addr.scale_bytes == 56,
            "generic ptr-arith base should stay as indexed semantic shape before rendering"
        );
        let _ = idx;
    }

    #[test]
    fn test_subscript_reconstructs_shift_scaled_index_expression() {
        let addr = make_var("tmp:9500", 1, 8);
        let dst = make_var("tmp:9501", 1, 4);
        let mut ctx = FoldingContext::new(64);
        ctx.state
            .analysis_ctx
            .use_info
            .type_hints
            .insert("arg1".to_string(), CType::ptr(CType::Int(32)));
        ctx.state
            .analysis_ctx
            .use_info
            .type_hints
            .insert("arg2".to_string(), CType::Int(32));
        ctx.state.analysis_ctx.use_info.definitions.insert(
            addr.display_name(),
            CExpr::binary(
                BinaryOp::Add,
                CExpr::Var("arg1".to_string()),
                CExpr::binary(
                    BinaryOp::Shl,
                    CExpr::Var("arg2".to_string()),
                    CExpr::IntLit(2),
                ),
            ),
        );
        ctx.state.analysis_ctx.use_info.semantic_values.insert(
            dst.display_name(),
            crate::analysis::SemanticValue::Load {
                addr: crate::analysis::NormalizedAddr {
                    base: crate::analysis::BaseRef::Value(crate::analysis::ValueRef::from(
                        make_var("arg1", 0, 8),
                    )),
                    index: Some(crate::analysis::ValueRef::from(make_var("arg2", 0, 4))),
                    scale_bytes: 4,
                    offset_bytes: 0,
                },
                size: 4,
            },
        );

        let mut visited = HashSet::new();
        let expr = ctx
            .render_semantic_value(
                ctx.state
                    .analysis_ctx
                    .use_info
                    .semantic_values
                    .get(&dst.display_name())
                    .expect("semantic load should exist"),
                0,
                &mut visited,
            )
            .expect("semantic load should render");
        let CExpr::Subscript { index, .. } = expr else {
            panic!("expected subscript expression, got {expr:?}");
        };
        assert!(
            matches!(index.as_ref(), CExpr::Var(name) if name == "arg2"),
            "shift-scaled index must preserve the semantic scalar index"
        );
    }

    #[test]
    fn test_member_access_reconstructs_combined_struct_array_index_scale() {
        let base = make_var("tmp:9600", 1, 8);
        let addr = make_var("tmp:9601", 1, 8);
        let dst = make_var("tmp:9602", 1, 4);
        let mut ctx = FoldingContext::new(64);
        ctx.state.analysis_ctx.use_info.ptr_members.insert(
            addr.display_name(),
            (base.clone(), 8),
        );
        ctx.state.analysis_ctx.use_info.definitions.insert(
            base.display_name(),
            CExpr::binary(
                BinaryOp::Add,
                CExpr::Var("arr".to_string()),
                CExpr::binary(
                    BinaryOp::Shl,
                    CExpr::binary(
                        BinaryOp::Sub,
                        CExpr::binary(
                            BinaryOp::Shl,
                            CExpr::Var("idx".to_string()),
                            CExpr::IntLit(3),
                        ),
                        CExpr::Var("idx".to_string()),
                    ),
                    CExpr::IntLit(3),
                ),
            ),
        );
        ctx.state
            .analysis_ctx
            .use_info
            .type_hints
            .insert("arr".to_string(), CType::ptr(CType::Struct("DemoStruct".to_string())));
        ctx.state
            .analysis_ctx
            .use_info
            .type_hints
            .insert("idx".to_string(), CType::Int(32));
        ctx.state.analysis_ctx.use_info.semantic_values.insert(
            dst.display_name(),
            crate::analysis::SemanticValue::Load {
                addr: crate::analysis::NormalizedAddr {
                    base: crate::analysis::BaseRef::Value(crate::analysis::ValueRef::from(
                        make_var("arr", 0, 8),
                    )),
                    index: Some(crate::analysis::ValueRef::from(make_var("idx", 0, 4))),
                    scale_bytes: 56,
                    offset_bytes: 8,
                },
                size: 4,
            },
        );
        let oracle = make_oracle_for_member(base.clone(), 8, "third");
        ctx.set_type_oracle(Some(&oracle));

        let semantic = ctx
            .state
            .analysis_ctx
            .use_info
            .semantic_values
            .get(&dst.display_name())
            .expect("semantic member load should exist");
        let crate::analysis::SemanticValue::Load { addr, .. } = semantic
        else {
            panic!("expected semantic member load, got {semantic:?}");
        };
        assert_eq!(addr.offset_bytes, 8);
        let Some(index) = &addr.index else {
            panic!("expected semantic indexed base, got {addr:?}");
        };
        assert!(
            index.var.name == "idx" && index.var.version == 0,
            "combined shift/sub scale should still recover the real struct-array index, got {index:?}"
        );
    }

    #[test]
    fn test_live_arm64_struct_array_store_keeps_semantic_base_after_stack_override_pass() {
        let sp0 = make_var("SP", 0, 8);
        let sp1 = make_var("SP", 1, 8);
        let x0 = make_var("X0", 0, 8);
        let w1 = make_var("W1", 0, 4);
        let w2 = make_var("W2", 0, 4);
        let tmp6500_1 = make_var("tmp:6500", 1, 8);
        let tmp6400_1 = make_var("tmp:6400", 1, 8);
        let tmp6500_2 = make_var("tmp:6500", 2, 8);
        let x9_1 = make_var("X9", 1, 8);
        let tmp6400_2 = make_var("tmp:6400", 2, 8);
        let tmp26b00_1 = make_var("tmp:26b00", 1, 4);
        let x10_1 = make_var("X10", 1, 8);
        let x10_2 = make_var("X10", 2, 8);
        let tmp12480_1 = make_var("tmp:12480", 1, 8);
        let x9_2 = make_var("X9", 2, 8);
        let tmp6400_3 = make_var("tmp:6400", 3, 8);

        let block = make_block(vec![
            SSAOp::IntSub {
                dst: sp1.clone(),
                a: sp0,
                b: make_var("const:10", 0, 8),
            },
            SSAOp::IntAdd {
                dst: tmp6500_1.clone(),
                a: sp1.clone(),
                b: make_var("const:8", 0, 8),
            },
            SSAOp::Store {
                space: "ram".to_string(),
                addr: tmp6500_1,
                val: x0.clone(),
            },
            SSAOp::IntAdd {
                dst: tmp6400_1.clone(),
                a: sp1.clone(),
                b: make_var("const:4", 0, 8),
            },
            SSAOp::Store {
                space: "ram".to_string(),
                addr: tmp6400_1,
                val: w1.clone(),
            },
            SSAOp::IntAdd {
                dst: tmp6500_2.clone(),
                a: sp1.clone(),
                b: make_var("const:8", 0, 8),
            },
            SSAOp::Load {
                dst: x9_1.clone(),
                space: "ram".to_string(),
                addr: tmp6500_2,
            },
            SSAOp::IntAdd {
                dst: tmp6400_2.clone(),
                a: sp1,
                b: make_var("const:4", 0, 8),
            },
            SSAOp::Load {
                dst: tmp26b00_1.clone(),
                space: "ram".to_string(),
                addr: tmp6400_2,
            },
            SSAOp::IntSExt {
                dst: x10_1.clone(),
                src: tmp26b00_1,
            },
            SSAOp::IntMult {
                dst: x10_2.clone(),
                a: x10_1,
                b: make_var("const:38", 0, 8),
            },
            SSAOp::IntAdd {
                dst: tmp12480_1.clone(),
                a: x9_1,
                b: x10_2,
            },
            SSAOp::Copy {
                dst: x9_2.clone(),
                src: tmp12480_1,
            },
            SSAOp::IntAdd {
                dst: tmp6400_3.clone(),
                a: x9_2,
                b: make_var("const:8", 0, 8),
            },
            SSAOp::Store {
                space: "ram".to_string(),
                addr: tmp6400_3.clone(),
                val: w2,
            },
        ]);

        let mut ctx = make_aarch64_ctx();
        ctx.inputs.param_register_aliases = Box::leak(Box::new(
            [("x0".to_string(), "arg1".to_string()), ("x1".to_string(), "arg2".to_string())]
                .into_iter()
                .collect(),
        ));
        ctx.set_type_hints(
            [
                ("arg1".to_string(), CType::ptr(CType::Struct("DemoStruct".to_string()))),
                ("arg2".to_string(), CType::Int(32)),
            ]
            .into_iter()
            .collect(),
        );
        let oracle = make_oracle_for_members(x0.clone(), &[(8, "third"), (0x34, "fourteenth")]);
        ctx.set_type_oracle(Some(&oracle));
        ctx.analyze_block(&block);

        assert!(matches!(
            ctx.lookup_semantic_value(&tmp6400_3.display_name()),
            Some(crate::analysis::SemanticValue::Address(crate::analysis::NormalizedAddr {
                base: crate::analysis::BaseRef::Value(value_ref),
                index: Some(_),
                scale_bytes: 56,
                offset_bytes: 8,
            })) if value_ref.var == x0
        ));

        let mut visited = HashSet::new();
        let rendered = ctx
            .render_memory_access_by_name(&tmp6400_3.display_name(), 4, 0, &mut visited)
            .expect("semantic store lhs should render");
        assert!(
            matches!(
                rendered,
                CExpr::Member { .. } | CExpr::PtrMember { .. }
            ),
            "semantic store lhs should render as member access, got {rendered:?}"
        );
        let rendered_text = format!("{rendered:?}");
        assert!(
            rendered_text.contains("arg1") && !rendered_text.contains("stack_8"),
            "semantic member access should stay rooted at arg1, got {rendered:?}"
        );
    }

    #[test]
    fn test_indexed_member_render_uses_external_layout_hint_without_solver_type() {
        let base = make_var("X0", 0, 8);
        let index = make_var("W1", 0, 4);
        let addr = make_var("tmp:6400", 3, 8);

        let mut ctx = make_aarch64_ctx();
        ctx.inputs.param_register_aliases = Box::leak(Box::new(
            [("x0".to_string(), "arg1".to_string()), ("x1".to_string(), "arg2".to_string())]
                .into_iter()
                .collect(),
        ));
        ctx.set_type_hints(
            [
                (
                    "arg1".to_string(),
                    CType::ptr(CType::Struct("demo_layout".to_string())),
                ),
                ("arg2".to_string(), CType::Int(32)),
            ]
            .into_iter()
            .collect(),
        );
        ctx.inputs.external_type_db = Box::leak(Box::new(ExternalTypeDb {
            structs: [(
                "demo_layout".to_string(),
                ExternalStruct {
                    name: "demo_layout".to_string(),
                    fields: [
                        (
                            8,
                            ExternalField {
                                name: "third".to_string(),
                                offset: 8,
                                ty: Some("int32_t".to_string()),
                            },
                        ),
                        (
                            0x34,
                            ExternalField {
                                name: "fourteenth".to_string(),
                                offset: 0x34,
                                ty: Some("int32_t".to_string()),
                            },
                        ),
                    ]
                    .into_iter()
                    .collect(),
                },
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        }));
        ctx.state.analysis_ctx.use_info.semantic_values.insert(
            addr.display_name(),
            crate::analysis::SemanticValue::Address(crate::analysis::NormalizedAddr {
                base: crate::analysis::BaseRef::Value(crate::analysis::ValueRef::from(base)),
                index: Some(crate::analysis::ValueRef::from(index)),
                scale_bytes: 56,
                offset_bytes: 8,
            }),
        );

        let mut visited = HashSet::new();
        let rendered = ctx
            .render_memory_access_by_name(&addr.display_name(), 4, 0, &mut visited)
            .expect("indexed member with external layout hint should render");
        let rendered_text = format!("{rendered:?}");
        assert!(
            matches!(rendered, CExpr::Member { .. } | CExpr::PtrMember { .. }),
            "expected indexed-member render, got {rendered:?}"
        );
        assert!(
            rendered_text.contains("third") && rendered_text.contains("arg1"),
            "expected layout-backed field render rooted at arg1, got {rendered:?}"
        );
    }

    #[test]
    fn test_load_generic_deref_inserts_minimal_pointer_cast() {
        let addr = make_var("tmp:9300", 1, 8);
        let dst = make_var("tmp:9301", 1, 4);
        let block = make_block(vec![SSAOp::Load {
            dst: dst.clone(),
            space: "ram".to_string(),
            addr: addr.clone(),
        }]);

        let mut ctx = FoldingContext::new(64);
        let mut hints = HashMap::new();
        hints.insert(addr.display_name(), CType::Int(64));
        hints.insert(dst.display_name(), CType::Int(32));
        ctx.set_type_hints(hints);
        ctx.analyze_block(&block);

        let stmt = ctx
            .op_to_stmt(&SSAOp::Load {
                dst,
                space: "ram".to_string(),
                addr,
            })
            .expect("load should emit statement");
        let CStmt::Expr(CExpr::Binary {
            op: BinaryOp::Assign,
            right,
            ..
        }) = stmt
        else {
            panic!("expected assignment expression");
        };
        let CExpr::Deref(inner) = right.as_ref() else {
            panic!("expected dereference expression");
        };
        assert!(
            matches!(
                inner.as_ref(),
                CExpr::Cast {
                    ty: CType::Pointer(_),
                    ..
                }
            ),
            "generic deref should cast integer-ish address to typed pointer"
        );
    }

    #[test]
    fn test_load_generic_deref_avoids_redundant_pointer_cast() {
        let addr = make_var("arg1", 0, 8);
        let dst = make_var("tmp:9401", 1, 4);
        let block = make_block(vec![SSAOp::Load {
            dst: dst.clone(),
            space: "ram".to_string(),
            addr: addr.clone(),
        }]);

        let mut ctx = FoldingContext::new(64);
        let mut hints = HashMap::new();
        hints.insert(addr.display_name(), CType::ptr(CType::Int(32)));
        hints.insert(dst.display_name(), CType::Int(32));
        ctx.set_type_hints(hints);
        ctx.analyze_block(&block);

        let stmt = ctx
            .op_to_stmt(&SSAOp::Load {
                dst,
                space: "ram".to_string(),
                addr,
            })
            .expect("load should emit statement");
        let CStmt::Expr(CExpr::Binary {
            op: BinaryOp::Assign,
            right,
            ..
        }) = stmt
        else {
            panic!("expected assignment expression");
        };
        let CExpr::Deref(inner) = right.as_ref() else {
            panic!("expected dereference expression");
        };
        assert!(
            !matches!(
                inner.as_ref(),
                CExpr::Cast {
                    ty: CType::Pointer(_),
                    ..
                }
            ),
            "address already typed as pointer should not get an extra cast"
        );
    }

    #[test]
    fn test_comparison_reconstruction() {
        // Test that CMP instruction pattern is reconstructed:
        // IntSub tmp = a - 0xdead
        // IntEqual ZF = tmp == 0
        // BoolNot cond = !ZF
        // CBranch cond  -> should become "if (a != 0xdead)"

        let edi_0 = make_var("EDI", 0, 4);
        let tmp_sub = make_var("tmp:1000", 1, 4);
        let zf_1 = make_var("ZF", 1, 1);
        let cond = make_var("tmp:2000", 1, 1);
        let const_dead = make_var("const:dead", 0, 4);
        let const_0 = make_var("const:0", 0, 4);

        let block = make_block(vec![
            // tmp_sub = edi_0 - 0xdead (the CMP)
            SSAOp::IntSub {
                dst: tmp_sub.clone(),
                a: edi_0.clone(),
                b: const_dead.clone(),
            },
            // ZF = tmp_sub == 0
            SSAOp::IntEqual {
                dst: zf_1.clone(),
                a: tmp_sub.clone(),
                b: const_0.clone(),
            },
            // cond = !ZF
            SSAOp::BoolNot {
                dst: cond.clone(),
                src: zf_1.clone(),
            },
            // CBranch cond
            SSAOp::CBranch {
                cond: cond.clone(),
                target: make_var("const:1000", 0, 8),
            },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);

        // Check that flag_origins was populated
        assert!(
            ctx.flag_origins_map().contains_key("ZF_1"),
            "ZF_1 should be in flag_origins"
        );

        // Check the origin values
        let (left, right) = ctx.flag_origins_map().get("ZF_1").unwrap();
        assert_eq!(left, "edi", "Left operand should be edi");
        assert_eq!(right, "0xdead", "Right operand should be 0xdead");
    }

    #[test]
    fn test_flag_only_transitive_marking() {
        let edi_0 = make_var("EDI", 0, 4);
        let tmp = make_var("tmp:3000", 1, 4);
        let zf_1 = make_var("ZF", 1, 1);
        let cond = make_var("tmp:3001", 1, 1);
        let const_0 = make_var("const:0", 0, 4);

        let block = make_block(vec![
            SSAOp::IntSub {
                dst: tmp.clone(),
                a: edi_0,
                b: const_0.clone(),
            },
            SSAOp::IntEqual {
                dst: zf_1.clone(),
                a: tmp.clone(),
                b: const_0,
            },
            SSAOp::BoolNot {
                dst: cond.clone(),
                src: zf_1,
            },
            SSAOp::CBranch {
                cond,
                target: make_var("const:1000", 0, 8),
            },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);

        assert!(ctx.flag_only_values_set().contains(&tmp.display_name()));
        assert!(ctx.is_dead(&tmp));
    }

    #[test]
    fn test_flag_only_preserved_for_non_flag_consumer() {
        let edi_0 = make_var("EDI", 0, 4);
        let tmp = make_var("tmp:4000", 1, 4);
        let zf_1 = make_var("ZF", 1, 1);
        let cond = make_var("tmp:4001", 1, 1);
        let const_0 = make_var("const:0", 0, 4);

        let block = make_block(vec![
            SSAOp::IntSub {
                dst: tmp.clone(),
                a: edi_0,
                b: const_0.clone(),
            },
            SSAOp::IntEqual {
                dst: zf_1.clone(),
                a: tmp.clone(),
                b: const_0.clone(),
            },
            SSAOp::BoolNot {
                dst: cond.clone(),
                src: zf_1,
            },
            SSAOp::Store {
                space: "ram".to_string(),
                addr: make_var("const:0x2000", 0, 8),
                val: tmp.clone(),
            },
            SSAOp::CBranch {
                cond,
                target: make_var("const:1000", 0, 8),
            },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);

        assert!(!ctx.flag_only_values_set().contains(&tmp.display_name()));
        assert!(!ctx.is_dead(&tmp));
    }

    #[test]
    fn test_simplify_predicate_rewrites_cmp_zero() {
        let ctx = FoldingContext::new(64);
        let expr = CExpr::unary(
            UnaryOp::Not,
            CExpr::binary(
                BinaryOp::Eq,
                CExpr::binary(BinaryOp::Sub, CExpr::Var("x".to_string()), CExpr::IntLit(0)),
                CExpr::IntLit(0),
            ),
        );
        let simplified = ctx.simplify_condition_expr(expr);
        assert_eq!(
            simplified,
            CExpr::binary(BinaryOp::Ne, CExpr::Var("x".to_string()), CExpr::IntLit(0))
        );
    }

    #[test]
    fn test_simplify_predicate_rewrites_sub_const_cmp_zero() {
        let ctx = FoldingContext::new(64);
        let expr = CExpr::binary(
            BinaryOp::Eq,
            CExpr::binary(
                BinaryOp::Sub,
                CExpr::Var("x".to_string()),
                CExpr::IntLit(0xdead),
            ),
            CExpr::IntLit(0),
        );
        let simplified = ctx.simplify_condition_expr(expr);
        assert_eq!(
            simplified,
            CExpr::binary(
                BinaryOp::Eq,
                CExpr::Var("x".to_string()),
                CExpr::Var("0xdead".to_string())
            )
        );
    }

    #[test]
    fn test_simplify_predicate_rewrites_sub_var_cmp_zero() {
        let ctx = FoldingContext::new(64);
        let expr = CExpr::binary(
            BinaryOp::Ne,
            CExpr::binary(
                BinaryOp::Sub,
                CExpr::Var("x".to_string()),
                CExpr::Var("y".to_string()),
            ),
            CExpr::IntLit(0),
        );
        let simplified = ctx.simplify_condition_expr(expr);
        assert_eq!(
            simplified,
            CExpr::binary(
                BinaryOp::Ne,
                CExpr::Var("x".to_string()),
                CExpr::Var("y".to_string())
            )
        );
    }

    #[test]
    fn test_simplify_predicate_rewrites_sub_all_ones_cmp_zero() {
        let ctx = FoldingContext::new(64);
        let expr = CExpr::binary(
            BinaryOp::Eq,
            CExpr::binary(
                BinaryOp::Sub,
                CExpr::Var("x".to_string()),
                CExpr::UIntLit(0xffff_ffff),
            ),
            CExpr::IntLit(0),
        );
        let simplified = ctx.simplify_condition_expr(expr);
        assert_eq!(
            simplified,
            CExpr::binary(
                BinaryOp::Eq,
                CExpr::Var("x".to_string()),
                CExpr::Var("0xffffffff".to_string())
            )
        );
    }

    #[test]
    fn test_simplify_predicate_rewrites_ne_ge_zero_to_gt_zero() {
        let ctx = FoldingContext::new(64);
        let expr = CExpr::binary(
            BinaryOp::And,
            CExpr::binary(BinaryOp::Ne, CExpr::Var("x".to_string()), CExpr::IntLit(0)),
            CExpr::binary(BinaryOp::Ge, CExpr::Var("x".to_string()), CExpr::IntLit(0)),
        );
        let simplified = ctx.simplify_condition_expr(expr);
        assert_eq!(
            simplified,
            CExpr::binary(BinaryOp::Gt, CExpr::Var("x".to_string()), CExpr::IntLit(0))
        );
    }

    #[test]
    fn test_identity_sub_zero() {
        let ctx = FoldingContext::new(64);
        let simplified = ctx.identity_simplify_binary(
            BinaryOp::Sub,
            CExpr::Var("x".to_string()),
            CExpr::IntLit(0),
            Some(4),
        );
        assert_eq!(simplified, CExpr::Var("x".to_string()));
    }

    #[test]
    fn test_identity_add_zero() {
        let ctx = FoldingContext::new(64);
        let simplified = ctx.identity_simplify_binary(
            BinaryOp::Add,
            CExpr::Var("x".to_string()),
            CExpr::IntLit(0),
            Some(4),
        );
        assert_eq!(simplified, CExpr::Var("x".to_string()));
    }

    #[test]
    fn test_identity_or_zero() {
        let ctx = FoldingContext::new(64);
        let simplified = ctx.identity_simplify_binary(
            BinaryOp::BitOr,
            CExpr::Var("x".to_string()),
            CExpr::IntLit(0),
            Some(4),
        );
        assert_eq!(simplified, CExpr::Var("x".to_string()));
    }

    #[test]
    fn test_identity_xor_zero() {
        let ctx = FoldingContext::new(64);
        let simplified = ctx.identity_simplify_binary(
            BinaryOp::BitXor,
            CExpr::Var("x".to_string()),
            CExpr::IntLit(0),
            Some(4),
        );
        assert_eq!(simplified, CExpr::Var("x".to_string()));
    }

    #[test]
    fn test_identity_xor_self() {
        let ctx = FoldingContext::new(64);
        let simplified = ctx.identity_simplify_binary(
            BinaryOp::BitXor,
            CExpr::Var("x".to_string()),
            CExpr::Var("x".to_string()),
            Some(4),
        );
        assert_eq!(simplified, CExpr::IntLit(0));
    }

    #[test]
    fn test_identity_mul_one() {
        let ctx = FoldingContext::new(64);
        let simplified = ctx.identity_simplify_binary(
            BinaryOp::Mul,
            CExpr::Var("x".to_string()),
            CExpr::IntLit(1),
            Some(4),
        );
        assert_eq!(simplified, CExpr::Var("x".to_string()));
    }

    #[test]
    fn test_identity_div_one() {
        let ctx = FoldingContext::new(64);
        let simplified = ctx.identity_simplify_binary(
            BinaryOp::Div,
            CExpr::Var("x".to_string()),
            CExpr::IntLit(1),
            Some(4),
        );
        assert_eq!(simplified, CExpr::Var("x".to_string()));
    }

    #[test]
    fn test_identity_and_all_ones_with_explicit_width() {
        let ctx = FoldingContext::new(64);
        let simplified = ctx.identity_simplify_binary(
            BinaryOp::BitAnd,
            CExpr::Var("x".to_string()),
            CExpr::UIntLit(0xffff_ffff),
            Some(4),
        );
        assert_eq!(simplified, CExpr::Var("x".to_string()));
    }

    #[test]
    fn test_identity_negative_cases_preserved() {
        let ctx = FoldingContext::new(64);
        let sub = ctx.identity_simplify_binary(
            BinaryOp::Sub,
            CExpr::Var("x".to_string()),
            CExpr::IntLit(1),
            Some(4),
        );
        assert_eq!(
            sub,
            CExpr::binary(BinaryOp::Sub, CExpr::Var("x".to_string()), CExpr::IntLit(1))
        );

        let add = ctx.identity_simplify_binary(
            BinaryOp::Add,
            CExpr::Var("x".to_string()),
            CExpr::IntLit(2),
            Some(4),
        );
        assert_eq!(
            add,
            CExpr::binary(BinaryOp::Add, CExpr::Var("x".to_string()), CExpr::IntLit(2))
        );

        let or = ctx.identity_simplify_binary(
            BinaryOp::BitOr,
            CExpr::Var("x".to_string()),
            CExpr::IntLit(1),
            Some(4),
        );
        assert_eq!(
            or,
            CExpr::binary(
                BinaryOp::BitOr,
                CExpr::Var("x".to_string()),
                CExpr::IntLit(1)
            )
        );
    }

    #[test]
    fn test_noop_assignment_is_suppressed() {
        let ctx = FoldingContext::new(64);
        let lhs = CExpr::Var("x".to_string());
        let rhs = CExpr::binary(BinaryOp::Sub, CExpr::Var("x".to_string()), CExpr::IntLit(0));
        let stmt = ctx.assign_stmt(lhs, rhs);
        assert!(stmt.is_none(), "x = x - 0 should be suppressed as a no-op");
    }

    #[test]
    fn test_rewrite_stack_deref_to_external_name() {
        let mut ctx = FoldingContext::new(64);
        let mut external = HashMap::new();
        external.insert(
            -64,
            ExternalStackVar {
                name: "buf".to_string(),
                ty: Some(CType::Array(Box::new(CType::Int(8)), Some(64))),
                base: Some("RBP".to_string()),
            },
        );
        ctx.set_external_stack_vars(external);
        ctx.analyze_blocks(&[]);

        let expr = CExpr::Deref(Box::new(CExpr::binary(
            BinaryOp::Add,
            CExpr::Var("rbp_1".to_string()),
            CExpr::IntLit(-0x40),
        )));

        assert_eq!(ctx.rewrite_stack_expr(expr), CExpr::Var("buf".to_string()));
    }

    #[test]
    fn test_rewrite_stack_address_expr_for_call_arg() {
        let mut ctx = FoldingContext::new(64);
        let mut external = HashMap::new();
        external.insert(
            -64,
            ExternalStackVar {
                name: "buf".to_string(),
                ty: None,
                base: Some("RBP".to_string()),
            },
        );
        ctx.set_external_stack_vars(external);
        ctx.analyze_blocks(&[]);

        let expr = CExpr::binary(
            BinaryOp::Add,
            CExpr::Var("rbp_1".to_string()),
            CExpr::IntLit(-0x40),
        );
        assert_eq!(ctx.rewrite_stack_expr(expr), CExpr::Var("buf".to_string()));
    }

    #[test]
    fn test_rewrite_stack_cast_paren_expr() {
        let mut ctx = FoldingContext::new(64);
        let mut external = HashMap::new();
        external.insert(
            -72,
            ExternalStackVar {
                name: "user_input".to_string(),
                ty: Some(CType::ptr(CType::Int(8))),
                base: Some("RBP".to_string()),
            },
        );
        ctx.set_external_stack_vars(external);
        ctx.analyze_blocks(&[]);

        let expr = CExpr::Deref(Box::new(CExpr::Cast {
            ty: CType::ptr(CType::Int(8)),
            expr: Box::new(CExpr::Paren(Box::new(CExpr::binary(
                BinaryOp::Add,
                CExpr::Var("rbp_1".to_string()),
                CExpr::IntLit(-0x48),
            )))),
        }));

        assert_eq!(
            ctx.rewrite_stack_expr(expr),
            CExpr::Var("user_input".to_string())
        );
    }

    #[test]
    fn test_rewrite_stack_unknown_offset_preserved() {
        let mut ctx = FoldingContext::new(64);
        let mut external = HashMap::new();
        external.insert(
            -64,
            ExternalStackVar {
                name: "buf".to_string(),
                ty: None,
                base: Some("RBP".to_string()),
            },
        );
        ctx.set_external_stack_vars(external);
        ctx.analyze_blocks(&[]);

        let expr = CExpr::binary(
            BinaryOp::Add,
            CExpr::Var("rbp_1".to_string()),
            CExpr::IntLit(-0x20),
        );
        assert_eq!(ctx.rewrite_stack_expr(expr.clone()), expr);
    }

    #[test]
    fn test_resolve_stack_var_canonicalizes_local_name_using_external_offset_mirror() {
        let mut ctx = FoldingContext::new(64);
        ctx.state
            .analysis_ctx
            .stack_info
            .stack_vars
            .insert(4, "local_4".to_string());
        ctx.set_external_stack_vars(HashMap::from([(
            -4,
            ExternalStackVar {
                name: "result".to_string(),
                ty: None,
                base: Some("RBP".to_string()),
            },
        )]));

        assert_eq!(ctx.resolve_stack_var(4), Some("result".to_string()));
    }

    #[test]
    fn test_resolve_stack_var_prefers_semantic_offset_zero_alias_over_stack_placeholder() {
        let mut ctx = FoldingContext::new(64);
        ctx.state
            .analysis_ctx
            .stack_info
            .stack_vars
            .insert(0, "stack_0".to_string());
        ctx.set_external_stack_vars(HashMap::from([(
            0,
            ExternalStackVar {
                name: "saved_rbp".to_string(),
                ty: None,
                base: Some("RBP".to_string()),
            },
        )]));

        assert_eq!(ctx.resolve_stack_var(0), Some("saved_rbp".to_string()));
    }

    #[test]
    fn test_var_name_canonicalizes_stack_alias_from_external_offset_mirror() {
        let mut ctx = FoldingContext::new(64);
        ctx.state
            .analysis_ctx
            .use_info
            .var_aliases
            .insert("tmp:1_1".to_string(), "local_4".to_string());
        ctx.set_external_stack_vars(HashMap::from([(
            -4,
            ExternalStackVar {
                name: "result".to_string(),
                ty: None,
                base: Some("RBP".to_string()),
            },
        )]));

        let rendered = ctx.var_name(&make_var("tmp:1", 1, 8));
        assert_eq!(rendered, "result");
    }

    #[test]
    fn test_condition_var_chain_resolves_stack_alias() {
        let mut ctx = FoldingContext::new(64);
        ctx.state
            .analysis_ctx
            .stack_info
            .stack_vars
            .insert(-4, "value".to_string());
        ctx.state.analysis_ctx.use_info.definitions.insert(
            "tmp:cond_1".to_string(),
            CExpr::binary(
                BinaryOp::Eq,
                CExpr::Var("result".to_string()),
                CExpr::IntLit(19),
            ),
        );
        ctx.state.analysis_ctx.use_info.definitions.insert(
            "result".to_string(),
            CExpr::Deref(Box::new(CExpr::binary(
                BinaryOp::Add,
                CExpr::Var("rbp_1".to_string()),
                CExpr::IntLit(-4),
            ))),
        );

        let cond = ctx.get_condition_expr(&make_var("tmp:cond", 1, 1));
        let mut reads = HashSet::new();
        ctx.collect_expr_reads(&cond, &mut reads);
        assert!(
            reads.contains("value"),
            "Condition should resolve var-chain stack alias into canonical stack name"
        );
        assert!(
            !reads.contains("result"),
            "Condition should not keep intermediate non-canonical alias"
        );
    }

    #[test]
    fn test_condition_var_chain_resolves_stack_alias_through_cast_paren() {
        let mut ctx = FoldingContext::new(64);
        ctx.state
            .analysis_ctx
            .stack_info
            .stack_vars
            .insert(-4, "value".to_string());
        ctx.state.analysis_ctx.use_info.definitions.insert(
            "tmp:cond_1".to_string(),
            CExpr::binary(
                BinaryOp::Eq,
                CExpr::Var("result".to_string()),
                CExpr::IntLit(19),
            ),
        );
        ctx.state.analysis_ctx.use_info.definitions.insert(
            "result".to_string(),
            CExpr::Paren(Box::new(CExpr::Cast {
                ty: CType::ptr(CType::Int(32)),
                expr: Box::new(CExpr::Deref(Box::new(CExpr::Paren(Box::new(
                    CExpr::binary(
                        BinaryOp::Add,
                        CExpr::Var("rbp_1".to_string()),
                        CExpr::IntLit(-4),
                    ),
                ))))),
            })),
        );

        let cond = ctx.get_condition_expr(&make_var("tmp:cond", 1, 1));
        let mut reads = HashSet::new();
        ctx.collect_expr_reads(&cond, &mut reads);
        assert!(
            reads.contains("value"),
            "Cast/paren wrapped condition chain should still resolve stack alias"
        );
    }

    #[test]
    fn test_condition_var_chain_non_stack_remains_unforced() {
        let mut ctx = FoldingContext::new(64);
        ctx.state.analysis_ctx.use_info.definitions.insert(
            "tmp:cond_1".to_string(),
            CExpr::binary(
                BinaryOp::Eq,
                CExpr::Var("result".to_string()),
                CExpr::IntLit(19),
            ),
        );
        ctx.state.analysis_ctx.use_info.definitions.insert(
            "result".to_string(),
            CExpr::binary(
                BinaryOp::Add,
                CExpr::Var("arg1".to_string()),
                CExpr::IntLit(1),
            ),
        );

        let cond = ctx.get_condition_expr(&make_var("tmp:cond", 1, 1));
        let mut reads = HashSet::new();
        ctx.collect_expr_reads(&cond, &mut reads);
        assert!(
            reads.contains("result"),
            "Non-stack var chains should not be force-rewritten"
        );
    }

    #[test]
    fn test_lookup_definition_resolves_formatted_temp_aliases() {
        let mut ctx = FoldingContext::new(64);
        ctx.state
            .analysis_ctx
            .use_info
            .definitions
            .insert("tmp:foo_2".to_string(), CExpr::Var("local_4".to_string()));
        ctx.state
            .analysis_ctx
            .use_info
            .var_aliases
            .insert("tmp:foo_2".to_string(), "t2".to_string());

        let resolved = ctx.lookup_definition("t2");
        assert_eq!(resolved, Some(CExpr::Var("local_4".to_string())));
    }

    #[test]
    fn test_lookup_definition_prefers_forwarded_semantic_value_over_register_artifact() {
        let mut ctx = FoldingContext::new(64);
        ctx.state.analysis_ctx.use_info.definitions.insert(
            "tmp:ret_1".to_string(),
            CExpr::Var("rax_2".to_string()),
        );
        ctx.state.analysis_ctx.use_info.definitions.insert(
            "src_1".to_string(),
            CExpr::Var("arg1".to_string()),
        );
        ctx.state.analysis_ctx.use_info.forwarded_values.insert(
            "tmp:ret_1".to_string(),
            crate::analysis::ValueProvenance {
                source: "src_1".to_string(),
                source_var: None,
                stack_slot: None,
            },
        );

        let resolved = ctx.lookup_definition("tmp:ret_1");
        assert_eq!(resolved, Some(CExpr::Var("arg1".to_string())));
    }

    #[test]
    fn test_sf_surrogate_cycle_is_guarded() {
        let mut ctx = FoldingContext::new(64);
        ctx.state
            .analysis_ctx
            .use_info
            .definitions
            .insert("sf_1".to_string(), CExpr::Var("sf_2".to_string()));
        ctx.state
            .analysis_ctx
            .use_info
            .definitions
            .insert("sf_2".to_string(), CExpr::Var("sf_1".to_string()));

        assert!(
            !ctx.is_sf_surrogate(&CExpr::Var("sf_1".to_string())),
            "Cyclic surrogate definitions must short-circuit without recursion overflow"
        );
    }

    #[test]
    fn test_prune_dead_temp_assignments_removes_unused_pure_copy() {
        let ctx = FoldingContext::new(64);
        let stmts = vec![
            CStmt::Expr(CExpr::assign(
                CExpr::Var("t1_1".to_string()),
                CExpr::Var("arg1".to_string()),
            )),
            CStmt::Expr(CExpr::assign(
                CExpr::Var("t2_2".to_string()),
                CExpr::Var("arg2".to_string()),
            )),
            CStmt::Return(Some(CExpr::Var("t2_2".to_string()))),
        ];

        let pruned = ctx.prune_dead_temp_assignments(stmts);
        assert_eq!(pruned.len(), 2, "Unused pure temp copy should be removed");
        assert!(
            !matches!(
                pruned.first(),
                Some(CStmt::Expr(CExpr::Binary {
                    op: BinaryOp::Assign,
                    left,
                    right: _,
                })) if left.as_ref() == &CExpr::Var("t1_1".to_string())
            ),
            "t1_1 copy should be pruned"
        );
    }

    #[test]
    fn test_prune_dead_temp_assignments_keeps_side_effecting_rhs() {
        let ctx = FoldingContext::new(64);
        let stmts = vec![
            CStmt::Expr(CExpr::assign(
                CExpr::Var("t1_1".to_string()),
                CExpr::call(CExpr::Var("foo".to_string()), vec![]),
            )),
            CStmt::Return(Some(CExpr::IntLit(0))),
        ];

        let pruned = ctx.prune_dead_temp_assignments(stmts);
        assert_eq!(
            pruned.len(),
            2,
            "Dead temp assignment must be kept when RHS has side effects"
        );
    }

    #[test]
    fn test_prune_dead_temp_assignments_removes_dead_register_ssa_assignment() {
        let ctx = FoldingContext::new(64);
        let stmts = vec![
            CStmt::Expr(CExpr::assign(
                CExpr::Var("rax_6".to_string()),
                CExpr::binary(
                    BinaryOp::Add,
                    CExpr::Var("rax_3".to_string()),
                    CExpr::IntLit(1),
                ),
            )),
            CStmt::Return(Some(CExpr::IntLit(0))),
        ];

        let pruned = ctx.prune_dead_temp_assignments(stmts);
        assert_eq!(
            pruned.len(),
            1,
            "Dead pure assignment to SSA register artifact should be removed"
        );
        assert!(
            matches!(pruned[0], CStmt::Return(_)),
            "Return should be retained"
        );
    }

    #[test]
    fn test_prune_dead_temp_assignments_keeps_dead_register_ssa_assignment_with_call_rhs() {
        let ctx = FoldingContext::new(64);
        let stmts = vec![
            CStmt::Expr(CExpr::assign(
                CExpr::Var("rax_6".to_string()),
                CExpr::call(CExpr::Var("foo".to_string()), vec![]),
            )),
            CStmt::Return(Some(CExpr::IntLit(0))),
        ];

        let pruned = ctx.prune_dead_temp_assignments(stmts);
        assert_eq!(
            pruned.len(),
            2,
            "Assignment with side-effecting RHS should not be pruned"
        );
    }

    #[test]
    fn test_prune_dead_temp_assignments_keeps_dead_dotted_global_like_target() {
        let ctx = FoldingContext::new(64);
        let stmts = vec![
            CStmt::Expr(CExpr::assign(
                CExpr::Var("obj.global_counter".to_string()),
                CExpr::IntLit(1),
            )),
            CStmt::Return(Some(CExpr::IntLit(0))),
        ];

        let pruned = ctx.prune_dead_temp_assignments(stmts);
        assert_eq!(
            pruned.len(),
            2,
            "Dotted/global-like semantic bindings should not be pruned"
        );
    }

    #[test]
    fn test_propagate_ephemeral_copies_rewrites_phi_copy_residue() {
        let ctx = FoldingContext::new(64);
        let stmts = vec![
            CStmt::Expr(CExpr::assign(
                CExpr::Var("eax_2".to_string()),
                CExpr::Var("arg1".to_string()),
            )),
            CStmt::Expr(CExpr::assign(
                CExpr::Var("eax_3".to_string()),
                CExpr::binary(
                    BinaryOp::Add,
                    CExpr::Var("eax_2".to_string()),
                    CExpr::Var("eax_2".to_string()),
                ),
            )),
            CStmt::Return(Some(CExpr::Var("eax_3".to_string()))),
        ];

        let propagated = ctx.propagate_ephemeral_copies(stmts);
        let Some((_, rhs)) = FoldingContext::assignment_target_and_rhs(&propagated[1]) else {
            panic!("expected assignment at propagated[1]");
        };
        let mut reads = HashSet::new();
        ctx.collect_expr_reads(rhs, &mut reads);
        assert!(
            reads.contains("arg1") && !reads.contains("eax_2"),
            "Copy-forward should substitute eax_2 uses with arg1"
        );

        let pruned = ctx.prune_dead_temp_assignments(propagated);
        assert!(
            !pruned.iter().any(|stmt| {
                matches!(
                    FoldingContext::assignment_target_and_rhs(stmt),
                    Some((target, _)) if target == "eax_2"
                )
            }),
            "Dead phi-copy assignment should be removed after propagation"
        );
    }

    #[test]
    fn test_propagate_ephemeral_copies_keeps_call_rhs_unsubstituted() {
        let ctx = FoldingContext::new(64);
        let stmts = vec![
            CStmt::Expr(CExpr::assign(
                CExpr::Var("eax_2".to_string()),
                CExpr::call(CExpr::Var("foo".to_string()), vec![]),
            )),
            CStmt::Expr(CExpr::assign(
                CExpr::Var("eax_3".to_string()),
                CExpr::binary(
                    BinaryOp::Add,
                    CExpr::Var("eax_2".to_string()),
                    CExpr::IntLit(1),
                ),
            )),
        ];

        let propagated = ctx.propagate_ephemeral_copies(stmts);
        let Some((_, rhs)) = FoldingContext::assignment_target_and_rhs(&propagated[1]) else {
            panic!("expected assignment at propagated[1]");
        };
        let mut reads = HashSet::new();
        ctx.collect_expr_reads(rhs, &mut reads);
        assert!(
            reads.contains("eax_2"),
            "Call RHS should not be used for copy-forward substitution"
        );
    }

    #[test]
    fn test_propagate_ephemeral_copies_invalidates_alias_when_source_redefined() {
        let ctx = FoldingContext::new(64);
        let stmts = vec![
            CStmt::Expr(CExpr::assign(
                CExpr::Var("eax_2".to_string()),
                CExpr::Var("rdi_1".to_string()),
            )),
            CStmt::Expr(CExpr::assign(
                CExpr::Var("rdi_1".to_string()),
                CExpr::IntLit(42),
            )),
            CStmt::Expr(CExpr::assign(
                CExpr::Var("eax_3".to_string()),
                CExpr::binary(
                    BinaryOp::Add,
                    CExpr::Var("eax_2".to_string()),
                    CExpr::IntLit(1),
                ),
            )),
        ];

        let propagated = ctx.propagate_ephemeral_copies(stmts);
        let Some((_, rhs)) = FoldingContext::assignment_target_and_rhs(&propagated[2]) else {
            panic!("expected assignment at propagated[2]");
        };
        let mut reads = HashSet::new();
        ctx.collect_expr_reads(rhs, &mut reads);
        assert!(
            reads.contains("eax_2"),
            "Alias must be invalidated when its RHS source variable is reassigned"
        );
    }

    #[test]
    fn test_propagate_ephemeral_copies_tracks_cast_var_rhs() {
        let ctx = FoldingContext::new(64);
        let stmts = vec![
            CStmt::Expr(CExpr::assign(
                CExpr::Var("eax_2".to_string()),
                CExpr::Cast {
                    ty: CType::Int(64),
                    expr: Box::new(CExpr::Var("arg1".to_string())),
                },
            )),
            CStmt::Expr(CExpr::assign(
                CExpr::Var("eax_3".to_string()),
                CExpr::binary(
                    BinaryOp::Add,
                    CExpr::Var("eax_2".to_string()),
                    CExpr::IntLit(1),
                ),
            )),
        ];

        let propagated = ctx.propagate_ephemeral_copies(stmts);
        let Some((_, rhs)) = FoldingContext::assignment_target_and_rhs(&propagated[1]) else {
            panic!("expected assignment at propagated[1]");
        };
        assert!(
            matches!(
                rhs,
                CExpr::Binary {
                    left,
                    right: _,
                    op: BinaryOp::Add,
                } if matches!(left.as_ref(), CExpr::Cast { expr, .. } if matches!(expr.as_ref(), CExpr::Var(name) if name == "arg1"))
            ),
            "Cast(Var(...)) should be propagated as a cheap copy RHS"
        );
    }

    #[test]
    fn test_propagate_ephemeral_copies_keeps_semantic_member_base() {
        let ctx = FoldingContext::new(64);
        let stmts = vec![
            CStmt::Expr(CExpr::assign(
                CExpr::Var("tmp:base_1".to_string()),
                CExpr::Var("rdx_2".to_string()),
            )),
            CStmt::Expr(CExpr::assign(
                CExpr::Var("eax_3".to_string()),
                CExpr::PtrMember {
                    base: Box::new(CExpr::Var("tmp:base_1".to_string())),
                    member: "third".to_string(),
                },
            )),
        ];

        let propagated = ctx.propagate_ephemeral_copies(stmts);
        let Some((_, rhs)) = FoldingContext::assignment_target_and_rhs(&propagated[1]) else {
            panic!("expected assignment at propagated[1]");
        };
        assert!(
            matches!(
                rhs,
                CExpr::PtrMember { base, .. }
                    if matches!(base.as_ref(), CExpr::Var(name) if name == "tmp:base_1")
            ),
            "copy propagation must not rewrite semantic member bases back into transient registers"
        );
    }

    #[test]
    fn test_copy_predicate_assignment_uses_simplified_rhs() {
        let edi_0 = make_var("EDI", 0, 4);
        let sub = make_var("tmp:9100", 1, 4);
        let zf_1 = make_var("ZF", 1, 1);
        let cond = make_var("tmp:9101", 1, 1);
        let const_0 = make_var("const:0", 0, 4);

        let block = make_block(vec![
            SSAOp::IntSub {
                dst: sub.clone(),
                a: edi_0,
                b: const_0.clone(),
            },
            SSAOp::IntEqual {
                dst: zf_1.clone(),
                a: sub,
                b: const_0,
            },
            SSAOp::BoolNot {
                dst: cond.clone(),
                src: zf_1,
            },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);
        let rhs = ctx.resolve_predicate_rhs_for_var(&cond, ctx.get_expr(&cond));

        assert!(
            expr_contains_binary_op(&rhs, BinaryOp::Ne),
            "Predicate copy helper should preserve high-level comparison form"
        );
        assert!(
            !expr_contains_flag_artifact(&rhs),
            "Predicate copy helper output should not contain raw flag temporaries"
        );
        assert!(
            !expr_contains_sub_zero_cmp_scaffold(&rhs),
            "Predicate copy helper output should not contain cmp-to-zero subtraction scaffold"
        );
    }

    #[test]
    fn test_predicate_cast_and_boolnot_assignment_preserve_source_expression() {
        let edi_0 = make_var("EDI", 0, 4);
        let cmp = make_var("tmp:9200", 1, 1);
        let casted = make_var("tmp:9201", 1, 4);
        let negated = make_var("tmp:9202", 1, 1);
        let const_0 = make_var("const:0", 0, 4);

        let block = make_block(vec![
            SSAOp::IntNotEqual {
                dst: cmp.clone(),
                a: edi_0,
                b: const_0,
            },
            SSAOp::IntZExt {
                dst: casted.clone(),
                src: cmp.clone(),
            },
            SSAOp::BoolNot {
                dst: negated.clone(),
                src: casted,
            },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);

        let cast_stmt = ctx
            .op_to_stmt(&block.ops[1])
            .expect("casted predicate assignment should lower");
        let Some((_, cast_rhs)) = FoldingContext::assignment_target_and_rhs(&cast_stmt) else {
            panic!("expected assignment statement for casted predicate");
        };
        assert!(
            expr_contains_binary_op(cast_rhs, BinaryOp::Ne),
            "Cast assignment should preserve the predicate comparison"
        );
        assert!(
            !matches!(cast_rhs, CExpr::IntLit(_) | CExpr::UIntLit(_)),
            "Predicate cast assignment must not collapse to a literal"
        );

        let negated_stmt = ctx
            .op_to_stmt(&block.ops[2])
            .expect("boolnot predicate assignment should lower");
        let Some((_, negated_rhs)) = FoldingContext::assignment_target_and_rhs(&negated_stmt)
        else {
            panic!("expected assignment statement for negated predicate");
        };
        assert!(
            ctx.is_assignment_predicate_expr(negated_rhs),
            "BoolNot assignment should still lower to a predicate expression"
        );
        assert!(
            !matches!(negated_rhs, CExpr::IntLit(_) | CExpr::UIntLit(_)),
            "Negated predicate assignment must not collapse to a literal"
        );
        assert!(
            !expr_contains_flag_artifact(negated_rhs),
            "BoolNot assignment should not reintroduce raw flag artifacts"
        );
    }

    #[test]
    fn test_copy_suppresses_entry_arg_alias_assignment() {
        let ctx = FoldingContext::new(64);
        let stmt = ctx.op_to_stmt(&SSAOp::Copy {
            dst: make_var("arg1", 0, 4),
            src: make_var("EDI", 0, 4),
        });
        assert!(
            stmt.is_none(),
            "arg1 = edi entry alias copy should be suppressed"
        );
    }

    #[test]
    fn test_assign_stmt_suppresses_entry_arg_alias_assignment() {
        let ctx = FoldingContext::new(64);
        let stmt = ctx.assign_stmt(
            CExpr::Var("arg1".to_string()),
            CExpr::Var("edi".to_string()),
        );
        assert!(
            stmt.is_none(),
            "arg1 = edi should be suppressed even after non-copy normalization paths"
        );
    }

    #[test]
    fn test_simplify_signed_gt_from_ne_and_of_eq_sf() {
        let mut ctx = FoldingContext::new(64);
        ctx.state.analysis_ctx.flag_info.flag_origins.insert(
            "OF_1".to_string(),
            ("a".to_string(), "const:0_0".to_string()),
        );

        let expr = CExpr::binary(
            BinaryOp::And,
            CExpr::binary(BinaryOp::Ne, CExpr::Var("a".to_string()), CExpr::IntLit(0)),
            CExpr::binary(
                BinaryOp::Eq,
                CExpr::Var("of_1".to_string()),
                CExpr::binary(BinaryOp::Lt, CExpr::Var("a".to_string()), CExpr::IntLit(0)),
            ),
        );

        let simplified = ctx.simplify_condition_expr(expr);
        assert_eq!(
            simplified,
            CExpr::binary(BinaryOp::Gt, CExpr::Var("a".to_string()), CExpr::IntLit(0))
        );
    }

    #[test]
    fn test_simplify_signed_gt_from_ne_and_of_eq_sf_with_casted_zero() {
        let mut ctx = FoldingContext::new(64);
        ctx.state.analysis_ctx.flag_info.flag_origins.insert(
            "OF_1".to_string(),
            ("a".to_string(), "const:0_0".to_string()),
        );

        let expr = CExpr::binary(
            BinaryOp::And,
            CExpr::binary(BinaryOp::Ne, CExpr::Var("a".to_string()), CExpr::IntLit(0)),
            CExpr::binary(
                BinaryOp::Eq,
                CExpr::Var("of_1".to_string()),
                CExpr::binary(
                    BinaryOp::Lt,
                    CExpr::cast(CType::Int(32), CExpr::Var("a".to_string())),
                    CExpr::cast(CType::Int(32), CExpr::IntLit(0)),
                ),
            ),
        );

        let simplified = ctx.simplify_condition_expr(expr);
        assert_eq!(
            simplified,
            CExpr::binary(BinaryOp::Gt, CExpr::Var("a".to_string()), CExpr::IntLit(0))
        );
    }

    #[test]
    fn test_extract_flag_name_requires_strict_token_match() {
        let ctx = FoldingContext::new(64);
        assert_eq!(
            ctx.extract_of(&CExpr::Var("of_12".to_string())),
            Some("of_12".to_string())
        );
        assert_eq!(ctx.extract_of(&CExpr::Var("offset_1".to_string())), None);
        assert_eq!(ctx.extract_of(&CExpr::Var("proof".to_string())), None);
    }

    #[test]
    fn test_simplify_signed_ge_from_of_eq_sf() {
        let mut ctx = FoldingContext::new(64);
        ctx.state
            .analysis_ctx
            .flag_info
            .flag_origins
            .insert("OF_2".to_string(), ("a".to_string(), "b".to_string()));

        let expr = CExpr::binary(
            BinaryOp::Eq,
            CExpr::Var("of_2".to_string()),
            CExpr::binary(
                BinaryOp::Lt,
                CExpr::binary(
                    BinaryOp::Sub,
                    CExpr::Var("a".to_string()),
                    CExpr::Var("b".to_string()),
                ),
                CExpr::IntLit(0),
            ),
        );

        let simplified = ctx.simplify_condition_expr(expr);
        assert_eq!(
            simplified,
            CExpr::binary(
                BinaryOp::Ge,
                CExpr::Var("a".to_string()),
                CExpr::Var("b".to_string())
            )
        );
    }

    #[test]
    fn test_simplify_signed_lt_from_of_ne_sf() {
        let mut ctx = FoldingContext::new(64);
        ctx.state
            .analysis_ctx
            .flag_info
            .flag_origins
            .insert("OF_3".to_string(), ("a".to_string(), "b".to_string()));

        let expr = CExpr::binary(
            BinaryOp::Ne,
            CExpr::Var("of_3".to_string()),
            CExpr::binary(
                BinaryOp::Lt,
                CExpr::binary(
                    BinaryOp::Sub,
                    CExpr::Var("a".to_string()),
                    CExpr::Var("b".to_string()),
                ),
                CExpr::IntLit(0),
            ),
        );

        let simplified = ctx.simplify_condition_expr(expr);
        assert_eq!(
            simplified,
            CExpr::binary(
                BinaryOp::Lt,
                CExpr::Var("a".to_string()),
                CExpr::Var("b".to_string())
            )
        );
    }

    #[test]
    fn test_simplify_direct_zf_and_not_zf_from_compare_provenance() {
        let mut ctx = FoldingContext::new(64);
        ctx.state.analysis_ctx.flag_info.compare_provenance.insert(
            "ZF_7".to_string(),
            crate::analysis::FlagCompareProvenance {
                lhs: "result".to_string(),
                rhs: "25".to_string(),
                kind: crate::analysis::FlagCompareKind::Equality,
            },
        );

        let eq = ctx.simplify_condition_expr(CExpr::Var("zf_7".to_string()));
        let ne = ctx.simplify_condition_expr(CExpr::unary(
            UnaryOp::Not,
            CExpr::Var("zf_7".to_string()),
        ));

        assert_eq!(
            eq,
            CExpr::binary(BinaryOp::Eq, CExpr::Var("result".to_string()), CExpr::IntLit(25))
        );
        assert_eq!(
            ne,
            CExpr::binary(BinaryOp::Ne, CExpr::Var("result".to_string()), CExpr::IntLit(25))
        );
    }

    #[test]
    fn test_simplify_unsigned_relations_from_cf_and_zf_provenance() {
        let mut ctx = FoldingContext::new(64);
        ctx.state.analysis_ctx.flag_info.compare_provenance.insert(
            "CF_1".to_string(),
            crate::analysis::FlagCompareProvenance {
                lhs: "x".to_string(),
                rhs: "10".to_string(),
                kind: crate::analysis::FlagCompareKind::UnsignedLess,
            },
        );
        ctx.state.analysis_ctx.flag_info.compare_provenance.insert(
            "ZF_1".to_string(),
            crate::analysis::FlagCompareProvenance {
                lhs: "x".to_string(),
                rhs: "10".to_string(),
                kind: crate::analysis::FlagCompareKind::Equality,
            },
        );

        let lt = ctx.simplify_condition_expr(CExpr::Var("cf_1".to_string()));
        let ge = ctx.simplify_condition_expr(CExpr::unary(
            UnaryOp::Not,
            CExpr::Var("cf_1".to_string()),
        ));
        let le = ctx.simplify_condition_expr(CExpr::binary(
            BinaryOp::Or,
            CExpr::Var("cf_1".to_string()),
            CExpr::Var("zf_1".to_string()),
        ));
        let gt = ctx.simplify_condition_expr(CExpr::binary(
            BinaryOp::And,
            CExpr::unary(UnaryOp::Not, CExpr::Var("cf_1".to_string())),
            CExpr::unary(UnaryOp::Not, CExpr::Var("zf_1".to_string())),
        ));

        assert_eq!(
            lt,
            CExpr::binary(BinaryOp::Lt, CExpr::Var("x".to_string()), CExpr::IntLit(10))
        );
        assert_eq!(
            ge,
            CExpr::binary(BinaryOp::Ge, CExpr::Var("x".to_string()), CExpr::IntLit(10))
        );
        assert_eq!(
            le,
            CExpr::binary(BinaryOp::Le, CExpr::Var("x".to_string()), CExpr::IntLit(10))
        );
        assert_eq!(
            gt,
            CExpr::binary(BinaryOp::Gt, CExpr::Var("x".to_string()), CExpr::IntLit(10))
        );
    }

    #[test]
    fn test_compare_flag_copy_chain_keeps_relation_and_not_tmp_scaffold() {
        let edi_0 = make_var("EDI", 0, 4);
        let sub = make_var("tmp:9300", 1, 4);
        let zf_1 = make_var("ZF", 1, 1);
        let alias = make_var("tmp:9301", 1, 1);
        let cond = make_var("tmp:9302", 1, 1);
        let const_25 = make_var("const:25", 0, 4);
        let const_0 = make_var("const:0", 0, 4);

        let block = make_block(vec![
            SSAOp::IntSub {
                dst: sub.clone(),
                a: edi_0,
                b: const_25,
            },
            SSAOp::IntEqual {
                dst: zf_1.clone(),
                a: sub,
                b: const_0,
            },
            SSAOp::Copy {
                dst: alias.clone(),
                src: zf_1,
            },
            SSAOp::BoolNot {
                dst: cond.clone(),
                src: alias,
            },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);
        let rhs = ctx.resolve_predicate_rhs_for_var(&cond, ctx.get_expr(&cond));

        assert_eq!(
            rhs,
            CExpr::binary(BinaryOp::Ne, CExpr::Var("arg1".to_string()), CExpr::IntLit(25))
        );
        assert!(
            !expr_contains_flag_artifact(&rhs),
            "predicate copy chain should collapse to the recovered comparison"
        );
        assert!(
            !expr_contains_sub_zero_cmp_scaffold(&rhs),
            "predicate copy chain should not preserve cmp-zero subtraction scaffolds"
        );
    }

    #[test]
    fn test_signed_canonicalization_mismatch_does_not_collapse() {
        let mut ctx = FoldingContext::new(64);
        ctx.state
            .analysis_ctx
            .flag_info
            .flag_origins
            .insert("OF_4".to_string(), ("a".to_string(), "b".to_string()));

        let expr = CExpr::binary(
            BinaryOp::And,
            CExpr::binary(BinaryOp::Ne, CExpr::Var("x".to_string()), CExpr::IntLit(0)),
            CExpr::binary(
                BinaryOp::Eq,
                CExpr::Var("of_4".to_string()),
                CExpr::binary(BinaryOp::Lt, CExpr::Var("y".to_string()), CExpr::IntLit(0)),
            ),
        );

        let simplified = ctx.simplify_condition_expr(expr.clone());
        assert!(
            matches!(
                simplified,
                CExpr::Binary {
                    op: BinaryOp::And,
                    ..
                }
            ),
            "Mismatched tuple should not collapse to a top-level signed relation"
        );
        assert!(
            !matches!(
                simplified,
                CExpr::Binary {
                    op: BinaryOp::Gt | BinaryOp::Ge | BinaryOp::Lt | BinaryOp::Le,
                    ..
                }
            ),
            "Mismatched tuple should remain conjunctive at top level"
        );
    }

    #[test]
    fn test_stack_prologue_arg_alias_recovery() {
        let rbp_1 = make_var("RBP", 1, 8);
        let edi_0 = make_var("EDI", 0, 4);
        let addr = make_var("tmp:7000", 1, 8);
        let arg_copy = make_var("tmp:7001", 1, 4);
        let loaded = make_var("tmp:7002", 1, 4);
        let cond = make_var("tmp:7003", 1, 1);
        let const_neg4 = make_var("const:fffffffffffffffc", 0, 8);
        let const_0 = make_var("const:0", 0, 4);

        let block = make_block(vec![
            SSAOp::IntAdd {
                dst: addr.clone(),
                a: rbp_1.clone(),
                b: const_neg4,
            },
            SSAOp::Copy {
                dst: arg_copy.clone(),
                src: edi_0,
            },
            SSAOp::Store {
                space: "ram".to_string(),
                addr: addr.clone(),
                val: arg_copy,
            },
            SSAOp::Load {
                dst: loaded.clone(),
                space: "ram".to_string(),
                addr,
            },
            SSAOp::IntNotEqual {
                dst: cond.clone(),
                a: loaded.clone(),
                b: const_0,
            },
            SSAOp::CBranch {
                cond,
                target: make_var("const:1000", 0, 8),
            },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_blocks(std::slice::from_ref(&block));

        assert_eq!(ctx.stack_vars_map().get(&-4), Some(&"arg1".to_string()));

        let mut visited = HashSet::new();
        let resolved =
            ctx.resolve_predicate_operand(&CExpr::Var(loaded.display_name()), 0, &mut visited);
        assert_eq!(resolved, CExpr::Var("arg1".to_string()));
    }

    #[test]
    fn test_use_info_deterministic() {
        let eax_0 = make_var("EAX", 0, 4);
        let tmp = make_var("tmp:8200", 1, 4);
        let block = make_block(vec![
            SSAOp::IntAdd {
                dst: tmp.clone(),
                a: eax_0,
                b: make_var("const:1", 0, 4),
            },
            SSAOp::Store {
                space: "ram".to_string(),
                addr: make_var("const:1000", 0, 8),
                val: tmp,
            },
        ]);

        let ctx_a = FoldingContext::new(64);
        let ctx_b = FoldingContext::new(64);
        let blocks = vec![block];

        let cfg_a = ctx_a.to_pass_env();
        let cfg_b = ctx_b.to_pass_env();
        let info_a = analysis::UseInfo::analyze(&blocks, &cfg_a);
        let info_b = analysis::UseInfo::analyze(&blocks, &cfg_b);
        assert_eq!(info_a, info_b, "UseInfo analysis should be deterministic");
    }

    #[test]
    fn test_flag_info_transitive_marking_and_guard() {
        let edi_0 = make_var("EDI", 0, 4);
        let tmp = make_var("tmp:8300", 1, 4);
        let zf_1 = make_var("ZF", 1, 1);
        let cond = make_var("tmp:8301", 1, 1);
        let const_0 = make_var("const:0", 0, 4);

        let flag_only_block = make_block(vec![
            SSAOp::IntSub {
                dst: tmp.clone(),
                a: edi_0.clone(),
                b: const_0.clone(),
            },
            SSAOp::IntEqual {
                dst: zf_1.clone(),
                a: tmp.clone(),
                b: const_0.clone(),
            },
            SSAOp::BoolNot {
                dst: cond.clone(),
                src: zf_1,
            },
            SSAOp::CBranch {
                cond,
                target: make_var("const:1000", 0, 8),
            },
        ]);

        let ctx = FoldingContext::new(64);
        let blocks = vec![flag_only_block];
        let cfg = ctx.to_pass_env();
        let use_info = analysis::UseInfo::analyze(&blocks, &cfg);
        let flag_info = analysis::FlagInfo::analyze(&blocks, &use_info, &cfg);
        assert!(flag_info.flag_only_values.contains(&tmp.display_name()));

        let tmp2 = make_var("tmp:8400", 1, 4);
        let zf_2 = make_var("ZF", 2, 1);
        let cond2 = make_var("tmp:8401", 1, 1);
        let guarded_block = make_block(vec![
            SSAOp::IntSub {
                dst: tmp2.clone(),
                a: edi_0,
                b: const_0.clone(),
            },
            SSAOp::IntEqual {
                dst: zf_2,
                a: tmp2.clone(),
                b: const_0,
            },
            SSAOp::BoolNot {
                dst: cond2.clone(),
                src: make_var("ZF", 2, 1),
            },
            SSAOp::Store {
                space: "ram".to_string(),
                addr: make_var("const:2000", 0, 8),
                val: tmp2.clone(),
            },
            SSAOp::CBranch {
                cond: cond2,
                target: make_var("const:1000", 0, 8),
            },
        ]);

        let ctx = FoldingContext::new(64);
        let blocks = vec![guarded_block];
        let cfg = ctx.to_pass_env();
        let use_info = analysis::UseInfo::analyze(&blocks, &cfg);
        let flag_info = analysis::FlagInfo::analyze(&blocks, &use_info, &cfg);
        assert!(!flag_info.flag_only_values.contains(&tmp2.display_name()));
    }

    #[test]
    fn test_stack_info_arg_alias_requires_version_zero() {
        let rbp_1 = make_var("RBP", 1, 8);
        let eax_1 = make_var("EAX", 1, 4);
        let addr = make_var("tmp:8500", 1, 8);
        let const_neg4 = make_var("const:fffffffffffffffc", 0, 8);
        let block = make_block(vec![
            SSAOp::IntAdd {
                dst: addr.clone(),
                a: rbp_1,
                b: const_neg4,
            },
            SSAOp::Store {
                space: "ram".to_string(),
                addr,
                val: eax_1,
            },
        ]);

        let ctx = FoldingContext::new(64);
        let blocks = vec![block];
        let cfg = ctx.to_pass_env();
        let use_info = analysis::UseInfo::analyze(&blocks, &cfg);
        let stack_info = analysis::StackInfo::analyze(&blocks, &use_info, &cfg);

        assert!(
            !stack_info.stack_arg_aliases.values().any(|v| v == "arg1"),
            "Non-argument registers must not be treated as prologue arg aliases"
        );
    }

    #[test]
    fn test_analyze_function_structure_marks_exit_as_return_context() {
        let mut block = R2ILBlock::new(0x1000, 1);
        block.push(R2ILOp::Return {
            target: Varnode::constant(0, 8),
        });
        let func = SSAFunction::from_blocks(&[block]).expect("SSA function should build");

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_function_structure(&func);

        assert!(ctx.state.return_blocks.contains(&0x1000));
    }

    #[test]
    fn test_arm64_return_slot_merge_blocks_fold_to_concrete_returns() {
        let blocks = vec![
            R2ILBlock {
                addr: 0x1000,
                size: 4,
                ops: vec![R2ILOp::CBranch {
                    target: Varnode::constant(0x1008, 8),
                    cond: Varnode::constant(1, 1),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1004,
                size: 4,
                ops: vec![R2ILOp::Branch {
                    target: Varnode::constant(0x100c, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x1008,
                size: 4,
                ops: vec![R2ILOp::Branch {
                    target: Varnode::constant(0x100c, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
            R2ILBlock {
                addr: 0x100c,
                size: 4,
                ops: vec![R2ILOp::Return {
                    target: Varnode::constant(0, 8),
                }],
                switch_info: None,
                op_metadata: Default::default(),
            },
        ];

        let mut func = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("ssa func");
        func.get_block_mut(0x1000).expect("entry").ops = vec![
            SSAOp::IntSub {
                dst: make_var("SP", 1, 8),
                a: make_var("SP", 0, 8),
                b: make_var("const:10", 0, 8),
            },
            SSAOp::IntNotEqual {
                dst: make_var("tmp:cond", 1, 1),
                a: make_var("X0", 0, 8),
                b: make_var("const:dead", 0, 8),
            },
            SSAOp::CBranch {
                cond: make_var("tmp:cond", 1, 1),
                target: make_var("ram:1008", 0, 8),
            },
        ];
        func.get_block_mut(0x1004).expect("fallthrough").ops = vec![
            SSAOp::IntAdd {
                dst: make_var("tmp:retaddr", 1, 8),
                a: make_var("SP", 1, 8),
                b: make_var("const:c", 0, 8),
            },
            SSAOp::Store {
                space: "ram".to_string(),
                addr: make_var("tmp:retaddr", 1, 8),
                val: make_var("const:1", 0, 4),
            },
            SSAOp::Branch {
                target: make_var("ram:100c", 0, 8),
            },
        ];
        func.get_block_mut(0x1008).expect("taken").ops = vec![
            SSAOp::IntAdd {
                dst: make_var("tmp:retaddr", 2, 8),
                a: make_var("SP", 1, 8),
                b: make_var("const:c", 0, 8),
            },
            SSAOp::Store {
                space: "ram".to_string(),
                addr: make_var("tmp:retaddr", 2, 8),
                val: make_var("const:0", 0, 4),
            },
            SSAOp::Branch {
                target: make_var("ram:100c", 0, 8),
            },
        ];
        func.get_block_mut(0x100c).expect("exit").ops = vec![
            SSAOp::IntAdd {
                dst: make_var("tmp:retaddr", 3, 8),
                a: make_var("SP", 1, 8),
                b: make_var("const:c", 0, 8),
            },
            SSAOp::Load {
                dst: make_var("tmp:ret", 1, 4),
                space: "ram".to_string(),
                addr: make_var("tmp:retaddr", 3, 8),
            },
            SSAOp::IntZExt {
                dst: make_var("X0", 1, 8),
                src: make_var("tmp:ret", 1, 4),
            },
            SSAOp::IntAdd {
                dst: make_var("tmp:sp", 1, 8),
                a: make_var("SP", 1, 8),
                b: make_var("const:10", 0, 8),
            },
            SSAOp::Copy {
                dst: make_var("SP", 2, 8),
                src: make_var("tmp:sp", 1, 8),
            },
            SSAOp::Copy {
                dst: make_var("PC", 1, 8),
                src: make_var("X30", 0, 8),
            },
            SSAOp::Return {
                target: make_var("PC", 1, 8),
            },
        ];

        let mut ctx = make_aarch64_ctx();
        let fold_blocks: Vec<_> = func.blocks().cloned().collect();
        ctx.analyze_blocks(&fold_blocks);
        ctx.analyze_function_structure(&func);

        assert!(ctx.state.return_blocks.contains(&0x1004));
        assert!(ctx.state.return_blocks.contains(&0x1008));
        assert!(ctx.state.return_stack_slots.contains(&12));

        let then_stmts = ctx.fold_block(func.get_block(0x1008).expect("then"), 0x1008);
        let else_stmts = ctx.fold_block(func.get_block(0x1004).expect("else"), 0x1004);

        let Some(CStmt::Return(Some(then_expr))) = then_stmts.last() else {
            panic!("then block should fold to return");
        };
        let Some(CStmt::Return(Some(else_expr))) = else_stmts.last() else {
            panic!("else block should fold to return");
        };
        assert_eq!(then_expr, &CExpr::IntLit(0));
        assert_eq!(else_expr, &CExpr::IntLit(1));
    }

    #[test]
    fn test_return_expr_inlines_simple_xor_chain_and_stops_after_return() {
        let eax_1 = make_var("EAX", 1, 4);
        let edi_0 = make_var("EDI", 0, 4);
        let esi_0 = make_var("ESI", 0, 4);
        let t1 = make_var("tmp:8000", 1, 1);
        let t2 = make_var("tmp:8001", 1, 1);
        let t3 = make_var("tmp:8002", 1, 1);
        let rip_1 = make_var("RIP", 1, 8);
        let const_0 = make_var("const:0", 0, 4);

        let block = make_block(vec![
            SSAOp::IntNotEqual {
                dst: t1.clone(),
                a: edi_0,
                b: const_0.clone(),
            },
            SSAOp::IntNotEqual {
                dst: t2.clone(),
                a: esi_0,
                b: const_0,
            },
            SSAOp::IntXor {
                dst: t3.clone(),
                a: t1,
                b: t2,
            },
            SSAOp::Copy {
                dst: eax_1,
                src: t3,
            },
            SSAOp::Return { target: rip_1 },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);
        ctx.state.return_blocks.insert(block.addr);

        let stmts = ctx.fold_block(&block, block.addr);
        assert_eq!(
            stmts.len(),
            1,
            "Should stop emitting after high-level return"
        );

        match &stmts[0] {
            CStmt::Return(Some(expr)) => {
                assert!(
                    expr_contains_binary_op(expr, BinaryOp::BitXor),
                    "Return expression should inline XOR chain"
                );
                assert!(
                    expr_contains_binary_op(expr, BinaryOp::Ne),
                    "Return expression should include inlined predicate comparisons"
                );
            }
            other => panic!("Expected return statement, got {:?}", other),
        }
    }

    #[test]
    fn test_no_duplicate_low_level_return_after_high_level_return() {
        let eax_1 = make_var("EAX", 1, 4);
        let tmp = make_var("tmp:8100", 1, 4);
        let rip_1 = make_var("RIP", 1, 8);

        let block = make_block(vec![
            SSAOp::Copy {
                dst: tmp.clone(),
                src: make_var("const:1", 0, 4),
            },
            SSAOp::Copy {
                dst: eax_1,
                src: tmp,
            },
            SSAOp::Return { target: rip_1 },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);
        ctx.state.return_blocks.insert(block.addr);

        let stmts = ctx.fold_block(&block, block.addr);
        let return_count = stmts
            .iter()
            .filter(|stmt| matches!(stmt, CStmt::Return(_)))
            .count();
        assert_eq!(return_count, 1, "Should emit a single high-level return");
    }

    #[test]
    fn test_non_return_block_return_rax0_uses_last_return_value() {
        let rax_1 = make_var("RAX", 1, 8);
        let rax_0 = make_var("RAX", 0, 8);

        let block = make_block(vec![
            SSAOp::Copy {
                dst: rax_1.clone(),
                src: make_var("const:2a", 0, 8),
            },
            SSAOp::Copy {
                dst: rax_0.clone(),
                src: rax_1,
            },
            SSAOp::Return { target: rax_0 },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);
        let stmts = ctx.fold_block(&block, block.addr);

        let Some(CStmt::Return(Some(expr))) = stmts.last() else {
            panic!("Expected trailing return statement");
        };
        assert!(
            !matches!(expr, CExpr::Var(name) if name.eq_ignore_ascii_case("rax_0")),
            "Return should not keep unresolved RAX_0 artifact in non-return blocks"
        );
    }

    #[test]
    fn test_non_return_block_return_eax0_uses_last_return_value() {
        let eax_1 = make_var("EAX", 1, 4);
        let eax_0 = make_var("EAX", 0, 4);

        let block = make_block(vec![
            SSAOp::Copy {
                dst: eax_1.clone(),
                src: make_var("const:7", 0, 4),
            },
            SSAOp::Copy {
                dst: eax_0.clone(),
                src: eax_1,
            },
            SSAOp::Return { target: eax_0 },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);
        let stmts = ctx.fold_block(&block, block.addr);

        let Some(CStmt::Return(Some(expr))) = stmts.last() else {
            panic!("Expected trailing return statement");
        };
        assert!(
            !matches!(expr, CExpr::Var(name) if name.eq_ignore_ascii_case("eax_0")),
            "Return should not keep unresolved EAX_0 artifact in non-return blocks"
        );
    }

    #[test]
    fn test_non_return_block_return_rax0_kept_when_no_resolution_available() {
        let block = make_block(vec![SSAOp::Return {
            target: make_var("RAX", 0, 8),
        }]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);
        let stmts = ctx.fold_block(&block, block.addr);

        let Some(CStmt::Return(Some(expr))) = stmts.last() else {
            panic!("Expected trailing return statement");
        };
        assert!(
            matches!(expr, CExpr::Var(name) if name.eq_ignore_ascii_case("rax_0") || name.eq_ignore_ascii_case("rax")),
            "Return register should remain unresolved when no better return value can be derived"
        );
    }

    #[test]
    fn test_return_does_not_collapse_to_generic_stack_alias() {
        let ret = make_var("tmp:ret", 1, 8);
        let block = make_block(vec![SSAOp::Return {
            target: ret.clone(),
        }]);

        let mut ctx = FoldingContext::new(64);
        ctx.state.analysis_ctx.use_info.definitions.insert(
            ret.display_name(),
            CExpr::Deref(Box::new(CExpr::binary(
                BinaryOp::Add,
                CExpr::Var("rbp".to_string()),
                CExpr::IntLit(0),
            ))),
        );
        ctx.analyze_block(&block);
        let stmts = ctx.fold_block(&block, block.addr);

        let Some(CStmt::Return(Some(expr))) = stmts.last() else {
            panic!("Expected trailing return statement");
        };
        assert!(
            !matches!(expr, CExpr::Var(name) if name == "stack_0" || name == "saved_fp"),
            "Generic stack placeholders must not leak into visible return expressions"
        );
    }

    #[test]
    fn test_return_does_not_collapse_to_plain_stack_alias() {
        let ret = make_var("tmp:ret2", 1, 8);
        let block = make_block(vec![SSAOp::Return {
            target: ret.clone(),
        }]);

        let mut ctx = FoldingContext::new(64);
        ctx.state
            .analysis_ctx
            .use_info
            .definitions
            .insert(ret.display_name(), CExpr::Var("stack".to_string()));
        ctx.analyze_block(&block);
        let stmts = ctx.fold_block(&block, block.addr);

        let Some(CStmt::Return(Some(expr))) = stmts.last() else {
            panic!("Expected trailing return statement");
        };
        assert!(
            !matches!(expr, CExpr::Var(name) if name == "stack"),
            "plain stack placeholder must not survive in final return expressions"
        );
    }

    #[test]
    fn test_return_prefers_semantic_value_over_unresolved_return_register() {
        let ret = make_var("RAX", 0, 8);
        let block = make_block(vec![SSAOp::Return {
            target: ret.clone(),
        }]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);
        ctx.state
            .analysis_ctx
            .use_info
            .definitions
            .insert(ret.display_name(), CExpr::Var("rax_0".to_string()));
        ctx.state.analysis_ctx.use_info.definitions.insert(
            "resolved_1".to_string(),
            CExpr::Var("arg1".to_string()),
        );
        ctx.state.analysis_ctx.use_info.forwarded_values.insert(
            ret.display_name(),
            crate::analysis::ValueProvenance {
                source: "resolved_1".to_string(),
                source_var: None,
                stack_slot: None,
            },
        );
        let stmts = ctx.fold_block(&block, block.addr);

        let Some(CStmt::Return(Some(expr))) = stmts.last() else {
            panic!("Expected trailing return statement");
        };
        assert_eq!(
            expr,
            &CExpr::Var("arg1".to_string()),
            "return selection should prefer the semantic forwarded value over the unresolved return register"
        );
    }

    #[test]
    fn test_return_control_artifact_prefers_last_semantic_return_value() {
        let rax_1 = make_var("RAX", 1, 8);
        let rip_1 = make_var("RIP", 1, 8);
        let block = make_block(vec![
            SSAOp::Copy {
                dst: rax_1.clone(),
                src: make_var("const:7", 0, 8),
            },
            SSAOp::Return { target: rip_1 },
        ]);

        let mut ctx = FoldingContext::new(64);
        ctx.analyze_block(&block);
        let stmts = ctx.fold_block(&block, block.addr);

        let Some(CStmt::Return(Some(expr))) = stmts.last() else {
            panic!("Expected trailing return statement");
        };
        assert_eq!(
            expr,
            &CExpr::IntLit(7),
            "control-artifact return targets should defer to the tracked semantic return value"
        );
    }

    #[test]
    fn test_return_register_write_keeps_semantic_indexed_load_shape() {
        let idx_src = make_var("ESI", 0, 4);
        let arr_src = make_var("RDI", 0, 8);
        let eax = make_var("EAX", 2, 4);
        let mut ctx = FoldingContext::new(64);
        ctx.state.analysis_ctx.use_info.type_hints.insert(
            arr_src.display_name(),
            CType::ptr(CType::Int(32)),
        );
        ctx.state.analysis_ctx.use_info.type_hints.insert(
            idx_src.display_name(),
            CType::Int(32),
        );
        ctx.state.analysis_ctx.use_info.semantic_values.insert(
            eax.display_name(),
            crate::analysis::SemanticValue::Load {
                addr: crate::analysis::NormalizedAddr {
                    base: crate::analysis::BaseRef::Value(crate::analysis::ValueRef::from(
                        arr_src,
                    )),
                    index: Some(crate::analysis::ValueRef::from(idx_src)),
                    scale_bytes: 4,
                    offset_bytes: 0,
                },
                size: 4,
            },
        );
        assert!(
            ctx.lookup_semantic_value(&eax.display_name()).is_some(),
            "semantic value should be present for the return source"
        );
        let mut base_visited = HashSet::new();
        let base_rendered = ctx.render_value_ref(
            &crate::analysis::ValueRef::from(make_var("RDI", 0, 8)),
            0,
            &mut base_visited,
        );
        let mut index_visited = HashSet::new();
        let index_rendered = ctx.render_value_ref(
            &crate::analysis::ValueRef::from(make_var("ESI", 0, 4)),
            0,
            &mut index_visited,
        );
        assert!(base_rendered.is_some(), "base should render");
        assert!(index_rendered.is_some(), "index should render");
        let mut visited = HashSet::new();
        let semantic = ctx.render_semantic_value_by_name(&eax.display_name(), 0, &mut visited);
        assert!(
            matches!(semantic, Some(CExpr::Subscript { .. })),
            "semantic return source should render as subscript before return selection, got {semantic:?}"
        );
        let expr = ctx.get_return_expr(&eax);
        assert!(
            matches!(expr, CExpr::Subscript { .. }),
            "semantic indexed load should survive get_return_expr for return-register sources, got {expr:?}"
        );
    }

    #[test]
    fn test_live_arm64_check_secret_then_block_folds_to_return_zero() {
        use r2il::R2ILBlock;
        use r2ssa::{PhiNode, SSAFunction};

        let mut b0 = R2ILBlock::new(0x1000, 4);
        b0.push(R2ILOp::CBranch {
            target: Varnode::constant(0x100c, 8),
            cond: Varnode::constant(1, 1),
        });
        let mut b_fallthrough = R2ILBlock::new(0x1004, 4);
        b_fallthrough.push(R2ILOp::Branch {
            target: Varnode::constant(0x1008, 8),
        });
        let mut b_else = R2ILBlock::new(0x1008, 4);
        b_else.push(R2ILOp::Branch {
            target: Varnode::constant(0x1010, 8),
        });
        let mut b_then = R2ILBlock::new(0x100c, 4);
        b_then.push(R2ILOp::Branch {
            target: Varnode::constant(0x1010, 8),
        });
        let mut b_exit = R2ILBlock::new(0x1010, 4);
        b_exit.push(R2ILOp::Return {
            target: Varnode::constant(0, 8),
        });
        let blocks = vec![b0, b_fallthrough, b_else, b_then, b_exit];
        let mut func = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("ssa function");

        func.get_block_mut(0x1000).expect("entry").ops = vec![SSAOp::CBranch {
            target: make_var("ram:1020", 0, 8),
            cond: make_var("tmp:a00", 1, 1),
        }];
        func.get_block_mut(0x1004).expect("fallthrough").ops = vec![SSAOp::Branch {
            target: make_var("ram:1008", 0, 8),
        }];
        func.get_block_mut(0x1008).expect("else").ops = vec![
            SSAOp::Copy {
                dst: make_var("X8", 3, 8),
                src: make_var("const:1", 0, 8),
            },
            SSAOp::IntAdd {
                dst: make_var("tmp:6400", 3, 8),
                a: make_var("SP", 1, 8),
                b: make_var("const:c", 0, 8),
            },
            SSAOp::Store {
                space: "ram".to_string(),
                addr: make_var("tmp:6400", 3, 8),
                val: make_var("W8", 0, 4),
            },
            SSAOp::Branch {
                target: make_var("ram:1010", 0, 8),
            },
        ];
        func.get_block_mut(0x100c).expect("then").ops = vec![
            SSAOp::IntAdd {
                dst: make_var("tmp:6400", 4, 8),
                a: make_var("SP", 1, 8),
                b: make_var("const:c", 0, 8),
            },
            SSAOp::Store {
                space: "ram".to_string(),
                addr: make_var("tmp:6400", 4, 8),
                val: make_var("const:0", 0, 4),
            },
            SSAOp::Branch {
                target: make_var("ram:1010", 0, 8),
            },
        ];
        let exit = func.get_block_mut(0x1010).expect("exit");
        exit.phis = vec![
            PhiNode {
                dst: make_var("X8", 4, 8),
                sources: vec![
                    (0x100c, make_var("X8", 0, 8)),
                    (0x1008, make_var("X8", 0, 8)),
                ],
            },
            PhiNode {
                dst: make_var("tmp:300", 2, 4),
                sources: vec![
                    (0x100c, make_var("tmp:300", 0, 4)),
                    (0x1008, make_var("tmp:300", 0, 4)),
                ],
            },
            PhiNode {
                dst: make_var("tmp:6400", 5, 8),
                sources: vec![
                    (0x100c, make_var("tmp:6400", 0, 8)),
                    (0x1008, make_var("tmp:6400", 0, 8)),
                ],
            },
        ];
        exit.ops = vec![
            SSAOp::IntAdd {
                dst: make_var("tmp:6400", 6, 8),
                a: make_var("SP", 1, 8),
                b: make_var("const:c", 0, 8),
            },
            SSAOp::Load {
                dst: make_var("tmp:24c00", 2, 4),
                space: "ram".to_string(),
                addr: make_var("tmp:6400", 6, 8),
            },
            SSAOp::IntZExt {
                dst: make_var("X0", 1, 8),
                src: make_var("tmp:24c00", 2, 4),
            },
            SSAOp::Copy {
                dst: make_var("PC", 1, 8),
                src: make_var("X30", 0, 8),
            },
            SSAOp::Return {
                target: make_var("PC", 1, 8),
            },
        ];

        let mut ctx = make_aarch64_ctx();
        ctx.analyze_blocks(&func.blocks().cloned().collect::<Vec<_>>());
        ctx.analyze_function_structure(&func);

        assert!(ctx.state.return_blocks.contains(&0x100c));
        assert!(ctx.state.return_blocks.contains(&0x1008));
        assert!(ctx.state.return_stack_slots.contains(&12));

        let then_block = func.get_block(0x100c).expect("then block");
        let then_stmts = ctx.fold_block(then_block, then_block.addr);
        let Some(CStmt::Return(Some(expr))) = then_stmts.last() else {
            panic!("expected trailing return in then block, got {then_stmts:?}");
        };
        assert_eq!(expr, &CExpr::IntLit(0));
    }

    #[test]
    fn test_observed_live_arm64_check_secret_then_block_folds_to_return_zero() {
        use r2il::R2ILBlock;
        use r2ssa::{PhiNode, SSAFunction};

        let mut b0 = R2ILBlock::new(0x1000, 4);
        b0.push(R2ILOp::CBranch {
            target: Varnode::constant(0x1020, 8),
            cond: Varnode::constant(1, 1),
        });
        let mut b_fallthrough = R2ILBlock::new(0x1004, 4);
        b_fallthrough.push(R2ILOp::Branch {
            target: Varnode::constant(0x1008, 8),
        });
        let mut b_else = R2ILBlock::new(0x1008, 4);
        b_else.push(R2ILOp::Branch {
            target: Varnode::constant(0x1010, 8),
        });
        let mut b_then = R2ILBlock::new(0x1020, 4);
        b_then.push(R2ILOp::Branch {
            target: Varnode::constant(0x1010, 8),
        });
        let mut b_exit = R2ILBlock::new(0x1010, 4);
        b_exit.push(R2ILOp::Return {
            target: Varnode::constant(0, 8),
        });
        let blocks = vec![b0, b_fallthrough, b_else, b_then, b_exit];
        let mut func = SSAFunction::from_blocks_raw_no_arch(&blocks).expect("ssa function");

        func.get_block_mut(0x1000).expect("entry").ops = vec![SSAOp::CBranch {
            target: make_var("ram:1020", 0, 8),
            cond: make_var("tmp:a00", 1, 1),
        }];
        func.get_block_mut(0x1004).expect("fallthrough").ops = vec![SSAOp::Branch {
            target: make_var("ram:1008", 0, 8),
        }];
        func.get_block_mut(0x1008).expect("else").ops = vec![
            SSAOp::Copy {
                dst: make_var("X8", 3, 8),
                src: make_var("const:1", 0, 8),
            },
            SSAOp::IntAdd {
                dst: make_var("tmp:6400", 3, 8),
                a: make_var("SP", 1, 8),
                b: make_var("const:c", 0, 8),
            },
            SSAOp::Store {
                space: "ram".to_string(),
                addr: make_var("tmp:6400", 3, 8),
                val: make_var("W8", 0, 4),
            },
            SSAOp::Branch {
                target: make_var("ram:1010", 0, 8),
            },
        ];
        func.get_block_mut(0x1020).expect("then").ops = vec![
            SSAOp::IntAdd {
                dst: make_var("tmp:6400", 6, 8),
                a: make_var("SP", 1, 8),
                b: make_var("const:c", 0, 8),
            },
            SSAOp::Copy {
                dst: make_var("tmp:300", 2, 4),
                src: make_var("const:0", 0, 4),
            },
            SSAOp::Store {
                space: "ram".to_string(),
                addr: make_var("tmp:6400", 6, 8),
                val: make_var("const:0", 0, 4),
            },
            SSAOp::Branch {
                target: make_var("ram:1010", 0, 8),
            },
        ];
        let exit = func.get_block_mut(0x1010).expect("exit");
        exit.phis = vec![
            PhiNode {
                dst: make_var("tmp:300", 1, 4),
                sources: vec![
                    (0x1020, make_var("const:0", 0, 4)),
                    (0x1008, make_var("tmp:300", 0, 4)),
                ],
            },
            PhiNode {
                dst: make_var("tmp:6400", 4, 8),
                sources: vec![
                    (0x1020, make_var("tmp:6400", 6, 8)),
                    (0x1008, make_var("tmp:6400", 0, 8)),
                ],
            },
            PhiNode {
                dst: make_var("X8", 4, 8),
                sources: vec![
                    (0x1020, make_var("X8", 2, 8)),
                    (0x1008, make_var("X8", 0, 8)),
                ],
            },
        ];
        exit.ops = vec![
            SSAOp::IntAdd {
                dst: make_var("tmp:6400", 5, 8),
                a: make_var("SP", 1, 8),
                b: make_var("const:c", 0, 8),
            },
            SSAOp::Load {
                dst: make_var("tmp:24c00", 2, 4),
                space: "ram".to_string(),
                addr: make_var("tmp:6400", 5, 8),
            },
            SSAOp::IntZExt {
                dst: make_var("X0", 1, 8),
                src: make_var("tmp:24c00", 2, 4),
            },
            SSAOp::Copy {
                dst: make_var("tmp:11e80", 1, 8),
                src: make_var("const:10", 0, 8),
            },
            SSAOp::IntCarry {
                dst: make_var("TMPCY", 2, 1),
                a: make_var("SP", 1, 8),
                b: make_var("const:10", 0, 8),
            },
            SSAOp::IntSCarry {
                dst: make_var("TMPOV", 2, 1),
                a: make_var("SP", 1, 8),
                b: make_var("const:10", 0, 8),
            },
            SSAOp::IntAdd {
                dst: make_var("tmp:11f80", 1, 8),
                a: make_var("SP", 1, 8),
                b: make_var("const:10", 0, 8),
            },
            SSAOp::IntSLess {
                dst: make_var("TMPNG", 2, 1),
                a: make_var("tmp:11f80", 1, 8),
                b: make_var("const:0", 0, 8),
            },
            SSAOp::IntEqual {
                dst: make_var("TMPZR", 2, 1),
                a: make_var("tmp:11f80", 1, 8),
                b: make_var("const:0", 0, 8),
            },
            SSAOp::Copy {
                dst: make_var("SP", 2, 8),
                src: make_var("tmp:11f80", 1, 8),
            },
            SSAOp::Copy {
                dst: make_var("PC", 1, 8),
                src: make_var("X30", 0, 8),
            },
            SSAOp::Return {
                target: make_var("PC", 1, 8),
            },
        ];

        let mut ctx = make_aarch64_ctx();
        ctx.analyze_blocks(&func.blocks().cloned().collect::<Vec<_>>());
        ctx.analyze_function_structure(&func);

        let then_block = func.get_block(0x1020).expect("then block");
        let then_stmts = ctx.fold_block(then_block, then_block.addr);
        let Some(CStmt::Return(Some(expr))) = then_stmts.last() else {
            panic!("expected trailing return in observed then block, got {then_stmts:?}");
        };
        assert_eq!(expr, &CExpr::IntLit(0));
    }

}
