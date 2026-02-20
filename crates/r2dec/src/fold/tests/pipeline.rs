#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use crate::ExternalStackVar;
    use r2il::{R2ILBlock, R2ILOp, Varnode};
    use r2types::{Signedness, SolvedTypes, SolverDiagnostics, TypeArena};

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
        let CExpr::PtrMember { member, .. } = expr else {
            panic!("expected pointer member access");
        };
        assert_eq!(member, "field_30");
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
}
