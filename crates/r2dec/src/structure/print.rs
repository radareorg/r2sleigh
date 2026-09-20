//! The structured tier, printed.
//!
//! The tree the C is generated from: the regions the structurer placed, the
//! control it chose, and the statements spelled by the same emitter that
//! writes the C. A defect in the output is either visible here or belongs to
//! the lowering below it, and being able to say which is the whole reason this
//! exists.
//!
//! This supersedes the one-line digest the control certificate used to build
//! for its own tracing, which collapsed every statement to `s;` and truncated
//! at four thousand characters.

use crate::ast::{CFunction, CStmt};
use crate::codegen::CodeGenConfig;
use crate::codegen::CodeGenerator;

/// The function's structured tier, one statement per line.
pub(crate) fn render(function: &CFunction, config: CodeGenConfig) -> String {
    let mut out = String::new();
    out.push_str(&format!("Function: {}\n", function.name));
    if !function.locals.is_empty() {
        out.push_str(&format!("Locals: {}\n", function.locals.len()));
    }
    out.push('\n');
    let mut generator = CodeGenerator::new(config);
    // The names in the tree were issued by this function's table, so the
    // emitter has to read them there and nowhere else.
    generator.adopt_symbols(&function.symbols.borrow());
    for stmt in &function.body {
        walk(stmt, 0, &mut generator, &mut out);
    }
    out
}

fn indent(depth: usize, out: &mut String) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

/// One statement, and whatever it contains.
fn walk(stmt: &CStmt, depth: usize, generator: &mut CodeGenerator, out: &mut String) {
    match stmt {
        // The marker is the point: it says which machine block this text is,
        // which is what a reader comparing tiers needs.
        CStmt::StructuredRegion { marker, stmt } => {
            indent(depth, out);
            out.push_str(&format!("{:?}@{:#x}\n", marker.kind(), marker.entry()));
            walk(stmt, depth + 1, generator, out);
        }
        CStmt::Observed { stmt, .. } => walk(stmt, depth, generator, out),
        CStmt::Block(stmts) => stmts
            .iter()
            .for_each(|stmt| walk(stmt, depth, generator, out)),
        CStmt::If {
            cond,
            then_body,
            else_body,
        } => {
            indent(depth, out);
            out.push_str(&format!("if ({})\n", generator.generate_expr(cond)));
            walk(then_body, depth + 1, generator, out);
            if let Some(else_body) = else_body {
                indent(depth, out);
                out.push_str("else\n");
                walk(else_body, depth + 1, generator, out);
            }
        }
        CStmt::While { cond, body } => {
            indent(depth, out);
            out.push_str(&format!("while ({})\n", generator.generate_expr(cond)));
            walk(body, depth + 1, generator, out);
        }
        CStmt::DoWhile { body, cond } => {
            indent(depth, out);
            out.push_str("do\n");
            walk(body, depth + 1, generator, out);
            indent(depth, out);
            out.push_str(&format!("while ({})\n", generator.generate_expr(cond)));
        }
        CStmt::For { cond, body, .. } => {
            indent(depth, out);
            match cond {
                Some(cond) => {
                    out.push_str(&format!("for (; {}; )\n", generator.generate_expr(cond)))
                }
                None => out.push_str("loop\n"),
            }
            walk(body, depth + 1, generator, out);
        }
        CStmt::Switch {
            expr,
            cases,
            default,
        } => {
            indent(depth, out);
            out.push_str(&format!("switch ({})\n", generator.generate_expr(expr)));
            for case in cases {
                indent(depth + 1, out);
                out.push_str(&format!("case {}:\n", generator.generate_expr(&case.value)));
                case.body
                    .iter()
                    .for_each(|stmt| walk(stmt, depth + 2, generator, out));
            }
            if let Some(default) = default {
                indent(depth + 1, out);
                out.push_str("default:\n");
                default
                    .iter()
                    .for_each(|stmt| walk(stmt, depth + 2, generator, out));
            }
        }
        // A leaf is spelled by the emitter that writes the C, so the tier and
        // the output disagree about nothing but their shape.
        other => {
            indent(depth, out);
            let text = generator.generate_stmt(other);
            out.push_str(text.trim_end());
            out.push('\n');
        }
    }
}
