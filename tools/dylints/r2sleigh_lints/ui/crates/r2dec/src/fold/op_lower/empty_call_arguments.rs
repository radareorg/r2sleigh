enum CExpr {
    Call(Box<CExpr>, Vec<CExpr>),
    Sym(&'static str),
    External { name: &'static str },
}

impl CExpr {
    fn call(target: CExpr, arguments: Vec<CExpr>) -> CExpr {
        CExpr::Call(Box::new(target), arguments)
    }
}

// The renderer writes the argument list empty: `f()` whatever the call passed.
fn lower_call(target: CExpr) -> CExpr {
    CExpr::call(target, vec![])
}

// The arguments come from the callsite facts.
fn lower_call_with_arguments(target: CExpr, arguments: Vec<CExpr>) -> CExpr {
    CExpr::call(target, arguments)
}

// A helper the renderer defines has the arity the renderer gave it.
fn trap() -> CExpr {
    CExpr::call(
        CExpr::External {
            name: "__builtin_trap",
        },
        vec![],
    )
}

fn main() {
    let _ = lower_call(CExpr::Sym("f"));
    let _ = lower_call_with_arguments(CExpr::Sym("g"), vec![CExpr::Sym("x")]);
    let _ = trap();
}
