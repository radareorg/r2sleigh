#![allow(dead_code)]

struct Var(u64);

enum SSAOp {
    Call { target: Var },
    CallInd { target: Var },
    Nop,
}

// r2ssa's `op.rs` owns the call class; its own list is not a restatement.
impl SSAOp {
    fn is_call(&self) -> bool {
        matches!(self, SSAOp::Call { .. } | SSAOp::CallInd { .. })
    }
}

fn main() {
    let _ = SSAOp::Nop.is_call();
}
