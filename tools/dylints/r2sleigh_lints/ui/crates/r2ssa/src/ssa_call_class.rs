#![allow(dead_code)]

struct Var(u64);

enum SSAOp {
    Copy { dst: Var, src: Var },
    Branch { target: Var, instruction: Option<u64> },
    BranchInd { target: Var, instruction: Option<u64> },
    Call { target: Var, instruction: Option<u64> },
    CallInd { target: Var, instruction: Option<u64> },
    CallOther { inputs: Vec<Var> },
    CallDefine { dst: Var },
    Nop,
}

impl SSAOp {
    fn is_call(&self) -> bool {
        false
    }
}

// Restates `is_call()`.
fn calls(op: &SSAOp) -> bool {
    matches!(op, SSAOp::Call { .. } | SSAOp::CallInd { .. })
}

// One variant is the class too: a direct call is `transfer()` with `direct`.
fn direct(op: &SSAOp) -> bool {
    matches!(op, SSAOp::Call { .. })
}

// Restates `transfer()`'s target.
fn target(op: &SSAOp) -> Option<&Var> {
    match op {
        SSAOp::Call { target, .. } | SSAOp::CallInd { target, .. } => Some(target),
        _ => None,
    }
}

// Two arms split the class and drop the rest behind a wildcard.
fn through(op: &SSAOp) -> Option<&Var> {
    match op {
        SSAOp::Call { .. } => None,
        SSAOp::CallInd { target, .. } => Some(target),
        _ => None,
    }
}

// A let-else takes the class apart.
fn instruction(op: &SSAOp) -> Option<u64> {
    let (SSAOp::CallInd { instruction, .. } | SSAOp::BranchInd { instruction, .. }) = op else {
        return None;
    };
    *instruction
}

// So does an `if let`.
fn indirect(op: &SSAOp) -> bool {
    if let SSAOp::CallInd { .. } = op {
        return true;
    }
    false
}

// A class beside others is still the class.
fn effect(op: &SSAOp) -> bool {
    matches!(op, SSAOp::Nop | SSAOp::Call { .. } | SSAOp::CallOther { .. })
}

// Behind a wrapper.
fn wrapped(op: Option<&SSAOp>) -> bool {
    matches!(op, Some(SSAOp::CallInd { .. }))
}

// A wildcard inside the wrapper is the default arm too.
fn nested(op: Option<&SSAOp>) -> u8 {
    match op {
        Some(SSAOp::Call { .. }) => 1,
        Some(_) => 0,
        None => 0,
    }
}

// Asks the owner, naming the other operations only.
fn reads_owner(op: &SSAOp) -> bool {
    op.is_call() || matches!(op, SSAOp::CallOther { .. })
}

// Not the call class.
fn jumps(op: &SSAOp) -> bool {
    matches!(op, SSAOp::Branch { .. } | SSAOp::BranchInd { .. })
}

// Every operation named: one added later fails to compile, so none is dropped.
fn exhaustive(op: &SSAOp) -> u8 {
    match op {
        SSAOp::Call { .. } | SSAOp::CallInd { .. } => 1,
        SSAOp::Copy { .. }
        | SSAOp::Branch { .. }
        | SSAOp::BranchInd { .. }
        | SSAOp::CallOther { .. }
        | SSAOp::CallDefine { .. }
        | SSAOp::Nop => 0,
    }
}

// A construction names no pattern.
fn build(target: Var) -> SSAOp {
    SSAOp::Call {
        target,
        instruction: None,
    }
}

#[cfg_attr(dylint_lib = "r2sleigh_lints", allow(ssa_call_class_outside_op, reason = "a policy of this pass"))]
fn guardable(op: &SSAOp) -> bool {
    matches!(op, SSAOp::Nop | SSAOp::Call { .. })
}

fn main() {
    let op = SSAOp::Nop;
    let _ = (calls(&op), direct(&op), target(&op).is_some(), through(&op).is_some());
    let _ = (instruction(&op), indirect(&op), effect(&op), wrapped(None), nested(None));
    let _ = (reads_owner(&op), jumps(&op), guardable(&op), exhaustive(&op));
    let _ = build(Var(0)).is_call();
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_test_may_classify() {
        let op = super::SSAOp::Nop;
        assert!(!matches!(op, super::SSAOp::Call { .. } | super::SSAOp::CallInd { .. }));
    }
}
