#![allow(dead_code)]

#[derive(Clone, PartialEq)]
struct Varnode(u64);

enum ValueUse {
    Carries,
    Consumes,
}

enum R2ILOp {
    Copy { dst: Varnode, src: Varnode },
    Select { dst: Varnode, cond: Varnode },
    Store { addr: Varnode, val: Varnode },
    Call { target: Varnode },
    CallInd { target: Varnode },
    Nop,
}

impl R2ILOp {
    fn inputs(&self) -> Vec<&Varnode> {
        Vec::new()
    }

    fn is_call(&self) -> bool {
        false
    }
}

// Restates `output()`: `Select` added later would fall to `None`.
fn output(op: &R2ILOp) -> Option<&Varnode> {
    match op {
        R2ILOp::Copy { dst, .. } | R2ILOp::Select { dst, .. } => Some(dst),
        _ => None,
    }
}

// Restates `is_call()`.
fn calls(op: &R2ILOp) -> bool {
    matches!(op, R2ILOp::Call { .. } | R2ILOp::CallInd { .. })
}

// Restates `inputs()` with a bare binding as the wildcard.
fn reads(op: &R2ILOp) -> Vec<&Varnode> {
    match op {
        R2ILOp::Copy { src, .. } => vec![src],
        R2ILOp::Store { addr, val } => vec![addr, val],
        _other => Vec::new(),
    }
}

// Restates `value_use()`: an r2il property answered in its own type.
fn value_use(op: &R2ILOp) -> ValueUse {
    match op {
        R2ILOp::Copy { .. } | R2ILOp::Select { .. } => ValueUse::Carries,
        _ => ValueUse::Consumes,
    }
}

// A wildcard inside the wrapper drops the rest too.
fn nested_output(op: Option<&R2ILOp>) -> Option<&Varnode> {
    match op {
        Some(R2ILOp::Copy { dst, .. } | R2ILOp::Select { dst, .. }) => Some(dst),
        Some(_) => None,
        None => None,
    }
}

// One operation named: "is it this one", not a class.
fn is_store(op: &R2ILOp) -> bool {
    matches!(op, R2ILOp::Store { .. })
}

// The wildcard asks r2il, so nothing is dropped.
fn reads_but_zeroing(op: &R2ILOp) -> Vec<&Varnode> {
    match op {
        R2ILOp::Copy { src, dst } | R2ILOp::Select { dst, cond: src } if src == dst => Vec::new(),
        op => op.inputs(),
    }
}

// A wildcard behind a guard is not the catch-all; the arm after it asks r2il.
fn boundary(op: &R2ILOp) -> bool {
    match op {
        R2ILOp::Nop | R2ILOp::Copy { .. } => false,
        _ if op.is_call() => true,
        _ => op.is_call(),
    }
}

// Not an op property's shape.
fn rank(op: &R2ILOp) -> u8 {
    match op {
        R2ILOp::Copy { .. } | R2ILOp::Select { .. } => 1,
        _ => 0,
    }
}

#[cfg_attr(dylint_lib = "r2sleigh_lints", allow(r2il_op_property_outside_r2il, reason = "a policy of this pass"))]
fn guardable(op: &R2ILOp) -> bool {
    matches!(op, R2ILOp::Store { .. } | R2ILOp::Copy { .. })
}

fn main() {
    let op = R2ILOp::Nop;
    let _ = (output(&op), calls(&op), reads(&op), value_use(&op), is_store(&op));
    let _ = (reads_but_zeroing(&op), boundary(&op), rank(&op), guardable(&op), nested_output(None));
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_test_may_classify() {
        let op = super::R2ILOp::Nop;
        assert!(!matches!(op, super::R2ILOp::Call { .. } | super::R2ILOp::CallInd { .. }));
    }
}
