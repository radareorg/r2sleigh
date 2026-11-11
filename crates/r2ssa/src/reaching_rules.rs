//! The rule both backward walks over a register's definitions obey.
//!
//! Two passes ask what value reaches a function's return register.
//! `liveout::FunctionLiveOut` asks it to recover the interface, before any
//! machine context exists; `semantic::reaching_abi_return_register_in_block`
//! asks it again at the return boundary, with one. Asking twice is not the
//! problem -- an interface recovered without a machine context and a boundary
//! checked with one are genuinely different questions about different inputs.
//!
//! Answering with two different rules is. The two disagreed, and the weaker
//! answer fed the recovered interface: the liveout walk read only each
//! operation's destination and so passed straight through a call, naming
//! whatever had been put in the register before it. For a function whose last
//! act is `warnx(fmt, ...)` that is the format string, recovered as the value
//! the function returns. Nothing rendered it only because the stricter walk
//! refused the boundary afterwards, which is luck rather than design.
//!
//! So the rule lives here, once, and both walks call it while keeping their own
//! traversals. That is the same arrangement the binding plan's construction and
//! seal already use, and for the same reason: two independent derivations of
//! one answer are a cross-check, two independently written statements of one
//! rule are two answerers that drift.

use crate::function::SSAFunction;
use crate::op::SSAOp;

/// Whether an operation overwrites the register a backward search is following.
///
/// A call owns the result register. The convention names the same register for
/// a callee's result and for its caller's, so a call reached walking backwards
/// has overwritten what came before it, and its predecessors cannot answer
/// either -- they run before the call.
///
/// A user operation writes only the output its p-code names, except one that enters the supervisor.
///
/// Two operations are deliberately not here, and both were in one of the two
/// walks before this rule was shared.
///
/// `Return` is a boundary, not a writer. Each walk already knows where its own
/// boundary is -- the return-boundary walk slices the operations before it, the
/// liveout walk starts at the returning block's last operation, which *is* the
/// return -- so treating it as a stop made the liveout walk halt on its own
/// starting point and find nothing at all.
///
/// `CallDefine` is the operation that gives a call's result a name, so it *is*
/// the definition a walk is looking for. Stopping on it refuses to see the
/// value a function returning `f(x)` hands back.
pub(crate) fn op_ends_reaching_walk(
    function: &SSAFunction,
    graph: &crate::graph::SsaGraph,
    op: &SSAOp<crate::ValueId>,
    storage: crate::CanonicalStorageId,
) -> bool {
    (op.is_call() && !call_passes(function, graph, op, storage)) || function.enters_supervisor(op)
}

/// Whether `op` is a direct call whose callee's body leaves every byte of `storage` as it found it on
/// every path (D212): what reaches the call reaches past it.
fn call_passes(
    function: &SSAFunction,
    graph: &crate::graph::SsaGraph,
    op: &SSAOp<crate::ValueId>,
    storage: crate::CanonicalStorageId,
) -> bool {
    let target = (op.call().filter(|call| call.direct))
        .and_then(|call| graph.value(*call.target)?.canonical_storage)
        .filter(|target| target.space == crate::CanonicalStorageSpace::Ram);
    target.is_some_and(|target| function.call_passes(target.offset, storage))
}
