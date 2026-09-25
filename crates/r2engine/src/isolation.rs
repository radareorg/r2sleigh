//! Where a defect in one function's analysis stops.
//!
//! A panic anywhere below a request -- in the walk, the SSA preparation, the
//! type analysis or the rendering -- used to unwind through the shell and end
//! the whole session, so one bad function took every other answer with it.
//! That is not the analysis refusing; it is the analysis failing to say
//! anything at all.
//!
//! **This is isolation, not a fix.** A caught panic is still a defect to
//! trace, so it is never swallowed: it becomes that function's refusal,
//! carrying the source location the panic hook saw and the panic's own
//! message, and the output says so wherever the refusal is printed. What the
//! boundary buys is only that the defect stays inside the function it
//! happened in: a callee's panic leaves its caller rendered with the callee
//! unread, and a root's panic leaves the session running.
//!
//! The boundaries are few and named: the per-function analysis the memo
//! derives, the sealed type analysis and rendering read from it, and each
//! callee a root reads. A memo never holds what unwound, because the value is
//! stored only after the derivation returns.
//!
//! An out-of-memory abort is not a panic and cannot be caught; the only
//! defence there is never to size an allocation by an unproven count.

use std::cell::{Cell, RefCell};
use std::panic::{AssertUnwindSafe, PanicHookInfo};
use std::sync::Once;

/// Where a panic was raised, as the panic hook saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanicLocation {
    pub file: String,
    pub line: u32,
    pub column: u32,
}

impl std::fmt::Display for PanicLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.file, self.line, self.column)
    }
}

/// A panic caught at an isolation boundary: where it was raised and what it said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Panicked {
    /// `None` only where something replaced the hook this module installs
    /// after it was installed, so the location was never seen.
    pub location: Option<PanicLocation>,
    pub message: String,
}

impl std::fmt::Display for Panicked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.location {
            Some(location) => write!(f, "panicked at {location}: {}", self.message),
            None => write!(f, "panicked at an unrecorded location: {}", self.message),
        }
    }
}

thread_local! {
    /// How many isolation boundaries this thread is inside.
    static DEPTH: Cell<usize> = const { Cell::new(0) };
    /// Where the last panic raised inside a boundary on this thread was raised.
    static RAISED: RefCell<Option<PanicLocation>> = const { RefCell::new(None) };
}

static HOOK: Once = Once::new();

/// Chain a hook that records where a panic inside a boundary was raised.
///
/// The hook it replaces still runs, so a caught panic is still reported
/// where panics are reported; only the location is kept beside it, because
/// the payload `catch_unwind` returns does not carry one.
fn install() {
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info: &PanicHookInfo<'_>| {
            if DEPTH.with(Cell::get) > 0 {
                let location = info.location().map(|location| PanicLocation {
                    file: location.file().to_owned(),
                    line: location.line(),
                    column: location.column(),
                });
                RAISED.with(|raised| *raised.borrow_mut() = location);
            }
            previous(info);
        }));
    });
}

/// Run `work`, and turn a panic inside it into the value that says where it was raised.
///
/// Every piece of state `work` touches is either owned by it or recovers
/// from a poisoned lock, and nothing it half-built is kept: whoever called
/// this stores `work`'s value only when it returned one.
pub fn isolated<T>(work: impl FnOnce() -> T) -> Result<T, Panicked> {
    install();
    RAISED.with(|raised| raised.borrow_mut().take());
    DEPTH.with(|depth| depth.set(depth.get() + 1));
    let result = std::panic::catch_unwind(AssertUnwindSafe(work));
    DEPTH.with(|depth| depth.set(depth.get() - 1));
    result.map_err(|payload| {
        let message = payload
            .downcast_ref::<&str>()
            .map(|message| (*message).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "a panic that carried no message".to_owned());
        Panicked {
            location: RAISED.with(|raised| raised.borrow_mut().take()),
            message,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panic_is_caught_with_where_it_was_raised_and_what_it_said() {
        let line = line!() + 1;
        let caught = isolated(|| -> u32 { panic!("the analysis broke") });
        let caught = caught.expect_err("the panic is caught");
        assert_eq!(caught.message, "the analysis broke");
        let location = caught.location.expect("the hook saw it");
        assert!(location.file.ends_with("isolation.rs"), "{location}");
        assert_eq!(location.line, line);
    }

    #[test]
    fn an_inner_boundary_keeps_its_own_panic_and_the_outer_one_returns() {
        let outer = isolated(|| isolated(|| -> u32 { panic!("inner") }));
        let inner = outer.expect("the outer boundary saw no panic");
        assert_eq!(inner.expect_err("the inner one did").message, "inner");
        assert_eq!(isolated(|| 7), Ok(7));
    }
}
