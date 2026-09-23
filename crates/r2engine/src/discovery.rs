//! Which addresses in a program are functions, and why each one is believed to
//! be.
//!
//! A symbol table is not discovery. `r2s` listed what the image named and
//! nothing else, so a stripped binary offered no function at all while its
//! entry points, its initialiser arrays and its procedure-linkage stubs were
//! already computed and thrown away.
//!
//! Discovery is the least set of addresses closed under "walk it and take
//! where it transfers", started from what the image states. It is a fixed
//! point, so it terminates: the set only grows, every member is an address in
//! the image, and the image is finite.
//!
//! Every address carries why it is here. That is the first inferred fact this
//! engine produces, so it is the first one that needs saying how far it can be
//! trusted -- an entry point is the format's own statement and a tail jump's
//! target is this engine's reading of one instruction, and a consumer that
//! cannot tell them apart has to treat both as the weaker.

use std::collections::{BTreeMap, BTreeSet};

use crate::native::Program;

/// Why an address is believed to begin a function.
///
/// Ordered by how much is being claimed, strongest first, so a consumer may
/// take everything at or above the level it is willing to act on. An address
/// found twice keeps the stronger reason: a symbol that is also called is
/// stated, not inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// The image says so. An entry point, an initialiser or finaliser array
    /// slot, a symbol typed as a function, a linkage stub the format declares.
    /// Nothing is inferred and nothing can be wrong here that is not wrong in
    /// the file.
    Stated,
    /// A walked body calls it. One decoded call instruction with a constant
    /// target, which is a reading of bytes this engine did itself.
    Called,
    /// A walked body hands it to a function whose declaration says that
    /// parameter is a function.
    ///
    /// `entry0` never calls `main`: it passes it to `__libc_start_main`, whose
    /// prototype spells the first parameter `func`. The address is a function
    /// on the declaration's authority plus a constant this engine folded, so
    /// it is weaker than a call the machine makes and stronger than a
    /// transfer that may be a jump inside one function.
    Handed,
    /// A walked body leaves for it without returning. The same reading, over
    /// an instruction that is a jump: whether the target is a function of its
    /// own or a continuation of this one is exactly what a tail call makes
    /// ambiguous.
    Reached,
}

/// One address discovery believes is a function.
#[derive(Debug, Clone)]
pub struct Discovered {
    pub address: u64,
    pub confidence: Confidence,
    /// Whether its code is Thumb rather than the image's own instruction set.
    pub thumb: bool,
    /// What the program calls it, where anything does. Presentation only.
    pub name: Option<String>,
}

/// Every function in the program, from what the image states and what the
/// bodies reach.
///
/// Each seed carries the instruction set the image states it is written in.
/// `walk` is told the one each address is entered in and answers with the
/// transfers that body makes, or `None` where it could not be walked at all; a
/// body that cannot be walked contributes no successors and is still a
/// function, because something stated or called it.
pub fn functions(
    program: &dyn Program,
    seeds: impl IntoIterator<Item = (u64, Confidence, bool)>,
    mut walk: impl FnMut(u64, bool) -> Option<Transfers>,
) -> Vec<Discovered> {
    let mut believed = BTreeMap::<u64, (Confidence, bool)>::new();
    let mut pending = Vec::new();
    // The first reason decides the instruction set: the seeds, which state
    // it, are offered before anything is walked.
    let offer = |believed: &mut BTreeMap<u64, (Confidence, bool)>,
                 pending: &mut Vec<u64>,
                 address: u64,
                 confidence: Confidence,
                 thumb: bool| {
        match believed.get_mut(&address) {
            // Already believed at least this strongly, and already queued.
            Some((held, _)) if *held <= confidence => {}
            Some((held, _)) => *held = confidence,
            None => {
                believed.insert(address, (confidence, thumb));
                pending.push(address);
            }
        }
    };
    for (address, confidence, thumb) in seeds {
        offer(&mut believed, &mut pending, address, confidence, thumb);
    }
    let mut walked = BTreeSet::new();
    while let Some(address) = pending.pop() {
        if !walked.insert(address) {
            continue;
        }
        let thumb = believed[&address].1;
        let Some(transfers) = walk(address, thumb) else {
            continue;
        };
        // A transfer that states no instruction set keeps this body's.
        let entered = |target: u64| transfers.entered_in.get(&target).copied().unwrap_or(thumb);
        for &target in &transfers.calls {
            offer(
                &mut believed,
                &mut pending,
                target,
                Confidence::Called,
                entered(target),
            );
        }
        for &target in &transfers.handed {
            offer(
                &mut believed,
                &mut pending,
                target,
                Confidence::Handed,
                entered(target),
            );
        }
        for &target in &transfers.tail_calls {
            offer(
                &mut believed,
                &mut pending,
                target,
                Confidence::Reached,
                entered(target),
            );
        }
    }
    believed
        .into_iter()
        .map(|(address, (confidence, thumb))| Discovered {
            address,
            confidence,
            thumb,
            name: program.name_at(address),
        })
        .collect()
}

/// Where one body transfers, which is the whole of what discovery reads from
/// it.
#[derive(Debug, Clone, Default)]
pub struct Transfers {
    pub calls: Vec<u64>,
    pub tail_calls: Vec<u64>,
    /// Addresses this body passed to a parameter a declaration calls a
    /// function. The walk cannot see these: they are constants in argument
    /// slots, not targets of any instruction.
    pub handed: Vec<u64>,
    /// Whether each target is entered in Thumb, where the transfer states it.
    pub entered_in: BTreeMap<u64, bool>,
}

impl From<&r2ssa::body::Body> for Transfers {
    fn from(body: &r2ssa::body::Body) -> Self {
        Self {
            calls: body.calls.clone(),
            tail_calls: body.tail_calls.clone(),
            handed: Vec::new(),
            // Sleigh's `ISAModeSwitch` holds the Thumb bit a call enters with.
            entered_in: body
                .entered_with
                .iter()
                .map(|(target, mode)| (*target, *mode != 0))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Named;

    impl r2ssa::body::Program for Named {
        fn read(&self, _vaddr: u64, _max: usize) -> Option<Vec<u8>> {
            None
        }

        fn is_entry(&self, _vaddr: u64) -> bool {
            false
        }
    }

    impl Program for Named {
        fn name_at(&self, vaddr: u64) -> Option<String> {
            (vaddr == 0x1000).then(|| "entry".to_owned())
        }

        fn import_at(&self, _vaddr: u64) -> Option<String> {
            None
        }

        fn holds_static_data(&self, _vaddr: u64) -> bool {
            false
        }
    }

    #[test]
    fn a_call_reaches_a_function_the_image_never_named() {
        let found = functions(
            &Named,
            [(0x1000, Confidence::Stated, false)],
            |address, _| {
                (address == 0x1000).then(|| Transfers {
                    calls: vec![0x2000],
                    tail_calls: vec![0x3000],
                    ..Transfers::default()
                })
            },
        );
        let seen = found
            .iter()
            .map(|one| (one.address, one.confidence))
            .collect::<Vec<_>>();
        assert_eq!(
            seen,
            [
                (0x1000, Confidence::Stated),
                (0x2000, Confidence::Called),
                (0x3000, Confidence::Reached),
            ]
        );
        assert_eq!(found[0].name.as_deref(), Some("entry"));
    }

    #[test]
    fn an_address_found_twice_keeps_the_stronger_reason() {
        // Reached first and stated second: the order a walk happens to take
        // must not decide how far a fact can be trusted.
        let found = functions(
            &Named,
            [
                (0x2000, Confidence::Stated, false),
                (0x1000, Confidence::Stated, false),
            ],
            |address, _| {
                (address == 0x1000).then(|| Transfers {
                    tail_calls: vec![0x2000],
                    ..Transfers::default()
                })
            },
        );
        assert_eq!(
            found
                .iter()
                .find(|one| one.address == 0x2000)
                .map(|one| one.confidence),
            Some(Confidence::Stated)
        );
    }

    #[test]
    fn an_address_handed_to_a_declared_function_parameter_is_believed() {
        // Nothing transfers to it: it was put in an argument register and the
        // callee's declaration says that parameter is a function.
        let found = functions(
            &Named,
            [(0x1000, Confidence::Stated, false)],
            |address, _| {
                (address == 0x1000).then(|| Transfers {
                    calls: Vec::new(),
                    tail_calls: Vec::new(),
                    handed: vec![0x4000],
                    ..Transfers::default()
                })
            },
        );
        let seen = found
            .iter()
            .map(|one| (one.address, one.confidence))
            .collect::<Vec<_>>();
        assert_eq!(
            seen,
            vec![(0x1000, Confidence::Stated), (0x4000, Confidence::Handed)]
        );
    }

    #[test]
    fn a_call_outranks_a_handoff_for_the_same_address() {
        // Both are true; the stronger reason is the one the machine makes.
        let found = functions(
            &Named,
            [(0x1000, Confidence::Stated, false)],
            |address, _| {
                (address == 0x1000).then(|| Transfers {
                    calls: vec![0x4000],
                    tail_calls: Vec::new(),
                    handed: vec![0x4000],
                    ..Transfers::default()
                })
            },
        );
        assert_eq!(
            found
                .iter()
                .find(|one| one.address == 0x4000)
                .map(|one| one.confidence),
            Some(Confidence::Called)
        );
    }

    #[test]
    fn a_cycle_of_calls_terminates() {
        let found = functions(
            &Named,
            [(0x1000, Confidence::Stated, false)],
            |address, _| {
                Some(Transfers {
                    calls: vec![match address {
                        0x1000 => 0x2000,
                        _ => 0x1000,
                    }],
                    tail_calls: Vec::new(),
                    ..Transfers::default()
                })
            },
        );
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn a_body_that_cannot_be_walked_is_still_a_function() {
        let found = functions(&Named, [(0x1000, Confidence::Stated, false)], |_, _| None);
        assert_eq!(found.len(), 1);
    }
}
