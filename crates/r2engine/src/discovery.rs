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
    /// What the program calls it, where anything does. Presentation only.
    pub name: Option<String>,
}

/// Every function in the program, from what the image states and what the
/// bodies reach.
///
/// `walk` answers with the transfers one body makes, or `None` where the body
/// could not be walked at all; a body that cannot be walked contributes no
/// successors and is still a function, because something stated or called it.
pub fn functions(
    program: &dyn Program,
    seeds: impl IntoIterator<Item = (u64, Confidence)>,
    mut walk: impl FnMut(u64) -> Option<Transfers>,
) -> Vec<Discovered> {
    let mut believed = BTreeMap::<u64, Confidence>::new();
    let mut pending = Vec::new();
    let offer = |believed: &mut BTreeMap<u64, Confidence>,
                 pending: &mut Vec<u64>,
                 address: u64,
                 confidence: Confidence| {
        match believed.get(&address) {
            // Already believed at least this strongly, and already queued.
            Some(held) if *held <= confidence => {}
            Some(_) => {
                believed.insert(address, confidence);
            }
            None => {
                believed.insert(address, confidence);
                pending.push(address);
            }
        }
    };
    for (address, confidence) in seeds {
        offer(&mut believed, &mut pending, address, confidence);
    }
    let mut walked = BTreeSet::new();
    while let Some(address) = pending.pop() {
        if !walked.insert(address) {
            continue;
        }
        let Some(transfers) = walk(address) else {
            continue;
        };
        for target in transfers.calls {
            offer(&mut believed, &mut pending, target, Confidence::Called);
        }
        for target in transfers.tail_calls {
            offer(&mut believed, &mut pending, target, Confidence::Reached);
        }
    }
    believed
        .into_iter()
        .map(|(address, confidence)| Discovered {
            address,
            confidence,
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
}

impl From<&r2ssa::body::Body> for Transfers {
    fn from(body: &r2ssa::body::Body) -> Self {
        Self {
            calls: body.calls.clone(),
            tail_calls: body.tail_calls.clone(),
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
        let found = functions(&Named, [(0x1000, Confidence::Stated)], |address| {
            (address == 0x1000).then(|| Transfers {
                calls: vec![0x2000],
                tail_calls: vec![0x3000],
            })
        });
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
            [(0x2000, Confidence::Stated), (0x1000, Confidence::Stated)],
            |address| {
                (address == 0x1000).then(|| Transfers {
                    calls: Vec::new(),
                    tail_calls: vec![0x2000],
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
    fn a_cycle_of_calls_terminates() {
        let found = functions(&Named, [(0x1000, Confidence::Stated)], |address| {
            Some(Transfers {
                calls: vec![match address {
                    0x1000 => 0x2000,
                    _ => 0x1000,
                }],
                tail_calls: Vec::new(),
            })
        });
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn a_body_that_cannot_be_walked_is_still_a_function() {
        let found = functions(&Named, [(0x1000, Confidence::Stated)], |_| None);
        assert_eq!(found.len(), 1);
    }
}
