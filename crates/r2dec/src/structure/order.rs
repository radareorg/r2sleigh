//! The write order of a placement, which the order-invariance gate permutes (ROADMAP D58); without
//! the `placement_mutants` feature there is one order and no branch.

#[cfg(feature = "placement_mutants")]
pub(crate) use crate::placement_mutants::WriteOrder;
#[cfg(not(feature = "placement_mutants"))]
pub(crate) use off::WriteOrder;

// Compiled under test with the feature too, so the production order is pinned wherever tests run.
#[cfg(any(test, not(feature = "placement_mutants")))]
mod off {
    /// The only order: the facts' own.
    #[derive(Clone, Copy)]
    pub(crate) struct WriteOrder;

    impl WriteOrder {
        pub(crate) const fn current() -> Self {
            Self
        }

        pub(crate) const fn inlines_exits(self) -> bool {
            true
        }

        pub(crate) fn exits(self, _: &mut [u64]) {}

        pub(crate) fn merges(self, _: &mut [u64]) {}
    }
}

#[cfg(test)]
mod tests {
    /// The order every production build writes in is the facts' own: exits inlined, no list permuted.
    #[test]
    fn production_writes_in_the_facts_own_order() {
        let production = super::off::WriteOrder::current();
        let mut list = [3, 1, 2];
        production.exits(&mut list);
        assert_eq!(list, [3, 1, 2]);
        production.merges(&mut list);
        assert_eq!(list, [3, 1, 2]);
        assert!(production.inlines_exits());
    }
}
