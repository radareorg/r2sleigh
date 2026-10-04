//! Dense containers over a sealed function's ids (doc/adr-one-ir.md, F2.0).
//!
//! A sealed function's operations, instructions, values and blocks are
//! numbered densely from zero. A fact about them is therefore a vector
//! indexed by id, not a tree or a hash keyed by one: a lookup is one index,
//! iteration is in id order and so deterministic, and two passes that need
//! the same relation can share it.
//!
//! - [`IdVec`]: a value for every id.
//! - [`IdMap`]: a value for some ids.
//! - [`IdSet`]: a set of ids, as a bitset.
//! - [`Csr`]: for each id, a slice of related items (def-use, predecessors),
//!   in compressed sparse row form.

use std::marker::PhantomData;

/// An id numbered densely from zero within one function.
pub trait DenseId: Copy + Ord {
    fn index(self) -> usize;
    fn from_index(index: usize) -> Self;
}

macro_rules! dense_id {
    ($id:ty) => {
        impl DenseId for $id {
            fn index(self) -> usize {
                self.0 as usize
            }
            fn from_index(index: usize) -> Self {
                Self(u32::try_from(index).expect("fewer than 2^32 ids"))
            }
        }
    };
}

dense_id!(crate::graph::ValueId);
dense_id!(crate::graph::InstId);
dense_id!(crate::graph::BlockId);

/// A value for every id below a bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdVec<I, T> {
    cells: Vec<T>,
    ids: PhantomData<fn(I) -> I>,
}

impl<I: DenseId, T> IdVec<I, T> {
    /// `len` cells, each computed from its id.
    pub fn from_fn(len: usize, mut cell: impl FnMut(I) -> T) -> Self {
        Self {
            cells: (0..len).map(|index| cell(I::from_index(index))).collect(),
            ids: PhantomData,
        }
    }

    /// `len` cells, each `value`.
    pub fn filled(len: usize, value: T) -> Self
    where
        T: Clone,
    {
        Self {
            cells: vec![value; len],
            ids: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.cells.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    pub fn get(&self, id: I) -> Option<&T> {
        self.cells.get(id.index())
    }

    pub fn get_mut(&mut self, id: I) -> Option<&mut T> {
        self.cells.get_mut(id.index())
    }

    /// Every id with its cell, in id order.
    pub fn iter(&self) -> impl Iterator<Item = (I, &T)> {
        self.cells
            .iter()
            .enumerate()
            .map(|(index, cell)| (I::from_index(index), cell))
    }
}

impl<I: DenseId, T> std::ops::Index<I> for IdVec<I, T> {
    type Output = T;

    fn index(&self, id: I) -> &T {
        &self.cells[id.index()]
    }
}

impl<I: DenseId, T> std::ops::IndexMut<I> for IdVec<I, T> {
    fn index_mut(&mut self, id: I) -> &mut T {
        &mut self.cells[id.index()]
    }
}

/// A value for some of the ids below a bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdMap<I, T> {
    cells: Vec<Option<T>>,
    count: usize,
    ids: PhantomData<fn(I) -> I>,
}

impl<I: DenseId, T> IdMap<I, T> {
    /// An empty map over ids below `len`.
    pub fn new(len: usize) -> Self {
        Self {
            cells: std::iter::repeat_with(|| None).take(len).collect(),
            count: 0,
            ids: PhantomData,
        }
    }

    /// How many ids have a value.
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn get(&self, id: I) -> Option<&T> {
        self.cells.get(id.index())?.as_ref()
    }

    pub fn get_mut(&mut self, id: I) -> Option<&mut T> {
        self.cells.get_mut(id.index())?.as_mut()
    }

    pub fn contains(&self, id: I) -> bool {
        self.get(id).is_some()
    }

    /// Set `id`'s value, returning the one it replaces. An id at or past
    /// the bound grows the map to hold it.
    pub fn insert(&mut self, id: I, value: T) -> Option<T> {
        let index = id.index();
        if index >= self.cells.len() {
            self.cells.resize_with(index + 1, || None);
        }
        let previous = self.cells[index].replace(value);
        if previous.is_none() {
            self.count += 1;
        }
        previous
    }

    pub fn remove(&mut self, id: I) -> Option<T> {
        let previous = self.cells.get_mut(id.index())?.take();
        if previous.is_some() {
            self.count -= 1;
        }
        previous
    }

    /// Every id with a value, in id order.
    pub fn iter(&self) -> impl Iterator<Item = (I, &T)> {
        self.cells
            .iter()
            .enumerate()
            .filter_map(|(index, cell)| Some((I::from_index(index), cell.as_ref()?)))
    }

    pub fn keys(&self) -> impl Iterator<Item = I> + '_ {
        self.iter().map(|(id, _)| id)
    }
}

/// A set of ids below a bound, one bit each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdSet<I> {
    words: Vec<u64>,
    ids: PhantomData<fn(I) -> I>,
}

impl<I: DenseId> IdSet<I> {
    /// An empty set over ids below `len`.
    pub fn new(len: usize) -> Self {
        Self {
            words: vec![0; len.div_ceil(64)],
            ids: PhantomData,
        }
    }

    pub fn contains(&self, id: I) -> bool {
        let index = id.index();
        self.words
            .get(index / 64)
            .is_some_and(|word| word & (1 << (index % 64)) != 0)
    }

    /// Add `id`; whether it was absent.
    pub fn insert(&mut self, id: I) -> bool {
        let index = id.index();
        if index / 64 >= self.words.len() {
            self.words.resize(index / 64 + 1, 0);
        }
        let word = &mut self.words[index / 64];
        let bit = 1 << (index % 64);
        let absent = *word & bit == 0;
        *word |= bit;
        absent
    }

    /// Remove `id`; whether it was present.
    pub fn remove(&mut self, id: I) -> bool {
        let index = id.index();
        let Some(word) = self.words.get_mut(index / 64) else {
            return false;
        };
        let bit = 1 << (index % 64);
        let present = *word & bit != 0;
        *word &= !bit;
        present
    }

    /// Add every member of `other`; whether this set grew.
    pub fn union_with(&mut self, other: &Self) -> bool {
        if other.words.len() > self.words.len() {
            self.words.resize(other.words.len(), 0);
        }
        let mut grew = false;
        for (mine, theirs) in self.words.iter_mut().zip(&other.words) {
            let joined = *mine | theirs;
            grew |= joined != *mine;
            *mine = joined;
        }
        grew
    }

    pub fn len(&self) -> usize {
        self.words
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }

    /// The members, in id order.
    pub fn iter(&self) -> impl Iterator<Item = I> + '_ {
        self.words.iter().enumerate().flat_map(|(at, word)| {
            let mut bits = *word;
            std::iter::from_fn(move || {
                (bits != 0).then(|| {
                    let bit = bits.trailing_zeros() as usize;
                    bits &= bits - 1;
                    I::from_index(at * 64 + bit)
                })
            })
        })
    }
}

/// For each id below a bound, a slice of items: an adjacency in compressed
/// sparse row form, built once from its pairs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Csr<I, T> {
    starts: Vec<u32>,
    items: Vec<T>,
    ids: PhantomData<fn(I) -> I>,
}

impl<I: DenseId, T> Csr<I, T> {
    /// From `(id, item)` pairs over ids below `len`. Each id's items keep
    /// the order the pairs gave them. Two passes: count, then place.
    pub fn from_pairs(len: usize, pairs: impl IntoIterator<Item = (I, T)>) -> Self {
        let pairs = pairs.into_iter().collect::<Vec<_>>();
        let mut starts = vec![0u32; len + 1];
        for (id, _) in &pairs {
            starts[id.index() + 1] += 1;
        }
        for index in 0..len {
            starts[index + 1] += starts[index];
        }
        let mut next = starts.clone();
        let mut slots = std::iter::repeat_with(|| None)
            .take(pairs.len())
            .collect::<Vec<Option<T>>>();
        for (id, item) in pairs {
            let at = &mut next[id.index()];
            slots[*at as usize] = Some(item);
            *at += 1;
        }
        Self {
            starts,
            items: slots
                .into_iter()
                .map(|slot| slot.expect("every slot is filled once"))
                .collect(),
            ids: PhantomData,
        }
    }

    /// `id`'s items; empty for an id at or past the bound.
    pub fn get(&self, id: I) -> &[T] {
        let index = id.index();
        match (self.starts.get(index), self.starts.get(index + 1)) {
            (Some(start), Some(end)) => &self.items[*start as usize..*end as usize],
            _ => &[],
        }
    }

    pub fn len(&self) -> usize {
        self.starts.len().saturating_sub(1)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::ValueId;

    #[test]
    fn a_map_keeps_id_order_and_counts_what_it_holds() {
        let mut map = IdMap::<ValueId, &str>::new(4);
        assert_eq!(map.insert(ValueId(2), "two"), None);
        assert_eq!(map.insert(ValueId(0), "zero"), None);
        assert_eq!(map.insert(ValueId(9), "nine"), None);
        assert_eq!(map.insert(ValueId(2), "again"), Some("two"));
        assert_eq!(map.len(), 3);
        assert_eq!(
            map.iter().collect::<Vec<_>>(),
            [
                (ValueId(0), &"zero"),
                (ValueId(2), &"again"),
                (ValueId(9), &"nine")
            ]
        );
        assert_eq!(map.remove(ValueId(0)), Some("zero"));
        assert!(!map.contains(ValueId(0)));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn a_set_unions_and_says_whether_it_grew() {
        let mut a = IdSet::<ValueId>::new(70);
        let mut b = IdSet::<ValueId>::new(130);
        assert!(a.insert(ValueId(3)));
        assert!(!a.insert(ValueId(3)));
        b.insert(ValueId(65));
        b.insert(ValueId(129));
        assert!(a.union_with(&b));
        assert!(!a.union_with(&b));
        assert_eq!(
            a.iter().collect::<Vec<_>>(),
            [ValueId(3), ValueId(65), ValueId(129)]
        );
        assert_eq!(a.len(), 3);
        assert!(a.remove(ValueId(65)));
        assert!(!a.contains(ValueId(65)));
    }

    #[test]
    fn a_csr_gives_each_id_its_items_in_the_order_given() {
        let csr = Csr::<ValueId, u32>::from_pairs(
            4,
            [
                (ValueId(2), 20),
                (ValueId(0), 1),
                (ValueId(2), 21),
                (ValueId(0), 2),
            ],
        );
        assert_eq!(csr.get(ValueId(0)), [1, 2]);
        assert!(csr.get(ValueId(1)).is_empty());
        assert_eq!(csr.get(ValueId(2)), [20, 21]);
        assert!(csr.get(ValueId(3)).is_empty());
        assert!(csr.get(ValueId(9)).is_empty());
    }
}
