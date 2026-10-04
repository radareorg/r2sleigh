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
///
/// Most facts hold for a few ids of many, and their values are large, so the
/// map does not keep a value cell per id: each id has a four-byte slot naming
/// its entry, entries are packed, and a bitset of the ids present makes
/// iteration in id order cost `O(bound / 64 + entries)`. A lookup is two
/// indexed loads; insertion and removal are `O(1)`.
#[derive(Debug, Clone)]
pub struct IdMap<I, T> {
    slots: Vec<u32>,
    entries: Vec<(I, T)>,
    present: IdSet<I>,
}

/// A slot no entry fills.
const VACANT: u32 = u32::MAX;

impl<I: DenseId, T> IdMap<I, T> {
    /// An empty map over ids below `len`.
    pub fn new(len: usize) -> Self {
        Self {
            slots: vec![VACANT; len],
            entries: Vec::new(),
            present: IdSet::new(len),
        }
    }

    /// How many ids have a value.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn slot(&self, id: I) -> Option<usize> {
        match self.slots.get(id.index()) {
            Some(&slot) if slot != VACANT => Some(slot as usize),
            _ => None,
        }
    }

    pub fn get(&self, id: I) -> Option<&T> {
        self.slot(id).map(|slot| &self.entries[slot].1)
    }

    pub fn get_mut(&mut self, id: I) -> Option<&mut T> {
        let slot = self.slot(id)?;
        Some(&mut self.entries[slot].1)
    }

    pub fn contains(&self, id: I) -> bool {
        self.slot(id).is_some()
    }

    /// Set `id`'s value, returning the one it replaces. An id at or past
    /// the bound grows the map to hold it.
    pub fn insert(&mut self, id: I, value: T) -> Option<T> {
        if let Some(slot) = self.slot(id) {
            return Some(std::mem::replace(&mut self.entries[slot].1, value));
        }
        let index = id.index();
        if index >= self.slots.len() {
            self.slots.resize(index + 1, VACANT);
        }
        self.slots[index] = u32::try_from(self.entries.len()).expect("fewer than 2^32 entries");
        self.entries.push((id, value));
        self.present.insert(id);
        None
    }

    /// `id`'s value, inserting `value()` first where it has none.
    pub fn get_or_insert_with(&mut self, id: I, value: impl FnOnce() -> T) -> &mut T {
        if self.slot(id).is_none() {
            self.insert(id, value());
        }
        self.get_mut(id).expect("inserted above")
    }

    pub fn remove(&mut self, id: I) -> Option<T> {
        let slot = self.slot(id)?;
        self.slots[id.index()] = VACANT;
        self.present.remove(id);
        let (_, value) = self.entries.swap_remove(slot);
        if let Some((moved, _)) = self.entries.get(slot) {
            self.slots[moved.index()] = slot as u32;
        }
        Some(value)
    }

    /// Keep only the values `keep` accepts, asking in id order as an
    /// ordered map would; `O(bound / 64 + entries)`.
    pub fn retain(&mut self, mut keep: impl FnMut(I, &mut T) -> bool) {
        let ids = self.present.iter().collect::<Vec<_>>();
        for id in ids {
            let slot = self.slots[id.index()] as usize;
            if !keep(id, &mut self.entries[slot].1) {
                self.remove(id);
            }
        }
    }

    /// Every id with a value, in id order.
    pub fn iter(&self) -> impl Iterator<Item = (I, &T)> {
        self.present
            .iter()
            .map(|id| (id, &self.entries[self.slots[id.index()] as usize].1))
    }

    pub fn keys(&self) -> impl Iterator<Item = I> + '_ {
        self.present.iter()
    }

    /// The values, in id order.
    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.iter().map(|(_, value)| value)
    }
}

impl<'a, I: DenseId, T> IntoIterator for &'a IdMap<I, T> {
    type Item = (I, &'a T);
    type IntoIter = Box<dyn Iterator<Item = (I, &'a T)> + 'a>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter())
    }
}

/// Written as a map from id to value, in id order: the shape an ordered map
/// of the same entries is written in.
impl<I: DenseId + serde::Serialize, T: serde::Serialize> serde::Serialize for IdMap<I, T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self.iter())
    }
}

impl<'de, I, T> serde::Deserialize<'de> for IdMap<I, T>
where
    I: DenseId + Ord + serde::Deserialize<'de>,
    T: serde::Deserialize<'de>,
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let entries = std::collections::BTreeMap::<I, T>::deserialize(deserializer)?;
        Ok(entries.into_iter().collect())
    }
}

/// The entries, moved out in id order.
impl<I: DenseId, T> IntoIterator for IdMap<I, T> {
    type Item = (I, T);
    type IntoIter = std::vec::IntoIter<(I, T)>;

    fn into_iter(self) -> Self::IntoIter {
        let mut entries = self.entries;
        entries.sort_unstable_by_key(|(id, _)| id.index());
        entries.into_iter()
    }
}

/// Two maps are equal when they hold the same values for the same ids,
/// whatever order the values were inserted in.
impl<I: DenseId, T: PartialEq> PartialEq for IdMap<I, T> {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}

impl<I: DenseId, T: Eq> Eq for IdMap<I, T> {}

/// An empty map; it grows to hold whatever is inserted.
impl<I: DenseId, T> Default for IdMap<I, T> {
    fn default() -> Self {
        Self::new(0)
    }
}

impl<I: DenseId, T> FromIterator<(I, T)> for IdMap<I, T> {
    fn from_iter<A: IntoIterator<Item = (I, T)>>(entries: A) -> Self {
        let mut map = Self::default();
        map.extend(entries);
        map
    }
}

impl<I: DenseId, T> Extend<(I, T)> for IdMap<I, T> {
    fn extend<A: IntoIterator<Item = (I, T)>>(&mut self, entries: A) {
        for (id, value) in entries {
            self.insert(id, value);
        }
    }
}

impl<I: DenseId, T> std::ops::Index<I> for IdMap<I, T> {
    type Output = T;

    fn index(&self, id: I) -> &T {
        self.get(id).expect("indexed an id the map holds")
    }
}

/// A set of ids below a bound, one bit each.
#[derive(Debug, Clone)]
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

/// Two sets are equal when they hold the same ids, whatever bound each was
/// made with or grew to.
impl<I> PartialEq for IdSet<I> {
    fn eq(&self, other: &Self) -> bool {
        let (short, long) = match self.words.len() <= other.words.len() {
            true => (&self.words, &other.words),
            false => (&other.words, &self.words),
        };
        long[..short.len()] == short[..] && long[short.len()..].iter().all(|word| *word == 0)
    }
}

impl<I> Eq for IdSet<I> {}

/// An empty set; it grows to hold whatever is inserted.
impl<I: DenseId> Default for IdSet<I> {
    fn default() -> Self {
        Self::new(0)
    }
}

impl<I: DenseId> FromIterator<I> for IdSet<I> {
    fn from_iter<T: IntoIterator<Item = I>>(ids: T) -> Self {
        let mut set = Self::default();
        set.extend(ids);
        set
    }
}

impl<I: DenseId> Extend<I> for IdSet<I> {
    fn extend<T: IntoIterator<Item = I>>(&mut self, ids: T) {
        for id in ids {
            self.insert(id);
        }
    }
}

/// The members, in id order.
impl<I: DenseId> IntoIterator for IdSet<I> {
    type Item = I;
    type IntoIter = std::vec::IntoIter<I>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter().collect::<Vec<_>>().into_iter()
    }
}

impl<'a, I: DenseId> IntoIterator for &'a IdSet<I> {
    type Item = I;
    type IntoIter = Box<dyn Iterator<Item = I> + 'a>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter())
    }
}

/// A worklist of ids that hands back the least one queued, each id at most
/// once while it waits: an ordered set used only through `insert` and
/// `pop_first`, at `O(log n)` per operation.
#[derive(Debug, Clone)]
pub struct IdWorklist<I> {
    heap: std::collections::BinaryHeap<std::cmp::Reverse<usize>>,
    queued: IdSet<I>,
}

impl<I: DenseId> Default for IdWorklist<I> {
    fn default() -> Self {
        Self {
            heap: std::collections::BinaryHeap::new(),
            queued: IdSet::default(),
        }
    }
}

impl<I: DenseId> IdWorklist<I> {
    /// Queue `id`; whether it was not already waiting.
    pub fn insert(&mut self, id: I) -> bool {
        let fresh = self.queued.insert(id);
        if fresh {
            self.heap.push(std::cmp::Reverse(id.index()));
        }
        fresh
    }

    /// The least id waiting, taken off the list.
    pub fn pop_first(&mut self) -> Option<I> {
        let std::cmp::Reverse(index) = self.heap.pop()?;
        let id = I::from_index(index);
        self.queued.remove(id);
        Some(id)
    }

    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
}

impl<I: DenseId> FromIterator<I> for IdWorklist<I> {
    fn from_iter<T: IntoIterator<Item = I>>(ids: T) -> Self {
        let mut list = Self::default();
        for id in ids {
            list.insert(id);
        }
        list
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

    proptest::proptest! {
        /// An `IdMap` is the map its operations describe: the same values,
        /// the same length, and iteration in id order, whatever order the
        /// ids were inserted and removed in.
        #[test]
        fn an_id_map_behaves_as_an_ordered_map(
            operations in proptest::collection::vec((0u32..200, proptest::option::of(0u32..1000)), 0..400)
        ) {
            let mut map = IdMap::<ValueId, u32>::new(64);
            let mut model = std::collections::BTreeMap::new();
            for (id, value) in operations {
                match value {
                    Some(value) => {
                        proptest::prop_assert_eq!(map.insert(ValueId(id), value), model.insert(id, value));
                    }
                    None => {
                        proptest::prop_assert_eq!(map.remove(ValueId(id)), model.remove(&id));
                    }
                }
                proptest::prop_assert_eq!(map.len(), model.len());
            }
            let held = map.iter().map(|(id, value)| (id.0, *value)).collect::<Vec<_>>();
            let expected = model.iter().map(|(id, value)| (*id, *value)).collect::<Vec<_>>();
            proptest::prop_assert_eq!(held, expected);
            for id in 0..200 {
                proptest::prop_assert_eq!(map.get(ValueId(id)), model.get(&id));
            }
            // Keeping the even ids is keeping them in the model.
            proptest::prop_assert_eq!(
                map.clone().into_iter().collect::<Vec<_>>(),
                map.iter().map(|(id, value)| (id, *value)).collect::<Vec<_>>()
            );
            let mut kept = map.clone();
            let mut asked = Vec::new();
            kept.retain(|id, _| {
                asked.push(id.0);
                id.0 % 2 == 0
            });
            let mut kept_model = model.clone();
            kept_model.retain(|id, _| id % 2 == 0);
            proptest::prop_assert_eq!(asked, model.keys().copied().collect::<Vec<_>>());
            proptest::prop_assert_eq!(
                kept.iter().map(|(id, value)| (id.0, *value)).collect::<Vec<_>>(),
                kept_model.into_iter().collect::<Vec<_>>()
            );
            // Collected afresh, from bound zero, it is the same map.
            let rebuilt = map.iter().map(|(id, value)| (id, *value)).collect::<IdMap<_, _>>();
            proptest::prop_assert!(rebuilt == map);
        }

        /// An `IdWorklist` hands back what an ordered set used as a worklist
        /// would: the least waiting id, each at most once while it waits.
        #[test]
        fn an_id_worklist_behaves_as_an_ordered_set_worklist(
            operations in proptest::collection::vec(proptest::option::of(0u32..100), 0..400)
        ) {
            let mut list = IdWorklist::<ValueId>::default();
            let mut model = std::collections::BTreeSet::new();
            for operation in operations {
                match operation {
                    Some(id) => {
                        proptest::prop_assert_eq!(list.insert(ValueId(id)), model.insert(id));
                    }
                    None => {
                        proptest::prop_assert_eq!(list.pop_first().map(|id| id.0), model.pop_first());
                    }
                }
                proptest::prop_assert_eq!(list.is_empty(), model.is_empty());
            }
        }

        /// An `IdSet` is the set its operations describe, and two sets are
        /// equal exactly when their members are, whatever bound each was made
        /// with or grew to.
        #[test]
        fn an_id_set_behaves_as_an_ordered_set(
            first in proptest::collection::vec((0u32..300, proptest::bool::ANY), 0..300),
            second in proptest::collection::vec((0u32..300, proptest::bool::ANY), 0..300),
        ) {
            let build = |bound: usize, operations: &[(u32, bool)]| {
                let mut set = IdSet::<ValueId>::new(bound);
                let mut model = std::collections::BTreeSet::new();
                for &(id, add) in operations {
                    let (changed, expected) = match add {
                        true => (set.insert(ValueId(id)), model.insert(id)),
                        false => (set.remove(ValueId(id)), model.remove(&id)),
                    };
                    assert_eq!(changed, expected);
                }
                (set, model)
            };
            let (left, left_model) = build(0, &first);
            let (right, right_model) = build(320, &second);
            proptest::prop_assert_eq!(left.len(), left_model.len());
            proptest::prop_assert_eq!(
                left.iter().map(|id| id.0).collect::<Vec<_>>(),
                left_model.iter().copied().collect::<Vec<_>>()
            );
            proptest::prop_assert_eq!(left == right, left_model == right_model);
            let (same, _) = build(320, &first);
            proptest::prop_assert!(same == left);
        }
    }
}
