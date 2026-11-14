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
//! - [`SparseMap`]: a value for a few ids, sized by its entries: a dataflow state copied per block.
//! - [`IdSet`]: a set of ids, as a bitset.
//! - [`Csr`]: for each id, a slice of related items (def-use, predecessors),
//!   in compressed sparse row form.
//! - [`Condensation`]: a `Csr` graph's strongly connected components, the one
//!   Tarjan's search; [`Reached`] numbers a graph stated on demand for it.
//! - [`Metered`]: a function-scale table whose whole iterations the work meter counts (D417).

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
dense_id!(crate::semantic::CallSiteId);

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

    #[inline]
    pub fn get(&self, id: I) -> Option<&T> {
        self.cells.get(id.index())
    }

    /// Every id with its cell, in id order.
    #[cfg_attr(feature = "work-meter", track_caller)]
    pub fn iter(&self) -> impl Iterator<Item = (I, &T)> {
        visits(self.cells.iter())
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

    #[inline]
    pub fn get(&self, id: I) -> Option<&T> {
        self.slot(id).map(|slot| &self.entries[slot].1)
    }

    #[inline]
    pub fn get_mut(&mut self, id: I) -> Option<&mut T> {
        let slot = self.slot(id)?;
        Some(&mut self.entries[slot].1)
    }

    #[inline]
    pub fn contains(&self, id: I) -> bool {
        self.slot(id).is_some()
    }

    /// Set `id`'s value, returning the one it replaces. An id at or past
    /// the bound grows the map to hold it.
    #[inline]
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
    #[inline]
    pub fn get_or_insert_with(&mut self, id: I, value: impl FnOnce() -> T) -> &mut T {
        if self.slot(id).is_none() {
            self.insert(id, value());
        }
        self.get_mut(id).expect("inserted above")
    }

    #[inline]
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
    #[cfg_attr(feature = "work-meter", track_caller)]
    pub fn iter(&self) -> impl Iterator<Item = (I, &T)> {
        self.present
            .iter()
            .map(|id| (id, &self.entries[self.slots[id.index()] as usize].1))
    }

    #[cfg_attr(feature = "work-meter", track_caller)]
    pub fn keys(&self) -> impl Iterator<Item = I> + '_ {
        self.present.iter()
    }

    /// Each value, to update in place, in no stated order: the updates must not depend on one
    /// another (removal swaps entries, so neither id nor insertion order holds).
    #[cfg_attr(feature = "work-meter", track_caller)]
    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut T> {
        visits(self.entries.iter_mut()).map(|(_, value)| value)
    }

    #[cfg_attr(feature = "work-meter", track_caller)]
    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.iter().map(|(_, value)| value)
    }
}

impl<'a, I: DenseId, T> IntoIterator for &'a IdMap<I, T> {
    type Item = (I, &'a T);
    type IntoIter = Box<dyn Iterator<Item = (I, &'a T)> + 'a>;

    #[cfg_attr(feature = "work-meter", track_caller)]
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

    #[cfg_attr(feature = "work-meter", track_caller)]
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
        let entries = entries.into_iter();
        self.entries.reserve(entries.size_hint().0);
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

    #[inline]
    pub fn contains(&self, id: I) -> bool {
        let index = id.index();
        self.words
            .get(index / 64)
            .is_some_and(|word| word & (1 << (index % 64)) != 0)
    }

    /// Add `id`; whether it was absent.
    #[inline]
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
    #[inline]
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
    #[cfg_attr(feature = "work-meter", track_caller)]
    pub fn iter(&self) -> impl Iterator<Item = I> + '_ {
        visits(self.words.iter().enumerate().flat_map(|(at, word)| {
            let mut bits = *word;
            std::iter::from_fn(move || {
                (bits != 0).then(|| {
                    let bit = bits.trailing_zeros() as usize;
                    bits &= bits - 1;
                    I::from_index(at * 64 + bit)
                })
            })
        }))
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

    #[cfg_attr(feature = "work-meter", track_caller)]
    fn into_iter(self) -> Self::IntoIter {
        self.iter().collect::<Vec<_>>().into_iter()
    }
}

impl<'a, I: DenseId> IntoIterator for &'a IdSet<I> {
    type Item = I;
    type IntoIter = Box<dyn Iterator<Item = I> + 'a>;

    #[cfg_attr(feature = "work-meter", track_caller)]
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
    #[inline]
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
/// sparse row form, built once from its pairs or a row at a time in id order.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(bound(
    serialize = "T: serde::Serialize",
    deserialize = "T: serde::Deserialize<'de>"
))]
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

    /// Room for `rows` rows of `items` items in all, holding none yet.
    pub fn with_capacity(rows: usize, items: usize) -> Self {
        let mut starts = Vec::with_capacity(rows + 1);
        starts.push(0);
        Self {
            starts,
            items: Vec::with_capacity(items),
            ids: PhantomData,
        }
    }

    /// Append the next id's row: ids are numbered in the order their rows are pushed.
    pub fn push_row(&mut self, row: impl IntoIterator<Item = T>) -> I {
        let id = I::from_index(self.len());
        self.items.extend(row);
        self.starts
            .push(u32::try_from(self.items.len()).expect("fewer than 2^32 items"));
        id
    }

    /// Give back the room the rows grew.
    pub fn shrink_to_fit(&mut self) {
        self.starts.shrink_to_fit();
        self.items.shrink_to_fit();
    }

    /// `id`'s items; empty for an id at or past the bound.
    #[inline]
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

/// A table's rows, open-addressed by hash and at most half full, so each key is held once and a
/// probe reads a slot or two (doc/adr-memory-model.md, MM.12).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HashIndex {
    /// The row's high hash bits, then one more than the row, so zero is an empty slot.
    slots: Vec<u64>,
    rows: usize,
}

impl HashIndex {
    /// An index over `rows` rows, hashed by `hash`.
    pub fn of(rows: usize, hash: impl Fn(u32) -> u64) -> Self {
        let mut index = Self {
            slots: vec![0; rows.next_power_of_two().max(4) * 2],
            rows,
        };
        for row in 0..rows as u32 {
            index.place(hash(row), row);
        }
        index
    }

    /// The row `matches` accepts among those that hash to `hash`.
    pub fn find(&self, hash: u64, matches: impl Fn(u32) -> bool) -> Option<u32> {
        let mask = self.slots.len().checked_sub(1)?;
        let tag = hash >> 32 << 32;
        let mut at = (hash as usize) & mask;
        loop {
            match self.slots[at] {
                0 => return None,
                slot if slot >> 32 << 32 == tag && matches(slot as u32 - 1) => {
                    return Some(slot as u32 - 1);
                }
                _ => at = (at + 1) & mask,
            }
        }
    }

    /// Index `row`, the next row, which hashes to `row_hash`; growing rehashes every row by `hash`.
    #[inline]
    pub fn insert(&mut self, row: u32, row_hash: u64, hash: impl Fn(u32) -> u64) {
        debug_assert_eq!(row as usize, self.rows, "rows are indexed in order");
        if (self.rows + 1) * 2 > self.slots.len() {
            let mut grown = Self {
                slots: vec![0; (self.slots.len() * 2).max(8)],
                rows: self.rows,
            };
            for at in 0..self.rows as u32 {
                grown.place(hash(at), at);
            }
            *self = grown;
        }
        self.place(row_hash, row);
        self.rows += 1;
    }

    fn place(&mut self, hash: u64, row: u32) {
        let mask = self.slots.len() - 1;
        let mut at = (hash as usize) & mask;
        while self.slots[at] != 0 {
            at = (at + 1) & mask;
        }
        self.slots[at] = hash >> 32 << 32 | u64::from(row + 1);
    }

    /// Give back the slots growth left beyond twice the rows.
    pub fn shrink_to_fit(&mut self, hash: impl Fn(u32) -> u64) {
        if self.slots.len() > self.rows.next_power_of_two().max(4) * 2 {
            *self = Self::of(self.rows, hash);
        }
    }
}

/// A value for a few ids, sorted by id and sized by its entries: a dataflow state copied per block
/// costs `O(entries)` (doc/adr-next-pass.md, model 8), where an [`IdMap`]'s grows with the bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseMap<I, T> {
    entries: Vec<(I, T)>,
}

impl<I, T> Default for SparseMap<I, T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<I: DenseId, T> SparseMap<I, T> {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn position(&self, id: I) -> Result<usize, usize> {
        self.entries.binary_search_by(|(at, _)| at.cmp(&id))
    }

    #[inline]
    pub fn get(&self, id: I) -> Option<&T> {
        let at = self.position(id).ok()?;
        Some(&self.entries[at].1)
    }

    #[inline]
    pub fn get_mut(&mut self, id: I) -> Option<&mut T> {
        let at = self.position(id).ok()?;
        Some(&mut self.entries[at].1)
    }

    /// Set `id`'s value, returning the one it replaces.
    #[inline]
    pub fn insert(&mut self, id: I, value: T) -> Option<T> {
        match self.position(id) {
            Ok(at) => Some(std::mem::replace(&mut self.entries[at].1, value)),
            Err(at) => {
                self.entries.insert(at, (id, value));
                None
            }
        }
    }

    /// Keep only the entries `other` holds with an equal value, in one pass over both.
    pub fn retain_agreeing(&mut self, other: &Self) -> bool
    where
        T: PartialEq,
    {
        let before = self.entries.len();
        let mut theirs = other.entries.iter().peekable();
        self.entries.retain(|(id, value)| {
            while theirs.next_if(|(at, _)| at < id).is_some() {}
            theirs
                .peek()
                .is_some_and(|(at, other)| at == id && other == value)
        });
        before != self.entries.len()
    }

    /// Keep only the values `keep` accepts, in id order.
    pub fn retain(&mut self, mut keep: impl FnMut(I, &mut T) -> bool) {
        self.entries.retain_mut(|(id, value)| keep(*id, value));
    }

    /// Every id with a value, in id order.
    #[cfg_attr(feature = "work-meter", track_caller)]
    pub fn iter(&self) -> impl Iterator<Item = (I, &T)> {
        visits(self.entries.iter()).map(|(id, value)| (*id, value))
    }
}

/// A node of a graph numbered for one search: a function of a call graph, a block, a view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Node(pub u32);
dense_id!(Node);

/// A strongly connected component, numbered in the order its search closed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Component(pub u32);
dense_id!(Component);

/// Not yet entered by the search.
const UNVISITED: u32 = u32::MAX;

/// A graph's strongly connected components by Tarjan's search, O(V + E): an edge `u → v` has
/// `component(v) <= component(u)` (doc/adr-one-ir.md, "Condensation").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condensation<I> {
    component: IdVec<I, Component>,
    finish: IdVec<I, u32>,
    members: Csr<Component, I>,
    cyclic: IdSet<Component>,
    visits: u64,
}

impl<I: DenseId> Condensation<I> {
    /// The search enters each of `starts`, then each node left in id order, and takes a node's
    /// successors in row order: those two fix every component and finish index.
    pub fn of(successors: &Csr<I, I>, starts: impl IntoIterator<Item = I>) -> Self {
        let count = successors.len();
        let mut search = Tarjan {
            successors,
            order: vec![UNVISITED; count],
            low: vec![0; count],
            on_stack: vec![false; count],
            self_edge: vec![false; count],
            stack: Vec::new(),
            frames: Vec::new(),
            component: vec![Component(UNVISITED); count],
            finish: vec![0; count],
            members: Csr::with_capacity(count, count),
            cyclic: IdSet::new(count),
            entered: 0,
            finished: 0,
            visits: 0,
        };
        let starts = starts.into_iter();
        for start in starts.chain((0..count).map(I::from_index)) {
            search.run(start);
        }
        Self {
            component: IdVec::from_fn(count, |node: I| search.component[node.index()]),
            finish: IdVec::from_fn(count, |node: I| search.finish[node.index()]),
            members: search.members,
            cyclic: search.cyclic,
            visits: search.visits,
        }
    }

    /// The component `node` is in.
    pub fn component(&self, node: I) -> Component {
        self.component[node]
    }

    /// When the search finished `node`: its depth-first postorder index.
    pub fn finish(&self, node: I) -> u32 {
        self.finish[node]
    }

    /// A component's members, ascending.
    pub fn members(&self, component: Component) -> &[I] {
        self.members.get(component)
    }

    /// Every component in the order it closed, each after every component it reaches.
    pub fn components(&self) -> impl Iterator<Item = (Component, &[I])> + '_ {
        (0..self.len())
            .map(Component::from_index)
            .map(|id| (id, self.members(id)))
    }

    /// Whether a component holds a cycle: several members, or one that is its own successor.
    pub fn is_cyclic(&self, component: Component) -> bool {
        self.cyclic.contains(component)
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Nodes entered plus edges followed: `V + E` for every search (the bound, metered).
    pub fn visits(&self) -> u64 {
        self.visits
    }
}

/// One condensation's search state, indexed by node.
struct Tarjan<'a, I> {
    successors: &'a Csr<I, I>,
    order: Vec<u32>,
    low: Vec<u32>,
    on_stack: Vec<bool>,
    self_edge: Vec<bool>,
    stack: Vec<I>,
    /// The depth-first path: each node with the index of its next successor.
    frames: Vec<(I, u32)>,
    component: Vec<Component>,
    finish: Vec<u32>,
    members: Csr<Component, I>,
    cyclic: IdSet<Component>,
    entered: u32,
    finished: u32,
    visits: u64,
}

impl<I: DenseId> Tarjan<'_, I> {
    /// One depth-first walk from `start`; it ends since each node is entered once and each frame
    /// moves past finitely many successors.
    fn run(&mut self, start: I) {
        if self.order[start.index()] != UNVISITED {
            return;
        }
        self.enter(start);
        while let Some(&mut (node, ref mut edge)) = self.frames.last_mut() {
            let Some(&successor) = self.successors.get(node).get(*edge as usize) else {
                self.frames.pop();
                self.leave(node);
                continue;
            };
            *edge += 1;
            self.visits += 1;
            self.self_edge[node.index()] |= successor == node;
            let at = successor.index();
            if self.order[at] == UNVISITED {
                self.enter(successor);
            } else if self.on_stack[at] {
                self.low[node.index()] = self.low[node.index()].min(self.order[at]);
            }
        }
    }

    fn enter(&mut self, node: I) {
        let at = node.index();
        self.order[at] = self.entered;
        self.low[at] = self.entered;
        self.entered += 1;
        self.visits += 1;
        self.on_stack[at] = true;
        self.stack.push(node);
        self.frames.push((node, 0));
    }

    /// Finish `node`: its parent takes its low link, and it closes a component where it is the
    /// root of one.
    fn leave(&mut self, node: I) {
        let at = node.index();
        self.finish[at] = self.finished;
        self.finished += 1;
        if let Some(&(parent, _)) = self.frames.last() {
            let low = self.low[at];
            let parent = &mut self.low[parent.index()];
            *parent = (*parent).min(low);
        }
        if self.low[at] != self.order[at] {
            return;
        }
        let root = (self.stack.iter())
            .rposition(|held| *held == node)
            .expect("an entered node is on the stack until its component closes");
        let mut members = self.stack.split_off(root);
        members.sort_unstable();
        let id = Component::from_index(self.members.len());
        for member in &members {
            self.on_stack[member.index()] = false;
            self.component[member.index()] = id;
        }
        if members.len() > 1 || self.self_edge[at] {
            self.cyclic.insert(id);
        }
        self.members.push_row(members);
    }
}

/// The nodes a graph stated on demand reaches from a root, numbered by ascending key, with their
/// edges: the call graphs the engine discovers as it asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reached<K> {
    keys: Vec<K>,
    root: Node,
    successors: Csr<Node, Node>,
}

impl<K: Copy + Ord + std::hash::Hash> Reached<K> {
    /// `successors` is asked once per node (a key enters `seen` once, so the walk ends), in the
    /// preorder Tarjan's search from `root` takes. O(V + E) probes, O(V log V) to number by key.
    pub fn from(root: K, mut successors: impl FnMut(K) -> Vec<K>) -> Self {
        let mut seen = rustc_hash::FxHashSet::default();
        seen.insert(root);
        let mut rows = vec![(root, successors(root))];
        let mut frames = vec![(0usize, 0usize)];
        while let Some((row, next)) = frames.last_mut() {
            let Some(&to) = rows[*row].1.get(*next) else {
                frames.pop();
                continue;
            };
            *next += 1;
            if seen.insert(to) {
                rows.push((to, successors(to)));
                frames.push((rows.len() - 1, 0));
            }
        }
        let mut keys = rows.iter().map(|(key, _)| *key).collect::<Vec<_>>();
        keys.sort_unstable();
        let index = (keys.iter().enumerate())
            .map(|(at, key)| (*key, Node::from_index(at)))
            .collect::<rustc_hash::FxHashMap<_, _>>();
        let index = &index;
        let edges = rows.iter().flat_map(|(from, to)| {
            let from = index[from];
            to.iter().map(move |to| (from, index[to]))
        });
        let successors = Csr::from_pairs(keys.len(), edges.collect::<Vec<_>>());
        Self {
            root: index[&root],
            keys,
            successors,
        }
    }

    pub fn root(&self) -> Node {
        self.root
    }

    /// The key a node stands for.
    pub fn key(&self, node: Node) -> K {
        self.keys[node.index()]
    }

    pub fn successors(&self) -> &Csr<Node, Node> {
        &self.successors
    }

    /// The condensation of what the root reaches, searched from the root.
    pub fn condensation(&self) -> Condensation<Node> {
        Condensation::of(&self.successors, [self.root])
    }
}

/// A function-scale table (a graph's instructions, values or blocks, a block's instructions, a
/// registry): each whole iteration counts its element visits in a `work-meter` build (D417).
/// Indexing and `len` pass through `Deref`; only `iter`, `values`, `keys` and `for` are counted.
#[derive(Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Metered<C>(C);

impl<C> Metered<C> {
    pub fn into_inner(self) -> C {
        self.0
    }
}

impl<C> From<C> for Metered<C> {
    fn from(table: C) -> Self {
        Self(table)
    }
}

impl<C> std::ops::Deref for Metered<C> {
    type Target = C;

    fn deref(&self) -> &C {
        &self.0
    }
}

impl<C> std::ops::DerefMut for Metered<C> {
    fn deref_mut(&mut self) -> &mut C {
        &mut self.0
    }
}

impl<C: std::fmt::Debug> std::fmt::Debug for Metered<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<T> Metered<Vec<T>> {
    #[cfg_attr(feature = "work-meter", track_caller)]
    pub fn iter(&self) -> Visits<std::slice::Iter<'_, T>> {
        visits(self.0.iter())
    }

    #[cfg_attr(feature = "work-meter", track_caller)]
    pub fn iter_mut(&mut self) -> Visits<std::slice::IterMut<'_, T>> {
        visits(self.0.iter_mut())
    }
}

impl<T> FromIterator<T> for Metered<Vec<T>> {
    fn from_iter<A: IntoIterator<Item = T>>(items: A) -> Self {
        Self(items.into_iter().collect())
    }
}

impl<'a, T> IntoIterator for &'a Metered<Vec<T>> {
    type Item = &'a T;
    type IntoIter = Visits<std::slice::Iter<'a, T>>;

    #[cfg_attr(feature = "work-meter", track_caller)]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut Metered<Vec<T>> {
    type Item = &'a mut T;
    type IntoIter = Visits<std::slice::IterMut<'a, T>>;

    #[cfg_attr(feature = "work-meter", track_caller)]
    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

impl<T> IntoIterator for Metered<Vec<T>> {
    type Item = T;
    type IntoIter = Visits<std::vec::IntoIter<T>>;

    #[cfg_attr(feature = "work-meter", track_caller)]
    fn into_iter(self) -> Self::IntoIter {
        visits(self.0.into_iter())
    }
}

impl<K, V> Metered<std::collections::BTreeMap<K, V>> {
    #[cfg_attr(feature = "work-meter", track_caller)]
    pub fn iter(&self) -> Visits<std::collections::btree_map::Iter<'_, K, V>> {
        visits(self.0.iter())
    }

    #[cfg_attr(feature = "work-meter", track_caller)]
    pub fn values(&self) -> Visits<std::collections::btree_map::Values<'_, K, V>> {
        visits(self.0.values())
    }

    #[cfg_attr(feature = "work-meter", track_caller)]
    pub fn keys(&self) -> Visits<std::collections::btree_map::Keys<'_, K, V>> {
        visits(self.0.keys())
    }

    #[cfg_attr(feature = "work-meter", track_caller)]
    pub fn values_mut(&mut self) -> Visits<std::collections::btree_map::ValuesMut<'_, K, V>> {
        visits(self.0.values_mut())
    }
}

impl<K: Ord, V> FromIterator<(K, V)> for Metered<std::collections::BTreeMap<K, V>> {
    fn from_iter<A: IntoIterator<Item = (K, V)>>(items: A) -> Self {
        Self(items.into_iter().collect())
    }
}

impl<'a, K, V> IntoIterator for &'a Metered<std::collections::BTreeMap<K, V>> {
    type Item = (&'a K, &'a V);
    type IntoIter = Visits<std::collections::btree_map::Iter<'a, K, V>>;

    #[cfg_attr(feature = "work-meter", track_caller)]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// The element visits counted since the process began, in a `work-meter` build; `None` in any
/// other build, never a zero that would claim no work was done.
pub fn element_visits() -> Option<u64> {
    #[cfg(feature = "work-meter")]
    return Some(meter::VISITS.load(std::sync::atomic::Ordering::Relaxed));
    #[cfg(not(feature = "work-meter"))]
    None
}

/// An iterator over a function-scale table: itself unless the build meters work.
#[cfg(not(feature = "work-meter"))]
pub type Visits<I> = I;
#[cfg(feature = "work-meter")]
pub type Visits<I> = meter::Counted<I>;

#[cfg(not(feature = "work-meter"))]
#[inline(always)]
fn visits<I: Iterator>(iter: I) -> Visits<I> {
    iter
}

#[cfg(feature = "work-meter")]
#[track_caller]
fn visits<I: Iterator>(iter: I) -> Visits<I> {
    meter::Counted {
        iter,
        at: std::panic::Location::caller(),
        count: 0,
    }
}

/// The element visits counted at each call site, most first, in a `work-meter` build.
pub fn element_visits_by_site() -> Vec<(String, u64)> {
    #[cfg(feature = "work-meter")]
    return meter::by_site();
    #[cfg(not(feature = "work-meter"))]
    Vec::new()
}

#[cfg(feature = "work-meter")]
mod meter {
    use rustc_hash::FxHashMap;
    use std::panic::Location;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    pub(super) static VISITS: AtomicU64 = AtomicU64::new(0);
    static SITES: Mutex<Option<FxHashMap<&'static Location<'static>, u64>>> = Mutex::new(None);

    pub(super) fn by_site() -> Vec<(String, u64)> {
        let sites = SITES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut sites = (sites.iter().flatten())
            .map(|(at, count)| (format!("{}:{}", at.file(), at.line()), *count))
            .collect::<Vec<_>>();
        sites.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        sites
    }

    /// Counts each element it hands out, against the site that asked for the iteration.
    #[derive(Debug)]
    pub struct Counted<I> {
        pub(super) iter: I,
        pub(super) at: &'static Location<'static>,
        pub(super) count: u64,
    }

    /// A copy counts only what it hands out itself.
    impl<I: Clone> Clone for Counted<I> {
        fn clone(&self) -> Self {
            Self {
                iter: self.iter.clone(),
                at: self.at,
                count: 0,
            }
        }
    }

    impl<I> Drop for Counted<I> {
        fn drop(&mut self) {
            if self.count > 0 {
                let mut sites = SITES
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *sites
                    .get_or_insert_with(FxHashMap::default)
                    .entry(self.at)
                    .or_default() += self.count;
            }
        }
    }

    impl<I: Iterator> Iterator for Counted<I> {
        type Item = I::Item;

        fn next(&mut self) -> Option<I::Item> {
            let item = self.iter.next()?;
            self.count += 1;
            VISITS.fetch_add(1, Ordering::Relaxed);
            Some(item)
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            self.iter.size_hint()
        }
    }

    impl<I: DoubleEndedIterator> DoubleEndedIterator for Counted<I> {
        fn next_back(&mut self) -> Option<I::Item> {
            let item = self.iter.next_back()?;
            self.count += 1;
            VISITS.fetch_add(1, Ordering::Relaxed);
            Some(item)
        }
    }

    impl<I: ExactSizeIterator> ExactSizeIterator for Counted<I> {}

    impl<I: std::iter::FusedIterator> std::iter::FusedIterator for Counted<I> {}
}

#[cfg(test)]
mod tests {
    /// A whole pass over a metered table counts each element it hands out once, at its call site;
    /// an early stop counts only what it read (D417).
    #[cfg(feature = "work-meter")]
    #[test]
    fn the_meter_counts_each_element_a_pass_hands_out() {
        let table = super::Metered::from(vec![1u32, 2, 3, 4]);
        let mut whole = table.iter();
        assert_eq!(whole.by_ref().count(), 4);
        assert_eq!(whole.count, 4);
        let mut early = table.iter();
        assert_eq!(early.by_ref().position(|x| *x == 2), Some(1));
        assert_eq!(early.count, 2);
        let set = (0..130)
            .map(crate::graph::InstId)
            .collect::<super::IdSet<_>>();
        let mut members = set.iter();
        assert_eq!(members.by_ref().count(), 130);
        drop(members);
        let here = format!("{}:", file!());
        assert!(
            super::element_visits_by_site()
                .iter()
                .any(|(at, _)| at.starts_with(&here))
        );
        assert!(super::element_visits().is_some_and(|visits| visits >= 136));
    }

    /// An index finds each row it was given, through growth and with colliding hashes.
    #[test]
    fn a_hash_index_finds_every_row_through_growth() {
        let keys = (0..100u64).map(|key| key * 7919).collect::<Vec<_>>();
        // Every fourth key shares a hash, so probes walk past rows that do not match.
        let hash = |row: u32| keys[row as usize] / 4;
        let mut index = HashIndex::default();
        for row in 0..keys.len() as u32 {
            index.insert(row, hash(row), hash);
        }
        index.shrink_to_fit(hash);
        for (row, key) in keys.iter().enumerate() {
            assert_eq!(
                index.find(key / 4, |at| keys[at as usize] == *key),
                Some(row as u32)
            );
        }
        assert_eq!(index.find(3, |at| keys[at as usize] == 3), None);
        assert_eq!(HashIndex::of(keys.len(), hash), index);
    }

    /// A sparse map answers as an ordered map does, whatever order its ids arrive in.
    #[test]
    fn a_sparse_map_keeps_its_ids_in_order() {
        use crate::graph::ValueId;
        let mut map = SparseMap::<ValueId, u32>::default();
        for id in [7u32, 2, 9, 2] {
            map.insert(ValueId(id), id * 10);
        }
        assert_eq!(map.len(), 3);
        assert_eq!(map.get(ValueId(2)), Some(&20));
        assert_eq!(map.get(ValueId(3)), None);
        map.retain(|id, _| id != ValueId(7));
        assert_eq!(map.iter().map(|(id, _)| id.0).collect::<Vec<_>>(), [2, 9]);
        let mut other = SparseMap::default();
        for (id, value) in [(1u32, 0u32), (2, 20), (9, 0)] {
            other.insert(ValueId(id), value);
        }
        assert!(map.retain_agreeing(&other));
        assert_eq!(map.iter().map(|(id, _)| id.0).collect::<Vec<_>>(), [2]);
    }

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

    /// A graph's condensation by its edges over `count` nodes.
    fn condensed(count: usize, edges: &[(u32, u32)]) -> (Csr<Node, Node>, Condensation<Node>) {
        let pairs = edges.iter().map(|(from, to)| (Node(*from), Node(*to)));
        let successors = Csr::from_pairs(count, pairs);
        let condensation = Condensation::of(&successors, []);
        (successors, condensation)
    }

    use super::{Condensation, Csr, DenseId, Node};

    /// Against mutual reachability on random graphs: the partition, callee-first order, ascending
    /// members, the cyclic flag, and one visit per node and per edge.
    #[test]
    fn a_condensation_matches_mutual_reachability() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = |bound: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % bound
        };
        for _ in 0..400 {
            let count = 1 + next(12) as usize;
            let edges = (0..next(3 * count as u64))
                .map(|_| (next(count as u64) as u32, next(count as u64) as u32))
                .collect::<Vec<_>>();
            let (successors, condensation) = condensed(count, &edges);
            let mut reach = vec![vec![false; count]; count];
            for (from, row) in reach.iter_mut().enumerate() {
                let mut stack = vec![from];
                while let Some(at) = stack.pop() {
                    for to in successors.get(Node::from_index(at)) {
                        if !std::mem::replace(&mut row[to.index()], true) {
                            stack.push(to.index());
                        }
                    }
                }
            }
            let of = |at: usize| condensation.component(Node::from_index(at));
            let pairs = (0..count).flat_map(|a| (0..count).map(move |b| (a, b)));
            for (a, b) in pairs {
                let mutual = a == b || (reach[a][b] && reach[b][a]);
                assert_eq!(of(a) == of(b), mutual, "{edges:?}");
            }
            for (from, to) in &edges {
                assert!(of(*to as usize) <= of(*from as usize), "{edges:?}");
            }
            for (component, members) in condensation.components() {
                assert!(members.windows(2).all(|pair| pair[0] < pair[1]));
                let cyclic = members.len() > 1 || reach[members[0].index()][members[0].index()];
                assert_eq!(condensation.is_cyclic(component), cyclic, "{edges:?}");
            }
            assert_eq!(condensation.visits(), (count + edges.len()) as u64);
            let finish = |at: u32| condensation.finish(Node(at));
            let mut order = (0..count as u32).map(finish).collect::<Vec<_>>();
            order.sort_unstable();
            assert!(order.iter().copied().eq(0..count as u32), "{edges:?}");
            for (from, to) in &edges {
                if of(*to as usize) != of(*from as usize) {
                    assert!(finish(*to) < finish(*from), "{edges:?}");
                }
            }
        }
    }

    /// A chain deeper than any thread's stack closes callee first with one visit per node and
    /// edge; finish indices are the depth-first postorder.
    #[test]
    fn a_deep_chain_condenses_in_linear_visits() {
        const COUNT: u32 = 200_000;
        let edges = (1..COUNT).map(|at| (at - 1, at)).collect::<Vec<_>>();
        let (_, condensation) = condensed(COUNT as usize, &edges);
        assert_eq!(condensation.len(), COUNT as usize);
        assert_eq!(condensation.visits(), u64::from(2 * COUNT - 1));
        assert_eq!(condensation.component(Node(COUNT - 1)).0, 0);
        assert_eq!(condensation.finish(Node(0)), COUNT - 1);
        // Closing the cycle makes one component, still visited once per node and edge.
        let mut cycle = edges;
        cycle.push((COUNT - 1, 0));
        let (_, condensation) = condensed(COUNT as usize, &cycle);
        assert_eq!(condensation.len(), 1);
        assert!(condensation.is_cyclic(condensation.component(Node(0))));
        assert_eq!(condensation.visits(), u64::from(2 * COUNT));
    }

    /// A graph stated on demand is asked once per node in the search's preorder and numbered by
    /// ascending key.
    #[test]
    fn a_reached_graph_asks_each_node_once_in_preorder() {
        use super::Reached;
        let edges = [(9u64, 4u64), (9, 7), (4, 7), (7, 4), (4, 9), (7, 1)];
        let mut asked = Vec::new();
        let reached = Reached::from(9, |at| {
            asked.push(at);
            edges
                .iter()
                .filter(|(from, _)| *from == at)
                .map(|(_, to)| *to)
                .collect()
        });
        assert_eq!(asked, [9, 4, 7, 1]);
        let keys = (0..4).map(|at| reached.key(Node(at))).collect::<Vec<_>>();
        assert_eq!(keys, [1, 4, 7, 9]);
        let condensation = reached.condensation();
        let closed = (condensation.components())
            .map(|(_, members)| {
                members
                    .iter()
                    .map(|at| reached.key(*at))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(closed, [vec![1], vec![4, 7, 9]]);
        assert_eq!(condensation.visits(), 4 + 6);
    }
}
