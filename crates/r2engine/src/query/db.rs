//! The query database (doc/adr-query-database.md, Q0).
//!
//! Every fact the engine derives about a program is a query: a pure function
//! of the program's bytes and of other queries, with a typed key and a value.
//! The database keeps each answer with what computing it read, and answers a
//! repeated question by checking those reads rather than by recomputing.
//!
//! **Dependencies are recorded, not declared.** While a query runs, every byte
//! range it says it reads and every query it asks is recorded against it. A
//! query cannot forget a dependency it used through the database, and it has
//! no other way to read the program.
//!
//! **Revalidation is red-green.** An answer is stamped with the byte revision
//! it was last checked at (`verified_at`) and the revision its value last
//! changed at (`changed_at`). Asked again after a write, it is still good when
//! none of the ranges it read was written since `verified_at` and every query
//! it asked, checked the same way first, has not changed since then. Only
//! otherwise is it recomputed, and a recomputed value equal to the old one
//! keeps its `changed_at`, so what depends on it stays good.
//!
//! **Cost.** A good answer costs one check per dependency, each a range test
//! or a recursive check that stops at the first answer already checked at
//! this revision. A write costs nothing until something is asked.
//!
//! **Cycles are values.** A query that asks, through any chain, for itself
//! gets [`Cycle`] rather than recursing; a strongly connected set of facts is
//! solved by one query over the set (P6).

use std::any::{Any, TypeId};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::Range;
use std::rc::Rc;

/// What the database reads: bytes, with a revision and a record of where
/// each was written.
pub trait Inputs {
    /// How many times the bytes have been written.
    fn byte_revision(&self) -> u64;

    /// Whether anything in `range` has been written since `revision`.
    fn written_since(&self, revision: u64, range: &Range<u64>) -> bool;
}

/// One kind of derived fact.
pub trait Query<I: Inputs>: 'static {
    type Key: Ord + Clone + Debug + 'static;
    /// Compared with the previous value when recomputed, so an unchanged
    /// answer leaves its dependents good.
    type Value: PartialEq + 'static;

    /// Named in a [`Cycle`].
    const NAME: &'static str;

    /// How many answers are held at once, the oldest dropped first; `None` holds every one.
    const CAPACITY: Option<usize> = None;

    /// The answer, reading the program only through `db`.
    fn compute(db: &Db<I>, key: &Self::Key) -> Self::Value;

    /// Whether this answer is the request's stop rather than the program's: never held, and neither is what read it.
    fn stopped(_value: &Self::Value) -> bool {
        false
    }
}

/// A query asked, through some chain, for itself.
#[derive(Debug, Clone)]
pub struct Cycle {
    pub query: &'static str,
    pub key: Rc<dyn CycleKey>,
}

impl PartialEq for Cycle {
    fn eq(&self, other: &Self) -> bool {
        self.query == other.query && self.key.same_key(other.key.as_ref())
    }
}

impl Eq for Cycle {}

/// The key a cycle went through, kept as the value it is.
pub trait CycleKey: Debug {
    fn same_key(&self, other: &dyn CycleKey) -> bool;
    fn as_any(&self) -> &dyn Any;
}

impl<K: Debug + PartialEq + 'static> CycleKey for K {
    fn same_key(&self, other: &dyn CycleKey) -> bool {
        other.as_any().downcast_ref::<K>() == Some(self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// What the database has done, for tests and for traces.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DbStats {
    /// Answers served without recomputing.
    pub reused: u64,
    /// Queries run.
    pub computed: u64,
    /// Recomputations whose value equalled the previous one.
    pub backdated: u64,
}

/// A held answer found good, with what it depends on.
type Green<V> = (Rc<V>, Rc<[Dep]>);

/// What one running query has read, and which held answers' dependencies it has already taken.
#[derive(Default)]
struct Frame {
    deps: Vec<Dep>,
    taken: BTreeSet<*const Dep>,
    /// Whether it read a stopped answer, which makes its own answer the request's too.
    stopped: bool,
}

#[derive(Clone)]
enum Dep {
    Bytes(Range<u64>),
    Query { table: TypeId, key: Rc<dyn Any> },
}

impl Dep {
    /// Whether what this dependency names has moved since `verified_at`.
    fn moved_since<I: Inputs + 'static>(
        &self,
        db: &Db<I>,
        verified_at: u64,
    ) -> Result<bool, Cycle> {
        Ok(match self {
            Dep::Bytes(range) => db.inputs.written_since(verified_at, range),
            Dep::Query { table, key } => {
                let table = db.tables.borrow().get(table).map(Rc::clone);
                let table = table.expect("a recorded query's table exists");
                table
                    .verify(db, key.as_ref())?
                    .is_none_or(|changed| changed > verified_at)
            }
        })
    }
}

struct Entry<V> {
    value: Rc<V>,
    deps: Rc<[Dep]>,
    verified_at: u64,
    changed_at: u64,
    /// When it was computed, so a table at capacity drops its oldest.
    stamp: u64,
}

/// The answers to one query, by key.
struct Table<Q: Query<I>, I: Inputs> {
    entries: RefCell<BTreeMap<Q::Key, Entry<Q::Value>>>,
    running: RefCell<BTreeSet<Q::Key>>,
    /// The next entry's stamp.
    clock: std::cell::Cell<u64>,
    query: PhantomData<fn(&I) -> Q>,
}

/// A table seen without its types, so one query's check can reach another's.
trait AnyTable<I: Inputs> {
    /// The revision `key`'s answer last changed at, rechecking or
    /// recomputing it first; `None` where nothing is held for `key`.
    fn verify(&self, db: &Db<I>, key: &dyn Any) -> Result<Option<u64>, Cycle>;
    fn as_any(&self) -> &dyn Any;
}

/// The program's derived facts.
pub struct Db<I: Inputs> {
    inputs: I,
    tables: RefCell<HashMap<TypeId, Rc<dyn AnyTable<I>>>>,
    /// The dependencies of each query running, innermost last.
    frames: RefCell<Vec<Frame>>,
    stats: RefCell<DbStats>,
}

impl<I: Inputs + 'static> Db<I> {
    pub fn new(inputs: I) -> Self {
        Self {
            inputs,
            tables: RefCell::new(HashMap::new()),
            frames: RefCell::new(Vec::new()),
            stats: RefCell::new(DbStats::default()),
        }
    }

    /// The inputs, to write through and to read from. A query reads bytes
    /// only after saying which with [`Self::reads`].
    pub fn inputs(&self) -> &I {
        &self.inputs
    }

    /// The inputs, to write to. Nothing is invalidated here: what a write
    /// moved is found when something is next asked.
    pub fn inputs_mut(&mut self) -> &mut I {
        &mut self.inputs
    }

    /// The revision `Q`'s answer at `key` last changed at, as last checked;
    /// `None` where nothing has asked.
    pub fn changed_at<Q: Query<I>>(&self, key: &Q::Key) -> Option<u64> {
        let tables = self.tables.borrow();
        let table = tables.get(&TypeId::of::<Q>())?;
        let typed = table.as_any().downcast_ref::<Table<Q, I>>()?;
        typed
            .entries
            .borrow()
            .get(key)
            .map(|entry| entry.changed_at)
    }

    pub fn stats(&self) -> DbStats {
        *self.stats.borrow()
    }

    /// Record that the query running reads `range`.
    pub fn reads(&self, range: Range<u64>) {
        self.record(Dep::Bytes(range));
    }

    /// The answer to `Q` at `key`, reused where nothing it read has moved.
    pub fn get<Q: Query<I>>(&self, key: &Q::Key) -> Result<Rc<Q::Value>, Cycle> {
        let table = self.table::<Q>();
        let typed = table
            .as_any()
            .downcast_ref::<Table<Q, I>>()
            .expect("a table is registered under its own query's type");
        let held = typed.entries.borrow().contains_key(key);
        let (value, changed_at) = match held {
            true => typed.check(self, key)?,
            false => typed.execute(self, key)?,
        };
        // A stopped answer is not held, so nothing can depend on it; the stop has tainted the asker.
        if changed_at.is_some() {
            self.record(Dep::Query {
                table: TypeId::of::<Q>(),
                key: Rc::new(key.clone()),
            });
        }
        Ok(value)
    }

    /// `Q`'s answer at `key` where held and good; never computes, and records the answer's own dependencies, so no cycle closes.
    pub fn held<Q: Query<I>>(&self, key: &Q::Key) -> Result<Option<Rc<Q::Value>>, Cycle> {
        let table = self.table::<Q>();
        let typed = table
            .as_any()
            .downcast_ref::<Table<Q, I>>()
            .expect("a table is registered under its own query's type");
        let Some((value, deps)) = typed.green(self, key)? else {
            return Ok(None);
        };
        // Deposits share one list, so each list is taken once per frame.
        if let Some(frame) = self.frames.borrow_mut().last_mut()
            && frame.taken.insert(deps.as_ptr())
        {
            frame.deps.extend(deps.iter().cloned());
        }
        Ok(Some(value))
    }

    /// Hold answers a computation found besides its own, depending on what it has read; each must equal a direct computation.
    pub fn deposit<Q: Query<I>>(&self, answers: impl IntoIterator<Item = (Q::Key, Q::Value)>) {
        let deps: Rc<[Dep]> = match self.frames.borrow().last() {
            Some(frame) if !frame.stopped => coalesced(frame.deps.clone()).into(),
            _ => return,
        };
        let table = self.table::<Q>();
        let typed = table
            .as_any()
            .downcast_ref::<Table<Q, I>>()
            .expect("a table is registered under its own query's type");
        let now = self.inputs.byte_revision();
        let running = typed.running.borrow();
        let mut entries = typed.entries.borrow_mut();
        for (key, value) in answers {
            if running.contains(&key) {
                continue;
            }
            let changed_at = match entries.get(&key) {
                Some(held) if held.verified_at == now => continue,
                Some(held) if *held.value == value => held.changed_at,
                _ => now,
            };
            entries.insert(
                key,
                Entry {
                    value: Rc::new(value),
                    deps: Rc::clone(&deps),
                    verified_at: now,
                    changed_at,
                    stamp: typed.tick(),
                },
            );
        }
        Table::<Q, I>::bound(&mut entries);
    }

    fn table<Q: Query<I>>(&self) -> Rc<dyn AnyTable<I>> {
        let mut tables = self.tables.borrow_mut();
        Rc::clone(tables.entry(TypeId::of::<Q>()).or_insert_with(|| {
            Rc::new(Table::<Q, I> {
                entries: RefCell::new(BTreeMap::new()),
                running: RefCell::new(BTreeSet::new()),
                clock: std::cell::Cell::new(0),
                query: PhantomData,
            })
        }))
    }

    fn record(&self, dep: Dep) {
        if let Some(frame) = self.frames.borrow_mut().last_mut() {
            frame.deps.push(dep);
        }
    }
}

/// The frame a running query records into, popped however `compute` ends.
struct Running<'a, I: Inputs + 'static, K: Ord> {
    db: &'a Db<I>,
    running: &'a RefCell<BTreeSet<K>>,
    key: Option<K>,
}

impl<I: Inputs + 'static, K: Ord> Running<'_, I, K> {
    /// What the query read, and whether it read a stopped answer.
    fn finish(mut self) -> (Vec<Dep>, bool) {
        if let Some(key) = self.key.take() {
            self.running.borrow_mut().remove(&key);
        }
        let frame = self.db.frames.borrow_mut().pop().unwrap_or_default();
        (coalesced(frame.deps), frame.stopped)
    }
}

impl<I: Inputs + 'static, K: Ord> Drop for Running<'_, I, K> {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            self.running.borrow_mut().remove(&key);
            self.db.frames.borrow_mut().pop();
        }
    }
}

/// The same dependencies with overlapping and adjacent byte ranges merged,
/// so checking an answer costs one test per region it read rather than one
/// per read. The queries asked keep their order.
fn coalesced(deps: Vec<Dep>) -> Vec<Dep> {
    let (mut ranges, queries): (Vec<Dep>, Vec<Dep>) = deps
        .into_iter()
        .partition(|dep| matches!(dep, Dep::Bytes(_)));
    let mut ranges = ranges
        .drain(..)
        .filter_map(|dep| match dep {
            Dep::Bytes(range) if range.start < range.end => Some(range),
            _ => None,
        })
        .collect::<Vec<_>>();
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut merged: Vec<Range<u64>> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match merged.last_mut() {
            Some(last) if range.start <= last.end => last.end = last.end.max(range.end),
            _ => merged.push(range),
        }
    }
    merged.into_iter().map(Dep::Bytes).chain(queries).collect()
}

impl<Q: Query<I>, I: Inputs + 'static> Table<Q, I> {
    /// The held answer and its dependencies where none has moved, checked without computing this query.
    fn green(&self, db: &Db<I>, key: &Q::Key) -> Result<Option<Green<Q::Value>>, Cycle> {
        let now = db.inputs.byte_revision();
        let Some((value, deps, verified_at)) = self.entries.borrow().get(key).map(|entry| {
            (
                Rc::clone(&entry.value),
                Rc::clone(&entry.deps),
                entry.verified_at,
            )
        }) else {
            return Ok(None);
        };
        if verified_at != now {
            // The first dependency that moved or cycled decides; none is checked past it.
            let mut checked = deps.iter().map(|dep| dep.moved_since(db, verified_at));
            if checked
                .find(|moved| !matches!(moved, Ok(false)))
                .transpose()?
                .is_some()
            {
                return Ok(None);
            }
            if let Some(entry) = self.entries.borrow_mut().get_mut(key) {
                entry.verified_at = now;
            }
        }
        db.stats.borrow_mut().reused += 1;
        Ok(Some((value, deps)))
    }

    fn tick(&self) -> u64 {
        let stamp = self.clock.get();
        self.clock.set(stamp + 1);
        stamp
    }

    /// Drop the oldest answers past the query's capacity; a dropped answer is recomputed when asked.
    fn bound(entries: &mut BTreeMap<Q::Key, Entry<Q::Value>>) {
        let Some(capacity) = Q::CAPACITY else {
            return;
        };
        while entries.len() > capacity {
            let oldest = entries.iter().min_by_key(|(_, entry)| entry.stamp);
            let Some(oldest) = oldest.map(|(key, _)| key.clone()) else {
                return;
            };
            entries.remove(&oldest);
        }
    }

    /// Recheck the held answer at `key`, recomputing where something it read has moved; its value and `changed_at`, none where it stopped.
    fn check(&self, db: &Db<I>, key: &Q::Key) -> Result<(Rc<Q::Value>, Option<u64>), Cycle> {
        let now = db.inputs.byte_revision();
        let (value, verified_at, changed_at, deps) = {
            let entries = self.entries.borrow();
            let entry = entries.get(key).expect("checked only where held");
            let value = Rc::clone(&entry.value);
            (
                value,
                entry.verified_at,
                entry.changed_at,
                Rc::clone(&entry.deps),
            )
        };
        if verified_at == now {
            db.stats.borrow_mut().reused += 1;
            return Ok((value, Some(changed_at)));
        }
        for dep in deps.iter() {
            if dep.moved_since(db, verified_at)? {
                return self.execute(db, key);
            }
        }
        db.stats.borrow_mut().reused += 1;
        if let Some(entry) = self.entries.borrow_mut().get_mut(key) {
            entry.verified_at = now;
        }
        Ok((value, Some(changed_at)))
    }

    /// Run the query at `key` and hold its answer unless it stopped; its value and `changed_at`.
    fn execute(&self, db: &Db<I>, key: &Q::Key) -> Result<(Rc<Q::Value>, Option<u64>), Cycle> {
        if !self.running.borrow_mut().insert(key.clone()) {
            return Err(Cycle {
                query: Q::NAME,
                key: Rc::new(key.clone()),
            });
        }
        db.frames.borrow_mut().push(Frame::default());
        let frame = Running {
            db,
            running: &self.running,
            key: Some(key.clone()),
        };
        let value = Q::compute(db, key);
        let (deps, tainted) = frame.finish();
        db.stats.borrow_mut().computed += 1;
        let mut entries = self.entries.borrow_mut();
        if tainted || Q::stopped(&value) {
            entries.remove(key);
            if let Some(asker) = db.frames.borrow_mut().last_mut() {
                asker.stopped = true;
            }
            return Ok((Rc::new(value), None));
        }
        let now = db.inputs.byte_revision();
        let (value, changed_at) = match entries.remove(key) {
            Some(old) if *old.value == value => {
                db.stats.borrow_mut().backdated += 1;
                (old.value, old.changed_at)
            }
            _ => (Rc::new(value), now),
        };
        entries.insert(
            key.clone(),
            Entry {
                value: Rc::clone(&value),
                deps: deps.into(),
                verified_at: now,
                changed_at,
                stamp: self.tick(),
            },
        );
        Self::bound(&mut entries);
        Ok((value, Some(changed_at)))
    }
}

impl<Q: Query<I>, I: Inputs + 'static> AnyTable<I> for Table<Q, I> {
    fn verify(&self, db: &Db<I>, key: &dyn Any) -> Result<Option<u64>, Cycle> {
        let key = key
            .downcast_ref::<Q::Key>()
            .expect("a dependency's key is its query's key type");
        if !self.entries.borrow().contains_key(key) {
            return Ok(None);
        }
        self.check(db, key).map(|(_, changed_at)| changed_at)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bytes with the revision each was last written at.
    #[derive(Clone)]
    struct Memory {
        bytes: Vec<u8>,
        written: Vec<u64>,
        revision: u64,
    }

    impl Memory {
        fn new(bytes: Vec<u8>) -> Self {
            let written = vec![0; bytes.len()];
            Self {
                bytes,
                written,
                revision: 0,
            }
        }

        fn write(&mut self, at: usize, value: u8) {
            self.revision += 1;
            self.bytes[at] = value;
            self.written[at] = self.revision;
        }
    }

    impl Inputs for Memory {
        fn byte_revision(&self) -> u64 {
            self.revision
        }

        fn written_since(&self, revision: u64, range: &Range<u64>) -> bool {
            self.written[range.start as usize..range.end as usize]
                .iter()
                .any(|at| *at > revision)
        }
    }

    fn read(db: &Db<Memory>, range: Range<u64>) -> &[u8] {
        db.reads(range.clone());
        &db.inputs().bytes[range.start as usize..range.end as usize]
    }

    /// The sum of a range of bytes.
    struct Sum;
    impl Query<Memory> for Sum {
        type Key = (u64, u64);
        type Value = u64;
        const NAME: &'static str = "sum";
        fn compute(db: &Db<Memory>, &(start, end): &(u64, u64)) -> u64 {
            read(db, start..end).iter().map(|b| u64::from(*b)).sum()
        }
    }

    /// Whether the sum of a range is even: a value that often survives a
    /// write unchanged, so its dependents should not be recomputed.
    struct Even;
    impl Query<Memory> for Even {
        type Key = (u64, u64);
        type Value = bool;
        const NAME: &'static str = "even";
        fn compute(db: &Db<Memory>, key: &(u64, u64)) -> bool {
            db.get::<Sum>(key).expect("acyclic").is_multiple_of(2)
        }
    }

    /// The sum of the bytes up to `at`, built on any shorter prefix already held, depositing each prefix it passes.
    struct Prefix;
    impl Query<Memory> for Prefix {
        type Key = u64;
        type Value = u64;
        const NAME: &'static str = "prefix";
        fn compute(db: &Db<Memory>, &at: &u64) -> u64 {
            let held = |shorter| db.held::<Prefix>(&shorter).expect("never computes");
            let start = (0..at)
                .rev()
                .find_map(|shorter| Some((shorter + 1, *held(shorter)?)));
            let (from, mut sum) = start.unwrap_or((0, 0));
            let mut found = Vec::new();
            for index in from..=at {
                sum += u64::from(read(db, index..index + 1)[0]);
                found.push((index, sum));
            }
            found.pop();
            db.deposit::<Prefix>(found);
            sum
        }
    }

    #[test]
    fn a_held_or_deposited_answer_equals_a_computed_one() {
        let mut db = Db::new(Memory::new((1..=16).collect()));
        assert_eq!(*db.get::<Prefix>(&9).unwrap(), 55);
        // Nothing held at 3 was computed, only deposited, and a miss records nothing.
        assert_eq!(db.held::<Prefix>(&3).unwrap().map(|sum| *sum), Some(10));
        assert_eq!(db.held::<Prefix>(&12).unwrap(), None);
        let computed = db.stats().computed;
        assert_eq!(*db.get::<Prefix>(&12).unwrap(), 91);
        assert_eq!(db.stats().computed, computed + 1);
        // A write below a deposit invalidates it, and the answers stay a fresh open's.
        db.inputs_mut().write(2, 100);
        assert_eq!(db.held::<Prefix>(&3).unwrap(), None);
        let fresh = Db::new(db.inputs().clone());
        for at in [3, 9, 12] {
            assert_eq!(
                *db.get::<Prefix>(&at).unwrap(),
                *fresh.get::<Prefix>(&at).unwrap()
            );
        }
    }

    /// A byte, where 0xff stands for a request that stopped.
    struct Halting;
    impl Query<Memory> for Halting {
        type Key = u64;
        type Value = u8;
        const NAME: &'static str = "halting";
        fn compute(db: &Db<Memory>, &at: &u64) -> u8 {
            read(db, at..at + 1)[0]
        }
        fn stopped(value: &u8) -> bool {
            *value == 0xff
        }
    }

    /// Twice a halting byte, holding at most one answer.
    struct Doubled;
    impl Query<Memory> for Doubled {
        type Key = u64;
        type Value = u16;
        const NAME: &'static str = "doubled";
        const CAPACITY: Option<usize> = Some(1);
        fn compute(db: &Db<Memory>, at: &u64) -> u16 {
            u16::from(*db.get::<Halting>(at).expect("acyclic")) * 2
        }
    }

    #[test]
    fn a_stopped_answer_is_held_by_neither_it_nor_what_read_it() {
        let mut bytes = vec![1; 16];
        bytes[3] = 0xff;
        let db = Db::new(Memory::new(bytes));
        assert_eq!(*db.get::<Doubled>(&3).unwrap(), 0x1fe);
        let computed = db.stats().computed;
        assert_eq!(*db.get::<Doubled>(&3).unwrap(), 0x1fe);
        assert_eq!(db.stats().computed, computed + 2, "both are computed again");
        // At capacity one, a second key drops the first.
        assert_eq!(*db.get::<Doubled>(&4).unwrap(), 2);
        assert_eq!(*db.get::<Doubled>(&5).unwrap(), 2);
        let computed = db.stats().computed;
        assert_eq!(*db.get::<Doubled>(&4).unwrap(), 2);
        assert_eq!(
            db.stats().computed,
            computed + 1,
            "the dropped answer is computed again"
        );
    }

    /// A query whose dependencies depend on the bytes: the byte at `at` names
    /// how many of the bytes after it to sum, and whether that sum is even
    /// picks one of two ranges to report.
    struct Pointer;
    impl Query<Memory> for Pointer {
        type Key = u64;
        type Value = u64;
        const NAME: &'static str = "pointer";
        fn compute(db: &Db<Memory>, &at: &u64) -> u64 {
            let len = u64::from(read(db, at..at + 1)[0] % 4);
            let end = (at + 1 + len).min(16);
            if *db.get::<Even>(&(at + 1, end)).expect("acyclic") {
                *db.get::<Sum>(&(0, 4)).expect("acyclic")
            } else {
                *db.get::<Sum>(&(12, 16)).expect("acyclic")
            }
        }
    }

    /// A query that asks for itself.
    struct Loop;
    impl Query<Memory> for Loop {
        type Key = u64;
        type Value = Result<u64, Cycle>;
        const NAME: &'static str = "loop";
        fn compute(db: &Db<Memory>, key: &u64) -> Result<u64, Cycle> {
            db.get::<Loop>(key).and_then(|inner| inner.as_ref().clone())
        }
    }

    #[test]
    fn an_answer_is_reused_until_a_byte_it_read_is_written() {
        let mut db = Db::new(Memory::new((0..16).collect()));
        assert_eq!(*db.get::<Sum>(&(0, 4)).unwrap(), 6);
        assert_eq!(*db.get::<Sum>(&(0, 4)).unwrap(), 6);
        assert_eq!(db.stats().computed, 1);
        db.inputs_mut().write(10, 0);
        assert_eq!(*db.get::<Sum>(&(0, 4)).unwrap(), 6);
        assert_eq!(db.stats().computed, 1, "a write elsewhere moves nothing");
        db.inputs_mut().write(2, 0);
        assert_eq!(*db.get::<Sum>(&(0, 4)).unwrap(), 4);
        assert_eq!(db.stats().computed, 2);
    }

    #[test]
    fn an_unchanged_value_leaves_what_depends_on_it_good() {
        let mut db = Db::new(Memory::new((0..16).collect()));
        assert!(*db.get::<Even>(&(0, 4)).unwrap());
        // 0+1+2+3 = 6, and 0+1+4+3 = 8: the sum changes, its parity does not.
        db.inputs_mut().write(2, 4);
        let before = db.stats();
        assert!(*db.get::<Even>(&(0, 4)).unwrap());
        let after = db.stats();
        assert_eq!(
            after.computed - before.computed,
            2,
            "the sum, then the parity"
        );
        assert_eq!(
            after.backdated - before.backdated,
            1,
            "the parity is unchanged"
        );
        db.inputs_mut().write(2, 5);
        assert!(!*db.get::<Even>(&(0, 4)).unwrap());
    }

    #[test]
    fn a_query_that_asks_for_itself_is_a_cycle() {
        let db = Db::new(Memory::new(vec![0; 16]));
        let answer = db.get::<Loop>(&7).unwrap();
        assert_eq!(
            *answer,
            Err(Cycle {
                query: "loop",
                key: Rc::new(7u64)
            })
        );
        // The failed run left nothing running, so the next question is asked afresh.
        assert!(db.get::<Sum>(&(0, 1)).is_ok());
    }

    /// One step of a session.
    #[derive(Debug, Clone)]
    enum Step {
        Write(usize, u8),
        Ask(u64),
    }

    fn steps() -> impl proptest::strategy::Strategy<Value = Vec<Step>> {
        use proptest::prelude::*;
        proptest::collection::vec(
            prop_oneof![
                (0usize..16, any::<u8>()).prop_map(|(at, value)| Step::Write(at, value)),
                (0u64..12).prop_map(Step::Ask),
            ],
            1..60,
        )
    }

    proptest::proptest! {
        /// The exit the ADR sets for Q: any interleaving of writes and
        /// questions answers exactly as a database opened fresh on the bytes
        /// as they stand.
        #[test]
        fn a_session_answers_as_a_fresh_open(
            start in proptest::collection::vec(proptest::prelude::any::<u8>(), 16),
            steps in steps(),
        ) {
            let mut db = Db::new(Memory::new(start));
            for step in steps {
                match step {
                    Step::Write(at, value) => db.inputs_mut().write(at, value),
                    Step::Ask(at) => {
                        let fresh = Db::new(db.inputs().clone());
                        proptest::prop_assert_eq!(
                            *db.get::<Pointer>(&at).unwrap(),
                            *fresh.get::<Pointer>(&at).unwrap()
                        );
                        // Prefixes peek and deposit, so what each depends on follows the order asked; the value does not.
                        proptest::prop_assert_eq!(
                            *db.get::<Prefix>(&at).unwrap(),
                            *fresh.get::<Prefix>(&at).unwrap()
                        );
                    }
                }
            }
        }
    }
}
