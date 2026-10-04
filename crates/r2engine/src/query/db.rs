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

    /// The answer, reading the program only through `db`.
    fn compute(db: &Db<I>, key: &Self::Key) -> Self::Value;
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

enum Dep {
    Bytes(Range<u64>),
    Query { table: TypeId, key: Rc<dyn Any> },
}

struct Entry<V> {
    value: Rc<V>,
    deps: Rc<[Dep]>,
    verified_at: u64,
    changed_at: u64,
}

/// The answers to one query, by key.
struct Table<Q: Query<I>, I: Inputs> {
    entries: RefCell<BTreeMap<Q::Key, Entry<Q::Value>>>,
    running: RefCell<BTreeSet<Q::Key>>,
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
    frames: RefCell<Vec<Vec<Dep>>>,
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
        if held {
            typed.check(self, key)?;
        } else {
            typed.execute(self, key)?;
        }
        self.record(Dep::Query {
            table: TypeId::of::<Q>(),
            key: Rc::new(key.clone()),
        });
        let entries = typed.entries.borrow();
        let entry = entries
            .get(key)
            .expect("an answer was just checked or computed");
        Ok(Rc::clone(&entry.value))
    }

    fn table<Q: Query<I>>(&self) -> Rc<dyn AnyTable<I>> {
        let mut tables = self.tables.borrow_mut();
        Rc::clone(tables.entry(TypeId::of::<Q>()).or_insert_with(|| {
            Rc::new(Table::<Q, I> {
                entries: RefCell::new(BTreeMap::new()),
                running: RefCell::new(BTreeSet::new()),
                query: PhantomData,
            })
        }))
    }

    fn record(&self, dep: Dep) {
        if let Some(frame) = self.frames.borrow_mut().last_mut() {
            frame.push(dep);
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
    fn finish(mut self) -> Vec<Dep> {
        if let Some(key) = self.key.take() {
            self.running.borrow_mut().remove(&key);
        }
        coalesced(self.db.frames.borrow_mut().pop().unwrap_or_default())
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
    /// Recheck the held answer at `key` against the current revision,
    /// recomputing it where something it read has moved; its `changed_at`.
    fn check(&self, db: &Db<I>, key: &Q::Key) -> Result<u64, Cycle> {
        let now = db.inputs.byte_revision();
        let (verified_at, changed_at, deps) = {
            let entries = self.entries.borrow();
            let entry = entries.get(key).expect("checked only where held");
            (entry.verified_at, entry.changed_at, Rc::clone(&entry.deps))
        };
        if verified_at == now {
            db.stats.borrow_mut().reused += 1;
            return Ok(changed_at);
        }
        for dep in deps.iter() {
            let moved = match dep {
                Dep::Bytes(range) => db.inputs.written_since(verified_at, range),
                Dep::Query { table, key } => {
                    let table = db
                        .tables
                        .borrow()
                        .get(table)
                        .map(Rc::clone)
                        .expect("a recorded query's table exists");
                    table
                        .verify(db, key.as_ref())?
                        .is_none_or(|changed| changed > verified_at)
                }
            };
            if moved {
                return self.execute(db, key);
            }
        }
        db.stats.borrow_mut().reused += 1;
        if let Some(entry) = self.entries.borrow_mut().get_mut(key) {
            entry.verified_at = now;
        }
        Ok(changed_at)
    }

    /// Run the query at `key` and hold its answer; its `changed_at`.
    fn execute(&self, db: &Db<I>, key: &Q::Key) -> Result<u64, Cycle> {
        if !self.running.borrow_mut().insert(key.clone()) {
            return Err(Cycle {
                query: Q::NAME,
                key: Rc::new(key.clone()),
            });
        }
        db.frames.borrow_mut().push(Vec::new());
        let frame = Running {
            db,
            running: &self.running,
            key: Some(key.clone()),
        };
        let value = Q::compute(db, key);
        let deps = frame.finish();
        let now = db.inputs.byte_revision();
        let mut stats = db.stats.borrow_mut();
        stats.computed += 1;
        let mut entries = self.entries.borrow_mut();
        let (value, changed_at) = match entries.remove(key) {
            Some(old) if *old.value == value => {
                stats.backdated += 1;
                (old.value, old.changed_at)
            }
            _ => (Rc::new(value), now),
        };
        entries.insert(
            key.clone(),
            Entry {
                value,
                deps: deps.into(),
                verified_at: now,
                changed_at,
            },
        );
        Ok(changed_at)
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
        self.check(db, key).map(Some)
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
                    }
                }
            }
        }
    }
}
