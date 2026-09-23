//! Late-bound typed locations — a proof-of-concept for `doc/scripting.md`.
//!
//! # What this proves
//!
//! The design claim is that a debugger location should NOT be an integer
//! address but a *section of a bundle over the execution timeline*:
//!
//! ```text
//!     Location = (region, offset, size, type, provenance, validity_domain)
//! ```
//!
//! This module is the executable form of the higher-dimensional-algebra model
//! in `MATH.md`:
//!
//!   * Addresses form a **torsor** over the additive group of offsets
//!     (`Addr`, `Offset`): you may translate an address by an offset and
//!     subtract two addresses to get an offset, but there is deliberately no
//!     `Addr + Addr`. (See [`Addr`].)
//!
//!   * The execution timeline `T` is the **base space** ([`Time`]). A location
//!     is a partial section `σ : U → E` of the address bundle, where `U` is its
//!     `validity_domain`. [`Location::resolve`] evaluates `σ(t)`; it is defined
//!     *exactly* on `U`. Outside `U` it returns an error — never a wrong
//!     address. That is the whole safety argument, made computational.
//!
//!   * **Provenance** decides how the section is defined:
//!     - `Alloc` — locally constant section on `[born, freed)` (snapshot
//!       address, liveness-tracked validity).
//!     - `FrameRel` — varying section `σ(t) = fp(t) + off` (live re-bind,
//!       scoped to a frame activation).
//!     - `Project` — fibered composition `load(σ_base(t)) + off`
//!       (`obj->next->data`, re-walked at evaluation time).
//!
//!   * `.at(t)` is stalk evaluation (pin the timeline point). `.snapshot(t)`
//!     forgets the sheaf structure and keeps a bare address — the *only*,
//!     explicit way to opt out of staleness detection.
//!
//! The tests at the bottom are the proof: each corresponds to one claim in
//! `doc/scripting.md`.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Base space: the execution timeline.
// ---------------------------------------------------------------------------

/// A point on the execution timeline (the base space `T`). A totally ordered
/// timeline here; `MATH.md` notes the generalisation to a happens-before poset
/// for multi-threaded / branching (time-travel) execution.
pub type Time = u64;

// ---------------------------------------------------------------------------
// The address torsor.
// ---------------------------------------------------------------------------

/// A machine address. Addresses form a **torsor** (affine space) over the group
/// of offsets: there is no canonical origin, so two addresses cannot be added,
/// but an offset may translate an address and two addresses differ by an offset.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Addr(pub u64);

/// An offset — an element of the acting group `(ℤ, +)`. Offsets *can* be added
/// (the group law); the type of a location grades this module with strides
/// (`sizeof`), which is why offset arithmetic stays inside the typed location.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Offset(pub i64);

impl std::ops::Add<Offset> for Addr {
    type Output = Addr;
    /// Torsor action: translate an address by an offset.
    fn add(self, o: Offset) -> Addr {
        Addr((self.0 as i64).wrapping_add(o.0) as u64)
    }
}

impl std::ops::Sub for Addr {
    type Output = Offset;
    /// Torsor difference: two addresses differ by an offset.
    fn sub(self, other: Addr) -> Offset {
        Offset((self.0 as i64).wrapping_sub(other.0 as i64))
    }
}

impl std::ops::Add for Offset {
    type Output = Offset;
    /// The group law on offsets.
    fn add(self, o: Offset) -> Offset {
        Offset(self.0 + o.0)
    }
}

// NOTE: there is intentionally NO `impl Add<Addr> for Addr`. That absence *is*
// the torsor axiom, enforced by the type system: `addr + addr` does not compile,
// which is exactly why an address can never be conflated with an offset.

// ---------------------------------------------------------------------------
// Types: the grading that turns raw offsets into field/element strides.
// ---------------------------------------------------------------------------

/// A minimal recovered type. In r2sleigh this comes from r2types / the
/// decompiler / DWARF; here it just supplies field offsets and pointer shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ty {
    U64,
    Ptr(Box<Ty>),
    Struct(StructTy),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructTy {
    pub name: String,
    pub fields: Vec<Field>,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub offset: Offset,
    pub ty: Ty,
}

impl StructTy {
    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.name == name)
    }
}

/// Errors that are about the *type* projection, not about time/validity.
#[derive(Debug, PartialEq, Eq)]
pub enum TypeErr {
    NotAStruct,
    NotAPointer,
    NoField(String),
}

// ---------------------------------------------------------------------------
// The world: a recorded execution we can resolve sections against.
// ---------------------------------------------------------------------------

/// A heap allocation — a stable *identity* with a lifetime.
#[derive(Clone, Debug)]
pub struct Alloc {
    pub id: u64,
    pub addr: Addr,
    pub size: u64,
    pub born: Time,
    pub freed: Option<Time>,
}

/// Registers we model (enough for the frame-relative demonstration).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Reg {
    Rbp,
    Rsp,
}

/// A recorded execution. Memory and registers are *versioned over time*, which
/// is what lets a single location handle be evaluated at any timepoint — the
/// same abstraction serves live debugging and replay.
#[derive(Default)]
pub struct World {
    allocs: Vec<Alloc>,
    regs: HashMap<Reg, Vec<(Time, u64)>>,
    mem: HashMap<Addr, Vec<(Time, u64)>>,
}

impl World {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn alloc(&mut self, id: u64, addr: Addr, size: u64, born: Time) {
        self.allocs.push(Alloc {
            id,
            addr,
            size,
            born,
            freed: None,
        });
    }

    pub fn free(&mut self, id: u64, when: Time) {
        if let Some(a) = self.allocs.iter_mut().find(|a| a.id == id) {
            a.freed = Some(when);
        }
    }

    pub fn get_alloc(&self, id: u64) -> Option<&Alloc> {
        self.allocs.iter().find(|a| a.id == id)
    }

    /// Record a register value taking effect at `time`.
    pub fn set_reg(&mut self, reg: Reg, time: Time, val: u64) {
        self.regs.entry(reg).or_default().push((time, val));
    }

    /// The register's value as of time `t` (latest write with `wt <= t`).
    pub fn reg_at(&self, reg: Reg, t: Time) -> Option<u64> {
        latest_leq(self.regs.get(&reg)?, t)
    }

    /// Record a memory store taking effect at `time`.
    pub fn store(&mut self, addr: Addr, time: Time, val: u64) {
        self.mem.entry(addr).or_default().push((time, val));
    }

    /// The memory contents at `addr` as of time `t` (latest store with `wt <= t`).
    pub fn load(&self, addr: Addr, t: Time) -> Option<u64> {
        latest_leq(self.mem.get(&addr)?, t)
    }
}

/// Latest value in a time-versioned log with write-time `<= t`.
fn latest_leq(log: &[(Time, u64)], t: Time) -> Option<u64> {
    log.iter()
        .filter(|(wt, _)| *wt <= t)
        .max_by_key(|(wt, _)| *wt)
        .map(|(_, v)| *v)
}

// ---------------------------------------------------------------------------
// Provenance: how a section is defined and over which domain it is valid.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum Provenance {
    /// Allocation-rooted. Address is constant over the lifetime (snapshot);
    /// validity is `[born, freed)` (liveness-tracked).
    Alloc { alloc_id: u64, offset: Offset },
    /// Frame/register-relative. `σ(t) = reg_at(fp_reg, t) + offset`, re-resolved
    /// at each `t`; validity is the frame activation interval `[start, end)`.
    FrameRel {
        fp_reg: Reg,
        offset: Offset,
        activation: (Time, Time),
    },
    /// Type-projected. Read a pointer out of `base`, then land at `*ptr + off`.
    /// Re-walked at evaluation time; validity is base's ∩ pointer-readable.
    Project {
        base: Box<Location>,
        ptr_field: Offset,
        result_offset: Offset,
    },
}

impl Provenance {
    /// Add a (typed) offset while staying inside the location — the raw integer
    /// never escapes to the caller.
    fn add_offset(&self, o: Offset) -> Provenance {
        match self {
            Provenance::Alloc { alloc_id, offset } => Provenance::Alloc {
                alloc_id: *alloc_id,
                offset: *offset + o,
            },
            Provenance::FrameRel {
                fp_reg,
                offset,
                activation,
            } => Provenance::FrameRel {
                fp_reg: *fp_reg,
                offset: *offset + o,
                activation: *activation,
            },
            Provenance::Project {
                base,
                ptr_field,
                result_offset,
            } => Provenance::Project {
                base: base.clone(),
                ptr_field: *ptr_field,
                result_offset: *result_offset + o,
            },
        }
    }
}

/// Errors from evaluating a section outside its validity domain, or from a
/// broken projection. The point of the whole model: these happen *instead of*
/// returning a wrong address.
#[derive(Debug, PartialEq, Eq)]
pub enum LocErr {
    NotYetLive { at: Time, born: Time },
    UseAfterFree { at: Time, freed: Time },
    OutOfFrame { at: Time, activation: (Time, Time) },
    NoRegister { reg: Reg, at: Time },
    NullDeref { at: Time },
    Unmapped { addr: Addr, at: Time },
    UnknownAlloc(u64),
}

// ---------------------------------------------------------------------------
// Location: a section of the address bundle over the timeline.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Location {
    pub ty: Ty,
    pub prov: Provenance,
    /// `Some(t)` pins evaluation to timeline point `t` (the `.at(t)` operator,
    /// i.e. stalk evaluation). `None` means "evaluate at the caller's `now`".
    pub eval_at: Option<Time>,
}

/// A deliberately-frozen bare address: the `.snapshot()` escape hatch. It has
/// forgotten the sheaf structure, so it carries no validity domain and performs
/// no staleness check. This is the *only* way to lose the safety, and it is
/// explicit and greppable.
#[derive(Clone, Copy, Debug)]
pub struct Frozen {
    pub addr: Addr,
    pub at: Time,
}

impl Frozen {
    /// Raw read at an arbitrary time — no liveness check, by construction.
    pub fn read_at(&self, w: &World, t: Time) -> Option<u64> {
        w.load(self.addr, t)
    }
}

impl Location {
    // --- constructors -----------------------------------------------------

    pub fn alloc_rooted(alloc_id: u64, ty: Ty) -> Location {
        Location {
            ty,
            prov: Provenance::Alloc {
                alloc_id,
                offset: Offset(0),
            },
            eval_at: None,
        }
    }

    pub fn frame_local(fp_reg: Reg, offset: Offset, activation: (Time, Time), ty: Ty) -> Location {
        Location {
            ty,
            prov: Provenance::FrameRel {
                fp_reg,
                offset,
                activation,
            },
            eval_at: None,
        }
    }

    // --- combinators ------------------------------------------------------

    /// Stalk evaluation: pin this section to timeline point `t`. The pin
    /// cascades into projected bases unless a base pins its own time.
    pub fn at(&self, t: Time) -> Location {
        let mut l = self.clone();
        l.eval_at = Some(t);
        l
    }

    /// Typed field access. The offset comes from the recovered struct layout,
    /// so it stays inside the location — a raw integer is never handed out.
    pub fn field(&self, name: &str) -> Result<Location, TypeErr> {
        let st = match &self.ty {
            Ty::Struct(s) => s,
            _ => return Err(TypeErr::NotAStruct),
        };
        let f = st
            .field(name)
            .ok_or_else(|| TypeErr::NoField(name.to_string()))?;
        Ok(Location {
            ty: f.ty.clone(),
            prov: self.prov.add_offset(f.offset),
            eval_at: self.eval_at,
        })
    }

    /// Follow a pointer: produce a projected location that reads the pointer at
    /// evaluation time and lands at the pointee. Only defined for `Ptr` types.
    pub fn deref(&self) -> Result<Location, TypeErr> {
        let inner = match &self.ty {
            Ty::Ptr(i) => (**i).clone(),
            _ => return Err(TypeErr::NotAPointer),
        };
        Ok(Location {
            ty: inner,
            prov: Provenance::Project {
                base: Box::new(self.clone()),
                ptr_field: Offset(0),
                result_offset: Offset(0),
            },
            eval_at: self.eval_at,
        })
    }

    // --- evaluation -------------------------------------------------------

    fn when(&self, now: Time) -> Time {
        self.eval_at.unwrap_or(now)
    }

    /// Materialise the address by evaluating the section `σ(t)`. Defined
    /// exactly on the validity domain; otherwise a [`LocErr`].
    pub fn resolve(&self, w: &World, now: Time) -> Result<Addr, LocErr> {
        let t = self.when(now);
        match &self.prov {
            Provenance::Alloc { alloc_id, offset } => {
                let a = w
                    .get_alloc(*alloc_id)
                    .ok_or(LocErr::UnknownAlloc(*alloc_id))?;
                if t < a.born {
                    return Err(LocErr::NotYetLive {
                        at: t,
                        born: a.born,
                    });
                }
                if let Some(f) = a.freed {
                    if t >= f {
                        return Err(LocErr::UseAfterFree { at: t, freed: f });
                    }
                }
                // Constant section: address fixed for the chunk's lifetime.
                Ok(a.addr + *offset)
            }
            Provenance::FrameRel {
                fp_reg,
                offset,
                activation,
            } => {
                let (s, e) = *activation;
                if t < s || t >= e {
                    return Err(LocErr::OutOfFrame {
                        at: t,
                        activation: (s, e),
                    });
                }
                // Live: read the frame pointer as of time t and re-resolve.
                let fp = w.reg_at(*fp_reg, t).ok_or(LocErr::NoRegister {
                    reg: *fp_reg,
                    at: t,
                })?;
                Ok(Addr(fp) + *offset)
            }
            Provenance::Project {
                base,
                ptr_field,
                result_offset,
            } => {
                // Evaluate the base at the same (possibly pinned) time; the pin
                // cascades because base.resolve re-applies base.eval_at.
                let base_addr = base.resolve(w, t)?;
                let slot = base_addr + *ptr_field;
                let p = w
                    .load(slot, t)
                    .ok_or(LocErr::Unmapped { addr: slot, at: t })?;
                if p == 0 {
                    return Err(LocErr::NullDeref { at: t });
                }
                Ok(Addr(p) + *result_offset)
            }
        }
    }

    /// Resolve, then read the value there — the address is materialised only at
    /// this access. A stale handle raises rather than reading garbage.
    pub fn read(&self, w: &World, now: Time) -> Result<u64, LocErr> {
        let t = self.when(now);
        let a = self.resolve(w, now)?;
        w.load(a, t).ok_or(LocErr::Unmapped { addr: a, at: t })
    }

    /// Resolve, then write — same validity guarantee as [`read`].
    pub fn write(&self, w: &mut World, now: Time, val: u64) -> Result<(), LocErr> {
        let t = self.when(now);
        let a = self.resolve(w, now)?;
        w.store(a, t, val);
        Ok(())
    }

    /// The explicit opt-out: freeze to a bare address, discarding validity.
    pub fn snapshot(&self, w: &World, now: Time) -> Result<Frozen, LocErr> {
        let t = self.when(now);
        Ok(Frozen {
            addr: self.resolve(w, now)?,
            at: t,
        })
    }
}

// ---------------------------------------------------------------------------
// Small scenario builder reused by the demo binary and the tests.
// ---------------------------------------------------------------------------

/// A `struct Node { Node* next; u64 data; }` layout — 16 bytes.
///
/// Note: encoding *unbounded* recursion (`next` pointing at a full `Node`,
/// whose `next` points at a full `Node`, ...) requires a by-id type arena —
/// exactly what r2types' `TypeArena` provides. Inline `Box` types cannot hold
/// an infinite value, so here the pointee is spelled out one level deep, which
/// is all `obj->next->data` needs. The location model under test does not
/// depend on how recursion is represented.
pub fn node_ty() -> Ty {
    // The type reached via `->next`: a `Node`-shaped struct with a `data` field.
    let pointee = StructTy {
        name: "Node".to_string(),
        size: 16,
        fields: vec![
            Field {
                name: "next".to_string(),
                offset: Offset(0),
                ty: Ty::Ptr(Box::new(Ty::U64)),
            },
            Field {
                name: "data".to_string(),
                offset: Offset(8),
                ty: Ty::U64,
            },
        ],
    };
    Ty::Struct(StructTy {
        name: "Node".to_string(),
        size: 16,
        fields: vec![
            Field {
                name: "next".to_string(),
                offset: Offset(0),
                ty: Ty::Ptr(Box::new(Ty::Struct(pointee))),
            },
            Field {
                name: "data".to_string(),
                offset: Offset(8),
                ty: Ty::U64,
            },
        ],
    })
}

// ===========================================================================
// PROOF: each test corresponds to a claim in doc/scripting.md.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Claim: addresses form a torsor over offsets (affine, no canonical origin).
    #[test]
    fn addresses_are_a_torsor_over_offsets() {
        let a = Addr(0x1000);
        let o1 = Offset(0x10);
        let o2 = Offset(-0x8);

        // Group action is associative w.r.t. the offset group law.
        assert_eq!((a + o1) + o2, a + (o1 + o2));
        // Identity element.
        assert_eq!(a + Offset(0), a);
        // Difference of two addresses is an offset, and it inverts translation.
        let b = a + o1;
        assert_eq!(b - a, o1);
        assert_eq!(a + (b - a), b);
        // `Addr + Addr` is deliberately not expressible (see the type: no
        // `impl Add<Addr> for Addr`). That absence is the torsor axiom.
    }

    /// Claim (policy #1): allocation-rooted = snapshot address + liveness domain.
    #[test]
    fn alloc_rooted_is_constant_over_its_lifetime() {
        let mut w = World::new();
        w.alloc(1, Addr(0x1000), 16, /*born*/ 10);
        w.free(1, /*freed*/ 100);
        let loc = Location::alloc_rooted(1, Ty::U64);

        // Before birth: not yet live.
        assert_eq!(
            loc.resolve(&w, 5),
            Err(LocErr::NotYetLive { at: 5, born: 10 })
        );
        // Across the lifetime: constant address.
        assert_eq!(loc.resolve(&w, 10), Ok(Addr(0x1000)));
        assert_eq!(loc.resolve(&w, 50), Ok(Addr(0x1000)));
        assert_eq!(loc.resolve(&w, 99), Ok(Addr(0x1000)));
        // At and after free: use-after-free.
        assert_eq!(
            loc.resolve(&w, 100),
            Err(LocErr::UseAfterFree {
                at: 100,
                freed: 100
            })
        );
        assert_eq!(
            loc.resolve(&w, 150),
            Err(LocErr::UseAfterFree {
                at: 150,
                freed: 100
            })
        );
    }

    /// Claim (policy #2): frame-relative = live re-bind, scoped to an activation.
    /// Within one activation the frame pointer can move (e.g. alloca); the SAME
    /// handle re-resolves against fp(t). Outside the activation it is invalid.
    #[test]
    fn frame_relative_rebinds_live() {
        let mut w = World::new();
        // Activation [10, 20). rbp starts at 0x7000, then alloca moves it to
        // 0x6f00 at t=13.
        w.set_reg(Reg::Rbp, 10, 0x7000);
        w.set_reg(Reg::Rbp, 13, 0x6f00);
        // local `buf` at rbp - 0x10.
        let buf = Location::frame_local(Reg::Rbp, Offset(-0x10), (10, 20), Ty::U64);

        assert_eq!(buf.resolve(&w, 11), Ok(Addr(0x6ff0))); // 0x7000 - 0x10
        assert_eq!(buf.resolve(&w, 14), Ok(Addr(0x6ef0))); // 0x6f00 - 0x10  (re-resolved!)
                                                           // Outside the activation: meaningless, so it raises.
        assert_eq!(
            buf.resolve(&w, 25),
            Err(LocErr::OutOfFrame {
                at: 25,
                activation: (10, 20)
            })
        );
        assert_eq!(
            buf.resolve(&w, 5),
            Err(LocErr::OutOfFrame {
                at: 5,
                activation: (10, 20)
            })
        );
    }

    /// Claim (policy #3): projected `obj->next->data` re-walks the pointer chain
    /// at evaluation time. Mutating `next` in memory changes where the SAME
    /// handle lands, with no re-query.
    #[test]
    fn projection_rewalks_at_evaluation_time() {
        let mut w = World::new();
        w.alloc(1, Addr(0x1000), 16, 0); // node A
        w.alloc(2, Addr(0x2000), 16, 0); // node B
        w.alloc(3, Addr(0x3000), 16, 0); // node C

        // t=5:  A.next -> B (0x2000), B.data = 111
        w.store(Addr(0x1000), 5, 0x2000);
        w.store(Addr(0x2008), 5, 111);
        // t=15: A.next -> C (0x3000), C.data = 222
        w.store(Addr(0x1000), 15, 0x3000);
        w.store(Addr(0x3008), 15, 222);

        let obj = Location::alloc_rooted(1, node_ty());
        // obj->next->data, built entirely from typed field/deref combinators.
        let data = obj
            .field("next")
            .unwrap()
            .deref()
            .unwrap()
            .field("data")
            .unwrap();

        // Same handle, different times -> different resolved address & value.
        assert_eq!(data.resolve(&w, 10), Ok(Addr(0x2008)));
        assert_eq!(data.read(&w, 10), Ok(111));
        assert_eq!(data.resolve(&w, 20), Ok(Addr(0x3008)));
        assert_eq!(data.read(&w, 20), Ok(222));
    }

    /// Claim (the safety property): a stale handle raises — it never returns a
    /// stale value, even though the bytes are still sitting in memory.
    #[test]
    fn stale_handle_raises_never_returns_garbage() {
        let mut w = World::new();
        w.alloc(1, Addr(0x1000), 16, 0);
        w.store(Addr(0x1000), 5, 42); // the value is written and never overwritten
        let loc = Location::alloc_rooted(1, Ty::U64);

        assert_eq!(loc.read(&w, 10), Ok(42)); // live: fine
        w.free(1, 100);
        // The bytes 42 are STILL in memory at 0x1000, but the read must refuse.
        assert_eq!(w.load(Addr(0x1000), 150), Some(42)); // proof the garbage is there
        assert_eq!(
            loc.read(&w, 150),
            Err(LocErr::UseAfterFree {
                at: 150,
                freed: 100
            })
        );
    }

    /// Claim: `.at(t)` is stalk evaluation — it unifies live and replay. The
    /// same handle can be read at a historical timepoint.
    #[test]
    fn at_evaluates_at_a_chosen_timepoint() {
        let mut w = World::new();
        w.alloc(1, Addr(0x1000), 16, 0);
        w.store(Addr(0x1000), 5, 42);
        w.free(1, 100);
        let loc = Location::alloc_rooted(1, Ty::U64);

        // "now" is 200 (long after free), but we ask about the past.
        assert_eq!(loc.at(10).read(&w, 200), Ok(42)); // well-defined: 10 ∈ validity
        assert_eq!(
            loc.at(150).read(&w, 200),
            Err(LocErr::UseAfterFree {
                at: 150,
                freed: 100
            })
        );
    }

    /// Claim: `.at(t)` cascades into a projected base (pins the whole walk).
    #[test]
    fn at_cascades_into_projection() {
        let mut w = World::new();
        w.alloc(1, Addr(0x1000), 16, 0);
        w.store(Addr(0x1000), 5, 0x2000);
        w.store(Addr(0x2008), 5, 111);
        w.store(Addr(0x1000), 15, 0x3000);
        w.store(Addr(0x3008), 15, 222);

        let obj = Location::alloc_rooted(1, node_ty());
        let data = obj
            .field("next")
            .unwrap()
            .deref()
            .unwrap()
            .field("data")
            .unwrap();

        // Pin the whole projection to t=10 even though now=999.
        assert_eq!(data.at(10).read(&w, 999), Ok(111));
        assert_eq!(data.at(20).read(&w, 999), Ok(222));
    }

    /// Claim: `.snapshot()` is the explicit opt-out — it keeps a bare address
    /// that survives free (deliberately unsafe), unlike the live handle.
    #[test]
    fn snapshot_opts_out_of_validity() {
        let mut w = World::new();
        w.alloc(1, Addr(0x1000), 16, 0);
        w.store(Addr(0x1000), 5, 42);
        let loc = Location::alloc_rooted(1, Ty::U64);

        let frozen = loc.snapshot(&w, 10).unwrap();
        assert_eq!(frozen.addr, Addr(0x1000));

        w.free(1, 100);
        // The live handle refuses after free...
        assert_eq!(
            loc.read(&w, 150),
            Err(LocErr::UseAfterFree {
                at: 150,
                freed: 100
            })
        );
        // ...but the frozen address still reads raw bytes: you chose this.
        assert_eq!(frozen.read_at(&w, 150), Some(42));
    }

    /// Claim: offset math stays inside the typed location; the type drives it.
    #[test]
    fn offset_math_is_type_driven_and_stays_inside() {
        let obj = Location::alloc_rooted(1, node_ty());

        // Field offsets come from the recovered layout, not hand-computed ints.
        let next = obj.field("next").unwrap();
        let data = obj.field("data").unwrap();
        match next.prov {
            Provenance::Alloc { offset, .. } => assert_eq!(offset, Offset(0)),
            _ => panic!("wrong provenance"),
        }
        match data.prov {
            Provenance::Alloc { offset, .. } => assert_eq!(offset, Offset(8)),
            _ => panic!("wrong provenance"),
        }

        // Type errors are caught structurally, before any address exists.
        assert_eq!(
            obj.field("nope").err(),
            Some(TypeErr::NoField("nope".to_string()))
        );
        assert_eq!(data.field("x").err(), Some(TypeErr::NotAStruct)); // data is U64
        assert_eq!(obj.deref().err(), Some(TypeErr::NotAPointer)); // Node is not a pointer
        assert!(next.deref().is_ok()); // next IS a pointer
    }

    /// Claim: null-pointer projection is a typed error, not a wild resolve.
    #[test]
    fn null_deref_is_an_error() {
        let mut w = World::new();
        w.alloc(1, Addr(0x1000), 16, 0);
        w.store(Addr(0x1000), 5, 0); // A.next = NULL
        let obj = Location::alloc_rooted(1, node_ty());
        let data = obj
            .field("next")
            .unwrap()
            .deref()
            .unwrap()
            .field("data")
            .unwrap();
        assert_eq!(data.resolve(&w, 10), Err(LocErr::NullDeref { at: 10 }));
    }
}
