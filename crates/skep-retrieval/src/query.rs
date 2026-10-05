//! The [`Query`] handle and what its seven operations share; one file per
//! operation beneath. Every operation begins by reading its slices off the
//! single pinned snapshot, runs its gate (typed rejection), then composes
//! upstream primitives. Which arrangement it then reads — the named
//! address's reading surface, or the named address's own — is the crate
//! doc's *Which arrangement an operation answers from*, and each
//! operation's card says which.
//!
//! Layout: this file is the handle — [`Query`] over one borrowed
//! [`Snapshot`], and [`RetrievalWorld`], the bound every observation reads
//! under — and the two projections more than one operation asks:
//! [`run_origin`] (RETRIEVEV's masked form, SHOWORIGIN) and
//! [`sorted_addr_set`] (SHOWORIGIN, SHOWDELETIONS). Each operation is a
//! child module holding its own `impl` block and the helpers no other
//! operation uses; it sees this file's private items — the snapshot a
//! `Query` holds among them — and none of its siblings'.

use std::collections::BTreeSet;
use std::fmt;

use skep_address::{document_of, Address};
use skep_arrangement::{HasM5, Run};
use skep_kernel::{Seq, Snapshot, WorldState};
use skep_namespace::HasM3;

// RETRIEVEV (ASN-0115): the one impl block bounded by `HasContent`.
mod retrieve;
// RETRIEVEDOCVSPAN / RETRIEVEDOCVSPANSET, and their D-SEQ★ tripwire.
mod extent;
// SHOWORIGIN, V-arity.
mod origin;
// SHOWDELETIONS, and the CURRENT enumeration only it uses.
mod deletions;
// COMPARE: the block join and its presentation.
mod compare;
// FINDDOCSCONTAINING, both doors.
mod find;

/// The world bound EVERY M6 observation reads under: the registry each one
/// gates on and the arrangements each one resolves through, and no slice of
/// its own (Engine Composition Contract — M6 contributes no slice, no record
/// variant, no accessor trait, no fold).
///
/// M4 is deliberately absent. Six of the seven operations answer from
/// addresses, counts and provenance without ever dereferencing a byte —
/// COMPARE's join is keyed on address equality, the extents are counts,
/// SHOWORIGIN projects, and SHOWDELETIONS and FINDDOCSCONTAINING read R — so a
/// content store is not among their collaborators, and under this bound it is
/// not in their scope either. RETRIEVEV is the one operation that delivers
/// bytes, and it declares `HasContent` on its own impl block, which is where
/// that obligation belongs.
pub trait RetrievalWorld: WorldState + HasM3 + HasM5 {}
impl<W: WorldState + HasM3 + HasM5> RetrievalWorld for W {}

/// Stateless observer over ONE pinned snapshot. Owns nothing; holds a borrow.
///
/// The caller (M10) takes the snapshot (`Kernel::snapshot()`) and constructs
/// the handle over it. The obligation is on the SNAPSHOT, not the handle: take
/// **one `Kernel::snapshot()` per logical query** and route every read of that
/// query through handles built on it, so all of them observe one consistent
/// `(M, R)` root — the discharge of M2's clause 6 and the single-Σ requirement
/// of ASN-0075/0122/0124. Reads never commit and have no
/// commit-before-acknowledge obligation.
pub struct Query<'s, W: RetrievalWorld>(&'s Snapshot<W>);

impl<'s, W: RetrievalWorld> Query<'s, W> {
    /// Pin one snapshot. No precondition: any `&Snapshot<W>` is
    /// admissible, and the single-Σ obligation is the caller's over the
    /// snapshot it takes (see the type's card), not over how many handles it
    /// builds on one.
    pub fn new(snap: &'s Snapshot<W>) -> Self {
        Query(snap)
    }

    /// The committed index this query reads (V1 retrospective).
    pub fn as_of(&self) -> Seq {
        self.0.seq()
    }
}

/// Renders the pinned coordinate, which is the whole of a `Query`'s
/// observable identity: the snapshot behind it has no `Debug` of its own, and
/// the world it holds is not a thing to print into a log. Hand-written
/// because a derive would demand `W: Debug` on an impl that never touches
/// `W`.
impl<W: RetrievalWorld> fmt::Debug for Query<'_, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Query")
            .field("as_of", &self.as_of())
            .finish_non_exhaustive()
    }
}

/// A `Query` IS a borrow, so it copies like one — a copy reads the SAME
/// pinned `Snapshot`, which is why the single-Σ obligation is stated over the
/// snapshot rather than over the handles built on it. The charter above (no
/// slice, no fold, no state) is what keeps that safe to promise: the day this
/// holds a field of its own, it stops being a borrow and loses `Copy` with it.
///
/// Hand-written because the derives would put `W: Clone`/`W: Copy` on impls
/// that never touch `W`, and no `WorldState` is `Copy`.
impl<W: RetrievalWorld> Clone for Query<'_, W> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<W: RetrievalWorld> Copy for Query<'_, W> {}

/// The ORIGIN of a run — the document that allocated its I-start, which by
/// block uniformity (ASN-0077 O2) is the origin of every position in it, so
/// one projection answers for the whole run. Asked of M1's `document_of`; the
/// `expect` is the one place M6 states that an element-level I-address has a
/// Document prefix. A link run's origin is its home document (CL-OWN), with
/// no special case.
fn run_origin(run: &Run) -> Address {
    document_of(run.i_start()).expect("an element-level I-address has a Document prefix")
}

/// A stream of addresses as the deduplicated, T1-SORTED set it denotes. Both
/// the dedup and the sort are published guarantees, not conveniences:
/// [`Query::show_origin_v`] answers "deduplicated origin documents in tumbler
/// order" and each half of [`Query::show_deletions`]' answer is a
/// deduplicated, T1-ascending listing, and this is the one place either is
/// established.
///
/// THE TWO GUARANTEES STAND ON DIFFERENT AUTHORITIES, and only one of them is
/// the corpus's. The DEDUP is the comprehension's: ASN-0075's
/// `DeletedFromAWithB` is `{a ∈ dom(C) : …}`, a set, and SHOWORIGIN_V's answer
/// is a set of origin documents. The ORDERING is M6's own presentation of that
/// set — D-ORD licenses it (each output half is a finite subset of
/// `dom(C) ⊆ T`, so T1-orderability is a property of the output addresses) and
/// does not require it (the operation "carries no ordering of its own"), which
/// is why fixing one is M6's to do and to state.
///
/// Identity and order are both `Address`'s own — its `Eq` is tumbler equality
/// (the level is a function of the tumbler) and its `Ord` IS the T1 tumbler
/// order — so the set those two keep is exactly the tumbler-deduplicated,
/// T1-ordered one, with no `.tumbler()` detour and no key clone.
///
/// BUILT AS THE STREAM ARRIVES. SHOWDELETIONS hands this a document's
/// positions WITH multiplicity, and a document's extent is virtual — M5 caps
/// the runs a placing request stores and no position count — so the stream
/// can be `N·W` items for a set of `W`. Each item is inserted as it arrives
/// and a duplicate is dropped on arrival, so what is held live is the set and
/// the item in hand, never the stream. Not `collect::<BTreeSet<_>>()`: std's
/// `FromIterator` buffers the whole stream into a `Vec` to build the tree in
/// bulk, and collecting into a `Vec` to sort and dedup holds it the same way.
///
/// Used for origin DOCUMENTS (SHOWORIGIN_V) and content I-ADDRESSES
/// (SHOWDELETIONS) alike — both are `Address`, so one neutral helper serves
/// either (the name says "addr", not "doc", because what the SHOWDELETIONS
/// site dedups is content addresses, not documents). Generic over the item
/// only so the suite can count what it holds live; both callers instantiate
/// it at `Address`.
fn sorted_addr_set<A: Ord>(it: impl IntoIterator<Item = A>) -> Vec<A> {
    let mut set = BTreeSet::new();
    set.extend(it); // one insert per item: `Extend`, never `FromIterator`
    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use skep_address::{validate, Nat, Tumbler};

    fn a(comps: &[u32]) -> Address {
        let t =
            Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty");
        validate(t).expect("test addresses are T4-valid")
    }

    #[test]
    fn sorted_addr_set_is_deduped_and_t1_ordered() {
        let d2 = a(&[1, 0, 1, 0, 2]);
        let d1 = a(&[1, 0, 1, 0, 1]);
        let got = sorted_addr_set(vec![d2.clone(), d1.clone(), d2.clone(), d1.clone()]);
        assert_eq!(got, vec![d1, d2]);
        assert!(sorted_addr_set(std::iter::empty::<Address>()).is_empty());
    }

    #[test]
    fn sorted_addr_set_holds_the_set_live_and_never_the_stream() {
        // SHOWDELETIONS hands this a stream whose multiplicity a few placing
        // requests choose, so a duplicate must be dropped as it arrives: the
        // peak is the set and the item in hand, whatever the stream's length.
        thread_local! {
            static LIVE: Cell<usize> = const { Cell::new(0) };
            static PEAK: Cell<usize> = const { Cell::new(0) };
        }
        #[derive(PartialEq, Eq, PartialOrd, Ord)]
        struct Counted(u32);
        impl Counted {
            fn new(v: u32) -> Counted {
                LIVE.with(|live| {
                    live.set(live.get() + 1);
                    PEAK.with(|peak| peak.set(peak.get().max(live.get())));
                });
                Counted(v)
            }
        }
        impl Drop for Counted {
            fn drop(&mut self) {
                LIVE.with(|live| live.set(live.get() - 1));
            }
        }
        let set = sorted_addr_set((0..10_000u32).map(|i| Counted::new(i % 2)));
        assert_eq!(set.iter().map(|c| c.0).collect::<Vec<_>>(), [0, 1]);
        let peak = PEAK.with(Cell::get);
        assert!(peak <= 3, "held {peak} live for a two-item set");
    }
}
