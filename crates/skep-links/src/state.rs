//! §A/§1 — the engine-plug slice: [`LinkState`] (the authoritative
//! append-only links map + the recomputable hints; the type registry is a
//! compiled format constant, not carried state), the one journal delta
//! [`LinkRec`], the pure fold [`LinkState::apply_link`], and the load-time
//! [`LinkState::rebuild_derived`].
//!
//! Beneath it, `state/reads.rs` holds the read surface (§E/§F/§G). It is this
//! file's child so that the map, the hints and their edges stay private to
//! the two: the rest of the crate asks the slice the four questions the write
//! surface needs — residence, the claim schema, the next link address and
//! the dedup incumbent — and no other file reaches the map.

use std::collections::BTreeSet;

use im::{HashMap, OrdMap, OrdSet};
use serde::{Deserialize, Serialize};
use skep_address::{
    document_of, elem_addr, link_subspace, validate, Address, ElemPos, Nat, Tumbler,
};

use crate::class::{coverage_class, CoverageClass};
use crate::dedup::DedupKey;
use crate::endset::Link;
use crate::registry::{registry, ShippedType};

// The read surface over this slice — the raw reads, the typed observers and
// the discovery primitives — as this file's child, so that the map and the
// hints stay private to the two.
mod reads;

pub use reads::{CurrentMember, Pattern, Tip, Tuple, View};

/// The ONE authoritative delta. Every write — MAKELINK link, Emit_K tuple,
/// retraction tuple, supersession claim, editlink successor, pdef/pd_stable
/// classifier — is a deposit of an immutable link at a fresh address. There
/// is no update, no delete, no tombstone record (L12/R2/R3).
///
/// The variant is `#[non_exhaustive]`, so no foreign crate can build a
/// `LinkRec` by struct literal: `emit_core` is the only constructor, and the
/// journal is the boundary that keeps it so. That is what puts
/// [`LinkState::apply_link`]'s totality domain — a fresh, T4-valid,
/// element-level address carrying an arity-3 all-level-uniform value — inside
/// this crate's reach, where the deposit gate discharges every clause of it.
/// The engine only `From`-lifts an already-built value and folds it; the
/// match in [`LinkState::apply_link`] is in M7's own crate, so it
/// destructures freely.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum LinkRec {
    #[non_exhaustive]
    Deposit { addr: Tumbler, value: Link },
}

/// One supersession edge out of `old`: the claimed successor and the
/// `[K_sup]` claim asserting it (ASN-0125's `new(e)` and `addr(e)`). It is
/// the CLAIM's activity that makes the edge operative (Df-SUCC), never the
/// endpoint's, which is why the claim address is carried rather than
/// discarded once the edge is built.
///
/// Two `Tumbler`s of different kinds, so they are named: `Ord` derives in
/// field order, making the set's iteration — and therefore `succs`' output
/// order — the claimed-successor order the walk reads.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SupEdge {
    new: Tumbler,
    claim: Tumbler,
}

/// The clause of the `[K_sup]` claim schema (Df-DISC(ii)) a value fails —
/// the verdict [`LinkState::check_sup_schema`] answers, declared in the order
/// it asks. Each writer of a claim translates it into its own vocabulary, so
/// the schema is stated once and refused in as many ways as there are
/// writers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SupSchemaFault {
    /// F or G is not a unit-depth single denoted address.
    NotSingleDenoted,
    /// F or G names a link that is not resident.
    NotResident,
    /// F and G name the same link — irreflexivity.
    Reflexive,
}

/// The recomputable hints — pure functions of `links` (+ `registry`),
/// maintained incrementally by [`LinkState::apply_link`] and re-seeded by
/// [`LinkState::rebuild_derived`]. The journal (via M2) is truth; lose any
/// hint and replay rebuilds it, never wrong.
#[derive(Debug, Clone, Default)]
struct Hints {
    /// Typed slices `L_K` (Observe / type-match, L8) — audit; active is
    /// derived at query time as `audit ∖ nullified`.
    type_slices: HashMap<CoverageClass, OrdSet<Tumbler>>,
    /// Resident retraction roots — the tombstone set (active = audit ∖ this).
    /// Monotone (R3/R6a). Membership is EXACT (`contains`), never
    /// prefix-closed: a root tombstones the one address it denotes and
    /// nothing beneath it. BH1's filter roots are the prefix-closed ones
    /// ([`crate::LinkState::is_filtered`]), and the two regimes must not be
    /// read across.
    nullified: OrdSet<Tumbler>,
    /// I0-class → addrs (audit; active-filtered at the check) — registered
    /// idem⊤ classes only (I1).
    dedup: HashMap<DedupKey, OrdSet<Tumbler>>,
    /// BH2 adjacency: `old` → its [`SupEdge`] set; `[K_sup]` only in v1 (§5).
    sup_fwd: HashMap<Tumbler, OrdSet<SupEdge>>,
    /// `f_d^Σ` — home document → its chain-frontier index, equal to M3's
    /// frontier by construction (Conflicts §7). The next emission lands at
    /// `chain_d(f_d^Σ)`, and BH4 age is measured back from it.
    home_frontier: HashMap<Tumbler, u64>,
}

/// M7's slice of the engine's `WorldState`, reached via
/// [`crate::HasLinks::links`].
///
/// The AUTHORITATIVE state is one map. The type registry it is read under is
/// NOT state at all — the five reserved classes are compiled format
/// constants (`ReservedAddrs::format`; owner ruling, 2026-08-26), so there
/// is no sealed configuration to carry, checkpoint, or re-validate. Identity
/// is the key, never the value: the store is never content-addressed on the
/// endset (NonInjectivity L11b).
///
/// Four INVARIANTS hold of `links`, each at a named gate:
///
/// * **Freshness** — every deposit lands at a key not already present, which
///   is what makes the map append-only with immutable values and so makes
///   Permanence (L12/R2), append-only audit (R3), retraction stability (R6a)
///   and lock-free MVCC reads free. Gate: [`LinkState::apply_link`], the one
///   insertion point, discharged by M3's `mint_link`.
/// * **Arity exactly 3** — every stored value has three slots, so the
///   FROM/TO/TYPE accessors and the discovery primitives' slot indexes are
///   total (ASN-0086's `|Σ.L| = 3`); the [`Link`] type itself holds only the
///   L3 capacity floor of ≥ 3. Gate: `emit_core`'s backstop, ahead of the
///   mint.
/// * **Every slot level-uniform** — so [`coverage_class`] is total on every
///   stored slot, at deposit and at every replay. Gates: `emit`'s
///   address-denoting check on `ty` and `enc` on the rest; `editlink`'s
///   all-slot check on a caller-supplied successor; M5's `Run::iextent` by
///   construction for a resolved slot.
/// * **Every key T4-valid and element-level** — so `home(addr)` exists for
///   the frontier fold and every index key lifts to an `Address`. Gate: the
///   hint fold's two `expect`s, which fail-stop rather than fold a corrupt
///   address.
///
/// The deserialization path constructs a `LinkState` without passing those
/// gates: it establishes the L3 floor (through [`Link`]'s serde door) and
/// fail-stops on a non-T4 key at the rebuild fold, and takes the other two on
/// checkpoint integrity.
///
/// `hints` is `#[serde(skip)]` RECOMPUTABLE state — a pure function of
/// `links`, which is the whole of the Lampson spine's claim: on deserialize
/// serde seeds it empty and [`LinkState::rebuild_derived`] recomputes it from
/// the decoded map BEFORE replay. Load-bearing, because M2 recovers from the
/// deserialized checkpoint whenever one exists and replay's `apply_link` folds
/// read the hints they maintain. The type registry the fold reads alongside
/// them is not carried here at all: it is the module's compiled format
/// constant, [`crate::registry()`], so there is nothing per-slice to seed, to
/// checkpoint, or to re-validate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkState {
    /// ── AUTHORITATIVE ── append-only, immutable values.
    links: OrdMap<Tumbler, Link>,
    /// ── RECOMPUTABLE ── rebuilt from `links` under the format registry.
    #[serde(skip)]
    hints: Hints,
}

impl LinkState {
    /// The genesis slice: `links = ∅`, read under the format registry.
    pub fn genesis() -> LinkState {
        LinkState {
            links: OrdMap::new(),
            hints: Hints::default(),
        }
    }

    /// The pure/total/deterministic M2 fold (§1): insert `addr ↦ value` into
    /// `links` and fold EVERY hint incrementally. Reads only `LinkState` + M1
    /// arithmetic + the module's format registry — which is a compiled
    /// constant, identical on every board, so reading it costs the fold's
    /// purity nothing. Applied exactly once per committed record (M2
    /// guarantees this — deliberately NOT coded idempotent).
    ///
    /// Totality domain over `addr`, all three clauses owed by M3's `mint_link`
    /// and held by every record M7's own paths stage: `addr` is T4-valid, is
    /// element-level, and is FRESH (`addr ∉ dom(links)`) — the mint allocates
    /// on the home's link frontier and never re-issues, and M2 replays each
    /// committed record exactly once. A hand-built `addr` is OUTSIDE the
    /// domain and fail-stops — corruption, not a live error path (the M3
    /// fold's precedent).
    ///
    /// The first two clauses fail-stop on the hint fold's `expect`s. Freshness
    /// is asserted HERE because it is the one that would fail SILENTLY: the
    /// insert would replace an immutable value, leaving its address in the
    /// displaced value's type slice, double-counting the home frontier and
    /// voiding Permanence — none of it observable at the fold that admitted
    /// it.
    ///
    /// Totality domain over `value`, two further clauses, owed by `emit_core`
    /// and the ops that reach it: ARITY EXACTLY 3, and EVERY SLOT
    /// LEVEL-UNIFORM. This is the store's one insertion point, so they are
    /// the same two value invariants [`LinkState`] states, met here or not at
    /// all — and they take different channels on violation. A
    /// non-level-uniform slot fail-stops inside the fold, where
    /// [`coverage_class`] aborts naming its precondition. An arity other than
    /// 3 is ADMITTED silently, the [`Link`] type holding only the L3 floor of
    /// ≥ 3, and makes ASN-0086's `|Σ.L| = 3` false for that stored value —
    /// which is why `emit_core` asserts it ahead of every mint rather than
    /// leaving it to the type.
    #[must_use = "apply_link returns the folded state; it does not modify the receiver"]
    pub fn apply_link(&self, r: &LinkRec) -> LinkState {
        match r {
            LinkRec::Deposit { addr, value } => {
                let mut next = self.clone();
                let displaced = next.links.insert(addr.clone(), value.clone());
                assert!(
                    displaced.is_none(),
                    "apply_link: a Deposit must land at a fresh address (M3's mint never \
                     re-issues); replacing an immutable value voids Permanence (L12/R2)"
                );
                next.hints = fold_hints(&self.hints, addr, value);
                next
            }
        }
    }

    /// Runs once at load, BEFORE replay (M2's `rebuild_derived` slot):
    /// recomputes every hint from the deserialized `links` map in one pass,
    /// under the module's format registry. Required because `hints` is
    /// `#[serde(skip)]` — M2's default identity would leave it empty, and
    /// replay's `apply_link` folds maintain exactly these hints.
    #[must_use = "rebuild_derived returns the rebuilt state; dropping it keeps the empty hints"]
    pub fn rebuild_derived(self) -> LinkState {
        let mut hints = Hints::default();
        for (addr, value) in self.links.iter() {
            hints = fold_hints(&hints, addr, value);
        }
        LinkState {
            links: self.links,
            hints,
        }
    }

    /// Residence: `t ∈ dom(links)` (crate-internal; the public forms are
    /// `readlink`/`is_active`).
    pub(crate) fn resident(&self, t: &Tumbler) -> bool {
        self.links.contains_key(t)
    }

    /// Tombstoned: `t` is a retraction root. The one statement of the rule
    /// every active view applies — active = audit ∖ this — monotone
    /// (R3/R6a). EXACT membership, never a prefix test: a root tombstones
    /// the one address it denotes, so nothing beneath a nullified document
    /// or account is nullified by it. The public form is `is_nullified`.
    fn nullified(&self, t: &Tumbler) -> bool {
        self.hints.nullified.contains(t)
    }

    /// Df-DISC(ii): the `[K_sup]` claim schema — F and G each a unit-depth
    /// single denoted address, both resident, the two distinct — answered as
    /// the FIRST clause the value fails, asked in that order: denotation
    /// first, because residence and irreflexivity are questions about the
    /// addresses F and G denote, then residence before irreflexivity, the
    /// precedence `assert_sup` publishes.
    ///
    /// The one statement of the invariant every stored claim holds, and the
    /// whole reason `assert_sup`/`editlink` are the sole `[K_sup]` writers:
    /// the supersession adjacency, the walk family and M8's lineage reads all
    /// take it as fact. Both writers ask it and translate the verdict into
    /// their own vocabulary — `assert_sup` into its two typed rejections,
    /// `editlink`'s DC guard into one — and `editlink`'s own claim meets it by
    /// construction rather than by asking: built by
    /// [`supersession_claim`](crate::supersession_claim), one address a side;
    /// F the original, checked resident against the base;
    /// G the successor minted a line earlier in the same transaction —
    /// resident in the working world, and distinct from every link resident
    /// before it, the original included.
    pub(crate) fn check_sup_schema(&self, value: &Link) -> Result<(), SupSchemaFault> {
        let (Some(f), Some(g)) = (
            value.from_slot().single_denoted(),
            value.to_slot().single_denoted(),
        ) else {
            return Err(SupSchemaFault::NotSingleDenoted);
        };
        if !self.resident(f) || !self.resident(g) {
            return Err(SupSchemaFault::NotResident);
        }
        if f == g {
            return Err(SupSchemaFault::Reflexive);
        }
        Ok(())
    }

    /// `f_d^Σ` — the home's chain-frontier hint, 0 for a home holding no
    /// links yet. The one reading of it: `next_link_address` mints at
    /// `1 + this`, BH4 `age` counts back from it.
    fn home_frontier(&self, home: &Address) -> u64 {
        self.hints
            .home_frontier
            .get(home.tumbler())
            .copied()
            .unwrap_or(0)
    }

    /// The link an INDEX KEY names. Every key in `type_slices`/`dedup`/
    /// `sup_fwd`, and every key `stab` returns, is a key of `links` —
    /// [`fold_hints`] only ever indexes the address it is inserting — so
    /// absence is corruption rather than a miss, and fail-stops here instead
    /// of reading downstream as an empty answer. `readlink` is the fallible
    /// form, for an address a caller supplies.
    fn link_at(&self, t: &Tumbler) -> &Link {
        self.links
            .get(t)
            .expect("an index key names a resident link: the fold indexes only what it inserts")
    }

    /// The address `mint_link(home)` would mint next —
    /// `home · 0 · s_L · (1 + f_d^Σ)`, assembled off M7's own frontier and
    /// equal to M3's by construction (FrontierUnification; Conflicts §7 — no
    /// upward M3 read). An absent frontier gives ordinal 1, the first
    /// emission itself. `home` is a registered Document, which is what makes
    /// the assembly total (§4).
    pub(crate) fn next_link_address(&self, home: &Address) -> Address {
        let ordinal = 1 + self.home_frontier(home);
        elem_addr(ElemPos {
            doc: home.clone(),
            subspace: link_subspace(),
            ordinal: Nat::from(ordinal),
        })
        .expect("P0 discharged: home is a Document; s_L ≥ 1; ordinal ≥ 1 (§4)")
    }

    /// The active-view dedup incumbent of an I0 class VISIBLE to the caller
    /// (§3 step 2; PUB-6.25): the audit matches filtered by `∉ nullified` and
    /// by `readable_home(home(addr))`, T1-least first — the EARLIEST READABLE
    /// incumbent, never merely the earliest. Reading the ACTIVE view (I2) is
    /// what gives resurrection — a nullified tuple is invisible here, so
    /// re-emitting lands fresh — and reading it through the caller's
    /// visibility class is what keeps a dedup hit from acking an address the
    /// caller could not learn by any read (PUB-6.26).
    ///
    /// The filter is applied at link-HOME identity: `home(addr)` is
    /// `document_of`, address arithmetic on the index key, no read. Every key
    /// here is element-level (the fold's frontier expect), so the home
    /// exists. The predicate itself is the caller's — M7 learns nothing about
    /// principals; it asks "may this caller read this document" of a closure
    /// the caller threaded in, over the world the caller is writing.
    pub(crate) fn active_incumbent(
        &self,
        key: &DedupKey,
        readable_home: impl Fn(&Address) -> bool,
    ) -> Option<Address> {
        self.hints
            .dedup
            .get(key)?
            .iter()
            .filter(|t| !self.nullified(t))
            .map(lift)
            .find(|addr| {
                let home = document_of(addr)
                    .expect("every stored link key is element-level, so its home Document exists");
                readable_home(&home)
            })
    }
}

/// `Tumbler → Address` lift of an INDEX KEY — infallible, every key of
/// `links` being T4-valid by M3's mint. THE boundary lift, applied wherever a
/// store key leaves the store: every §F tuple address, every §G result and
/// every dedup incumbent passes through here, so no reader — inside the crate
/// or out — restates the mint's guarantee to lift a key of its own. It sits
/// beside [`LinkState::link_at`] because both are facts about the keys of one
/// map.
///
/// Borrows, because an index key belongs to the store and the read only looks
/// at it — the ownership counterpart of the read surface's `lift_denoted`,
/// whose argument the read produced and is about to drop.
fn lift(t: &Tumbler) -> Address {
    validate(t.clone()).expect("every stored link key is T4-valid by M3's mint")
}

/// The incremental hint fold shared by [`LinkState::apply_link`] (per record)
/// and [`LinkState::rebuild_derived`] (whole-map pass) — one function so the
/// recovered hints are exactly the live-maintained ones (M2's consistency
/// obligation).
///
/// Class recognition and every write-path guard evaluate the SAME pure
/// [`coverage_class`] — the shipped classes this fold recognizes are that
/// function's own verdicts, fixed once at `TypeRegistry::build`. No second
/// classifier exists anywhere in M7 (class coherence, §Core data model). The
/// registry it recognizes them through is the module's compiled constant, so
/// this stays a pure function of `(hints, addr, value)`: the same three
/// arguments give the same hints on every board.
fn fold_hints(hints: &Hints, addr: &Tumbler, value: &Link) -> Hints {
    let registry = registry();
    let mut out = hints.clone();
    let class = coverage_class(value.type_slot());

    // type_slices — `L_K` per coverage class (L8).
    out.type_slices
        .entry(class.clone())
        .or_default()
        .insert(addr.clone());

    // nullified — the replay-critical [R] fold, pinned off the surface
    // discipline (§1): insert EVERY denoted to-root (zero roots ⇒ no insert,
    // several ⇒ all inserted; a non-unit-depth [R] to-span contributes no
    // root). Every v1 surface path yields exactly one root, but the fold
    // never invents behavior. A root tombstones the ONE address it denotes:
    // the set is read by exact membership, so inserting a document address
    // here would tombstone that document and no link under it.
    if class == *registry.shipped_class(ShippedType::Retraction) {
        for root in value.to_slot().addrs() {
            out.nullified.insert(root.clone());
        }
    }

    // dedup — registered idem⊤ classes only (§1), by the registry's one
    // statement of that predicate, which is also what decides whether a
    // deposit takes M2's I0 section — so what the fold indexes and what the
    // lock serializes cannot come apart. An unregistered or idem⊥ class
    // skips the key entirely (no dedup check ever reads it). Keyed by
    // CLASS, never by the surface a deposit arrived through, so a MAKELINK
    // deposit whose resolved type class is a registered idem⊤ one is indexed
    // here too (possibly with extent-classed from/to). No such key ever
    // reaches a LockKey — the open surface takes no dedup lock (Conflicts §1)
    // — but the key IS a live entry: an `emit` whose whole I0 triple matches
    // it hits that link as the incumbent, having applied to it none of the
    // managed surface's shape or dedup discipline.
    if registry.is_idempotent(&class) {
        out.dedup
            .entry(DedupKey::of(value))
            .or_default()
            .insert(addr.clone());
    }

    // sup_fwd — one SupEdge out of each denoted old, for a [K_sup]-classed
    // tuple; both endpoints via addrs() (§5). DISTINCT endpoints, because the
    // schema admits repeats: Df-DISC(ii) demands one distinct denoted address
    // a side, so a slot may name it any number of times, and a repeated span
    // cannot add an edge — it can only multiply the work of adding one, at
    // every deposit AND at every replay. Deduplicating first makes the
    // schema-conformant case the 1 × 1 it is.
    if class == *registry.shipped_class(ShippedType::Supersedes) {
        let olds: BTreeSet<&Tumbler> = value.from_slot().addrs().collect();
        let news: BTreeSet<&Tumbler> = value.to_slot().addrs().collect();
        for old in olds {
            let edges = out.sup_fwd.entry(old.clone()).or_default();
            for new in &news {
                edges.insert(SupEdge {
                    new: (*new).clone(),
                    claim: addr.clone(),
                });
            }
        }
    }

    // home_frontier — keyed by home(addr) (Conflicts §7). The expects mark the
    // totality domain: every staged addr is M3-minted, T4-valid, element-level.
    let home = document_of(
        &validate(addr.clone()).expect("LinkRec addrs are M3-minted T4-valid link addresses"),
    )
    .expect("link addresses are element-level, so their home Document exists");
    *out.home_frontier.entry(home.tumbler().clone()).or_insert(0) += 1;

    out
}

#[cfg(test)]
mod tests {
    use skep_address::Nat;

    use super::*;
    use crate::endset::{enc, Endset};

    /// doc1's content element `k`.
    fn ca(k: u32) -> Address {
        addr(&[1, 0, 1, 0, 1, 0, 1, k])
    }

    /// doc1's link element `k` — where a deposit lands.
    fn la(k: u32) -> Address {
        addr(&[1, 0, 1, 0, 1, 0, 2, k])
    }

    fn addr(comps: &[u32]) -> Address {
        validate(Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty"))
            .expect("T4-valid")
    }

    #[test]
    #[should_panic(expected = "fresh address")]
    fn apply_link_refuses_a_second_deposit_at_one_address() {
        // Freshness is the one store invariant whose violation is SILENT — the
        // insert would replace an immutable value, leaving its address in the
        // displaced value's type slice, double-counting the home frontier and
        // voiding Permanence, none of it observable at the fold that admitted
        // it. Unconstructible through the kernel (M3's mint never re-issues and
        // M2 replays each record once) and unconstructible outside this crate
        // (the `Deposit` variant is `#[non_exhaustive]`), which is why the
        // assert is its only witness and why the witness lives here.
        let state = LinkState::genesis();
        let rec = LinkRec::Deposit {
            addr: la(1).tumbler().clone(),
            value: Link::triple(enc([&ca(1)]), enc([&ca(2)]), enc([&ca(9)])),
        };
        let once = state.apply_link(&rec);
        let _twice = once.apply_link(&rec); // corruption, not a live error path
    }

    #[test]
    fn the_claim_schema_answers_the_first_clause_a_value_fails() {
        // The verdict both `[K_sup]` writers translate. `assert_sup` can only
        // ever meet two of its clauses and `editlink` folds all three into one
        // rejection, so neither op's surface shows which clause a value fails
        // or the order they are asked in; this is where both are watched.
        let deposit = |at: Address, k: u32| LinkRec::Deposit {
            addr: at.tumbler().clone(),
            value: Link::triple(enc([&ca(k)]), Endset::empty(), enc([&ca(9)])),
        };
        let state = LinkState::genesis()
            .apply_link(&deposit(la(1), 1))
            .apply_link(&deposit(la(2), 2));
        let sup = registry().reserved_type(ShippedType::Supersedes).clone();
        let check = |f: &[&Address], g: &[&Address]| {
            state.check_sup_schema(&Link::triple(
                enc(f.iter().copied()),
                enc(g.iter().copied()),
                sup.clone(),
            ))
        };

        assert_eq!(check(&[&la(1)], &[&la(2)]), Ok(()));
        // One DISTINCT address a side, however many times a slot names it.
        assert_eq!(check(&[&la(1), &la(1)], &[&la(2)]), Ok(()));
        // Each clause on its own.
        assert_eq!(
            check(&[&la(1), &la(2)], &[&la(2)]),
            Err(SupSchemaFault::NotSingleDenoted)
        );
        assert_eq!(
            check(&[&la(1)], &[&la(9)]),
            Err(SupSchemaFault::NotResident)
        );
        assert_eq!(
            check(&[&la(9)], &[&la(1)]),
            Err(SupSchemaFault::NotResident)
        );
        assert_eq!(check(&[&la(1)], &[&la(1)]), Err(SupSchemaFault::Reflexive));
        // The order, on values failing two clauses at once: a ghost named on
        // both sides is non-resident before it is reflexive — the precedence
        // `assert_sup` publishes — and a two-ghost F is not one denoted
        // address before any of its addresses is asked for residence.
        assert_eq!(
            check(&[&la(9)], &[&la(9)]),
            Err(SupSchemaFault::NotResident)
        );
        assert_eq!(
            check(&[&la(8), &la(9)], &[&la(9)]),
            Err(SupSchemaFault::NotSingleDenoted)
        );
    }
}
