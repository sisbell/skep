//! The look at guest class: M7's read surface as the evaluator sees it.
//!
//! It is `&LinkState` behind one home filter that drops every tuple whose
//! home document the coordinator's injected guest predicate refuses. Every
//! read the evaluator makes of the store goes through this surface, and
//! through nothing else: `EvalCtx.links` *is* this surface in every
//! construction (`eval`/`decide`, the rule engine's domain enumeration,
//! trigger evaluation and scope test, the fire's own re-check, the def-path
//! denotation), so no draft-homed tuple can satisfy a rule's trigger, seed
//! its domain, or move a PL verdict. M7's `LinkState` reads take no
//! visibility class; the home filter is the delegator's, applied here.
//!
//! **Why by home (PUB-1.26, PUB-1.31, PUB-6.13).** A link carries no
//! publication flag of its own — its publishedness is its home's — so a
//! tuple is visible at guest class iff the guest predicate admits
//! `document_of(t.addr)` — its home document being published. That is the
//! same test M7's own value-keyed gates apply at link-home identity and the
//! result-set row applies to every link (PUB-6.13). The slice
//! (`Active`/`Audit`) is orthogonal to the visibility class: an `AuditSlice`
//! domain still shows the retracted tuples of readable homes, and never a
//! draft's tuples. This axis keeps its own words: a tuple is visible at guest
//! class when its home is readable there, a read outside this surface is at
//! no visibility class, and this surface is the look — never a "view", which
//! in this crate is PC3's term view, nor a bare "class", which is a coverage
//! class (ASN-0128 I0).
//!
//! **Why here (PUB-6.28; the visibility class is threaded from the
//! caller).** "a fire's verdict never turns on a document rule 4 hides, and a
//! fire commits byte-identically to a world with no drafts" — rule 4 being
//! PUB's model rule (PUB-1.13–1.16: addresses are not secret; a draft's bytes
//! and structure are), not a registered rule. The verdict is the trigger's as
//! much as the write's, so the guest class pinned on the action's home
//! (`FireError::DraftBoundary`) and on the writer's gates is applied to the
//! look too — in M9, the delegator that holds `guest`. M7 is told nothing.
//!
//! **Cost (PUB-7.15's shape).** One `document_of` (M1 arithmetic, no read)
//! and one predicate call per candidate tuple a collection read tests — a
//! rule's domain over a type slice of N tuples costs N home tests,
//! proportional to the unfiltered candidate set, as the read-side filters
//! are; a membership predicate stops at the first tuple that answers, so it
//! pays at most that. No per-home memo is kept: the context is borrow-scoped
//! to one verdict, the predicate the engine injects is an exception-set
//! membership test (one hash, and a second for a draft home), and the
//! evaluator carries no interior mutability.
//!
//! **The reads.** Each is answered over the visible slice exactly as M7's own
//! answers it over the whole — the collections by dropping the tuples of
//! unreadable homes, the membership predicates by scanning for the first one
//! that answers: `is_k` and `observe`, and the rest the evaluator makes —
//! `members`, `targets_of` and `targets_of_denoting` (ASN-0128 D1/D3 over the
//! visible slice, the last in V-AUD's exact-denotation regime, which is the
//! one read where a PL view changes which tuples match); the BH2 walk family
//! `succs`/`chain`/`tip`/`is_in_chain` (rebuilt over the visible active
//! `[K_sup]` claims, so a draft-homed claim moves no walk); the BH3 pair
//! `sources_to`/`target_of` (the `targets_keyed` join is `EvalCtx`'s, over
//! the catalog's `ReverseLookup` classes, each answered by `target_of` here);
//! and BH4's `is_active_tuple`/`age`/`stale` (dormant in this format,
//! filtered the same way). Signatures follow M7's, save four departures: a
//! read whose counterpart there takes a term view names the stored [`Slice`]
//! it reads instead, and so does `is_k`, whose counterpart reads the active
//! slice alone; the set-valued reads answer in the ℘_fin(T) shape the
//! evaluator holds, `OrdSet<Address>` — each tumbler M7's endsets denote
//! lifted once as the set is gathered ([`lift`]), and for `stale` M7's own
//! addresses kept as they are — rather than M7's `Vec<Address>`;
//! `is_active_tuple` — BH4's totalization premise — is PL's composition of
//! `observe`, M7 offering no such read; and so is `targets_of_denoting`,
//! V-AUD's exact regime.

use std::collections::BTreeMap;
use std::slice::from_ref;

use im::OrdSet;
use skep_address::{document_of, Address, Tumbler};
use skep_links::{Endset, HasLinks, LinkState, NotBh4, Pattern, Tip, Tuple, View, Visibility};

use crate::value::{lift, Slice};

/// The widening of a stored slice to a `View`, which is total.
///
/// It is the one conversion, made where M9 calls M7
/// (`GuestLinks::candidates`), so it belongs to this read surface. The slice
/// itself, and its relation to a term view (`Slice::of`), are PL vocabulary
/// (`value.rs`): the evaluator and the analyzer ask that relation, and this
/// surface, which never sees a term view, reads by the slice alone.
impl From<Slice> for View {
    fn from(s: Slice) -> View {
        match s {
            Slice::Active => View::Active,
            Slice::Audit => View::Audit,
        }
    }
}

/// The visible operative claims as a forward map, `old → {new}` by denotation.
///
/// Each endpoint is lifted to its address as the map is built — built once
/// per walk, so a walk of C steps over C claims costs C map probes, not C
/// scans of the claim set.
type ForwardClaims = BTreeMap<Address, OrdSet<Address>>;

/// One forward walk's result over the visible operative claims.
#[derive(Debug)]
struct Walk {
    /// The traversed path from the starting node, inclusive of it.
    path: Vec<Address>,
    /// The successor-free node the walk halted at.
    ///
    /// It is `None` at a branch or a cycle, where the head is indeterminate.
    sink: Option<Address>,
}

/// M7's read surface at guest class, over the world of one pinned snapshot.
pub(crate) struct GuestLinks<'a, W> {
    world: &'a W,
    /// M7's own answers, before this module's home filter narrows them.
    ///
    /// They are the side every read below starts from and none of them hands
    /// back.
    unfiltered: &'a LinkState,
    guest: &'a Visibility<'a, W>,
}

impl<'a, W> GuestLinks<'a, W> {
    /// Returns the read surface over `world`, filtered by `guest`.
    ///
    /// `world` is the world of one pinned snapshot, and `guest` the
    /// guest-class predicate the coordinator lends (a borrow of the one
    /// closure it holds — the same one every `LinkWriter` it builds runs at).
    /// M7's `LinkState` is taken *from* that world, so the tuples read and the
    /// homes they are filtered by cannot come from two worlds; the bound sits
    /// here alone, the reads below staying unbounded in `W`.
    pub(crate) fn new(world: &'a W, guest: &'a Visibility<'a, W>) -> GuestLinks<'a, W>
    where
        W: HasLinks,
    {
        GuestLinks { world, unfiltered: world.links(), guest }
    }

    /// Returns whether `link` passes the guest-class test.
    ///
    /// The test is at link-home identity, as M7's dedup gate applies it:
    /// `document_of(link)` is address arithmetic (no read), then the
    /// predicate on that home. A stored link key is element-level, so its
    /// home exists; an address with no document is answered `false`
    /// (fail-closed).
    fn home_readable(&self, link: &Address) -> bool {
        document_of(link).is_some_and(|home| (self.guest)(self.world, &home))
    }

    fn admits(&self, t: &Tuple) -> bool {
        self.home_readable(&t.addr)
    }

    /// Returns M7's `observe` over one stored slice, unfiltered.
    ///
    /// It is the one place a slice widens to the `View` M7 names it by. Every
    /// tuple read here starts from it and narrows by [`GuestLinks::admits`]:
    /// the collections through [`GuestLinks::observe`]'s `retain`, the two
    /// membership predicates through `any`, which stops at the first tuple
    /// that answers. BH4's `age` and `stale` name no slice — M7 answers them
    /// over addresses, from its own computation — and narrow by
    /// [`GuestLinks::home_readable`] directly.
    fn candidates(&self, ty: &Endset, pat: Pattern<'_>, slice: Slice) -> Vec<Tuple> {
        self.unfiltered.observe(ty, pat, slice.into())
    }

    /// Returns M7's `observe` over one stored slice, home-filtered.
    ///
    /// The tuples of unreadable homes are dropped — the one filtering
    /// primitive every tuple-collection read here is built on. `stale`, whose
    /// answer is M7's own staleness computation over addresses, filters
    /// through [`GuestLinks::home_readable`] directly, and the guest-class
    /// test has its one statement there.
    pub(crate) fn observe(&self, ty: &Endset, pat: Pattern<'_>, slice: Slice) -> Vec<Tuple> {
        let mut out = self.candidates(ty, pat, slice);
        out.retain(|t| self.admits(t));
        out
    }

    /// Answers ASN-0128 D2 over the visible slice.
    ///
    /// It holds when some visible type-`ty` tuple's F *covers* the probe.
    /// M7's own `is_k` does not expose the witnessing tuple, so the answer is
    /// a home-filtered scan at the same coverage pattern — a predicate over
    /// the slice, stopping at the first visible match. The UV rewrite is
    /// `EvalCtx`'s own, and asks this read at the active slice rather than
    /// rewriting it.
    pub(crate) fn is_k(&self, ty: &Endset, probe: &Tumbler, slice: Slice) -> bool {
        self.candidates(ty, Pattern { from: from_ref(probe), to: &[] }, slice)
            .iter()
            .any(|t| self.admits(t))
    }

    /// Returns the deduplicated denotation of one slot over `tuples`.
    ///
    /// That is `⋃ slot(t).addrs()` as the ℘_fin(T) value the evaluator holds,
    /// each denoted tumbler lifted to its address ([`lift`]) — the shape
    /// V-AUD's D3 takes, and M7's own equations for ASN-0128 D1, D3 and BH3's
    /// reverse, so each of those is one line over its own tuple source, and
    /// the last three are checkable against M7's.
    fn denote_slot(tuples: Vec<Tuple>, slot: fn(&Tuple) -> &Endset) -> OrdSet<Address> {
        tuples.iter().flat_map(|t| slot(t).addrs()).map(lift).collect()
    }

    /// Returns [`GuestLinks::denote_slot`] over the visible matching tuples.
    ///
    /// They are the visible tuples of `slice` matching `pat` — the
    /// *coverage*-matched reads.
    fn denoted(
        &self,
        ty: &Endset,
        pat: Pattern<'_>,
        slice: Slice,
        slot: fn(&Tuple) -> &Endset,
    ) -> OrdSet<Address> {
        Self::denote_slot(self.observe(ty, pat, slice), slot)
    }

    /// Returns the visible `slice` tuples whose F *denotes* `x`.
    ///
    /// That is `x ∈ F.addrs()`, V-AUD's exact regime, which M7's `Pattern`
    /// cannot express (it matches F by *coverage*). A matching regime on the
    /// source, yielding tuples, where [`GuestLinks::denote_slot`] and
    /// [`GuestLinks::denoted`] are the denotation fold over one slot, yielding
    /// a ℘_fin(T) value.
    ///
    /// Denotation implies coverage — a denoted address is the start of a
    /// unit-depth span, which covers it — so the coverage pattern is a sound
    /// pre-filter: the scan runs over the covering tuples, not over the whole
    /// slice.
    fn tuples_denoting(&self, ty: &Endset, x: &Address, slice: Slice) -> Vec<Tuple> {
        let mut out = self.observe(ty, Pattern { from: from_ref(x.tumbler()), to: &[] }, slice);
        out.retain(|t| t.from.addrs().any(|f| f == x.tumbler()));
        out
    }

    /// Returns ASN-0128 D1 over the visible slice: `⋃ F.addrs()`.
    ///
    /// That is M7's own equation.
    pub(crate) fn members(&self, ty: &Endset, slice: Slice) -> OrdSet<Address> {
        self.denoted(ty, Pattern::default(), slice, |t| &t.from)
    }

    /// Returns ASN-0128 D3 over the visible slice.
    ///
    /// That is `⋃ G.addrs()` of the tuples whose F *covers* `x` (M7's own
    /// coverage regime for this read).
    pub(crate) fn targets_of(&self, ty: &Endset, x: &Address, slice: Slice) -> OrdSet<Address> {
        let pat = Pattern { from: from_ref(x.tumbler()), to: &[] };
        self.denoted(ty, pat, slice, |t| &t.to)
    }

    /// Returns V-AUD's form of ASN-0128 D3 over the visible audit slice.
    ///
    /// That is `⋃ G.addrs()` of the tuples whose F *denotes* `x`, where
    /// [`GuestLinks::targets_of`] takes those whose F *covers* it — the one
    /// place a PL view changes which tuples match and not merely which slice
    /// is read.
    pub(crate) fn targets_of_denoting(&self, ty: &Endset, x: &Address) -> OrdSet<Address> {
        Self::denote_slot(self.tuples_denoting(ty, x, Slice::Audit), |t| &t.to)
    }

    // ─────────── BH2 — the walk over the visible operative claims ───────────
    //
    // Served for whatever link type the caller names: the type checker admits
    // the walk atoms only at the shipped `Supersedes` key (`UnservedWalkClass`
    // otherwise — M7 v1's serving scope), so that question is decided once,
    // at check time, and never re-asked here.

    /// Returns the visible operative claim set, indexed forward.
    ///
    /// It holds the active `[K_sup]` tuples of readable homes, as
    /// `old → {new}`. Edges run `old → new` by *denotation* on both slots,
    /// exactly as M7's `sup_fwd` fold keys them; a claim is operative iff
    /// unnullified (Df-SUCC), which the active slice gives. One pass over the
    /// claims per walk.
    fn forward_claims(&self, ty: &Endset) -> ForwardClaims {
        let mut fwd = ForwardClaims::new();
        for t in self.observe(ty, Pattern::default(), Slice::Active) {
            for old in t.from.addrs() {
                fwd.entry(lift(old)).or_default().extend(t.to.addrs().map(lift));
            }
        }
        fwd
    }

    /// Returns `succ_o(x)` over the visible claims, deduplicated over `new`.
    fn succs_operative(fwd: &ForwardClaims, x: &Address) -> OrdSet<Address> {
        fwd.get(x).cloned().unwrap_or_default()
    }

    /// Returns the visited-set-bounded forward walk from `x`.
    ///
    /// The bound is M7's own halting rule.
    fn walk_claims(fwd: &ForwardClaims, x: &Address) -> Walk {
        let mut path = vec![x.clone()];
        let mut visited = OrdSet::unit(x.clone());
        let mut node = x.clone();
        loop {
            // "Exactly one successor" as the two `next`s that decide it, in
            // `target_of`'s shape — so the sole successor is taken from the
            // iterator that found it rather than fetched again behind a
            // length test.
            let mut succs = Self::succs_operative(fwd, &node).into_iter();
            match (succs.next(), succs.next()) {
                (None, _) => return Walk { path, sink: Some(node) },
                (Some(next), None) => {
                    if visited.contains(&next) {
                        return Walk { path, sink: None }; // cycle
                    }
                    visited.insert(next.clone());
                    path.push(next.clone());
                    node = next;
                }
                _ => return Walk { path, sink: None }, // branch
            }
        }
    }

    /// Returns the BH2 forward step over the visible operative claims.
    pub(crate) fn succs(&self, ty: &Endset, x: &Address) -> OrdSet<Address> {
        Self::succs_operative(&self.forward_claims(ty), x)
    }

    /// Returns the BH2 chain over the visible operative claims.
    pub(crate) fn chain(&self, ty: &Endset, x: &Address) -> Vec<Address> {
        Self::walk_claims(&self.forward_claims(ty), x).path
    }

    /// Returns the BH2 head over the visible operative claims.
    ///
    /// It is `Sink(head)` at a successor-free node, `Indeterminate` at a
    /// branch or cycle.
    pub(crate) fn tip(&self, ty: &Endset, x: &Address) -> Tip {
        match Self::walk_claims(&self.forward_claims(ty), x).sink {
            Some(sink) => Tip::Sink(sink),
            None => Tip::Indeterminate,
        }
    }

    /// Returns BH2 chain membership, `target ∈ chain(ty, addr)`.
    ///
    /// It is walk-result membership, never a coverage test.
    pub(crate) fn is_in_chain(&self, ty: &Endset, addr: &Address, target: &Address) -> bool {
        Self::walk_claims(&self.forward_claims(ty), addr).path.contains(target)
    }

    // ───────────────────── BH3 — over the visible slice ─────────────────────

    /// Returns the BH3 reverse over the visible slice.
    ///
    /// That is the F-denoted sources of the visible active type-`ty` tuples
    /// whose G *covers* `target`.
    pub(crate) fn sources_to(&self, ty: &Endset, target: &Address) -> OrdSet<Address> {
        let pat = Pattern { from: &[], to: from_ref(target.tumbler()) };
        self.denoted(ty, pat, Slice::Active, |t| &t.from)
    }

    /// Returns the BH3 forward target over the visible slice.
    ///
    /// It is ⊥ unless exactly one visible active type-`ty` tuple denotes
    /// `source` in F with a single-address-denoting G.
    pub(crate) fn target_of(&self, ty: &Endset, source: &Address) -> Option<Address> {
        let mut matches = self.tuples_denoting(ty, source, Slice::Active).into_iter();
        match (matches.next(), matches.next()) {
            (Some(t), None) => t.to.single_denoted().map(lift),
            _ => None, // no visible active match, or several ⇒ ⊥
        }
    }

    // ───────────────────── BH4 — over the visible slice ─────────────────────

    /// Returns whether `a` is the address of a visible active type-`ty` tuple.
    ///
    /// A tuple-*identity* test, not [`GuestLinks::is_k`]'s coverage-of-F
    /// membership — the two reads differ, and BH4's totalization keys on this
    /// one ([`GuestLinks::age`] is untyped, M7's being untyped, so the
    /// type-indexing is PL's and the read is answered here with the rest).
    /// The address test comes first, so the visibility test — which builds a
    /// tumbler per call — runs at most once over the slice rather than once
    /// per tuple in it.
    pub(crate) fn is_active_tuple(&self, ty: &Endset, a: &Address) -> bool {
        self.candidates(ty, Pattern::default(), Slice::Active)
            .iter()
            .any(|t| t.addr == *a && self.admits(t))
    }

    /// Returns BH4 age: M7's own for a link of a readable home, ⊥ otherwise.
    ///
    /// A draft-homed tuple has no age at guest class, as it has no residence.
    pub(crate) fn age(&self, a: &Address) -> Option<u64> {
        if !self.home_readable(a) {
            return None;
        }
        self.unfiltered.age(a)
    }

    /// Returns the BH4 stale set: M7's own, minus unreadable homes' tuples.
    ///
    /// It is the one read here whose M7 answer is already in addresses, kept
    /// as the addresses a ℘_fin(T) value holds.
    ///
    /// # Errors
    ///
    /// `NotBh4`, the fence of the read it wraps, where `ty` is no BH4 class.
    pub(crate) fn stale(&self, ty: &Endset, horizon: u64) -> Result<OrdSet<Address>, NotBh4> {
        let stale = self.unfiltered.stale(ty, horizon)?;
        Ok(stale.into_iter().filter(|a| self.home_readable(a)).collect())
    }
}
