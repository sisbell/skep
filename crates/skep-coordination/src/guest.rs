//! THE LOOK AT GUEST CLASS (PUB round 2, lane 4.1): M7's read surface as the
//! evaluator sees it — one filtered view over `&LinkState` that DROPS every
//! tuple whose HOME document the coordinator's injected guest predicate
//! refuses. Every read the evaluator makes of the store goes through this
//! view, and through nothing else: `EvalCtx.links` IS this view in every
//! construction (`eval`/`decide`, the rule engine's domain enumeration and
//! trigger evaluation, the fire's own re-check, the def-path denotation), so
//! no draft-homed tuple can satisfy a rule's trigger, seed its domain, or
//! move a PL verdict. M7's `LinkState` reads stay class-free; the filter is
//! the delegator's, applied here.
//!
//! WHY BY HOME (PUB-1.26, PUB-1.31, PUB-6.13): a link carries no publication
//! flag of its own — its publishedness is its HOME's — so a tuple is visible
//! at guest class iff `readable_guest(document_of(t.addr))`, its home
//! document being published. That is the same test M7's own value-keyed
//! gates apply at link-home identity (lane 3.3b) and the result-set row
//! applies to every link (PUB-6.13). The SLICE (`Active`/`Audit`) is
//! ORTHOGONAL to the class: an `AuditSlice` domain still shows the retracted
//! tuples of READABLE homes, and never a draft's tuples.
//!
//! WHY HERE (PUB-6.28; the owner's placement ruling of 2026-09-06 — the
//! class is threaded from the caller): "a fire's verdict never turns on a
//! document rule 4 hides, and a fire commits byte-identically to a world
//! with no drafts". The verdict is the trigger's as much as the write's, so
//! the class lane 3.3 pinned on the action's home (`FireError::DraftBoundary`)
//! and lane 3.3b on the writer's gates is applied to the LOOK too — in M9,
//! the delegator that holds `guest`. M7 is told nothing.
//!
//! COST (PUB-7.15's shape): one `document_of` (M1 arithmetic, no read) and
//! one predicate call per candidate tuple of the unfiltered read — a rule's
//! domain over a type slice of N tuples costs N home tests, proportional to
//! the unfiltered candidate set, as the read-side filters are. No per-home
//! memo is kept: the context is borrow-scoped to one verdict, the predicate the
//! engine injects is an exception-set membership miss (one hash), and the
//! evaluator carries no interior mutability.
//!
//! THE READS, each answered over the visible slice exactly as M7's own
//! answers it over the whole: `is_k` and `observe` (the two reads the delta
//! names) and, listed as the delta asks, the rest the evaluator makes —
//! `members`, `targets_of` and `targets_of_denoting` (D1/D3 over the visible
//! slice, the last in V-AUD's exact-denotation regime, which is the one read
//! where a PL view changes which tuples match); the BH2 walk
//! family `succs`/`chain`/`tip`/`is_in_chain` (rebuilt over the VISIBLE
//! active `[K_sup]` claims, so a draft-homed claim moves no walk); the BH3
//! pair `sources_to`/`target_of` (the `targets_keyed` join is `EvalCtx`'s,
//! over the catalog's `ReverseLookup` classes, each answered by `target_of`
//! here); and BH4's `is_active_tuple`/`age`/`stale` (dormant in this format,
//! filtered the same way). Signatures mirror M7's so the evaluator's call
//! sites read as before, save that each names the stored [`Slice`] it reads
//! rather than a term view, and that `is_active_tuple` — BH4's totalization
//! premise — is PL's composition of `observe`, M7 offering no such read.

use std::collections::BTreeMap;
use std::slice::from_ref;

use im::OrdSet;
use skep_address::{document_of, Address, Tumbler};
use skep_links::{Endset, HasLinks, LinkState, NotBh4, Pattern, Tip, Tuple, View, Visibility};

use crate::value::lift;

/// Which STORED SLICE a read touches: the active tuples, or the whole audit
/// record. `A_K` and `L_K` — PL's two tuple domains — are its two values, and
/// `Observe_K`'s two selectable slices (§Internal 2).
///
/// DISTINCT from a term's [`View`] (PC3), an evaluation parameter with three
/// values: `default` names no slice — it is the active slice plus M9's UV
/// rewrite over it (`EvalCtx`). [`Slice::of`] is the one statement of that
/// relation. At a DIRECT `LinkState` read — the class-free def probes
/// (`defs.rs`) and the divergence monitor (`engine.rs`) — M9 speaks M7's
/// `View`; inside this read surface, where a term view also circulates, the
/// slice has its own name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Slice {
    Active,
    Audit,
}

impl Slice {
    /// The slice a term at `view` reads: `audit` reads the whole record;
    /// `active` and `default` both read the active tuples — they differ only
    /// by the UV rewrite applied OVER them (`EvalCtx::uv_keeps`), never
    /// by which slice is read. Deliberately not a `From`: the step is lossy,
    /// and naming it is what keeps the two concepts apart.
    pub(crate) fn of(view: View) -> Slice {
        match view {
            View::Audit => Slice::Audit,
            View::Active | View::Default => Slice::Active,
        }
    }
}

/// Widening is total — the one conversion, made where M9 calls M7.
impl From<Slice> for View {
    fn from(s: Slice) -> View {
        match s {
            Slice::Active => View::Active,
            Slice::Audit => View::Audit,
        }
    }
}

/// The visible operative claims as a forward map, `old → {new}` by
/// denotation — built once per walk, so a walk of C steps over C claims
/// costs C map probes, not C scans of the claim set.
type ForwardClaims = BTreeMap<Tumbler, OrdSet<Tumbler>>;

/// One forward walk's result over the visible operative claims.
struct Walk {
    /// The traversed path from the starting node, inclusive of it.
    path: Vec<Tumbler>,
    /// The successor-free node the walk halted at — `None` at a branch or a
    /// cycle, where the head is indeterminate.
    sink: Option<Tumbler>,
}

/// M7's read surface at guest class, over the world of one pinned snapshot.
pub(crate) struct GuestLinks<'a, W> {
    world: &'a W,
    /// M7's own answers, before this module's home filter narrows them — the
    /// side every read below starts from and none of them hands back.
    unfiltered: &'a LinkState,
    guest: &'a Visibility<'a, W>,
}

impl<'a, W> GuestLinks<'a, W> {
    /// Over the world of one pinned snapshot and the guest-class predicate
    /// the coordinator lends (a borrow of the one closure it holds — the same
    /// one every `LinkWriter` it builds runs at). The link slice is taken
    /// FROM that world, so the tuples read and the homes they are filtered by
    /// cannot come from two worlds; the bound sits here alone, the reads
    /// below staying unbounded in `W`.
    pub(crate) fn new(world: &'a W, guest: &'a Visibility<'a, W>) -> GuestLinks<'a, W>
    where
        W: HasLinks,
    {
        GuestLinks { world, unfiltered: world.links(), guest }
    }

    /// The guest-class test, at link-HOME identity — as M7's dedup gate
    /// applies it: `document_of(link)` is address arithmetic (no read), then
    /// the predicate on that home. A stored link key is element-level, so its
    /// home exists; an address with no document is answered `false`
    /// (fail-closed).
    fn home_readable(&self, link: &Address) -> bool {
        document_of(link).is_some_and(|home| (self.guest)(self.world, &home))
    }

    fn admits(&self, t: &Tuple) -> bool {
        self.home_readable(&t.addr)
    }

    /// M7's `observe` over one stored slice, with the tuples of unreadable
    /// homes dropped — the ONE filtering primitive every other read here is
    /// built on (so the guest-class test has one statement), and the ONE
    /// place a slice widens to the `View` M7 names it by.
    pub(crate) fn observe(&self, ty: &Endset, pat: Pattern<'_>, slice: Slice) -> Vec<Tuple> {
        let mut out = self.unfiltered.observe(ty, pat, slice.into());
        out.retain(|t| self.admits(t));
        out
    }

    /// D2 over the visible slice: some visible type-`ty` tuple's F COVERS the
    /// probe. M7's own `is_k` does not expose the witnessing tuple, so the
    /// answer is the home-filtered `observe` at the same coverage pattern —
    /// the two are one predicate on the whole slice. The UV rewrite over the
    /// active read is `EvalCtx`'s own.
    pub(crate) fn is_k(&self, ty: &Endset, probe: &Tumbler, slice: Slice) -> bool {
        !self
            .observe(ty, Pattern { from: from_ref(probe), to: &[] }, slice)
            .is_empty()
    }

    /// The deduplicated denotation of one slot over `tuples`: `⋃
    /// slot(t).addrs()`, in Tumbler order — the shape M7's own equations for
    /// D1, D3, V-AUD's D3 and BH3's reverse all take, so each of those is one
    /// line over its own tuple source and checkable against M7's.
    fn denote_slot(tuples: Vec<Tuple>, slot: fn(&Tuple) -> &Endset) -> Vec<Address> {
        let mut out: OrdSet<Tumbler> = OrdSet::new();
        for t in tuples {
            for a in slot(&t).addrs() {
                out.insert(a.clone());
            }
        }
        out.iter().map(lift).collect()
    }

    /// [`GuestLinks::denote_slot`] over the visible tuples of `slice` matching
    /// `pat` — the COVERAGE-matched reads.
    fn denoted(
        &self,
        ty: &Endset,
        pat: Pattern<'_>,
        slice: Slice,
        slot: fn(&Tuple) -> &Endset,
    ) -> Vec<Address> {
        Self::denote_slot(self.observe(ty, pat, slice), slot)
    }

    /// The visible `slice` tuples whose F DENOTES `x` — `x ∈ F.addrs()`,
    /// V-AUD's exact regime, which M7's `Pattern` cannot express (it matches F
    /// by COVERAGE). A MATCHING REGIME on the source, yielding tuples, where
    /// [`GuestLinks::denote_slot`] and [`GuestLinks::denoted`] are the
    /// denotation fold over one slot, yielding addresses.
    ///
    /// Denotation implies coverage — a denoted address is the start of a
    /// unit-depth span, which covers it — so the coverage pattern is a sound
    /// PRE-FILTER: the scan runs over the covering tuples, not over the whole
    /// slice.
    fn tuples_denoting(&self, ty: &Endset, x: &Address, slice: Slice) -> Vec<Tuple> {
        let mut out = self.observe(ty, Pattern { from: from_ref(x.tumbler()), to: &[] }, slice);
        out.retain(|t| t.from.addrs().any(|f| f == x.tumbler()));
        out
    }

    /// D1 over the visible slice: `⋃ F.addrs()` — M7's own equation.
    pub(crate) fn members(&self, ty: &Endset, slice: Slice) -> Vec<Address> {
        self.denoted(ty, Pattern::default(), slice, |t| &t.from)
    }

    /// D3 over the visible slice: `⋃ G.addrs()` of the tuples whose F COVERS
    /// `x` (M7's own coverage regime for this read).
    pub(crate) fn targets_of(&self, ty: &Endset, x: &Address, slice: Slice) -> Vec<Address> {
        let pat = Pattern { from: from_ref(x.tumbler()), to: &[] };
        self.denoted(ty, pat, slice, |t| &t.to)
    }

    /// V-AUD's audit form of D3 over the visible audit slice: `⋃ G.addrs()` of
    /// the tuples whose F DENOTES `x`, where [`GuestLinks::targets_of`] takes
    /// those whose F COVERS it — the one place a PL view changes WHICH TUPLES
    /// MATCH and not merely which slice is read.
    pub(crate) fn targets_of_denoting(&self, ty: &Endset, x: &Address) -> Vec<Address> {
        Self::denote_slot(self.tuples_denoting(ty, x, Slice::Audit), |t| &t.to)
    }

    // ───────────── BH2 — the walk over the VISIBLE operative claims ─────────────
    //
    // Served for whatever LINK TYPE the caller names: the type checker admits
    // the walk atoms only at the shipped `Supersedes` key (`UnservedWalkClass`
    // otherwise — M7 v1's serving scope), so that question is decided once,
    // at check time, and never re-asked here.

    /// The visible OPERATIVE claim set, indexed forward: the active
    /// `[K_sup]` tuples of readable homes, as `old → {new}`. Edges run
    /// `old → new` by DENOTATION on both slots, exactly as M7's `sup_fwd`
    /// fold keys them; a claim is operative iff unnullified (Df-SUCC), which
    /// the active slice gives. One pass over the claims per walk.
    fn forward_claims(&self, ty: &Endset) -> ForwardClaims {
        let mut fwd = ForwardClaims::new();
        for t in self.observe(ty, Pattern::default(), Slice::Active) {
            for old in t.from.addrs() {
                let succs = fwd.entry(old.clone()).or_default();
                for new in t.to.addrs() {
                    succs.insert(new.clone());
                }
            }
        }
        fwd
    }

    /// `succ_o(x)` over the visible claims — deduplicated over `new`.
    fn succs_operative(fwd: &ForwardClaims, x: &Tumbler) -> OrdSet<Tumbler> {
        fwd.get(x).cloned().unwrap_or_default()
    }

    /// The visited-set-bounded forward walk (M7's own halting rule).
    fn walk_sup(fwd: &ForwardClaims, x: &Tumbler) -> Walk {
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

    /// BH2 forward step over the visible operative claims (Tumbler order).
    pub(crate) fn succs(&self, ty: &Endset, x: &Address) -> Vec<Address> {
        let fwd = self.forward_claims(ty);
        Self::succs_operative(&fwd, x.tumbler()).iter().map(lift).collect()
    }

    /// BH2 chain over the visible operative claims.
    pub(crate) fn chain(&self, ty: &Endset, x: &Address) -> Vec<Address> {
        let fwd = self.forward_claims(ty);
        Self::walk_sup(&fwd, x.tumbler()).path.iter().map(lift).collect()
    }

    /// BH2 head over the visible operative claims: `Sink(head)` at a
    /// successor-free node, `Indeterminate` at a branch or cycle.
    pub(crate) fn tip(&self, ty: &Endset, x: &Address) -> Tip {
        let fwd = self.forward_claims(ty);
        match Self::walk_sup(&fwd, x.tumbler()).sink {
            Some(sink) => Tip::Sink(lift(&sink)),
            None => Tip::Indeterminate,
        }
    }

    /// BH2 chain membership: `target ∈ chain(ty, addr)` — walk-result
    /// membership, never a coverage test.
    pub(crate) fn is_in_chain(&self, ty: &Endset, addr: &Address, target: &Address) -> bool {
        self.chain(ty, addr).contains(target)
    }

    // ────────────────────────── BH3 — over the visible slice ──────────────────────────

    /// BH3 reverse: the F-denoted sources of the visible active type-`ty`
    /// tuples whose G COVERS `target`.
    pub(crate) fn sources_to(&self, ty: &Endset, target: &Address) -> Vec<Address> {
        let pat = Pattern { from: &[], to: from_ref(target.tumbler()) };
        self.denoted(ty, pat, Slice::Active, |t| &t.from)
    }

    /// BH3 forward: ⊥ unless EXACTLY ONE visible active type-`ty` tuple
    /// denotes `source` in F with a single-address-denoting G.
    pub(crate) fn target_of(&self, ty: &Endset, source: &Address) -> Option<Address> {
        let mut matches = self.tuples_denoting(ty, source, Slice::Active).into_iter();
        match (matches.next(), matches.next()) {
            (Some(t), None) => t.to.single_denoted().map(lift),
            _ => None, // no visible active match, or several ⇒ ⊥
        }
    }

    // ────────────────────────── BH4 — over the visible slice ──────────────────────────

    /// Is `a` the address of a VISIBLE ACTIVE type-`ty` tuple? A tuple-IDENTITY
    /// test, not [`GuestLinks::is_k`]'s coverage-of-F membership — the two
    /// reads differ, and BH4's totalization keys on this one ([`GuestLinks::age`]
    /// is untyped, M7's being untyped, so the type-indexing is PL's and the
    /// read is answered here with the rest).
    pub(crate) fn is_active_tuple(&self, ty: &Endset, a: &Address) -> bool {
        self.observe(ty, Pattern::default(), Slice::Active)
            .iter()
            .any(|t| t.addr == *a)
    }

    /// BH4 age: M7's own for a link of a readable home, ⊥ otherwise (a
    /// draft-homed tuple has no age at guest class, as it has no residence).
    pub(crate) fn age(&self, a: &Address) -> Option<u64> {
        if !self.home_readable(a) {
            return None;
        }
        self.unfiltered.age(a)
    }

    /// BH4 stale set: M7's own (its `NotBh4` fence included), with the
    /// tuples of unreadable homes dropped; ascending address order kept.
    pub(crate) fn stale(&self, ty: &Endset, horizon: u64) -> Result<Vec<Address>, NotBh4> {
        let stale = self.unfiltered.stale(ty, horizon)?;
        Ok(stale.into_iter().filter(|a| self.home_readable(a)).collect())
    }
}
