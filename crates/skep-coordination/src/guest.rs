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
//! applies to every link (PUB-6.13). The VIEW (`Active`/`Audit`) is
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
//! domain over a class of N tuples costs N home tests, proportional to the
//! unfiltered candidate set, as the read-side filters are. No per-home memo
//! is kept: the context is borrow-scoped to one verdict, the predicate the
//! engine injects is an exception-set membership miss (one hash), and the
//! evaluator carries no interior mutability.
//!
//! THE READS, each answered over the visible slice exactly as M7's own
//! answers it over the whole: `is_k` and `observe` (the two reads the delta
//! names) and, listed as the delta asks, the rest the evaluator makes —
//! `members`, `targets_of` (D1/D3 over the visible slice); the BH2 walk
//! family `succs`/`chain`/`tip`/`is_in_chain` (rebuilt over the VISIBLE
//! active `[K_sup]` claims, so a draft-homed claim moves no walk); the BH3
//! pair `sources_to`/`target_of` (the `targets_keyed` join is `EvalCtx`'s,
//! over the catalog's BH3 classes, each answered by `target_of` here); and
//! BH4's `age`/`stale` (dormant in this format, filtered the same way).
//! Signatures mirror M7's so the evaluator's call sites read as before.

use std::slice;

use im::OrdSet;
use skep_address::{document_of, Address, Tumbler};
use skep_links::{Endset, LinkState, NotBh4, Pattern, Tip, Tuple, View, Visibility};

use crate::eval::lift;

/// M7's read surface at guest class, over the world of one pinned snapshot.
pub(crate) struct GuestLinks<'a, W> {
    world: &'a W,
    state: &'a LinkState,
    guest: &'a Visibility<'a, W>,
}

impl<'a, W> GuestLinks<'a, W> {
    /// Over the world `w` of one pinned snapshot: its link slice, and the
    /// guest-class predicate the coordinator lends (a borrow of the one
    /// closure it holds — the same one every `LinkWriter` it builds runs at).
    pub(crate) fn new(world: &'a W, state: &'a LinkState, guest: &'a Visibility<'a, W>) -> GuestLinks<'a, W> {
        GuestLinks { world, state, guest }
    }

    /// The class test, at link-HOME identity — as M7's dedup gate applies it:
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

    /// M7's `observe` with the tuples of unreadable homes dropped — the ONE
    /// filtering primitive every other read here is built on (so the class
    /// test has one statement).
    pub(crate) fn observe(&self, ty: &Endset, pat: Pattern<'_>, view: View) -> Vec<Tuple> {
        let mut out = self.state.observe(ty, pat, view);
        out.retain(|t| self.admits(t));
        out
    }

    /// D2 over the visible active slice: some visible active type-`ty`
    /// tuple's F COVERS the probe. M7's own `is_k` does not expose the
    /// witnessing tuple, so the answer is the home-filtered `observe` at the
    /// same coverage pattern — the two are one predicate on the whole slice.
    pub(crate) fn is_k(&self, ty: &Endset, probe: &Tumbler) -> bool {
        !self
            .observe(ty, Pattern { from: slice::from_ref(probe), to: &[] }, View::Active)
            .is_empty()
    }

    /// D1 over the visible slice: `⋃ F.addrs()`, deduplicated, Tumbler order
    /// — M7's own equation, a SLICE read at `Active` or `Audit` (the UV
    /// rewrite is `EvalCtx`'s own per-type filter over the active read, so
    /// `Default` names no slice here and, as at M7's `observe`, reads as
    /// `Active`).
    pub(crate) fn members(&self, ty: &Endset, view: View) -> Vec<Address> {
        let mut out: OrdSet<Tumbler> = OrdSet::new();
        for t in self.observe(ty, Pattern::default(), view) {
            for m in t.from.addrs() {
                out.insert(m.clone());
            }
        }
        out.iter().map(lift).collect()
    }

    /// D3 over the visible slice: `⋃ G.addrs()` of the tuples whose F COVERS
    /// `x`, deduplicated, Tumbler order (M7's own coverage regime for this
    /// read) — a slice read at `Active` or `Audit`, as `members`.
    pub(crate) fn targets_of(&self, ty: &Endset, x: &Address, view: View) -> Vec<Address> {
        let mut out: OrdSet<Tumbler> = OrdSet::new();
        for t in self.observe(ty, Pattern { from: slice::from_ref(x.tumbler()), to: &[] }, view) {
            for g in t.to.addrs() {
                out.insert(g.clone());
            }
        }
        out.iter().map(lift).collect()
    }

    // ───────────── BH2 — the walk over the VISIBLE operative claims ─────────────
    //
    // Served for whatever class the caller names: the type checker admits
    // the walk atoms only at the shipped `Supersedes` key (`UnservedWalkClass`
    // otherwise — M7 v1's serving scope), so the class question is decided
    // once, at check time, and never re-asked here.

    /// The visible OPERATIVE claim set: the active `[K_sup]` tuples of
    /// readable homes. Edges run `old → new` by DENOTATION on both slots,
    /// exactly as M7's `sup_fwd` fold keys them; a claim is operative iff
    /// unnullified (Df-SUCC), which the active view gives.
    fn visible_claims(&self, ty: &Endset) -> Vec<Tuple> {
        self.observe(ty, Pattern::default(), View::Active)
    }

    /// `succ_o(x)` over the visible claims — deduplicated over `new`.
    fn succs_operative(claims: &[Tuple], x: &Tumbler) -> OrdSet<Tumbler> {
        claims
            .iter()
            .filter(|t| t.from.addrs().any(|old| old == x))
            .flat_map(|t| t.to.addrs().cloned())
            .collect()
    }

    /// The visited-set-bounded forward walk (M7's own halting rule): the
    /// traversed path from `x` (inclusive) and `Some(sink)` iff halted at a
    /// successor-free node — a branch or a cycle yields `None`.
    fn walk_sup(claims: &[Tuple], x: &Tumbler) -> (Vec<Tumbler>, Option<Tumbler>) {
        let mut path = vec![x.clone()];
        let mut visited = OrdSet::unit(x.clone());
        let mut node = x.clone();
        loop {
            let succs = Self::succs_operative(claims, &node);
            match succs.len() {
                0 => return (path, Some(node)),
                1 => {
                    let next = succs.iter().next().expect("len == 1").clone();
                    if visited.contains(&next) {
                        return (path, None); // cycle
                    }
                    visited.insert(next.clone());
                    path.push(next.clone());
                    node = next;
                }
                _ => return (path, None), // branch
            }
        }
    }

    /// BH2 forward step over the visible operative claims (Tumbler order).
    pub(crate) fn succs(&self, ty: &Endset, x: &Address) -> Vec<Address> {
        let claims = self.visible_claims(ty);
        Self::succs_operative(&claims, x.tumbler()).iter().map(lift).collect()
    }

    /// BH2 chain over the visible operative claims.
    pub(crate) fn chain(&self, ty: &Endset, x: &Address) -> Vec<Address> {
        let claims = self.visible_claims(ty);
        Self::walk_sup(&claims, x.tumbler()).0.iter().map(lift).collect()
    }

    /// BH2 head over the visible operative claims: `Sink(head)` at a
    /// successor-free node, `Indeterminate` at a branch or cycle.
    pub(crate) fn tip(&self, ty: &Endset, x: &Address) -> Tip {
        let claims = self.visible_claims(ty);
        match Self::walk_sup(&claims, x.tumbler()).1 {
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
    /// tuples whose G COVERS `target`, deduplicated, Tumbler order.
    pub(crate) fn sources_to(&self, ty: &Endset, target: &Address) -> Vec<Address> {
        let mut out: OrdSet<Tumbler> = OrdSet::new();
        for t in self.observe(
            ty,
            Pattern { from: &[], to: slice::from_ref(target.tumbler()) },
            View::Active,
        ) {
            for f in t.from.addrs() {
                out.insert(f.clone());
            }
        }
        out.iter().map(lift).collect()
    }

    /// BH3 forward: ⊥ unless EXACTLY ONE visible active type-`ty` tuple
    /// denotes `source` in F with a single-address-denoting G.
    pub(crate) fn target_of(&self, ty: &Endset, source: &Address) -> Option<Address> {
        let mut survivor: Option<Tuple> = None;
        for t in self.observe(ty, Pattern::default(), View::Active) {
            if t.from.addrs().any(|f| f == source.tumbler()) {
                if survivor.is_some() {
                    return None; // several visible active matches ⇒ ⊥
                }
                survivor = Some(t);
            }
        }
        let survivor = survivor?;
        survivor.to.single_denoted().map(lift)
    }

    // ────────────────────────── BH4 — over the visible slice ──────────────────────────

    /// BH4 age: M7's own for a link of a readable home, ⊥ otherwise (a
    /// draft-homed tuple has no age at guest class, as it has no residence).
    pub(crate) fn age(&self, a: &Address) -> Option<u64> {
        if !self.home_readable(a) {
            return None;
        }
        self.state.age(a)
    }

    /// BH4 stale set: M7's own (its `NotBh4` fence included), with the
    /// tuples of unreadable homes dropped; ascending address order kept.
    pub(crate) fn stale(&self, ty: &Endset, horizon: u64) -> Result<Vec<Address>, NotBh4> {
        let stale = self.state.stale(ty, horizon)?;
        Ok(stale.into_iter().filter(|a| self.home_readable(a)).collect())
    }
}
