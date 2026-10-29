//! The pure read surface on [`LinkState`] (§E/§F/§G).
//!
//! It holds the raw reads (READLINK / FOLLOWLINK), the typed-relation
//! observers (Observe + the default predicates + BH1–BH4), ASN-0125
//! currency, and the discovery primitives for M8: `stab` / `match_links` /
//! `type_slice`, the homes-first pair beneath them — `homes_touching`, the
//! candidate homes a query could meet, and `stab_in`, one home's hits, with
//! `match_links_in` the AND over one home and `stab_in_slots` beside
//! `count_in_slots`, one home's hits at several slots lifted or counted —
//! the home ranges `homes_under` /
//! `homed_in` / `homed_under` and the store's `homes`, and the typed stab
//! `stab_typed` with `stab_typed_in`, one home's share of it. The stabs
//! answer from the spanfilade beside this file, home by home; the home
//! ranges and the type slot's candidate homes come off the map's and the
//! typed slices' own key order. All `&self` over any M2 `Snapshot`; nothing
//! here writes.

use std::collections::BTreeSet;
use std::ops::Bound::{Excluded, Included, Unbounded};
use std::sync::Arc;

use im::OrdSet;
use skep_address::{
    document_of, is_prefix, link_subspace, ordinal, validate, Address, Nat, Span, SpanSet,
    Tumbler,
};

use super::spanfilade::{overlaps, Home, Parts, Stream, Touch, Touching};
use super::{lift, LinkState, TYPE};
use crate::class::{coverage_class, CoverageClass};
use crate::endset::{Endset, Link};
use crate::error::{Invalid, NotBh4};
use crate::registry::{registry, Behavior, ShippedType};

/// A read view (ASN-0128).
///
/// `Default` (active ∖ filtered) is meaningful only on
/// `members`/`targets_of`; on `observe` and the §G index primitives it reads
/// as `Active` (result-side BH1 filtering is undefined for a raw index
/// probe).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    /// Every resident link, nullified or not.
    Audit,
    /// The audit view less every nullified link.
    Active,
    /// Active less filtered results, on `members`/`targets_of`.
    Default,
}

/// The std default is `View::Default`, the module's own default view.
///
/// Written by hand rather than derived; declaration order here is the
/// design's, `Audit` first.
impl Default for View {
    fn default() -> View {
        View::Default
    }
}

/// One observed typed-relation tuple — endsets are M7's readable [`Endset`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tuple {
    /// The tuple's own address.
    pub addr: Address,
    /// Its `FROM` endset, as stored.
    pub from: Endset,
    /// Its `TO` endset, as stored.
    pub to: Endset,
}

/// ASN-0086's pattern pair for [`LinkState::observe`].
///
/// They are the F-side and G-side probes, named so the two same-typed
/// tumbler slices cannot trade places at a call. Each side is an AND of
/// coverage probes; an empty side is no constraint, so `Default` is the
/// unconstrained pattern `(⟨⟩, ⟨⟩)` matching the whole typed slice.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Pattern<'a> {
    /// Tumblers every match's F must cover.
    pub from: &'a [Tumbler],
    /// Tumblers every match's G must cover.
    pub to: &'a [Tumbler],
}

/// The BH2 head: what a supersession walk halts at.
///
/// `Sink` at a successor-free node, `Indeterminate` (⊥) at a branch or cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tip {
    /// The walk halted at this successor-free node.
    Sink(Address),
    /// ⊥ — a branch or a cycle, or a `ty` the walk does not serve.
    Indeterminate,
}

/// One current member (EL14 disclosure-not-decision): an operative sink.
///
/// It carries the sink, its own activity (a member can be a current sink yet
/// itself nullified — EL14e), and `claims` = the full operative `out(sink)` —
/// every operative `[K_sup]` claim whose `new` endpoint is this sink,
/// including one asserted from outside `reach_o(y)`. Homes recoverable by
/// M1's `document_of` (EL8b). The reader applies narrowing; M7 decides
/// nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentMember {
    /// The operative sink.
    pub member: Address,
    /// Whether the sink is itself active.
    pub active: bool,
    /// Every operative claim naming the sink as `new`, by claim address.
    pub claims: Vec<Address>,
}

/// Returns whether `link`'s coverage at `slot` overlaps `query`.
///
/// It is the spanfilade's relation asked of one link — some span of the
/// query [`overlaps`] some span of the slot — and an absent slot matches
/// nothing. [`LinkState::match_links`] narrows by it after its first
/// constraint. The index [`LinkState::stab`] answers from holds every span
/// under the same `overlaps`, and `tests/it/spanfilade.rs` holds the two to
/// agree over every slot, view and query of a world holding every span shape,
/// so the AND cannot answer differently from its own conjuncts.
fn slot_overlaps(link: &Link, slot: usize, query: &Endset) -> bool {
    link.slot(slot)
        .is_some_and(|endset| query.spans().any(|q| endset.spans().any(|s| overlaps(q, s))))
}

/// Lifts a denoted address from `Tumbler` to `Address`.
///
/// Named apart from the store's own [`lift`] so the two families of
/// obligation can be audited separately.
///
/// Consumes its argument: a denoted address is read out of a slot into a set
/// or a path the read owns and is about to drop, so the caller hands it over
/// rather than making `validate` copy its `Vec<Nat>` and every component in
/// it. The one caller still holding a borrow clones at its own site.
///
/// # Panics
///
/// Panics if `t` is not T4-valid, which a denoted address is on either of
/// two grounds. A tumbler read back out of a stored slot rests on the slot's
/// construction: every slot a deposit path builds comes from
/// [`enc`](crate::enc), whose spans start at an `Address`'s tumbler, or from
/// M5's `Run::iextent`, whose start is the run's `i_start` `Address`; an
/// `editlink` successor's slots are its caller's to build, and M10 builds
/// them the same way. A tumbler the walk family hands back may instead be
/// the caller's own argument — `chain` seeds its path with it, `tip` reports
/// a successor-free node as its own sink, and `current` reaches `y` when
/// nothing supersedes it — and there the ground is stronger still: the
/// caller held an `Address`.
fn lift_denoted(t: Tumbler) -> Address {
    validate(t).expect(
        "a denoted address is T4-valid: it is either a slot start (enc or a Run's iextent) \
         or the caller's own argument, echoed back by the walk",
    )
}

/// Returns whether some root is a prefix of the probe — BH1's test.
///
/// It is that test against a root set: prefix-closure over the roots. The
/// one statement of it, so the single-probe read and the result-side
/// subtraction cannot answer differently. The probe ranges over all of
/// carrier T, roots or not.
///
/// On roots denoted out of an `enc`-built endset this reproduces exactly that
/// endset's coverage, which is why the prefix form and a whole-endset `covers`
/// are indistinguishable everywhere the managed surface writes.
fn under_any<'a>(roots: impl IntoIterator<Item = &'a Tumbler>, probe: &Tumbler) -> bool {
    roots.into_iter().any(|root| is_prefix(root, probe))
}

/// Maps `Default` to `Active`, for the surfaces where `Default` is undefined.
fn default_to_active(view: View) -> View {
    match view {
        View::Default => View::Active,
        other => other,
    }
}

/// Returns the home of a key of `links`.
///
/// Every stored key is an element-level address (the hint fold's two
/// `expect`s), so its home Document exists; the `expect` restates that fact
/// where a read reads it back.
fn home_of_key(t: &Tumbler) -> Address {
    document_of(&lift(t)).expect(
        "a stored link key is element-level, so its home Document exists: the hint fold \
         fail-stopped on exactly this",
    )
}

/// The homes a typed slice holds, ascending, one seek apiece.
///
/// A typed slice is in M1's address order and so grouped by home, a link's
/// address being `home · 0 · s_L · n`: each step seeks the first key at or
/// past the cursor, reads that key's home, and moves the cursor past the
/// home's link chain, as [`LinkState::homes_under`] walks the map. The type
/// slot's candidate homes come from here rather than from the directory,
/// whose block holds sibling types a query never names.
struct ClassHomes<'a> {
    slice: &'a OrdSet<Tumbler>,
    cursor: Option<Tumbler>,
}

impl<'a> ClassHomes<'a> {
    /// Opens the walk at `slice`'s first key.
    fn over(slice: &'a OrdSet<Tumbler>) -> ClassHomes<'a> {
        ClassHomes {
            slice,
            cursor: None,
        }
    }
}

impl Iterator for ClassHomes<'_> {
    type Item = Home;

    fn next(&mut self) -> Option<Home> {
        let from = self.cursor.as_ref().map_or(Unbounded, Included);
        let key = self.slice.range((from, Unbounded)).next()?;
        let home = home_of_key(key);
        self.cursor = Some(link_chain_bounds(&home).1);
        Some(Arc::new(home.into()))
    }
}

/// Returns the bounds of `home`'s link chain in the key order of `links`.
///
/// A link's address is `home · 0 · s_L · n`
/// ([`LinkState::next_link_address`]), so in T1 order — lexicographic,
/// prefix-smaller — the home's own links are exactly the keys at or past
/// `home · 0 · s_L` and short of `home · 0 · (s_L + 1)`: the first bound is a
/// prefix of every one of them and of nothing else in the map, and a
/// version member's links, `home · k · 0 · s_L · n` for a `k ≥ 1`, sort past
/// the second. The bounds are carrier tumblers, never addresses: a range is
/// cut at them, nothing is minted.
fn link_chain_bounds(home: &Address) -> (Tumbler, Tumbler) {
    let chain = |last: Nat| {
        Tumbler::new(
            home.tumbler()
                .iter()
                .cloned()
                .chain([Nat::from(0u32), last]),
        )
        .expect("a home's tumbler is nonempty, so the chain's bound is")
    };
    (chain(link_subspace()), chain(link_subspace() + 1u32))
}

impl LinkState {
    // ───────────────────────── §E — raw reads ─────────────────────────

    /// READLINK (ASN-0111): returns `Σ.L(a)` verbatim, or `None` (= ⊥).
    ///
    /// The endsets come back readable, and `None` means absence. Total;
    /// recorded, never resolved; never dereferences covered links (RL4/RL6).
    /// The persistent map is already the positive cache (immutability ⇒ never
    /// stale).
    ///
    /// Borrows out of the snapshot, `get`-shaped, so a caller that only tests
    /// residence or reads one slot pays nothing and a caller that keeps the
    /// value clones at its own site. `link_at` is the crate-internal
    /// infallible twin, for an address that came off an index key rather than
    /// from a caller.
    pub fn readlink(&self, a: &Address) -> Option<&Link> {
        self.links.get(a.tumbler())
    }

    /// FOLLOWLINK (ASN-0114): returns the recorded slot's coverage.
    ///
    /// The coverage comes as a `SpanSet` (the verbatim endset folded — F1/F3
    /// by construction). `Ok(spans)` coverage-exact to `slot`;
    /// `Ok(SpanSet::empty())` = ⟨⟩ (valid-but-empty success). The
    /// Result/Ok-empty shape makes ⟨⟩ ≠ ⊥ unforgeable (F7).
    ///
    /// # Errors
    ///
    /// `Err(Invalid)` = ⊥ (link or slot absent).
    pub fn followlink(&self, a: &Address, slot: usize) -> Result<SpanSet, Invalid> {
        let link = self.links.get(a.tumbler()).ok_or(Invalid)?;
        let endset = link.slot(slot).ok_or(Invalid)?;
        Ok(endset.to_spanset())
    }

    // ─────────────── §F — typed reads & the PL surface ────────────────

    /// Observe (ASN-0086): returns the typed slice's tuples `pattern` matches.
    ///
    /// The match is exact ⊆-coverage over the `view` typed slice — every
    /// [`Pattern`] tumbler covered by the tuple's F (resp. G); an empty
    /// pattern side is no constraint. The pattern domain is all of carrier T
    /// (ASN-0086): membership rides [`Endset::covers`], total on T, so ghost
    /// (unallocated) addresses and the non-T4 tumblers inside a non-unit
    /// span's coverage are honest probes. `Default → Active` (raw Observe
    /// never filters — ASN-0128). Matches come back in ascending
    /// tuple-address order, the typed slice's own.
    ///
    /// # Panics
    ///
    /// `ty`'s precondition is address-denoting (a registered or reserved
    /// type) or `iextent`-built. [`coverage_class`] classifies it, so a
    /// hand-built non-level-uniform `ty` panics naming that precondition
    /// (§Core data model totality).
    pub fn observe(&self, ty: &Endset, pattern: Pattern<'_>, view: View) -> Vec<Tuple> {
        let class = coverage_class(ty);
        let mut out = Vec::new();
        for (t, link) in self.typed_links(&class, view) {
            let f_ok = pattern.from.iter().all(|probe| link.from_slot().covers(probe));
            let g_ok = pattern.to.iter().all(|probe| link.to_slot().covers(probe));
            if f_ok && g_ok {
                out.push(Tuple {
                    addr: lift(t),
                    from: link.from_slot().clone(),
                    to: link.to_slot().clone(),
                });
            }
        }
        out
    }

    /// Returns whether some active type-`ty` tuple's F covers the probe.
    ///
    /// This is ASN-0128 D2: exact active coverage-membership, the probe
    /// ranging over all of carrier T (`observe`'s pattern domain). Never a
    /// `stab` overlap call (an ancestor pattern would over-match) and never
    /// BH1-filtered (BH1 Rewrite scope).
    ///
    /// # Panics
    ///
    /// `ty`'s precondition is address-denoting (a registered or reserved
    /// type) or `iextent`-built. [`coverage_class`] classifies it, so a
    /// hand-built non-level-uniform `ty` panics naming that precondition
    /// (§Core data model totality).
    pub fn is_k(&self, ty: &Endset, probe: &Tumbler) -> bool {
        let class = coverage_class(ty);
        self.typed_links(&class, View::Active)
            .any(|(_, link)| link.from_slot().covers(probe))
    }

    /// Returns the denoted member set of the `view` typed slice.
    ///
    /// This is ASN-0128 D1: `F.addrs()` over the slice, deduplicated, in
    /// Tumbler order. Alone with [`LinkState::targets_of`] it honors
    /// `View::Default` = active ∖ filtered — result-side, lazily, honoring
    /// the `J ≠ K'` exclusion (no self-subtraction when `ty` is the shipped
    /// Retired class).
    ///
    /// # Panics
    ///
    /// `ty`'s precondition is address-denoting (a registered or reserved
    /// type) or `iextent`-built. [`coverage_class`] classifies it, so a
    /// hand-built non-level-uniform `ty` panics naming that precondition
    /// (§Core data model totality).
    pub fn members(&self, ty: &Endset, view: View) -> Vec<Address> {
        let class = coverage_class(ty);
        let members: OrdSet<Tumbler> = self
            .typed_links(&class, view)
            .flat_map(|(_, link)| link.from_slot().addrs().cloned())
            .collect();
        self.subtract_filtered(&class, view, members)
    }

    /// Returns the denoted targets of the tuples whose F covers `x`.
    ///
    /// This is ASN-0128 D3: `G.addrs()`, deduplicated, in Tumbler order;
    /// `View::Default` subtracts filtered results (with the `J ≠ K'`
    /// exclusion, as `members`). The source argument is matched by coverage
    /// here; [`LinkState::target_of`] and the walk family match a source
    /// vertex by denotation instead.
    ///
    /// # Panics
    ///
    /// `ty`'s precondition is address-denoting (a registered or reserved
    /// type) or `iextent`-built. [`coverage_class`] classifies it, so a
    /// hand-built non-level-uniform `ty` panics naming that precondition
    /// (§Core data model totality).
    pub fn targets_of(&self, ty: &Endset, x: &Address, view: View) -> Vec<Address> {
        let class = coverage_class(ty);
        let targets: OrdSet<Tumbler> = self
            .typed_links(&class, view)
            .filter(|(_, link)| link.from_slot().covers(x.tumbler()))
            .flat_map(|(_, link)| link.to_slot().addrs().cloned())
            .collect();
        self.subtract_filtered(&class, view, targets)
    }

    /// Returns whether the tuple at `a` is active: resident and not nullified.
    pub fn is_active(&self, a: &Address) -> bool {
        self.resident(a.tumbler()) && !self.nullified(a.tumbler())
    }

    /// Returns whether `a` is a resident retraction root — the tombstone set.
    ///
    /// The tombstone set is monotone (R3/R6a). Exact membership: `a` is
    /// nullified iff `a` itself is a retraction root, so nullifying a
    /// document or an account address tombstones that address alone and no
    /// link beneath it. The module's other suppression mechanism reads the
    /// opposite way — [`LinkState::is_filtered`] is prefix-closed over BH1's
    /// retired roots — so the two are not interchangeable at a probe.
    pub fn is_nullified(&self, a: &Address) -> bool {
        self.nullified(a.tumbler())
    }

    /// Returns whether the probe falls under BH1's read-filter (§7).
    ///
    /// The filter is `∃ x ∈ addrs(F) : x ≼ probe` over the active shipped
    /// `Retired` slice — some address a retired tuple's F denotes is a prefix
    /// of the probe, computed lazily (the filtered subtree is never
    /// materialized). The probe ranges over all of carrier T: every tumbler
    /// under a denoted retired root is filtered, addresses or not.
    ///
    /// Equal to [`Endset::covers`] on an address-denoting F — a unit-depth
    /// span's coverage is its start's prefix set — hence on every `Retired`
    /// tuple `emit` can build, `emit` forcing `enc({from})`. Strictly narrower
    /// on an F carrying a non-unit-depth span, which the open surface can
    /// deposit and which denotes nothing: such a span contributes no root and
    /// filters nothing, where its coverage is non-empty. Not
    /// [`LinkState::is_k`]'s regime, which is `covers` outright.
    ///
    /// Correct type-less because exactly one BH1 type is registered — the
    /// registry's population is the compiled shipped table and `Retired` is
    /// its one `ReadFilter` (§B).
    pub fn is_filtered(&self, probe: &Tumbler) -> bool {
        under_any(self.retired_roots(), probe)
    }

    /// Returns the operative successors of `x` — BH2's forward step (§5).
    ///
    /// They are `sup_fwd[x]` filtered to claims ∉ nullified — deduplicated,
    /// Tumbler order. v1 serves the walk family only for the shipped
    /// `Supersedes` class (the registry's population is the compiled shipped
    /// table, so no second BH2 declaration exists — §B); any other registered
    /// `ty` yields the empty vec (the service-scope guard).
    ///
    /// # Panics
    ///
    /// `ty`'s precondition is address-denoting (a registered or reserved
    /// type) or `iextent`-built. The walk-scope test classifies it, so a
    /// hand-built non-level-uniform `ty` panics naming that precondition
    /// (§Core data model totality) rather than reading as out-of-scope.
    pub fn succs(&self, ty: &Endset, x: &Address) -> Vec<Address> {
        if !self.serves_walk(ty) {
            return Vec::new();
        }
        self.succs_operative(x.tumbler())
            .into_iter()
            .map(lift_denoted)
            .collect()
    }

    /// Returns the BH2 chain: the walk over operative successors from `x`.
    ///
    /// The walk is bounded and iterative, from `x` (inclusive), halting at
    /// sink (no successor), branch (≥ 2), or cycle (revisit) — the finite
    /// link set is the termination bound. Empty for a registered `ty` other
    /// than `Supersedes` (v1 serving scope, as `succs`).
    ///
    /// # Panics
    ///
    /// `ty`'s precondition is address-denoting (a registered or reserved
    /// type) or `iextent`-built. The walk-scope test classifies it, so a
    /// hand-built non-level-uniform `ty` panics naming that precondition
    /// (§Core data model totality) rather than reading as out-of-scope.
    pub fn chain(&self, ty: &Endset, x: &Address) -> Vec<Address> {
        if !self.serves_walk(ty) {
            return Vec::new();
        }
        let (path, _) = self.walk_sup(x.tumbler());
        path.into_iter().map(lift_denoted).collect()
    }

    /// Returns whether `target` is in `chain(ty, addr)` — BH2 chain membership.
    ///
    /// Membership in the walk's result list, never a coverage test. Inherits
    /// `chain`'s halting rule (branch/cycle truncate the path) and its v1
    /// serving scope — a registered `ty` other than `Supersedes` has an empty
    /// chain, so nothing is a member.
    ///
    /// # Panics
    ///
    /// Panics where [`LinkState::chain`] does: it inherits `chain`'s `ty`
    /// precondition.
    pub fn is_in_chain(&self, ty: &Endset, addr: &Address, target: &Address) -> bool {
        self.chain(ty, addr).contains(target)
    }

    /// Returns the BH2 head of the walk from `x`.
    ///
    /// `Sink(head)` when the walk halts at a successor-free node;
    /// `Indeterminate` (⊥) at a branch or cycle — and for a registered `ty`
    /// other than `Supersedes` (v1 serving scope: no positive head is
    /// fabricated).
    ///
    /// # Panics
    ///
    /// `ty`'s precondition is address-denoting (a registered or reserved
    /// type) or `iextent`-built. The walk-scope test classifies it, so a
    /// hand-built non-level-uniform `ty` panics naming that precondition
    /// (§Core data model totality) rather than reading as out-of-scope.
    pub fn tip(&self, ty: &Endset, x: &Address) -> Tip {
        if !self.serves_walk(ty) {
            return Tip::Indeterminate;
        }
        match self.walk_sup(x.tumbler()).1 {
            Some(sink) => Tip::Sink(lift_denoted(sink)),
            None => Tip::Indeterminate,
        }
    }

    /// Returns the sources of active type-`ty` tuples whose G covers `target`.
    ///
    /// This is BH3's reverse (§7), AM's reverse-lookup rule — the one member
    /// of the family matched by coverage rather than denotation — collecting
    /// each match's `F.addrs()`, deduplicated, in Tumbler order, as
    /// `members`/`targets_of`. The active typed slice is the domain and
    /// `covers` is the whole test.
    ///
    /// # Panics
    ///
    /// `ty`'s precondition is address-denoting (a registered or reserved
    /// type) or `iextent`-built. [`coverage_class`] classifies it, so a
    /// hand-built non-level-uniform `ty` panics naming that precondition
    /// (§Core data model totality).
    pub fn sources_to(&self, ty: &Endset, target: &Address) -> Vec<Address> {
        let class = coverage_class(ty);
        let sources: OrdSet<Tumbler> = self
            .typed_links(&class, View::Active)
            .filter(|(_, link)| link.to_slot().covers(target.tumbler()))
            .flat_map(|(_, link)| link.from_slot().addrs().cloned())
            .collect();
        sources.into_iter().map(lift_denoted).collect()
    }

    /// Returns the single target of `source` — BH3's forward projection (§7).
    ///
    /// It is ⊥ unless exactly one active type-`ty` tuple denotes `source` in F
    /// (denotation match — `source ∈ F.addrs()`, AM's source-vertex rule) with
    /// a single-address-denoting G, whose one address it returns. Restricting
    /// to the active typed slice is what makes "exactly one active K-tuple"
    /// exact.
    ///
    /// # Panics
    ///
    /// `ty`'s precondition is address-denoting (a registered or reserved
    /// type) or `iextent`-built. [`coverage_class`] classifies it, so a
    /// hand-built non-level-uniform `ty` panics naming that precondition
    /// (§Core data model totality).
    pub fn target_of(&self, ty: &Endset, source: &Address) -> Option<Address> {
        self.target_of_class(&coverage_class(ty), source)
    }

    /// Returns [`LinkState::target_of`] across the BH3 join's classes (§7).
    ///
    /// Those classes are the ones the registry's
    /// [`reverse_lookup_classes`](crate::TypeRegistry::reverse_lookup_classes)
    /// names — the registered Binary classes declaring BH3 — each answered
    /// over its own active typed slice and keyed by its class. Which classes
    /// those are is the registry's rule, read here rather than restated; in
    /// this format it names none, so the map is empty for every source.
    pub fn targets_keyed(&self, source: &Address) -> im::HashMap<CoverageClass, Address> {
        let mut out = im::HashMap::new();
        for class in registry().reverse_lookup_classes() {
            if let Some(t) = self.target_of_class(class, source) {
                out.insert(class.clone(), t);
            }
        }
        out
    }

    /// Returns BH4 age (§7): `f_d^Σ − ordinal(a)` at `a`'s own home.
    ///
    /// It answers for a resident link, else `None` — a raw distance back along
    /// the home's allocation chain (`chain_d`, ordinal time, no clock — never
    /// BH2's supersession chain), meaningful as staleness only for an idem⊥
    /// BH4 type (under idem⊤ a renewal dedups to the incumbent and age never
    /// resets — which is exactly why R-C0 forces BH4 ⇒ idem⊥).
    ///
    /// `None` means non-residence and nothing else — an exactness M9 already
    /// builds on.
    ///
    /// # Panics
    ///
    /// Panics if the resident key has no home, if its ordinal is outside
    /// `u64`, or if the ordinal is past its home's frontier. The home and the
    /// ordinal are facts about a key of `links` that this module has already
    /// committed to elsewhere, so each fail-stops rather than answering `None`
    /// and reading as absence.
    pub fn age(&self, a: &Address) -> Option<u64> {
        if !self.resident(a.tumbler()) {
            return None;
        }
        let home = document_of(a).expect(
            "a resident link key is element-level, so its home exists: the hint fold that \
             indexed it fail-stopped on exactly this",
        );
        // A resident link's ordinal counts deposits on its home's chain, and
        // `home_frontier` counts the same deposits in a `u64` — so an ordinal
        // outside `u64` is a frontier that overflowed first, and the field
        // type is the commitment this reads back.
        //
        // The subtraction cannot underflow for the same reason it is exact:
        // the mint allocates at `1 + f_d^Σ` and the fold that indexes the
        // deposit increments that same frontier, in one transaction, so a
        // resident link's ordinal runs `1..=f` and the newest link's is `f`.
        // An ordinal past the frontier is corruption, and fail-stops here
        // rather than reporting 0 — which means "deposited just now", the one
        // wrong answer `stale` would propagate as freshness.
        let ord = u64::try_from(ordinal(a.tumbler()))
            .expect("a link ordinal indexes its home's chain, which `home_frontier` counts in u64");
        Some(self.home_frontier(&home).checked_sub(ord).expect(
            "a resident link's ordinal is at most its home's frontier: the fold that indexed \
             the link incremented that same frontier",
        ))
    }

    /// Returns the active type-`ty` tuples older than `horizon` (BH4, §7).
    ///
    /// This is the stale set, in ascending address order — the active typed
    /// slice's own order — served only where declared. The typed rejection
    /// keeps `Ok(vec![])` a truthful freshness answer (never conflated with
    /// "not a BH4 type") and is the fence: `retract_stale` builds its batch
    /// from this call, so a refusal here is the batch's refusal, and the
    /// nullifier can never be aimed at an idem⊤ class (e.g. mass-nullifying
    /// old `[K_sup]` claims).
    ///
    /// The order is load-bearing, not incidental: `retract_stale` issues one
    /// `nullify` per element in it, and its published guarantee that a batch
    /// halted by a foreign-owned tuple halts at the same point on every
    /// re-run is exactly this determinism.
    ///
    /// # Errors
    ///
    /// `Err(NotBh4)` unless the in-contract `ty` is registered with BH4 (Age).
    ///
    /// # Panics
    ///
    /// `ty`'s precondition is address-denoting (a registered or reserved
    /// type) or `iextent`-built. [`coverage_class`] classifies it before the
    /// BH4 lookup, so a hand-built non-level-uniform `ty` panics naming that
    /// precondition (§Core data model totality) rather than reaching the
    /// typed refusal. It also fail-stops where [`LinkState::age`] does, and on
    /// a typed-slice key that names no resident link.
    pub fn stale(&self, ty: &Endset, horizon: u64) -> Result<Vec<Address>, NotBh4> {
        let class = coverage_class(ty);
        if !registry().declares(&class, Behavior::Age) {
            return Err(NotBh4);
        }
        Ok(self
            .type_slice_class(&class, View::Active)
            .filter_map(|t| {
                let a = lift(t);
                // A typed-slice key is a key of `links`, so `age` is `Some`.
                // `None` there means non-residence and nothing else, which for
                // an index key is corruption — fail-stop rather than read it
                // as freshness and silently shrink the batch `retract_stale`
                // builds from this list.
                let age = self.age(&a).expect(
                    "a typed-slice key names a resident link: the fold indexes only what \
                     it inserts",
                );
                (age > horizon).then_some(a)
            })
            .collect())
    }

    /// Returns the operative sinks reachable from `y` — ASN-0125 currency.
    ///
    /// Currency is EL14, hardwired to `[K_sup]`: the sinks reachable via
    /// `succ_o` (the `reach_o(y)` fixpoint within the finite link set),
    /// returned entire — linear → 1, forked → ≥ 2, mutual-supersession
    /// standoff → 0, all legitimate. Each sink carries its own activity and
    /// the full operative `out(sink)`, read from the inbound claim relation in
    /// one walk for all sinks at once, rather than accumulated during the walk
    /// — accumulation would drop an operative claim asserted on the sink from
    /// outside the closure. M7 discloses; the consumer narrows — no single
    /// "latest" is fabricated.
    ///
    /// Members come back ascending by address, and each member's `claims`
    /// ascending by claim address.
    pub fn current(&self, y: &Address) -> Vec<CurrentMember> {
        let mut reach: OrdSet<Tumbler> = OrdSet::unit(y.tumbler().clone());
        let mut stack = vec![y.tumbler().clone()];
        while let Some(x) = stack.pop() {
            // The successor set is built fresh for this call, so it is
            // consumed: a newly-reached node moves onto the stack rather than
            // being cloned out of a set about to be dropped.
            for succ in self.succs_operative(&x) {
                if !reach.contains(&succ) {
                    reach.insert(succ.clone());
                    stack.push(succ);
                }
            }
        }
        // The sinks, an ordered set as `reach` is — then one walk of the
        // active claim slice for all of them together.
        let sinks: OrdSet<Tumbler> = reach.into_iter().filter(|t| self.is_sink(t)).collect();
        self.out_claims(sinks)
            .into_iter()
            .map(|(t, claims)| {
                let member = lift_denoted(t);
                CurrentMember {
                    active: self.is_active(&member),
                    member,
                    claims,
                }
            })
            .collect()
    }

    /// Returns the format-fixed endset of a shipped class.
    ///
    /// It is for a caller holding the slice: the engine's observe dump names
    /// all five this way. A caller holding the registry itself asks
    /// [`TypeRegistry::reserved_type`](crate::TypeRegistry::reserved_type),
    /// which is public and is where this delegates; the answer is the same
    /// value either way, the registry being the module's format constant.
    pub fn reserved_type(&self, ty: ShippedType) -> &'static Endset {
        registry().reserved_type(ty)
    }

    // ─────────────── §G — discovery primitives for M8 ────────────────

    /// Returns the links whose coverage at `slot` overlaps `query`.
    ///
    /// It is the spanfilade primitive; overlap is
    /// `ProperOverlap | Containment | Equal` — not `Adjacent`. `query` is
    /// M7's readable `Endset` (M8 builds it via `enc`/`Endset::from_spans`).
    /// `view ∈ {Audit, Active}` only (`Default` reads as `Active`).
    ///
    /// **What this costs.** Stated because the query family reaches the wire
    /// and no budget refuses one. The answer comes from the spanfilade, the
    /// per-slot coverage index the hint fold keeps beside `links`
    /// (`state/spanfilade.rs`), never from a walk of the store, and it is
    /// [`homes_touching`](LinkState::homes_touching) composed with
    /// [`stab_in`](LinkState::stab_in): the directory ranges the query opens,
    /// one step per candidate home they name and one lift of each, then the
    /// per-home stab of every candidate over the spans that named it — per
    /// span one range over the home's starts, one lookup per prefix of the
    /// span's start and one range per level of each of those prefixes that
    /// is an axis, then one step per stored span the query overlaps, and an
    /// overlap test of each stored span the index holds for the home as
    /// residue, spans no deposit path the wire reaches stores. The store's
    /// size enters only as the logarithm inside each range. The query is the
    /// caller's: its span count, which skepd's codec, M10's production
    /// `Codec`, caps at [`MAX_SLOT_SPANS`](crate::MAX_SLOT_SPANS), and the
    /// depth of its starts, which sets the prefixes probed. The hits are the
    /// store's: a query over a widely linked region answers every link that
    /// reaches it, one lift apiece. A caller reading for a reader composes
    /// the two primitives itself, asking its predicate of each candidate home
    /// between them, and pays nothing of a home it leaves unstabbed.
    ///
    /// Every returned address is a key of `links`, so [`LinkState::readlink`]
    /// on it is `Some`; the set is in M1's address order (T1), which is the
    /// permanent enumeration key a cursor resumes from.
    pub fn stab(&self, slot: usize, query: &Endset, view: View) -> OrdSet<Address> {
        self.homes_touching([(slot, query)])
            .flat_map(|touch| self.stab_in(touch.home(), slot, touch.spans(0), view))
            .collect()
    }

    /// Returns the links that satisfy every per-slot overlap constraint.
    ///
    /// It is the AND-of-(per-slot overlap) combiner — findlinks' core,
    /// factored into M7 (Conflicts §6). `constraints` lists only constrained
    /// slots — an unconstrained slot is omitted, never an empty `Endset`
    /// (`stab(slot, ⟨⟩, ·) = ∅` would empty the AND); empty `constraints` ⇒
    /// the whole `view` slice. `view ∈ {Audit, Active}` only (`Default` reads
    /// as `Active`).
    ///
    /// The first constraint is answered by [`stab`](LinkState::stab) from the
    /// spanfilade; every later one narrows that answer link by link, testing
    /// each survivor's slot under the same overlap relation, rather than
    /// probing the index again and intersecting afterwards. The index and the
    /// per-link test answer by one relation, and `tests/it/spanfilade.rs`
    /// holds them to agree, so the AND cannot come apart from its own
    /// conjuncts — and a caller's constraint count multiplies the surviving
    /// set instead of the store, which matters because the query is
    /// caller-supplied and the constraint count with it.
    ///
    /// It carries [`stab`](LinkState::stab)'s cost for the constraint that
    /// drives and `|query spans| × |slot spans|` per survivor for each other
    /// one. Which constraint drives is a cost decision and never a semantic
    /// one, and it is this combiner's: the constraint with the fewest
    /// candidate homes ([`LinkState::fewest_homes`]), so the caller's order
    /// decides only a tie. A caller reading for a reader composes
    /// [`LinkState::match_links_in`] over the homes it admits instead of
    /// calling this, choosing its driver by the same rule. The unconstrained
    /// branch is the one store walk left: with no constraint to answer from
    /// the index, every link the view admits is lifted into the returned set,
    /// one `Tumbler` clone apiece, before any caller-side filter or window
    /// applies. That branch is reachable from a descriptor constraining
    /// nothing — the all-`"any"` query — so such a request materializes an
    /// address per link in the store; a caller reading for a reader walks
    /// [`LinkState::homes`] and [`LinkState::homed_in`] instead, and a
    /// descriptor constraining the home alone is a different read, `homed_in`
    /// over each home's own key range, since `home` is not a link slot and
    /// this combiner never sees it.
    ///
    /// Each query is borrowed, as [`stab`](LinkState::stab) borrows its own:
    /// a constraint is read and dropped, never kept, so a caller assembling
    /// its list out of a request it already holds hands over references
    /// rather than a copy per constrained slot.
    ///
    /// Every returned address is a key of `links`, so [`LinkState::readlink`]
    /// on it is `Some`; the set is in M1's address order (T1), which is the
    /// permanent enumeration key a cursor resumes from.
    pub fn match_links(&self, constraints: &[(usize, &Endset)], view: View) -> OrdSet<Address> {
        if constraints.is_empty() {
            return self.scan(view); // no constraint: the whole view slice
        }
        let driver = self.fewest_homes(constraints);
        let (slot, query) = constraints[driver];
        let mut acc = self.stab(slot, query, view);
        for (i, &(slot, query)) in constraints.iter().enumerate() {
            if i == driver {
                continue;
            }
            // Consumed, not read: the accumulator is this call's own and only
            // shrinks, so a survivor moves into the next round rather than
            // being deep-copied out of the last one — a caller's constraint
            // count is otherwise a per-address copy count.
            acc = acc
                .into_iter()
                .filter(|a| slot_overlaps(self.link_at(a.tumbler()), slot, query))
                .collect();
        }
        acc
    }

    /// Returns the index of the constraint with the fewest candidate homes —
    /// the one a conjunctive read should drive from.
    ///
    /// [`homes_touching`](LinkState::homes_touching) walks a constraint's
    /// candidate homes lazily, so the walks are stepped in lockstep, one home
    /// from each in turn, and the first to run out has the fewest: a bounded
    /// walk of directory entries, never of links, costing at most the
    /// constraint count times the smallest home count plus one. Ties fall to
    /// the earliest constraint. The cheapest constraint drives because a
    /// conjunction stabs the driver's homes and tests the rest on every
    /// survivor, so the constraint with the fewest homes costs the fewest
    /// home tests, stabs and survivors; an AND is order-free, so the choice
    /// moves work and never the answer. [`match_links`](LinkState::match_links)
    /// chooses by it, and so does a caller composing
    /// [`LinkState::match_links_in`] home by home. A list of one constraint
    /// answers `0` without a walk.
    pub fn fewest_homes(&self, constraints: &[(usize, &Endset)]) -> usize {
        if constraints.len() < 2 {
            return 0;
        }
        let mut walks: Vec<_> = constraints
            .iter()
            .map(|&(slot, e)| self.homes_touching([(slot, e)]))
            .collect();
        loop {
            for (i, walk) in walks.iter_mut().enumerate() {
                if walk.next().is_none() {
                    return i;
                }
            }
        }
    }

    /// Returns the typed slice: `L_K` (Audit) or `A_K` (Active).
    ///
    /// `view ∈ {Audit, Active}` only (`Default` reads as `Active`).
    ///
    /// Every returned address is a key of `links`, so [`LinkState::readlink`]
    /// on it is `Some`; the set is in M1's address order (T1), which is the
    /// permanent enumeration key a cursor resumes from.
    ///
    /// # Panics
    ///
    /// `ty`'s precondition is address-denoting (a registered or reserved
    /// type) or `iextent`-built. [`coverage_class`] classifies it, so a
    /// hand-built non-level-uniform `ty` panics naming that precondition
    /// (§Core data model totality).
    pub fn type_slice(&self, ty: &Endset, view: View) -> OrdSet<Address> {
        let class = coverage_class(ty);
        self.type_slice_class(&class, view).map(lift).collect()
    }

    /// Returns the homes holding a link whose address `home` covers.
    ///
    /// They are the documents — version members among them, a member being a
    /// home exactly as its document is — under which some resident link,
    /// nullified or not, is homed, and which some span of `home` contains:
    /// the homes a four-set's `home` slot admits (ASN-0121's `athome`, asked
    /// of each home once rather than of each link), in M1's address order,
    /// each once however many spans cover it. A span at an account or at the
    /// node names every such home under it; a span beneath a document names
    /// none, since it contains no home.
    ///
    /// **What this costs.** One seek per home found and one per span, never a
    /// step per link. A link's address is `home · 0 · s_L · n`
    /// (`LinkState::next_link_address`), so in T1 order a home's links are
    /// one key range of `links` and the keys' homes ascend with the keys:
    /// per span the walk seeks the first key at or past the span's start,
    /// reads that key's home, and seeks again past the home's link chain —
    /// `O(log n)` apiece — until the home it reaches lies at or past the
    /// span's reach, which no later key's home can precede. A span at a
    /// document or a member costs one seek and finds one home; at an account,
    /// one per document under it that holds links; at the node, one per such
    /// home on the board. The store's size enters only as the logarithm
    /// inside each seek. `tests/it/discovery.rs` holds this to answer exactly
    /// the homes a scan of the store filtered by coverage of each key's home
    /// would.
    pub fn homes_under(&self, home: &Endset) -> OrdSet<Address> {
        let mut homes = OrdSet::new();
        for span in home.spans() {
            let (start, reach) = (span.start(), span.reach());
            let mut cursor = start.clone();
            while let Some((key, _)) = self.links.range((Included(&cursor), Unbounded)).next() {
                let at = home_of_key(key);
                if *at.tumbler() >= reach {
                    break; // every later key is homed at or past this one
                }
                if *at.tumbler() >= *start {
                    homes.insert(at.clone());
                }
                cursor = link_chain_bounds(&at).1;
            }
        }
        homes
    }

    /// Returns `home`'s own links that satisfy every per-slot overlap
    /// constraint.
    ///
    /// They are the links homed in `home` itself — its link chain
    /// `home · 0 · s_L · n`, never its members', which are homes of their
    /// own — that `view` admits and whose every constrained slot overlaps its
    /// constraint, under the relation [`LinkState::match_links`] tests its
    /// later constraints by. `constraints` lists only constrained slots, as
    /// `match_links` takes them, and an empty list is the home's whole
    /// `view` slice. `view ∈ {Audit, Active}` only (`Default` reads as
    /// `Active`). In M1's address order, as every §G result is.
    ///
    /// **What this costs.** One range over `links` — the home's own key
    /// range, which a link's address shape makes contiguous — and, per link in
    /// it, the view's membership test and `|query spans| × |slot spans|` per
    /// constraint; never a probe of the index and never a step outside the
    /// home. With [`LinkState::homes_under`] it is the home-first read of a
    /// four-set whose `home` slot is constrained (M8's descriptor family;
    /// PUB-7.18): the caller asks its reader of each home once, ahead of this
    /// range, and skips the range of a home it may not read, so an unreadable
    /// home costs one test whatever it holds, and a readable one costs its own
    /// links and no other home's.
    ///
    /// # Panics
    ///
    /// Panics if `home` is not a document address — the caller's bug, since a
    /// home is one [`LinkState::homes_under`] answered or M1's `document_of`
    /// of a link; an account or an element here would name a key range that
    /// is no home's chain, and an answer off it would read as that home's
    /// links.
    pub fn homed_in(
        &self,
        home: &Address,
        constraints: &[(usize, &Endset)],
        view: View,
    ) -> OrdSet<Address> {
        assert!(
            document_of(home).as_ref() == Some(home),
            "homed_in: `home` is a document address — one `homes_under` answered"
        );
        let active = default_to_active(view) == View::Active;
        let (lo, hi) = link_chain_bounds(home);
        self.links
            .range((Included(&lo), Excluded(&hi)))
            .filter(|(t, _)| !(active && self.nullified(t)))
            .filter(|(_, link)| {
                constraints
                    .iter()
                    .all(|&(slot, query)| slot_overlaps(link, slot, query))
            })
            .map(|(t, _)| lift(t))
            .collect()
    }

    /// Returns the links homed where `home` covers — the home slot's clause of
    /// a four-set, answered for every home at once.
    ///
    /// It is [`LinkState::homes_under`] composed with
    /// [`LinkState::homed_in`] under no link-slot constraint: the links whose
    /// home some span of `home` contains and `view` admits, in M1's address
    /// order — which is the order of the homes with each home's chain inside
    /// it, so the ranges concatenate and nothing is merged. Exactly what a
    /// walk of the store filtered by coverage of each key's home would
    /// answer, at the cost of the covered homes' seeks and their links alone;
    /// `tests/it/discovery.rs` holds the two to agree. A caller that reads
    /// for a reader composes the two primitives itself, asking its predicate
    /// of each home between them.
    pub fn homed_under(&self, home: &Endset, view: View) -> OrdSet<Address> {
        self.homes_under(home)
            .iter()
            .fold(OrdSet::new(), |acc, at| acc.union(self.homed_in(at, &[], view)))
    }

    /// Returns every home holding a resident link, nullified or not, in M1's
    /// address order.
    ///
    /// It is [`LinkState::homes_under`] over the whole map: one seek per
    /// home found, never a step per link, so the store's homes cost their
    /// count and the logarithm inside each seek. With [`LinkState::homed_in`]
    /// it is the home-first read of a four-set constraining no slot at all —
    /// the all-`"any"` query — which a caller reading for a reader answers
    /// home by home, asking its predicate of each once and reading the
    /// readable ones' chains, rather than through
    /// [`match_links`](LinkState::match_links)' walk of the whole slice.
    pub fn homes(&self) -> OrdSet<Address> {
        let mut homes = OrdSet::new();
        let mut cursor: Option<Tumbler> = None;
        loop {
            let from = cursor.as_ref().map_or(Unbounded, Included);
            let Some((key, _)) = self.links.range((from, Unbounded)).next() else {
                return homes;
            };
            let at = home_of_key(key);
            cursor = Some(link_chain_bounds(&at).1);
            homes.insert(at);
        }
    }

    /// Returns the candidate homes of a list of `(slot, query)` pairs: every
    /// home holding a link whose `slot` could overlap `query` under some
    /// pair, in M1's address order, each once, lazily, with the spans of
    /// each query that could meet it.
    ///
    /// It is the first of the homes-first pair [`stab`](LinkState::stab) is
    /// composed from; [`stab_in`](LinkState::stab_in) is the second. The
    /// answer is a superset of the homes of the hits: a home some filing of
    /// which the directory names for the query — one with a run starting in
    /// a block the query's coordinates cross on its axis, or filed at a node
    /// of the axis index the query's start meets, or holding a span the
    /// index tests whole — and, at [`TYPE`] with an address-denoting query,
    /// every home holding a link of a class the query's addresses stand in
    /// the prefix relation with (the named types, the subtypes beneath them
    /// and the wider types above), a class denoting no address counted
    /// whole. A home named for a query may yet hold no hit of it: the
    /// directory answers at block and node grain, and [`Touch::spans`] names
    /// the spans whose ranges reached the home, which the per-home stab
    /// probes and no other. The touch carries, beside each span, the parts of
    /// the stab its ranges stand for — the starting half, the containing half,
    /// the residue test — and [`stab_in_slots`](LinkState::stab_in_slots)
    /// probes the span at those parts alone.
    ///
    /// **What this costs.** The ranges the queries open — per span, one per
    /// block its coordinates cross on each axis holding a start inside it
    /// and one per `(axis, level, node)` the containing probe set visits;
    /// per typed slice in the relation, one seek per home it holds — and
    /// then one step per directory entry stepped and one lift per home
    /// yielded, the entries of one home across its ranges drained together.
    /// Lazy: a caller that stops early steps no entry past the homes it
    /// took, so a window pays for the homes it passes and a caller choosing
    /// which of two queries to drive walks both until the first exhausts.
    /// Never a step per link. `tests/it/discovery.rs` holds the walk to
    /// name every home of every hit, once, ascending.
    pub fn homes_touching<'q>(
        &'q self,
        queries: impl IntoIterator<Item = (usize, &'q Endset)>,
    ) -> impl Iterator<Item = Touch<'q>> + 'q {
        let queries: Vec<(usize, &'q Endset)> = queries.into_iter().collect();
        let spans: Vec<Vec<&'q Span>> = queries.iter().map(|(_, q)| q.spans().collect()).collect();
        let mut streams = Vec::new();
        for (pair, &(slot, query)) in queries.iter().enumerate() {
            if slot == TYPE && query.is_address_denoting() {
                for slice in self.related_slices(query) {
                    streams.push(Stream::new(pair, None, Parts::ALL, ClassHomes::over(slice)));
                }
                continue;
            }
            let Some(index) = self.hints.spanfilade.slot(slot) else {
                continue;
            };
            for (i, span) in spans[pair].iter().enumerate() {
                index.streams(span, pair, i, &mut streams);
            }
            streams.extend(index.residue_stream(pair));
        }
        Touching::open(spans, streams)
    }

    /// Returns the links homed in `home` whose `slot` overlaps some span of
    /// `query`, under `view`.
    ///
    /// It is the stab of one home — [`stab`](LinkState::stab) within `home`'s
    /// keys alone — and the second of the homes-first pair: the same two
    /// halves and residue test, each range bound prefixed with the home, so
    /// it costs `O(log n)` per probe plus the home's hits and nothing of any
    /// other home's. `query` is any span sequence — the whole of a query's
    /// spans, or the ones [`Touch::spans`] names for the home, which answer
    /// the same hits for less. A home no link is filed under answers none
    /// at no cost. `view ∈ {Audit, Active}` only (`Default` reads as
    /// `Active`).
    ///
    /// Every returned address is a key of `links`, so [`LinkState::readlink`]
    /// on it is `Some`; the set is in M1's address order, and since a link's
    /// address is `home · 0 · s_L · n` the sets of two homes never interleave:
    /// the answers of the homes [`LinkState::homes_touching`] yields,
    /// concatenated in its order, are one address-ordered sequence, which is
    /// what lets a caller read home by home with no merge and resume a window
    /// in the cursor's home. `tests/it/discovery.rs` holds that over every
    /// address shape the mint produces.
    pub fn stab_in<'s>(
        &self,
        home: &Address,
        slot: usize,
        query: impl IntoIterator<Item = &'s Span>,
        view: View,
    ) -> OrdSet<Address> {
        let active = default_to_active(view) == View::Active;
        self.stab_keys_in(home, slot, query)
            .into_iter()
            .filter(|t| !(active && self.nullified(t)))
            .map(lift)
            .collect()
    }

    /// Returns the links homed in a touch's home whose slot overlaps a span
    /// the walk named the home for at that slot — one home's stabs at
    /// several slots, answered together.
    ///
    /// `touch` is one the walk [`homes_touching`](LinkState::homes_touching)
    /// yielded, and `probes` are `(slot, query)` pairs: at slot `slot`, the
    /// spans [`Touch::spans`] names for the home at the walk's pair `query`,
    /// each probed at the parts of the stab — the starting half, the
    /// containing half, the residue test — whose directory ranges named the
    /// home for it. A part no range of which named the home finds none of its
    /// links for the span, so the answer at a slot is the one
    /// [`stab_in`](LinkState::stab_in) gives over those spans. The answer is
    /// `(link, slot)` pairs in M1's address order and then slot order, one for
    /// every slot at which some named span overlaps the link — so a caller
    /// after the disjunction over slots (ASN-0127's `findlinks`) reads the
    /// distinct links, and one after slot attribution (RETRIEVEENDSETS) reads
    /// the pairs. A slot no filed link has, a query that named the home by no
    /// span, and a slot given no probe contribute none. `view ∈ {Audit,
    /// Active}` only (`Default` reads as `Active`).
    ///
    /// **Precondition.** `touch` was yielded by this state's
    /// `homes_touching`, and each probe's `query` is the index of the walk's
    /// pair whose query was asked of its `slot`. A probe breaking it does not
    /// panic: it answers what the named spans find at the named parts of that
    /// slot, which may miss hits.
    ///
    /// **What this costs.** No lookup of the home — the touch holds it as the
    /// index does — each named `(slot, span)` probed at the parts that named
    /// it alone, one sort of the hits and one lift per distinct link; no set
    /// built per slot, so a home that holds no hit costs the parts that named
    /// it and allocates nothing for its answer (PUB-7.18: the readable homes'
    /// links, and not a price per readable home).
    ///
    /// Every returned address is a key of `links`, so [`LinkState::readlink`]
    /// on it is `Some`. The pairs of two homes never interleave, as
    /// `stab_in`'s sets do not, so the answers of the homes `homes_touching`
    /// yields, concatenated in its order, are one address-ordered sequence.
    /// `tests/it/discovery.rs` holds this to the per-slot `stab_in`s over
    /// every slot, query and view of a world holding every address shape, and
    /// `tests/it/spanfilade.rs` holds a reader's walk through it to a scan of
    /// the store.
    ///
    /// # Panics
    ///
    /// Panics in a debug build where two links of the home differ in length,
    /// which no mint produces: a home's links are `home · 0 · s_L · n`.
    pub fn stab_in_slots(
        &self,
        touch: &Touch<'_>,
        probes: impl IntoIterator<Item = (usize, usize)>,
        view: View,
    ) -> Vec<(Address, usize)> {
        let active = default_to_active(view) == View::Active;
        let hits = self.keys_in_slots(touch, probes);
        let mut out: Vec<(Address, usize)> = Vec::with_capacity(hits.len());
        for (t, slot) in hits {
            if active && self.nullified(t) {
                continue;
            }
            // Lifted once per distinct link: a link touching at a second slot
            // follows its first pair directly.
            let address = match out.last() {
                Some((a, _)) if a.tumbler() == t => a.clone(),
                _ => lift(t),
            };
            out.push((address, slot));
        }
        out
    }

    /// Returns how many links homed in a touch's home have a slot
    /// overlapping a span the walk named the home for at that slot — the
    /// distinct links of [`stab_in_slots`](LinkState::stab_in_slots)' pairs,
    /// counted and never lifted.
    ///
    /// It is the count by home that lifts no link (the link-sets design
    /// §7, W10 (a)): `touch` and `probes` are what `stab_in_slots` takes,
    /// the same spans probed at the same parts, the hits sorted and held
    /// once per `(link, slot)` pair, then once per LINK — a link touching at
    /// two slots counts once, ASN-0127's disjunction over slots — and a
    /// nullified link dropped under `View::Active`. So for every touch,
    /// under either view, this is the number of distinct addresses among
    /// `stab_in_slots`' pairs, which `tests/it/discovery.rs` holds; and the
    /// pairs' precondition is this count's.
    ///
    /// **What this costs.** `stab_in_slots`' probes and sort and nothing
    /// after them: no `Address` is made and no vector of them grows, so a
    /// home's count costs its hits' keys as references and the one vector
    /// that holds them, which a home of ten thousand hits pays as its stab
    /// pays it less ten thousand lifts (PUB-7.18: the readable homes' links,
    /// never a price per link beyond the index's own step). A caller that
    /// wants a number per home and no link — the region family's count by
    /// home — composes this over
    /// [`homes_touching`](LinkState::homes_touching), asking its predicate
    /// of each candidate home between them, and stops at a budget of its
    /// own, so an unreadable or a passed home costs the walk's step and
    /// nothing of its links.
    pub fn count_in_slots(
        &self,
        touch: &Touch<'_>,
        probes: impl IntoIterator<Item = (usize, usize)>,
        view: View,
    ) -> usize {
        let active = default_to_active(view) == View::Active;
        let mut hits = self.keys_in_slots(touch, probes);
        // The pairs of one link are adjacent, so the second slot of a link
        // follows its first: kept once per key.
        hits.dedup_by(|later, earlier| later.0 == earlier.0);
        hits.into_iter().filter(|(t, _)| !(active && self.nullified(t))).count()
    }

    /// Returns the links homed in `home` that satisfy every per-slot overlap
    /// constraint: `driver` by [`stab_in`](LinkState::stab_in), the `rest`
    /// narrowing its hits link by link.
    ///
    /// It is [`match_links`](LinkState::match_links) over one home, for a
    /// caller composing the AND home by home: `driver` is the constraint
    /// that stabs — its slot and the spans to probe, which are the ones
    /// [`Touch::spans`] names where the caller enumerated the home through
    /// [`LinkState::homes_touching`] on that constraint — and each of `rest`
    /// is tested on every survivor under the same overlap, at
    /// `|query spans| × |slot spans|` apiece, as `match_links` tests its
    /// later constraints. `rest` lists only constrained slots, never an empty
    /// endset; `view ∈ {Audit, Active}` only (`Default` reads as `Active`).
    /// In M1's address order, as every §G result is.
    pub fn match_links_in<'s>(
        &self,
        home: &Address,
        driver: (usize, impl IntoIterator<Item = &'s Span>),
        rest: &[(usize, &Endset)],
        view: View,
    ) -> OrdSet<Address> {
        let (slot, spans) = driver;
        let mut acc = self.stab_in(home, slot, spans, view);
        for &(slot, query) in rest {
            acc = acc
                .into_iter()
                .filter(|a| slot_overlaps(self.link_at(a.tumbler()), slot, query))
                .collect();
        }
        acc
    }

    /// Returns the `ty`-typed tuples whose `slot` overlaps `query`.
    ///
    /// It is Observe answered from the index: [`stab`](LinkState::stab)'s
    /// hits restricted to the typed slice `ty` names, each as the [`Tuple`]
    /// [`LinkState::observe`] hands over, in ascending tuple-address order.
    /// It is [`homes_touching`](LinkState::homes_touching) composed with
    /// [`stab_typed_in`](LinkState::stab_typed_in), as `stab` is composed
    /// with [`stab_in`](LinkState::stab_in), the type classified once. The
    /// relation is the index's overlap, not `observe`'s coverage of a probe:
    /// a probe `p` asked as the unit query `enc([p])` reaches every tuple
    /// whose slot covers `p` and, beside them, the tuples whose slot starts
    /// strictly inside `p`'s subtree, which a reader after coverage drops by a
    /// test of its own. `view ∈ {Audit, Active}` only (`Default` reads as
    /// `Active`).
    ///
    /// **What this costs.** The stab's probes and hits — the directory
    /// ranges the query opens and a step per candidate home, then a step per
    /// link whose `slot` overlaps the query, whatever its type — then one
    /// slice-membership test per hit, and a lift and two endset clones per
    /// member; never a walk of the class, which `observe` pays for every
    /// probe. A type no link was ever deposited under answers none without
    /// the walk. `tests/it/discovery.rs` holds it to the stab cut to the
    /// slice and to `observe`'s own answer after the reader's coverage test.
    ///
    /// # Panics
    ///
    /// `ty`'s precondition is address-denoting (a registered or reserved
    /// type) or `iextent`-built. [`coverage_class`] classifies it, so a
    /// hand-built non-level-uniform `ty` panics naming that precondition
    /// (§Core data model totality).
    pub fn stab_typed(&self, ty: &Endset, slot: usize, query: &Endset, view: View) -> Vec<Tuple> {
        let Some(slice) = self.hints.type_slices.get(&coverage_class(ty)) else {
            return Vec::new(); // no link of the type is filed
        };
        self.homes_touching([(slot, query)])
            .flat_map(|touch| {
                self.stab_typed_in_slice(slice, touch.home(), slot, touch.spans(0), view)
            })
            .collect()
    }

    /// Returns the typed stab of one home: `class`'s tuples homed in `home`.
    ///
    /// They are the tuples whose `slot` overlaps some span of `query` —
    /// [`stab_typed`](LinkState::stab_typed) within `home`'s keys alone, as
    /// [`stab_in`](LinkState::stab_in) is [`stab`](LinkState::stab) within
    /// them: the home's hits at `slot` that the class's typed slice holds,
    /// each as the [`Tuple`] [`LinkState::observe`] hands over, in ascending
    /// tuple-address order. `query` is any span sequence — the whole of a
    /// query's spans, or the ones [`Touch::spans`] names for the home, which
    /// answer the same hits for less. A home holding no link of the class
    /// answers none, and so does every home for a class no link was ever
    /// deposited under. `view ∈ {Audit, Active}` only (`Default` reads as
    /// `Active`).
    ///
    /// Keyed by class rather than by endset, so a caller composing it over
    /// many homes classifies its type once — by [`coverage_class`], or off
    /// [`TypeRegistry::shipped_class`](crate::TypeRegistry::shipped_class)
    /// for a shipped type — and not once a home.
    ///
    /// **What this costs.** `stab_in`'s probes of the home, then one
    /// slice-membership test per hit before anything is lifted, and a lift
    /// and two endset clones per member; nothing of any other home. A
    /// reader composes it over [`homes_touching`](LinkState::homes_touching),
    /// asking its predicate of each candidate home between them, so a home it
    /// may not read costs the walk's step and nothing of its links
    /// (PUB-7.18) — M8's lineage pair does, at a link's unit span.
    /// `tests/it/discovery.rs` holds each home's share to the stab cut to the
    /// slice and to the home, and the shares concatenated to
    /// [`stab_typed`](LinkState::stab_typed).
    pub fn stab_typed_in<'s>(
        &self,
        class: &CoverageClass,
        home: &Address,
        slot: usize,
        query: impl IntoIterator<Item = &'s Span>,
        view: View,
    ) -> Vec<Tuple> {
        match self.hints.type_slices.get(class) {
            Some(slice) => self.stab_typed_in_slice(slice, home, slot, query, view),
            None => Vec::new(), // no link of the class is filed
        }
    }

    // ───────────────────────── internal helpers ─────────────────────────

    /// Returns the keys a stab of one home finds, ascending, in every view.
    ///
    /// They are the keys of the links homed in `home` whose `slot` overlaps
    /// some span of `query`: the one walk of a home's share of the index,
    /// which [`LinkState::stab_in`] lifts under its view and the typed stabs
    /// test against their slice before they lift one. Each span of `query`
    /// is stabbed within the home's keys, and a link found by two spans or
    /// by both halves is held once. A home no link is filed under, and a
    /// slot no filed link has, answer none at no cost.
    fn stab_keys_in<'a, 's>(
        &'a self,
        home: &Address,
        slot: usize,
        query: impl IntoIterator<Item = &'s Span>,
    ) -> BTreeSet<&'a Tumbler> {
        let mut keys = BTreeSet::new();
        if let (Some(home), Some(index)) = (
            self.hints.spanfilade.home(home.tumbler()),
            self.hints.spanfilade.slot(slot),
        ) {
            for q in query {
                index.stab_in(home, q, &mut |link| {
                    keys.insert(link);
                });
            }
        }
        keys
    }

    /// Returns the `(key, slot)` pairs a stab of one home finds at several
    /// slots, ascending, in every view.
    ///
    /// They are the raw hits of [`LinkState::stab_in_slots`]' probes —
    /// `touch` and `probes` as that read takes them, each named `(slot,
    /// span)` probed at the parts that named the home — sorted in M1's
    /// address order and then slot order and held once per pair: the one
    /// walk of a home's share of the index at several slots, which
    /// `stab_in_slots` lifts under its view and
    /// [`LinkState::count_in_slots`] counts by key, neither lifting here. A
    /// link reached by two spans, or by both halves, of one slot is handed
    /// over twice; sorted, the repeats are adjacent. The home's links are
    /// `home · 0 · s_L · n` (`LinkState::next_link_address`), one length
    /// under one prefix, so their address order is their ordinals' and the
    /// sort compares one component, not the prefix they share. No probe asks
    /// the heap for nothing.
    ///
    /// # Panics
    ///
    /// Panics in a debug build where two links of the home differ in length,
    /// which no mint produces.
    fn keys_in_slots<'a>(
        &'a self,
        touch: &Touch<'_>,
        probes: impl IntoIterator<Item = (usize, usize)>,
    ) -> Vec<(&'a Tumbler, usize)> {
        let mut hits: Vec<(&Tumbler, usize)> = Vec::new();
        for (slot, query) in probes {
            let Some(index) = self.hints.spanfilade.slot(slot) else {
                continue;
            };
            for (q, parts) in touch.named_at(query) {
                index.stab_in_parts(touch.held(), q, parts, &mut |link| hits.push((link, slot)));
            }
        }
        hits.sort_unstable_by(|(t, i), (u, j)| {
            debug_assert_eq!(t.len(), u.len(), "one home's links have one length");
            ordinal(t).cmp(ordinal(u)).then(i.cmp(j))
        });
        hits.dedup();
        hits
    }

    /// Returns the tuples of `slice` homed in `home` that a typed stab finds.
    ///
    /// It is the one statement of the typed stab's cut, which
    /// [`LinkState::stab_typed`] asks of every candidate home and
    /// [`LinkState::stab_typed_in`] of one: the home's keys whose `slot`
    /// overlaps some span of `query`, as [`LinkState::stab_in`] finds them,
    /// each tested against the slice and `view` before it is lifted, so only
    /// a member is lifted and has its slots cloned, in ascending order. The
    /// `_slice` suffix keys it as `_class` keys
    /// [`LinkState::type_slice_class`]: the same question as `stab_typed_in`,
    /// asked of the slice its class names, which each caller looks up once a
    /// call.
    fn stab_typed_in_slice<'s>(
        &self,
        slice: &OrdSet<Tumbler>,
        home: &Address,
        slot: usize,
        query: impl IntoIterator<Item = &'s Span>,
        view: View,
    ) -> Vec<Tuple> {
        let active = default_to_active(view) == View::Active;
        self.stab_keys_in(home, slot, query)
            .into_iter()
            .filter(|t| slice.contains(*t) && !(active && self.nullified(t)))
            .map(|t| {
                let link = self.link_at(t);
                Tuple {
                    addr: lift(t),
                    from: link.from_slot().clone(),
                    to: link.to_slot().clone(),
                }
            })
            .collect()
    }

    /// Walks the whole store under a view, lifting every link the view admits.
    ///
    /// They come back as addresses in M1's order. It is the one place a read
    /// walks `links` end to end — [`LinkState::match_links`]' unconstrained
    /// branch, which has no constraint to answer from the spanfilade — and it
    /// turns `Default` into `Active` for that branch. ([`LinkState::stab`] and
    /// the typed reads' slice walk make the same conversion at their own
    /// sites.)
    fn scan(&self, view: View) -> OrdSet<Address> {
        let active = default_to_active(view) == View::Active;
        self.links
            .keys()
            .filter(|addr| !(active && self.nullified(addr)))
            .map(lift)
            .collect()
    }

    /// Returns the typed slices of the classes an address-denoting `ty`
    /// could overlap at the type slot.
    ///
    /// A link's address-denoting type slot overlaps `ty` exactly when some
    /// address its class denotes is a prefix of, or extends, some address
    /// `ty` denotes — the named type itself, the subtypes beneath it and the
    /// wider types above it — one prefix test per denoted address per class.
    /// A class that denotes no address (a type slot built from a content
    /// extent) is answered whole: whether its spans overlap `ty` is not
    /// decided here, and over-inclusion costs a candidate home where
    /// omission would lose a hit. `O(classes)`, a class being a distinct type
    /// the board has deposited.
    fn related_slices<'a>(&'a self, ty: &'a Endset) -> impl Iterator<Item = &'a OrdSet<Tumbler>> + 'a {
        let named: Vec<&Tumbler> = ty.addrs().collect();
        self.hints
            .type_slices
            .iter()
            .filter(move |(class, _)| {
                class.denoted().is_none_or(|minimal| {
                    minimal
                        .iter()
                        .any(|u| named.iter().any(|t| is_prefix(u, t) || is_prefix(t, u)))
                })
            })
            .map(|(_, slice)| slice)
    }

    /// Walks the typed slice of a class, lazily, over the audit hint.
    ///
    /// Active = audit ∖ nullified, decided per element at query time (the
    /// indexes are append-only — the default of the Active/audit indexing
    /// open decision).
    ///
    /// Lazy because nearly every caller wants a walk or a boolean, not a
    /// container: materializing the `Active` view means a fresh persistent
    /// tree plus a deep clone of every `Tumbler` in it, which every
    /// `is_filtered` probe and every `View::Default` read of
    /// `members`/`targets_of` would pay. The one caller that genuinely
    /// returns a set — [`LinkState::type_slice`] — collects here, where the
    /// copy is visible.
    ///
    /// Takes `view` raw and applies [`default_to_active`] here — the one
    /// place a slice read turns `Default` into `Active`, so a caller that
    /// also honors `Default` result-side (`members`/`targets_of`) reads its
    /// own `view` for that and hands this the same value unaltered.
    ///
    /// The `_class` suffix is the module's: the same question as
    /// [`LinkState::type_slice`], keyed by class rather than by endset. The
    /// two differ in shape as well — this hands back a walk, that one
    /// collects — so a caller wanting a set says so at its own site.
    fn type_slice_class<'a>(
        &'a self,
        class: &CoverageClass,
        view: View,
    ) -> impl Iterator<Item = &'a Tumbler> + 'a {
        let active = default_to_active(view) == View::Active;
        self.hints
            .type_slices
            .get(class)
            .into_iter()
            .flatten()
            .filter(move |t| !(active && self.nullified(t)))
    }

    /// Walks the typed slice as links: each index key with the value it names.
    ///
    /// The keys are [`type_slice_class`](LinkState::type_slice_class)'s — the
    /// one place the slice walk meets [`LinkState::link_at`], so a read that
    /// wants the value rather than the key discharges the index-key
    /// obligation here once. Lazy, as the slice walk is, and taking `view`
    /// raw as it does.
    fn typed_links<'a>(
        &'a self,
        class: &CoverageClass,
        view: View,
    ) -> impl Iterator<Item = (&'a Tumbler, &'a Link)> + 'a {
        self.type_slice_class(class, view)
            .map(move |t| (t, self.link_at(t)))
    }

    /// Returns BH1's filter domain.
    ///
    /// It is the addresses every active shipped `Retired` tuple's F denotes.
    /// Denotation, so a non-unit-depth span in a `Retired` F contributes no
    /// root — the managed surface cannot build one (`emit` forces
    /// `enc({from})`), the open surface can.
    ///
    /// Lazy, so a single probe still short-circuits at the first root that
    /// covers it; collectable, so a read that filters many probes derives the
    /// domain once instead of re-walking the slice — and re-deriving each
    /// root's span — per result element.
    fn retired_roots(&self) -> impl Iterator<Item = &Tumbler> + '_ {
        let retired_class = registry().shipped_class(ShippedType::Retired);
        self.typed_links(retired_class, View::Active)
            .flat_map(|(_, link)| link.from_slot().addrs())
    }

    /// Applies the result-side BH1 rewrite, whole, to a denoted result set.
    ///
    /// The set is lifted to addresses, minus the filtered ones under
    /// `View::Default`. Two rules and one judgement, stated once for the two
    /// reads (`members`/`targets_of`) that honor them.
    ///
    /// The rules are BH1's Rewrite scope, which confines `Default` = active ∖
    /// filtered to those two reads, and the `J ≠ K'` exclusion, which stops
    /// the shipped filter class from subtracting itself. The judgement is that
    /// the filter domain is derived once for the whole result rather than once
    /// per element: [`LinkState::is_filtered`] re-walks the active `Retired`
    /// slice per probe, which is right for a single probe and quadratic across
    /// a result set.
    fn subtract_filtered(
        &self,
        class: &CoverageClass,
        view: View,
        denoted: OrdSet<Tumbler>,
    ) -> Vec<Address> {
        let subtract =
            view == View::Default && *class != *registry().shipped_class(ShippedType::Retired);
        let roots: Vec<&Tumbler> = if subtract {
            self.retired_roots().collect()
        } else {
            Vec::new()
        };
        denoted
            .into_iter()
            .filter(|t| !(subtract && under_any(roots.iter().copied(), t)))
            .map(lift_denoted)
            .collect()
    }

    /// Returns whether the walk family serves `ty` — the v1 scope (§5).
    ///
    /// The v1 walk-serving scope: the walk family serves the shipped
    /// `Supersedes` class and no other — the one statement of the rule
    /// `succs`/`chain`/`tip` apply. With the registry's population fixed to
    /// the compiled shipped table, no second BH2 declaration can exist to be
    /// unserved; this scope test lifts when the parameterized multi-BH2 path
    /// lands.
    ///
    /// Also the walk family's one classification site, so their shared `ty`
    /// precondition has one origin.
    ///
    /// # Panics
    ///
    /// [`coverage_class`] is total on the address-denoting and
    /// `iextent`-built endsets those ops document, and panics naming that
    /// precondition on a non-level-uniform one.
    fn serves_walk(&self, ty: &Endset) -> bool {
        coverage_class(ty) == *registry().shipped_class(ShippedType::Supersedes)
    }

    /// Returns whether `x` is a sink — successor-free in the operative graph.
    ///
    /// `x` has no edges at all, or every edge out of it carries a nullified
    /// claim. Answered without building `succ_o(x)`: the Df-SUCC filter is the
    /// same one [`LinkState::succs_operative`] applies, and deduplicating the
    /// survivors over `new` cannot change whether there are any, so the raw
    /// edge set decides it. [`LinkState::current`] asks only whether a
    /// reached node is a sink; the walk, which needs the successors
    /// themselves, builds them.
    fn is_sink(&self, x: &Tumbler) -> bool {
        self.hints
            .sup_fwd
            .get(x)
            .is_none_or(|edges| edges.iter().all(|e| self.nullified(&e.claim)))
    }

    /// Returns the operative successor set `succ_o(x)`.
    ///
    /// It is `sup_fwd[x]` filtered to edges whose claim is unnullified
    /// (Df-SUCC), deduplicated over `new`.
    fn succs_operative(&self, x: &Tumbler) -> OrdSet<Tumbler> {
        match self.hints.sup_fwd.get(x) {
            None => OrdSet::new(),
            Some(edges) => edges
                .iter()
                .filter(|e| !self.nullified(&e.claim))
                .map(|e| e.new.clone())
                .collect(),
        }
    }

    /// Returns operative `out(x)` for every vertex `x` in `vertices`.
    ///
    /// Each comes paired with its vertex and in claim-address order — the
    /// reverse of [`LinkState::succs_operative`], which reads the forward
    /// `sup_fwd` hint. This direction has no hint, so it is answered for a set
    /// in one walk of the active claim slice rather than re-walked per vertex:
    /// [`LinkState::current`] asks it of every sink it reaches, and a
    /// per-vertex form makes that quadratic in a store whose claim count a
    /// caller chooses.
    ///
    /// Matched by denotation, the claim schema's own regime — a claim's `new`
    /// is a single denoted address (Df-DISC(ii)), so `g == x` is the
    /// relation, total over every argument and needing no precondition. The
    /// vertices are link addresses, never coverage probes: the spanfilade's
    /// overlap would agree on one, where the `dom(L)` prefix antichain (R0a)
    /// makes the two coincide, and would answer with every claim beneath a
    /// document- or account-level argument.
    ///
    /// Vertices arrive as an `OrdSet`: ascending and deduplicated by the
    /// argument's type, so the binary search the walk does is sound by
    /// construction and nothing is sorted twice — the caller holds its reach
    /// set ordered already.
    fn out_claims(&self, vertices: OrdSet<Tumbler>) -> Vec<(Tumbler, Vec<Address>)> {
        let mut out: Vec<(Tumbler, Vec<Address>)> =
            vertices.into_iter().map(|t| (t, Vec::new())).collect();
        let sup_class = registry().shipped_class(ShippedType::Supersedes);
        for (claim, link) in self.typed_links(sup_class, View::Active) {
            for g in link.to_slot().addrs() {
                if let Ok(i) = out.binary_search_by(|(t, _)| t.cmp(g)) {
                    out[i].1.push(lift(claim));
                }
            }
        }
        out
    }

    /// Walks forward from `x`, bounded by a visited set.
    ///
    /// It returns the traversed path (from `x`, inclusive) and `Some(sink)`
    /// iff halted at a successor-free node (branch and cycle yield `None`).
    fn walk_sup(&self, x: &Tumbler) -> (Vec<Tumbler>, Option<Tumbler>) {
        let mut path = vec![x.clone()];
        let mut visited = OrdSet::unit(x.clone());
        let mut node = x.clone();
        loop {
            let succs = self.succs_operative(&node);
            match succs.len() {
                0 => return (path, Some(node)),
                1 => {
                    // Consumed, as in `current`: the set is this call's own,
                    // so the sole successor moves out of it.
                    let next = succs.into_iter().next().expect("len == 1");
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

    /// Answers `target_of` by class.
    ///
    /// Shared with `targets_keyed`, whose registry walk has classes, not
    /// endsets. Walks the active typed slice and applies the denotation test
    /// directly: "exactly one" is a property of the set, not of the iteration
    /// order.
    fn target_of_class(&self, class: &CoverageClass, source: &Address) -> Option<Address> {
        let mut survivor: Option<&Link> = None;
        for (_, link) in self.typed_links(class, View::Active) {
            if link.from_slot().addrs().any(|f| f == source.tumbler()) {
                if survivor.is_some() {
                    return None; // several active type-ty matches ⇒ ⊥
                }
                survivor = Some(link);
            }
        }
        survivor?
            .to_slot()
            .single_denoted()
            .cloned()
            .map(lift_denoted)
    }
}
