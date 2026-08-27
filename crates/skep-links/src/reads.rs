//! §E/§F/§G — the pure read surface on [`LinkState`]: raw reads (READLINK /
//! FOLLOWLINK), the typed-relation observers (Observe + the default
//! predicates + BH1–BH4), ASN-0125 currency, and the discovery primitives
//! for M8 (`stab` / `match_links` / `type_slice`). All `&self` over any M2
//! `Snapshot`; nothing here writes.

use im::OrdSet;
use skep_address::{
    classify_spans, document_of, is_prefix, ordinal, validate, Address, Span, SpanRel, SpanSet,
    Tumbler,
};

use crate::endset::{coverage_class, CoverageClass, Endset, Link};
use crate::error::{Invalid, NotBh4};
use crate::registry::{Behavior, ShippedType};
use crate::state::{lift, LinkState};

/// Read view (ASN-0128). `Default` (active ∖ filtered) is meaningful only on
/// `members`/`targets_of`; on `observe` and the §G index primitives it reads
/// as `Active` (result-side BH1 filtering is undefined for a raw index
/// probe).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Audit,
    Active,
    Default,
}

/// `View::Default` — the std name for the variant this module already calls
/// the default view (not derived: `Audit` is declared first, and declaration
/// order here is the design's).
impl Default for View {
    fn default() -> View {
        View::Default
    }
}

/// One observed typed-relation tuple — endsets are M7's readable [`Endset`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tuple {
    pub addr: Address,
    pub from: Endset,
    pub to: Endset,
}

/// ASN-0086's pattern pair for [`LinkState::observe`] — the F-side and G-side
/// probes, named so the two same-typed tumbler slices cannot trade places at
/// a call. Each side is an AND of coverage probes; an empty side is no
/// constraint, so `Default` is the unconstrained pattern `(⟨⟩, ⟨⟩)` matching
/// the whole typed slice.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Pattern<'a> {
    /// Tumblers every match's F must COVER.
    pub from: &'a [Tumbler],
    /// Tumblers every match's G must COVER.
    pub to: &'a [Tumbler],
}

/// BH2 head: `Sink` at a successor-free node, `Indeterminate` (⊥) at a
/// branch or cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tip {
    Sink(Address),
    Indeterminate,
}

/// EL14 disclosure-not-decision: the operative sink, its OWN activity (a
/// member can be a current sink yet itself nullified — EL14e), and `claims` =
/// the FULL operative `out(sink)` — every operative `[K_sup]` claim whose
/// `new` endpoint is this sink, including one asserted from outside
/// `reach_o(y)`. Homes recoverable by M1's `document_of` (EL8b). The reader
/// applies narrowing; M7 decides nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentMember {
    pub member: Address,
    pub active: bool,
    pub claims: Vec<Address>,
}

/// Overlap for the spanfilade (§6): `ProperOverlap | Containment | Equal` —
/// NOT `Adjacent` (abutting spans share no tumbler; matching them would
/// false-positive every link whose slot coverage merely abuts the query) and
/// never M1's `intersect` (which faults on the mixed-length endpoints M5's
/// resolve runs routinely produce).
fn overlaps(a: &Span, b: &Span) -> bool {
    matches!(
        classify_spans(a, b),
        SpanRel::ProperOverlap | SpanRel::Containment | SpanRel::Equal
    )
}

/// The spanfilade's per-link predicate: `link`'s coverage at `slot` overlaps
/// `query`. Absent slot ⇒ no match. The ONE statement of the test, so
/// [`LinkState::stab`] and every later conjunct of
/// [`LinkState::match_links`] cannot answer differently.
fn slot_overlaps(link: &Link, slot: usize, query: &Endset) -> bool {
    link.slot(slot)
        .is_some_and(|endset| query.spans().any(|q| endset.spans().any(|s| overlaps(q, s))))
}

/// `Tumbler → Address` lift of a DENOTED address, T4-valid on either of two
/// grounds. A tumbler read back out of a stored slot rests on the slot's
/// construction: every slot a deposit path builds comes from [`enc`], whose
/// spans start at an `Address`'s tumbler, or from M5's `Run::iextent`, whose
/// start is the run's `i_start` `Address`. A tumbler the walk family hands
/// back may instead be the CALLER'S OWN ARGUMENT — `chain` seeds its path
/// with it, `tip` reports a successor-free node as its own sink, and
/// `current` reaches `y` when nothing supersedes it — and there the ground is
/// stronger still: the caller held an `Address`. Named apart from the store's
/// own [`lift`] so the two families of obligation can be audited separately.
///
/// CONSUMES its argument: a denoted address is read out of a slot into a set
/// or a path the read owns and is about to drop, so the caller hands it over
/// rather than making `validate` copy a `Vec<Nat>` per component. The one
/// caller still holding a borrow clones at its own site.
fn lift_denoted(t: Tumbler) -> Address {
    validate(t).expect(
        "a denoted address is T4-valid: it is either a slot start (enc or a Run's iextent) \
         or the caller's own argument, echoed back by the walk",
    )
}

/// BH1's test against a root set: PREFIX-CLOSURE over the roots — some root
/// is a prefix of the probe. The ONE statement of it, so the single-probe read
/// and the result-side subtraction cannot answer differently. The probe ranges
/// over all of carrier T, roots or not.
///
/// On roots denoted out of an `enc`-built endset this reproduces exactly that
/// endset's coverage, which is why the prefix form and a whole-endset `covers`
/// are indistinguishable everywhere the managed surface writes.
fn under_any<'a>(roots: impl IntoIterator<Item = &'a Tumbler>, probe: &Tumbler) -> bool {
    roots.into_iter().any(|root| is_prefix(root, probe))
}

/// `Default → Active` for the surfaces where `Default` is undefined.
fn default_to_active(view: View) -> View {
    match view {
        View::Default => View::Active,
        other => other,
    }
}

impl LinkState {
    // ───────────────────────── §E — raw reads ─────────────────────────

    /// READLINK (ASN-0111): `Σ.L(a)` verbatim (readable endsets), or `None`
    /// (= ⊥) on absence. Total; recorded, never resolved; never dereferences
    /// covered links (RL4/RL6). The persistent map is already the positive
    /// cache (immutability ⇒ never stale).
    ///
    /// Borrows out of the snapshot, `get`-shaped, so a caller that only tests
    /// residence or reads one slot pays nothing and a caller that keeps the
    /// value clones at its own site. `link_at` is the crate-internal
    /// infallible twin, for an address that came off an index key rather than
    /// from a caller.
    pub fn readlink(&self, a: &Address) -> Option<&Link> {
        self.links.get(a.tumbler())
    }

    /// FOLLOWLINK (ASN-0114): the recorded slot's coverage as a `SpanSet`
    /// (the verbatim endset folded — F1/F3 by construction). `Ok(spans)`
    /// coverage-exact to `slot`; `Ok(SpanSet::empty())` = ⟨⟩
    /// (valid-but-empty success); `Err(Invalid)` = ⊥ (link or slot absent).
    /// The Result/Ok-empty shape makes ⟨⟩ ≠ ⊥ unforgeable (F7).
    pub fn followlink(&self, a: &Address, slot: usize) -> Result<SpanSet, Invalid> {
        let link = self.links.get(a.tumbler()).ok_or(Invalid)?;
        let endset = link.slot(slot).ok_or(Invalid)?;
        Ok(endset.to_spanset())
    }

    // ─────────────── §F — typed reads & the PL surface ────────────────

    /// Observe (ASN-0086): exact ⊆-coverage match over the `view` typed slice
    /// — every [`Pattern`] tumbler COVERED by the tuple's F (resp. G); an
    /// empty pattern side is no constraint. The pattern domain is ALL of
    /// carrier T (ASN-0086): membership rides [`Endset::covers`], total on T,
    /// so ghost (unallocated) addresses and the non-T4 tumblers inside a
    /// non-unit span's coverage are honest probes. `Default → Active` (raw
    /// Observe never filters — ASN-0128). Matches come back in ASCENDING
    /// TUPLE-ADDRESS order, the typed slice's own.
    ///
    /// `ty` PRECONDITION: address-denoting (a registered or reserved type)
    /// or `iextent`-built — [`coverage_class`] classifies it, so a
    /// hand-built non-level-uniform `ty` panics naming that precondition
    /// (§Core data model totality).
    pub fn observe(&self, ty: &Endset, pat: Pattern<'_>, view: View) -> Vec<Tuple> {
        let class = coverage_class(ty);
        let mut out = Vec::new();
        for t in self.type_slice_class(&class, view) {
            let link = self.link_at(t);
            let f_ok = pat.from.iter().all(|probe| link.from_slot().covers(probe));
            let g_ok = pat.to.iter().all(|probe| link.to_slot().covers(probe));
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

    /// D2: exact ACTIVE coverage-membership — some active type-`ty` tuple's
    /// F COVERS the probe, which ranges over all of carrier T (`observe`'s
    /// pattern domain). Never a `stab` overlap call (an ancestor pattern
    /// would over-match) and never BH1-filtered (BH1 Rewrite scope).
    ///
    /// `ty` PRECONDITION: address-denoting (a registered or reserved type)
    /// or `iextent`-built — [`coverage_class`] classifies it, so a
    /// hand-built non-level-uniform `ty` panics naming that precondition
    /// (§Core data model totality).
    pub fn is_k(&self, ty: &Endset, probe: &Tumbler) -> bool {
        let class = coverage_class(ty);
        self.type_slice_class(&class, View::Active)
            .any(|t| self.link_at(t).from_slot().covers(probe))
    }

    /// D1: the denoted member set (F.addrs() over the slice), deduplicated,
    /// in Tumbler order. Alone with [`LinkState::targets_of`] honors
    /// `View::Default` = active ∖ filtered — result-side, lazily, honoring
    /// the `J ≠ K'` exclusion (no self-subtraction when `ty` IS the shipped
    /// Retired class).
    ///
    /// `ty` PRECONDITION: address-denoting (a registered or reserved type)
    /// or `iextent`-built — [`coverage_class`] classifies it, so a
    /// hand-built non-level-uniform `ty` panics naming that precondition
    /// (§Core data model totality).
    pub fn members(&self, ty: &Endset, view: View) -> Vec<Address> {
        let class = coverage_class(ty);
        let mut members: OrdSet<Tumbler> = OrdSet::new();
        for t in self.type_slice_class(&class, view) {
            let link = self.link_at(t);
            for m in link.from_slot().addrs() {
                members.insert(m.clone());
            }
        }
        self.subtract_filtered(&class, view, members)
    }

    /// D3: the denoted targets (G.addrs()) of tuples whose F COVERS `x`,
    /// deduplicated, in Tumbler order; `View::Default` subtracts filtered
    /// results (with the `J ≠ K'` exclusion, as `members`). The source
    /// argument is matched by COVERAGE here; [`LinkState::target_of`] and the
    /// walk family match a source vertex by DENOTATION instead.
    ///
    /// `ty` PRECONDITION: address-denoting (a registered or reserved type)
    /// or `iextent`-built — [`coverage_class`] classifies it, so a
    /// hand-built non-level-uniform `ty` panics naming that precondition
    /// (§Core data model totality).
    pub fn targets_of(&self, ty: &Endset, x: &Address, view: View) -> Vec<Address> {
        let class = coverage_class(ty);
        let mut targets: OrdSet<Tumbler> = OrdSet::new();
        for t in self.type_slice_class(&class, view) {
            let link = self.link_at(t);
            if link.from_slot().covers(x.tumbler()) {
                for g in link.to_slot().addrs() {
                    targets.insert(g.clone());
                }
            }
        }
        self.subtract_filtered(&class, view, targets)
    }

    /// Tuple status by address: resident and not nullified.
    pub fn is_active(&self, a: &Address) -> bool {
        self.resident(a.tumbler()) && !self.nullified(a.tumbler())
    }

    /// Tuple status by address: a resident retraction root (the tombstone
    /// set; monotone — R3/R6a). EXACT membership: `a` is nullified iff `a`
    /// itself is a retraction root, so nullifying a document or an account
    /// address tombstones that address alone and no link beneath it. The
    /// module's other suppression mechanism reads the opposite way —
    /// [`LinkState::is_filtered`] is prefix-closed over BH1's retired roots
    /// — so the two are not interchangeable at a probe.
    pub fn is_nullified(&self, a: &Address) -> bool {
        self.nullified(a.tumbler())
    }

    /// BH1 read-filter (§7): `∃ x ∈ addrs(F) : x ≼ probe` over the active
    /// shipped `Retired` slice — some address a retired tuple's F DENOTES is
    /// a prefix of the probe, computed lazily (the filtered subtree is never
    /// materialized). The probe ranges over all of carrier T: every tumbler
    /// under a denoted retired root is filtered, addresses or not.
    ///
    /// Equal to [`Endset::covers`] on an address-denoting F — a unit-depth
    /// span's coverage IS its start's prefix set — hence on every `Retired`
    /// tuple `emit` can build, `emit` forcing `enc({from})`. STRICTLY NARROWER
    /// on an F carrying a non-unit-depth span, which the open surface can
    /// deposit and which denotes nothing: such a span contributes no root and
    /// filters nothing, where its coverage is non-empty. NOT
    /// [`LinkState::is_k`]'s regime, which is `covers` outright.
    ///
    /// Correct TYPE-LESS because v1 registers exactly one BH1 type —
    /// build-enforced (`UnservedSecondFilter`, §B).
    pub fn is_filtered(&self, probe: &Tumbler) -> bool {
        under_any(self.retired_roots(), probe)
    }

    /// BH2 forward step (§5): the operative successors of `x` — `sup_fwd[x]`
    /// filtered to claims ∉ nullified — deduplicated, Tumbler order. v1
    /// serves the walk family ONLY for the shipped `Supersedes` class
    /// (build-enforced, §B); any other REGISTERED `ty` yields the empty vec
    /// (the service-scope guard).
    ///
    /// `ty` PRECONDITION: address-denoting (a registered or reserved type)
    /// or `iextent`-built — the walk-scope test classifies it, so a
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

    /// BH2 chain: the bounded iterative walk over operative successors from
    /// `x` (inclusive), halting at sink (no successor), branch (≥ 2), or
    /// cycle (revisit) — the finite link set is the termination bound. Empty
    /// for a registered `ty` other than `Supersedes` (v1 serving scope, as
    /// `succs`).
    ///
    /// `ty` PRECONDITION: address-denoting (a registered or reserved type)
    /// or `iextent`-built — the walk-scope test classifies it, so a
    /// hand-built non-level-uniform `ty` panics naming that precondition
    /// (§Core data model totality) rather than reading as out-of-scope.
    pub fn chain(&self, ty: &Endset, x: &Address) -> Vec<Address> {
        if !self.serves_walk(ty) {
            return Vec::new();
        }
        let (path, _) = self.walk_sup(x.tumbler());
        path.into_iter().map(lift_denoted).collect()
    }

    /// BH2 chain membership: `target ∈ chain(ty, addr)` — membership in the
    /// walk's result list, never a coverage test. Inherits `chain`'s halting
    /// rule (branch/cycle truncate the path), its v1 serving scope — a
    /// registered `ty` other than `Supersedes` has an empty chain, so nothing
    /// is a member — and its `ty` precondition.
    pub fn is_in_chain(&self, ty: &Endset, addr: &Address, target: &Address) -> bool {
        self.chain(ty, addr).contains(target)
    }

    /// BH2 head: `Sink(head)` when the walk halts at a successor-free node;
    /// `Indeterminate` (⊥) at a branch or cycle — and for a registered `ty`
    /// other than `Supersedes` (v1 serving scope: no positive head is
    /// fabricated).
    ///
    /// `ty` PRECONDITION: address-denoting (a registered or reserved type)
    /// or `iextent`-built — the walk-scope test classifies it, so a
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

    /// BH3 reverse (§7): sources of active type-`ty` tuples whose G COVERS
    /// `target` (AM's reverse-lookup rule — the one member of the family
    /// matched by coverage rather than denotation), collecting each match's
    /// F.addrs() — deduplicated, in Tumbler order, as `members`/`targets_of`.
    /// The active typed slice is the domain and `covers` is the whole test —
    /// the store-wide span scan [`LinkState::stab`] performs would read every
    /// link in the docuverse to narrow a set that is a hint lookup away and
    /// already a subset of what it scanned.
    ///
    /// `ty` PRECONDITION: address-denoting (a registered or reserved type)
    /// or `iextent`-built — [`coverage_class`] classifies it, so a
    /// hand-built non-level-uniform `ty` panics naming that precondition
    /// (§Core data model totality).
    pub fn sources_to(&self, ty: &Endset, target: &Address) -> Vec<Address> {
        let class = coverage_class(ty);
        let mut sources: OrdSet<Tumbler> = OrdSet::new();
        for t in self.type_slice_class(&class, View::Active) {
            let link = self.link_at(t);
            if link.to_slot().covers(target.tumbler()) {
                for f in link.from_slot().addrs() {
                    sources.insert(f.clone());
                }
            }
        }
        sources.into_iter().map(lift_denoted).collect()
    }

    /// BH3 forward projection (§7): ⊥ unless EXACTLY ONE active type-`ty`
    /// tuple denotes `source` in F (denotation match — `source ∈ F.addrs()`,
    /// AM's source-vertex rule) with a single-address-denoting G; returns
    /// that single target. Restricting to the ACTIVE typed slice is what
    /// makes "exactly one active K-tuple" exact.
    ///
    /// `ty` PRECONDITION: address-denoting (a registered or reserved type)
    /// or `iextent`-built — [`coverage_class`] classifies it, so a
    /// hand-built non-level-uniform `ty` panics naming that precondition
    /// (§Core data model totality).
    pub fn target_of(&self, ty: &Endset, source: &Address) -> Option<Address> {
        self.target_of_class(&coverage_class(ty), source)
    }

    /// BH3 join (§7): `target_of` across EVERY BH3-registered Binary type,
    /// keyed by the public [`coverage_class`] (M9 indexes with
    /// `coverage_class(ty)`; the registry is private to `LinkState`, which is
    /// why M7 composes the join).
    pub fn targets_keyed(&self, source: &Address) -> im::HashMap<CoverageClass, Address> {
        let mut out = im::HashMap::new();
        for class in self.registry.reverse_lookup_classes() {
            if let Some(t) = self.target_of_class(class, source) {
                out.insert(class.clone(), t);
            }
        }
        out
    }

    /// BH4 age (§7): `f_d^Σ − ordinal(a)` at `a`'s own home, for a resident
    /// link, else `None` — a raw distance back along the home's ALLOCATION
    /// chain (`chain_d`, ordinal time, no clock — never BH2's supersession
    /// chain), meaningful as staleness only for an idem⊥ BH4 type (under
    /// idem⊤ a renewal dedups to the incumbent and age never resets — which
    /// is exactly why R-C0 forces BH4 ⇒ idem⊥).
    ///
    /// `None` means NON-RESIDENCE and nothing else — an exactness M9 already
    /// builds on. The home and the ordinal are facts about a key of `links`
    /// that this module has already committed to elsewhere, so each
    /// fail-stops rather than answering `None` and reading as absence.
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
        // resident link's ordinal runs `1..f` and the newest link's IS `f`.
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

    /// BH4 stale set (§7): active type-`ty` tuples older than `horizon`, in
    /// ASCENDING ADDRESS ORDER — the active typed slice's own order — served
    /// only where declared: `Err(NotBh4)` unless the in-contract `ty` is
    /// registered with BH4 (Age). The typed rejection keeps `Ok(vec![])` a
    /// truthful freshness answer (never conflated with "not a BH4 type") and
    /// IS the fence: `retract_stale` builds its batch from this call, so a
    /// refusal here is the batch's refusal, and the nullifier can never be
    /// aimed at an idem⊤ class (e.g. mass-nullifying old `[K_sup]` claims).
    ///
    /// The ORDER is load-bearing, not incidental: `retract_stale` issues one
    /// `nullify` per element in it, and its published guarantee that a batch
    /// halted by a foreign-owned tuple halts at the same point on every
    /// re-run is exactly this determinism.
    ///
    /// `ty` PRECONDITION: address-denoting (a registered or reserved type)
    /// or `iextent`-built — [`coverage_class`] classifies it BEFORE the BH4
    /// lookup, so a hand-built non-level-uniform `ty` panics naming that
    /// precondition (§Core data model totality) rather than reaching the
    /// typed refusal.
    pub fn stale(&self, ty: &Endset, horizon: u64) -> Result<Vec<Address>, NotBh4> {
        let class = coverage_class(ty);
        let registered_bh4 = self
            .registration(&class)
            .is_some_and(|r| r.behaviors.contains(&Behavior::Age));
        if !registered_bh4 {
            return Err(NotBh4);
        }
        Ok(self
            .type_slice_class(&class, View::Active)
            .filter_map(|t| {
                let a = lift(t);
                // A typed-slice key is a key of `links`, so `age` is `Some`.
                // `None` there means NON-RESIDENCE and nothing else, which for
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

    /// ASN-0125 currency (EL14, hardwired to `[K_sup]`): the operative sinks
    /// reachable from `y` via `succ_o` (the `reach_o(y)` fixpoint within the
    /// finite link set), returned ENTIRE — linear → 1, forked → ≥ 2,
    /// mutual-supersession standoff → 0, all legitimate. Each sink carries
    /// its OWN activity and the FULL operative `out(sink)`, read from the
    /// inbound claim relation in ONE walk for all sinks at once, rather than
    /// accumulated during the walk — accumulation would
    /// drop an operative claim asserted on the sink from outside the closure.
    /// M7 discloses; the consumer narrows — no single "latest" is fabricated.
    ///
    /// Members come back ASCENDING by address, and each member's `claims`
    /// ascending by claim address.
    pub fn current(&self, y: &Address) -> Vec<CurrentMember> {
        let mut reach: OrdSet<Tumbler> = OrdSet::unit(y.tumbler().clone());
        let mut stack = vec![y.tumbler().clone()];
        while let Some(x) = stack.pop() {
            for succ in self.succs_operative(&x).iter() {
                if !reach.contains(succ) {
                    reach.insert(succ.clone());
                    stack.push(succ.clone());
                }
            }
        }
        // The sinks, ascending because `reach` is — then ONE walk of the
        // active claim slice for all of them together.
        let sinks: Vec<Tumbler> = reach.into_iter().filter(|t| self.is_sink(t)).collect();
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

    /// The genesis-fixed endset of a shipped class, read off a snapshot — for
    /// a caller holding the SLICE: M8's lineage reads name `Supersedes` this
    /// way, and the engine's observe dump and its genesis-drift check name all
    /// five. A caller holding the registry itself asks
    /// [`TypeRegistry::reserved_type`](crate::TypeRegistry::reserved_type),
    /// which is public and is where this delegates.
    pub fn reserved_type(&self, ty: ShippedType) -> &Endset {
        self.registry.reserved_type(ty)
    }

    // ─────────────── §G — discovery primitives for M8 ────────────────

    /// Spanfilade primitive: links whose coverage at `slot` OVERLAPS `query`
    /// (overlap = `ProperOverlap | Containment | Equal` — NOT `Adjacent`).
    /// `query` is M7's READABLE `Endset` (M8 builds it via `enc`/
    /// `Endset::from_spans`). `view ∈ {Audit, Active}` only (`Default` reads
    /// as `Active`). v1 bootstrap: a brute scan of `links` reading each
    /// endset's spans — trivially correct, O(n); the deferred interval index
    /// swaps in behind the same signature and overlap predicate (Open build
    /// decisions).
    ///
    /// Every returned address is a KEY of `links`, so [`LinkState::readlink`]
    /// on it is `Some`; the set is in M1's address order (T1), which is the
    /// permanent enumeration key a cursor resumes from.
    pub fn stab(&self, slot: usize, query: &Endset, view: View) -> OrdSet<Address> {
        self.scan(view, |link| slot_overlaps(link, slot, query))
    }

    /// The AND-of-(per-slot overlap) combiner — findlinks' core, factored
    /// into M7 (Conflicts §6). `constraints` lists ONLY constrained slots —
    /// an unconstrained slot is OMITTED, never an empty `Endset`
    /// (`stab(slot, ⟨⟩, ·) = ∅` would empty the AND); empty `constraints` ⇒
    /// the whole `view` slice. `view ∈ {Audit, Active}` only (`Default` reads
    /// as `Active`).
    ///
    /// The first constraint scans `links`; every later one NARROWS the
    /// accumulator with the same per-link predicate [`stab`](LinkState::stab)
    /// applies, rather than scanning the store again and intersecting
    /// afterwards. Both read the store through the same per-link overlap test,
    /// so the AND cannot come apart from
    /// its own conjuncts — and a caller's constraint count multiplies the
    /// surviving set instead of the whole store, which matters because the
    /// query is caller-supplied and the constraint count with it.
    ///
    /// Each query is BORROWED, as [`stab`](LinkState::stab) borrows its own:
    /// a constraint is read and dropped, never kept, so a caller assembling
    /// its list out of a request it already holds hands over references
    /// rather than a copy per constrained slot.
    ///
    /// Every returned address is a KEY of `links`, so [`LinkState::readlink`]
    /// on it is `Some`; the set is in M1's address order (T1), which is the
    /// permanent enumeration key a cursor resumes from.
    pub fn match_links(&self, constraints: &[(usize, &Endset)], view: View) -> OrdSet<Address> {
        let Some((&(first_slot, first_query), rest)) = constraints.split_first() else {
            return self.scan(view, |_| true); // no constraint: the whole view slice
        };
        let mut acc = self.stab(first_slot, first_query, view);
        for &(slot, query) in rest {
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

    /// `L_K` (Audit) / `A_K` (Active) — the typed slice.
    /// `view ∈ {Audit, Active}` only (`Default` reads as `Active`).
    ///
    /// Every returned address is a KEY of `links`, so [`LinkState::readlink`]
    /// on it is `Some`; the set is in M1's address order (T1), which is the
    /// permanent enumeration key a cursor resumes from.
    ///
    /// `ty` PRECONDITION: address-denoting (a registered or reserved type)
    /// or `iextent`-built — [`coverage_class`] classifies it, so a
    /// hand-built non-level-uniform `ty` panics naming that precondition
    /// (§Core data model totality).
    pub fn type_slice(&self, ty: &Endset, view: View) -> OrdSet<Address> {
        let class = coverage_class(ty);
        self.type_slice_class(&class, view).map(lift).collect()
    }

    // ───────────────────────── internal helpers ─────────────────────────

    /// The whole-store scan under a view: every link `keep` admits, as
    /// addresses in M1's order. The ONE place `links` is walked end to end,
    /// and the ONE place a STORE SCAN turns `Default` into `Active`, so
    /// [`LinkState::stab`] and [`LinkState::match_links`]' unconstrained
    /// branch cannot answer differently about a view. (The typed reads make
    /// the same conversion at their own one place, the slice walk.)
    fn scan(&self, view: View, keep: impl Fn(&Link) -> bool) -> OrdSet<Address> {
        let active = default_to_active(view) == View::Active;
        let mut out = OrdSet::new();
        for (addr, link) in self.links.iter() {
            if active && self.nullified(addr) {
                continue;
            }
            if keep(link) {
                out.insert(lift(addr));
            }
        }
        out
    }

    /// The typed slice by class, as a LAZY walk of the audit hint: active =
    /// audit ∖ nullified, decided per element at query time (the indexes are
    /// append-only — Active/audit indexing open decision, default taken).
    ///
    /// Lazy because nearly every caller wants a walk or a boolean, not a
    /// container: materializing the `Active` view means a fresh persistent
    /// tree plus a deep clone of every `Tumbler` in it, and `is_filtered`
    /// pays that once per result element of `members`/`targets_of` under
    /// `View::Default`. The one caller that genuinely returns a set —
    /// [`LinkState::type_slice`] — collects here, where the copy is visible.
    ///
    /// Takes `view` RAW and applies [`default_to_active`] here — the one
    /// place a slice read turns `Default` into `Active`, so a caller that
    /// also honors `Default` result-side (`members`/`targets_of`) reads its
    /// own `view` for that and hands this the same value unaltered.
    ///
    /// The `_class` suffix is the module's: the same question as
    /// [`LinkState::type_slice`], keyed by class rather than by endset. The
    /// two differ in shape as well — this hands back a walk, that one
    /// collects — so a caller wanting a set says so at its own site.
    pub(crate) fn type_slice_class<'a>(
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

    /// BH1's filter DOMAIN: the addresses every active shipped `Retired`
    /// tuple's F DENOTES. Denotation, so a non-unit-depth span in a `Retired`
    /// F contributes no root — the managed surface cannot build one (`emit`
    /// forces `enc({from})`), the open surface can.
    ///
    /// Lazy, so a single probe still short-circuits at the first root that
    /// covers it; collectable, so a read that filters MANY probes derives the
    /// domain once instead of re-walking the slice — and re-deriving each
    /// root's span — per result element.
    pub(crate) fn retired_roots(&self) -> impl Iterator<Item = &Tumbler> + '_ {
        let retired = self.shipped_class(ShippedType::Retired);
        self.type_slice_class(retired, View::Active)
            .flat_map(move |t| self.link_at(t).from_slot().addrs())
    }

    /// The result-side BH1 rewrite, whole: a denoted result set lifted to
    /// addresses, minus the filtered ones under `View::Default`. Two rules and
    /// one judgement, stated once for the two reads (`members`/`targets_of`)
    /// that honor them.
    ///
    /// The rules are BH1's Rewrite scope, which confines `Default` = active ∖
    /// filtered to those two reads, and the `J ≠ K'` exclusion, which stops
    /// the shipped filter class from subtracting itself. The judgement is that
    /// the filter DOMAIN is derived ONCE for the whole result rather than once
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
            view == View::Default && *class != *self.shipped_class(ShippedType::Retired);
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

    /// The v1 walk-serving scope (§5): the walk family serves the shipped
    /// `Supersedes` class and no other. The one statement of the rule
    /// `succs`/`chain`/`tip` apply, and the read-side half of the build-time
    /// fence `RegistryError::UnservedWalk` holds up — both lift together when
    /// the parameterized multi-BH2 path lands.
    ///
    /// Also the walk family's ONE classification site, so their shared `ty`
    /// precondition has one origin: [`coverage_class`] is total on the
    /// address-denoting and `iextent`-built endsets those ops document, and
    /// panics naming that precondition on anything else.
    fn serves_walk(&self, ty: &Endset) -> bool {
        coverage_class(ty) == *self.shipped_class(ShippedType::Supersedes)
    }

    /// Whether `x` is a SINK — successor-free in the operative graph: `x` has
    /// no edges at all, or every edge out of it carries a nullified claim.
    /// Answered without building `succ_o(x)`: the Df-SUCC filter is the same
    /// one [`LinkState::succs_operative`] applies, and deduplicating the
    /// survivors over `new` cannot change whether there are any, so the raw
    /// edge set decides it. [`LinkState::current`] asks only whether a
    /// reached node is a sink; the walk, which needs the successors
    /// themselves, builds them.
    pub(crate) fn is_sink(&self, x: &Tumbler) -> bool {
        self.hints
            .sup_fwd
            .get(x)
            .is_none_or(|edges| edges.iter().all(|e| self.nullified(&e.claim)))
    }

    /// Operative successor set `succ_o(x)` — `sup_fwd[x]` filtered to edges
    /// whose CLAIM is unnullified (Df-SUCC), deduplicated over `new`.
    pub(crate) fn succs_operative(&self, x: &Tumbler) -> OrdSet<Tumbler> {
        match self.hints.sup_fwd.get(x) {
            None => OrdSet::new(),
            Some(edges) => edges
                .iter()
                .filter(|e| !self.nullified(&e.claim))
                .map(|e| e.new.clone())
                .collect(),
        }
    }

    /// Operative `out(x)` for EVERY vertex `x` in `vertices`, paired with it
    /// and in claim-address order — the reverse of
    /// [`LinkState::succs_operative`], which reads the forward `sup_fwd` hint.
    /// This direction has no hint, so it is answered for a SET in one walk of
    /// the active claim slice rather than re-walked per vertex:
    /// [`LinkState::current`] asks it of every sink it reaches, and a
    /// per-vertex form makes that quadratic in a store whose claim count a
    /// caller chooses.
    ///
    /// Matched by DENOTATION, the claim schema's own regime — a claim's `new`
    /// is a single denoted address (Df-DISC(ii)), so `g == x` IS the
    /// relation, total over every argument and needing no precondition. The
    /// vertices are link addresses, never coverage probes: the spanfilade's
    /// overlap would agree on one, where the `dom(L)` prefix antichain (R0a)
    /// makes the two coincide, and would answer with every claim beneath a
    /// document- or account-level argument.
    ///
    /// Vertices come back ASCENDING, deduplicated, whatever order they arrived
    /// in — sorted here rather than asked of the caller, so the binary search
    /// the walk does is sound by construction.
    pub(crate) fn out_claims(&self, vertices: Vec<Tumbler>) -> Vec<(Tumbler, Vec<Address>)> {
        let mut out: Vec<(Tumbler, Vec<Address>)> =
            vertices.into_iter().map(|t| (t, Vec::new())).collect();
        out.sort_by(|(a, _), (b, _)| a.cmp(b));
        out.dedup_by(|(a, _), (b, _)| a == b);
        for claim in
            self.type_slice_class(self.shipped_class(ShippedType::Supersedes), View::Active)
        {
            for g in self.link_at(claim).to_slot().addrs() {
                if let Ok(i) = out.binary_search_by(|(t, _)| t.cmp(g)) {
                    out[i].1.push(lift(claim));
                }
            }
        }
        out
    }

    /// The visited-set-bounded forward walk: the traversed path (from `x`,
    /// inclusive) and `Some(sink)` iff halted at a successor-free node
    /// (branch and cycle yield `None`).
    fn walk_sup(&self, x: &Tumbler) -> (Vec<Tumbler>, Option<Tumbler>) {
        let mut path = vec![x.clone()];
        let mut visited = OrdSet::unit(x.clone());
        let mut node = x.clone();
        loop {
            let succs = self.succs_operative(&node);
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

    /// `target_of` by class (shared with `targets_keyed`, whose registry walk
    /// has classes, not endsets). Walks the active typed slice and applies
    /// the denotation test directly: "exactly one" is a property of the set,
    /// not of the iteration order, so no prefilter is wanted — and a
    /// whole-store span scan to narrow a hint lookup would cost more than the
    /// walk it replaced.
    fn target_of_class(&self, class: &CoverageClass, source: &Address) -> Option<Address> {
        let mut survivor: Option<&Tumbler> = None;
        for t in self.type_slice_class(class, View::Active) {
            let link = self.link_at(t);
            if link.from_slot().addrs().any(|f| f == source.tumbler()) {
                if survivor.is_some() {
                    return None; // several active type-ty matches ⇒ ⊥
                }
                survivor = Some(t);
            }
        }
        self.link_at(survivor?)
            .to_slot()
            .single_denoted()
            .cloned()
            .map(lift_denoted)
    }
}
