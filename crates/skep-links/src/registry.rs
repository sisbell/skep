//! §B — the immutable, construction-time type registry: shape/idempotence/
//! behavior registration per coverage class, built from compiled format
//! constants at genesis ([`TypeRegistry::build`]) and never mutated (P1/P2 of
//! ASN-0126, R1/R2 of ASN-0128 — no mutator exists). The registry's
//! population is the five shipped classes and nothing else: the app-declared
//! types seam was deleted by the owner ruling of 2026-08-26 (second clause) —
//! the architecture's extension path is predicates (pdef content), not new
//! compiled substrate classes.

use std::collections::BTreeSet;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use skep_address::{content_subspace, Address, Level};
use skep_namespace::ghost_position;

use crate::endset::{coverage_class, enc, CoverageClass, Endset, Link};

/// A registered type's tuple shape (ASN-0126 P3): conformance counts the
/// stored decomposition's spans — one FROM span always, and per shape no TO
/// span (Unary), exactly one (Binary), or any finite number (Multi). That
/// count is P3's set-valued `|F|`/`|G|` on the duplicate-free endsets the
/// managed surface builds ([`Endset::len`]).
///
/// Sh-conf is a GATE ON THE MANAGED SURFACE, not an invariant of the store:
/// `emit`, `assert_sup` and `editlink`'s claim pass it; MAKELINK and an
/// `editlink` successor take the open deposit gate and are shape-blind. So a
/// stored link may sit in a registered class without conforming to that
/// class's shape, and a read over a typed slice must not assume otherwise.
/// The two classes whose STORED discipline is guaranteed are `[R]` and
/// `[K_sup]`, held by their sole-writer fences rather than by this shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Shape {
    Unary,
    Binary,
    Multi,
}

/// Sh-conf (P3): a value's SPAN COUNTS against a REGISTERED shape — the rule
/// [`Shape`] states, deciding it where the shape is declared rather than at
/// the gate that happens to consult it. Never infers a shape from the tuple
/// (a `(1,0)` tuple conforms under Unary AND Multi). Reads both counts off
/// the link itself, so they cannot arrive in the wrong order.
///
/// The counts are of the stored decomposition ([`Endset::len`]), which is
/// ASN-0126's set-valued `|F|`/`|G|` on a duplicate-free endset — every endset
/// this gate sees, since `emit` builds both slots through [`enc`] — and
/// over-counts a repeated span.
pub(crate) fn sh_conf(shape: Shape, value: &Link) -> bool {
    value.from_slot().len() == 1
        && match shape {
            Shape::Unary => value.to_slot().is_empty(),
            Shape::Binary => value.to_slot().len() == 1,
            Shape::Multi => true,
        }
}

/// The four behavior atoms of ASN-0128, whose names there are `ReadFilter`
/// (BH1), `DeterminateWalk` (BH2), `TypedReverseLookup` (BH3) and
/// `AgeStaleness` (BH4); each variant below names its own. `Ord` so the set
/// backs a `BTreeSet`.
///
/// Declaring one CONFERS a set of reads and, separately, GATES a smaller set
/// — in v1 only BH3's join and BH4's `stale` read a declaration back, the
/// other two being fixed to their shipped class and fenced at build. Each
/// variant says which is which, because "declared ⇒ served" is the property
/// the two serving fences buy and it is not the same as "declared ⇒
/// consulted". The registry's population being the shipped five (no app
/// decls exist in this format), the only declarations in force are the
/// note-pinned shipped ones — BH1 on `Retired`, BH2 on `Supersedes` — and
/// the two declaration-reading gates run over a population that declares
/// neither BH3 nor BH4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Behavior {
    /// BH1 — ASN-0128's `ReadFilter` (⇒ Unary). CONFERS `is_filtered` and the
    /// result-side `View::Default` rewrite. GATES NOTHING at read time: v1's
    /// `is_filtered` is type-less, reading the shipped `Retired` class
    /// directly, so this declaration exists on exactly one registration and
    /// no read consults it.
    ReadFilter,
    /// BH2 — ASN-0128's `DeterminateWalk` (⇒ Binary), and DETERMINACY is the
    /// half of that name the variant drops: the walk it confers halts at a
    /// branch or a cycle rather than choosing, which is what `Tip`'s
    /// `Indeterminate` reports the absence of. CONFERS `succs`, `chain`,
    /// `tip`, `is_in_chain`. GATES NOTHING at read time: the walk-scope test
    /// compares against the shipped `Supersedes` CLASS.
    Walk,
    /// BH3 — ASN-0128's `TypedReverseLookup` (⇒ Binary). CONFERS `sources_to`,
    /// `target_of`, `targets_keyed`. Of those, `targets_keyed` alone consults
    /// the declaration (through `reverse_lookup_classes`); `sources_to` and
    /// `target_of` answer for any registered class, declared or not. No
    /// shipped class declares it, so in this format `targets_keyed`'s join
    /// covers no class.
    ReverseLookup,
    /// BH4 — ASN-0128's `AgeStaleness` (⇒ idem = ⊥, any shape). CONFERS `age`,
    /// `stale`, `retract_stale`. GATES `stale` — and so `retract_stale`, which
    /// builds its batch from it — and NOT `age`, which reads no registration
    /// and answers for any resident link. The `Age` half of the corpus name is
    /// the ungated one; the `Staleness` half is the gate. No shipped class
    /// declares it (all five are idem⊤), so in this format `stale` refuses
    /// every class.
    Age,
}

/// One type's registration: shape, idempotence flag, behavior set. A `std`
/// `BTreeSet` over a four-variant `Copy` enum; every registration is seeded
/// at [`TypeRegistry::build`] from the note-pinned shipped table and is
/// immutable thereafter — there are no persistent updates to share. The
/// per-fold sharing the design asks for is one level up, on
/// [`crate::LinkState`]'s `Arc<TypeRegistry>`.
///
/// `idem` is the MANAGED SURFACE'S DEDUP DISCIPLINE, not a uniqueness
/// invariant on the class: MAKELINK deposits into a registered idem⊤ class
/// with neither the dedup lock nor the in-transaction check, so a class may
/// hold several active tuples of one I0 identity. That is why the incumbent
/// a dedup hit returns is specified as the T1-LEAST active match rather than
/// as "the one". `shape` is a gate in the same sense — see [`Shape`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    pub shape: Shape,
    pub idem: bool,
    pub behaviors: BTreeSet<Behavior>,
}

/// The five reserved type addresses — GHOST TUMBLERS, compiled format
/// constants (owner ruling, 2026-08-26; [`ReservedAddrs::format`] is the one
/// value): in-docuverse, T4-valid content positions at which nothing exists
/// and nothing is ever minted. A type is a number — the daemon's semantics
/// for the five shipped classes are compiled in, every other type means what
/// its interpreting client says it means, and no document anywhere is
/// semantically authoritative for a type.
///
/// `pred_def`/`pred_stable` are M9-coordinated addresses; their `Unary/⊤/{}`
/// registrations are the PredLayer registration agreement — the companion
/// M7↔M9 build-time coordination point, an M9-negotiated constant, never a
/// local M7 edit (§B).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservedAddrs {
    pub pred_def: Address,
    pub pred_stable: Address,
    /// `[K_ret]` — the shipped BH1 filter class.
    pub retired: Address,
    /// `[K_sup]` — the shipped BH2 walk class.
    pub supersedes: Address,
    /// `[R]` — the retraction class.
    pub retraction: Address,
}

impl ReservedAddrs {
    /// THE five values, format-frozen 2026-08-26: ghost tumblers
    /// `1.1.0.1.0.1.0.1.x` for x = 1..=5 — content positions 1–5 of doc 1 of
    /// account 1 (the operator's) of the registry node `1.1`, read verbatim
    /// from M3's [`ghost_position`] so the addresses M7 dispatches on and the
    /// region M3's allocator skips are one definition. Identical on every
    /// board because they ARE the format, not because a sealed configuration
    /// enforces agreement.
    ///
    /// Collision-freedom — "a reserved name can never equal an allocated
    /// address" — is the ALLOCATOR'S non-reissue guarantee, not subtree
    /// unreachability: the ghost content namespace's frontier is floored past
    /// the region and its membership excludes the five forever (M3's
    /// `ghost_floor` carries the argument; the old out-of-tree `9.0.9.…`
    /// space this replaces is abolished — no address space exists outside the
    /// docuverse).
    pub fn format() -> ReservedAddrs {
        ReservedAddrs {
            pred_def: ghost_position(1),
            pred_stable: ghost_position(2),
            retired: ghost_position(3),
            supersedes: ghost_position(4),
            retraction: ghost_position(5),
        }
    }
}

/// The genesis-fixed shipped classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShippedType {
    Retired,
    Supersedes,
    Retraction,
    PredDef,
    PredStable,
}

/// The immutable lookup registry: coverage class → registration, plus the
/// five genesis-fixed shipped types held BOTH ways — as the endset a caller
/// names them by and as the [`CoverageClass`] every guard, fold and read
/// recognizes them by. Both are fixed at [`TypeRegistry::build`], so the
/// class each shipped type belongs to is a fact this registry knows rather
/// than one its callers re-derive. RECOMPUTABLE from nothing but the compiled
/// format constants — keyed by the non-`Serialize` [`CoverageClass`], so it
/// never rides a checkpoint, and carrying no sealed configuration, because
/// none exists: `LinkState::rebuild_derived` reconstructs this by calling
/// `build()` again before replay.
///
/// INVARIANT, established by [`TypeRegistry::build`], its sole constructor:
/// the five shipped classes are pairwise distinct, each is registered, and
/// `shipped_class(t)` is the class of `reserved_type(t)`. Every guard that
/// recognizes a deposit by its class, and every read that compares one
/// against a shipped class, leans on all three.
///
/// ONE value holds none of it, and it is crate-private and unreachable live:
/// `placeholder_registry` is the serde seed for
/// [`crate::LinkState`]'s skipped field, which
/// [`LinkState::rebuild_derived`](crate::LinkState::rebuild_derived) replaces
/// with a fresh `build()` BEFORE replay. So every registry a caller can reach
/// through the published surface is one `build` established.
#[derive(Debug, Clone)]
pub struct TypeRegistry {
    registrations: im::HashMap<CoverageClass, Registration>,
    retired: Endset,
    supersedes: Endset,
    retraction: Endset,
    pred_def: Endset,
    pred_stable: Endset,
    retired_class: CoverageClass,
    supersedes_class: CoverageClass,
    retraction_class: CoverageClass,
    pred_def_class: CoverageClass,
    pred_stable_class: CoverageClass,
}

/// The empty registry, which holds NONE of [`TypeRegistry`]'s invariant: it
/// registers nothing, every shipped endset is `⟨⟩`, and all five shipped
/// classes are one value. It exists solely so serde can seed `LinkState`'s
/// `#[serde(skip)] registry` field on deserialize, which is why it is named
/// here and has no other caller: `rebuild_derived` replaces it with a fresh
/// [`TypeRegistry::build`] BEFORE replay, so it is never consulted live. Not
/// a `Default` impl — the type publishes one constructor, and a second one
/// that establishes nothing would be a legal way to state a fact no endset
/// has.
pub(crate) fn placeholder_registry() -> Arc<TypeRegistry> {
    let empty_class = coverage_class(&Endset::empty());
    Arc::new(TypeRegistry {
        registrations: im::HashMap::new(),
        retired: Endset::empty(),
        supersedes: Endset::empty(),
        retraction: Endset::empty(),
        pred_def: Endset::empty(),
        pred_stable: Endset::empty(),
        retired_class: empty_class.clone(),
        supersedes_class: empty_class.clone(),
        retraction_class: empty_class.clone(),
        pred_def_class: empty_class.clone(),
        pred_stable_class: empty_class,
    })
}

impl TypeRegistry {
    /// The registry's ONLY constructor (§B), a pure function of the compiled
    /// format constants: seeds the five shipped types (each
    /// `key = enc({reserved.<addr>})`) with their note-pinned registrations —
    /// `Retired = Unary/⊤/{ReadFilter}` (ASN-0128 S1), `Supersedes =
    /// Binary/⊤/{Walk}` (S2), `Retraction = Binary/⊤/{}` (S3), and the
    /// PredLayer registration agreement `PredDef = PredStable = Unary/⊤/{}`
    /// (an M9-negotiated constant, §B).
    ///
    /// Infallible: what was caller-facing input validation under the retired
    /// `GenesisConfig` seam is now a STARTUP ASSERTION over the constants — a
    /// sanity check that the five ghost tumblers are element-level content
    /// positions with pairwise-distinct classes, which can only fail if the
    /// format constants themselves are edited inconsistently. There is no
    /// caller who could be handed an `Err`, because there is no caller who
    /// chooses the input.
    pub fn build() -> TypeRegistry {
        let reserved = ReservedAddrs::format();
        // Startup assertion over the constants: each ghost tumbler is an
        // element-level CONTENT position — the in-docuverse form the 2026-08-26
        // ruling pins, and the shape M3's ghost-region floor protects. (The
        // superseded reserved-isolation clause demanded the opposite subspace;
        // its collision-freedom job now belongs to the allocator's
        // non-reissue guarantee — see `ReservedAddrs::format`.)
        for addr in [
            &reserved.pred_def,
            &reserved.pred_stable,
            &reserved.retired,
            &reserved.supersedes,
            &reserved.retraction,
        ] {
            assert_eq!(
                addr.level(),
                Level::Element,
                "a reserved type address is element-level"
            );
            assert_eq!(
                addr.subspace(),
                Some(&content_subspace()),
                "a ghost tumbler is a content position (owner ruling, 2026-08-26)"
            );
        }

        let key_of = |a: &Address| enc([a]);
        let retired = key_of(&reserved.retired);
        let supersedes = key_of(&reserved.supersedes);
        let retraction = key_of(&reserved.retraction);
        let pred_def = key_of(&reserved.pred_def);
        let pred_stable = key_of(&reserved.pred_stable);

        // Each shipped class is bound to its name where it is computed, so
        // the class this registry hands out for a `ShippedType` is that
        // type's own endset classified — never a positional coincidence.
        let retired_class = coverage_class(&retired);
        let supersedes_class = coverage_class(&supersedes);
        let retraction_class = coverage_class(&retraction);
        let pred_def_class = coverage_class(&pred_def);
        let pred_stable_class = coverage_class(&pred_stable);

        let unary_top = |behaviors: BTreeSet<Behavior>| Registration {
            shape: Shape::Unary,
            idem: true,
            behaviors,
        };
        let shipped: [(&CoverageClass, Registration); 5] = [
            (
                &retired_class,
                unary_top(BTreeSet::from([Behavior::ReadFilter])),
            ),
            (
                &supersedes_class,
                Registration {
                    shape: Shape::Binary,
                    idem: true,
                    behaviors: BTreeSet::from([Behavior::Walk]),
                },
            ),
            (
                &retraction_class,
                Registration {
                    shape: Shape::Binary,
                    idem: true,
                    behaviors: BTreeSet::new(),
                },
            ),
            // The PredLayer registration agreement (M7↔M9 constant, §B).
            (&pred_def_class, unary_top(BTreeSet::new())),
            (&pred_stable_class, unary_top(BTreeSet::new())),
        ];

        let mut registrations: im::HashMap<CoverageClass, Registration> = im::HashMap::new();
        for (class, reg) in shipped {
            // The C0 key-uniqueness half of the startup assertion: five
            // distinct constants classify to five distinct classes.
            assert!(
                !registrations.contains_key(class),
                "the five reserved format constants must be pairwise class-distinct (C0)"
            );
            registrations.insert(class.clone(), reg);
        }

        TypeRegistry {
            registrations,
            retired,
            supersedes,
            retraction,
            pred_def,
            pred_stable,
            retired_class,
            supersedes_class,
            retraction_class,
            pred_def_class,
            pred_stable_class,
        }
    }

    /// The public class → registration lookup: `Some(reg)` for a registered
    /// class, `None` for an unregistered one. [`CoverageClass`] is opaque and
    /// [`coverage_class`] is its only constructor, so every argument is some
    /// endset's actual class and `None` means unregistered — a caller holding
    /// an `Endset` classifies it first (M9 projects the shipped registrations
    /// this way; M7's own gates and reads go through the same lookup).
    pub fn registration(&self, class: &CoverageClass) -> Option<&Registration> {
        self.registrations.get(class)
    }

    /// The classes the BH3 join covers: registered `Binary` classes declaring
    /// `ReverseLookup`. Which registrations answer to a behavior is this
    /// registry's own knowledge, so the predicate reads here, where the
    /// shipped table above is in view. No shipped registration declares BH3,
    /// so over this format's fixed population the iterator is empty — kept as
    /// the one statement of the rule, not specialized to the population.
    pub(crate) fn reverse_lookup_classes(&self) -> impl Iterator<Item = &CoverageClass> + '_ {
        self.registrations
            .iter()
            .filter(|(_, reg)| {
                reg.shape == Shape::Binary && reg.behaviors.contains(&Behavior::ReverseLookup)
            })
            .map(|(class, _)| class)
    }

    /// The genesis-fixed type endset for a shipped class — for a caller
    /// holding the registry: M9's catalog projection reads each shipped
    /// class from this at assembly, and M7's own write ops read the
    /// `Retraction` and `Supersedes` endsets here to build their tuples.
    /// [`crate::LinkState::reserved_type`] is the snapshot-bound delegate, for
    /// a caller holding the slice instead.
    pub fn reserved_type(&self, ty: ShippedType) -> &Endset {
        match ty {
            ShippedType::Retired => &self.retired,
            ShippedType::Supersedes => &self.supersedes,
            ShippedType::Retraction => &self.retraction,
            ShippedType::PredDef => &self.pred_def,
            ShippedType::PredStable => &self.pred_stable,
        }
    }

    /// The coverage class of a shipped type — the recognition key the write
    /// gates, the hint fold and the read surface all compare against, fixed
    /// at build alongside the endset it classifies.
    pub(crate) fn shipped_class(&self, ty: ShippedType) -> &CoverageClass {
        match ty {
            ShippedType::Retired => &self.retired_class,
            ShippedType::Supersedes => &self.supersedes_class,
            ShippedType::Retraction => &self.retraction_class,
            ShippedType::PredDef => &self.pred_def_class,
            ShippedType::PredStable => &self.pred_stable_class,
        }
    }
}

#[cfg(test)]
mod tests {
    use skep_address::{validate, Nat, Tumbler};
    use skep_namespace::GHOST_POSITIONS;

    use super::*;

    fn ra(k: u32) -> Address {
        validate(
            Tumbler::new([1, 1, 0, 1, 0, 1, 0, 1, k].iter().map(|&c| Nat::from(c)))
                .expect("nonempty"),
        )
        .expect("T4-valid")
    }

    #[test]
    fn the_class_a_shipped_type_reports_is_the_class_of_the_endset_it_reports() {
        let registry = TypeRegistry::build();
        for ty in [
            ShippedType::Retired,
            ShippedType::Supersedes,
            ShippedType::Retraction,
            ShippedType::PredDef,
            ShippedType::PredStable,
        ] {
            assert_eq!(
                *registry.shipped_class(ty),
                coverage_class(registry.reserved_type(ty))
            );
            // ...and each is registered under exactly that class.
            assert!(registry.registration(registry.shipped_class(ty)).is_some());
        }
    }

    /// The five format constants are the ghost tumblers the ruling pins, in
    /// the ruling's own assignment order — position x of the ghost doc for
    /// x = 1..=5 — and they agree with M3's spelling of the region, so the
    /// addresses M7 dispatches on are the ones the allocator skips.
    #[test]
    fn the_format_constants_are_the_five_ghost_tumblers_in_ruling_order() {
        let reserved = ReservedAddrs::format();
        for (name, addr, x) in [
            ("pred_def", &reserved.pred_def, 1u32),
            ("pred_stable", &reserved.pred_stable, 2),
            ("retired", &reserved.retired, 3),
            ("supersedes", &reserved.supersedes, 4),
            ("retraction", &reserved.retraction, 5),
        ] {
            assert_eq!(addr, &ra(x), "{name} must sit at ghost position {x}");
            assert_eq!(addr, &skep_namespace::ghost_position(x), "{name} drifted from M3");
        }
        assert_eq!(GHOST_POSITIONS, 5, "the region has exactly the five reserved names");
    }

    #[test]
    fn sh_conf_reads_both_span_counts_against_the_declared_shape() {
        // The rule [`Shape`] states, decided where the shape is declared: one
        // FROM span always, and per shape no TO span, exactly one, or any
        // finite number. The `|F| = 1` clause is the half no write path can
        // present — `emit` forces `enc({from})` and an `editlink` successor
        // takes the open gate — so it holds here or nowhere.
        let none = Endset::empty;
        let one = || enc([&ra(1)]);
        let two = || enc([&ra(1), &ra(2)]);
        for (shape, admits) in [
            (Shape::Unary, [true, false, false]),
            (Shape::Binary, [false, true, false]),
            (Shape::Multi, [true, true, true]),
        ] {
            for (g, to) in [none(), one(), two()].into_iter().enumerate() {
                assert_eq!(
                    sh_conf(shape, &Link::triple(one(), to.clone(), one())),
                    admits[g],
                    "{shape:?} admits |G| = {g} at |F| = 1"
                );
                // A shape is never inferred from the tuple: whatever |G| does,
                // an |F| off 1 conforms to none of the three.
                for from in [none(), two()] {
                    assert!(
                        !sh_conf(shape, &Link::triple(from, to.clone(), one())),
                        "{shape:?} refuses |F| ≠ 1 at |G| = {g}"
                    );
                }
            }
        }
    }
}
