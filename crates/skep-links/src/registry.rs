//! §B — the immutable, construction-time type registry: shape/idempotence/
//! behavior registration per coverage class, validated once at genesis
//! ([`TypeRegistry::build`]) and never mutated (P1/P2 of ASN-0126, R1/R2 of
//! ASN-0128 — no mutator exists).

use std::collections::BTreeSet;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use skep_address::{content_subspace, link_subspace, Address, Level};

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
/// the two serving fences buy and it is not the same as "declared ⇒ consulted".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Behavior {
    /// BH1 — ASN-0128's `ReadFilter` (⇒ Unary). CONFERS `is_filtered` and the
    /// result-side `View::Default` rewrite. GATES NOTHING at read time: v1's
    /// `is_filtered` is type-less, reading the shipped `Retired` class
    /// directly, and an app declaration is refused at build
    /// (`UnservedSecondFilter`), so this declaration exists on exactly one
    /// registration and no read consults it.
    ReadFilter,
    /// BH2 — ASN-0128's `DeterminateWalk` (⇒ Binary), and DETERMINACY is the
    /// half of that name the variant drops: the walk it confers halts at a
    /// branch or a cycle rather than choosing, which is what `Tip`'s
    /// `Indeterminate` reports the absence of. CONFERS `succs`, `chain`,
    /// `tip`, `is_in_chain`. GATES NOTHING at read time: the walk-scope test
    /// compares against the shipped `Supersedes` CLASS, and an app declaration
    /// is refused at build (`UnservedWalk`).
    Walk,
    /// BH3 — ASN-0128's `TypedReverseLookup` (⇒ Binary). CONFERS `sources_to`,
    /// `target_of`, `targets_keyed`. Of those, `targets_keyed` alone consults
    /// the declaration (through `reverse_lookup_classes`); `sources_to` and
    /// `target_of` answer for any registered class, declared or not.
    ReverseLookup,
    /// BH4 — ASN-0128's `AgeStaleness` (⇒ idem = ⊥, any shape). CONFERS `age`,
    /// `stale`, `retract_stale`. GATES `stale` — and so `retract_stale`, which
    /// builds its batch from it — and NOT `age`, which reads no registration
    /// and answers for any resident link. The `Age` half of the corpus name is
    /// the ungated one; the `Staleness` half is the gate.
    Age,
}

/// One type's registration: shape, idempotence flag, behavior set. A `std`
/// `BTreeSet` over a four-variant `Copy` enum — an app declaring a type
/// constructs this, and the registration is immutable after
/// [`TypeRegistry::build`], so there are no persistent updates to share and
/// nothing here is worth a third-party collection in an app's manifest. The
/// per-fold sharing the design asks for is one level up, on
/// [`crate::LinkState`]'s `Arc<TypeConfig>`.
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

/// An app-declared type; `key` names the coverage class (address-denoting by
/// [`TypeRegistry::build`]'s key-denotation clause).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeDecl {
    pub key: Endset,
    pub reg: Registration,
}

/// The five reserved type addresses — parameters in the manner of `s_C`/`s_L`.
/// `pred_def`/`pred_stable` are M9-coordinated addresses; their `Unary/⊤/{}`
/// registrations are the PredLayer registration agreement — the companion
/// M7↔M9 build-time coordination point, an M9-negotiated constant, never a
/// local M7 edit (§B).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// The TYPE CONFIGURATION: the reserved type addresses the substrate ships
/// and the types an app declares — [`TypeRegistry::build`]'s whole input, and
/// the authoritative genesis state [`crate::LinkState`] seals, checkpoints and
/// re-validates at load.
///
/// One declaration is a [`TypeDecl`], the configuration is this, the validated
/// lookup is [`TypeRegistry`]. The three are one chain, and it is the middle
/// link that every seam names: a caller builds one configuration, seals it
/// once, and hands the same value to every registry consumer, so the halves
/// cannot arrive matched at one door and mismatched at the next.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeConfig {
    /// The five M7↔M9 build-time constants.
    pub reserved: ReservedAddrs,
    /// App-declared types, validated once at [`TypeRegistry::build`].
    pub decls: Vec<TypeDecl>,
}

/// [`TypeRegistry::build`] rejection. `UnservedWalk` and
/// `UnservedSecondFilter` are the v1 serving fence (§B), making "declared ⇒
/// served" a build-time property — without them an app-declared
/// Walk/ReadFilter behavior would be admitted and then silently unserved by
/// the v1 read surface. Both rejections lift when the parameterized
/// multi-BH1/multi-BH2 paths land (Open build decisions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    /// C0 key uniqueness: two keys (shipped or app) share a coverage class.
    KeyCollision,
    /// C0 non-empty representatives: an app key is `⟨⟩`.
    EmptyKey,
    /// R-C0 behavior↔shape compatibility violated: BH1 ⇒ Unary, BH2 ⇒
    /// Binary, BH3 ⇒ Binary, BH4 ⇒ idem = ⊥.
    BadBehavior,
    /// R-C1: an app key is coverage-equal to a reserved shipped class.
    ReservedClassClash,
    /// Reserved-isolation: a `ReservedAddrs` entry is not element-level with
    /// `subspace ∉ {s_C, s_L}` (§Core data model — the no-collision guarantee
    /// Conflicts §1 leans on).
    ReservedSubspaceClash,
    /// Key-denotation: a `TypeDecl.key` is not address-denoting (keeps
    /// `coverage_class` on level-uniform keys AND every idem⊤ dedup `LockKey`
    /// on the serializable denoted class — §B).
    NonAddressDenotingKey,
    /// v1 serving fence: an app-declared BH2 Walk is rejected — only the
    /// shipped Supersedes walk is served (§5).
    UnservedWalk,
    /// v1 serving fence: an app-declared BH1 ReadFilter is rejected — the
    /// type-less `is_filtered` serves ONE filter, the shipped Retired (§7).
    UnservedSecondFilter,
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            RegistryError::KeyCollision => "registry: two type keys share one coverage class (C0)",
            RegistryError::EmptyKey => "registry: an app type key is the empty endset (C0)",
            RegistryError::BadBehavior => {
                "registry: behavior↔shape compatibility violated (R-C0: BH1⇒Unary, BH2⇒Binary, BH3⇒Binary, BH4⇒idem⊥)"
            }
            RegistryError::ReservedClassClash => {
                "registry: an app key is coverage-equal to a reserved shipped class (R-C1)"
            }
            RegistryError::ReservedSubspaceClash => {
                "registry: a reserved type address is not element-level outside {s_C, s_L} (reserved-isolation)"
            }
            RegistryError::NonAddressDenotingKey => {
                "registry: a type key is not address-denoting (key-denotation clause)"
            }
            RegistryError::UnservedWalk => {
                "registry: app-declared Walk rejected — v1 serves the walk family only for the shipped Supersedes class"
            }
            RegistryError::UnservedSecondFilter => {
                "registry: app-declared ReadFilter rejected — v1's type-less is_filtered serves one filter (shipped Retired)"
            }
        })
    }
}

impl std::error::Error for RegistryError {}

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
/// than one its callers re-derive. RECOMPUTABLE — keyed by the
/// non-`Serialize` [`CoverageClass`], so it never rides a checkpoint; the
/// serializable [`TypeConfig`] it was built from is the authoritative state
/// and `LinkState::rebuild_derived` reconstructs this before replay.
///
/// INVARIANT, established by [`TypeRegistry::build`], its sole VALIDATING
/// constructor: the five shipped classes are pairwise distinct
/// (`KeyCollision` refuses a duplicate reserved address), each is registered,
/// and `shipped_class(t)` is the class of `reserved_type(t)`. Every guard
/// that recognizes a deposit by its class, and every read that compares one
/// against a shipped class, leans on all three.
///
/// ONE value holds none of it, and it is crate-private and unreachable live:
/// `placeholder_registry` is the serde seed for
/// [`crate::LinkState`]'s skipped field, which
/// [`LinkState::rebuild_derived`](crate::LinkState::rebuild_derived) replaces
/// from the sealed [`TypeConfig`] BEFORE replay. So every registry a caller
/// can reach through the published surface is one `build` validated.
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
/// here and has no other caller: `rebuild_derived` replaces it from the
/// sealed [`TypeConfig`] BEFORE replay, so it is never consulted live. Not a
/// `Default` impl — the type publishes one constructor, and a second one
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
    /// Validate-once-or-fail — the registry's ONLY write point (§B). Seeds
    /// the five shipped types (each `key = enc({reserved.<addr>})`) BEFORE
    /// app decls: note-pinned `Retired = Unary/⊤/{ReadFilter}` (ASN-0128 S1),
    /// `Supersedes = Binary/⊤/{Walk}` (S2), `Retraction = Binary/⊤/{}` (S3),
    /// and the PredLayer registration agreement `PredDef = PredStable =
    /// Unary/⊤/{}` (an M9-negotiated constant, §B).
    ///
    /// Realized check order (pinned here; the design lists the clauses
    /// without an order): reserved-isolation over the five addresses; shipped
    /// seeding (a duplicate reserved class ⇒ `KeyCollision`); then per app
    /// decl `EmptyKey` → `NonAddressDenotingKey` (BEFORE any class
    /// computation, keeping `coverage_class` on the safe denoted path) →
    /// `ReservedClassClash` → `KeyCollision` → `BadBehavior` →
    /// `UnservedWalk` → `UnservedSecondFilter`.
    /// Borrows the configuration: the shipped keys clone through [`enc`] and
    /// each app registration clones out of `decls`, so the caller keeps the
    /// config it is about to seal — `rebuild_derived` re-validates straight
    /// off the `Arc` it already holds, copying no declaration vector.
    pub fn build(config: &TypeConfig) -> Result<TypeRegistry, RegistryError> {
        let reserved = &config.reserved;
        // Reserved-isolation: element-level with subspace ∉ {s_C, s_L}, so a
        // content type class (in s_C) or a link address (in s_L) can never
        // coverage-equal a reserved class (Conflicts §1).
        for addr in [
            &reserved.pred_def,
            &reserved.pred_stable,
            &reserved.retired,
            &reserved.supersedes,
            &reserved.retraction,
        ] {
            if addr.level() != Level::Element {
                return Err(RegistryError::ReservedSubspaceClash);
            }
            let subspace = addr
                .subspace()
                .expect("an Element-level address carries a subspace (T7)");
            if *subspace == content_subspace() || *subspace == link_subspace() {
                return Err(RegistryError::ReservedSubspaceClash);
            }
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
        let mut shipped_classes: Vec<CoverageClass> = Vec::with_capacity(5);
        for (class, reg) in shipped {
            if registrations.contains_key(class) {
                return Err(RegistryError::KeyCollision);
            }
            shipped_classes.push(class.clone());
            registrations.insert(class.clone(), reg);
        }

        for decl in &config.decls {
            if decl.key.is_empty() {
                return Err(RegistryError::EmptyKey);
            }
            if !decl.key.is_address_denoting() {
                return Err(RegistryError::NonAddressDenotingKey);
            }
            let class = coverage_class(&decl.key);
            if shipped_classes.contains(&class) {
                return Err(RegistryError::ReservedClassClash);
            }
            if registrations.contains_key(&class) {
                return Err(RegistryError::KeyCollision);
            }
            let behaviors = &decl.reg.behaviors;
            let bad = (behaviors.contains(&Behavior::ReadFilter)
                && decl.reg.shape != Shape::Unary)
                || (behaviors.contains(&Behavior::Walk) && decl.reg.shape != Shape::Binary)
                || (behaviors.contains(&Behavior::ReverseLookup)
                    && decl.reg.shape != Shape::Binary)
                || (behaviors.contains(&Behavior::Age) && decl.reg.idem);
            if bad {
                return Err(RegistryError::BadBehavior);
            }
            if behaviors.contains(&Behavior::Walk) {
                return Err(RegistryError::UnservedWalk);
            }
            if behaviors.contains(&Behavior::ReadFilter) {
                return Err(RegistryError::UnservedSecondFilter);
            }
            registrations.insert(class, decl.reg.clone());
        }

        Ok(TypeRegistry {
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
        })
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
    /// shipped table above and R-C0's app-decl clause are both in view —
    /// R-C0 already forces `ReverseLookup ⇒ Binary` on every app decl, so the
    /// shape conjunct guards the shipped literals, which are seeded without
    /// passing it. Order is the table's, which `targets_keyed` keys away.
    pub(crate) fn reverse_lookup_classes(&self) -> impl Iterator<Item = &CoverageClass> + '_ {
        self.registrations
            .iter()
            .filter(|(_, reg)| {
                reg.shape == Shape::Binary && reg.behaviors.contains(&Behavior::ReverseLookup)
            })
            .map(|(class, _)| class)
    }

    /// The genesis-fixed type endset for a shipped class — for a caller
    /// holding the registry: M9's catalog projection compares each shipped
    /// class against this at assembly, and M7's own write ops read the
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

    use super::*;

    fn ra(k: u32) -> Address {
        validate(
            Tumbler::new([9, 0, 9, 0, 9, 0, 9, k].iter().map(|&c| Nat::from(c)))
                .expect("nonempty"),
        )
        .expect("T4-valid")
    }

    #[test]
    fn the_class_a_shipped_type_reports_is_the_class_of_the_endset_it_reports() {
        let registry = TypeRegistry::build(&TypeConfig {
            reserved: ReservedAddrs {
                pred_def: ra(1),
                pred_stable: ra(2),
                retired: ra(3),
                supersedes: ra(4),
                retraction: ra(5),
            },
            decls: Vec::new(),
        })
        .expect("the reserved addresses are element-level outside {s_C, s_L}");
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
