//! §B — the immutable, construction-time type registry: shape/idempotence/
//! behavior registration per coverage class, validated once at genesis
//! ([`TypeRegistry::build`]) and never mutated (P1/P2 of ASN-0126, R1/R2 of
//! ASN-0128 — no mutator exists).

use std::slice;

use im::OrdSet;
use serde::{Deserialize, Serialize};
use skep_address::{Address, Level};

use crate::endset::{coverage_class, enc, is_address_denoting, CoverageClass, Endset};
use crate::{s_c, s_l};

/// A registered type's tuple shape (ASN-0126 P3): span-count conformance is
/// `|F| = 1` always, `|G|` per shape — Unary 0, Binary 1, Multi finite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Shape {
    Unary,
    Binary,
    Multi,
}

/// The four behavior atoms BH1–BH4 (ASN-0128). `Ord` so the set backs
/// `im::OrdSet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Behavior {
    /// BH1 — read-filter (⇒ Unary).
    ReadFilter,
    /// BH2 — walk (⇒ Binary).
    Walk,
    /// BH3 — reverse lookup (⇒ Binary).
    ReverseLookup,
    /// BH4 — age/staleness (⇒ idem = ⊥, any shape).
    Age,
}

/// One type's registration: shape, idempotence flag, behavior set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registration {
    pub shape: Shape,
    pub idem: bool,
    pub behaviors: OrdSet<Behavior>,
}

/// An app-declared type; `key` names the coverage class (address-denoting by
/// [`TypeRegistry::build`]'s key-denotation clause).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeDecl {
    pub key: Endset,
    pub reg: Registration,
}

/// The five reserved type addresses — parameters in the manner of `s_C`/`s_L`.
/// `pred_def`/`pred_stable` are M9-coordinated addresses; their `Unary/⊤/{}`
/// registrations are the PredLayer registration agreement — the companion
/// M7↔M9 build-time coordination point, an M9-negotiated constant, never a
/// local M7 edit (§B).
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// on the serializable `Addrs` class — §B).
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
/// serializable build inputs (`reserved` + `decls`) are the authoritative
/// state and `LinkState::rebuild_derived` reconstructs this before replay.
#[derive(Debug, Clone)]
pub struct TypeRegistry {
    pub(crate) map: im::HashMap<CoverageClass, Registration>,
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

/// The empty registry — exists ONLY so serde can seed `LinkState`'s
/// `#[serde(skip)] registry` field on deserialize; `rebuild_derived` replaces
/// it from `reserved`+`decls` BEFORE replay, so it is never consulted live.
impl Default for TypeRegistry {
    fn default() -> TypeRegistry {
        let empty_class = coverage_class(&Endset::empty());
        TypeRegistry {
            map: im::HashMap::new(),
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
        }
    }
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
    /// computation, keeping `coverage_class` on the safe `Addrs` path) →
    /// `ReservedClassClash` → `KeyCollision` → `BadBehavior` →
    /// `UnservedWalk` → `UnservedSecondFilter`.
    pub fn build(reserved: ReservedAddrs, decls: Vec<TypeDecl>) -> Result<TypeRegistry, RegistryError> {
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
            let ss = addr
                .subspace()
                .expect("an Element-level address carries a subspace (T7)");
            if *ss == s_c() || *ss == s_l() {
                return Err(RegistryError::ReservedSubspaceClash);
            }
        }

        let key_of = |a: &Address| enc(slice::from_ref(a));
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

        let unary_top = |behaviors: OrdSet<Behavior>| Registration {
            shape: Shape::Unary,
            idem: true,
            behaviors,
        };
        let shipped: [(&CoverageClass, Registration); 5] = [
            (&retired_class, unary_top(OrdSet::unit(Behavior::ReadFilter))),
            (
                &supersedes_class,
                Registration {
                    shape: Shape::Binary,
                    idem: true,
                    behaviors: OrdSet::unit(Behavior::Walk),
                },
            ),
            (
                &retraction_class,
                Registration {
                    shape: Shape::Binary,
                    idem: true,
                    behaviors: OrdSet::new(),
                },
            ),
            // The PredLayer registration agreement (M7↔M9 constant, §B).
            (&pred_def_class, unary_top(OrdSet::new())),
            (&pred_stable_class, unary_top(OrdSet::new())),
        ];

        let mut map: im::HashMap<CoverageClass, Registration> = im::HashMap::new();
        let mut shipped_classes: Vec<CoverageClass> = Vec::with_capacity(5);
        for (class, reg) in shipped {
            if map.contains_key(class) {
                return Err(RegistryError::KeyCollision);
            }
            shipped_classes.push(class.clone());
            map.insert(class.clone(), reg);
        }

        for d in &decls {
            if d.key.is_empty() {
                return Err(RegistryError::EmptyKey);
            }
            if !is_address_denoting(&d.key) {
                return Err(RegistryError::NonAddressDenotingKey);
            }
            let class = coverage_class(&d.key);
            if shipped_classes.contains(&class) {
                return Err(RegistryError::ReservedClassClash);
            }
            if map.contains_key(&class) {
                return Err(RegistryError::KeyCollision);
            }
            let b = &d.reg.behaviors;
            let bad = (b.contains(&Behavior::ReadFilter) && d.reg.shape != Shape::Unary)
                || (b.contains(&Behavior::Walk) && d.reg.shape != Shape::Binary)
                || (b.contains(&Behavior::ReverseLookup) && d.reg.shape != Shape::Binary)
                || (b.contains(&Behavior::Age) && d.reg.idem);
            if bad {
                return Err(RegistryError::BadBehavior);
            }
            if b.contains(&Behavior::Walk) {
                return Err(RegistryError::UnservedWalk);
            }
            if b.contains(&Behavior::ReadFilter) {
                return Err(RegistryError::UnservedSecondFilter);
            }
            map.insert(class, d.reg.clone());
        }

        Ok(TypeRegistry {
            map,
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

    /// Internal lookup: the registration of a coverage class, if registered.
    pub fn registration(&self, class: &CoverageClass) -> Option<&Registration> {
        self.map.get(class)
    }

    /// The genesis-fixed type endset for a shipped class (M9 reads
    /// PredDef/PredStable through `LinkState::reserved_type`, which delegates
    /// here).
    pub fn reserved(&self, t: ShippedType) -> &Endset {
        match t {
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
    pub(crate) fn shipped_class(&self, t: ShippedType) -> &CoverageClass {
        match t {
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
        let registry = TypeRegistry::build(
            ReservedAddrs {
                pred_def: ra(1),
                pred_stable: ra(2),
                retired: ra(3),
                supersedes: ra(4),
                retraction: ra(5),
            },
            vec![],
        )
        .expect("the reserved addresses are element-level outside {s_C, s_L}");
        for t in [
            ShippedType::Retired,
            ShippedType::Supersedes,
            ShippedType::Retraction,
            ShippedType::PredDef,
            ShippedType::PredStable,
        ] {
            assert_eq!(*registry.shipped_class(t), coverage_class(registry.reserved(t)));
            // ...and each is registered under exactly that class.
            assert!(registry.registration(registry.shipped_class(t)).is_some());
        }
    }
}
