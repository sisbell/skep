//! §Core data model — the type catalog: a frozen projection of the ONE
//! engine-built `TypeRegistry` (M9 never rebuilds it — Conflicts §7), keyed by
//! the verbatim type-key endset so a lookup both authorizes a `TypeKey` and
//! yields its PRECOMPUTED `CoverageClass` — M9 never calls M7's
//! `coverage_class` on unvalidated input, and nothing in M9 consults the
//! registry after construction: every "which classes, with what behaviors"
//! question the checker, the evaluator and the analyses ask is answered
//! here. A cached copy of genesis-immutable data (R1): it never goes stale.
//! The registry's population is the compiled shipped five (owner ruling,
//! 2026-08-26 — the app-decl seam is deleted), so the projection reads
//! everything from the registry itself and there is no twice-passed
//! configuration left to drift.

use std::collections::HashMap;

use skep_links::{
    coverage_class, Behavior, CoverageClass, Endset, Registration, Shape, ShippedType,
    TypeRegistry,
};

use crate::ast::TypeKey;

/// One cataloged class: its precomputed coverage class and its registration
/// (the injected registry's truth).
#[derive(Debug, Clone)]
pub(crate) struct CatalogEntry {
    pub(crate) class: CoverageClass,
    pub(crate) reg: Registration,
}

/// The frozen catalog. `order` fixes the deterministic `Reg`-expansion class
/// order (the shipped types in `ShippedType` declaration order — the whole
/// population).
#[derive(Debug, Clone)]
pub(crate) struct TypeCatalog {
    map: HashMap<TypeKey, CatalogEntry>,
    order: Vec<TypeKey>,
    /// Shipped endsets, one per `ShippedType`, at the index [`slot`] assigns
    /// — the one function that both places and fetches.
    shipped: [Endset; 5],
    /// Φ — the cataloged BH1 classes (class, verbatim key endset), for the UV
    /// default-view per-type filter (`is_k(J, ·) ≡ is_filtered_J`, D2).
    bh1: Vec<(CoverageClass, Endset)>,
    /// The BH3-attached Binary classes (class, verbatim key endset) —
    /// `targets_keyed`'s footprint and its join. Empty in this format: no
    /// shipped registration declares ReverseLookup.
    bh3: Vec<(CoverageClass, Endset)>,
    pub(crate) retraction_class: CoverageClass,
    pub(crate) supersedes_key: TypeKey,
    pub(crate) pred_def_class: CoverageClass,
    pub(crate) pred_stable_class: CoverageClass,
}

/// The `shipped` array's index for a shipped type — used by the projection
/// to place and by [`TypeCatalog::reserved`] to fetch, so the array is
/// positionally right by construction.
fn slot(t: ShippedType) -> usize {
    match t {
        ShippedType::Retired => 0,
        ShippedType::Supersedes => 1,
        ShippedType::Retraction => 2,
        ShippedType::PredDef => 3,
        ShippedType::PredStable => 4,
    }
}

impl TypeCatalog {
    /// The projection, a pure read of the injected registry: each shipped
    /// class's endset, class and registration, walking `ShippedType::ALL`
    /// (the one enumeration of the five, in declaration order). Infallible:
    /// the five values are compiled into the registry itself, so there is
    /// no second copy to disagree, and genesis seeds every shipped class,
    /// so the registration lookups cannot miss (the `expect` states that).
    pub(crate) fn project(registry: &TypeRegistry) -> TypeCatalog {
        let mut map: HashMap<TypeKey, CatalogEntry> = HashMap::new();
        let mut order: Vec<TypeKey> = Vec::new();
        let mut shipped: [Endset; 5] = std::array::from_fn(|_| Endset::empty());

        for t in ShippedType::ALL {
            let e = registry.reserved_type(t).clone();
            let class = coverage_class(&e);
            let reg = registry
                .registration(&class)
                .expect("genesis seeds every shipped class (TypeRegistry::build)");
            let key = TypeKey(e.clone());
            shipped[slot(t)] = e;
            order.push(key.clone());
            map.insert(key, CatalogEntry { class, reg: reg.clone() });
        }

        let bh1 = order
            .iter()
            .filter_map(|k| {
                let e = &map[k];
                e.reg
                    .behaviors
                    .contains(&Behavior::ReadFilter)
                    .then(|| (e.class.clone(), k.0.clone()))
            })
            .collect();
        let bh3 = order
            .iter()
            .filter_map(|k| {
                let e = &map[k];
                (e.reg.shape == Shape::Binary && e.reg.behaviors.contains(&Behavior::ReverseLookup))
                    .then(|| (e.class.clone(), k.0.clone()))
            })
            .collect();

        // The named classes read back from the map — the precomputed class,
        // never a second classification.
        let class_at = |t: ShippedType| map[&TypeKey(shipped[slot(t)].clone())].class.clone();
        TypeCatalog {
            retraction_class: class_at(ShippedType::Retraction),
            supersedes_key: TypeKey(shipped[slot(ShippedType::Supersedes)].clone()),
            pred_def_class: class_at(ShippedType::PredDef),
            pred_stable_class: class_at(ShippedType::PredStable),
            shipped,
            map,
            order,
            bh1,
            bh3,
        }
    }

    /// The `Endset`-equality probe — authorizes the key AND yields its
    /// precomputed class (§Core data model).
    pub(crate) fn get(&self, k: &TypeKey) -> Option<&CatalogEntry> {
        self.map.get(k)
    }

    /// M9's own cached accessor over the shipped endsets (no snapshot) —
    /// distinct from M7's snapshot-bound `LinkState::reserved_type`.
    pub(crate) fn reserved(&self, t: ShippedType) -> &Endset {
        &self.shipped[slot(t)]
    }

    /// The finite, fixed class list `Reg`-expansion instantiates over
    /// (deterministic order).
    pub(crate) fn classes(&self) -> &[TypeKey] {
        &self.order
    }

    /// Φ — the cataloged BH1 set, for the UV `K_queried` self-exclusion.
    pub(crate) fn bh1(&self) -> &[(CoverageClass, Endset)] {
        &self.bh1
    }

    /// The BH3-attached Binary classes — the classes `targets_keyed` joins
    /// over, and its footprint.
    pub(crate) fn bh3(&self) -> &[(CoverageClass, Endset)] {
        &self.bh3
    }

    /// V-atom: `targets_keyed` is in the vocabulary iff some cataloged class
    /// attaches BH3 — none does in this format, so the atom is out of the
    /// vocabulary on every board.
    pub(crate) fn has_bh3(&self) -> bool {
        !self.bh3.is_empty()
    }
}
