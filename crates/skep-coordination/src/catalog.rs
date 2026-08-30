//! §Core data model — the type catalog: a frozen projection of the ONE
//! engine-built `TypeRegistry` (M9 never rebuilds it — Conflicts §7), keyed by
//! the verbatim type-key endset so a lookup both authorizes a `TypeKey` and
//! yields its PRECOMPUTED `CoverageClass` — M9 never calls M7's
//! `coverage_class` on unvalidated input. A cached copy of genesis-immutable
//! data (R1): it never goes stale. The registry's population is the compiled
//! shipped five (owner ruling, 2026-08-26 — the app-decl seam is deleted), so
//! the projection reads everything from the registry itself and there is no
//! twice-passed configuration left to drift.

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
    /// Shipped endsets, indexed [Retired, Supersedes, Retraction, PredDef,
    /// PredStable].
    shipped: [Endset; 5],
    /// Φ — the cataloged BH1 classes (class, verbatim key endset), for the UV
    /// default-view per-type filter (`is_k(J, ·) ≡ is_filtered_J`, D2).
    bh1: Vec<(CoverageClass, Endset)>,
    /// The BH3-attached Binary classes (targets_keyed's footprint) — empty in
    /// this format: no shipped registration declares ReverseLookup.
    bh3: Vec<CoverageClass>,
    pub(crate) retraction_class: CoverageClass,
    pub(crate) supersedes_key: TypeKey,
    pub(crate) pred_def_class: CoverageClass,
    pub(crate) pred_stable_class: CoverageClass,
}

const SHIPPED: [ShippedType; 5] = [
    ShippedType::Retired,
    ShippedType::Supersedes,
    ShippedType::Retraction,
    ShippedType::PredDef,
    ShippedType::PredStable,
];

impl TypeCatalog {
    /// The projection, a pure read of the injected registry: each shipped
    /// class's endset, class and registration, in `ShippedType` declaration
    /// order. Infallible — under the retired `GenesisConfig` seam this was
    /// validate-once-or-fail over a twice-passed `(reserved, decls)` pair;
    /// with the five values compiled into the registry itself there is no
    /// second copy to disagree, and genesis seeds every shipped class, so
    /// the registration lookups cannot miss (the `expect` states that).
    pub(crate) fn project(registry: &TypeRegistry) -> TypeCatalog {
        let mut map: HashMap<TypeKey, CatalogEntry> = HashMap::new();
        let mut order: Vec<TypeKey> = Vec::new();
        let mut shipped_endsets: Vec<Endset> = Vec::with_capacity(5);

        for t in SHIPPED {
            let e = registry.reserved_type(t).clone();
            let class = coverage_class(&e);
            let reg = registry
                .registration(&class)
                .expect("genesis seeds every shipped class (TypeRegistry::build)");
            let key = TypeKey(e.clone());
            shipped_endsets.push(e);
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
                    .then(|| e.class.clone())
            })
            .collect();

        let class_of = |i: usize| coverage_class(&shipped_endsets[i]);
        TypeCatalog {
            retraction_class: class_of(2),
            supersedes_key: TypeKey(shipped_endsets[1].clone()),
            pred_def_class: class_of(3),
            pred_stable_class: class_of(4),
            shipped: [
                shipped_endsets[0].clone(),
                shipped_endsets[1].clone(),
                shipped_endsets[2].clone(),
                shipped_endsets[3].clone(),
                shipped_endsets[4].clone(),
            ],
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
        match t {
            ShippedType::Retired => &self.shipped[0],
            ShippedType::Supersedes => &self.shipped[1],
            ShippedType::Retraction => &self.shipped[2],
            ShippedType::PredDef => &self.shipped[3],
            ShippedType::PredStable => &self.shipped[4],
        }
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

    /// The BH3-attached Binary classes.
    pub(crate) fn bh3(&self) -> &[CoverageClass] {
        &self.bh3
    }

    /// V-atom: `targets_keyed` is in the vocabulary iff some cataloged class
    /// attaches BH3 — none does in this format, so the atom is out of the
    /// vocabulary on every board.
    pub(crate) fn has_bh3(&self) -> bool {
        !self.bh3.is_empty()
    }
}
