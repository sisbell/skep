//! §Core data model — the type catalog: a frozen projection of the ONE
//! engine-built `TypeRegistry` (M9 never rebuilds it — Conflicts §7), keyed by
//! the verbatim type-key endset so a lookup both authorizes a `TypeKey` and
//! yields its PRECOMPUTED `CoverageClass` — M9 never calls M7's
//! `coverage_class` on unvalidated input. A cached copy of genesis-immutable
//! data (R1): it never goes stale.

use std::collections::HashMap;

use skep_links::{
    coverage_class, enc, Behavior, CoverageClass, Endset, Registration, ReservedAddrs, Shape,
    ShippedType, TypeDecl, TypeRegistry,
};

use crate::ast::TypeKey;
use crate::error::CatalogError;

/// One cataloged class: its precomputed coverage class and its registration
/// (the injected registry's truth, not the decl's copy).
#[derive(Debug, Clone)]
pub(crate) struct CatalogEntry {
    pub(crate) class: CoverageClass,
    pub(crate) reg: Registration,
}

/// The frozen catalog. `order` fixes the deterministic `Reg`-expansion class
/// order (shipped types in `ShippedType` declaration order, then app decls in
/// submission order).
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
    /// The BH3-attached Binary classes (targets_keyed's footprint).
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
    /// VALIDATE-ONCE-OR-FAIL projection (mirroring genesis): each
    /// `enc(&[reserved.X])` must be coverage-equal to the injected registry's
    /// own `reserved_type(X)` (else `ReservedMismatch(X)`), and each `decls` key
    /// must hold a registration in that registry (else
    /// `DeclNotInRegistry(key)`) — residual drift of the twice-passed
    /// `(reserved, decls)` is caught at assembly, never as a spurious
    /// `UnregisteredType` at type-check.
    pub(crate) fn project(
        registry: &TypeRegistry,
        reserved: &ReservedAddrs,
        decls: &[TypeDecl],
    ) -> Result<TypeCatalog, CatalogError> {
        let addr_of = |t: ShippedType| match t {
            ShippedType::Retired => &reserved.retired,
            ShippedType::Supersedes => &reserved.supersedes,
            ShippedType::Retraction => &reserved.retraction,
            ShippedType::PredDef => &reserved.pred_def,
            ShippedType::PredStable => &reserved.pred_stable,
        };

        let mut map: HashMap<TypeKey, CatalogEntry> = HashMap::new();
        let mut order: Vec<TypeKey> = Vec::new();
        let mut shipped_endsets: Vec<Endset> = Vec::with_capacity(5);

        for t in SHIPPED {
            let e = enc([addr_of(t)]);
            let class = coverage_class(&e);
            // Coverage-equality against the registry's own reserved endset —
            // the drift check (byte-identical in fact, both enc of one addr,
            // but only coverage-equality is required: M7 identifies a type
            // by coverage, I0).
            if class != coverage_class(registry.reserved_type(t)) {
                return Err(CatalogError::ReservedMismatch(t));
            }
            let Some(reg) = registry.registration(&class) else {
                // Genesis seeds every shipped class; absence means the
                // injected registry is not the genesis one.
                return Err(CatalogError::ReservedMismatch(t));
            };
            let key = TypeKey(e.clone());
            shipped_endsets.push(e);
            order.push(key.clone());
            map.insert(key, CatalogEntry { class, reg: reg.clone() });
        }

        for d in decls {
            // Pre-checked address-denoting, keeping the coverage_class probe
            // total: a non-denoting key cannot hold a genesis registration.
            if !d.key.is_address_denoting() {
                return Err(CatalogError::DeclNotInRegistry(TypeKey(d.key.clone())));
            }
            let class = coverage_class(&d.key);
            let Some(reg) = registry.registration(&class) else {
                return Err(CatalogError::DeclNotInRegistry(TypeKey(d.key.clone())));
            };
            let key = TypeKey(d.key.clone());
            if !map.contains_key(&key) {
                order.push(key.clone());
                map.insert(key, CatalogEntry { class, reg: reg.clone() });
            }
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
        let catalog = TypeCatalog {
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
        };
        Ok(catalog)
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
    /// attaches BH3.
    pub(crate) fn has_bh3(&self) -> bool {
        !self.bh3.is_empty()
    }
}
