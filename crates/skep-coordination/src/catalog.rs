//! §Core data model — the type catalog: a frozen projection of the ONE
//! engine-built `TypeRegistry` (M9 never rebuilds it — Conflicts §7), keyed by
//! the verbatim type-key endset so a lookup both authorizes a `TypeKey` and
//! yields its PRECOMPUTED `CoverageClass` — M9 never calls M7's
//! `coverage_class` at all: each shipped class is read from the registry's
//! own endset/class pairing, and nothing in M9 consults the registry after
//! construction: every "which classes, with what behaviors" question the
//! checker, the evaluator and the analyses ask is answered here. A cached
//! copy of genesis-immutable data (R1): it never goes stale. The registry's
//! population is the compiled shipped five (owner ruling, 2026-08-26 — the
//! app-decl seam is deleted), so the projection reads everything from the
//! registry itself — the classes, and the two behavior rules it publishes as
//! `declares` and `reverse_lookup_classes` — and there is no twice-passed
//! configuration and no restated rule left to drift.

use std::collections::HashMap;

use skep_links::{Behavior, CoverageClass, Endset, Registration, ShippedType, TypeRegistry};

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
    entries: HashMap<TypeKey, CatalogEntry>,
    order: Vec<TypeKey>,
    /// Shipped endsets, one per `ShippedType`, at the index [`slot`] assigns
    /// — the one function that both places and fetches. Its length is the
    /// population's own count, so a shipped type added upstream widens the
    /// array with it rather than leaving [`slot`]'s new index out of bounds.
    shipped: [Endset; ShippedType::ALL.len()],
    /// Φ — the cataloged classes declaring `ReadFilter` (class, verbatim key
    /// endset), for the UV default-view per-type filter
    /// (`is_k(J, ·) ≡ is_filtered_J`, D2 — BH1).
    read_filter: Vec<(CoverageClass, Endset)>,
    /// The classes declaring `ReverseLookup` (class, verbatim key endset) —
    /// `targets_keyed`'s footprint and its join (BH3). Empty in this format:
    /// no shipped registration declares it.
    reverse_lookup: Vec<(CoverageClass, Endset)>,
    pub(crate) retraction_class: CoverageClass,
    pub(crate) supersedes_key: TypeKey,
    pub(crate) pred_def_class: CoverageClass,
    pub(crate) pred_stable_class: CoverageClass,
}

/// The `shipped` array's index for a shipped type — used by the projection
/// to place and by [`TypeCatalog::reserved_type`] to fetch, so the array is
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
    /// (the one enumeration of the five, in declaration order). The class is
    /// the registry's own `shipped_class` — the half of its endset/class
    /// pairing fixed at build — never a classification of the endset made
    /// here. Infallible: the five values are compiled into the registry
    /// itself, so there is no second copy to disagree, and the registry
    /// registers every shipped class, so the lookups cannot miss (the
    /// `expect` states that).
    pub(crate) fn project(registry: &TypeRegistry) -> TypeCatalog {
        let mut entries: HashMap<TypeKey, CatalogEntry> = HashMap::new();
        let mut order: Vec<TypeKey> = Vec::new();
        let mut shipped: [Endset; ShippedType::ALL.len()] =
            std::array::from_fn(|_| Endset::empty());

        for t in ShippedType::ALL {
            let endset = registry.reserved_type(t).clone();
            let class = registry.shipped_class(t).clone();
            let reg = registry
                .registration(&class)
                .expect("the registry registers every shipped class (TypeRegistry::build)");
            let key = TypeKey(endset.clone());
            shipped[slot(t)] = endset;
            order.push(key.clone());
            entries.insert(key, CatalogEntry { class, reg: reg.clone() });
        }

        // The two behavior footprints are the registry's own rules, asked of
        // it rather than restated over the cached registrations: the
        // `ReadFilter` set is what `declares` answers, and the
        // `ReverseLookup` set is exactly the classes `targets_keyed` joins
        // over — so the join and the footprint analysis of what it reads
        // cannot come apart.
        let read_filter = order
            .iter()
            .filter_map(|k| {
                let entry = &entries[k];
                registry
                    .declares(&entry.class, Behavior::ReadFilter)
                    .then(|| (entry.class.clone(), k.0.clone()))
            })
            .collect();
        let reverse_lookup = order
            .iter()
            .filter_map(|k| {
                let entry = &entries[k];
                registry
                    .reverse_lookup_classes()
                    .any(|class| *class == entry.class)
                    .then(|| (entry.class.clone(), k.0.clone()))
            })
            .collect();

        // The named classes are the registry's own pairing, the same value
        // each entry above carries — never a second classification.
        let class_at = |t: ShippedType| registry.shipped_class(t).clone();
        TypeCatalog {
            retraction_class: class_at(ShippedType::Retraction),
            supersedes_key: TypeKey(shipped[slot(ShippedType::Supersedes)].clone()),
            pred_def_class: class_at(ShippedType::PredDef),
            pred_stable_class: class_at(ShippedType::PredStable),
            shipped,
            entries,
            order,
            read_filter,
            reverse_lookup,
        }
    }

    /// The `Endset`-equality probe — authorizes the key AND yields its
    /// precomputed class (§Core data model).
    pub(crate) fn get(&self, k: &TypeKey) -> Option<&CatalogEntry> {
        self.entries.get(k)
    }

    /// The precomputed class of an AUTHORIZED key — the one question every
    /// walk over a checked tree, and the rule engine over a validated Marker
    /// type, asks of the catalog. Total on such a key: it was admitted by
    /// [`TypeCatalog::get`] against this same projection, which is frozen at
    /// construction (R1), so the probe that authorized it cannot since have
    /// gone stale.
    pub(crate) fn class_of(&self, k: &TypeKey) -> &CoverageClass {
        &self
            .get(k)
            .expect("an authorized TypeKey is cataloged")
            .class
    }

    /// M9's own cached accessor over the shipped endsets (no snapshot) —
    /// distinct from M7's snapshot-bound `LinkState::reserved_type`.
    pub(crate) fn reserved_type(&self, t: ShippedType) -> &Endset {
        &self.shipped[slot(t)]
    }

    /// The finite, fixed class list `Reg`-expansion instantiates over
    /// (deterministic order).
    pub(crate) fn classes(&self) -> &[TypeKey] {
        &self.order
    }

    /// Φ — the cataloged `ReadFilter` classes (BH1), for the UV `K_queried`
    /// self-exclusion.
    pub(crate) fn read_filter_classes(&self) -> &[(CoverageClass, Endset)] {
        &self.read_filter
    }

    /// The cataloged `ReverseLookup` classes (BH3) — the classes
    /// `targets_keyed` joins over, and its footprint. The projection of the
    /// registry's own `reverse_lookup_classes`, and named for it.
    pub(crate) fn reverse_lookup_classes(&self) -> &[(CoverageClass, Endset)] {
        &self.reverse_lookup
    }

    /// V-atom: `targets_keyed` is in the vocabulary iff some cataloged class
    /// declares `ReverseLookup` (BH3) — none does in this format, so the atom
    /// is out of the vocabulary on every board.
    pub(crate) fn has_reverse_lookup_class(&self) -> bool {
        !self.reverse_lookup.is_empty()
    }
}
