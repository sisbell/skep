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

use skep_links::{
    Behavior, CoverageClass, Endset, Registration, Shape, ShippedType, TypeRegistry,
};

use crate::ast::TypeKey;

/// One cataloged class: its precomputed coverage class, handed out, and its
/// registration — the injected registry's truth, which it ANSWERS questions
/// about rather than exposes, so a collaborator names the property it needs
/// instead of knowing how a `Registration` records one.
#[derive(Debug, Clone)]
pub(crate) struct CatalogEntry {
    pub(crate) class: CoverageClass,
    registration: Registration,
}

impl CatalogEntry {
    /// Does the class's registration declare this behavior? V-STAT's test,
    /// and M7's own question (`TypeRegistry::declares`) asked of the frozen
    /// projection — so the checker names the behavior it needs.
    pub(crate) fn declares(&self, behavior: Behavior) -> bool {
        self.registration.behaviors.contains(&behavior)
    }

    /// Is the class Unary — `emit`'s shape, which a Marker action's tuple
    /// must be (`register_rule`'s `BadMarkerType`)?
    pub(crate) fn is_unary(&self) -> bool {
        self.registration.shape == Shape::Unary
    }

    /// Is the class idem⊤? What the fire executor's gap dedup-absorption and
    /// the Q3/I1a extinction analysis both require of a Marker type
    /// (`register_rule`'s `NonIdemMarkerType`).
    pub(crate) fn is_idem(&self) -> bool {
        self.registration.idem
    }
}

/// The frozen catalog. `order` fixes the deterministic `Reg`-expansion class
/// order (the shipped types in `ShippedType` declaration order — the whole
/// population).
#[derive(Debug, Clone)]
pub(crate) struct TypeCatalog {
    entries: HashMap<TypeKey, CatalogEntry>,
    order: Vec<TypeKey>,
    /// Shipped endsets, one per `ShippedType`, at the index
    /// [`shipped_index`] assigns — the one function that both places and
    /// fetches. Its length is the population's own count, so a shipped type
    /// added upstream widens the array with it rather than leaving
    /// [`shipped_index`]'s new index out of bounds.
    shipped: [Endset; ShippedType::ALL.len()],
    /// Φ — the cataloged classes declaring `ReadFilter` (class, verbatim key
    /// endset), for the UV default-view per-type filter
    /// (`is_k(J, ·) ≡ is_filtered_J`, D2 — BH1).
    read_filter: Vec<(CoverageClass, Endset)>,
    /// The classes declaring `ReverseLookup` (class, verbatim key endset) —
    /// `targets_keyed`'s footprint and its join (BH3). Empty in this format:
    /// no shipped registration declares it.
    reverse_lookup: Vec<(CoverageClass, Endset)>,
    /// The `[R]` class, the shipped `Supersedes` key, and the two PredLayer
    /// classes — each answered by an accessor below, so a collaborator asks
    /// the catalog the question rather than performing the comparison itself.
    retraction_class: CoverageClass,
    supersedes_key: TypeKey,
    pred_def_class: CoverageClass,
    pred_stable_class: CoverageClass,
}

/// The `shipped` array's index for a shipped type — used by the projection
/// to place and by [`TypeCatalog::reserved_type`] to fetch, so the array is
/// positionally right by construction. Named for the array it indexes, not
/// `slot`, which throughout the workspace is a link's F/G/TYPE endset
/// position (M7's `SlotArg`, `followlink(a, slot)`) and is `usize` too.
fn shipped_index(ty: ShippedType) -> usize {
    match ty {
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

        for ty in ShippedType::ALL {
            let endset = registry.reserved_type(ty).clone();
            let class = registry.shipped_class(ty).clone();
            let registration = registry
                .registration(&class)
                .expect("the registry registers every shipped class (TypeRegistry::build)")
                .clone();
            let key = TypeKey(endset.clone());
            shipped[shipped_index(ty)] = endset;
            order.push(key.clone());
            entries.insert(key, CatalogEntry { class, registration });
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
        let shipped_class = |ty: ShippedType| registry.shipped_class(ty).clone();
        TypeCatalog {
            retraction_class: shipped_class(ShippedType::Retraction),
            supersedes_key: TypeKey(shipped[shipped_index(ShippedType::Supersedes)].clone()),
            pred_def_class: shipped_class(ShippedType::PredDef),
            pred_stable_class: shipped_class(ShippedType::PredStable),
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
    pub(crate) fn reserved_type(&self, ty: ShippedType) -> &Endset {
        &self.shipped[shipped_index(ty)]
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

    /// Is this one of the two classes PR-DISC reserves for the predicate
    /// layer (`pdef`, `pd_stable`)? A rule's Marker action may emit into
    /// neither — `register_rule`'s `PredLayerMarkerType`, the in-module half
    /// of the discipline `lib.rs` states. Takes the class the caller already
    /// holds, so the answer costs no second probe.
    pub(crate) fn is_pred_layer(&self, class: &CoverageClass) -> bool {
        *class == self.pred_def_class || *class == self.pred_stable_class
    }

    /// The `[R]` class every Nullify fire deposits into — §8's retraction
    /// emission, which arms any active-reading trigger.
    pub(crate) fn retraction_class(&self) -> &CoverageClass {
        &self.retraction_class
    }

    /// The shipped `Supersedes` key — the one class M7 v1 serves the BH2 walk
    /// at, so the one key `Guard::Walk` admits (Conflicts §8).
    pub(crate) fn supersedes_key(&self) -> &TypeKey {
        &self.supersedes_key
    }
}
