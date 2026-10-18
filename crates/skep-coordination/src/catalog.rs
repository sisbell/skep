//! The type catalog (§Core data model): a frozen projection of the registry.
//!
//! It projects the one engine-built `TypeRegistry` (M9 never rebuilds it —
//! Conflicts §7), keyed by the verbatim type-key endset so a lookup both
//! authorizes a `TypeKey` and yields its precomputed `CoverageClass` — the
//! catalog never calls M7's `coverage_class`, and M9 never classifies a type
//! key: each shipped class is read from the registry's own endset/class
//! pairing (M9's one use of `coverage_class` is the def layer's
//! registration identity, over address-denoting F slots — `names` in
//! `coordinator/defs.rs`), and nothing in M9 consults the registry after
//! construction: every "which classes, with what behaviors" question the
//! checker, the evaluator and the analyses ask is answered here.
//!
//! A cached copy of genesis-immutable data (R1): it never goes stale. The
//! registry's population is the compiled shipped five, so the projection
//! reads everything from the registry itself — the classes, and the two
//! behavior rules it publishes as `declares` and `reverse_lookup_classes` —
//! and restates none of them.

use std::collections::HashMap;

use skep_links::{
    Behavior, CoverageClass, Endset, Registration, Shape, ShippedType, TypeRegistry,
};

use crate::ast::TypeKey;

/// One cataloged class: its precomputed coverage class and its registration.
///
/// The class is handed out; the registration is the injected registry's
/// truth, which the entry *answers* questions about rather than exposes, so
/// a collaborator names the property it needs instead of knowing how a
/// `Registration` records one.
#[derive(Debug, Clone)]
pub(crate) struct CatalogEntry {
    pub(crate) class: CoverageClass,
    registration: Registration,
}

impl CatalogEntry {
    /// Returns whether the class's registration declares `behavior`.
    ///
    /// V-STAT's test, and M7's own question (`TypeRegistry::declares`) asked
    /// of the frozen projection — so the checker names the behavior it needs.
    pub(crate) fn declares(&self, behavior: Behavior) -> bool {
        self.registration.behaviors.contains(&behavior)
    }

    /// Returns whether the class is Unary.
    ///
    /// That is the shape of a Marker fire's `emit`, whose G is empty, which a
    /// Marker action's tuple must be (`register_rule`'s `BadMarkerType`).
    pub(crate) fn is_unary(&self) -> bool {
        self.registration.shape == Shape::Unary
    }

    /// Returns whether the class is idem⊤.
    ///
    /// That is what the fire executor's gap dedup-absorption and the Q3/I1a
    /// extinction analysis both require of a Marker type (`register_rule`'s
    /// `NonIdemMarkerType`).
    pub(crate) fn is_idem(&self) -> bool {
        self.registration.idem
    }
}

/// The frozen catalog.
///
/// `classes` fixes the deterministic `Reg`-expansion class order (the shipped
/// types in `ShippedType` declaration order — the whole population).
#[derive(Debug, Clone)]
pub(crate) struct TypeCatalog {
    entries: HashMap<TypeKey, CatalogEntry>,
    classes: Vec<TypeKey>,
    /// The shipped endsets, one per `ShippedType`, placed by [`shipped_index`].
    ///
    /// [`shipped_index`] is the one function that both places and fetches.
    /// The array's length is the population's own count, so a shipped type
    /// added upstream widens the array with it rather than leaving
    /// [`shipped_index`]'s new index out of bounds.
    shipped: [Endset; ShippedType::ALL.len()],
    /// Φ: the cataloged classes declaring `ReadFilter`.
    ///
    /// Each is held as (class, verbatim key endset), for the UV default-view
    /// per-type filter (`is_k(J, ·) ≡ is_filtered_J`, ASN-0128 D2 — BH1).
    read_filter_classes: Vec<(CoverageClass, Endset)>,
    /// The classes declaring `ReverseLookup`.
    ///
    /// Each is held as (class, verbatim key endset): `targets_keyed`'s
    /// footprint and its join (BH3). Empty in this format: no shipped
    /// registration declares it.
    reverse_lookup_classes: Vec<(CoverageClass, Endset)>,
    /// The `[R]` class, the first of the four named classes and keys.
    ///
    /// The other three follow it: the shipped `Supersedes` key and the two
    /// PredLayer classes. Each is answered by an accessor below, so a
    /// collaborator asks the catalog the question rather than performing the
    /// comparison itself.
    retraction_class: CoverageClass,
    supersedes_key: TypeKey,
    pred_def_class: CoverageClass,
    pred_stable_class: CoverageClass,
}

/// Returns the `shipped` array's index for a shipped type.
///
/// It is used by the projection to place and by
/// [`TypeCatalog::reserved_type`] to fetch, so the array is positionally
/// right by construction. Named for the array it indexes, not
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
    /// Returns the projection: a pure read of the injected `registry`.
    ///
    /// It reads each shipped class's endset, class and registration, walking
    /// `ShippedType::ALL` (the one enumeration of the five, in declaration
    /// order). The class is the registry's own `shipped_class` — the half of
    /// its endset/class pairing fixed at build — never a classification of
    /// the endset made here. Infallible: the five values are compiled into
    /// the registry itself, so there is no second copy to disagree, and the
    /// registry registers every shipped class, so the lookups cannot miss
    /// (the `expect` states that).
    pub(crate) fn project(registry: &TypeRegistry) -> TypeCatalog {
        let mut entries: HashMap<TypeKey, CatalogEntry> = HashMap::new();
        let mut classes: Vec<TypeKey> = Vec::new();
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
            classes.push(key.clone());
            entries.insert(key, CatalogEntry { class, registration });
        }

        // The two behavior footprints are the registry's own rules, asked of
        // it rather than restated over the cached registrations: the
        // `ReadFilter` set is what `declares` answers, and the
        // `ReverseLookup` set is exactly the classes `targets_keyed` joins
        // over — so the join and the footprint analysis of what it reads
        // cannot come apart.
        let read_filter_classes = classes
            .iter()
            .filter_map(|k| {
                let entry = &entries[k];
                registry
                    .declares(&entry.class, Behavior::ReadFilter)
                    .then(|| (entry.class.clone(), k.0.clone()))
            })
            .collect();
        let reverse_lookup_classes = classes
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
            classes,
            read_filter_classes,
            reverse_lookup_classes,
        }
    }

    /// Returns the entry for `k`, by the `Endset`-equality probe.
    ///
    /// The probe authorizes the key and yields its precomputed class
    /// (§Core data model).
    pub(crate) fn get(&self, k: &TypeKey) -> Option<&CatalogEntry> {
        self.entries.get(k)
    }

    /// Returns the precomputed class of an *authorized* key.
    ///
    /// That is the one question every walk over a checked tree, and the rule
    /// engine over a validated Marker type, asks of the catalog about a key.
    ///
    /// # Panics
    ///
    /// Panics on a key the catalog does not hold. It is total on an
    /// authorized key: that key was admitted by [`TypeCatalog::get`] against
    /// this same projection, which is frozen at construction (R1), so the
    /// probe that authorized it cannot since have gone stale.
    pub(crate) fn class_of(&self, k: &TypeKey) -> &CoverageClass {
        &self
            .get(k)
            .expect("an authorized TypeKey is cataloged")
            .class
    }

    /// Returns the endset of shipped type `ty`.
    ///
    /// M9's own cached accessor over the shipped endsets (no snapshot) —
    /// distinct from M7's snapshot-bound `LinkState::reserved_type`.
    pub(crate) fn reserved_type(&self, ty: ShippedType) -> &Endset {
        &self.shipped[shipped_index(ty)]
    }

    /// Returns the finite, fixed class list `Reg`-expansion instantiates over.
    ///
    /// Its order is deterministic.
    pub(crate) fn classes(&self) -> &[TypeKey] {
        &self.classes
    }

    /// Returns Φ, the cataloged `ReadFilter` classes (BH1).
    ///
    /// They serve the UV `K_queried` self-exclusion.
    pub(crate) fn read_filter_classes(&self) -> &[(CoverageClass, Endset)] {
        &self.read_filter_classes
    }

    /// Returns the cataloged `ReverseLookup` classes (BH3).
    ///
    /// They are the classes `targets_keyed` joins over, and its footprint:
    /// the projection of the registry's own `reverse_lookup_classes`, and
    /// named for it.
    pub(crate) fn reverse_lookup_classes(&self) -> &[(CoverageClass, Endset)] {
        &self.reverse_lookup_classes
    }

    /// Returns whether `targets_keyed` is in the vocabulary (V-atom).
    ///
    /// It is iff some cataloged class declares `ReverseLookup` (BH3) — none
    /// does in this format, so the atom is out of the vocabulary on every
    /// board.
    pub(crate) fn has_reverse_lookup_class(&self) -> bool {
        !self.reverse_lookup_classes.is_empty()
    }

    /// Returns whether `class` is one PR-DISC reserves for the predicate layer.
    ///
    /// The two are `pdef` and `pd_stable`. A rule's Marker action may emit
    /// into neither — `register_rule`'s `PredLayerMarkerType`, the in-module
    /// half of the discipline `lib.rs` states. Takes the class the caller
    /// already holds, so the answer costs no second probe.
    pub(crate) fn is_pred_layer(&self, class: &CoverageClass) -> bool {
        *class == self.pred_def_class || *class == self.pred_stable_class
    }

    /// Returns the `[R]` class every Nullify fire deposits into.
    ///
    /// That is §8's retraction emission, which arms any active-reading
    /// trigger.
    pub(crate) fn retraction_class(&self) -> &CoverageClass {
        &self.retraction_class
    }

    /// Returns the shipped `Supersedes` key.
    ///
    /// It is the one class M7 v1 serves the BH2 walk at, so the one key
    /// `Guard::Walk` admits (Conflicts §8).
    pub(crate) fn supersedes_key(&self) -> &TypeKey {
        &self.supersedes_key
    }
}
