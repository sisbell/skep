//! The immutable, construction-time type registry (§B).
//!
//! It holds the shape/idempotence/behavior registration per coverage class,
//! built from compiled format constants ([`TypeRegistry::build`]) and never
//! mutated (P1/P2 of ASN-0126, R1/R2 of ASN-0128 — no mutator exists). The
//! registry's population is the five shipped classes and nothing else: there
//! is no app-declared types seam — the architecture's extension path is
//! predicates (pdef content), not new compiled substrate classes.

use std::collections::BTreeSet;
use std::sync::{Arc, LazyLock};

use skep_address::{content_subspace, Address, Level};
use skep_namespace::ghost_position;

use crate::class::{coverage_class, CoverageClass};
use crate::endset::{enc, Endset, Link};

/// A registered type's tuple shape (ASN-0126 P3).
///
/// Conformance counts each slot's spans as a set — ASN-0126's `|e|`, the
/// cardinality of `e` as a finite set of spans (`Endset = 𝒫_fin(Span)`,
/// ASN-0043) — one `FROM` span always, and per shape no `TO` span (Unary),
/// exactly one (Binary), or any finite number (Multi). A span the stored
/// decomposition repeats counts once, so a slot naming one address twice
/// conforms wherever naming it once does.
///
/// Sh-conf is a gate on the managed surface, not an invariant of the store:
/// `emit`, `nullify`, `assert_sup` and `editlink`'s claim pass it; MAKELINK
/// and an `editlink` successor take the open deposit gate and are
/// shape-blind. So a stored link may sit in a registered class without
/// conforming to that class's shape, and a read over a typed slice must not
/// assume otherwise. The three classes whose stored discipline is guaranteed
/// are `[R]`, `[K_sup]` and the `replaces` class (PUB-5.15), held by their
/// sole-writer fences rather than by this shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// No `TO` span.
    Unary,
    /// Exactly one `TO` span.
    Binary,
    /// Any finite number of `TO` spans.
    Multi,
}

/// Checks a value's span counts against a registered shape (Sh-conf, P3).
///
/// It decides the rule [`Shape`] states where the shape is declared rather
/// than at the gate that happens to consult it. Never infers a shape from the
/// tuple (a `(1,0)` tuple conforms under Unary and Multi). Reads both counts
/// off the link itself, so they cannot arrive in the wrong order.
///
/// Each count is ASN-0126's `|e|`, the slot's cardinality as a set of spans,
/// never the stored sequence's [`Endset::len`]: a span the decomposition
/// repeats counts once ([`enc`] keeps a repeated address as a repeated span),
/// while two distinct spans count two however they sit, nested or abutting.
/// The value is read, never merged — the gate adds preconditions and does not
/// alter what it admits (effect-identity, ASN-0126) — so a repeat is stored as
/// given.
pub(crate) fn sh_conf(shape: Shape, value: &Link) -> bool {
    holds_one_span(value.from_slot())
        && match shape {
            Shape::Unary => value.to_slot().is_empty(),
            Shape::Binary => holds_one_span(value.to_slot()),
            Shape::Multi => true,
        }
}

/// Returns whether `e` holds exactly one span, counted as a set.
///
/// That is ASN-0126's `|e| = 1`: a span the decomposition repeats counts
/// once, two distinct spans count two however they sit — one inside the
/// other, or abutting — and one span over an extent counts one (span count,
/// not coverage, not denotation). Answered without collecting the set: a
/// first span, and every other equal to it.
fn holds_one_span(e: &Endset) -> bool {
    let mut spans = e.spans();
    spans.next().is_some_and(|first| spans.all(|s| s == first))
}

/// The four behavior atoms of ASN-0128.
///
/// Their names there are `ReadFilter` (BH1), `DeterminateWalk` (BH2),
/// `TypedReverseLookup` (BH3) and `AgeStaleness` (BH4); each variant below
/// names its own. `Ord` so the set backs a `BTreeSet`.
///
/// Declaring one confers a set of reads and, separately, gates a smaller set
/// — in v1 only BH3's join and BH4's `stale` read a declaration back, the
/// other two being fixed to their shipped class. Each variant says which is
/// which, because "declared ⇒ served" is not the same as "declared ⇒
/// consulted", and what buys the first here is the population rather than
/// any check: the registry holds the compiled shipped table and nothing else,
/// so the only declarations in force are the note-pinned shipped ones — BH1
/// on `Retired`, BH2 on `Supersedes` — no second BH1 or BH2 declaration can
/// exist to be unserved, and the two declaration-reading gates run over a
/// population that declares neither BH3 nor BH4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Behavior {
    /// BH1 — ASN-0128's `ReadFilter` (⇒ Unary).
    ///
    /// It confers `is_filtered` and the result-side `View::Default` rewrite,
    /// and gates nothing at read time: v1's `is_filtered` is type-less,
    /// reading the shipped `Retired` class directly, so this declaration
    /// exists on exactly one registration and no read consults it.
    ReadFilter,
    /// BH2 — ASN-0128's `DeterminateWalk` (⇒ Binary).
    ///
    /// Determinacy is the half of that name the variant drops: the walk it
    /// confers halts at a branch or a cycle rather than choosing, which is
    /// what `Tip`'s `Indeterminate` reports the absence of. It confers
    /// `succs`, `chain`, `tip`, `is_in_chain`, and gates nothing at read
    /// time: the walk-scope test compares against the shipped `Supersedes`
    /// class.
    Walk,
    /// BH3 — ASN-0128's `TypedReverseLookup` (⇒ Binary).
    ///
    /// It confers `sources_to`, `target_of`, `targets_keyed`. Of those,
    /// `targets_keyed` alone consults the declaration (through
    /// [`TypeRegistry::reverse_lookup_classes`], which M9's catalog also
    /// reads for the join's footprint); `sources_to` and `target_of` answer
    /// for any registered class, declared or not. No shipped class declares
    /// it, so in this format `targets_keyed`'s join covers no class.
    ReverseLookup,
    /// BH4 — ASN-0128's `AgeStaleness` (⇒ idem = ⊥, any shape).
    ///
    /// It confers `age`, `stale`, `retract_stale`. It gates `stale` — and so
    /// `retract_stale`, which builds its batch from it — and not `age`, which
    /// reads no registration and answers for any resident link. The `Age`
    /// half of the corpus name is the ungated one; the `Staleness` half is
    /// the gate. No shipped class declares it (all five are idem⊤), so in
    /// this format `stale` refuses every class.
    Age,
}

/// One type's registration: shape, idempotence flag, behavior set.
///
/// The behavior set is a `std` `BTreeSet` over a four-variant `Copy` enum;
/// every registration is seeded from the note-pinned shipped table when the
/// module's [`registry`] is built and is immutable thereafter — there are no
/// persistent updates to share, and that registry is built once per process,
/// so no fold copies it.
///
/// `idem` is the managed surface's dedup discipline, not a uniqueness
/// invariant on the class: MAKELINK deposits into a registered idem⊤ class
/// with neither the dedup lock nor the in-transaction check, so a class may
/// hold several active tuples of one I0 identity. That is why the incumbent
/// a dedup hit returns is specified as the T1-least active match the caller
/// can read rather than as "the one". `shape` is a gate in the same sense —
/// see [`Shape`].
///
/// Not `Serialize`, and neither are [`Shape`] and [`Behavior`]: a
/// registration is read out of the module's compiled format registry, which
/// rides no checkpoint (it is keyed by the non-`Serialize` [`CoverageClass`]),
/// so nothing in the crate's serialized reach contains one. Deriving serde
/// across the three would fix `Shape`'s and `Behavior`'s variant order for
/// bincode and their variant names for JSON on behalf of no wire — and
/// `Behavior` is the one ASN-0128 could extend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// The registered tuple shape.
    pub shape: Shape,
    /// Whether the class is idem⊤: its managed deposits de-duplicate.
    pub idem: bool,
    /// The behavior atoms the class declares.
    pub behaviors: BTreeSet<Behavior>,
}

/// The five reserved type addresses: ghost tumblers, compiled format constants.
///
/// [`ReservedAddrs::format`] is the one value: in-docuverse, T4-valid
/// content positions at which nothing exists and nothing is ever minted. A
/// type is a number — the daemon's semantics for the five shipped classes
/// are compiled in, every other type means what its interpreting client says
/// it means, and no document anywhere is semantically authoritative for a
/// type.
///
/// `pred_def`/`pred_stable` are M9-coordinated addresses; their `Unary/⊤/{}`
/// registrations are the PredLayer registration agreement — the companion
/// M7↔M9 build-time coordination point, an M9-negotiated constant, never a
/// local M7 edit (§B).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservedAddrs {
    /// The `PredDef` class's address — ghost position 1.
    pub pred_def: Address,
    /// The `PredStable` class's address — ghost position 2.
    pub pred_stable: Address,
    /// `[K_ret]` — the shipped BH1 filter class.
    pub retired: Address,
    /// `[K_sup]` — the shipped BH2 walk class.
    pub supersedes: Address,
    /// `[R]` — the retraction class.
    pub retraction: Address,
}

impl ReservedAddrs {
    /// Returns the five values, frozen in the format.
    ///
    /// They are ghost tumblers `1.1.0.1.0.1.0.1.x` for x = 1..=5 — content
    /// positions 1–5 of doc 1 of account 1 (the system account, keyless and
    /// no operator's) of the registry node `1.1`, read verbatim from M3's
    /// [`ghost_position`] so the addresses M7 dispatches on and the region
    /// M3's allocator skips are one definition. Identical on every board
    /// because they are the format, not because a sealed configuration
    /// enforces agreement.
    ///
    /// Collision-freedom — "a reserved name can never equal an allocated
    /// address" — is the allocator's non-reissue guarantee, not subtree
    /// unreachability: the ghost content namespace's frontier is floored past
    /// the region and its membership excludes the five forever (M3's
    /// `ghost_floor` carries the argument; no address space exists outside
    /// the docuverse).
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

/// The format-fixed shipped classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShippedType {
    /// `[K_ret]`, the shipped filter class — ghost position 3.
    Retired,
    /// `[K_sup]`, the shipped walk class — ghost position 4.
    Supersedes,
    /// `[R]`, the retraction class — ghost position 5.
    Retraction,
    /// The predicate layer's `pred_def` class — ghost position 1.
    PredDef,
    /// The predicate layer's `pred_stable` class — ghost position 2.
    PredStable,
}

impl ShippedType {
    /// The shipped set, once — the one enumeration of the five.
    ///
    /// It lists them in declaration order. Every walk over them reads it
    /// here: M7's own suite, the engine's world dump, and whatever enumerates
    /// next. A second copy is how a walk silently comes to cover four classes
    /// out of five. (`TypeRegistry::build` names the five without walking
    /// this, binding each to its own reserved address, and so do exhaustive
    /// matches such as `TypeRegistry::shipped`'s; a variant added here
    /// without a binding there is a missing field, not a silent gap.)
    pub const ALL: [ShippedType; 5] = [
        ShippedType::Retired,
        ShippedType::Supersedes,
        ShippedType::Retraction,
        ShippedType::PredDef,
        ShippedType::PredStable,
    ];
}

/// One shipped type's two format-fixed facts, paired.
///
/// They are the endset a caller names the type by, and the [`CoverageClass`]
/// every guard, fold and read recognizes it by. One constructor, so "the
/// class is that type's own endset classified" holds by construction rather
/// than by two five-arm matches a reader has to cross-check against each
/// other.
#[derive(Debug)]
struct Shipped {
    endset: Endset,
    class: CoverageClass,
}

impl Shipped {
    /// Builds a shipped type's pair from its reserved address.
    ///
    /// It carries the per-address half of [`TypeRegistry::build`]'s startup
    /// assertion, rather than a second loop over the same five: a ghost
    /// tumbler is an element-level content position — the in-docuverse form
    /// the format pins, and the shape M3's ghost-region floor protects.
    /// Collision-freedom is the allocator's non-reissue guarantee — see
    /// [`ReservedAddrs::format`].
    ///
    /// # Panics
    ///
    /// Panics if `addr` is not an element-level content position, which can
    /// only happen if the format constants themselves are edited
    /// inconsistently.
    fn of(addr: &Address) -> Shipped {
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
        let endset = enc([addr]);
        Shipped {
            class: coverage_class(&endset),
            endset,
        }
    }
}

/// The immutable lookup registry: coverage class → registration.
///
/// It also holds the five shipped types both ways — as the endset a caller
/// names them by and as the class every guard recognizes them by, the two
/// paired in one value per type so they cannot fall out of step. Both are
/// fixed when the value is built, so the class a shipped type belongs to is a
/// fact this registry knows rather than one its callers re-derive.
/// Recomputable from nothing but the compiled format constants — keyed by the
/// non-`Serialize` [`CoverageClass`], so it never rides a checkpoint, and
/// carrying no sealed configuration, because none exists.
///
/// **Invariant.** Established by `TypeRegistry::build`, its sole constructor
/// and private to this file: the five shipped classes are pairwise distinct,
/// each is registered, and `shipped_class(t)` is the class of
/// `reserved_type(t)`. Every guard that recognizes a deposit by its class,
/// and every read that compares one against a shipped class, leans on all
/// three. That constructor is the one way to make one and nothing outside
/// this file can reach it, so every `TypeRegistry` a caller can hold is
/// [`registry`] — a fact the startup assertion established rather than a
/// value anyone can state.
///
/// An entity, defined by that identity and not by its contents: the type is
/// deliberately not `Clone`, because a copy would be a second registry equal
/// by value and distinct by identity — the very thing the private
/// constructor exists to make unconstructible — and the workspace asserts
/// the identity as `Arc::ptr_eq`. Every holder shares the one instance
/// through the `Arc` [`registry`] hands out or a borrow of it.
///
/// A pair, and both halves are load-bearing. The second says a copy cannot
/// be made — the `Clone` bound is unsatisfiable, so a registry equal by value
/// and distinct by identity is unconstructible as well as unbuildable. The
/// first is what keeps that a statement about `Clone`: a bare `compile_fail`
/// is satisfied by any compile error, so were the surrounding code to stop
/// compiling for some unrelated reason — a renamed accessor, a changed
/// return type — the refusal below would keep passing and pin nothing. The
/// twin exercises everything but the bound, so such a break turns this half
/// red and localizes itself. (The `E0277` code is checked on nightly only,
/// which is why the twin rather than the annotation carries the weight.)
///
/// ```
/// fn needs_debug<T: std::fmt::Debug>(_: &T) {}
/// needs_debug(&**skep_links::registry());
/// ```
/// ```compile_fail,E0277
/// fn needs_clone<T: Clone>(_: &T) {}
/// needs_clone(&**skep_links::registry());
/// ```
#[derive(Debug)]
pub struct TypeRegistry {
    registrations: im::HashMap<CoverageClass, Registration>,
    retired: Shipped,
    supersedes: Shipped,
    retraction: Shipped,
    pred_def: Shipped,
    pred_stable: Shipped,
}

impl TypeRegistry {
    /// Builds the registry — its only constructor (§B).
    ///
    /// A pure function of the compiled format constants, it seeds the five
    /// shipped types (each keyed by the class of `enc({reserved.<addr>})`)
    /// with their note-pinned registrations — `Retired = Unary/⊤/{ReadFilter}`
    /// (ASN-0128 S1), `Supersedes = Binary/⊤/{Walk}` (S2),
    /// `Retraction = Binary/⊤/{}` (S3), and the PredLayer registration
    /// agreement `PredDef = PredStable = Unary/⊤/{}` (an M9-negotiated
    /// constant, §B).
    ///
    /// Private to this file, which is what makes [`registry`] "the one
    /// instance" rather than a convention: a second build would be equal by
    /// value and distinct by identity, and the property this module publishes
    /// — that an assembler shares the instance the fold runs against — is an
    /// `Arc::ptr_eq`. No caller has reason to want a second: `build` takes
    /// nothing, so [`registry`] answers every question it could. Its one other
    /// caller is the unit suite beside it, which tests the build itself.
    ///
    /// # Panics
    ///
    /// Its checks are a startup assertion over the constants — the five ghost
    /// tumblers are element-level content positions with pairwise-distinct
    /// classes — so it panics only if the format constants are edited
    /// inconsistently; no caller chooses the input, so none is handed an
    /// `Err`.
    fn build() -> TypeRegistry {
        let reserved = ReservedAddrs::format();
        // Each shipped type's endset and its class are built together, so the
        // class this registry hands out for a `ShippedType` is that type's own
        // endset classified — never a positional coincidence. `Shipped::of`
        // carries the per-address half of the startup assertion, so the five
        // are named here once rather than walked again for it.
        let retired = Shipped::of(&reserved.retired);
        let supersedes = Shipped::of(&reserved.supersedes);
        let retraction = Shipped::of(&reserved.retraction);
        let pred_def = Shipped::of(&reserved.pred_def);
        let pred_stable = Shipped::of(&reserved.pred_stable);

        let unary_top = |behaviors: BTreeSet<Behavior>| Registration {
            shape: Shape::Unary,
            idem: true,
            behaviors,
        };
        let shipped_table: [(&Shipped, Registration); 5] = [
            (&retired, unary_top(BTreeSet::from([Behavior::ReadFilter]))),
            (
                &supersedes,
                Registration {
                    shape: Shape::Binary,
                    idem: true,
                    behaviors: BTreeSet::from([Behavior::Walk]),
                },
            ),
            (
                &retraction,
                Registration {
                    shape: Shape::Binary,
                    idem: true,
                    behaviors: BTreeSet::new(),
                },
            ),
            // The PredLayer registration agreement (M7↔M9 constant, §B).
            (&pred_def, unary_top(BTreeSet::new())),
            (&pred_stable, unary_top(BTreeSet::new())),
        ];

        let mut registrations: im::HashMap<CoverageClass, Registration> = im::HashMap::new();
        for (shipped, reg) in shipped_table {
            // The C0 key-uniqueness half of the startup assertion: five
            // distinct constants classify to five distinct classes.
            assert!(
                !registrations.contains_key(&shipped.class),
                "the five reserved format constants must be pairwise class-distinct (C0)"
            );
            registrations.insert(shipped.class.clone(), reg);
        }

        TypeRegistry {
            registrations,
            retired,
            supersedes,
            retraction,
            pred_def,
            pred_stable,
        }
    }

    /// Looks up a class's registration: `None` for an unregistered class.
    ///
    /// It is the public class → registration lookup, `Some(reg)` for a
    /// registered class. [`CoverageClass`] is opaque and [`coverage_class`] is
    /// its only constructor, so every argument is some endset's actual class
    /// and `None` means unregistered. M7's own gates and reads go through this
    /// lookup, save the BH3 join, which walks the registrations through
    /// [`TypeRegistry::reverse_lookup_classes`]; a caller holding a shipped
    /// type asks [`TypeRegistry::shipped_class`] for the key rather than
    /// classifying the endset it reports, and a caller holding some other
    /// `Endset` classifies it first.
    pub fn registration(&self, class: &CoverageClass) -> Option<&Registration> {
        self.registrations.get(class)
    }

    /// Returns whether a registered class declares a behavior.
    ///
    /// It is the "served only where declared" test, decided here where the
    /// shipped table above is in view, as
    /// [`TypeRegistry::reverse_lookup_classes`] is. An unregistered class
    /// declares nothing. Which registrations answer to a behavior is this
    /// registry's own knowledge, so `stale`'s BH4 fence, the one gate that
    /// reads a declaration back through this test, asks rather than
    /// destructuring a `Registration` at the read surface — and M9's catalog
    /// reads its BH1 footprint through it rather than through the field.
    pub fn declares(&self, class: &CoverageClass, behavior: Behavior) -> bool {
        self.registration(class)
            .is_some_and(|reg| reg.behaviors.contains(&behavior))
    }

    /// Returns whether a class is registered and idem⊤.
    ///
    /// That is a class whose managed deposits de-duplicate (ASN-0128 I1); an
    /// unregistered class is not idempotent. Which classes de-duplicate is
    /// this registry's own knowledge, as which declare a behavior is, so it
    /// is decided here beside [`TypeRegistry::declares`]. The one statement
    /// of the predicate the two derived decisions apply — whether a deposit
    /// takes M2's I0 section, and whether the hint fold indexes it under its
    /// dedup key — so the section M2 serializes and the key the fold indexes
    /// agree by one name. The in-transaction check reads the same flag off
    /// the `Registration` it already holds for the shape, which is the third
    /// spelling this one is the source of.
    pub(crate) fn is_idempotent(&self, class: &CoverageClass) -> bool {
        self.registration(class).is_some_and(|reg| reg.idem)
    }

    /// Returns the classes the BH3 join covers.
    ///
    /// They are the registered `Binary` classes declaring `ReverseLookup`.
    /// Which registrations answer to a behavior is this registry's own
    /// knowledge, so the predicate reads here, where the shipped table above
    /// is in view. No shipped registration declares BH3, so over this
    /// format's fixed population the iterator is empty — kept as the one
    /// statement of the rule, not specialized to the population — and M9's
    /// catalog reads `targets_keyed`'s footprint from it, so the join and the
    /// analysis of what it reads cannot come apart.
    pub fn reverse_lookup_classes(&self) -> impl Iterator<Item = &CoverageClass> + '_ {
        self.registrations
            .iter()
            .filter(|(_, reg)| {
                reg.shape == Shape::Binary && reg.behaviors.contains(&Behavior::ReverseLookup)
            })
            .map(|(class, _)| class)
    }

    /// Returns the format-fixed type endset for a shipped class.
    ///
    /// It is for a caller holding the registry: M9's catalog projection reads
    /// each shipped class from this at assembly, and M7's own write ops read
    /// the `Retraction` and `Supersedes` endsets here to build their tuples.
    /// [`crate::LinkState::reserved_type`] is the snapshot-bound delegate, for
    /// a caller holding the slice instead.
    pub fn reserved_type(&self, ty: ShippedType) -> &Endset {
        &self.shipped(ty).endset
    }

    /// Returns the coverage class of a shipped type.
    ///
    /// It is the recognition key the write gates, the hint fold and the read
    /// surface all compare against, fixed at build alongside the endset it
    /// classifies — and the class M9's catalog carries for each shipped type,
    /// read from the pairing rather than re-derived from
    /// [`TypeRegistry::reserved_type`]'s answer.
    pub fn shipped_class(&self, ty: ShippedType) -> &CoverageClass {
        &self.shipped(ty).class
    }

    /// Returns a shipped type's pair — the one dispatch over the five.
    ///
    /// Dispatching once means the endset a shipped type reports and the class
    /// it reports come out of one [`Shipped`] rather than out of two matches
    /// that could fall out of step.
    fn shipped(&self, ty: ShippedType) -> &Shipped {
        match ty {
            ShippedType::Retired => &self.retired,
            ShippedType::Supersedes => &self.supersedes,
            ShippedType::Retraction => &self.retraction,
            ShippedType::PredDef => &self.pred_def,
            ShippedType::PredStable => &self.pred_stable,
        }
    }
}

/// The registry — the compiled format constant, built once per process.
///
/// [`TypeRegistry::build`] is a pure function of [`ReservedAddrs::format`], so
/// there is nothing per-instance to hold: every slice, every writer and every
/// assembler reads this one value, and "the assembler shares the instance the
/// fold runs against" is true by construction rather than by an accessor and
/// an agreement check.
///
/// The `Arc` is the M9 seam's, not a preference: `Coordinator::new` takes an
/// `Arc<TypeRegistry>`, so this hands out one to clone.
static REGISTRY: LazyLock<Arc<TypeRegistry>> = LazyLock::new(|| Arc::new(TypeRegistry::build()));

/// Returns the module's format registry — the one instance.
///
/// It is the one M7's own fold, gates and reads run against. An assembler
/// that needs the registry (M9's catalog projection, the engine's world
/// dump) reads it here rather than building a second copy from the same
/// constants, which is what makes agreement structural.
pub fn registry() -> &'static Arc<TypeRegistry> {
    &REGISTRY
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use skep_address::{validate, Nat, Span, Tumbler};
    use skep_namespace::GHOST_POSITIONS;

    use super::*;

    fn ra(k: u32) -> Address {
        validate(
            Tumbler::new([1, 1, 0, 1, 0, 1, 0, 1, k].iter().map(|&c| Nat::from(c)))
                .expect("nonempty"),
        )
        .expect("T4-valid")
    }

    /// A walk over [`ShippedType::ALL`] must reach all five shipped classes.
    ///
    /// It is the enumeration. A dropped variant is a compile error (the array
    /// is length-5, [`TypeRegistry::shipped`]'s match is exhaustive, and the
    /// registry holds five fields); a duplicated one is not, and it would
    /// leave a class out of every walk — this suite's, and the engine's world
    /// dump, which compares dumps against each other and so would agree with
    /// itself about the gap. Distinctness is the whole test: five pairwise
    /// distinct values of a five-variant enum are all of them, so the property
    /// is stated without a second copy of the list to fall out of step.
    #[test]
    fn a_walk_over_all_reaches_every_shipped_class_once() {
        let built = TypeRegistry::build();
        let classes: HashSet<&CoverageClass> = ShippedType::ALL
            .iter()
            .map(|&ty| built.shipped_class(ty))
            .collect();
        assert_eq!(
            classes.len(),
            ShippedType::ALL.len(),
            "ALL names each shipped type exactly once"
        );
    }

    #[test]
    fn the_class_a_shipped_type_reports_is_the_class_of_the_endset_it_reports() {
        let built = TypeRegistry::build();
        for ty in ShippedType::ALL {
            assert_eq!(
                *built.shipped_class(ty),
                coverage_class(built.reserved_type(ty))
            );
            // ...and each is registered under exactly that class.
            assert!(built.registration(built.shipped_class(ty)).is_some());
        }
    }

    /// The module's registry is one value every reader shares.
    ///
    /// It is the instance M7's own fold and gates run against, so agreement
    /// between an assembler and the store is a construction and not a
    /// comparison.
    #[test]
    fn the_module_registry_is_one_shared_instance() {
        assert!(
            Arc::ptr_eq(registry(), registry()),
            "the format registry is built once per process"
        );
        // ...and it is a built one, not a placeholder: every shipped class
        // answers with its own endset and is registered under its own class.
        for ty in ShippedType::ALL {
            let endset = registry().reserved_type(ty);
            assert!(!endset.is_empty(), "{ty:?} names a real endset");
            assert!(registry().registration(registry().shipped_class(ty)).is_some());
        }
    }

    /// `declares` is the "served only where declared" test.
    ///
    /// It answers for the note-pinned shipped declarations, refuses the
    /// behaviors no shipped class carries, and treats an unregistered class
    /// as declaring nothing.
    #[test]
    fn declares_reads_the_shipped_declarations_and_nothing_else() {
        let built = TypeRegistry::build();
        let retired_class = built.shipped_class(ShippedType::Retired);
        let supersedes_class = built.shipped_class(ShippedType::Supersedes);
        assert!(built.declares(retired_class, Behavior::ReadFilter));
        assert!(built.declares(supersedes_class, Behavior::Walk));
        assert!(!built.declares(retired_class, Behavior::Walk));
        // No shipped class declares BH3 or BH4 in this format, which is why
        // `targets_keyed`'s join covers nothing and `stale` refuses every ty.
        for ty in ShippedType::ALL {
            let class = built.shipped_class(ty);
            assert!(!built.declares(class, Behavior::Age), "{ty:?} is idem⊤");
            assert!(!built.declares(class, Behavior::ReverseLookup), "{ty:?}");
        }
        // An unregistered class declares nothing rather than faulting.
        let unregistered = coverage_class(&enc([&ra(9)]));
        assert!(built.registration(&unregistered).is_none());
        assert!(!built.declares(&unregistered, Behavior::ReadFilter));
    }

    /// `is_idempotent` is the one statement of "a registered idem⊤ class".
    ///
    /// It is the predicate that decides both whether a deposit takes M2's I0
    /// section and whether the hint fold keys it — so it must agree with the
    /// registration it summarizes on every shipped class, and refuse an
    /// unregistered one rather than fault.
    #[test]
    fn is_idempotent_is_the_registration_s_idem_flag_and_refuses_an_unregistered_class() {
        let built = TypeRegistry::build();
        for ty in ShippedType::ALL {
            let class = built.shipped_class(ty);
            let registration = built.registration(class).expect("every shipped class is registered");
            assert_eq!(built.is_idempotent(class), registration.idem, "{ty:?}");
            // ...and in this format that flag is ⊤ on all five, which is why
            // every managed deposit takes a section save `editlink`'s claim,
            // whose check is a guaranteed miss.
            assert!(built.is_idempotent(class), "{ty:?} is idem⊤");
        }
        let unregistered = coverage_class(&enc([&ra(9)]));
        assert!(built.registration(&unregistered).is_none());
        assert!(!built.is_idempotent(&unregistered), "unregistered ⇒ not idempotent");
    }

    /// The five format constants are the ghost tumblers, in assignment order.
    ///
    /// That order is position x of the ghost doc for x = 1..=5, and they
    /// agree with M3's spelling of the region, so the addresses M7 dispatches
    /// on are the ones the allocator skips.
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
    fn sh_conf_counts_each_slot_as_a_set_of_spans() {
        // ASN-0126's `|e|` is the cardinality of `e` as a finite set of spans,
        // and each row pairs a slot with that count. Every pair of rows is
        // checked as (F, G); the |F| = 1 clause is the half no write path
        // presents (`emit` forces `enc({from})`), so it holds here or nowhere.
        let extent = |lo: u32, hi: u32| {
            Span::from_endpoints(ra(lo).tumbler().clone(), ra(hi).tumbler()).expect("an extent")
        };
        let rows = [
            (Endset::empty(), 0),
            (enc([&ra(1)]), 1),
            (enc([&ra(1), &ra(3)]), 2),
            // A repeated span counts once.
            (enc([&ra(1), &ra(1)]), 1),
            // Two spans, one inside the other, count two.
            (enc([&skep_namespace::ghost_home_document(), &ra(1)]), 2),
            // One span over an extent counts one; the same extent split into
            // two abutting spans counts two — span count, not coverage.
            (Endset::from_spans([extent(1, 3)]), 1),
            (Endset::from_spans([extent(1, 2), extent(2, 3)]), 2),
        ];
        for shape in [Shape::Unary, Shape::Binary, Shape::Multi] {
            let admits = |g: usize| match shape {
                Shape::Unary => g == 0,
                Shape::Binary => g == 1,
                Shape::Multi => true,
            };
            for (from, f) in &rows {
                for (to, g) in &rows {
                    let value = Link::triple(from.clone(), to.clone(), enc([&ra(1)]));
                    assert_eq!(
                        sh_conf(shape, &value),
                        *f == 1 && admits(*g),
                        "{shape:?} at |F| = {f}, |G| = {g}: {from:?}, {to:?}"
                    );
                }
            }
        }
    }
}
