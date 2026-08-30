//! The assembled engine handle: `Kernel::open` over the genesis [`World`],
//! the one `Arc<TypeRegistry>` (M7's own, shared out of the recovered slice),
//! the store-driver constructors, the M9 `Coordinator` assembly, and the
//! `Stores<World>` factory M10's transport injects. All dispatch and
//! construction — no semantics.

use std::fmt;
use std::sync::Arc;

use skep_arrangement::Vstream;
use skep_coordination::{CatalogError, Coordinator};
use skep_febe::Stores;
use skep_kernel::{HistoryError, Kernel, KernelConfig, OpenError, Seq};
use skep_links::{
    coverage_class, HasLinks, LinkState, LinkWriter, RegistryError, ShippedType, TypeDecl,
    TypeRegistry,
};
use skep_namespace::Namespace;

use crate::genesis::{GenesisConfig, SHIPPED};
use crate::world::World;

/// `Engine::open` failure: the genesis type configuration failed validation,
/// M2's recovery failed, or the passed configuration disagrees with the one
/// the recovered journal was sealed under. All are operator-intervention
/// conditions, not auto-retried (M2 caller contract).
///
/// The set of ways an open can fail is the assembler's to extend as the
/// stores below it grow conditions worth naming, so it is `#[non_exhaustive]`:
/// a caller matching on the variants keeps its catch-all, and an addition
/// costs a recompile rather than a broken build.
#[derive(Debug)]
#[non_exhaustive]
pub enum EngineError {
    /// `World::genesis`, through `LinkState::genesis`, rejected the passed
    /// type configuration — before any kernel exists. That is the one site
    /// where a configuration is validated, once per open.
    Registry(RegistryError),
    /// `Kernel::open` failed (`InvalidConfig` / `Io` / `BadCheckpoint` /
    /// `Corruption`).
    Open(OpenError),
    /// The reserved half: the type config the recovered journal was sealed
    /// under disagrees with the configuration passed to this open on the
    /// named shipped class. Detected only where recovery restored a
    /// checkpointed world — see `check_genesis_drift` for the limits.
    ///
    /// One disagreement, the first found, and the reserved half is compared
    /// before the decl half: a fixed config may be refused again on the next
    /// open. `check_genesis_drift` states the precedence in full.
    GenesisReservedDrift(ShippedType),
    /// The decl half: the same disagreement on an app-declared type — the
    /// passed decl's key holds no registration in the sealed registry, or
    /// holds one that is not the registration passed. Carries the PASSED
    /// decl, which is the half an operator can act on; the sealed one is not
    /// publicly enumerable.
    ///
    /// One disagreement, the first found in `decls` order, and reached only
    /// once the whole reserved half agrees — so this refusal is evidence
    /// about one decl and about no other.
    GenesisDeclDrift(TypeDecl),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineError::Registry(e) => write!(f, "engine genesis: {e}"),
            EngineError::Open(e) => write!(f, "engine open: {e}"),
            EngineError::GenesisReservedDrift(ty) => write!(
                f,
                "engine open: recovered journal was sealed under a different genesis type \
                 config (disagrees on {ty:?}); reopen with the original GenesisConfig"
            ),
            EngineError::GenesisDeclDrift(d) => {
                // The key by its addresses, in the dotted form an operator's
                // own config file spells them — a nested Debug of the endset
                // is not a sentence anyone can act on. The registration is a
                // small flat struct and reads as itself.
                let key: Vec<String> = d.key.addrs().map(|t| t.to_string()).collect();
                write!(
                    f,
                    "engine open: recovered journal was sealed under a different genesis type \
                     config (disagrees on the app-declared type keyed [{}], passed as {:?}); \
                     reopen with the original GenesisConfig",
                    key.join(", "),
                    d.reg
                )
            }
        }
    }
}

/// `Display` states the whole condition on one line — that is what the
/// operator reads — and `source` additionally exposes the inner failure as a
/// link, so a reporter walking the chain reaches M2's or M7's own account
/// instead of stopping at the assembler. Spelled out variant by variant: a
/// wildcard would compile and silently drop the next variant's cause.
impl std::error::Error for EngineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EngineError::Registry(e) => Some(e),
            EngineError::Open(e) => Some(e),
            EngineError::GenesisReservedDrift(_) | EngineError::GenesisDeclDrift(_) => None,
        }
    }
}

/// The assembled engine: the recovered kernel over the one concrete
/// [`World`], the registry M7's slice validated from its own sealed
/// configuration, and that configuration — held so every later consumer (M9's
/// catalog, the world dump's app-class enumeration) reads the SAME registry
/// and the SAME config, never a copy that could drift.
///
/// The kernel is held as the [`EngineStores`] factory rather than bare: the
/// engine's own driver accessors read through it, so which driver constructor
/// fills which slot is written once, in one type, for both the engine's
/// callers and M10's transport.
pub struct Engine {
    stores: EngineStores,
    registry: Arc<TypeRegistry>,
    genesis_config: GenesisConfig,
}

/// `skepd` serves a whole worker pool off one shared `Engine`, so `Send +
/// Sync` is part of what this type promises. [`World`] and [`EngineStores`]
/// have theirs enforced by `WorldState`'s and `Stores`'s supertrait bounds;
/// `Engine` implements no trait that would hold it, so it is pinned here —
/// where a field that revoked it would fail, rather than one crate away in
/// the daemon's `serve`.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Engine>();
};

/// The kernel's head and the size of the configuration behind it — enough to
/// tell two engines apart in a log line. The world itself is not printed: its
/// rendering is a `WorldDump`, which needs the genesis config this engine
/// holds and `Debug` cannot take.
impl fmt::Debug for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Engine")
            .field("kernel", self.kernel())
            .field("app_decls", &self.genesis_config.types.decls.len())
            .finish_non_exhaustive()
    }
}

impl Engine {
    /// Recover-or-init (M2's `Kernel::open`) over the full genesis world.
    ///
    /// The genesis seam, and the one door the caller's type configuration
    /// comes through — so `check_genesis_drift` runs here, against the
    /// config the recovered slice was actually sealed under. M2's caller
    /// contract is that the SAME configuration is passed on every open of a
    /// given journal; that check is what holds the caller to it, within the
    /// limits stated on it.
    ///
    /// The registry the engine keeps is M7's own: the slice reconstructs it
    /// from the configuration the journal sealed, before replay, so the
    /// instance every later consumer reads (M9's catalog, the world dump) is
    /// the one the store's fold and write gates actually run against, not a
    /// second build that would then owe an agreement check.
    ///
    /// Validation of the passed configuration is `World::genesis`'s, through
    /// `LinkState::genesis` — before any kernel exists, refusing as
    /// [`EngineError::Registry`].
    pub fn open(cfg: KernelConfig, genesis_config: GenesisConfig) -> Result<Engine, EngineError> {
        let world = World::genesis(&genesis_config).map_err(EngineError::Registry)?;
        let kernel = Arc::new(Kernel::open(cfg, world).map_err(EngineError::Open)?);
        let registry = {
            let snap = kernel.snapshot();
            let links = snap.world().links();
            check_genesis_drift(links, &genesis_config)?;
            Arc::clone(links.registry())
        };
        Ok(Engine { stores: EngineStores::new(kernel), registry, genesis_config })
    }

    /// The kernel (M2). Snapshots, checkpoints, and `current_seq` are reached
    /// through this; the engine adds nothing over them. [`Engine::world_at`]
    /// is the one M2 method the engine forwards rather than leaves to this
    /// handle, and it forwards verbatim.
    ///
    /// A borrow, matching `Stores::kernel` below: that the kernel is shared
    /// behind an `Arc` is how the engine hands the same one to M9 and to every
    /// driver, and it is not something a reader of this method needs to hold.
    /// The shared-ownership seam is [`EngineStores`], which clones.
    pub fn kernel(&self) -> &Kernel<World> {
        &self.stores.kernel
    }

    /// The ONE registry behind the genesis-sealed config — M7's own instance,
    /// shared rather than rebuilt, and the one M9 projects (M9 builds no
    /// second `TypeRegistry`).
    pub fn registry(&self) -> &Arc<TypeRegistry> {
        &self.registry
    }

    /// The genesis configuration this engine was opened under.
    pub fn genesis_config(&self) -> &GenesisConfig {
        &self.genesis_config
    }

    /// M3's driver (borrows the kernel for the call).
    pub fn namespace(&self) -> Namespace<'_, World> {
        self.stores.namespace()
    }

    /// M5's driver (borrows the kernel for the call).
    pub fn vstream(&self) -> Vstream<'_, World> {
        self.stores.vstream()
    }

    /// M7's driver (borrows the kernel; clones the slice's rebuilt registry
    /// `Arc` internally, per M7's as-built constructor).
    pub fn linkstore(&self) -> LinkWriter<'_, World> {
        self.stores.linkstore()
    }

    /// Assemble M9's `Coordinator` (M9 interface: "engine-assembled"): the
    /// shared kernel, the one registry, the type configuration it was
    /// validated from, and the two op-handle factories whose bodies discharge
    /// M9's standing assembly obligation (constructing `Vstream`/`LinkWriter`
    /// from `&Kernel<W>`). M9 takes the configuration as its two halves and
    /// its catalog projection is validate-once-or-fail, so a disagreement
    /// between the configuration and the registry fails at assembly rather
    /// than as a spurious type-check miss later.
    ///
    /// After a successful [`Engine::open`] that channel carries no operator
    /// condition: `check_genesis_drift` has already compared this same pair
    /// against this same registry, and more strictly — `Endset` equality on
    /// all five shipped classes where M9 asks coverage-equality, and the exact
    /// passed `Registration` for each decl where M9 asks only that one exists.
    /// So an `Err` here is the engine's check and M9's projection disagreeing:
    /// an assembler bug, not a configuration an operator can fix.
    pub fn coordinator(&self) -> Result<Coordinator<World>, CatalogError> {
        Coordinator::new(
            Arc::clone(&self.stores.kernel),
            Arc::clone(&self.registry),
            self.genesis_config.types.reserved.clone(),
            self.genesis_config.types.decls.clone(),
            Box::new(mk_vstream),
            Box::new(mk_link_store),
        )
    }

    /// The `Stores<World>` factory the transport passes to M10's
    /// `Operation::new` — the engine-facing store-driver constructors,
    /// wrapped once so the binary holds no assembly knowledge.
    pub fn stores(&self) -> EngineStores {
        self.stores.clone()
    }

    /// The committed world as of position `at`: [`Kernel::world_at`] over the
    /// assembled world, forwarded verbatim. The contract, the refusal
    /// precedence and the cost are M2's, at that link.
    pub fn world_at(&self, at: Seq) -> Result<World, HistoryError> {
        self.kernel().world_at(at)
    }
}

/// The engine's one act of judgment: does the type configuration the
/// recovered slice was SEALED under agree with the one this open was passed?
/// `links` is read off the recovered world at its post-replay HEAD, and what
/// makes that the seal is M7's own fold — `apply_link` carries the genesis
/// config and its registry forward unchanged on every record, and no
/// `LinkRec` replaces either, so the head's config is the recovery base's,
/// deserialized from the journal rather than taken from `genesis_config`. The
/// two are compared on both halves of M7's `TypeConfig` — every shipped class
/// ([`EngineError::GenesisReservedDrift`]) and every app decl the passed
/// config carries ([`EngineError::GenesisDeclDrift`]).
///
/// Both halves are checked because both are fed onward from the passed value:
/// [`Engine::coordinator`] hands M9 the decls, and the world dump enumerates
/// its per-class hint sections from them. A daemon that never assembles a
/// `Coordinator` would otherwise run with its dump reporting classes genesis
/// never sealed.
///
/// PRECONDITION: `genesis_config` has already passed `TypeRegistry::build`.
/// The one caller, [`Engine::open`], discharges it a line earlier at
/// `World::genesis` and refuses there as [`EngineError::Registry`] — so the
/// build below is a READ, not a second check, and it is here for one reason:
/// it resolves the passed reserved endsets through M7's OWN
/// `ShippedType`-to-address mapping, so the assembler never copies that
/// mapping into a match of its own, and a copy is what would go blind to a
/// sixth shipped class. The build is a pure function of a configuration that
/// nothing touches between the two calls, so its refusal cannot arrive here.
///
/// The decl side compares by coverage class, M7's own identity rule for a
/// type; that same upstream build has already refused an empty or
/// non-denoting key, so the class probe is total and needs no second guard,
/// and a missing or unequal registration is drift and nothing else.
///
/// PRECEDENCE: the first disagreement found speaks, and several can hold at
/// once. The reserved half is compared before the decl half, in `SHIPPED`
/// order within the one and `decls` order within the other. So a refusal
/// names one disagreement and is evidence about no other — a corrected
/// config may be refused again on the next open, and only a clean reopen
/// says the whole configuration agrees.
///
/// THREE LIMITS, all structural, all worth knowing before trusting this. It
/// has force only where recovery restored a CHECKPOINTED world: with no
/// retained checkpoint the replay base is the passed config's own genesis
/// world (M2 §Fsync), so the slice's config IS the passed config and every
/// comparison here is vacuously true. It can only check what the passed
/// config mentions — the registry is keyed by coverage class and publishes no
/// enumeration, so a decl the JOURNAL sealed and this caller dropped, or a
/// reordering of `decls`, passes unremarked. Closing that direction needs an
/// M7 accessor for the sealed `TypeConfig`.
///
/// And it cannot speak AT ALL where the sealed config no longer re-validates,
/// which is the limit to read before tightening `TypeRegistry::build`.
/// Recovery runs `WorldState::rebuild_derived` over every base it selects,
/// and M7's rebuild reconstructs its registry with a `TypeRegistry::build`
/// it `expect`s — so a checkpoint whose sealed config decodes but no longer
/// passes a tightened validation aborts the process inside `Kernel::open`,
/// before this function is ever reached. Two things go with it: M2's
/// fallback chain, which would otherwise skip that checkpoint for the
/// next-older base and refuse cleanly as `OpenError::BadCheckpoint`, is
/// bypassed — the load SUCCEEDED, and the panic is after it — and so is the
/// diagnosis this check exists to give. Note which case survives to that
/// panic: `World::genesis` validates the PASSED config first and would refuse
/// as [`EngineError::Registry`], so what is left is passed-valid,
/// sealed-invalid — a drifted config, exactly the family named here.
fn check_genesis_drift(
    links: &LinkState,
    genesis_config: &GenesisConfig,
) -> Result<(), EngineError> {
    let passed = TypeRegistry::build(&genesis_config.types).expect(
        "the passed config validated at World::genesis, and TypeRegistry::build is a pure \
         function of it",
    );
    for ty in SHIPPED {
        if links.reserved_type(ty) != passed.reserved_type(ty) {
            return Err(EngineError::GenesisReservedDrift(ty));
        }
    }
    let sealed = links.registry();
    for d in &genesis_config.types.decls {
        if sealed.registration(&coverage_class(&d.key)) != Some(&d.reg) {
            return Err(EngineError::GenesisDeclDrift(d.clone()));
        }
    }
    Ok(())
}

/// M9's factory bodies as named fn items (the proven coercion shape for the
/// `for<'k>` boxed-Fn parameters).
fn mk_vstream(k: &Kernel<World>) -> Vstream<'_, World> {
    Vstream::new(k)
}

fn mk_link_store(k: &Kernel<World>) -> LinkWriter<'_, World> {
    LinkWriter::new(k)
}

/// The concrete `Stores<World>` impl (M10 §Seams: "at startup, the `Stores`
/// factory passed to `Operation::new`, built via the engine-facing
/// store-driver constructors"). Holds only the shared kernel; each call
/// hands out a fresh driver.
#[derive(Clone, Debug)]
pub struct EngineStores {
    kernel: Arc<Kernel<World>>,
}

impl EngineStores {
    /// Over any `Kernel<World>` — the live recovered one [`Engine`] holds, or
    /// a throwaway kernel rooted at a reconstructed historical world. WHICH
    /// driver constructor fills which `Stores` slot is the assembler's
    /// knowledge, and the impl below is the one statement of it: the engine's
    /// own `namespace`/`vstream`/`linkstore` read through this type, so a
    /// caller that has a kernel and needs an M10 over it asks for this rather
    /// than restating the four constructors and inheriting the next change to
    /// them.
    ///
    /// PRECONDITION, and the assembler's to state because the pairing is the
    /// assembler's: `kernel`'s root must be a world that has been through
    /// `WorldState::rebuild_derived`. In practice that means one
    /// [`World::genesis`] built — which carries its own derived hints, and
    /// says so — or one [`Engine::world_at`] reconstructed, whose replay
    /// seeds its base through the rebuild. `Durability::InMemory` installs
    /// the passed world unrebuilt, so a `World` that arrived any other way
    /// (deserialized straight from bytes, say — `World: Deserialize` is
    /// forced on it by `WorldState`) is served here with M7's skip-serialized
    /// registry still at serde's seed: it "registers nothing, reports every
    /// shipped endset as `⟨⟩`, and holds none of `TypeRegistry`'s invariant",
    /// in `LinkState::registry`'s own words. Reads then answer with
    /// nullification invisible, `Active` equal to `Audit`, and no
    /// supersession or retraction recognized at all — and nothing about the
    /// answers looks wrong.
    pub fn new(kernel: Arc<Kernel<World>>) -> EngineStores {
        EngineStores { kernel }
    }
}

impl Stores<World> for EngineStores {
    fn kernel(&self) -> &Kernel<World> {
        &self.kernel
    }

    fn namespace(&self) -> Namespace<'_, World> {
        Namespace::new(&self.kernel)
    }

    fn vstream(&self) -> Vstream<'_, World> {
        Vstream::new(&self.kernel)
    }

    fn linkstore(&self) -> LinkWriter<'_, World> {
        LinkWriter::new(&self.kernel)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::error::Error;

    use skep_kernel::{CheckpointPolicy, Durability};
    use skep_links::{enc, Registration, Shape};

    use super::*;

    fn mem_engine() -> Engine {
        let cfg = KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
        };
        Engine::open(cfg, GenesisConfig::standard()).expect("in-memory open cannot fail")
    }

    /// What a missing `Debug` costs is not the print, it is the wall: a
    /// caller's own type holding an assembled engine derives its own.
    #[test]
    fn a_holder_of_the_assembled_types_derives_debug() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            engine: Engine,
            stores: EngineStores,
            config: GenesisConfig,
        }

        let engine = mem_engine();
        let holder = Holder {
            stores: engine.stores(),
            config: engine.genesis_config().clone(),
            engine,
        };
        let rendered = format!("{holder:?}");
        assert!(rendered.contains("Engine"), "the engine renders as itself: {rendered}");
        assert!(
            rendered.contains("seq"),
            "the kernel's head is the one thing worth reading here: {rendered}"
        );
    }

    /// M2's contract is that the SAME configuration is passed on every open of
    /// a journal, so a caller can compare the one it holds against the one it
    /// stored — before an open turns the question into a recovery.
    #[test]
    fn a_genesis_config_equals_only_the_same_configuration() {
        assert_eq!(GenesisConfig::standard(), GenesisConfig::standard());
        let mut edited = GenesisConfig::standard();
        edited.types.reserved.retired = GenesisConfig::standard().types.reserved.supersedes;
        assert_ne!(GenesisConfig::standard(), edited);
    }

    /// The chain does not stop at the assembler: what an operator reads is
    /// M2's own sentence about the journal, wrapped rather than restated, and
    /// what a reporter walking `source` finds is M2's error itself.
    #[test]
    fn an_open_failure_carries_the_kernel_s_own_account_both_ways() {
        let open_failure = EngineError::Open(OpenError::BadCheckpoint);
        let rendered = open_failure.to_string();
        assert!(
            rendered.contains(&OpenError::BadCheckpoint.to_string()),
            "the operator must read M2's sentence, not a paraphrase: {rendered}"
        );
        assert!(
            !rendered.contains("BadCheckpoint"),
            "a Debug form is not an operator's sentence: {rendered}"
        );
        assert!(open_failure.source().is_some(), "M2's failure stays reachable as a cause");
        assert!(
            EngineError::GenesisReservedDrift(ShippedType::Retired).source().is_none(),
            "a drift verdict is the engine's own; it wraps no inner failure"
        );
    }

    /// A decl-drift refusal names the key the way the operator wrote it: the
    /// dotted addresses, not a nested Debug of the endset that carries them.
    #[test]
    fn a_decl_drift_names_its_key_in_the_operator_s_own_form() {
        let addr = GenesisConfig::standard().types.reserved.retired;
        let dotted = addr.tumbler().to_string();
        let rendered = EngineError::GenesisDeclDrift(TypeDecl {
            key: enc(std::slice::from_ref(&addr)),
            reg: Registration {
                shape: Shape::Binary,
                idem: true,
                behaviors: BTreeSet::new(),
            },
        })
        .to_string();
        assert!(
            rendered.contains(&dotted),
            "the operator must read the key as they wrote it ({dotted}): {rendered}"
        );
        assert!(
            !rendered.contains("Endset"),
            "an endset's Debug form is not an operator's sentence: {rendered}"
        );
    }
}
