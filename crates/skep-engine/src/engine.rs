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
#[derive(Debug)]
pub enum EngineError {
    /// `TypeRegistry::build` / `LinkState::genesis` rejected the config.
    Registry(RegistryError),
    /// `Kernel::open` failed (`InvalidConfig` / `Io` / `BadCheckpoint` /
    /// `Corruption`).
    Open(OpenError),
    /// The reserved half: the type config the recovered journal was sealed
    /// under disagrees with the configuration passed to this open on the
    /// named shipped class. Detected only where recovery restored a
    /// checkpointed world — see `check_genesis_drift` for the limits.
    GenesisReservedDrift(ShippedType),
    /// The decl half: the same disagreement on an app-declared type — the
    /// passed decl's key holds no registration in the sealed registry, or
    /// holds one that is not the registration passed. Carries the PASSED
    /// decl, which is the half an operator can act on; the sealed one is not
    /// publicly enumerable.
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

    /// The shared kernel (M2). Snapshots, checkpoints, and `current_seq` are
    /// reached through this; the engine adds nothing over them.
    /// [`Engine::world_at`] is the one M2 method the engine forwards rather
    /// than leaves to this handle, and it forwards verbatim.
    pub fn kernel(&self) -> &Arc<Kernel<World>> {
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
    /// its catalog projection is validate-once-or-fail: drift between the
    /// configuration and the registry fails HERE, at assembly, never as a
    /// spurious type-check miss later.
    pub fn coordinator(&self) -> Result<Coordinator<World>, CatalogError> {
        Coordinator::new(
            Arc::clone(self.kernel()),
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
/// `links` is read off the recovered world, so its config was deserialized
/// from the journal rather than taken from `genesis_config`, and the two are
/// compared on both halves of M7's `TypeConfig` — every shipped class
/// ([`EngineError::GenesisReservedDrift`]) and every app decl the passed
/// config carries ([`EngineError::GenesisDeclDrift`]).
///
/// Both halves are checked because both are fed onward from the passed value:
/// [`Engine::coordinator`] hands M9 the decls, and the world dump enumerates
/// its per-class hint sections from them. A daemon that never assembles a
/// `Coordinator` would otherwise run with its dump reporting classes genesis
/// never sealed.
///
/// The passed side is read through a registry built from the passed config,
/// which is what that build is for and all it is for: it resolves the passed
/// reserved endsets through M7's OWN `ShippedType`-to-address mapping, so the
/// assembler never copies that mapping into a match of its own — and a copy
/// is what would go blind to a sixth shipped class. The decl side compares by
/// coverage class, M7's own identity rule for a type; `TypeRegistry::build`
/// has already refused an empty or non-denoting key, so the class probe is
/// total and needs no second guard, and a missing or unequal registration is
/// drift and nothing else.
///
/// TWO LIMITS, both structural, both worth knowing before trusting this. It
/// has force only where recovery restored a CHECKPOINTED world: with no
/// retained checkpoint the replay base is the passed config's own genesis
/// world (M2 §Fsync), so the slice's config IS the passed config and every
/// comparison here is vacuously true. And it can only check what the passed
/// config mentions — the registry is keyed by coverage class and publishes no
/// enumeration, so a decl the JOURNAL sealed and this caller dropped, or a
/// reordering of `decls`, passes unremarked. Closing that direction needs an
/// M7 accessor for the sealed `TypeConfig`.
fn check_genesis_drift(
    links: &LinkState,
    genesis_config: &GenesisConfig,
) -> Result<(), EngineError> {
    let passed = TypeRegistry::build(&genesis_config.types).map_err(EngineError::Registry)?;
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
#[derive(Clone)]
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

    use skep_links::{enc, Registration, Shape};

    use super::*;

    /// The chain does not stop at the assembler: what an operator reads is
    /// M2's own sentence about the journal, wrapped rather than restated, and
    /// what a reporter walking `source` finds is M2's error itself.
    #[test]
    fn an_open_failure_carries_the_kernel_s_own_account_both_ways() {
        let engine_err = EngineError::Open(OpenError::BadCheckpoint);
        let rendered = engine_err.to_string();
        assert!(
            rendered.contains(&OpenError::BadCheckpoint.to_string()),
            "the operator must read M2's sentence, not a paraphrase: {rendered}"
        );
        assert!(
            !rendered.contains("BadCheckpoint"),
            "a Debug form is not an operator's sentence: {rendered}"
        );
        assert!(engine_err.source().is_some(), "M2's failure stays reachable as a cause");
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
