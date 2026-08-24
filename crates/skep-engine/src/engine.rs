//! The assembled engine handle: `Kernel::open` over the genesis [`World`],
//! the engine-built `Arc<TypeRegistry>` (the second consumer of the one
//! genesis configuration), the store-driver constructors, the M9
//! `Coordinator` assembly, and the `Stores<World>` factory M10's transport
//! injects. All dispatch and construction — no semantics.

use std::fmt;
use std::sync::Arc;

use skep_arrangement::Vstream;
use skep_coordination::{CatalogError, Coordinator};
use skep_febe::Stores;
use skep_kernel::{HistoryError, Kernel, KernelConfig, OpenError, Seq};
use skep_links::{HasLinks, LinkWriter, RegistryError, ShippedType, TypeRegistry};
use skep_namespace::Namespace;

use crate::genesis::GenesisConfig;
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
    /// The recovered world's genesis-sealed type config disagrees with the
    /// configuration passed to this open on the named shipped class — the
    /// caller violated M2's byte-identical-genesis contract (e.g. reopened a
    /// journal under an edited `GenesisConfig`).
    GenesisDrift(ShippedType),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineError::Registry(e) => write!(f, "engine genesis: {e}"),
            EngineError::Open(e) => write!(f, "engine open: {e:?}"),
            EngineError::GenesisDrift(ty) => write!(
                f,
                "engine open: recovered journal was sealed under a different genesis type \
                 config (disagrees on {ty:?}); reopen with the original GenesisConfig"
            ),
        }
    }
}

impl std::error::Error for EngineError {}

/// The five shipped classes, in declaration order — the drift-check walk.
const SHIPPED: [ShippedType; 5] = [
    ShippedType::Retired,
    ShippedType::Supersedes,
    ShippedType::Retraction,
    ShippedType::PredDef,
    ShippedType::PredStable,
];

/// The assembled engine: the recovered kernel over the one concrete
/// [`World`], the engine-built registry, and the genesis configuration both
/// were fed from — held so every later consumer (M9's catalog, the observe
/// surface's app-class enumeration) reads the SAME config, never a copy that
/// could drift.
pub struct Engine {
    kernel: Arc<Kernel<World>>,
    registry: Arc<TypeRegistry>,
    genesis: GenesisConfig,
}

impl Engine {
    /// Recover-or-init (M2's `Kernel::open`) over the full genesis world.
    ///
    /// The one genesis configuration feeds BOTH registry consumers here
    /// (the genesis seam): `World::genesis` seals `(reserved, decls)` into
    /// M7's slice, and the engine builds its own `Arc<TypeRegistry>` from
    /// the same inputs — M7's slice-internal registry `Arc` is crate-private
    /// (as built), so the engine cannot share it and must rebuild; identical
    /// inputs through the one validate-once-or-fail `TypeRegistry::build`
    /// make the two equal, and M9's catalog projection re-checks that at
    /// `coordinator()`.
    ///
    /// Caller contract (M2, restated): pass the SAME `genesis` config on
    /// every open of a given `cfg.journal_path`. The engine trips a wire on
    /// violation: when recovery restores a checkpointed world, the slice's
    /// OWN sealed config (deserialized from the journal, not from `genesis`)
    /// must agree with the passed one on every shipped class, else
    /// [`EngineError::GenesisDrift`] — a pure agreement check, catching the
    /// drifted-reopen mistake loudly instead of splitting the registry
    /// consumers silently. (App-decl drift beyond the shipped five is not
    /// publicly enumerable from the slice; M9's catalog projection at
    /// [`Engine::coordinator`] covers the decl side.)
    pub fn open(cfg: KernelConfig, genesis: GenesisConfig) -> Result<Engine, EngineError> {
        let registry = Arc::new(
            TypeRegistry::build(genesis.reserved.clone(), genesis.decls.clone())
                .map_err(EngineError::Registry)?,
        );
        let world = World::genesis(&genesis).map_err(EngineError::Registry)?;
        let kernel = Arc::new(Kernel::open(cfg, world).map_err(EngineError::Open)?);
        {
            let snap = kernel.snapshot();
            for ty in SHIPPED {
                if snap.world().links().reserved_type(ty) != registry.reserved(ty) {
                    return Err(EngineError::GenesisDrift(ty));
                }
            }
        }
        Ok(Engine { kernel, registry, genesis })
    }

    /// The shared kernel (M2). Snapshots, checkpoints, and `current_seq` are
    /// reached through this; the engine adds nothing over them.
    pub fn kernel(&self) -> &Arc<Kernel<World>> {
        &self.kernel
    }

    /// The ONE engine-built registry behind the genesis-sealed config — the
    /// instance M9 projects (M9 builds no second `TypeRegistry`).
    pub fn registry(&self) -> &Arc<TypeRegistry> {
        &self.registry
    }

    /// The genesis configuration this engine was opened under.
    pub fn genesis_config(&self) -> &GenesisConfig {
        &self.genesis
    }

    /// M3's driver (borrows the kernel for the call).
    pub fn namespace(&self) -> Namespace<'_, World> {
        Namespace::new(&self.kernel)
    }

    /// M5's driver (borrows the kernel for the call).
    pub fn vstream(&self) -> Vstream<'_, World> {
        Vstream::new(&self.kernel)
    }

    /// M7's driver (borrows the kernel; clones the slice's rebuilt registry
    /// `Arc` internally, per M7's as-built constructor).
    pub fn linkstore(&self) -> LinkWriter<'_, World> {
        LinkWriter::new(&self.kernel)
    }

    /// Assemble M9's `Coordinator` (M9 interface: "engine-assembled"): the
    /// shared kernel, the engine-built registry, the SAME `(reserved,
    /// decls)` pair, and the two op-handle factories whose bodies discharge
    /// M9's standing assembly obligation (constructing `Vstream`/`LinkWriter`
    /// from `&Kernel<W>`). M9's catalog projection is validate-once-or-fail:
    /// drift between the twice-passed pair and the registry fails HERE, at
    /// assembly, never as a spurious type-check miss later.
    pub fn coordinator(&self) -> Result<Coordinator<World>, CatalogError> {
        Coordinator::new(
            Arc::clone(&self.kernel),
            Arc::clone(&self.registry),
            self.genesis.reserved.clone(),
            self.genesis.decls.clone(),
            Box::new(mk_vstream),
            Box::new(mk_link_store),
        )
    }

    /// The `Stores<World>` factory the transport passes to M10's
    /// `Operation::new` — the engine-facing store-driver constructors,
    /// wrapped once so the binary holds no assembly knowledge.
    pub fn stores(&self) -> EngineStores {
        EngineStores { kernel: Arc::clone(&self.kernel) }
    }

    /// The committed world as of position `at` — M2's read-only bounded
    /// replay ([`Kernel::world_at`]), which folds from the Σ₀ the kernel was
    /// opened under, so a historical position starts from the same genesis
    /// every recovery starts from. Observation-surface API: writes nothing,
    /// takes no kernel lock, and leaves the live paths untouched.
    pub fn world_at(&self, at: Seq) -> Result<World, HistoryError> {
        self.kernel.world_at(at)
    }
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
