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
    coverage_class, HasLinks, LinkWriter, RegistryError, ShippedType, TypeDecl, TypeRegistry,
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
    /// The type config the recovered journal was sealed under disagrees with
    /// the configuration passed to this open on the named shipped class.
    /// Detected only where recovery restored a checkpointed world — see
    /// [`Engine::open`] for what that leaves unchecked.
    GenesisDrift(ShippedType),
    /// The same disagreement on an app-declared type: the passed decl's key
    /// holds no registration in the sealed registry, or holds one that is not
    /// the registration passed. Carries the PASSED decl, which is the half an
    /// operator can act on — the sealed one is not publicly enumerable.
    GenesisDeclDrift(TypeDecl),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineError::Registry(e) => write!(f, "engine genesis: {e}"),
            EngineError::Open(e) => write!(f, "engine open: {e}"),
            EngineError::GenesisDrift(ty) => write!(
                f,
                "engine open: recovered journal was sealed under a different genesis type \
                 config (disagrees on {ty:?}); reopen with the original GenesisConfig"
            ),
            EngineError::GenesisDeclDrift(d) => write!(
                f,
                "engine open: recovered journal was sealed under a different genesis type \
                 config (disagrees on the app-declared type {d:?}); reopen with the original \
                 GenesisConfig"
            ),
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
            EngineError::GenesisDrift(_) | EngineError::GenesisDeclDrift(_) => None,
        }
    }
}

/// The assembled engine: the recovered kernel over the one concrete
/// [`World`], the registry M7's slice validated from its own sealed
/// configuration, and that configuration — held so every later consumer (M9's
/// catalog, the observe surface's app-class enumeration) reads the SAME
/// registry and the SAME config, never a copy that could drift.
pub struct Engine {
    kernel: Arc<Kernel<World>>,
    registry: Arc<TypeRegistry>,
    genesis: GenesisConfig,
}

impl Engine {
    /// Recover-or-init (M2's `Kernel::open`) over the full genesis world.
    ///
    /// The genesis seam. `TypeRegistry::build` validates the PASSED
    /// configuration — validate-once-or-fail, before any kernel exists — and
    /// the resulting registry is the comparison basis below and nothing else.
    /// The registry the engine keeps is M7's own: the slice reconstructs it
    /// from the configuration the journal sealed, before replay, so the
    /// instance every later consumer reads (M9's catalog, the observe surface)
    /// is the one the store's fold and write gates actually run against, not a
    /// second build that would then owe an agreement check.
    ///
    /// Caller contract (M2, restated): pass the SAME `genesis` config on
    /// every open of a given journal. This is the one door that config comes
    /// through, so the wire is here: the slice's OWN sealed config
    /// (deserialized from the journal, not taken from `genesis`) must agree
    /// with the passed one on every shipped class
    /// ([`EngineError::GenesisDrift`]) AND on every app decl the passed
    /// config carries ([`EngineError::GenesisDeclDrift`]). Both halves are
    /// checked here because both are fed onward from the passed value —
    /// [`Engine::coordinator`] hands M9 the decls, and the observe surface
    /// enumerates its per-class hint sections from them — so a daemon that
    /// never assembles a `Coordinator` would otherwise run with its
    /// observation surface reporting classes genesis never sealed.
    ///
    /// TWO LIMITS, both structural, both worth knowing before trusting the
    /// wire. It has force only where recovery restored a CHECKPOINTED world:
    /// with no retained checkpoint the replay base is the passed `genesis`
    /// itself (M2 §Fsync), so the slice's config IS the passed config and
    /// every comparison below is vacuously true. And it can only check what
    /// the passed config mentions — the registry is keyed by coverage class
    /// and publishes no enumeration, so a decl the JOURNAL sealed and this
    /// caller dropped, or a reordering of `decls`, passes unremarked.
    /// Closing that direction needs an M7 accessor for the sealed
    /// `TypeConfig`.
    pub fn open(cfg: KernelConfig, genesis: GenesisConfig) -> Result<Engine, EngineError> {
        let passed = TypeRegistry::build(&genesis.types).map_err(EngineError::Registry)?;
        let world = World::genesis(&genesis).map_err(EngineError::Registry)?;
        let kernel = Arc::new(Kernel::open(cfg, world).map_err(EngineError::Open)?);
        let registry = {
            let snap = kernel.snapshot();
            let links = snap.world().links();
            let sealed = links.registry();
            for ty in SHIPPED {
                if links.reserved_type(ty) != passed.reserved_type(ty) {
                    return Err(EngineError::GenesisDrift(ty));
                }
            }
            // The decl side, compared by coverage class — M7's own identity
            // rule for a type. `TypeRegistry::build` above has already refused
            // an empty or non-denoting key, so the class probe is total here
            // and needs no second guard; a missing or unequal registration is
            // drift and nothing else.
            for d in &genesis.types.decls {
                if sealed.registration(&coverage_class(&d.key)) != Some(&d.reg) {
                    return Err(EngineError::GenesisDeclDrift(d.clone()));
                }
            }
            Arc::clone(sealed)
        };
        Ok(Engine { kernel, registry, genesis })
    }

    /// The shared kernel (M2). Snapshots, checkpoints, and `current_seq` are
    /// reached through this; the engine adds nothing over them.
    /// [`Engine::world_at`] is the one M2 method the engine forwards rather
    /// than leaves to this handle, and it forwards verbatim.
    pub fn kernel(&self) -> &Arc<Kernel<World>> {
        &self.kernel
    }

    /// The ONE registry behind the genesis-sealed config — M7's own instance,
    /// shared rather than rebuilt, and the one M9 projects (M9 builds no
    /// second `TypeRegistry`).
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
    /// shared kernel, the one registry, the type configuration it was
    /// validated from, and the two op-handle factories whose bodies discharge
    /// M9's standing assembly obligation (constructing `Vstream`/`LinkWriter`
    /// from `&Kernel<W>`). M9 takes the configuration as its two halves and
    /// its catalog projection is validate-once-or-fail: drift between the
    /// configuration and the registry fails HERE, at assembly, never as a
    /// spurious type-check miss later.
    pub fn coordinator(&self) -> Result<Coordinator<World>, CatalogError> {
        Coordinator::new(
            Arc::clone(&self.kernel),
            Arc::clone(&self.registry),
            self.genesis.types.reserved.clone(),
            self.genesis.types.decls.clone(),
            Box::new(mk_vstream),
            Box::new(mk_link_store),
        )
    }

    /// The `Stores<World>` factory the transport passes to M10's
    /// `Operation::new` — the engine-facing store-driver constructors,
    /// wrapped once so the binary holds no assembly knowledge.
    pub fn stores(&self) -> EngineStores {
        EngineStores::new(Arc::clone(&self.kernel))
    }

    /// The committed world as of position `at`: [`Kernel::world_at`] over the
    /// assembled world, forwarded verbatim. The contract, the refusal
    /// precedence and the cost are M2's, at that link.
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

impl EngineStores {
    /// Over any `Kernel<World>` — the live recovered one [`Engine::stores`]
    /// passes, or a throwaway kernel rooted at a reconstructed historical
    /// world. WHICH driver constructor fills which `Stores` slot is the
    /// assembler's knowledge, so it is stated once, here: a caller that has a
    /// kernel and needs an M10 over it asks for this rather than restating
    /// the four constructors and inheriting the next change to them.
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
    use std::error::Error;

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
            EngineError::GenesisDrift(ShippedType::Retired).source().is_none(),
            "a drift verdict is the engine's own; it wraps no inner failure"
        );
    }
}
