//! The assembled engine handle: `Kernel::open` over the genesis [`World`],
//! the one `Arc<TypeRegistry>` (M7's own module constant, shared), the
//! store-driver constructors, the M9 `Coordinator` assembly, and the
//! `Stores<World>` factory M10's transport injects. All dispatch and
//! construction — no semantics.

use std::fmt;
use std::sync::Arc;

use skep_arrangement::Vstream;
use skep_coordination::Coordinator;
use skep_febe::Stores;
use skep_kernel::{HistoryError, Kernel, KernelConfig, OpenError, Seq};
use skep_links::{LinkWriter, TypeRegistry};
use skep_namespace::Namespace;

use crate::world::World;

/// `Engine::open` failure: M2's recovery failed. The genesis and its type
/// registry are compiled format constants (owner ruling, 2026-08-26), so the
/// configuration-shaped refusals the retired `GenesisConfig` seam carried —
/// an invalid passed config, a reopen under a drifted one — have no input
/// left to fire on; what remains is the kernel's own account of the journal.
///
/// The set of ways an open can fail is the assembler's to extend as the
/// stores below it grow conditions worth naming, so it is `#[non_exhaustive]`:
/// a caller matching on the variants keeps its catch-all, and an addition
/// costs a recompile rather than a broken build.
#[derive(Debug)]
#[non_exhaustive]
pub enum EngineError {
    /// `Kernel::open` failed (`InvalidConfig` / `Io` / `BadCheckpoint` /
    /// `Corruption`).
    Open(OpenError),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineError::Open(e) => write!(f, "engine open: {e}"),
        }
    }
}

/// `Display` states the whole condition on one line — that is what the
/// operator reads — and `source` additionally exposes the inner failure as a
/// link, so a reporter walking the chain reaches M2's own account instead of
/// stopping at the assembler.
impl std::error::Error for EngineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EngineError::Open(e) => Some(e),
        }
    }
}

/// The assembled engine: the recovered kernel over the one concrete
/// [`World`], and M7's own registry over the compiled format constants — held
/// so every later consumer (M9's catalog, the world dump) reads the SAME
/// instance, never a copy that could drift.
///
/// The kernel is held as the [`EngineStores`] factory rather than bare: the
/// engine's own driver accessors read through it, so which driver constructor
/// fills which slot is written once, in one type, for both the engine's
/// callers and M10's transport.
pub struct Engine {
    stores: EngineStores,
    registry: Arc<TypeRegistry>,
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

/// The kernel's head — enough to tell two engines apart in a log line. The
/// world itself is not printed: its rendering is a `WorldDump`.
impl fmt::Debug for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Engine").field("kernel", self.kernel()).finish_non_exhaustive()
    }
}

impl Engine {
    /// Recover-or-init (M2's `Kernel::open`) over the genesis world — which
    /// is a compiled constant, so M2's byte-identical-genesis caller
    /// contract is discharged by construction: there is no configuration for
    /// a caller to pass differently on a reopen, and no drift check left to
    /// run. A journal names the format that wrote it through the journal's
    /// own format stamp; one written under the retired `GenesisConfig`
    /// regime (the 9-space reserved addresses, the config-carrying M7
    /// checkpoint shape) does not reopen under this format.
    ///
    /// The registry the engine keeps is M7's own: `skep_links::registry` is
    /// that module's compiled format constant, built once per process, so the
    /// instance every later consumer reads (M9's catalog, the world dump) IS
    /// the one the store's fold and write gates run against — not a second
    /// build that would then owe an agreement check, and not a copy read out
    /// of whichever slice happened to be at hand.
    pub fn open(cfg: KernelConfig) -> Result<Engine, EngineError> {
        let kernel = Arc::new(Kernel::open(cfg, World::genesis()).map_err(EngineError::Open)?);
        let registry = Arc::clone(skep_links::registry());
        Ok(Engine { stores: EngineStores::new(kernel), registry })
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

    /// The ONE registry — M7's own module constant, shared rather than
    /// rebuilt, and the one M9 projects (M9 builds no second `TypeRegistry`).
    pub fn registry(&self) -> &Arc<TypeRegistry> {
        &self.registry
    }

    /// M3's driver (borrows the kernel for the call).
    pub fn namespace(&self) -> Namespace<'_, World> {
        self.stores.namespace()
    }

    /// M5's driver (borrows the kernel for the call).
    pub fn vstream(&self) -> Vstream<'_, World> {
        self.stores.vstream()
    }

    /// M7's driver (borrows the kernel, and holds nothing else).
    pub fn linkstore(&self) -> LinkWriter<'_, World> {
        self.stores.linkstore()
    }

    /// Assemble M9's `Coordinator` (M9 interface: "engine-assembled"): the
    /// shared kernel, the one registry, and the two op-handle factories whose
    /// bodies discharge M9's standing assembly obligation (constructing
    /// `Vstream`/`LinkWriter` from `&Kernel<W>`). Infallible: M9's catalog is
    /// a pure projection of the injected registry — with the type set
    /// compiled into the format there is no twice-passed configuration whose
    /// drift a validate-once-or-fail step would catch.
    pub fn coordinator(&self) -> Coordinator<World> {
        Coordinator::new(
            Arc::clone(&self.stores.kernel),
            Arc::clone(&self.registry),
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
    /// a throwaway kernel rooted at a reconstructed historical world. Holding
    /// the kernel is the whole of what an assembler owes `Stores<World>`: M3's
    /// and M5's drivers follow from it and the trait gives them, and the impl
    /// below writes only M7's. The engine's own `namespace`/`vstream`/
    /// `linkstore` read through this type, so a caller that has a kernel and
    /// needs an M10 over it asks for this rather than restating the
    /// constructors and inheriting the next change to them.
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
    /// HINTS still empty. Reads then answer with nullification invisible,
    /// `Active` equal to `Audit`, every typed slice empty and no supersession
    /// edge at all — and nothing about the answers looks wrong. (The type
    /// registry is not in that hazard: it is M7's module constant, so it
    /// answers the same on any world however the world arrived.)
    pub fn new(kernel: Arc<Kernel<World>>) -> EngineStores {
        EngineStores { kernel }
    }
}

impl Stores<World> for EngineStores {
    fn kernel(&self) -> &Kernel<World> {
        &self.kernel
    }

    fn linkstore(&self) -> LinkWriter<'_, World> {
        LinkWriter::new(&self.kernel)
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use skep_kernel::{CheckpointPolicy, Durability};

    use super::*;

    fn mem_engine() -> Engine {
        let cfg = KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
        };
        Engine::open(cfg).expect("in-memory open cannot fail")
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
        }

        let engine = mem_engine();
        let holder = Holder { stores: engine.stores(), engine };
        let rendered = format!("{holder:?}");
        assert!(rendered.contains("Engine"), "the engine renders as itself: {rendered}");
        assert!(
            rendered.contains("seq"),
            "the kernel's head is the one thing worth reading here: {rendered}"
        );
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
    }
}
