//! The assembled engine handle: `Kernel::open` over the genesis [`World`],
//! the one `Arc<TypeRegistry>` (M7's own module constant, reached and
//! shared), the driver accessors that reach M10's provided `Stores` bodies,
//! the M9 `Coordinator` assembly, and the `Stores<World>` factory M10's
//! transport injects. All dispatch and construction — no semantics.

use std::fmt;
use std::sync::Arc;

use skep_arrangement::Vstream;
use skep_coordination::Coordinator;
use skep_febe::Stores;
use skep_kernel::{HistoryError, Kernel, KernelConfig, OpenError, Seq};
use skep_links::{Caller, LinkWriter, TypeRegistry, Visibility};
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

/// The one lift the assembler makes, so `?` carries M2's refusal out of
/// [`Engine::open`] rather than a `map_err` at the one construction site.
impl From<OpenError> for EngineError {
    fn from(e: OpenError) -> EngineError {
        EngineError::Open(e)
    }
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
/// [`World`].
///
/// The kernel is held as the [`EngineStores`] factory rather than bare, so
/// the engine's own driver accessors reach the same driver bodies M10's
/// transport does — `Stores`' provided methods, which are M10's to write —
/// rather than restating them. That factory is the whole of what an engine
/// carries — the type registry [`Engine::registry`] hands out is M7's own
/// module constant, not state of this handle's.
pub struct Engine {
    stores: EngineStores,
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
    /// checkpoint shape) does not reopen under this format. A CHECKPOINT
    /// names the World layout that wrote it through the World's own leading
    /// format stamp (`world.rs`), so a base from a build before M3's
    /// publication bit fails to DECODE (PUB-7.8) and M2's fallback chain
    /// takes over: the next-older retained base, genesis while the journal
    /// still reaches it, else `OpenError::BadCheckpoint` (PUB-7.9) — never a
    /// decoded world with an empty exception set.
    ///
    /// There is nothing to assemble beyond that recovery. The type registry
    /// M9 is handed at [`Engine::coordinator`] is `skep_links::registry` —
    /// M7's own compiled format constant, built once per process — so the
    /// instance a consumer reads IS the one the store's fold and write gates
    /// run against, by construction rather than by an agreement anything here
    /// would have to keep.
    ///
    /// The kernel this hands [`EngineStores`] satisfies that constructor's
    /// PRECONDITION under either durability mode, by a different route each
    /// time. Journalled: M2 seeds whatever base it loads through
    /// `WorldState::rebuild_derived` before replay, so the root is rebuilt
    /// whether it came from a checkpoint or from genesis. In-memory: M2
    /// installs the passed world unrebuilt, and the passed world is
    /// [`World::genesis`], which carries its own derived hints and says why it
    /// must. So the mode that skips the rebuild is the mode whose root needs
    /// none.
    pub fn open(cfg: KernelConfig) -> Result<Engine, EngineError> {
        let kernel = Arc::new(Kernel::open(cfg, World::genesis())?);
        Ok(Engine { stores: EngineStores::new(kernel) })
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

    /// The ONE registry — M7's own module constant, reached rather than
    /// rebuilt, and the one M9 projects (M9 builds no second `TypeRegistry`).
    /// It is a process constant and not this handle's state, so every engine
    /// answers with the same instance and a world's own slice answers with it
    /// too; the world dump reads it off the slice for that reason.
    ///
    /// `'static`, because that is what it is: the borrow outlives this handle,
    /// and a caller keeping the registry past the engine that named it is
    /// holding a compiled constant rather than a dangling piece of state. The
    /// `Arc` stays because M9 takes an owned one — [`Engine::coordinator`]
    /// clones through here — so the shared ownership is real.
    pub fn registry(&self) -> &'static Arc<TypeRegistry> {
        skep_links::registry()
    }

    /// M3's driver (borrows the kernel for the call).
    pub fn namespace(&self) -> Namespace<'_, World> {
        self.stores.namespace()
    }

    /// M5's driver (borrows the kernel for the call).
    pub fn vstream(&self) -> Vstream<'_, World> {
        self.stores.vstream()
    }

    /// M7's driver (borrows the kernel and the caller's VISIBILITY class, and
    /// holds nothing else). The class is the caller's to thread (lane 3.3b):
    /// an engine-direct caller passes [`World::visible_to`] of the `Caller`
    /// it will write as; M10 passes its session principal's through
    /// [`EngineStores`]; M9 receives the guest class through
    /// [`Engine::coordinator`].
    pub fn linkstore<'a>(&'a self, visibility: &'a Visibility<'a, World>) -> LinkWriter<'a, World> {
        self.stores.linkstore(visibility)
    }

    /// Assemble M9's `Coordinator` (M9 interface: "engine-assembled"): the
    /// shared kernel, the one registry, the two op-handle factories whose
    /// bodies discharge M9's standing assembly obligation (constructing
    /// `Vstream` from `&Kernel<W>`, and `LinkWriter` from `&Kernel<W>` plus
    /// the visibility class M9 lends it), and the read predicate M9's fires
    /// run at (PUB round 2, lane 3.3, §5). M9 is the System caller — the one
    /// with no session — so its class is [`World::visible_to`]'s System arm,
    /// asked for here rather than restated: `published(doc)`, so a rule's
    /// effect never crosses the draft boundary. M9 threads that same
    /// predicate into every writer it builds (lane 3.3b, PUB-6.28), so a
    /// fire's value-keyed gates see only guest-readable incumbents.
    /// Infallible: M9's catalog is a pure projection of the injected registry
    /// — with the type set compiled into the format there is no twice-passed
    /// configuration whose drift a validate-once-or-fail step would catch.
    pub fn coordinator(&self) -> Coordinator<World> {
        Coordinator::new(
            Arc::clone(&self.stores.kernel),
            Arc::clone(self.registry()),
            Box::new(mk_vstream),
            Box::new(mk_link_store),
            Box::new(World::visible_to(Caller::System)),
        )
    }

    /// The `Stores<World>` factory the transport passes to M10's
    /// `OperationSurface::new`: a clone of the handle on this engine's one
    /// kernel, never a second kernel. The drivers it yields are M10's —
    /// `Stores`' provided bodies, built over that kernel.
    pub fn stores(&self) -> EngineStores {
        self.stores.clone()
    }

    /// The committed world as of position `at`: [`Kernel::world_at`] over the
    /// assembled world, forwarded verbatim. The contract, the refusal
    /// precedence and the cost are M2's, at that link.
    ///
    /// POSTCONDITION, which is the assembler's rather than M2's because it is
    /// [`World`]'s invariant it discharges: the returned world HAS been
    /// through `WorldState::rebuild_derived`. M2 seeds every base it selects
    /// through that call before folding onto it, and the fold is
    /// [`WorldState::apply`], which carries both derived indexes on their own
    /// arms. So a reconstruction satisfies the invariant [`World`] states and
    /// needs no rebuild from its receiver: it may be dumped, checked, served
    /// at a reader's class, or paired with a kernel at [`EngineStores::new`],
    /// whose precondition it discharges. That is the one thing a caller must
    /// know and M2 cannot say, being generic over every `WorldState` and
    /// knowing nothing of this world's indexes.
    ///
    /// [`WorldState::apply`]: skep_kernel::WorldState::apply
    /// [`WorldState::rebuild_derived`]: skep_kernel::WorldState::rebuild_derived
    pub fn world_at(&self, at: Seq) -> Result<World, HistoryError> {
        self.kernel().world_at(at)
    }
}

/// M9's factory bodies as named fn items (the proven coercion shape for the
/// `for<'k>` boxed-Fn parameters).
fn mk_vstream(k: &Kernel<World>) -> Vstream<'_, World> {
    Vstream::new(k)
}

fn mk_link_store<'k>(
    k: &'k Kernel<World>,
    visibility: &'k Visibility<'k, World>,
) -> LinkWriter<'k, World> {
    LinkWriter::new(k, visibility)
}

/// The concrete `Stores<World>` impl — the factory passed to M10's
/// `OperationSurface::new` at startup (M10 §Seams). It holds the engine's one
/// kernel and nothing else: the three drivers are `Stores`' provided bodies,
/// each a fresh handle built over that kernel per call.
#[derive(Clone, Debug)]
pub struct EngineStores {
    kernel: Arc<Kernel<World>>,
}

impl EngineStores {
    /// Over any `Kernel<World>` — the live recovered one [`Engine`] holds, or
    /// a throwaway kernel rooted at a reconstructed historical world. Holding
    /// the kernel is the whole of what an assembler owes `Stores<World>`: all
    /// three drivers follow from it, and the trait gives them. The engine's
    /// own `namespace`/`vstream`/`linkstore` read through this type, so a
    /// caller that has a kernel and needs an M10 over it asks for this rather
    /// than writing a second `Stores` impl, which would owe M10's one-kernel
    /// precondition afresh.
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
    /// HINTS still empty and BOTH of the engine's derived indexes empty.
    /// Reads then answer with
    /// nullification invisible, `Active` equal to `Audit`, every typed slice
    /// empty and no supersession edge at all; EVERY document published —
    /// the fail-open sign PUB-7.5 names; and every grant ungiven, which is
    /// that sign the other way (PUB-7.68), so the two derived indexes fail in
    /// OPPOSITE directions over one unrebuilt world and neither looks wrong
    /// from a single answer. (The type
    /// registry is not in that hazard: it is M7's module constant, so it
    /// answers the same on any world however the world arrived.)
    pub fn new(kernel: Arc<Kernel<World>>) -> EngineStores {
        EngineStores { kernel }
    }
}

/// The one kernel every driver M10 acquires is built over — the one method
/// this impl writes, the three drivers being `Stores`' provided bodies over it
/// (M7's writer among them, at the class M10 hands in per write, lane 3.3b).
///
/// M10 places one PRECONDITION on an implementer: this answers the SAME
/// kernel on every call, since every coordinate M10 reports rests on it. It is
/// discharged by construction — one `Arc`, fixed at [`EngineStores::new`] and
/// never replaced, shared by every clone of the handle
/// (`every_stores_clone_answers_the_engine_s_one_kernel` holds it). Overriding
/// one of the provided bodies here would take that obligation back on for the
/// driver it returned.
impl Stores<World> for EngineStores {
    fn kernel(&self) -> &Kernel<World> {
        &self.kernel
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::testkit::mem_engine;
    use crate::{Draft, IssuerGrant, ReaderClass, Record, UniversalGrant};

    use super::*;

    /// M10's one precondition on a `Stores` implementer, as a check: the
    /// engine's own kernel read, the factory [`Engine::stores`] hands out, and
    /// a clone of that factory all answer ONE kernel. Every coordinate M10
    /// reports rests on it — `log_position` and each read's `as_of` come from
    /// `kernel()`, while each link write commits through `linkstore()` — and
    /// the discharge is structural, one `Arc` fixed at construction, so this
    /// is what fails if the handle ever learns to swap or reopen its kernel.
    #[test]
    fn every_stores_clone_answers_the_engine_s_one_kernel() {
        let engine = mem_engine();
        let stores = engine.stores();
        let clone = stores.clone();
        assert!(
            std::ptr::eq(engine.kernel(), stores.kernel()),
            "the factory answers the engine's own kernel"
        );
        assert!(
            std::ptr::eq(stores.kernel(), clone.kernel()),
            "…and so does every clone of the factory"
        );
    }

    /// What a missing `Debug` costs is not the print, it is the wall: a
    /// caller's own type holding an assembled engine derives its own. Held of
    /// every type this crate exports that a caller can hold, the world and the
    /// central record included — the record and a reader class through a
    /// bound rather than a value, since each store's record is that store's to
    /// construct and a reader class borrows the world it reads.
    #[test]
    fn a_holder_of_the_assembled_types_derives_debug() {
        fn assert_debug<T: fmt::Debug>() {}
        assert_debug::<Record>();
        assert_debug::<ReaderClass<'static>>();

        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            engine: Engine,
            stores: EngineStores,
            world: World,
        }

        let engine = mem_engine();
        let world = engine.kernel().snapshot().world().clone();
        let holder = Holder { stores: engine.stores(), engine, world };
        let rendered = format!("{holder:?}");
        assert!(rendered.contains("Engine"), "the engine renders as itself: {rendered}");
        assert!(
            rendered.contains("seq"),
            "the kernel's head is the one thing worth reading here: {rendered}"
        );
        // …and the world renders as ITSELF and nothing of its slices: its
        // rendering is a `WorldDump`, asked for.
        assert!(rendered.contains("World"), "the world renders as itself: {rendered}");
        assert!(
            !rendered.contains("namespace"),
            "a world's slices are not a debug form: {rendered}"
        );
    }

    /// The enumeration ROWS are values a caller keys collections by, so each
    /// carries every standard trait its fields support: a row sorts, and goes
    /// into a `BTreeSet` or a `HashSet`, with nothing wrapped around it. A
    /// derive dropped from one of them is a wall and not an omission, since a
    /// caller cannot implement a standard trait for a type it does not own.
    #[test]
    fn the_enumeration_rows_are_ordered_hashable_values() {
        fn assert_value<T: Clone + fmt::Debug + Eq + std::hash::Hash + Ord>() {}
        assert_value::<Draft<'static>>();
        assert_value::<UniversalGrant<'static>>();
        assert_value::<IssuerGrant<'static>>();
    }

    /// The chain does not stop at the assembler: what an operator reads is
    /// M2's own sentence about the journal, wrapped rather than restated, and
    /// what a reporter walking `source` finds is M2's error itself.
    #[test]
    fn an_open_failure_carries_the_kernel_s_own_account_both_ways() {
        let open_failure = EngineError::Open(OpenError::BadCheckpoint { cause: None });
        let rendered = open_failure.to_string();
        assert!(
            rendered.contains(&OpenError::BadCheckpoint { cause: None }.to_string()),
            "the operator must read M2's sentence, not a paraphrase: {rendered}"
        );
        assert!(
            !rendered.contains("BadCheckpoint"),
            "a Debug form is not an operator's sentence: {rendered}"
        );
        assert!(open_failure.source().is_some(), "M2's failure stays reachable as a cause");
    }
}
