//! The assembled engine handle, and the `Stores<World>` factory it shares.
//!
//! It holds `Kernel::open` over the genesis [`World`], the one
//! `Arc<TypeRegistry>` (M7's own module constant, reached and shared), the
//! driver accessors that reach M10's provided `Stores` bodies, the M9
//! `Coordinator` assembly, and the `Stores<World>` factory M10's transport
//! injects. All dispatch and construction — no semantics.

use std::fmt;
use std::sync::Arc;

use skep_arrangement::Vstream;
use skep_coordination::Coordinator;
use skep_febe::Stores;
use skep_kernel::{Attestation, HistoryError, Kernel, KernelConfig, OpenError, Seq, SkippedBase};
use skep_links::{Caller, LinkWriter, TypeRegistry, Visibility};
use skep_namespace::Namespace;

use crate::world::World;

/// What [`Engine::open`] found in the journal directory and did there.
///
/// It is M2's own account of the open (AUTH-2.85, AUTH-2.86) — the start
/// point its derivation resolved from, every retained checkpoint it passed
/// over, each with why, the commits it replayed above the start point, the
/// un-acked tail it cut, in bytes and from where, with the intact frames
/// among them no torn write leaves, the position their markers claimed and
/// the files the cut's bytes were kept in, whether any journal stood to
/// recover at all, and the corrupt runs below the start point it read and
/// passed over — and the one fact only this assembler can add to it,
/// whether the start point's identity slice was resolved to the empty table
/// rather than carried (AUTH-2.83). The daemon above logs them at startup: a
/// skipped checkpoint with the start point it resolved from, a slice-less
/// checkpoint that resolved empty — the operator's one tell of a build that
/// wrote no slice — the corrupt runs passed over below the start point, the
/// open's own landing in figures, a journal the open began, and the tail it
/// cut. A report and never a verdict: the open succeeded from the start
/// point named; the chain's one failure is [`EngineError::Open`]'s. Absent
/// under `Durability::InMemory`, which loads nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recovery {
    /// The base the recovered world was folded from.
    ///
    /// It is a retained checkpoint's seq, or `Seq(0)` where genesis stood in.
    pub start_point: Seq,
    /// The checkpoints above the start point that were not start points.
    ///
    /// They are retained ones, newest first, each with the refusal that
    /// passed it over — a base written without the identity slice over
    /// credential deposits among the causes, in M2's slice-agnostic words.
    pub skipped: Vec<SkippedBase>,
    /// The commits the open replayed above the start point.
    ///
    /// They are transactions, never the records they carry, as M2 counted
    /// them (`skep_kernel::Recovery`'s `replayed`); `0` where the start point
    /// was the committed head.
    pub replayed: u64,
    /// The bytes of tail the open cut, as M2 counted them.
    ///
    /// They are `skep_kernel::Recovery`'s `tail_cut`, un-acked save where
    /// `tail_cut_intact` counts a frame; `0` after a clean shutdown.
    pub tail_cut: u64,
    /// Of the frames that cut removed, the intact ones no torn write leaves.
    ///
    /// They are a commit marker that commits nothing, or a frame whose CRC
    /// passes and that does not decode — as M2 counted them
    /// (`skep_kernel::Recovery`'s `tail_cut_intact`): `0` after every clean
    /// shutdown and nearly every crash, and otherwise the sign that the cut
    /// may have taken a write the daemon acknowledged.
    pub tail_cut_intact: u64,
    /// Where the cut began, as M2 answered it.
    ///
    /// That is the segment's name in the data directory and the byte of it
    /// (`skep_kernel::Recovery`'s `tail_cut_from`); `None` where nothing was
    /// cut.
    pub tail_cut_from: Option<(String, u64)>,
    /// The files the cut's bytes were kept in, by name, as M2 answered them.
    ///
    /// Where the cut took an intact frame no torn write leaves, every byte it
    /// took was first kept beside the journal, in the data directory, in
    /// `seg-{n}.wal.cut-{byte}` files (`….{k}` where that name already
    /// stands; `skep_kernel::Recovery`'s `tail_cut_kept`): the operator's,
    /// which no open reads, removes or writes over. Empty for a crash's tail
    /// and where nothing was cut.
    pub tail_cut_kept: Vec<String>,
    /// The greatest position an intact commit marker in the cut claimed.
    ///
    /// Where the cut may have taken an acknowledged write, it is the position
    /// its acknowledgement named (`skep_kernel::Recovery`'s
    /// `tail_cut_claimed`); `None` where no intact marker stood in the cut.
    pub tail_cut_claimed: Option<Seq>,
    /// Whether no journal stood in the directory, so the open began one.
    ///
    /// It began one at genesis rather than recovering one
    /// (`skep_kernel::Recovery`'s `began`): right on a fresh board's first
    /// open, and on any other the tell that the directory opened is not where
    /// the journal lives.
    pub began: bool,
    /// The corrupt runs below the start point the open read and passed over.
    ///
    /// They are `skep_kernel::Recovery`'s `runs_passed_over`: harmless to this
    /// open, which the start point carries past them, and met by any
    /// derivation from a base below one — the fallback past the start point
    /// among them.
    pub runs_passed_over: u64,
    /// The first of them, in M2's words.
    ///
    /// That is its files and bytes, the position it holds none above, and the
    /// act that clears it (`skep_kernel::Recovery`'s `first_run_passed_over`).
    pub first_run_passed_over: Option<String>,
    /// Whether the start point's identity table resolved empty (AUTH-2.83).
    ///
    /// It did where the start point carried no identity slice and its link
    /// slice held no credential deposit — the true table, and the one case a
    /// slice-less base is a start point.
    pub identity_resolved_empty: bool,
}

/// The `Engine::open` failure: M2's `Kernel::open` refused.
///
/// The genesis and its type registry are compiled format constants, so the
/// configuration-shaped refusals a genesis configuration would carry — an
/// invalid passed config, a reopen under a drifted one — have no input to
/// fire on; what remains is the kernel's own account of its configuration
/// and of the journal.
///
/// The set of ways an open can fail is the assembler's to extend as the
/// stores below it grow conditions worth naming, so it is `#[non_exhaustive]`:
/// a caller matching on the variants keeps its catch-all, and an addition
/// costs a recompile rather than a broken build.
#[derive(Debug)]
#[non_exhaustive]
pub enum EngineError {
    /// `Kernel::open` failed: M2's [`OpenError`], carried whole.
    ///
    /// Its variants and their remedies are M2's to name.
    Open(OpenError),
}

/// The assembler's one error lift: [`OpenError`] into [`EngineError`].
///
/// So `?` carries M2's refusal out of [`Engine::open`] rather than a
/// `map_err` at its one call of `Kernel::open`.
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

/// `Display` states the whole condition in one line, `source` its cause.
///
/// The one line is what the operator reads, and `source` additionally
/// exposes the inner failure as a link, so a reporter walking the chain
/// reaches M2's own account instead of stopping at the assembler.
impl std::error::Error for EngineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EngineError::Open(e) => Some(e),
        }
    }
}

/// The assembled engine: the recovered kernel over the one concrete [`World`].
///
/// The kernel is held as the [`EngineStores`] factory rather than bare, so
/// the engine's own driver accessors reach the same driver bodies M10's
/// transport does — `Stores`' provided methods, which are M10's to write —
/// rather than restating them. That factory and the open's report
/// ([`Engine::recovery`]) are the whole of what an engine carries — the
/// type registry [`Engine::registry`] hands out is M7's own module constant,
/// not state of this handle's.
pub struct Engine {
    stores: EngineStores,
    /// What the open found, for the daemon's startup warnings.
    ///
    /// It is `None` under the in-memory mode.
    recovery: Option<Recovery>,
}

/// The compile-time pin that `Engine` and `EngineError` are `Send + Sync`.
///
/// `skepd` serves a whole worker pool off one shared `Engine`, so `Send +
/// Sync` is part of what this type promises. [`World`] and [`EngineStores`]
/// have theirs enforced by `WorldState`'s and `Stores`'s supertrait bounds;
/// `Engine` implements no trait that would hold it, so it is pinned here —
/// where a field that revoked it would fail, rather than one crate away in
/// the daemon's `serve`.
///
/// [`EngineError`] is pinned beside it, and its promise rests on another
/// crate: an error type is expected to be `Send + Sync` — a caller boxes it
/// into a `dyn Error + Send + Sync`, and the daemon's `DaemonError` carries it
/// under an assertion of its own — and its auto traits are M2's `OpenError`'s,
/// which hold because M2 boxes every cause `Send + Sync`. A cause boxed
/// without them would revoke the promise with no signature of this crate's
/// moving, and this is where that change fails first.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Engine>();
    assert_send_sync::<EngineError>();
};

/// The kernel's head — enough to tell two engines apart in a log line.
///
/// The world itself is not printed: its rendering is a `WorldDump`.
impl fmt::Debug for Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Engine").field("kernel", self.kernel()).finish_non_exhaustive()
    }
}

impl Engine {
    /// Opens the engine: M2's recover-or-init over the genesis world.
    ///
    /// The genesis world is a compiled constant, so M2's byte-identical-genesis
    /// caller contract on `Kernel::open` is discharged by construction: there
    /// is no configuration for a caller to pass differently on a reopen, and no
    /// drift check to run.
    ///
    /// A journal and its checkpoints carry M2's own format stamps, and M2
    /// refuses a board written under any other M2 format by name, with its
    /// one remedy, no migration (PUB-1.2); `OpenError::ForeignFormat` states
    /// the journal's channel and the checkpoint's. A checkpoint body that
    /// passes M2's header then meets the World's own format stamp, the door
    /// for a World layout that moves under an unchanged M2 stamp
    /// (`FormatStamp`'s card, `world.rs`, states which bases reach it). A
    /// checkpoint either door refuses hands M2's fallback chain its turn
    /// (PUB-7.9) — never a decoded world with an empty exception set.
    ///
    /// There is nothing to assemble beyond that recovery. The type registry
    /// M9 is handed at [`Engine::coordinator`] is `skep_links::registry` —
    /// M7's own compiled format constant, built once per process — so the
    /// instance a consumer reads *is* the one the store's fold and write gates
    /// run against, by construction rather than by an agreement anything here
    /// would have to keep.
    ///
    /// The kernel this hands [`EngineStores`] satisfies that constructor's
    /// precondition — its root satisfies [`World`]'s invariant — under either
    /// durability mode, by a different route each time. Journalled: M2 seeds
    /// whatever base it loads, a checkpoint or genesis, through
    /// `WorldState::rebuild_derived`, which establishes the invariant, and
    /// replays onto it through `WorldState::apply`, which preserves it.
    /// In-memory: M2 installs the passed world unrebuilt, and the passed world
    /// is [`World::genesis`], which satisfies the invariant as built and says
    /// why it must. So the mode that skips the rebuild is the mode whose root
    /// needs none.
    ///
    /// **Preconditions passed through, not discharged.** M2's caller contract
    /// on a journalled `cfg` — the kernel owns its names in the journal
    /// directory, creating, reading and deleting the segment, checkpoint and
    /// lock files, and creating, never removing, the files its tail cut keeps
    /// (§7), and leaves every other name alone — binds this method's caller
    /// unchanged. So does M2's salt discipline on `cfg.salt`, which no
    /// configuration can check and nothing here enforces: `SaltSource::Os` for
    /// every deployment, `SaltSource::Seeded` for fixtures and tests alone — a
    /// daemon opened under a seeded source serves chain values a reader can
    /// invert (M2's `SaltSource`). The crate root re-exports every type a
    /// `KernelConfig` is built from, so a binary can open an engine without
    /// naming M2; this card is where it reads both contracts. M2's genesis
    /// contracts, byte-identical on every reopen and consistent in its derived
    /// state as passed, are the caller contracts this method discharges.
    ///
    /// **The identity slice's load (AUTH-2.83–2.86).** A retained checkpoint
    /// written *without* the slice — by a build that writes none — is a start
    /// point only where its link slice holds no credential deposit, resolving
    /// to the empty table; one holding any is *not* a start point, and M2's
    /// fallback chain steps back to the next-older retained checkpoint that
    /// is, or to genesis while the journal reaches it, and replays forward —
    /// the true table, slower, once; with no start point left the open
    /// refuses, `OpenError::BadCheckpoint` carrying the slice's own sentence
    /// and remedy (AUTH-2.88). What the chain did is [`Engine::recovery`]'s to
    /// tell, and the daemon's to log.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Open`] carrying M2's `OpenError` whole where
    /// `Kernel::open` refuses: an invalid configuration, a journal under
    /// another format, an I/O failure, an exhausted fallback chain, or durable
    /// committed data that cannot be read or is not the history it claims to
    /// be.
    ///
    /// # Panics
    ///
    /// Panics, rather than returning `Err`, under `Durability::Fsync` when
    /// recovery meets state that decodes but violates a structural fact a fold
    /// or a rebuild asserts — the stores' own, M7's that every link key is a
    /// T4-valid element address among them, and the exception set's that a
    /// registered draft's owner resolves to an account, reached from a
    /// checkpoint base through its seed and from a replayed `Allocate` through
    /// its fold. `WorldState::rebuild_derived`'s one error channel is the
    /// identity slice's refusal above, `WorldState::apply` has none, and M2
    /// selects and folds a base with no unwind boundary, so such a checkpoint
    /// does not fall back to an older retained base. No state the stores' ops
    /// produce holds such a shape.
    pub fn open(cfg: KernelConfig) -> Result<Engine, EngineError> {
        let kernel = Arc::new(Kernel::open(cfg, World::genesis())?);
        // M2's account of the open, and the assembler's one addition to it —
        // read off the recovered root before anything commits over it, which
        // is this constructor's own position.
        let recovery = kernel.recovery().map(|found| Recovery {
            start_point: found.start_point,
            skipped: found.skipped.clone(),
            replayed: found.replayed,
            tail_cut: found.tail_cut,
            tail_cut_intact: found.tail_cut_intact,
            tail_cut_from: found.tail_cut_from.clone(),
            tail_cut_kept: found.tail_cut_kept.clone(),
            tail_cut_claimed: found.tail_cut_claimed,
            began: found.began,
            runs_passed_over: found.runs_passed_over,
            first_run_passed_over: found.first_run_passed_over.clone(),
            identity_resolved_empty: kernel.snapshot().world().identity_resolved,
        });
        Ok(Engine { stores: EngineStores::new(kernel), recovery })
    }

    /// Returns what this engine's open found in the journal directory and did.
    ///
    /// That is the [`Recovery`]: the start point, the checkpoints it passed
    /// over, the commits it replayed, the tail it cut, and whether the start
    /// point's identity slice resolved empty — `None` under
    /// `Durability::InMemory`. Fixed at [`Engine::open`]; a checkpoint taken
    /// since does not move it.
    pub fn recovery(&self) -> Option<&Recovery> {
        self.recovery.as_ref()
    }

    /// Returns the kernel (M2).
    ///
    /// Snapshots, checkpoints, and `current_seq` are reached through this; the
    /// engine adds nothing over them. [`Engine::world_at`] is the one M2
    /// method the engine forwards rather than leaves to this handle, and it
    /// forwards verbatim.
    ///
    /// A borrow, matching `Stores::kernel` below: that the kernel is shared
    /// behind an `Arc` is how the engine hands the same one to M9 and to every
    /// driver, and it is not something a reader of this method needs to hold.
    /// The shared-ownership seam is [`EngineStores`], which clones.
    pub fn kernel(&self) -> &Kernel<World> {
        &self.stores.kernel
    }

    /// Returns the one registry: M7's own module constant, reached not rebuilt.
    ///
    /// It is the one M9 projects (M9 builds no second `TypeRegistry`). It is a
    /// process constant and not this handle's state, so every engine answers
    /// with the same instance and a world's own slice answers with it too;
    /// the world dump reads it off the slice for that reason.
    ///
    /// `'static`, because that is what it is: the borrow outlives this handle,
    /// and a caller keeping the registry past the engine that named it is
    /// holding a compiled constant rather than a dangling piece of state. The
    /// `Arc` stays because M9 takes an owned one — [`Engine::coordinator`]
    /// clones through here — so the shared ownership is real.
    pub fn registry(&self) -> &'static Arc<TypeRegistry> {
        skep_links::registry()
    }

    /// Returns M3's driver, which borrows the kernel for the call.
    pub fn namespace(&self) -> Namespace<'_, World> {
        self.stores.namespace()
    }

    /// Returns the attested M3 driver (signed ops).
    ///
    /// That is [`Engine::namespace`] with the attestation its two document
    /// mints commit under — `Stores`' `namespace_attested` body, the one M10's
    /// dispatch acquires for a mint the daemon's check admitted. `None` is
    /// [`Engine::namespace`] exactly.
    pub fn namespace_attested<'a>(&'a self, attest: Option<&'a Attestation>) -> Namespace<'a, World> {
        self.stores.namespace_attested(attest)
    }

    /// Returns M5's driver, which borrows the kernel for the call.
    pub fn vstream(&self) -> Vstream<'_, World> {
        self.stores.vstream()
    }

    /// Returns M7's driver over the kernel and the caller's visibility class.
    ///
    /// It borrows the two and holds nothing else. The class is the caller's
    /// to thread: an engine-direct caller passes [`World::visible_to`] of the
    /// `Caller` it will write as; M10 passes its session principal's through
    /// [`EngineStores`]; M9 receives the guest class through
    /// [`Engine::coordinator`].
    pub fn linkstore<'a>(&'a self, visibility: &'a Visibility<'a, World>) -> LinkWriter<'a, World> {
        self.stores.linkstore(visibility)
    }

    /// Assembles M9's `Coordinator` (M9 interface: "engine-assembled").
    ///
    /// It is the shared kernel, the one registry, the two op-handle factories
    /// whose bodies discharge M9's standing assembly obligation (constructing
    /// `Vstream` from `&Kernel<W>`, and `LinkWriter` from `&Kernel<W>` plus
    /// the visibility class M9 lends it), and the read predicate M9's fires
    /// run at. M9 is the System caller — the one that writes as no principal
    /// — so its class is [`World::visible_to`]'s System arm, asked for here
    /// rather than restated: `readable(None, ·)`, publication at the
    /// document's trunk (PUB-2.15), so a rule's effect never crosses the
    /// draft boundary. M9 threads that same predicate into every writer it
    /// builds (PUB-6.28), so a fire's value-keyed gates see only
    /// guest-readable incumbents. Infallible: M9's catalog is a pure
    /// projection of the injected registry — with the type set compiled into
    /// the format there is no twice-passed configuration whose drift a
    /// validate-once-or-fail step would catch.
    ///
    /// M9 places three obligations on the values injected here, and its types
    /// carry part of one: the factory types are `fn` pointers, which hold
    /// nothing. The rest is discharged by construction. The two factories are
    /// named fn items whose bodies build their handle over exactly the kernel
    /// — and, for the writer, the visibility class — they are handed. The
    /// guest predicate is [`World::visible_to`]'s System arm, pure and total
    /// as that method states. For an address M3 never registered it answers
    /// `true` — PUB-7.5's fail-open sign, and the answer M10's
    /// `ReadableWorld` requires of the same predicate — not the `false` M9's
    /// constructor calls safe, so a fire whose action home no mint produced
    /// passes the draft boundary and is refused by M7's H-HOME gate, as
    /// `FireError::HomeNotRegistered`
    /// (`a_fire_into_a_home_no_mint_produced_is_refused_as_not_registered`).
    ///
    /// With one exception, the one [`World::readable`] and its
    /// `ReadableWorld` impl record: an address shaped as a version member of
    /// a registered draft reads as that draft, so a fire whose home — or
    /// whose bound argument's document — is such an address is refused at
    /// the draft boundary, as `FireError::DraftBoundary` naming an address no
    /// mint produced, ahead of H-HOME
    /// (`a_fire_into_a_version_member_shaped_home_under_a_draft_is_refused_at_the_draft_boundary`).
    pub fn coordinator(&self) -> Coordinator<World> {
        Coordinator::new(
            Arc::clone(&self.stores.kernel),
            Arc::clone(self.registry()),
            mk_vstream,
            mk_link_writer,
            World::visible_to(Caller::System),
        )
    }

    /// Returns the `Stores<World>` factory the transport passes on.
    ///
    /// It goes to M10's `OperationSurface::new`: a clone of the handle on this
    /// engine's one kernel, never a second kernel. The drivers it yields are
    /// M10's — `Stores`' provided bodies, built over that kernel — and it is
    /// the handle an in-process writer outside M10 holds too
    /// ([`EngineStores`] states both).
    pub fn stores(&self) -> EngineStores {
        self.stores.clone()
    }

    /// Returns the committed world as of position `at`.
    ///
    /// It is [`Kernel::world_at`] over the assembled world, forwarded
    /// verbatim. The contract and the cost are M2's, at that link.
    ///
    /// **Postcondition.** It is the assembler's rather than M2's, because the
    /// invariant it names is [`World`]'s: the returned world satisfies that
    /// invariant — its derived state agrees with its authoritative state. M2
    /// seeds every base it selects through [`WorldState::rebuild_derived`],
    /// which establishes it, and folds onto that base through
    /// [`WorldState::apply`], which carries both derived indexes on their own
    /// arms and so preserves it. A reconstruction therefore needs no rebuild
    /// from its receiver: it may be dumped, checked, served at a reader's
    /// class, or paired with a kernel at [`EngineStores::new`], whose
    /// precondition it discharges. That is the one thing a caller must know
    /// and M2 cannot say, being generic over every `WorldState` and knowing
    /// nothing of this world's indexes.
    ///
    /// # Errors
    ///
    /// Returns the [`HistoryError`] [`Kernel::world_at`] refuses with, in the
    /// refusal precedence stated there: `Unjournaled` under
    /// `Durability::InMemory`, `BeyondHead` for a position above the
    /// installed head, `Reclaimed` where no base at or below `at` remains
    /// derivable, `Corruption` from the scan, `NotABoundary` for a position
    /// that is no committed boundary, and `Corruption` from the fold; `Io`
    /// speaks wherever the read that failed sits.
    ///
    /// # Panics
    ///
    /// Panics on the shapes [`Engine::open`] names, since M2 seeds every base
    /// it selects through the same rebuild and folds the same records over it,
    /// with no unwind boundary. A caller that serves historical reads per
    /// request holds its own panic boundary around this call; the daemon's
    /// request handler does.
    ///
    /// [`WorldState::apply`]: skep_kernel::WorldState::apply
    /// [`WorldState::rebuild_derived`]: skep_kernel::WorldState::rebuild_derived
    pub fn world_at(&self, at: Seq) -> Result<World, HistoryError> {
        self.kernel().world_at(at)
    }
}

/// Returns a `Vstream` over `k`: one factory body, as a named fn item.
///
/// M9's factory bodies are named fn items — this and `mk_link_writer` —
/// which coerce to its `for<'k>` `fn`-pointer factory types: each declares
/// its lifetime on itself, where `Vstream::new` and `LinkWriter::new` take
/// theirs from their impls and so do not coerce themselves.
fn mk_vstream(k: &Kernel<World>) -> Vstream<'_, World> {
    Vstream::new(k)
}

fn mk_link_writer<'k>(
    k: &'k Kernel<World>,
    visibility: &'k Visibility<'k, World>,
) -> LinkWriter<'k, World> {
    LinkWriter::new(k, visibility)
}

/// The concrete `Stores<World>` impl: the factory the transport injects.
///
/// It is the factory passed to M10's `OperationSurface::new` at startup (M10
/// §Seams). It holds the engine's one kernel and nothing else: the three
/// drivers are `Stores`' provided bodies, each a fresh handle built over
/// that kernel per call.
///
/// Cloning it is how the engine's one kernel is shared outside [`Engine`]:
/// M10's transport holds one clone, and an in-process writer outside M10 —
/// the daemon's write path and its head writer — holds another, reaching the
/// same drivers through the same provided bodies. [`Engine::kernel`] names it
/// the shared-ownership seam for that reason.
#[derive(Clone, Debug)]
pub struct EngineStores {
    kernel: Arc<Kernel<World>>,
}

impl EngineStores {
    /// Returns the factory over `kernel`, any `Kernel<World>`.
    ///
    /// That is the live recovered one [`Engine`] holds, or a throwaway kernel
    /// rooted at a reconstructed historical world. Holding the kernel is the
    /// whole of what an assembler owes `Stores<World>`: all three drivers
    /// follow from it, and the trait gives them. The engine's own
    /// `namespace`/`vstream`/`linkstore` read through this type, so a caller
    /// that has a kernel and needs an M10 over it asks for this rather than
    /// writing a second `Stores` impl, which would owe M10's one-kernel
    /// precondition afresh.
    ///
    /// **Precondition.** It is the assembler's to state, because the pairing
    /// is the assembler's: `kernel`'s installed world satisfies [`World`]'s
    /// invariant — its derived state agrees with its authoritative state.
    /// Every world this crate hands out satisfies it — [`World::genesis`] as
    /// built, and each [`Engine::world_at`] reconstruction — and [`World`]'s
    /// note names the paths that establish and preserve it.
    /// `Durability::InMemory` installs the passed world unrebuilt, so a
    /// `World` that arrived any other way (deserialized straight from bytes,
    /// say) is served here exactly as it arrived; [`World`]'s note says what
    /// reads then answer.
    pub fn new(kernel: Arc<Kernel<World>>) -> EngineStores {
        EngineStores { kernel }
    }
}

/// The `Stores<World>` impl: the one kernel every driver M10 acquires.
///
/// The kernel every driver is built over is the one method this impl
/// writes, the drivers and the halt report being `Stores`' provided bodies
/// over it (M7's writer among the drivers, at the class M10 hands in per
/// write).
///
/// M10 places one precondition on an implementer: this answers the same
/// kernel on every call, since every coordinate M10 reports rests on it. It is
/// discharged by construction — one `Arc`, fixed at [`EngineStores::new`] and
/// never replaced, shared by every clone of the handle
/// (`every_stores_clone_answers_the_engine_s_one_kernel` holds it). Overriding
/// one of the provided bodies here would take that obligation back on for
/// what it returned.
impl Stores<World> for EngineStores {
    fn kernel(&self) -> &Kernel<World> {
        &self.kernel
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::testkit::mem_engine;
    use crate::{Draft, IssuerGrantIndexRow, ReaderClass, Record, UniversalGrantIndexRow};

    use super::*;

    /// Checks M10's one precondition on a `Stores` implementer: one kernel.
    ///
    /// The engine's own kernel read, the factory [`Engine::stores`] hands out,
    /// and a clone of that factory all answer one kernel. Every coordinate M10
    /// reports rests on it — `log_position` and each read's `as_of` come from
    /// `kernel()`, while each link write commits through
    /// `linkstore_attested()` — and the discharge is structural, one `Arc`
    /// fixed at construction, so this is what fails if the handle ever learns
    /// to swap or reopen its kernel.
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

    /// Checks that a caller's type holding the assembled types derives `Debug`.
    ///
    /// What a missing `Debug` costs is not the print, it is the wall: a
    /// caller's own type holding an assembled engine derives its own. Held of
    /// the engine, its stores factory and the world, and of the central record
    /// and a reader class — those two through a bound rather than a value,
    /// since each store's record is that store's to construct and a reader
    /// class borrows the world it reads.
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
        // …and the world renders as itself and nothing of its slices: its
        // rendering is a `WorldDump`, asked for.
        assert!(rendered.contains("World"), "the world renders as itself: {rendered}");
        assert!(
            !rendered.contains("namespace"),
            "a world's slices are not a debug form: {rendered}"
        );
    }

    /// Checks that the enumeration rows are ordered, hashable values.
    ///
    /// The enumeration rows are values a caller keys collections by, so each
    /// carries every standard trait its fields support: a row sorts, and goes
    /// into a `BTreeSet` or a `HashSet`, with nothing wrapped around it. A
    /// derive dropped from one of them is a wall and not an omission, since a
    /// caller cannot implement a standard trait for a type it does not own.
    #[test]
    fn the_enumeration_rows_are_ordered_hashable_values() {
        fn assert_value<T: Clone + fmt::Debug + Eq + std::hash::Hash + Ord>() {}
        assert_value::<Draft<'static>>();
        assert_value::<UniversalGrantIndexRow<'static>>();
        assert_value::<IssuerGrantIndexRow<'static>>();
    }

    /// Checks an open failure carries the kernel's own account both ways.
    ///
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
