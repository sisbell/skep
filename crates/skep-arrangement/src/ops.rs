//! §B / §3–§7 — the editing & versioning surface: `Vstream`, one M2
//! `transact` per operation, every mutation under an M3 lock key for the
//! touched document's allocation domain (§Serialization key).
//!
//! A REJECTION LEAVES NO STATE CHANGE, and that is M2's guarantee rather than
//! an ordering these ops keep: `transact` returns `TxnError::Rejected(E)`
//! straight out of the closure phase, discarding the staging, drawing no
//! `Seq` and appending nothing. Four of the six ops do reject before staging
//! anything; INSERT and the publish shot cannot, since each stages a mint and
//! a content write per fresh value as it goes ([`allocate_for_placement`],
//! J0's one step) and may reject after them — on a later value, and for the
//! shot on its run budget or its own version mint as well.
//! M10 surfaces the rejection as a typed one and acknowledges only after
//! commit.
//!
//! Ownership: five ops take a [`Caller`] and open with [`gate_write`] — the
//! in-txn ω gate — on the address the caller NAMES: the four edits and the
//! shot (COPY: its destination only; VERSION is ungated, non-owner
//! versioning being denial-as-fork, O10). The address named is not always
//! the arrangement written. A DECLARED DEPOSIT into a published chain that
//! has a head lands on that head ([`deposit_surface`]) rather than in the
//! named address's arrangement, and a shot writes only the member it mints;
//! both are members of the named document's chain, minted under it, so the
//! owner the gate checked is theirs too.
//!
//! Publication (PUB round 2, lane 3.1; owner ruling D2b): the version-chain
//! model's refusals, each stated with its op's check order, are evaluated
//! inside that op's own transaction on an address its own check has already
//! found registered (PUB-6.37), and are enforced here whatever runs ahead of
//! the store. Their one reading of the publication bit is
//! [`published_target`], whose own card says why it is public.
//!
//! WHICH ERROR WINS when several conditions fail at once is stated on each op
//! below, and this is the only statement of it: the error types name verdicts,
//! not precedence, and the integration suite pins what is written here.
//!
//! Per-op trait bounds: each impl block names exactly the slices its ops
//! read and the records they stage, so a minimal test world can drive
//! `delete`/`rearrange` with `HasM5 + HasM3` and `From<M5Rec>` alone.

use std::collections::BTreeSet;
use std::fmt;

use num_traits::{One, Zero};
use skep_address::{content_subspace, document_of, Address, Nat};
use skep_content::{stage_write, ContentError, ContentWrite, HasContent, Val};
use skep_kernel::{Kernel, Seq, Staging, TxnError, WorldState};
use skep_namespace::{HasM3, M3Rec, M3State, MintError, PrincipalId};

use crate::auth::{gate_write, Caller};
use crate::chain::{deposit_surface, published_target, reading_surface, trunk_head, trunk_of};
use crate::error::{
    CopyError, DeleteError, InsertError, PublishError, RearrangeError, VersionError,
};
use crate::run::Run;
use crate::runlist::extend_or_push_run;
use crate::shot::Shot;
use crate::state::M5Rec;
use crate::vspace::{as_ordinal_vspan, VPos, VSpec};
use crate::HasM5;

/// The deposit DECLARATION an INSERT carries or omits (PUB-9.13's DECLARED
/// horn; PUB-2.59, PUB-2.61): the one claim on M5's write surface that clears
/// the in-place refusal on a published document, and only for an insert at a
/// fresh content position ([`Vstream::insert`] states the shape). Into a
/// private document it is inert. Content only — a link deposit is outside the
/// rule (PUB-2.12).
///
/// A type and not a flag because the claim is read where it is made, and the
/// two ways of making it wrongly are not alike. An insert that should have
/// been declared is refused `PublishedTarget`, loudly. A declaration on an
/// ordinary edit is admitted at a fresh position of a published document —
/// the write the refusal exists to stop, placed wherever [`deposit_surface`]
/// points — and nothing reports it; on the [`Caller::System`] path no ω check
/// stands between the claim and the arrangement either. For the same reason
/// there is no `From<bool>`: a boolean becomes this value with both arms
/// written out, where a reader sees which one is claimed.
///
/// Two variants because the corpus has two — an insert is declared or it is
/// not — so a match on it is exhaustive, and a third variant would change the
/// exemption itself. `Default` is `Undeclared`: the wire reads an absent,
/// `null` or `false` field as no declaration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Deposit {
    /// No declaration: an ordinary edit — and, on a published document, an
    /// in-place edit, refused.
    #[default]
    Undeclared,
    /// The deposit declaration: admitted on a published document at a fresh
    /// content position of the arrangement the deposit lands in.
    Declared,
}

/// The most runs one COPY, or one publish shot, may place — and so the
/// ceiling on what one request can make M5 hold live while it decides
/// whether to place anything at all.
///
/// The budget: a `Run` journals as an element `Address` and a width, about a
/// hundred bytes as bincode writes them, so M2's `MAX_TXN_BYTES` (64 MiB)
/// admits on the order of half a million of them and no more — past that the
/// transaction cannot commit whatever M5 does, and the work of building it
/// is spent for a refusal. `2^16` sits an order inside that ceiling, which
/// keeps the LIVE heap one placing request commands to the same order as the
/// transaction budget M2 already prices rather than several times it. The
/// arithmetic is checked against the real encoding rather than restated here
/// (`the_placement_budget_stays_inside_the_transaction_budget`).
///
/// IT BINDS WHAT ONE COPY OR ONE SHOT PLACES AND HOLDS LIVE, and that is the
/// whole of what it binds. Both accumulators are measured as each run is
/// accumulated, and what feeds them is pulled a run at a time — COPY's LAZY
/// resolution of each spec, the shot's walk of its base's carried tail — so
/// the cap also stops the walk: an over-budget request is refused at the cap
/// rather than built in full and measured afterwards.
///
/// THE REMEDY DIFFERS BETWEEN THE TWO. A copy needing more runs than this is
/// split by the caller, exactly as an over-budget transaction already is. A
/// shot CANNOT be split: the member it produces is born whole, from the
/// whole arrangement the client rendered plus the base's carried deposits.
/// For a shot the refusal is therefore a ceiling on the run count of the
/// member one shot produces — the client's runs as the accumulator coalesces
/// them, plus the base's deposit runs — and a retry of the same arrangement
/// is refused the same way.
///
/// WHAT IT DOES NOT BIND is the WORK of resolving, which is a separate
/// quantity with a separate owner. Each COPY spec costs a prefix-sum walk of
/// its source's run-list to reach the span — `Θ(#runs(source))` for a span
/// near the end, however narrow the answer — and a request multiplies that
/// by its spec count. Neither factor has a ceiling here: `#runs(source)` has
/// none in v1 (Open decision #1) and grows with editing, and a spec count is
/// bounded only by M10's wire list cap. So admission control and concurrency
/// for a route carrying COPY are the CALLER's, as they are for the reads that
/// state their own cost, and a route that carries this op owes that number.
/// The shot's own per-run work is stated on [`Vstream::publish`].
pub const MAX_PLACED_RUNS: usize = 1 << 16;

/// M5's transact-driving op handle over M2 (§B): a thin borrow of the
/// engine's kernel. The pure reads live on [`M5State`](crate::M5State)
/// (reached through [`HasM5`]); this type owns only the six editing/
/// versioning operations — INSERT, DELETE, COPY, REARRANGE, VERSION and the
/// publish SHOT — that M10 (and, for `insert`, M9) dispatches.
pub struct Vstream<'k, W: WorldState> {
    kernel: &'k Kernel<W>,
}

impl<'k, W: WorldState> Vstream<'k, W> {
    /// The only constructor — M10 (and M9, for predicate-def `insert`) build
    /// a Vstream over the engine's kernel this way.
    pub fn new(kernel: &'k Kernel<W>) -> Vstream<'k, W> {
        Vstream { kernel }
    }
}

/// The handle's name and nothing else — it holds one kernel borrow, and a
/// world is not a thing to print into a diagnostic. Written out rather than
/// derived: a derive would bound the impl on `W: Debug`, and a world composed
/// of persistent store slices need not be, so the derived impl would apply to
/// no `W` that exists.
impl<W: WorldState> fmt::Debug for Vstream<'_, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Vstream")
    }
}

impl<W> Vstream<'_, W>
where
    W: WorldState + HasM5 + HasM3 + HasContent, // reads M3 (registration, mints) + M4 (write) + M5
    W::Record: From<M5Rec> + From<M3Rec> + From<ContentWrite>, // stages M3Rec + ContentWrite + M5Rec
{
    /// INSERT (ASN-0116; §3): mint n fresh content addresses (M3), write
    /// their bytes (M4), splice the run at `at` (content subspace), record
    /// provenance — one M2 composite under
    /// `M3State::content_lock_key(doc)` and, for a declared deposit, its
    /// document's `version_lock_key`. Returns the inserted run's START
    /// address (the predicate-def identity for M9) and the commit `Seq`.
    ///
    /// Check order (which error wins): `DocNotRegistered` → `NotOwner` (the
    /// in-txn ω gate) → `PublishedTarget` (below) → `EmptyContent` →
    /// `NotContentSubspace` (`at.subspace ≠ s_C`) → `OutOfBounds` (the
    /// arrangement does not admit `at.ordinal` as a placement boundary —
    /// Valid(First)InsertionPosition, so ordinal = 1 when n_C = 0). Then,
    /// PER VALUE in the order given, `Mint` (the content mint) → `Content`
    /// (the byte write), with the FIRST value to fail deciding.
    ///
    /// THE PUBLISHED TARGET, and the deposit that clears it (PUB-2.11,
    /// PUB-2.59, PUB-2.61; PUB-9.13's DECLARED horn, owner-ruled). When the
    /// document `doc` projects to (PUB-2.15) is PUBLISHED, an insert is an
    /// in-place edit (PUB-2.11's in-place advance) and refuses
    /// `PublishedTarget` — UNLESS `deposit` is [`Deposit::Declared`] AND the
    /// insert is deposit-SHAPED: `at` names a fresh content position past the
    /// arranged extent, so the placement appends and disturbs no arrangement.
    /// The declaration is a claim the shape must bear out, never a bypass: a
    /// declared insert at an arranged position refuses with the same code, and
    /// an UNDECLARED append refuses too (the cost RES-209 item 5 named,
    /// closed). Into a PRIVATE document
    /// the declaration is inert — every insert is admitted there as before.
    /// A declared deposit whose fresh position lies past the append boundary
    /// clears this refusal and meets `OutOfBounds` below, so it is told its
    /// position is bad rather than that its target is published.
    /// `Caller::System` is NOT exempt (PUB-6.28): a rule fire never advances
    /// a published arrangement in place.
    ///
    /// So a published document admits exactly ONE insert: a declared deposit
    /// at `[s_C, n_C + 1]` of the arrangement it lands in — the one position
    /// both fresh and inside the append boundary. A caller builds that
    /// position by asking [`deposit_surface`] for the arrangement and
    /// [`content_count`](crate::M5State::content_count) of it for `n_C`. A
    /// position read before another deposit landed there is no longer fresh,
    /// and the deposit carrying it is refused `PublishedTarget` like any
    /// in-place edit — the remedy being a fresh position, not the draft the
    /// refusal's face proposes.
    ///
    /// AN ACCOUNT'S HOME IS SUCH A TARGET. The flagless first mint into an
    /// empty account is born published — M3's own create path resolves that
    /// bit (PUB-8.21), not a flag the caller sent — so content enters doc 1
    /// only by a DECLARED deposit at a fresh position: the record atoms that
    /// accrete there outside the version discipline (PUB-2.4, PUB-2.60), its
    /// prose advancing by shots like any edition's (PUB-2.58). A client or
    /// fixture that mints a home and then inserts into it undeclared meets
    /// this refusal, and that is the rule working; the account's LATER
    /// flagless mints are private by default (PUB-1.1) and take an ordinary
    /// insert.
    ///
    /// WHICH ARRANGEMENT THE DEPOSIT LANDS IN (PUB-2.65, PUB-2.66; lane 3.2's
    /// ruling): the HEAD member's, ALONE — the version-chain reads' own answer
    /// ([`deposit_surface`]), which is the trunk head once the chain has one
    /// ([`trunk_head`]), whichever address of the chain the caller named: the
    /// bare document, the head itself, or a pinned member, which never grows.
    /// It differs from the [`reading_surface`] at exactly that pinned member,
    /// whose readers answer the member itself. `at` is therefore judged fresh
    /// against the HEAD's extent, and the placement record names the head.
    /// While the document has no member the deposit lands in its own
    /// arrangement, which is what its readers answer from until a head exists
    /// (PUB-2.66's memberless reading). The atom's IDENTITY is minted under
    /// the content chain of the address the caller NAMED (`mint_content(doc)`)
    /// — the document's own I-space for a bare address, one prefix down the
    /// chain (PUB-2.52) — so the start returned is under that chain; only the
    /// placement floats.
    ///
    /// Only one of those last two is a verdict an honest request can earn.
    /// `Mint(MintError::Gate)` is M3's defence against a corrupted frontier;
    /// `Mint(MintError::HomeNotRegistered)` cannot arrive past the gate above
    /// and is M3's own boundary discharge; and `Content(AlreadyPresent)`
    /// cannot occur in production at all — M3 mints fresh and M5 writes once,
    /// which is the argument `stage_write` itself makes for keeping the guard.
    ///
    /// COST, AND WHO OWNS IT. This op admits any `values` length: there is no
    /// analogue of COPY's [`MAX_PLACED_RUNS`](crate::MAX_PLACED_RUNS) here,
    /// and none is owed, because the size of an INSERT is the size of the
    /// request that carries it rather than a source document's fragmentation
    /// multiplied by a spec count. What `n` values cost is `2n + 1` staged
    /// records — a mint and a content write apiece, plus one placement — and
    /// `n` content addresses that are allocated permanently, M5 having no
    /// reclamation path. M2's `MAX_TXN_BYTES` refuses the transaction past its
    /// own ceiling, but it refuses AFTER the mints and writes are staged, so
    /// a caller that wants the refusal to arrive before that work owes its own
    /// cap: M10's codec sets one on the wire route (`MAX_INSERT_VALUES`), and
    /// a route that carries this op without one owes the number.
    ///
    /// J0/J1★ by construction: mint + write + place + provenance ride one
    /// transaction, each value through `allocate_for_placement` — J0's one
    /// step, shared with the shot's re-insert, whose own doc states why the
    /// placement it accumulates is never widened over addresses nobody
    /// allocated. INSERT's values are minted one after another under the held
    /// content key, so they are I-adjacent and INSERT places exactly ONE run,
    /// whose start is the first address minted.
    pub fn insert(
        &self,
        caller: Caller,
        doc: &Address,
        at: VPos,
        values: Vec<Val>,
        deposit: Deposit,
    ) -> Result<(Address, Seq), TxnError<InsertError>> {
        // The mint chain's key, and — for a declared deposit — the key of the
        // chain frontier it reads to find where it lands on a published
        // document (`deposit_surface` → `trunk_head`). Every transaction that
        // advances that frontier, or writes the arrangement a published
        // chain's deposits land in, holds the same key, so the landing decided
        // inside cannot move under it. Both keys are arithmetic on the
        // request; neither is read from the world.
        let declared = deposit == Deposit::Declared;
        let mut keys = vec![M3State::content_lock_key(doc)];
        if declared {
            keys.push(M3State::version_lock_key(&trunk_of(doc)));
        }
        self.kernel.transact(&keys, |stg| {
            gate_write(
                stg.working().m3(),
                caller,
                doc,
                InsertError::DocNotRegistered,
                InsertError::NotOwner,
            )?;
            // PUB-6.36 slot 5: on a registered, owned target, the
            // published-target refusal — cleared only by a DECLARED deposit
            // at a FRESH position (PUB-2.59, PUB-9.13) of the arrangement the
            // deposit lands in: the HEAD member's, or the document's own
            // while it has none (PUB-2.66).
            let surface = {
                let world = stg.working();
                let m3 = world.m3();
                let surface = deposit_surface(m3, doc);
                if published_target(m3, doc)
                    && !(declared && world.m5().names_fresh_content_position(&surface, &at))
                {
                    return Err(InsertError::PublishedTarget);
                }
                surface
            };
            if values.is_empty() {
                return Err(InsertError::EmptyContent);
            }
            if !at.is_content() {
                return Err(InsertError::NotContentSubspace);
            }
            if !stg.working().m5().admits_content_boundary(&surface, &at.ordinal) {
                return Err(InsertError::OutOfBounds);
            }
            let mut runs: Vec<Run> = Vec::new();
            for value in values {
                allocate_for_placement::<_, InsertError>(stg, doc, value, &mut runs)?;
            }
            // The placement's start is the FIRST address minted: the
            // accumulator only ever widens a run rightwards or opens a new
            // one after it, so the first run's start is the first mint.
            let start = runs
                .first()
                .expect("EmptyContent guard ⇒ at least one value ⇒ at least one run")
                .i_start()
                .clone();
            stg.push(
                M5Rec::ContentPlace {
                    doc: surface,
                    at: at.ordinal,
                    runs,
                }
                .into(),
            );
            Ok(start)
        })
    }

    /// PUBLISH — the SHOT (PUB-2.33; PUB round 2, lane 3.2): append the next
    /// member of `doc`'s chain, born PUBLISHED, in ONE commit, its
    /// arrangement taken from the CLIENT-SUPPLIED runs of `shot` (PUB-8.1)
    /// and from nothing any draft holds at commit. Returns the member's
    /// address and the commit `Seq`. The birth version of the mint ceremony
    /// (PUB-2.34) is this same composite with `shot.base` absent.
    ///
    /// DESTINATION (PUB-2.37, PUB-2.39, PUB-2.55): the next member of the
    /// chain anchored at the base, decided AT COMMIT — the trunk's next
    /// member (`mint_version(doc)`, `D.4`) when the base is still the trunk
    /// head ([`trunk_head`], the head every reader floats to, read before
    /// the member is minted), the base's own DAUGHTER (`mint_version(base)`,
    /// `D.3.1`) when it is not. Two shots racing off one head both commit,
    /// the first on the trunk and the second as the head's daughter
    /// (PUB-2.44); nothing is positionally applied to an advanced head and
    /// nothing is refused for want of a base (PUB-2.38). A memberless
    /// document is its own base — the chain's first member is `D.1` either
    /// way — and the base absent is that same birth shape (PUB-2.34),
    /// admitted only while the chain is empty: once a member exists the
    /// document's own pre-chain arrangement is no base, and the shot must
    /// name the member it was staged from (`BaseSuperseded`).
    ///
    /// THE MEMBER'S ARRANGEMENT (PUB-2.40, PUB-2.41, PUB-2.42): each supplied
    /// run by its ORIGIN DOCUMENT — the trunk (PUB-2.15) of the document that
    /// minted its addresses, which the run's own start settles (`document_of`
    /// then `trunk_of`) and the client's stated `origin` must project to. The
    /// document's OWN I-space (its own chain or any member's) is placed by
    /// reference; the STAGING DRAFT's is RE-INSERTED as fresh identity under
    /// the document's own I-space, each value through INSERT's own
    /// allocation step (`allocate_for_placement`), the bytes read at the
    /// draft's addresses — a byte read, never an arrangement read — so the
    /// committed member references no address of the draft; any OTHER
    /// document's stays a window, answering its origin. The runs are placed
    /// in the order given, then the BASE'S POST-RENDER DEPOSITS after them: a
    /// published member changes only by exempt deposits appended at fresh
    /// positions (PUB-2.43), so its positions past `base.extent` — the extent
    /// the staged copy took — are exactly the deposits the render post-dates,
    /// asked of the base's arrangement, which knows its own extent, and
    /// carried unchanged (PUB-2.45, PUB-2.67). What the shot un-arranges is
    /// what the stager un-arranged and nothing else. One `ContentPlace` at
    /// ordinal 1 journals the whole arrangement — the fold appends every
    /// placed run's extent to R (J1★), the by-reference runs as COPY's are and
    /// the fresh ones as INSERT's; an empty placement pushes no record, the
    /// member then reading as the lazy empty arrangement.
    ///
    /// Check order (which error wins), PUB-6.36's slots: `DocNotRegistered`
    /// → `NotOwner` (slot 1, the destination's ω) → registration (slot 3):
    /// `SourceNotRegistered` for the base, then the draft, then each run's
    /// origin document in run order, each run's SHAPE (`BadRun`) settled as
    /// its origin document is derived → `PrivateSourceVersionless` (slot 5: a
    /// private document has no chain, PUB-2.9's `true` face) → the base's
    /// shape: `BaseNotInChain` → `BaseSuperseded` → `BaseExtentTooLarge` →
    /// the SOURCE GATE (slot 6, PUB-6.23; PUB-8.1's second constraint):
    /// `readable` consulted PER DISTINCT ORIGIN DOCUMENT, in run order,
    /// skipping the document's own I-space and every run the base already
    /// arranges (PUB-6.24's carried cell), the FIRST unreadable origin
    /// document answering `Withheld` with it — BEFORE any existence answer,
    /// so a run onto an unreadable origin is refused whether or not its
    /// addresses exist → existence, `DanglingSource` on the first run any of
    /// whose addresses M4 does not hold → `TooManyRuns` as the placement is
    /// accumulated → `Mint` / `Content` from the mints and writes.
    ///
    /// `readable(world, origin_doc)` answers whether the shooter may read
    /// `origin_doc`; `true` admits it. M5 hands it the TRANSACTION's working
    /// world — the world in which `publish` has just found `origin_doc`
    /// registered — and asks only about an ORIGIN DOCUMENT (PUB-2.15): once
    /// per distinct origin document, in run order, skipping the document's
    /// own and every run the base already arranges. Because it is never asked
    /// of a world that has not registered what it is asked about, a predicate
    /// that is fail-open on an unregistered address (PUB-7.5) cannot decide
    /// the gate.
    ///
    /// LOCKS: `version_lock_key(trunk_of(doc))` (the trunk's frontier),
    /// `content_lock_key(trunk_of(doc))` (the fresh-identity mints), and the
    /// base's own version key when the base is a member — the daughter
    /// chain's frontier, taken since which chain the member joins is decided
    /// inside. Every origin is read off the transaction's working world; no
    /// origin is locked (a window is a reference).
    ///
    /// A member address given as `doc` is projected to its document first:
    /// the shot is the document's, whichever member names it.
    ///
    /// `shot` is taken by value because the composite keeps it: the member's
    /// arrangement is built from the shot's runs, and each by-reference run
    /// moves into the placement record rather than being cloned out of a
    /// borrow.
    ///
    /// COST, AND WHO OWNS IT: the re-insert pushes `2n + 1` records for `n`
    /// draft-native values, exactly as INSERT does, plus one placement whose
    /// run count — the client's runs, coalesced, plus the base's deposit
    /// runs — is capped at [`MAX_PLACED_RUNS`](crate::MAX_PLACED_RUNS),
    /// measured as each run is accumulated; a ceiling a shot cannot be split
    /// to meet, since the member it produces is born whole. The carried-run
    /// test costs one sweep of the base's runs per supplied run. The wire caps
    /// the run list; a route that carries this op owes the value count.
    pub fn publish(
        &self,
        caller: Caller,
        doc: &Address,
        shot: Shot,
        readable: &dyn Fn(&W, &Address) -> bool,
    ) -> Result<(Address, Seq), TxnError<PublishError>> {
        let trunk = trunk_of(doc);
        let mut keys = vec![
            M3State::version_lock_key(&trunk),
            M3State::content_lock_key(&trunk),
        ];
        if let Some(base) = &shot.base {
            if base.member != trunk {
                keys.push(M3State::version_lock_key(&base.member));
            }
        }
        self.kernel.transact(&keys, |stg| {
            // Slot 1: the destination's registration and ω.
            gate_write(
                stg.working().m3(),
                caller,
                doc,
                PublishError::DocNotRegistered,
                PublishError::NotOwner,
            )?;
            let world = stg.working();
            let (m3, m5, content) = (world.m3(), world.m5(), world.content());
            // Slot 3: registration — the base, the draft, every origin
            // document (PUB-6.37: an unregistered argument answers
            // registration and nothing later).
            if let Some(base) = &shot.base {
                if !m3.is_registered_document(&base.member) {
                    return Err(PublishError::SourceNotRegistered);
                }
            }
            let draft_doc: Option<Address> = shot.draft.as_ref().map(trunk_of);
            if let Some(d) = &draft_doc {
                if !m3.is_registered_document(d) {
                    return Err(PublishError::SourceNotRegistered);
                }
            }
            // Each run's origin document, derived from its own start (address
            // arithmetic, no read) and required to be the document the
            // client's stated `origin` projects to — then registered.
            let mut origin_docs: Vec<Address> = Vec::with_capacity(shot.runs.len());
            for r in &shot.runs {
                let origin_doc = run_origin_document(&r.run).ok_or(PublishError::BadRun)?;
                if origin_doc != trunk_of(&r.origin) {
                    return Err(PublishError::BadRun);
                }
                if !m3.is_registered_document(&origin_doc) {
                    return Err(PublishError::SourceNotRegistered);
                }
                origin_docs.push(origin_doc);
            }
            // Slot 5: the model's refusal — a private document has no chain
            // to append to (PUB-2.9).
            if !published_target(m3, doc) {
                return Err(PublishError::PrivateSourceVersionless);
            }
            // The base's shape, and the anchor the member is minted under —
            // judged against the head every reader floats to, read before the
            // member is minted.
            let head = trunk_head(m3, doc);
            let anchor: Address = match &shot.base {
                None => {
                    if head.is_some() {
                        return Err(PublishError::BaseSuperseded);
                    }
                    trunk.clone()
                }
                Some(base) => {
                    if base.member == trunk {
                        if head.is_some() {
                            return Err(PublishError::BaseSuperseded);
                        }
                    } else if trunk_of(&base.member) != trunk {
                        return Err(PublishError::BaseNotInChain);
                    }
                    if base.extent > m5.content_count(&base.member) {
                        return Err(PublishError::BaseExtentTooLarge);
                    }
                    // The head/pinned distinction is the commit's own
                    // (PUB-2.39's head/older): the memberless document, or a
                    // base that is still the head ⇒ the trunk's next member;
                    // else the base's daughter.
                    if base.member == trunk || head.as_ref() == Some(&base.member) {
                        trunk.clone()
                    } else {
                        base.member.clone()
                    }
                }
            };
            // Slot 6: the source gate, per distinct origin document, in run
            // order — the document's own I-space needs no consult, a run the
            // base already arranges takes none (PUB-6.24), and the FIRST
            // unreadable origin document speaks before any existence answer.
            // An origin document is DECIDED only once the consult has admitted
            // it: a carried run marks nothing, so a later run from the same
            // origin that the base does not arrange is still asked about.
            let mut decided: BTreeSet<&Address> = BTreeSet::new();
            for (r, origin_doc) in shot.runs.iter().zip(&origin_docs) {
                if *origin_doc == trunk || decided.contains(origin_doc) {
                    continue;
                }
                let carried = shot
                    .base
                    .as_ref()
                    .is_some_and(|base| m5.arranges_run(&base.member, &r.run));
                if carried {
                    continue;
                }
                if !readable(world, origin_doc) {
                    return Err(PublishError::Withheld(origin_doc.clone()));
                }
                decided.insert(origin_doc);
            }
            // Existence (S3★): every address a run names holds a value —
            // the draft-native run's bytes are what is re-inserted, and a
            // by-reference run is the CLIENT's extent rather than one an
            // arrangement resolved, so each address is asked, not only the
            // start.
            for r in &shot.runs {
                if !r.run.addrs().all(|a| content.contains(a.tumbler())) {
                    return Err(PublishError::DanglingSource);
                }
            }
            // The member's arrangement: the client's runs in order — the
            // draft-native ones re-minted as fresh identity under the
            // document's own I-space — then the base's post-render deposits.
            let mut placed: Vec<Run> = Vec::new();
            for (r, origin_doc) in shot.runs.into_iter().zip(&origin_docs) {
                if draft_doc.as_ref() == Some(origin_doc) {
                    for a in r.run.addrs() {
                        let val = stg
                            .working()
                            .content()
                            .value_at(a.tumbler())
                            .cloned()
                            .expect("every address of every run was found present above");
                        allocate_for_placement::<_, PublishError>(stg, &trunk, val, &mut placed)?;
                    }
                } else {
                    extend_or_push_run(&mut placed, r.run);
                }
                if placed.len() > MAX_PLACED_RUNS {
                    return Err(PublishError::TooManyRuns);
                }
            }
            // The base's positions past the extent its staged copy took are
            // the deposits the render post-dates (PUB-2.43, PUB-2.45) — asked
            // of the arrangement, which knows its own extent, and measured as
            // each is accumulated, the walk stopping at the cap.
            if let Some(base) = &shot.base {
                for run in stg.working().m5().content_runs_past(&base.member, &base.extent) {
                    extend_or_push_run(&mut placed, run);
                    if placed.len() > MAX_PLACED_RUNS {
                        return Err(PublishError::TooManyRuns);
                    }
                }
            }
            // The member: born published (PUB-2.5, PUB-2.10), under the
            // anchor decided above.
            let (member, m3rec) = stg.working().m3().mint_version(&anchor, true)?;
            stg.push(m3rec.into());
            if !placed.is_empty() {
                stg.push(
                    M5Rec::ContentPlace {
                        doc: member.clone(),
                        at: Nat::one(),
                        runs: placed,
                    }
                    .into(),
                );
            }
            Ok(member)
        })
    }
}

/// A supplied run's ORIGIN DOCUMENT — the trunk (PUB-2.15) of the document
/// its addresses were minted under, `document_of` of its start and then
/// `trunk_of` — provided the start is a CONTENT element; `None` for a link
/// element or an address with no document. What the source gate asks about
/// and `Withheld` names (PUB-8.4's `site.addr`), and what a shot's stated
/// `origin` must project to. Pure address arithmetic: it reads nothing.
fn run_origin_document(run: &Run) -> Option<Address> {
    if run.i_start().subspace() != Some(&content_subspace()) {
        return None;
    }
    document_of(run.i_start()).map(|d| trunk_of(&d))
}

/// J0 at the composite boundary (content-allocation ⇒ placement): mint one
/// fresh content address under `home`'s I-space (M3), write `value` there
/// (M4), stage both records, and accumulate the address into the placement
/// `runs`. The ONE step INSERT and the publish shot's re-insert share, so
/// the coupling has one enforcement site: what is allocated here rides the
/// transaction the caller's placement record rides, and so cannot commit
/// unplaced. The mint precedes the write, which is the `Mint` → `Content`
/// order each of the two ops states for a value.
///
/// Successive calls read `stg.working()`, and under the content key both
/// callers hold for `home` (`M3State::content_lock_key`) they advance ONE
/// frontier and hand back I-adjacent addresses, which the accumulator
/// coalesces. The accumulator is ASKED rather than assumed: were the
/// frontier ever to hand back a non-adjacent address — a batched or striped
/// allocator in M3 — the placement would be a correct multi-run one, never a
/// single run widened over addresses M3 never allocated and M4 never wrote.
fn allocate_for_placement<W, E>(
    stg: &mut Staging<W>,
    home: &Address,
    value: Val,
    runs: &mut Vec<Run>,
) -> Result<(), E>
where
    W: WorldState + HasM3 + HasContent,
    W::Record: From<M3Rec> + From<ContentWrite>,
    E: From<MintError> + From<ContentError>,
{
    let (addr, m3rec) = stg.working().m3().mint_content(home)?;
    stg.push(m3rec.into());
    let write = stage_write(stg.working().content(), &addr, value)?;
    stg.push(write.into());
    extend_or_push_run(
        runs,
        Run {
            i_start: addr,
            width: Nat::one(),
        },
    );
    Ok(())
}

impl<W> Vstream<'_, W>
where
    W: WorldState + HasM5 + HasM3 + HasContent, // reads M3 (registration) + M4 (`contains` gate) + M5
    W::Record: From<M5Rec>,                     // stages only M5Rec (no mint, no byte write)
{
    /// COPY (ASN-0118; §5): transclude existing content by reference —
    /// resolve `specs` against source arrangements off the transaction's
    /// working state, splice into doc's content subspace at `at`, record
    /// provenance for the placed runs. Allocates NO content (CP1/CP2); the
    /// resolved addresses stay valid forever by content immutability (S0),
    /// so no source lock is needed.
    ///
    /// `specs` is borrowed: COPY reads each spec's source and span and keeps
    /// neither, so a caller that holds its spec list behind a reference is not
    /// made to clone it.
    ///
    /// Check order (which error wins). Destination first, as INSERT:
    /// `DocNotRegistered` → `NotOwner` (the ω gate on the DESTINATION only;
    /// source spans stay unrestricted, transclusion of anyone's content being
    /// the point of the medium) → `PublishedTarget` (PUB-2.11 on the
    /// DESTINATION's document, PUB-2.15 projected; copy-into is an in-place
    /// edit and carries no deposit exemption — the sources, published or
    /// private, are never what this refuses on) →
    /// `NotContentSubspace` → `OutOfBounds`. Then, per spec:
    /// `SourceNotRegistered`
    /// → `NotOrdinalVSpan` (the span fails
    /// [`is_ordinal_vspan`](crate::is_ordinal_vspan) — the one shape `resolve`
    /// folds on, so a span COPY rejects is exactly a span `resolve` would
    /// refuse to serve, Conflicts #7)
    /// → `SourceNotContentSubspace` (that span's subspace ≠ s_C)
    /// → `EmptySource` (ASN-0118
    /// enabled(COPY)) → per-run `DanglingSource` (`M4::contains` on the run
    /// start — S3★, Open decision #5 default) → `TooManyRuns`
    /// ([`MAX_PLACED_RUNS`](crate::MAX_PLACED_RUNS), measured after each run
    /// is accumulated; the resolution is pulled LAZILY, so an over-budget spec
    /// stops the source walk at the cap rather than being resolved in full and
    /// measured afterwards); finally `EmptyResult` when nothing survives
    /// clipping. Cross-origin runs never coalesce
    /// (the placement accumulator's I-adjacency guard), preserving the origin
    /// multiset (CP11).
    ///
    /// WHICH SPEC SPEAKS, when more than one is defective: the specs are
    /// examined in the order given and the FIRST spec to fail any of its
    /// guards decides, with the per-spec order above applying within that
    /// spec. So a mis-shaped span in an earlier spec outranks an unregistered
    /// source in a later one — the list is walked, not the guards.
    ///
    /// The two guards whose subject is not the request's shape but an
    /// invariant, stated so that widening what they gate obliges widening
    /// them:
    ///
    /// * `SourceNotContentSubspace` keeps LINK addresses out of content
    ///   V-positions. It is not a formality: `resolve` serves whichever
    ///   run-list the span's subspace numeral selects, so a link-subspace span
    ///   resolves against the source's LINK runs, and placing those here would
    ///   bind link addresses at content positions — links seated under an
    ///   origin that is not this document, which CL-OWN forbids and no read
    ///   downstream would report.
    /// * `DanglingSource` is S3★ on the content side, and it is checked on run
    ///   STARTS alone. Sound for the interior by induction: every address a
    ///   source arranges was itself admitted through this gate or written by
    ///   INSERT in the composite that placed it, so a present start implies a
    ///   present run. The induction is over the ways an address can enter an
    ///   arrangement — a new one obliges re-examining this check.
    pub fn copy(
        &self,
        caller: Caller,
        doc: &Address,
        at: VPos,
        specs: &[VSpec],
    ) -> Result<Seq, TxnError<CopyError>> {
        let key = M3State::content_lock_key(doc);
        self.kernel
            .transact(&[key], |stg| {
                let world = stg.working();
                gate_write(
                    world.m3(),
                    caller,
                    doc,
                    CopyError::DocNotRegistered,
                    CopyError::NotOwner,
                )?;
                // PUB-6.36 slot 5: the in-place advance refusal on the
                // destination (PUB-2.11).
                if published_target(world.m3(), doc) {
                    return Err(CopyError::PublishedTarget);
                }
                if !at.is_content() {
                    return Err(CopyError::NotContentSubspace);
                }
                if !world.m5().admits_content_boundary(doc, &at.ordinal) {
                    return Err(CopyError::OutOfBounds);
                }
                let mut runs: Vec<Run> = Vec::new();
                for spec in specs {
                    if !world.m3().is_registered_document(&spec.source) {
                        return Err(CopyError::SourceNotRegistered);
                    }
                    let span = &spec.span;
                    let Some(vspan) = as_ordinal_vspan(span) else {
                        return Err(CopyError::NotOrdinalVSpan);
                    };
                    if !vspan.is_content() {
                        return Err(CopyError::SourceNotContentSubspace);
                    }
                    if world.m5().content_count(&spec.source).is_zero() {
                        return Err(CopyError::EmptySource);
                    }
                    // Resolved BEFORE staging ⇒ a self-copy sees the pre-edit
                    // arrangement. Resolved LAZILY, so what one spec makes
                    // this closure hold live is the accumulator (capped
                    // below) and not the source's whole run-list, whose size
                    // the request does not choose.
                    for run in world.m5().iter_resolve(&spec.source, span) {
                        if !world.content().contains(run.i_start().tumbler()) {
                            return Err(CopyError::DanglingSource);
                        }
                        extend_or_push_run(&mut runs, run);
                        // Measured where the run is produced, not after the
                        // whole spec list has been folded: the accumulator is
                        // what a request's spec count multiplies, and a
                        // refusal that arrives at the end has already been
                        // paid for. With the resolution pulled lazily, this
                        // return also ends the source walk, so an over-budget
                        // spec is not resolved past the cap.
                        if runs.len() > MAX_PLACED_RUNS {
                            return Err(CopyError::TooManyRuns);
                        }
                    }
                }
                // Every `Run` has `width ≥ 1` by standing invariant, so a
                // nonempty accumulator places at least one position: the net
                // placement is empty exactly when nothing survived clipping.
                if runs.is_empty() {
                    return Err(CopyError::EmptyResult);
                }
                stg.push(
                    M5Rec::ContentPlace {
                        doc: doc.clone(),
                        at: at.ordinal,
                        runs,
                    }
                    .into(),
                );
                Ok(())
            })
            .map(|((), seq)| seq)
    }
}

impl<W> Vstream<'_, W>
where
    W: WorldState + HasM5 + HasM3, // reads M3 registration + M5 only
    W::Record: From<M5Rec>,        // stages only M5Rec
{
    /// DELETE (ASN-0117; §4): remove content range `[p, p + width)` and
    /// close the gap (shift the suffix left). Content store and R untouched
    /// — NonDestruction is structural (M5 has no reclamation path); link
    /// survival is automatic (a text delete never touches the link
    /// run-list).
    ///
    /// Check order (which error wins): `DocNotRegistered` → `NotOwner` (the ω
    /// gate) → `PublishedTarget` (PUB-2.11 on the document `doc` projects
    /// to, PUB-2.15 — a delete is an in-place edit and has no deposit form)
    /// → `NotContentSubspace` → `NotArranged`
    /// (`p.ordinal ∉ [1, n_C]`) → `OutOfBounds` (`ordinal + width − 1 > n_C`)
    /// → `EmptyWidth` (`width = 0`).
    ///
    /// THE ARRANGED AND CONTAINMENT CHECKS MAY NOT BE TRANSPOSED, and the
    /// reason is not only which verdict a caller reads: `NotArranged` also
    /// DISCHARGES the next check's precondition. `contains_content_range`
    /// tests the upper bound alone and means containment only for
    /// `p.ordinal ≥ 1`, which the arranged-position check has just
    /// established. Asked the other way round, a range opening at ordinal 0
    /// would be admitted as contained.
    pub fn delete(
        &self,
        caller: Caller,
        doc: &Address,
        p: VPos,
        width: Nat,
    ) -> Result<Seq, TxnError<DeleteError>> {
        let key = M3State::content_lock_key(doc);
        self.kernel
            .transact(&[key], |stg| {
                gate_write(
                    stg.working().m3(),
                    caller,
                    doc,
                    DeleteError::DocNotRegistered,
                    DeleteError::NotOwner,
                )?;
                // PUB-6.36 slot 5: the in-place advance refusal (PUB-2.11).
                if published_target(stg.working().m3(), doc) {
                    return Err(DeleteError::PublishedTarget);
                }
                if !p.is_content() {
                    return Err(DeleteError::NotContentSubspace);
                }
                let m5 = stg.working().m5();
                if !m5.arranges_content_position(doc, &p.ordinal) {
                    return Err(DeleteError::NotArranged);
                }
                if !m5.contains_content_range(doc, &p.ordinal, &width) {
                    return Err(DeleteError::OutOfBounds);
                }
                if width.is_zero() {
                    return Err(DeleteError::EmptyWidth);
                }
                stg.push(
                    M5Rec::ContentRemove {
                        doc: doc.clone(),
                        from: p.ordinal,
                        width,
                    }
                    .into(),
                );
                Ok(())
            })
            .map(|((), seq)| seq)
    }

    /// REARRANGE (ASN-0119/0084; §6): pivot (3 cuts) / swap (4 cuts)
    /// transpose in the content subspace. Pure cut-determined, value-blind
    /// permutation — content, links, R untouched (a duplicate-I interval
    /// correctly yields π ≠ id with M' = M).
    ///
    /// THE RESULTING ORDER, which is what a caller relays. With THREE cuts the
    /// two adjacent regions `α = [c₀, c₁)` and `β = [c₁, c₂)` exchange in
    /// place, so the arranged content reads `α`'s positions where `β`'s stood
    /// and `β`'s where `α`'s stood. With FOUR, the outer regions
    /// `α = [c₀, c₁)` and `β = [c₂, c₃)` exchange around `μ = [c₁, c₂)`, which
    /// keeps its positions. Everything outside `[ord(c₀), ord(c_last))` is
    /// untouched, and the result is a permutation of the same run multiset:
    /// `content_count` is unchanged, no I-address enters or leaves the
    /// arrangement, and `deletions` therefore reports exactly what it did
    /// before (RA1/RA6).
    ///
    /// `cuts` is borrowed, as COPY's specs are, so the caller keeps the cut
    /// sequence it asked with — to report it beside a rejection, say. The
    /// record then clones the three or four ordinals out; against a
    /// transaction that will fsync, four small clones buy the caller its own
    /// value back.
    ///
    /// Check order (which error wins, per R-PRE): `DocNotRegistered` →
    /// `NotOwner` (the ω gate) → `PublishedTarget` (PUB-2.11 on the document
    /// `doc` projects to, PUB-2.15; a re-arrangement is an in-place edit and
    /// has no deposit form) → `BadCutCount` (3|4) →
    /// `NotAscending` (strict) → `NotContentSubspace` (every cut) →
    /// `OutOfBounds` (CS5 lower bound `1 ≤ ord(c₀)` and upper bound
    /// `ord(c_last) ≤ n_C + 1`) → `EmptyContentSubspace` (R-PRE(ii);
    /// defensive after the bounds — see [`RearrangeError`]). Strict ascent
    /// already forces every region width ≥ 1, so no per-region emptiness
    /// check is reachable.
    pub fn rearrange(
        &self,
        caller: Caller,
        doc: &Address,
        cuts: &[VPos],
    ) -> Result<Seq, TxnError<RearrangeError>> {
        let key = M3State::content_lock_key(doc);
        self.kernel
            .transact(&[key], |stg| {
                gate_write(
                    stg.working().m3(),
                    caller,
                    doc,
                    RearrangeError::DocNotRegistered,
                    RearrangeError::NotOwner,
                )?;
                // PUB-6.36 slot 5: the in-place advance refusal (PUB-2.11).
                if published_target(stg.working().m3(), doc) {
                    return Err(RearrangeError::PublishedTarget);
                }
                if cuts.len() != 3 && cuts.len() != 4 {
                    return Err(RearrangeError::BadCutCount);
                }
                // Ascent is judged on the ordinals alone, not on `VPos`'s own
                // order: a cut's subspace is the NEXT verdict's subject, and
                // comparing whole positions would answer a stray subspace here
                // as `NotAscending`.
                if !cuts.windows(2).all(|w| w[0].ordinal < w[1].ordinal) {
                    return Err(RearrangeError::NotAscending);
                }
                if cuts.iter().any(|c| !c.is_content()) {
                    return Err(RearrangeError::NotContentSubspace);
                }
                let m5 = stg.working().m5();
                // Strict ascent is established above, so asking the
                // arrangement about the first and last cut settles CS5 for
                // every cut between them.
                if !m5.admits_content_boundary(doc, &cuts[0].ordinal)
                    || !m5.admits_content_boundary(doc, &cuts[cuts.len() - 1].ordinal)
                {
                    return Err(RearrangeError::OutOfBounds);
                }
                if m5.content_count(doc).is_zero() {
                    return Err(RearrangeError::EmptyContentSubspace);
                }
                let cut_ordinals: Vec<Nat> = cuts.iter().map(|c| c.ordinal.clone()).collect();
                stg.push(
                    M5Rec::ContentReorder {
                        doc: doc.clone(),
                        cut_ordinals,
                    }
                    .into(),
                );
                Ok(())
            })
            .map(|((), seq)| seq)
    }
}

impl<W> Vstream<'_, W>
where
    W: WorldState + HasM5 + HasM3, // reads M3 (ω pre-read, registration, mints) + M5
    W::Record: From<M5Rec> + From<M3Rec>, // stages M3Rec + M5Rec
{
    /// CREATENEWVERSION (ASN-0123; §7): fork — mint a new identity (M3),
    /// install its content arrangement as a snapshot of `source`'s content
    /// subspace (the multiplicity-preserving V→I map share, V2), record
    /// provenance. Returns the new document address and the commit `Seq`.
    ///
    /// `ω(source)` is pre-read off a snapshot (stable for an existing
    /// document, per M3) to choose branch + lock key: an owned fork mints
    /// `mint_version(source, bit)` under `version_lock_key(source)`
    /// (serializing forks of that source); a cross-owner fork requires the
    /// forker's prefix to be a registered ACCOUNT — M3's
    /// `is_registered_account`, which is the predicate `mint_document` itself
    /// gates on, so the P-tier rule has one spelling and asking it here
    /// surfaces `NodeTierCrossOwner` BEFORE any mint rather than obliquely as
    /// `Mint(NotAnAccount)` — and mints `mint_document(prefix, bit)` under
    /// `document_lock_key(prefix)`. Either branch also holds the source's
    /// TRUNK `version_lock_key`: the fork snapshots its source's reading
    /// surface (below), and a published chain's frontier and head
    /// arrangement serialize under that key (§Serialization key). On the
    /// owned arm of a trunk the two keys are one, which M2 normalizes.
    /// Source untouched (V3); the fork diverges copy-on-write (V11).
    ///
    /// THE PUBLICATION BIT (PUB round 1): the new document's RESOLVED
    /// publication state, which THIS composite resolves off its own working
    /// state and passes down (PUB-8.17) — the mints apply no default of their
    /// own (PUB-8.18). `published` is the three-valued wire flag (PUB-8.16):
    /// `Some(b)` ⇒ `b`, and ABSENT (`None`) ⇒ INHERIT `published(source)`,
    /// on BOTH branches — a cross-owner fork into an EMPTY account inherits
    /// too, never the create path's born-published rule (lane 0's rider: the
    /// copy inherits; M3 applies no default). The source's state is read on
    /// the DOCUMENT a version member projects to ([`published_target`],
    /// PUB-2.15).
    ///
    /// THE TWO REFUSALS OF THE VERSION-CHAIN MODEL (PUB round 2, lane 3.1;
    /// owner ruling D2b), both EXACT OF THE OWN-SOURCE ARM (PUB-2.14) and
    /// evaluated inside the transaction off its working state, in PUB-6.36's
    /// one slot, after registration:
    ///
    /// * `PrivateSourceVersionless` (PUB-2.9) — the caller OWNS `source` and
    ///   its document is PRIVATE: private documents are versionless, whatever
    ///   the flag says (absent, `false` or `true` — one code; the FACE splits
    ///   on the flag the caller SENT, which is the daemon's to render).
    /// * `PrivateVersionOfPublished` (PUB-2.7) — the caller OWNS `source`,
    ///   its document is PUBLISHED, and the RESOLVED state is private, which
    ///   only an explicit `false` produces (absent inherits published and is
    ///   legal, PUB-2.8).
    ///
    /// The CROSS-OWNER branch is refused by NEITHER: it mints a fresh
    /// document in the caller's own account off the source default plus the
    /// flag, as round 1 built it — the entitled reader's private working copy
    /// of published material (an explicit `false`), the inherited copy (an
    /// absent flag), and the fork of another's draft all stand (PUB-2.18,
    /// PUB-2.21). Applying the refusals to that arm would forbid every
    /// private working copy of every published document to every principal,
    /// which PUB-2.14 forbids.
    ///
    /// ALL THREE PRE-TRANSACTION READS ARE OFF A SNAPSHOT, taken before the
    /// applier lock and so possibly stale by the time the transaction runs,
    /// and each is sound for its own reason. `ω(source)` is stable for an
    /// existing document (per M3), which is what makes the branch and the
    /// lock key safe to choose before the transaction opens. The two
    /// REGISTRATION reads — `is_registered_document(source)` and
    /// `is_registered_account(prefix)` — are sound because M3's registrations
    /// are MONOTONE: its record set allocates and registers and never
    /// withdraws, so a `true` here cannot go stale, and a `false` can only be
    /// a rejection a retry need not repeat. Any future M2 realization that
    /// widens what may land between a snapshot and its transaction must
    /// re-examine this, along with [`M5Rec::VersionSnapshot`]'s
    /// linearization-at-fold, which the same change already obliges.
    ///
    /// UNGATED, deliberately: this op takes no [`Caller`] and applies no ω
    /// check, because forking a document one may not write IS the remedy the
    /// medium offers for that denial (denial-as-fork, ASN-0042 O10). What
    /// bounds a cross-owner fork is the forker's own tier, not the source's
    /// ownership. `principal` is the forker's identity, not an authorization.
    ///
    /// Check order (which error wins): `SourceNotRegistered` first, so a fork
    /// aimed at an address naming no document discloses nothing about who owns
    /// it. Then the branch decides the rest — an OWNED fork has no further
    /// rejection of its own and can fail only at the mint (`Mint`); a
    /// CROSS-OWNER fork is `NotAPrincipal` (the id names no registered
    /// principal) → `NodeTierCrossOwner` → `Mint`.
    ///
    /// EMPTY SOURCE: a source whose content subspace is empty yields a fork
    /// that is registered and ABSENT from the arrangement map — the lazy
    /// absent-⇒-empty convention, with no redundant entry and no provenance
    /// (ASN-0123 V1). Every read answers for it as it does for any document
    /// M5 has not yet touched.
    ///
    /// WHICH ARRANGEMENT IS SNAPSHOTTED (lane 3.2's head-float): the source's
    /// READING SURFACE ([`reading_surface`]) — a bare published source with
    /// members forks its trunk HEAD's arrangement, the one its readers answer
    /// from (PUB-2.49), never its own pre-chain arrangement, which a shot has
    /// superseded and which a trunk member built from it would have the bare
    /// address float back to. A version address forks its own member
    /// (PUB-2.50); a private or memberless source forks itself. The record's
    /// `source` is that surface, read off the working state before the new
    /// member's own mint is staged, as [`trunk_head`] requires — after it,
    /// an owned fork would be the head it asks about.
    ///
    /// COST, AND WHO OWNS IT. One request names one address, and the record
    /// it stages names two; what the fold then does is share the source's
    /// run-list (O(1), structural) and append `#runs(source)` freshly-built
    /// spans to R, permanently, R losing no member ever (P2). So the work and
    /// the state a request commands are set by the SOURCE's fragmentation and
    /// not by the request, and `#runs(source)` is itself grown by editing —
    /// a self-COPY doubles it, within `MAX_PLACED_RUNS` per request.
    ///
    /// M5 CAPS NONE OF IT, and no cap upstream reaches it: M2's
    /// `MAX_TXN_BYTES` prices the staged record, which is two addresses;
    /// M10's `MAX_INSERT_VALUES` prices values and `MAX_WIRE_LIST` prices
    /// lists, and this request carries neither. The asymmetry against COPY is
    /// deliberate to state and not to defend: COPY's R-append is bounded at
    /// [`MAX_PLACED_RUNS`](crate::MAX_PLACED_RUNS) per request and this one is
    /// unbounded, though the two append by the same mechanism and with the
    /// same permanence — a fork cannot be split by its caller the way an
    /// over-budget copy can, so a ceiling here would refuse
    /// `enabled(VERSION)` rather than shape a request. Replay re-does the
    /// expansion from the same two addresses ([`M5Rec::VersionSnapshot`]), so
    /// the bill is charged again at every `Kernel::open`. Admission control
    /// for a route carrying this op is therefore the CALLER's, and a route
    /// that carries it owes the number.
    pub fn version(
        &self,
        principal: PrincipalId,
        source: &Address,
        published: Option<bool>,
    ) -> Result<(Address, Seq), TxnError<VersionError>> {
        enum Branch {
            Owned,
            Cross(Address),
        }
        let snap = self.kernel.snapshot();
        let m3 = snap.world().m3();
        if !m3.is_registered_document(source) {
            return Err(TxnError::Rejected(VersionError::SourceNotRegistered));
        }
        let (key, branch) = match m3.effective_owner(source) {
            Some(p) if p == principal => (M3State::version_lock_key(source), Branch::Owned),
            _ => {
                // Cross-owner fork.
                let prefix = m3
                    .principal_prefix(principal)
                    .cloned()
                    .ok_or_else(|| TxnError::Rejected(VersionError::NotAPrincipal))?;
                if !m3.is_registered_account(&prefix) {
                    return Err(TxnError::Rejected(VersionError::NodeTierCrossOwner));
                }
                (M3State::document_lock_key(&prefix), Branch::Cross(prefix))
            }
        };
        let keys = [key, M3State::version_lock_key(&trunk_of(source))];
        self.kernel.transact(&keys, |stg| {
            let m3 = stg.working().m3();
            // PUB-8.16/8.17: resolve the three-valued flag off this
            // composite's OWN working state — `Some(b)` ⇒ `b`, ABSENT ⇒
            // INHERIT `published(d_src)` — and pass the RESOLVED bit down as
            // the bit the record journals (PUB-7.10, PUB-8.18). `source` is a
            // registered document (the monotone pre-read above), so the
            // inherit read is inside `published_target`'s contract; it is
            // read on the DOCUMENT a version member projects to (PUB-2.15).
            let source_published = published_target(m3, source);
            let resolved = published.unwrap_or(source_published);
            // PUB-6.36 slot 5, the own-source arm alone (PUB-2.14): private
            // documents are versionless (PUB-2.9), and a published one
            // admits no private member (PUB-2.7).
            if matches!(&branch, Branch::Owned) {
                if !source_published {
                    return Err(VersionError::PrivateSourceVersionless);
                }
                if !resolved {
                    return Err(VersionError::PrivateVersionOfPublished);
                }
            }
            let (v, m3rec) = match &branch {
                Branch::Owned => m3.mint_version(source, resolved),
                Branch::Cross(prefix) => m3.mint_document(prefix, resolved),
            }?;
            // The arrangement shared is the source's reading surface — its
            // trunk head when it has one (head-float, PUB-2.49) — asked of
            // the working state before this member's mint is staged below.
            let surface = reading_surface(m3, source);
            stg.push(m3rec.into());
            stg.push(
                M5Rec::VersionSnapshot {
                    source: surface,
                    new: v.clone(),
                }
                .into(),
            );
            Ok(v)
        })
    }
}

#[cfg(test)]
mod tests {
    //! The design's per-op-bound claim, verified literally: a MINIMAL test
    //! world — `HasM5 + HasM3`, `Record = M5Rec` (the identity `From`) —
    //! drives `delete` and `rearrange`; no content store, no `From<M3Rec>`.
    //!
    //! And COPY's content-side referential gate (S3★), which needs a world
    //! whose arrangement and content store can be seeded INDEPENDENTLY — a
    //! state no engine reaches, every arranged address there having been
    //! written by INSERT in the same composite. And J0's allocation step,
    //! driven directly in a world of M3 and M4 alone, which is all it reads.
    //! And the publish shot's placement claims — its run budget at both sites,
    //! and its empty member — in a world whose three slices are seeded apart,
    //! so a head can arrange more runs than a test could build by
    //! transactions.

    use serde::{Deserialize, Serialize};
    use skep_content::ContentStore;
    use skep_kernel::{CheckpointPolicy, Durability, Kernel, KernelConfig};
    use skep_namespace::M3State;

    use super::*;
    use crate::shot::{Base, ShotRun};
    use crate::state::M5State;
    use crate::testutil::{a, ca, doc1, doc2, n, pca, pdoc, run, seeded_m3, vp, vspan};

    /// Unwrap an op's typed rejection (`TxnError::Rejected(E)` — surfaced
    /// verbatim, per M2's transact contract).
    fn rejected<T, E: fmt::Debug>(r: Result<T, TxnError<E>>) -> E {
        match r {
            Err(TxnError::Rejected(e)) => e,
            Err(other) => panic!("expected TxnError::Rejected, got {other:?}"),
            Ok(_) => panic!("expected TxnError::Rejected, got Ok"),
        }
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct MiniWorld {
        m3: M3State,
        m5: M5State,
    }

    impl WorldState for MiniWorld {
        type Record = M5Rec;
        fn apply(&self, r: &M5Rec) -> MiniWorld {
            MiniWorld {
                m3: self.m3.clone(),
                m5: self.m5.apply_m5(r),
            }
        }
    }
    impl HasM3 for MiniWorld {
        fn m3(&self) -> &M3State {
            &self.m3
        }
    }
    impl HasM5 for MiniWorld {
        fn m5(&self) -> &M5State {
            &self.m5
        }
    }

    fn mini_kernel() -> Kernel<MiniWorld> {
        let m5 = M5State::genesis().apply_m5(&M5Rec::ContentPlace {
            doc: doc1(),
            at: n(1),
            runs: vec![run(&ca(1), 5)],
        });
        let cfg = KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
        };
        Kernel::open(cfg, MiniWorld { m3: seeded_m3(), m5 }).expect("in-memory open")
    }

    #[test]
    fn the_handle_prints_without_its_world_being_printable() {
        // `MiniWorld` is not `Debug`, and the handle is — which is the whole
        // reason the impl is written out rather than derived.
        let k = mini_kernel();
        assert_eq!(format!("{:?}", Vstream::new(&k)), "Vstream");
    }

    #[test]
    fn the_absent_declaration_is_the_default() {
        // The wire reads an absent, `null` or `false` `deposit` field as no
        // declaration, so the value a caller gets without saying anything is
        // the one that clears no refusal — never the exemption.
        assert_eq!(Deposit::default(), Deposit::Undeclared);
    }

    /// A world carrying a content store beside the arrangement — the one
    /// slice `MiniWorld` deliberately lacks, kept a separate type so the
    /// per-op-bound claim `MiniWorld` witnesses stays witnessed.
    #[derive(Clone, Serialize, Deserialize)]
    struct GateWorld {
        m3: M3State,
        content: ContentStore,
        m5: M5State,
    }

    impl WorldState for GateWorld {
        type Record = M5Rec;
        fn apply(&self, r: &M5Rec) -> GateWorld {
            GateWorld {
                m3: self.m3.clone(),
                content: self.content.clone(),
                m5: self.m5.apply_m5(r),
            }
        }
    }
    impl HasM3 for GateWorld {
        fn m3(&self) -> &M3State {
            &self.m3
        }
    }
    impl HasContent for GateWorld {
        fn content(&self) -> &ContentStore {
            &self.content
        }
    }
    impl HasM5 for GateWorld {
        fn m5(&self) -> &M5State {
            &self.m5
        }
    }

    /// doc1 arranged as `run(ca(1), 3)`, with the content store holding the
    /// bytes of exactly `present`. The two halves of S3★ are set apart from
    /// each other, which is what lets one test say which of them COPY reads.
    fn gate_kernel(present: &[u32]) -> Kernel<GateWorld> {
        gate_kernel_arranging(vec![run(&ca(1), 3)], present)
    }

    /// The same world arranging the runs a caller chooses — for the tests
    /// whose subject is the source's RUN COUNT rather than its bytes.
    fn gate_kernel_arranging(runs: Vec<Run>, present: &[u32]) -> Kernel<GateWorld> {
        let m5 = M5State::genesis().apply_m5(&M5Rec::ContentPlace {
            doc: doc1(),
            at: n(1),
            runs,
        });
        let mut content = ContentStore::default();
        for &k in present {
            let cw = stage_write(&content, &ca(k), Val::new(&b"x"[..]))
                .expect("each seeded address is written once");
            content = content.apply_write(&cw);
        }
        let cfg = KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
        };
        Kernel::open(
            cfg,
            GateWorld {
                m3: seeded_m3(),
                content,
                m5,
            },
        )
        .expect("in-memory open")
    }

    /// The two slices J0's allocation step touches — M3's frontier and M4's
    /// store — with a record for each, and nothing else: no arrangement, no
    /// `M5Rec`. So the step's bounds are witnessed as `MiniWorld` witnesses
    /// the per-op ones: it needs M3 and M4 and stages their records alone.
    #[derive(Clone, Serialize, Deserialize)]
    struct AllocWorld {
        m3: M3State,
        content: ContentStore,
    }

    #[derive(Clone, Serialize, Deserialize)]
    enum AllocRec {
        M3(M3Rec),
        Content(ContentWrite),
    }

    impl From<M3Rec> for AllocRec {
        fn from(r: M3Rec) -> AllocRec {
            AllocRec::M3(r)
        }
    }
    impl From<ContentWrite> for AllocRec {
        fn from(r: ContentWrite) -> AllocRec {
            AllocRec::Content(r)
        }
    }

    impl WorldState for AllocWorld {
        type Record = AllocRec;
        fn apply(&self, r: &AllocRec) -> AllocWorld {
            match r {
                AllocRec::M3(x) => AllocWorld {
                    m3: self.m3.apply_m3(x),
                    content: self.content.clone(),
                },
                AllocRec::Content(x) => AllocWorld {
                    m3: self.m3.clone(),
                    content: self.content.apply_write(x),
                },
            }
        }
    }
    impl HasM3 for AllocWorld {
        fn m3(&self) -> &M3State {
            &self.m3
        }
    }
    impl HasContent for AllocWorld {
        fn content(&self) -> &ContentStore {
            &self.content
        }
    }

    #[test]
    fn the_allocation_step_mints_writes_and_accumulates_through_the_merge_condition() {
        // J0's one enforcement site, which INSERT and the shot's re-insert
        // both call: each call mints under the home it is given, writes the
        // value there, and accumulates the address through the element that
        // owns the merge condition — so consecutive mints under one home
        // coalesce into one run, and a mint under another home, whose address
        // is not I-adjacent, opens a run of its own rather than widening the
        // first over addresses nobody allocated.
        let cfg = KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
        };
        let k = Kernel::open(
            cfg,
            AllocWorld {
                m3: seeded_m3(),
                content: ContentStore::default(),
            },
        )
        .expect("in-memory open");
        let keys = [M3State::content_lock_key(&doc1()), M3State::content_lock_key(&doc2())];
        let (runs, _) = k
            .transact(&keys, |stg| {
                let mut runs: Vec<Run> = Vec::new();
                for (home, byte) in [(doc1(), b"a"), (doc1(), b"b"), (doc2(), b"c")] {
                    allocate_for_placement::<_, InsertError>(stg, &home, Val::new(&byte[..]), &mut runs)?;
                }
                Ok::<_, InsertError>(runs)
            })
            .expect("the allocations commit");
        let doc2_first = a(&[1, 0, 1, 0, 2, 0, 1, 1]);
        assert_eq!(runs, vec![run(&ca(1), 2), run(&doc2_first, 1)]);
        // Each address holds the value written at it, and each mint advanced
        // its home's frontier: the next mint under doc1 is ca(3).
        let s = k.snapshot();
        let content = s.world().content();
        for (addr, byte) in [(ca(1), b"a"), (ca(2), b"b"), (doc2_first, b"c")] {
            assert_eq!(content.value_at(addr.tumbler()).map(Val::as_bytes), Some(&byte[..]));
        }
        let (next, _) = s.world().m3().mint_content(&doc1()).expect("doc1 is registered");
        assert_eq!(next, ca(3));
    }

    #[test]
    fn copy_rejects_a_source_run_whose_start_is_absent_from_the_content_store() {
        // §5/S3★: COPY asserts each resolved run start ∈ dom(C) before
        // placing it, so a transclusion cannot manufacture a reference to
        // bytes that were never written — a reference R would then keep
        // permanently (P2) and every later RETRIEVEV would fail to resolve.
        let p1 = Caller::Principal(PrincipalId(1));
        // `count` positions from doc1's first content ordinal.
        let from_doc1 = |count: u32| {
            vec![VSpec {
                source: doc1(),
                span: vspan(1, 1, count),
            }]
        };

        // Nothing written: the resolved run's start, ca(1), is absent.
        let k = gate_kernel(&[]);
        assert!(matches!(
            rejected(Vstream::new(&k).copy(p1, &doc2(), vp(1, 1), &from_doc1(2))),
            CopyError::DanglingSource
        ));

        // The identical COPY against a store that holds the bytes commits —
        // without this, the rejection above could be earned by anything.
        let k = gate_kernel(&[1, 2, 3]);
        Vstream::new(&k)
            .copy(p1, &doc2(), vp(1, 1), &from_doc1(2))
            .expect("a resolved run whose start is present is admitted");
        assert_eq!(k.snapshot().world().m5().content_count(&doc2()), n(2));

        // Open decision #5's default, pinned: the gate reads run STARTS and
        // relies on the source's own S3★ for the interior. ca(3) is absent,
        // yet the width-3 run starting at the present ca(1) is admitted —
        // widening the gate to every address of a run turns this red, which
        // is how such a change announces itself.
        let k = gate_kernel(&[1, 2]);
        Vstream::new(&k)
            .copy(p1, &doc2(), vp(1, 1), &from_doc1(3))
            .expect("the run start is present, so the run is admitted");
    }

    #[test]
    fn copy_refuses_a_placement_past_the_run_budget_before_building_it() {
        // §5: the runs one COPY places are bounded, and the bound binds the
        // ACCUMULATOR rather than the request — a spec list is a multiplier,
        // so a small request can name an unbounded placement. Here 65_537
        // single-position specs against a one-address source: each resolves
        // to `run(ca(1), 1)`, which is never I-adjacent to the run before it
        // (`shift(ca(1), 1) = ca(2)`), so every one of them pushes.
        let p1 = Caller::Principal(PrincipalId(1));
        let k = gate_kernel(&[1, 2, 3]);
        let one = VSpec {
            source: doc1(),
            span: vspan(1, 1, 1),
        };
        let over_budget_specs: Vec<VSpec> = std::iter::repeat_with(|| one.clone())
            .take(MAX_PLACED_RUNS + 1)
            .collect();
        assert!(matches!(
            rejected(Vstream::new(&k).copy(p1, &doc2(), vp(1, 1), &over_budget_specs)),
            CopyError::TooManyRuns
        ));
        // Nothing was placed: the refusal happens inside the closure, before
        // a record is staged, so the destination is untouched.
        assert_eq!(k.snapshot().world().m5().content_count(&doc2()), n(0));
        // And the cap refuses only what is past it — an ordinary copy still
        // commits, so the assertion above is not earned by refusing COPY.
        Vstream::new(&k)
            .copy(p1, &doc2(), vp(1, 1), &over_budget_specs[..3])
            .expect("a placement inside the budget commits");
        assert_eq!(k.snapshot().world().m5().content_count(&doc2()), n(3));
    }

    #[test]
    fn one_spec_over_a_fragmented_source_is_refused_at_the_cap_not_after_it() {
        // §5: a spec list is one multiplier of the source's fragmentation and
        // the SPAN is the other — a single spec over a heavily fragmented
        // source names as many runs as the source holds in range. The cap
        // therefore has to bind one spec, and because the resolution is pulled
        // lazily the refusal arrives AT the cap: the accumulator never holds
        // more than the budget, whatever the source's run count.
        let p1 = Caller::Principal(PrincipalId(1));
        // Non-adjacent starts (`shift(ca(2k), 1) = ca(2k + 1) ≠ ca(2k + 2)`),
        // so nothing coalesces and the source really holds this many runs.
        let over_budget_runs = MAX_PLACED_RUNS + 1;
        let present: Vec<u32> = (1..=over_budget_runs as u32).map(|k| 2 * k).collect();
        let runs: Vec<Run> = present.iter().map(|&k| run(&ca(k), 1)).collect();
        let k = gate_kernel_arranging(runs, &present);
        assert_eq!(
            k.snapshot().world().m5().content_runs(&doc1()).len(),
            over_budget_runs,
            "the source arranges one run per placed address"
        );
        // ONE spec, whose span covers the whole source.
        let whole = [VSpec {
            source: doc1(),
            span: vspan(1, 1, over_budget_runs as u32),
        }];
        assert!(matches!(
            rejected(Vstream::new(&k).copy(p1, &doc2(), vp(1, 1), &whole)),
            CopyError::TooManyRuns
        ));
        assert_eq!(k.snapshot().world().m5().content_count(&doc2()), n(0));
        // A span inside the budget over the same source still commits, so the
        // refusal above is about the count and not about the source.
        Vstream::new(&k)
            .copy(
                p1,
                &doc2(),
                vp(1, 1),
                &[VSpec {
                    source: doc1(),
                    span: vspan(1, 1, 4),
                }],
            )
            .expect("a span inside the budget commits");
        assert_eq!(k.snapshot().world().m5().content_count(&doc2()), n(4));
    }

    #[test]
    fn the_placement_budget_stays_inside_the_transaction_budget() {
        // MAX_PLACED_RUNS is a number with an argument behind it, and the
        // argument is about M2's encoding — so it is measured against that
        // encoding rather than remembered. A full placement must still be a
        // transaction M2 could accept: a cap above the journal's own ceiling
        // would be no cap at all, since the work would be done and then
        // refused downstream, which is the cost the cap exists to refuse.
        const SAMPLE: usize = 64;
        let runs: Vec<Run> = (1..=SAMPLE as u32).map(|k| run(&ca(2 * k), 1)).collect();
        let rec = M5Rec::ContentPlace {
            doc: doc1(),
            at: n(1),
            runs,
        };
        let per_run = bincode::serialize(&rec).expect("the record encodes").len() / SAMPLE;
        let full = MAX_PLACED_RUNS as u64 * per_run as u64;
        assert!(
            full < skep_kernel::MAX_TXN_BYTES,
            "a full placement encodes to ~{full} bytes, past M2's {}",
            skep_kernel::MAX_TXN_BYTES
        );
    }

    /// A world carrying all three slices the SHOT touches — M3 (its member's
    /// mint), M4 (the existence check and the re-insert's writes) and M5 (the
    /// base's tail and the member's placement) — seeded APART, as `GateWorld`'s
    /// two are. The shot is the one op whose records span all three.
    #[derive(Clone, Serialize, Deserialize)]
    struct ShotWorld {
        m3: M3State,
        content: ContentStore,
        m5: M5State,
    }

    #[derive(Clone, Serialize, Deserialize)]
    enum ShotRec {
        M3(M3Rec),
        Content(ContentWrite),
        M5(M5Rec),
    }

    impl From<M3Rec> for ShotRec {
        fn from(r: M3Rec) -> ShotRec {
            ShotRec::M3(r)
        }
    }
    impl From<ContentWrite> for ShotRec {
        fn from(r: ContentWrite) -> ShotRec {
            ShotRec::Content(r)
        }
    }
    impl From<M5Rec> for ShotRec {
        fn from(r: M5Rec) -> ShotRec {
            ShotRec::M5(r)
        }
    }

    impl WorldState for ShotWorld {
        type Record = ShotRec;
        fn apply(&self, r: &ShotRec) -> ShotWorld {
            match r {
                ShotRec::M3(x) => ShotWorld {
                    m3: self.m3.apply_m3(x),
                    content: self.content.clone(),
                    m5: self.m5.clone(),
                },
                ShotRec::Content(x) => ShotWorld {
                    m3: self.m3.clone(),
                    content: self.content.apply_write(x),
                    m5: self.m5.clone(),
                },
                ShotRec::M5(x) => ShotWorld {
                    m3: self.m3.clone(),
                    content: self.content.clone(),
                    m5: self.m5.apply_m5(x),
                },
            }
        }
    }
    impl HasM3 for ShotWorld {
        fn m3(&self) -> &M3State {
            &self.m3
        }
    }
    impl HasContent for ShotWorld {
        fn content(&self) -> &ContentStore {
            &self.content
        }
    }
    impl HasM5 for ShotWorld {
        fn m5(&self) -> &M5State {
            &self.m5
        }
    }

    /// pdoc's first member, the head of its chain in `shot_kernel`'s world.
    fn pdoc_member() -> Address {
        a(&[1, 0, 1, 0, 3, 1])
    }

    /// pdoc with `pdoc_member()` heading its chain and arranging
    /// `member_runs` — nothing placed at all when they are empty, as no op
    /// stages an empty placement — and pdoc's content elements stored at the
    /// ordinals in `present`.
    fn shot_kernel(member_runs: Vec<Run>, present: &[u32]) -> Kernel<ShotWorld> {
        let m3 = seeded_m3().apply_m3(&M3Rec::Allocate {
            addr: pdoc_member(),
            published: true,
        });
        let m5 = if member_runs.is_empty() {
            M5State::genesis()
        } else {
            M5State::genesis().apply_m5(&M5Rec::ContentPlace {
                doc: pdoc_member(),
                at: n(1),
                runs: member_runs,
            })
        };
        let mut content = ContentStore::default();
        for &k in present {
            let cw = stage_write(&content, &pca(k), Val::new(&b"x"[..]))
                .expect("each seeded address is written once");
            content = content.apply_write(&cw);
        }
        let cfg = KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
        };
        Kernel::open(cfg, ShotWorld { m3, content, m5 }).expect("in-memory open")
    }

    /// A shot staged off `pdoc_member()`, its copy having taken `extent` of
    /// the head, supplying `runs` and naming no draft.
    fn shot_off_the_head(extent: u32, runs: Vec<ShotRun>) -> Shot {
        Shot {
            base: Some(Base {
                member: pdoc_member(),
                extent: n(extent),
            }),
            draft: None,
            runs,
        }
    }

    #[test]
    fn the_shot_refuses_a_client_arrangement_past_the_run_budget_and_places_one_at_it() {
        // MAX_PLACED_RUNS binds what one SHOT places, and a shot cannot be
        // split to meet it. Width-1 runs of the edition's own I-space at even
        // ordinals: none is I-adjacent to the one before it
        // (`shift(pca(2k), 1) = pca(2k + 1)`), so each pushes. Own I-space
        // takes no consult — and this consult admits everything — so the
        // source gate plays no part.
        let p1 = Caller::Principal(PrincipalId(1));
        let ordinals: Vec<u32> = (1..=MAX_PLACED_RUNS as u32 + 1).map(|o| 2 * o).collect();
        let k = shot_kernel(vec![], &ordinals);
        let runs = |count: usize| -> Vec<ShotRun> {
            ordinals[..count]
                .iter()
                .map(|&o| ShotRun {
                    origin: pdoc(),
                    run: run(&pca(o), 1),
                })
                .collect()
        };
        let anyone = |_: &ShotWorld, _: &Address| true;
        let before = k.current_seq();
        assert!(matches!(
            rejected(Vstream::new(&k).publish(
                p1,
                &pdoc(),
                shot_off_the_head(0, runs(MAX_PLACED_RUNS + 1)),
                &anyone
            )),
            PublishError::TooManyRuns
        ));
        assert_eq!(k.current_seq(), before, "the refusal commits nothing");
        // The equal case: a member of exactly the budget is placed, whole.
        let (member, _) = Vstream::new(&k)
            .publish(p1, &pdoc(), shot_off_the_head(0, runs(MAX_PLACED_RUNS)), &anyone)
            .expect("a placement at the budget commits");
        assert_eq!(
            k.snapshot().world().m5().content_runs(&member).len(),
            MAX_PLACED_RUNS
        );
    }

    #[test]
    fn the_shot_refuses_a_carried_tail_past_the_run_budget() {
        // The base's post-render deposits count against the same budget,
        // measured as each is carried: a head arranging MAX_PLACED_RUNS + 1
        // non-adjacent runs cannot be shot from extent 0, though the client
        // supplies nothing. The head's bytes are stored as well, so the
        // budget is the only thing this world could refuse the shot for.
        let p1 = Caller::Principal(PrincipalId(1));
        let ordinals: Vec<u32> = (1..=MAX_PLACED_RUNS as u32 + 1).map(|o| 2 * o).collect();
        let head_runs: Vec<Run> = ordinals.iter().map(|&o| run(&pca(o), 1)).collect();
        let k = shot_kernel(head_runs.clone(), &ordinals);
        let anyone = |_: &ShotWorld, _: &Address| true;
        let before = k.current_seq();
        assert!(matches!(
            rejected(Vstream::new(&k).publish(p1, &pdoc(), shot_off_the_head(0, vec![]), &anyone)),
            PublishError::TooManyRuns
        ));
        assert_eq!(k.current_seq(), before, "the refusal commits nothing");
        // The equal case: from extent 1 the tail is exactly the budget, and it
        // is carried whole, in order.
        let (member, _) = Vstream::new(&k)
            .publish(p1, &pdoc(), shot_off_the_head(1, vec![]), &anyone)
            .expect("a tail of exactly the budget is carried");
        assert_eq!(
            k.snapshot().world().m5().content_runs(&member),
            head_runs[1..].to_vec()
        );
    }

    #[test]
    fn an_empty_shot_mints_its_member_and_leaves_the_arrangement_slice_as_it_found_it() {
        // An empty placement pushes no record. The member's mint is M3's
        // record; with nothing to place, M5's slice comes out exactly as it
        // went in — no arrangement entry and no R record for the member, which
        // reads as the lazy empty arrangement, as an empty fork's does.
        let p1 = Caller::Principal(PrincipalId(1));
        let k = shot_kernel(vec![], &[]);
        let untouched = k.snapshot().world().m5().clone();
        let anyone = |_: &ShotWorld, _: &Address| true;
        let (member, _) = Vstream::new(&k)
            .publish(p1, &pdoc(), shot_off_the_head(0, vec![]), &anyone)
            .expect("an empty shot commits");
        let s = k.snapshot();
        assert!(s.world().m3().is_registered_document(&member), "the member is minted");
        assert_eq!(*s.world().m5(), untouched, "and nothing is placed for it");
    }

    #[test]
    fn delete_and_rearrange_drive_a_minimal_world() {
        let k = mini_kernel();
        let vs = Vstream::new(&k);
        // The seeded owner of doc1 — the ω gate is exercised, not skipped.
        let p1 = Caller::Principal(PrincipalId(1));
        vs.delete(p1, &doc1(), vp(1, 2), n(1)).expect("delete commits");
        let seq = vs
            .rearrange(p1, &doc1(), &[vp(1, 1), vp(1, 2), vp(1, 3)])
            .expect("rearrange commits");
        let s = k.snapshot();
        assert_eq!(s.seq(), seq);
        let m5 = s.world().m5();
        // After deleting V2 (ca(2)): [ca1, ca3, ca4, ca5]; pivot at [1,2,3]
        // exchanges V1 and V2: [ca3, ca1, ca4, ca5].
        assert_eq!(m5.content_count(&doc1()), n(4));
        assert_eq!(m5.point(&doc1(), &vp(1, 1)), Some(ca(3)));
        assert_eq!(m5.point(&doc1(), &vp(1, 2)), Some(ca(1)));
        assert_eq!(m5.point(&doc1(), &vp(1, 3)), Some(ca(4)));
    }

    #[test]
    fn the_in_place_refusal_needs_only_the_registry_and_the_arrangement() {
        // PUB-2.11 in the MINIMAL world: the published-target refusal reads
        // M3's bit and nothing else, so `delete`/`rearrange` refuse it under
        // `HasM5 + HasM3` alone — after ω, before every shape check (the
        // edition is empty, and the shape checks would have said so), and for
        // `Caller::System` as for the owner (PUB-6.28).
        let k = mini_kernel();
        let vs = Vstream::new(&k);
        let p1 = Caller::Principal(PrincipalId(1));
        let before = k.current_seq();
        assert!(matches!(
            rejected(vs.delete(p1, &pdoc(), vp(1, 1), n(1))),
            DeleteError::PublishedTarget
        ));
        assert!(matches!(
            rejected(vs.rearrange(p1, &pdoc(), &[vp(1, 1), vp(1, 2), vp(1, 3)])),
            RearrangeError::PublishedTarget
        ));
        assert!(matches!(
            rejected(vs.delete(Caller::System, &pdoc(), vp(1, 1), n(1))),
            DeleteError::PublishedTarget
        ));
        // ω stands ahead of it: a stranger learns nothing about publication.
        assert!(matches!(
            rejected(vs.delete(Caller::Principal(PrincipalId(2)), &pdoc(), vp(1, 1), n(1))),
            DeleteError::NotOwner(d) if d == pdoc()
        ));
        assert_eq!(k.current_seq(), before, "a refusal commits nothing");
        // And the draft beside it is edited as before.
        vs.delete(p1, &doc1(), vp(1, 1), n(1)).expect("a draft's delete commits");
    }

    #[test]
    fn copy_into_a_published_destination_refuses_before_reading_its_sources() {
        // PUB-2.11 on COPY's destination, in the content-store world: the
        // refusal fires ahead of every per-spec check, so a spec that would
        // otherwise be refused for its own reasons never speaks.
        let p1 = Caller::Principal(PrincipalId(1));
        let k = gate_kernel(&[1, 2, 3]);
        assert!(matches!(
            rejected(Vstream::new(&k).copy(p1, &pdoc(), vp(2, 99), &[])),
            CopyError::PublishedTarget
        ));
        assert_eq!(k.snapshot().world().m5().content_count(&pdoc()), n(0));
    }
}
