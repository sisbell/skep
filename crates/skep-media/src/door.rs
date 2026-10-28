//! The write door's media step: one step of the plain write sequence.
//!
//! Its rules are `media.md` Op inventory 2 — "both refusals are skepd's,
//! run at its write door on the guard the `insert` commits under", "a shot
//! mints a cell only from a draft its caller owns"; §The publication seam —
//! "the half is the write door's whole step, its armed set landing with it";
//! the register M-I1 (a), (f). It runs between the sequence's admission and
//! the commit, answering every value naming the cell's kind. The reads are
//! M5's, M3's and M4's public ones and the world's read predicate
//! (`ReadableWorld::readable`) off the locked snapshot the commit will read
//! (the serialization guard admits no commit between, so the check that
//! passed and the commit it guards are one interval); the parse is
//! `cell::classify`'s, the one classification.
//!
//! **The armed set**, in answer order (PATTERNS P6 — enumerated here, at the
//! surface, and in `docs/wire.md` §Media, so no later change moves one
//! state's answer from one code to another):
//!
//! 1. `published_target` — an `insert` into a published document (or a
//!    member of one, PUB-2.15) the caller owns whose values hold one naming
//!    the kind, whatever its `deposit` declaration. M10's own door answers
//!    this code to an undeclared insert at a published target before any
//!    consult; the declared deposit is M5's one door that admits a published
//!    target on its class, and it judges the type and never the atom
//!    (`skep-febe`'s `Op::Insert` card; PUB-2.59, PUB-2.64), so this arm is
//!    what refuses a cell declared under a deposit class — the one cell the
//!    stores do not cover — ahead of every refusal below; for an undeclared
//!    one it is the same code M10 would answer, so the order against M10 is
//!    unobservable.
//! 2. `not_owner`, naming the draft — a `publish` whose draft-native runs
//!    (the ones the shot re-inserts as fresh identity, PUB-2.40) hold a
//!    value naming the kind, from a caller who does not own the draft: ω,
//!    exact — the same predicate `not_owner` makes of `doc`
//!    (`skep-arrangement`'s `Caller::is_owner`, never a second spelling). A
//!    grantee's, an ancestor's or a descendant's shot naming the owner's
//!    private original would otherwise re-mint its cell with no `insert`
//!    and no refusal on the way — the binding's own attack, one op over.
//! 3. `unbound_cell` (`credential_refused`, permanent) — a cell in a draft
//!    `insert`, or at the owner's own shot, naming a hash this principal did
//!    not deposit under its own lease: the binding's refusal — the media
//!    gate reads the principal's own side first, the cell index where its
//!    walk has completed and then the principal's own lease record, and the
//!    file only where its own cells or a live lease of its own name the hash
//!    (`MediaGate::binding`); a cell whose hash the principal holds a live
//!    lease on, over a whole file whose length the cell's `size` names, is
//!    admitted and goes on to the store. A deposit whole on disk whose size
//!    the cell contradicts is this refusal too — no deposit of this
//!    principal's is the cell as written. Permanent for the request as
//!    sent: the act that exists is a PUT of the bytes, then the cell the
//!    PUT's answer spells. The face (M-I7 (e)) says that no deposit of the
//!    person's here is the cell as written, and never that none was made —
//!    it is the answer too to a person who did deposit, past the horizon or
//!    at an operator's honest nulls: "no deposit of yours here is this
//!    picture's cell as written: upload the file, then place the cell its
//!    answer spells." P10's fence-only face ("this board takes no
//!    uploads") is not this arm's: on a board whose uploads are closed the
//!    client keys that face off `/health`'s echo before this token's face
//!    speaks.
//! 4. `unknown_cell_schema` (`credential_refused`, permanent) — a value
//!    naming either media kind — the picture's or the blind document's —
//!    that parses under no pinned schema, in the same two positions:
//!    DOCTRINE D13's carve-out, the halt a reader makes at a permanent act
//!    on a schema it does not know, so the day a second schema is pinned no
//!    board holds a cell of it that was never bound (the record's H1). The
//!    same bytes are never admitted. The face a client renders: "this value
//!    names a media cell — a picture's or a blind document's — in a form
//!    this board does not read".
//! 5. `lease_lapsed` (`credential_refused`, permanent for the request as
//!    sent) — a cell naming a hash this principal did deposit, whose lease
//!    has lapsed within the horizon, or whose lease is live over a file
//!    that is not there or not whole — or a hash its own cells already
//!    name, whose file is not there or not whole: the deposit is gone, and
//!    the act is a re-PUT of the bytes, which re-takes the lease. Told apart
//!    from the binding's refusal so a client's resume can be written against
//!    it, and read off this principal's own side alone — its cells and its
//!    record — never off the file's presence beyond them (Op inventory 1, "a
//!    client meeting a lapsed lease meets its own refusal"). Past the
//!    horizon the record answers no lease and the binding's refusal stands.
//! 6. `index_rebuilding` (`credential_refused`, retry) — the rebuild
//!    window's answer, in the binding's position and during the walk alone:
//!    the index's rebuild at open has not completed, and the lease arm alone
//!    would have answered `unbound_cell` or `lease_lapsed` — a verdict the
//!    index arm, unread, may overturn (a hash the principal's own cells
//!    name, its file whole). The readiness token re-used, its class the
//!    readiness refusal's: the request as sent may be perfectly good, and
//!    the walk momentarily unfinished (the door never waits; P22; the
//!    register M-I5 (b)). A cell the lease arm admits in the rebuild window
//!    is admitted. The one arm of the armed set that is not permanent.
//!
//! **Every value is judged** (M-I1 (a): the binding is per cell, at every
//! mint). A write carrying several values naming the kind is answered by
//! the first refusal any of them earns — in V-order at an `insert`, in
//! placement order at a shot — the target's arm and the owner's asked once,
//! ahead of every value's own verdict. A cell admitted beside one refused
//! admits nothing for it, and the write lands whole or not at all.
//!
//! **The kind column** (`media.md` item 4; the blind-document investigation
//! §5 (i)). The arms above are read per kind. The picture's cell meets every
//! arm. The blind document's cell (`cell/blind.rs`) meets arms 1, 2 and 4 as
//! the picture's does — `published_target` at a published target,
//! `not_owner` at a reader's shot, the halt on a malformed body — and never
//! arms 3, 5 and 6: it is admitted into a draft and at the owner's shot with
//! no store consulted, there being no deposit to bind (the board holds no
//! byte of a blind picture) and no lease to lapse. The same door, the same
//! order, one classification ahead of it.
//!
//! **The shot's binding.** The owner's own shot re-inserting a draft's cell
//! asks the binding again, as its `insert` did — the whole armed set lands
//! together at both positions. The binding reads the cell index first
//! (`MediaGate::binding`): a hash the requester's own cells already name
//! is a reference, kept by no lease — so the owner's shot of a draft whose
//! cell was admitted is admitted after the lease lapsed, while the file is
//! whole at the cell's size, and `lease_lapsed` where it is not. Until the
//! index's walk at open completes the index arm is skipped and the lease
//! arm alone admits, so a lease lapsed between the insert and the shot
//! answers `index_rebuilding` in the rebuild window — retry-class — and the
//! shot is admitted after the walk with no re-PUT: the door never waits on
//! the index.
//!
//! **What stands ahead.** The plain sequence's producers — the mint class,
//! the `replaces` fence, the board-state gate with the write-path check
//! behind it, the `nullify` class — have answered before this step runs: a
//! bare session's write into a published document is
//! `signed_session_required`, an unsigned shot `attestation_required`, an
//! attested shot copying in a draft the caller may not read
//! `attestation_invalid:withheld` or the store's `withheld`. What stands
//! behind it — the store's own slots — is kept ahead of its arms by
//! construction: an `insert` is read only where `doc` is registered and the
//! caller owns it (PUB-6.36's slot 1, PUB-6.37), and a `publish` only where
//! M5's own admission of the shot ([`shot_admission`], slots 1 through 6,
//! the source gate included) passes it, the draft is readable to the caller
//! (PATTERNS P31: no value the caller may not read is read on its behalf —
//! a verdict here is answered to the caller) and the re-insert is within
//! M5's budget; every other case answers nothing here and the store answers
//! it as built. A refusal here commits nothing and gives the head writer its
//! turn, as an admission refusal does.

use skep_address::{Address, Nat};
use skep_arrangement::{published_target, shot_admission, Caller, Shot, MAX_REINSERTED_VALUES};
use skep_content::Val;
use skep_febe::{Disposition, FebeWorld, Op, ReadableWorld, RejectCode};
use skep_namespace::PrincipalId;

use crate::cell;
use crate::gate::{Binding, MediaGate};

/// The door's answer: one variant per arm of the armed set.
///
/// They come in the module's order. One is M10's own code, raised here on
/// the daemon's channel with M10's classification; four are the daemon's
/// tokens, riding `credential_refused` as every daemon-side refusal but the
/// registry sequence's does (AUTH-3.53's family; wire.md §Credential
/// refusals). The shot's draft-owner test — once this door's arm 2 — is
/// M5's own now, at every drafted shot (the link-sets design §5.7's
/// unowned-draft edge: `not_owner`, `site.addr` the draft, asked in the
/// shot's admission right after the draft's registration), so this door
/// walks the draft-native runs of a shot whose draft is the caller's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaRefusal {
    /// Arm 1: `published_target`, M10's code, no site.
    PublishedTarget,
    /// Arm 3: the binding's refusal, token `unbound_cell`.
    ///
    /// A hash this principal did not deposit under its own lease, or a
    /// deposit whole on disk whose size the cell contradicts: no deposit of
    /// this principal's is the cell as written.
    UnboundCell,
    /// Arm 4: D13's halt — token `unknown_cell_schema`.
    UnknownCellSchema,
    /// Arm 5: the binding's lapsed arm, token `lease_lapsed`.
    ///
    /// The deposit is gone: re-PUT the bytes. Interim in spelling.
    LeaseLapsed,
    /// Arm 6: the rebuild window, token `index_rebuilding`.
    ///
    /// The readiness token re-used, retry-class: the index's walk at open has
    /// neither completed nor died, and the lease arm alone would have
    /// refused. Interim in spelling.
    IndexRebuilding,
}

impl MediaRefusal {
    /// Returns the refusal's `detail` token, or `None` for M10's own codes.
    ///
    /// The four refusals that ride `credential_refused` carry one. Spelled
    /// here, but for arm 4's: `unknown_cell_schema` is the name of the cell's
    /// own verdict on a value naming a media kind under no pinned schema,
    /// spelled with that verdict in `cell` (`UNKNOWN_SCHEMA_TOKEN`), where
    /// the index's halt marks record it too.
    pub fn token(&self) -> Option<&'static str> {
        match self {
            MediaRefusal::PublishedTarget => None,
            MediaRefusal::UnboundCell => Some("unbound_cell"),
            MediaRefusal::UnknownCellSchema => Some(cell::UNKNOWN_SCHEMA_TOKEN),
            MediaRefusal::LeaseLapsed => Some("lease_lapsed"),
            MediaRefusal::IndexRebuilding => Some("index_rebuilding"),
        }
    }

    /// Returns the class of each refusal.
    ///
    /// The M10 code is asked of M10's own classification
    /// ([`RejectCode::disposition`]) — the row `Rejection::classified`
    /// applies to the reply built for it — so this answer and that reply
    /// cannot drift. The tokens: permanent for three — for the request as
    /// sent no act admits it: a value under an unknown schema is never
    /// admitted, and an unbound or lapsed cell is admitted only after a PUT,
    /// which is another act (the lease re-taken by it), never a retry of
    /// this one — and retry for the rebuild window's answer alone, the class
    /// the reply layer gives the readiness refusal: the same request may be
    /// admitted once the walk completes. Exhaustive, so a new arm is classed
    /// where it is added.
    pub fn disposition(&self) -> Disposition {
        match self {
            MediaRefusal::PublishedTarget => RejectCode::PublishedTarget.disposition(),
            MediaRefusal::UnboundCell
            | MediaRefusal::UnknownCellSchema
            | MediaRefusal::LeaseLapsed => Disposition::Permanent,
            MediaRefusal::IndexRebuilding => Disposition::Retry,
        }
    }
}

/// What a value is to this door, by kind.
///
/// Per `media.md` item 4, "one classification", and the blind-document
/// investigation §5, it is the picture's cell, which the binding is asked
/// about; the blind document's cell, which the target's and the owner's arms
/// judge as the picture's and the binding never sees — the board holds no
/// byte of its picture, so there is no deposit to bind and no media gate to
/// ask (`cell/blind.rs`); a value naming either kind under no pinned schema;
/// or — `None` — nothing it answers.
#[derive(Debug, Clone)]
enum Named {
    Cell(cell::Cell),
    Blind,
    UnknownSchema,
}

/// Reads the one classification for what the door acts on.
///
/// It reads over the bytes, which is what a request's `Val` and M4's
/// borrowed piece both lend; a one-byte piece inside a stretch names no
/// kind.
fn names_the_kind(bytes: &[u8]) -> Option<Named> {
    match cell::classify(bytes) {
        cell::Class::Picture(Ok(c)) => Some(Named::Cell(c)),
        cell::Class::Blind(Ok(_)) => Some(Named::Blind),
        cell::Class::Picture(Err(_)) | cell::Class::Blind(Err(_)) => Some(Named::UnknownSchema),
        cell::Class::None(_) => None,
    }
}

/// Answers arms 3, 4, 5 and 6: the value's own verdict.
///
/// It runs once the target's and the owner's arms have passed: a picture's
/// cell is asked of the binding at the media gate, `None` where it is
/// admitted, the rebuild window's state retry-class; a blind cell is
/// admitted with no store consulted — the kind's whole deposit story is its
/// owner's, off this board.
fn value_arm(
    named: Named,
    media_gate: &MediaGate,
    principal: PrincipalId,
) -> Option<MediaRefusal> {
    match named {
        Named::Cell(c) => match media_gate.binding(principal, &c) {
            Binding::Admitted => None,
            Binding::Lapsed => Some(MediaRefusal::LeaseLapsed),
            Binding::Unbound => Some(MediaRefusal::UnboundCell),
            Binding::Rebuilding => Some(MediaRefusal::IndexRebuilding),
        },
        Named::Blind => None,
        Named::UnknownSchema => Some(MediaRefusal::UnknownCellSchema),
    }
}

/// Returns the door's answer to `op` by `principal` on `world`: the step.
///
/// `world` is the locked snapshot and `media_gate` the media gate, the
/// daemon's media resource the binding is asked of — `Some` where an arm
/// fires, `None` where the write goes on to the store. The plain sequence is
/// its one caller, which holds the credential lock's read arm across this
/// step and the commit. Generic over the world M10 reads ([`FebeWorld`], the
/// one bound): the daemon instantiates it at its `World`, and this crate
/// names no engine.
///
/// **Precondition.** `world` must be the snapshot taken under the
/// serialization guard for this request, the one the commit will run
/// against.
///
/// Exhaustive with no `_` arm, the treatment `deposits_credential_link`
/// gives the route: a new `Op` fails to compile here until someone decides
/// whether it can carry or re-insert a value naming the kind. `copy`,
/// `reinstate` and `version` share identity and mint no cell (`media.md`
/// §The publication seam, consequence (b): "a `copy` of a cell shares
/// identity and mints no baptism" — and a re-placement by I-address is the
/// same sharing), so they take no arm; every other op carries no content
/// value.
pub fn media_door<W: FebeWorld>(
    world: &W,
    op: &Op,
    principal: PrincipalId,
    media_gate: &MediaGate,
) -> Option<MediaRefusal> {
    match op {
        Op::Insert { doc, values, .. } => insert_arm(world, doc, values, principal, media_gate),
        Op::Publish { doc, shot, .. } => publish_arm(world, doc, shot, principal, media_gate),
        Op::CreateNewDocument { .. }
        | Op::Delegate { .. }
        | Op::RegisterNode { .. }
        | Op::Fork { .. }
        | Op::NextAccountPrefix { .. }
        | Op::PrincipalPrefix { .. }
        | Op::EffectiveOwner { .. }
        | Op::UniversalGrants
        | Op::Delete { .. }
        | Op::Copy { .. }
        | Op::Reinstate { .. }
        | Op::Rearrange { .. }
        | Op::Version { .. }
        | Op::MakeLink { .. }
        | Op::Emit { .. }
        | Op::Nullify { .. }
        | Op::AssertSup { .. }
        | Op::EditLink { .. }
        | Op::ReadLink { .. }
        | Op::FollowLink { .. }
        | Op::RetrieveV { .. }
        | Op::RetrieveI { .. }
        | Op::ContentFrontier { .. }
        | Op::RetrieveDocVSpan { .. }
        | Op::RetrieveDocVSpanSet { .. }
        | Op::ShowOrigin { .. }
        | Op::ShowDeletions { .. }
        | Op::Compare { .. }
        | Op::FindDocsContaining { .. }
        | Op::Image { .. }
        | Op::FindLinksV { .. }
        | Op::FindLinksFtt { .. }
        | Op::CountV { .. }
        | Op::CountFtt { .. }
        | Op::WindowV { .. }
        | Op::WindowFtt { .. }
        | Op::RetrieveEndsets { .. }
        | Op::Project { .. }
        | Op::DiscoverableFrom { .. }
        | Op::DeleteOrphans { .. }
        | Op::InClaims { .. }
        | Op::OutClaims { .. }
        | Op::DocMetadata { .. }
        | Op::EditionClaims { .. } => None,
    }
}

/// Answers the `insert` arms, 1 and 3 to 6.
///
/// They are read only where `doc` is registered and the caller owns it —
/// the store's ownership-gate question, asked of M5
/// ([`Caller::passes_ownership_gate`]): PUB-6.36's slot 1 ahead of
/// everything here, as every producer ahead of the store keeps it, so an
/// unregistered or foreign `doc` answers the store's own
/// `doc_not_registered` or `not_owner` and is never told whether it is
/// published. Every value naming the kind is judged (M-I1 (a): the binding
/// is per cell, and a cell bound beside one that is not binds nothing for
/// it), in V-order, the first refusal answering; a value that names it not
/// is passed over at the cost of the classification — one byte compare for
/// a value that opens no JSON object.
fn insert_arm<W: FebeWorld>(
    world: &W,
    doc: &Address,
    values: &[Val],
    principal: PrincipalId,
    media_gate: &MediaGate,
) -> Option<MediaRefusal> {
    let m3 = world.m3();
    if !Caller::Principal(principal).passes_ownership_gate(m3, doc) {
        return None;
    }
    let mut named = values.iter().filter_map(|v| names_the_kind(v.as_bytes())).peekable();
    named.peek()?;
    // Arm 1 — the target's refusal first, whatever the value's form and
    // whatever the declaration: M5's own publication read, projected to the
    // document (PUB-2.15), on the registered address the line above found.
    if published_target(m3, doc) {
        return Some(MediaRefusal::PublishedTarget);
    }
    named.find_map(|named| value_arm(named, media_gate, principal))
}

/// Answers the `publish` arms, 3 to 6.
///
/// They are read only where M5's own admission of the shot passes it
/// through the source gate — the draft's registration and ownership among
/// its slots, so the draft here is the caller's own — the staging draft is
/// readable to the caller, and
/// the re-insert is within M5's budget — so every refusal the store gives
/// ahead of its existence walk stands ahead of this door, in the store's own
/// words, and the door reads no value the caller may not read. The
/// draft-native runs are walked as the commit re-mints them
/// ([`Shot::reinserted_runs`], M5's own family rule, in the commit's order —
/// a run named twice walked twice, the verdict the same either way), each
/// position read by M4's point read — a one-byte piece inside a stretch
/// names no kind and is passed over by the classification itself; every
/// value naming the kind is judged (M-I1 (a)), each value's own verdict in
/// placement order, the first refusal answering. Per address still, bounded
/// by the re-insert's cap.
fn publish_arm<W: FebeWorld>(
    world: &W,
    doc: &Address,
    shot: &Shot,
    principal: PrincipalId,
    media_gate: &MediaGate,
) -> Option<MediaRefusal> {
    let caller = Caller::Principal(principal);
    // Slots 1 through 6 — registration and ω of `doc`, the arguments'
    // registration and shape, the document's publication, the base's shape,
    // the source gate — asked of the snapshot the transaction will open on.
    // The predicate handed the source gate is the one M10 lends the real shot:
    // `World::readable` at the principal (the write-path check's premise,
    // `policy/attestation.rs`), built here over the trait ([`visible_to`]).
    if shot_admission(world, caller, doc, shot, &visible_to::<W>(caller)).is_err() {
        return None;
    }
    // The staging draft, judged as the document it projects to (PUB-2.15) —
    // M5's own projection; with none, no run is draft-native and the shot
    // re-inserts nothing.
    let draft = shot.draft_document()?;
    // P31: nothing of a draft the caller may not read is read on its behalf.
    // (The admission passes a run the base carries without consulting its
    // origin, PUB-6.24; the write-path check has refused an attested shot
    // over such a run already, and this door reads nothing either way.) The
    // read predicate is `ReadableWorld::readable`'s, the seam M10 reaches
    // the engine's own through; `Some(principal)` is the principal's class.
    if !ReadableWorld::readable(world, Some(principal), &draft) {
        return None;
    }
    // M5's re-insert budget — request arithmetic the store refuses
    // `too_many_values` by before it probes an address: nothing past it is
    // walked here either.
    if shot.reinserted_values() > Nat::from(MAX_REINSERTED_VALUES) {
        return None;
    }
    // Every draft-native value naming the kind is judged (M-I1 (a)): each
    // value in placement order, the first refusal answering. The owner test
    // the shot once took here is the admission's above — ω of the draft,
    // asked of every drafted shot, cell or none.
    let content = world.content();
    // The runs the commit re-mints, in its order — M5's own family rule
    // (PUB-2.40): a run of the trunk's own I-space is placed by reference
    // and a window kept as one, and neither mints.
    for run in shot.reinserted_runs() {
        for a in run.addrs() {
            // An address holding no value is the store's `dangling_source`;
            // there is nothing to read.
            let Some(named) =
                content.value_at(a.tumbler()).and_then(|piece| names_the_kind(piece.as_bytes()))
            else {
                continue;
            };
            if let Some(refusal) = value_arm(named, media_gate, principal) {
                return Some(refusal);
            }
        }
    }
    None
}

/// Returns the visibility class a caller writes at, over the trait.
///
/// It is the predicate M10 lends the real shot's source gate — the engine's
/// `World::visible_to`, which this crate cannot name — rebuilt on
/// [`ReadableWorld::readable`], whose contract makes `None` the guest: a
/// principal reads at its own class, the system caller (M9's automation
/// path) at the guest's, which is exactly the closure the engine returns.
/// `Copy`-free and borrowing nothing: it reads the world handed to it per
/// consult and nothing else.
fn visible_to<W: ReadableWorld>(caller: Caller) -> impl Fn(&W, &Address) -> bool {
    move |world: &W, doc: &Address| match caller {
        Caller::Principal(p) => world.readable(Some(p), doc),
        Caller::System => world.readable(None, doc),
    }
}

#[cfg(test)]
mod tests;
