//! THE WRITE DOOR's MEDIA STEP (media lane A; `media.md` Op inventory 2 —
//! "BOTH REFUSALS ARE skepd's, RUN AT ITS WRITE DOOR ON THE GUARD THE
//! `insert` COMMITS UNDER", "A SHOT MINTS A CELL ONLY FROM A DRAFT ITS
//! CALLER OWNS"; §The publication seam — "THE HALF IS THE WRITE DOOR's WHOLE
//! STEP, ITS ARMED SET LANDING WITH IT"; the register M-I1 (a), (f)): ONE
//! step of the plain write sequence, between its admission and the commit,
//! answering every value naming the cell's kind. The reads are M5's, M3's
//! and M4's public ones off the locked snapshot the commit will read (the
//! serialization guard admits no commit between, so the check that passed
//! and the commit it guards are one interval); the parse is
//! [`cell::parse`]'s, the one parser.
//!
//! THE ARMED SET, in answer order (PATTERNS P6 — enumerated here, at the
//! surface, and in `docs/wire.md` §Media, so no later lane moves one
//! state's answer from one code to another):
//!
//! 1. `published_target` — an `insert` into a PUBLISHED document (or a
//!    member of one, PUB-2.15) the caller owns whose values hold one naming
//!    the kind, WHATEVER its `deposit` declaration. M10's own door answers
//!    this code to an UNDECLARED insert at a published target before any
//!    consult; the DECLARED deposit is M5's one door that admits a published
//!    target on its class, and it judges the type and never the atom
//!    (`skep-febe`'s `Op::Insert` card; PUB-2.59, PUB-2.64), so this arm is
//!    what refuses a cell declared under a deposit class — the one cell the
//!    stores do not cover — ahead of both refusals below; for an undeclared
//!    one it is the same code M10 would answer, so the order against M10 is
//!    unobservable.
//! 2. `not_owner`, naming the draft — a `publish` whose draft-native runs
//!    (the ones the shot re-inserts as fresh identity, PUB-2.40) hold a
//!    value naming the kind, from a caller who does not OWN the draft: ω,
//!    exact — the same predicate `not_owner` makes of `doc`
//!    (`skep-arrangement`'s `Caller::is_owner`, never a second spelling). A
//!    grantee's, an ancestor's or a descendant's shot naming the owner's
//!    private original would otherwise re-mint its cell with no `insert`
//!    and no refusal on the way — the binding's own attack, one op over.
//! 3. `unbound_cell` (`credential_refused`, PERMANENT) — a cell in a draft
//!    `insert`, or at the owner's own shot, naming a hash THIS PRINCIPAL
//!    DID NOT DEPOSIT UNDER ITS OWN LEASE: THE BINDING's refusal, real from
//!    lane B — the gate reads the principal's own lease record first and the
//!    file only where that record names the hash under a live lease
//!    ([`MediaGate::binding`]); a cell whose hash the principal holds a live
//!    lease on, over a whole file whose length the cell's `size` names, is
//!    ADMITTED and goes on to the store. A deposit whole on disk whose size
//!    the cell contradicts is this refusal too — no deposit of this
//!    principal's is the cell as written. PERMANENT for the request as
//!    sent: the act that exists is a PUT of the bytes, then the cell the
//!    PUT's answer spells. THE FACE (M-I7 (e)) says that NO DEPOSIT OF THE
//!    PERSON's HERE IS THE CELL AS WRITTEN, and never that none was made —
//!    it is the answer too to a person who did deposit, past the horizon or
//!    at an operator's honest nulls: "no deposit of yours here is this
//!    picture's cell as written: upload the file, then place the cell its
//!    answer spells." P10's fence-only face ("this board takes no
//!    uploads") is RETIRED with the store at this arm: on a board whose
//!    uploads are CLOSED the client keys that face off `/health`'s echo
//!    before this token's face speaks.
//! 4. `unknown_cell_schema` (`credential_refused`, PERMANENT) — a value
//!    naming EITHER media kind — the picture's or the blind document's —
//!    that parses under no pinned schema, in the same two positions:
//!    DOCTRINE D13's carve-out, the halt a reader makes at a permanent act
//!    on a schema it does not know, so the day a second schema is pinned no
//!    board holds a cell of it that was never bound (the record's H1). The
//!    same bytes are never admitted. The face a client renders: "this value
//!    names a media cell — a picture's or a blind document's — in a form
//!    this board does not read".
//! 5. `lease_lapsed` (`credential_refused`, PERMANENT for the request as
//!    sent) — a cell naming a hash this principal DID deposit, whose lease
//!    has lapsed within the horizon, or whose lease is live over a file
//!    that is not there or not whole: the deposit is gone, and the act is a
//!    re-PUT of the bytes, which re-takes the lease. Told apart from the
//!    binding's refusal so a client's resume can be written against it,
//!    and read off this principal's own record alone — never off the file's
//!    presence beyond that record's live lease (Op inventory 1, "a client
//!    meeting a LAPSED lease meets its OWN refusal"). Past the horizon the
//!    record answers no lease and the binding's refusal stands.
//! 6. `index_rebuilding` (`credential_refused`, RETRY) — THE WINDOW's
//!    answer, in the binding's position and during the walk alone: the
//!    index's rebuild at open has not completed, and the lease arm alone
//!    would have answered `unbound_cell` or `lease_lapsed` — a verdict the
//!    index arm, unread, may overturn (a hash the principal's own cells
//!    name, its file whole). The readiness token re-used, its class the
//!    readiness refusal's: the request as sent may be perfectly good, and
//!    the walk momentarily unfinished (ms5-R: the door never waits; P22; the
//!    register M-I5 (b)). A cell the lease arm ADMITS in the window is
//!    admitted. The one arm of the armed set that is not PERMANENT.
//!
//! THE KIND COLUMN (`media.md` item 4; the blind-document investigation §5
//! (i); s6-D3): the arms above are read PER KIND. The picture's cell meets
//! every arm. THE BLIND DOCUMENT's cell (`media/blind.rs`) meets arms 1, 2
//! and 4 as the picture's does — `published_target` at a published target,
//! `not_owner` at a reader's shot, the halt on a malformed body — and
//! NEVER arms 3 and 5: it is ADMITTED into a draft and at the owner's shot
//! with no store consulted, there being no deposit to bind (the board holds
//! no byte of a blind picture) and no lease to lapse. The same door, the
//! same order, one classification ahead of it.
//!
//! THE SHOT'S BINDING: the owner's own shot re-inserting a draft's cell asks
//! the binding again, as its `insert` did — the whole armed set lands
//! together at both positions. The binding reads THE CELL INDEX FIRST
//! ([`MediaGate::binding`]): a hash the requester's own cells already name
//! is a reference, kept by no lease — so the owner's shot of a draft whose
//! cell was admitted is admitted after the lease lapsed, while the file is
//! whole at the cell's size, and `lease_lapsed` where it is not. Until the
//! index's walk at open completes the index arm is skipped and the lease
//! arm alone ADMITS, so a lease lapsed between the insert and the shot
//! answers `index_rebuilding` in that window — retry-class — and the shot
//! is admitted after the walk with no re-PUT: the door never waits on the
//! index.
//!
//! WHAT STANDS AHEAD. The plain sequence's producers — the mint class, the
//! `replaces` fence, the board-state gate with the write-path check behind
//! it, the `nullify` class — have answered before this step runs: a bare
//! session's write into a published document is `signed_session_required`,
//! an unsigned shot `attestation_required`, an attested shot copying in a
//! draft the caller may not read `attestation_invalid:withheld` or the
//! store's `withheld`. What stands BEHIND it — the store's own slots — is
//! kept ahead of its arms by construction: an `insert` is read only where
//! `doc` is registered and the caller owns it (PUB-6.36's slot 1, PUB-6.37),
//! and a `publish` only where M5's own admission of the shot
//! ([`shot_admission`], slots 1 through 6, the source gate included) passes
//! it, the draft is readable to the caller (PATTERNS P31: no value the
//! caller may not read is read on its behalf — a verdict here is answered
//! to the caller) and the re-insert is within M5's budget; every other case
//! answers nothing here and the store answers it as built. A refusal here
//! commits nothing and gives the head writer its turn, as an admission
//! refusal does (l7-C1).

use skep_address::{document_of, Address, Nat};
use skep_arrangement::{
    published_target, shot_admission, trunk_of, Caller, PlacedSegment, Shot, MAX_REINSERTED_VALUES,
};
use skep_content::{HasContent, Val};
use skep_febe::{Disposition, Op};
use skep_namespace::{HasM3, PrincipalId};

use super::cell;
use super::gate::{Binding, MediaGate};
use crate::World;

/// The door's answer — one variant per arm of the armed set, in the
/// module's order. Two are M10's own codes, raised here on the daemon's
/// channel with M10's classification; four are the daemon's tokens, riding
/// `credential_refused` as every daemon-side refusal does (AUTH-3.53's
/// family; wire.md §Credential refusals).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MediaRefusal {
    /// Arm 1: `published_target`, M10's code, no site.
    PublishedTarget,
    /// Arm 2: `not_owner`, M10's code, `site.addr` the DRAFT — the document
    /// that failed the ω test, as every `not_owner` names one.
    NotOwner { draft: Address },
    /// Arm 3: the binding's refusal — token `unbound_cell`: a hash this
    /// principal did not deposit under its own lease.
    UnboundCell,
    /// Arm 4: D13's halt — token `unknown_cell_schema`.
    UnknownCellSchema,
    /// Arm 5: the binding's LAPSED arm — token `lease_lapsed`: the deposit
    /// is gone, re-PUT the bytes. INTERIM in spelling (the board's sm-Q8).
    LeaseLapsed,
    /// Arm 6: THE WINDOW — token `index_rebuilding`, the readiness token
    /// re-used, RETRY-CLASS: the index's walk at open is not done and the
    /// lease arm alone would have refused. INTERIM in spelling (sm-Q8).
    IndexRebuilding,
}

impl MediaRefusal {
    /// The `detail` token of the four refusals that ride
    /// `credential_refused`; `None` for the two that are M10's own codes.
    /// Spelled here and only here.
    pub(crate) fn token(&self) -> Option<&'static str> {
        match self {
            MediaRefusal::PublishedTarget | MediaRefusal::NotOwner { .. } => None,
            MediaRefusal::UnboundCell => Some("unbound_cell"),
            MediaRefusal::UnknownCellSchema => Some("unknown_cell_schema"),
            MediaRefusal::LeaseLapsed => Some("lease_lapsed"),
            MediaRefusal::IndexRebuilding => Some("index_rebuilding"),
        }
    }

    /// The class of the tokens: PERMANENT for three — for the request AS
    /// SENT no act admits it: a value under an unknown schema is never
    /// admitted, and an unbound or lapsed cell is admitted only after a
    /// PUT, which is another act (the lease re-taken by it), never a retry
    /// of this one — and RETRY for the window's answer alone, the class the
    /// reply layer gives the readiness refusal: the same request may be
    /// admitted once the walk completes. The two M10 codes take M10's own
    /// classification, `RejectCode::disposition`, where the reply is built.
    pub(crate) fn disposition(&self) -> Disposition {
        match self {
            MediaRefusal::IndexRebuilding => Disposition::Retry,
            _ => Disposition::Permanent,
        }
    }
}

/// What a value is to this door, BY KIND (`media.md` item 4, "ONE
/// CLASSIFICATION"; the blind-document investigation §5): the picture's
/// cell, which the binding is asked about; the BLIND document's cell, which
/// the target's and the owner's arms judge as the picture's and the
/// binding never sees — the board holds no byte of its picture, so there is
/// no deposit to bind and no gate to ask (`media/blind.rs`); a value naming
/// either kind under no pinned schema; or — `None` — nothing it answers.
#[derive(Debug, Clone)]
enum Named {
    Cell(cell::Cell),
    Blind,
    UnknownSchema,
}

/// The one classification, read for what the door acts on.
fn names_the_kind(value: &Val) -> Option<Named> {
    match cell::classify(value.as_bytes()) {
        cell::Class::Picture(Ok(c)) => Some(Named::Cell(c)),
        cell::Class::Blind(Ok(_)) => Some(Named::Blind),
        cell::Class::Picture(Err(_)) | cell::Class::Blind(Err(_)) => Some(Named::UnknownSchema),
        cell::Class::None(_) => None,
    }
}

/// Arms 3, 4, 5 and 6 — the value's own verdict once the target's and the
/// owner's arms have passed: a picture's cell is asked of THE BINDING at
/// the gate, `None` where it is admitted, the window's state retry-class; a
/// blind cell is ADMITTED with no store consulted — the kind's whole
/// deposit story is its owner's, off this board.
fn value_arm(named: Named, gate: &MediaGate, principal: PrincipalId) -> Option<MediaRefusal> {
    match named {
        Named::Cell(c) => match gate.binding(principal, &c) {
            Binding::Admitted => None,
            Binding::Lapsed => Some(MediaRefusal::LeaseLapsed),
            Binding::Unbound => Some(MediaRefusal::UnboundCell),
            Binding::Rebuilding => Some(MediaRefusal::IndexRebuilding),
        },
        Named::Blind => None,
        Named::UnknownSchema => Some(MediaRefusal::UnknownCellSchema),
    }
}

/// THE STEP: the door's answer to `op` by `principal` on `world`, the
/// locked snapshot, with `gate` the daemon's media resource the binding is
/// asked of — `Some` where an arm fires, `None` where the write goes on to
/// the store. `world` MUST be the snapshot taken under the serialization
/// guard for this request, the one the commit will run against; the plain
/// sequence is its one caller, which holds the credential lock's read arm
/// across this step and the commit.
///
/// EXHAUSTIVE with no `_` arm, the treatment `deposits_credential_link`
/// gives the route: a new `Op` fails to compile here until someone decides
/// whether it can carry or re-insert a value naming the kind. `copy` and
/// `version` share identity and mint no cell (`media.md` §The publication
/// seam, consequence (b): "a `copy` of a cell shares identity and mints no
/// baptism"), so they take no arm; every other op carries no content value.
pub(crate) fn media_door(
    world: &World,
    op: &Op,
    principal: PrincipalId,
    gate: &MediaGate,
) -> Option<MediaRefusal> {
    match op {
        Op::Insert { doc, values, .. } => insert_arm(world, doc, values, principal, gate),
        Op::Publish { doc, shot } => publish_arm(world, doc, shot, principal, gate),
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

/// The `insert` arms (1, 3, 4): read only where `doc` is registered and the
/// caller owns it — PUB-6.36's slot 1 ahead of everything here, as every
/// producer ahead of the store keeps it, so an unregistered or foreign
/// `doc` answers the store's own `doc_not_registered` or `not_owner` and is
/// never told whether it is published. The first value naming the kind, in
/// V-order, decides; a value that names it not is read and passed over at
/// the cost of one byte compare.
fn insert_arm(
    world: &World,
    doc: &Address,
    values: &[Val],
    principal: PrincipalId,
    gate: &MediaGate,
) -> Option<MediaRefusal> {
    let m3 = world.m3();
    if !(m3.is_registered_document(doc) && Caller::Principal(principal).is_owner(m3, doc)) {
        return None;
    }
    let named = values.iter().find_map(names_the_kind)?;
    // Arm 1 — the TARGET's refusal first, whatever the value's form and
    // whatever the declaration: M5's own publication read, projected to the
    // document (PUB-2.15), on the registered address the line above found.
    if published_target(m3, doc) {
        return Some(MediaRefusal::PublishedTarget);
    }
    value_arm(named, gate, principal)
}

/// The `publish` arms (2, 3, 4): read only where M5's own admission of the
/// shot passes it through the source gate, the staging draft is readable
/// to the caller, and the re-insert is within M5's budget — so every
/// refusal the store gives ahead of its existence walk stands ahead of this
/// door, in the store's own words, and the door reads no value the caller
/// may not read. The draft-native runs are walked as the commit will class
/// them ([`Shot::address_form`], M5's own classing), each position's value
/// read by `value_at`, the accessor the re-insert reads with; the first
/// value naming the kind decides. Then the owner test, then the form.
fn publish_arm(
    world: &World,
    doc: &Address,
    shot: &Shot,
    principal: PrincipalId,
    gate: &MediaGate,
) -> Option<MediaRefusal> {
    let caller = Caller::Principal(principal);
    // Slots 1 through 6 — registration and ω of `doc`, the arguments'
    // registration and shape, the document's publication, the base's shape,
    // the source gate — asked of the snapshot the transaction will open on.
    // The predicate handed the gate is the one M10 lends the real shot:
    // `World::readable` at the principal (the write-path check's premise,
    // `policy/attestation.rs`).
    if shot_admission(world, caller, doc, shot, &World::visible_to(caller)).is_err() {
        return None;
    }
    // The staging draft, judged as the document it projects to (PUB-2.15);
    // with none, no run is draft-native and the shot re-inserts nothing.
    let draft = trunk_of(shot.draft.as_ref()?);
    // P31: nothing of a draft the caller may not read is read on its behalf.
    // (The admission passes a run the base carries without consulting its
    // origin, PUB-6.24; the write-path check has refused an attested shot
    // over such a run already, and this door reads nothing either way.)
    if !world.readable(Some(principal), &draft) {
        return None;
    }
    // M5's re-insert budget — request arithmetic the store refuses
    // `too_many_values` by before it probes an address: nothing past it is
    // walked here either.
    if shot.reinserted_values() > Nat::from(MAX_REINSERTED_VALUES) {
        return None;
    }
    let content = world.content();
    let mut named = None;
    'runs: for segment in shot.address_form(doc) {
        let PlacedSegment::Value(run) = segment else {
            continue; // a window: a reference, read from nowhere
        };
        // A value run of the trunk's own I-space is placed by reference and
        // mints nothing; the draft's is re-inserted (PUB-2.40).
        if document_of(run.i_start()).map(|d| trunk_of(&d)).as_ref() != Some(&draft) {
            continue;
        }
        for a in run.addrs() {
            // An address holding no value is the store's `dangling_source`;
            // there is nothing to read.
            if let Some(found) = content.value_at(a.tumbler()).and_then(names_the_kind) {
                named = Some(found);
                break 'runs;
            }
        }
    }
    let named = named?;
    // Arm 2 — the owner test, ω exact, the same predicate as `doc`'s.
    if !caller.is_owner(world.m3(), &draft) {
        return Some(MediaRefusal::NotOwner { draft });
    }
    value_arm(named, gate, principal)
}

#[cfg(test)]
mod tests;
