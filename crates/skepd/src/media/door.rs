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
//!    PUT's answer spells. P10's fence-only face ("this board takes no
//!    uploads") is RETIRED with the store: the face now names the deposit
//!    the cell lacks.
//! 4. `unknown_cell_schema` (`credential_refused`, PERMANENT) — a value
//!    naming the kind that parses under no pinned schema, in the same two
//!    positions: DOCTRINE D13's carve-out, the halt a reader makes at a
//!    permanent act on a schema it does not know, so the day a second
//!    schema is pinned no board holds a cell of it that was never bound
//!    (the record's H1). The same bytes are never admitted.
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
//!
//! THE SHOT'S BINDING, lane B's reading: the owner's own shot re-inserting
//! a draft's cell asks the binding again, as its `insert` did — the whole
//! armed set lands together at both positions — so a lease lapsed between
//! the insert and the shot answers `lease_lapsed` there until the bytes are
//! re-PUT. Lane C's cell index re-reads this arm: a hash the requester's
//! own cells already name is a reference, kept by no lease.
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
    published_target, shot_admission, trunk_of, Caller, PlacedSegment, Shot,
    MAX_REINSERTED_VALUES,
};
use skep_content::{HasContent, Val};
use skep_febe::{Disposition, Op};
use skep_namespace::{HasM3, PrincipalId};

use super::cell;
use super::gate::{Binding, MediaGate};
use crate::World;

/// The door's answer — one variant per arm of the armed set, in the
/// module's order. Two are M10's own codes, raised here on the daemon's
/// channel with M10's classification; three are the daemon's tokens, riding
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
}

impl MediaRefusal {
    /// The `detail` token of the three refusals that ride
    /// `credential_refused`; `None` for the two that are M10's own codes.
    /// Spelled here and only here.
    pub(crate) fn token(&self) -> Option<&'static str> {
        match self {
            MediaRefusal::PublishedTarget | MediaRefusal::NotOwner { .. } => None,
            MediaRefusal::UnboundCell => Some("unbound_cell"),
            MediaRefusal::UnknownCellSchema => Some("unknown_cell_schema"),
            MediaRefusal::LeaseLapsed => Some("lease_lapsed"),
        }
    }

    /// The class of the three tokens: PERMANENT, the family's — for the
    /// request AS SENT no act admits it: a value under an unknown schema is
    /// never admitted, and an unbound or lapsed cell is admitted only after
    /// a PUT, which is another act (the lease re-taken by it), never a
    /// retry of this one. The two M10 codes take M10's own classification,
    /// `RejectCode::disposition`, where the reply is built.
    pub(crate) fn disposition(&self) -> Disposition {
        Disposition::Permanent
    }
}

/// What a value is to this door: a cell, a value naming the kind under no
/// pinned schema, or — `None` — nothing it answers.
#[derive(Debug, Clone)]
enum Named {
    Cell(cell::Cell),
    UnknownSchema,
}

/// The one parse, read for what the door acts on.
fn names_the_kind(value: &Val) -> Option<Named> {
    match cell::parse(value.as_bytes()) {
        Ok(c) => Some(Named::Cell(c)),
        Err(refusal) if refusal.names_kind() => Some(Named::UnknownSchema),
        Err(_) => None,
    }
}

/// Arms 3, 4 and 5 — the value's own verdict once the target's and the
/// owner's arms have passed: a cell is asked of THE BINDING at the gate,
/// `None` where it is admitted.
fn value_arm(named: Named, gate: &MediaGate, principal: PrincipalId) -> Option<MediaRefusal> {
    match named {
        Named::Cell(c) => match gate.binding(principal, &c) {
            Binding::Admitted => None,
            Binding::Lapsed => Some(MediaRefusal::LeaseLapsed),
            Binding::Unbound => Some(MediaRefusal::UnboundCell),
        },
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
mod tests {
    use skep_arrangement::{Deposit, ShotRun, Run, VPos};
    use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource};
    use skep_namespace::{head_document, system_account, BOOTSTRAP_PRINCIPAL, SYSTEM_PRINCIPAL};

    use super::*;

    const HASH: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";

    fn canonical() -> Vec<u8> {
        format!(r#"{{"type":"{}","hash":"{HASH}","size":5}}"#, cell::KIND).into_bytes()
    }

    fn unknown_schema() -> Vec<u8> {
        format!(r#"{{"type":"{}","hash":"{HASH}","size":5,"hash_alg":"sha256-tree"}}"#, cell::KIND)
            .into_bytes()
    }

    fn insert(doc: &Address, bytes: Vec<u8>) -> Op {
        Op::Insert {
            doc: doc.clone(),
            at: VPos::content(Nat::from(1u32)),
            values: vec![Val::new(bytes)],
            deposit: Deposit::Undeclared,
        }
    }

    /// Over the genesis world, as the system principal — the one principal
    /// genesis seats with documents: the head document `H` (published, its
    /// own) and a private draft it mints — the insert arms: a cell into a
    /// draft `unbound_cell` while the principal holds no lease on its hash,
    /// a value under an unknown schema `unknown_cell_schema`, prose and a
    /// def nothing; into `H` `published_target` whatever the value's form
    /// and whatever the declaration; and a caller who does not own the
    /// draft meets nothing here (the store's `not_owner` stands). Then the
    /// shot: the owner's own shot of the draft holding a cell is refused
    /// `unbound_cell` the same, a shot naming no draft meets nothing, and
    /// nothing commits. Then THE BINDING MADE REAL (lane B): the bytes
    /// deposited under the principal's own lease, the same insert and the
    /// same shot are ADMITTED; the lease lapsed, both answer `lease_lapsed`;
    /// and another principal's deposit of the same bytes admits nothing of
    /// this one's.
    #[test]
    fn the_insert_arms_and_the_owners_shot_over_the_genesis_world() {
        let dir = tempfile::tempdir().expect("tempdir");
        let gate = MediaGate::open(dir.path()).expect("the store opens");
        let engine = skep_engine::Engine::open(KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
            salt: SaltSource::Seeded(0),
        })
        .expect("in-memory genesis cannot fail");
        let (draft, _) = engine
            .namespace()
            .create_new_document(SYSTEM_PRINCIPAL, &system_account(), Some(false))
            .expect("the system principal mints a private draft in its own account");
        let cell_at = engine
            .vstream()
            .insert(
                Caller::Principal(SYSTEM_PRINCIPAL),
                &draft,
                VPos::content(Nat::from(1u32)),
                vec![Val::new(canonical())],
                Deposit::Undeclared,
            )
            .expect("the engine, below the door, writes any bytes")
            .0;
        let snap = engine.kernel().snapshot();
        let world = snap.world();
        let h = head_document();
        let door = |op: Op, p: PrincipalId| media_door(world, &op, p, &gate);

        assert_eq!(door(insert(&draft, canonical()), SYSTEM_PRINCIPAL), Some(MediaRefusal::UnboundCell));
        assert_eq!(
            door(insert(&draft, unknown_schema()), SYSTEM_PRINCIPAL),
            Some(MediaRefusal::UnknownCellSchema)
        );
        assert_eq!(door(insert(&draft, b"prose".to_vec()), SYSTEM_PRINCIPAL), None);
        assert_eq!(door(insert(&draft, vec![0x0b, 1, 0, 1, 2]), SYSTEM_PRINCIPAL), None, "a def");
        assert_eq!(door(insert(&h, canonical()), SYSTEM_PRINCIPAL), Some(MediaRefusal::PublishedTarget));
        assert_eq!(door(insert(&h, unknown_schema()), SYSTEM_PRINCIPAL), Some(MediaRefusal::PublishedTarget));
        let declared = Op::Insert {
            doc: h.clone(),
            at: VPos::content(Nat::from(1u32)),
            values: vec![Val::new(canonical())],
            deposit: Deposit::Declared(skep_engine::types::t_grant().clone()),
        };
        assert_eq!(door(declared, SYSTEM_PRINCIPAL), Some(MediaRefusal::PublishedTarget));
        assert_eq!(door(insert(&draft, canonical()), BOOTSTRAP_PRINCIPAL), None, "not the owner: the store's");

        let shot = |draft: Option<Address>| Op::Publish {
            doc: h.clone(),
            shot: Shot {
                base: None,
                draft: draft.clone(),
                runs: vec![ShotRun {
                    origin: draft.clone().unwrap_or_else(|| h.clone()),
                    run: Run::new(cell_at.clone(), Nat::from(1u32)).expect("one position"),
                }],
            },
        };
        assert_eq!(door(shot(Some(draft.clone())), SYSTEM_PRINCIPAL), Some(MediaRefusal::UnboundCell));
        // The same runs with no draft named: the store's `bad_run` stands
        // (the run's origin is not `H`), and this door answers nothing.
        assert_eq!(door(shot(None), SYSTEM_PRINCIPAL), None);
        assert_eq!(engine.kernel().current_seq(), snap.seq(), "the door commits nothing");
        for (refusal, token) in [
            (MediaRefusal::UnboundCell, Some("unbound_cell")),
            (MediaRefusal::UnknownCellSchema, Some("unknown_cell_schema")),
            (MediaRefusal::LeaseLapsed, Some("lease_lapsed")),
            (MediaRefusal::PublishedTarget, None),
            (MediaRefusal::NotOwner { draft: draft.clone() }, None),
        ] {
            assert_eq!(refusal.token(), token);
            assert_eq!(refusal.disposition(), Disposition::Permanent);
        }

        // THE BINDING MADE REAL: five real bytes, the cell naming THEIR
        // hash — the fixture's `HASH` above is the empty input's, which no
        // five-byte deposit can carry — in a second draft the engine seeds
        // below the door, as the first was.
        let bytes = b"hello";
        let hex = blake3::hash(bytes).to_hex();
        let real = || format!(r#"{{"type":"{}","hash":"{hex}","size":5}}"#, cell::KIND).into_bytes();
        let (draft2, _) = engine
            .namespace()
            .create_new_document(SYSTEM_PRINCIPAL, &system_account(), Some(false))
            .expect("a second private draft");
        let real_at = engine
            .vstream()
            .insert(
                Caller::Principal(SYSTEM_PRINCIPAL),
                &draft2,
                VPos::content(Nat::from(1u32)),
                vec![Val::new(real())],
                Deposit::Undeclared,
            )
            .expect("the engine, below the door, writes any bytes")
            .0;
        let snap = engine.kernel().snapshot();
        let world = snap.world();
        let door = |op: Op, p: PrincipalId| media_door(world, &op, p, &gate);
        let shot2 = || Op::Publish {
            doc: h.clone(),
            shot: Shot {
                base: None,
                draft: Some(draft2.clone()),
                runs: vec![ShotRun {
                    origin: draft2.clone(),
                    run: Run::new(real_at.clone(), Nat::from(1u32)).expect("one position"),
                }],
            },
        };
        let deposit = |p: PrincipalId, interval: u64| {
            let key = MediaGate::key(p);
            let now = gate.now_ms();
            let store = gate.store();
            let rec = store.create_upload(&key, "blake3", 5, now + interval, None).unwrap();
            store.resume(&key, &rec.id, 0, now).unwrap();
            store.append(&key, &rec.id, bytes, now, interval).unwrap();
            store.settle(&key, &rec.id, now, interval).unwrap();
            store.finish(&key, &rec.id, now, now + interval).unwrap();
        };
        assert_eq!(door(insert(&draft2, real()), SYSTEM_PRINCIPAL), Some(MediaRefusal::UnboundCell));
        assert_eq!(door(shot2(), SYSTEM_PRINCIPAL), Some(MediaRefusal::UnboundCell));
        deposit(BOOTSTRAP_PRINCIPAL, 1_000_000);
        assert_eq!(
            door(insert(&draft2, real()), SYSTEM_PRINCIPAL),
            Some(MediaRefusal::UnboundCell),
            "another principal's deposit admits nothing of this one's"
        );
        deposit(SYSTEM_PRINCIPAL, 1_000);
        assert_eq!(door(insert(&draft2, real()), SYSTEM_PRINCIPAL), None, "admitted under its own live lease");
        assert_eq!(door(shot2(), SYSTEM_PRINCIPAL), None, "the owner's shot too");
        let wrong_size = format!(r#"{{"type":"{}","hash":"{hex}","size":4}}"#, cell::KIND).into_bytes();
        assert_eq!(door(insert(&draft2, wrong_size), SYSTEM_PRINCIPAL), Some(MediaRefusal::UnboundCell), "the size check");
        assert_eq!(door(insert(&h, real()), SYSTEM_PRINCIPAL), Some(MediaRefusal::PublishedTarget), "the target first, lease or none");
        gate.advance_clock_ms(1_000);
        assert_eq!(door(insert(&draft2, real()), SYSTEM_PRINCIPAL), Some(MediaRefusal::LeaseLapsed));
        assert_eq!(door(shot2(), SYSTEM_PRINCIPAL), Some(MediaRefusal::LeaseLapsed));
        assert_eq!(engine.kernel().current_seq(), snap.seq(), "the door commits nothing");
    }
}
