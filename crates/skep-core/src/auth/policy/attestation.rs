//! The write-path check (signed ops).
//!
//! It is what the plain sequence's publish-class gate runs on a claimed
//! board ([`attestation_check`]), whose admitted attestation is what the
//! write's commit marker carries — and the question it asks M5's own
//! admission of a shot to decide what a shot the composer could not read is
//! owed ([`refused_at_or_before_the_source_gate`]).

use skep_address::Address;
use skep_arrangement::{shot_admission, Caller, Deposit};
use skep_febe::Op;
use skep_identity::{
    parse_record_value, CredentialKind, Enrollment, Fingerprint, HasIdentity, PublicKey, SigAlgRow,
};
use skep_kernel::Attestation;
use skep_namespace::{system_account, HasM3, PrincipalId};

use super::{
    addr_spans, homed_in_doc_one, record_deposit_kind, registry_deposit_kind, AttestFault,
    CredentialRefusal,
};
use crate::auth::entry::{self, ComposeFault};
use crate::auth::session::key_subject;
use crate::commits::board_term;
use skep_engine::World;

/// Runs the write-path check (signed ops; the design record §4.5 (1)–(2)).
///
/// The check runs before the transaction, beside the publish-class gate
/// (wire.md §Credential refusals; the design record's `publish_gate`) —
/// here `board_state_admission`'s claimed arm — on the snapshot the gates
/// read, its key table the snapshot's own slice, which under the
/// serialization guard *is* the transaction's base.
///
/// The entry frame the daemon composes for a `publish` reads the copied
/// runs' values off the snapshot by the content store's run read
/// (`pieces`) — a second Σ-width walk per attested shot, off the snapshot
/// and not under M2's applier lock but under the daemon's serialization
/// lock (the investigation §3.3's price), stopped at the body's budget —
/// and over the staging draft's runs, before it starts, at the store's own
/// re-insert budget; a window is spelled by address and read from nowhere.
/// It reads a value only where the principal may read it: this check's
/// verdict is answered to the principal, so a value read on its behalf is a
/// value disclosed to it, and every refusal it gives a shot with an
/// unreadable copied run is the same whatever that run's bytes are. A run
/// naming an address with no value cannot commit; the store's
/// `dangling_source` is that write's answer, so the check passes it through
/// unattested rather than refusing a signature over bytes nobody holds.
///
/// # Errors
///
/// Reached for a publish-class write from a signed session on a claimed
/// board, the check answers in this order:
///
/// 1. The checked set — [`crate::codec::in_checked_set`]: the ten
///    publish-class op kinds — `create_new_document`, `fork`, `version`,
///    `insert`, `publish`, `make_link`, `emit`, `nullify`, `assert_sup`,
///    `edit_link` — each with its cell of the entry frame (signed-ops D24);
///    `delete`, `copy`, `reinstate` and `rearrange` carry no `attest` (the
///    codec refuses the member there) and have no cell, the store refusing
///    each into a published document, so no publish-class entry of their
///    kind commits above the claim.
/// 2. The record deposit exemption, narrowed (§2.5's `insert` cell;
///    signed-ops D26; SO-I4): the one `insert` the check demands no `attest`
///    of is the atom a credential or registry record rides — an `insert` (i)
///    declared under a kind of the record-deposit set
///    ([`crate::auth::policy::record_deposit_kind`]) or of the registry's
///    ([`registry_deposit_kind`]), (ii) carrying one value that parses as a
///    record of that kind ([`declared_record_atom`] — the one parse, one
///    site, one reading), (iii) whose record carries its `sig` member, and
///    (iv) into a doc 1, the home a credential link can name (AUTH-2.127's
///    pin — the fold's `not_doc_one` test, read here through M3's own slot,
///    `crate::auth::policy`'s `homed_in_doc_one`). Such an atom's signature
///    is the record's own `sig`, verified one position later at its
///    `make_link` under the set that opens its home (the record grade, 2a;
///    for a registry record, 2b). The deposit's other half, the `make_link`
///    naming the atom, never reaches this producer at all:
///    `deposits_credential_link` routes it to the credential sequence, whose
///    `precheck` is the record grade's door, and `deposits_registry_link` a
///    registry record's to the registry sequence — which is how the check
///    tells signed-ops D26's case: by route for the link, by the bytes for
///    the atom. Three outcomes beside the exemption, each its own path: (a)
///    the atom is no record of the declared kind — prose, a record past
///    [`skep_identity::MAX_RECORD_BYTES`], a record of another kind — and
///    the entry check runs as for any `insert`: unsigned it answers
///    `attestation_required`, attested it commits signed, its row carrying
///    `attest`; (b) the atom parses as a record of the kind and carries no
///    `sig`: refused here, at the `insert`, `record_sig_required`, permanent
///    — nothing lands and no orphan is minted (P13, the earliest act the
///    fault is decidable from), the act that exists being a new record
///    composed with its `sig`; (c) the atom parses with its `sig` but the
///    document is no doc 1 — no credential link can name it there — and the
///    entry check runs. At or below the claim nothing here runs (A5).
/// 3. A3 — a document whose owner is the system account `1.1.0.1` is exempt,
///    read by ω — the longest registered prefix over the board's principal
///    list Π, a read and never address arithmetic — and never by the
///    `"system"` testimony. The head writer never passes dispatch, so this
///    arm is stated for a dispatched write that names one and is met by
///    none.
/// 4. The board term, `H.1`'s pair ([`crate::commits::board_term`]), read
///    *before* the member is asked for: a board with no `H.1` — the states
///    `board_term` names — answers `attestation_invalid:board_unavailable`,
///    never "carry an attest", since no client can sign over a term the board
///    lacks.
/// 5. (1): no `attest` → `attestation_required`, ahead of the composition
///    (the design record §4.5's head; SO-I7 (f), SO-I9 (a)): every unsigned
///    write of the checked set above the claim that reaches this step is
///    told this one thing whatever its body names, and pays no walk of a
///    shot's values to be told it — so an unsigned publish that also names a
///    missing source answers `attestation_required` before `dangling_source`.
/// 6. The entry frame, composed for an attested write alone, from the op,
///    the snapshot and the board term (`crate::auth::entry`) — every member
///    but `alg`, which only the presented member names: a `publish` copying
///    in an address with no value passes unattested to the store's own
///    `dangling_source`; a `publish` copying in a staging draft's run whose
///    document the principal may not read is never composed, and what the
///    shot is owed is decided here by asking M5's own admission of the shot
///    ([`refused_at_or_before_the_source_gate`]) — unattested to the store's
///    own refusal where it refuses (`withheld`, or an answer ahead of the
///    source gate), `attestation_invalid:withheld` where it would admit the
///    shot, the base carrying the run (a window is signed by address in the
///    address form, and never raises this: the store's gate alone decides
///    it, after the signature); a body past `entry::MAX_SHOT_BODY_BYTES`
///    answers `attestation_invalid:frame_too_large` before it is built past
///    the budget; a term the frame cannot spell — a width, an extent or a
///    count past 2^64 − 1 — passes unattested to the store's refusal of the
///    shot (`base_extent_too_large`, `too_many_values`, `dangling_source`); a
///    shot whose staging-draft runs re-insert more values than M5's
///    `MAX_REINSERTED_VALUES` passes unattested to the store's
///    `too_many_values`, its values never walked; a `make_link` or an `emit`
///    whose slot is over either of M7's per-slot budgets passes unattested
///    to M7's own `slot_too_large`, the slot never resolved past the budget;
///    a `make_link` or `edit_link` whose V-spec names a source the principal
///    may not read is never resolved and passes unattested to the write
///    door's own `withheld`, naming the source — the door judges every write
///    that reaches here, both homes being registered and the principal's —
///    so no slot is composed over an arrangement the principal may not read;
///    an `edit_link` whose successor M10's own build refuses — an ill-formed
///    spec, an unregistered source, a slot past a budget — passes unattested
///    to that refusal; a principal with no account answers
///    `attestation_invalid:not_enrolled_at_position`. A write passed through
///    unattested here drops the member it presented — never verified, never
///    written — and is one the store or the door refuses, each passing arm's
///    premise, so nothing commits unattested; the pairing of each arm with
///    the refusal it defers to is pinned in skepd's `signed_ops.rs`.
/// 7. (2): the member's marker tag names its row (a tag no row names is
///    `malformed`), whose token is the entry frame's `alg`; the blob's width
///    under it (a width not the row's is `malformed` too); the key set that
///    opens the act's principal as of this base (AUTH-4.30 (i)'s walk,
///    `key_subject`) — the fold's own set at this position, the check's table
///    being the daemon's own (the write path reads the fold's key table, on
///    the equality that above the claim every credential record the fold
///    honors passed the record grade's check at this daemon's own write
///    path); the candidates are that set's keys of the tag's row (A2's empty
///    walk answers `not_enrolled_at_position`, permanent), `signer`'s first
///    ([`candidates`]); any candidate verifying both halves over the entry
///    frame admits the presented `attest`, else `signature`.
pub(super) fn attestation_check(
    world: &World,
    op: &Op,
    principal: PrincipalId,
    signer: Option<&Fingerprint>,
    presented: Option<Attestation>,
) -> Result<Option<Attestation>, CredentialRefusal> {
    // 1 — the checked set, [`crate::codec::in_checked_set`]'s one
    // statement of it.
    if !crate::codec::in_checked_set(op.kind()) {
        return Ok(None);
    }
    // 2 — the record deposit's atom (signed-ops D26), narrowed: the bytes
    // decide, by the one parse `declared_record_atom` makes — a sig-less
    // record is refused at its insert, a signed one into a doc 1 is exempt,
    // and everything else takes the check below.
    if let Some(record) = declared_record_atom(op) {
        if !record.carries_sig {
            return Err(CredentialRefusal::RecordSigRequired);
        }
        if homed_in_doc_one(world, record.doc) {
            return Ok(None);
        }
    }
    // 3 — A3, by ω.
    if system_owned(world, op) {
        return Ok(None);
    }
    let invalid = CredentialRefusal::AttestationInvalid;
    // 4 — the board term, ahead of the member: with none, no client can sign.
    let Some(board) = board_term(world) else {
        return Err(invalid(AttestFault::BoardUnavailable));
    };
    // 5 — (1), ahead of the composition (the design record §4.5's order):
    // an unsigned write is told this whatever its body names, and pays no
    // walk of a shot's values to be told it.
    let Some(presented) = presented else {
        return Err(CredentialRefusal::AttestationRequired);
    };
    // 6 — the entry frame, every member but `alg`, for an attested write
    // alone; what each fault is answered is doc item 6's. `alg` is the
    // member's own, so it waits for step 7.
    let entry_frame = match entry::compose(world, op, principal, board) {
        Ok(entry_frame) => entry_frame,
        Err(ComposeFault::NoAccount) => return Err(invalid(AttestFault::NotEnrolledAtPosition)),
        Err(ComposeFault::UnreadableCopiedRunOrigin) => {
            return if refused_at_or_before_the_source_gate(world, op, principal) {
                Ok(None)
            } else {
                Err(invalid(AttestFault::Withheld))
            };
        }
        Err(ComposeFault::PastBodyBudget) => return Err(invalid(AttestFault::FrameTooLarge)),
        // A write the store or the door refuses whatever it carries: the walk
        // finds no value, a term names what no store holds, the staging
        // draft's runs pass the store's re-insert budget, a link slot passes
        // M7's budgets, a V-spec names a source the door withholds, or M10's
        // successor build refuses the request. The store's or the door's own
        // answer is owed, so the write passes through unattested to it.
        Err(
            ComposeFault::MissingValue
            | ComposeFault::Unspellable
            | ComposeFault::PastReinsertBudget
            | ComposeFault::SlotTooLarge
            | ComposeFault::UnreadableSlotSource
            | ComposeFault::SuccessorRefused,
        ) => return Ok(None),
    };
    // 7 — (2): the member's marker tag names its row, whose token is the
    // entry frame's `alg`.
    let row = SigAlgRow::of_tag(presented.sig_alg()).ok_or(invalid(AttestFault::Malformed))?;
    if presented.sig().len() != row.sig_len() {
        return Err(invalid(AttestFault::Malformed));
    }
    let bytes = entry_frame.to_bytes(row.token);
    let candidates = candidates(world, principal, signer, row);
    if candidates.is_empty() {
        return Err(invalid(AttestFault::NotEnrolledAtPosition));
    }
    if candidates
        .iter()
        .any(|key| skep_signature::verify(row.tag, key, &bytes, presented.sig()).is_ok())
    {
        Ok(Some(presented))
    } else {
        Err(invalid(AttestFault::Signature))
    }
}

/// Returns the keys an attestation under `row` is tried against, in order.
///
/// They are the enrolled keys of the row's token in the set that opens the
/// act's principal as of this base (AUTH-4.30 (i)'s walk, `key_subject`), in
/// the set's own order but for one: `signer`'s key — the one that
/// established the writing session — leads. A client attests an entry with
/// the key that opened its session, so an honest write's first verify is the
/// one that admits it, where the set's order would cost it one verify per
/// key ahead of its own, under the serialization guard. The order moves no
/// verdict: any candidate that verifies admits, and a blob none verifies is
/// tried against every one.
fn candidates<'w>(
    world: &'w World,
    principal: PrincipalId,
    signer: Option<&Fingerprint>,
    row: &SigAlgRow,
) -> Vec<&'w PublicKey> {
    let identity = world.identity();
    let mut keyed: Vec<(&Fingerprint, &PublicKey)> = key_subject(world, principal)
        .map(|subject| {
            identity
                .key_set(&subject)
                .enrolled()
                .map(|(fp, e)| (fp, &e.key))
                .filter(|(_, key)| key.alg() == row.token)
                .collect()
        })
        .unwrap_or_default();
    if let Some(at) = keyed.iter().position(|(fp, _)| Some(*fp) == signer) {
        keyed[..=at].rotate_right(1);
    }
    keyed.into_iter().map(|(_, key)| key).collect()
}

/// A declared deposit's atom that *is* a record of its declared kind.
///
/// It is what [`declared_record_atom`] answers: the document the `insert`
/// lands in, and whether the record carries its `sig` member.
struct DeclaredRecord<'a> {
    doc: &'a Address,
    carries_sig: bool,
}

/// Parses a declared deposit's atom — the one parse of it (signed-ops D26).
///
/// It is the record grade's parse, 2a, and for registry records 2b's.
/// `Some` iff `op` is an `insert` declared under a kind of the
/// record-deposit set — the credential set's, or the registry's two
/// ([`registry_deposit_kind`]: the exemption widened to the registry's
/// kinds) — its type read as a type slot through the one spelling of `enc`,
/// as every classification here reads one — whose one value parses as a
/// record of that kind, the entries and the `sig` as one value
/// ([`parse_record_value`] for a credential kind, `skep-registry`'s parse
/// under the canonical rule for a registry kind — the parse the record grade
/// makes again at the deposit's `make_link`), with whether the record's
/// `sig` member is present. `None` for every other insert: undeclared,
/// declared under no record kind, more or fewer than one value, or bytes
/// that are no record of the kind — prose, a record of another kind, a
/// record past [`skep_identity::MAX_RECORD_BYTES`] or a registry body past
/// its own cap (`too_large` at the parse's own head, as at the read, which
/// is also what bounds this parse of a value no read has capped, under the
/// serialization lock). A claim's kind answers `None`: a claim carries no
/// record (AUTH-2.48) and a declared claim atom is refused at M5's door, so
/// none commits.
///
/// **Presence, not verification.** The record grade's trial needs the
/// link's type and target and the grade the act needs, which the atom's
/// `insert` does not yet name — its `make_link`, one position later,
/// verifies the `sig` under the set that opens the home (`credential.rs`'s
/// `record_grade_check`, or `registry.rs`'s `registry_admission` for a
/// registry record) or is refused, leaving the atom an orphan no link
/// names, which a reader renders *undeterminable here* (the design record
/// §7.3 (i)), its row carrying `key` and no `attest`. Read by step 2 of
/// [`attestation_check`] alone; the row's `key` does not turn on this
/// parse: a record deposit's atom row always carries `key`, the daemon's
/// testimony of the writing session — the link row is the one its record's
/// `sig` signs.
fn declared_record_atom(op: &Op) -> Option<DeclaredRecord<'_>> {
    let Op::Insert { doc, deposit: Deposit::Declared(ty), values, .. } = op else {
        return None;
    };
    let slot = addr_spans(std::slice::from_ref(ty));
    let [atom] = values.as_slice() else {
        return None;
    };
    if let Some(kind) = record_deposit_kind(&slot) {
        let carries_sig = match kind {
            CredentialKind::Enroll => {
                parse_record_value::<Enrollment>(atom.as_bytes()).ok()?.sig.is_some()
            }
            CredentialKind::Retire => {
                parse_record_value::<Fingerprint>(atom.as_bytes()).ok()?.sig.is_some()
            }
            CredentialKind::Claim => return None,
        };
        return Some(DeclaredRecord { doc, carries_sig });
    }
    // The registry's two kinds (2b): the body under the canonical rule, by
    // the kind the declaration names.
    let kind = registry_deposit_kind(&slot)?;
    let record = skep_registry::parse(kind.body_kind(), atom.as_bytes()).ok()?;
    Some(DeclaredRecord { doc, carries_sig: record.sig.is_some() })
}

/// Answers A3's test: whether the system account owns every `doc` in the frame.
///
/// The system account is `1.1.0.1` (PUB-6.65). The frame's `doc` is an
/// arrangement write's target, a link write's home, both of an
/// `edit_link`'s homes, a mint's parent account, and its owner is read by ω
/// — a read of the board's principal list Π and never address arithmetic —
/// and by nothing served or testified. A `fork` or a `version` names the
/// acting principal's own account, which is the system account's only for
/// the system principal, which never passes dispatch.
fn system_owned(world: &World, op: &Op) -> bool {
    let m3 = world.m3();
    let system = system_account();
    let owned = |a: &Address| m3.effective_owner_prefix(a) == Some(&system);
    match op {
        Op::Insert { doc, .. } | Op::Publish { doc, .. } => owned(doc),
        Op::MakeLink { home, .. }
        | Op::Emit { home, .. }
        | Op::Nullify { home, .. }
        | Op::AssertSup { home, .. } => owned(home),
        Op::EditLink { d_s, d_a, .. } => owned(d_s) && owned(d_a),
        Op::CreateNewDocument { account, .. } => owned(account),
        _ => false,
    }
}

/// Returns whether the store refuses a shot at or before its source gate.
///
/// This is the check's question about a shot the composer could not read —
/// a copied run onto a draft the principal may not read
/// ([`ComposeFault::UnreadableCopiedRunOrigin`]): whether the store refuses
/// it at or before its source gate (M5 `publish`'s slots 1–6, PUB-6.36) —
/// asked of M5's own admission of the shot
/// ([`skep_arrangement::shot_admission`], the checks `publish` opens with),
/// over this snapshot, so the base's chain and shape, the carried-run test
/// (PUB-6.24) and the gate's own skips are M5's answers and never a second
/// statement of them here. Under the serialization guard this snapshot *is*
/// the base the real transaction opens on, and the predicate handed the
/// gate — [`World::visible_to`] at the principal — answers what M10 lends it
/// on the real write: M10's `visible_to` asks its front door's `readable`,
/// which is `World::readable` at the principal wherever that door carries no
/// read consult, and the daemon's live door carries none
/// (`Daemon::open_under` builds it so). That premise is this check's to rely
/// on and the open's to keep: a consult on the live door would make the two
/// gates two predicates, and one more lenient than `World::readable` would
/// pass through unattested a shot the real store then admits. So a refusal
/// here is the refusal the real shot meets.
///
/// `false` where the admission passes the shot — every run the principal may
/// not read then carried by the base — and for an op that is no shot, which
/// names no run origin at all. [`attestation_check`] refuses the write on
/// `false`, which is safe whether or not the store would have; it passes the
/// shot through unattested on `true` alone, which is safe because the real
/// shot is then refused with the same answer.
fn refused_at_or_before_the_source_gate(world: &World, op: &Op, principal: PrincipalId) -> bool {
    let Op::Publish { doc, shot } = op else {
        return false;
    };
    let caller = Caller::Principal(principal);
    shot_admission(world, caller, doc, shot, &World::visible_to(caller)).is_err()
}

#[cfg(test)]
mod tests;
