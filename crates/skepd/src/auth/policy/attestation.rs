//! THE WRITE-PATH CHECK (signed ops): what the plain sequence's
//! publish-class gate runs on a claimed board ([`attestation_check`]), whose
//! ADMITTED attestation is what the write's commit marker carries — and the
//! question it asks M5's own admission of a shot to decide what a shot the
//! composer could not read is owed ([`refused_at_or_before_the_source_gate`]).

use skep_arrangement::{shot_admission, Caller, Deposit};
use skep_febe::Op;
use skep_identity::{
    parse_record_value, CredentialKind, Enrollment, Fingerprint, IdentityState, PublicKey,
    SigAlgRow,
};
use skep_kernel::Attestation;
use skep_namespace::{system_account, HasM3, PrincipalId};

use super::{addr_spans, record_deposit_kind, AttestFault, CredentialRefusal};
use crate::auth::entry::{self, ComposeFault};
use crate::auth::session::key_subject;
use crate::write_path::board_term;
use crate::World;

/// THE WRITE-PATH CHECK (signed ops; the design record §4.5 (1)–(2) made
/// concrete at the placement the owner confirmed 2026-09-25 — BEFORE the
/// transaction, beside the publish-class gate (wire.md §Credential refusals;
/// the design record's `publish_gate`) — here `board_state_admission`'s
/// claimed arm — on the snapshot pair the gates read, which under the
/// serialization guard IS the transaction's base). Reached for a
/// publish-class write from a SIGNED session on a CLAIMED board:
///
/// 1. THE CHECKED SET — [`crate::codec::in_checked_set`]: the three ops the seam
///    build's check reaches (`insert`, `make_link`, `publish`); every other
///    publish-class op carries no `attest` (the codec refuses the member
///    there) and commits on its signed session as before — the widening
///    lane's, not this one's.
/// 2. THE RECORD DEPOSIT EXEMPTION (§2.5's `insert` cell as re-cut at
///    required signing; D26): a DECLARED deposit under a kind of THE
///    RECORD-DEPOSIT SET ([`crate::auth::policy::record_deposit_kind`],
///    BW-03) — the atom a credential record rides — carries its signature in
///    the record's own `sig` member (the record grade, 2a), and (1) demands
///    no `attest` for it. The deposit's OTHER half, the `make_link` naming
///    the atom, never reaches this producer at all: `deposits_credential_link`
///    routes it to the credential sequence, whose `precheck` is the record
///    grade's door — its `record_grade_check` verifies the record's `sig`
///    there, above the claim — which is how the check tells D26's case: BY
///    ROUTE for the link, BY DECLARED TYPE for the atom.
/// 3. A3 — a document whose OWNER is the SYSTEM ACCOUNT `1.1.0.1` is exempt,
///    read by ω — the longest registered prefix over the board's principal
///    list Π, a READ and never address arithmetic (m3, the design record's
///    round 5 rulings 2026-09-26) — and never by the `"system"` testimony.
///    The head writer never passes dispatch, so this arm is stated for a
///    dispatched write that names one and is met by none today.
/// 4. THE BOARD TERM, `H.1`'s pair ([`crate::write_path::board_term`]), read
///    BEFORE the member is asked for: a board with no `H.1` — the states
///    `board_term` names — answers `attestation_invalid:board_unavailable`,
///    never "carry an attest", since no client can sign over a term the board
///    lacks.
/// 5. (1): no `attest` → `attestation_required`, AHEAD OF THE COMPOSITION
///    (the design record §4.5's head, ratified round 5 rulings 2026-09-26,
///    owner "keep", m1 — "an unsigned publish that also names a missing
///    source answers `attestation_required` BEFORE `dangling_source`";
///    SO-I7 (f), SO-I9 (a)): every unsigned write of the checked set above
///    the claim is told this one thing whatever its body names, and pays no
///    walk of a shot's values to be told it.
/// 6. THE ENTRY FRAME, composed for an ATTESTED write alone, from the op, the
///    snapshot and the board term (`crate::auth::entry`) — every member but
///    `alg`, which only the presented member names: a `publish` COPYING IN
///    an address with no value passes UNATTESTED to the store's own
///    `dangling_source`; a `publish` copying in a staging draft's run whose
///    document the principal may not read is never composed, and what the
///    shot is owed is decided here by asking M5's own admission of the shot
///    ([`refused_at_or_before_the_source_gate`]) — UNATTESTED to the store's
///    own refusal where it refuses (`withheld`, or an answer ahead of the
///    source gate), `attestation_invalid:withheld` where it would admit the
///    shot, the base carrying the run (a WINDOW is signed by address since
///    the address form, l6-A4, and never raises this: the store's gate alone
///    decides it, after the signature); a body past
///    `entry::MAX_SHOT_BODY_BYTES` answers
///    `attestation_invalid:frame_too_large` before it is built past the
///    budget; a term the frame cannot spell — a width, an extent or a count
///    past 2^64 − 1 — passes UNATTESTED to the store's refusal of the shot
///    (`base_extent_too_large`, `too_many_values`, `dangling_source`); a shot
///    whose staging-draft runs re-insert more values than M5's
///    `MAX_REINSERTED_VALUES` passes UNATTESTED to the store's
///    `too_many_values`, its values never walked; a principal with no
///    account answers `attestation_invalid:not_enrolled_at_position`. A write
///    passed through UNATTESTED here DROPS the member it presented — never
///    verified, never written — and is one the store refuses, each passing
///    arm's premise, so nothing commits unattested.
/// 7. (2): the member's marker tag names its row (a tag no row names is
///    `malformed`), whose token is the entry frame's `alg`; the blob's width
///    under it; the KEY SET that OPENS the act's principal AS OF this base
///    (AUTH-4.30 (i)'s walk, `key_subject`) — the fold's own set at this
///    position, the check's table being the daemon's own (BW-02, owner-ruled
///    2026-09-29: the write path reads the FOLD's key table, on the equality
///    that above the claim every credential record the fold honors passed
///    the record grade's check at this daemon's own write path); the
///    candidates are that set's keys of the tag's row (A2's empty walk
///    answers `not_enrolled_at_position`, PERMANENT); any candidate verifying
///    BOTH halves over the entry frame admits the presented `attest`, else
///    `signature`.
///
/// The entry frame the daemon composes for a `publish` reads the COPIED
/// runs' values off the snapshot by `value_at` — a second Σ-width walk per
/// attested shot, off the snapshot and not under M2's applier lock but under
/// the daemon's serialization lock (the investigation §3.3's price), stopped
/// at the body's budget — and over the staging draft's runs, before it
/// starts, at the store's own re-insert budget; a window is spelled by
/// address and read from nowhere (l6-A4). It reads a value only
/// where the principal may read it: this check's verdict is answered to the
/// principal, so a value read on its behalf is a value disclosed to it, and
/// every refusal it gives a shot with an unreadable copied run is the same
/// whatever that run's bytes are. A run naming an address with no value
/// cannot commit; the store's `dangling_source` is that write's answer, so
/// the check passes it through unattested rather than refusing a signature
/// over bytes nobody holds.
pub(super) fn attestation_check(
    world: &World,
    identity: &IdentityState,
    op: &Op,
    principal: PrincipalId,
    presented: Option<Attestation>,
) -> Result<Option<Attestation>, CredentialRefusal> {
    // 1 — the checked set, [`crate::codec::in_checked_set`]'s one statement of it.
    if !crate::codec::in_checked_set(op.kind()) {
        return Ok(None);
    }
    // 2 — the record deposit's atom (D26): its DECLARED type read as a type
    // slot through the one spelling of `enc`, as every classification here
    // reads one, against THE RECORD-DEPOSIT SET (BW-03).
    if let Op::Insert { deposit: Deposit::Declared(ty), .. } = op {
        if record_deposit_kind(&addr_spans(std::slice::from_ref(ty))).is_some() {
            return Ok(None);
        }
    }
    // 3 — A3, by ω.
    if system_owned(world, op) {
        return Ok(None);
    }
    let invalid = CredentialRefusal::AttestationInvalid;
    // 4 — THE BOARD TERM, ahead of the member: with none, no client can sign.
    let Some(board) = board_term(world) else {
        return Err(invalid(AttestFault::BoardUnavailable));
    };
    // 5 — (1), AHEAD OF THE COMPOSITION (the design record §4.5's ratified
    // order): an unsigned write is told this whatever its body names, and
    // pays no walk of a shot's values to be told it.
    let Some(presented) = presented else {
        return Err(CredentialRefusal::AttestationRequired);
    };
    // 6 — THE ENTRY FRAME, every member but `alg`, for an attested write
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
        // A shot the store refuses whatever it carries: the walk finds no
        // value, a term names what no store holds, or the staging draft's runs
        // pass the store's re-insert budget. The store's own answer is owed,
        // so the write passes through UNATTESTED to it.
        Err(
            ComposeFault::MissingValue
            | ComposeFault::Unspellable
            | ComposeFault::PastReinsertBudget,
        ) => return Ok(None),
    };
    // 7 — (2): the member's marker tag names its row, whose token is the
    // entry frame's `alg`.
    let row = SigAlgRow::of_tag(presented.sig_alg()).ok_or(invalid(AttestFault::Malformed))?;
    if presented.sig().len() != row.sig_len() {
        return Err(invalid(AttestFault::Malformed));
    }
    let bytes = entry_frame.to_bytes(row.token);
    let candidates: Vec<&PublicKey> = key_subject(world, identity, principal)
        .map(|subject| {
            identity
                .key_set(&subject)
                .enrolled()
                .map(|(_, e)| &e.key)
                .filter(|k| k.alg() == row.token)
                .collect()
        })
        .unwrap_or_default();
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

/// THE RECORD DEPOSIT'S ATOM CARRIES ITS OWN `sig` (signed ops, 2a; D26;
/// D12 as l6-E2 re-cut it — "a row whose entry carries a signature, in its
/// marker slot or in its record's `sig` member"): on a CLAIMED board, the
/// `insert` is a DECLARED deposit under a kind of the record-deposit set
/// (step 2's exemption above, the atom the check demands no `attest` for),
/// its one value parses as a record of that kind, and the record's `sig`
/// member is PRESENT. What the change feed's row records as the entry's
/// signedness for that `insert` (the write path's `Signed::RecordSig`), so
/// its `key` is absent as its `make_link`'s is: the record's `sig` covers
/// both positions (D26; e-Q2).
///
/// PRESENCE, not verification: the record grade's trial needs the link's
/// type and target and the grade the act needs, which the atom's `insert`
/// does not yet name — its `make_link`, one position later, verifies the
/// `sig` under the set that opens the home (`credential.rs`'s
/// `record_grade_check`) or is refused, leaving the atom an orphan no link
/// names, which a reader renders UNDETERMINABLE HERE (the design record
/// §7.3 (i)). The daemon serves and never judges; this is its statement of
/// WHERE the entry's signature is. At or below the claim nothing is signed
/// (A5) and this answers `false`: the ceremony's own record, `sig` or not,
/// keeps its row's `key`. A claim carries no record and answers `false`.
///
/// An atom past [`skep_identity::MAX_RECORD_BYTES`] parses as no record —
/// `too_large` at the parse's own head, as at the read — so this answers
/// `false` and its row serves its `key`: its `make_link` is refused
/// `malformed_payload:too_large` at the credential precheck's slot (3), the
/// fold's own read, and no `sig` it carries covers any position. That cap is
/// also what bounds this parse, of a value no read has capped, under the
/// serialization lock.
pub(crate) fn record_deposit_carries_sig(identity: &IdentityState, op: &Op) -> bool {
    if identity.claimant().is_none() {
        return false;
    }
    let Op::Insert { deposit: Deposit::Declared(ty), values, .. } = op else {
        return false;
    };
    let Some(kind) = record_deposit_kind(&addr_spans(std::slice::from_ref(ty))) else {
        return false;
    };
    let [atom] = values.as_slice() else {
        return false;
    };
    match kind {
        CredentialKind::Enroll => {
            parse_record_value::<Enrollment>(atom.as_bytes()).is_ok_and(|v| v.sig.is_some())
        }
        CredentialKind::Retire => {
            parse_record_value::<Fingerprint>(atom.as_bytes()).is_ok_and(|v| v.sig.is_some())
        }
        CredentialKind::Claim => false,
    }
}

/// A3's test: the write's target or home document is OWNED BY THE SYSTEM
/// ACCOUNT `1.1.0.1` (PUB-6.65) — ω, a READ of the board's principal list
/// Π and never address arithmetic (m3) — and by nothing served or
/// testified.
fn system_owned(world: &World, op: &Op) -> bool {
    let target = match op {
        Op::Insert { doc, .. } | Op::Publish { doc, .. } => doc,
        Op::MakeLink { home, .. } => home,
        _ => return false,
    };
    world.m3().effective_owner_prefix(target) == Some(&system_account())
}

/// THE CHECK'S QUESTION about a shot the composer could not read — a copied
/// run onto a draft the principal may not read
/// ([`ComposeFault::UnreadableCopiedRunOrigin`]): whether the STORE refuses it
/// at or before its source gate (M5 `publish`'s slots 1–6, PUB-6.36) — asked
/// of M5's own admission of the shot ([`skep_arrangement::shot_admission`],
/// the checks `publish` opens with), over this snapshot, so the base's chain
/// and shape, the carried-run test (PUB-6.24) and the gate's own skips are
/// M5's answers and never a second statement of them here. Under the
/// serialization guard this snapshot IS the base the real transaction opens
/// on, and the predicate handed the gate — [`World::visible_to`] at the
/// principal — answers what M10 lends it on the real write: M10's
/// `visible_to` asks its front door's `readable`, which is `World::readable`
/// at the principal wherever that door carries NO read consult, and the
/// daemon's live door carries none (`Daemon::open_under` builds it so). That
/// premise is this check's to rely on and the open's to keep: a consult on
/// the live door would make the two gates two predicates, and one MORE
/// lenient than `World::readable` would pass through UNATTESTED a shot the
/// real store then admits. So a refusal here is the refusal the real shot
/// meets.
///
/// `false` where the admission passes the shot — every run the principal may
/// not read then CARRIED by the base — and for an op that is no shot, which
/// names no run origin at all. [`attestation_check`] REFUSES the write on
/// `false`, which is safe whether or not the store would have; it passes the
/// shot through UNATTESTED on `true` alone, which is safe because the real
/// shot is then refused with the same answer.
fn refused_at_or_before_the_source_gate(world: &World, op: &Op, principal: PrincipalId) -> bool {
    let Op::Publish { doc, shot } = op else {
        return false;
    };
    let caller = Caller::Principal(principal);
    shot_admission(world, caller, doc, shot, &World::visible_to(caller)).is_err()
}

#[cfg(test)]
mod tests {
    use skep_address::{Address, Nat};
    use skep_arrangement::Shot;
    use skep_engine::types::t_grant;
    use skep_febe::Disposition;
    use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource};
    use skep_links::SlotArg;
    use skep_namespace::BOOTSTRAP_PRINCIPAL;

    use super::*;
    use crate::auth::fold::{addr_of, T_CLAIM, T_ENROLL, T_RETIRE};

    /// The check's arms no wire test can reach, on a board with no `H.1` —
    /// the genesis world. A3: a home the SYSTEM ACCOUNT owns by ω is exempt,
    /// nothing demanded even with no board term (the head writer never passes
    /// dispatch, so no wire write meets A3). D26 and the checked set stand
    /// aside ahead of the entry frame too. Every other checked write answers
    /// `attestation_invalid:board_unavailable` with NO attest presented — the
    /// board term is read before the member is asked for (the design record
    /// §4.5's order: `board_unavailable` and (1) ahead of the composition), so
    /// the absent term is told as its own cause, never as
    /// `attestation_required` — a declared deposit of NO credential kind
    /// included. And the token and its class are the wire's.
    #[test]
    fn a_board_with_no_h1_answers_board_unavailable_except_where_the_check_stands_aside() {
        use skep_arrangement::VPos;
        use skep_content::Val;

        let engine = skep_engine::Engine::open(KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
            salt: SaltSource::Seeded(0),
        })
        .expect("in-memory genesis cannot fail");
        let snap = engine.kernel().snapshot();
        let world = snap.world();
        let identity = IdentityState::genesis();
        let doc1 = addr_of(&[1, 0, 1, 0, 1]);
        let grant_in = |home: Address| Op::MakeLink {
            home,
            from: SlotArg::Addrs(Vec::new()),
            to: SlotArg::Addrs(Vec::new()),
            ty: SlotArg::Addrs(vec![t_grant().clone()]),
            replaces: None,
        };
        let insert = |deposit: Deposit| Op::Insert {
            doc: doc1.clone(),
            at: VPos::content(Nat::from(1u32)),
            values: vec![Val::new(vec![b'x'])],
            deposit,
        };
        let check = |op: Op| attestation_check(world, &identity, &op, BOOTSTRAP_PRINCIPAL, None);
        let unavailable: Result<Option<Attestation>, CredentialRefusal> =
            Err(CredentialRefusal::AttestationInvalid(AttestFault::BoardUnavailable));

        assert_eq!(check(grant_in(skep_namespace::head_document())), Ok(None), "A3: exempt by ω");
        for ty in [T_ENROLL, T_RETIRE, T_CLAIM] {
            assert_eq!(
                check(insert(Deposit::Declared(addr_of(&ty)))),
                Ok(None),
                "D26: a credential kind"
            );
        }
        let delete =
            Op::Delete { doc: doc1.clone(), p: VPos::content(Nat::from(1u32)), width: Nat::from(1u32) };
        assert_eq!(check(delete), Ok(None), "outside the checked set");
        assert_eq!(check(grant_in(doc1.clone())), unavailable, "a grant, no attest presented");
        assert_eq!(check(insert(Deposit::Undeclared)), unavailable, "an undeclared insert");
        assert_eq!(
            check(insert(Deposit::Declared(t_grant().clone()))),
            unavailable,
            "a declared deposit of no credential kind is no D26 case"
        );
        let r = CredentialRefusal::AttestationInvalid(AttestFault::BoardUnavailable);
        assert_eq!(
            (r.token(), r.disposition()),
            ("attestation_invalid:board_unavailable".to_string(), Disposition::Reorder)
        );
    }

    /// The check asks M5's own admission of the shot, over the snapshot it
    /// is handed. Over genesis, the system principal's shot into the head
    /// document `H` (published, memberless, its own): with no base the
    /// admission passes the shot through its gate, so `false` — and with a
    /// base outside `H`'s chain the store refuses `base_not_in_chain` ahead
    /// of the gate, so `true`. An op that is no shot names no run origin at
    /// all and is answered `false`, the side the check refuses on.
    #[test]
    fn the_check_answers_the_store_s_own_admission_of_the_shot() {
        use skep_arrangement::{Base, VPos};
        use skep_namespace::{ghost_home_document, head_document, SYSTEM_PRINCIPAL};

        let engine = skep_engine::Engine::open(KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
            salt: SaltSource::Seeded(0),
        })
        .expect("in-memory genesis cannot fail");
        let snap = engine.kernel().snapshot();
        let world = snap.world();
        let h = head_document();
        let into_h = |base: Option<Base>| Op::Publish {
            doc: h.clone(),
            shot: Shot { base, draft: None, runs: Vec::new() },
        };
        assert!(
            !refused_at_or_before_the_source_gate(world, &into_h(None), SYSTEM_PRINCIPAL),
            "a shot the store admits through its gate is not refused there"
        );
        let foreign = Base { member: ghost_home_document(), extent: Nat::from(0u32) };
        assert!(
            refused_at_or_before_the_source_gate(world, &into_h(Some(foreign)), SYSTEM_PRINCIPAL),
            "a base outside the document's chain is refused ahead of the gate"
        );
        let not_a_shot =
            Op::Delete { doc: h.clone(), p: VPos::content(Nat::from(1u32)), width: Nat::from(1u32) };
        assert!(
            !refused_at_or_before_the_source_gate(world, &not_a_shot, SYSTEM_PRINCIPAL),
            "an op that is no shot is answered on the side the check refuses on"
        );
        assert_eq!(
            engine.kernel().current_seq(),
            snap.seq(),
            "the admission commits nothing to the live kernel"
        );
    }
}
