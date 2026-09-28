//! THE WRITE-PATH CHECK (signed ops): what the plain sequence's
//! publish-class gate runs on a claimed board ([`attestation_check`]), whose
//! ADMITTED attestation is what the write's commit marker carries.

use skep_arrangement::Deposit;
use skep_febe::Op;
use skep_identity::{IdentityState, PublicKey, SigAlgRow};
use skep_kernel::Attestation;
use skep_namespace::{system_account, HasM3, PrincipalId};

use super::{addr_spans, AttestFault, CredentialRefusal};
use crate::auth::entry::{self, ComposeFault};
use crate::auth::fold::identity_types;
use crate::auth::hybrid;
use crate::auth::session::key_subject;
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
///    required signing; D26): a DECLARED deposit under a CREDENTIAL kind —
///    the atom a credential record rides — carries its signature in the
///    record's own `sig` member (the record grade's lane), and (1) demands
///    no `attest` for it. The deposit's OTHER half, the `make_link` naming
///    the atom, never reaches this producer at all: `deposits_credential_link`
///    routes it to the credential sequence, whose `precheck` is the record
///    grade's door — which is how the check tells D26's case: BY ROUTE for
///    the link, BY DECLARED TYPE for the atom.
/// 3. A3 — a document whose OWNER is the SYSTEM ACCOUNT `1.1.0.1` is exempt,
///    read by ω — the longest registered prefix over the board's principal
///    list Π, a READ and never address arithmetic (m3, the design record's
///    round 5 rulings 2026-09-26) — and never by the `"system"` testimony.
///    The head writer never passes dispatch, so this arm is stated for a
///    dispatched write that names one and is met by none today.
/// 4. THE ENTRY FRAME, composed from the op and the snapshot
///    (`crate::auth::entry`) — every member but `alg`, which only the
///    presented member names — BEFORE the member is asked for, so a write
///    no entry frame can be composed for is told what it is whatever it
///    carries: a `publish` run naming an address with no value passes
///    UNATTESTED to the store's own `dangling_source`; a `publish` run onto
///    an origin the principal may not read is never composed — the shot
///    passes UNATTESTED to the store's own refusal where its gates refuse it
///    (`withheld`, or an answer ahead of the source gate), and is refused
///    `attestation_invalid:withheld` where they would admit it, the base
///    carrying the run; a body past `entry::MAX_SHOT_BODY_BYTES` answers
///    `attestation_invalid:frame_too_large` before it is built; a board with
///    no `H.1` answers `attestation_invalid:board_unavailable`, never "carry
///    an attest"; a principal with no account answers
///    `attestation_invalid:not_enrolled_at_position`.
/// 5. (1): no `attest` → `attestation_required`.
/// 6. (2): the member's marker tag names its row (a tag no row names is
///    `malformed`), whose token is the entry frame's `alg`; the blob's width
///    under it; the KEY SET that OPENS the act's principal AS OF this base
///    (AUTH-4.30 (i)'s walk, `key_subject`) — the fold's own set at this
///    position, the check's table being the daemon's own since no record
///    grade is built yet; the candidates are that set's keys of the tag's
///    row (A2's empty walk answers `not_enrolled_at_position`, PERMANENT);
///    any candidate verifying BOTH halves over the entry frame admits the
///    value, else `signature`.
///
/// The entry frame the daemon composes for a `publish` reads the runs'
/// values off the snapshot by `value_at` — a second Σ-width walk per
/// attested shot, off the snapshot and not under the applier lock (the
/// investigation §3.3's price), stopped at the body's budget. It reads a
/// value only where the principal may read it: this check's verdict is
/// answered to the principal, so a value read on its behalf is a value
/// disclosed to it, and every refusal it gives a shot with an unreadable run
/// is the same whatever that run's bytes are. A run naming an address with
/// no value cannot commit; the store's `dangling_source` is that write's
/// answer, so the check passes it through unattested rather than refusing a
/// signature over bytes nobody holds.
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
    // reads one.
    if let Op::Insert { deposit: Deposit::Declared(ty), .. } = op {
        if identity_types().kind_of(&addr_spans(std::slice::from_ref(ty))).is_some() {
            return Ok(None);
        }
    }
    // 3 — A3, by ω.
    if system_owned(world, op) {
        return Ok(None);
    }
    // 4 — THE ENTRY FRAME, every member but `alg`, composed before the
    // member is asked for: a write the daemon cannot compose an entry frame
    // for because the store refuses it (a `publish` run naming an address
    // with no value, or onto an origin the store withholds) is passed through
    // UNATTESTED for the store's own refusal, attest or none; one the store
    // would admit — the base CARRYING a run its author may not read — is
    // refused as its own cause with that value unread, and one whose body
    // passes the budget before the body is built; and a board with no `H.1` —
    // its first head refused by the head writer's driver, or its journal
    // damaged below it (`board_term` states both), since the claim writes
    // `H.1` in its own step (s1) — has no `board` term for ANY client to sign
    // over, which is told as its own cause rather than as "carry an attest".
    // `alg` is the member's own, so it waits for step 6.
    let invalid = CredentialRefusal::AttestationInvalid;
    let entry_frame = match entry::compose(world, op, principal) {
        Ok(entry_frame) => entry_frame,
        Err(ComposeFault::NoBoardTerm) => return Err(invalid(AttestFault::BoardUnavailable)),
        Err(ComposeFault::NoAccount) => return Err(invalid(AttestFault::NotEnrolledAtPosition)),
        Err(ComposeFault::CarriedUnreadable) => return Err(invalid(AttestFault::Withheld)),
        Err(ComposeFault::OverBudget) => return Err(invalid(AttestFault::FrameTooLarge)),
        Err(ComposeFault::MissingValue)
        | Err(ComposeFault::StoreRefuses)
        | Err(ComposeFault::OutsideCheckedSet) => return Ok(None),
    };
    // 5 — (1).
    let Some(presented) = presented else {
        return Err(CredentialRefusal::AttestationRequired);
    };
    // 6 — (2): the member's marker tag names its row, whose token is the
    // entry frame's `alg`.
    let row = SigAlgRow::of_tag(presented.sig_alg()).ok_or(invalid(AttestFault::Malformed))?;
    if presented.sig().len() != row.sig_len() {
        return Err(invalid(AttestFault::Malformed));
    }
    let bytes = entry_frame.bytes(row.token);
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
        .any(|key| hybrid::verify(row.tag, key, &bytes, presented.sig()).is_ok())
    {
        Ok(Some(presented))
    } else {
        Err(invalid(AttestFault::Signature))
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

#[cfg(test)]
mod tests {
    use skep_address::{Address, Nat};
    use skep_engine::types::t_grant;
    use skep_febe::Disposition;
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
    /// entry frame is composed before the member is asked for, so the absent
    /// term is told as its own cause, never as `attestation_required` — a
    /// declared deposit of NO credential kind included. And the token and its
    /// class are the wire's.
    #[test]
    fn a_board_with_no_h1_answers_board_unavailable_except_where_the_check_stands_aside() {
        use skep_arrangement::VPos;
        use skep_content::Val;
        use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource};

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
}
