//! The registry sequence's producers: the record grade for registry records.
//!
//! Its parts (signed ops, 2b; REG-1.86 (e); SO-I4, SO-I2) are the
//! registry's two record-deposit kinds ([`RegistryKind`],
//! [`registry_deposit_kind`]), the route of their links
//! ([`deposits_registry_link`], the credential route's sibling, the two sets
//! disjoint by construction), the sequence's ordered admission
//! ([`registry_admission`]) and its refusal vocabulary ([`RegistryRefusal`])
//! — and, beside them, the seeding check as the genesis hand runs it
//! ([`genesis_seeding_check`]), over the parent's whole domain as this
//! daemon alone can see it.
//!
//! A registry record is two positions (signed-ops D26): the atom's
//! `insert`, exempt from the entry check where it parses as a record of its
//! declared kind, carries its `sig` and lands in a doc 1
//! (`policy/attestation.rs`'s `declared_record_atom`, widened to these
//! kinds), and its `make_link`, routed here, where the record's own `sig` is
//! verified under the set that opens its home — the claimant's for a binding
//! in the registrar's doc 1, the node account's own for an endpoint in its
//! doc 1 — and the link commits with its marker slot empty by route
//! (REG-1.86 (e): "at both of the deposit's positions"). `replaces` rides
//! *inside* the signed body for these two kinds (REG-1.86 (g)) and no
//! `replaces` link is written by either: the link's own `replaces` member
//! is a form fault.

use skep_address::{Address, Span};
use skep_arrangement::deposit_class_types;
use skep_engine::types::{
    pins_outside_the_registry, t_binding, t_claim, t_endpoint, t_enroll, t_retire,
};
use skep_febe::{Disposition, Op};
use skep_identity::{record_bytes, single_address, Fingerprint, HasIdentity, Inert, PayloadError};
use skep_links::SlotArg;
use skep_namespace::HasM3;
use skep_registry::{BodyKind, SeedingRefusal};

use super::credential::{verify_record_sig, RecordTrial};
use super::{addr_spans, homed_in_doc_one, AttestFault, CredentialRefusal};
use crate::auth::LockRead;
use skep_engine::World;

/// The registry's record-deposit kinds: the binding and the endpoint.
///
/// They are the two kinds whose body the daemon parses and whose record
/// carries a `sig` (REG-1.14's first two, the deposit class's third and
/// fourth members). The five other body-bearing rows and the three
/// link-alone rows answer no kind here: a declared `insert` under one of
/// them into a published document is refused `published_target` at M5's
/// door, as a declaration under any type outside the deposit class is, and
/// a bare `make_link` typed one is an ordinary link write on the plain path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RegistryKind {
    Binding,
    Endpoint,
}

impl RegistryKind {
    /// Returns the body this kind's record carries, the parse's own kind.
    pub(super) fn body_kind(self) -> BodyKind {
        match self {
            RegistryKind::Binding => BodyKind::Binding,
            RegistryKind::Endpoint => BodyKind::Endpoint,
        }
    }
}

/// Returns the registry's record-deposit kind that `ty` names, if any.
///
/// `Some(kind)` where `ty` — a type slot in M7's deposited form — names one
/// of the two kinds by exact unit-subtree equality on the kind's bare
/// ordinal (REG-1.21: a kind is recognized at the type slot as a kind is,
/// and the precheck matches by unit-subtree equality, AUTH-2.22): one span,
/// `Equal` to the subtree of the row's own address, [`single_address`]'s
/// reading. A subtype or any other row answers `None`. Read by every arm
/// that tells a registry deposit apart: the entry check's exemption of the
/// record's atom, the pre-claim gate's refusal of a registry-kind deposit
/// into the system account, and the route of its link to the registry
/// sequence — stated once so the readers cannot part.
pub(super) fn registry_deposit_kind<'s>(
    ty: impl IntoIterator<Item = &'s Span>,
) -> Option<RegistryKind> {
    let named = single_address(ty)?;
    if named == *t_binding() {
        Some(RegistryKind::Binding)
    } else if named == *t_endpoint() {
        Some(RegistryKind::Endpoint)
    } else {
        None
    }
}

/// Returns the registry kind a slot names, read in M7's own deposited form.
///
/// The address form is read through [`addr_spans`]; `Resolve` and `Spans`
/// answer `None`, since neither can name a commons row — a resolved slot
/// names content, and an I-span slot is held by M7's content clause to
/// content-subspace starts, under which no subspace-3 row has a span.
fn slotarg_kind(s: &SlotArg) -> Option<RegistryKind> {
    match s {
        SlotArg::Addrs(addrs) => registry_deposit_kind(&addr_spans(addrs)),
        SlotArg::Resolve(_) | SlotArg::Spans(_) => None,
    }
}

/// Returns whether `op` deposits a registry-typed link: the registry route.
///
/// It is [`super::deposits_credential_link`]'s sibling: the op's own type
/// slot, no world read, so the sequence is chosen before any lock is taken.
/// True for the three deposit-shaped ops whose type slot names a registry
/// kind; the sequence then refuses every shape but an address-form
/// `make_link` ([`RegistryRefusal::Form`]), as the credential sequence's
/// shape slots refuse theirs. Disjoint from the credential route by
/// construction: the two sets name different rows, and the credential route
/// is asked first. Exhaustive with no `_` arm, for the reason the credential
/// route's card gives: a new `Op` decides here whether it can carry a type
/// slot.
pub fn deposits_registry_link(op: &Op) -> bool {
    match op {
        Op::MakeLink { ty, .. } => slotarg_kind(ty).is_some(),
        Op::Emit { ty, .. } => registry_deposit_kind(ty).is_some(),
        Op::EditLink { successor, .. } => slotarg_kind(&successor.ty).is_some(),
        Op::CreateNewDocument { .. }
        | Op::Delegate { .. }
        | Op::RegisterNode { .. }
        | Op::Fork { .. }
        | Op::NextAccountPrefix { .. }
        | Op::PrincipalPrefix { .. }
        | Op::EffectiveOwner { .. }
        | Op::UniversalGrants
        | Op::Insert { .. }
        | Op::Delete { .. }
        | Op::Copy { .. }
        | Op::Reinstate { .. }
        | Op::Rearrange { .. }
        | Op::Version { .. }
        | Op::Publish { .. }
        | Op::Nullify { .. }
        | Op::AssertSup { .. }
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
        | Op::EditionClaims { .. } => false,
    }
}

/// The registry sequence's refusal vocabulary.
///
/// Every one marshals as `code: registry_refused, detail: token(),
/// disposition: disposition()` (`codec/marshal.rs`'s
/// `registry_refused_reply`, through `registry_refused` in skepd's
/// `server/reply.rs`) — the credential family's shape under a code of its
/// own, so a client tells the two families apart; no token of the
/// credential family is renamed, the tokens this sequence shares with it
/// are spelled through it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryRefusal {
    /// At or below the claim: token `claim_first`, the pre-claim gate's own.
    ///
    /// The only registry rows below the claim are the seeded pins (REG-1.32),
    /// and no registry record is deposited there.
    ClaimFirst,
    /// A bare session above the claim: token `signed_session_required`.
    ///
    /// A published write takes a signed session (RES-26), as the credential
    /// sequence's slot (7) demands of a credential deposit.
    SignedSessionRequired,
    /// The home pin: the link's home is no doc 1.
    ///
    /// A doc 1 is the one home a registry deposit can name (REG-2.18,
    /// REG-1.9), the credential path's own test (`homed_in_doc_one`). Token
    /// `not_doc_one`, the fold's own.
    NotDocOne,
    /// The form (REG-2.18 to REG-2.21, REG-2.23, REG-2.26).
    ///
    /// The deposit is no address-form `make_link`, or carries a `replaces`
    /// member (the member rides the signed body, REG-1.86 (g)), or its `from`
    /// names other than one atom in the home's own space, or its `to` names
    /// more than one address — or, for a binding, one that is no registered
    /// account on this board (REG-2.20; a targetless binding is the one
    /// spelling of "no account", REG-2.21), or, for an endpoint, any address
    /// at all (its carriage: a link from the atom, no target). Token
    /// `registry_form`, permanent.
    Form,
    /// The record value: the atom's bytes are no record of the slot's kind.
    ///
    /// The bytes are read under the canonical rule, the parser's cause
    /// joined. Token `malformed_record:<cause>`, permanent.
    MalformedRecord(skep_registry::ParseRefusal),
    /// No `sig` at all (§4.5 (4)).
    ///
    /// It is the credential's fence, which the insert's own gate narrows: a
    /// sig-less atom that parses as a record of its declared kind is refused
    /// at its `insert` above the claim, so an atom this reaches was inserted
    /// below the claim, declared under another kind, or placed past the
    /// check. Token `attestation_required`, `Reorder`.
    AttestationRequired,
    /// The trial's causes over the record's `sig`, each with its class.
    ///
    /// They are the credential record grade's own ([`AttestFault`]).
    AttestationInvalid(AttestFault),
}

impl RegistryRefusal {
    /// Returns the wire `detail` token.
    pub fn token(&self) -> String {
        match self {
            RegistryRefusal::ClaimFirst => CredentialRefusal::ClaimFirst.token(),
            RegistryRefusal::SignedSessionRequired => {
                CredentialRefusal::SignedSessionRequired.token()
            }
            RegistryRefusal::NotDocOne => Inert::NotDocOne.detail(),
            RegistryRefusal::Form => "registry_form".into(),
            RegistryRefusal::MalformedRecord(cause) => {
                format!("malformed_record:{}", cause.token())
            }
            RegistryRefusal::AttestationRequired => CredentialRefusal::AttestationRequired.token(),
            RegistryRefusal::AttestationInvalid(fault) => {
                CredentialRefusal::AttestationInvalid(*fault).token()
            }
        }
    }

    /// Returns the wire `disposition`.
    ///
    /// The attestation codes take their own classes, `Permanent` the rest.
    pub fn disposition(&self) -> Disposition {
        match self {
            RegistryRefusal::AttestationRequired => Disposition::Reorder,
            RegistryRefusal::AttestationInvalid(fault) => fault.disposition(),
            RegistryRefusal::ClaimFirst
            | RegistryRefusal::SignedSessionRequired
            | RegistryRefusal::NotDocOne
            | RegistryRefusal::Form
            | RegistryRefusal::MalformedRecord(_) => Disposition::Permanent,
        }
    }
}

/// The registry deposit the sequence reads off an address-form `make_link`.
///
/// It is borrowed from the op: the kind the type slot names, the home, the
/// `from` slot's spans (the record read's input, the one member built), the
/// one target or none, and the type address the frame names.
struct RegistryDeposit<'a> {
    kind: RegistryKind,
    home: &'a Address,
    from: Vec<Span>,
    to: Option<&'a Address>,
    ty: &'a Address,
}

/// Returns a routed op's home, for the home pin ahead of the form.
///
/// It is a `make_link`'s or an `emit`'s home, an `edit_link`'s successor
/// home.
fn home_of(op: &Op) -> Option<&Address> {
    match op {
        Op::MakeLink { home, .. } | Op::Emit { home, .. } => Some(home),
        Op::EditLink { d_s, .. } => Some(d_s),
        _ => None,
    }
}

/// Returns the deposit where `op` has the form's shape half, else `None`.
///
/// The shape is an address-form `make_link` with no `replaces` member,
/// `from` one address, `to` empty or one address, typed a registry kind.
fn deposit_of(op: &Op) -> Option<RegistryDeposit<'_>> {
    let Op::MakeLink { home, from, to, ty, replaces: None } = op else { return None };
    let (SlotArg::Addrs(from), SlotArg::Addrs(to), SlotArg::Addrs(ty)) = (from, to, ty) else {
        return None;
    };
    let kind = registry_deposit_kind(&addr_spans(ty))?;
    let [ty] = ty.as_slice() else { return None };
    let [_atom] = from.as_slice() else { return None };
    let to = match to.as_slice() {
        [] => None,
        [one] => Some(one),
        _ => return None,
    };
    Some(RegistryDeposit { kind, home, from: addr_spans(from), to, ty })
}

/// Runs the registry admission: the sequence's ordered producers.
///
/// They run under the serialization lock and the credential lock's read arm
/// (the key set is read and never stepped: no credential commits here), on
/// the snapshot taken under them.
///
/// **Precondition.** `world` must be the snapshot taken under the guards for
/// this request — its key table is that snapshot's own slice; the guard
/// argument is that contract's cheap half.
///
/// # Errors
///
/// In order:
///
/// 0. Above the claim only: on an unclaimed board `claim_first` (REG-1.32),
///    and from a bare session `signed_session_required` (RES-26).
/// 1. The home pin — the link's home is a doc 1 (`homed_in_doc_one`), else
///    `not_doc_one`.
/// 2. The form — an address-form `make_link` with no `replaces` member, its
///    `from` one atom (REG-2.23), its `to` empty or one address; a binding's
///    target a registered account on this board, M3's seat read answering
///    exactly it (REG-2.20) or none (REG-2.21); an endpoint's target none
///    (REG-2.26's carriage) — else `registry_form`.
/// 3. The record value — the atom's bytes off the link's `from`, the record
///    grade's one read ([`record_bytes`]), parsed by the kind the slot names
///    under the canonical rule; a refusal `malformed_record:<cause>` — a
///    `type` that is not the slot's kind among them. A `from` the read
///    cannot walk — a position outside the home, an unoccupied one — is
///    the form's fault; bytes past the read's own cap are the parser's.
/// 4. No `sig` → `attestation_required`.
/// 5. The trial — the blob, the frame, the candidates and the trial, the
///    credential record grade's own steps (`verify_record_sig`), each fault
///    answered `attestation_invalid:<cause>`: the `record` frame over the
///    home's account (ω over the home), the home, the type address and the
///    target as stored, the `replaces` and lineage rows empty, the sig-less
///    canonical projection the parser's; the candidates the set that opens
///    the home's account, anchor grade false (no rule names an anchor grade
///    for a registry record). The system account's doc 1 refuses here —
///    `1.1.0.1` holds no key set, so
///    `attestation_invalid:not_enrolled_at_position` (SO-I2 (g)(iv)); a home
///    with no owner, a premise broken, answers the same, fail-closed.
///
/// # Panics
///
/// Panics in a debug build where the home the pin found as a doc 1 has no
/// owner, a premise broken (step 5).
pub fn registry_admission(
    _lock: &LockRead<'_>,
    world: &World,
    op: &Op,
    signer: Option<&Fingerprint>,
) -> Result<(), RegistryRefusal> {
    // 0 — above the claim, from a signed session.
    if world.identity().claimant().is_none() {
        return Err(RegistryRefusal::ClaimFirst);
    }
    if signer.is_none() {
        return Err(RegistryRefusal::SignedSessionRequired);
    }
    // 1 — the home pin.
    let home = home_of(op).ok_or(RegistryRefusal::Form)?;
    if !homed_in_doc_one(world, home) {
        return Err(RegistryRefusal::NotDocOne);
    }
    // 2 — the form: the shape, then the target by kind.
    let dep = deposit_of(op).ok_or(RegistryRefusal::Form)?;
    match (dep.kind, dep.to) {
        (RegistryKind::Binding, None) => {}
        (RegistryKind::Binding, Some(account)) => {
            let seated =
                world.m3().account_seat(account).is_some_and(|(prefix, _)| prefix == account);
            if !seated {
                return Err(RegistryRefusal::Form);
            }
        }
        (RegistryKind::Endpoint, None) => {}
        (RegistryKind::Endpoint, Some(_)) => return Err(RegistryRefusal::Form),
    }
    // 3 — the record value, by the kind the slot names, read over the world
    // as the fold's ctx (the engine's `FoldCtx for World`).
    let bytes = match record_bytes(world, dep.home, &dep.from) {
        Ok(bytes) => bytes,
        Err(PayloadError::TooLarge) => {
            return Err(RegistryRefusal::MalformedRecord(skep_registry::ParseRefusal::PastCap))
        }
        Err(_) => return Err(RegistryRefusal::Form),
    };
    let record = skep_registry::parse(dep.kind.body_kind(), &bytes)
        .map_err(RegistryRefusal::MalformedRecord)?;
    // 4 — no `sig` at all.
    let Some(sig) = record.sig.as_deref() else {
        return Err(RegistryRefusal::AttestationRequired);
    };
    // 5 — the trial under the set that opens the home's account. The home
    // has an owner — the home pin found its doc 1 by ω — so an absence is a
    // premise broken, answered fail-closed and asserted.
    let Some(home_account) = world.m3().effective_owner_prefix(dep.home) else {
        debug_assert!(false, "the home pin found a doc 1 under an owner");
        return Err(RegistryRefusal::AttestationInvalid(AttestFault::NotEnrolledAtPosition));
    };
    let canonical = record.canonical_sigless();
    verify_record_sig(
        world,
        RecordTrial {
            home: dep.home,
            home_account,
            ty: dep.ty,
            to: dep.to.map(std::slice::from_ref).unwrap_or(&[]),
            canonical: canonical.as_bytes(),
            sig,
            anchor_grade: false,
        },
    )
    .map_err(RegistryRefusal::AttestationInvalid)
}

// ── the seeding check, the genesis hand's (REG-1.28 to REG-1.32) ─────────

/// Returns the parent's domain as the daemon sees it (REG-1.31).
///
/// It is every commons row the build holds that the registry does not
/// itself allocate — the engine ledger's class pins outside the registry,
/// the three credential pins (`3.1`–`3.3`, the engine's own as the World
/// seats the identity fold, standing beside that ledger's list rather than
/// in it), and M5's deposit-class members that are no registry row, which
/// spell the first two a second time. The binding and the endpoint are M5's
/// third and fourth members and the registry's own rows spelled a second
/// time — held equal by the suite that sees both spellings, and no foreign
/// row here.
fn seeding_domain() -> Vec<Address> {
    pins_outside_the_registry()
        .into_iter()
        .chain([t_enroll(), t_retire(), t_claim()])
        .cloned()
        .chain(
            deposit_class_types().iter().filter(|ty| skep_registry::row_at(ty).is_none()).cloned(),
        )
        .collect()
}

/// Runs the seeding check at the board's genesis (REG-1.28, REG-1.32).
///
/// This daemon is its hand. Its three arms run over the registry's rows and
/// `seeding_domain`, run by the open ahead of the engine on every open — a
/// fresh data dir's genesis and a reopen's re-genesis alike. The rows and the
/// domain are compiled constants, so no hook mutates them: the arms are
/// proved on lists the suites build, the shipped lists pass here.
///
/// # Errors
///
/// The [`SeedingRefusal`] of an arm that refuses, so a refusal is a genesis
/// that does not complete: no claim, no session and no board record,
/// nothing written.
pub fn genesis_seeding_check() -> Result<(), SeedingRefusal> {
    skep_registry::seeding_check(skep_registry::rows(), &seeding_domain())
}

#[cfg(test)]
mod tests {
    use skep_febe::Disposition::{Permanent, Reorder};

    use super::*;
    use crate::auth::policy::addr_of;
    use crate::auth::policy::{deposits_credential_link, record_deposit_kind};

    /// Checks that the registry set and the credential set are disjoint.
    ///
    /// They are disjoint by construction: over every registry row, the three
    /// credential pins and the ordinal `…3.4`, no type slot answers both
    /// `record_deposit_kind` and `registry_deposit_kind`; the registry set
    /// holds the binding and the endpoint alone; and a `make_link` so typed
    /// is routed to exactly one sequence.
    #[test]
    fn the_registry_set_and_the_credential_set_are_disjoint() {
        let doc = addr_of(&[1, 0, 1, 0, 1]);
        let mut types: Vec<Address> =
            skep_registry::rows().iter().map(|r| r.address.clone()).collect();
        types.extend([
            t_enroll().clone(),
            t_retire().clone(),
            t_claim().clone(),
            addr_of(&[1, 1, 0, 1, 0, 1, 0, 3, 4]),
        ]);
        for ty in types {
            let slot = addr_spans(std::slice::from_ref(&ty));
            let (credential, registry) = (record_deposit_kind(&slot), registry_deposit_kind(&slot));
            assert!(!(credential.is_some() && registry.is_some()), "{}", ty.tumbler());
            let expected = if ty == *t_binding() {
                Some(RegistryKind::Binding)
            } else if ty == *t_endpoint() {
                Some(RegistryKind::Endpoint)
            } else {
                None
            };
            assert_eq!(registry, expected, "{}", ty.tumbler());
            let link = Op::MakeLink {
                home: doc.clone(),
                from: SlotArg::Addrs(Vec::new()),
                to: SlotArg::Addrs(Vec::new()),
                ty: SlotArg::Addrs(vec![ty.clone()]),
                replaces: None,
            };
            assert_eq!(deposits_registry_link(&link), registry.is_some(), "{}", ty.tumbler());
            assert!(!(deposits_registry_link(&link) && deposits_credential_link(&link)));
        }
    }

    /// Checks that the shipped domain passes the seeding check.
    ///
    /// It holds the eight class pins outside the registry, the three
    /// credential pins and M5's two credential members, no registry row — and
    /// the check over it passes, so a daemon opens.
    #[test]
    fn the_shipped_domain_passes_the_seeding_check() {
        let domain = seeding_domain();
        assert_eq!(domain.len(), 8 + 3 + 2);
        assert!(domain.iter().all(|a| skep_registry::row_at(a).is_none()));
        for c in [t_enroll(), t_retire(), t_claim()] {
            assert!(domain.contains(c));
        }
        assert_eq!(genesis_seeding_check(), Ok(()));
    }

    /// Checks every refusal's token and class.
    ///
    /// The tokens shared with the credential family are spelled through it.
    #[test]
    fn every_refusal_answers_its_token_and_class() {
        let cases = [
            (RegistryRefusal::ClaimFirst, "claim_first", Permanent),
            (RegistryRefusal::SignedSessionRequired, "signed_session_required", Permanent),
            (RegistryRefusal::NotDocOne, "not_doc_one", Permanent),
            (RegistryRefusal::Form, "registry_form", Permanent),
            (
                RegistryRefusal::MalformedRecord(skep_registry::ParseRefusal::WrongType),
                "malformed_record:wrong_type",
                Permanent,
            ),
            (RegistryRefusal::AttestationRequired, "attestation_required", Reorder),
            (
                RegistryRefusal::AttestationInvalid(AttestFault::Signature),
                "attestation_invalid:signature",
                Permanent,
            ),
            (
                RegistryRefusal::AttestationInvalid(AttestFault::BoardUnavailable),
                "attestation_invalid:board_unavailable",
                Reorder,
            ),
        ];
        for (refusal, token, class) in cases {
            assert_eq!(
                (refusal.token(), refusal.disposition()),
                (token.to_string(), class),
                "{refusal:?}"
            );
        }
    }
}
