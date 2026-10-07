//! The REGISTRY sequence's producers — THE RECORD GRADE FOR REGISTRY RECORDS
//! (signed ops, 2b; REG-1.86 (e); SO-I4, SO-I2): the registry's two
//! record-deposit kinds ([`RegistryKind`], [`registry_deposit_kind`]), the
//! ROUTE of their links ([`deposits_registry_link`], the credential route's
//! sibling, the two sets disjoint by construction), the sequence's ordered
//! admission ([`registry_admission`]) and its refusal vocabulary
//! ([`RegistryRefusal`]) — and, beside them, THE SEEDING CHECK as the
//! genesis hand runs it ([`genesis_seeding_check`]), over the parent's whole
//! domain as this daemon alone can see it.
//!
//! A registry record is TWO POSITIONS (D26): the atom's `insert`, exempt
//! from the entry check where it parses as a record of its declared kind,
//! carries its `sig` and lands in a doc 1 (`policy/attestation.rs`'s
//! `declared_record_atom`, widened to these kinds), and its `make_link`,
//! routed here, where the record's own `sig` is verified under the set that
//! opens its home — the claimant's for a binding in the registrar's doc 1,
//! the node account's own for an endpoint in its doc 1 — and the link
//! commits with its marker slot EMPTY by route (REG-1.86 (e): "at both of
//! the deposit's positions"). `replaces` rides INSIDE the signed body for
//! these two kinds (REG-1.86 (g)) and no `replaces` LINK is written by
//! either: the link's own `replaces` member is a form fault.

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
use crate::World;

/// THE REGISTRY'S RECORD-DEPOSIT KINDS: the two kinds whose body the daemon
/// parses and whose record carries a `sig` — the BINDING and the ENDPOINT
/// (REG-1.14's first two, the deposit class's third and fourth members).
/// The five other body-bearing rows and the three link-alone rows answer
/// no kind here and so stand as they did: a declared `insert` under one of
/// them is refused `published_target` at M5's door, as a declaration under
/// any type outside the deposit class is, and a bare `make_link` typed one
/// is an ordinary link write on the plain path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RegistryKind {
    Binding,
    Endpoint,
}

impl RegistryKind {
    /// The body this kind's record carries, the parse's own kind.
    pub(super) fn body_kind(self) -> BodyKind {
        match self {
            RegistryKind::Binding => BodyKind::Binding,
            RegistryKind::Endpoint => BodyKind::Endpoint,
        }
    }
}

/// THE REGISTRY'S RECORD-DEPOSIT SET: `Some(kind)` where `ty` — a type slot
/// in M7's deposited form — names one of the two kinds by EXACT UNIT-SUBTREE
/// EQUALITY on the kind's bare ordinal (REG-1.21: a kind is recognized at
/// the type slot as a kind is, and the precheck matches by unit-subtree
/// equality, AUTH-2.22): one span, `Equal` to the subtree of the row's own
/// address, [`single_address`]'s reading. A subtype or any other row answers
/// `None`. Read by every arm that tells a registry deposit apart: the entry
/// check's exemption of the record's atom, the pre-claim gate's refusal of
/// a registry-kind deposit into the system account, and the route of its
/// link to the registry sequence — stated once so the readers cannot part.
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

/// A slot's kind in M7's own deposited form: the address form through
/// [`addr_spans`]; `None` for `Resolve`, which can never name a commons row.
fn slotarg_kind(s: &SlotArg) -> Option<RegistryKind> {
    match s {
        SlotArg::Addrs(addrs) => registry_deposit_kind(&addr_spans(addrs)),
        SlotArg::Resolve(_) => None,
    }
}

/// THE ROUTE — [`super::deposits_credential_link`]'s sibling: the op's OWN
/// type slot, no world read, so the sequence is chosen before any lock is
/// taken. True for the three deposit-shaped ops whose type slot names a
/// registry kind; the sequence then refuses every shape but an address-form
/// `make_link` ([`RegistryRefusal::Form`]), as the credential sequence's
/// shape slots refuse theirs. DISJOINT from the credential route by
/// construction: the two sets name different rows, and the credential route
/// is asked first. Exhaustive with no `_` arm, for the reason the credential
/// route's card gives: a new `Op` decides here whether it can carry a type
/// slot.
pub(crate) fn deposits_registry_link(op: &Op) -> bool {
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

/// The registry sequence's refusal vocabulary. Every one marshals as
/// `code: registry_refused, detail: token(), disposition: disposition()`
/// (`codec/marshal.rs`'s `registry_refused_reply`, through `server/reply.rs`'s
/// `registry_refused`) — the credential family's shape under a code of its
/// own, so a client tells the two families apart; no token of the credential
/// family is renamed, the tokens this sequence shares with it are spelled
/// through it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RegistryRefusal {
    /// At or below the claim: the only registry rows below the claim are the
    /// seeded pins (REG-1.32), and no registry record is deposited there.
    /// Token `claim_first`, the pre-claim gate's own.
    ClaimFirst,
    /// A BARE session above the claim: a published write takes a signed
    /// session (RES-26), as the credential sequence's slot (7) demands of a
    /// credential deposit. Token `signed_session_required`.
    SignedSessionRequired,
    /// THE HOME PIN: the link's home is no doc 1 — the one home a registry
    /// deposit can name (REG-2.18, REG-1.9), the credential path's own test
    /// (`homed_in_doc_one`). Token `not_doc_one`, the fold's own.
    NotDocOne,
    /// THE FORM (REG-2.18 to REG-2.21, REG-2.23, REG-2.26): the deposit is
    /// no address-form `make_link`, or carries a `replaces` member (the
    /// member rides the signed body, REG-1.86 (g)), or its `from` names
    /// other than ONE atom in the home's own space, or its `to` names more
    /// than one address — or, for a BINDING, one that is no registered
    /// account on this board (REG-2.20; a targetless binding is the one
    /// spelling of "no account", REG-2.21), or, for an ENDPOINT, any address
    /// at all (its carriage: a link from the atom, no target). Token
    /// `registry_form`, PERMANENT.
    Form,
    /// THE RECORD VALUE: the atom's bytes are no record of the kind the slot
    /// names, under the canonical rule — the parser's cause joined. Token
    /// `malformed_record:<cause>`, PERMANENT.
    MalformedRecord(skep_registry::ParseRefusal),
    /// NO `sig` at all (§4.5 (4)) — the fence with no population, as the
    /// credential's: a sig-less record-kind atom is refused at its `insert`.
    /// Token `attestation_required`, REORDER.
    AttestationRequired,
    /// The trial's causes over the record's `sig`, each with its class —
    /// the credential record grade's own ([`AttestFault`]).
    AttestationInvalid(AttestFault),
}

impl RegistryRefusal {
    /// The wire `detail` token.
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

    /// The wire `disposition`: the attestation codes' own classes, PERMANENT
    /// for the rest.
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

/// THE REGISTRY DEPOSIT as the sequence reads it off an address-form
/// `make_link`: the kind the type slot names, the home, the `from` slot's
/// spans (the record read's input), the one target or none, and the type
/// address the frame names.
struct RegistryDeposit {
    kind: RegistryKind,
    home: Address,
    from: Vec<Span>,
    to: Option<Address>,
    ty: Address,
}

/// The home an op the route sends here names, for the home pin ahead of
/// the form: a `make_link`'s or an `emit`'s home, an `edit_link`'s
/// successor home.
fn home_of(op: &Op) -> Option<&Address> {
    match op {
        Op::MakeLink { home, .. } | Op::Emit { home, .. } => Some(home),
        Op::EditLink { d_s, .. } => Some(d_s),
        _ => None,
    }
}

/// THE FORM'S SHAPE HALF: an address-form `make_link` with no `replaces`
/// member, `from` ONE address, `to` empty or ONE address, typed a registry
/// kind — else `None`.
fn deposit_of(op: &Op) -> Option<RegistryDeposit> {
    let Op::MakeLink { home, from, to, ty, replaces: None } = op else { return None };
    let (SlotArg::Addrs(from), SlotArg::Addrs(to), SlotArg::Addrs(ty)) = (from, to, ty) else {
        return None;
    };
    let kind = registry_deposit_kind(&addr_spans(ty))?;
    let [ty] = ty.as_slice() else { return None };
    let [_atom] = from.as_slice() else { return None };
    let to = match to.as_slice() {
        [] => None,
        [one] => Some(one.clone()),
        _ => return None,
    };
    Some(RegistryDeposit { kind, home: home.clone(), from: addr_spans(from), to, ty: ty.clone() })
}

/// THE REGISTRY ADMISSION — the sequence's ordered producers, under the
/// serialization lock and the credential lock's READ arm (the key set is
/// read and never stepped: no credential commits here), on the snapshot
/// taken under them:
///
/// 0. ABOVE THE CLAIM ONLY: on an unclaimed board `claim_first` (REG-1.32),
///    and from a BARE session `signed_session_required` (RES-26).
/// 1. THE HOME PIN — the link's home is a doc 1 (`homed_in_doc_one`), else
///    `not_doc_one`.
/// 2. THE FORM — an address-form `make_link` with no `replaces` member, its
///    `from` ONE atom (REG-2.23), its `to` EMPTY or ONE address; a binding's
///    target a REGISTERED ACCOUNT ON THIS BOARD, M3's seat read answering
///    exactly it (REG-2.20) or none (REG-2.21); an endpoint's target none
///    (REG-2.26's carriage) — else `registry_form`.
/// 3. THE RECORD VALUE — the atom's bytes off the link's `from`, the record
///    grade's one read ([`record_bytes`]), parsed by the KIND THE SLOT NAMES
///    under the canonical rule; a refusal `malformed_record:<cause>` — a
///    `type` that is not the slot's kind among them. A `from` the read
///    cannot walk — a position outside the home, an unoccupied one — is
///    the form's fault; bytes past the read's own cap are the parser's.
/// 4. NO `sig` → `attestation_required`.
/// 5. THE TRIAL — the blob, the frame, the candidates and the trial, the
///    credential record grade's own steps ([`verify_record_sig`]): the
///    `record` frame over the home's account (ω over the home), the home,
///    the type address and the target as stored, the `replaces` and lineage
///    rows EMPTY, the sig-less canonical projection the parser's; the
///    candidates THE SET THAT OPENS THE HOME'S ACCOUNT, anchor grade FALSE
///    (no rule names an anchor grade for a registry record). The system
///    account's doc 1 refuses here — `1.1.0.1` holds no key set, so
///    `attestation_invalid:not_enrolled_at_position` (SO-I2 (g)(iv)).
///
/// `world` MUST be the snapshot taken under the guards for this request —
/// its key table is that snapshot's own slice; the guard argument is that
/// contract's cheap half.
pub(crate) fn registry_admission(
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
    match (dep.kind, &dep.to) {
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
    let bytes = match record_bytes(world, &dep.home, &dep.from) {
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
    let Some(home_account) = world.m3().effective_owner_prefix(&dep.home) else {
        debug_assert!(false, "the home pin found a doc 1 under an owner");
        return Err(RegistryRefusal::AttestationInvalid(AttestFault::NotEnrolledAtPosition));
    };
    let to: Vec<Address> = dep.to.iter().cloned().collect();
    let canonical = record.canonical_sigless();
    verify_record_sig(
        world,
        RecordTrial {
            home: &dep.home,
            home_account,
            ty: &dep.ty,
            to: &to,
            canonical: canonical.as_bytes(),
            sig,
            anchor_grade: false,
        },
    )
    .map_err(RegistryRefusal::AttestationInvalid)
}

// ── the seeding check, the genesis hand's (REG-1.28 to REG-1.32) ─────────

/// THE PARENT'S DOMAIN AS THE DAEMON SEES IT (REG-1.31): every commons row
/// the build holds that the registry does not itself allocate — the engine
/// ledger's class pins outside the registry, the three credential pins
/// (`3.1`–`3.3`, the engine's own since the World seats the identity fold,
/// standing beside that ledger's list rather than in it), and M5's
/// deposit-class members that are no registry row, which spell the first two
/// a second time. The binding and the endpoint are M5's third and fourth
/// members and the registry's own rows spelled a second time — held EQUAL by
/// the suite that sees both spellings, and no foreign row here.
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

/// THE SEEDING CHECK AT THE BOARD'S GENESIS, THIS DAEMON ITS HAND
/// (REG-1.28, REG-1.32): the three arms over the registry's rows and
/// [`seeding_domain`], run by the open ahead of the engine on every open —
/// a fresh data dir's genesis and a reopen's re-genesis alike — so a
/// refusal is a genesis that does not complete: no claim, no session and
/// no board record, nothing written. The rows and the domain are compiled
/// constants, so no hook mutates them: the arms are proved on lists the
/// suites build, the shipped lists pass here.
pub(crate) fn genesis_seeding_check() -> Result<(), SeedingRefusal> {
    skep_registry::seeding_check(skep_registry::rows(), &seeding_domain())
}

#[cfg(test)]
mod tests {
    use skep_febe::Disposition::{Permanent, Reorder};

    use super::*;
    use crate::auth::policy::addr_of;
    use crate::auth::policy::{deposits_credential_link, record_deposit_kind};

    /// THE TWO SETS ARE DISJOINT BY CONSTRUCTION: over every registry row,
    /// the three credential pins and the disavowal's released ordinal,
    /// no type slot answers both `record_deposit_kind` and
    /// `registry_deposit_kind`; the registry set holds the binding and the
    /// endpoint alone; and a `make_link` so typed is routed to exactly one
    /// sequence.
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

    /// The shipped domain holds the eight class pins outside the registry,
    /// the three credential pins and M5's two credential members, no
    /// registry row — and the check over it passes, so a daemon opens.
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

    /// Every refusal's token and class, the tokens shared with the
    /// credential family spelled through it.
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
