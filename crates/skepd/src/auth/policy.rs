//! The write-path policy surface (AUTH part 03): which of the two write
//! sequences a write takes ([`deposits_credential_link`], read off the op's
//! own type slot before any lock), the refusal vocabulary both answer in
//! ([`CredentialRefusal`]), and — one file per sequence, and one for the
//! check the plain sequence runs — their ordered producers:
//!
//! - `credential` — the CREDENTIAL sequence's (AUTH-3.37): slots (1)–(2)
//!   ahead of the credential write lock, the precheck's slots (3)–(8) under
//!   it;
//! - `plain` — the PLAIN sequence's admission (AUTH-3.35): the mint class,
//!   the board-state pair and the nullify class, in their pinned order;
//! - `attestation` — THE WRITE-PATH CHECK (signed ops), run behind the plain
//!   sequence's publish-class gate on a claimed board, whose ADMITTED
//!   attestation is what the write's commit marker carries, and which asks
//!   the store's own gates, on a detached kernel, what a shot it could not
//!   read is owed.
//!
//! `addr_spans`, the one spelling of a type slot all three read, lives here,
//! where each child sees it without a widening.

mod attestation;
mod credential;
mod plain;

pub(crate) use credential::{op_shape_refusal, precheck, DepositSpans};
pub(crate) use plain::plain_admission;

use skep_address::{Address, Span};
use skep_febe::{Disposition, Op};
use skep_identity::{CredentialKind, Inert};
use skep_links::{enc, SlotArg};

use super::fold::identity_types;

/// One address-form slot in M7's own deposited form — `enc(addrs)`. The
/// ONE spelling, so [`deposits_credential_link`]'s classification and
/// [`DepositSpans::of`]'s deposit read a type slot through the same call:
/// two of the three readings the obligation on that classifier rests on
/// become one, and only the rebuild's (M7's stored slot) stays separate.
/// The write-path check asks the same classifier of an `insert`'s DECLARED
/// type through it too (D26's record-deposit exemption), so a type is one
/// slot shape wherever this module classifies one.
fn addr_spans(addrs: &[Address]) -> Vec<Span> {
    enc(addrs.iter()).spans().cloned().collect()
}

/// A slot's spans in M7's own deposited form: [`addr_spans`] for the
/// address form; `None` for `Resolve` — a resolved slot can never name a
/// credential type (the allocation in [`super::fold`]), so classification never
/// resolves.
fn slotarg_kind(s: &SlotArg) -> Option<CredentialKind> {
    match s {
        SlotArg::Addrs(addrs) => identity_types().kind_of(&addr_spans(addrs)),
        SlotArg::Resolve(_) => None,
    }
}

/// AUTH-2.61 — op classification: the op's OWN type slot, no world read,
/// so the lock is chosen before any lock is taken. True for the three
/// deposit-shaped ops whose type slot names a credential type; a `Nullify`
/// deposits nothing (its class is `nullify_refusal`'s, under the read
/// lock).
///
/// OBLIGATION, and the one this predicate cannot check: `true` for exactly
/// the deposits [`precheck`]'s classify and
/// [`crate::auth::fold::canonical_identity`] will read as credential-typed.
/// All three read the type slot's spans, and two of the three readings are
/// structural rather than claimed — this one and [`DepositSpans::of`] both
/// go through [`addr_spans`], the one spelling of `enc(addrs)`. Only the
/// rebuild's stays a claim: it reads M7's stored slot, which records `enc`
/// verbatim. The subspace-3 allocation in [`super::fold`] is what keeps a `Resolve` slot
/// out of the codomain. A FALSE NEGATIVE is the divergence this module
/// cannot detect: the deposit commits through the plain path with no gate
/// and no fold step, so the world holds a credential the live fold never
/// saw, `key_set` answers one thing until restart and another after it, and
/// nothing reports either. A false positive reaches [`precheck`]'s defect
/// arm at the classify line.
///
/// EXHAUSTIVE with no `_` arm, the treatment [`crate::write_path::write_meta`]
/// already gives the read/write partition: the non-deposit arm is written
/// out, so a new `Op` fails to compile here until someone decides whether it
/// can carry a credential type slot. A wildcard would default that decision
/// to `false` — the false negative above, which is the one answer this
/// module cannot detect being wrong.
pub(crate) fn deposits_credential_link(op: &Op) -> bool {
    match op {
        Op::MakeLink { ty, .. } => slotarg_kind(ty).is_some(),
        Op::Emit { ty, .. } => identity_types().kind_of(ty).is_some(),
        Op::EditLink { successor, .. } => slotarg_kind(&successor.ty).is_some(),
        // Every other op deposits no link at all, so none can be
        // credential-typed — including `Nullify`, whose class is
        // `nullify_refusal`'s under the read lock.
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

/// The daemon-side refusal vocabulary (AUTH-3.53). Every one marshals as
/// `code: credential_refused, detail: token(), disposition: disposition()`
/// through [`crate::codec::credential_refused_reply`], which fixes the code
/// and renders the other two as the refusal names them. The DISPOSITION is
/// the refusal's own to name, because the refusal is what knows its class:
/// `Permanent` for the family as AUTH-3.54 pins it (the remedy lives in the
/// face), and the two attestation codes' own classes beside it (signed ops;
/// the design record §7.3 (iii)). [`CredentialRefusal::disposition`] is the
/// one place a class is chosen, and a new refusal takes the family's
/// `Permanent` there unless it names another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CredentialRefusal {
    /// The fold's own verdict — produced by `precheck`, slot (3).
    Inert(Inert),
    /// Slot (1), ahead of the write lock.
    EmitNotMakeLink,
    /// Slot (4), FIRST of the slot's two tokens (AUTH-3.44 as AUTH RES-206
    /// landed it; the hybrid-only launch's Q5, owner 2026-09-26 "b"): an
    /// enrolment record naming ANY key of the PREVIEW row, tag 3
    /// (`fndsa512-preview-ed25519`, AUTH-1.5), unless the daemon's setting
    /// `allow_preview_keys` allows it (AUTH-1.44) — EVERY enrolment record,
    /// `Genesis` INSIDE; the test reads each key entry's `alg` and decodes
    /// nothing. Tag-3 VERIFICATION stays compiled in (the frozen-tag rule);
    /// this refuses ENROLLMENT alone. Token `preview_key` — AUTH-3.56's row,
    /// AUTH-6.23's; the face, the row's verbatim: "this is a PREVIEW key, and
    /// this board enrolls no preview keys — make a key with a released client
    /// and enroll that".
    PreviewKey,
    /// Slot (4), behind [`CredentialRefusal::PreviewKey`]: a key ANY half of
    /// which does not decode (AUTH-3.56 as RES-206 landed it: every half the
    /// key's row names — the Ed25519 point, the post-quantum key).
    UndecodableKey,
    /// The NULLIFY class, under the read lock, outside slots (1)–(8): a
    /// `nullify` whose target is CREDENTIAL-typed (PUB-6.10).
    NullifyNotRetraction,
    /// The NULLIFY class's GRANT-TYPED cell (PUB-6.30): retraction is never a
    /// second revocation path — a share is withdrawn by revoking it, and the
    /// grant fold reads the audit view (PUB-6.31). Token
    /// `nullify_not_revocation` — the wire's, CONFIRMED by the owner
    /// 2026-09-07 (wire.md §Credential refusals; the v7.10 changelog entry
    /// records the confirmation).
    NullifyNotRevocation,
    /// The NULLIFY class's AUDIT-VIEW cell (PUB-6.64): a target of a class
    /// whose honored state the spec reads under the AUDIT view — the
    /// succession pair, the consumption marker, the journal designation, the
    /// rail record, the steward's classification link in a published home —
    /// ONE code for the class list; the client splits the face by the
    /// target's type, which the owner can read. Token `nullify_audit_view` —
    /// the wire's, CONFIRMED by the owner 2026-09-07 (wire.md §Credential
    /// refusals; the v7.10 changelog entry records the confirmation).
    NullifyAuditView,
    /// Slot (6), FIRST of the slot's two tokens (AUTH-3.44; RES-63): any
    /// credential-typed deposit, retirement or claim from a CONTENT-scoped
    /// session (AUTH-4.39) — whatever key opened it, and whether or not the
    /// act is an anchor act. Token `content_session`, PINNED (AUTH-6.23).
    ContentSession,
    /// Slot (6), behind [`CredentialRefusal::ContentSession`].
    AnchorSessionRequired,
    /// Slot (2), ahead of the write lock.
    ResolvedFrom,
    /// Slot (5) — present because the build takes the cap (RES-57, at 16).
    TooManyEnrolled,
    /// The MINT class, on the plain path.
    MintHomeFirst,
    /// The FIRST-MINT publication door (PUB-8.20, owner ruling D2c): an
    /// explicit `published: false` on an account's first `create_new_document`.
    /// Token `mint_home_public` — the wire's, tabled beside `mint_home_first`
    /// (wire.md §Credential refusals) and carrying no confirmation debt.
    MintHomePublic,
    /// Slot (7), and the plain path's publish-class gate (RES-26).
    SignedSessionRequired,
    /// Slot (8), and the plain path's pre-claim admission gate (RES-27).
    ClaimFirst,
    /// Slot (8)'s CLAIM arm — the claim's own admission (PUB-6.63, RES-24;
    /// PUB round 2, lane 4.2): the claim is refused where the top-level
    /// account space holds any principal above the genesis floor but the one
    /// this ceremony's own `delegate` minted. Token `claim_residue` —
    /// owner-confirmed as named and worded (2026-09-20; AUTH RES-202 pins it
    /// beside `claim_first` in the pre-claim tokens' convention). The face is
    /// PUB-6.63's verbatim: "this board carries pre-claim residue — re-genesis
    /// before claiming."
    ClaimResidue,
    /// THE WRITE-PATH CHECK's first refusal (signed ops; the design record
    /// §4.5 (1); A1): a DISPATCHED, publish-class write of the checked set's
    /// ops ABOVE THE CLAIM on a claimed board, from a signed session,
    /// carrying no `attest`. Token `attestation_required`, class REORDER —
    /// the answer is a DIFFERENT request the client composes (the same
    /// content, signed and attached), which under ATTACH WHEN IN DOUBT is the
    /// ordinary path and no error case.
    AttestationRequired,
    /// THE WRITE-PATH CHECK's second refusal (§4.5 (2)): an `attest` that
    /// does not verify, or a write over which none can be verified, with the
    /// cause the check can tell from what it holds — the `detail` split §7.3
    /// (iii) asks for, at least between SIGNATURE and
    /// NOT-ENROLLED-AT-POSITION. Token `attestation_invalid:<cause>`, the
    /// class the cause's own.
    AttestationInvalid(AttestFault),
}

/// The causes of `attestation_invalid` — the `<cause>` sub-token, joined as
/// the payload arm joins `malformed_payload:<sub>` (AUTH-2.55), each with
/// the disposition class its next act takes: the design record §7.3 (iii)'s
/// for the four causes it lands, and for the two the entry frame's own
/// limits add — a value its author may not read, a body past its budget —
/// the class of the store refusal each stands beside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttestFault {
    /// The blob is not the tag's fixed width (a re-compose: a client bug;
    /// REORDER).
    Malformed,
    /// The board has no `H.1`, so the entry frame's `board` term (D13) has
    /// no value and nothing can be verified. Since s1 (RULED 2026-09-25) the
    /// claim writes `H.1` in its own step and the daemon's open writes it
    /// where a crash split the two, so on a claimed board this answers only
    /// the two states [`crate::write_path::board_term`] names: a first head
    /// the head writer's driver refused — a refusal the claim survives,
    /// surfaced on the operator stream, and cleared by the next head or the
    /// next open — or a journal damaged below `H.1` (the member gone, or its
    /// record not one this build reads). REORDER, not PERMANENT: the board's
    /// state refused it, not the client's key, and the first of the two
    /// states clears without the client. Its own cause so a client is not
    /// told its signature was wrong.
    BoardUnavailable,
    /// The set that OPENS the act's principal at this write's base holds no
    /// key of the attestation's algorithm — A2's empty walk among them — so
    /// no retry under the same key can succeed (PERMANENT).
    NotEnrolledAtPosition,
    /// A candidate key exists and none verifies the blob over the entry frame
    /// the daemon composed — wrong bytes, a wrong `board` term, a body
    /// composed otherwise: the client re-composes (REORDER).
    Signature,
    /// A `publish` places a value its author may not READ, and the store
    /// would admit it — the base CARRIES the run (PUB-6.24). No entry frame
    /// is composed over such a value, since a verdict over it would answer
    /// by its bytes, so no signature can be verified over one: the shot is
    /// refused whatever it carries, the value unread. REORDER, as `withheld`
    /// is: the client re-composes without the run, or re-sends once a grant
    /// lets it read the origin.
    Withheld,
    /// A `publish`'s entry-frame body would pass
    /// `entry::MAX_SHOT_BODY_BYTES` — the runs name more value bytes than
    /// one attested write may carry. PERMANENT, as M5's own `too_many_values`
    /// is: a shot cannot be split to meet it, the member it mints being born
    /// whole.
    FrameTooLarge,
}

impl AttestFault {
    fn sub_token(self) -> &'static str {
        match self {
            AttestFault::Malformed => "malformed",
            AttestFault::BoardUnavailable => "board_unavailable",
            AttestFault::NotEnrolledAtPosition => "not_enrolled_at_position",
            AttestFault::Signature => "signature",
            AttestFault::Withheld => "withheld",
            AttestFault::FrameTooLarge => "frame_too_large",
        }
    }
}

impl CredentialRefusal {
    /// The wire `detail` token: the fold arm delegates to `Inert::detail()`,
    /// which writes the payload arm's `malformed_payload:<sub>` join itself
    /// (AUTH-2.55); the daemon-side tokens are hand-spelled here and only
    /// here.
    pub fn token(&self) -> String {
        match self {
            CredentialRefusal::Inert(i) => i.detail(),
            CredentialRefusal::EmitNotMakeLink => "emit_not_make_link".into(),
            CredentialRefusal::PreviewKey => "preview_key".into(),
            CredentialRefusal::UndecodableKey => "undecodable_key".into(),
            CredentialRefusal::NullifyNotRetraction => "nullify_not_retraction".into(),
            CredentialRefusal::NullifyNotRevocation => "nullify_not_revocation".into(),
            CredentialRefusal::NullifyAuditView => "nullify_audit_view".into(),
            CredentialRefusal::ContentSession => "content_session".into(),
            CredentialRefusal::AnchorSessionRequired => "anchor_session_required".into(),
            CredentialRefusal::ResolvedFrom => "resolved_from".into(),
            CredentialRefusal::TooManyEnrolled => "too_many_enrolled".into(),
            CredentialRefusal::MintHomeFirst => "mint_home_first".into(),
            CredentialRefusal::MintHomePublic => "mint_home_public".into(),
            CredentialRefusal::SignedSessionRequired => "signed_session_required".into(),
            CredentialRefusal::ClaimFirst => "claim_first".into(),
            CredentialRefusal::ClaimResidue => "claim_residue".into(),
            CredentialRefusal::AttestationRequired => "attestation_required".into(),
            CredentialRefusal::AttestationInvalid(f) => {
                format!("attestation_invalid:{}", f.sub_token())
            }
        }
    }

    /// The wire `disposition`: `Permanent` for the family as AUTH-3.54 pins
    /// it, and the two attestation codes' own classes (signed ops; the
    /// design record §7.3 (iii)) — `attestation_required` REORDER, and
    /// `attestation_invalid` PERMANENT at not-enrolled-at-position and at
    /// frame-too-large, and REORDER at the re-compose causes.
    pub fn disposition(&self) -> Disposition {
        match self {
            CredentialRefusal::AttestationRequired => Disposition::Reorder,
            CredentialRefusal::AttestationInvalid(
                AttestFault::NotEnrolledAtPosition | AttestFault::FrameTooLarge,
            ) => Disposition::Permanent,
            CredentialRefusal::AttestationInvalid(_) => Disposition::Reorder,
            _ => Disposition::Permanent,
        }
    }
}
