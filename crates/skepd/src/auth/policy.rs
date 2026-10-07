//! The write-path policy surface (AUTH part 03): which of the three write
//! sequences a write takes ([`deposits_credential_link`] and
//! [`deposits_registry_link`], each read off the op's own type slot before
//! any lock, the credential route asked first), the refusal vocabularies they
//! answer in ([`CredentialRefusal`]; the registry's own, [`RegistryRefusal`];
//! the upload family's, [`UploadRefusal`]), and — one file per sequence, one
//! for the check the plain sequence runs, and one for the upload family's
//! gate — their ordered producers:
//!
//! - `credential` — the CREDENTIAL sequence's (AUTH-3.37): slots (1)–(2)
//!   ahead of the credential write lock, the precheck's slots (3)–(8) under
//!   it, and the record grade's check inside slot (7), whose trial the
//!   registry sequence shares;
//! - `registry` — the REGISTRY sequence's (the record grade for registry
//!   records, 2b): the registry's two record-deposit kinds, the route of
//!   their links, the admission's ordered producers under the credential
//!   lock's read arm, and the seeding check the open runs ahead of every
//!   genesis;
//! - `plain` — the PLAIN sequence's admission (AUTH-3.35): the mint class,
//!   the `replaces` fence, the board-state pair and the nullify class, in
//!   their pinned order;
//! - `attestation` — THE WRITE-PATH CHECK (signed ops), run behind the plain
//!   sequence's publish-class gate on a claimed board, whose ADMITTED
//!   attestation is what the write's commit marker carries, and which asks
//!   M5's own admission of the shot what a shot it could not read is owed;
//! - `upload` — the UPLOAD family's admission at the session layer (D12;
//!   PUB-6.35's I10; M-I6 (b)): no write sequence, the family committing
//!   nothing to the journal, but the session layer's gate on who may take
//!   bytes into the blob store at all, kept beside the sequences' gates.
//!
//! `addr_spans`, the one spelling of a type slot the sequences and the check
//! read, lives here, where each child sees it without a widening.

mod attestation;
mod credential;
mod plain;
mod registry;
mod upload;

pub(crate) use credential::{op_shape_refusal, precheck, DepositSpans, RecordSig};
pub(crate) use plain::plain_admission;
pub(crate) use registry::{
    deposits_registry_link, genesis_seeding_check, registry_admission, RegistryRefusal,
};
pub(crate) use upload::{upload_admission, UploadRefusal};
// The registry's record-deposit set: read by this module's children alone,
// through `super::`, as `record_deposit_kind` is.
use registry::registry_deposit_kind;

use skep_address::{Address, Span};
use skep_febe::{Disposition, Op};
use skep_identity::{CredentialKind, Inert};
use skep_links::{enc, SlotArg};
use skep_namespace::{first_document_address, HasM3};

use skep_engine::types::IDENTITY_TYPES;

use crate::World;

/// THE DOC-1 TEST — the daemon's spelling of AUTH-2.127's home pin, the
/// fold's `not_doc_one` (`skep_identity`'s `homed_in_doc_one`: a credential
/// link is honored only where its home IS its account's `doc_1_of`, `A·0·1`)
/// read through M3's own public slot for that question,
/// [`skep_namespace::first_document_address`]: `doc` is the FIRST document
/// of the account that owns it by ω — a READ of the board's principal list Π
/// and never arithmetic over the address (m3). The one home a credential
/// link can name, and so the one place a record deposit's atom is exempt
/// from the entry check (`policy/attestation.rs`'s step 2 (iv), as7-E1
/// ARM (a)). No projection is taken: a version member of a doc 1 is no doc 1,
/// as the fold reads it (`a_version_member_of_doc_1_is_not_doc_one`), and an
/// unregistered or node-owned address has no doc 1 to be. Stated once here,
/// where both children see it.
fn homed_in_doc_one(world: &World, doc: &Address) -> bool {
    world
        .m3()
        .effective_owner_prefix(doc)
        .and_then(first_document_address)
        .is_some_and(|doc_one| doc_one == *doc)
}

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

/// A T4-valid address from its components — the policy suites' one spelling
/// of a test address.
#[cfg(test)]
fn addr_of(comps: &[u32]) -> Address {
    use skep_address::{validate, Nat, Tumbler};
    let t = Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty");
    validate(t).expect("test addresses are T4-valid by construction")
}

/// A slot's spans in M7's own deposited form: [`addr_spans`] for the
/// address form; `None` for `Resolve` — a resolved slot can never name a
/// credential type (the subspace-3 allocation the engine's pins state,
/// [`skep_engine::types`]), so classification never resolves.
fn slotarg_kind(s: &SlotArg) -> Option<CredentialKind> {
    match s {
        SlotArg::Addrs(addrs) => record_deposit_kind(&addr_spans(addrs)),
        SlotArg::Resolve(_) => None,
    }
}

/// THE RECORD-DEPOSIT SET (signed ops; the design record's BW-03, owner-ruled
/// 2026-09-29): `Some(kind)` where `ty` — a type slot in M7's deposited form,
/// any borrowed walk of it (a slice, or M7's `&Endset`) — names one of its
/// kinds. Read by name wherever this module tells a record deposit apart: the
/// entry check's EXEMPTION of the record's atom (`policy/attestation.rs`'s
/// `insert` cell — its one parse, `declared_record_atom`), the pre-claim
/// gate's refusal of a credential-kind deposit into the system account
/// (`policy/plain.rs`), and the ROUTE of its link to the credential sequence
/// ([`deposits_credential_link`], every arm), where the record grade
/// verifies the record's `sig` (D26). Stated once so the readers cannot
/// part: a kind exempt at the atom but never verified at the link would
/// commit a record no signature covers.
///
/// The set IS the fold's credential kinds (the engine's [`IDENTITY_TYPES`]:
/// enroll, retire, claim), and the route rests on that equality: the credential
/// sequence classifies every deposit routed to it through the FOLD (the
/// precheck's slot (3)), and the record grade parses the record by the kind
/// the fold's verdict names. So a kind the fold does not fold never joins
/// by an edit here: an edit here alone routes such a kind's link to a
/// classify that answers `NotCredential` — the precheck's defect arm, which
/// in a release build commits the deposit with no `sig` verified — and
/// exempts its atom from the entry check with no record grade behind it.
/// Each joins with its own classify and the precheck its record needs: the
/// registry's two record-deposit kinds, the binding and the endpoint, joined
/// as a SECOND SET with a sequence of their own ([`registry_deposit_kind`],
/// `policy/registry.rs`; the record grade for registry records, 2b), the two
/// sets disjoint by construction and this one asked first at the route; the
/// disavowal's (`…3.58.2`, the registry's subtype row) joins the same way
/// where its schema lands. The claim is a member though a claim carries no
/// record, because the fold folds it: on a published document — the only
/// place the entry check runs — a declared claim atom is refused at M5's
/// door, whose deposit class holds the kinds that deposit an atom (enroll,
/// retire, the binding, the endpoint), and a claim's link above the claim
/// is `already_claimed` at slot (3), before the record grade runs.
///
/// Private to this module and its children, where its readers live;
/// `every_arm_of_the_route_reads_the_one_set_the_fold_folds` holds every arm
/// of the route to it, and it to the fold.
fn record_deposit_kind<'s>(ty: impl IntoIterator<Item = &'s Span>) -> Option<CredentialKind> {
    IDENTITY_TYPES.kind_of(ty)
}

/// AUTH-2.61 — op classification: the op's OWN type slot, no world read,
/// so the lock is chosen before any lock is taken. True for the three
/// deposit-shaped ops whose type slot names a credential type; a `Nullify`
/// deposits nothing (its class is `nullify_refusal`'s, under the read
/// lock).
///
/// OBLIGATION, and the one this predicate cannot check: `true` for exactly
/// the deposits [`precheck`]'s classify and the engine's fold hook
/// (`World::apply`, AUTH-2.80) will read as credential-typed. All three read
/// the type slot's spans, and two of the three readings are structural
/// rather than claimed — this one and [`DepositSpans::of`] both go through
/// [`addr_spans`], the one spelling of `enc(addrs)`. Only the hook's stays a
/// claim: it reads M7's stored slot, which records `enc` verbatim. And the
/// three read one SET, the engine's one `IDENTITY_TYPES`: every arm here
/// names the kind through [`record_deposit_kind`], which IS the fold's
/// credential kinds — the equality its card states, and the reason no kind
/// the fold does not fold joins it by an edit there. The subspace-3
/// allocation the engine's pins state is what keeps a `Resolve` slot out of
/// the codomain. A FALSE NEGATIVE is the divergence this module cannot
/// detect: the deposit commits through the plain path with no gate, the
/// engine folds it all the same, and the world holds a credential the
/// precheck never judged. A false positive reaches [`precheck`]'s defect arm
/// at the classify line.
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
        Op::Emit { ty, .. } => record_deposit_kind(ty).is_some(),
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

/// The daemon-side refusal vocabulary (AUTH-3.53). Every one marshals as
/// `code: credential_refused, detail: token(), disposition: disposition()`
/// through [`crate::codec::credential_refused_reply`], which fixes the code
/// and renders the other two as the refusal names them. The DISPOSITION is
/// the refusal's own to name, because the refusal is what knows its class:
/// `Permanent` for the family as AUTH-3.54 pins it (the remedy lives in the
/// face), and the two attestation codes' own classes beside it (signed ops;
/// the design record §7.3 (iii)). [`CredentialRefusal::disposition`] is the
/// one place a refusal's class is answered — an `attestation_invalid`
/// cause's by the cause itself, beside its token
/// ([`AttestFault::disposition`]) — and a new refusal takes the family's
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
    /// rail record, the steward's classification link in a published home,
    /// the `replaces` link a grant is deposited with (PUB-5.15) — ONE code
    /// for the class list; the client splits the face by the target's type,
    /// which the owner can read. Token `nullify_audit_view` — the wire's,
    /// CONFIRMED by the owner 2026-09-07 (wire.md §Credential refusals; the
    /// v7.10 changelog entry records the confirmation).
    NullifyAuditView,
    /// THE `replaces` CLASS's SOLE-WRITER FENCE (PUB-5.15; RES-309, its code
    /// RES-310's, owner-ruled 2026-09-28): a write whose OWN type slot lands
    /// in the `replaces` class — a bare `make_link`, an `emit`, an
    /// `edit_link` successor — from its home's owner. The class has one
    /// writer, the `make_link` that carries the `replaces` MEMBER, minting
    /// the link in its record's own transaction; a `replaces` link any other
    /// act deposited would name a state for a record whose signed bytes named
    /// none. Token `replaces_not_standalone`; PERMANENT, the family's: the
    /// same act is never admitted. Its FACE is I8 (a)'s (PUB-3.83), owed to
    /// the UX track and written into no rule.
    ReplacesNotStandalone,
    /// THE CREDENTIAL DEPOSIT'S `replaces` FENCE (signed ops; the design
    /// record's BW-04, owner-ruled 2026-09-29): a credential-typed
    /// `make_link` carrying a `replaces` member. A credential deposit's
    /// `replaces` row is EMPTY BY KIND — the credential class's fold is a set,
    /// and the record's `sig` is made over the empty row — so a member there
    /// names a state no credential record replaces and would deposit a
    /// `replaces` link beside a record whose signed bytes named none. A shape
    /// slot, ahead of the lock, beside `resolved_from`. Token
    /// `replaces_not_credential` — the `replaces_not_standalone` pattern, a
    /// spelling this build chose (the design names none) — and PERMANENT,
    /// the family's: the same act is never admitted.
    ReplacesNotCredential,
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
    /// ordinary path and no error case. AND THE RECORD GRADE'S FENCE (§4.5
    /// (4) step 2; 2a): a credential deposit above the claim whose record
    /// carries no `sig` at all, answered at the deposit's `make_link` (D26)
    /// — a fence with NO POPULATION on a conforming daemon since round 7
    /// (bu7-E1 ARM (a)): a sig-less record-kind atom is refused at its
    /// `insert`, [`CredentialRefusal::RecordSigRequired`], so the only atom
    /// this reaches was deposited past that gate — below the claim, or by an
    /// operator past the check — and the act that exists is a new record,
    /// composed WITH its `sig`, inserted and linked.
    AttestationRequired,
    /// THE SIG-LESS RECORD ATOM, REFUSED AT ITS `insert` (signed ops, round
    /// 7 — bu7-E1 ARM (a), owner 2026-10-01, with as7-E1's narrowing; SO-I4;
    /// P13): an `insert` above the claim DECLARED under a kind of the
    /// record-deposit set whose one value PARSES as a record of that kind and
    /// carries NO `sig` member. Decided at the earliest act the fault is
    /// decidable from — the write-path check's step 2, where the atom's
    /// bytes are already parsed — so nothing lands and no orphan atom is
    /// minted: the retry the record grade's REORDER once named ("re-inserted
    /// and re-linked") was never free, each attempt leaving a permanent
    /// orphan in a published doc 1. Token `record_sig_required` — a
    /// spelling this build chose, the `signed_session_required` pattern —
    /// and PERMANENT, the family's: the same bytes are never admitted, and
    /// the act that exists is a DIFFERENT record, the same entries composed
    /// WITH their `sig` over the `record` frame. Its face is the record
    /// grade's: "this record carries no `sig`; above the claim a credential
    /// record is signed by its author — compose it with its `sig` and insert
    /// that".
    RecordSigRequired,
    /// THE SYSTEM ACCOUNT HOLDS NO KEY (PUB-6.65; signed ops, round 7 —
    /// as7-F2 = reg-S3; SO-I2 (g)(iv), SO-I4 (c)): a credential deposit whose
    /// SUBJECT — the account the record's own entries enrol, retire or claim,
    /// the fold's reading of the link's `to` — or whose HOME's owner by ω is
    /// the system account `1.1.0.1`, refused at the credential sequence's
    /// precheck on a claimed board (ahead of the record grade) and on an
    /// unclaimed one (the pre-claim gate's genesis arm), and a declared
    /// credential-kind `insert` into that account's doc 1 refused at the
    /// plain path's pre-claim admission. Without it a loopback party on an
    /// UNCLAIMED board binds a bare session as the system principal, plants
    /// a genesis in `1.1.0.1.0.1` — the one pre-claim plant `claim_residue`
    /// cannot see, the account sitting at the genesis floor — and after the
    /// claim opens SIGNED system sessions whose writes into `H` are A3-exempt
    /// and poison the head writer's resume. The head writer's own rows are no
    /// credential deposits and never meet this. Token
    /// `system_account_keyless` — a spelling this build chose — and
    /// PERMANENT, the family's: the system account enrols no key, ever; the
    /// act that exists is an enrolment under an account of one's own.
    SystemAccountKeyless,
    /// THE WRITE-PATH CHECK's second refusal (§4.5 (2)): an `attest` that
    /// does not verify, or a write over which none can be verified, with the
    /// cause the check can tell from what it holds — the `detail` split §7.3
    /// (iii) asks for, at least between SIGNATURE and
    /// NOT-ENROLLED-AT-POSITION. Token `attestation_invalid:<cause>`, the
    /// class the cause's own. At the record grade (2a) the same causes over a
    /// record's `sig`: `malformed` a `sig` that is no hybrid blob's hex,
    /// `not_enrolled_at_position` a home whose opening set holds no key of the
    /// blob's row at the grade the act needs, `signature` a `sig` no such key
    /// verifies over the `record` frame the daemon composed,
    /// `board_unavailable` as for an entry.
    AttestationInvalid(AttestFault),
}

/// The causes of `attestation_invalid` — the `<cause>` sub-token, joined as
/// the payload arm joins `malformed_payload:<sub>` (AUTH-2.55) — each with
/// its disposition class ([`AttestFault::disposition`]), re-derived off the
/// wire's own class definitions (the board's r6-6, owner-ruled 2026-09-29,
/// taking BW-07's derivation): PERMANENT where reissuing the same request
/// cannot succeed, REORDER where a later committed state may satisfy it, and
/// the two the entry frame's own limits add — a value its author may not
/// read, a body past its budget — in the class of the store refusal each
/// stands beside. Each variant says which, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttestFault {
    /// The blob is not the tag's fixed width — a member the client composed
    /// wrong. PERMANENT (r6-6): the same bytes are refused however the board
    /// moves, and the client's next act is a DIFFERENT request, re-composed,
    /// never a reissue.
    Malformed,
    /// The board has no `H.1`, so the entry frame's `board` term (D13) has
    /// no value and nothing can be verified — on a claimed board, one of the
    /// two states [`crate::write_path::board_term`] names. REORDER, not
    /// PERMANENT: the board's state refused it, not the client's key, and the
    /// state a refused first head leaves clears without the client. Its own
    /// cause so a client is not told its signature was wrong.
    BoardUnavailable,
    /// The set that OPENS the act's principal at this write's base holds no
    /// key of the attestation's algorithm — A2's empty walk among them — so
    /// no retry under the same key can succeed (PERMANENT).
    NotEnrolledAtPosition,
    /// A candidate key exists and none verifies the blob over the entry frame
    /// the daemon composed — wrong bytes, a wrong `board` term, a body
    /// composed otherwise. PERMANENT (r6-6): no committed state makes those
    /// bytes verify — the board term is fixed from the claim on — so the
    /// client's next act is a DIFFERENT request, the frame re-composed and
    /// re-signed, never a reissue of this one.
    Signature,
    /// A `publish` COPIES IN a value its author may not READ — a staging
    /// draft's run onto a draft the read predicate withholds from it — and
    /// the store would admit it, the base CARRYING the run (PUB-6.24). No
    /// entry frame is composed over such a value, since a verdict over it
    /// would answer by its bytes, so no signature can be verified over one:
    /// an attested shot is refused whatever its signature was made over, the
    /// value unread (an unattested one meets `attestation_required` first, the
    /// check's (1) standing ahead of the composition). A WINDOW is no such
    /// case since the address form (l6-A4): signed by its address, it is
    /// composed unread and the store's gate decides it. REORDER, as `withheld`
    /// is: the client re-composes without the run, or re-sends once a grant
    /// lets it read the run's origin.
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

    /// The cause's disposition class, beside its token — its variant's card
    /// says why. Exhaustive, so a new cause is classed here before this
    /// compiles.
    fn disposition(self) -> Disposition {
        match self {
            AttestFault::BoardUnavailable | AttestFault::Withheld => Disposition::Reorder,
            AttestFault::Malformed
            | AttestFault::Signature
            | AttestFault::NotEnrolledAtPosition
            | AttestFault::FrameTooLarge => Disposition::Permanent,
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
            CredentialRefusal::ReplacesNotStandalone => "replaces_not_standalone".into(),
            CredentialRefusal::ReplacesNotCredential => "replaces_not_credential".into(),
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
            CredentialRefusal::RecordSigRequired => "record_sig_required".into(),
            CredentialRefusal::SystemAccountKeyless => "system_account_keyless".into(),
            CredentialRefusal::AttestationInvalid(f) => {
                format!("attestation_invalid:{}", f.sub_token())
            }
        }
    }

    /// The wire `disposition`: `Permanent` for the family as AUTH-3.54 pins
    /// it, and the two attestation codes' own classes (signed ops; the
    /// board's r6-6, off the wire's definitions) — `attestation_required`
    /// REORDER (ATTACH WHEN IN DOUBT: the same content, signed and attached,
    /// is the ordinary path), and `attestation_invalid` its cause's
    /// ([`AttestFault::disposition`]).
    pub fn disposition(&self) -> Disposition {
        match self {
            CredentialRefusal::AttestationRequired => Disposition::Reorder,
            CredentialRefusal::AttestationInvalid(fault) => fault.disposition(),
            _ => Disposition::Permanent,
        }
    }
}

#[cfg(test)]
mod tests {
    use skep_address::{subtree_of, Nat};
    use skep_febe::SuccessorSpec;

    use super::*;
    use skep_engine::types::{t_claim, t_enroll, t_retire};

    /// THE RECORD-DEPOSIT SET IS THE FOLD'S KINDS, and every arm of the route
    /// reads it: over the three credential kinds, the disavowal's released
    /// ordinal (`…3.4`, which the fold does not fold) and the registry's two
    /// kinds (a second set, never this one), [`record_deposit_kind`] answers
    /// what the engine's [`IDENTITY_TYPES`] answers, and a `make_link`, an
    /// `emit` and an `edit_link` successor so typed are routed to the
    /// credential sequence exactly where it answers `Some`. The route rests
    /// on that equality — the credential sequence classifies what it is
    /// routed through the fold — so an edit adding a kind to the set alone,
    /// the join its card rules out, fails here.
    #[test]
    fn every_arm_of_the_route_reads_the_one_set_the_fold_folds() {
        let doc = addr_of(&[1, 0, 1, 0, 1]);
        let disavowal = addr_of(&[1, 1, 0, 1, 0, 1, 0, 3, 4]);
        let binding = addr_of(&[1, 1, 0, 1, 0, 1, 0, 3, 55]);
        let endpoint = addr_of(&[1, 1, 0, 1, 0, 1, 0, 3, 56]);
        for ty in [
            t_enroll().clone(),
            t_retire().clone(),
            t_claim().clone(),
            disavowal,
            binding,
            endpoint,
        ] {
            let slot = addr_spans(std::slice::from_ref(&ty));
            let folded = IDENTITY_TYPES.kind_of(&slot);
            assert_eq!(
                record_deposit_kind(&slot),
                folded,
                "{}: the set is the fold's kinds",
                ty.tumbler()
            );
            let typed = || SlotArg::Addrs(vec![ty.clone()]);
            let empty = || SlotArg::Addrs(Vec::new());
            let make_link = Op::MakeLink {
                home: doc.clone(),
                from: empty(),
                to: empty(),
                ty: typed(),
                replaces: None,
            };
            let emit =
                Op::Emit { home: doc.clone(), ty: enc([&ty]), from: doc.clone(), to: Vec::new() };
            let edit_link = Op::EditLink {
                original: doc.clone(),
                successor: SuccessorSpec { from: Vec::new(), to: Vec::new(), ty: typed() },
                d_s: doc.clone(),
                d_a: doc.clone(),
            };
            for (op, name) in [(make_link, "make_link"), (emit, "emit"), (edit_link, "edit_link")] {
                assert_eq!(
                    deposits_credential_link(&op),
                    folded.is_some(),
                    "{}: a {name} so typed is routed exactly where the set answers",
                    ty.tumbler()
                );
            }
        }
    }

    /// Every `attestation_invalid` cause answers its OWN class beside its
    /// token — [`AttestFault::disposition`], the one place a cause is classed
    /// (r6-6): REORDER where a later committed state may satisfy it, PERMANENT
    /// where reissuing the same request cannot. `attestation_required` beside
    /// them is REORDER, and the family's other refusals are `Permanent`.
    #[test]
    fn every_attestation_invalid_cause_answers_its_own_class() {
        use skep_febe::Disposition::{Permanent, Reorder};
        for (fault, token, class) in [
            (AttestFault::Malformed, "malformed", Permanent),
            (AttestFault::BoardUnavailable, "board_unavailable", Reorder),
            (AttestFault::NotEnrolledAtPosition, "not_enrolled_at_position", Permanent),
            (AttestFault::Signature, "signature", Permanent),
            (AttestFault::Withheld, "withheld", Reorder),
            (AttestFault::FrameTooLarge, "frame_too_large", Permanent),
        ] {
            let refusal = CredentialRefusal::AttestationInvalid(fault);
            assert_eq!(
                (refusal.token(), refusal.disposition()),
                (format!("attestation_invalid:{token}"), class),
                "{fault:?}"
            );
        }
        assert_eq!(CredentialRefusal::AttestationRequired.disposition(), Reorder);
        assert_eq!(CredentialRefusal::ClaimFirst.disposition(), Permanent);
        // Round 7's two: a sig-less record atom and the system account's
        // credential deposit are PERMANENT — no committed state admits the
        // same bytes (SO-I7 (f)).
        for refusal in
            [CredentialRefusal::RecordSigRequired, CredentialRefusal::SystemAccountKeyless]
        {
            assert_eq!(refusal.disposition(), Permanent, "{}", refusal.token());
        }
        assert_eq!(CredentialRefusal::RecordSigRequired.token(), "record_sig_required");
        assert_eq!(CredentialRefusal::SystemAccountKeyless.token(), "system_account_keyless");
    }

    /// The five reserved subtree spans overlap nothing the credential types
    /// name: the identity types live in subspace 3 while the shipped classes
    /// sit at content positions 1..=5 — pinned so a change to either
    /// allocation fails here rather than in a fold. The table is the
    /// engine's one instance, which the fold hook and this daemon's
    /// classifiers all read.
    #[test]
    fn identity_types_are_distinct_and_recognized() {
        let enroll_span = subtree_of(t_enroll().tumbler());
        assert_eq!(IDENTITY_TYPES.kind_of(&[enroll_span]), Some(CredentialKind::Enroll));
        let retire_span = subtree_of(t_retire().tumbler());
        assert_eq!(IDENTITY_TYPES.kind_of(&[retire_span]), Some(CredentialKind::Retire));
        let claim_span = subtree_of(t_claim().tumbler());
        assert_eq!(IDENTITY_TYPES.kind_of(&[claim_span]), Some(CredentialKind::Claim));
        // A shipped reserved type (ghost position 1, the content subspace)
        // is NOT a credential type.
        let shipped_span = subtree_of(addr_of(&[1, 1, 0, 1, 0, 1, 0, 1, 1]).tumbler());
        assert_eq!(IDENTITY_TYPES.kind_of(&[shipped_span]), None);
    }

    /// AUTH-3.70's conformance expression in miniature: a content-I-span
    /// type slot answers no credential kind — a resolved span's start is a
    /// mintable content position, never a subspace-3 name.
    #[test]
    fn a_content_span_ty_is_never_credential() {
        // Content position 1 of some ordinary doc: <doc>.0.1.1.
        let content = subtree_of(addr_of(&[1, 0, 1, 0, 1, 0, 1, 1]).tumbler());
        assert_eq!(IDENTITY_TYPES.kind_of(&[content]), None);
    }

    /// The class types a `deposit` field can usefully carry are SPELLED
    /// TWICE — M5's set, which its insert door tests a declaration against
    /// and which sits below this crate and the engine, and the engine's
    /// credential pins, which the fold hook classifies the pair's
    /// `make_link` by — and the two are pinned EQUAL here, member for member
    /// in the set's order, ENROLL then RETIRE (PUB-2.11, PUB-2.63; RES-249,
    /// RES-261), the set's two further members being the registry's binding
    /// and endpoint, the engine ledger's rows, which the registry sequence
    /// classifies by (REG-1.37 as the record grade for registry records
    /// re-reads it). The engine's own ledger holds the same equality; this
    /// is the daemon's reading of it, at the door where a declared type
    /// enters: if this fails, an enrollment a client declares as the fold
    /// will classify it is refused `published_target` at the store — or
    /// admitted there and typed as nothing the fold honors.
    #[test]
    fn the_deposit_class_types_are_the_engines_enroll_and_retire_pins() {
        let spelled: Vec<Vec<Nat>> = skep_arrangement::deposit_class_types()
            .iter()
            .map(|ty| ty.tumbler().iter().cloned().collect())
            .collect();
        let row = |a: &Address| -> Vec<Nat> { a.tumbler().iter().cloned().collect() };
        assert_eq!(
            spelled,
            [
                row(t_enroll()),
                row(t_retire()),
                row(skep_engine::types::t_binding()),
                row(skep_engine::types::t_endpoint()),
            ]
        );
        assert_eq!(t_enroll().tumbler().to_string(), "1.1.0.1.0.1.0.3.1");
        assert_eq!(t_retire().tumbler().to_string(), "1.1.0.1.0.1.0.3.2");
        assert_eq!(t_claim().tumbler().to_string(), "1.1.0.1.0.1.0.3.3");
    }
}
