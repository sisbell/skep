//! The write-path policy surface (AUTH part 03): the credential type
//! addresses, op classification, the refusal producers at their pinned lock
//! scopes, and the precheck's ordered slots.

use std::sync::LazyLock;

use skep_address::{document_of, ordinal, parent, validate, Address, Nat, Span, Tumbler};
use skep_arrangement::trunk_of;
use skep_engine::types::{
    t_consumption_marker, t_delegator_endorsement, t_grant, t_journal_designation, t_rail_record,
    t_steward_classification, t_successor_of,
};
use skep_febe::Op;
use skep_identity::{
    AuditClass, CredentialKind, Effect, IdentityState, Inert, LinkDeposit, TypeAddrs, Verdict,
    WriteClass, WriteTypes,
};
use skep_links::{enc, HasLinks, SlotArg};
use skep_namespace::{first_document_address, HasM3, PrincipalId, BOOTSTRAP_PRINCIPAL};

use super::fold::WorldCtx;
use super::{LockRead, LockWrite};
use crate::World;

/// The enrolled-set cap (RES-57, AUTH-3.57): daemon POLICY — a
/// config-visible constant, never a fold constant — `Enroll` arm only,
/// `Genesis` exempt. Raisable later without format consequence — but not
/// without CPU consequence: the enrolled set is what
/// [`super::session::handshake`] walks in full on every signed
/// `POST /session` attempt, so raising this raises that unauthenticated
/// route's per-attempt work linearly. The budget is written on
/// [`MAX_GENESIS_KEYS`], which bounds the same quantity on the arm this
/// cap exempts.
pub(crate) const MAX_ENROLLED_KEYS: usize = 16;

/// The seeding hand's own bound (daemon POLICY, the same standing as
/// [`MAX_ENROLLED_KEYS`]). RES-57 exempts `Genesis` from the ENROLLED
/// SET's cap — an account seeded past it keeps its keys — and what is
/// bounded here is ONE RECORD's key count, which is a different quantity:
/// it is what [`super::session::find_signer`] walks, in full, on every
/// signed `POST /session` attempt, and that route is unauthenticated and
/// reachable from any page.
///
/// The budget is N × `verify_strict` against the two cheap requests that
/// buy it — one `GET /challenge`, one `POST /session`, neither carrying a
/// credential. At [`MAX_ENROLLED_KEYS`] the bill is order 800 µs,
/// commensurate with the frame parse beside it; at the record's own
/// [`skep_identity::MAX_RECORD_BYTES`] bound it is order 40 ms, which the
/// worker pool cannot absorb. "No cutoff, ever" (AUTH-4.33) is what makes
/// the cap belong HERE, at the deposit, rather than at the verification.
///
/// The pre-claim window is the reachable one and the exposure is
/// permanent: slot (7) is arm-blind, so a bare genesis plant on a claimed
/// board dies there, while anything seeded before the claim can be retired
/// only by an anchor session of that account — whose keys the planter
/// chose.
pub(crate) const MAX_GENESIS_KEYS: usize = MAX_ENROLLED_KEYS;

/// The most keys slot (4) point-decodes: ONE past the cap slot (5) applies.
/// A record past that cap is refused whatever the rest decode to, so every
/// decode beyond it is work an over-cap frame buys and never spends — order
/// 800 decompressions at the record's own upstream
/// [`skep_identity::MAX_RECORD_BYTES`], order 10 µs each, held under
/// `credential_lock.write()` AND the serialization lock, bought by a
/// 150-byte deposit naming one pre-inserted atom.
///
/// The two caps are equal by definition today. If they ever diverge this
/// must be the LARGER, or an over-cap record on the larger arm re-opens the
/// same bill.
const MAX_DECODED_KEYS: usize = MAX_GENESIS_KEYS + 1;

/// The three credential type addresses — AUTH-7.1 horn B's allocation,
/// recorded for the commons-seeding table (see the build report): subspace
/// 3 of the ghost document `1.1.0.1.0.1`, ordinals 1–3 in the order
/// enroll · retire · claim.
///
/// Why subspace 3 discharges AUTH-3.70's unreachability obligation with no
/// store edit: content V-spec RESOLUTION only ever yields I-spans in the
/// CONTENT subspace (subspace 1) of real documents — M3's content mints are
/// the resolution's whole codomain — and no M3 door mints into any
/// document's subspace 3 at all, so these names are never allocated and no
/// resolved span can equal their subtree spans. `deposits_credential_link`
/// therefore answers false for every `Resolve` type slot without resolving
/// anything, which is exactly AUTH-2.61's lock-free classifier.
pub(crate) const T_ENROLL: [u32; 9] = [1, 1, 0, 1, 0, 1, 0, 3, 1];
pub(crate) const T_RETIRE: [u32; 9] = [1, 1, 0, 1, 0, 1, 0, 3, 2];
pub(crate) const T_CLAIM: [u32; 9] = [1, 1, 0, 1, 0, 1, 0, 3, 3];

fn addr_of(comps: &[u32]) -> Address {
    let t = Tumbler::new(comps.iter().map(|&c| Nat::from(c)))
        .expect("the credential type components are nonempty");
    validate(t).expect("the credential type addresses are T4-valid by construction")
}

/// The ONE `TypeAddrs` (`IDENTITY_TYPES`, AUTH-2.79) — an I2 frozen
/// constant; every classifier and the fold read this instance.
pub(crate) fn identity_types() -> &'static TypeAddrs {
    static TYPES: LazyLock<TypeAddrs> = LazyLock::new(|| {
        TypeAddrs::new(addr_of(&T_ENROLL), addr_of(&T_RETIRE), addr_of(&T_CLAIM))
    });
    &TYPES
}

/// The WRITE PATH's type-recognition input (PUB-6.30, PUB-6.64; owner ruling
/// D3, 2026-09-05) — [`identity_types`]'s sibling: the same three credential
/// kinds (a clone of the one frozen instance, so the fold and the write path
/// cannot disagree about a credential), WIDENED beside them by the GRANTS
/// class and PUB-6.64's audit-view members. Read by [`nullify_refusal`]
/// alone; the fold and `deposits_credential_link` keep reading
/// [`identity_types`] (`kind_of`, the I2 rule, is untouched — a class here
/// is never a credential there).
///
/// The class addresses are the engine's commons pins (`skep_engine::types`):
/// the grant `3.90`, `successor-of` `3.59`, `endorse` `3.42`, the consumption
/// marker `3.91`, the journal designation `3.22`, the rail record `3.60`, the
/// steward's classification link `3.61` — each cited to its commons row
/// there and to the owner's confirmation of 2026-09-07. Adding a member of
/// PUB-6.64's class is one `AuditClass` arm and one address in this list;
/// the refusal that reads them takes no edit. The list order is the
/// recognition order and every address is pairwise prefix-free
/// (`WriteTypes::new` asserts it, once, here).
pub(crate) fn write_types() -> &'static WriteTypes {
    static TYPES: LazyLock<WriteTypes> = LazyLock::new(|| {
        WriteTypes::new(
            identity_types().clone(),
            t_grant().clone(),
            [
                (AuditClass::SuccessorOf, t_successor_of().clone()),
                (AuditClass::DelegatorEndorsement, t_delegator_endorsement().clone()),
                (AuditClass::ConsumptionMarker, t_consumption_marker().clone()),
                (AuditClass::JournalDesignation, t_journal_designation().clone()),
                (AuditClass::RailRecord, t_rail_record().clone()),
                (AuditClass::StewardClassification, t_steward_classification().clone()),
            ],
        )
    });
    &TYPES
}

/// One address-form slot in M7's own deposited form — `enc(addrs)`. The
/// ONE spelling, so [`deposits_credential_link`]'s classification and
/// [`DepositSpans::of`]'s deposit read a type slot through the same call:
/// two of the three readings the obligation on that classifier rests on
/// become one, and only the rebuild's (M7's stored slot) stays separate.
fn addr_spans(addrs: &[Address]) -> Vec<Span> {
    enc(addrs.iter()).spans().cloned().collect()
}

/// A slot's spans in M7's own deposited form: [`addr_spans`] for the
/// address form; `None` for `Resolve` — a resolved slot can never name a
/// credential type (the allocation above), so classification never
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
/// verbatim. The subspace-3 allocation above is what keeps a `Resolve` slot
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
        Op::Emit { ty, .. } => {
            let spans: Vec<Span> = ty.spans().cloned().collect();
            identity_types().kind_of(&spans).is_some()
        }
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
/// `code: credential_refused, disposition: permanent, detail: token()`
/// (AUTH-3.54 — `Permanent` UNIFORMLY; the remedy lives in the face).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CredentialRefusal {
    /// The fold's own verdict — produced by `precheck`, slot (3).
    Inert(Inert),
    /// Slot (1), ahead of the write lock.
    EmitNotMakeLink,
    /// Slot (4).
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
    /// Slot (6).
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
    /// Slot (7), and the plain path's publish gate (RES-26).
    SignedSessionRequired,
    /// Slot (8), and the plain path's pre-claim admission gate (RES-27).
    ClaimFirst,
    /// Slot (8)'s CLAIM arm — the claim's own admission (PUB-6.63, RES-24;
    /// PUB round 2, lane 4.2): the claim is refused where the top-level
    /// account space holds any principal above the genesis floor but the one
    /// this ceremony's own `delegate` minted. Token `claim_residue` — OWNER
    /// CONFIRM OWED (the code is the wire's to name beside `claim_first`;
    /// proposed in the pre-claim tokens' convention). The face is PUB-6.63's
    /// verbatim: "this board carries pre-claim residue — re-genesis before
    /// claiming."
    ClaimResidue,
}

impl CredentialRefusal {
    /// The wire `detail` token: the fold arm delegates to `Inert::token()`
    /// (the payload arm is the one `malformed_payload:<sub>` join,
    /// AUTH-2.55); the daemon-side tokens are hand-spelled here and only
    /// here.
    pub fn token(&self) -> String {
        match self {
            CredentialRefusal::Inert(Inert::MalformedPayload(p)) => {
                format!("malformed_payload:{}", p.token())
            }
            CredentialRefusal::Inert(i) => i.token().to_string(),
            CredentialRefusal::EmitNotMakeLink => "emit_not_make_link".into(),
            CredentialRefusal::UndecodableKey => "undecodable_key".into(),
            CredentialRefusal::NullifyNotRetraction => "nullify_not_retraction".into(),
            CredentialRefusal::NullifyNotRevocation => "nullify_not_revocation".into(),
            CredentialRefusal::NullifyAuditView => "nullify_audit_view".into(),
            CredentialRefusal::AnchorSessionRequired => "anchor_session_required".into(),
            CredentialRefusal::ResolvedFrom => "resolved_from".into(),
            CredentialRefusal::TooManyEnrolled => "too_many_enrolled".into(),
            CredentialRefusal::MintHomeFirst => "mint_home_first".into(),
            CredentialRefusal::MintHomePublic => "mint_home_public".into(),
            CredentialRefusal::SignedSessionRequired => "signed_session_required".into(),
            CredentialRefusal::ClaimFirst => "claim_first".into(),
            CredentialRefusal::ClaimResidue => "claim_residue".into(),
        }
    }
}

// ── op_shape_refusal — slots (1)–(2), lock-free (AUTH-3.4–3.6) ───────────

/// Slots (1) `emit_not_make_link` and (2) `resolved_from`, evaluated (1)
/// then (2), reading the op's OWN slots and nothing else — evaluated
/// beside `deposits_credential_link` and AHEAD of `credential_lock.write()`
/// (AUTH-3.5): a refusal here never takes the write lock.
pub(crate) fn op_shape_refusal(op: &Op) -> Option<CredentialRefusal> {
    match op {
        // (1) — every credential-typed emit, unconditionally: M7's dedup
        // could hand a phantom ack for an act key_set never shows.
        Op::Emit { .. } => Some(CredentialRefusal::EmitNotMakeLink),
        // (2) — a credential deposit whose from OR to entity slot is a
        // Resolve, either of them, regardless of emptiness.
        Op::MakeLink { from, to, .. } => {
            if matches!(from, SlotArg::Resolve(_)) || matches!(to, SlotArg::Resolve(_)) {
                Some(CredentialRefusal::ResolvedFrom)
            } else {
                None
            }
        }
        // (2) — every credential edit_link, unconditionally: the successor
        // endsets are V-spec-only as built (AUTH-3.18's dead rule stands
        // recorded there; the op never reaches deposit construction).
        Op::EditLink { .. } => Some(CredentialRefusal::ResolvedFrom),
        _ => None,
    }
}

// ── nullify_refusal — the NULLIFY class, read lock (AUTH-3.7–3.9; PUB-6.10,
//    PUB-6.30, PUB-6.64 — slot 5's three cells) ─────────────────────────────

/// The NULLIFY class — slot 5's position in [`plain_refusal`]'s order
/// (PUB-6.36 as RES-195 places it): `Some(token)` iff `op` is a `Nullify`
/// whose target's `readlink` type slot the write path's recognition input
/// ([`write_types`]) classifies, AND that class's token is the caller's to
/// receive. The op-kind test is INSIDE and first (one match arm for the
/// common case); `world` MUST be the snapshot taken under the read guard for
/// this request — the guard argument is that contract's cheap half.
///
/// ONE READ SHAPE FOR EVERY CALLER, THE TOKEN CHOSEN LAST (PUB-6.10, extended
/// by lane 3.5 to the two new cells): the target's link and its class are
/// read before entitlement is decided, so the arms are byte- and
/// timing-identical except the token — a non-owner's answer on a classified
/// target is `None` here, the op reaches `execute`, and ω answers `not_owner`
/// exactly as it would for a plain link (occupancy-blind: PUB-6.9's ω-first
/// order stands ahead of `bad_target` in M7's own gate). Three cells:
///
/// * CREDENTIAL-typed (PUB-6.10; RES-32) → `nullify_not_retraction`, the cell
///   lane 3.3c built, its token and scope UNCHANGED: on a CLAIMED board the
///   token reaches only the owner of the `home` the retraction record is
///   filed in; anyone else falls through. (A credential-typed link is never
///   draft-homed — the credential path refuses `unpublished` — so the home
///   test alone admits no occupancy oracle here.)
/// * GRANT-typed (PUB-6.30) → `nullify_not_revocation`: the grant fold reads
///   the AUDIT view (PUB-6.31), so retraction is never a second revocation
///   path — a share is withdrawn by REVOKING it (a superseding grant record,
///   lane 3.3's supersession shape).
/// * AUDIT-VIEW class (PUB-6.64) → `nullify_audit_view`, ONE code for the
///   class list: the honored state is read under the audit view, so a landed
///   retraction would drop the record from the ACTIVE-view reads that serve
///   it (PUB-6.13, PUB-6.20) and make PUB-4.12's "a nullified marker STILL
///   CONSUMES" false. The steward's classification link is a member only
///   where the LINK's OWN HOME is published (RES-207, keyed on the type AND
///   on `published(document_of(target))` — the same read the publish gate
///   takes one slot earlier, no read added); draft-homed it is an ordinary
///   link, admitted.
///
/// THE TWO NEW CELLS' ENTITLEMENT is the caller who could otherwise open the
/// path — M7's own v1 gate mirrored: ω of the record's `home` AND ω of the
/// TARGET (address arithmetic; the target-home owner PUB-6.30 and PUB-6.64
/// name). The target half is load-bearing HERE where it is not at the
/// credential cell: a grant-typed or audit-class link CAN sit in a draft's
/// link subspace (an ordinary `make_link`, nothing refuses it), so a token
/// keyed on the record's home alone would tell a stranger filing from a home
/// of its own which addresses in the draft hold one — the occupancy oracle
/// PUB-6.9 forbids. Pre-claim every producer's answer stands for every
/// caller, but in [`plain_refusal`]'s order the pre-claim admission gate
/// answers `claim_first` ahead of this one (PUB-6.35, PUB-6.36 slot 4 before
/// slot 5), so over the wire a token is reached only once the board is
/// claimed — and once claimed, the publish-class gate's `nullify` row
/// (PUB-6.43) stands ahead too, so a BARE owner's retraction landing in the
/// published world answers `signed_session_required` and never a token here.
pub(crate) fn nullify_refusal(
    _lock: &LockRead<'_>,
    world: &World,
    identity: &IdentityState,
    op: &Op,
    principal: PrincipalId,
) -> Option<CredentialRefusal> {
    let Op::Nullify { home, target } = op else { return None };
    // The same reads for every caller: the target's link, then its class.
    let link = world.links().readlink(target)?;
    let spans: Vec<Span> = link.type_slot().spans().cloned().collect();
    let class = write_types().write_class(&spans)?;
    let m3 = world.m3();
    let claimed = identity.claimant().is_some();
    // The class's own token, chosen before entitlement is consulted — the one
    // arm carrying a second key of its own is the classification link's
    // (RES-207): the LINK's own home published. A resident link's home is
    // registered (M7's HomeNotRegistered gate), so `published()`'s
    // registered-only contract (PUB-6.37) holds on it; draft-homed it is an
    // ordinary link and this producer answers nothing.
    let token = match class {
        WriteClass::Credential(_) => CredentialRefusal::NullifyNotRetraction,
        WriteClass::Grant => CredentialRefusal::NullifyNotRevocation,
        WriteClass::AuditView(AuditClass::StewardClassification)
            if !document_of(target).as_ref().is_some_and(|d| published(world, d)) =>
        {
            return None
        }
        WriteClass::AuditView(_) => CredentialRefusal::NullifyAuditView,
    };
    // THE ENTITLEMENT, once and last, which is what makes "the token chosen
    // last" a fact about this function rather than three copies that agree:
    // ω of the home the record is filed in AND ω of the TARGET (PUB-6.10
    // names the target-home OWNER). Keyed on the record's home alone, a
    // stranger filing from a home of its own would be told the target's
    // class — the occupancy oracle PUB-6.9 forbids.
    if claimed
        && !(m3.is_effective_owner(principal, home) && m3.is_effective_owner(principal, target))
    {
        return None;
    }
    Some(token)
}

// ── mint_home_refusal — the MINT class (AUTH-3.10–3.14) ──────────────────

/// AUTH-3.68's `has_documents(account)`, built over M3's PUBLIC read
/// surface: the account's document chain is empty iff the slot it opens at
/// — `first_document_address(A)` — holds no registered document. Exact
/// because that chain is contiguous from its first ordinal, which is M3's
/// own guarantee and M3's own arithmetic. A subject that anchors no
/// document chain answers `None` there, hence `false` here.
pub(crate) fn has_documents(world: &World, account: &Address) -> bool {
    first_document_address(account)
        .is_some_and(|first| world.m3().is_registered_document(&first))
}

/// `Some(MintHomeFirst)` iff `op` is a document-minting op OTHER than
/// `create_new_document` and the subject account's chain is empty. The
/// subject is `principal_prefix(p)` THEN an account-hood test — never
/// `key_subject` (AUTH-3.11); a subject that is not an account answers
/// `None` and no arm fires. Reads the op's KIND and the PRINCIPAL and
/// nothing else — never a fork/version source (AUTH-3.13).
///
/// `world` MUST be the snapshot taken under the read guard for this
/// request; the guard argument is that contract's cheap half.
pub(crate) fn mint_home_refusal(
    _lock: &LockRead<'_>,
    world: &World,
    op: &Op,
    principal: PrincipalId,
) -> Option<CredentialRefusal> {
    if !matches!(op, Op::Fork { .. } | Op::Version { .. }) {
        return None;
    }
    let subject = world.m3().principal_prefix(principal)?;
    if !world.m3().is_registered_account(subject) {
        return None;
    }
    if has_documents(world, subject) {
        None
    } else {
        Some(CredentialRefusal::MintHomeFirst)
    }
}

// ── first_mint_private_refusal — the first-mint publication door ─────────

/// PUB-8.20 / owner ruling D2c: an account's FIRST `create_new_document`
/// carrying an explicit `published: false` is REFUSED here, at the DAEMON's
/// door — the ONLY place this refusal exists. Its class is PERMANENT.
///
/// The engine is NOT changed to refuse (D2c): `create_new_document` mints a
/// private home for an explicit `Some(false)` (PUB-8.19's letter — a typed
/// `MintError` out of M3's own transaction — is the departure the owner
/// ruled away), so a first mint that reaches M3 with `Some(false)` commits
/// a private document. This producer is what a conforming board puts ahead
/// of it; a build that skips it serves a private "home", inverting PUB-1.17.
///
/// The face the client derives from `mint_home_public`, keyed on the token
/// (PUB-6.7), is PUB-8.20's verbatim (RES-207): "your home page is public
/// from birth — it is where this board keeps your name and your keys; create
/// it first, and every other document you make here is private by default."
///
/// Placed in the mint slot beside [`mint_home_refusal`] (PUB-8.22's seat),
/// so ownership stands AHEAD (PUB-6.36 slot 1): only the account's own owner
/// reaches this refusal — a non-owner falls through to execute's
/// `not_owner`, which never leaks whether the account is empty — and a
/// non-empty account is an ordinary private mint that refuses nothing. A
/// flagless or explicit-`true` first mint is honored, the home born
/// published (PUB-8.21), by this producer answering `None` for it.
///
/// `world` MUST be the snapshot taken under the read guard for this request;
/// the guard argument is that contract's cheap half.
pub(crate) fn first_mint_private_refusal(
    _lock: &LockRead<'_>,
    world: &World,
    op: &Op,
    principal: PrincipalId,
) -> Option<CredentialRefusal> {
    let Op::CreateNewDocument { account, published: Some(false) } = op else {
        return None;
    };
    if world.m3().is_effective_owner(principal, account) && !has_documents(world, account) {
        Some(CredentialRefusal::MintHomePublic)
    } else {
        None
    }
}

// ── board_state_refusal — the two CLAIM-complementary gates (AUTH-3.78) ──

/// The publish gate's publication read — the engine's ONE definition (owner
/// ruling D1, 2026-09-05): `published(trunk_of(doc))`, a membership miss on
/// the exception set (PUB-7.5), after the projection of a version member to
/// its DOCUMENT (PUB-2.15). The projection is M5's `trunk_of` — the ONE
/// spelling of it, shared with the write-path refusals that run one crate
/// below this gate (PUB-8.2, D2b), which is why the daemon's own copy was
/// retired rather than kept beside it. The gate reads `published()` on the
/// document, never on the member: a member's own bit is what its own mint
/// journaled (PUB-8.17's inheritance makes the two agree today; the
/// projection is what keeps the gate exact of the DOCUMENT's state, which is
/// the state the gate is about). The drift sweep's claim-2 defect — doc 1's
/// versions read unpublished under the retired equality compare, so a bare
/// session wrote into them — stays closed, and no interim `prefix_contains`
/// patch ships. The retired `is_published_v1` (a document is published iff
/// it IS its account's doc 1) answered off address arithmetic what the set
/// now answers off M3's bit.
///
/// The AUTH fold reads [`published_unprojected`] — the same membership
/// lookup WITHOUT this projection, which is the one step the two differ by;
/// the fold's own card states the cell where that is observable.
///
/// CONTRACT — `doc` is a REGISTERED document (PUB-6.37): a membership miss
/// is also what an unregistered address answers, so every caller below tests
/// registration first and an unregistered argument takes the registration
/// refusal, never `signed_session_required`.
fn published(world: &World, doc: &Address) -> bool {
    published_unprojected(world, &trunk_of(doc))
}

/// The engine's publication read on ONE address, unprojected: `a ∉
/// exception_set` and nothing else (PUB-7.5) — the AUTH fold's read
/// (AUTH-2.34), reached through [`super::fold::WorldCtx`]'s `is_published`.
/// [`published`] is this after PUB-2.15's version-member projection, so the
/// two share their membership lookup and differ by exactly that step.
pub(super) fn published_unprojected(world: &World, a: &Address) -> bool {
    world.published(a)
}

/// The plain path's one producer for the two board-state gates, dispatched
/// on claimed-ness (AUTH-3.78): once claimed, the public-permanent gate
/// (RES-26, `signed_session_required`); in UNCLAIMED the pre-claim
/// admission gate (RES-27, `claim_first`). Exact under the read guard: the
/// claim commits only under `credential_lock.write()`.
///
/// `world` and `identity` MUST be the pair taken under the read guard for
/// this request; the guard argument is that contract's cheap half.
pub(crate) fn board_state_refusal(
    _lock: &LockRead<'_>,
    world: &World,
    identity: &IdentityState,
    op: &Op,
    principal: PrincipalId,
    signer: Option<&skep_identity::Fingerprint>,
) -> Option<CredentialRefusal> {
    if identity.claimant().is_some() {
        publish_gate(world, op, principal, signer)
    } else {
        pre_claim_gate(world, op, principal)
    }
}

/// RES-26 (AUTH-3.79–3.81): on a claimed board, an op whose write lands in
/// the published world is accepted only from a signed session. Domain per
/// input form (PUB-6.43's input table):
/// * an EXPLICIT flag — the argument itself, resolved pre-dispatch: a
///   `create`/`fork`/`version` carrying `published: Some(true)` publishes,
///   so a bare session is refused; `Some(false)` is a draft (outside). The
///   first mint stays EXEMPT — the content-empty mechanical home (PUB-6.43),
///   so a first `create` with any flag is accepted from a bare session;
/// * a flagless `version` reads `published(d_src)` (INHERIT);
/// * a homed write reads `published(home)` — both through [`published`], the
///   engine's exception set with the version-member projection (PUB-2.15).
///
/// * an `edit_link` reads `published(d_s) ∨ published(d_a)` — it DEPOSITS
///   TWICE, the successor link into `d_s` and the supersession claim into
///   `d_a` (M7's `editlink`: the claim's home is the caller's own `d_a`,
///   never the original's document), and PUB-6.43's row is per DEPOSIT —
///   "each of its two deposits takes the `published(home)` row on ITS OWN
///   home", the record's own home sufficing because supersession lands no
///   effect at the original (PUB-6.22). Registration and ω on BOTH homes
///   stand ahead, mirroring M7's own `home_gate` over the pair (lane 4.2,
///   F1; register cell I3.c, matrix 2.5).
///
/// * a `nullify` reads `published(home) ∨ published(document_of(target))` —
///   PUB-6.43's own row for the one op whose effect and record home part
///   (lane 3.5; RES-3's owed input).
///
/// Flagless `create`/`fork` resolve draft (outside), and
/// `delegate`/`register_node` present no input form here.
///
/// Registration and ω stand AHEAD (PUB-6.37, PUB-6.36 slot 1) on every arm
/// that reads a HOME or a TARGET — the homed writes, `edit_link`'s two
/// homes, `nullify`'s home and `publish`'s document — so an unregistered or
/// foreign address there answers `execute`'s own code and is never told
/// whether it is published. (`nullify`'s TARGET takes ω at the gate and its
/// document's registration one line later, at the publication read that
/// needs it.) The three MINTING arms take something else, each stated on the
/// arm: `create` tests ω of the ACCOUNT, `fork` that the caller HAS one, and
/// `version` registration of the SOURCE alone. An empty-account
/// `fork`/`version` is refused `mint_home_first` before this gate is
/// reached.
///
/// The projection reaches every arm that reads an address: `published(home)`
/// on a version member answers its DOCUMENT's bit, so a member minted
/// `Some(false)` under a published document — PUB-2.7's private-member
/// cell, admitted until the routed write-path item lands (PUB-8.2) — is
/// gated as published, its own journaled bit notwithstanding. The explicit
/// flag on the `version` itself is the argument's own input (row 1 of the
/// table), which is why that mint is admitted from a bare session.
fn publish_gate(
    world: &World,
    op: &Op,
    principal: PrincipalId,
    signer: Option<&skep_identity::Fingerprint>,
) -> Option<CredentialRefusal> {
    if signer.is_some() {
        return None;
    }
    // Registration and ω — the pair that stands AHEAD of this gate (PUB-6.37,
    // PUB-6.36 slot 1) on every HOME and TARGET arm, in ONE spelling, so an
    // arm that means to take the pair cannot take half of it: an address
    // failing either falls through to execute's own code and is never told
    // whether it is published. The three MINTING arms below take something
    // else and each says what.
    let m3 = world.m3();
    let owned = |a: &Address| m3.is_registered_document(a) && m3.is_effective_owner(principal, a);
    let homed_refusal = |home: &Address| -> Option<CredentialRefusal> {
        (owned(home) && published(world, home))
            .then_some(CredentialRefusal::SignedSessionRequired)
    };
    match op {
        // An EXPLICIT `published: true` on a mint IS the gate input
        // (PUB-6.43): it lands in the published world. The first mint stays
        // exempt — a first `create` into an empty account the caller owns is
        // the content-empty mechanical home (PUB-6.43's enumerated
        // exemption), so it answers `None` here (accepted).
        Op::CreateNewDocument { account, published: Some(true) } => {
            if world.m3().is_effective_owner(principal, account) && has_documents(world, account) {
                Some(CredentialRefusal::SignedSessionRequired)
            } else {
                None
            }
        }
        // `fork` mints into the caller's OWN account; an empty account is
        // refused `mint_home_first` ahead of this gate, so only a non-first
        // published fork reaches here.
        Op::Fork { published: Some(true) } => {
            if world.m3().principal_prefix(principal).is_some_and(|pfx| {
                world.m3().is_registered_account(pfx)
            }) {
                Some(CredentialRefusal::SignedSessionRequired)
            } else {
                None
            }
        }
        // `version` with the flag: explicit `true` publishes; `false` is a
        // draft; ABSENT INHERITS `published(d_src)`. Registration stands
        // ahead (PUB-6.37): an unregistered source answers `execute`'s own
        // `source_not_registered`, not this gate.
        //
        // REGISTRATION ALONE, and not the ω beside it that the homed arms
        // take: versioning a FOREIGN document is a legitimate act, so ω of
        // the source is not this gate's to demand, and the gate's question
        // is where the minted member lands, which is `d_src`'s publication
        // whoever owns it. Nothing is disclosed by answering: a published
        // document is readable to every class, so `signed_session_required`
        // here tells a caller what `doc_metadata` already would.
        Op::Version { d_src, published: flag } => {
            if !world.m3().is_registered_document(d_src) {
                None
            } else {
                match flag {
                    Some(true) => Some(CredentialRefusal::SignedSessionRequired),
                    Some(false) => None,
                    None => {
                        if published(world, d_src) {
                            Some(CredentialRefusal::SignedSessionRequired)
                        } else {
                            None
                        }
                    }
                }
            }
        }
        // The SHOT (lane 3.2) is a mint resolving PUBLISHED by definition —
        // every member is published-born (PUB-2.5) — so it is this gate's
        // input whatever the document's own state: on a private document
        // the signed session then meets the store's
        // `private_source_versionless` (slot 5), exactly as a bare
        // `version(d, published:true)` does. Registration and ω stand ahead
        // (PUB-6.37, PUB-6.36 slot 1), as everywhere.
        Op::Publish { doc, .. } => {
            owned(doc).then_some(CredentialRefusal::SignedSessionRequired)
        }
        Op::Insert { doc, .. }
        | Op::Delete { doc, .. }
        | Op::Copy { doc, .. }
        | Op::Rearrange { doc, .. } => homed_refusal(doc),
        Op::MakeLink { home, .. } | Op::Emit { home, .. } | Op::AssertSup { home, .. } => {
            homed_refusal(home)
        }
        // `edit_link` DEPOSITS TWICE (lane 4.2, F1): the successor into
        // `d_s`, the supersession CLAIM into `d_a` — M7's `editlink` files
        // the claim in the caller's own `d_a`, so that, not the original's
        // document, is the claim's home — and PUB-6.43's row is per DEPOSIT,
        // so the gate fires where EITHER deposit lands in a published home.
        // Registration and ω stand AHEAD on BOTH homes (PUB-6.37, PUB-6.36
        // slot 1 — M7's own `home_gate` runs P0 then ω over the pair): a
        // caller owning either alone, or naming an unregistered home, falls
        // through to execute's own code and is never told whether the other
        // home is published. The finding cell: `d_s` a draft, `d_a` the
        // published doc 1, bare — refused here, nothing deposited.
        Op::EditLink { d_s, d_a, .. } => {
            if !(owned(d_s) && owned(d_a)) {
                return None;
            }
            (published(world, d_s) || published(world, d_a))
                .then_some(CredentialRefusal::SignedSessionRequired)
        }
        // PUB-6.43's `nullify` ROW (RES-3; landed with lane 3.5, whose
        // bare-owner cell presupposes it): a retraction LANDS AT ITS TARGET
        // (PUB-6.20), so the gate keys on the target link's home BESIDE the
        // record's — `published(home) ∨ published(document_of(target))`. A
        // draft-homed record against a published-homed link takes the gate
        // exactly as a published-homed write does; a draft-homed record
        // against a draft-homed target stays a bare-writable draft write.
        // Registration and ω stand AHEAD on BOTH addresses (PUB-6.37;
        // PUB-6.9's target ω beside slot 1's home ω — M7's own v1
        // self-retraction gate, mirrored): a caller owning neither, or the
        // home alone, or naming an unregistered home, falls through to
        // execute's own code and is never told whether either is published.
        // `document_of(target)` is address arithmetic (PUB-6.38);
        // `published()` on it takes PUB-6.37's registered-only evaluation.
        // What this row hides behind the gate is occupancy too: a bare
        // owner's `nullify` of an EMPTY address in its published doc 1
        // answers here, never `bad_target`.
        Op::Nullify { home, target } => {
            if !(owned(home) && m3.is_effective_owner(principal, target)) {
                return None;
            }
            let lands_published = published(world, home)
                || document_of(target)
                    .as_ref()
                    .is_some_and(|d| m3.is_registered_document(d) && published(world, d));
            lands_published.then_some(CredentialRefusal::SignedSessionRequired)
        }
        // create/fork with a non-`true` flag: a draft, or the exempt home
        // mint (the explicit-`false` first mint is the door's, upstream).
        _ => None,
    }
}

/// RES-27/27a (AUTH-3.82–3.83): an UNCLAIMED daemon admits only the claim
/// ceremony's own op SHAPES — per op, by shape, no ceremony state machine:
/// the `delegate` from principal 0, the mechanical home mint, and the
/// record atom's `insert` into the depositing account's own doc 1. The
/// credential deposits' pre-claim cells are the precheck's slot (8), never
/// this producer's. Everything else refuses `claim_first`, bare and signed
/// sessions alike.
fn pre_claim_gate(world: &World, op: &Op, principal: PrincipalId) -> Option<CredentialRefusal> {
    let admitted = match op {
        Op::Delegate { .. } => principal == BOOTSTRAP_PRINCIPAL,
        // The ceremony's home mint (flagged or not); an explicit `false`
        // first mint is refused by the door in the mint slot, ahead of this
        // gate, so it never reaches admission.
        Op::CreateNewDocument { account, .. } => !has_documents(world, account),
        Op::Insert { doc, .. } => world
            .m3()
            .principal_prefix(principal)
            .and_then(first_document_address)
            .is_some_and(|first| first == *doc),
        // Fail-CLOSED, which is why this arm may be a wildcard where
        // `deposits_credential_link`'s may not: a new op defaults to
        // `claim_first` and costs its author one decision, rather than
        // defaulting to admission on an unclaimed board.
        _ => false,
    };
    if admitted {
        None
    } else {
        Some(CredentialRefusal::ClaimFirst)
    }
}

// ── claim_residue_refusal — the claim's own admission (PUB-6.63; RES-24) ──

/// PUB-6.63 (PUB-6.35 clause (b); PUB round 2, lane 4.2 — F2): THE CLAIM
/// REFUSES OVER RESIDUE. The claim — the ceremony's step 5 — is admitted
/// ONLY where the TOP-LEVEL account space holds EXACTLY ONE principal minted
/// by `delegate` ABOVE THE GENESIS FLOOR — the one this ceremony's own
/// `delegate` minted — and is refused `claim_residue` otherwise, from every
/// hand, bare and signed alike: unrefused, a second hand's keyed partial
/// (register cell I10.b) or the operator's own abandoned partial beside its
/// lost-state retry (I11.d) survives the claim as a keyed top-level
/// principal no act removes (PUB-1.44, PUB-1.45), inside every ANY-PRINCIPAL
/// grant the board ever issues. The cure is the one PUB-6.63 pins, verbatim
/// in the face: "this board carries pre-claim residue — re-genesis before
/// claiming."
///
/// THE INPUT is the daemon's own top-level frontier, read AT the claim off
/// the snapshot the write guard pinned — the same fact `next_account_prefix`
/// answers principal-free (PUB-6.52), so a door can face the residue ahead
/// of the ceremony's step 1 from the same read. CARDINALITY, never
/// provenance (provenance is AUTH's: the latch, AUTH-3.82/3.83, is what makes
/// the one counted principal claimable by its minter alone). "Top-level" is
/// the claimant's own tier — the node its account was delegated under
/// (`parent`, the same M1 step the fold's delegator test takes; a claim
/// reaching this producer has already passed `claimant_not_top_level`).
///
/// THE FLOOR is what the daemon's own genesis writes seeded, computed from
/// [`World::genesis`] and never hard-coded: every account genesis mints under
/// that node stands BELOW the count. Genesis seeds none today, so the floor
/// is zero and the two frontiers coincide — counted from the live frontier
/// alone, a board whose genesis seeded a top-level account would refuse
/// every honest claim and its named cure would re-seed it (PUB-6.63's own
/// cycle warning).
///
/// Placed at the claim's own admission in the pre-claim path — slot (8)'s
/// CLAIM arm in [`precheck`], behind the fold's verdict (an `already_claimed`
/// or `claimant_keyless` claim never reaches this) and ahead of the claim's
/// `make_link` ever reaching the store — so a refused claim commits nothing
/// and the board stays unclaimed. The honest single-principal ceremony is
/// exactly the admitted case: one top-level principal above the floor.
/// Fail-CLOSED on the two unreachable shapes (an account with no parent, a
/// node with no frontier): a claim whose count cannot be read is refused,
/// which is the spec's direction ("admitted ONLY where … and refused
/// otherwise").
///
/// `world` MUST be the snapshot taken under the write guard for this
/// request — the frontier is read AT the claim, off the snapshot that guard
/// pinned — and the guard argument is that contract's cheap half, as it is
/// on every other producer in this family.
pub(crate) fn claim_residue_refusal(
    _lock: &LockWrite<'_>,
    world: &World,
    account: &Address,
) -> Option<CredentialRefusal> {
    let Some(node) = parent(account) else {
        return Some(CredentialRefusal::ClaimResidue);
    };
    let Some(count) = accounts_under(world, &node) else {
        return Some(CredentialRefusal::ClaimResidue);
    };
    let floor = accounts_under(&World::genesis(), &node).unwrap_or_else(|| Nat::from(0u32));
    if count == floor + Nat::from(1u32) {
        None
    } else {
        Some(CredentialRefusal::ClaimResidue)
    }
}

/// The number of accounts minted under `node`, read off the frontier exactly
/// as `next_account_prefix` publishes it (PUB-6.52): the next delegable
/// prefix under a node is `node·0·(n+1)`, so its ordinal less one is `n`.
/// `None` where the node anchors no account chain — not a registered node,
/// or a frontier whose ordinal is not the positive number that arithmetic
/// needs.
///
/// The ordinal is ≥ 1 twice over: `next_account_prefix` publishes
/// `node·0·(n+1)`, and T4 refuses a trailing zero on every `Address`, which
/// is what `ordinal` reads. CHECKED rather than trusted, because `Nat` is a
/// `BigUint` and its subtraction PANICS on underflow — and this runs under
/// `credential_lock.write()` AND the write-serialization lock, so a zero
/// here would be a 500 on the claim path where a refusal is available.
/// Fail-CLOSED, joining the two unreachable shapes
/// [`claim_residue_refusal`] already refuses: a claim whose count cannot be
/// read is refused.
fn accounts_under(world: &World, node: &Address) -> Option<Nat> {
    let next = world.m3().next_account_prefix(node)?;
    let ord = ordinal(next.tumbler());
    (ord > &Nat::from(0u32)).then(|| ord.clone() - Nat::from(1u32))
}

// ── plain_refusal — the plain path's ordered producers (AUTH-3.35) ───────

/// The plain path's ordered producers: the MINT class — the first-mint
/// publication door then MINT-FIRST — then the CLAIM-complementary board-state
/// pair, then the NULLIFY class. The ORDER is the pin, so it lives here with
/// the producers rather than at the call site — the same treatment
/// [`precheck`] gives the credential path's eight slots.
///
/// [`first_mint_private_refusal`] (PUB-8.20's door) shares the mint slot with
/// [`mint_home_refusal`] and is disjoint from it — the door reads a
/// `create` with an explicit `false`, MINT-FIRST reads a `fork`/`version` —
/// so their relative order is inert; both stand ahead of the board-state
/// pair (PUB-6.36 slot 2 before slot 4), which is why an explicit-`false`
/// home mint answers `mint_home_public` and never the pre-claim
/// `claim_first`.
///
/// The order is PUB-6.36's write-side order as RES-195 places the
/// `nullify` cells: MINT-FIRST is slot 2; the board-state pair stands in
/// slot 4's position (the publish-class gate once claimed, the pre-claim
/// admission gate before); the `nullify` class's three cells — the
/// credential-typed (PUB-6.10), the grant-typed (PUB-6.30) and the
/// audit-view class (PUB-6.64) — take slot 5's position, AFTER the gate and
/// never before it, "a session that may not write here never being told
/// what the target link is". The order is observable on BOTH sides of the
/// claim. Post-claim, since lane 3.5 gave [`publish_gate`] PUB-6.43's
/// `nullify` row: a BARE owner's retraction of a grant record in its own
/// published doc 1 answers `signed_session_required`, never the grant-typed
/// token — the cell the delta pins. Pre-claim: an UNCLAIMED board admits no
/// `nullify` at all, so the admission gate (PUB-6.35; RES-27) answers
/// `claim_first` first and no token is reached, for the home's own owner as
/// for anyone else.
///
/// Re-ordering moves no input: all three are pure functions of the same
/// `(world, identity, op, principal, signer)` under the same guard, and
/// [`mint_home_refusal`] fires only on `fork`/`version`, so its position
/// relative to the `nullify` cell is inert either way.
///
/// `world` and `identity` MUST be the pair taken under the read guard for
/// this request; the guard argument each producer takes is that contract's
/// cheap half.
pub(crate) fn plain_refusal(
    lock: &LockRead<'_>,
    world: &World,
    identity: &IdentityState,
    op: &Op,
    principal: PrincipalId,
    signer: Option<&skep_identity::Fingerprint>,
) -> Option<CredentialRefusal> {
    first_mint_private_refusal(lock, world, op, principal)
        .or_else(|| mint_home_refusal(lock, world, op, principal))
        .or_else(|| board_state_refusal(lock, world, identity, op, principal, signer))
        .or_else(|| nullify_refusal(lock, world, identity, op, principal))
}

// ── precheck — slots (3)–(8), under the write lock (AUTH-3.15–3.19) ──────

/// The owned span form of one would-be deposit, built from the frame
/// VERBATIM (AUTH-3.17): `home` verbatim, `from`/`to`/`ty` as
/// address-form spans via M7's `enc`, in endset order.
pub(crate) struct DepositSpans {
    pub home: Address,
    pub from: Vec<Span>,
    pub to: Vec<Span>,
    pub ty: Vec<Span>,
}

impl DepositSpans {
    /// `Some` only for a `MakeLink` whose three slots are all address-form
    /// — the one op that reaches deposit construction (`Emit` dies at slot
    /// (1), `EditLink` at slot (2), a `Nullify` is `nullify_refusal`'s).
    pub fn of(op: &Op) -> Option<DepositSpans> {
        let Op::MakeLink { home, from, to, ty } = op else { return None };
        let slot = |s: &SlotArg| -> Option<Vec<Span>> {
            match s {
                SlotArg::Addrs(a) => Some(addr_spans(a)),
                SlotArg::Resolve(_) => None,
            }
        };
        Some(DepositSpans {
            home: home.clone(),
            from: slot(from)?,
            to: slot(to)?,
            ty: slot(ty)?,
        })
    }

    pub fn deposit(&self) -> LinkDeposit<'_> {
        LinkDeposit { home: &self.home, from: &self.from, to: &self.to, ty: &self.ty }
    }
}

/// The precheck's answer: the refusal, or nothing. The previewed effect is
/// deliberately NOT returned — the committed tail re-derives from the same
/// deposit under the same guard
/// ([`crate::auth::fold::IdentityFold::step_committed`]), so handing it
/// forward would be a second path to one state change, and a signature
/// that offers it invites exactly that.
///
/// The `Ok` taken at the classify line is AUTH-3.19's defect arm —
/// `NotCredential` there is unreachable by construction (the classifier
/// that chose this path reads the same spans through the same
/// [`addr_spans`]); if reached, this assert fires, the write passes with
/// no slot (4)–(8), and the caller runs the committed tail like any other,
/// where the fold's own step reaches the same `NotCredential` verdict and
/// does not advance — so AUTH-3.19's "no fold feed" holds of the OUTCOME
/// and not of the CALL, and in a debug build `step_committed`'s assert
/// fires second.
///
/// `world` and `identity` MUST be the pair taken under the write guard for
/// this request; the guard argument is that contract's cheap half.
pub(crate) fn precheck(
    lock: &LockWrite<'_>,
    world: &World,
    identity: &IdentityState,
    dep: &DepositSpans,
    signer: Option<&skep_identity::Fingerprint>,
) -> Result<(), CredentialRefusal> {
    // (3) — the classify preview's verdict (AUTH-2.57): the fold's own
    // order — kind, home account, publication, the per-kind arm.
    let verdict = identity.classify(identity_types(), &WorldCtx(world), &dep.deposit());
    let effect = match verdict {
        Verdict::NotCredential => {
            debug_assert!(false, "classify answered NotCredential on a classified deposit");
            return Ok(());
        }
        Verdict::Inert(i) => return Err(CredentialRefusal::Inert(i)),
        Verdict::Honored(e) => e,
    };
    // (4) — undecodable_key: a valid-hex non-point key can never sign; the
    // fold accepts syntax, the daemon extends the courtesy. The decode is
    // the SAME one `super::session::verify` performs, so the courtesy is
    // exact rather than an approximation of it. It is BOUNDED by
    // [`MAX_DECODED_KEYS`] — the discipline [`crate::codec`]'s `room`
    // states, applied to the one slot whose input this module cannot cap.
    //
    // CONSEQUENCE: a record that is BOTH over-cap and carries an
    // undecodable key past [`MAX_DECODED_KEYS`] answers `too_many_enrolled`
    // where the slot order alone would say `undecodable_key`. The boundary
    // is the SCAN's and not slot (5)'s: the scan reaches one key past the
    // cap slot (5) applies, so an undecodable key AT that one-past position
    // is still seen and still answers `undecodable_key`. It is refused
    // either way, permanently, in the same vocabulary and by the same
    // function; what changes is which of two true things it is told.
    let keys_decodable = |keys: &[skep_identity::Enrolled]| {
        keys.iter().take(MAX_DECODED_KEYS).all(|e| super::verifying_key(&e.key).is_some())
    };
    match &effect {
        Effect::Enroll { added, .. } if !keys_decodable(added) => {
            return Err(CredentialRefusal::UndecodableKey)
        }
        Effect::Genesis { keys, .. } if !keys_decodable(keys) => {
            return Err(CredentialRefusal::UndecodableKey)
        }
        _ => {}
    }
    // (5) — the enrolled-set cap (RES-57): Enroll arm only, Genesis exempt
    // from the SET's cap.
    if let Effect::Enroll { account, added } = &effect {
        if identity.key_set(account).enrolled().count() + added.len() > MAX_ENROLLED_KEYS {
            return Err(CredentialRefusal::TooManyEnrolled);
        }
    }
    // (5, second arm) — the seeding hand's own record ([`MAX_GENESIS_KEYS`]):
    // a different quantity from the set's cap, and the one every signed
    // handshake attempt walks. Refused in the SAME vocabulary, which is
    // honest for it and adds no wire code.
    if let Effect::Genesis { keys, .. } = &effect {
        if keys.len() > MAX_GENESIS_KEYS {
            return Err(CredentialRefusal::TooManyEnrolled);
        }
    }
    // (6) — the anchor gate (AUTH-3.20–3.23): an anchor retirement or a
    // post-genesis anchor-flagged enrollment needs a session an anchor of
    // that account established; a bare session never satisfies it; the
    // record is refused WHOLE. Genesis is exempt (the seeding hand records
    // the initial set, flags included).
    let anchor_subject = match &effect {
        Effect::Retire { account, removed } => {
            let set = identity.key_set(account);
            removed.iter().any(|fp| set.is_anchor(fp)).then_some(account)
        }
        Effect::Enroll { account, added } => {
            added.iter().any(|e| e.anchor).then_some(account)
        }
        _ => None,
    };
    if let Some(account) = anchor_subject {
        let set = identity.key_set(account);
        if !signer.is_some_and(|fp| set.is_anchor(fp)) {
            return Err(CredentialRefusal::AnchorSessionRequired);
        }
    }
    // (7)/(8) — the claim-disjoint board-state slots.
    let claimed = identity.claimant().is_some();
    if claimed {
        // (7) — arm-blind: Genesis is NOT exempt here; a bare genesis
        // plant on a claimed board dies at this slot.
        if signer.is_none() {
            return Err(CredentialRefusal::SignedSessionRequired);
        }
    } else {
        // (8) — the pre-claim admission gate's deposit cell, evaluated on
        // the slot-(3) preview: only the ceremony's own deposits pass — and
        // the claim passes only where its OWN admission admits it
        // (PUB-6.63's residue test, [`claim_residue_refusal`]): behind the
        // fold's verdict, ahead of the store, so a refused claim commits
        // nothing and the board stays unclaimed.
        match &effect {
            Effect::Genesis { .. } => {}
            Effect::Claim { account } => {
                if let Some(r) = claim_residue_refusal(lock, world, account) {
                    return Err(r);
                }
            }
            _ => return Err(CredentialRefusal::ClaimFirst),
        }
    }
    Ok(())
}

/// The five reserved subtree spans overlap nothing the credential types
/// name: the identity types live in subspace 3 while the shipped classes
/// sit at content positions 1..=5 — pinned so a change to either
/// allocation fails here rather than in a fold.
#[cfg(test)]
mod tests {
    use skep_address::subtree_of;

    use super::*;

    #[test]
    fn identity_types_are_distinct_and_recognized() {
        let types = identity_types();
        let enroll_span = subtree_of(addr_of(&T_ENROLL).tumbler());
        assert_eq!(types.kind_of(&[enroll_span]), Some(CredentialKind::Enroll));
        let retire_span = subtree_of(addr_of(&T_RETIRE).tumbler());
        assert_eq!(types.kind_of(&[retire_span]), Some(CredentialKind::Retire));
        let claim_span = subtree_of(addr_of(&T_CLAIM).tumbler());
        assert_eq!(types.kind_of(&[claim_span]), Some(CredentialKind::Claim));
        // A shipped reserved type (ghost position 1, the content subspace)
        // is NOT a credential type.
        let retired = subtree_of(addr_of(&[1, 1, 0, 1, 0, 1, 0, 1, 1]).tumbler());
        assert_eq!(types.kind_of(&[retired]), None);
    }

    /// PUB-2.15's projection is address arithmetic and total: a version
    /// member answers its document, a document answers itself, a member of
    /// a member peels to the same document — and off the document tier the
    /// arithmetic changes nothing (an account has no document field; an
    /// element's field is its document's own). The projection the gate
    /// reads is M5's, so this pins the ONE spelling the daemon shares with
    /// the write path.
    #[test]
    fn a_version_member_projects_to_its_document() {
        let doc = addr_of(&[1, 0, 1, 0, 1]);
        assert_eq!(trunk_of(&doc), doc, "a document is its own trunk");
        assert_eq!(trunk_of(&addr_of(&[1, 0, 1, 0, 1, 1])), doc, "a version");
        assert_eq!(trunk_of(&addr_of(&[1, 0, 1, 0, 1, 1, 2])), doc, "a version of a version");
        let acct = addr_of(&[1, 0, 1]);
        assert_eq!(trunk_of(&acct), acct);
        let element = addr_of(&[1, 0, 1, 0, 1, 0, 1, 1]);
        assert_eq!(trunk_of(&element), element);
    }

    /// AUTH-3.70's conformance expression in miniature: a content-I-span
    /// type slot answers no credential kind — a resolved span's start is a
    /// mintable content position, never a subspace-3 name.
    #[test]
    fn a_content_span_ty_is_never_credential() {
        // Content position 1 of some ordinary doc: <doc>.0.1.1.
        let content = subtree_of(addr_of(&[1, 0, 1, 0, 1, 0, 1, 1]).tumbler());
        assert_eq!(identity_types().kind_of(&[content]), None);
    }

    /// The write path's input as wired (lane 3.5 §1): every pinned class
    /// address classifies to its own arm, the credential kinds answer through
    /// the same input as `kind_of` does, the edition class is NO class
    /// (PUB-6.32 — its owner's retraction is admitted), and a content span
    /// is nothing. The wiring itself — the `LazyLock` constructing without
    /// the prefix-free assertion firing — is what the first call proves.
    #[test]
    fn the_write_path_input_recognizes_every_pinned_class() {
        let types = write_types();
        let unit = |a: &Address| vec![subtree_of(a.tumbler())];
        assert_eq!(
            types.write_class(&unit(&addr_of(&T_ENROLL))),
            Some(WriteClass::Credential(CredentialKind::Enroll))
        );
        assert_eq!(types.write_class(&unit(t_grant())), Some(WriteClass::Grant));
        for (class, addr) in [
            (AuditClass::SuccessorOf, t_successor_of()),
            (AuditClass::DelegatorEndorsement, t_delegator_endorsement()),
            (AuditClass::ConsumptionMarker, t_consumption_marker()),
            (AuditClass::JournalDesignation, t_journal_designation()),
            (AuditClass::RailRecord, t_rail_record()),
            (AuditClass::StewardClassification, t_steward_classification()),
        ] {
            assert_eq!(
                types.write_class(&unit(addr)),
                Some(WriteClass::AuditView(class)),
                "{} is {class:?}",
                addr.tumbler()
            );
        }
        // The edition class (3.14) is read under the ACTIVE view: no class.
        assert_eq!(types.write_class(&unit(skep_engine::types::t_edition())), None);
        // A content I-span names nothing here either.
        let content = subtree_of(addr_of(&[1, 0, 1, 0, 1, 0, 1, 1]).tumbler());
        assert_eq!(types.write_class(&[content]), None);
        // A subtype by prefix is its class's member (L10): `endorse.trust`.
        let trust = addr_of(&[1, 1, 0, 1, 0, 1, 0, 3, 42, 2]);
        assert_eq!(
            types.write_class(&unit(&trust)),
            Some(WriteClass::AuditView(AuditClass::DelegatorEndorsement))
        );
    }
}
