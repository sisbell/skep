//! The plain sequence's admission (AUTH-3.35).
//!
//! It holds its ordered producers ([`plain_admission`]) — the mint class, the
//! `replaces` class's fence, the claim-complementary board-state pair and the
//! nullify class — with the publish-class classification (PUB-6.43) the pair
//! reads and the type-recognition input the nullify class reads.

use std::sync::LazyLock;

use skep_address::{document_of, Address};
use skep_arrangement::{trunk_of, Caller, Deposit};
use skep_engine::types::{
    t_binding, t_consumption_marker, t_endorse, t_grant, t_journal_designation, t_policy_link,
    t_rail_record, t_replaces, t_steward_classification, t_successor_of, t_takedown,
    IDENTITY_TYPES,
};
use skep_febe::Op;
use skep_identity::{AuditClass, Fingerprint, HasIdentity, TargetClass, WriteTypes};
use skep_kernel::Attestation;
use skep_links::{enc, is_replaces_class, HasLinks, SlotArg};
use skep_namespace::{
    first_document_address, system_account, HasM3, PrincipalId, BOOTSTRAP_PRINCIPAL,
};

use super::attestation::attestation_check;
use super::{addr_spans, record_deposit_kind, registry_deposit_kind, CredentialRefusal};
use crate::auth::LockRead;
use skep_engine::World;

/// Returns the write path's type-recognition input (PUB-6.30, PUB-6.64).
///
/// It is the input PUB-kickoff D3 names: [`IDENTITY_TYPES`]'s sibling, the
/// same three credential kinds (a clone of the engine's one frozen
/// instance, so the fold and the write path cannot disagree about a
/// credential), widened beside them by the grants class and PUB-6.64's
/// audit-view members. Read by [`nullify_refusal`] alone; the fold and
/// `deposits_credential_link` read [`IDENTITY_TYPES`] (`kind_of`, the I2
/// rule, takes none of these classes — a class here is never a credential
/// there).
///
/// The class addresses are the engine's commons pins (`skep_engine::types`):
/// the grant `3.90`, `successor-of` `3.59`, `endorse` `3.42`, the consumption
/// marker `3.91`, the journal designation `3.22`, the rail record `3.60`, the
/// steward's classification link `3.61` — each cited to its commons row
/// there — the `replaces` link `3.12` (PUB-5.15, RES-310), and the
/// registry's three audit-view kinds (REG-1.44, REG-1.46: "adds members to
/// that class list and no code") — the binding `3.55`, the takedown record
/// `3.57` and the policy link `3.58`, each at its kind's address so every
/// subtype row under the last two is a member by prefix (REG-1.21); the
/// endpoint `3.56` is not listed, read on the active view with its org's own
/// `nullify` effective (REG-1.11). Adding a member of PUB-6.64's class is one
/// `AuditClass` arm and one address in this list; the refusal that reads
/// them takes no edit. The list order is the recognition order and every
/// address is pairwise prefix-free.
///
/// # Panics
///
/// Panics at the first call where `WriteTypes::new` refuses the list: it
/// asserts, once, here, that every audit-view class has an address, that no
/// class address is a credential type, and that the addresses are pairwise
/// prefix-free.
fn write_types() -> &'static WriteTypes {
    static TYPES: LazyLock<WriteTypes> = LazyLock::new(|| {
        WriteTypes::new(
            IDENTITY_TYPES.clone(),
            t_grant().clone(),
            [
                (AuditClass::SuccessorOf, t_successor_of().clone()),
                (AuditClass::DelegatorEndorsement, t_endorse().clone()),
                (AuditClass::ConsumptionMarker, t_consumption_marker().clone()),
                (AuditClass::JournalDesignation, t_journal_designation().clone()),
                (AuditClass::RailRecord, t_rail_record().clone()),
                (AuditClass::StewardClassification, t_steward_classification().clone()),
                (AuditClass::Replaces, t_replaces().clone()),
                (AuditClass::Binding, t_binding().clone()),
                (AuditClass::TakedownRecord, t_takedown().clone()),
                (AuditClass::PolicyLink, t_policy_link().clone()),
            ],
        )
    });
    &TYPES
}

// ── nullify_refusal — the nullify class, read lock (AUTH-3.7–3.9; PUB-6.10,
//    PUB-6.30, PUB-6.64 — slot 5's three cells) ─────────────────────────────

/// Answers the nullify class (PUB-6.36 as RES-195 places it).
///
/// It holds slot 5's position in [`plain_admission`]'s order: `Some(token)`
/// iff `op` is a `Nullify` whose target's `readlink` type slot the write
/// path's recognition input ([`write_types`]) classifies, *and* that class's
/// token is the caller's to receive. The op-kind test is inside and first
/// (one match arm for the common case).
///
/// **Precondition.** `world` must be the snapshot taken under the read guard
/// for this request — the guard argument is that contract's cheap half.
///
/// **One read shape for every caller, the token chosen last** (PUB-6.10,
/// extended to the grant and audit-view cells): the target's link and its
/// class are read before entitlement is decided, so the arms are byte- and
/// timing-identical except the token — a non-owner's answer on a classified
/// target is `None` here, the op reaches `execute`, and ω answers `not_owner`
/// exactly as it would for a plain link (occupancy-blind: PUB-6.9's ω-first
/// order stands ahead of `bad_target` in M7's own gate). Three cells:
///
/// * credential-typed (PUB-6.10; RES-32) → `nullify_not_retraction`: on a
///   claimed board the token reaches only the owner of both the `home` the
///   retraction record is filed in and the target; anyone else falls
///   through. (A credential-typed link is never draft-homed — the credential
///   path refuses `unpublished` — so the home test alone admits no occupancy
///   oracle here.)
/// * grant-typed (PUB-6.30) → `nullify_not_revocation`: the grant fold reads
///   the audit view (PUB-6.31), so retraction is never a second revocation
///   path — a share is withdrawn by *revoking* it (a superseding grant
///   record, in the supersession shape).
/// * audit-view class (PUB-6.64) → `nullify_audit_view`, one code for the
///   class list: the honored state is read under the audit view, so a landed
///   retraction would drop the record from the active-view reads that serve
///   it (PUB-6.13, PUB-6.20) and make PUB-4.12's "a nullified marker still
///   consumes" false — and, at the `replaces` link a grant is deposited with
///   (PUB-5.15), would leave every active-view read of the pair naming the
///   empty state for a grant that named a revocation, the replay the link
///   closes re-opened to every reader that folds off those reads. The
///   steward's classification link is a member only where the link's own
///   home is published (RES-207, keyed on the type *and* on
///   `published(document_of(target))` — the same read the publish-class
///   gate takes one slot earlier, no read added); draft-homed it is an
///   ordinary link, admitted.
///
/// **The grant and audit-view cells' entitlement** is the caller who could
/// otherwise open the path — M7's own v1 gate mirrored: ω of the record's
/// `home` and ω of the target — ω over the target link's own address, a
/// read of Π that needs no `readlink` and is never address arithmetic; the
/// target-home owner PUB-6.30 and PUB-6.64 name. The target half is
/// load-bearing here where it is not at the credential cell: a grant-typed
/// or audit-class link *can* sit in a draft's link subspace (an ordinary
/// `make_link`, nothing refuses it), so a token keyed on the record's home
/// alone would tell a stranger filing from a home of its own which addresses
/// in the draft hold one — the occupancy oracle PUB-6.9 forbids. Pre-claim
/// every producer's answer stands for every caller, but in
/// [`plain_admission`]'s order the pre-claim admission gate answers
/// `claim_first` ahead of this one (PUB-6.35, PUB-6.36 slot 4 before slot
/// 5), so over the wire a token is reached only once the board is claimed —
/// and once claimed, the publish-class gate's `nullify` row (PUB-6.43)
/// stands ahead too, so a bare owner's retraction landing in the published
/// world answers `signed_session_required` and never a token here.
fn nullify_refusal(
    _lock: &LockRead<'_>,
    world: &World,
    op: &Op,
    principal: PrincipalId,
) -> Option<CredentialRefusal> {
    let Op::Nullify { home, target } = op else { return None };
    // The same reads for every caller: the target's link, then its class.
    let link = world.links().readlink(target)?;
    let class = write_types().target_class(link.type_slot())?;
    let m3 = world.m3();
    let claimed = world.identity().claimant().is_some();
    // The class's own token, chosen before entitlement is consulted — the arm
    // carrying a second key of its own is a home-conditional class's (RES-207,
    // `AuditClass::requires_published_home` — the classification link
    // alone): the link's own home published. A resident link's home is
    // registered (M7's HomeNotRegistered gate), so `published()`'s
    // registered-only contract (PUB-6.37) holds on it; draft-homed it is an
    // ordinary link and this producer answers nothing.
    let token = match class {
        TargetClass::Credential(_) => CredentialRefusal::NullifyNotRetraction,
        TargetClass::Grant => CredentialRefusal::NullifyNotRevocation,
        TargetClass::AuditView(audit_class)
            if audit_class.requires_published_home()
                && !document_of(target).as_ref().is_some_and(|d| published(world, d)) =>
        {
            return None
        }
        TargetClass::AuditView(_) => CredentialRefusal::NullifyAuditView,
    };
    // The entitlement, once and last, which is what makes "the token chosen
    // last" a fact about this function rather than three copies that agree:
    // ω of the home the record is filed in and ω of the target (PUB-6.10
    // names the target-home owner). Keyed on the record's home alone, a
    // stranger filing from a home of its own would be told the target's
    // class — the occupancy oracle PUB-6.9 forbids.
    if claimed
        && !(m3.is_effective_owner(principal, home) && m3.is_effective_owner(principal, target))
    {
        return None;
    }
    Some(token)
}

// ── mint_home_refusal — the mint class (AUTH-3.10–3.14) ──────────────────

/// Answers the mint class's refusal, `mint_home_first`.
///
/// `Some(MintHomeFirst)` iff `op` is a `fork` or a `version` — a
/// document-minting op other than `create_new_document` — and the subject
/// account's chain is empty — AUTH-3.68's `has_documents(account)`, which is
/// M3's own read of its document chain. The subject is `principal_prefix(p)`
/// *then* an account-hood test — never `key_subject` (AUTH-3.11); a subject
/// that is not an account answers `None` and no arm fires. Reads the op's
/// kind and the principal and nothing else — never a fork/version source
/// (AUTH-3.13).
///
/// **Precondition.** `world` must be the snapshot taken under the read guard
/// for this request; the guard argument is that contract's cheap half.
fn mint_home_refusal(
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
    if world.m3().has_documents(subject) {
        None
    } else {
        Some(CredentialRefusal::MintHomeFirst)
    }
}

// ── first_mint_private_refusal — the first-mint publication door ─────────

/// Refuses an account's first `create_new_document` with `published: false`.
///
/// It is refused here (PUB-8.20 / PUB-kickoff D2c), at the daemon's door —
/// the only place this refusal exists. Its class is permanent.
///
/// The engine does not refuse it (PUB-kickoff D2c): `create_new_document`
/// mints a private home for an explicit `Some(false)` (not PUB-8.19's
/// letter, a typed `MintError` out of M3's own transaction), so a first mint
/// that reaches M3 with `Some(false)` commits a private document. This
/// producer is what a conforming board puts ahead of it; a build that skips
/// it serves a private "home", inverting PUB-1.17.
///
/// The face the client derives from `mint_home_public`, keyed on the token
/// (PUB-6.7), is PUB-8.20's verbatim (RES-207): "your home page is public
/// from birth — it is where this board keeps your name and your keys; create
/// it first, and every other document you make here is private by default."
///
/// Placed in the mint slot beside [`mint_home_refusal`] (PUB-8.22's seat),
/// so ownership stands ahead (PUB-6.36 slot 1): only the account's own owner
/// reaches this refusal — a non-owner falls through to execute's
/// `not_owner`, which never leaks whether the account is empty — and a
/// non-empty account is an ordinary private mint that refuses nothing. A
/// flagless or explicit-`true` first mint is honored, the home born
/// published (PUB-8.21), by this producer answering `None` for it.
///
/// **Precondition.** `world` must be the snapshot taken under the read guard
/// for this request; the guard argument is that contract's cheap half.
fn first_mint_private_refusal(
    _lock: &LockRead<'_>,
    world: &World,
    op: &Op,
    principal: PrincipalId,
) -> Option<CredentialRefusal> {
    let Op::CreateNewDocument { account, published: Some(false) } = op else {
        return None;
    };
    if world.m3().is_effective_owner(principal, account) && !world.m3().has_documents(account) {
        Some(CredentialRefusal::MintHomePublic)
    } else {
        None
    }
}

// ── replaces_refusal — the `replaces` class's sole-writer fence (PUB-5.15) ──

/// Answers the `replaces` type's one-writer fence (PUB-5.15).
///
/// The fence is RES-309's, its code RES-310's: `Some(ReplacesNotStandalone)`
/// iff `op` is a link write whose own type slot lands in the `replaces`
/// class — a `make_link`'s `ty`, an `emit`'s, an `edit_link` successor's —
/// and `principal` owns every home it would deposit into. The class's one
/// writer is the `make_link` that carries the `replaces` member, which mints
/// the link beside its record in the record's own transaction; a link of the
/// class deposited by itself would sit where the grant fold reads a record's
/// pair and name a state for a record whose signed bytes named none. The
/// class test is M7's own, [`skep_links::is_replaces_class`], asked of the
/// slot the store would deposit — `enc(addrs)` for the address form, and
/// nothing for a `Resolve` slot, which resolves to content and never names
/// the class — so this refusal and the store's own fence fall on the same
/// slots, and the wire answers `replaces_not_standalone` where the store
/// would have answered `dc_violation`. A `replaces`-typed write is never a
/// credential deposit, so the fence is the plain sequence's alone.
///
/// **Its place in the write order** (PUB-5.15: its "place in the write
/// path's order" is owed at the build): in the plain path's admission, after
/// the mint class — which reads no link write, so the two are disjoint — and
/// *ahead* of the board-state pair: the pre-claim gate, the publish-class
/// gate and the write-path check behind it. So the home's owner is told the
/// act is never admitted before being asked to claim, to sign, or to attach
/// an attestation it could only spend on a refusal. And *after* the
/// destination's registration and ω, as PUB-6.36 puts the destination's
/// `not_owner` first everywhere: a caller who does not own every home the
/// write names — an `edit_link` names two — answers `None` here and meets
/// `execute`'s own `home_not_registered` or `not_owner`, M7's home gate
/// running ahead of its own fence exactly so. What the refusal discloses is
/// the op's own shape, to the one caller whose write it is.
///
/// **Precondition.** `world` must be the snapshot taken under the read guard
/// for this request; the guard argument is that contract's cheap half.
fn replaces_refusal(
    _lock: &LockRead<'_>,
    world: &World,
    op: &Op,
    principal: PrincipalId,
) -> Option<CredentialRefusal> {
    let in_class = |slot: &SlotArg| match slot {
        SlotArg::Addrs(addrs) => is_replaces_class(&enc(addrs.iter())),
        SlotArg::Resolve(_) => false,
    };
    let (replaces_typed, homes): (bool, Vec<&Address>) = match op {
        Op::MakeLink { home, ty, .. } => (in_class(ty), vec![home]),
        Op::Emit { home, ty, .. } => (is_replaces_class(ty), vec![home]),
        Op::EditLink { successor, d_s, d_a, .. } => (in_class(&successor.ty), vec![d_s, d_a]),
        _ => return None,
    };
    if !replaces_typed {
        return None;
    }
    let m3 = world.m3();
    homes
        .into_iter()
        .all(|home| Caller::Principal(principal).passes_ownership_gate(m3, home))
        .then_some(CredentialRefusal::ReplacesNotStandalone)
}

// ── board_state_admission — the two claim-complementary gates (AUTH-3.78) ─

/// Returns the publish-class gate's publication read of `doc` (PUB-kickoff D1).
///
/// It is the engine's one definition: `published(trunk_of(doc))`, a
/// membership miss on the exception set (PUB-7.5), after the projection of a
/// version member to its document (PUB-2.15). The projection is M5's
/// `trunk_of` — the one spelling of it, shared with the write-path refusals
/// that run one crate below this gate (PUB-8.2, PUB-kickoff D2b), so the
/// daemon keeps no copy of its own. The gate reads `published()` on the
/// document, never on the member: a member's own bit is what its own mint
/// journaled (PUB-8.17's inheritance makes the two agree; the projection is
/// what keeps the gate exact of the document's state, which is the state the
/// gate is about). So doc 1's versions read published and a bare session
/// cannot write into them; the read is the set's, off M3's bit, and never
/// address arithmetic — neither a `prefix_contains` test nor a document read
/// as published because it *is* its account's doc 1.
///
/// The AUTH fold — the engine's, through its `FoldCtx for World` (AUTH-2.34)
/// — reads the same lookup *without* this projection, the one step the two
/// differ by; the fold's own card states the cell where that is observable.
///
/// **Precondition.** `doc` is a registered document (PUB-6.37): a membership
/// miss is also what an unregistered address answers, so every caller below
/// tests registration first and an unregistered argument takes the
/// registration refusal, never `signed_session_required`.
fn published(world: &World, doc: &Address) -> bool {
    world.published(&trunk_of(doc))
}

/// Answers the plain path's admission at the two board-state gates (AUTH-3.78).
///
/// It is dispatched on claimed-ness: once claimed, the publish-class gate
/// (RES-26 — PUB's section "The public-permanent gate" —
/// `signed_session_required`) and — behind it, on the same classification
/// (signed ops; the design record §4.5 (1)–(2), §5.5) — the write-path
/// check; unclaimed, the pre-claim admission gate (RES-27, `claim_first`).
/// Exact under the read guard: the claim commits only under
/// `credential_lock.write()`.
///
/// **The answer is what reaches the store.** `Ok(Some(a))` is an attestation
/// the check verified, to be written into this write's marker slot;
/// `Ok(None)` is a write that reaches the store with the marker slot empty —
/// no `attest` demanded, or one dropped, never verified and never written:
/// off the publish class (signed-ops D1); on the unclaimed board (A5: the
/// ceremony's own span, where an `attest` a cautious client attached could
/// verify under no key); on the claimed board where the check stands aside
/// — outside the checked set, at a credential record deposit's atom
/// (signed-ops D26: the record's own `sig` is its carrier), at a
/// system-owned home (A3); and where the check passes an attested write
/// through to a store refusal no signature changes (`attestation_check`'s
/// doc item 6), where nothing commits. The marker slot's producer set is
/// stated here in code: a dispatched publish-class write above the claim
/// whose presented `attest` this admission verified, and nothing else —
/// which holds because the codec hands the member over *beside* the request
/// and not inside it (`DaemonOp::Febe`'s `presented`), so the plain
/// sequence's assignment of this answer is `Request::attest`'s one writer.
/// The member arrives by value and leaves as the answer or not at all: what
/// the check admits is the presented `Attestation` itself, moved into
/// `Ok(Some(_))`, and every arm that drops it drops it here — so the
/// admitted value is the presented one by construction, not by a copy that
/// must match it.
///
/// **Precondition.** `world` must be the snapshot taken under the read guard
/// for this request — the key table it reads is that snapshot's own slice;
/// the guard argument is that contract's cheap half.
///
/// # Errors
///
/// On a claimed board, `signed_session_required` for a publish-class write
/// from a bare session, then the write-path check's refusals
/// ([`attestation_check`]); on an unclaimed board, the pre-claim gate's
/// `system_account_keyless` or `claim_first` ([`pre_claim_gate`]).
fn board_state_admission(
    _lock: &LockRead<'_>,
    world: &World,
    op: &Op,
    principal: PrincipalId,
    signer: Option<&Fingerprint>,
    presented: Option<Attestation>,
) -> Result<Option<Attestation>, CredentialRefusal> {
    if world.identity().claimant().is_some() {
        // A1: the check runs on a claimed board — every write reaching this
        // arm is above the claim entry, the claim having committed before
        // the snapshot it reads was taken.
        if !publish_class(world, op, principal) {
            return Ok(None);
        }
        if signer.is_none() {
            return Err(CredentialRefusal::SignedSessionRequired);
        }
        attestation_check(world, op, principal, presented)
    } else {
        // A5: the unclaimed board's span — the `attest` is dropped whole.
        match pre_claim_gate(world, op, principal) {
            Some(r) => Err(r),
            None => Ok(None),
        }
    }
}

/// Returns whether the write is publish-class for this caller (RES-26).
///
/// On a claimed board (AUTH-3.79–3.81), an op whose write lands in the
/// published world is accepted only from a signed session — and is where the
/// write-path check runs (`board_state_admission`). This is the
/// classification oracle (PUB-6.43, the daemon's own). Domain per input form
/// (PUB-6.43's input table):
/// * an explicit flag — the argument itself, resolved pre-dispatch: a
///   `create`/`fork`/`version` carrying `published: Some(true)` publishes,
///   so a bare session is refused; `Some(false)` is a draft (outside). The
///   first mint stays exempt — the content-empty mechanical home (PUB-6.43),
///   so a first `create` with any flag is accepted from a bare session;
/// * a flagless `version` reads `published(d_src)` (inherit);
/// * a homed write reads `published(home)` — both through [`published`], the
///   engine's exception set with the version-member projection (PUB-2.15).
///
/// * an `edit_link` reads `published(d_s) ∨ published(d_a)` — it deposits
///   twice, the successor link into `d_s` and the supersession claim into
///   `d_a` (M7's `editlink`: the claim's home is the caller's own `d_a`,
///   never the original's document), and PUB-6.43's row is per deposit —
///   "each of its two deposits takes the `published(home)` row on its own
///   home", the record's own home sufficing because supersession lands no
///   effect at the original (PUB-6.22). Registration and ω on both homes
///   stand ahead, mirroring M7's own `home_gate` over the pair.
///
/// * a `nullify` reads `published(home) ∨ published(document_of(target))` —
///   PUB-6.43's own row for the one op whose effect and record home part
///   (RES-3's owed input).
///
/// Flagless `create`/`fork` resolve draft (outside), and
/// `delegate`/`register_node` present no input form here.
///
/// Registration and ω stand ahead (PUB-6.37, PUB-6.36 slot 1) on every arm
/// that reads a home or a target — the homed writes, `edit_link`'s two
/// homes, `nullify`'s home and `publish`'s document — so an unregistered or
/// foreign address there answers `execute`'s own code and is never told
/// whether it is published. (`nullify`'s target takes ω at the gate and its
/// document's registration one line later, at the publication read that
/// needs it.) The three minting arms take something else, each stated on the
/// arm: `create` tests ω of the account, `fork` that the caller *has* one,
/// and `version` registration of the source alone. An empty-account
/// `fork`/`version` is refused `mint_home_first` before this gate is
/// reached.
///
/// The projection reaches every arm that reads an address: `published(home)`
/// on a version member answers its document's bit, so a member minted
/// `Some(false)` under a published document — PUB-2.7's private-member
/// cell, which the write path refuses (PUB-8.2) and a fold can reach — is
/// gated as published, its own journaled bit notwithstanding. The explicit
/// flag on the `version` itself is the argument's own input (row 1 of the
/// table), which is why that mint is admitted from a bare session.
fn publish_class(world: &World, op: &Op, principal: PrincipalId) -> bool {
    // Registration and ω — the pair that stands ahead of this gate (PUB-6.37,
    // PUB-6.36 slot 1) on every home and target arm, in one spelling, the
    // store's own ownership-gate question (M5's
    // `Caller::passes_ownership_gate`), so an arm that means to take the pair
    // cannot take half of it: an address failing either falls through to
    // execute's own code and is never told whether it is published. The three
    // minting arms below take something else and each says what.
    let m3 = world.m3();
    let owned = |a: &Address| Caller::Principal(principal).passes_ownership_gate(m3, a);
    let homed = |home: &Address| -> bool { owned(home) && published(world, home) };
    match op {
        // An explicit `published: true` on a mint *is* the gate input
        // (PUB-6.43): it lands in the published world. The first mint stays
        // exempt — a first `create` into an empty account the caller owns is
        // the content-empty mechanical home (PUB-6.43's enumerated
        // exemption), so it answers `false` here (accepted).
        Op::CreateNewDocument { account, published: Some(true) } => {
            world.m3().is_effective_owner(principal, account) && world.m3().has_documents(account)
        }
        // `fork` mints into the caller's own account; an empty account is
        // refused `mint_home_first` ahead of this gate, so only a non-first
        // published fork reaches here.
        Op::Fork { published: Some(true) } => world
            .m3()
            .principal_prefix(principal)
            .is_some_and(|pfx| world.m3().is_registered_account(pfx)),
        // `version` with the flag: explicit `true` publishes; `false` is a
        // draft; absent inherits `published(d_src)`. Registration stands
        // ahead (PUB-6.37): an unregistered source answers `execute`'s own
        // `source_not_registered`, not this gate.
        //
        // Registration alone, and not the ω beside it that the homed arms
        // take: versioning a foreign document is a legitimate act, so ω of
        // the source is not this gate's to demand, and the gate's question
        // is where the minted member lands, which is `d_src`'s publication
        // whoever owns it. Nothing is disclosed by answering: a published
        // document is readable to every class, so `signed_session_required`
        // here tells a caller what `doc_metadata` already would.
        Op::Version { d_src, published: flag } => {
            world.m3().is_registered_document(d_src)
                && match flag {
                    Some(true) => true,
                    Some(false) => false,
                    None => published(world, d_src),
                }
        }
        // The shot is a mint resolving published by definition — every
        // member is published-born (PUB-2.5) — so it is this gate's
        // input whatever the document's own state: on a private document
        // the signed session then meets the store's
        // `private_source_versionless` (slot 5), exactly as a bare
        // `version(d, published:true)` does. Registration and ω stand ahead
        // (PUB-6.37, PUB-6.36 slot 1), as everywhere.
        Op::Publish { doc, .. } => owned(doc),
        // The five in-place edits (PUB-2.11): the write by identity among
        // them — a re-placement into an owned published document lands in
        // the published world exactly as a `copy` into it would.
        Op::Insert { doc, .. }
        | Op::Delete { doc, .. }
        | Op::Copy { doc, .. }
        | Op::Reinstate { doc, .. }
        | Op::Rearrange { doc, .. } => homed(doc),
        Op::MakeLink { home, .. } | Op::Emit { home, .. } | Op::AssertSup { home, .. } => {
            homed(home)
        }
        // `edit_link` deposits twice: the successor into `d_s`, the
        // supersession claim into `d_a` — M7's `editlink` files the claim in
        // the caller's own `d_a`, so that, not the original's document, is
        // the claim's home — and PUB-6.43's row is per deposit, so the gate
        // fires where *either* deposit lands in a published home.
        // Registration and ω stand ahead on both homes (PUB-6.37, PUB-6.36
        // slot 1 — M7's own `home_gate` runs P0 then ω over the pair): a
        // caller owning either alone, or naming an unregistered home, falls
        // through to execute's own code and is never told whether the other
        // home is published. So with `d_s` a draft and `d_a` the published
        // doc 1, a bare session is refused here and nothing is deposited.
        Op::EditLink { d_s, d_a, .. } => {
            owned(d_s) && owned(d_a) && (published(world, d_s) || published(world, d_a))
        }
        // PUB-6.43's `nullify` row (RES-3): a retraction lands at its target
        // (PUB-6.20), so the gate keys on the target link's home beside the
        // record's — `published(home) ∨ published(document_of(target))`. A
        // draft-homed record against a published-homed link takes the gate
        // exactly as a published-homed write does; a draft-homed record
        // against a draft-homed target stays a bare-writable draft write.
        // Registration and ω stand ahead on both addresses (PUB-6.37;
        // PUB-6.9's target ω beside slot 1's home ω — M7's own v1
        // self-retraction gate, mirrored): a caller owning neither, or the
        // home alone, or naming an unregistered home, falls through to
        // execute's own code and is never told whether either is published.
        // `document_of(target)` is address arithmetic (PUB-6.38);
        // `published()` on it takes PUB-6.37's registered-only evaluation.
        // What this row hides behind the gate is occupancy too: a bare
        // owner's `nullify` of an empty address in its published doc 1
        // answers here, never `bad_target`.
        Op::Nullify { home, target } => {
            owned(home)
                && m3.is_effective_owner(principal, target)
                && (published(world, home)
                    || document_of(target)
                        .as_ref()
                        .is_some_and(|d| m3.is_registered_document(d) && published(world, d)))
        }
        // create/fork with a non-`true` flag: a draft, or the exempt home
        // mint (the explicit-`false` first mint is the door's, upstream).
        _ => false,
    }
}

/// Answers the pre-claim admission gate (RES-27/27a; AUTH-3.82–3.83).
///
/// An unclaimed daemon admits only the claim ceremony's own op shapes — per
/// op, by shape, no ceremony state machine: the `delegate` from principal
/// 0, the mechanical home mint, and an `insert` into the depositing
/// account's own doc 1 — the record atom's shape, admitted by its address
/// whatever it carries — but never a record atom into the system account's
/// (SO-I2 (g)(iv)): a declared record-kind `insert` — a credential kind's,
/// or a registry kind's (REG-1.32: the system account's doc 1 takes no
/// registry record either, the only registry rows below the claim being the
/// seeded pins) — into `1.1.0.1`'s doc 1 is refused `system_account_keyless`,
/// since that account holds no key and the plant it would seed is the one
/// `claim_residue` cannot count. The credential deposits' pre-claim cells
/// are the precheck's slot (8), never this producer's. Everything else
/// refuses `claim_first`, bare and signed sessions alike.
fn pre_claim_gate(world: &World, op: &Op, principal: PrincipalId) -> Option<CredentialRefusal> {
    let admitted = match op {
        Op::Delegate { .. } => principal == BOOTSTRAP_PRINCIPAL,
        // The ceremony's home mint (flagged or not); an owner's explicit
        // `false` first mint is refused by the door in the mint slot, ahead
        // of this gate, so it never reaches admission — a non-owner's falls
        // through to `execute`'s `not_owner`.
        Op::CreateNewDocument { account, .. } => !world.m3().has_documents(account),
        Op::Insert { doc, deposit, .. } => {
            let own_doc_one = world
                .m3()
                .principal_prefix(principal)
                .and_then(first_document_address)
                .is_some_and(|first| first == *doc);
            let record_kind = match deposit {
                Deposit::Declared(ty) => {
                    let slot = addr_spans(std::slice::from_ref(ty));
                    record_deposit_kind(&slot).is_some() || registry_deposit_kind(&slot).is_some()
                }
                Deposit::Undeclared => false,
            };
            if own_doc_one
                && record_kind
                && world.m3().effective_owner_prefix(doc) == Some(&system_account())
            {
                return Some(CredentialRefusal::SystemAccountKeyless);
            }
            own_doc_one
        }
        // Fail-closed, which is why this arm may be a wildcard where
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

// ── plain_admission — the plain path's ordered producers (AUTH-3.35) ─────

/// Runs the plain path's admission: its producers, in their pinned order.
///
/// The order is the pin, so it lives here with the producers rather than at
/// the call site — the same treatment [`precheck`](super::precheck) gives
/// the credential path's slots (3)–(8).
///
/// `first_mint_private_refusal` (PUB-8.20's door) shares the mint slot with
/// `mint_home_refusal` and is disjoint from it — the door reads a
/// `create` with an explicit `false`, mint-first reads a `fork`/`version` —
/// so their relative order is inert; both stand ahead of the board-state
/// pair (PUB-6.36 slot 2 before slot 4), which is why an explicit-`false`
/// home mint answers `mint_home_public` and never the pre-claim
/// `claim_first`.
///
/// The order is PUB-6.36's write-side order as RES-195 places the
/// `nullify` cells: mint-first is slot 2; the board-state pair stands in
/// slot 4's position (the publish-class gate once claimed, the pre-claim
/// admission gate before); the `nullify` class's three cells — the
/// credential-typed (PUB-6.10), the grant-typed (PUB-6.30) and the
/// audit-view class (PUB-6.64) — take slot 5's position, *after* the gate
/// and never before it, "a session that may not write here never being told
/// what the target link is". The order is observable on both sides of the
/// claim. Post-claim, `publish_class` holds PUB-6.43's `nullify` row, so a
/// bare owner's retraction of a grant record in its own published doc 1
/// answers `signed_session_required`, never the grant-typed token — the
/// cell `nullify_class.rs` pins. Pre-claim: an unclaimed board admits no
/// `nullify` at all, so the admission gate (PUB-6.35; RES-27) answers
/// `claim_first` first and no token is reached, for the home's own owner as
/// for anyone else.
///
/// Re-ordering moves no input: all three are pure functions of the same
/// `(world, op, principal, signer)` — the board-state pair's of the
/// presented attestation too — under the same guard, and
/// `mint_home_refusal` fires only on `fork`/`version`, so its position
/// relative to the `nullify` cell is inert either way.
///
/// **The `replaces` fence's place** is this build's (PUB-5.15 leaves it
/// owed): it reads link writes alone, so it is disjoint from the mint class
/// and its position against that class is inert; it stands ahead of the
/// board-state pair, so a write that can never be admitted is refused as
/// such before the pair asks its owner to claim, to sign or to attach an
/// attestation; and it answers the owner of every home the write names
/// alone, so PUB-6.36's destination `not_owner` still stands first for
/// everyone else, at `execute`.
///
/// **Precondition.** `world` must be the snapshot taken under the read guard
/// for this request; the guard argument each producer takes is that
/// contract's cheap half.
///
/// # Errors
///
/// The order is the mint class — the first-mint publication door's
/// `mint_home_public`, then mint-first's `mint_home_first`; then the
/// `replaces` class's fence, `replaces_not_standalone` (`replaces_refusal`,
/// PUB-5.15); then the claim-complementary board-state pair
/// (`board_state_admission`); then the nullify class (`nullify_refusal`).
///
/// Named an admission and not a refusal because both sides of its answer
/// are load-bearing: `Err` is the refusal the first producer to fire names,
/// and `Ok` carries the attestation the write-path check verified — the
/// value this write's commit marker will hold — or `None`. The `*_refusal`
/// producers it composes answer `Option<CredentialRefusal>` and nothing on
/// success.
pub fn plain_admission(
    lock: &LockRead<'_>,
    world: &World,
    op: &Op,
    principal: PrincipalId,
    signer: Option<&Fingerprint>,
    presented: Option<Attestation>,
) -> Result<Option<Attestation>, CredentialRefusal> {
    if let Some(r) = first_mint_private_refusal(lock, world, op, principal) {
        return Err(r);
    }
    if let Some(r) = mint_home_refusal(lock, world, op, principal) {
        return Err(r);
    }
    if let Some(r) = replaces_refusal(lock, world, op, principal) {
        return Err(r);
    }
    // The board-state pair — and, inside its claimed arm, the write-path
    // check (signed ops), whose admitted attestation is this function's
    // answer. It stands ahead of the `nullify` class, so a signed `nullify`
    // into the published world is judged by the check first —
    // `attestation_required` with no `attest`, its signature verified with
    // one — and its class token speaks last: a session that may not write
    // here is never told what the target link is.
    let admitted = board_state_admission(lock, world, op, principal, signer, presented)?;
    if let Some(r) = nullify_refusal(lock, world, op, principal) {
        return Err(r);
    }
    Ok(admitted)
}

#[cfg(test)]
mod tests {
    use skep_address::subtree_of;
    use skep_identity::CredentialKind;

    use skep_engine::types::t_enroll;

    use super::*;
    use crate::auth::policy::addr_of;

    /// Checks that PUB-2.15's projection is address arithmetic and total.
    ///
    /// A version member answers its document, a document answers itself, a
    /// member of a member peels to the same document — and off the document
    /// tier the arithmetic changes nothing (an account has no document field;
    /// an element's field is its document's own). The projection the gate
    /// reads is M5's, so this pins the one spelling the daemon shares with the
    /// write path.
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

    /// Checks the write path's input as wired.
    ///
    /// Every pinned class address classifies to its own arm, the credential
    /// kinds answer through the same input as `kind_of` does, the edition
    /// class is *no* class (PUB-6.32 — its owner's retraction is admitted),
    /// and a content span is nothing. The wiring itself — the `LazyLock`
    /// constructing without the prefix-free assertion firing — is what the
    /// first call proves.
    #[test]
    fn the_write_path_input_recognizes_every_pinned_class() {
        let types = write_types();
        let unit = |a: &Address| vec![subtree_of(a.tumbler())];
        assert_eq!(
            types.target_class(&unit(t_enroll())),
            Some(TargetClass::Credential(CredentialKind::Enroll))
        );
        assert_eq!(types.target_class(&unit(t_grant())), Some(TargetClass::Grant));
        for (class, addr) in [
            (AuditClass::SuccessorOf, t_successor_of()),
            (AuditClass::DelegatorEndorsement, t_endorse()),
            (AuditClass::ConsumptionMarker, t_consumption_marker()),
            (AuditClass::JournalDesignation, t_journal_designation()),
            (AuditClass::RailRecord, t_rail_record()),
            (AuditClass::StewardClassification, t_steward_classification()),
            (AuditClass::Replaces, t_replaces()),
            (AuditClass::Binding, t_binding()),
            (AuditClass::TakedownRecord, t_takedown()),
            (AuditClass::PolicyLink, t_policy_link()),
        ] {
            assert_eq!(
                types.target_class(&unit(addr)),
                Some(TargetClass::AuditView(class)),
                "{} is {class:?}",
                addr.tumbler()
            );
        }
        // The registry's subtype rows are their kinds' members by prefix
        // (REG-1.21); the endpoint is no class at all (REG-1.11, REG-1.46).
        for (class, addr) in [
            (AuditClass::TakedownRecord, skep_engine::types::t_takedown_lifted()),
            (AuditClass::PolicyLink, skep_engine::types::t_disavowal()),
            (AuditClass::PolicyLink, skep_engine::types::t_succession_policy()),
        ] {
            assert_eq!(types.target_class(&unit(addr)), Some(TargetClass::AuditView(class)));
        }
        assert_eq!(types.target_class(&unit(skep_engine::types::t_endpoint())), None);
        // The edition class (3.14) is read under the active view: no class.
        assert_eq!(types.target_class(&unit(skep_engine::types::t_edition())), None);
        // A content I-span names nothing here either.
        let content = subtree_of(addr_of(&[1, 0, 1, 0, 1, 0, 1, 1]).tumbler());
        assert_eq!(types.target_class(&[content]), None);
        // A subtype by prefix is its class's member (L10): `endorse.trust`.
        let trust = addr_of(&[1, 1, 0, 1, 0, 1, 0, 3, 42, 2]);
        assert_eq!(
            types.target_class(&unit(&trust)),
            Some(TargetClass::AuditView(AuditClass::DelegatorEndorsement))
        );
    }
}
