//! Shape recognition — AUTH-2.20–2.28: the fold's credential kinds, the
//! one-address slot rule, and the fold's view of a deposit.

use skep_address::{classify_spans, subtree_of, validate, Address, Span, SpanRel};

/// AUTH-2.20 — the three credential kinds a link's type slot can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialKind {
    /// An enrollment record (`ty = {T_enroll}`).
    Enroll,
    /// A retirement record (`ty = {T_retire}`).
    Retire,
    /// The board claim (`ty = {T_claim}`).
    Claim,
}

/// AUTH-2.20 — the three credential type addresses with their precomputed
/// `subtree_of(T)` unit-subtree spans. All fields private, no reader outside
/// [`TypeAddrs::kind_of`]. The engine constructs its one `IDENTITY_TYPES`
/// from the commons-seeding constants via [`TypeAddrs::new`] (AUTH-2.79);
/// the exact three addresses are OPEN (AUTH-7.1) and this crate is
/// parametric over them — `IDENTITY_TYPES` itself is an I2 frozen constant
/// (AUTH-2.90), and a mirror must fix ONE address form for it (AUTH-2.125):
/// the agreement `PartialEq` exists to let a cross-mirror test state, since
/// AUTH-2.20's field list leaves no reader to compare through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeAddrs {
    // The addresses, kept per AUTH-2.20's field list; nothing reads them
    // outside `kind_of`'s precomputed spans, hence the allows.
    #[allow(dead_code)]
    enroll: Address,
    #[allow(dead_code)]
    retire: Address,
    #[allow(dead_code)]
    claim: Address,
    enroll_span: Span,
    retire_span: Span,
    claim_span: Span,
}

impl TypeAddrs {
    /// AUTH-2.21 — precomputes the three `subtree_of(T)` unit-subtree spans
    /// ONCE, so [`TypeAddrs::kind_of`] allocates nothing of its own on the
    /// fold hook (span comparison allocation, if any, is M1's — AUTH-2.107).
    ///
    /// PRECONDITION — the three addresses are PAIRWISE DISTINCT.
    /// [`TypeAddrs::kind_of`] answers the FIRST span a `ty` is `Equal` to, in
    /// the declared order enroll · retire · claim, so a repeat makes the
    /// LATER kind UNREACHABLE — `kind_of` never answers it, for any `ty`.
    /// With `claim == enroll` every board claim folds as an enrollment
    /// instead, is refused for the shape an enrollment has not got (a
    /// claim's `to` is empty, so `malformed_shape`), and the board can never
    /// be claimed. That is the CALLER's bug — the engine wires ONE
    /// `IDENTITY_TYPES` from three distinct commons-seeding constants
    /// (AUTH-2.79) — so it stops here rather than travelling as a value. The
    /// assertion is unconditional: this runs once at construction, off the
    /// fold path AUTH-2.57 governs.
    pub fn new(enroll: Address, retire: Address, claim: Address) -> TypeAddrs {
        assert!(
            enroll != retire && enroll != claim && retire != claim,
            "TypeAddrs::new: the three credential type addresses must be \
             pairwise distinct (AUTH-2.20); a repeat shadows a whole kind"
        );
        let enroll_span = subtree_of(enroll.tumbler());
        let retire_span = subtree_of(retire.tumbler());
        let claim_span = subtree_of(claim.tumbler());
        TypeAddrs {
            enroll,
            retire,
            claim,
            enroll_span,
            retire_span,
            claim_span,
        }
    }

    /// AUTH-2.22 — `Some` iff `ty` is EXACTLY ONE span that is `Equal` (M1
    /// `classify_spans`) to one of the three precomputed spans: an arity
    /// check and at most three span comparisons. Any other arity, and any
    /// `SpanRel` other than `Equal` (`Containment` included), answers `None`.
    /// An I2 frozen rule (AUTH-2.90).
    ///
    /// `ty` is any borrowed walk of the slot — a slice, or M7's `&Endset` as
    /// the store holds it — and the arity check takes at most two steps of
    /// it, so no caller copies a slot to have it classified.
    pub fn kind_of<'s>(&self, ty: impl IntoIterator<Item = &'s Span>) -> Option<CredentialKind> {
        let span = sole_span(ty)?;
        if classify_spans(span, &self.enroll_span) == SpanRel::Equal {
            return Some(CredentialKind::Enroll);
        }
        if classify_spans(span, &self.retire_span) == SpanRel::Equal {
            return Some(CredentialKind::Retire);
        }
        if classify_spans(span, &self.claim_span) == SpanRel::Equal {
            return Some(CredentialKind::Claim);
        }
        None
    }
}

/// AUTH-2.23 — the fold's view of one link deposit. Exactly TWO constructors
/// build it, neither inventing a field: the fold hook
/// (`home = document_of(addr)`, computed once — AUTH-2.82; the engine's in
/// the spec's cast, skepd's canonical rebuild as built) and skepd's precheck
/// (the frame's `home`). Address-form slots are constructed via M7's `enc`
/// on ALL THREE slots (AUTH-2.24); `from` is in ENDSET ORDER and stays that
/// way — no constructor may sort, dedup, or normalize it (AUTH-2.25).
///
/// PRECONDITION — `home` is a REGISTERED DOCUMENT, the only home M7's gate
/// admits a link into. Both halves are the constructor's, and the fold checks
/// neither. DOCUMENT level: [`record_bytes`](crate::record_bytes) and the
/// home pin compare `home` against document addresses, so at any other level
/// every span refuses and no deposit passes the pin. REGISTERED: item 3 of
/// [`IdentityState::classify`](crate::IdentityState::classify) asks
/// [`FoldCtx::is_published`](crate::FoldCtx::is_published) of it — a BIRTH
/// state, which only a registered document has — and the fold has no way to
/// test registration first: the seam carries no such fact (AUTH-2.31's four),
/// and ω answers an unallocated address as readily as a minted one (M3), so
/// item 2 screens nothing out. The fold hook has both halves from
/// `document_of` of a link M7 admitted; skepd's precheck takes the frame's
/// `home` as sent, before M7 runs, and owes both ahead of `classify`. Outside
/// the precondition no verdict is specified: the seam's answer outside its
/// domain decides which refusal speaks.
#[derive(Debug, Clone, Copy)]
pub struct LinkDeposit<'a> {
    /// The link's home — a REGISTERED document (the PRECONDITION above).
    pub home: &'a Address,
    /// The FROM slot — the record's spans, in ENDSET ORDER (AUTH-2.3).
    pub from: &'a [Span],
    /// The TO slot — read by [`single_address`] (AUTH-2.26).
    pub to: &'a [Span],
    /// The TYPE slot — read by [`TypeAddrs::kind_of`] (AUTH-2.22).
    pub ty: &'a [Span],
}

/// AUTH-2.26 — `Some(A)` iff the slot is exactly ONE span whose start
/// VALIDATES to an address `A` (M1 `validate`) and which is `Equal` (M1
/// `classify_spans`) to `subtree_of(A)`; `None` otherwise, and the answer is
/// that validated start. The validity clause is NOT implied by the other
/// two: `subtree_of` takes a tumbler and `classify_spans` compares
/// endpoints, so neither consults T4 — a span may be `Equal` to
/// `subtree_of(its start)` with a T4-INVALID start (adjacent zeros, say),
/// and such a slot answers `None`, never a panic (AUTH-2.57). Governs both
/// kinds' `to` and the claim's `from`; it is NOT applied to enroll/retire's
/// `from` in either direction (AUTH-2.27 — non-emptiness plus the per-span
/// home check are that slot's whole rule). `pub` so every discovery caller
/// applies it paired with `kind_of` (AUTH-2.28, AUTH-2.112). The write path
/// reads a TYPE slot through it too
/// ([`WriteTypes::target_class`](crate::WriteTypes::target_class)), outside
/// the fold. `slot` is a borrowed walk of the slot, as on
/// [`TypeAddrs::kind_of`]. An I2 frozen rule (AUTH-2.90).
pub fn single_address<'s>(slot: impl IntoIterator<Item = &'s Span>) -> Option<Address> {
    let span = sole_span(slot)?;
    let addr = validate(span.start().clone()).ok()?;
    if classify_spans(span, &subtree_of(addr.tumbler())) == SpanRel::Equal {
        Some(addr)
    } else {
        None
    }
}

/// The slot's ONE span, or `None` for every other arity — the arity half
/// AUTH-2.22 and AUTH-2.26 share, decided in at most two steps of the walk,
/// so no slot is counted, collected or copied to be refused.
pub(crate) fn sole_span<'s>(slot: impl IntoIterator<Item = &'s Span>) -> Option<&'s Span> {
    let mut spans = slot.into_iter();
    match (spans.next(), spans.next()) {
        (Some(span), None) => Some(span),
        _ => None,
    }
}
