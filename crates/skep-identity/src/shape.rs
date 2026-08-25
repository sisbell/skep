//! Shape recognition — AUTH-2.20–2.28.

use skep_address::{classify_spans, subtree_of, validate, Address, Span, SpanRel};

/// AUTH-2.20 — the three credential kinds a link's type slot can name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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
/// (AUTH-2.90), and a mirror must fix ONE address form for it (AUTH-2.125).
#[derive(Clone)]
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
    pub fn new(enroll: Address, retire: Address, claim: Address) -> TypeAddrs {
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
    /// `classify_spans`) to one of the three precomputed spans: one length
    /// check and at most three span comparisons. Any other arity, and any
    /// overlap class other than `Equal` (`Containment` included), answers
    /// `None`. An I2 frozen rule (AUTH-2.90).
    pub fn kind_of(&self, ty: &[Span]) -> Option<CredentialKind> {
        let [span] = ty else { return None };
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
/// build it, neither inventing a field: the engine hook
/// (`home = document_of(addr)`, computed once — AUTH-2.82) and skepd's
/// precheck (the frame's `home`). Address-form slots are constructed via
/// M7's `enc` on ALL THREE slots (AUTH-2.24); `from` is in ENDSET ORDER and
/// stays that way — no constructor may sort, dedup, or normalize it
/// (AUTH-2.25).
pub struct LinkDeposit<'a> {
    /// The link's home document.
    pub home: &'a Address,
    /// The FROM endset — the record's spans, in endset order (AUTH-2.3).
    pub from: &'a [Span],
    /// The TO endset.
    pub to: &'a [Span],
    /// The type slot.
    pub ty: &'a [Span],
}

/// AUTH-2.26 — `Some(A)` iff the slot is exactly one span `Equal` to
/// `subtree_of(its start)`, `None` otherwise. Governs both kinds' `to` and
/// the claim's `from`; it is NOT applied to enroll/retire's `from` in either
/// direction (AUTH-2.27 — non-emptiness plus the per-span home check are
/// that slot's whole rule). `pub` so every discovery caller applies it
/// paired with `kind_of` (AUTH-2.28, AUTH-2.112). An I2 frozen rule
/// (AUTH-2.90).
pub fn single_address(slot: &[Span]) -> Option<Address> {
    let [span] = slot else { return None };
    let addr = validate(span.start().clone()).ok()?;
    if classify_spans(span, &subtree_of(addr.tumbler())) == SpanRel::Equal {
        Some(addr)
    } else {
        None
    }
}
