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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone, Copy)]
pub struct LinkDeposit<'a> {
    /// The link's home document.
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
/// applies it paired with `kind_of` (AUTH-2.28, AUTH-2.112). An I2 frozen
/// rule (AUTH-2.90).
pub fn single_address(slot: &[Span]) -> Option<Address> {
    let [span] = slot else { return None };
    let addr = validate(span.start().clone()).ok()?;
    if classify_spans(span, &subtree_of(addr.tumbler())) == SpanRel::Equal {
        Some(addr)
    } else {
        None
    }
}
