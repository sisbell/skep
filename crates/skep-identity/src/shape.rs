//! Shape recognition — AUTH-2.20–2.28 — and, beside the fold's credential
//! kinds, the WRITE PATH's wider type-recognition input (PUB-6.30,
//! PUB-6.64; owner ruling D3, 2026-09-05): [`WriteTypes`]/[`WriteClass`].

use skep_address::{classify_spans, is_prefix, subtree_of, validate, Address, Span, SpanRel};

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

// ── the write path's wider recognition input (PUB-6.30, PUB-6.64; D3) ─────

/// PUB-6.64's MEMBERS — the record classes whose HONORED STATE the
/// publication spec reads under the AUDIT view, so a `nullify` of one clears
/// nothing and is refused at the write path. The list is the members' list
/// and never the boundary: the next audit-view class is one arm here and one
/// address at [`WriteTypes::new`], with no edit to the rule that reads them.
/// WHICH address names each class is the caller's to supply (the commons
/// ledger's numbers, pinned in the engine) — this crate is parametric over
/// them exactly as it is over the three credential addresses (AUTH-7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditClass {
    /// The succession pair's `successor-of` claim (PUB-7.63).
    SuccessorOf,
    /// The succession pair's delegator endorsement — the `endorse` type
    /// (PUB-7.63).
    DelegatorEndorsement,
    /// The consumption marker (PUB-4.12): a nullified marker STILL CONSUMES.
    ConsumptionMarker,
    /// The journal designation (PUB-4.12): a nullified designation still
    /// designates.
    JournalDesignation,
    /// The rail record (PUB-5.76), inheriting on PUB-6.30's ground.
    RailRecord,
    /// The steward's classification link (PUB-5.43) — a member only where its
    /// HOME is published (RES-207, PUB-6.64). This classifier answers the
    /// TYPE half; the home half is the caller's, off a read it already has.
    StewardClassification,
}

/// The write path's answer for one type slot (owner ruling D3): the class a
/// `nullify`'s target belongs to. `None` from [`WriteTypes::write_class`] is
/// an ORDINARY link — the R20 edition claim among them (PUB-6.32: read under
/// the ACTIVE view, so its owner's retraction clears the state its faces read
/// and is ADMITTED).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WriteClass {
    /// A credential type — exactly [`TypeAddrs::kind_of`]'s answer
    /// (AUTH-2.22; PUB-6.10's cell).
    Credential(CredentialKind),
    /// The GRANTS class (PUB-6.30): retraction is never a second revocation
    /// path — a share is withdrawn by REVOKING it.
    Grant,
    /// A class read under the audit view (PUB-6.64).
    AuditView(AuditClass),
}

/// One class address with its precomputed `subtree_of(T)` unit span — the
/// shape [`TypeAddrs`] keeps per credential kind, kept here per class.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ClassAddr {
    addr: Address,
    span: Span,
}

impl ClassAddr {
    fn new(addr: Address) -> ClassAddr {
        let span = subtree_of(addr.tumbler());
        ClassAddr { addr, span }
    }

    /// AUTH-2.22's discipline, plus L10: `span` is `Equal` to the precomputed
    /// `subtree_of(T)` — the class itself — or is the unit subtree span of a
    /// SUBTYPE, an address under `T` by tumbler prefix (`3.42.1` is an
    /// `endorse`; commons-map.md's standing rule: "hierarchy is prefix — one
    /// subtree span matches a type and its subtypes"). Any other overlap
    /// class — a span across the type's subtree, a span containing it — is no
    /// member: the subtype path admits only a span `Equal` to the subtree of
    /// its own T4-VALID start ([`single_address`]'s test).
    fn admits(&self, span: &Span) -> bool {
        if classify_spans(span, &self.span) == SpanRel::Equal {
            return true;
        }
        single_address(std::slice::from_ref(span))
            .is_some_and(|a| is_prefix(self.addr.tumbler(), a.tumbler()))
    }
}

/// The WRITE PATH's type-recognition input (PUB-6.30, PUB-6.64; owner ruling
/// D3, 2026-09-05): the fold's three credential kinds — [`TypeAddrs`],
/// UNCHANGED, still the one authority the fold reads — WIDENED beside them by
/// the GRANTS class and PUB-6.64's audit-view classes, for the ONE question
/// the write path asks that the fold does not: which refusal a `nullify`'s
/// target class earns. Constructed once by the daemon from the credential
/// types it already holds and the class addresses the engine pins; nothing
/// here is fold state (AUTH-2.90's I2 rule is `kind_of`'s alone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteTypes {
    credential: TypeAddrs,
    grant: ClassAddr,
    audit: Vec<(AuditClass, ClassAddr)>,
}

impl WriteTypes {
    /// Assemble the input: the credential kinds (answered FIRST — a
    /// credential type is never also a class), then the grant, then the
    /// audit-view classes in the order given. Precomputes every
    /// `subtree_of(T)` once, so [`WriteTypes::write_class`] allocates only
    /// on the subtype path.
    ///
    /// PRECONDITION — the class addresses are PAIRWISE PREFIX-FREE and none
    /// is a credential type. [`WriteTypes::write_class`] answers the FIRST
    /// class a slot is a member of, in the declared order, so a class
    /// address under another's prefix (or equal to it) would make the LATER
    /// class UNREACHABLE for every slot — the same mis-wiring
    /// [`TypeAddrs::new`] refuses, refused the same way: a panic at
    /// construction, off every request path, since the addresses are the
    /// engine's compiled constants and never a value a record can carry.
    pub fn new(
        credential: TypeAddrs,
        grant: Address,
        audit: impl IntoIterator<Item = (AuditClass, Address)>,
    ) -> WriteTypes {
        let audit: Vec<(AuditClass, ClassAddr)> =
            audit.into_iter().map(|(class, addr)| (class, ClassAddr::new(addr))).collect();
        let grant = ClassAddr::new(grant);
        {
            let classes: Vec<&ClassAddr> =
                std::iter::once(&grant).chain(audit.iter().map(|(_, c)| c)).collect();
            for (i, a) in classes.iter().enumerate() {
                assert!(
                    credential.kind_of(std::slice::from_ref(&a.span)).is_none(),
                    "WriteTypes::new: class address {} is a credential type address \
                     (AUTH-2.20); the credential kinds answer first, so the class would be \
                     unreachable",
                    a.addr.tumbler()
                );
                for b in &classes[i + 1..] {
                    assert!(
                        !is_prefix(a.addr.tumbler(), b.addr.tumbler())
                            && !is_prefix(b.addr.tumbler(), a.addr.tumbler()),
                        "WriteTypes::new: class addresses {} and {} are prefix-related; the \
                         later class would be unreachable for every slot (the class addresses \
                         must be pairwise prefix-free)",
                        a.addr.tumbler(),
                        b.addr.tumbler()
                    );
                }
            }
        }
        WriteTypes { credential, grant, audit }
    }

    /// The fold's own three kinds — the SAME instance the fold reads, so a
    /// caller holding a `WriteTypes` need not carry the `TypeAddrs` beside it.
    pub fn credential(&self) -> &TypeAddrs {
        &self.credential
    }

    /// The write path's classification of a type slot: `Some` iff `ty` is
    /// EXACTLY ONE span that names a class — a credential type by
    /// [`TypeAddrs::kind_of`]'s frozen rule (`Equal` to the type's own
    /// subtree, no subtypes), else the grant or an audit-view class by
    /// [`ClassAddr::admits`] (`Equal` to the class's subtree, or the unit
    /// subtree span of a subtype under it by prefix), first match in the
    /// declared order. Any other arity, and any slot naming no class, answers
    /// `None`: an ordinary link.
    pub fn write_class(&self, ty: &[Span]) -> Option<WriteClass> {
        let [span] = ty else { return None };
        if let Some(kind) = self.credential.kind_of(ty) {
            return Some(WriteClass::Credential(kind));
        }
        if self.grant.admits(span) {
            return Some(WriteClass::Grant);
        }
        self.audit
            .iter()
            .find(|(_, class)| class.admits(span))
            .map(|(class, _)| WriteClass::AuditView(*class))
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
