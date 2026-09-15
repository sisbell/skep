//! The WRITE PATH's type-recognition input — PUB-6.30, PUB-6.64; owner ruling
//! D3, 2026-09-05. The fold's credential kinds widened by the grants class
//! and PUB-6.64's audit-view classes, for the one question the write path
//! asks that the fold does not: which refusal a `nullify`'s target class
//! earns. It READS the fold's recognition — [`TypeAddrs::kind_of`] and
//! [`single_address`], in `crate::shape` — and changes none of it; nothing
//! here is fold state.

use skep_address::{is_prefix, subtree_of, Address, Span};

use crate::shape::{single_address, CredentialKind, TypeAddrs};

/// PUB-6.64's MEMBERS — the record classes whose HONORED STATE the
/// publication spec reads under the AUDIT view, so a `nullify` of one clears
/// nothing and is refused at the write path. The list is the members' list
/// and never the boundary: the next audit-view class is one arm here — with
/// its [`AuditClass::requires_published_home`] answer, which the compiler
/// demands — and one address at [`WriteTypes::new`], with no edit to any rule
/// that reads them. WHICH address names each class is the caller's to supply
/// (the commons ledger's numbers, pinned in the engine) — this crate is
/// parametric over them exactly as it is over the three credential addresses
/// (AUTH-7.1).
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
    /// HOME is published (RES-207, PUB-6.64).
    /// [`AuditClass::requires_published_home`] answers `true` for it: this
    /// classifier gives the TYPE half, and the home half is the caller's, off
    /// a read it already has.
    StewardClassification,
}

impl AuditClass {
    /// ⇔ a link of this class is a MEMBER only where the link's OWN HOME is
    /// published (RES-207, PUB-6.64); draft-homed it is an ordinary link.
    /// The class's second key, answered by the class: the TYPE half is
    /// [`WriteTypes::write_class`]'s, and the home half is a world read this
    /// crate cannot take, so the caller takes it — keyed on THIS answer, never
    /// on a variant it names. Matched exhaustively with no wildcard, so a new
    /// class does not compile until it says which kind of member it is.
    pub fn requires_published_home(self) -> bool {
        match self {
            AuditClass::StewardClassification => true,
            AuditClass::SuccessorOf
            | AuditClass::DelegatorEndorsement
            | AuditClass::ConsumptionMarker
            | AuditClass::JournalDesignation
            | AuditClass::RailRecord => false,
        }
    }
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
    /// A class read under the audit view (PUB-6.64), recognized by TYPE:
    /// where [`AuditClass::requires_published_home`] holds, the link is a
    /// member only if its own home is published — the one half of membership
    /// this pure classifier leaves to its caller.
    AuditView(AuditClass),
}

/// The WRITE PATH's type-recognition input (PUB-6.30, PUB-6.64; owner ruling
/// D3, 2026-09-05): a copy of the fold's three credential kinds —
/// [`TypeAddrs`] and its `kind_of`, UNCHANGED, still the one rule the fold
/// reads — WIDENED beside them by the GRANTS class and PUB-6.64's audit-view
/// classes, for the ONE question the write path asks that the fold does not:
/// which refusal a `nullify`'s target class earns. Constructed once by the
/// daemon from the credential types it already holds and the class addresses
/// the engine pins; nothing here is fold state (AUTH-2.90's I2 rule is
/// `kind_of`'s alone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteTypes {
    credential: TypeAddrs,
    grant: Address,
    audit: Vec<(AuditClass, Address)>,
}

impl WriteTypes {
    /// Assemble the input: the credential kinds (answered FIRST — a
    /// credential type is never also a class), then the grant, then the
    /// audit-view classes in the order given. Keeps the class addresses
    /// themselves: [`WriteTypes::write_class`] reads a slot's address once
    /// and asks each class a prefix question of it.
    ///
    /// PRECONDITION — the class addresses are PAIRWISE PREFIX-FREE and none
    /// is a credential type. A class address at or under another's puts one
    /// address under two classes, so the answer would be the declared
    /// order's rather than the class's — and a later class at or under an
    /// earlier one UNREACHABLE for every slot. Prefix-free, no address is
    /// under two classes and their order decides nothing; the one order that
    /// decides is the credential kinds answering first. The same mis-wiring
    /// [`TypeAddrs::new`] refuses, refused the same way: a panic at
    /// construction, off every request path, since the addresses are the
    /// engine's compiled constants and never a value a record can carry.
    pub fn new(
        credential: TypeAddrs,
        grant: Address,
        audit: impl IntoIterator<Item = (AuditClass, Address)>,
    ) -> WriteTypes {
        let audit: Vec<(AuditClass, Address)> = audit.into_iter().collect();
        {
            let classes: Vec<&Address> =
                std::iter::once(&grant).chain(audit.iter().map(|(_, a)| a)).collect();
            for (i, a) in classes.iter().enumerate() {
                assert!(
                    credential.kind_of(&[subtree_of(a.tumbler())]).is_none(),
                    "WriteTypes::new: class address {} is a credential type address \
                     (AUTH-2.20); the credential kinds answer first, so the class would be \
                     unreachable",
                    a.tumbler()
                );
                for b in &classes[i + 1..] {
                    assert!(
                        !is_prefix(a.tumbler(), b.tumbler()) && !is_prefix(b.tumbler(), a.tumbler()),
                        "WriteTypes::new: class addresses {} and {} are prefix-related; an \
                         address under both would answer by declared order rather than by class \
                         (the class addresses must be pairwise prefix-free)",
                        a.tumbler(),
                        b.tumbler()
                    );
                }
            }
        }
        WriteTypes { credential, grant, audit }
    }

    /// The credential kinds this input answers first: an OWNED copy of the
    /// [`TypeAddrs`] it was built from — equal to it, never shared. It agrees
    /// with the fold about a credential only because its builder hands
    /// [`WriteTypes::new`] the `TypeAddrs` the fold reads (skepd clones its
    /// `IDENTITY_TYPES`); that agreement is the builder's to keep.
    pub fn credential(&self) -> &TypeAddrs {
        &self.credential
    }

    /// The write path's classification of a type slot: `Some` iff `ty` is
    /// EXACTLY ONE span that names a class — a credential type by
    /// [`TypeAddrs::kind_of`]'s frozen rule (`Equal` to the type's own
    /// subtree, no subtypes), else the grant or the audit-view class whose
    /// address is a (possibly improper) prefix of the ONE address the slot
    /// names. That address is [`single_address`]'s answer — one span `Equal`
    /// to the subtree of its own T4-VALID start — so a span across a class's
    /// subtree, or one containing it, names no address and is no member; and
    /// a class names the address by being it or a prefix of it, the subtype
    /// rule L10 states (commons-map.md: "hierarchy is prefix — one subtree
    /// span matches a type and its subtypes"; `3.42.1` is an `endorse`). The
    /// classes are prefix-free, so at most one names it. Any other arity, and
    /// any slot naming no class, answers `None`: an ordinary link.
    pub fn write_class(&self, ty: &[Span]) -> Option<WriteClass> {
        if let Some(kind) = self.credential.kind_of(ty) {
            return Some(WriteClass::Credential(kind));
        }
        // The address the slot names, read ONCE: a class names the slot by
        // being that address or a prefix of it (L10) — a question about this
        // address, never a re-reading of the span per class.
        let named = single_address(ty)?;
        let names = |class_addr: &Address| is_prefix(class_addr.tumbler(), named.tumbler());
        if names(&self.grant) {
            return Some(WriteClass::Grant);
        }
        self.audit
            .iter()
            .find(|(_, class_addr)| names(class_addr))
            .map(|(class, _)| WriteClass::AuditView(*class))
    }
}
