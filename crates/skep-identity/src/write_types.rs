//! The write path's type-recognition input — PUB-6.30, PUB-6.64.
//!
//! The fold's credential kinds widened by the grants class and PUB-6.64's
//! audit-view classes (PUB-kickoff D3) — the registry's three among them,
//! the binding, the takedown record and the policy link with their subtype
//! rows by prefix (REG-1.44, REG-1.46) — for the one question the write path
//! asks that the fold does not: which refusal a `nullify`'s target class
//! earns. It reads the fold's recognition — [`TypeAddrs::kind_of`] and
//! [`single_address`], in `crate::shape` — and changes none of it; nothing
//! here is fold state.

use skep_address::{is_prefix, subtree_of, Address, Span};

use crate::shape::{single_address, sole_span, CredentialKind, TypeAddrs};

/// PUB-6.64's members, the record classes read under the audit view.
///
/// The publication spec reads each class's honored state under the audit
/// view, so a `nullify` of one clears nothing and is refused at the write
/// path. The list is the members' list and never the boundary: the next
/// audit-view class is one arm here — with its
/// [`AuditClass::requires_published_home`] and
/// [`AuditClass::requires_published_new`] answers, which the compiler
/// demands, and its entry in this type's own list of classes, which it does
/// not — and one address at [`WriteTypes::new`], which refuses a builder that
/// gives a class none, with no edit to any rule that reads them. Which type
/// address each class sits at is the caller's to supply (the commons ledger's
/// numbers, pinned in the engine; M7's own reserved tumbler for the
/// supersession claim) — this crate is parametric over them exactly as it is
/// over the three credential addresses (AUTH-7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditClass {
    /// The succession pair's `successor-of` claim (PUB-7.63).
    SuccessorOf,
    /// The succession pair's delegator endorsement (PUB-7.63).
    ///
    /// It is the member PUB-6.64 lists by that name, recognized by its type,
    /// `endorse`, and so every endorsement: the type and its subtypes by
    /// prefix (L10; `endorse.trust` is one), whoever deposits it and whatever
    /// it endorses, since [`WriteTypes::target_class`] reads the type slot
    /// alone. The name is the role the pair reads the type in, not the breadth
    /// of what the class admits (`skep_engine::types::t_endorse`).
    DelegatorEndorsement,
    /// The consumption marker (PUB-4.12): a nullified marker still consumes.
    ConsumptionMarker,
    /// The journal designation (PUB-4.12).
    ///
    /// A nullified designation still designates.
    JournalDesignation,
    /// The rail record (PUB-5.76), inheriting on PUB-6.30's ground.
    RailRecord,
    /// The steward's classification link (PUB-5.43).
    ///
    /// It is a member only where its home is published (RES-207, PUB-6.64).
    /// [`AuditClass::requires_published_home`] answers `true` for it: this
    /// classifier gives the type half, and the home half is the caller's, off
    /// a read it already has.
    StewardClassification,
    /// The `replaces` link a grant is deposited with (PUB-5.15 (iii), (iv)).
    ///
    /// It is PUB-6.64's member as RES-308 lists it: the grant fold reads a
    /// grant's pair on the audit view, so a retraction of the link clears
    /// nothing the fold reads — and a `nullify` admitted here would leave the
    /// active-view reads naming the grant's `replaces` as the empty state, the
    /// replay the link exists to close. Its home is the grant's own doc 1,
    /// published by the residence pin (PUB-5.17), so its membership waits on
    /// nothing more.
    Replaces,
    /// The registry's binding: the registration record, prefix → account.
    ///
    /// It is REG-1.39's first member (REG-1.44, REG-1.46): the binding walk
    /// reads the audit view at every log position, so a retraction clears
    /// nothing it reads; a later binding at the prefix is the one correction.
    /// Homed in the binding-writing account's own doc 1 by rule, so its
    /// membership waits on no home read.
    Binding,
    /// The registry's takedown record.
    ///
    /// It sits at its kind's address, so the two rows under it — its base
    /// reading and lifted — are members by prefix (REG-1.21, REG-1.42,
    /// REG-1.46): the serving layer reads both on the audit view at their own
    /// log positions, and the lift stays the class's one reversal. Homed in
    /// the operator's own doc 1 by rule.
    TakedownRecord,
    /// The registry's policy link.
    ///
    /// It sits at its kind's address, so the five rows under it — its own
    /// reading, the disavowal, an expulsion's and a succession's ground
    /// record, the org-chosen succession policy — are members by prefix
    /// (REG-1.21, REG-1.40, REG-1.46): the grounded reads take each at its own
    /// key on the audit view, corrected by a positive later record from the
    /// same home and never by a retraction. Homed in a doc 1 by rule. The
    /// endpoint, the registry's other kind, is no member: read on the active
    /// view, its org's own `nullify` effective (REG-1.11).
    PolicyLink,
    /// The supersession claim — `assert_sup`'s and `edit_link`'s `[K_sup]`
    /// link, typed M7's reserved supersedes ghost tumbler.
    ///
    /// It is a member where the claim's `new` — its `to`, one denoted
    /// address — is homed in a PUBLISHED document and its `old`, its `from`,
    /// is the claim's maker's own (PUB-6.64; the link-sets wire-lane
    /// decision 3 and sweep-4 O6 (b)): [`AuditClass::requires_published_new`]
    /// answers `true` for it, the endpoint keys in RES-207's shape on the
    /// claim's ends, the type half this classifier's and both endpoint reads
    /// the caller's, off the target link it already reads. The ground: a
    /// claim that its maker's public copy supersedes its maker's own original
    /// is a fact of its maker's own past act that no act legitimately
    /// retracts, and refusing its retraction keeps the ACTIVE view's claim
    /// reads exact — where a claim whose `new` is private, a correction
    /// inside the owner's own notes, and one its maker asserted over another
    /// account's link stay ordinary links, retractable by `nullify`, M7's
    /// one correction path for a wrong claim. The address is not a commons
    /// pin but M7's own constant (`1.1.0.1.0.1.0.1.4`), read from M7's
    /// registry by the builder.
    Supersession,
}

impl AuditClass {
    /// Every class: what [`WriteTypes::new`] holds a builder's audit list to.
    ///
    /// The language enumerates no enum's arms, so it is kept by hand: the
    /// compiler does not hold it to the enum, and the suite holds it only to
    /// the classes its fixture names. It sits beside
    /// [`AuditClass::requires_published_home`] and
    /// [`AuditClass::requires_published_new`], whose exhaustive matches are
    /// where a new class first fails to compile, so the class joins it in
    /// that edit.
    const ALL: [AuditClass; 11] = [
        AuditClass::SuccessorOf,
        AuditClass::DelegatorEndorsement,
        AuditClass::ConsumptionMarker,
        AuditClass::JournalDesignation,
        AuditClass::RailRecord,
        AuditClass::StewardClassification,
        AuditClass::Replaces,
        AuditClass::Binding,
        AuditClass::TakedownRecord,
        AuditClass::PolicyLink,
        AuditClass::Supersession,
    ];

    /// Returns whether membership needs the link's own home published.
    ///
    /// Where it answers `true`, a link of this class is a member only where
    /// the link's own home is published (RES-207, PUB-6.64); draft-homed it is
    /// an ordinary link. The class's second key, answered by the class: the
    /// type half is [`WriteTypes::target_class`]'s, and the home half is a
    /// world read this crate cannot take, so the caller takes it — keyed on
    /// this answer, never on a variant it names. Matched exhaustively with no
    /// wildcard, so a new class does not compile until it says whether its
    /// membership waits on the link's home.
    pub fn requires_published_home(self) -> bool {
        match self {
            AuditClass::StewardClassification => true,
            AuditClass::SuccessorOf
            | AuditClass::DelegatorEndorsement
            | AuditClass::ConsumptionMarker
            | AuditClass::JournalDesignation
            | AuditClass::RailRecord
            | AuditClass::Replaces
            | AuditClass::Binding
            | AuditClass::TakedownRecord
            | AuditClass::PolicyLink
            | AuditClass::Supersession => false,
        }
    }

    /// Returns whether membership needs the home of the link's `to`
    /// published — the claim's `new` — and its `from` the maker's own.
    ///
    /// [`AuditClass::requires_published_home`]'s neighbour, in RES-207's
    /// shape on the link's ends: where it answers `true`, a link of this
    /// class is a member only where the one address its `to` slot denotes is
    /// homed in a published document *and* the one address its `from` slot
    /// denotes — the claim's `old` — is owned by the account that owns the
    /// link itself (PUB-6.64); otherwise it is an ordinary link. The
    /// supersession claim alone answers `true` (the wire-lane decision 3 and
    /// sweep-4 O6 (b)): a claim naming a published copy as `new` over its
    /// maker's own `old` is permanent, one naming a private successor, or
    /// another account's link as `old`, is correctable by its maker. The type
    /// half is [`WriteTypes::target_class`]'s, and the endpoints'
    /// denotations, the publication read and the two owner reads are the
    /// caller's, off the target link it reads for the type — keyed on this
    /// answer, never on a variant it names. Matched exhaustively with no
    /// wildcard, so a new class does not compile until it says whether its
    /// membership waits on its endpoints.
    pub fn requires_published_new(self) -> bool {
        match self {
            AuditClass::Supersession => true,
            AuditClass::SuccessorOf
            | AuditClass::DelegatorEndorsement
            | AuditClass::ConsumptionMarker
            | AuditClass::JournalDesignation
            | AuditClass::RailRecord
            | AuditClass::StewardClassification
            | AuditClass::Replaces
            | AuditClass::Binding
            | AuditClass::TakedownRecord
            | AuditClass::PolicyLink => false,
        }
    }
}

/// The class of a `nullify`'s target link.
///
/// It is recognized by its type slot (PUB-kickoff D3) — the "class of target
/// link" wire.md's `nullify` cells are keyed on. `None` from
/// [`WriteTypes::target_class`] is an ordinary link — the R20 edition claim
/// among them (PUB-6.32: read under the active view, so its owner's
/// retraction clears the state its faces read and is admitted).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetClass {
    /// A credential type, exactly [`TypeAddrs::kind_of`]'s answer (AUTH-2.22).
    ///
    /// Its cell is PUB-6.10's.
    Credential(CredentialKind),
    /// The grants class (PUB-6.30).
    ///
    /// Retraction is never a second revocation path: a share is withdrawn by
    /// revoking it.
    Grant,
    /// A class read under the audit view (PUB-6.64), recognized by type.
    ///
    /// Where [`AuditClass::requires_published_home`] holds, the link is a
    /// member only if its own home is published — the one half of membership
    /// this pure classifier leaves to its caller.
    AuditView(AuditClass),
}

/// The write path's type-recognition input (PUB-6.30, PUB-6.64).
///
/// It is a copy of the fold's three credential kinds (PUB-kickoff D3) —
/// [`TypeAddrs`] and its `kind_of`, untouched and the one rule the fold reads
/// — widened beside them by the grants class and PUB-6.64's audit-view
/// classes, for the one question the write path asks that the fold does not:
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
    /// Assembles the write path's type-recognition input.
    ///
    /// The credential kinds answer first — a credential type is never also a
    /// class — then the grant, then the audit-view classes in the order
    /// given. It keeps the class addresses themselves:
    /// [`WriteTypes::target_class`] reads a slot's address once and asks each
    /// class a prefix question of it.
    ///
    /// `credential` is kept as an owned copy, so this input agrees with the
    /// fold about what a credential is only when its builder hands in the
    /// `TypeAddrs` the fold reads (`skep-core` clones the engine's
    /// `IDENTITY_TYPES`). That agreement is the builder's to keep: nothing
    /// here can see the fold's.
    ///
    /// # Panics
    ///
    /// Panics where `audit` does not give every [`AuditClass`] an address. A
    /// slot answers [`TargetClass::AuditView`] for a class only if the class
    /// was given one here, so [`TargetClass`]'s "`None` is an ordinary link"
    /// holds only over a complete list: a class left out would answer `None`
    /// for every one of its slots, and the `nullify` PUB-6.64 refuses would be
    /// admitted.
    ///
    /// Panics where the class addresses are not pairwise prefix-free, or one
    /// is a credential type. A class address at or under another's puts one
    /// address under two classes, so the answer would be the declared order's
    /// rather than the class's — and a later class at or under an earlier one
    /// unreachable for every slot. Prefix-free, no address is under two
    /// classes and their order decides nothing; the one order that decides is
    /// the credential kinds answering first.
    ///
    /// The credential half is asked through [`TypeAddrs::kind_of`], on the
    /// unit subtree span of the class address — the very call
    /// [`WriteTypes::target_class`] makes, on the very span form an
    /// address-form slot carries — rather than against the three addresses
    /// [`TypeAddrs`] holds. That is what makes the wiring check and the
    /// runtime rule one question: they cannot drift, whatever `kind_of`'s
    /// frozen rule turns out to compare.
    ///
    /// Both are mis-wirings of the kind [`TypeAddrs::new`] refuses, refused
    /// the same way, completeness first: a panic at construction, since the
    /// addresses are the engine's compiled constants and never a value a
    /// record can carry. `skep-core` calls this lazily, when its write path
    /// first classifies a `nullify` target, so a mis-wired build panics on
    /// that request's path.
    pub fn new(
        credential: TypeAddrs,
        grant: Address,
        audit: impl IntoIterator<Item = (AuditClass, Address)>,
    ) -> WriteTypes {
        let audit: Vec<(AuditClass, Address)> = audit.into_iter().collect();
        for class in AuditClass::ALL {
            assert!(
                audit.iter().any(|(listed, _)| *listed == class),
                "WriteTypes::new: audit-view class {class:?} has no address (PUB-6.64); a \
                 class left out answers every one of its slots as an ordinary link, so the \
                 nullify it refuses would be admitted"
            );
        }
        {
            let class_addrs: Vec<&Address> =
                std::iter::once(&grant).chain(audit.iter().map(|(_, a)| a)).collect();
            for (i, a) in class_addrs.iter().enumerate() {
                assert!(
                    credential.kind_of(&[subtree_of(a.tumbler())]).is_none(),
                    "WriteTypes::new: class address {} is a credential type address \
                     (AUTH-2.20); the credential kinds answer first, so the class would be \
                     unreachable",
                    a.tumbler()
                );
                for b in &class_addrs[i + 1..] {
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

    /// Returns the class of the target link a type slot belongs to, if any.
    ///
    /// `Some` iff `ty` is exactly one span recognized as a class — a
    /// credential type by [`TypeAddrs::kind_of`]'s frozen rule (`Equal` to
    /// the type's own subtree, no subtypes), else the grant or the audit-view
    /// class that the one address the slot names is at or under: the class's
    /// own type, or a subtype of it, the rule L10 states (commons-map.md:
    /// "hierarchy is prefix — one subtree span matches a type and its
    /// subtypes"; `3.42.1` is an `endorse`). That address is
    /// [`single_address`]'s answer — one span `Equal` to the subtree of its
    /// own T4-valid start — so a span across a class's subtree, or one
    /// containing it, names no address and is no member. The classes are
    /// prefix-free, so an address is at or under at most one of them. Any
    /// other arity, and any slot whose address is under no class, answers
    /// `None`: an ordinary link.
    ///
    /// `ty` is a borrowed walk of the slot, as on [`TypeAddrs::kind_of`], and
    /// is walked once.
    pub fn target_class<'s>(&self, ty: impl IntoIterator<Item = &'s Span>) -> Option<TargetClass> {
        // Arity once: every class — credential or not — is a one-span slot,
        // so any other arity is an ordinary link, and the one span is what
        // both rules below are asked about.
        let span = sole_span(ty)?;
        if let Some(kind) = self.credential.kind_of([span]) {
            return Some(TargetClass::Credential(kind));
        }
        // The address the slot names, read once: the slot is a class's when
        // that address is at or under the class's own — its type or a subtype
        // (L10) — a question about this address, never a re-reading of the
        // span per class.
        let named = single_address([span])?;
        let at_or_under = |class_addr: &Address| is_prefix(class_addr.tumbler(), named.tumbler());
        if at_or_under(&self.grant) {
            return Some(TargetClass::Grant);
        }
        self.audit
            .iter()
            .find(|(_, class_addr)| at_or_under(class_addr))
            .map(|(class, _)| TargetClass::AuditView(*class))
    }
}
