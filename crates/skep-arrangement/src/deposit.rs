//! The deposit declaration an INSERT carries ([`Deposit`]), and the deposit
//! class's types the insert door compares it against ([`deposit_class_types`]).

use std::sync::LazyLock;

use skep_address::{elem_addr, Address, ElemPos, Nat};
use skep_namespace::ghost_home_document;

/// The deposit DECLARATION an INSERT carries or omits (PUB-9.13's DECLARED
/// horn; PUB-2.59, PUB-2.61): the one declaration M5's writes take,
/// and the one thing that clears the in-place refusal on a published
/// document — and only for an insert at a fresh content position
/// ([`Vstream::insert`](crate::Vstream::insert) states the shape). Into a
/// private document it is inert. Content only — a link deposit is outside the
/// rule (PUB-2.12).
///
/// THE DECLARATION NAMES THE RECORD CLASS (PUB-2.11, PUB-2.64; RES-249): what
/// it carries is the class's TYPE address — the type the `make_link` naming
/// the atom then carries (PUB-2.63) — and the write path tests it, admitting
/// a declared insert on a published document only where that type is one
/// [`deposit_class_types`] holds. A bare "this is a deposit" would not
/// separate the exempt record atom from ordinary prose at a fresh position;
/// the class type does, and the `make_link` naming the atom, carrying that
/// same type, is where the declaration is borne out.
///
/// A type and not a flag because the declaration is read where it is made,
/// and the two ways of making it wrongly are not alike. An insert that should
/// have been declared is refused `PublishedTarget`, loudly. A declaration on
/// an ordinary edit, under a type the deposit class holds, is admitted at a
/// fresh position of a published document — PUB-2.60's residue, placed
/// wherever [`deposit_surface`](crate::deposit_surface) points — and nothing
/// reports it; on the [`Caller::System`](crate::Caller::System) path no ω
/// check stands between the declaration and the arrangement either. For the
/// same reason there is no `From<bool>` and no `From<Address>`: an address
/// becomes this value with the variant written out, where a reader sees that
/// it is declared.
///
/// Two variants because the corpus has two — an insert is declared or it is
/// not — so a match on it is exhaustive, and a third variant would change the
/// exemption itself. `Default` is `Undeclared`: on the wire an ABSENT field
/// is the one spelling of no declaration (PUB-2.64).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum Deposit {
    /// No declaration: an ordinary edit — and, on a published document, an
    /// in-place edit, refused.
    #[default]
    Undeclared,
    /// The deposit declaration, carrying the record class's TYPE: admitted on
    /// a published document where the type is a member of
    /// [`deposit_class_types`] AND the insert names a fresh content position
    /// of the arrangement the deposit lands in. A type the set does not hold
    /// is refused `PublishedTarget`, as an undeclared append is.
    Declared(Address),
}

/// The commons' TYPE subspace of the ghost home document — subspace 3, the
/// core vocabulary's home, where nothing is ever minted (no M3 door mints
/// into any document's subspace 3), so no content address can equal a type
/// spelled there.
const COMMONS_TYPE_SUBSPACE: u32 = 3;

/// The commons ordinals of [`deposit_class_types`]' members, in the set's
/// order — the two atom-bearing CREDENTIAL classes (AUTH-5.4: a credential
/// record is ONE ATOM, a DECLARED deposit into the home document), then the
/// two atom-bearing REGISTRY kinds whose bodies the daemon parses (REG-1.14;
/// REG-2.26's first two members, each an atom plus a link into a doc 1):
///
/// * `1` — ENROLL, `1.1.0.1.0.1.0.3.1`;
/// * `2` — RETIRE, `1.1.0.1.0.1.0.3.2`;
/// * `55` — the BINDING, `1.1.0.1.0.1.0.3.55`;
/// * `56` — the ENDPOINT, `1.1.0.1.0.1.0.3.56`.
///
/// The daemon's own constants for the credential pair (`T_ENROLL`,
/// `T_RETIRE`) and the registry's own table for the other two
/// (`skep-registry`, read by the engine's ledger) sit above this crate,
/// where the door cannot read them, so this is a SECOND SPELLING — and the
/// daemon's suite pins the four EQUAL, member for member, and this set
/// prefix-free against every pin of the engine's commons ledger
/// (`skep-engine/src/types.rs`) but the two rows it spells again, so neither
/// spelling moves alone.
const DEPOSIT_CLASS_ORDINALS: [u32; 4] = [1, 2, 55, 56];

/// THE DEPOSIT CLASS's TYPE-RECOGNITION INPUT at the insert door (PUB-2.11;
/// RES-249, RES-261; the owner's ruling, 2026-09-18): the members' list of
/// PUB-2.61's class sentence RESTRICTED TO THE CLASSES THAT DEPOSIT AN ATOM —
/// a BUILD-TIME set, M5's own, each member the ghost home document's
/// ([`ghost_home_document`]) subspace-3 element at its commons ordinal
/// (`DEPOSIT_CLASS_ORDINALS`). Today: ENROLL, RETIRE, the registry's
/// BINDING and its ENDPOINT, in that order.
///
/// Membership is EQUALITY — the membership compare RES-249 pins, and the
/// compare the credential classifier makes of the type slot of the
/// `make_link` naming the atom (exactly one span `Equal` to the class's,
/// containment answering nothing): a subtype beneath a member is no member.
/// A class joins at the rule that mints it or that states it rides this
/// class (RES-261), by one ordinal above and nothing else — and with the
/// daemon arm that parses its record and verifies its `sig`, as the two
/// registry kinds joined with the record grade's registry arm (REG-1.37 as
/// the record grade re-reads it); each type held here that no conforming
/// `insert` bears out is one more prose path under PUB-2.60's residue, so
/// the set holds what deposits an atom TODAY and no more.
///
/// JOINING LATER, each at its own type's allocation:
///
/// * the DISPLAY-NAME record — IN by PUB-2.62 (RES-261): its doc-1 content
///   write is a deposit into a published home; it joins at P8's allocation
///   (the write itself is deferred, AUTH RES-62);
/// * the INVITE LETTER — RES-221 gave it a body, so it deposits an atom; it
///   joins at its type's allocation (no type is pinned for it yet);
/// * the registry's five other body-bearing rows — the takedown record's
///   base reading `3.57.1`, the disavowal `3.58.2`, an expulsion's and a
///   succession's ground record `3.58.3`, `3.58.4`, the org-chosen
///   succession policy `3.58.5` (REG-1.15, REG-1.86) — each where its
///   schema is pinned and the daemon parses it; a declared `insert` under
///   one is refused `PublishedTarget` at this door until then.
///
/// NEVER — a class that deposits its typed link and endsets alone, and no
/// atom: PUB-2.61's class sentence names it, but its type is never one the
/// deposit class holds (RES-261), no conforming `insert` ever declaring it:
///
/// * the GRANT — its link and endsets alone, NO BODY (PUB-5.15, RES-221);
/// * `published-in-error` — the same (PUB-5.116, RES-220);
/// * the EDITION CLAIM — NO BODY (RES-221);
/// * `successor-of` — NO BODY (RES-221; REG-2.26's link-alone row);
/// * the registry's two other link-alone rows — LIFTED `3.57.2` and the
///   policy link's own reading `3.58.1` (REG-2.26) — NO BODY;
/// * the two bare ordinals of the registry kinds that read more than one
///   way — the takedown record `3.57`, the policy link `3.58` — which carry
///   NO deposit at all (REG-1.18);
/// * the CLAIM link — names the account in its FROM and deposits no atom
///   (AUTH's third credential type, `3.3`).
///
/// HELD, not manufactured per call: one process-wide value, constructed at
/// its first read — the addresses are compiled format constants, and the door
/// consults them on every declared insert into a published document.
pub fn deposit_class_types() -> &'static [Address] {
    static TYPES: LazyLock<[Address; 4]> = LazyLock::new(|| {
        DEPOSIT_CLASS_ORDINALS.map(|ordinal| {
            elem_addr(ElemPos {
                doc: ghost_home_document(),
                subspace: Nat::from(COMMONS_TYPE_SUBSPACE),
                ordinal: Nat::from(ordinal),
            })
            .expect("ghost_home_document is Document-level; the subspace and every ordinal are ≥ 1")
        })
    });
    &*TYPES
}

#[cfg(test)]
mod tests {
    use skep_address::document_of;

    use super::*;
    use crate::testutil::n;

    #[test]
    fn the_absent_declaration_is_the_default() {
        // The wire reads an absent `deposit` field as no declaration
        // (PUB-2.64), so the value a caller gets without saying anything is
        // the one that clears no refusal — never the exemption.
        assert_eq!(Deposit::default(), Deposit::Undeclared);
    }

    /// The set as spelled: ENROLL, RETIRE, the BINDING, the ENDPOINT, each
    /// the ghost home document's subspace-3 element at its commons ordinal —
    /// where no M3 door mints, so no content address equals a member —
    /// pairwise prefix-free, since membership is equality and a member
    /// beneath another would be a subtype the door never reads as one. The
    /// pin EQUAL to the daemon's constants and the registry's table, and
    /// prefix-free against the engine's ledger, is the daemon suite's, which
    /// can see every spelling; this crate sits below the others.
    #[test]
    fn the_deposit_class_types_are_the_four_atom_bearing_kinds_in_the_ghost_homes_type_subspace() {
        let types = deposit_class_types();
        let spelled: Vec<String> = types.iter().map(|ty| ty.tumbler().to_string()).collect();
        assert_eq!(
            spelled,
            ["1.1.0.1.0.1.0.3.1", "1.1.0.1.0.1.0.3.2", "1.1.0.1.0.1.0.3.55", "1.1.0.1.0.1.0.3.56"]
        );
        for ty in types {
            assert_eq!(
                document_of(ty),
                Some(ghost_home_document()),
                "{ty:?}: homed in the ghost document"
            );
            assert_eq!(ty.subspace(), Some(&n(COMMONS_TYPE_SUBSPACE)), "{ty:?}: the type subspace");
        }
        for (i, a) in types.iter().enumerate() {
            for b in &types[i + 1..] {
                let (a, b) = (a.tumbler(), b.tumbler());
                assert!(!skep_address::is_prefix(a, b) && !skep_address::is_prefix(b, a), "{a} / {b}");
            }
        }
    }

    /// The set is ONE value, held: two reads hand back the same slice, not
    /// two equal ones — the door consults it on every declared insert into a
    /// published document, and a member is nine big-integer components.
    #[test]
    fn the_deposit_class_types_are_one_held_value_rather_than_a_construction_per_read() {
        assert!(std::ptr::eq(deposit_class_types(), deposit_class_types()));
    }
}
