//! The deposit declaration an INSERT carries, and the deposit class's types.
//!
//! The declaration is [`Deposit`]; the insert door compares it against the
//! types [`deposit_class_types`] holds.

use std::sync::LazyLock;

use skep_address::{elem_addr, Address, ElemPos, Nat};
use skep_namespace::ghost_home_document;

/// The deposit declaration an INSERT carries or omits.
///
/// It is PUB-9.13's declared horn (PUB-2.59, PUB-2.61): the one declaration
/// M5's writes take, and the one thing that clears the in-place refusal on a
/// published document — and only for an insert at a fresh content position
/// ([`Vstream::insert`](crate::Vstream::insert) states the shape). Into a
/// private document it is inert. Content only — a link deposit is outside the
/// rule (PUB-2.12).
///
/// **The declaration names the record class** (PUB-2.11, PUB-2.64; RES-249):
/// what it carries is the class's type address — the type the `make_link`
/// naming the atom then carries (PUB-2.63) — and the write path tests it,
/// admitting a declared insert on a published document only where that type
/// is one [`deposit_class_types`] holds. A bare "this is a deposit" would not
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
/// exemption itself. `Default` is `Undeclared`: on the wire an absent field
/// is the one spelling of no declaration (PUB-2.64).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum Deposit {
    /// No declaration: an ordinary edit.
    ///
    /// On a published document it is an in-place edit, refused.
    #[default]
    Undeclared,
    /// The deposit declaration, carrying the record class's type.
    ///
    /// It is admitted on a published document where the type is a member of
    /// [`deposit_class_types`] and the insert names a fresh content position
    /// of the arrangement the deposit lands in. A type the set does not hold
    /// is refused `PublishedTarget`, as an undeclared append is.
    Declared(Address),
}

/// The commons' type subspace of the ghost home document: subspace 3.
///
/// It is the core vocabulary's home, where nothing is ever minted (no M3
/// door mints into any document's subspace 3), so no content address can
/// equal a type spelled there.
const COMMONS_TYPE_SUBSPACE: u32 = 3;

/// The commons ordinals of [`deposit_class_types`]' members, in order.
///
/// In the set's order, they are the two atom-bearing credential classes
/// (AUTH-5.4: a credential record is one atom, a declared deposit into the
/// home document), then the two atom-bearing registry kinds whose bodies the
/// daemon parses (REG-1.14; REG-2.26's first two members, each an atom plus a
/// link into a doc 1):
///
/// * `1` — enroll, `1.1.0.1.0.1.0.3.1`;
/// * `2` — retire, `1.1.0.1.0.1.0.3.2`;
/// * `55` — the binding, `1.1.0.1.0.1.0.3.55`;
/// * `56` — the endpoint, `1.1.0.1.0.1.0.3.56`.
///
/// The engine ledger's pins for the credential pair (`t_enroll`, `t_retire`)
/// sit above this crate, where the door cannot read them, and the registry's
/// own table for the other two (`skep-registry`, read by the engine's ledger)
/// lies in a crate this one does not depend on, so this is a second spelling —
/// and the tests of the engine's commons ledger (`skep-engine/src/types.rs`)
/// pin the four equal, member for member, and this set prefix-free against
/// every other pin of that ledger, and the daemon's suite pins the four equal
/// too, so neither spelling moves alone.
const DEPOSIT_CLASS_ORDINALS: [u32; 4] = [1, 2, 55, 56];

/// Returns the deposit class's type-recognition input at the insert door.
///
/// It is the members' list of PUB-2.61's class sentence restricted to the
/// classes that deposit an atom (PUB-2.11; RES-249, RES-261) — a build-time
/// set, M5's own, each member the ghost home document's
/// ([`ghost_home_document`]) subspace-3 element at its commons ordinal
/// (`DEPOSIT_CLASS_ORDINALS`). Today: enroll, retire, the registry's binding
/// and its endpoint, in that order.
///
/// Membership is equality — the membership compare RES-249 pins, and the
/// compare the credential classifier makes of the type slot of the
/// `make_link` naming the atom (exactly one span `Equal` to the class's,
/// containment answering nothing): a subtype beneath a member is no member.
/// A class joins at the rule that mints it or that states it rides this
/// class (RES-261), by one ordinal above and nothing else — and with the
/// daemon arm that parses its record and verifies its `sig`, as the two
/// registry kinds are held with the record grade's registry arm (REG-1.37 as
/// the record grade re-reads it); each type held here that no conforming
/// `insert` bears out is one more prose path under PUB-2.60's residue, so
/// the set holds what deposits an atom today and no more.
///
/// **Joining later**, each at its own type's allocation:
///
/// * the display-name record — in by PUB-2.62 (RES-261): its doc-1 content
///   write is a deposit into a published home; it joins at P8's allocation
///   (the write itself is deferred, AUTH RES-62);
/// * the invite letter — RES-221 gives it a body, so it deposits an atom; it
///   joins at its type's allocation (no type is pinned for it yet);
/// * the registry's five other body-bearing rows — the takedown record's
///   base reading `3.57.1`, the disavowal `3.58.2`, an expulsion's and a
///   succession's ground record `3.58.3`, `3.58.4`, the org-chosen
///   succession policy `3.58.5` (REG-1.15, REG-1.86) — each where its
///   schema is pinned and the daemon parses it; a declared `insert` under
///   one is refused `PublishedTarget` at this door until then.
///
/// **Never** — a class that deposits its typed link and endsets alone, and
/// no atom: PUB-2.61's class sentence names it, but its type is never one
/// the deposit class holds (RES-261), no conforming `insert` ever declaring
/// it:
///
/// * the grant — its link and endsets alone, no body (PUB-5.15, RES-221);
/// * `published-in-error` — the same (PUB-5.116, RES-220);
/// * the edition claim — no body (RES-221);
/// * `successor-of` — no body (RES-221; REG-2.26's link-alone row);
/// * the registry's two other link-alone rows — lifted `3.57.2` and the
///   policy link's own reading `3.58.1` (REG-2.26) — no body;
/// * the two bare ordinals of the registry kinds that read more than one
///   way — the takedown record `3.57`, the policy link `3.58` — which carry
///   no deposit at all (REG-1.18);
/// * the claim link — names the account in its `FROM` and deposits no atom
///   (AUTH's third credential type, `3.3`).
///
/// **Held, not manufactured per call**: one process-wide value, constructed
/// at its first read — the addresses are compiled format constants, and the
/// door consults them on every declared insert into a published document.
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

    /// The set is spelled enroll, retire, the binding, the endpoint.
    ///
    /// Each is the ghost home document's subspace-3 element at its commons
    /// ordinal — where no M3 door mints, so no content address equals a
    /// member — pairwise prefix-free, since membership is equality and a
    /// member beneath another would be a subtype the door never reads as
    /// one. The pin equal to the engine ledger's credential pins and the
    /// registry's table, and prefix-free against the rest of the engine's
    /// ledger, is that ledger's own tests', which can see every spelling, and
    /// the daemon's suite pins the equality too; this crate sits below the
    /// engine and the daemon, and does not depend on `skep-registry`.
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

    /// The set is one value, held: two reads hand back the same slice.
    ///
    /// They are not two equal ones — the door consults it on every declared
    /// insert into a published document, and a member is nine big-integer
    /// components.
    #[test]
    fn the_deposit_class_types_are_one_held_value_rather_than_a_construction_per_read() {
        assert!(std::ptr::eq(deposit_class_types(), deposit_class_types()));
    }
}
