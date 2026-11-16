use skep_address::is_prefix;

use super::*;

/// One pin's READER — the accessor half of a [`PINS`] row, and the word
/// the module doc uses for it.
type Reader = fn() -> &'static Address;

/// THE LEDGER as the tests walk it: each pin's reader, with the commons
/// ordinals its own doc cites — one for a kind's row, the kind's then
/// the subtype's for a registry subtype row, and one more for a row under
/// a registry parent row. ONE list, because a pin's
/// obligations are the ledger's rather than that pin's — three hand-kept
/// lists would be three places to be forgotten, and a pin absent from
/// all of them reaches the daemon's refusal set with nothing here
/// failing. So this is the single gate the next pin passes
/// through, and each test below is one question asked of every row.
const PINS: &[(Reader, &str)] = &[
    (t_enroll, "1"),
    (t_retire, "2"),
    (t_claim, "3"),
    (t_grant, "90"),
    (t_edition, "14"),
    (t_successor_of, "59"),
    (t_endorse, "42"),
    (t_consumption_marker, "91"),
    (t_journal_designation, "22"),
    (t_rail_record, "60"),
    (t_steward_classification, "61"),
    (t_replaces, "12"),
    (t_registration, "54"),
    (t_request, "54.1"),
    (t_request_fresh, "54.1.1"),
    (t_request_board_carries_on, "54.1.2"),
    (t_reply, "54.2"),
    (t_reply_approved, "54.2.1"),
    (t_reply_refused, "54.2.2"),
    (t_reply_denied, "54.2.3"),
    (t_vouch, "54.3"),
    (t_approval, "54.4"),
    (t_binding, "55"),
    (t_endpoint, "56"),
    (t_takedown, "57"),
    (t_takedown_base, "57.1"),
    (t_takedown_lifted, "57.2"),
    (t_policy_link, "58"),
    (t_policy_link_own, "58.1"),
    (t_disavowal, "58.2"),
    (t_expulsion_ground, "58.3"),
    (t_succession_ground, "58.4"),
    (t_succession_policy, "58.5"),
    (t_read_with, "71"),
    (t_correspondence, "102.1"),
    (t_held_removal, "24"),
];

/// Whether `a` is a registry row — one of `skep-registry`'s table.
fn is_registry_row(a: &Address) -> bool {
    skep_registry::row_at(a).is_some()
}

/// The pairs the registry's own nesting admits (REG-1.20): each subtype
/// row under its own kind's row, each row under a parent row under that
/// parent's row too, and nothing else.
fn nested_pairs() -> Vec<(&'static Address, &'static Address)> {
    skep_registry::rows()
        .iter()
        .flat_map(|r| {
            let subtype = r.of.subtype();
            let kind = subtype.map(|s| (&s.kind().row().address, &r.address));
            let parent = subtype.and_then(|s| s.parent()).map(|p| (&p.row().address, &r.address));
            kind.into_iter().chain(parent)
        })
        .collect()
}

/// The ledger's GUARANTEE (the module doc's): the pins are pairwise
/// distinct and — since a consumer recognizes a class's SUBTYPES by
/// prefix — pairwise prefix-free, so no class swallows another; the ONE
/// prefix relation admitted is a registry subtype row under its own
/// kind's row, and under its own parent row where it is a row under a
/// row, the nesting the registry designs (REG-1.20) — so every registry
/// row stays prefix-free against every pin outside the registry's table,
/// the kinds against each other, and a row against every registry row
/// that is neither its kind nor its parent.
#[test]
fn the_commons_pins_are_pairwise_prefix_free_but_for_the_registrys_own_nesting() {
    let pins: Vec<&'static Address> = PINS.iter().map(|(read, _)| read()).collect();
    let nested = nested_pairs();
    let (subtypes, under_a_parent) = (
        skep_registry::Subtype::ALL.len(),
        skep_registry::Subtype::ALL.iter().filter(|s| s.parent().is_some()).count(),
    );
    assert!(under_a_parent > 0, "the registration's rows under `request` and `reply`");
    assert_eq!(
        nested.len(),
        subtypes + under_a_parent,
        "every subtype row nests under its kind, and a row under a parent row under that too"
    );
    for (i, a) in pins.iter().enumerate() {
        for b in &pins[i + 1..] {
            assert_ne!(a, b, "{} is pinned twice", a.tumbler());
            if is_prefix(a.tumbler(), b.tumbler()) || is_prefix(b.tumbler(), a.tumbler()) {
                assert!(
                    nested.contains(&(a, b)) || nested.contains(&(b, a)),
                    "{} and {} are prefix-related and no registry kind/subtype pair",
                    a.tumbler(),
                    b.tumbler()
                );
            }
        }
    }
}

/// The deposit class's types — M5's set: the credential types ENROLL
/// and RETIRE, and the registry's rows whose bodies the daemon parses —
/// the registration's six deposit-carrying rows, the binding and the
/// endpoint — each spelled a second time below this crate — are EXACTLY
/// the pins the set spells again, member for member and in the set's order
/// (PUB-2.11, PUB-2.63; RES-249, RES-261; REG-1.23): the two credential
/// pins the fold hook classifies a record's `make_link` by, so a record
/// atom declared under one is the class its pair's link folds as, and the
/// registry rows the daemon's registry sequence reads. No member is any
/// OTHER pin — which would make a typed-link class with no atom (the
/// grant, the edition claim, `successor-of`, the registration's approval)
/// or a row that carries no deposit (a kind's bare ordinal, a parent row)
/// a member the insert door admits a declared deposit under. THE
/// CREDENTIAL HALF IS STRICT: enroll and retire sit above and beneath no
/// pin at all, which would make the daemon's prefix-recognizing write path
/// read a credential as that pin's class or subtype. THE REGISTRY HALF
/// ADMITS ITS OWN NESTING AND NO OTHER: a registry member is prefix-free
/// against every pin but the registry rows it nests under by design — its
/// kind's row, and its parent row's — so the request's fresh kind sits
/// under `request` and under the registration and beside everything else.
/// Walked off the same ONE list, so the next pin meets the set where it
/// joins.
#[test]
fn the_deposit_class_types_are_the_pins_they_spell_again_and_prefix_free_otherwise() {
    let spelled: Vec<&Address> = skep_arrangement::deposit_class_types().iter().collect();
    let parsed_rows = [
        t_request_fresh(),
        t_request_board_carries_on(),
        t_reply_approved(),
        t_reply_refused(),
        t_reply_denied(),
        t_vouch(),
        t_binding(),
        t_endpoint(),
    ];
    let expected: Vec<&Address> = [t_enroll(), t_retire()].into_iter().chain(parsed_rows).collect();
    assert_eq!(
        spelled, expected,
        "the set is the two credential pins, then the registry's parsed rows in the table's order"
    );
    // The registry's members are its deposit-carrying rows whose body the
    // registry crate parses: the binding's and the endpoint's, and each row
    // a registration kind names — never a row that carries no deposit.
    for row in parsed_rows {
        let row = skep_registry::row_at(row).expect("a registry row");
        assert!(row.carries_deposits() && row.type_value.is_some(), "{}", row.address);
        let parsed = skep_registry::RegistrationKind::at(&row.address).is_some()
            || [t_binding(), t_endpoint()].contains(&&row.address);
        assert!(parsed, "{}: a row whose body is parsed", row.address);
    }
    let nested = nested_pairs();
    for ty in skep_arrangement::deposit_class_types() {
        let credential = [t_enroll(), t_retire()].contains(&ty);
        for (read, _) in PINS {
            let pin = read();
            if pin == ty {
                continue;
            }
            let related =
                is_prefix(ty.tumbler(), pin.tumbler()) || is_prefix(pin.tumbler(), ty.tumbler());
            let own_nesting = !credential && nested.contains(&(pin, ty));
            assert!(
                !related || own_nesting,
                "the deposit-class type {} and the pin {} are prefix-related",
                ty.tumbler(),
                pin.tumbler()
            );
            assert!(
                !is_prefix(ty.tumbler(), pin.tumbler()),
                "the pin {} sits beneath the deposit-class type {}: a member is a leaf",
                pin.tumbler(),
                ty.tumbler()
            );
        }
    }
}

/// THE ONE `TypeAddrs` (AUTH-2.79) is built over the three credential
/// pins — each recognized as its own kind, in the declared order enroll ·
/// retire · claim — and recognizes nothing else: a content I-span (the
/// shape a V-spec type slot records, AUTH-3.70's conformance expression
/// in miniature), a shipped reserved class (ghost position 1, the content
/// subspace), and the grant's subspace-3 pin beside them all answer
/// `None`. And it is ONE value, held: two reads are one instance, so the
/// fold hook and the daemon's classifiers cannot drift apart.
#[test]
fn identity_types_recognize_the_three_credential_pins_and_nothing_else() {
    use skep_address::subtree_of;
    use skep_identity::CredentialKind;

    let unit = |a: &Address| [subtree_of(a.tumbler())];
    assert_eq!(IDENTITY_TYPES.kind_of(&unit(t_enroll())), Some(CredentialKind::Enroll));
    assert_eq!(IDENTITY_TYPES.kind_of(&unit(t_retire())), Some(CredentialKind::Retire));
    assert_eq!(IDENTITY_TYPES.kind_of(&unit(t_claim())), Some(CredentialKind::Claim));
    let ghost_one = commons_type(1);
    let shipped = {
        let comps = [1u32, 1, 0, 1, 0, 1, 0, 1, 1];
        validate(Tumbler::new(comps.into_iter().map(Nat::from)).expect("nonempty"))
            .expect("T4-valid")
    };
    assert_ne!(shipped, ghost_one, "subspace 1 of the ghost document is not subspace 3");
    assert_eq!(IDENTITY_TYPES.kind_of(&unit(&shipped)), None);
    assert_eq!(IDENTITY_TYPES.kind_of(&unit(t_grant())), None);
    let content = {
        let comps = [1u32, 0, 1, 0, 1, 0, 1, 1];
        validate(Tumbler::new(comps.into_iter().map(Nat::from)).expect("nonempty"))
            .expect("T4-valid")
    };
    assert_eq!(IDENTITY_TYPES.kind_of(&unit(&content)), None);
    assert!(
        std::ptr::eq(&*IDENTITY_TYPES, &*IDENTITY_TYPES),
        "one instance, however many readers"
    );
}

/// Every pin sits in the ghost document's subspace 3, where nothing is
/// ever minted (the credential types' own unreachability argument,
/// AUTH-3.70), so no content resolution can ever equal one — and at the
/// ordinals its own doc cites, so a silent renumbering fails here.
#[test]
fn every_pin_is_a_ghost_subspace_3_element() {
    for (read, ordinals) in PINS {
        assert_eq!(read().tumbler().to_string(), format!("1.1.0.1.0.1.0.3.{ordinals}"));
    }
}

/// THE REGISTRY'S ROWS ARE THE CRATE'S TABLE (the module doc): the
/// readers hand back the crate's own held rows, `t_successor_of`
/// — the engine's own pin, the registry's fourth kind — EQUALS the
/// crate's `3.59`, and the class pins outside the registry are exactly
/// the ledger's rows the crate's table does not hold, the three
/// credential pins — the fold's kinds, which stand beside that list —
/// set apart.
#[test]
fn the_registry_rows_are_the_crates_table_and_successor_of_is_held_equal() {
    for r in skep_registry::rows() {
        let held = PINS.iter().find(|(read, _)| *read() == r.address);
        assert!(held.is_some(), "{} is a registry row and no pin", r.address.tumbler());
    }
    assert_eq!(t_successor_of(), skep_registry::t_successor_of());
    assert!(std::ptr::eq(t_binding(), skep_registry::t_binding()), "one held row, not a copy");
    let credential = [t_enroll(), t_retire(), t_claim()];
    let outside: Vec<&Address> = PINS
        .iter()
        .map(|(read, _)| read())
        .filter(|a| !is_registry_row(a) && !credential.contains(a))
        .collect();
    assert_eq!(outside, pins_outside_the_registry());
}

/// THE PIN SPELLED TWICE (the module doc): [`t_replaces`] and M7's own
/// spelling, which its sole-writer fences and its one writer read, are
/// one address — so the class the fold reads a grant's `replaces` by is
/// the class M7 fences and mints, and a renumbering of either fails here.
#[test]
fn the_replaces_pin_is_the_address_m7_fences_and_mints() {
    assert_eq!(t_replaces(), skep_links::replaces_type());
    assert!(skep_links::is_replaces_class(&skep_links::enc([t_replaces()])));
}

/// THE SECOND PIN SPELLED TWICE (the module doc): [`t_correspondence`] and
/// M7's own spelling, which its sole-writer fences read ahead of the one
/// writer the publish lane will build, are one address — so the class the
/// daemon refuses a `nullify` at is the class M7 fences, and a renumbering
/// of either fails here. The class is subtype-exact: the parent
/// `counterpart` `3.102`, which is no pin, is not it, and the two
/// sole-writer classes are disjoint.
#[test]
fn the_correspondence_pin_is_the_address_m7_fences() {
    use skep_links::{enc, is_correspondence_class, is_replaces_class};

    assert_eq!(t_correspondence(), skep_links::correspondence_type());
    assert_eq!(t_correspondence().tumbler().to_string(), "1.1.0.1.0.1.0.3.102.1");
    assert!(is_correspondence_class(&enc([t_correspondence()])));
    let parent = commons_type(102);
    assert!(is_prefix(parent.tumbler(), t_correspondence().tumbler()), "a subtype under counterpart");
    assert!(!is_correspondence_class(&enc([&parent])), "the parent is not the class");
    assert!(!is_correspondence_class(&enc([&parent, t_correspondence()])), "the parent covers its subtype");
    assert!(!is_replaces_class(&enc([t_correspondence()])) && !is_correspondence_class(&enc([t_replaces()])));
    assert!(PINS.iter().all(|(read, _)| *read() != parent), "`3.102` is no pin");
}

/// A pin is ONE value, held: two reads hand back the same address, not
/// two equal ones. The ledger's readers are on hot paths — the grant fold
/// consults [`t_grant`] per folded link record, live and through replay —
/// so a reader that rebuilt its address per call would be paying nine
/// big-integer allocations and a T4 walk for a compiled constant.
#[test]
fn every_pin_is_one_held_value_rather_than_a_construction_per_read() {
    for (read, _) in PINS {
        assert!(
            std::ptr::eq(read(), read()),
            "{} is rebuilt per read, not held",
            read().tumbler()
        );
    }
}
