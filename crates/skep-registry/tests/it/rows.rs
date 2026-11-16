//! The rows from outside the crate. Commons-map's table is transcribed here
//! ONCE, [`THE_MAP`], and every question the map answers of a row is asked
//! of every line; beside it stand the laws the table holds whatever its
//! lines, the counts read off the lists, and `commons_type`'s panics. What
//! only `rows.rs`'s privates can show — the registry range, its ordinal
//! reader, and `row_at` against the type subspace's own prefix — is that
//! module's unit suite.

use skep_address::{is_prefix, Address};
use skep_registry::{
    commons_type, rows, t_approval, t_binding, t_disavowal, t_endpoint, t_expulsion_ground,
    t_policy_link, t_policy_link_own, t_registration, t_reply, t_reply_approved, t_reply_denied,
    t_reply_refused, t_request, t_request_board_carries_on, t_request_fresh, t_succession_ground,
    t_succession_policy, t_successor_of, t_takedown_base, t_takedown_lifted, t_takedown_record,
    t_vouch, Kind, Row, RowOf, Subtype,
};

/// One line of commons-map's table "THE REGISTRY'S ROWS", as this suite
/// transcribes it: what the row is the row of, its held reader, its
/// ordinals under the commons' type subspace, the `type` string its body
/// carries, and whether a deposit rides its address (the map's "Deposits"
/// column, REG-1.18).
struct MapLine {
    of: RowOf,
    read: fn() -> &'static Address,
    ordinals: &'static str,
    type_value: Option<&'static str>,
    carries_deposits: bool,
}

/// THE MAP, line by line in its order — this suite's ONE transcription of
/// the table, kept as the engine's ledger tests keep their `PINS`: every
/// question the map answers of a row is asked of every line at once
/// (`the_table_is_the_maps_line_by_line`), so a row the table gains
/// (REG-1.15) owes one line here and meets every question where it joins.
/// No line already here changes its Deposits: a new subtype row joins under
/// the takedown record, the policy link or the registration — or under the
/// parent rows `request` and `reply` — whose own addresses carry no deposit
/// already (REG-1.19), and a kind that reads one way takes none (REG-1.86,
/// HOW A FORM CHANGES LATER).
const THE_MAP: &[MapLine] = &[
    MapLine {
        of: RowOf::Kind(Kind::Registration),
        read: t_registration,
        ordinals: "54",
        type_value: None,
        carries_deposits: false,
    },
    MapLine {
        of: RowOf::Subtype(Subtype::Request),
        read: t_request,
        ordinals: "54.1",
        type_value: None,
        carries_deposits: false,
    },
    MapLine {
        of: RowOf::Subtype(Subtype::RequestFresh),
        read: t_request_fresh,
        ordinals: "54.1.1",
        type_value: Some("fresh"),
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Subtype(Subtype::RequestBoardCarriesOn),
        read: t_request_board_carries_on,
        ordinals: "54.1.2",
        type_value: Some("board-carries-on"),
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Subtype(Subtype::Reply),
        read: t_reply,
        ordinals: "54.2",
        type_value: None,
        carries_deposits: false,
    },
    MapLine {
        of: RowOf::Subtype(Subtype::ReplyApproved),
        read: t_reply_approved,
        ordinals: "54.2.1",
        type_value: Some("approved"),
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Subtype(Subtype::ReplyRefused),
        read: t_reply_refused,
        ordinals: "54.2.2",
        type_value: Some("refused"),
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Subtype(Subtype::ReplyDenied),
        read: t_reply_denied,
        ordinals: "54.2.3",
        type_value: Some("denied"),
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Subtype(Subtype::Vouch),
        read: t_vouch,
        ordinals: "54.3",
        type_value: Some("vouch"),
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Subtype(Subtype::Approval),
        read: t_approval,
        ordinals: "54.4",
        type_value: None,
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Kind(Kind::Binding),
        read: t_binding,
        ordinals: "55",
        type_value: Some("binding"),
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Kind(Kind::Endpoint),
        read: t_endpoint,
        ordinals: "56",
        type_value: Some("endpoint"),
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Kind(Kind::TakedownRecord),
        read: t_takedown_record,
        ordinals: "57",
        type_value: None,
        carries_deposits: false,
    },
    MapLine {
        of: RowOf::Subtype(Subtype::TakedownBase),
        read: t_takedown_base,
        ordinals: "57.1",
        type_value: Some("takedown"),
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Subtype(Subtype::TakedownLifted),
        read: t_takedown_lifted,
        ordinals: "57.2",
        type_value: None,
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Kind(Kind::PolicyLink),
        read: t_policy_link,
        ordinals: "58",
        type_value: None,
        carries_deposits: false,
    },
    MapLine {
        of: RowOf::Subtype(Subtype::PolicyLinkOwn),
        read: t_policy_link_own,
        ordinals: "58.1",
        type_value: None,
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Subtype(Subtype::Disavowal),
        read: t_disavowal,
        ordinals: "58.2",
        type_value: Some("disavowal"),
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Subtype(Subtype::ExpulsionGround),
        read: t_expulsion_ground,
        ordinals: "58.3",
        type_value: Some("expulsion-ground"),
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Subtype(Subtype::SuccessionGround),
        read: t_succession_ground,
        ordinals: "58.4",
        type_value: Some("succession-ground"),
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Subtype(Subtype::SuccessionPolicy),
        read: t_succession_policy,
        ordinals: "58.5",
        type_value: Some("succession-policy"),
        carries_deposits: true,
    },
    MapLine {
        of: RowOf::Kind(Kind::SuccessorOf),
        read: t_successor_of,
        ordinals: "59",
        type_value: None,
        carries_deposits: true,
    },
];

/// REG-1.14, REG-1.15, REG-1.18, REG-1.26, REG-1.86 (a) — THE TABLE IS THE
/// MAP'S, line by line, in its order and no line short: each row is the
/// row of its line's kind or subtype, at its line's address, with its line's
/// `type` string and deposits, and its reader hands back that row's own
/// address, held — two reads one address, not two equal ones.
#[test]
fn the_table_is_the_maps_line_by_line() {
    assert_eq!(rows().len(), THE_MAP.len(), "one line per row of the table");
    for (r, line) in rows().iter().zip(THE_MAP) {
        let (of, read) = (line.of, line.read);
        assert_eq!(r.of, of);
        assert_eq!(r.address.to_string(), format!("1.1.0.1.0.1.0.3.{}", line.ordinals), "{of:?}");
        assert_eq!(r.type_value, line.type_value, "{of:?}");
        assert_eq!(
            r.carries_deposits(),
            line.carries_deposits,
            "{of:?}: no line's Deposits moves — a kind that reads one way takes no subtype row \
             (REG-1.86, HOW A FORM CHANGES LATER)"
        );
        assert!(std::ptr::eq(read(), &r.address), "{of:?}: the reader is the row's own address");
        assert!(std::ptr::eq(read(), read()), "{of:?}: rebuilt per read");
        assert_eq!(r.ordinal_path(), format!("3.{}", line.ordinals), "{of:?}: the ordinal path");
    }
}

/// REG-1.25, REG-1.26 — THE COUNTS ARE READ OFF THE LISTS and written as a
/// tally nowhere: the table holds one row a kind and one a subtype, each
/// once, so its length is the two lists' and no number of its own; the
/// kinds are the rows whose address is a bare ordinal, the subtype rows the
/// rest; and as the list stands that is REG-1.26's own sentence — six
/// kinds and sixteen subtype rows, twenty-two rows, a parent row counted as
/// the row it is — which this suite's one transcription of the map agrees
/// with line for line.
#[test]
fn the_counts_are_read_off_the_lists() {
    let (kinds, subtypes) = (Kind::ALL.len(), Subtype::ALL.len());
    assert_eq!(rows().len(), kinds + subtypes, "every kind's row plus every subtype's");
    for &kind in Kind::ALL {
        assert_eq!(rows().iter().filter(|r| r.of == RowOf::Kind(kind)).count(), 1, "{kind:?}");
    }
    for &subtype in Subtype::ALL {
        let held = rows().iter().filter(|r| r.of == RowOf::Subtype(subtype)).count();
        assert_eq!(held, 1, "{subtype:?}");
    }
    let bare = |r: &&Row| r.address.element_field().is_some_and(|e| e.len() == 2);
    assert_eq!(rows().iter().filter(bare).count(), kinds, "a kind's row is a bare ordinal");
    let transcribed = |want: fn(&RowOf) -> bool| THE_MAP.iter().filter(|l| want(&l.of)).count();
    assert_eq!(transcribed(|of| matches!(of, RowOf::Kind(_))), kinds);
    assert_eq!(transcribed(|of| matches!(of, RowOf::Subtype(_))), subtypes);
    assert_eq!(
        (kinds, subtypes, rows().len()),
        (6, 16, 22),
        "REG-1.26, as the list stands: six kinds and sixteen subtype rows, twenty-two rows"
    );
}

/// REG-1.18's test read off the table's ADDRESSES: a row carries
/// deposits exactly where no other row nests under it — so the column
/// computed off the subtypes' kinds agrees with the subtype rows the table
/// places under each kind.
#[test]
fn a_row_carries_deposits_exactly_where_no_other_row_nests_under_it() {
    for r in rows() {
        let nested = rows()
            .iter()
            .any(|s| s.address != r.address && is_prefix(r.address.tumbler(), s.address.tumbler()));
        assert_eq!(r.carries_deposits(), !nested, "{}", r.address);
    }
}

/// … and answered off what a row is the row OF, never off its address, as
/// `Row::carries_deposits`' doc states: each line's row built again at
/// `3.53` — an address no row of the table holds and nothing nests under —
/// answers its line's Deposits, the takedown record's, the policy link's
/// and the registration's `false` among them, and the parent rows'
/// `request` and `reply` with them: a parent row carries none (REG-1.18).
#[test]
fn a_row_answers_its_deposits_off_what_it_is_the_row_of() {
    let elsewhere = commons_type(&[53]);
    for line in THE_MAP {
        let row = Row { of: line.of, address: elsewhere.clone(), type_value: line.type_value };
        assert_eq!(row.carries_deposits(), line.carries_deposits, "{:?} at {elsewhere}", line.of);
    }
}

/// Every row nests under its own kind's row alone: a subtype row is a
/// PREFIX under its own kind's row (REG-1.20) and under no other kind's,
/// and a kind's own row is that row itself, under no other kind's — the
/// kind rows are pairwise prefix-free. And A ROW UNDER A ROW NESTS UNDER
/// ITS PARENT ROW ALONE: among the subtype rows one is a prefix of another
/// exactly where it is that row's parent ([`Subtype::parent`]), one ordinal
/// deeper, so a row under `request` is no row under `reply` and the vouch
/// and the approval stand under neither.
#[test]
fn every_row_nests_under_its_own_kinds_row_alone() {
    let kind_rows: Vec<&Row> = rows().iter().filter(|r| matches!(r.of, RowOf::Kind(_))).collect();
    for (i, a) in kind_rows.iter().enumerate() {
        for b in &kind_rows[i + 1..] {
            assert!(
                !is_prefix(a.address.tumbler(), b.address.tumbler())
                    && !is_prefix(b.address.tumbler(), a.address.tumbler())
            );
        }
    }
    let subtype_rows: Vec<&Row> =
        rows().iter().filter(|r| matches!(r.of, RowOf::Subtype(_))).collect();
    for r in &subtype_rows {
        for k in &kind_rows {
            let nested = is_prefix(k.address.tumbler(), r.address.tumbler());
            assert_eq!(nested, k.of.kind() == r.of.kind(), "{:?} under {:?}", r.of, k.of);
        }
        for p in &subtype_rows {
            if p.address == r.address {
                continue;
            }
            let nested = is_prefix(p.address.tumbler(), r.address.tumbler());
            let is_parent = r.of.subtype().and_then(Subtype::parent) == p.of.subtype();
            assert_eq!(nested, is_parent, "{:?} under {:?}", r.of, p.of);
        }
        let above = r.of.above().expect("a subtype row stands beneath a row");
        let above_row = rows().iter().find(|a| a.of == above).expect("the row above is a row");
        assert_eq!(
            r.address.tumbler().len(),
            above_row.address.tumbler().len() + 1,
            "{:?}: one ordinal deeper than the row it stands beneath",
            r.of
        );
    }
}

/// REG-1.18, REG-1.15 — THE PARENT ROWS: `request` and `reply` are the
/// subtype rows that read more than one way — each names no parent of its
/// own, stands directly beneath the registration's kind row, is named the
/// parent of its readings and of no other row, and carries no deposit; the
/// rows beneath them, the vouch and the approval carry theirs.
#[test]
fn the_parent_rows_are_the_request_and_the_reply() {
    let parents: Vec<Subtype> =
        Subtype::ALL.iter().copied().filter(|s| Subtype::ALL.iter().any(|c| c.parent() == Some(*s))).collect();
    assert_eq!(parents, [Subtype::Request, Subtype::Reply]);
    for parent in parents {
        assert_eq!(parent.parent(), None, "{parent:?}: a parent row stands under its kind");
        assert_eq!(RowOf::Subtype(parent).above(), Some(RowOf::Kind(Kind::Registration)));
        assert!(!parent.row().carries_deposits(), "{parent:?}: no deposit on a parent row");
        assert_eq!(parent.row().type_value, None, "{parent:?}: the type of no body");
    }
    let under = |parent: Subtype| -> Vec<Subtype> {
        Subtype::ALL.iter().copied().filter(|s| s.parent() == Some(parent)).collect()
    };
    assert_eq!(under(Subtype::Request), [Subtype::RequestFresh, Subtype::RequestBoardCarriesOn]);
    assert_eq!(
        under(Subtype::Reply),
        [Subtype::ReplyApproved, Subtype::ReplyRefused, Subtype::ReplyDenied]
    );
    for &subtype in Subtype::ALL {
        let of = RowOf::Subtype(subtype);
        let above = of.above().expect("a subtype row stands beneath a row");
        assert_eq!(above.kind(), subtype.kind(), "{subtype:?}: the row above is of its kind");
        let listed = |s: Subtype| Subtype::ALL.iter().position(|x| *x == s).expect("listed");
        if let Some(parent) = subtype.parent() {
            assert!(listed(parent) < listed(subtype), "{subtype:?}: its parent is listed ahead");
        }
    }
    assert_eq!(RowOf::Kind(Kind::Registration).above(), None, "a kind's row stands beneath none");
}

/// Each kind and each subtype names its own row of the table, held: a
/// kind its bare row, a subtype the row under the kind it names — and
/// the row's [`RowOf`] reads back the kind and the subtype it is of.
#[test]
fn each_kind_and_subtype_names_its_own_row() {
    for &kind in Kind::ALL {
        let r = kind.row();
        assert_eq!((r.of, r.of.kind(), r.of.subtype()), (RowOf::Kind(kind), kind, None));
        assert!(std::ptr::eq(r, kind.row()), "{kind:?}");
    }
    for &subtype in Subtype::ALL {
        let r = subtype.row();
        let of = (r.of, r.of.kind(), r.of.subtype());
        assert_eq!(of, (RowOf::Subtype(subtype), subtype.kind(), Some(subtype)));
        assert!(std::ptr::eq(r, subtype.row()), "{subtype:?}");
    }
}

/// `commons_type` PANICS on no ordinal, as its doc states: the commons' type
/// subspace itself, above every row, is no row and never answered as one.
#[test]
#[should_panic(expected = "a commons row names at least one ordinal")]
fn commons_type_panics_on_an_empty_ordinal_list() {
    let _ = commons_type(&[]);
}

/// … and PANICS on a zero among the ordinals, by a check of its own whose
/// message names the caller's broken obligation: a row is an element at
/// positive ordinals — a zero there would be a fourth zero component, which
/// no T4-valid address holds.
#[test]
#[should_panic(expected = "a commons row's ordinals are positive")]
fn commons_type_panics_on_a_zero_ordinal() {
    let _ = commons_type(&[58, 0]);
}

/// THE MAP'S ORDER as a law, whatever the table's lines: `rows()` ascends in
/// the tumbler order (T1), as its doc states, so a row the table gains
/// (REG-1.15) takes its place by its address. The instances — the
/// registration and its rows ahead of the binding, though `Kind::ALL`,
/// REG-1.14's order, lists the registration last, and the policy link and
/// its readings ahead of `successor-of`, which that order lists first — are
/// [`THE_MAP`]'s line order.
#[test]
fn the_rows_stand_in_ascending_tumbler_order() {
    for pair in rows().windows(2) {
        let (a, b) = (&pair[0].address, &pair[1].address);
        assert!(a < b, "{a} stands ahead of {b}");
    }
}
