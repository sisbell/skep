//! The line-break counts and the two reads over them, with no kernel: that a
//! line break is a position whose value is the single byte `0x0A` — a byte of
//! a stretch or a one-byte value, staged by this build or folded from the
//! per-byte record a build without stretches journals — and nothing else,
//! neither `\r`, U+2028, nor any byte of an atom; that the line breaks
//! before an address are exactly those the point queries find below it on
//! its chain, inside one stretch, across stretches and a value, across a
//! gap, at and past the frontier and on a chain nothing is stored on, so a
//! run's count is the difference of two reads whatever it spans and
//! wherever it is cut; that a key off a chain neither adds to the chain's
//! count nor hides the entries below it; that the n-th line break from an
//! address is the one a walk of the chain finds, within a stretch and
//! across stretches, and none past the last or past `u64`; and that the
//! counts are a function of the entries, the same in every order one
//! chain's entries can be folded in and after a decode, each chain's its
//! own in every order several chains' entries can be folded in, the same
//! once both maps are several B-tree leaves deep, and kept at an address of
//! every shape a decode admits, a one-component one included.

use std::collections::BTreeSet;

use skep_address::{Nat, Tumbler};
use skep_content::{stage_stretch, stage_write, ContentStore, ContentStretch, ContentWrite, Piece};

use crate::common::*;

/// The line break's byte, spelled here as the rule spells it.
const LINE_BREAK: u8 = 0x0A;

/// The chain `ca` mints on: document `[1, 0, 1, 0, 1]`'s content.
const CONTENT: &[u32] = &[1, 0, 1, 0, 1, 0, 1];

/// The tumbler at `ordinal` of the chain whose other components are `chain`.
/// Ordinal zero included: no address, and a tumbler a read answers at.
fn on(chain: &[u32], ordinal: u32) -> Tumbler {
    t(&[chain, &[ordinal][..]].concat())
}

/// The ordinals up to `limit` on `chain` where a point query answers exactly
/// the line break's byte: the rule, read off `value_at` one address at a
/// time.
fn line_breaks_found(c: &ContentStore, chain: &[u32], limit: u32) -> Vec<u32> {
    (0..=limit).filter(|&o| read(c, &on(chain, o)) == Some(vec![LINE_BREAK])).collect()
}

/// Holds `line_breaks_before` to the point queries at every ordinal of
/// `chain` up to `limit`, which the caller sets past the chain's last stored
/// address.
#[track_caller]
fn assert_the_count_before_every_address_is_the_point_queries(
    c: &ContentStore,
    chain: &[u32],
    limit: u32,
) {
    let found = line_breaks_found(c, chain, limit);
    for ordinal in 0..=limit {
        let below = found.iter().filter(|&&o| o < ordinal).count() as u64;
        assert_eq!(
            c.line_breaks_before(&on(chain, ordinal)),
            below,
            "the line breaks before {} are not those the point queries find below it",
            on(chain, ordinal)
        );
    }
}

/// Holds `nth_line_break_from` to a walk of the point queries: from every
/// ordinal of `chain` up to `limit`, every `n` up to one past the chain's
/// count.
#[track_caller]
fn assert_the_nth_from_every_address_is_the_one_a_walk_finds(
    c: &ContentStore,
    chain: &[u32],
    limit: u32,
) {
    let found = line_breaks_found(c, chain, limit);
    for from in 0..=limit {
        for n in 0..=found.len() {
            let walked = found.iter().filter(|&&o| o >= from).nth(n).map(|&o| on(chain, o));
            assert_eq!(
                c.nth_line_break_from(&on(chain, from), n as u64),
                walked,
                "line break {n} from {} is not the one a walk of the chain finds",
                on(chain, from)
            );
        }
    }
}

/// The line breaks of the I-extent `[start, start ⊕ width)`, counted over
/// its flattened positions as the run read lends them — each byte of a
/// stretch one position, each value one — and whether the extent is covered.
fn line_breaks_flattened(c: &ContentStore, start: &Tumbler, width: u32) -> (u64, bool) {
    let mut walk = c.pieces(start, &Nat::from(width));
    let breaks = walk
        .by_ref()
        .map(|piece| match piece {
            Piece::Bytes(b) => b.iter().filter(|&&byte| byte == LINE_BREAK).count() as u64,
            Piece::Value(v) => u64::from(v.as_bytes() == [LINE_BREAK]),
        })
        .sum();
    (breaks, walk.covered())
}

/// Three chains with content and line breaks on each: document 1's, a
/// stretch cut by an atom, a gap and a one-byte value; a version document's
/// beneath it, which sorts between document 1's content and document 64's;
/// and document 64's, starting above its first ordinal.
fn several_chains() -> ContentStore {
    let c = ContentStore::default();
    let c = with_stretch(&c, 1, b"ab\ncd\n"); // 1..=6
    let c = with_value(&c, 7, b"at\nom"); // 7: an atom
    let c = with_stretch(&c, 8, b"\n\n\n"); // 8..=10
    let c = with_stretch(&c, 13, b"x\ny\n"); // 13..=16, past a gap at 11..=12
    let c = with_value(&c, 17, b"\n"); // 17: a one-byte value
    let version = a(&[1, 0, 1, 0, 1, 1, 0, 1, 2]);
    let c = c.apply_stretch(&stage_stretch(&c, version, bytes(b"\nq\n")).expect("fresh"));
    let other = a(&[1, 0, 1, 0, 64, 0, 1, 3]);
    c.apply_stretch(&stage_stretch(&c, other, bytes(b"\n\n\nz")).expect("fresh"))
}

/// The two chains `several_chains` stores on beside `CONTENT` — the version
/// document's and document 64's — and document 65's, which it leaves empty.
const VERSION: &[u32] = &[1, 0, 1, 0, 1, 1, 0, 1];
const OTHER: &[u32] = &[1, 0, 1, 0, 64, 0, 1];
const EMPTY: &[u32] = &[1, 0, 1, 0, 65, 0, 1];

#[test]
fn a_line_break_is_a_position_holding_the_single_byte_0x0a() {
    // store/lines.rs, the rule: a line break is a position whose value is
    // the single byte `0x0A`. So in a stretch each `0x0A` is one — its first
    // byte and its last alike, the `\n` of `\r\n` and never the `\r`, no
    // byte of U+2028 (E2 80 A8); a one-byte value holding `0x0A` is one,
    // staged at this build's door or folded from the per-byte record a build
    // without stretches journals; and no other value is one — a one-byte
    // `\r`, the zero-length value, and atoms whose bytes hold `0x0A`. The
    // expected ordinals are written out, not read back from the store, so
    // the rule is held to the bytes.
    let c = ContentStore::default();
    let c = with_stretch(&c, 1, b"\nab\n"); // 1..=4: the first byte and the last
    let c = with_stretch(&c, 5, b"cd"); // 5..=6: none, and none at its end
    let c = with_stretch(&c, 7, b"\r\n"); // 7..=8: the `\n` alone
    let c = with_stretch(&c, 9, "\u{2028}".as_bytes()); // 9..=11: three bytes, none
    let c = with_value(&c, 12, b"\n"); // a one-byte value, staged

    // A one-byte value as a journal written before stretches holds it: a
    // `ContentWrite`'s bytes, its address then its value.
    let key: Vec<Nat> = ca(13).tumbler().iter().cloned().collect();
    let old_form: ContentWrite = bincode::deserialize(
        &bincode::serialize(&(key, b"\n".to_vec())).expect("the raw record serializes"),
    )
    .expect("a record's bytes are its address, then its value");
    let c = c.apply_write(&old_form);
    let c = with_value(&c, 14, b"\r"); // a one-byte value, another byte
    let c = with_value(&c, 15, b""); // the zero-length value
    let c = with_value(&c, 16, b"\n\n"); // an atom of two line-break bytes
    let c = with_value(&c, 17, b"a\nb"); // an atom holding one
    let c = with_stretch(&c, 18, b"\n"); // a stretch of one
    let line_breaks = [1u32, 4, 8, 12, 13, 18];
    assert_eq!(line_breaks_found(&c, CONTENT, 20), line_breaks, "the point queries' own answer");
    for ordinal in 0..=20u32 {
        let (at, next) = (on(CONTENT, ordinal), on(CONTENT, ordinal + 1));
        assert_eq!(
            c.line_breaks_before(&next) - c.line_breaks_before(&at),
            u64::from(line_breaks.contains(&ordinal)),
            "{at} counted as a line break, or not counted as one, against the rule"
        );
    }
    assert_eq!(c.line_breaks_before(&on(CONTENT, 0)), 0);
    assert_eq!(c.line_breaks_before(&on(CONTENT, 21)), 6);
    let answered: Vec<Option<Tumbler>> =
        (0..=6).map(|n| c.nth_line_break_from(&on(CONTENT, 0), n)).collect();
    let expected: Vec<Option<Tumbler>> =
        line_breaks.iter().map(|&o| Some(on(CONTENT, o))).chain(std::iter::once(None)).collect();
    assert_eq!(answered, expected, "the chain's line breaks, in order, then none");
}

#[test]
fn the_breaks_before_an_address_are_those_the_point_queries_find_below_it() {
    // store.rs (`line_breaks_before`): the count before `a` is the count of
    // addresses below `a` on its chain where `value_at` answers `[0x0A]`.
    // A law over every address, so it is held at every ordinal of three
    // chains from zero to past the frontier — inside a stretch, at each
    // entry boundary, at the atom, in the gap nothing is stored in — and on
    // a fourth chain nothing is stored on, which answers zero everywhere.
    // One chain's count never reaches another's: the version document's
    // keys sort between document 1's content and document 64's.
    let c = several_chains();
    for (chain, limit) in [(CONTENT, 20), (VERSION, 7), (OTHER, 9), (EMPTY, 5)] {
        assert_the_count_before_every_address_is_the_point_queries(&c, chain, limit);
    }
    assert_eq!(c.line_breaks_before(&on(CONTENT, 20)), 8, "document 1's chain holds eight");
    assert_eq!(c.line_breaks_before(&on(VERSION, 7)), 2);
    assert_eq!(c.line_breaks_before(&on(OTHER, 9)), 3);
    assert_eq!(c.line_breaks_before(&on(EMPTY, 5)), 0);
    // A run's line breaks are the count before its reach less the count
    // before its start, whatever it spans: inside one stretch and cut at
    // both ends, across a stretch, the atom and a stretch, entered and left
    // mid-stretch, and up to the frontier across a stretch and a one-byte
    // value — each against a count over the run's flattened positions.
    for (what, start, width) in [
        ("inside one stretch, cut at both ends", 2u32, 3u32),
        ("one stretch whole", 1, 6),
        ("a stretch, the atom and a stretch", 1, 10),
        ("entered and left mid-stretch", 5, 5),
        ("a stretch and a one-byte value, to the frontier", 14, 4),
        ("no position at all", 9, 0),
    ] {
        let (flattened, covered) = line_breaks_flattened(&c, &on(CONTENT, start), width);
        assert!(covered, "{what}: the premise, a run every address of which is stored");
        assert_eq!(
            c.line_breaks_before(&on(CONTENT, start + width))
                - c.line_breaks_before(&on(CONTENT, start)),
            flattened,
            "{what}: the two reads disagree with the run's flattened bytes"
        );
    }
}

#[test]
fn a_key_off_the_chain_neither_adds_to_a_chains_count_nor_hides_it() {
    // store/lines.rs (`floor`): a key that extends a chain address —
    // `D·0·1·3·7` beside the value at `D·0·1·3` — sorts above that address
    // and below the next, is admitted by both doors, and counts for a chain
    // of its own. So the greatest counted key at or below an address is not
    // always on its chain: here the keys under ordinals 3 and 4 each hold a
    // line break and stand between the stretch at 1 and every address above
    // 4. The reads pass over them: the count before each address of
    // `D·0·1·x` is the point queries', the breaks in the stretch at 1
    // neither hidden nor joined by the three keys' own, and each of the two
    // chains those keys open counts by itself.
    let c = with_stretch(&ContentStore::default(), 1, b"\n\n"); // 1..=2
    let c = with_value(&c, 3, b"atom"); // 3
    let c = with_value(&c, 4, b"next"); // 4
    let c = with_stretch(&c, 5, b"cd"); // 5..=6: no line break of its own
    let c = with_stretch(&c, 8, b"\n"); // 8, past a gap
    let i = a(&[1, 0, 1, 0, 1, 0, 1, 3, 7]);
    let kl = a(&[1, 0, 1, 0, 1, 0, 1, 3, 8]);
    let j = a(&[1, 0, 1, 0, 1, 0, 1, 4, 2, 9]);
    let c = c.apply_write(&stage_write(&c, i, val(b"\n")).expect("nothing covers it"));
    let c = c.apply_stretch(&stage_stretch(&c, kl, bytes(b"\n\n")).expect("nothing covers it"));
    let c = c.apply_write(&stage_write(&c, j, val(b"\n")).expect("nothing covers it"));
    assert_eq!(c.len(), 8, "the premise: five entries on the chain, three off it");
    let under_3: &[u32] = &[1, 0, 1, 0, 1, 0, 1, 3];
    let under_4_2: &[u32] = &[1, 0, 1, 0, 1, 0, 1, 4, 2];
    for (chain, limit) in [(CONTENT, 10), (under_3, 11), (under_4_2, 11)] {
        assert_the_count_before_every_address_is_the_point_queries(&c, chain, limit);
        assert_the_nth_from_every_address_is_the_one_a_walk_finds(&c, chain, limit);
    }
    // The counts, written out: two below ordinal 3 and up to 8, where the
    // keys off the chain stand between; three past 8; and the two chains
    // the keys open, three and one.
    for ordinal in 3..=8 {
        assert_eq!(c.line_breaks_before(&on(CONTENT, ordinal)), 2, "before ordinal {ordinal}");
    }
    assert_eq!(c.line_breaks_before(&on(CONTENT, 9)), 3);
    assert_eq!(c.line_breaks_before(&on(under_3, 11)), 3);
    assert_eq!(c.line_breaks_before(&on(under_4_2, 11)), 1);
    assert_eq!(c.nth_line_break_from(&on(CONTENT, 3), 0), Some(on(CONTENT, 8)));
}

#[test]
fn the_nth_break_from_an_address_is_found_within_and_across_stretches() {
    // store.rs (`nth_line_break_from`): the n-th line break at or above an
    // address, `n` from zero, is the one a walk of the chain's addresses
    // finds — inside the stretch the address falls in, in a later entry
    // across an atom and a gap, at the address itself where it is one — and
    // `None` past the chain's last. A law over every address and every `n`,
    // held on three chains and on one nothing is stored on.
    let c = several_chains();
    for (chain, limit) in [(CONTENT, 20), (VERSION, 7), (OTHER, 9), (EMPTY, 5)] {
        assert_the_nth_from_every_address_is_the_one_a_walk_finds(&c, chain, limit);
    }
    // Written out: from inside the first stretch, the break at its own
    // address, the next in the same stretch, and the first of the next
    // entry past the atom; from the gap, the first past it.
    assert_eq!(c.nth_line_break_from(&on(CONTENT, 3), 0), Some(on(CONTENT, 3)));
    assert_eq!(c.nth_line_break_from(&on(CONTENT, 3), 1), Some(on(CONTENT, 6)));
    assert_eq!(c.nth_line_break_from(&on(CONTENT, 4), 1), Some(on(CONTENT, 8)));
    assert_eq!(c.nth_line_break_from(&on(CONTENT, 11), 0), Some(on(CONTENT, 14)));
    assert_eq!(c.nth_line_break_from(&on(CONTENT, 18), 0), None, "none at or past the frontier");
    // An `n` no chain holds, added to the count already below the address:
    // the sum passes `u64`, and the answer is `None`, never a wrapped count
    // that names the chain's first line break.
    for from in [0u32, 4, 20] {
        assert_eq!(
            c.nth_line_break_from(&on(CONTENT, from), u64::MAX),
            None,
            "line break u64::MAX from ordinal {from}"
        );
    }
}

#[test]
fn every_fold_order_of_one_chain_gives_one_store_equal_to_its_decode() {
    // store/lines.rs: the counts are a function of the entries, in whatever
    // order they are folded — a fold below a chain's highest counted entry
    // raises the running sum of each one above it — and the decode counts
    // the same entries again. So six entries of one chain, holding 1, 1, 1,
    // 0, 2 and 1 line breaks — stretches, a one-byte value, and one stretch
    // with none, which must stand in neither map — are folded in each of
    // their 720 orders: each order's slice equals the one folded in address
    // order and its decode, and answers both reads as that one does.
    let entries: [(u32, &[u8], bool); 6] = [
        (1, b"a\n", true),  // 1..=2
        (3, b"\n", false),  // 3: a one-byte value
        (4, b"\nb", true),  // 4..=5
        (6, b"cd", true),   // 6..=7: no line break
        (8, b"\n\n", true), // 8..=9
        (10, b"e\n", true), // 10..=11
    ];
    let fold = |order: &[usize]| {
        order.iter().fold(ContentStore::default(), |c, &k| {
            let (ordinal, b, stretch) = entries[k];
            if stretch {
                with_stretch(&c, ordinal, b)
            } else {
                with_value(&c, ordinal, b)
            }
        })
    };
    let in_order = fold(&[0, 1, 2, 3, 4, 5]);
    assert_the_count_before_every_address_is_the_point_queries(&in_order, CONTENT, 13);
    assert_the_nth_from_every_address_is_the_one_a_walk_finds(&in_order, CONTENT, 13);
    assert_eq!(in_order.line_breaks_before(&on(CONTENT, 13)), 6);
    let decoded: ContentStore =
        bincode::deserialize(&bincode::serialize(&in_order).expect("slice serializes"))
            .expect("slice decodes");
    assert_eq!(decoded, in_order, "the decode's counts are not the fold's");
    assert_the_count_before_every_address_is_the_point_queries(&decoded, CONTENT, 13);
    assert_the_nth_from_every_address_is_the_one_a_walk_finds(&decoded, CONTENT, 13);
    let orders = every_order(&[0usize, 1, 2, 3, 4, 5]);
    assert_eq!(
        orders.iter().collect::<BTreeSet<_>>().len(),
        720,
        "the generator did not yield each of the 720 orders"
    );
    for order in &orders {
        let folded = fold(order);
        assert_eq!(
            folded, in_order,
            "folded as entries {order:?}, the slice is not the one folded in address order"
        );
        for ordinal in 0..=13 {
            assert_eq!(
                folded.line_breaks_before(&on(CONTENT, ordinal)),
                in_order.line_breaks_before(&on(CONTENT, ordinal)),
                "folded as entries {order:?}: the line breaks before ordinal {ordinal}"
            );
        }
        for n in 0..=6 {
            assert_eq!(
                folded.nth_line_break_from(&on(CONTENT, 0), n),
                in_order.nth_line_break_from(&on(CONTENT, 0), n),
                "folded as entries {order:?}: line break {n} of the chain"
            );
        }
    }
}

#[test]
fn every_fold_order_of_several_chains_leaves_each_chain_its_own_counts() {
    // store/lines.rs (`Lines::count`): a fold raises the running sums above
    // it on its own chain and on no other, though every chain's entries
    // stand in one map by chain and sum. So five entries over three chains —
    // document 1's content, a version document's beneath it, which sorts
    // between, and document 64's — are folded in each of their 120 orders,
    // one chain's entries landing below, between and above the others': each
    // order's slice equals the one folded in address order, and each chain
    // answers both reads as that one does.
    let entries: [(&[u32], &[u8]); 5] = [
        (&[1, 0, 1, 0, 1, 0, 1, 1], b"a\n"),      // document 1: 1..=2
        (&[1, 0, 1, 0, 1, 0, 1, 3], b"\n\nb"),    // 3..=5
        (&[1, 0, 1, 0, 1, 1, 0, 1, 2], b"\nq\n"), // the version document: 2..=4
        (&[1, 0, 1, 0, 64, 0, 1, 3], b"\n"),      // document 64: 3
        (&[1, 0, 1, 0, 64, 0, 1, 4], b"z\n\n"),   // 4..=6
    ];
    let fold = |order: &[usize]| {
        order.iter().fold(ContentStore::default(), |c, &k| {
            let (key, b) = entries[k];
            c.apply_stretch(&stage_stretch(&c, a(key), bytes(b)).expect("fresh"))
        })
    };
    let chains = [(CONTENT, 7u32, 3u64), (VERSION, 6, 2), (OTHER, 8, 3)];
    let in_order = fold(&[0, 1, 2, 3, 4]);
    for (chain, limit, held) in chains {
        assert_the_count_before_every_address_is_the_point_queries(&in_order, chain, limit);
        assert_the_nth_from_every_address_is_the_one_a_walk_finds(&in_order, chain, limit);
        assert_eq!(in_order.line_breaks_before(&on(chain, limit)), held);
    }
    let orders = every_order(&[0usize, 1, 2, 3, 4]);
    assert_eq!(
        orders.iter().collect::<BTreeSet<_>>().len(),
        120,
        "the generator did not yield each of the 120 orders"
    );
    for order in &orders {
        let folded = fold(order);
        assert_eq!(
            folded, in_order,
            "folded as entries {order:?}, the slice is not the one folded in address order"
        );
        for (chain, limit, held) in chains {
            for ordinal in 0..=limit {
                assert_eq!(
                    folded.line_breaks_before(&on(chain, ordinal)),
                    in_order.line_breaks_before(&on(chain, ordinal)),
                    "folded as entries {order:?}: the line breaks before {}",
                    on(chain, ordinal)
                );
            }
            for n in 0..=held {
                assert_eq!(
                    folded.nth_line_break_from(&on(chain, 0), n),
                    in_order.nth_line_break_from(&on(chain, 0), n),
                    "folded as entries {order:?}: line break {n} from {}",
                    on(chain, 0)
                );
            }
        }
    }
}

#[test]
fn the_counts_hold_across_b_tree_leaves_in_a_scattered_fold_order() {
    // store/lines.rs: both maps are B-trees, and every lookup the counts
    // make — the predecessor on a chain, the entries above a key by running
    // sum, the entry holding the n-th line break — is a range read that
    // must stay sound across leaves, as the slice's own predecessor read
    // does. So 300 stretches of three bytes, a third of them holding three
    // line breaks, a third one and a third none, put both maps several
    // leaves deep; folded in a scattered order, where most folds land below
    // entries already counted and move a range of them, the slice equals
    // the one folded in address order and the one decoded, and both reads
    // answer at every address as the point queries do.
    fn stretch(k: u32) -> &'static [u8] {
        match k % 3 {
            0 => b"\n\n\n",
            1 => b"a\nb",
            _ => b"abc",
        }
    }
    fn folded(order: impl Iterator<Item = u32>) -> ContentStore {
        // Stretches at ordinals 1, 5, 9, …: three bytes each, a gap of one.
        order.fold(ContentStore::default(), |c, k| with_stretch(&c, 1 + 4 * k, stretch(k)))
    }
    let in_order = folded(0..300);
    // 37 is coprime to 300: every stretch once, out of order.
    let scattered = folded((0..300).map(|k| k * 37 % 300));
    assert_eq!(scattered, in_order, "the scattered fold's slice is not the address-order one");
    let decoded: ContentStore =
        bincode::deserialize(&bincode::serialize(&scattered).expect("slice serializes"))
            .expect("slice decodes");
    assert_eq!(decoded, in_order, "the decode's counts are not the fold's");
    let limit = 4 * 300 + 2;
    let found = line_breaks_found(&in_order, CONTENT, limit);
    assert_eq!(found.len(), 400, "the premise: 100 stretches of three and 100 of one");
    for (how, c) in [("in order", &in_order), ("scattered", &scattered), ("decoded", &decoded)] {
        let mut below = 0;
        for ordinal in 0..=limit {
            assert_eq!(
                c.line_breaks_before(&on(CONTENT, ordinal)),
                below,
                "{how}: the line breaks before ordinal {ordinal}"
            );
            below += u64::from(found.binary_search(&ordinal).is_ok());
        }
        for (n, &ordinal) in found.iter().enumerate() {
            assert_eq!(
                c.nth_line_break_from(&on(CONTENT, 0), n as u64),
                Some(on(CONTENT, ordinal)),
                "{how}: line break {n} of the chain"
            );
            // And from the line break itself, the next one.
            assert_eq!(
                c.nth_line_break_from(&on(CONTENT, ordinal), 1),
                found.get(n + 1).map(|&next| on(CONTENT, next)),
                "{how}: the line break after ordinal {ordinal}"
            );
        }
        assert_eq!(c.nth_line_break_from(&on(CONTENT, 0), 400), None, "{how}: past the last");
    }
}

#[test]
fn an_address_of_any_shape_counts_on_its_own_chain_a_one_component_one_included() {
    // store/lines.rs (`Chain`): a chain is named by the components its
    // addresses share, all but the last — none at all for a one-component
    // address. The decode and a release build's doors admit every T4-valid
    // address (common.rs, `MIS_ROUTED`), so the counts must stand at each
    // shape. A stretch of two line breaks at each, folded from a record's
    // bytes since a debug build's doors stage none, counts two on its own
    // chain, finds both, and decodes to the same slice. And a key under a
    // one-component address is off that address's chain: the line break at
    // the node address `1` — a one-byte value, whose reach is itself alone
    // — and the two under the account `1.0.1` count apart, the account's
    // passed over from `2`.
    let record = |key: &[u32], b: &[u8]| -> ContentStretch {
        let key: Vec<Nat> = key.iter().map(|&c| Nat::from(c)).collect();
        bincode::deserialize(
            &bincode::serialize(&(key, b.to_vec())).expect("the raw stretch serializes"),
        )
        .expect("a stretch's bytes are its first address, then its bytes")
    };
    for &(shape, key) in MIS_ROUTED {
        let c = ContentStore::default().apply_stretch(&record(key, b"\n\n"));
        let at = |offset: u32| skep_address::shift(&t(key), &Nat::from(offset));
        for offset in 0..=4u32 {
            assert_eq!(
                c.line_breaks_before(&at(offset)),
                u64::from(offset.min(2)),
                "{shape}: the line breaks before {}",
                at(offset)
            );
        }
        assert_eq!(c.nth_line_break_from(&at(0), 0), Some(at(0)), "{shape}: the first");
        assert_eq!(c.nth_line_break_from(&at(0), 1), Some(at(1)), "{shape}: the second");
        assert_eq!(c.nth_line_break_from(&at(0), 2), None, "{shape}: no third");
        let decoded: ContentStore =
            bincode::deserialize(&bincode::serialize(&c).expect("slice serializes"))
                .expect("slice decodes");
        assert_eq!(decoded, c, "{shape}: the decode's counts are not the fold's");
    }
    let node: ContentWrite = bincode::deserialize(
        &bincode::serialize(&(vec![Nat::from(1u32)], b"\n".to_vec()))
            .expect("the raw record serializes"),
    )
    .expect("a record's bytes are its address, then its value");
    let c = ContentStore::default().apply_write(&node).apply_stretch(&record(&[1, 0, 1], b"\n\n"));
    assert_eq!(c.line_breaks_before(&t(&[2])), 1, "the node chain holds its own one");
    assert_eq!(c.line_breaks_before(&t(&[1, 0, 3])), 2, "the account chain holds its own two");
    assert_eq!(c.nth_line_break_from(&t(&[1]), 0), Some(t(&[1])));
    assert_eq!(c.nth_line_break_from(&t(&[1]), 1), None, "the account's are no part of it");
    assert_eq!(c.nth_line_break_from(&t(&[1, 0, 1]), 1), Some(t(&[1, 0, 2])));
}
