use std::sync::Arc;

use skep_address::validate;
use skep_arrangement::{AsOf, Base, DraftBase, SetArrangement, SetMerge, Shot, ShotTerms};
use skep_content::Val;
use skep_links::{Caller, SlotArg};

use crate::canon::{to_tree, SerdeTree};
use crate::testkit::{addr, delegated_account, element, mem_engine, USER};

use super::*;

/// The top-level field names a value's serde form carries, in the order
/// its `Serialize` impl emits them — which is the order bincode lays their
/// bytes down in, and so the order M2's checkpoints encode.
fn field_names(value: &impl Serialize) -> Vec<String> {
    let SerdeTree::Map(entries) = to_tree(value) else {
        panic!("a struct transcodes as a map of its fields")
    };
    entries
        .into_iter()
        .map(|(k, _)| match k {
            SerdeTree::Str(s) => s,
            other => panic!("struct field keys are strings, got {other:?}"),
        })
        .collect()
}

/// `World`'s DECLARATION order is what M2's bincode checkpoints encode —
/// positionally, with no field names — so a reordering silently mis-reads
/// every checkpoint on disk while a rename is byte-neutral. Serde emits
/// fields in declaration order to any serializer, so the transcode's
/// COLLECTION order (before a rendering sorts it) is that order. The names
/// are here to identify the fields; the ORDER is the claim — the format
/// stamp FIRST (it is what refuses a base under a foreign format count
/// before any slice is read), the identity slice LAST (a body written before
/// it ends where it would begin, which is what lets that body read as the
/// absent slice, AUTH-2.79), and the three skip-serialized derived fields
/// absent, since they occupy no bytes.
#[test]
fn the_world_serializes_its_slices_in_declaration_order() {
    assert_eq!(
        field_names(&World::genesis()),
        ["format", "namespace", "content", "arrangement", "links", "identity"]
    );
}

/// Each slice's own checkpoint layout, at its TOP LEVEL, pinned to the
/// World format count that names it. A slice's layout is a World layout
/// ([`FormatStamp`]), and the author who changes one is a store's, with
/// no edge to this file: count 1 names thirteen layouts because slices grew
/// fields under it. This pin is where such a change meets the count — a
/// field appended, removed, renamed or reordered on any slice fails here,
/// and the failure says what it owes. The count is asserted beside the
/// fields, so a bump that leaves this pin behind fails too.
///
/// It cannot see BELOW a slice's top level: a nested type gaining a field
/// moves the World's bytes with every name here unchanged. A store that
/// pins its slice's bytes whole meets that change in its own suite — M4's
/// `the_slice_serializes_as_its_map_alone_in_tumbler_order` and M5's
/// `the_slice_serializes_as_its_eight_maps_down_to_each_entry_s_fields`,
/// each message naming the same debt, and `skep-identity`'s checkpoint
/// encodings (AUTH-1.40) — and M3's and M7's nested forms are held by M2's
/// golden where its fixture's ops reach them. Nor is the
/// dump filter's field-set check a substitute: that one asks for a
/// reduction's DISPOSITION, compiles with the `dump` feature alone, and is
/// answered without touching the count.
#[test]
fn each_slice_serializes_the_fields_the_format_count_names() {
    const PINNED_COUNT: u64 = 0x534B_5057_0000_0001;
    assert_eq!(
        WORLD_FORMAT, PINNED_COUNT,
        "WORLD_FORMAT moved without this pin: restate each slice's fields under the new count"
    );
    let world = World::genesis();
    for (slice, found, pinned) in [
        // M3's fifth field, `minted_at` — the commit position of every
        // document, member and link minted — joined the slice under the
        // same ruling renewed (the permanence record, 2026-10-22), so the
        // count did not move with it either.
        (
            "namespace",
            field_names(&world.namespace),
            &["frontiers", "nodes", "principals", "publication", "minted_at"][..],
        ),
        ("content", field_names(&world.content), &["map"]),
        // M5's fifth field, `fork_sources`, joined the slice under the
        // standing no-stamp ruling renewed (the fork-source design record,
        // decision 3, 2026-10-17: no served board exists; dev boards
        // regenerate), so the count above did not move with it — its
        // sixth, `arranged_at`, the position each document's content
        // arrangement last changed at (skep #442), under the same ruling
        // renewed once more — its seventh, `draft_bases`, each staged
        // draft's base, the extent its copy took and its source (the
        // staging act, B3-S10), under the same ruling renewed again — and
        // its eighth, `source_copied`, each forked or staged document's
        // count of its source the copy took (skep #1111), under the same
        // ruling once more.
        (
            "arrangement",
            field_names(&world.arrangement),
            &[
                "arrangements",
                "provenance",
                "birth_extents",
                "shot_terms",
                "fork_sources",
                "arranged_at",
                "draft_bases",
                "source_copied",
            ],
        ),
        ("links", field_names(&world.links), &["links"]),
        // AUTH-1.40's compatibility surface, at the World: the slice's two
        // fields, in the order `skep-identity`'s own suite pins their bytes.
        (
            "identity",
            field_names(world.identity.as_ref().expect("Σ₀ carries its slice")),
            &["sets", "claimant"],
        ),
    ] {
        assert_eq!(
            found, pinned,
            "{slice}'s checkpoint layout moved under WORLD_FORMAT {WORLD_FORMAT:#018x}: \
             that is a World layout change — bump the count, then this pin; or, under the \
             owner's no-stamp ruling, name the change in FormatStamp's list of the layouts the \
             count names, then this pin"
        );
    }
}

/// Decodes `bytes` as a World and returns the store slice its refusal names.
///
/// The refusal must say the body is in another layout of this build's format
/// (`slice`'s words) and name one of the four store slices; a body that
/// decodes, or a refusal in other words, fails at the caller's line.
#[track_caller]
fn refused_in(bytes: &[u8], what: &str) -> &'static str {
    let refusal = match bincode::deserialize::<World>(bytes) {
        Ok(_) => panic!("{what}: the body decoded"),
        Err(refusal) => refusal.to_string(),
    };
    assert!(
        refusal.contains(&format!("a body in another layout of world format {WORLD_FORMAT:#018x}")),
        "{what}: the refusal does not name another layout of this build's format: {refusal}"
    );
    ["namespace", "content", "arrangement", "links"]
        .into_iter()
        .find(|slice| refusal.contains(&format!("its {slice} slice does not decode")))
        .unwrap_or_else(|| panic!("{what}: the refusal names no store slice: {refusal}"))
}

/// Each store slice's decode refusal names that slice by its field name.
///
/// Each decodes through a door that names it: a body cut one byte into a
/// slice, every slice before it whole, is refused naming that slice by the
/// field name the World's serde form gives it, and the format beside it.
/// So the four names the doors spell are the four store fields
/// `the_world_serializes_its_slices_in_declaration_order` pins, in that
/// order. The identity slice has no such door: a body that ends in it reads
/// as the absent slice (`identity::slice_or_absent`).
#[test]
fn a_body_that_stops_decoding_in_a_store_slice_is_refused_naming_it() {
    let world = World::genesis();
    let names = field_names(&world);
    let slices = [
        bincode::serialize(&world.namespace).expect("M3 serializes"),
        bincode::serialize(&world.content).expect("M4 serializes"),
        bincode::serialize(&world.arrangement).expect("M5 serializes"),
        bincode::serialize(&world.links).expect("M7 serializes"),
    ];
    let mut whole = bincode::serialize(&FormatStamp).expect("the stamp serializes");
    for (field, bytes) in names[1..5].iter().zip(&slices) {
        let cut = [whole.as_slice(), &bytes[..1]].concat();
        assert_eq!(refused_in(&cut, field), field.as_str(), "the body cut one byte into {field}");
        whole.extend_from_slice(bytes);
    }
}

/// [`Record`]'s VARIANT ORDER is what M2's replay decodes by: bincode
/// encodes a variant as its INDEX, positionally and with no name, so a
/// rename is byte-neutral for replay and a reordering silently mis-reads
/// every journal and checkpoint on disk.
/// `the_world_serializes_its_slices_in_declaration_order` holds the same
/// obligation for [`World`]'s fields; this holds it here, where the enum
/// is `#[non_exhaustive]` because the set grows with the decomposition —
/// and the next state-contributing store's variant would sit most
/// naturally in the MIDDLE of this list, which is the edit that costs.
///
/// Four payloads come from their own stores' public steps — M3's
/// `mint_document`, M4's `stage_write` and `stage_stretch`, M5's
/// `stage_seat_link` — so each index is read off a record a store really
/// built. M7 seals its `Deposit` variant, so no crate but M7 can construct
/// a [`LinkRec`] — its index is pinned by what the decoder REFUSES instead.
/// A bare tag naming a variant gets past the tag and runs out of payload
/// (an I/O end-of-file), where one naming none is refused as a value serde
/// has no variant for. So index 3 NAMES a variant, index 4 is M4's second
/// record, `ContentStretch`, read off a record, and index 5 names the end
/// of the list; with the other four pinned that says `Links` is at 3.
///
/// A variant APPENDED after `ContentStretch` is byte-safe for replay and
/// still reddens the last refusal. That is the intent: the enum is expected
/// to grow, and an addition should be made to state where it landed here
/// rather than to land anywhere in silence.
#[test]
fn the_central_record_lifts_each_store_to_its_own_variant_index() {
    let doc = addr(&[1, 0, 1, 0, 1]);
    let (_, namespace_rec) = M3State::genesis()
        .mint_document(&skep_namespace::system_account(), false)
        .expect("the seeded system account mints a document");
    let content_rec = skep_content::stage_write(
        &ContentStore::default(),
        addr(&[1, 0, 1, 0, 1, 0, 1, 1]),
        Val::new(vec![b'x']),
    )
    .expect("a fresh content address stages a write");
    let arrangement_rec = skep_arrangement::stage_seat_link(
        &M5State::genesis(),
        &doc,
        &addr(&[1, 0, 1, 0, 1, 0, 2, 1]),
    )
    .expect("an unseated link of the document stages a seat");
    let stretch_rec = skep_content::stage_stretch(
        &ContentStore::default(),
        addr(&[1, 0, 1, 0, 1, 0, 1, 1]),
        Arc::from(&b"xy"[..]),
    )
    .expect("a fresh content address stages a stretch");

    let tag_of = |r: Record| {
        let bytes = bincode::serialize(&r).expect("a record serializes");
        u32::from_le_bytes(
            bytes[..4].try_into().expect("bincode writes a four-byte variant tag"),
        )
    };
    assert_eq!(tag_of(namespace_rec.into()), 0, "Namespace is variant 0");
    assert_eq!(tag_of(content_rec.into()), 1, "Content is variant 1");
    assert_eq!(tag_of(arrangement_rec.into()), 2, "Arrangement is variant 2");
    assert_eq!(tag_of(stretch_rec.into()), 4, "ContentStretch is variant 4");

    let refuses = |tag: u32| -> bincode::ErrorKind {
        *bincode::deserialize::<Record>(&tag.to_le_bytes())
            .expect_err("a bare tag is not a whole record")
    };
    assert!(
        matches!(refuses(3), bincode::ErrorKind::Io(_)),
        "index 3 names no variant, so Links is not there: {}",
        refuses(3)
    );
    assert!(
        matches!(refuses(4), bincode::ErrorKind::Io(_)),
        "index 4 names no variant, so ContentStretch is not there: {}",
        refuses(4)
    );
    assert!(
        matches!(refuses(5), bincode::ErrorKind::Custom(_)),
        "index 5 names a variant, so ContentStretch is not the last: {}",
        refuses(5)
    );
}

/// ONE NUMBER, TWO RECORDS, the fold-side fence: a range mint of N beside a
/// stretch of N + 1 — a pair M5's one staging site never produces, so it is
/// built here by hand through the stores' own public doors, the range off
/// M3's `mint_content_range` and the stretch off M4's `stage_stretch` —
/// fail-stops a debug build at `World::apply`'s `ContentStretch` arm, which
/// holds the stretch to the chain's frontier M3's slice carries, live and on
/// replay. The pair the staging site DOES produce, N beside N, folds and
/// answers every byte (the test below).
#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "a content stretch reaches past its document's content frontier")]
fn a_stretch_longer_than_its_range_mint_fail_stops_the_fold() {
    let engine = mem_engine();
    let acct = delegated_account(&engine, USER);
    let (doc, _) = engine
        .namespace()
        .create_new_document(USER, &acct, Some(false))
        .expect("an explicit-false mint is a draft");
    let _ = engine.kernel().transact::<_, skep_content::ContentError>(
        &[M3State::content_lock_key(&doc)],
        |stg| {
            let (first, range) = stg
                .working()
                .m3()
                .mint_content_range(&doc, &Nat::from(3u32))
                .expect("the draft is registered");
            stg.push(range.into());
            let stretch =
                skep_content::stage_stretch(stg.working().content(), first, Arc::from(&b"abcd"[..]))?;
            // The fold runs at the push: four bytes over a range of three.
            stg.push(stretch.into());
            Ok(())
        },
    );
}

/// The pair the staging site produces — a range of N and a stretch of N —
/// folds through the engine's two arms into a world whose content answers
/// every byte at the address the range minted, whose frontier stands at the
/// range's reach, and whose checkpoint bytes carry the one entry.
#[test]
fn a_range_mint_and_its_stretch_fold_into_a_world_that_answers_every_byte() {
    let engine = mem_engine();
    let acct = delegated_account(&engine, USER);
    let (doc, _) = engine
        .namespace()
        .create_new_document(USER, &acct, Some(false))
        .expect("an explicit-false mint is a draft");
    let (first, _) = engine
        .kernel()
        .transact::<_, skep_content::ContentError>(&[M3State::content_lock_key(&doc)], |stg| {
            let (first, range) = stg
                .working()
                .m3()
                .mint_content_range(&doc, &Nat::from(5u32))
                .expect("the draft is registered");
            stg.push(range.into());
            let stretch = skep_content::stage_stretch(
                stg.working().content(),
                first.clone(),
                Arc::from(&b"hello"[..]),
            )?;
            stg.push(stretch.into());
            Ok(first)
        })
        .expect("a range and its stretch commit");
    let snapshot = engine.kernel().snapshot();
    let world = snapshot.world();
    for (k, byte) in b"hello".iter().enumerate() {
        let at = validate(shift(first.tumbler(), &Nat::from(k))).expect("T4-valid");
        assert_eq!(
            world.content().value_at(at.tumbler()).map(|piece| piece.as_bytes().to_vec()),
            Some(vec![*byte])
        );
        assert!(world.m3().is_allocated(&at));
    }
    assert_eq!(
        world.m3().next_content_address(&doc),
        Some(validate(shift(first.tumbler(), &Nat::from(5u32))).expect("T4-valid")),
        "the frontier stands at the range's reach"
    );
    assert_eq!(world.content().len(), 1, "one entry for the five addresses");
    let decoded: World =
        bincode::deserialize(&bincode::serialize(world).expect("a world serializes"))
            .expect("this build's own bytes decode");
    assert_eq!(decoded.content().len(), 1);
}

/// The stamp leads the encoding, and it is eight bytes of a value no
/// pre-stamp checkpoint's first word can equal: that word is M3's
/// frontier-map LENGTH, a count.
#[test]
fn the_format_stamp_leads_the_world_s_bytes() {
    let stamp = bincode::serialize(&FormatStamp).expect("a u64 serializes");
    assert_eq!(stamp, WORLD_FORMAT.to_le_bytes(), "bincode writes the word little-endian");
    let world = bincode::serialize(&World::genesis()).expect("a world serializes");
    assert!(world.starts_with(&stamp), "the stamp is the first field");
    assert_eq!(
        bincode::deserialize::<FormatStamp>(&stamp).expect("this build's word decodes"),
        FormatStamp
    );
    assert!(
        bincode::deserialize::<FormatStamp>(&(WORLD_FORMAT + 1).to_le_bytes()).is_err(),
        "any other word refuses"
    );
}

/// PUB-7.8, at the World: a checkpoint written without the publication
/// bit FAILS TO DECODE — and so does one written with the bit but before
/// the stamp. The premise is pinned first, so the hand-built shapes are
/// the old ones and not a strawman: the current encoding IS the stamp
/// followed by the four slices and then the identity slice, and M3's slice
/// at genesis IS its old bytes followed by the publication map and the
/// position map — PUB-6.65's seed: the system account's four documents, each
/// with the bit it was born with, behind an eight-byte length, then the same
/// four at the genesis coordinate behind another (M3's own test pins that
/// half; this one rides it).
#[test]
fn a_checkpoint_without_the_bit_or_the_stamp_fails_to_decode() {
    use skep_namespace::{ghost_home_document, head_document, staging_draft, time_document};

    let world = World::genesis();
    let current = bincode::serialize(&world).expect("a world serializes");
    let stamp = bincode::serialize(&FormatStamp).expect("a u64 serializes");
    let identity = bincode::serialize(&world.identity).expect("the slice serializes");

    // The pre-stamp layout (the bit present, no leading stamp): the four
    // slices alone, in order — a tuple encodes exactly as a struct does.
    let pre_stamp =
        bincode::serialize(&(&world.namespace, &world.content, &world.arrangement, &world.links))
            .expect("the slices serialize");
    assert_eq!(
        current,
        [stamp.as_slice(), pre_stamp.as_slice(), identity.as_slice()].concat(),
        "the current layout is the stamp, then the old bytes, then the identity slice"
    );
    assert!(
        bincode::deserialize::<World>(&pre_stamp).is_err(),
        "a pre-stamp checkpoint decoded — it must refuse at the stamp"
    );

    // The pre-bit layout: additionally without M3's publication map, which
    // at genesis holds the seed's four documents and nothing else — three
    // born published and the staging draft born unpublished, hand-built
    // from the seed's public pins (a `Vec` of pairs encodes exactly as the
    // map does) — and without the position map after it, the same four
    // documents at the genesis coordinate; the two maps are pinned as the
    // bytes that end M3's slice.
    let namespace_bytes = bincode::serialize(&world.namespace).expect("M3 serializes");
    let seeded = [
        (ghost_home_document(), true),
        (head_document(), true),
        (staging_draft(), false),
        (time_document(), true),
    ];
    let publication_bytes =
        bincode::serialize(&seeded.to_vec()).expect("the map's entries serialize");
    let position_bytes =
        bincode::serialize(&seeded.iter().map(|(doc, _)| (doc.clone(), 0u64)).collect::<Vec<_>>())
            .expect("the map's entries serialize");
    let trailing = [publication_bytes.as_slice(), position_bytes.as_slice()].concat();
    assert!(
        namespace_bytes.ends_with(&trailing),
        "genesis's publication map and position map are the seed's four documents: their \
         entries end M3's bytes"
    );
    let mut pre_bit = pre_stamp.clone();
    pre_bit.drain(namespace_bytes.len() - trailing.len()..namespace_bytes.len());
    assert!(
        bincode::deserialize::<World>(&pre_bit).is_err(),
        "a pre-publication checkpoint decoded — it must fail, never read as everything-published"
    );

    // …and this build's own bytes decode. The exception set is no part of
    // the bytes, so the decoded world's is empty though genesis registers a
    // draft, and stays so until a rebuild runs over it: the hazard the
    // invariant note names, which
    // `the_hint_check_refuses_a_world_whose_derived_state_was_never_rebuilt`
    // holds over a world a write minted its draft in.
    let decoded = bincode::deserialize::<World>(&current).expect("this build's own bytes decode");
    assert_eq!(world.drafts().count(), 1, "genesis seeds its one draft's entry");
    assert_eq!(decoded.drafts().count(), 0, "a decoded world's set is empty until rebuilt");
}

/// A world holding one link per entry of `shapes`, each homed in a
/// private DRAFT — where no version mints, so M5's birth memo stays empty
/// — its `from` and its `to` each naming one never-minted content position
/// of the draft (`true`) or none, and its type slot a never-minted address
/// of the draft's own subspace 3.
fn links_in_a_draft(shapes: &[(bool, bool)]) -> World {
    links_in_a_draft_named(shapes).0
}

/// [`links_in_a_draft`] with the draft's address beside the world, for a pin
/// that hand-builds the slice's bytes from the addresses the fixture minted.
fn links_in_a_draft_named(shapes: &[(bool, bool)]) -> (World, Address) {
    let engine = mem_engine();
    let acct = delegated_account(&engine, USER);
    let (draft, _) = engine
        .namespace()
        .create_new_document(USER, &acct, Some(false))
        .expect("an explicit-false mint is a draft");
    let caller = Caller::Principal(USER);
    let visibility = World::visible_to(caller);
    let writer = engine.linkstore(&visibility);
    let slot = |names: bool, subspace: u32| {
        SlotArg::Addrs(if names { vec![element(&draft, subspace, 1)] } else { Vec::new() })
    };
    for &(with_from, with_to) in shapes {
        writer
            .makelink(caller, &draft, slot(with_from, 1), slot(with_to, 1), slot(true, 3))
            .expect("a link in the owner's own draft");
    }
    (engine.kernel().snapshot().world().clone(), draft)
}

/// `world`'s bytes as a build from before M5's birth memo wrote them: the
/// stamp, then each store slice's, with M5's cut short of its six trailing
/// maps — the memo, after it the shot terms that joined the slice with D25's
/// (c′), after those the fork sources that joined it with the fork-source
/// record's arm A, after those the arranged-at positions that joined it
/// with the stale-edit check (skep #442), after those the draft bases that
/// joined it with the staging act (B3-S10), and after those the copied
/// counts that joined it with the recorded base (skep #1111)
/// (`each_slice_serializes_the_fields_the_format_count_names`), all EMPTY
/// in every world handed here, so the six eight-byte zero lengths that
/// end M5's bytes — and no identity slice, which no build of that age wrote
/// either. Checked rather than assumed: each length is read off the slice's
/// serde form, and the same parts kept whole, with the identity slice after
/// them, must be this build's own bytes.
fn written_before_the_birth_memo(world: &World) -> Vec<u8> {
    let SerdeTree::Map(fields) = to_tree(&world.arrangement) else {
        panic!("M5State serializes as a struct — a map of its fields")
    };
    for trailing in [
        "birth_extents",
        "shot_terms",
        "fork_sources",
        "arranged_at",
        "draft_bases",
        "source_copied",
    ] {
        let field = fields.iter().find_map(|(name, value)| match name {
            SerdeTree::Str(s) if s.as_str() == trailing => Some(value),
            _ => None,
        });
        assert!(
            matches!(field, Some(SerdeTree::Map(entries)) if entries.is_empty()),
            "the fixture must leave M5's {trailing} empty, or cutting its length misreads M5"
        );
    }
    let stamp = bincode::serialize(&FormatStamp).expect("the stamp serializes");
    let namespace_bytes = bincode::serialize(&world.namespace).expect("M3 serializes");
    let content_bytes = bincode::serialize(&world.content).expect("M4 serializes");
    let arrangement_bytes = bincode::serialize(&world.arrangement).expect("M5 serializes");
    let links_bytes = bincode::serialize(&world.links).expect("M7 serializes");
    let identity_bytes = bincode::serialize(&world.identity).expect("the identity slice serializes");
    assert_eq!(
        bincode::serialize(world).expect("a world serializes"),
        [
            stamp.as_slice(),
            namespace_bytes.as_slice(),
            content_bytes.as_slice(),
            arrangement_bytes.as_slice(),
            links_bytes.as_slice(),
            identity_bytes.as_slice(),
        ]
        .concat(),
        "a World's bytes are the stamp, then each store slice's, then the identity slice"
    );
    assert!(
        arrangement_bytes.ends_with(&[0u8; 48]),
        "the empty memo's, the empty shot terms', the empty fork sources', the empty \
         arranged-at positions', the empty draft bases' and the empty copied counts' zero \
         lengths end M5's bytes"
    );
    [
        stamp.as_slice(),
        namespace_bytes.as_slice(),
        content_bytes.as_slice(),
        &arrangement_bytes[..arrangement_bytes.len() - 48],
        links_bytes.as_slice(),
    ]
    .concat()
}

/// The older layout count 1 has also named — the publication-bit layout,
/// before M5's birth memo was appended — fails to DECODE under a header
/// this build loads, and by the encoding's arithmetic rather than by
/// chance. No base any build wrote in that layout reaches the decoder,
/// since M2's stamps refuse it first (`FormatStamp`'s card); what this
/// holds is the World door's own refusal of such a body under a current
/// header.
///
/// This build reads such a base's M7 bytes as the memo. With no link, the
/// memo takes M7's link count as its own empty length, and M7 then finds
/// nothing left to read. Otherwise the memo takes that count as its own,
/// the first link's key as its first key (both are addresses), and the
/// first 20 bytes of that link as its first value: a `Nat` is a counted
/// run of `u32`s, and the count it meets is the link's arity, which is 3
/// for every stored link. Byte 20 falls midway through a count whose high
/// half is zero — `to`'s span count where `from` is empty, else the first
/// `from` span's component count — so the NEXT count read, M7's link
/// count where the store holds one link and the memo's second key where it
/// holds more, is the low half of the count after that one, shifted up 32
/// bits: the type slot's span count, a `to` span's component count, or a
/// component's digit count. At least 2³² runs the decode off the end.
/// Zero reads as an empty tumbler where there is a second key, which
/// `Tumbler`'s door refuses; where there is none it DECODES, as an empty
/// links map. And zero needs a link whose three slots are all empty, or
/// whose first `from` span opens with a zero component, and no deposit
/// surface leaves either as a store's sole link: the open gate refuses an
/// empty type slot (MAKELINK's `EmptyTypeResolution`) and the managed gate
/// types every tuple with a registered class; and a sole link is
/// MAKELINK's, `emit`'s or `nullify`'s — `assert_sup` and `editlink` need
/// resident links beside the ones they deposit — each of which starts
/// every `from` span at an address, which opens nonzero (T4).
///
/// So the refusal is held on each shape that arithmetic branches on: no
/// link; one link through its type count, through a `to` and through a
/// `from`; and two links — each world's own bytes decoding beside it, so
/// the cut and not the fixture is what refuses, and each refusal saying the
/// body is in another layout of this format and naming the slice it stopped
/// in. Pinned because
/// `each_slice_serializes_the_fields_the_format_count_names` cannot see
/// beneath a slice's top level: a change to `Link`, `Endset`, `Span`,
/// `Tumbler` or `Nat`'s encoding that moved this arithmetic would otherwise
/// let such a body decode as a world with its links misread.
#[test]
fn a_base_written_before_the_birth_memo_fails_to_decode() {
    let stores: [(&str, &[(bool, bool)]); 5] = [
        ("no link", &[]),
        ("one link, `from` and `to` empty: the type count", &[(false, false)]),
        ("one link with a `to`: a span start's component count", &[(false, true)]),
        ("one link with a `from`: a component's digit count", &[(true, false)]),
        ("two links: the memo's second key", &[(false, false), (false, false)]),
    ];
    for (store, shapes) in stores {
        let world = links_in_a_draft(shapes);
        bincode::deserialize::<World>(&bincode::serialize(&world).expect("a world serializes"))
            .expect("this build's own bytes decode");
        refused_in(
            &written_before_the_birth_memo(&world),
            &format!("{store}: a base written before the birth memo, its links read as the memo"),
        );
    }
}

/// The bytes of `world` as a build before the position map wrote them: M3's
/// slice without its trailing `minted_at` map, the rest as this build
/// writes it. The map's bytes are hand-built from the public read, one
/// entry per address the fixture minted — the seed's four documents and
/// whatever `addresses` names — in address order, a `Vec` of pairs encoding
/// exactly as the map does; the cut is pinned against the slice's own
/// bytes first, so the shape is the old one and not a strawman.
fn written_before_the_position_map(world: &World, addresses: &[Address]) -> Vec<u8> {
    let mut entries: Vec<(Address, u64)> = [
        skep_namespace::ghost_home_document(),
        skep_namespace::head_document(),
        skep_namespace::staging_draft(),
        skep_namespace::time_document(),
    ]
        .into_iter()
        .chain(addresses.iter().cloned())
        .map(|a| {
            let at = world.namespace.minted_at(&a).unwrap_or_else(|| panic!("{a} was minted")).0;
            (a, at)
        })
        .collect();
    entries.sort();
    let map_bytes = bincode::serialize(&entries).expect("the map's entries serialize");
    let namespace_bytes = bincode::serialize(&world.namespace).expect("M3 serializes");
    assert!(
        namespace_bytes.ends_with(&map_bytes),
        "the position map's entries end M3's bytes, one per document, member and link minted"
    );
    let stamp = bincode::serialize(&FormatStamp).expect("the stamp serializes");
    let rest = bincode::serialize(&(&world.content, &world.arrangement, &world.links, &world.identity))
        .expect("the slices serialize");
    [stamp.as_slice(), &namespace_bytes[..namespace_bytes.len() - map_bytes.len()], rest.as_slice()]
        .concat()
}

/// A base written before the position map — the seventh layout count 1
/// names, under a current header — fails to DECODE, by the encoding's
/// arithmetic: this build reads the content slice's bytes as the map, and
/// every slice after it the bytes of the slice before, so the decode runs
/// off the body's end — an unexpected end of file on every shape held here,
/// never a decoded world, and a refusal that says the body is in another
/// layout of this format and names the slice it stopped in. Held on
/// genesis, where every slice is empty and
/// the shifted read finds nothing to refuse until the body ends, and on the
/// link worlds the birth-memo pin uses — each world's own bytes decoding
/// beside it, so the cut and not the fixture is what refuses. The engine
/// opens such a board from genesis where its journal still reaches it
/// (`FormatStamp`'s card); what this pins is that it never opens it from
/// the base.
#[test]
fn a_base_written_before_the_position_map_fails_to_decode() {
    let genesis = World::genesis();
    bincode::deserialize::<World>(&bincode::serialize(&genesis).expect("a world serializes"))
        .expect("this build's own bytes decode");
    refused_in(
        &written_before_the_position_map(&genesis, &[]),
        "genesis written before the position map",
    );
    let stores: [(&str, &[(bool, bool)]); 3] = [
        ("one link, `from` and `to` empty", &[(false, false)]),
        ("one link with a `from` and a `to`", &[(true, true)]),
        ("two links", &[(false, false), (true, false)]),
    ];
    for (store, shapes) in stores {
        let (world, draft) = links_in_a_draft_named(shapes);
        // The draft, the mailbox its commit made beside it — the account's
        // first mint (M3's mailbox rule) — and each link.
        let account = skep_address::parent(&draft).expect("a document lies in an account");
        let mailbox = skep_namespace::mailbox_address(&account).expect("an account's slot");
        let mut minted = vec![draft.clone(), mailbox];
        minted.extend((1..=shapes.len() as u32).map(|k| element(&draft, 2, k)));
        bincode::deserialize::<World>(&bincode::serialize(&world).expect("a world serializes"))
            .expect("this build's own bytes decode");
        refused_in(
            &written_before_the_position_map(&world, &minted),
            &format!("{store}: a base written before the position map"),
        );
    }
}

/// Returns a world of staged drafts, with merges landed and links homed.
///
/// One draft is staged per entry of `landed`, a merge landed in each whose
/// entry is `true`, and `links` links homed in the first. The drafts are
/// staged from the birth version of the owner's memberless published
/// edition, in mint order, so their draft-base entries lie in that order and
/// are the map's only ones. Each landing sets its draft to an empty
/// arrangement, the version at extent zero named as both its head and its
/// base, and carries a merge of one side, which the fold stamps at the
/// landing's commit.
fn staged_drafts(landed: &[bool], links: u32) -> (World, Vec<Address>) {
    let engine = mem_engine();
    let acct = delegated_account(&engine, USER);
    let (edition, _) = engine
        .namespace()
        .create_new_document(USER, &acct, Some(true))
        .expect("a published edition, memberless");
    let vstream = engine.vstream();
    let (version, _) = vstream.version(USER, &edition, None).expect("the edition's birth version");
    let drafts: Vec<Address> = landed
        .iter()
        .map(|_| vstream.stage(USER, &version).expect("a staging draft of the version").0)
        .collect();
    let base = Base { member: version, extent: Nat::from(0u32) };
    let landing = SetArrangement {
        runs: Vec::new(),
        head: Some(base.clone()),
        base: Some(base),
        merge: Some(SetMerge { sides: vec![edition], at: None }),
    };
    for (draft, _) in drafts.iter().zip(landed).filter(|(_, land)| **land) {
        vstream
            .set_arrangement(skep_arrangement::Caller::Principal(USER), draft, &landing, AsOf::Unchecked)
            .expect("a merge landed in the owner's staged draft");
    }
    let caller = Caller::Principal(USER);
    let visibility = World::visible_to(caller);
    let writer = engine.linkstore(&visibility);
    for n in 1..=links {
        let ty = SlotArg::Addrs(vec![element(&drafts[0], 3, n)]);
        writer
            .makelink(caller, &drafts[0], SlotArg::Addrs(Vec::new()), SlotArg::Addrs(Vec::new()), ty)
            .expect("a link in the owner's own draft");
    }
    (engine.kernel().snapshot().world().clone(), drafts)
}

/// Returns `world`'s bytes as a build before the marker stamps wrote them.
///
/// Each draft-base entry is written without its stamps, and the slice ends
/// at the draft bases, the copied counts a later layout appended after them
/// left off; the rest as this build writes it. The entries' bytes are
/// hand-built from the public reads — one per draft in `drafts`, in address
/// order, and one copied count per document the fixture's snapshots minted,
/// the edition's version the drafts were staged from and each draft — each
/// list a `Vec` of pairs encoding exactly as its map does, and pinned
/// against the slice's own bytes first, so the shape is the old one and not
/// a strawman.
fn written_before_the_marker_stamps(world: &World, drafts: &[Address]) -> Vec<u8> {
    let entries: Vec<(&Address, &DraftBase)> = drafts
        .iter()
        .map(|draft| (draft, world.arrangement.draft_base(draft).expect("a staged draft has a base")))
        .collect();
    let stamped = bincode::serialize(&entries).expect("the entries serialize");
    let version =
        world.arrangement.fork_source(&drafts[0]).expect("a staged draft has a source").clone();
    let mut minted: Vec<Address> = drafts.to_vec();
    minted.push(version);
    minted.sort();
    let copied: Vec<(&Address, &skep_address::Nat)> = minted
        .iter()
        .map(|doc| {
            (doc, world.arrangement.fork_source_copied(doc).expect("a snapshot noted its count"))
        })
        .collect();
    let copied = bincode::serialize(&copied).expect("the counts serialize");
    let arrangement_bytes = bincode::serialize(&world.arrangement).expect("M5 serializes");
    assert!(
        arrangement_bytes.ends_with(&[stamped.as_slice(), copied.as_slice()].concat()),
        "the draft bases' entries, one per staged draft, then the copied counts end M5's bytes"
    );
    let unstamped = bincode::serialize(
        &entries
            .iter()
            .map(|(draft, b)| (*draft, (&b.base, &b.extent, &b.source, &b.merge)))
            .collect::<Vec<_>>(),
    )
    .expect("the entries serialize");
    let stamp = bincode::serialize(&FormatStamp).expect("the stamp serializes");
    let before = bincode::serialize(&(&world.namespace, &world.content)).expect("M3 and M4 serialize");
    let after = bincode::serialize(&(&world.links, &world.identity)).expect("M7 and identity serialize");
    [
        stamp.as_slice(),
        before.as_slice(),
        &arrangement_bytes[..arrangement_bytes.len() - stamped.len() - copied.len()],
        unstamped.as_slice(),
        after.as_slice(),
    ]
    .concat()
}

/// A base written before the marker stamps is refused, never misread.
///
/// Such a base — the tenth layout count 1 names, under a current header,
/// its draft bases holding an entry — fails to decode, refused naming the
/// slice the decode stopped in and the layout: this build reads the eight
/// bytes after each entry's marker as that entry's stamp count. Held on each
/// shape that read branches on.
/// An entry with another after it reads the next key's component count, and
/// the markers it then reads run off the body's end. The last entry, with a
/// link after it, reads M7's link count, and the one marker it then reads
/// takes its first side from the link's key, an address T4 refuses. The last
/// entry with no link after it reads a count of zero, so the draft bases
/// decode: the copied counts then read their count off the identity slice's
/// first eight bytes — one, the slice's tag beside its empty table's count —
/// and the entry they then read runs off the body's end. Each world's own
/// bytes decode beside it, so the cut and not the fixture is what refuses. A
/// body whose draft bases are empty needs no pin: it meets the copied
/// counts' absence, as every body before the thirteenth layout does.
#[test]
fn a_base_written_before_the_marker_stamps_fails_to_decode() {
    let shapes: [(&str, &[bool], u32, &str); 3] = [
        ("an entry with a marker, another after it", &[true, false], 1, "arrangement"),
        ("the one entry, a link after it", &[true], 1, "arrangement"),
        ("the one entry, no link after it", &[true], 0, "arrangement"),
    ];
    for (shape, landed, links, slice) in shapes {
        let (world, drafts) = staged_drafts(landed, links);
        bincode::deserialize::<World>(&bincode::serialize(&world).expect("a world serializes"))
            .expect("this build's own bytes decode");
        assert_eq!(
            refused_in(&written_before_the_marker_stamps(&world, &drafts), shape),
            slice,
            "{shape}: the slice the decode stopped in"
        );
    }
}

/// Returns a world of shot members, one per shot in `shots`, and the members.
///
/// The shots publish into the owner's memberless published edition, none of
/// them placing a run: the first in the birth shape, each next off the
/// member before it at that member's whole count, so its terms carry that
/// member as their base. The world has no fork source and no copied count.
fn shot_members(shots: usize) -> (World, Vec<Address>) {
    let engine = mem_engine();
    let acct = delegated_account(&engine, USER);
    let (edition, _) = engine
        .namespace()
        .create_new_document(USER, &acct, Some(true))
        .expect("a published edition, memberless");
    let caller = Caller::Principal(USER);
    let vstream = engine.vstream();
    let mut members: Vec<Address> = Vec::new();
    for _ in 0..shots {
        let base = members.last().map(|member| Base {
            member: member.clone(),
            extent: engine.kernel().snapshot().world().arrangement.content_count(member),
        });
        let shot = Shot { base, draft: None, also: vec![], keep_base: false, runs: vec![] };
        let (member, _) = vstream
            .publish(caller, &edition, &shot, &World::visible_to(caller))
            .expect("a shot into the owner's own edition");
        members.push(member);
    }
    (engine.kernel().snapshot().world().clone(), members)
}

/// Returns `world`'s bytes as a build before the shot's base wrote them.
///
/// Each shot-terms entry is written without its base, and the slice without
/// the copied counts a later layout appended — the eleventh layout's shape;
/// the rest as this build writes it. The entries' bytes are hand-built from
/// the public read, one per member in `members`, in address order — a `Vec`
/// of pairs encoding exactly as the map does — and found once in the slice's
/// own bytes first, so the shape is the old one and not a strawman.
fn written_before_the_shot_base(world: &World, members: &[Address]) -> Vec<u8> {
    let entries: Vec<(&Address, &ShotTerms)> = members
        .iter()
        .map(|member| {
            (member, world.arrangement.shot_terms(member).expect("a shot's member has its terms"))
        })
        .collect();
    let based = bincode::serialize(&entries).expect("the entries serialize");
    let arrangement_bytes = bincode::serialize(&world.arrangement).expect("M5 serializes");
    let found: Vec<usize> = arrangement_bytes
        .windows(based.len())
        .enumerate()
        .filter(|(_, window)| *window == based.as_slice())
        .map(|(at, _)| at)
        .collect();
    let [at] = found[..] else {
        panic!("the shot terms' entries stand once in M5's bytes: {found:?}")
    };
    let SerdeTree::Map(fields) = to_tree(&world.arrangement) else {
        panic!("M5State serializes as a struct — a map of its fields")
    };
    assert!(
        fields.iter().any(|(name, value)| matches!(
            (name, value),
            (SerdeTree::Str(s), SerdeTree::Map(entries)) if s.as_str() == "source_copied" && entries.is_empty()
        )),
        "the fixture leaves the copied counts empty, their zero length ending M5's bytes"
    );
    assert!(arrangement_bytes.ends_with(&[0u8; 8]));
    let unbased = bincode::serialize(
        &entries
            .iter()
            .map(|(member, t)| (*member, (&t.placed, &t.base_extent)))
            .collect::<Vec<_>>(),
    )
    .expect("the entries serialize");
    let stamp = bincode::serialize(&FormatStamp).expect("the stamp serializes");
    let before =
        bincode::serialize(&(&world.namespace, &world.content)).expect("M3 and M4 serialize");
    let after =
        bincode::serialize(&(&world.links, &world.identity)).expect("M7 and identity serialize");
    [
        stamp.as_slice(),
        before.as_slice(),
        &arrangement_bytes[..at],
        unbased.as_slice(),
        &arrangement_bytes[at + based.len()..arrangement_bytes.len() - 8],
        after.as_slice(),
    ]
    .concat()
}

/// A base written before the shot's base is refused, never misread.
///
/// Such a base — the eleventh layout count 1 names, under a current header,
/// its shot terms holding an entry — fails to decode, refused naming the
/// slice the decode stopped in and the layout: this build reads the byte
/// after each entry's extent as that entry's base's option tag. Held on each
/// shape that read branches on. An entry with another after it reads the
/// next key's component count, which no option tag spells. The last entry
/// reads the fork sources' count, zero in this fixture, as no base; the
/// fork sources then read their count off the arranged-at positions' count
/// shifted up 56 bits, and the entries they then read run off the body's
/// end. Each world's own bytes decode beside it, so the cut and not the
/// fixture is what refuses. A body whose shot terms are empty needs no pin:
/// it meets the copied counts' absence, as every body before the thirteenth
/// layout does.
#[test]
fn a_base_written_before_the_shot_base_fails_to_decode() {
    for (shape, shots) in
        [("an entry with another after it", 2), ("the one entry, the fork sources after it", 1)]
    {
        let (world, members) = shot_members(shots);
        bincode::deserialize::<World>(&bincode::serialize(&world).expect("a world serializes"))
            .expect("this build's own bytes decode");
        assert_eq!(
            refused_in(&written_before_the_shot_base(&world, &members), shape),
            "arrangement",
            "{shape}: the slice the decode stopped in"
        );
    }
}
