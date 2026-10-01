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
/// before any slice is read), and the two skip-serialized derived indexes
/// absent, since they occupy no bytes.
#[test]
fn the_world_serializes_its_slices_in_declaration_order() {
    assert_eq!(
        field_names(&World::genesis()),
        ["format", "namespace", "content", "arrangement", "links"]
    );
}

/// Each slice's own checkpoint layout, at its TOP LEVEL, pinned to the
/// World format count that names it. A slice's layout is a World layout
/// ([`FormatStamp`]), and the author who changes one is a store's, with
/// no edge to this file: count 1 names two layouts because a slice grew a
/// field under it. This pin is where such a change meets the count — a
/// field appended, removed, renamed or reordered on any slice fails here,
/// and the failure says what it owes. The count is asserted beside the
/// fields, so a bump that leaves this pin behind fails too.
///
/// It cannot see BELOW a slice's top level: a nested type gaining a field
/// moves the World's bytes with every name here unchanged, and that change
/// still owes the bump by hand. Nor is the dump filter's field-set check a
/// substitute: that one asks for a reduction's DISPOSITION, compiles with
/// the `dump` feature alone, and is answered without touching the count.
#[test]
fn each_slice_serializes_the_fields_the_format_count_names() {
    const PINNED_COUNT: u64 = 0x534B_5057_0000_0001;
    assert_eq!(
        WORLD_FORMAT, PINNED_COUNT,
        "WORLD_FORMAT moved without this pin: restate each slice's fields under the new count"
    );
    let world = World::genesis();
    for (slice, found, pinned) in [
        (
            "namespace",
            field_names(&world.namespace),
            &["frontiers", "nodes", "principals", "publication"][..],
        ),
        ("content", field_names(&world.content), &["map"]),
        (
            "arrangement",
            field_names(&world.arrangement),
            &["arrangements", "provenance", "birth_extents", "shot_terms"],
        ),
        ("links", field_names(&world.links), &["links"]),
    ] {
        assert_eq!(
            found, pinned,
            "{slice}'s checkpoint layout moved under WORLD_FORMAT {WORLD_FORMAT:#018x}: \
             that is a World layout change — bump the count, then this pin"
        );
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
/// Three payloads come from their own stores' public constructors, so
/// each index is read off a record a store really built. M7 seals its
/// `Deposit` variant, so no crate but M7 can construct a [`LinkRec`] —
/// the fourth index is pinned by what the decoder REFUSES instead. A bare
/// tag naming a variant gets past the tag and runs out of payload (an
/// I/O end-of-file), where one naming none is refused as a value serde
/// has no variant for. So index 3 NAMES a variant and index 4 names the
/// end of the list, and with the first three pinned that says `Links` is
/// at 3.
///
/// A variant APPENDED after `Links` is byte-safe for replay and still
/// reddens the second refusal. That is the intent: the enum is expected
/// to grow, and an addition should be made to state where it landed here
/// rather than to land anywhere in silence.
#[test]
fn the_central_record_lifts_each_store_to_its_own_variant_index() {
    let doc = addr(&[1, 0, 1, 0, 1]);
    let namespace_rec = M3Rec::Allocate { addr: doc.clone(), published: false };
    let content_rec = skep_content::stage_write(
        &ContentStore::default(),
        &addr(&[1, 0, 1, 0, 1, 0, 1, 1]),
        Val::new(vec![b'x']),
    )
    .expect("a fresh content address stages a write");
    let arrangement_rec = skep_arrangement::stage_seat_link(
        &M5State::genesis(),
        &doc,
        &addr(&[1, 0, 1, 0, 1, 0, 2, 1]),
    )
    .expect("an unseated link of the document stages a seat");

    let tag_of = |r: Record| {
        let bytes = bincode::serialize(&r).expect("a record serializes");
        u32::from_le_bytes(
            bytes[..4].try_into().expect("bincode writes a four-byte variant tag"),
        )
    };
    assert_eq!(tag_of(namespace_rec.into()), 0, "Namespace is variant 0");
    assert_eq!(tag_of(content_rec.into()), 1, "Content is variant 1");
    assert_eq!(tag_of(arrangement_rec.into()), 2, "Arrangement is variant 2");

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
        matches!(refuses(4), bincode::ErrorKind::Custom(_)),
        "index 4 names a variant, so Links is not the last: {}",
        refuses(4)
    );
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
/// followed by the four slices, and M3's slice at genesis IS its old
/// bytes followed by the publication map — since PUB-6.65's seed, the
/// system account's two born-published documents behind an eight-byte
/// length (M3's own test pins that half; this one rides it).
#[test]
fn a_checkpoint_without_the_bit_or_the_stamp_fails_to_decode() {
    use skep_namespace::{ghost_home_document, head_document};

    let world = World::genesis();
    let current = bincode::serialize(&world).expect("a world serializes");
    let stamp = bincode::serialize(&FormatStamp).expect("a u64 serializes");

    // The pre-stamp layout (the bit present, no leading stamp): the four
    // slices alone, in order — a tuple encodes exactly as a struct does.
    let pre_stamp =
        bincode::serialize(&(&world.namespace, &world.content, &world.arrangement, &world.links))
            .expect("the slices serialize");
    assert_eq!(
        current,
        [stamp.as_slice(), pre_stamp.as_slice()].concat(),
        "the current layout is the stamp, then the old bytes"
    );
    assert!(
        bincode::deserialize::<World>(&pre_stamp).is_err(),
        "a pre-stamp checkpoint decoded — it must refuse at the stamp"
    );

    // The pre-bit layout: additionally without M3's publication map, which
    // at genesis holds the seed's two born-published documents and nothing
    // else — hand-built from the seed's public pins (a `Vec` of pairs
    // encodes exactly as the map does) and pinned as the bytes that end
    // M3's slice.
    let namespace_bytes = bincode::serialize(&world.namespace).expect("M3 serializes");
    let publication_bytes =
        bincode::serialize(&vec![(ghost_home_document(), true), (head_document(), true)])
            .expect("the map's entries serialize");
    assert!(
        namespace_bytes.ends_with(&publication_bytes),
        "genesis's publication map is the seed's two documents: their entries end M3's bytes"
    );
    let mut pre_bit = pre_stamp.clone();
    pre_bit.drain(namespace_bytes.len() - publication_bytes.len()..namespace_bytes.len());
    assert!(
        bincode::deserialize::<World>(&pre_bit).is_err(),
        "a pre-publication checkpoint decoded — it must fail, never read as everything-published"
    );

    // …and this build's own bytes decode. Genesis holds no draft, so the
    // empty set below says nothing about a rebuild: the hazard the
    // invariant note names is held over a world that has one, in
    // `the_hint_check_refuses_a_world_whose_derived_state_was_never_rebuilt`.
    let decoded = bincode::deserialize::<World>(&current).expect("this build's own bytes decode");
    assert_eq!(decoded.drafts().count(), 0);
}

/// A world holding one link per entry of `shapes`, each homed in a
/// private DRAFT — where no version mints, so M5's birth memo stays empty
/// — its `from` and its `to` each naming one never-minted content position
/// of the draft (`true`) or none, and its type slot a never-minted address
/// of the draft's own subspace 3.
fn links_in_a_draft(shapes: &[(bool, bool)]) -> World {
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
    engine.kernel().snapshot().world().clone()
}

/// `world`'s bytes as a build from before M5's birth memo wrote them: the
/// stamp, then each slice's, with M5's cut short of its two trailing maps —
/// the memo and, after it, the shot terms that joined the slice with D25's
/// (c′) (`each_slice_serializes_the_fields_the_format_count_names`), both
/// EMPTY in every world handed here, so the two eight-byte zero lengths
/// that end M5's bytes. Checked rather than assumed: both are read off the
/// slice's serde form, and the same parts kept whole must be this build's
/// own bytes.
fn written_before_the_birth_memo(world: &World) -> Vec<u8> {
    let SerdeTree::Map(fields) = to_tree(&world.arrangement) else {
        panic!("M5State serializes as a struct — a map of its fields")
    };
    for trailing in ["birth_extents", "shot_terms"] {
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
    assert_eq!(
        bincode::serialize(world).expect("a world serializes"),
        [
            stamp.as_slice(),
            namespace_bytes.as_slice(),
            content_bytes.as_slice(),
            arrangement_bytes.as_slice(),
            links_bytes.as_slice(),
        ]
        .concat(),
        "a World's bytes are the stamp, then each slice's"
    );
    assert!(
        arrangement_bytes.ends_with(&[0u8; 16]),
        "the empty memo's and the empty shot terms' zero lengths end M5's bytes"
    );
    [
        stamp.as_slice(),
        namespace_bytes.as_slice(),
        content_bytes.as_slice(),
        &arrangement_bytes[..arrangement_bytes.len() - 16],
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
/// the cut and not the fixture is what refuses. Pinned because
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
        assert!(
            bincode::deserialize::<World>(&written_before_the_birth_memo(&world)).is_err(),
            "{store}: a base written before the birth memo decoded, its links read as the memo"
        );
    }
}
