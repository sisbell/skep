//! The declared-value assertions I2 pins (AUTH-2.92 `ALGS`, AUTH-2.93
//! `TAGS`, and AUTH-1.21's record cap), the framing byte pins, the fold
//! token authority, the standard trait surface every consumer dispatches
//! through, and the checkpoint-facing serde surface.

mod common;

use common::{addr, fp, key, ACCT_A};
use sha2::{Digest, Sha256};
use skep_identity::{
    framed, CredentialKind, Enrolled, Enrollment, Fingerprint, IdentityState, Inert, KeyParseError,
    LabelError, PayloadError, PublicKey, ALGS, ALG_ED25519, KEY_TAG, MAX_RECORD_BYTES,
    NODE_HELLO_TAG, SESSION_TAG, TAGS,
};

/// AUTH-1.18/AUTH-1.21 — the record cap's VALUE, not merely its name: a
/// PERMANENT pin, an I2 frozen constant (AUTH-2.90) with no fold version, so
/// a board that folded a record under one cap and a mirror reading under
/// another disagree forever about which records are `too_large`. Every other
/// vector sizes its payload FROM this constant and so stays green if it
/// moves; this is the one assertion a change is discovered at.
#[test]
fn max_record_bytes_is_64_kib() {
    assert_eq!(MAX_RECORD_BYTES, 65_536);
}

/// AUTH-1.12 — `framed(tag, fields) = tag ‖ (be32(len(f)) ‖ f)…`, byte-pinned.
#[test]
fn framed_bytes_are_pinned() {
    let raw = [0u8; 32];
    let got = framed(KEY_TAG, &[b"ed25519", &raw]);
    let mut want: Vec<u8> = Vec::new();
    want.extend_from_slice(b"skep-key-v1");
    want.extend_from_slice(&7u32.to_be_bytes());
    want.extend_from_slice(b"ed25519");
    want.extend_from_slice(&32u32.to_be_bytes());
    want.extend_from_slice(&raw);
    assert_eq!(got, want);
}

/// AUTH-1.12 — the length prefixes make the framing injective for a fixed
/// tag: shifting a byte across a field boundary changes the frame.
#[test]
fn framed_is_injective_across_field_boundaries() {
    assert_ne!(framed(KEY_TAG, &[b"ab", b"c"]), framed(KEY_TAG, &[b"a", b"bc"]));
    assert_ne!(framed(KEY_TAG, &[b"abc"]), framed(KEY_TAG, &[b"ab", b"c"]));
    assert_ne!(framed(KEY_TAG, &[]), framed(KEY_TAG, &[b""]));
}

/// AUTH-1.12 — injectivity survives fields no narrower prefix could measure.
/// Every example above uses one- to three-byte fields, which stay separated
/// even under a one-byte length; these pairs are the ones that collide the
/// moment the prefix width shrinks (256 wraps a u8, 65536 a u16), so this is
/// where the be32 in the frame is actually load-bearing.
#[test]
fn framing_is_injective_at_the_prefix_width_boundaries() {
    for len in [256usize, 65_536] {
        let big = vec![0u8; len];
        assert_ne!(
            framed(KEY_TAG, &[&big, b""]),
            framed(KEY_TAG, &[b"", &big]),
            "a {len}-byte field must not frame alike across a boundary shift"
        );
    }
}

/// AUTH-1.8 — `Fingerprint::of(key) = SHA-256(framed(KEY_TAG, [alg, raw]))`,
/// checked against the formula's own two halves.
#[test]
fn fingerprint_is_sha256_of_the_framed_key() {
    let k = key(0x5a);
    let preimage = framed(KEY_TAG, &[k.alg().as_bytes(), k.raw()]);
    let want: [u8; 32] = Sha256::digest(&preimage).into();
    assert_eq!(Fingerprint::of(&k).as_bytes(), &want);
}

/// AUTH-2.92 — the `ALGS` assertion: `PublicKey`'s arms and `ALGS` agree in
/// BOTH directions and in ALL THREE columns.
#[test]
fn algs_and_arms_agree_both_directions() {
    // Table → arms: every token parses at its row's length, and the
    // constructed arm answers that token at that raw length.
    for row in ALGS {
        let hex = "00".repeat(row.raw_len);
        let k = PublicKey::parse(row.token, &hex).unwrap_or_else(|_| {
            panic!(
                "ALGS token {} does not parse — no arm carries it, or the arm's \
                 array is not this row's raw_len of {}",
                row.token, row.raw_len
            )
        });
        assert_eq!(k.alg(), row.token, "arm answers a different token than its row");
        assert_eq!(
            k.raw().len(),
            row.raw_len,
            "row length is not the arm's raw length"
        );
    }
    // Arms → table: every variant's token is a row. A NEW VARIANT MUST BE
    // ADDED HERE beside its ALGS row (AUTH-2.91's one-edit-plus-assertion).
    let arms: &[PublicKey] = &[PublicKey::Ed25519([0u8; 32])];
    assert_eq!(arms.len(), ALGS.len(), "arm count and table row count differ");
    for arm in arms {
        let row = ALGS
            .iter()
            .find(|a| a.token == arm.alg())
            .expect("arm token absent from ALGS");
        assert_eq!(arm.raw().len(), row.raw_len);
    }
    // No two rows name one key family (AUTH-1.5, the I4 encoding bridge's
    // per-family half — AUTH-2.99).
    for (i, a) in ALGS.iter().enumerate() {
        for b in &ALGS[i + 1..] {
            assert_ne!(a.family, b.family, "two ALGS rows name one key family");
        }
    }
    assert_eq!(ALG_ED25519, "ed25519");
}

/// AUTH-2.93 — the `TAGS` assertion: every tag begins `skep-`, and no tag
/// is a prefix of another (AUTH-1.15).
#[test]
fn tags_are_skep_prefixed_and_prefix_free() {
    for tag in TAGS {
        assert!(
            tag.as_bytes().starts_with(b"skep-"),
            "{tag:?} does not begin skep-"
        );
    }
    for (i, a) in TAGS.iter().enumerate() {
        for (j, b) in TAGS.iter().enumerate() {
            if i != j {
                assert!(
                    !b.as_bytes().starts_with(a.as_bytes()),
                    "{a:?} is a prefix of {b:?}"
                );
            }
        }
    }
    // The three declared constants are the table, in declaration order.
    assert_eq!(TAGS.len(), 3);
    assert_eq!(TAGS[0], KEY_TAG);
    assert_eq!(TAGS[1], SESSION_TAG);
    assert_eq!(TAGS[2], NODE_HELLO_TAG);
}

/// AUTH-1.11 — the three declared tags' BYTES, not merely their properties.
/// A tag IS the domain separator, so its bytes are the protocol; two of the
/// three are consumed outside this crate (skepd signs under [`SESSION_TAG`],
/// bebe under [`NODE_HELLO_TAG`], AUTH-2.118), where no shared test would
/// notice an edit. `tags_are_skep_prefixed_and_prefix_free` keeps holding
/// after any rename that stays `skep-`-prefixed, and `framed_bytes_are_pinned`
/// states [`KEY_TAG`] alone; this is where a changed session or node-hello
/// tag — which silently invalidates every signature made under the old one —
/// is discovered.
#[test]
fn the_declared_tag_bytes_are_pinned() {
    assert_eq!(KEY_TAG.as_bytes(), b"skep-key-v1".as_slice());
    assert_eq!(SESSION_TAG.as_bytes(), b"skep-session-v1".as_slice());
    assert_eq!(NODE_HELLO_TAG.as_bytes(), b"skep-node-hello-v1".as_slice());
}

/// AUTH-2.55 — `Inert::token()`: the one authority, all twelve rows,
/// snake_case of the variant name.
#[test]
fn every_inert_variant_has_its_pinned_token() {
    assert_eq!(Inert::Unpublished.token(), "unpublished");
    assert_eq!(Inert::MalformedShape.token(), "malformed_shape");
    assert_eq!(
        Inert::MalformedPayload(PayloadError::TooLarge).token(),
        "malformed_payload"
    );
    assert_eq!(Inert::NotDocOne.token(), "not_doc_one");
    assert_eq!(Inert::NoHolder.token(), "no_holder");
    assert_eq!(Inert::NotGenesisRegistry.token(), "not_genesis_registry");
    assert_eq!(Inert::NotHolderRetirement.token(), "not_holder_retirement");
    assert_eq!(Inert::WouldEmpty.token(), "would_empty");
    assert_eq!(Inert::NothingChanged.token(), "nothing_changed");
    assert_eq!(Inert::AlreadyClaimed.token(), "already_claimed");
    assert_eq!(Inert::ClaimantKeyless.token(), "claimant_keyless");
    assert_eq!(Inert::ClaimantNotTopLevel.token(), "claimant_not_top_level");
}

/// AUTH-1.41 — `genesis() == default()`; AUTH-2.58 — the empty set for an
/// unknown account; AUTH-2.56 — no claimant, no keyed accounts at genesis.
#[test]
fn genesis_state_is_default_and_answers_empty() {
    let st = IdentityState::genesis();
    assert_eq!(st, IdentityState::default());
    assert!(st.key_set(&addr(ACCT_A)).is_empty());
    assert!(st.claimant().is_none());
    assert_eq!(st.keyed_accounts().count(), 0);
}

/// AUTH-1.1/AUTH-1.7/AUTH-1.29 — the journaled/checkpointed value types
/// survive a serde round trip (through a format that admits non-string map
/// keys; the full `IdentityState` round trip rides in `fold.rs` where a
/// populated state exists).
#[test]
fn value_types_survive_serde() {
    let k = key(0x11);
    let bytes = bincode::serialize(&k).expect("serialize PublicKey");
    let back: PublicKey = bincode::deserialize(&bytes).expect("deserialize PublicKey");
    assert_eq!(back, k);

    let f = fp(0x22);
    let bytes = bincode::serialize(&f).expect("serialize Fingerprint");
    let back: Fingerprint = bincode::deserialize(&bytes).expect("deserialize Fingerprint");
    assert_eq!(back, f);

    let e = Enrolled { key: k, anchor: true };
    let bytes = bincode::serialize(&e).expect("serialize Enrolled");
    let back: Enrolled = bincode::deserialize(&bytes).expect("deserialize Enrolled");
    assert_eq!(back, e);
}

/// AUTH-1.40 — the checkpointed shape, pinned as BYTES rather than as a
/// round trip. `Enrolled` rides inside `KeySet` inside `IdentityState`, so
/// its encoding is part of the compatibility surface that freezes with the
/// first checkpoint a v1 board writes; a round trip agrees with itself after
/// any field-type change and would not notice. The anchor flag is ONE byte:
/// widening it — to an enum, an integer, a struct — moves every later field
/// of every checkpoint written since, and this assertion is where that is
/// discovered.
#[test]
fn enrolled_checkpoint_encoding_is_pinned() {
    let raw = [0x11u8; 32];
    let e = Enrolled {
        key: PublicKey::Ed25519(raw),
        anchor: true,
    };

    let mut want: Vec<u8> = Vec::new();
    want.extend_from_slice(&0u32.to_le_bytes()); // the Ed25519 variant index
    want.extend_from_slice(&raw); // the raw key bytes
    want.push(1); // the anchor flag, one byte

    assert_eq!(bincode::serialize(&e).expect("serialize Enrolled"), want);
}

/// AUTH-1.40 — the FIRST checkpoint a v1 board writes, pinned as bytes,
/// because that is the one the shape freezes with: the empty `sets` map's
/// eight-byte length and `claimant`'s one-byte `None`, and no `Address`,
/// which is why this shape can be stated here at all. NINE bytes is the
/// claim: eight for the map's length prefix, one for the `Option`
/// discriminant. A third field, or either field's width at empty changing —
/// a `claimant` that stopped being an `Option`, a length prefix that is not
/// a `u64` — moves every later byte of every checkpoint written since, and
/// `populated_state_survives_serde` agrees with itself after all of them.
/// What this cannot see is the two fields' ORDER, because at genesis every
/// byte is zero; `identity_state_encodes_sets_before_claimant` is where that
/// half is pinned, over a state that has a row to put first.
#[test]
fn genesis_checkpoint_encoding_is_pinned() {
    let mut want: Vec<u8> = Vec::new();
    want.extend_from_slice(&0u64.to_le_bytes()); // `sets`: an empty map
    want.push(0); // `claimant`: None

    assert_eq!(
        bincode::serialize(&IdentityState::genesis()).expect("serialize IdentityState"),
        want
    );
}

/// AUTH-1.28 — `PayloadError`'s `Display` is a second ENTRY to `token()`'s
/// one authority and never a second vocabulary: over EVERY variant, both
/// spell the same string. A row whose `Display` drifted from its token would
/// give a formatting consumer a fault name the wire does not use.
#[test]
fn payload_error_display_is_the_token() {
    for e in [
        PayloadError::TooLarge,
        PayloadError::ForeignContent,
        PayloadError::MissingValue,
        PayloadError::NotUtf8,
        PayloadError::BadHeader,
        PayloadError::Empty,
        PayloadError::BadLine(7),
        PayloadError::DuplicateKey(12),
    ] {
        assert_eq!(e.to_string(), e.token(), "Display and token disagree");
    }
}

/// The three types this crate returns in `Err` compose with `?` into
/// `Box<dyn Error>`, so a consumer plumbs them rather than defining a local
/// wrapper enum to re-implement `Display` behind.
#[test]
fn error_types_lift_into_dyn_error() {
    fn lift(e: impl std::error::Error + 'static) -> Box<dyn std::error::Error> {
        Box::new(e)
    }
    // Each carries its own message through the erasure.
    let boxed = lift(PublicKey::parse("rsa", "00").expect_err("unknown alg"));
    assert_eq!(boxed.to_string(), KeyParseError::UnknownAlg.to_string());
    let boxed = lift(Enrollment::new(key(1), false, Some("a\nb".to_owned())).expect_err("newline"));
    assert_eq!(boxed.to_string(), LabelError::Newline.to_string());
    let boxed = lift(PayloadError::BadLine(4));
    assert_eq!(boxed.to_string(), "bad_line:4");
}

/// The vocabularies a consumer tallies are usable as MAP KEYS. `Eq` without
/// `Hash` walls off `HashMap`/`HashSet` with no way for a caller to climb it
/// (the orphan rule puts both the trait and the type out of reach), and only
/// [`Inert`] and [`PayloadError`] carry a `token()` to key by instead —
/// [`CredentialKind`] has no escape hatch at all, so a per-kind tally would
/// have nowhere to go.
#[test]
fn vocabulary_types_are_usable_as_map_keys() {
    use std::collections::{HashMap, HashSet};

    // The per-reason tally a refusal metric is: three verdicts, two rows.
    let mut tally: HashMap<Inert, u32> = HashMap::new();
    for inert in [
        Inert::NotDocOne,
        Inert::NotDocOne,
        Inert::MalformedPayload(PayloadError::BadLine(2)),
    ] {
        *tally.entry(inert).or_insert(0) += 1;
    }
    assert_eq!(tally.len(), 2);
    assert_eq!(tally[&Inert::NotDocOne], 2);

    // The other four, in the shape a conformance list takes.
    let faults: HashSet<PayloadError> = [
        PayloadError::BadLine(2),
        PayloadError::BadLine(2),
        PayloadError::NotUtf8,
    ]
    .into_iter()
    .collect();
    assert_eq!(faults.len(), 2);
    let kinds = HashSet::from([CredentialKind::Enroll, CredentialKind::Claim]);
    assert_eq!(kinds.len(), 2);
    let key_faults = HashSet::from([KeyParseError::BadHex, KeyParseError::UnknownAlg]);
    assert_eq!(key_faults.len(), 2);
    // `LabelError` has one variant, so a set over it holds at most one row.
    assert_eq!(
        HashSet::from([LabelError::Newline, LabelError::Newline]).len(),
        1
    );
}

/// AUTH-1.9/AUTH-1.3 — the hand-written renderings, so a fingerprint in a
/// log line or a `{:?}` is the hex a reader can grep for, never thirty-two
/// decimal bytes. `Display` on a fingerprint is `to_hex` exactly: the flat
/// form the daemon emits (grouped rendering is the client's, AUTH-1.10).
#[test]
fn key_and_fingerprint_render_as_their_hex() {
    let k = key(0xab);
    let want = format!("PublicKey(ed25519 {})", k.to_hex());
    assert_eq!(format!("{k:?}"), want);

    let f = fp(0xab);
    assert_eq!(f.to_string(), f.to_hex());
    assert_eq!(format!("{f:?}"), format!("Fingerprint({})", f.to_hex()));
}

/// A `Tag` is `Copy`, so a BOUND tag frames as often as a caller likes and
/// `TAGS` iterates by value — the framing surface does not ration the
/// declared constants (AUTH-1.13's private field is what rations WHICH tags
/// exist). `Debug` renders the bytes, which for a `skep-` ASCII tag is the
/// name (AUTH-1.15).
#[test]
fn tag_is_copy_and_debugs_as_its_bytes() {
    let tag = KEY_TAG;
    let once = framed(tag, &[b"a"]);
    let twice = framed(tag, &[b"a"]);
    assert_eq!(once, twice);
    for t in TAGS {
        assert_eq!(framed(*t, &[]), t.as_bytes());
    }
    assert_eq!(format!("{KEY_TAG:?}"), "Tag(skep-key-v1)");
}
