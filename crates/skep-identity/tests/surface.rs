//! The declared-value assertions I2 pins (AUTH-2.92 `ALGS`, AUTH-2.93
//! `TAGS`), the framing byte pins, the fold token authority, and the
//! checkpoint-facing serde surface.

mod common;

use common::{addr, fp, key, ACCT_A};
use sha2::{Digest, Sha256};
use skep_identity::{
    framed, Enrolled, Fingerprint, IdentityState, Inert, PayloadError, PublicKey, ALGS,
    ALG_ED25519, KEY_TAG, NODE_HELLO_TAG, SESSION_TAG, TAGS,
};

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
    for (token, raw_len, _family) in ALGS {
        let hex = "00".repeat(*raw_len);
        let k = PublicKey::parse(token, &hex)
            .unwrap_or_else(|_| panic!("ALGS token {token} does not parse — no arm carries it"));
        assert_eq!(k.alg(), *token, "arm answers a different token than its row");
        assert_eq!(k.raw().len(), *raw_len, "row length is not the arm's raw length");
    }
    // Arms → table: every variant's token is a row. A NEW VARIANT MUST BE
    // ADDED HERE beside its ALGS row (AUTH-2.91's one-edit-plus-assertion).
    let arms: &[PublicKey] = &[PublicKey::Ed25519([0u8; 32])];
    assert_eq!(arms.len(), ALGS.len(), "arm count and table row count differ");
    for arm in arms {
        let row = ALGS.iter().find(|(token, _, _)| *token == arm.alg());
        let (_, raw_len, _) = row.expect("arm token absent from ALGS");
        assert_eq!(arm.raw().len(), *raw_len);
    }
    // No two rows name one key family (AUTH-1.5, the I4 encoding bridge's
    // per-family half — AUTH-2.99).
    for (i, (_, _, fam_a)) in ALGS.iter().enumerate() {
        for (_, _, fam_b) in &ALGS[i + 1..] {
            assert_ne!(fam_a, fam_b, "two ALGS rows name one key family");
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
            "tag {:?} does not begin skep-",
            core::str::from_utf8(tag.as_bytes())
        );
    }
    for (i, a) in TAGS.iter().enumerate() {
        for (j, b) in TAGS.iter().enumerate() {
            if i != j {
                assert!(
                    !b.as_bytes().starts_with(a.as_bytes()),
                    "tag {:?} is a prefix of {:?}",
                    core::str::from_utf8(a.as_bytes()),
                    core::str::from_utf8(b.as_bytes())
                );
            }
        }
    }
    // The three declared constants are the table, in declaration order.
    assert_eq!(TAGS.len(), 3);
    assert_eq!(TAGS[0].as_bytes(), KEY_TAG.as_bytes());
    assert_eq!(TAGS[1].as_bytes(), SESSION_TAG.as_bytes());
    assert_eq!(TAGS[2].as_bytes(), NODE_HELLO_TAG.as_bytes());
}

/// AUTH-2.55 — `Inert::token()`: the one authority, all twelve rows,
/// snake_case of the variant name.
#[test]
fn inert_token_map() {
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
/// unknown account; AUTH-2.56 — no claimant, no accounts at genesis.
#[test]
fn genesis_state_is_default_and_answers_empty() {
    let st = IdentityState::genesis();
    assert!(st == IdentityState::default());
    assert!(st.key_set(&addr(ACCT_A)).is_empty());
    assert!(st.claimant().is_none());
    assert_eq!(st.accounts().count(), 0);
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
    assert!(back == k);

    let f = fp(0x22);
    let bytes = bincode::serialize(&f).expect("serialize Fingerprint");
    let back: Fingerprint = bincode::deserialize(&bytes).expect("deserialize Fingerprint");
    assert!(back == f);

    let e = Enrolled { key: k, anchor: true };
    let bytes = bincode::serialize(&e).expect("serialize Enrolled");
    let back: Enrolled = bincode::deserialize(&bytes).expect("deserialize Enrolled");
    assert!(back == e);
}
