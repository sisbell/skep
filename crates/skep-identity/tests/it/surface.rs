//! The declared-value assertions I2 pins (AUTH-2.92 `ALGS` and its frozen
//! tokens by value, AUTH-2.93 `TAGS` and their bytes, and AUTH-1.21's record
//! cap), the key's own surface (AUTH-1.1–1.10: `PublicKey::parse`'s pinned
//! refusal order, the row deciding a key's variant, the two token lookups'
//! one token set, the KEY PIN's halves, the key's width, the fingerprint's
//! formula, hex and rendering), the hybrid blob a `sig` naming no row spells
//! (AUTH-4.34, AUTH-6.3), the framing byte pins, the fold token authority,
//! the standard trait surface every consumer dispatches through and the two
//! traits it withholds, and the items published for the readers the spec
//! names.

use crate::common;

use common::{
    addr, assert_detail, assert_honored, doc1, enroll_payload, fp, key, Fixture, TestCtx, ACCT_A,
};
use sha2::{Digest, Sha256};
use skep_identity::{
    canonical_record, doc_1_of, entry_body_publish, framed, parse_enroll, parse_record_value,
    parse_retire, record_bytes, single_address, AlgRow, BoardTerm, CredentialKind, Enrollment,
    Fingerprint, FoldCtx, HasIdentity, HybridBlob, IdentityState, Inert, LabelError, ParseKeyError,
    PayloadError, PublicKey, PublishBody, PublishRefusal, RecordValue, SigAlgRow, Values, ALGS,
    ALG_FNDSA512_PREVIEW_ED25519, ALG_MLDSA65_ED25519, ED25519_KEY_LEN, ENROLL_TYPE, ENTRY_TAG,
    FNDSA512_PREVIEW_ED25519_KEY_LEN, FNDSA512_PREVIEW_KEY_LEN, KEY_TAG, MAX_RECORD_BYTES,
    MLDSA65_ED25519_KEY_LEN, MLDSA65_KEY_LEN, NODE_HELLO_TAG, RETIRE_TYPE, SESSION_TAG,
    SESSION_TAG_V2, SIG_ALGS, TAGS,
};

/// AUTH-1.18/AUTH-1.21 — the record cap's VALUE, not merely its name: 128 KiB,
/// RAISED from 64 KiB before the first served board (the hybrid-only launch's
/// Q8; AUTH RES-204) and from that board a PERMANENT pin, an I2 frozen
/// constant (AUTH-2.90) with no fold version, so a board that folded a record
/// under one cap and a mirror reading under another disagree forever about
/// which records are `too_large`. Every other vector sizes its payload FROM
/// this constant and so stays green if it moves; this is the one assertion a
/// change is discovered at.
#[test]
fn max_record_bytes_is_128_kib() {
    assert_eq!(MAX_RECORD_BYTES, 131_072);
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
fn framed_is_injective_at_the_prefix_width_boundaries() {
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
/// BOTH directions and in ALL FOUR columns.
#[test]
fn algs_and_arms_agree_both_directions() {
    // Table → arms: every row's `from_raw` accepts that row's raw length, and
    // the key it builds answers that row's token at that raw length.
    for row in ALGS {
        let hex = "00".repeat(row.raw_len);
        let k = PublicKey::parse(row.token, &hex).unwrap_or_else(|_| {
            panic!(
                "ALGS token {} does not parse — the row's `from_raw` does not \
                 accept this row's raw_len of {} bytes",
                row.token, row.raw_len
            )
        });
        assert_eq!(k.alg(), row.token, "arm answers a different token than its row");
        assert_eq!(
            k.raw().len(),
            row.raw_len,
            "row length is not the arm's raw length"
        );
        // …and NO OTHER length: `from_raw` answers `None` IFF the bytes are not
        // this row's raw length (AUTH-1.4), so one byte either side is
        // `BadLength`. Every other length vector in the suite is SHORT, and a
        // `from_raw` spelled over a 32-byte PREFIX — `raw.get(..32)` — accepts
        // every longer key and TRUNCATES it, so two distinct `key` hex strings
        // fold to one fingerprint, against AUTH-2.99's one canonical raw form
        // per token. At the record level AUTH-2.130's compare hides that (the
        // 64-hex re-encoding differs from the body), so the over-length row has
        // to be stated here, against `parse` itself.
        for wrong in [row.raw_len - 1, row.raw_len + 1] {
            assert_eq!(
                PublicKey::parse(row.token, &"00".repeat(wrong)),
                Err(ParseKeyError::BadLength),
                "{}: {wrong} bytes must not parse — raw_len is {}",
                row.token,
                row.raw_len
            );
        }
    }
    // Arms → table: every variant's token is a row. A NEW VARIANT MUST BE
    // ADDED HERE beside its ALGS row (AUTH-2.91's one-edit-plus-assertion).
    let arms: &[PublicKey] = &[
        PublicKey::MlDsa65Ed25519(Box::new([0u8; MLDSA65_ED25519_KEY_LEN])),
        PublicKey::FnDsa512PreviewEd25519(Box::new([0u8; FNDSA512_PREVIEW_ED25519_KEY_LEN])),
    ];
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
    // THE KEY KINDS ARE THE TWO HYBRID ROWS (AUTH-1.1, AUTH-1.5; the
    // hybrid-only launch, owner 2026-09-26 "Q1 b delete it"): tag 1's and tag
    // 3's tokens, in that order; the classical `ed25519` row is DELETED and
    // tag 2's reserved `fndsa512-ed25519` has no row — both name no row at
    // the parse, the frozen token set's own refusal (AUTH-2.96).
    let tokens: Vec<&str> = ALGS.iter().map(|a| a.token).collect();
    assert_eq!(tokens, [ALG_MLDSA65_ED25519, ALG_FNDSA512_PREVIEW_ED25519]);
    for deleted_or_reserved in ["ed25519", "fndsa512-ed25519"] {
        assert_eq!(
            PublicKey::parse(deleted_or_reserved, &"00".repeat(32)),
            Err(ParseKeyError::UnknownAlg),
            "{deleted_or_reserved} names no ALGS row"
        );
    }
}

/// AUTH-1.4 — the ROW decides the variant, never the width: a row's token
/// admits exactly its OWN raw length and never another row's, by either
/// constructor (`AlgRow::from_raw`: "a `PublicKey` of THIS row's variant,
/// `None` iff they are not this row's raw length"). The two hybrid widths are
/// distinct — 1,984 and 929 — so a constructor that picked the variant by
/// length builds the right key at every row's own width, which is every width
/// the rest of the suite tries, and ALSO admits the other row's width under a
/// real token, answering a key whose `alg()` is not the token it was named
/// by. That is the nearly-valid input: a width the table admits under a token
/// the table admits, that are not one row's. A record naming such a pair is
/// still `bad_record` (AUTH-2.130's compare re-encodes the other `alg`), so
/// the contract stated here is `parse`'s and `from_halves`' own — the one a
/// signing client and a mirror call directly.
#[test]
fn a_rows_token_admits_its_own_width_and_never_another_rows() {
    for named in SIG_ALGS {
        for sized in SIG_ALGS {
            let parsed = PublicKey::parse(named.token, &"00".repeat(sized.key_len()));
            let composed =
                PublicKey::from_halves(named.token, &vec![0u8; sized.pq_key_len], &[0u8; 32]);
            if named == sized {
                assert_eq!(
                    parsed.map(|k| k.alg()),
                    Ok(named.token),
                    "parse at {}'s own width",
                    named.token
                );
                assert_eq!(
                    composed.map(|k| k.alg()),
                    Ok(named.token),
                    "from_halves at {}'s own width",
                    named.token
                );
            } else {
                assert_eq!(
                    parsed,
                    Err(ParseKeyError::BadLength),
                    "parse: {} over {}'s {} raw bytes",
                    named.token,
                    sized.token,
                    sized.key_len()
                );
                assert_eq!(
                    composed,
                    Err(ParseKeyError::BadLength),
                    "from_halves: {} over {}'s {}-byte post-quantum half",
                    named.token,
                    sized.token,
                    sized.pq_key_len
                );
            }
        }
    }
}

/// THE MARKER-TAG TABLE beside `ALGS` (signed ops; the design record §7.3
/// (i)'s two-row `u8 ↔ token` table): every row's token is an `ALGS` row
/// whose raw length is the row's own key width, and every `ALGS` row has a
/// marker tag — the key kinds are the hybrid rows alone.
#[test]
fn every_marker_tag_row_is_an_algs_row_of_its_own_key_width() {
    for row in SIG_ALGS {
        let alg_row =
            ALGS.iter().find(|a| a.token == row.token).expect("a SIG_ALGS token is an ALGS row");
        assert_eq!(
            alg_row.raw_len,
            row.key_len(),
            "{}: the row's key width is its ALGS raw_len",
            row.token
        );
    }
    assert_eq!(SIG_ALGS.len(), ALGS.len(), "every key kind signs under a marker tag");
}

/// The marker tags are distinct, never `0` — the empty marker slot — and
/// never `2`, reserved for the final FIPS 206; neither of those two names a
/// row.
#[test]
fn the_marker_tags_are_distinct_and_never_the_empty_slot_or_the_reserved_tag() {
    for row in SIG_ALGS {
        assert_ne!(row.tag, 0, "tag 0 is the empty marker slot");
        assert_ne!(row.tag, 2, "tag 2 is reserved for the final FIPS 206");
    }
    for (i, a) in SIG_ALGS.iter().enumerate() {
        for b in &SIG_ALGS[i + 1..] {
            assert_ne!(a.tag, b.tag, "two rows name one tag");
        }
    }
    assert_eq!(SigAlgRow::of_tag(0), None, "tag 0 is the empty marker slot");
    assert_eq!(SigAlgRow::of_tag(2), None, "tag 2 is reserved for the final FIPS 206");
}

/// Every route to a marker row answers the whole row, the same one — its
/// token, its tag, and a key's own [`PublicKey::sig_alg_row`] — and the
/// deleted classical token names no row.
#[test]
fn the_token_the_tag_and_the_key_each_reach_the_same_marker_row() {
    for row in SIG_ALGS {
        let token_row = SigAlgRow::of_token(row.token);
        assert_eq!(token_row, Some(row), "{}: the token names this row", row.token);
        assert_eq!(SigAlgRow::of_tag(row.tag), Some(row), "{}: the tag names this row", row.token);
        let key = PublicKey::parse(row.token, &"0a".repeat(row.key_len())).unwrap();
        // The key's own row, reached by its arm and never by the table, is the
        // table's row for its token — the whole row, as a value.
        assert_eq!(key.sig_alg_row(), row, "{}: the key's row is the table's", row.token);
        assert_eq!(SigAlgRow::of_token(key.alg()), Some(key.sig_alg_row()), "{}", row.token);
    }
    assert_eq!(SigAlgRow::of_token("ed25519"), None, "the deleted classical token names no row");
}

/// The tag lookup is `const`: a width a type is sized by is read off the row
/// at compile time, never by a consumer's own walk of the table.
#[test]
fn the_marker_tag_lookup_reads_a_blob_width_at_compile_time() {
    const TAG1_BLOB: usize = match SigAlgRow::of_tag(1) {
        Some(row) => row.sig_len(),
        None => 0,
    };
    assert_eq!(TAG1_BLOB, 3373, "tag 1's blob width, read at compile time");
}

/// The ruled widths, by literal: tag 1's 1,984-byte key and 3,373-byte blob
/// (6,746 hex), tag 3's 929 and 730 (1,460 hex) — the widths a `sig` naming
/// no row is admitted at, and no other (AUTH-6.3) — each key width the
/// `*_KEY_LEN` constant beside it, and the preview saying so in its token.
#[test]
fn the_marker_rows_carry_the_ruled_widths() {
    let tag1 = SigAlgRow::of_token(ALG_MLDSA65_ED25519).unwrap();
    assert_eq!((tag1.tag, tag1.key_len(), tag1.sig_len(), tag1.pq_sig_len), (1, 1984, 3373, 3309));
    assert_eq!(tag1.key_len(), MLDSA65_ED25519_KEY_LEN);
    let tag3 = SigAlgRow::of_token(ALG_FNDSA512_PREVIEW_ED25519).unwrap();
    assert_eq!((tag3.tag, tag3.key_len(), tag3.sig_len(), tag3.pq_sig_len), (3, 929, 730, 666));
    assert_eq!(tag3.key_len(), FNDSA512_PREVIEW_ED25519_KEY_LEN);
    assert!(ALG_FNDSA512_PREVIEW_ED25519.contains("preview"), "the preview says so in its token");
}

/// THE KEY PIN, read out of a parsed hybrid: the post-quantum half leads at
/// its row's width and the Ed25519 half is the LAST 32 raw bytes — at every
/// row, and at tag 1 over bytes that vary by position, so a swap or a
/// misplaced split shows.
#[test]
fn a_parsed_hybrid_leads_with_its_post_quantum_half_and_closes_with_its_ed25519_half() {
    for row in SIG_ALGS {
        let key = PublicKey::parse(row.token, &"0a".repeat(row.key_len())).unwrap();
        assert_eq!(key.pq_half().len(), row.pq_key_len, "the PQ half leads");
        assert_eq!(key.ed25519_half().len(), 32, "the Ed25519 half closes");
    }
    let raw: Vec<u8> = (0..1984u32).map(|i| (i % 251) as u8).collect();
    let k = PublicKey::parse(
        ALG_MLDSA65_ED25519,
        &raw.iter().map(|b| format!("{b:02x}")).collect::<String>(),
    )
    .unwrap();
    assert_eq!(k.ed25519_half(), &raw[1952..]);
    assert_eq!(k.pq_half(), &raw[..1952]);
}

/// One fingerprint over the whole concatenated raw value (the design record
/// §4.4): a hybrid's fingerprint is not either half's.
#[test]
fn a_hybrids_fingerprint_covers_its_whole_raw_value() {
    let hybrid = PublicKey::parse(ALG_MLDSA65_ED25519, &"0a".repeat(1984)).unwrap();
    let want: [u8; 32] =
        Sha256::digest(framed(KEY_TAG, &[ALG_MLDSA65_ED25519.as_bytes(), &[0x0a; 1984]])).into();
    assert_eq!(Fingerprint::of(&hybrid).as_bytes(), &want);
}

/// THE HYBRID BLOB a `sig` naming no row spells (AUTH-4.34, AUTH-6.3; signed
/// ops, the design record §4.5 (4)'s step (3), l7-C3): hex, case-free, at
/// EXACTLY a width some `SIG_ALGS` row's blob takes — every row's width
/// admitted, read off the table as the parse reads it, its bytes the ones the
/// hex spells and its uppercase spelling the same blob — and nothing else: one
/// byte either side of a row's width, an odd hex length, a non-hex byte at a
/// row's width, the classical 64 bytes and the empty string are each no blob.
/// The daemon's handshake and record grade, the resolver and the signing
/// client's reader all read a `sig` through this one parse, so none answers a
/// blob of no row's width as one no key verifies.
#[test]
fn a_hybrid_blob_is_hex_of_a_rows_width_and_nothing_else() {
    for row in SIG_ALGS {
        let n = row.sig_len();
        let blob = HybridBlob::parse_hex(&"ab".repeat(n))
            .unwrap_or_else(|| panic!("tag {}'s width is a blob's", row.tag));
        let bytes = vec![0xab_u8; n];
        assert_eq!(blob.as_bytes(), bytes.as_slice(), "tag {}: the bytes the hex spells", row.tag);
        assert_eq!(
            HybridBlob::parse_hex(&"AB".repeat(n)),
            Some(blob),
            "tag {}: case-free — decoded, never framed",
            row.tag
        );
        for off_by_one in [n - 1, n + 1] {
            if SIG_ALGS.iter().any(|other| other.sig_len() == off_by_one) {
                continue; // another row's width
            }
            let wrong = HybridBlob::parse_hex(&"ab".repeat(off_by_one));
            assert_eq!(wrong, None, "tag {}: {off_by_one} bytes", row.tag);
        }
        let odd = HybridBlob::parse_hex(&"a".repeat(2 * n - 1));
        assert_eq!(odd, None, "tag {}: an odd hex length", row.tag);
        let non_hex = HybridBlob::parse_hex(&format!("zz{}", "ab".repeat(n - 1)));
        assert_eq!(non_hex, None, "tag {}: a non-hex byte at the row's width", row.tag);
    }
    let classical = HybridBlob::parse_hex(&"ab".repeat(64));
    assert_eq!(classical, None, "the classical 64 bytes are no row's");
    assert_eq!(HybridBlob::parse_hex(""), None, "the empty string");
}

/// A hybrid blob's `{:?}` is its width and the SHA-256 of its bytes in flat
/// lowercase hex — never the bytes, which at tag 1's 3,373 a failing
/// assertion over two blobs would print in full — as a key's `{:?}` is its
/// fingerprint and never its raw value.
#[test]
fn a_hybrid_blob_renders_as_its_width_and_digest() {
    let row = SigAlgRow::of_tag(1).expect("tag 1's row");
    let blob = HybridBlob::parse_hex(&"ab".repeat(row.sig_len())).expect("tag 1's width");
    let digest: String =
        Sha256::digest(blob.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(format!("{blob:?}"), format!("HybridBlob(3373 bytes, sha-256 {digest})"));
}

/// The two token lookups admit ONE token set, exactly the rows':
/// `PublicKey::parse`'s row lookup over `ALGS` (the record grammar's) and
/// `SigAlgRow::of_token` over `SIG_ALGS` (skepd's codec lifts a request's
/// `attest.alg` through it). Each is held to the two real tokens and to the
/// near-misses a lenient lookup would admit — case, surrounding whitespace, a
/// truncation, an extension, tag 2's reserved token (which `of_token`'s own
/// card names), the deleted classical one, the empty string — so neither
/// grows a leniency the other lacks: an `of_token` that ignored case would
/// lift `MLDSA65-ED25519` to tag 1 on the wire while the grammar calls a
/// record naming it `bad_record`. The parse half reads an EMPTY key, so the
/// refusal says which check spoke: `BadLength` is the row, found, refusing
/// its length; `UnknownAlg` is no row at all.
#[test]
fn both_token_lookups_admit_exactly_the_row_tokens() {
    for token in [ALG_MLDSA65_ED25519, ALG_FNDSA512_PREVIEW_ED25519] {
        assert!(SigAlgRow::of_token(token).is_some(), "of_token({token:?})");
        assert_eq!(
            PublicKey::parse(token, ""),
            Err(ParseKeyError::BadLength),
            "parse({token:?}, \"\")"
        );
    }
    for near_miss in [
        "MLDSA65-ED25519",
        "Mldsa65-Ed25519",
        " mldsa65-ed25519",
        "mldsa65-ed25519 ",
        "mldsa65-ed25519\n",
        "mldsa65",
        "mldsa65-ed2551",
        "mldsa65-ed25519-v2",
        "FNDSA512-PREVIEW-ED25519",
        "fndsa512-preview",
        "fndsa512-ed25519",
        "ed25519",
        "",
    ] {
        assert_eq!(SigAlgRow::of_token(near_miss), None, "of_token({near_miss:?})");
        assert_eq!(
            PublicKey::parse(near_miss, ""),
            Err(ParseKeyError::UnknownAlg),
            "parse({near_miss:?}, \"\")"
        );
    }
}

/// THE KEY PIN, written and read by one crate: at every row, the key
/// [`PublicKey::from_halves`] composes IS the key whose halves
/// `pq_half`/`ed25519_half` read back — post-quantum half first, Ed25519 half
/// last — and the key `parse` admits for the concatenated hex. A signer that
/// composes through the constructor cannot swap the halves; one that spelled
/// the raw value itself could, and the fold, judging length alone (AUTH-1.4),
/// would enroll the result. The constructor answers `parse`'s own refusals:
/// a token no row carries, a post-quantum half of the wrong width.
#[test]
fn a_key_composed_from_its_halves_reads_back_the_same_halves() {
    for row in SIG_ALGS {
        let raw: Vec<u8> = (0..row.key_len()).map(|i| (i % 251) as u8).collect();
        let (pq, tail) = raw.split_at(row.pq_key_len);
        let ed25519: &[u8; 32] = tail.try_into().expect("the Ed25519 half is 32 bytes");
        let composed = PublicKey::from_halves(row.token, pq, ed25519).expect("the row's widths");
        assert_eq!(composed.raw(), &raw[..], "{}: the post-quantum half first", row.token);
        assert_eq!(composed.pq_half(), pq, "{}", row.token);
        assert_eq!(composed.ed25519_half(), ed25519, "{}", row.token);
        let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(PublicKey::parse(row.token, &hex), Ok(composed), "{}", row.token);
        assert_eq!(
            PublicKey::from_halves(row.token, &pq[1..], ed25519),
            Err(ParseKeyError::BadLength),
            "{}: a post-quantum half one byte short",
            row.token
        );
    }
    assert_eq!(
        PublicKey::from_halves("ed25519", &[], &[0; 32]),
        Err(ParseKeyError::UnknownAlg),
        "the deleted classical token names no row, whatever the halves"
    );
}

/// `PublicKey`'s card: the hybrid arms are BOXED, "so a hybrid key is one
/// allocation and the enum stays a few words wide" — the seam build's first
/// run overflowed a daemon worker's stack with a 1,984-byte key inline, riding
/// every `Enrolled` through `im`'s inline-chunked map nodes. The width IS the
/// claim, stated at FOUR words: room for any boxed arm, a fat box's length
/// included, and hundreds of bytes short of the narrowest key an arm could
/// carry inline. An arm unboxed again — even the 929-byte preview arm alone —
/// need not overflow a test stack to put its bytes back into every map node,
/// and this is where it is discovered.
#[test]
fn a_public_key_is_a_few_words_wide() {
    let width = std::mem::size_of::<PublicKey>();
    assert!(
        width <= 4 * std::mem::size_of::<usize>(),
        "PublicKey is {width} bytes wide: a key is inline again"
    );
}

/// AUTH-1.2/AUTH-1.3 — a key answers its row's token and raw value — at the
/// tag-1 row, 1,984 raw bytes — and spells that value as lowercase hex, two
/// digits a byte, 3,968 characters.
#[test]
fn a_key_answers_its_rows_token_and_spells_its_raw_value_in_lowercase_hex() {
    let k = key(0xab);
    assert_eq!(k.alg(), "mldsa65-ed25519");
    assert_eq!(k.raw().len(), 1984);
    let key_hex = k.to_hex();
    assert_eq!(key_hex.len(), 3968);
    assert_eq!(key_hex, key_hex.to_lowercase());
}

/// AUTH-1.3 — `parse` reads hex in either case: a key's hex spelled in
/// uppercase parses to that key, so `parse` inverts `to_hex` whatever case a
/// caller wrote.
#[test]
fn parse_reads_either_case_and_inverts_to_hex() {
    let k = key(0xab);
    let key_hex = k.to_hex();
    assert_eq!(PublicKey::parse("mldsa65-ed25519", &key_hex.to_uppercase()).unwrap(), k);
}

/// AUTH-1.4 — SYNTAX ONLY: `parse` decodes no point and no lattice key, so
/// bytes of the row's raw width are a key whatever they hold — 1,984 bytes of
/// `0xff` here.
#[test]
fn parse_judges_syntax_alone_and_admits_any_bytes_of_the_rows_width() {
    assert_eq!(PublicKey::parse("mldsa65-ed25519", &"ff".repeat(1984)).err(), None);
}

/// AUTH-1.4 — `parse`'s checks run in ONE order and the first failure is the
/// verdict: the token, then the hex, then the length. A token no row carries
/// is `UnknownAlg` whatever the hex: hex that does not decode — the card's
/// own example, `("rsa", "zz")` — a key's own hex, and the deleted classical
/// token over a classical-width key. Then hex that does not decode is
/// `BadHex`: non-hex digits, `"zz"`, and an odd length, a key's hex one
/// character short. Only then is a wrong length `BadLength`: a key's hex one
/// byte short. A decode hoisted above the lookup answers `BadHex` for
/// `("rsa", "zz")`; a length test hoisted above the decode answers
/// `BadLength` for `"zz"` and for the odd length.
#[test]
fn parse_refuses_in_its_pinned_order_token_then_hex_then_length() {
    let key_hex = key(0xab).to_hex();
    assert_eq!(PublicKey::parse("rsa", "zz"), Err(ParseKeyError::UnknownAlg));
    assert_eq!(PublicKey::parse("rsa", &key_hex), Err(ParseKeyError::UnknownAlg));
    // The deleted classical token names no row (AUTH-1.5): `UnknownAlg`, as
    // any unadmitted token, whatever the key.
    assert_eq!(PublicKey::parse("ed25519", &"ab".repeat(32)), Err(ParseKeyError::UnknownAlg));
    assert_eq!(PublicKey::parse("mldsa65-ed25519", "zz"), Err(ParseKeyError::BadHex));
    assert_eq!(
        PublicKey::parse("mldsa65-ed25519", &key_hex[..key_hex.len() - 1]),
        Err(ParseKeyError::BadHex)
    );
    assert_eq!(
        PublicKey::parse("mldsa65-ed25519", &key_hex[..key_hex.len() - 2]),
        Err(ParseKeyError::BadLength)
    );
}

/// `parse`'s two arguments are both `&str`, so a caller can pass either where
/// the other belongs, and neither is ever read as the other: a key's hex in
/// the token's place names no row (`UnknownAlg`), and a token in the hex's
/// place is no hex (`BadHex`).
#[test]
fn parse_never_reads_a_keys_hex_as_a_token_or_a_token_as_hex() {
    let key_hex = key(0xab).to_hex();
    assert_eq!(PublicKey::parse(&key_hex, ALG_MLDSA65_ED25519), Err(ParseKeyError::UnknownAlg));
    assert_eq!(
        PublicKey::parse(ALG_MLDSA65_ED25519, ALG_MLDSA65_ED25519),
        Err(ParseKeyError::BadHex)
    );
}

/// AUTH-1.9 — `Fingerprint::to_hex`/`parse_hex`: 64 lowercase out; exactly
/// 64 hex in, case-insensitively; `None` for anything else.
#[test]
fn fingerprint_hex_round_trips_and_admits_exactly_64_chars() {
    let f = fp(9);
    let fp_hex = f.to_hex();
    assert_eq!(fp_hex.len(), 64);
    assert_eq!(fp_hex, fp_hex.to_lowercase());
    assert_eq!(Fingerprint::parse_hex(&fp_hex).unwrap(), f);
    assert_eq!(Fingerprint::parse_hex(&fp_hex.to_uppercase()).unwrap(), f);
    assert_eq!(Fingerprint::parse_hex(&fp_hex[..62]), None);
    assert_eq!(Fingerprint::parse_hex(&format!("{fp_hex}00")), None);
    assert_eq!(Fingerprint::parse_hex(&format!("g{}", &fp_hex[1..])), None);
}

/// AUTH-2.93 — the `TAGS` assertion: every tag begins `skep-`, and no tag
/// is a prefix of another (AUTH-1.15). With `SESSION_TAG_V2` (RES-63) the
/// check is load-bearing: `skep-session-v1` and `skep-session-v2` share the
/// prefix `skep-session-v` yet neither is a prefix of the other.
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
    // The five declared constants are the table, in declaration order — the
    // fifth the ENTRY frame's (signed ops).
    assert_eq!(TAGS.len(), 5);
    assert_eq!(TAGS[0], KEY_TAG);
    assert_eq!(TAGS[1], SESSION_TAG);
    assert_eq!(TAGS[2], SESSION_TAG_V2);
    assert_eq!(TAGS[3], NODE_HELLO_TAG);
    assert_eq!(TAGS[4], ENTRY_TAG);
}

/// AUTH-1.11 — the five declared tags' BYTES, not merely their properties.
/// A tag IS the domain separator, so its bytes are the protocol: a changed
/// tag silently invalidates every signature made under the old one, and
/// moves every fingerprint. [`KEY_TAG`] sits inside every fingerprint
/// (AUTH-1.8), and the other four separate signatures made and checked
/// outside this crate — skepd's session layer frames the handshake under
/// [`SESSION_TAG`] and [`SESSION_TAG_V2`], every entry signer and verifier
/// frames under [`ENTRY_TAG`] through `entry_frame`, and bebe consumes
/// [`NODE_HELLO_TAG`] (AUTH-2.118). `tags_are_skep_prefixed_and_prefix_free`
/// keeps holding after any rename that stays `skep-`-prefixed and
/// prefix-free, so this is where a changed tag is discovered: all five, in
/// the one test named for them.
#[test]
fn the_declared_tag_bytes_are_pinned() {
    assert_eq!(KEY_TAG.as_bytes(), b"skep-key-v1".as_slice());
    assert_eq!(SESSION_TAG.as_bytes(), b"skep-session-v1".as_slice());
    assert_eq!(SESSION_TAG_V2.as_bytes(), b"skep-session-v2".as_slice());
    assert_eq!(NODE_HELLO_TAG.as_bytes(), b"skep-node-hello-v1".as_slice());
    assert_eq!(ENTRY_TAG.as_bytes(), b"skep-entry-v1".as_slice());
}

/// AUTH-2.90/AUTH-2.96 — the frozen `ALGS` token set by VALUE, both rows. A
/// token sits inside every key's fingerprint preimage (AUTH-1.8), every
/// record's `alg` member and every entry frame's first member, so renaming
/// one moves all three for every key of its row, and every signature made
/// under the old spelling stops verifying. Tag 1's spelling is also stated by
/// `a_key_answers_its_rows_token_and_spells_its_raw_value_in_lowercase_hex`
/// and the grammar corpus's literal records; tag 3's is stated nowhere else in
/// this crate — `contains("preview")` admits most renames — and outside it
/// only skepd's tag-3 golden would notice, as a fingerprint digest that moved.
#[test]
fn the_alg_tokens_are_pinned_by_value() {
    assert_eq!(ALG_MLDSA65_ED25519, "mldsa65-ed25519");
    assert_eq!(ALG_FNDSA512_PREVIEW_ED25519, "fndsa512-preview-ed25519");
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

/// AUTH-2.55/AUTH-1.28 — `Inert::detail()`: the wire detail, which is the
/// token on eleven arms and the JOIN on the twelfth.
/// `every_inert_variant_has_its_pinned_token` pins the token half; this pins
/// the join — the half every consumer would otherwise assemble for itself,
/// and the `duplicate_key:<n>` row carries a parameterized sub through it.
#[test]
fn inert_detail_is_the_token_joined_to_its_payload_fault() {
    assert_eq!(Inert::NotDocOne.detail(), Inert::NotDocOne.token());
    assert_eq!(
        Inert::MalformedPayload(PayloadError::BadRecord).detail(),
        "malformed_payload:bad_record"
    );
    assert_eq!(
        Inert::MalformedPayload(PayloadError::DuplicateKey(3)).detail(),
        "malformed_payload:duplicate_key:3"
    );
}

/// AUTH-1.41 — `genesis() == default()`; AUTH-2.58 — the empty set for an
/// unknown account; AUTH-2.56 — no claimant, no keyed accounts at genesis.
#[test]
fn genesis_state_is_default_and_answers_empty() {
    let st = IdentityState::genesis();
    assert_eq!(st, IdentityState::default());
    assert!(st.key_set(&addr(ACCT_A)).is_empty());
    assert_eq!(st.claimant(), None);
    assert_eq!(st.keyed_accounts().count(), 0);
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
        PayloadError::BadRecord,
        PayloadError::Empty,
        PayloadError::DuplicateKey(12),
    ] {
        assert_eq!(e.to_string(), e.token(), "Display and token disagree");
    }
}

/// The four types this crate returns in `Err` compose with `?` into
/// `Box<dyn Error>`, so a consumer plumbs them rather than defining a local
/// wrapper enum to re-implement `Display` behind.
#[test]
fn error_types_lift_into_dyn_error() {
    fn lift(e: impl std::error::Error + 'static) -> Box<dyn std::error::Error> {
        Box::new(e)
    }
    // Each carries its own message through the erasure.
    let boxed = lift(PublicKey::parse("rsa", "00").expect_err("unknown alg"));
    assert_eq!(boxed.to_string(), ParseKeyError::UnknownAlg.to_string());
    let boxed = lift(Enrollment::new(key(1), false, Some("a\nb".to_owned())).expect_err("newline"));
    assert_eq!(boxed.to_string(), LabelError::Newline.to_string());
    let boxed = lift(PayloadError::DuplicateKey(4));
    assert_eq!(boxed.to_string(), "duplicate_key:4");
    let floor = entry_body_publish([], None).as_bytes().len();
    let past_budget = PublishBody::within(floor, None).and_then(|body| body.push(b""));
    let boxed = lift(past_budget.expect_err("an empty value costs its length prefix"));
    assert_eq!(boxed.to_string(), PublishRefusal::PastBudget.to_string());
}

/// Three of this crate's promises are kept by a trait their type does NOT
/// implement, which no call can test and a derive added for symmetry breaks —
/// so they are held here at compile time, as `PublishBody`'s not-`Clone` is
/// beside its type: the `_` below is inferred while the blanket impl is the
/// only one that applies, and a type meeting the second makes the path
/// ambiguous. `Inert` is deliberately not `Display`, and so no
/// `std::error::Error`: its wire detail is [`Inert::detail`]'s join on the
/// payload arm, and the `{}` a consumer reaches for first would answer the
/// token alone — `malformed_payload` where the detail is
/// `malformed_payload:bad_record`. `Enrollment::new` is the ONLY constructor
/// (AUTH-1.25): a derived `Deserialize` — `PublicKey`, `Fingerprint` and
/// `Enrolled` each carry one — would be a second, building a label outside
/// AUTH-1.24's domain that no record admits and that I1's round trip, drawing
/// through `new`, never meets. And [`HybridBlob::parse_hex`] is its type's
/// ONLY constructor (AUTH-4.34): a derived `Deserialize` — `PublicKey` and
/// `Fingerprint` carry one in the same file — would be a second, admitting a
/// blob of any width, the one value the type exists to make unrepresentable.
const _: fn() = || {
    trait AmbiguousIfDisplay<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfDisplay<()> for T {}
    #[allow(dead_code)]
    struct IsDisplay;
    impl<T: ?Sized + std::fmt::Display> AmbiguousIfDisplay<IsDisplay> for T {}
    let _ = <Inert as AmbiguousIfDisplay<_>>::check;

    trait AmbiguousIfDeserialize<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfDeserialize<()> for T {}
    #[allow(dead_code)]
    struct IsDeserialize;
    impl<T: for<'de> serde::Deserialize<'de>> AmbiguousIfDeserialize<IsDeserialize> for T {}
    let _ = <Enrollment as AmbiguousIfDeserialize<_>>::check;
    let _ = <HybridBlob as AmbiguousIfDeserialize<_>>::check;
};

/// The fold's seam forwards through `&T` and `Box<T>`, as std's own traits
/// do, so a host holding its world behind a trait object reaches the fold
/// and the read. An `impl FoldCtx` parameter is a generic with an implicit
/// `Sized` bound: `dyn FoldCtx` itself never satisfies one, so a host holding
/// `&dyn FoldCtx` or `Box<dyn FoldCtx>` hands the fold that reference or box
/// as the ctx — a ctx only through these impls, which the orphan rule leaves
/// the host no way to write, only a newtype forwarding every fact. The test
/// is a compile-time witness of all four impls, and each call is held to the
/// same call on the concrete ctx — over TWO deposits, because `is_account` and
/// `is_published` share one signature and a forwarding impl can answer one
/// with the other: on a deposit every fact honors, both answer `true` for the
/// address the fold asks each about, and only a `to` naming no account —
/// where `is_account` answers `false` and `is_published`, asked the same
/// address, `true` — tells them apart.
#[test]
fn a_ctx_behind_a_trait_object_reaches_the_fold_and_the_read() {
    let mut fx = Fixture::new();
    let honored = fx.enroll_dep(&doc1(ACCT_A), ACCT_A, &enroll_payload(&[(1, true)]));
    // A later child of ACCT_A at which no principal is registered.
    let no_account = fx.enroll_dep(&doc1(ACCT_A), &[1, 1, 0, 5, 2], &enroll_payload(&[(2, true)]));
    let st = IdentityState::genesis();
    assert_honored(&fx.classify(&st, &honored));
    assert_detail(&fx.classify(&st, &no_account), "malformed_shape");
    let borrowed: &dyn FoldCtx = &fx.ctx;
    let boxed: Box<dyn FoldCtx> = Box::new(fx.ctx.clone());
    for (name, dep) in [("honored", &honored), ("no_account", &no_account)] {
        let want = fx.classify(&st, dep);
        let dep = dep.as_link_deposit();
        assert_eq!(st.classify(&fx.types, &borrowed, &dep), want, "{name} through &dyn FoldCtx");
        assert_eq!(st.classify(&fx.types, &boxed, &dep), want, "{name} through Box<dyn FoldCtx>");
    }
    let borrowed_values: &dyn Values = &fx.ctx;
    assert_eq!(
        record_bytes(&borrowed_values, &honored.home, &honored.from),
        record_bytes(&fx.ctx, &honored.home, &honored.from),
        "&dyn Values"
    );
    let boxed_values: Box<dyn Values> = Box::new(fx.ctx.clone());
    assert_eq!(
        record_bytes(&boxed_values, &honored.home, &honored.from),
        record_bytes(&fx.ctx, &honored.home, &honored.from),
        "Box<dyn Values>"
    );
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
        Inert::MalformedPayload(PayloadError::BadRecord),
    ] {
        *tally.entry(inert).or_insert(0) += 1;
    }
    assert_eq!(tally.len(), 2);
    assert_eq!(tally[&Inert::NotDocOne], 2);

    // The other five, in the shape a conformance list takes.
    let faults: HashSet<PayloadError> = [
        PayloadError::BadRecord,
        PayloadError::BadRecord,
        PayloadError::NotUtf8,
    ]
    .into_iter()
    .collect();
    assert_eq!(faults.len(), 2);
    let kinds = HashSet::from([CredentialKind::Enroll, CredentialKind::Claim]);
    assert_eq!(kinds.len(), 2);
    let key_faults = HashSet::from([ParseKeyError::BadHex, ParseKeyError::UnknownAlg]);
    assert_eq!(key_faults.len(), 2);
    // `LabelError` has two variants (AUTH-1.23), so a set over it holds at
    // most two rows.
    assert_eq!(
        HashSet::from([LabelError::Newline, LabelError::TooLong, LabelError::Newline]).len(),
        2
    );
    let refusals = HashSet::from([
        PublishRefusal::PastBudget,
        PublishRefusal::Unspellable,
        PublishRefusal::PastBudget,
    ]);
    assert_eq!(refusals.len(), 2);
}

/// AUTH-1.9/AUTH-1.7 — the hand-written renderings: a key's `{:?}` is its
/// token and its FINGERPRINT's flat hex — the identity a reader greps a log
/// for — never its raw value, which at a hybrid's 1,984 bytes every `Debug`
/// holding a key would repeat; a fingerprint's `{:?}` and `Display` are its
/// flat hex, `Display` exactly `to_hex`: the form the daemon emits (grouped
/// rendering is the client's, AUTH-1.10).
#[test]
fn key_and_fingerprint_render_as_the_fingerprint_hex() {
    let k = key(0xab);
    let want = format!("PublicKey(mldsa65-ed25519, fingerprint {})", Fingerprint::of(&k).to_hex());
    assert_eq!(format!("{k:?}"), want);

    let f = fp(0xab);
    assert_eq!(f.to_string(), f.to_hex());
    assert_eq!(format!("{f:?}"), format!("Fingerprint({})", f.to_hex()));
}

/// A board term's `{:?}` is its two halves as the wire spells them (D13): the
/// LOG position in decimal and the chain in flat lowercase hex — `/health`'s
/// `chain_head` and `H.1`'s `chain` — never thirty-two decimal bytes; and its
/// `{:#?}` lays the two out field by field, as a derived `Debug` does. The
/// chain counts up from `00`, so a rendering that reversed, dropped or
/// reordered a byte reads otherwise.
#[test]
fn a_board_term_renders_its_chain_as_hex() {
    let term = BoardTerm { log_position: 12, chain: std::array::from_fn(|i| i as u8) };
    let chain: String = (0u8..32).map(|b| format!("{b:02x}")).collect();
    assert_eq!(format!("{term:?}"), format!("BoardTerm {{ log_position: 12, chain: {chain} }}"));
    assert_eq!(
        format!("{term:#?}"),
        format!("BoardTerm {{\n    log_position: 12,\n    chain: {chain},\n}}")
    );
}

/// A `Tag` is `Copy`, so a BOUND tag frames as often as a caller likes and
/// `TAGS` iterates by value — the framing surface does not ration the
/// declared constants (AUTH-1.13's private field is what rations WHICH tags
/// exist). `Debug` renders the bytes, which for a `skep-` ASCII tag is the
/// name (AUTH-1.15).
#[test]
fn tag_is_copy_and_debugs_as_its_bytes() {
    let tag = KEY_TAG;
    let first = framed(tag, &[b"a"]);
    let second = framed(tag, &[b"a"]);
    assert_eq!(first, second);
    for t in TAGS {
        assert_eq!(framed(*t, &[]), t.as_bytes());
    }
    assert_eq!(format!("{KEY_TAG:?}"), "Tag(skep-key-v1)");
}

/// The items this crate publishes for the readers the spec or the design
/// record names — the ones `lib.rs`'s "Composition, as built" lists with the
/// rule that declares each, some of those readers in this workspace and some
/// outside it — named here, from outside the crate. Whether a crate of the
/// workspace calls one today is no part of why it is public: where none does,
/// a visibility audit that looks for callers finds nothing and narrowing the
/// item to `pub(crate)` leaves every other build green; this one stops
/// compiling, at the item. An item published for such a reader joins this
/// list and that paragraph together.
#[test]
fn the_items_published_for_the_readers_the_spec_names_are_public() {
    // The signing client and the verifier beside the table (the design
    // record §4.2 (C)) — the verifier's parse answering the entries and the
    // `sig` together.
    let _ = canonical_record::<Enrollment>(&[], None);
    let _ = (parse_enroll(b""), parse_retire(b""));
    let _: Result<RecordValue<Enrollment>, PayloadError> = parse_record_value(b"");
    let _: Result<RecordValue<Fingerprint>, PayloadError> = parse_record_value(b"");
    // A non-folding reader, which LINKS the read (AUTH-2.37); a discovery
    // caller, beside `kind_of` (AUTH-2.28); a host that seats the slice
    // (AUTH-2.60); bebe (AUTH-2.118).
    let _ = record_bytes(&TestCtx::default(), &addr(ACCT_A), &[]);
    let _ = single_address(std::iter::empty());
    let _: Option<&dyn HasIdentity> = None;
    let _ = NODE_HELLO_TAG;
    // A reader holding no M3, finding the doc 1 every honored credential link
    // is homed in (AUTH-2.126, AUTH-2.127).
    let _ = doc_1_of(&addr(ACCT_A));
    // The tables and constants the spec declares as the crate's surface
    // (AUTH-1.5, AUTH-1.11, AUTH-1.17, AUTH-1.18), and the widths the design
    // record declares beside them.
    let _: &[AlgRow] = ALGS;
    let _ = (TAGS, KEY_TAG, ENTRY_TAG, ENROLL_TYPE, RETIRE_TYPE);
    let _ = (ED25519_KEY_LEN, MLDSA65_KEY_LEN, FNDSA512_PREVIEW_KEY_LEN);
    let _ = (MLDSA65_ED25519_KEY_LEN, FNDSA512_PREVIEW_ED25519_KEY_LEN);
}
