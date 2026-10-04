//! THE VERIFY (rm-2; REG-1.86 (e); R5 (f), (h); the seam investigation's
//! Q7) — the record grade for registry records, judged CLIENT-SIDE over the
//! crates below the daemon and never by linking it: the same check the
//! daemon makes at a registry deposit's `make_link` (its registry sequence's
//! trial), so the resolver's verdict on every row of a board equals the
//! daemon's admission of it.
//!
//! For every registry body the mirror folds — a binding's, an endpoint's:
//!
//! 1. THE BODY is parsed under THE CANONICAL RULE by `skep_registry::parse`
//!    (REG-1.86 (h): a parser is never derived from another parser) — the
//!    kind the link's type slot names; a refusal is a MALFORMED record,
//!    suppressed and counted by the mirror.
//! 2. THE BLOB — the `sig` member is the hybrid signature in hex, no `alg`
//!    beside it, decoding to exactly a width some `SIG_ALGS` row's blob
//!    takes; hex of no row's width is no signature.
//! 3. THE FRAME — the entry frame under the `record` grammar
//!    (`entry_frame`, `entry_body_record`, `RecordRows`), rebuilt from the
//!    row's own members as wire.md §Registry spells them: `board` `H.1`'s
//!    pair, `account` the HOME's account (ω over the home: the claimant's for
//!    a binding in the registrar's doc 1, the node account's for an endpoint
//!    in its own), `doc` the home, and the five body rows — the link's type
//!    address, its target as stored (the account bound, or none), the
//!    `replaces` row EMPTY (the member rides INSIDE the signed body for these
//!    kinds and no `replaces` link is written with them), the lineage row the
//!    trial hands — the lineage the reader's own root hint names (REG-3.45),
//!    EMPTY at this build (D2: the daemon composes every record grade so) —
//!    and the SIG-LESS CANONICAL PROJECTION of the body.
//! 4. THE CANDIDATES — the enrolled keys of THE SET THAT OPENS THE HOME'S
//!    ACCOUNT as of the record's own position, of the blob's width (the
//!    mirror supplies that set, `mirror/keys.rs`; anchor grade is never
//!    asked of a registry record).
//! 5. THE TRIAL — each candidate, the frame under its own token as `alg`,
//!    both halves (`skep_signature::verify`); the first that verifies names
//!    the hand, SIGNED(fingerprint); none, or no `sig` at all, is UNSIGNED.
//!
//! What the mirror cannot supply — no board term held, the set as of the
//! position unreadable, the bytes unfetchable — is UNDETERMINABLE HERE and
//! the mirror's to say; this module judges what it is handed.

use skep_address::Address;
use skep_identity::{
    entry_body_record, entry_frame, BoardTerm, DocTerm, Enrolled, Fingerprint, RecordRows, SIG_ALGS,
};
use skep_registry::Record;

use crate::hex_byte;
use crate::state::Verdict;

/// THE TRIAL's inputs by name — the frame's members beside the candidates.
#[derive(Debug, Clone, Copy)]
pub struct Trial<'a> {
    /// `H.1`'s committed pair, the board term (D13).
    pub board: BoardTerm,
    /// The deposit's home — the doc 1 the link sits in.
    pub home: &'a Address,
    /// The home's account — the frame's `account`, ω over the home.
    pub home_account: &'a Address,
    /// The link's type address — the binding's or the endpoint's row.
    pub ty: &'a Address,
    /// The link's target as stored: the account bound, or none.
    pub to: &'a [Address],
    /// The lineage row: the fork point of the lineage the reader's own root
    /// hint names (REG-3.45, REG-3.40), `None` for the EMPTY row.
    pub lineage: Option<&'a Address>,
    /// The set that opens the home's account AS OF the record's position.
    pub keys: &'a [Enrolled],
}

/// THE BLOB: a record's `sig` as the hybrid signature's bytes — hex,
/// case-free, decoding to EXACTLY a width some `SIG_ALGS` row's blob takes
/// (6,746 hex for tag 1's 3,373 bytes, 1,460 for tag 3's 730); `None` for
/// every other length and for a non-hex byte. The width is checked first, so
/// no allocation is sized by a stranger's string.
pub fn hybrid_blob(sig: &str) -> Option<Vec<u8>> {
    if !SIG_ALGS.iter().any(|row| row.sig_len() * 2 == sig.len()) {
        return None;
    }
    let (pairs, rest) = sig.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs.iter().map(|pair| hex_byte(*pair)).collect()
}

/// THE VERDICT on one parsed record under its trial (steps 2 to 5 of the
/// module doc): SIGNED by the first candidate whose verify passes, else
/// UNSIGNED — a `sig` absent, of no row's width, or verifying under no key of
/// the set as of the position earns no word of its own.
pub fn judge(record: &Record, trial: &Trial<'_>) -> Verdict {
    let Some(sig) = record.sig.as_deref() else {
        return Verdict::Unsigned;
    };
    let Some(blob) = hybrid_blob(sig) else {
        return Verdict::Unsigned;
    };
    let canonical = record.canonical_sigless();
    let body = entry_body_record(RecordRows {
        ty: trial.ty,
        to: trial.to,
        replaces: None,
        lineage_fork_point: trial.lineage,
        sigless_canonical_record: canonical.as_bytes(),
    });
    for enrolled in trial.keys {
        let key = &enrolled.key;
        let row = key.sig_alg_row();
        if row.sig_len() != blob.len() {
            continue;
        }
        let bytes = entry_frame(key.alg(), trial.board, trial.home_account, DocTerm::One(trial.home), &body);
        if skep_signature::verify(row.tag, key, &bytes, &blob).is_ok() {
            return Verdict::Signed(Fingerprint::of(key));
        }
    }
    Verdict::Unsigned
}

#[cfg(test)]
mod tests {
    use skep_registry::{encode, parse, Binding, Body, BodyKind, Record};
    use skep_signature::{HybridSigner, TAG_FNDSA512_PREVIEW_ED25519, TAG_MLDSA65_ED25519};

    use super::*;
    use crate::parse_address;

    fn trial_parts() -> (BoardTerm, Address, Address, Address, Address) {
        let board = BoardTerm { log_position: 12, chain: [7; 32] };
        let home = parse_address("1.0.1.0.1").unwrap();
        let account = parse_address("1.0.1").unwrap();
        let ty = skep_registry::t_binding().clone();
        let to = parse_address("1.0.2").unwrap();
        (board, home, account, ty, to)
    }

    /// A body signed over the record frame by a key of the set is SIGNED
    /// under that key's fingerprint; the same body is UNSIGNED under a set
    /// without the key, under a different board term, under another target,
    /// under a lineage row the trial hands where the frame bore none, with a
    /// byte of its `sig` flipped, with a `sig` of no row's width, and with no
    /// `sig` at all. A body signed on a forked lineage is SIGNED under the
    /// trial that hands that fork point alone: the frame is composed with the
    /// lineage the trial hands.
    #[test]
    fn a_record_is_signed_under_its_own_key_alone() {
        let (board, home, account, ty, to) = trial_parts();
        let signer = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[3; 32]).expect("tag 1");
        let other = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[4; 32]).expect("tag 1");
        let body = Body::Binding(Binding { prefix: "1.5".into(), replaces: None });
        let sigless = encode(&body, None);
        let frame = |board: BoardTerm, to: &[Address], lineage: Option<&Address>| {
            entry_frame(
                signer.public_key().alg(),
                board,
                &account,
                DocTerm::One(&home),
                &entry_body_record(RecordRows {
                    ty: &ty,
                    to,
                    replaces: None,
                    lineage_fork_point: lineage,
                    sigless_canonical_record: sigless.as_bytes(),
                }),
            )
        };
        let hex = |bytes: Vec<u8>| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
        let to_slot = [to.clone()];
        let sig = hex(signer.sign(&frame(board, &to_slot, None)));
        let text = encode(&body, Some(&sig));
        let record = parse(BodyKind::Binding, text.as_bytes()).expect("canonical");
        let keys = [Enrolled { key: signer.public_key().clone(), anchor: false }];
        let foreign = [Enrolled { key: other.public_key().clone(), anchor: false }];
        let parts = (home.clone(), account.clone(), ty.clone());
        let judged = |record: &Record, keys: &[Enrolled], board: BoardTerm, to: &[Address], lineage: Option<&Address>| -> Verdict {
            judge(record, &Trial { board, home: &parts.0, home_account: &parts.1, ty: &parts.2, to, lineage, keys })
        };
        let verdict = |record: &Record, keys: &[Enrolled], board: BoardTerm, to: &[Address]| judged(record, keys, board, to, None);
        let fork = parse_address("1.0.1.0.1.0.2.9").unwrap();
        assert_eq!(judged(&record, &keys, board, &to_slot, Some(&fork)), Verdict::Unsigned, "a lineage row the frame bore none of");
        let forked_sig = hex(signer.sign(&frame(board, &to_slot, Some(&fork))));
        let forked = parse(BodyKind::Binding, encode(&body, Some(&forked_sig)).as_bytes()).expect("canonical");
        assert_eq!(judged(&forked, &keys, board, &to_slot, Some(&fork)), Verdict::Signed(Fingerprint::of(signer.public_key())));
        assert_eq!(verdict(&forked, &keys, board, &to_slot), Verdict::Unsigned, "a forked record under the empty row");
        assert_eq!(verdict(&record, &keys, board, &to_slot), Verdict::Signed(Fingerprint::of(signer.public_key())));
        assert_eq!(verdict(&record, &foreign, board, &to_slot), Verdict::Unsigned, "a key outside the set");
        assert_eq!(verdict(&record, &[], board, &to_slot), Verdict::Unsigned, "an empty set");
        let moved = BoardTerm { log_position: 13, chain: [7; 32] };
        assert_eq!(verdict(&record, &keys, moved, &to_slot), Verdict::Unsigned, "another board term");
        assert_eq!(verdict(&record, &keys, board, &[]), Verdict::Unsigned, "another target");
        let mut flipped = sig.clone().into_bytes();
        flipped[10] = if flipped[10] == b'0' { b'1' } else { b'0' };
        let flipped = parse(BodyKind::Binding, encode(&body, Some(std::str::from_utf8(&flipped).unwrap())).as_bytes()).unwrap();
        assert_eq!(verdict(&flipped, &keys, board, &to_slot), Verdict::Unsigned, "a flipped byte");
        let short = parse(BodyKind::Binding, encode(&body, Some("abcd")).as_bytes()).unwrap();
        assert_eq!(verdict(&short, &keys, board, &to_slot), Verdict::Unsigned, "no row's width");
        let unsigned = parse(BodyKind::Binding, sigless.as_bytes()).unwrap();
        assert_eq!(verdict(&unsigned, &keys, board, &to_slot), Verdict::Unsigned, "no sig at all");
    }

    /// THE TRIAL runs over the whole set, in its order (steps 4 and 5): a
    /// key that does not verify is passed over for the next, and so is a key
    /// of another row's width — never the trial's end — and the hand named is
    /// the fingerprint of the key that verified, never the set's first; a
    /// record signed under the other row is SIGNED by its own key alike.
    #[test]
    fn the_first_candidate_that_verifies_names_the_hand() {
        let (board, home, account, ty, to) = trial_parts();
        let one = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[3; 32]).expect("tag 1");
        let foreign = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[4; 32]).expect("tag 1");
        let three = HybridSigner::from_seed(TAG_FNDSA512_PREVIEW_ED25519, &[5; 32]).expect("tag 3");
        let body = Body::Binding(Binding { prefix: "1.5".into(), replaces: None });
        let sigless = encode(&body, None);
        let to_slot = [to];
        let signed_by = |signer: &HybridSigner| -> Record {
            let rows = RecordRows {
                ty: &ty,
                to: &to_slot,
                replaces: None,
                lineage_fork_point: None,
                sigless_canonical_record: sigless.as_bytes(),
            };
            let frame = entry_frame(signer.public_key().alg(), board, &account, DocTerm::One(&home), &entry_body_record(rows));
            let sig: String = signer.sign(&frame).iter().map(|b| format!("{b:02x}")).collect();
            parse(BodyKind::Binding, encode(&body, Some(&sig)).as_bytes()).expect("canonical")
        };
        let set = |signers: &[&HybridSigner]| -> Vec<Enrolled> {
            signers.iter().map(|s| Enrolled { key: s.public_key().clone(), anchor: false }).collect()
        };
        let verdict = |record: &Record, keys: &[Enrolled]| {
            judge(record, &Trial { board, home: &home, home_account: &account, ty: &ty, to: &to_slot, lineage: None, keys })
        };
        let hand = |signer: &HybridSigner| Verdict::Signed(Fingerprint::of(signer.public_key()));
        let (by_one, by_three) = (signed_by(&one), signed_by(&three));
        assert_eq!(verdict(&by_one, &set(&[&foreign, &one])), hand(&one), "a key that does not verify is passed over");
        assert_eq!(verdict(&by_one, &set(&[&three, &foreign, &one])), hand(&one), "a key of another row's width is passed over");
        assert_eq!(verdict(&by_three, &set(&[&one, &foreign, &three])), hand(&three), "a record signed under the other row");
    }

    #[test]
    fn the_blob_is_a_rows_width_of_hex_alone() {
        assert_eq!(hybrid_blob(&"ab".repeat(3373)).map(|b| b.len()), Some(3373));
        assert_eq!(hybrid_blob(&"AB".repeat(730)).map(|b| b.len()), Some(730));
        assert_eq!(hybrid_blob(&"ab".repeat(64)), None, "a classical width is no row's");
        assert_eq!(hybrid_blob(&"zz".repeat(3373)), None, "not hex");
        assert_eq!(hybrid_blob(""), None);
    }
}
