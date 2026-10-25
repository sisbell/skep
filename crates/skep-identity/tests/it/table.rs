//! THE SIGNATURE-FILTERED KEY TABLE's rules (AUTH-2.94; the design record
//! §4.5's table paragraph, clauses (a)–(d); REG-3.39, REG-5.9), one test each
//! for the gaps a shared table closes — G1 the one host-trusted genesis, G2
//! the grade read off this table and never the fold's, G3 the candidates the
//! home's account opens and never the subject's, G4 journal order across
//! accounts, G5 the home pin before the trial, G10 the width filter before
//! it — beside the genuine rotation, the one host-trusted record and the
//! missing input.
//!
//! Under a STUB SIGNATURE CHECK: this crate links no signature library
//! (AUTH-2.1), the table hands the check in, so this suite hands in one of
//! its own — a blob of the key's row's width spelling the signing key's
//! fingerprint and the message's digest — and what it pins is the table's
//! rules and never a signature scheme's. The real check runs over the same
//! table in the signing client's and the resolver's suites.

use sha2::{Digest, Sha256};
use skep_address::{validate, Address, Nat, Tumbler};
use skep_identity::{
    canonical_record, BoardTerm, CredentialRecord, Enrollment, FilteredTable, Fingerprint, Outcome,
    PublicKey, RecordFrame, RecordKind, RecordRows, RefusedCause,
};

use crate::common::{addr, doc1, doc2, enrollment, fp, key, key_of, KeyKind, ACCT_A, CLAIMANT, NESTED, ORG, T_ENROLL, T_RETIRE};

/// The board term every record below is framed under.
const TERM: BoardTerm = BoardTerm { log_position: 2, chain: [7; 32] };

/// The position of the board's claim: the claimant's genesis at 1 lies at or
/// below it, every other record above.
const CLAIM_AT: u64 = 2;

/// The stub signature of `key` over `message`, in hex: a blob of the key's
/// row's width — so `HybridBlob::parse_hex` admits it — whose first
/// thirty-two bytes are the key's fingerprint and the next thirty-two the
/// message's SHA-256, every other byte zero.
fn stub_sign(key: &PublicKey, message: &[u8]) -> String {
    let mut blob = vec![0u8; key.sig_alg_row().sig_len()];
    blob[..32].copy_from_slice(Fingerprint::of(key).as_bytes());
    blob[32..64].copy_from_slice(&Sha256::digest(message));
    blob.iter().map(|b| format!("{b:02x}")).collect()
}

/// The stub check, `skep_signature::verify`'s shape: the tag the key's row's,
/// the blob the row's width, spelling this key and this message.
fn stub_verify(tag: u8, key: &PublicKey, message: &[u8], blob: &[u8]) -> bool {
    let row = key.sig_alg_row();
    tag == row.tag
        && blob.len() == row.sig_len()
        && blob[..32] == Fingerprint::of(key).as_bytes()[..]
        && blob[32..64] == Sha256::digest(message)[..]
}

/// The link `home·0·2·n`.
fn link_of(home: &Address, n: u64) -> Address {
    let mut comps: Vec<Nat> = home.tumbler().iter().cloned().collect();
    comps.extend([Nat::from(0u32), Nat::from(2u32), Nat::from(n)]);
    validate(Tumbler::new(comps).expect("nonempty")).expect("a link address")
}

/// One credential record as a test spells it, owned, lent to the table as a
/// [`CredentialRecord`] through [`Rec::view`].
struct Rec {
    kind: RecordKind,
    link: Address,
    home: Address,
    home_account: Address,
    subject: Address,
    ty: Address,
    entries: Vec<Enrollment>,
    fps: Vec<Fingerprint>,
    sigless: String,
    sig: Option<String>,
    position: Option<u64>,
}

impl Rec {
    /// An enrollment at position `n` of `entries` into `subject`, homed in
    /// `home_account`'s doc 1, unsigned.
    fn enroll(n: u64, home_account: &[u32], subject: &[u32], entries: &[(u8, bool)]) -> Rec {
        let entries: Vec<Enrollment> = entries.iter().map(|&(i, anchor)| enrollment(i, anchor)).collect();
        let sigless = canonical_record(&entries, None);
        let home = doc1(home_account);
        Rec {
            kind: RecordKind::Enroll,
            link: link_of(&home, n),
            home,
            home_account: addr(home_account),
            subject: addr(subject),
            ty: addr(T_ENROLL),
            entries,
            fps: Vec::new(),
            sigless,
            sig: None,
            position: Some(n),
        }
    }

    /// A retirement at position `n` of the keys `indices` name from `subject`,
    /// homed in `home_account`'s doc 1, unsigned.
    fn retire(n: u64, home_account: &[u32], subject: &[u32], indices: &[u8]) -> Rec {
        let fps: Vec<Fingerprint> = indices.iter().map(|&i| fp(i)).collect();
        let sigless = canonical_record(&fps, None);
        let home = doc1(home_account);
        Rec {
            kind: RecordKind::Retire,
            link: link_of(&home, n),
            home,
            home_account: addr(home_account),
            subject: addr(subject),
            ty: addr(T_RETIRE),
            entries: Vec::new(),
            fps,
            sigless,
            sig: None,
            position: Some(n),
        }
    }

    /// The same record deposited in `home` instead — the home pin's object.
    fn homed(mut self, home: Address) -> Rec {
        self.link = link_of(&home, self.position.unwrap_or(0));
        self.home = home;
        self
    }

    /// The record's frame under `key`'s token (the design record §4.2 (C)).
    fn frame(&self, key: &PublicKey) -> Vec<u8> {
        let to = [self.subject.clone()];
        RecordFrame {
            board: TERM,
            home_account: &self.home_account,
            home: &self.home,
            rows: RecordRows {
                ty: &self.ty,
                to: &to,
                replaces: None,
                lineage_fork_point: None,
                sigless_canonical_record: self.sigless.as_bytes(),
            },
        }
        .to_bytes(key.alg())
    }

    /// The record signed by `key` over its own frame.
    fn signed_with(mut self, key: &PublicKey) -> Rec {
        self.sig = Some(stub_sign(key, &self.frame(key)));
        self
    }

    /// The record signed by test key `i`.
    fn signed_by(self, i: u8) -> Rec {
        let key = key(i);
        self.signed_with(&key)
    }

    fn view(&self) -> CredentialRecord<'_> {
        CredentialRecord {
            kind: self.kind,
            link: &self.link,
            home: &self.home,
            home_account: &self.home_account,
            subject: &self.subject,
            ty: &self.ty,
            sigless: self.sigless.as_bytes(),
            sig: self.sig.as_deref(),
            enrolled: &self.entries,
            retired: &self.fps,
            position: self.position,
        }
    }
}

fn admit(table: &mut FilteredTable, rec: &Rec) -> Outcome {
    table.admit(&rec.view(), Some(TERM), stub_verify)
}

fn admitted_by(i: u8) -> Outcome {
    Outcome::Admitted { signer: Some(fp(i)) }
}

fn refused(cause: RefusedCause) -> Outcome {
    Outcome::Refused(cause)
}

/// The fingerprints of the set that opens `account` now, sorted by hex.
fn opening_now(table: &FilteredTable, account: &[u32]) -> Option<Vec<Fingerprint>> {
    table.opening_now(&addr(account)).map(|set| sorted(set.iter().map(|e| Fingerprint::of(&e.key))))
}

fn opening_at(table: &FilteredTable, account: &[u32], position: u64) -> Option<Vec<Fingerprint>> {
    table.opening_at(&addr(account), position).map(|set| sorted(set.iter().map(|e| Fingerprint::of(&e.key))))
}

fn sorted(fps: impl Iterator<Item = Fingerprint>) -> Vec<Fingerprint> {
    let mut v: Vec<Fingerprint> = fps.collect();
    v.sort_by_key(Fingerprint::to_hex);
    v
}

fn fps(indices: &[u8]) -> Vec<Fingerprint> {
    sorted(indices.iter().map(|&i| fp(i)))
}

/// A table under the claim at [`CLAIM_AT`] holding the claimant's genesis —
/// key 1 an anchor, key 2 a device key — host-trusted at position 1.
fn claimed_board() -> FilteredTable {
    let mut table = FilteredTable::new(Some((CLAIM_AT, addr(CLAIMANT))));
    let genesis = Rec::enroll(1, CLAIMANT, CLAIMANT, &[(1, true), (2, false)]);
    assert_eq!(admit(&mut table, &genesis), Outcome::Admitted { signer: None }, "the claimant's genesis, host-trusted");
    table
}

/// [`claimed_board`] with `ORG` hired at position 3 — its genesis, key 11,
/// homed in the claimant's doc 1 and signed by the claimant's device key: a
/// top-level account's genesis enters no cone, so it is device-grade.
fn board_with_org() -> FilteredTable {
    let mut table = claimed_board();
    let hire = Rec::enroll(3, CLAIMANT, ORG, &[(11, false)]).signed_by(2);
    assert_eq!(admit(&mut table, &hire), admitted_by(2), "the org's genesis under the claimant's set");
    table
}

/// THE ONE HOST-TRUSTED RECORD (AUTH-4.55 (3), AUTH-4.58; G1's premise): the
/// claimant's own genesis at or below the claim enters unsigned; every other
/// record is judged — another account's unsigned genesis below the claim, the
/// claimant's own unsigned enrollment above it, and the claimant's genesis
/// under a table built with no claim — and none of those enters.
#[test]
fn only_the_claimants_own_genesis_at_or_below_the_claim_is_host_trusted() {
    let mut table = claimed_board();
    assert_eq!(opening_now(&table, CLAIMANT), Some(fps(&[1, 2])));
    let stranger = Rec::enroll(1, ACCT_A, ACCT_A, &[(5, true)]);
    assert_eq!(admit(&mut table, &stranger), refused(RefusedCause::NoSig), "another account's genesis below the claim");
    let later = Rec::enroll(3, CLAIMANT, CLAIMANT, &[(3, false)]);
    assert_eq!(admit(&mut table, &later), refused(RefusedCause::NoSig), "the claimant's own unsigned enrollment above the claim");
    assert_eq!(opening_now(&table, CLAIMANT), Some(fps(&[1, 2])), "the table unchanged");
    let mut unclaimed = FilteredTable::new(None);
    let genesis = Rec::enroll(1, CLAIMANT, CLAIMANT, &[(1, true), (2, false)]);
    assert_eq!(admit(&mut unclaimed, &genesis), refused(RefusedCause::NoSig), "no claim held: nothing is host-trusted");
    assert_eq!(opening_now(&unclaimed, CLAIMANT), Some(Vec::new()));
    let refusals: Vec<(Option<u64>, RefusedCause)> = table.refused().iter().map(|r| (r.position, r.cause)).collect();
    assert_eq!(refusals, [(Some(1), RefusedCause::NoSig), (Some(3), RefusedCause::NoSig)]);
    assert_eq!(table.refused()[0].subject, addr(ACCT_A));
}

/// G1 — A SUB-ACCOUNT's GENESIS IS JUDGED UNDER ITS DELEGATOR's TABLE (the
/// design record §4.2 (C), §4.5's clause (a); REG-2.33): a genesis of `NESTED`
/// homed in `ORG`'s doc 1 with no `sig`, or self-signed by the key it enrolls
/// — a key no table holds — is inert, and the account stays unkeyed; the same
/// genesis signed by the delegator's key enters.
#[test]
fn a_sub_account_genesis_with_no_valid_delegator_sig_is_inert() {
    let mut table = board_with_org();
    let unsigned = Rec::enroll(4, ORG, NESTED, &[(21, true)]);
    assert_eq!(admit(&mut table, &unsigned), refused(RefusedCause::NoSig));
    let self_signed = Rec::enroll(5, ORG, NESTED, &[(21, true)]).signed_by(21);
    assert_eq!(admit(&mut table, &self_signed), refused(RefusedCause::Unsigned), "a key no table holds");
    assert_eq!(opening_now(&table, NESTED), Some(fps(&[11])), "unkeyed: the walk opens it through the org");
    let by_delegator = Rec::enroll(6, ORG, NESTED, &[(21, true)]).signed_by(11);
    assert_eq!(admit(&mut table, &by_delegator), admitted_by(11));
    assert_eq!(opening_now(&table, NESTED), Some(fps(&[21])));
}

/// G2 — THE GRADE IS READ OFF THIS TABLE, NEVER THE FOLD's (AUTH-3.20–3.22;
/// the design record §4.5's clause (a)): an operator's unsigned retirement of
/// the claimant's anchor is inert here while the fold honors it; a
/// device-signed retirement of that anchor after it is anchor-grade off this
/// table — the anchor still stands — and admits the device key's `sig` no
/// more than the fold's device-grade reading would have refused it; the
/// anchor's own retirement of itself, with a key left, enters.
#[test]
fn a_device_signed_retirement_of_an_anchor_the_fold_retired_is_anchor_grade_and_inert() {
    let mut table = claimed_board();
    let planted = Rec::retire(5, CLAIMANT, CLAIMANT, &[1]);
    assert_eq!(admit(&mut table, &planted), refused(RefusedCause::NoSig), "the operator's unsigned retirement");
    let by_device = Rec::retire(6, CLAIMANT, CLAIMANT, &[1]).signed_by(2);
    assert_eq!(admit(&mut table, &by_device), refused(RefusedCause::Unsigned), "anchor-grade: the device key is no candidate");
    assert_eq!(opening_now(&table, CLAIMANT), Some(fps(&[1, 2])), "the anchor stands");
    let by_device_of_device = Rec::retire(7, CLAIMANT, CLAIMANT, &[2]).signed_by(2);
    assert_eq!(admit(&mut table, &by_device_of_device), admitted_by(2), "a device key retires a device key");
    assert_eq!(opening_now(&table, CLAIMANT), Some(fps(&[1])));
    let would_empty = Rec::retire(8, CLAIMANT, CLAIMANT, &[1]).signed_by(1);
    assert_eq!(admit(&mut table, &would_empty), refused(RefusedCause::WouldEmpty), "I3: a set never re-empties");
    let third = Rec::enroll(9, CLAIMANT, CLAIMANT, &[(3, true)]).signed_by(1);
    assert_eq!(admit(&mut table, &third), admitted_by(1), "an anchor enrolls an anchor");
    let by_anchor = Rec::retire(10, CLAIMANT, CLAIMANT, &[1]).signed_by(1);
    assert_eq!(admit(&mut table, &by_anchor), admitted_by(1), "the anchor retires itself, a key left");
    assert_eq!(opening_now(&table, CLAIMANT), Some(fps(&[3])));
}

/// G3 — THE CANDIDATES ARE THE SET THAT OPENS THE HOME's ACCOUNT, NEVER THE
/// SUBJECT's (AUTH-4.30 (i); the design record §4.5's clause (a)): a genesis
/// homed in the delegator's doc 1 verifies under the delegator's key, not
/// under the key it enrolls; and a genesis homed in an unkeyed account's doc 1
/// — a hire's, beneath the agent space — verifies under the nearest keyed
/// account above, the walk's answer, at device grade.
#[test]
fn a_genesis_homed_in_the_delegators_doc_one_verifies_under_the_delegators_set_not_the_subjects() {
    let mut table = board_with_org();
    let by_subject = Rec::enroll(4, ORG, NESTED, &[(21, true)]).signed_by(21);
    assert_eq!(admit(&mut table, &by_subject), refused(RefusedCause::Unsigned), "the subject's own key opens nothing");
    let by_delegator = Rec::enroll(5, ORG, NESTED, &[(21, true)]).signed_by(11);
    assert_eq!(admit(&mut table, &by_delegator), admitted_by(11));
    // A hire: the org's agent space `ORG·1` holds no key of its own, so a
    // genesis homed in its doc 1 is judged under `ORG`'s set, reached by the
    // walk; the hire's anchor flag asks no anchor of the giver (AUTH-3.21).
    let agent_space: Vec<u32> = ORG.iter().copied().chain([1]).collect();
    let hire: Vec<u32> = agent_space.iter().copied().chain([5]).collect();
    let hired = Rec::enroll(6, &agent_space, &hire, &[(31, true)]).signed_by(11);
    assert_eq!(admit(&mut table, &hired), admitted_by(11), "under the set that opens the agent space");
    assert_eq!(opening_now(&table, &hire), Some(fps(&[31])));
}

/// G4 — JOURNAL ORDER ACROSS ACCOUNTS (the design record §4.5's clause (d)):
/// a delegator's own enrollment before the genesis it signs is honored —
/// `ORG` enrolls key 12 at 5, key 12 signs `NESTED`'s genesis at 6 — and the
/// same two records in the other order are not: the genesis at 4 finds key
/// 12 in no table, and key 12's enrollment at 5 keys nothing after the fact.
#[test]
fn a_delegators_enrol_before_the_genesis_it_signs_is_honored_in_journal_order_across_accounts() {
    let mut table = board_with_org();
    let second = Rec::enroll(5, ORG, ORG, &[(12, false)]).signed_by(11);
    assert_eq!(admit(&mut table, &second), admitted_by(11));
    let genesis = Rec::enroll(6, ORG, NESTED, &[(21, true)]).signed_by(12);
    assert_eq!(admit(&mut table, &genesis), admitted_by(12), "the enrollment before the genesis it signs");
    assert_eq!(opening_now(&table, NESTED), Some(fps(&[21])));
    let mut reversed = board_with_org();
    let early = Rec::enroll(4, ORG, NESTED, &[(21, true)]).signed_by(12);
    assert_eq!(admit(&mut reversed, &early), refused(RefusedCause::Unsigned), "key 12 is in no table yet");
    assert_eq!(admit(&mut reversed, &second), admitted_by(11));
    assert_eq!(opening_now(&reversed, NESTED), Some(fps(&[11, 12])), "unkeyed still: the org's set opens it");
}

/// G5 — THE HOME PIN BEFORE THE TRIAL (AUTH-2.127, AUTH-2.62; the design
/// record §4.5's clause (c)): a record whose `sig` verifies over the frame
/// naming its home is inert where that home is not the one the fold honors
/// — an enrollment of a keyed account into its own doc 2; a genesis into a
/// stranger's doc 1, keyed or not; a holder act into the delegator's doc 1,
/// and a retirement there — each refused by the fold's own token.
#[test]
fn a_credential_record_homed_outside_the_two_doc_ones_is_inert_though_its_sig_verifies() {
    let mut table = board_with_org();
    let stranger = Rec::enroll(4, CLAIMANT, ACCT_A, &[(41, false)]).signed_by(2);
    assert_eq!(admit(&mut table, &stranger), admitted_by(2), "a second org, keyed by the claimant");
    let in_doc_two = Rec::enroll(5, ORG, ORG, &[(12, false)]).homed(doc2(ORG)).signed_by(11);
    assert_eq!(admit(&mut table, &in_doc_two), refused(RefusedCause::NotDocOne), "the org's own doc 2");
    let strangers_doc_one = Rec::enroll(6, ACCT_A, NESTED, &[(21, true)]).signed_by(41);
    assert_eq!(admit(&mut table, &strangers_doc_one), refused(RefusedCause::NotGenesisRegistry), "a keyed stranger's doc 1");
    let orgs_act_in_claimants = Rec::enroll(7, CLAIMANT, ORG, &[(12, false)]).signed_by(2);
    assert_eq!(admit(&mut table, &orgs_act_in_claimants), refused(RefusedCause::NotGenesisRegistry), "the latch: a keyed account's enrollment in the delegator's doc 1");
    let retire_in_claimants = Rec::retire(8, CLAIMANT, ORG, &[11]).signed_by(2);
    assert_eq!(admit(&mut table, &retire_in_claimants), refused(RefusedCause::NotHolderRetirement), "no ancestor retires a holder's keys");
    let retire_unkeyed = Rec::retire(9, NESTED, NESTED, &[21]).signed_by(11);
    assert_eq!(admit(&mut table, &retire_unkeyed), refused(RefusedCause::NoHolder), "a retirement on a never-keyed account");
    assert_eq!(opening_now(&table, ORG), Some(fps(&[11])), "nothing of it entered");
    assert_eq!(opening_now(&table, NESTED), Some(fps(&[11])), "the walk, through the org");
}

/// THE HANDOFF LATCH (AUTH-2.71; the design record §4.5's clause (c)): a
/// genesis of a subdivision naming a key the set that opens the account above
/// it already holds is no handoff and enters no table, though its delegator
/// signs it over the right home — the fold refuses it, so the table does;
/// the same key named at a bootstrap-tier account, a sibling, is legitimate.
#[test]
fn a_genesis_naming_a_key_the_set_above_already_holds_is_no_handoff() {
    let mut table = board_with_org();
    let same_key = Rec::enroll(4, ORG, NESTED, &[(11, true)]).signed_by(11);
    assert_eq!(admit(&mut table, &same_key), refused(RefusedCause::NotGenesisRegistry), "the latch");
    assert_eq!(opening_now(&table, NESTED), Some(fps(&[11])), "unkeyed: the walk opens it through the org");
    let sibling = Rec::enroll(5, CLAIMANT, ACCT_A, &[(2, false)]).signed_by(2);
    assert_eq!(admit(&mut table, &sibling), admitted_by(2), "a bootstrap-tier account under the claimant's own key");
    let fresh_key = Rec::enroll(6, ORG, NESTED, &[(21, true)]).signed_by(11);
    assert_eq!(admit(&mut table, &fresh_key), admitted_by(11));
}

/// A GENUINE ROTATION (REG-3.39's fold forward; the design record §4.5's
/// clause (b)): a second device key enrolled under the first, the first
/// retired under the second — in the set as of its own retirement's position,
/// out of it one past — so a record the retired key signs before the
/// retirement enters and one it signs after does not; and a retired
/// fingerprint never re-enters (I4, AUTH-2.98).
#[test]
fn a_genuine_rotation_moves_the_set_as_of_each_position() {
    let mut table = claimed_board();
    let third = Rec::enroll(5, CLAIMANT, CLAIMANT, &[(3, false)]).signed_by(2);
    assert_eq!(admit(&mut table, &third), admitted_by(2));
    let before = Rec::enroll(6, CLAIMANT, CLAIMANT, &[(4, false)]).signed_by(2);
    assert_eq!(admit(&mut table, &before), admitted_by(2), "signed by the device key before its retirement");
    let retire = Rec::retire(7, CLAIMANT, CLAIMANT, &[2]).signed_by(3);
    assert_eq!(admit(&mut table, &retire), admitted_by(3));
    assert_eq!(opening_at(&table, CLAIMANT, 7), Some(fps(&[1, 2, 3, 4])), "in the set at its own retirement's position");
    assert_eq!(opening_at(&table, CLAIMANT, 8), Some(fps(&[1, 3, 4])));
    assert_eq!(opening_at(&table, CLAIMANT, 6), Some(fps(&[1, 2, 3])), "key 4 not yet in at 6");
    let after = Rec::enroll(9, CLAIMANT, CLAIMANT, &[(5, false)]).signed_by(2);
    assert_eq!(admit(&mut table, &after), refused(RefusedCause::Unsigned), "signed by the retired key");
    let again = Rec::enroll(10, CLAIMANT, CLAIMANT, &[(2, false)]).signed_by(3);
    assert_eq!(admit(&mut table, &again), refused(RefusedCause::NothingChanged), "a retired fingerprint never re-enters");
    assert_eq!(opening_now(&table, CLAIMANT), Some(fps(&[1, 3, 4])));
    let admissions: Vec<(Option<u64>, skep_identity::Until)> = table.admissions(&addr(CLAIMANT)).iter().map(|a| (a.since, a.until)).collect();
    use skep_identity::Until::{Enrolled, RetiredAt};
    assert_eq!(admissions, [(Some(1), Enrolled), (Some(1), RetiredAt(7)), (Some(5), Enrolled), (Some(6), Enrolled)]);
}

/// A MISSING INPUT IS A VERDICT (the design record §7.2's REFUSE
/// disposition): a record of an account a reader could not fetch makes that
/// account's table undeterminable from its position — the set that opens it
/// `None`, never the table as it stood — and every account that opens
/// through it; a record judged under such a set is refused undeterminable
/// and marks its own subject the same; the accounts beside them are
/// untouched.
#[test]
fn a_record_a_reader_could_not_fetch_makes_the_accounts_table_undeterminable_from_its_position() {
    let mut table = board_with_org();
    table.missing(&addr(ORG), 5);
    assert_eq!(opening_at(&table, ORG, 5), Some(fps(&[11])), "determinable as of the missing record's own position");
    assert_eq!(opening_at(&table, ORG, 6), None);
    assert_eq!(opening_now(&table, ORG), None);
    let genesis = Rec::enroll(7, ORG, NESTED, &[(21, true)]).signed_by(11);
    assert_eq!(admit(&mut table, &genesis), refused(RefusedCause::Undeterminable));
    assert_eq!(opening_at(&table, NESTED, 8), None, "its subject's table undeterminable too");
    assert_eq!(opening_at(&table, NESTED, 5), Some(fps(&[11])), "and determinable before the org's gap, through the org");
    assert_eq!(opening_now(&table, CLAIMANT), Some(fps(&[1, 2])), "the claimant's table untouched");
    assert_eq!(table.refused().last().map(|r| r.cause), Some(RefusedCause::Undeterminable));
}

/// G10 — THE WIDTH FILTER BEFORE THE TRIAL, AND THE GRADE's (the design record
/// §4.5 (4), step 5): of the set that opens the home's account, the check is
/// asked of the keys whose row's width is the blob's, and of the anchors
/// alone at an anchor-grade act — never of the rest; a device key's `sig` on
/// an anchor-flagged enrollment is tried against no key at all.
#[test]
fn a_candidate_of_another_rows_width_or_grade_is_passed_over_untried() {
    let mut table = FilteredTable::new(Some((CLAIM_AT, addr(CLAIMANT))));
    // The other row's key first, so the trial meets it before any key of
    // the blob's width.
    let other_row = key_of(KeyKind::FnDsa512PreviewEd25519, 9);
    let entries = [Enrollment::new(other_row, false, None).expect("label-free"), enrollment(1, true), enrollment(2, false)];
    let sigless = canonical_record(&entries, None);
    let genesis = Rec { entries: entries.to_vec(), sigless, ..Rec::enroll(1, CLAIMANT, CLAIMANT, &[(1, true)]) };
    assert_eq!(table.admit(&genesis.view(), Some(TERM), stub_verify), Outcome::Admitted { signer: None });
    assert_eq!(table.current(&addr(CLAIMANT)).count(), 3);
    let tried: std::cell::RefCell<Vec<Fingerprint>> = std::cell::RefCell::new(Vec::new());
    let counting = |tag: u8, key: &PublicKey, message: &[u8], blob: &[u8]| {
        tried.borrow_mut().push(Fingerprint::of(key));
        stub_verify(tag, key, message, blob)
    };
    let by_device = Rec::enroll(3, CLAIMANT, CLAIMANT, &[(3, false)]).signed_by(2);
    assert_eq!(table.admit(&by_device.view(), Some(TERM), counting), admitted_by(2));
    assert_eq!(*tried.borrow(), [fp(1), fp(2)], "the other row's key, first in the set, is never tried");
    tried.borrow_mut().clear();
    let anchor_flagged = Rec::enroll(4, CLAIMANT, CLAIMANT, &[(4, true)]).signed_by(2);
    assert_eq!(table.admit(&anchor_flagged.view(), Some(TERM), counting), refused(RefusedCause::Unsigned));
    assert_eq!(*tried.borrow(), [fp(1)], "anchor-grade: the anchor alone is tried");
}
