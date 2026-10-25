use super::*;
use crate::derive::records::{Hand, Kind, Record};
use crate::sign::RecordFrame;
use skep_identity::{canonical_record, entry_body_make_link, entry_frame, unit_span, DocTerm, Enrollment, EntrySlot, LinkSlots, RefusedCause, Until};
use skep_signature::HybridSigner;

fn signer(b: u8) -> HybridSigner {
    crate::sign::signer_from_seed(&[b; 32])
}

fn enroll(signer: &HybridSigner, anchor: bool, label: &str) -> Enrollment {
    Enrollment::new(HybridSigner::public_key(signer).clone(), anchor, Some(label.into())).unwrap()
}

fn board() -> BoardTerm {
    BoardTerm { log_position: 12, chain: [7u8; 32] }
}

/// The account every record below acts on, the board's claimant.
const ACCOUNT: &str = "1.0.1";

fn account() -> Address {
    parse_address(ACCOUNT).unwrap()
}

fn record(kind: Kind, link: &str, entries: &[Enrollment], retired: &[Fingerprint], sig: Option<String>, position: Option<u64>) -> Record {
    let sigless = match kind {
        Kind::Enroll => canonical_record(entries, None),
        Kind::Retire => canonical_record(retired, None),
    };
    Record {
        kind,
        link: link.into(),
        home: "1.0.1.0.1".into(),
        home_account: ACCOUNT.into(),
        subject: ACCOUNT.into(),
        atom: "1.0.1.0.1.0.1.1".into(),
        bytes: sigless.clone().into_bytes(),
        sigless,
        sig,
        enrolled: entries.to_vec(),
        retired: retired.to_vec(),
        position,
        base: position.map(|p| p - 1),
        hand: Hand::Bare,
        anchor_grade: entries.iter().any(|e| e.anchor),
    }
}

fn sign_record(signer: &HybridSigner, ty: &str, sigless: &str) -> String {
    let frame = RecordFrame {
        alg: HybridSigner::public_key(signer).alg(),
        board: board(),
        home_account: ACCOUNT,
        home: "1.0.1.0.1",
        ty,
        to: &[ACCOUNT],
        sigless: sigless.as_bytes(),
    }
    .compose()
    .unwrap();
    crate::hex::encode(&HybridSigner::sign(signer, &frame))
}

/// The table over `records`, built under the claim the read derived and the
/// account as the board's claimant.
fn table_of(records: &Records) -> FilteredTable {
    filtered_table(records, Some(ACCOUNT), Some(board()))
}

/// The fingerprints the table holds enrolled now for the account.
fn current(table: &FilteredTable) -> Vec<Fingerprint> {
    table.current(&account()).map(|a| a.fingerprint).collect()
}

/// The records the table refused, as `(link, cause)`.
fn refused(table: &FilteredTable) -> Vec<(String, RefusedCause)> {
    table.refused().iter().map(|r| (r.link.to_string(), r.cause)).collect()
}

/// D14 — THE FILTER, NEVER THE FOLD: a key PLANTED into doc 1 by a record
/// whose `sig` no key of the set verifies is inert here, and an entry it
/// signs reads UNSIGNED, never SIGNED — where the fold (and the served
/// `key_set`) would honour the enrollment whatever its `sig` holds.
/// MUTATION 4's neighbour: a verifier that took the served set would
/// answer `Signed` here.
#[test]
fn a_planted_key_with_no_valid_sig_reads_unsigned() {
    let device = signer(1);
    let anchor = signer(2);
    let plant = signer(3);
    let genesis = record(
        Kind::Enroll,
        "1.0.1.0.1.0.2.1",
        &[enroll(&anchor, true, "paper-a"), enroll(&device, false, "notebook")],
        &[],
        None,
        Some(9),
    );
    // The plant: self-signed by the planted key, which stands in no set.
    let plant_entries = [enroll(&plant, false, "plant")];
    let plant_sigless = canonical_record(&plant_entries, None);
    let plant_sig = sign_record(&plant, crate::board::T_ENROLL, &plant_sigless);
    let planted = record(Kind::Enroll, "1.0.1.0.1.0.2.3", &plant_entries, &[], Some(plant_sig), Some(20));
    // A legitimate second device, signed by the enrolled device key.
    let second = signer(4);
    let second_entries = [enroll(&second, false, "phone")];
    let second_sigless = canonical_record(&second_entries, None);
    let second_sig = sign_record(&device, crate::board::T_ENROLL, &second_sigless);
    let enrolled_second = record(Kind::Enroll, "1.0.1.0.1.0.2.4", &second_entries, &[], Some(second_sig), Some(24));
    let records = Records {
        account: ACCOUNT.into(),
        records: vec![genesis, planted, enrolled_second],
        head: 30,
        floor: None,
        claim_entry: Some(12),
        claimed: true,
    };
    let table = table_of(&records);
    let current = current(&table);
    assert!(current.contains(&Fingerprint::of(HybridSigner::public_key(&device))));
    assert!(current.contains(&Fingerprint::of(HybridSigner::public_key(&second))), "the signed second device is admitted");
    assert!(!current.contains(&Fingerprint::of(HybridSigner::public_key(&plant))), "the plant is inert to the table");
    assert_eq!(refused(&table), [("1.0.1.0.1.0.2.3".to_string(), RefusedCause::Unsigned)]);
    // Admitted AT 24: the entry at 24 is that admission, judged at its base.
    assert!(!table.as_of(&account(), 24).any(|a| a.fingerprint == Fingerprint::of(HybridSigner::public_key(&second))));

    // An entry at 28, signed by the plant: UNSIGNED here.
    let home = parse_address("1.0.1.0.1").unwrap();
    let ty = [unit_span(&parse_address("1.1.0.1.0.1.0.3.90").unwrap())];
    let from = [unit_span(&parse_address("1.0.1.0.2").unwrap())];
    let to: [skep_address::Span; 0] = [];
    let body = entry_body_make_link(LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) });
    let frame = entry_frame(HybridSigner::public_key(&plant).alg(), board(), &account(), DocTerm::One(&home), &body);
    let plant_blob = HybridSigner::sign(&plant, &frame);
    let bounds = Bounds { boundary: Some(12), floor: None };
    let entry = Entry { position: 28, frame: &frame, attest: Some(("mldsa65-ed25519", &plant_blob)) };
    assert_eq!(verdict(&entry, &table, &account(), bounds), Verdict::Unsigned);
    // The same entry signed by the device key: SIGNED, by that key.
    let device_blob = HybridSigner::sign(&device, &frame);
    let entry = Entry { position: 28, frame: &frame, attest: Some(("mldsa65-ed25519", &device_blob)) };
    assert_eq!(verdict(&entry, &table, &account(), bounds), Verdict::Signed(Fingerprint::of(HybridSigner::public_key(&device))));
    // Below the floor: UNDETERMINABLE, never judged.
    assert!(matches!(verdict(&entry, &table, &account(), Bounds { boundary: Some(12), floor: Some(29) }), Verdict::Undeterminable(_)));
    // Before the boundary, and with no boundary.
    let entry = Entry { position: 9, frame: &frame, attest: None };
    assert_eq!(verdict(&entry, &table, &account(), bounds), Verdict::BeforeAttestation);
    assert!(matches!(verdict(&entry, &table, &account(), Bounds::default()), Verdict::Undeterminable(_)));
    assert_eq!(Bounds::from(&records), bounds, "the admitted read's claim entry and floor");
    // A retired key is out of the set at the base of a later entry, in it
    // at the base of an earlier one (P12).
    let retire_entries = [Fingerprint::of(HybridSigner::public_key(&second))];
    let retire_sigless = canonical_record(&retire_entries, None);
    let retire_sig = sign_record(&device, crate::board::T_RETIRE, &retire_sigless);
    let retirement = record(Kind::Retire, "1.0.1.0.1.0.2.5", &[], &retire_entries, Some(retire_sig), Some(26));
    let mut with_retire = records.clone();
    with_retire.records.push(retirement);
    let table = table_of(&with_retire);
    assert!(table.as_of(&account(), 25).any(|a| a.fingerprint == retire_entries[0]));
    // Retired AT 26: the entry at 26 is that retirement, its base the set
    // the key still stood in.
    assert!(table.as_of(&account(), 26).any(|a| a.fingerprint == retire_entries[0]));
    assert!(!table.as_of(&account(), 27).any(|a| a.fingerprint == retire_entries[0]));
    let retired = table.admissions(&account()).iter().find(|a| a.fingerprint == retire_entries[0]).expect("admitted at 24");
    assert_eq!(retired.until, Until::RetiredAt(26));
}

/// THE CLAIMANT IS AN INPUT (AUTH-4.55 (3); G1): the same genesis at or
/// below the claim is host-trusted only where the account is the board's
/// claimant — under another claimant, or none named, the sig-less genesis
/// enters no table and the device key's entry reads UNSIGNED, never
/// manufactured from a stranger's first record.
#[test]
fn only_the_claimants_genesis_is_host_trusted() {
    let (device, anchor) = (signer(1), signer(2));
    let genesis = record(Kind::Enroll, "1.0.1.0.1.0.2.1", &[enroll(&anchor, true, "paper-a"), enroll(&device, false, "notebook")], &[], None, Some(9));
    let records = records(vec![genesis]);
    assert_eq!(current(&table_of(&records)).len(), 2, "the claimant's own genesis");
    let other_claimant = filtered_table(&records, Some("1.0.2"), Some(board()));
    assert!(current(&other_claimant).is_empty(), "another claimant's board: a stranger's unsigned genesis");
    assert_eq!(refused(&other_claimant), [("1.0.1.0.1.0.2.1".to_string(), RefusedCause::NoSig)]);
    let no_claimant = filtered_table(&records, None, Some(board()));
    assert!(current(&no_claimant).is_empty(), "no claimant named: nothing host-trusted");
    let frame = link_frame();
    let blob = HybridSigner::sign(&device, &frame);
    let entry = Entry { position: 30, frame: &frame, attest: Some(("mldsa65-ed25519", &blob)) };
    assert_eq!(verdict(&entry, &other_claimant, &account(), Bounds { boundary: Some(12), floor: None }), Verdict::Unsigned);
}

/// A make-link entry's frame in the account's doc 1 — the bytes an
/// `attest` on it signs.
fn link_frame() -> Vec<u8> {
    let home = parse_address("1.0.1.0.1").unwrap();
    let ty = [unit_span(&parse_address("1.1.0.1.0.1.0.3.90").unwrap())];
    let from = [unit_span(&parse_address("1.0.1.0.2").unwrap())];
    let to: [skep_address::Span; 0] = [];
    let body = entry_body_make_link(LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) });
    entry_frame("mldsa65-ed25519", board(), &account(), DocTerm::One(&home), &body)
}

fn fp(signer: &HybridSigner) -> Fingerprint {
    Fingerprint::of(HybridSigner::public_key(signer))
}

/// An enrollment of `entries` at `link`, signed by `hand`.
fn signed_enrollment(hand: &HybridSigner, link: &str, entries: &[Enrollment], position: Option<u64>) -> Record {
    let sig = sign_record(hand, crate::board::T_ENROLL, &canonical_record(entries, None));
    record(Kind::Enroll, link, entries, &[], Some(sig), position)
}

/// A retirement of `fps` at `link`, signed by `hand`.
fn signed_retirement(hand: &HybridSigner, link: &str, fps: &[Fingerprint], position: Option<u64>) -> Record {
    let sig = sign_record(hand, crate::board::T_RETIRE, &canonical_record(fps, None));
    record(Kind::Retire, link, &[], fps, Some(sig), position)
}

fn records(records: Vec<Record>) -> Records {
    Records { account: ACCOUNT.into(), records, head: 30, floor: None, claim_entry: Some(12), claimed: true }
}

/// THE GRADE (AUTH-3.20/3.22; G2): an anchor-grade record — an anchor-flagged
/// enrollment, a retirement naming an anchor OF THE TABLE as of its base — is
/// admitted only under an ANCHOR of the filtered set; a device key's `sig` on
/// one is inert, however good the signature, the grade read off the table
/// and never off a served set.
#[test]
fn an_anchor_grade_record_is_admitted_only_under_an_anchor() {
    let (anchor, device, x, y) = (signer(2), signer(1), signer(5), signer(6));
    let genesis = record(Kind::Enroll, "1.0.1.0.1.0.2.1", &[enroll(&anchor, true, "paper-a"), enroll(&device, false, "notebook")], &[], None, Some(9));
    let table = table_of(&records(vec![
        genesis,
        signed_enrollment(&device, "1.0.1.0.1.0.2.2", &[enroll(&x, true, "paper-x")], Some(20)),
        signed_enrollment(&anchor, "1.0.1.0.1.0.2.3", &[enroll(&y, true, "paper-y")], Some(22)),
        signed_retirement(&device, "1.0.1.0.1.0.2.4", &[fp(&y)], Some(24)),
    ]));
    let current: Vec<(Fingerprint, bool)> = table.current(&account()).map(|a| (a.fingerprint, a.anchor)).collect();
    assert!(!current.iter().any(|(f, _)| *f == fp(&x)), "a device key's hand minted an anchor");
    assert!(current.contains(&(fp(&y), true)), "an anchor's hand enrolls one, and a device key's retires none");
    assert_eq!(
        refused(&table),
        [("1.0.1.0.1.0.2.2".to_string(), RefusedCause::Unsigned), ("1.0.1.0.1.0.2.4".to_string(), RefusedCause::Unsigned)]
    );
}

/// I4 (AUTH-2.98) in the filter: a RETIRED key admits nothing after its
/// retirement — a record it signs is inert — and an entry it signs after
/// reads UNSIGNED.
#[test]
fn a_retired_key_admits_nothing_after_its_retirement() {
    let (anchor, device, planted) = (signer(2), signer(1), signer(7));
    let genesis = record(Kind::Enroll, "1.0.1.0.1.0.2.1", &[enroll(&anchor, true, "paper-a"), enroll(&device, false, "notebook")], &[], None, Some(9));
    let table = table_of(&records(vec![
        genesis,
        signed_retirement(&anchor, "1.0.1.0.1.0.2.2", &[fp(&device)], Some(20)),
        signed_enrollment(&device, "1.0.1.0.1.0.2.3", &[enroll(&planted, false, "planted")], Some(24)),
    ]));
    let device_admission = table.admissions(&account()).iter().find(|a| a.fingerprint == fp(&device)).expect("the genesis admits it");
    assert_eq!(device_admission.until, Until::RetiredAt(20));
    assert!(!table.current(&account()).any(|a| a.fingerprint == fp(&planted)), "a retired key admitted a key");
    assert_eq!(refused(&table), [("1.0.1.0.1.0.2.3".to_string(), RefusedCause::Unsigned)]);
    let frame = link_frame();
    let blob = HybridSigner::sign(&device, &frame);
    let entry = Entry { position: 30, frame: &frame, attest: Some(("mldsa65-ed25519", &blob)) };
    assert_eq!(verdict(&entry, &table, &account(), Bounds { boundary: Some(12), floor: None }), Verdict::Unsigned);
}

/// THE BLOB BEFORE THE TRIAL: a record whose `sig` is hex of NO row's width —
/// the classical 64 bytes, here — is no hybrid blob, read through
/// skep-identity's `HybridBlob::parse_hex`, and is left inert for that, never
/// tried against each key and reported as signed by none of them.
#[test]
fn a_sig_of_no_rows_width_is_no_hybrid_blob() {
    let (anchor, device, x) = (signer(2), signer(1), signer(5));
    let genesis = record(Kind::Enroll, "1.0.1.0.1.0.2.1", &[enroll(&anchor, true, "paper-a"), enroll(&device, false, "notebook")], &[], None, Some(9));
    let classical = record(Kind::Enroll, "1.0.1.0.1.0.2.2", &[enroll(&x, false, "x")], &[], Some("ab".repeat(64)), Some(20));
    let table = table_of(&records(vec![genesis, classical]));
    assert_eq!(refused(&table), [("1.0.1.0.1.0.2.2".to_string(), RefusedCause::NoBlob)]);
    assert!(!table.current(&account()).any(|a| a.fingerprint == fp(&x)), "nothing it names is admitted");
}

/// Below the retention floor the records read POSITION-FREE and the filter
/// builds in RECORD ORDER: a retirement read there takes its key out of the
/// set for every record after it and every entry judged, and a key it
/// retired admits nothing after it.
#[test]
fn below_the_floor_the_filter_builds_in_record_order() {
    let (anchor, device, e, f) = (signer(2), signer(1), signer(8), signer(9));
    let genesis = record(Kind::Enroll, "1.0.1.0.1.0.2.1", &[enroll(&anchor, true, "paper-a"), enroll(&device, false, "notebook")], &[], None, None);
    let table = table_of(&records(vec![
        genesis,
        signed_retirement(&anchor, "1.0.1.0.1.0.2.2", &[fp(&device)], None),
        signed_enrollment(&anchor, "1.0.1.0.1.0.2.3", &[enroll(&e, false, "laptop")], None),
        signed_enrollment(&device, "1.0.1.0.1.0.2.4", &[enroll(&f, false, "after")], None),
    ]));
    let device_admission = table.admissions(&account()).iter().find(|a| a.fingerprint == fp(&device)).expect("the genesis admits it");
    assert_eq!(device_admission.until, Until::RetiredPositionFree);
    let mut expected = vec![fp(&anchor), fp(&e)];
    expected.sort_by_key(Fingerprint::to_hex);
    for (name, mut members) in [("current", current(&table)), ("as of 30", table.as_of(&account(), 30).map(|a| a.fingerprint).collect())] {
        members.sort_by_key(Fingerprint::to_hex);
        assert_eq!(members, expected, "{name}");
    }
    assert_eq!(table.refused().len(), 1, "the retired key's own enrollment, after its retirement");
    let frame = link_frame();
    let bounds = Bounds { boundary: Some(12), floor: Some(20) };
    let by = |s: &HybridSigner| HybridSigner::sign(s, &frame);
    let (device_blob, e_blob) = (by(&device), by(&e));
    assert_eq!(verdict(&Entry { position: 30, frame: &frame, attest: Some(("mldsa65-ed25519", &device_blob)) }, &table, &account(), bounds), Verdict::Unsigned);
    assert_eq!(verdict(&Entry { position: 30, frame: &frame, attest: Some(("mldsa65-ed25519", &e_blob)) }, &table, &account(), bounds), Verdict::Signed(fp(&e)));
}
