//! THE READER'S VERIFIER (`client.md` §1.1's `verify` row; cp-1, owner-ruled
//! 2026-10-04): a COMMITTED signature checked against the key set AS OF THE
//! ENTRY's BASE (AUTH-2.94; P12 — never the head, at which every entry
//! signed by a key since retired would read as forged) — and that set is
//! THE SIGNATURE-FILTERED ONE, NEVER THE FOLD's (D14): the fold honours an
//! enrollment whatever its `sig` holds (AUTH-2.13), so `key_set` over `/op-at`
//! fixes a position and never this input's members.
//!
//! THE FILTER, derived from the account's credential records and their
//! `sig`s: a record is ADMITTED only where its own `sig` verifies over its
//! `record` frame under the filtered set as of THAT record's base, at the
//! act's GRADE — an anchor of that set where the act is anchor-grade, any
//! enrolled key of it otherwise; the PRE-CLAIM genesis is admitted unsigned
//! and HOST-TRUSTED (AUTH-4.55 (3); AUTH-4.58); a record whose `sig` fails is
//! inert to this table. THE ATTESTATION BOUNDARY is an input beside the set
//! — the board's CLAIM ENTRY — so BEFORE-ATTESTATION is told from UNSIGNED.
//! A MISSING INPUT IS A VERDICT AND NEVER A FALLBACK: where the caller
//! cannot derive it, the entry reads UNDETERMINABLE HERE, never judged
//! against the served `key_set`. Below the retention floor the records are
//! still read, position-free, and the filter builds in RECORD ORDER; what
//! the floor loses is the ENTRY and its base, and UNDETERMINABLE HERE is
//! that entry's verdict.
//!
//! A PURE FUNCTION OF ITS CALLER's READS: the entry, the frame its caller
//! composed through `skep_identity::entry_frame`, the table, `H.1`'s pair in;
//! the verdict out. The arithmetic is `skep_signature::verify`'s; nothing
//! here reads a board. The SESSION verify is `skepd`'s (AUTH-2.2).

use skep_identity::{BoardTerm, Fingerprint, PublicKey, SigAlgRow};

use crate::derive::records::{Kind, Records};

/// One admission of the FILTERED table: a key, from the record that admitted
/// it, until the record that retired it — positions where known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    pub fingerprint: Fingerprint,
    pub key: PublicKey,
    pub anchor: bool,
    /// The label the admitting record carried (AUTH-5.69).
    pub label: Option<String>,
    /// The admitting record's position; `None` position-free.
    pub since: Option<u64>,
    /// Where the admission's lifecycle stands.
    pub until: Until,
}

/// Where an admission's lifecycle stands — one lifecycle per fingerprint
/// and set (I4, AUTH-2.98).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Until {
    /// No admitted retirement names it: it stands enrolled.
    Enrolled,
    /// Retired by an admitted record at this position.
    RetiredAt(u64),
    /// Retired by an admitted record read position-free, below the
    /// retention floor: no base reads it as enrolled.
    RetiredPositionFree,
}

/// One record the filter refused, and why — inert to the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inert {
    /// The record's link address.
    pub link: String,
    pub why: String,
}

/// THE FILTERED TABLE and the records it left inert.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FilteredTable {
    pub admissions: Vec<Admission>,
    /// The records the filter refused.
    pub inert: Vec<Inert>,
}

impl FilteredTable {
    /// THE FILTER over `records` (genesis-first, record order): the genesis
    /// host-trusted; every later record admitted iff its `sig` verifies under
    /// the table as it stands at that record's base, at the act's grade.
    pub fn build(records: &Records, board: Option<BoardTerm>) -> FilteredTable {
        let mut table = FilteredTable::default();
        let mut genesis_seen = false;
        for r in &records.records {
            if r.kind == Kind::Enroll && !genesis_seen {
                genesis_seen = true;
                // AUTH-4.55 (3): the pre-claim genesis, host-trusted.
                for e in &r.enrolled {
                    table.admissions.push(Admission {
                        fingerprint: Fingerprint::of(&e.key),
                        key: e.key.clone(),
                        anchor: e.anchor,
                        label: e.label().map(str::to_string),
                        since: r.position,
                        until: Until::Enrolled,
                    });
                }
                continue;
            }
            let inert = |why: &str| Inert { link: r.link.clone(), why: why.to_string() };
            let Some(sig) = &r.sig else {
                table.inert.push(inert("no `sig` above the claim"));
                continue;
            };
            let Some(board) = board else {
                table.inert.push(inert("no H.1: the record frame cannot be composed"));
                continue;
            };
            let Some(blob) = crate::hex::decode(sig) else {
                table.inert.push(inert("the `sig` is no hybrid blob's hex"));
                continue;
            };
            // The table as it stands at this record's base — record order
            // being position order where positions are known.
            let candidates = table
                .admissions
                .iter()
                .filter(|a| a.until == Until::Enrolled && (!r.anchor_grade || a.anchor))
                .map(|a| (&a.fingerprint, &a.key));
            match r.signed_by(board, &blob, candidates) {
                None => table.inert.push(inert("signed by no key of this account's filtered set")),
                Some(_) => match r.kind {
                    Kind::Enroll => {
                        for e in &r.enrolled {
                            let fp = Fingerprint::of(&e.key);
                            if table.admissions.iter().any(|a| a.fingerprint == fp) {
                                continue; // I4: a fingerprint has one lifecycle per set.
                            }
                            table.admissions.push(Admission {
                                fingerprint: fp,
                                key: e.key.clone(),
                                anchor: e.anchor,
                                label: e.label().map(str::to_string),
                                since: r.position,
                                until: Until::Enrolled,
                            });
                        }
                    }
                    Kind::Retire => {
                        for fp in &r.retired {
                            if let Some(a) = table.admissions.iter_mut().find(|a| a.fingerprint == *fp && a.until == Until::Enrolled) {
                                a.until = r.position.map_or(Until::RetiredPositionFree, Until::RetiredAt);
                            }
                        }
                    }
                },
            }
        }
        table
    }

    /// The admissions ENROLLED as of the base of an entry at `position`
    /// (P12): admitted at a position below it (or position-free), not yet
    /// retired at one below it.
    pub fn as_of(&self, position: u64) -> impl Iterator<Item = &Admission> + '_ {
        self.admissions.iter().filter(move |a| a.since.is_none_or(|s| s < position)).filter(move |a| match a.until {
            Until::Enrolled => true,
            Until::RetiredAt(r) => r >= position,
            Until::RetiredPositionFree => false,
        })
    }

    /// The table's CURRENT members — every admission not retired.
    pub fn current(&self) -> impl Iterator<Item = &Admission> + '_ {
        self.admissions.iter().filter(|a| a.until == Until::Enrolled)
    }
}

/// One committed ENTRY under trial: its position, the frame its caller
/// composed from the stored entry (`skep_identity::entry_frame` over the
/// op's own body builder), and its `attest` as the feed served it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry<'a> {
    pub position: u64,
    pub frame: &'a [u8],
    /// `(alg token, blob)` where the row carried an `attest`; `None` where it
    /// carried none.
    pub attest: Option<(&'a str, &'a [u8])>,
}

/// The five verdicts' shape (the signed-ops record §3.5), the three a reader
/// of one entry reaches and the one a missing input forces. Non-exhaustive:
/// the record's shape names more verdicts than a reader of one entry meets.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verdict {
    /// The entry's `attest` verifies under a member of the filtered set as
    /// of its base.
    Signed(Fingerprint),
    /// Above the claim, no `attest`, or one no member verifies.
    Unsigned,
    /// At or below the attestation boundary — the claim entry.
    BeforeAttestation,
    /// A missing input: no boundary derivable, the entry below the floor,
    /// the records unfetchable — never judged against the served `key_set`.
    Undeterminable(&'static str),
}

/// The two positions a verdict is judged at beside the table, each `None`
/// where the caller could not derive it — named, so neither can stand in the
/// other's place: THE ATTESTATION BOUNDARY, the board's claim entry
/// (SIGNED-OPS §5.5 as RULED), at or below which an entry reads BEFORE
/// ATTESTATION, its absence UNDETERMINABLE HERE and never a fallback; and
/// the RETENTION FLOOR, below which an entry and its base are lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bounds {
    /// The board's claim entry.
    pub boundary: Option<u64>,
    /// The retention floor, where a position-addressed read met it.
    pub floor: Option<u64>,
}

/// The bounds the admitted read derived: its claim entry and its floor.
impl From<&Records> for Bounds {
    fn from(records: &Records) -> Bounds {
        Bounds { boundary: records.claim_entry, floor: records.floor }
    }
}

/// THE VERDICT of `entry` under `table`, at `bounds`.
pub fn verdict(entry: &Entry<'_>, table: &FilteredTable, bounds: Bounds) -> Verdict {
    let Some(boundary) = bounds.boundary else { return Verdict::Undeterminable("the attestation boundary could not be derived here") };
    if entry.position <= boundary {
        return Verdict::BeforeAttestation;
    }
    if bounds.floor.is_some_and(|f| entry.position < f) {
        return Verdict::Undeterminable("the entry lies below this board's retention floor");
    }
    let Some((alg, blob)) = entry.attest else { return Verdict::Unsigned };
    let Some(row) = SigAlgRow::of_token(alg) else { return Verdict::Unsigned };
    for a in table.as_of(entry.position) {
        if a.key.alg() != alg {
            continue;
        }
        if skep_signature::verify(row.tag, &a.key, entry.frame, blob).is_ok() {
            return Verdict::Signed(a.fingerprint);
        }
    }
    Verdict::Unsigned
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::parse_address;
    use crate::derive::records::{Hand, Record};
    use crate::sign::RecordFrame;
    use skep_identity::{canonical_record, entry_body_make_link, entry_frame, unit_span, DocTerm, Enrollment, EntrySlot, LinkSlots};
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

    fn record(kind: Kind, link: &str, entries: &[Enrollment], retired: &[Fingerprint], sig: Option<String>, position: Option<u64>, anchor_grade: bool) -> Record {
        let sigless = match kind {
            Kind::Enroll => canonical_record(entries, None),
            Kind::Retire => canonical_record(retired, None),
        };
        Record {
            kind,
            link: link.into(),
            home: "1.0.1.0.1".into(),
            home_account: "1.0.1".into(),
            subject: "1.0.1".into(),
            atom: "1.0.1.0.1.0.1.1".into(),
            bytes: sigless.clone().into_bytes(),
            sigless,
            sig,
            enrolled: entries.to_vec(),
            retired: retired.to_vec(),
            position,
            base: position.map(|p| p - 1),
            hand: Hand::Bare,
            anchor_grade,
        }
    }

    fn sign_record(signer: &HybridSigner, ty: &str, sigless: &str) -> String {
        let frame = RecordFrame {
            alg: HybridSigner::public_key(signer).alg(),
            board: board(),
            home_account: "1.0.1",
            home: "1.0.1.0.1",
            ty,
            to: &["1.0.1"],
            sigless: sigless.as_bytes(),
        }
        .compose()
        .unwrap();
        crate::hex::encode(&HybridSigner::sign(signer, &frame))
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
            true,
        );
        // The plant: self-signed by the planted key, which stands in no set.
        let plant_entries = [enroll(&plant, false, "plant")];
        let plant_sigless = canonical_record(&plant_entries, None);
        let plant_sig = sign_record(&plant, crate::board::T_ENROLL, &plant_sigless);
        let planted = record(Kind::Enroll, "1.0.1.0.1.0.2.3", &plant_entries, &[], Some(plant_sig), Some(20), false);
        // A legitimate second device, signed by the enrolled device key.
        let second = signer(4);
        let second_entries = [enroll(&second, false, "phone")];
        let second_sigless = canonical_record(&second_entries, None);
        let second_sig = sign_record(&device, crate::board::T_ENROLL, &second_sigless);
        let enrolled_second = record(Kind::Enroll, "1.0.1.0.1.0.2.4", &second_entries, &[], Some(second_sig), Some(24), false);
        let records = Records {
            account: "1.0.1".into(),
            records: vec![genesis, planted, enrolled_second],
            head: 30,
            floor: None,
            claim_entry: Some(12),
            claimed: true,
        };
        let table = FilteredTable::build(&records, Some(board()));
        let current: Vec<Fingerprint> = table.current().map(|a| a.fingerprint).collect();
        assert!(current.contains(&Fingerprint::of(HybridSigner::public_key(&device))));
        assert!(current.contains(&Fingerprint::of(HybridSigner::public_key(&second))), "the signed second device is admitted");
        assert!(!current.contains(&Fingerprint::of(HybridSigner::public_key(&plant))), "the plant is inert to the table");
        assert_eq!(table.inert, [Inert { link: "1.0.1.0.1.0.2.3".into(), why: "signed by no key of this account's filtered set".into() }]);

        // An entry at 28, signed by the plant: UNSIGNED here.
        let home = parse_address("1.0.1.0.1").unwrap();
        let ty = [unit_span(&parse_address("1.1.0.1.0.1.0.3.90").unwrap())];
        let from = [unit_span(&parse_address("1.0.1.0.2").unwrap())];
        let to: [skep_address::Span; 0] = [];
        let body = entry_body_make_link(LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) });
        let frame = entry_frame(
            HybridSigner::public_key(&plant).alg(),
            board(),
            &parse_address("1.0.1").unwrap(),
            DocTerm::One(&home),
            &body,
        );
        let plant_blob = HybridSigner::sign(&plant, &frame);
        let bounds = Bounds { boundary: Some(12), floor: None };
        let entry = Entry { position: 28, frame: &frame, attest: Some(("mldsa65-ed25519", &plant_blob)) };
        assert_eq!(verdict(&entry, &table, bounds), Verdict::Unsigned);
        // The same entry signed by the device key: SIGNED, by that key.
        let device_blob = HybridSigner::sign(&device, &frame);
        let entry = Entry { position: 28, frame: &frame, attest: Some(("mldsa65-ed25519", &device_blob)) };
        assert_eq!(verdict(&entry, &table, bounds), Verdict::Signed(Fingerprint::of(HybridSigner::public_key(&device))));
        // Below the floor: UNDETERMINABLE, never judged.
        assert!(matches!(verdict(&entry, &table, Bounds { boundary: Some(12), floor: Some(29) }), Verdict::Undeterminable(_)));
        // Before the boundary, and with no boundary.
        let entry = Entry { position: 9, frame: &frame, attest: None };
        assert_eq!(verdict(&entry, &table, bounds), Verdict::BeforeAttestation);
        assert!(matches!(verdict(&entry, &table, Bounds::default()), Verdict::Undeterminable(_)));
        assert_eq!(Bounds::from(&records), bounds, "the admitted read's claim entry and floor");
        // A retired key is out of the set at the base of a later entry, in it
        // at the base of an earlier one (P12).
        let retire_entries = [Fingerprint::of(HybridSigner::public_key(&second))];
        let retire_sigless = canonical_record(&retire_entries, None);
        let retire_sig = sign_record(&device, crate::board::T_RETIRE, &retire_sigless);
        let retirement = record(Kind::Retire, "1.0.1.0.1.0.2.5", &[], &retire_entries, Some(retire_sig), Some(26), false);
        let mut with_retire = records.clone();
        with_retire.records.push(retirement);
        let table = FilteredTable::build(&with_retire, Some(board()));
        assert!(table.as_of(25).any(|a| a.fingerprint == retire_entries[0]));
        assert!(!table.as_of(27).any(|a| a.fingerprint == retire_entries[0]));
        let retired = table.admissions.iter().find(|a| a.fingerprint == retire_entries[0]).expect("admitted at 24");
        assert_eq!(retired.until, Until::RetiredAt(26));
    }
}
