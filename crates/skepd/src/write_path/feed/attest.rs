//! THE ATTEST STORE (signed ops; the design record §7.3 (i); BW-01,
//! owner-ruled 2026-09-29) — `feed-attest.log`: the marker slot's signature
//! per attested position, which `GET /changes` serves as the row's `attest`
//! member (`CommitMeta::entry`). It rides [`LineFile`]'s line discipline
//! under a class of its own:
//!
//! One line per ATTESTED position — `alg` the marker's `sig_alg` TAG (the
//! wire's token is rendered at serve), `sig` the blob as lowercase hex,
//! byte-equal to what the request presented — appended AT COMMIT from the
//! value the plain sequence admitted and handed the kernel, under the write
//! path's serialization lock in the same `record` that appends `commits.log`;
//! REBUILT on loss or a short tail from `Kernel::attestation_at` for every
//! position the journal still answers, ABOVE THE RECLAIM FLOOR alone — a
//! position the journal refuses `Reclaimed` is neither rebuilt nor dropped,
//! and its row renders `attest: null` (LOST). Below the floor the checkpoint
//! body holds no marker, so a line here is an entry signature's ONLY copy at
//! the origin: there the store is PRIMARY state and not a projection — NEVER
//! COMPACTED to the journal's retention (where `commits.log` and the four
//! derived sidecars drop their entries below the floor at open, this file
//! KEEPS them), neither prunable nor rebuildable, backed up by location with
//! the board directory as `blobs/` is, its loss served as `null`. The
//! coverage fence, the torn-tail truncation, the foreign-line purge and the
//! stop on a failed append apply above the floor as in the four. At HEAD no
//! read serves a below-floor slot (`/changes` answers `410
//! history_reclaimed` below the feed's floor): the lines below it are kept
//! for a read that does not yet exist, the class being the design record's
//! and not this build's to narrow.
//!
//! What keeps the class is this card's privacy: [`AttestStore`]'s file is its
//! own, and nothing rewrites it but [`LineFile::open`]'s purge of the lines
//! above the head — another journal's — which copies every line of this
//! journal verbatim, so no other card can compact it.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::sync::Arc;

use serde_json::{Map, Value};
use skep_engine::Engine;
use skep_kernel::{Attestation, Seq};

use super::derived::LineFile;
use super::super::sidecar::CommitsLog;
use crate::codec::{hex_string, parse_lower_hex_bytes};

// The file is named BESIDE the fields its records carry, and both beside the
// line's one writer ([`attest_fields`]) and its one reader
// ([`attest_of_record`]): a write site that spelled a field apart from the
// read site would write lines that replay as no slot.

/// The store's file.
const ATTEST_FILE: &str = "feed-attest.log";
/// Its records' first field: the marker's `sig_alg` tag, a number.
const ATTEST_ALG: &str = "alg";
/// Its records' second field: the signature blob, lowercase hex.
const ATTEST_SIG: &str = "sig";

/// THE ATTEST STORE: its file, and the slots of the positions `commits.log`
/// serves — resident at one blob (~3.4 KB under tag 1) per attested position
/// it serves: the retained window at open, then every attested commit this
/// uptime records — nothing prunes it before the next open. The FILE holds
/// more: every line ever appended, the positions the log compacted away
/// included, where the store is primary state.
pub(super) struct AttestStore {
    /// `feed-attest.log`: appended, replayed and fenced, and never compacted.
    file: LineFile,
    /// Position → the marker slot, for the served positions — behind an
    /// `Arc`, so a page rendered after the feed's lock is released
    /// ([`super::Feed::page`]) clones a pointer, never a signature.
    served: BTreeMap<u64, Arc<Attestation>>,
}

impl AttestStore {
    /// Open the store beside the replayed `log`: replay every line at or
    /// below the head, a line at a time, holding resident the SERVED window
    /// alone — the lines below the log's fence are read past and stay in the
    /// FILE, untouched — then rebuild the missing tail from the journal's
    /// markers, then fence at the head.
    ///
    /// A line this daemon cannot read (a tag of no signature, a blob of none,
    /// hex it did not write) is reported and not held: the row then renders
    /// `attest: null` where its line records the marker filled, never an
    /// invented slot. The tail is every served position above the file's
    /// coverage, asked of the journal — the marker-mirroring rebuild, above
    /// the floor alone. `Ok(None)` is an empty slot and contributes nothing; a
    /// refusal (`Reclaimed` — the segment holding the marker is gone though
    /// the position is still served; or any other) rebuilds nothing and drops
    /// nothing, and the fence still closes over it: the journal will not
    /// answer it on a later open either, and the row's own line says LOST.
    ///
    /// COST: O(the file) to READ it, a line at a time — holding one line and
    /// the served window, never the file, which keeps a line for every
    /// attested commit the board ever made — and one `Kernel::attestation_at`
    /// — a bounded journal scan from the base below the position — per
    /// uncovered retained position, so a lost store is O(retained window ×
    /// scan) at the open that rebuilds it. Never a compaction: the store keeps
    /// what the log drops.
    pub(super) fn open(dir: &Path, engine: &Engine, log: &CommitsLog) -> io::Result<AttestStore> {
        let head = log.open_head();
        let served_only = |at: u64| log.entries().contains_key(&at);
        let (mut file, lines) = LineFile::open(dir, ATTEST_FILE, head, served_only)?;
        let mut served = BTreeMap::new();
        for (at, m) in &lines {
            match attest_of_record(m) {
                Some(slot) => {
                    served.insert(*at, Arc::new(slot));
                }
                None => crate::notice::line(format_args!(
                    "{ATTEST_FILE} position {at} carries a slot this daemon cannot read"
                )),
            }
        }
        for (&at, _) in log.entries().range(file.first_uncovered()..) {
            if let Ok(Some(slot)) = engine.kernel().attestation_at(Seq(at)) {
                file.append(at, attest_fields(&slot))?;
                served.insert(at, Arc::new(slot));
            }
        }
        file.fence(head)?;
        Ok(AttestStore { file, served })
    }

    /// Mirror one admitted marker slot at RECORD time — the attestation the
    /// plain sequence's check admitted and handed the kernel — into the file
    /// and the served window. A failed append is reported and stops the file
    /// for the uptime ([`LineFile::append_or_report`]); this uptime still
    /// serves the slot, and the next open rebuilds it from the journal.
    pub(super) fn record(&mut self, at: u64, slot: Attestation) {
        self.file.append_or_report(at, attest_fields(&slot));
        self.served.insert(at, Arc::new(slot));
    }

    /// The slot the store holds for a served position — `None` where it holds
    /// none, which `CommitMeta::entry` renders `null` where the position's
    /// line records the marker filled (LOST) and absent otherwise. A pointer,
    /// cloned: the page that asks renders it after the feed's lock is gone.
    pub(super) fn slot(&self, at: u64) -> Option<Arc<Attestation>> {
        self.served.get(&at).cloned()
    }
}

/// One attest-store record's two fields for the marker slot `a`: the tag as
/// a number, the blob as lowercase hex — the spelling [`attest_of_record`]
/// reads back, and the one the codec's `j_attest` renders on the wire from
/// the same value (the token for the tag there).
fn attest_fields(a: &Attestation) -> Vec<(&'static str, Value)> {
    vec![
        (ATTEST_ALG, Value::Number(u64::from(a.sig_alg()).into())),
        (ATTEST_SIG, Value::String(hex_string(a.sig()))),
    ]
}

/// The marker slot one replayed attest-store record holds — [`attest_fields`]'s
/// inverse — or `None` where the record is not one this daemon wrote: a tag
/// past a byte or of no signature (`0`), a blob of no bytes, hex not in
/// `hex_string`'s own lowercase. `Attestation::new` holds the
/// one-spelling-of-empty rule, so a value read here is one the kernel could
/// have written.
fn attest_of_record(m: &Map<String, Value>) -> Option<Attestation> {
    let tag = u8::try_from(m.get(ATTEST_ALG)?.as_u64()?).ok()?;
    let sig = parse_lower_hex_bytes(m.get(ATTEST_SIG)?.as_str()?)?;
    Attestation::new(tag, sig).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A slot the store records is served at once and replays from its line
    /// as the same slot — [`attest_fields`] and [`attest_of_record`] one
    /// spelling in both directions — and a line this daemon did not write
    /// replays as no slot: an uppercase blob, a tag of no signature, a tag
    /// past a byte, an empty blob.
    #[test]
    fn a_recorded_slot_is_served_and_replays_from_its_line_as_itself() {
        let dir = tempfile::tempdir().expect("tempdir");
        let slot = Attestation::new(1, vec![0xab, 0x01]).expect("tag 1 and a non-empty blob");
        {
            let (file, lines) =
                LineFile::open(dir.path(), ATTEST_FILE, 9, |_| true).expect("a fresh store opens");
            assert!(lines.is_empty());
            let mut store = AttestStore { file, served: BTreeMap::new() };
            store.record(5, slot.clone());
            assert_eq!(store.slot(5).as_deref(), Some(&slot), "served at once");
            assert_eq!(store.slot(4).as_deref(), None, "and only where recorded");
        }
        let (_file, lines) =
            LineFile::open(dir.path(), ATTEST_FILE, 9, |_| true).expect("reopen");
        let replayed: Vec<(u64, Option<Attestation>)> =
            lines.iter().map(|(at, m)| (*at, attest_of_record(m))).collect();
        assert_eq!(replayed, [(5, Some(slot))], "the line replays as the slot it mirrors");

        let record = |alg: Value, sig: &str| {
            let mut m = Map::new();
            m.insert(ATTEST_ALG.to_string(), alg);
            m.insert(ATTEST_SIG.to_string(), Value::String(sig.to_string()));
            m
        };
        for (alg, sig, why) in [
            (Value::from(1u64), "AB01", "hex not in the store's own lowercase"),
            (Value::from(0u64), "ab01", "the empty slot's tag signs nothing"),
            (Value::from(256u64), "ab01", "a tag past a byte"),
            (Value::from(1u64), "", "a blob of no bytes"),
        ] {
            assert_eq!(attest_of_record(&record(alg, sig)), None, "{why}");
        }
    }
}
