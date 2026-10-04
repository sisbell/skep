//! The crate's one integration-test target: every suite below is a module
//! of this binary. Nothing but module declarations and the shared helpers
//! belongs here.

mod blobs;
mod lease;
mod uploads;

use std::any::Any;
use std::path::Path;
use std::time::Duration;

use skep_blobs::{Lease, Store, UploadRecord};

/// The interval every suite hands the store — each upload's at its
/// creation, each lease's at its finish — and the horizon every suite opens
/// with: a day and a week — numbers, not the daemon's pins. `INTERVAL_MS`
/// and `HORIZON_MS` are the same spans as the milliseconds a suite adds to
/// a clock reading.
pub const INTERVAL_MS: u64 = 24 * 3600 * 1000;
pub const HORIZON_MS: u64 = 7 * INTERVAL_MS;
pub const INTERVAL: Duration = Duration::from_millis(INTERVAL_MS);
pub const HORIZON: Duration = Duration::from_millis(HORIZON_MS);

/// A fresh store at `root`, opened at `now`.
pub fn open(root: &Path, now: u64) -> Store {
    Store::open(root, HORIZON, now).expect("the store opens")
}

/// One whole upload by `principal` of `bytes` at `now`: created under
/// `INTERVAL`, resumed at 0, appended whole, settled, finished with a lease
/// `INTERVAL` past `now`. Answers the finish.
pub fn put_whole(store: &Store, principal: &str, bytes: &[u8], now: u64) -> skep_blobs::Finished {
    let rec = store.create_upload(principal, "blake3", bytes.len() as u64, INTERVAL, now).expect("create");
    store.resume(principal, &rec.id, 0, now).expect("resume");
    store.append(principal, &rec.id, bytes, now).expect("append");
    store.settle(principal, &rec.id, now).expect("settle");
    store.finish(principal, &rec.id, INTERVAL, now).expect("finish")
}

/// BLAKE3 of `bytes` as the hex the store answers.
pub fn hex_of(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// A standing upload of `principal` with `bytes` received, left unfinished.
pub fn standing(store: &Store, principal: &str, length: u64, bytes: &[u8], now: u64) -> UploadRecord {
    let rec = store.create_upload(principal, "blake3", length, INTERVAL, now).expect("create");
    store.resume(principal, &rec.id, 0, now).expect("resume");
    if !bytes.is_empty() {
        store.append(principal, &rec.id, bytes, now).expect("append");
    }
    store.settle(principal, &rec.id, now).expect("settle")
}

/// THE SUITES' CELLS: none. This crate reads no cell, so in its suites
/// every deposit is unplaced — the answer `Store::pending_bytes` and
/// `Store::pending_total` are handed.
pub fn every_deposit_unplaced(_: &Lease) -> bool {
    true
}

/// The message a caught panic carried — what a suite reads a broken
/// precondition's name off: a formatted panic's `String`, a literal's
/// `&str`, and nothing for any other payload.
pub fn panic_message(payload: Box<dyn Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(message) => *message,
        Err(payload) => payload.downcast_ref::<&str>().map_or_else(String::new, |message| (*message).to_string()),
    }
}
