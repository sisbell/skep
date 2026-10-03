//! The crate's one integration-test target: every suite below is a module
//! of this binary. Nothing but module declarations and the shared helpers
//! belongs here.

mod blobs;
mod lease;
mod uploads;

use std::path::Path;

use skep_blobs::{Store, UploadRecord};

/// The lease interval and the horizon every suite opens with: a day and a
/// week, in milliseconds — numbers, not the daemon's pins.
pub const INTERVAL: u64 = 24 * 3600 * 1000;
pub const HORIZON: u64 = 7 * INTERVAL;

/// A fresh store at `root`, opened at `now`.
pub fn open(root: &Path, now: u64) -> Store {
    Store::open(root, now, HORIZON).expect("the store opens")
}

/// One whole upload by `key` of `bytes` at `now`: created, resumed at 0,
/// appended whole, settled, finished with a lease to `now + INTERVAL`.
/// Answers the finish.
pub fn put_whole(store: &Store, key: &str, bytes: &[u8], now: u64) -> skep_blobs::Finished {
    let rec = store.create_upload(key, "blake3", bytes.len() as u64, now + INTERVAL, None).expect("create");
    store.resume(key, &rec.id, 0, now).expect("resume");
    store.append(key, &rec.id, bytes, now, INTERVAL).expect("append");
    store.settle(key, &rec.id, now, INTERVAL).expect("settle");
    store.finish(key, &rec.id, now, now + INTERVAL).expect("finish")
}

/// BLAKE3 of `bytes` as the hex the store answers.
pub fn hex_of(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// A standing upload of `key` with `bytes` received, left unfinished.
pub fn standing(store: &Store, key: &str, length: u64, bytes: &[u8], now: u64) -> UploadRecord {
    let rec = store.create_upload(key, "blake3", length, now + INTERVAL, None).expect("create");
    store.resume(key, &rec.id, 0, now).expect("resume");
    if !bytes.is_empty() {
        store.append(key, &rec.id, bytes, now, INTERVAL).expect("append");
    }
    store.settle(key, &rec.id, now, INTERVAL).expect("settle")
}
