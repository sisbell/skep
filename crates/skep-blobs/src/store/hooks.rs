//! THE TEST SEAM — compiled only with `test-hooks`, which this crate's own
//! suites and the daemon's turn on and no shipped build does. The HAZARD
//! SEAM: the gate before each [`Step`] of a finish, where a HOLD runs a
//! closure (the daemon's SIGKILL harness parks the thread in it and kills
//! the process) or an injected FAILURE answers an I/O error in the step's
//! place (the fsync-order suite observes what each failure leaves). A hold
//! runs with none of the seam's own state locked, so it parks its own
//! finish alone: the finish keeps what any finish holds — the store's lock
//! on its handles, which runs the finishes one at a time — and nothing of
//! the seam's. And the four methods only a test calls: [`Store::install`],
//! which plants a file under a hex its bytes need not hash to;
//! [`Store::written`], the bytes a request's handle has written, durable or
//! not, answered to its own principal alone; [`Store::asides_queued`], the
//! deferred unlink's queue; and [`Store::handles_open`], the handles
//! requests hold. A build without the feature carries none of it, and its
//! gate before a step is a no-op (`store.rs`).

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;

use super::{Step, Store};
use crate::blobs::fsync_dir;
use crate::uploads::UploadId;

/// The hazard seam's state: at most one failure point and one hold — the
/// hold shared, so the gate takes it out and runs it with this state
/// unlocked.
#[derive(Default)]
pub(super) struct Hooks {
    fail_at: Option<Step>,
    hold: Option<(Step, Arc<dyn Fn() + Send + Sync>)>,
}

impl Store {
    /// The seam's gate before a step of the finish: a hold runs its
    /// closure (which may park the thread for good); an injected failure
    /// answers an I/O error in the step's place, read once the hold has
    /// returned. The hold is cloned out and run with the seam unlocked, so
    /// a hold that parks for good stalls its own finish alone, and one that
    /// sets the seam does not wait on itself.
    pub(super) fn before(&self, step: Step) -> io::Result<()> {
        let hold = self.hooks.lock().hold.as_ref().filter(|(at, _)| *at == step).map(|(_, f)| Arc::clone(f));
        if let Some(f) = hold {
            f();
        }
        if self.hooks.lock().fail_at == Some(step) {
            return Err(io::Error::other(format!("injected failure at {step:?}")));
        }
        Ok(())
    }

    /// TEST HOOK (`test-hooks`): FAIL the named step of every later finish
    /// with an I/O error, or `None` to fail nothing — the fsync-order test's
    /// seeded injection.
    pub fn fail_at(&self, step: Option<Step>) {
        self.hooks.lock().fail_at = step;
    }

    /// TEST HOOK (`test-hooks`): HOLD every later finish before the named
    /// step by calling `f` there — the SIGKILL harness parks the thread in
    /// it and kills the process. A hold inside a finish parks that finish
    /// with the store's lock on its handles held, as every finish holds it,
    /// so another finish waits on it as on any; one at the deferred
    /// [`Step::UnlinkAside`] parks the drain that met it. No lock of the
    /// seam's is held while `f` runs.
    pub fn hold_at(&self, step: Step, f: impl Fn() + Send + Sync + 'static) {
        self.hooks.lock().hold = Some((step, Arc::new(f)));
    }

    /// TEST HOOK (`test-hooks`): install `bytes` as `<designation>/<hex>`
    /// by the blob's own order — a temp file beside the target, fsynced,
    /// renamed over it, the directory and the root fsynced — with no
    /// upload, no lease, and the hex NOT checked against the bytes: a
    /// test's way to plant a file, the corrupt one a REPLACE repairs
    /// included. It is the one way to name a file by a hash its bytes do
    /// not have, so only the seam carries it; the operator's pull
    /// (`media.md` §Recovery) re-hashes what it installs and opens no store.
    pub fn install(&self, designation: &str, hex: &str, bytes: &[u8]) -> io::Result<()> {
        let Some(path) = self.blob_path(designation, hex) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "designation or hex"));
        };
        install_whole(&path, bytes)?;
        fsync_dir(&self.root)
    }

    /// TEST HOOK (`test-hooks`): the bytes written so far through the handle
    /// a request has open on the upload (durable or not), or the record's
    /// offset where no request has one open — the suites' read of bytes
    /// written and not yet received. `None` for an identifier `principal`'s
    /// records do not name, as [`Store::append`] answers it; the daemon
    /// takes the count from [`Store::append`]'s answer instead.
    pub fn written(&self, principal: &str, id: &UploadId, now_ms: u64) -> Option<u64> {
        self.uploads.lock().of_principal(principal, id)?;
        if let Some(handle) = self.handles.lock().get(id) {
            return Some(handle.written());
        }
        self.upload(principal, id, now_ms).map(|r| r.offset)
    }

    /// TEST HOOK (`test-hooks`): the asides queued — those of replaces this
    /// process has answered, not yet unlinked — what
    /// [`Store::unlink_asides`] will take.
    pub fn asides_queued(&self) -> usize {
        self.asides.lock().len()
    }

    /// TEST HOOK (`test-hooks`): the handles this process holds open — one
    /// per upload a request has resumed and not yet settled, finished,
    /// ended or closed.
    pub fn handles_open(&self) -> usize {
        self.handles.lock().len()
    }
}

/// Write `bytes` at `path` by the blob's own order: a temp file beside the
/// target, fsynced, renamed over it, the directory fsynced.
fn install_whole(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().expect("a blob sits in its designation directory");
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".install-{}", std::process::id()));
    {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    fsync_dir(dir)?;
    Ok(())
}
