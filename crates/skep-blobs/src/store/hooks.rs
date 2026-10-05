//! THE TEST SEAM — compiled only with `test-hooks`, which this crate's own
//! suites and the daemon's turn on and no shipped build does. The HAZARD
//! SEAM: the hook before each [`Step`] of a finish, where a HOLD runs a
//! closure (the daemon's SIGKILL harness parks the thread in it and kills
//! the process) or an injected FAILURE answers an I/O error in the step's
//! place (the `finish` and `replace` suites observe what each failure
//! leaves). A hold runs with none of the seam's own state locked, so it
//! parks its own finish alone: the finish keeps what any finish holds — the
//! store's finish lock, which runs the finishes one at a time — and nothing
//! of the seam's. And the three methods only a test calls:
//! [`Store::install`], which plants a file under a hex its bytes need not
//! hash to; [`Stream::written`], the bytes a stream has written, durable or
//! not; and [`Store::asides_queued`], the deferred unlink's queue. A build
//! without the feature carries none of it, and its hook before a step is a
//! no-op (`store.rs`).

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;

use super::{Step, Store, Stream};
use crate::blobs::fsync_dir;

/// The hazard seam's state: at most one failure point and one hold — the
/// hold shared, so the hook takes it out and runs it with this state
/// unlocked.
#[derive(Default)]
pub(super) struct Hooks {
    fail_at: Option<Step>,
    hold: Option<(Step, Arc<dyn Fn() + Send + Sync>)>,
}

impl Store {
    /// The seam's hook before a step of the finish: a hold runs its
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
    /// with an I/O error, or `None` to fail nothing — the `finish` and
    /// `replace` suites' seeded injection. At [`Step::UnlinkAside`] it fails
    /// the deferred unlink ([`Store::unlink_asides`]), never a finish.
    pub fn fail_at(&self, step: Option<Step>) {
        self.hooks.lock().fail_at = step;
    }

    /// TEST HOOK (`test-hooks`): HOLD every later finish before the named
    /// step by calling `f` there — the SIGKILL harness parks the thread in
    /// it and kills the process. A hold inside a finish parks that finish
    /// with the store's finish lock held, as every finish holds it, so
    /// another finish waits on it as on any; one at [`Step::UnlinkAside`]
    /// parks the deferred unlink that met it. No lock of the seam's is held
    /// while `f` runs. A hold must not call [`Store::install`], which takes
    /// the finish lock too.
    pub fn hold_at(&self, step: Step, f: impl Fn() + Send + Sync + 'static) {
        self.hooks.lock().hold = Some((step, Arc::new(f)));
    }

    /// TEST HOOK (`test-hooks`): install `bytes` as `<designation>/<hex>`
    /// by the blob's own order — a temp file beside the target, fsynced,
    /// renamed over it, the directory and the root fsynced, the root's fsync
    /// paid for the designation directory as a finish's is — with no
    /// upload, no lease, and the hex NOT checked against the bytes: a
    /// test's way to plant a file, the corrupt one a REPLACE repairs
    /// included. It holds the finish lock throughout, as a finish does, so
    /// its rename onto a hash's name never falls between a finish's check,
    /// link and rename. It is the one way to name a file by a hash its bytes
    /// do not have, so only the seam carries it; the operator's pull
    /// (`media.md` §Recovery) re-hashes what it installs and opens no store.
    pub fn install(&self, designation: &str, hex: &str, bytes: &[u8]) -> io::Result<()> {
        let Some(path) = self.blob_path(designation, hex) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "designation or hex"));
        };
        let mut finishing = self.finishing.lock();
        install_whole(&path, bytes)?;
        fsync_dir(&self.root)?;
        finishing.root_synced.insert(designation.to_string());
        Ok(())
    }

    /// TEST HOOK (`test-hooks`): the asides queued — those of replaces this
    /// process has answered, not yet unlinked — what
    /// [`Store::unlink_asides`] will take.
    pub fn asides_queued(&self) -> usize {
        self.aside_queue.lock().len()
    }
}

impl Stream<'_> {
    /// TEST HOOK (`test-hooks`): the bytes this stream has written, durable
    /// or not — the suites' read of bytes written and not yet received; the
    /// daemon takes the count from [`Stream::append`]'s answer instead.
    pub fn written(&self) -> u64 {
        self.handle.written()
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
