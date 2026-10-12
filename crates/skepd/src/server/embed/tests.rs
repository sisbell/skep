use std::io;
use std::time::Duration;

use skep_engine::EngineError;
use skep_kernel::OpenError;

use super::*;

/// The open's refusal as `Kernel::open` surfaces an I/O failure of `kind` —
/// the journal directory's lock among them: `DaemonError::Engine` over M2's
/// `OpenError::Io`.
fn kernel_io(kind: io::ErrorKind) -> DaemonError {
    DaemonError::Engine(EngineError::Open(OpenError::Io(io::Error::from(kind))))
}

/// THE RETRY's ONE CONDITION: an `io::Error` of kind `WouldBlock` in the
/// refusal's `source` chain — the kernel's `flock` answer for a lock a
/// kernel just dropped still holds — is retried; every other kind, at the
/// kernel's arm or at another subsystem's, and a chain that carries no
/// `io::Error` at all, is answered at once.
#[test]
fn only_the_locks_would_block_is_retried() {
    assert!(lost_the_lock_race(&kernel_io(io::ErrorKind::WouldBlock)), "the lock race is retried");
    for kind in [
        io::ErrorKind::AlreadyExists,
        io::ErrorKind::NotADirectory,
        io::ErrorKind::NotFound,
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::ReadOnlyFilesystem,
        io::ErrorKind::Other,
    ] {
        assert!(!lost_the_lock_race(&kernel_io(kind)), "{kind:?} at the kernel's arm is a fault");
    }
    assert!(
        !lost_the_lock_race(&DaemonError::Sidecar(io::Error::from(
            io::ErrorKind::PermissionDenied
        ))),
        "a feed file the directory refuses is a fault"
    );
    assert!(
        !lost_the_lock_race(&DaemonError::Media(io::Error::other("the store refused"))),
        "a blob store the directory refuses is a fault"
    );
    assert!(
        !lost_the_lock_race(&DaemonError::Engine(EngineError::Open(OpenError::InvalidConfig(
            "a policy the kernel does not offer"
        )))),
        "a chain that carries no io::Error is a fault"
    );
}

/// EACH REFUSAL NAMES ITS STEP, ahead of the step's own words — so a face
/// says which — and `source` is the step's own error; the wait's refusal
/// names the walk and the deadline it was given.
#[test]
fn each_refusal_names_its_step_and_the_wait_its_deadline() {
    let bind = EmbedError::Bind(io::Error::from(io::ErrorKind::AddrInUse));
    assert!(bind.to_string().starts_with("bind: "), "{bind}");
    let open = EmbedError::Open(kernel_io(io::ErrorKind::PermissionDenied));
    assert!(open.to_string().starts_with("open: "), "{open}");
    let serve = EmbedError::Serve(io::Error::from(io::ErrorKind::OutOfMemory));
    assert!(serve.to_string().starts_with("serve: the OS refused a worker thread: "), "{serve}");
    for (refusal, kind) in [(&bind, io::ErrorKind::AddrInUse), (&serve, io::ErrorKind::OutOfMemory)]
    {
        let source = refusal.source().and_then(|e| e.downcast_ref::<io::Error>());
        assert_eq!(source.map(io::Error::kind), Some(kind), "{refusal}");
    }
    assert!(open.source().is_some_and(|e| e.is::<DaemonError>()), "{open}");
    let late = IndexNotReady(Duration::from_millis(200));
    assert_eq!(late.deadline(), Duration::from_millis(200));
    assert_eq!(late.to_string(), "the cell index's walk did not complete within 200ms");
}
