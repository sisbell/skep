//! §Types & errors — the typed rejections of M4's write surface.

use std::error::Error;
use std::fmt;

use skep_address::Tumbler;

/// Rejections of [`crate::stage_write`] (and, wrapped in
/// `TxnError::Rejected`, of the standalone op).
///
/// `#[non_exhaustive]`: the variant set is not closed. Open build decision
/// #4's error-returning sub-choice would add a routing rejection beside
/// `AlreadyPresent` (the debug-assert sub-choice this build takes panics
/// instead, and adds none), so the compiler holds every `match` on it
/// outside this crate to a wildcard arm, and that variant can land without
/// breaking one.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentError {
    /// Defensive S0 guard (ASN-0036 S0; ASN-0093 C0): a value is already
    /// stored at this address. Cannot occur in production (M3 mints fresh;
    /// M5 writes once) — converts an upstream bug into a clean typed
    /// rejection instead of a silent permascroll overwrite.
    AlreadyPresent(Tumbler),
}

impl fmt::Display for ContentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContentError::AlreadyPresent(t) => write!(
                f,
                "content write rejected: a value is already stored at {t:?} (S0 no-overwrite)"
            ),
        }
    }
}

impl Error for ContentError {}
