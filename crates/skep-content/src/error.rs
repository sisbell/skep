//! §Types & errors — the typed rejections of M4's write surface.

use std::error::Error;
use std::fmt;

use skep_address::Tumbler;

/// Rejections of [`crate::stage_write`] (and, wrapped in
/// `TxnError::Rejected`, of the standalone op).
///
/// `#[non_exhaustive]`: the variant set is not closed — Open build decision
/// #1's out-of-line values would stage through a blob store whose write can
/// fail — so every `match` outside this crate carries a wildcard arm, and
/// such a variant can land without breaking one.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentError {
    /// An upstream duplicate (ASN-0036 S0; ASN-0093 C0): a value is already
    /// stored at this address. Cannot occur in production (M3 mints fresh;
    /// M5 writes once) — converts an upstream bug into a clean typed
    /// rejection instead of a write the fold would drop.
    AlreadyStored(Tumbler),
}

/// The refusal's own fact, with its address in M1's dotted form. Which write
/// was rejected, and by what operation, is the wrapper's to say: M5's
/// `InsertError` and `PublishError` say it, and carry this as their `source`,
/// so a reporter that walks the chain prints each layer once.
impl fmt::Display for ContentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContentError::AlreadyStored(t) => {
                write!(f, "a value is already stored at {t} (S0 no-overwrite)")
            }
        }
    }
}

impl Error for ContentError {}
