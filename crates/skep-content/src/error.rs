//! §Types & errors — the typed rejections of M4's write surface.

use std::error::Error;
use std::fmt;

use skep_address::Tumbler;

/// Rejections of [`crate::stage_write`] (and, wrapped in
/// `TxnError::Rejected`, of the standalone op).
///
/// `#[non_exhaustive]`: the `content-addr-guard` feature adds/removes
/// `NotContentAddress`, changing the variant set across build configs, so
/// every downstream matcher — chiefly M10's surfacing of
/// `TxnError::Rejected(ContentError)` — must carry a wildcard arm; flipping
/// the feature then cannot break a `match`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentError {
    /// Defensive S0 guard (ASN-0036 S0; ASN-0093 C0): a value is already
    /// stored at this address. Cannot occur in production (M3 mints fresh;
    /// M5 writes once) — converts an upstream bug into a clean typed
    /// rejection instead of a silent permascroll overwrite.
    AlreadyPresent(Tumbler),
    /// Optional defense-in-depth: not a content-subspace element address.
    /// Routing is M5's job, mint-conformance M3's — see Open build decision
    /// #4. Ships ONLY with the `content-addr-guard` feature, so the base
    /// build carries no dead variant. Under the recommended debug-assert
    /// sub-choice taken in this build the guard PANICS in debug builds
    /// rather than returning this variant — it is declared because the
    /// interface pins the feature-gated variant set (callers must be ready
    /// for it), not because the current sub-choice constructs it.
    #[cfg(feature = "content-addr-guard")]
    NotContentAddress(Tumbler),
}

impl fmt::Display for ContentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContentError::AlreadyPresent(t) => write!(
                f,
                "content write rejected: a value is already stored at {t:?} (S0 no-overwrite)"
            ),
            #[cfg(feature = "content-addr-guard")]
            ContentError::NotContentAddress(t) => write!(
                f,
                "content write rejected: {t:?} is not a content-subspace element address (content-addr-guard)"
            ),
        }
    }
}

impl Error for ContentError {}
