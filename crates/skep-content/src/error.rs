//! §Types & errors — the typed rejections of M4's write surface.

use std::error::Error;
use std::fmt;

use skep_address::Tumbler;

/// Rejections of [`crate::stage_write`] and [`crate::stage_stretch`].
///
/// They are the standalone ops' rejections too, wrapped in
/// `TxnError::Rejected`.
///
/// `#[non_exhaustive]`: the variant set is not closed — Open build decision
/// #1's out-of-line values would stage through a blob store whose write can
/// fail — so every `match` outside this crate carries a wildcard arm, and
/// such a variant can land without breaking one.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentError {
    /// A second write at one address (ASN-0036 S0; ASN-0093 C0).
    ///
    /// The address is already covered — a value or a stretch is stored at
    /// it, or it lies inside a stored stretch's reach, `key ≤ t < key ⊕ N` by
    /// tumbler order ([`crate::ContentStore::contains`]). Never produced in
    /// correct operation (M3 mints fresh; M5 writes once): it reports an
    /// upstream invariant violation, and reports it as a refusal rather than
    /// a panic because the fault turns on runtime state no test can exhaust —
    /// the frontier M3 mints from, what a composite has already pushed — and
    /// a refusal aborts the caller's whole transaction, where a release
    /// build's fold would drop the write and leave the caller's placement on
    /// another write's value. Reachable whenever that upstream is wrong, so a
    /// caller handles it as a refusal, never as unreachable.
    AlreadyStored(Tumbler),
    /// A stretch of zero bytes: a range of nothing.
    ///
    /// Refused at [`crate::stage_stretch`] before any other check, and at the
    /// record's decode once both its fields have decoded.
    EmptyStretch,
    /// A stretch whose window `[first, first ⊕ N)` holds a stored key.
    ///
    /// The first key at or past `first` lies below `reach` by tumbler order,
    /// whatever that key's chain or length (containment, the test
    /// `AlreadyStored` makes of the first address alone). Never produced in
    /// correct operation, for `AlreadyStored`'s reasons, and handled as a
    /// refusal for the same.
    Overlap {
        /// The stretch's first address.
        first: Tumbler,
        /// The first address past the stretch, `first ⊕ N`.
        reach: Tumbler,
    },
}

/// The refusal's own fact, with any address it names in M1's dotted form.
///
/// Which write was rejected, and by what operation, is the wrapper's to say:
/// M5's `InsertError` and `PublishError` say it, and carry this as their
/// `source`, so a reporter that walks the chain prints each layer once.
impl fmt::Display for ContentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContentError::AlreadyStored(t) => {
                write!(f, "a value is already stored at {t} (S0 content immutability)")
            }
            ContentError::EmptyStretch => f.write_str("a content stretch of zero bytes"),
            ContentError::Overlap { first, reach } => write!(
                f,
                "a content stretch from {first} up to {reach} overlaps a stored entry (S0 \
                 content immutability)"
            ),
        }
    }
}

impl Error for ContentError {}
