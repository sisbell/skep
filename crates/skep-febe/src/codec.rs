//! The wire codec seam. The byte format is fixed by no source note (Open
//! build decision 1): the transport supplies the one concrete impl; M10 fixes
//! only the typed [`Request`]/[`Response`]/`Rejection` targets.

use std::fmt;

use crate::op::Request;
use crate::response::Response;

/// The transport's codec (builder supplies one concrete impl).
///
/// A [`Codec::parse`] failure never reaches `Operation::execute` (which takes
/// an already-parsed [`Request`]), so it has no `Op` and no `OpKind` from
/// `Op::kind()`. The TRANSPORT surfaces it through M10's never-silent model
/// by wrapping [`Rejection::unparseable`] in `Response::Rejected` and
/// marshaling that via [`Codec::marshal`] — the one never-silent obligation
/// outside M10's exhaustive-dispatch enforcement (Invariants). The
/// classification is M10's either way: the constructor applies the same code
/// and disposition table every other rejection goes through.
///
/// [`Rejection::unparseable`]: crate::Rejection::unparseable
///
/// A marshaled frame carries **no correlation id** (§8): the transport's own
/// envelope, not the codec's frame, pairs each reply with the in-flight
/// request's `ReqId`.
pub trait Codec {
    /// wire → `Op` (+ id).
    fn parse(&self, frame: &[u8]) -> Result<Request, ParseError>;
    /// Typed response → wire bytes.
    fn marshal(&self, resp: &Response) -> Vec<u8>;
}

/// A frame that failed to parse — unknown op / bad arg encoding. Constructed
/// by the transport's `Codec` impl; `detail` feeds the `Unparseable`
/// rejection's message slot.
///
/// A std error like every other failure in this workspace, so the transport
/// author writing the one required [`Codec`] impl can `unwrap`, `expect`,
/// `?` it into a boxed error, and log it with `{}` — the ordinary handling
/// of a parse failure, none of which is available to a bare struct.
#[derive(Debug)]
pub struct ParseError {
    /// Optional human-readable cause for the `Unparseable` rejection.
    pub detail: Option<String>,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.detail {
            Some(d) => write!(f, "unparseable frame: {d}"),
            None => f.write_str("unparseable frame"),
        }
    }
}

/// No `source`: the codec's own cause arrives as `detail` text, since the
/// byte format — and so the type of anything that failed inside it — is the
/// transport's, not M10's.
impl std::error::Error for ParseError {}
