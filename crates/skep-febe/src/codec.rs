//! The wire codec seam. The byte format is fixed by no source note (Open
//! build decision 1): the transport supplies the one concrete impl; M10 fixes
//! only the typed [`Request`]/[`Response`]/`Rejection` targets.

use crate::op::Request;
use crate::response::Response;

/// The transport's codec (builder supplies one concrete impl).
///
/// A [`Codec::parse`] failure never reaches `Operation::execute` (which takes
/// an already-parsed [`Request`]), so it has no `Op` and no `OpKind` from
/// `Op::kind()`. The TRANSPORT surfaces it through M10's never-silent model
/// by building `Response::Rejected(Rejection { op: OpKind::Unparseable,
/// code: Malformed, disposition: Permanent, site: None, detail })` and
/// marshaling that via [`Codec::marshal`] — the one never-silent obligation
/// outside M10's exhaustive-dispatch enforcement (Invariants).
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
pub struct ParseError {
    /// Optional human-readable cause for the `Unparseable` rejection.
    pub detail: Option<String>,
}
