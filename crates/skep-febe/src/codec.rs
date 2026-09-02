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
    ///
    /// **The implementer owes the request's SIZE.** M10 measures no field of
    /// the [`Op`] it is handed: `values`, `specs`, `cuts`, `regions`,
    /// `rho1`/`rho2`, `to`, `n` and every tumbler's components and magnitudes
    /// reach the owning store as presented. The one list M10 measures is the
    /// EDITLINK successor slot it builds for itself, against M7's per-slot
    /// budget; nothing it RECEIVES is measured. So this parser is the only
    /// bound on how large a request may be, and a costed frame — a maximal
    /// COMPARE, an `insert` whose values outrun the transaction budget —
    /// reaches the store exactly as it arrives.
    ///
    /// Shape is not the implementer's: `Address`, `Span` and `Tumbler`
    /// validate in their own constructors (and re-enter them on deserialize),
    /// so a parsed argument is well formed by construction and no dispatch arm
    /// re-checks it.
    ///
    /// A [`Request`]'s `id` past [`MAX_REQ_ID_BYTES`] is accepted and simply
    /// not memoized, so a retry re-executes and the client is never told. A
    /// parser that wants it TOLD refuses the id here.
    ///
    /// The production instance (skepd's `JsonCodec`) enforces a per-array
    /// element cap, a per-`insert` minted-value cap, and per-tumbler digit and
    /// component caps. Those numbers are the transport's — each sized against
    /// its own request-body cap — not M10 policy: a transport with a different
    /// frame budget owes its own.
    ///
    /// [`Op`]: crate::Op
    /// [`MAX_REQ_ID_BYTES`]: crate::MAX_REQ_ID_BYTES
    fn parse(&self, frame: &[u8]) -> Result<Request, ParseError>;
    /// Typed response → wire bytes. Total by signature: there is no failure
    /// channel, so the implementer must be able to encode EVERY [`Response`],
    /// every `Rejected` among them. The never-silent contract rests on that
    /// totality — an answer M10 produced and the codec cannot render is a
    /// silence.
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
