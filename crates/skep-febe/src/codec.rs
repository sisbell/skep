//! The wire codec seam. The byte format is fixed by no source note (Open
//! build decision 1): the transport supplies the one concrete impl; M10 fixes
//! only the typed [`Request`]/[`Response`]/`Rejection` targets.

use std::fmt;

use crate::op::Request;
use crate::response::Response;

/// The transport's codec (builder supplies one concrete impl).
///
/// A [`Codec::parse`] failure never reaches `OperationSurface::execute`
/// (which takes an already-parsed [`Request`]), so it has no `Op` and no
/// `OpKind` from `Op::kind()`. The TRANSPORT surfaces it through M10's
/// never-silent model by wrapping [`Rejection::unparseable`] in
/// `Response::Rejected` and marshaling that via [`Codec::marshal`] — the one
/// never-silent obligation outside M10's exhaustive-dispatch enforcement
/// (Invariants). The classification is M10's either way: the constructor
/// applies the same code and disposition table every other rejection goes
/// through.
///
/// [`Rejection::unparseable`]: crate::Rejection::unparseable
///
/// A marshaled frame carries **no correlation id** (§8). Pairing a reply with
/// its in-flight request is the TRANSPORT's, by whatever its own envelope
/// carries — never by the request's [`ReqId`], which is an optional
/// idempotency key ([`Request::id`]) and is absent from most requests.
///
/// [`ReqId`]: crate::ReqId
/// [`Request::id`]: crate::Request::id
pub trait Codec {
    /// wire → `Op` (+ id).
    ///
    /// **The implementer owes the request's SIZE.** M10 measures no field of
    /// the [`Op`] it is handed: `values`, `specs`, `cuts`, `regions`,
    /// `rho1`/`rho2`, `to`, `n`, the shot's `runs` — each run's `origin`,
    /// `i_start` and `width` — and its `base`'s `extent`, and every tumbler's
    /// components and magnitudes reach the owning store as presented. The one
    /// list M10 measures is the EDITLINK successor slot it builds for itself,
    /// against M7's per-slot budget; nothing it RECEIVES is measured. So this
    /// parser is the only bound on how large a request may be, and a costed
    /// frame — a maximal COMPARE, an `insert` whose values outrun the
    /// transaction budget — reaches the store exactly as it arrives.
    ///
    /// AND FOR SOME OPERATIONS, BOUNDING THE REQUEST'S SIZE DOES NOT BOUND
    /// ITS WORK. Three shapes break the correspondence between a frame's size
    /// and its cost, each in its own way, and a transport author should know
    /// them before relying on the paragraph above.
    ///
    /// [`Op::Publish`]'s existence check derives and probes EVERY address of
    /// EVERY by-reference run, stopping only at the first one M4 does not
    /// hold, so the quantity is `Σ min(width, the contiguous stored content
    /// under that run's origin)`. A per-array cap on `runs` is a MULTIPLIER
    /// on that sum rather than a bound on it, and a per-tumbler digit cap
    /// bounds how many digits a `width` is written with, not how far it walks
    /// — one run of eighteen digits outruns any content a store will ever
    /// hold. M5 prices the walk and names this layer as the owner of the
    /// number: `Vstream::publish`'s COST paragraph ends by calling the
    /// by-reference runs' `Σ width` one of "the numbers a route that carries
    /// this op owes". It is spent INSIDE the write transaction, under M2's
    /// applier lock, so it is paid by every other writer in the engine and
    /// not by the caller alone. A parser that means to bound it caps that sum
    /// here; nothing downstream of this door does.
    ///
    /// [`Op::RetrieveV`] delivers one heap item per active V-POSITION of
    /// every run it names, and a document's V-extent is VIRTUAL: M5 caps the
    /// RUNS an arrangement stores (`MAX_PLACED_RUNS`) and caps no position
    /// count, so a `copy` transcluding a document's whole extent onto its own
    /// tail DOUBLES that extent for one request's cost. The quantity is
    /// therefore `Σᵢ |specᵢ's span ∩ the arranged extent|`, set by stored
    /// state a prior request grew geometrically rather than by this request's
    /// size — so a cap on `specs` bounds the MULTIPLIER and leaves the
    /// per-spec term, and a SINGLE spec naming one document is unbounded.
    /// Nor does a response-size cap at marshal close it: M6 materializes the
    /// whole delivery before this trait sees a `Response`, so such a cap
    /// refuses one allocation too late. M6 declines the cap on semantic
    /// grounds — its exactness, per-spec order and no-dedup clauses are what
    /// ASN-0115 specifies — and names this layer: `Query::retrieve_v`'s COST
    /// paragraph ends "the only cap that closes it is a spec-count or
    /// response-size cap on the route, which is M10's as the request
    /// lifecycle's owner". What closes it is a cap on that sum, taken here,
    /// before the first address is expanded.
    ///
    /// The FTT descriptor family ([`Op::FindLinksFtt`] and its two siblings)
    /// has NO FIELD TO CAP. A four-set of `Any` slots constrains nothing M7
    /// can index, so the matcher materializes an address per active link in
    /// the store: the frame is minimal and uniform and its cost is wholly
    /// stored state. M7 and M8 each document and accept that walk, so a
    /// parser is not being asked to refuse it — only to know that for this
    /// shape it has nothing to measure, and that paging does not avoid it,
    /// since every page re-materializes the candidate set. The RESPONSE is
    /// what a transport can still bound: `find_links_ftt` returns the whole
    /// matched set where `window_ftt` pages it.
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
    /// [`Op::Publish`]: crate::Op::Publish
    /// [`Op::RetrieveV`]: crate::Op::RetrieveV
    /// [`Op::FindLinksFtt`]: crate::Op::FindLinksFtt
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
/// of a parse failure, none of which is available to a bare struct. A value
/// besides, with the workspace's value derives: [`Rejection::unparseable`]
/// consumes one, so a transport that also logs its failure needs to keep a
/// copy, and a codec test comparing an observed failure against an expected
/// one needs to compare them.
///
/// [`Rejection::unparseable`]: crate::Rejection::unparseable
#[derive(Debug, Clone, PartialEq, Eq)]
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
