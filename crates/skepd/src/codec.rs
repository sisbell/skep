//! The one concrete [`Codec`]: JSON frames ↔ M10's typed `Request`/`Response`.
//!
//! The wire conventions are a cross-client contract, specified for client
//! authors in `skep/docs/wire.md` and pinned by the tests in
//! `tests/wire_doc.rs` (the doc's examples are asserted, not decorative).
//! The rules the whole file hangs on:
//!
//! * Requests are internally tagged objects (`{"op": "insert", ...}`) with
//!   snake_case op names mirroring `OpKind`; unknown ops and unknown fields
//!   are parse failures, never ignored (the never-silent contract applied to
//!   client typos).
//! * `make_link`'s three endset slots are two-form (wire v5): a V-spec array
//!   (content-resolved, byte-identical to v4 — existing frames mean exactly
//!   what they meant) or
//!   `{"addrs": [addresses…]}` — the names recorded verbatim, no resolution;
//!   the addrs-object encoding is identical to `edit_link`'s successor `ty`
//!   addrs form.
//! * Tumblers and addresses are dotted-decimal strings (`"1.1.0.1.0.2"`);
//!   spans are `{"start": …, "width": …}` objects; unbounded ℕ values ride
//!   as decimal strings (T0 admits magnitudes no JSON number can carry),
//!   with non-negative JSON integers accepted leniently on parse;
//!   machine-bounded values (`Seq`, slots, counts, principal ids) are JSON
//!   numbers.
//! * Content values carry granularity explicitly (wire v2): the per-byte
//!   write forms (`"str"`, `{"hex"}`) mint one single-byte value per byte —
//!   the substrate's text discipline, under which V-span widths measure
//!   exact bytes — while `{"atom"}`/`{"atom_hex"}` mint ONE composite value
//!   whose interior is permanently unaddressable. Deliveries render maximal
//!   per-byte runs as one `content`/`hex` item and every composite value as
//!   its own `atom`/`atom_hex` item, so the marshal is injective across
//!   granularity: two distinct position-value sequences never render alike.
//! * Marshaling is deterministic: every object is built through [`obj`],
//!   which sorts keys, so two marshals of one response are byte-equal and
//!   the canonical form never depends on serde_json's map backend.
//! * Every `Response` variant — every `Rejected` shape included — has a
//!   defined encoding: a client that cannot decode a rejection has been
//!   silently failed.
//!
//! Parsing strings into `skep-address` values goes through M1's validating
//! front doors (`Tumbler::new`, `validate`, `Span::new`), so no malformed
//! address or zero-width span survives the trust boundary.

use std::str::FromStr;

use serde_json::{Map, Value};
use skep_address::{validate, Address, Nat, Span, SpanSet, Tumbler};
use skep_arrangement::{Run, VPos, VSpec};
use skep_content::Val;
use skep_discovery::{FourSet, SlotSpec, SupClaim, Window};
use skep_febe::{
    Codec, Disposition, FaultSite, Op, OpKind, ParseError, RejectCode, Rejection, ReqId, Request,
    Response, SlotArg, SuccessorSpec,
};
use skep_kernel::Seq;
use skep_links::{Endset, Invalid, Link, View, MAX_SLOT_SPANS};
use skep_namespace::PrincipalId;
use skep_retrieval::{CorrPair, Deletions, DeliveryItem, Operand, Region, Spec, SpecFault};

/// The most elements one wire array may carry, applied at [`p_list`] — so
/// every attacker-sized list on the request surface (span regions, spec and
/// region lists, address lists, v-spec lists, `rearrange` cuts, and the
/// query endsets of the ftt family) meets it at one door.
///
/// NOT a round number: it is M7's published per-slot budget
/// ([`MAX_SLOT_SPANS`]), whose argument transfers verbatim. That argument
/// is that a span's LIVE cost is not bounded by the wire bytes that carry
/// it — an address is ~19 wire bytes and the span it becomes is two
/// multi-component `BigUint` tumblers, order half a kilobyte — so a list
/// bounded only by the request body names hundreds of thousands of spans.
/// A QUERY endset is built the same way and then costs more, not less: M8
/// answers the ftt family by scanning the link store and testing every
/// query span against every slot span of every link, so a query's span
/// count multiplies the whole store rather than one stored value.
///
/// Reading the two budgets as one number is the point: a query slot larger
/// than the largest slot that can be STORED cannot discriminate anything a
/// smaller one does not, so the cap costs no expressible question. The
/// refusal rides the ordinary parse channel — an over-cap frame is
/// `unparseable`/`malformed` with the count named, exactly as any other
/// malformed frame is, rather than a new wire vocabulary.
///
/// Applied at [`p_list`], so the cap is per ARRAY. Two ops nest —
/// `compare`'s two operands and `find_docs_containing`'s `regions` are
/// lists of regions, each carrying its own span list — so a frame's TOTAL
/// span count is the product of two caps and is bounded by
/// [`crate::server`]'s request-body cap alone. The budget argument above
/// transfers to one query slot; it does not price a region set, whose cost
/// model is M6's rather than M8's. Anyone raising the body cap for a route
/// that carries these ops owes that number.
const MAX_WIRE_LIST: usize = MAX_SLOT_SPANS;

/// The most values one `insert` frame may mint. Denominated in VALUES and
/// not in wire bytes, because the per-byte write discipline mints one
/// [`Val`] per input byte: each is its own `Arc<[u8]>` allocation — order
/// 32 live bytes after allocator rounding, plus 16 for the fat pointer the
/// vector holds — so the daemon's 8 MiB body cap bounds the request at
/// roughly one part in forty of the allocation it commands. That ratio, not
/// the body size, is what this cap exists to bound.
///
/// The number is M2's transaction budget divided by what one value costs
/// inside it. An `insert` of N values commits 2N + 1 records (a mint and a
/// content write per value, plus one placement), and a content record
/// carries a multi-component address, so a value's encoded share of the
/// transaction runs to order a hundred bytes: [`skep_kernel::MAX_TXN_BYTES`]
/// (64 MiB) therefore admits a few hundred thousand values and no more.
/// Rounding down to a power of two leaves the cap comfortably inside a
/// budget M2 would enforce anyway — the point being WHEN it is enforced.
/// Without this the refusal arrives from M2 after the codec has allocated
/// and M5 has staged; with it, a frame that cannot commit is refused
/// before either.
const MAX_INSERT_VALUES: usize = 1 << 18;

/// The most decimal digits one tumbler component may carry on the wire.
/// M1 leaves component magnitude unbounded (T0(a)) and this does not narrow
/// that: the carrier stays a `BigUint`, and M3 — which owns the one door by
/// which caller-chosen component values enter the permanent name space —
/// records that a magnitude bound, should a deployment want one, "belongs
/// where the codec parses a tumbler". This is that place.
///
/// The budget is the read path's, not storage's. A stored magnitude costs
/// once; a magnitude in a QUERY span is cloned on every comparison M8's
/// scan performs — `classify_spans` derives both operands' endpoints, which
/// copies the start tumbler and computes its reach — so one span carrying a
/// D-digit component costs order D bytes of allocator traffic per link in
/// the store, per query span. That is the amplification a digit cap closes.
///
/// 4096 digits is far above anything the substrate can mint: every ordinal
/// M3 allocates is bounded by the commit count, and every address under a
/// node inherits that node's magnitudes, so a component naming a real
/// entity is a handful of digits. It is chosen to leave the T0(a) carrier
/// visibly unbounded in kind while removing the per-comparison multiplier —
/// a component that would take 10^4000 commits to reach cannot be one a
/// caller needs to name.
const MAX_NAT_DIGITS: usize = 4096;

/// The most components one tumbler may carry on the wire. The same budget
/// as [`MAX_NAT_DIGITS`] on the other axis: a tumbler's components are
/// cloned together on every comparison, so depth multiplies exactly as
/// magnitude does. M3 caps a registered node at 32 components and every
/// other address is a registered parent extended by separators, a subspace
/// identifier and an ordinal — four fields at most — so a deep-node
/// element address is under forty components. 256 leaves that room over
/// several times without admitting a tumbler whose depth is the request's
/// only real content.
const MAX_TUMBLER_COMPONENTS: usize = 256;

/// The most bytes one frame's idempotency `id` may carry. This daemon never
/// interprets the id — but M10 RETAINS it: the idempotency cache is keyed
/// `(SessionId, ReqId)`, so a committed write's key stays resident until its
/// entry is evicted or its session is closed
/// ([`skep_febe::Operation::close_session`] purges exactly one session's
/// entries). Retention is therefore (cache capacity) × (this cap), and with
/// the second factor uncapped the first would be the daemon's 8 MiB body
/// cap: one session's worth of committed writes retains gigabytes that do
/// not clear when the caller stops, unlike every CPU cost on this surface.
///
/// 256 bytes is far above any key a client needs — a UUID is 36 characters,
/// a hex-encoded 256-bit value 64, and this suite's own keys are `"retry-1"`,
/// `"k1"`, `"w17"` — and puts the retained bill at a quarter megabyte
/// against M10's 1024 cache entries, commensurate with the session table's
/// own bounded retention ([`crate::server`]'s `MAX_LIVE_SESSIONS`) rather
/// than four orders above it.
const MAX_REQ_ID_BYTES: usize = 256;

/// The daemon's JSON codec — stateless; one instance serves every client.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    fn parse(&self, frame: &[u8]) -> Result<Request, ParseError> {
        parse_request(frame).map_err(|e| ParseError { detail: Some(e.0) })
    }

    fn marshal(&self, resp: &Response) -> Vec<u8> {
        to_bytes(j_response(resp))
    }
}

impl JsonCodec {
    /// The canonical request encoding — the inverse seam `Codec` itself does
    /// not name (M10 fixes parse only). Clients and the round-trip tests use
    /// it.
    ///
    /// PRECONDITION: `req` is within the wire caps this codec enforces on
    /// parse — [`MAX_WIRE_LIST`] elements per array, [`MAX_INSERT_VALUES`]
    /// minted values per `insert`, [`MAX_NAT_DIGITS`] per tumbler
    /// component, [`MAX_TUMBLER_COMPONENTS`] per tumbler,
    /// [`MAX_REQ_ID_BYTES`] per idempotency id — and carries no zero-byte
    /// `Val`, which [`j_atom`] renders as `{"atom": ""}` and [`p_val_form`]
    /// refuses by design (coarse granularity must be said, and a zero-byte
    /// atom says nothing). Under all of that, `parse(marshal_request(r))`
    /// reproduces `r` and re-marshaling the parse is byte-identical.
    ///
    /// Outside it, marshaling SUCCEEDS and yields a frame `parse` refuses:
    /// this is the parse side's trust-boundary obligation and this direction
    /// does not re-check it (one check, one owner). The upstream value types
    /// admit every violation — `Endset::from_spans` takes any span count,
    /// T0(a) leaves a component's magnitude unbounded by design, and
    /// `Val::new` takes any bytes — so a caller assembling a `Request` by
    /// hand owes the whole precondition. A `Request` this codec produced
    /// satisfies it by construction, which is what makes the round-trip
    /// oracle sound.
    ///
    /// One normalization survives the precondition rather than being
    /// excluded by it: `SlotSpec::Spans` over an EMPTY endset marshals as
    /// `[]`, which [`p_slotspec`] deliberately reads back as
    /// `SlotSpec::Empty` — M8's same constraint under its canonical name. So
    /// for such an `r` the round trip is EQUAL and not identical, and
    /// re-marshaling gives `"empty"`. `parse` cannot mint that value, so a
    /// `Request` this codec produced is again unaffected.
    ///
    /// Wire invariant: a `ReqId` is the UTF-8 bytes of the frame's `id`
    /// string (parse can produce nothing else); an off-wire non-UTF-8 id is
    /// rendered lossily rather than panicking.
    pub fn marshal_request(&self, req: &Request) -> Vec<u8> {
        let (name, mut pairs) = req_pairs(&req.op);
        if let Some(ReqId(bytes)) = &req.id {
            pairs.push(("id", Value::String(String::from_utf8_lossy(bytes).into_owned())));
        }
        pairs.push(("op", Value::String(name.into())));
        to_bytes(obj(pairs))
    }

    /// Parse a frame that arrived already decoded — the `/op-at` envelope
    /// carries its frame as a JSON value, so this is the same parse
    /// [`Codec::parse`] performs, entered one step later. Identical
    /// verdicts: the envelope reader does no parsing of its own beyond
    /// deciding that a non-object `frame` is a transport fault rather than
    /// an operation rejection.
    pub(crate) fn parse_frame(&self, frame: Value) -> Result<Request, ParseError> {
        parse_value(frame).map_err(|e| ParseError { detail: Some(e.0) })
    }

    /// The transport's one never-silent obligation outside M10's dispatch
    /// (M10 §Codec): a frame that failed to parse still gets exactly one
    /// response — the `Unparseable` rejection, built HERE and marshaled like
    /// any other.
    pub fn unparseable(&self, e: ParseError) -> Response {
        Response::Rejected(Rejection {
            op: OpKind::Unparseable,
            code: RejectCode::Malformed,
            disposition: Disposition::Permanent,
            site: None,
            detail: e.detail,
        })
    }
}

/// Serialize a finished `Value` tree — the one place this crate turns a
/// `Value` into bytes, so the proof that it cannot fail is written once and
/// holds everywhere it is used: wire responses, transport-error bodies, the
/// commit stream's event payloads, and the sidecar's own file lines are all
/// trees built HERE, out of [`obj`] and the leaf marshalers, which means
/// string keys only and no foreign `Serialize` impl to fault.
pub(crate) fn to_bytes(v: Value) -> Vec<u8> {
    serde_json::to_vec(&v).expect("serializing a serde_json::Value with string keys cannot fail")
}

/// Build a JSON object with keys sorted — THE determinism device. Every
/// JSON object this crate emits is constructed through it — wire responses,
/// transport-error bodies, the commit stream's event payloads, and the
/// sidecar's own file lines — so canonical output is alphabetical-by-key
/// under any serde_json map backend. The sort is STABLE, which is what
/// makes "the last pair given wins" a fact about duplicate keys rather than
/// an accident of the sort.
pub(crate) fn obj(mut pairs: Vec<(&'static str, Value)>) -> Value {
    pairs.sort_by_key(|&(k, _)| k);
    let mut m = Map::new();
    for (k, v) in pairs {
        m.insert(k.to_string(), v);
    }
    Value::Object(m)
}

// ── parse (wire → Request) ──────────────────────────────────────────────

/// Internal parse fault; becomes `ParseError::detail`.
#[derive(Debug)]
struct PErr(String);

impl std::fmt::Display for PErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

type PResult<T> = Result<T, PErr>;

fn parse_request(frame: &[u8]) -> PResult<Request> {
    let v: Value =
        serde_json::from_slice(frame).map_err(|e| PErr(format!("invalid JSON: {e}")))?;
    parse_value(v)
}

/// The frame grammar over a decoded value — everything past `from_slice`,
/// so a frame that arrives already decoded meets the identical rules.
fn parse_value(v: Value) -> PResult<Request> {
    let Value::Object(m) = v else {
        return Err(PErr("request frame must be a JSON object".into()));
    };
    let mut fields = Fields(m);
    let name = fields.string("op")?;
    // The id is capped where it is minted: M10 retains it for the life of a
    // cached write, so its LENGTH is the second factor in a retention bill
    // nothing downstream bounds (see [`MAX_REQ_ID_BYTES`]).
    let id = match fields.opt_string("id")? {
        None => None,
        Some(s) if s.len() > MAX_REQ_ID_BYTES => {
            return Err(PErr(format!(
                "id is {} bytes, past the {MAX_REQ_ID_BYTES}-byte wire cap",
                s.len()
            )))
        }
        Some(s) => Some(ReqId(s.into_bytes())),
    };
    let op = parse_op(&name, &mut fields)?;
    fields.finish()?;
    Ok(Request { id, op })
}

/// One request-envelope arm per `Op` variant. Field names are the wire
/// contract (wire.md §Operations); the one Rust-name departure is
/// `principal_prefix`, whose argument rides as `"principal"` because the
/// envelope key `"id"` is the idempotency slot.
fn parse_op(name: &str, fields: &mut Fields) -> PResult<Op> {
    Ok(match name {
        "create_new_document" => Op::CreateNewDocument { account: fields.addr("account")? },
        "delegate" => Op::Delegate {
            new_prefix: fields.tum("new_prefix")?,
            new_id: PrincipalId(fields.u64("new_id")?),
        },
        "register_node" => Op::RegisterNode { addr: fields.tum("addr")? },
        "fork" => Op::Fork,
        "next_account_prefix" => Op::NextAccountPrefix { parent: fields.addr("parent")? },
        "principal_prefix" => Op::PrincipalPrefix { id: PrincipalId(fields.u64("principal")?) },
        "insert" => Op::Insert {
            doc: fields.addr("doc")?,
            at: fields.vpos("at")?,
            values: fields.vals("values")?,
        },
        "delete" => Op::Delete {
            doc: fields.addr("doc")?,
            p: fields.vpos("p")?,
            width: fields.nat("width")?,
        },
        "copy" => Op::Copy {
            doc: fields.addr("doc")?,
            at: fields.vpos("at")?,
            specs: fields.vspecs("specs")?,
        },
        "rearrange" => Op::Rearrange { doc: fields.addr("doc")?, cuts: fields.vposes("cuts")? },
        "version" => Op::Version { d_src: fields.addr("d_src")? },
        "make_link" => Op::MakeLink {
            home: fields.addr("home")?,
            from: fields.slotarg("from")?,
            to: fields.slotarg("to")?,
            ty: fields.slotarg("ty")?,
        },
        "emit" => Op::Emit {
            home: fields.addr("home")?,
            ty: fields.endset("ty")?,
            from: fields.addr("from")?,
            to: fields.addrs("to")?,
        },
        "nullify" => Op::Nullify { home: fields.addr("home")?, target: fields.addr("target")? },
        "assert_sup" => Op::AssertSup {
            home: fields.addr("home")?,
            old: fields.addr("old")?,
            new: fields.addr("new")?,
        },
        "edit_link" => Op::EditLink {
            original: fields.addr("original")?,
            successor: fields.successor("successor")?,
            d_s: fields.addr("d_s")?,
            d_a: fields.addr("d_a")?,
        },
        "read_link" => Op::ReadLink { a: fields.addr("a")? },
        "follow_link" => Op::FollowLink { a: fields.addr("a")?, slot: fields.usize("slot")? },
        "retrieve_v" => Op::RetrieveV { specs: fields.specs("specs")? },
        "retrieve_doc_v_span" => Op::RetrieveDocVSpan { doc: fields.addr("doc")? },
        "retrieve_doc_v_span_set" => Op::RetrieveDocVSpanSet { doc: fields.addr("doc")? },
        "show_origin" => Op::ShowOrigin { doc: fields.addr("doc")?, span: fields.span("span")? },
        "show_deletions" => {
            Op::ShowDeletions { d_a: fields.addr("d_a")?, d_b: fields.addr("d_b")? }
        }
        "compare" => Op::Compare { rho1: fields.regions("rho1")?, rho2: fields.regions("rho2")? },
        "find_docs_containing" => Op::FindDocsContaining { regions: fields.regions("regions")? },
        "image" => Op::Image { d: fields.addr("d")?, region: fields.spans("region")? },
        "find_links_v" => Op::FindLinksV { d: fields.addr("d")?, region: fields.spans("region")? },
        "find_links_ftt" => Op::FindLinksFtt { q: fields.fourset("q")? },
        "count_v" => Op::CountV { d: fields.addr("d")?, region: fields.spans("region")? },
        "count_ftt" => Op::CountFtt { q: fields.fourset("q")? },
        "window_v" => Op::WindowV {
            d: fields.addr("d")?,
            region: fields.spans("region")?,
            cur: fields.cursor("cur")?,
            n: fields.usize("n")?,
        },
        "window_ftt" => Op::WindowFtt {
            q: fields.fourset("q")?,
            cur: fields.cursor("cur")?,
            n: fields.usize("n")?,
        },
        "retrieve_endsets" => {
            Op::RetrieveEndsets { d: fields.addr("d")?, region: fields.spans("region")? }
        }
        "project" => Op::Project {
            a: fields.addr("a")?,
            slot: fields.usize("slot")?,
            d: fields.addr("d")?,
        },
        "discoverable_from" => Op::DiscoverableFrom { a: fields.addr("a")?, d: fields.addr("d")? },
        "delete_orphans" => Op::DeleteOrphans {
            d: fields.addr("d")?,
            p: fields.vpos("p")?,
            width: fields.nat("width")?,
        },
        "in_claims" => Op::InClaims { y: fields.addr("y")?, view: fields.view("view")? },
        "out_claims" => Op::OutClaims { x: fields.addr("x")?, view: fields.view("view")? },
        other => return Err(PErr(format!("unknown op '{}'", bounded(other)))),
    })
}

/// The request object being consumed: known fields are taken out; anything
/// left at [`Fields::finish`] is an unknown field and fails the parse.
#[derive(Debug)]
struct Fields(Map<String, Value>);

impl Fields {
    fn take(&mut self, k: &'static str) -> PResult<Value> {
        self.0.remove(k).ok_or_else(|| PErr(format!("missing field '{k}'")))
    }

    /// Absent and explicit `null` are the same absence.
    fn take_opt(&mut self, k: &'static str) -> Option<Value> {
        match self.0.remove(k) {
            None | Some(Value::Null) => None,
            Some(v) => Some(v),
        }
    }

    fn finish(self) -> PResult<()> {
        match self.0.keys().next() {
            Some(k) => Err(PErr(format!("unknown field '{}'", bounded(k)))),
            None => Ok(()),
        }
    }

    fn field<T>(&mut self, k: &'static str, f: impl FnOnce(&Value) -> PResult<T>) -> PResult<T> {
        let v = self.take(k)?;
        f(&v).map_err(|e| PErr(format!("field '{k}': {e}")))
    }

    fn string(&mut self, k: &'static str) -> PResult<String> {
        self.field(k, p_string)
    }

    fn opt_string(&mut self, k: &'static str) -> PResult<Option<String>> {
        match self.take_opt(k) {
            None => Ok(None),
            Some(v) => p_string(&v).map(Some).map_err(|e| PErr(format!("field '{k}': {e}"))),
        }
    }

    fn u64(&mut self, k: &'static str) -> PResult<u64> {
        self.field(k, p_u64)
    }

    fn usize(&mut self, k: &'static str) -> PResult<usize> {
        self.field(k, p_usize)
    }

    fn nat(&mut self, k: &'static str) -> PResult<Nat> {
        self.field(k, p_nat)
    }

    fn tum(&mut self, k: &'static str) -> PResult<Tumbler> {
        self.field(k, p_tum)
    }

    fn addr(&mut self, k: &'static str) -> PResult<Address> {
        self.field(k, p_addr)
    }

    fn addrs(&mut self, k: &'static str) -> PResult<Vec<Address>> {
        self.field(k, |v| p_list(v, p_addr))
    }

    fn span(&mut self, k: &'static str) -> PResult<Span> {
        self.field(k, p_span)
    }

    fn spans(&mut self, k: &'static str) -> PResult<Vec<Span>> {
        self.field(k, |v| p_list(v, p_span))
    }

    fn vpos(&mut self, k: &'static str) -> PResult<VPos> {
        self.field(k, p_vpos)
    }

    fn vposes(&mut self, k: &'static str) -> PResult<Vec<VPos>> {
        self.field(k, |v| p_list(v, p_vpos))
    }

    fn vspecs(&mut self, k: &'static str) -> PResult<Vec<VSpec>> {
        self.field(k, |v| p_list(v, p_vspec))
    }

    fn slotarg(&mut self, k: &'static str) -> PResult<SlotArg> {
        self.field(k, p_slotarg)
    }

    fn specs(&mut self, k: &'static str) -> PResult<Vec<Spec>> {
        self.field(k, |v| p_list(v, p_spec))
    }

    fn regions(&mut self, k: &'static str) -> PResult<Vec<Region>> {
        self.field(k, |v| p_list(v, p_region))
    }

    fn vals(&mut self, k: &'static str) -> PResult<Vec<Val>> {
        self.field(k, p_values)
    }

    fn endset(&mut self, k: &'static str) -> PResult<Endset> {
        self.field(k, p_endset)
    }

    fn view(&mut self, k: &'static str) -> PResult<View> {
        self.field(k, p_view)
    }

    fn fourset(&mut self, k: &'static str) -> PResult<FourSet> {
        self.field(k, p_fourset)
    }

    /// Absent ≡ null ≡ ⊥ (start of the enumeration).
    fn cursor(&mut self, k: &'static str) -> PResult<Option<Address>> {
        match self.take_opt(k) {
            None => Ok(None),
            Some(v) => {
                p_addr(&v).map(Some).map_err(|e| PErr(format!("field '{k}': {e}")))
            }
        }
    }

    fn successor(&mut self, k: &'static str) -> PResult<SuccessorSpec> {
        self.field(k, p_successor)
    }
}

// ── leaf parsers, each through M1's validating constructors ──

/// The offending text, bounded — a refusal must not be a copy of the input
/// it refuses. The wire-supplied strings echoed below are bounded only by
/// the request body, and a parse fault is wrapped by each enclosing field,
/// element and region on the way out, so an unbounded echo is copied once
/// per level and then again into the response.
///
/// The cut is on a CHARACTER boundary: the argument is arbitrary UTF-8 from
/// the wire, and a byte-index slice would panic on one. Applied only where
/// the echoed value is wire-supplied and unbounded; the transport's own
/// echoes (a path, a query parameter, a header line) are already bounded by
/// the request-head cap and are left as they are.
fn bounded(s: &str) -> String {
    const MAX: usize = 64;
    match s.char_indices().nth(MAX) {
        None => s.to_string(),
        Some((i, _)) => format!("{}… ({} bytes)", &s[..i], s.len()),
    }
}

fn p_string(v: &Value) -> PResult<String> {
    v.as_str().map(str::to_owned).ok_or_else(|| PErr("expected a JSON string".into()))
}

fn p_u64(v: &Value) -> PResult<u64> {
    v.as_u64().ok_or_else(|| PErr("expected a non-negative JSON integer".into()))
}

fn p_usize(v: &Value) -> PResult<usize> {
    usize::try_from(p_u64(v)?).map_err(|_| PErr("integer exceeds this platform's usize".into()))
}

/// ℕ: canonical decimal string; a non-negative JSON integer is accepted
/// leniently (canonical output is always the string form).
fn p_nat(v: &Value) -> PResult<Nat> {
    match v {
        Value::Number(_) => p_u64(v).map(Nat::from),
        Value::String(s) => p_nat_str(s),
        _ => Err(PErr("expected a decimal string or non-negative integer".into())),
    }
}

/// One decimal component. The [`MAX_NAT_DIGITS`] refusal comes BEFORE the
/// radix conversion, so a hostile digit run is never converted — the
/// conversion is the expensive half, and refusing after it would pay
/// exactly the cost the cap exists to avoid.
fn p_nat_str(s: &str) -> PResult<Nat> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PErr(format!("'{}' is not a decimal natural", bounded(s))));
    }
    if s.len() > MAX_NAT_DIGITS {
        return Err(PErr(format!(
            "component has {} digits, past the {MAX_NAT_DIGITS}-digit wire cap",
            s.len()
        )));
    }
    Nat::from_str(s).map_err(|e| PErr(format!("'{}': {e}", bounded(s))))
}

/// A dotted-decimal tumbler, depth-capped at [`MAX_TUMBLER_COMPONENTS`]
/// before any component is converted.
fn p_tum(v: &Value) -> PResult<Tumbler> {
    let s = v.as_str().ok_or_else(|| PErr("expected a dotted-decimal string".into()))?;
    let depth = s.split('.').count();
    if depth > MAX_TUMBLER_COMPONENTS {
        return Err(PErr(format!(
            "tumbler has {depth} components, past the \
             {MAX_TUMBLER_COMPONENTS}-component wire cap"
        )));
    }
    let comps = s.split('.').map(p_nat_str).collect::<PResult<Vec<Nat>>>()?;
    Tumbler::new(comps).map_err(|e| PErr(format!("'{}': {e}", bounded(s))))
}

fn p_addr(v: &Value) -> PResult<Address> {
    validate(p_tum(v)?).map_err(|e| PErr(format!("not a T4-valid address: {e}")))
}

/// Guard a sub-object's key set; unknown keys fail like unknown envelope
/// fields do.
fn p_obj<'a>(v: &'a Value, allowed: &[&str]) -> PResult<&'a Map<String, Value>> {
    let m = v.as_object().ok_or_else(|| PErr("expected a JSON object".into()))?;
    check_keys(m, allowed).map_err(PErr)?;
    Ok(m)
}

/// Refuse any key outside `allowed` — THE never-silent device, applied
/// wherever this crate accepts a JSON object: a client's typo is a named
/// failure, never a field quietly ignored. Errors as a bare `String` so the
/// transport envelopes (whose faults are not `ParseError`s) share it.
pub(crate) fn check_keys(m: &Map<String, Value>, allowed: &[&str]) -> Result<(), String> {
    match m.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(k) => Err(format!("unknown field '{}'", bounded(k))),
        None => Ok(()),
    }
}

fn need<'a>(m: &'a Map<String, Value>, k: &'static str) -> PResult<&'a Value> {
    m.get(k).ok_or_else(|| PErr(format!("missing field '{k}'")))
}

fn field<T>(
    m: &Map<String, Value>,
    k: &'static str,
    f: impl FnOnce(&Value) -> PResult<T>,
) -> PResult<T> {
    f(need(m, k)?).map_err(|e| PErr(format!("{k}: {e}")))
}

/// Every list on the request surface, and THE place [`MAX_WIRE_LIST`] is
/// enforced: the elements are counted before any is parsed, so an
/// over-length array is refused without building what it asked for.
fn p_list<T>(v: &Value, f: impl Fn(&Value) -> PResult<T>) -> PResult<Vec<T>> {
    let arr = v.as_array().ok_or_else(|| PErr("expected a JSON array".into()))?;
    if arr.len() > MAX_WIRE_LIST {
        return Err(PErr(format!(
            "array has {} elements, past the {MAX_WIRE_LIST}-element wire cap",
            arr.len()
        )));
    }
    arr.iter()
        .enumerate()
        .map(|(i, x)| f(x).map_err(|e| PErr(format!("[{i}]: {e}"))))
        .collect()
}

fn p_span(v: &Value) -> PResult<Span> {
    let m = p_obj(v, &["start", "width"])?;
    let start = field(m, "start", p_tum)?;
    let width = field(m, "width", p_tum)?;
    Span::new(start, width).map_err(|e| PErr(format!("ill-formed span: {e}")))
}

fn p_vpos(v: &Value) -> PResult<VPos> {
    let m = p_obj(v, &["ordinal", "subspace"])?;
    Ok(VPos { subspace: field(m, "subspace", p_nat)?, ordinal: field(m, "ordinal", p_nat)? })
}

fn p_vspec(v: &Value) -> PResult<VSpec> {
    let m = p_obj(v, &["source", "span"])?;
    Ok(VSpec { source: field(m, "source", p_addr)?, span: field(m, "span", p_span)? })
}

/// A `make_link` endset slot (wire v5): a V-spec array (content-resolved,
/// byte-identical to v4) or `{"addrs": [addresses…]}` — the names
/// recorded verbatim, the same addrs-object encoding as `edit_link`'s
/// successor `ty`.
fn p_slotarg(v: &Value) -> PResult<SlotArg> {
    match v {
        Value::Array(_) => Ok(SlotArg::Resolve(p_list(v, p_vspec)?)),
        Value::Object(_) => {
            let m = p_obj(v, &["addrs"])?;
            Ok(SlotArg::Addrs(field(m, "addrs", |v| p_list(v, p_addr))?))
        }
        _ => Err(PErr("expected a v-spec array or {\"addrs\": [addresses…]}".into())),
    }
}

fn p_spec(v: &Value) -> PResult<Spec> {
    let m = p_obj(v, &["doc", "span"])?;
    Ok(Spec { doc: field(m, "doc", p_addr)?, span: field(m, "span", p_span)? })
}

fn p_region(v: &Value) -> PResult<Region> {
    let m = p_obj(v, &["doc", "spans"])?;
    Ok(Region { doc: field(m, "doc", p_addr)?, spans: field(m, "spans", |v| p_list(v, p_span))? })
}

/// The `values` array of `insert`: each element is one of the four write
/// forms (wire.md §Content values), contributing zero or more values that
/// concatenate in order.
///
/// What bounds the whole array is [`MAX_INSERT_VALUES`], which [`p_val_form`]
/// enforces against this accumulator before each element mints into it — the
/// array's element count bounds nothing on its own, since one per-byte string
/// mints one value per byte.
fn p_values(v: &Value) -> PResult<Vec<Val>> {
    let arr = v.as_array().ok_or_else(|| PErr("expected a JSON array".into()))?;
    let mut out = Vec::new();
    for (i, x) in arr.iter().enumerate() {
        p_val_form(x, &mut out).map_err(|e| PErr(format!("[{i}]: {e}")))?;
    }
    Ok(out)
}

/// Room for what an element is ABOUT to mint — THE place
/// [`MAX_INSERT_VALUES`] is enforced, and enforced ahead of the mint rather
/// than behind it. An element's whole contribution is added in ONE `extend`,
/// so a check that runs once the element has returned has already paid the
/// peak the cap exists to prevent: an 8 MiB per-byte string mints 8.4M
/// [`Val`]s, each its own `Arc` allocation, order 400 MB of live heap, for a
/// frame that is then refused. Asked in VALUES — the unit the cap counts —
/// and measured against the accumulator, so an element's own length is
/// never mistaken for the budget it consumes.
fn room(out: &[Val], adding: usize) -> PResult<()> {
    if out.len().saturating_add(adding) > MAX_INSERT_VALUES {
        return Err(PErr(format!(
            "values mint more than the {MAX_INSERT_VALUES}-value cap on one insert"
        )));
    }
    Ok(())
}

/// The values one hex field will mint, read from the ENCODED text without
/// copying or decoding it, so [`room`] can refuse before either. A
/// non-string field needs no room; `field` below reports its own fault.
fn hex_values(m: &Map<String, Value>, k: &'static str) -> PResult<usize> {
    Ok(need(m, k)?.as_str().map_or(0, |s| s.len() / 2))
}

/// One element of `values`. The per-byte forms (`"str"`, `{"hex"}`) mint one
/// single-byte value per byte — the substrate's text discipline, under which
/// every interior byte stays addressable — and admit the vacuous `""`. The
/// atom forms (`{"atom"}`, `{"atom_hex"}`) mint ONE composite value of all
/// the bytes: coarse granularity must be said, never fallen into; a
/// zero-byte atom is not expressible.
///
/// Every arm asks [`room`] for what it is about to add before it adds it, so
/// an over-budget element mints nothing — and on the hex path is never even
/// decoded. An atom asks for ONE value whatever its byte count, which is
/// what a composite value is.
fn p_val_form(v: &Value, out: &mut Vec<Val>) -> PResult<()> {
    let m = match v {
        Value::String(s) => {
            room(out, s.len())?;
            out.extend(s.bytes().map(|b| Val::new(vec![b])));
            return Ok(());
        }
        Value::Object(_) => p_obj(v, &["atom", "atom_hex", "hex"])?,
        _ => {
            return Err(PErr(
                "expected a string or an object with one of 'hex', 'atom', 'atom_hex'".into(),
            ))
        }
    };
    if m.len() != 1 {
        return Err(PErr("expected exactly one of 'hex', 'atom', or 'atom_hex'".into()));
    }
    if m.contains_key("hex") {
        room(out, hex_values(m, "hex")?)?;
        let bytes = field(m, "hex", |v| p_hex(&p_string(v)?))?;
        out.extend(bytes.into_iter().map(|b| Val::new(vec![b])));
    } else if m.contains_key("atom") {
        room(out, 1)?;
        let s = field(m, "atom", p_string)?;
        if s.is_empty() {
            return Err(PErr("atom: a zero-byte atom is not expressible".into()));
        }
        out.push(Val::new(s.into_bytes()));
    } else {
        room(out, 1)?;
        let bytes = field(m, "atom_hex", |v| p_hex(&p_string(v)?))?;
        if bytes.is_empty() {
            return Err(PErr("atom_hex: a zero-byte atom is not expressible".into()));
        }
        out.push(Val::new(bytes));
    }
    Ok(())
}

fn p_hex(s: &str) -> PResult<Vec<u8>> {
    // The odd-length refusal comes FIRST, because `chunks_exact` below
    // drops a trailing half-byte in silence — exactly the reading this
    // check exists to refuse. (`% 2` and not `is_multiple_of`: the
    // workspace MSRV is 1.85 and that stabilized in 1.87 —
    // clippy::incompatible_msrv.)
    if s.len() % 2 != 0 {
        return Err(PErr("hex string has odd length".into()));
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(hex_digit(pair[0])? * 16 + hex_digit(pair[1])?))
        .collect()
}

fn hex_digit(c: u8) -> PResult<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(PErr(format!("invalid hex digit '{}'", c as char))),
    }
}

fn p_endset(v: &Value) -> PResult<Endset> {
    Ok(Endset::from_spans(p_list(v, p_span)?))
}

fn p_view(v: &Value) -> PResult<View> {
    match v.as_str() {
        Some("audit") => Ok(View::Audit),
        Some("active") => Ok(View::Active),
        Some("default") => Ok(View::Default),
        _ => Err(PErr("expected \"audit\", \"active\", or \"default\"".into())),
    }
}

/// A slot constraint: `"any"` (drops out), `"empty"` (annihilates), or a
/// span array. An empty array IS the empty constraint and normalizes onto
/// `"empty"` — M8 documents the empty endset as exactly that zero.
fn p_slotspec(v: &Value) -> PResult<SlotSpec> {
    match v {
        Value::String(s) if s == "any" => Ok(SlotSpec::Any),
        Value::String(s) if s == "empty" => Ok(SlotSpec::Empty),
        Value::Array(_) => {
            let spans = p_list(v, p_span)?;
            if spans.is_empty() {
                Ok(SlotSpec::Empty)
            } else {
                Ok(SlotSpec::Spans(Endset::from_spans(spans)))
            }
        }
        _ => Err(PErr("expected \"any\", \"empty\", or a span array".into())),
    }
}

fn p_fourset(v: &Value) -> PResult<FourSet> {
    let m = p_obj(v, &["from", "home", "to", "ty"])?;
    Ok(FourSet {
        home: field(m, "home", p_slotspec)?,
        from: field(m, "from", p_slotspec)?,
        to: field(m, "to", p_slotspec)?,
        ty: field(m, "ty", p_slotspec)?,
    })
}

/// EditLink's successor: content V-specs for from/to; the type slot is
/// exactly one of `{"addrs": […]}` (address-denoting — the identical
/// encoding of `make_link`'s addrs form) or `{"resolve": […]}`
/// (content-resolved), mirroring M10's `SlotArg`.
fn p_successor(v: &Value) -> PResult<SuccessorSpec> {
    let m = p_obj(v, &["from", "to", "ty"])?;
    Ok(SuccessorSpec {
        from: field(m, "from", |v| p_list(v, p_vspec))?,
        to: field(m, "to", |v| p_list(v, p_vspec))?,
        ty: field(m, "ty", p_successor_ty)?,
    })
}

fn p_successor_ty(v: &Value) -> PResult<SlotArg> {
    let m = p_obj(v, &["addrs", "resolve"])?;
    match (m.get("addrs"), m.get("resolve")) {
        (Some(a), None) => {
            Ok(SlotArg::Addrs(p_list(a, p_addr).map_err(|e| PErr(format!("addrs: {e}")))?))
        }
        (None, Some(r)) => {
            Ok(SlotArg::Resolve(p_list(r, p_vspec).map_err(|e| PErr(format!("resolve: {e}")))?))
        }
        _ => Err(PErr("expected exactly one of 'addrs' or 'resolve'".into())),
    }
}

// ── marshal (Request → wire, the canonical inverse) ──────────────────────

/// One arm per `Op` variant; the name comes from the SAME [`op_name`] table
/// the rejection marshal uses, so the two directions cannot drift.
fn req_pairs(op: &Op) -> (&'static str, Vec<(&'static str, Value)>) {
    match op {
        Op::CreateNewDocument { account } => {
            (op_name(OpKind::CreateNewDocument), vec![("account", j_addr(account))])
        }
        Op::Delegate { new_prefix, new_id } => (
            op_name(OpKind::Delegate),
            vec![("new_prefix", j_tum(new_prefix)), ("new_id", j_u64(new_id.0))],
        ),
        Op::RegisterNode { addr } => (op_name(OpKind::RegisterNode), vec![("addr", j_tum(addr))]),
        Op::Fork => (op_name(OpKind::Fork), vec![]),
        Op::NextAccountPrefix { parent } => {
            (op_name(OpKind::NextAccountPrefix), vec![("parent", j_addr(parent))])
        }
        Op::PrincipalPrefix { id } => {
            (op_name(OpKind::PrincipalPrefix), vec![("principal", j_u64(id.0))])
        }
        Op::Insert { doc, at, values } => (
            op_name(OpKind::Insert),
            vec![("doc", j_addr(doc)), ("at", j_vpos(at)), ("values", j_values(values))],
        ),
        Op::Delete { doc, p, width } => (
            op_name(OpKind::Delete),
            vec![("doc", j_addr(doc)), ("p", j_vpos(p)), ("width", j_nat(width))],
        ),
        Op::Copy { doc, at, specs } => (
            op_name(OpKind::Copy),
            vec![("doc", j_addr(doc)), ("at", j_vpos(at)), ("specs", j_vspecs(specs))],
        ),
        Op::Rearrange { doc, cuts } => {
            (op_name(OpKind::Rearrange), vec![("doc", j_addr(doc)), ("cuts", j_vposes(cuts))])
        }
        Op::Version { d_src } => (op_name(OpKind::Version), vec![("d_src", j_addr(d_src))]),
        Op::MakeLink { home, from, to, ty } => (
            op_name(OpKind::MakeLink),
            vec![
                ("home", j_addr(home)),
                ("from", j_slotarg(from)),
                ("to", j_slotarg(to)),
                ("ty", j_slotarg(ty)),
            ],
        ),
        Op::Emit { home, ty, from, to } => (
            op_name(OpKind::Emit),
            vec![
                ("home", j_addr(home)),
                ("ty", j_endset(ty)),
                ("from", j_addr(from)),
                ("to", j_addrs(to)),
            ],
        ),
        Op::Nullify { home, target } => (
            op_name(OpKind::Nullify),
            vec![("home", j_addr(home)), ("target", j_addr(target))],
        ),
        Op::AssertSup { home, old, new } => (
            op_name(OpKind::AssertSup),
            vec![("home", j_addr(home)), ("old", j_addr(old)), ("new", j_addr(new))],
        ),
        Op::EditLink { original, successor, d_s, d_a } => (
            op_name(OpKind::EditLink),
            vec![
                ("original", j_addr(original)),
                ("successor", j_successor(successor)),
                ("d_s", j_addr(d_s)),
                ("d_a", j_addr(d_a)),
            ],
        ),
        Op::ReadLink { a } => (op_name(OpKind::ReadLink), vec![("a", j_addr(a))]),
        Op::FollowLink { a, slot } => {
            (op_name(OpKind::FollowLink), vec![("a", j_addr(a)), ("slot", j_usize(*slot))])
        }
        Op::RetrieveV { specs } => (op_name(OpKind::RetrieveV), vec![("specs", j_specs(specs))]),
        Op::RetrieveDocVSpan { doc } => {
            (op_name(OpKind::RetrieveDocVSpan), vec![("doc", j_addr(doc))])
        }
        Op::RetrieveDocVSpanSet { doc } => {
            (op_name(OpKind::RetrieveDocVSpanSet), vec![("doc", j_addr(doc))])
        }
        Op::ShowOrigin { doc, span } => {
            (op_name(OpKind::ShowOrigin), vec![("doc", j_addr(doc)), ("span", j_span(span))])
        }
        Op::ShowDeletions { d_a, d_b } => {
            (op_name(OpKind::ShowDeletions), vec![("d_a", j_addr(d_a)), ("d_b", j_addr(d_b))])
        }
        Op::Compare { rho1, rho2 } => (
            op_name(OpKind::Compare),
            vec![("rho1", j_regions(rho1)), ("rho2", j_regions(rho2))],
        ),
        Op::FindDocsContaining { regions } => {
            (op_name(OpKind::FindDocsContaining), vec![("regions", j_regions(regions))])
        }
        Op::Image { d, region } => {
            (op_name(OpKind::Image), vec![("d", j_addr(d)), ("region", j_spans(region))])
        }
        Op::FindLinksV { d, region } => (
            op_name(OpKind::FindLinksV),
            vec![("d", j_addr(d)), ("region", j_spans(region))],
        ),
        Op::FindLinksFtt { q } => (op_name(OpKind::FindLinksFtt), vec![("q", j_fourset(q))]),
        Op::CountV { d, region } => {
            (op_name(OpKind::CountV), vec![("d", j_addr(d)), ("region", j_spans(region))])
        }
        Op::CountFtt { q } => (op_name(OpKind::CountFtt), vec![("q", j_fourset(q))]),
        Op::WindowV { d, region, cur, n } => (
            op_name(OpKind::WindowV),
            vec![
                ("d", j_addr(d)),
                ("region", j_spans(region)),
                ("cur", j_cursor(cur)),
                ("n", j_usize(*n)),
            ],
        ),
        Op::WindowFtt { q, cur, n } => (
            op_name(OpKind::WindowFtt),
            vec![("q", j_fourset(q)), ("cur", j_cursor(cur)), ("n", j_usize(*n))],
        ),
        Op::RetrieveEndsets { d, region } => (
            op_name(OpKind::RetrieveEndsets),
            vec![("d", j_addr(d)), ("region", j_spans(region))],
        ),
        Op::Project { a, slot, d } => (
            op_name(OpKind::Project),
            vec![("a", j_addr(a)), ("slot", j_usize(*slot)), ("d", j_addr(d))],
        ),
        Op::DiscoverableFrom { a, d } => {
            (op_name(OpKind::DiscoverableFrom), vec![("a", j_addr(a)), ("d", j_addr(d))])
        }
        Op::DeleteOrphans { d, p, width } => (
            op_name(OpKind::DeleteOrphans),
            vec![("d", j_addr(d)), ("p", j_vpos(p)), ("width", j_nat(width))],
        ),
        Op::InClaims { y, view } => {
            (op_name(OpKind::InClaims), vec![("y", j_addr(y)), ("view", j_view(*view))])
        }
        Op::OutClaims { x, view } => {
            (op_name(OpKind::OutClaims), vec![("x", j_addr(x)), ("view", j_view(*view))])
        }
    }
}

// ── marshal (Response → wire) ────────────────────────────────────────────

fn j_response(r: &Response) -> Value {
    let (name, mut pairs): (&'static str, Vec<(&'static str, Value)>) = match r {
        Response::Ack { at } => ("ack", vec![("at", j_seq(*at))]),
        Response::AckAddr { addr, at } => {
            ("ack_addr", vec![("addr", j_addr(addr)), ("at", j_seq(*at))])
        }
        Response::AckEdit { successor, claim, at } => (
            "ack_edit",
            vec![("successor", j_addr(successor)), ("claim", j_addr(claim)), ("at", j_seq(*at))],
        ),
        Response::Delivery { items, as_of } => {
            ("delivery", vec![("items", j_items(&items.0)), ("as_of", j_seq(*as_of))])
        }
        Response::SpanSet { set, as_of } => {
            ("span_set", vec![("set", j_spanset(set)), ("as_of", j_seq(*as_of))])
        }
        Response::Addrs { addrs, as_of } => {
            ("addrs", vec![("addrs", j_addrs(addrs)), ("as_of", j_seq(*as_of))])
        }
        // The payload option: always present, null = absent/ineligible.
        Response::MaybeAddr { addr, as_of } => (
            "maybe_addr",
            vec![
                ("addr", addr.as_ref().map(j_addr).unwrap_or(Value::Null)),
                ("as_of", j_seq(*as_of)),
            ],
        ),
        Response::Count { n, as_of } => {
            ("count", vec![("n", j_usize(*n)), ("as_of", j_seq(*as_of))])
        }
        Response::Page { window, as_of } => {
            ("page", vec![("window", j_window(window)), ("as_of", j_seq(*as_of))])
        }
        Response::Endsets { pairs: ps, as_of } => {
            ("endsets", vec![("pairs", j_endset_pairs(ps)), ("as_of", j_seq(*as_of))])
        }
        Response::Runs { runs, as_of } => {
            ("runs", vec![("runs", j_runs(runs)), ("as_of", j_seq(*as_of))])
        }
        Response::Bool { val, as_of } => {
            ("bool", vec![("val", Value::Bool(*val)), ("as_of", j_seq(*as_of))])
        }
        // The payload option: null = ⊥ (no link at that address).
        Response::LinkValue { link, as_of } => (
            "link_value",
            vec![
                ("link", link.as_ref().map(j_link).unwrap_or(Value::Null)),
                ("as_of", j_seq(*as_of)),
            ],
        ),
        Response::Follow { result, as_of } => {
            ("follow", vec![("result", j_follow_result(result)), ("as_of", j_seq(*as_of))])
        }
        Response::Deletions { rep, as_of } => {
            ("deletions", vec![("rep", j_deletions(rep)), ("as_of", j_seq(*as_of))])
        }
        Response::Compare { rep, as_of } => {
            ("compare", vec![("pairs", j_corrs(&rep.0)), ("as_of", j_seq(*as_of))])
        }
        Response::Orphans { report, as_of } => (
            "orphans",
            vec![("orphaned", j_addrs(&report.orphaned)), ("as_of", j_seq(*as_of))],
        ),
        Response::Claims { claims, as_of } => {
            ("claims", vec![("claims", j_claims(claims)), ("as_of", j_seq(*as_of))])
        }
        Response::Rejected(rej) => return j_rejection(rej),
    };
    pairs.push(("resp", Value::String(name.into())));
    obj(pairs)
}

fn j_rejection(rej: &Rejection) -> Value {
    let mut pairs = vec![
        ("resp", Value::String("rejected".into())),
        ("op", Value::String(op_name(rej.op).into())),
        ("code", Value::String(code_name(rej.code).into())),
        ("disposition", Value::String(disposition_name(rej.disposition).into())),
    ];
    // Diagnostic options are omitted when absent (payload options are null).
    if let Some(site) = &rej.site {
        pairs.push(("site", j_site(site)));
    }
    if let Some(d) = &rej.detail {
        pairs.push(("detail", Value::String(d.clone())));
    }
    obj(pairs)
}

fn j_site(s: &FaultSite) -> Value {
    let mut pairs: Vec<(&'static str, Value)> = Vec::new();
    if let Some(o) = s.operand {
        let name = match o {
            Operand::First => "first",
            Operand::Second => "second",
        };
        pairs.push(("operand", Value::String(name.into())));
    }
    if let Some(r) = s.region {
        pairs.push(("region", j_usize(r)));
    }
    if let Some(i) = s.index {
        pairs.push(("index", j_usize(i)));
    }
    if let Some(f) = s.fault {
        pairs.push(("fault", Value::String(fault_name(f).into())));
    }
    if let Some(a) = &s.addr {
        pairs.push(("addr", j_addr(a)));
    }
    obj(pairs)
}

// ── leaf marshalers ──

fn j_seq(s: Seq) -> Value {
    j_u64(s.0)
}

fn j_u64(n: u64) -> Value {
    Value::Number(n.into())
}

fn j_usize(n: usize) -> Value {
    j_u64(n as u64)
}

fn j_nat(n: &Nat) -> Value {
    Value::String(n.to_string())
}

/// Dotted-decimal, zeros explicit, components canonical decimal — M1's own
/// `Display`, so the wire form and a tumbler's canonical text are ONE
/// rendering rather than two that must be kept equal. (The conformance
/// goldens read the same encoding.)
fn j_tum(t: &Tumbler) -> Value {
    Value::String(t.to_string())
}

fn j_addr(a: &Address) -> Value {
    j_tum(a.tumbler())
}

fn j_addrs(addrs: &[Address]) -> Value {
    Value::Array(addrs.iter().map(j_addr).collect())
}

fn j_span(s: &Span) -> Value {
    obj(vec![("start", j_tum(s.start())), ("width", j_tum(s.width()))])
}

fn j_spans(spans: &[Span]) -> Value {
    Value::Array(spans.iter().map(j_span).collect())
}

fn j_spanset(s: &SpanSet) -> Value {
    Value::Array(s.iter().map(j_span).collect())
}

fn j_endset(e: &Endset) -> Value {
    Value::Array(e.spans().map(j_span).collect())
}

fn j_vpos(u: &VPos) -> Value {
    obj(vec![("subspace", j_nat(&u.subspace)), ("ordinal", j_nat(&u.ordinal))])
}

fn j_vposes(us: &[VPos]) -> Value {
    Value::Array(us.iter().map(j_vpos).collect())
}

fn j_vspec(v: &VSpec) -> Value {
    obj(vec![("source", j_addr(&v.source)), ("span", j_span(&v.span))])
}

fn j_vspecs(vs: &[VSpec]) -> Value {
    Value::Array(vs.iter().map(j_vspec).collect())
}

/// [`p_slotarg`]'s inverse: the Resolve form is the bare v-spec array
/// (byte-identical to v4), the Addrs form the tagged object.
fn j_slotarg(s: &SlotArg) -> Value {
    match s {
        SlotArg::Resolve(v) => j_vspecs(v),
        SlotArg::Addrs(a) => obj(vec![("addrs", j_addrs(a))]),
    }
}

fn j_spec(s: &Spec) -> Value {
    obj(vec![("doc", j_addr(&s.doc)), ("span", j_span(&s.span))])
}

fn j_specs(ss: &[Spec]) -> Value {
    Value::Array(ss.iter().map(j_spec).collect())
}

fn j_region(r: &Region) -> Value {
    obj(vec![("doc", j_addr(&r.doc)), ("spans", j_spans(&r.spans))])
}

fn j_regions(rs: &[Region]) -> Value {
    Value::Array(rs.iter().map(j_region).collect())
}

/// The canonical rendering of a position-value sequence into wire items —
/// a request's `values` array or a delivery's `items` array — and the one
/// place its rule lives: consecutive single-byte values accumulate into a
/// run rendered as ONE item (UTF-8 judged on the whole run, else
/// `{"hex"}`); a composite value flushes the run and renders as its own
/// atom item, never coalesced with a neighbor. Maximal runs are what make
/// the rendering injective — two distinct position-value sequences never
/// render alike — and what re-canonicalize the parse-side normalizations
/// (element boundaries between adjacent per-byte forms, one-byte atoms),
/// so `parse(marshal_request(r))` reproduces `r`.
///
/// `utf8` is the ONLY thing the two renderings differ by: a request
/// `values` element is the bare string, a delivery item is
/// `{"content": …}`.
#[derive(Debug)]
struct ValueItems {
    out: Vec<Value>,
    byte_run: Vec<u8>,
    utf8: fn(String) -> Value,
}

impl ValueItems {
    fn new(utf8: fn(String) -> Value) -> ValueItems {
        ValueItems { out: Vec::new(), byte_run: Vec::new(), utf8 }
    }

    /// One position's value: a single-byte value joins the pending run, a
    /// composite one breaks it and becomes its own atom item.
    fn value(&mut self, v: &Val) {
        if let [b] = v.as_bytes() {
            self.byte_run.push(*b);
        } else {
            self.flush();
            self.out.push(j_atom(v));
        }
    }

    /// A rendered item that is not a content value (a delivery `{"ref"}`):
    /// it breaks the run, since a run is consecutive by definition.
    fn item(&mut self, v: Value) {
        self.flush();
        self.out.push(v);
    }

    /// Emit the pending run, if any: `utf8`'s form when the whole run
    /// decodes, else `{"hex"}` over its raw bytes.
    fn flush(&mut self) {
        if self.byte_run.is_empty() {
            return;
        }
        let item = match String::from_utf8(std::mem::take(&mut self.byte_run)) {
            Ok(s) => (self.utf8)(s),
            Err(e) => obj(vec![("hex", Value::String(hex_string(e.as_bytes())))]),
        };
        self.out.push(item);
    }

    fn finish(mut self) -> Value {
        self.flush();
        Value::Array(self.out)
    }
}

/// The canonical `values` encoding — [`p_values`]'s inverse, under
/// [`ValueItems`]' rule with the bare-string run form.
fn j_values(vs: &[Val]) -> Value {
    let mut out = ValueItems::new(Value::String);
    for v in vs {
        out.value(v);
    }
    out.finish()
}

/// One composite value as its atom item: `{"atom"}` when its bytes are
/// UTF-8, else `{"atom_hex"}` — exactly one value per item, never coalesced
/// with its neighbors.
fn j_atom(v: &Val) -> Value {
    match std::str::from_utf8(v.as_bytes()) {
        Ok(s) => obj(vec![("atom", Value::String(s.to_owned()))]),
        Err(_) => obj(vec![("atom_hex", Value::String(hex_string(v.as_bytes())))]),
    }
}

/// Lowercase hex — the encoding behind `{"hex"}`, `{"atom_hex"}`, and the
/// fuzz harness's reproduction form, so all three read the same bytes back.
/// `pub` because [`crate::fuzz_support`] re-exports it as its `hex`: this
/// module is private, so that re-export stays the only public path to it.
pub fn hex_string(b: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &byte in b {
        s.push(DIGITS[(byte >> 4) as usize] as char);
        s.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    s
}

fn j_view(v: View) -> Value {
    Value::String(
        match v {
            View::Audit => "audit",
            View::Active => "active",
            View::Default => "default",
        }
        .into(),
    )
}

fn j_slotspec(s: &SlotSpec) -> Value {
    match s {
        SlotSpec::Any => Value::String("any".into()),
        SlotSpec::Empty => Value::String("empty".into()),
        SlotSpec::Spans(e) => j_endset(e),
    }
}

fn j_fourset(q: &FourSet) -> Value {
    obj(vec![
        ("home", j_slotspec(&q.home)),
        ("from", j_slotspec(&q.from)),
        ("to", j_slotspec(&q.to)),
        ("ty", j_slotspec(&q.ty)),
    ])
}

fn j_cursor(c: &Option<Address>) -> Value {
    c.as_ref().map(j_addr).unwrap_or(Value::Null)
}

fn j_window(w: &Window) -> Value {
    obj(vec![
        ("batch", j_addrs(&w.batch)),
        ("next", j_cursor(&w.next)),
        ("exhausted", Value::Bool(w.exhausted)),
    ])
}

/// Delivery items — [`ValueItems`]' rule with the `{"content"}` run form,
/// plus link positions as `{"ref"}`. The item key names the granularity, so
/// a client always knows which world it is looking at.
fn j_items(items: &[DeliveryItem]) -> Value {
    let mut out = ValueItems::new(|s| obj(vec![("content", Value::String(s))]));
    for it in items {
        match it {
            DeliveryItem::Content(v) => out.value(v),
            DeliveryItem::Ref(a) => out.item(obj(vec![("ref", j_addr(a))])),
        }
    }
    out.finish()
}

/// Positional slots, 1-based on the wire as in M7 (slot 1 = FROM, 2 = TO,
/// 3 = TYPE).
fn j_link(l: &Link) -> Value {
    let slots: Vec<Value> = (1..=l.arity())
        .map(|i| j_endset(l.slot(i).expect("1..=arity is in range by Link::slot's contract")))
        .collect();
    obj(vec![("slots", Value::Array(slots))])
}

fn j_run(r: &Run) -> Value {
    obj(vec![("i_start", j_addr(r.i_start())), ("width", j_nat(r.width()))])
}

fn j_runs(rs: &[Run]) -> Value {
    Value::Array(rs.iter().map(j_run).collect())
}

fn j_corr(p: &CorrPair) -> Value {
    obj(vec![
        ("d1", j_addr(&p.d1)),
        ("u1", j_vpos(&p.u1)),
        ("d2", j_addr(&p.d2)),
        ("u2", j_vpos(&p.u2)),
        ("width", j_nat(&p.width)),
    ])
}

fn j_corrs(ps: &[CorrPair]) -> Value {
    Value::Array(ps.iter().map(j_corr).collect())
}

fn j_claim(c: &SupClaim) -> Value {
    obj(vec![
        ("claim", j_addr(&c.claim)),
        ("old", j_addr(&c.old)),
        ("new", j_addr(&c.new)),
        ("home", j_addr(&c.home)),
        ("active", Value::Bool(c.active)),
    ])
}

fn j_claims(cs: &[SupClaim]) -> Value {
    Value::Array(cs.iter().map(j_claim).collect())
}

/// One `retrieve_endsets` pair: the 1-based slot and its endset.
fn j_endset_pair(slot: usize, e: &Endset) -> Value {
    obj(vec![("slot", j_usize(slot)), ("endset", j_endset(e))])
}

fn j_endset_pairs(ps: &[(usize, Endset)]) -> Value {
    Value::Array(ps.iter().map(|(slot, e)| j_endset_pair(*slot, e)).collect())
}

/// SHOWDELETIONS' two directions, each an address list.
fn j_deletions(d: &Deletions) -> Value {
    obj(vec![("a_with_b", j_addrs(&d.a_with_b)), ("b_with_a", j_addrs(&d.b_with_a))])
}

/// FOLLOWLINK's in-band `Result`: the empty span set is a defined answer,
/// so ⟨⟩ and ⊥ are distinct wire shapes rather than one nullable field.
fn j_follow_result(r: &Result<SpanSet, Invalid>) -> Value {
    match r {
        Ok(set) => obj(vec![("ok", j_spanset(set))]),
        Err(_) => obj(vec![("err", Value::String("invalid".into()))]),
    }
}

fn j_successor(s: &SuccessorSpec) -> Value {
    obj(vec![
        ("from", j_vspecs(&s.from)),
        ("to", j_vspecs(&s.to)),
        ("ty", j_successor_ty(&s.ty)),
    ])
}

fn j_successor_ty(t: &SlotArg) -> Value {
    match t {
        SlotArg::Addrs(a) => obj(vec![("addrs", j_addrs(a))]),
        SlotArg::Resolve(v) => obj(vec![("resolve", j_vspecs(v))]),
    }
}

// ── the two name tables (marshal-side; parse mirrors op_name) ──

/// snake_case of the `OpKind` variant name — the request tag AND the
/// rejection's `op` field, one table for both.
pub(crate) fn op_name(k: OpKind) -> &'static str {
    match k {
        OpKind::CreateNewDocument => "create_new_document",
        OpKind::Delegate => "delegate",
        OpKind::RegisterNode => "register_node",
        OpKind::Fork => "fork",
        OpKind::NextAccountPrefix => "next_account_prefix",
        OpKind::PrincipalPrefix => "principal_prefix",
        OpKind::Insert => "insert",
        OpKind::Delete => "delete",
        OpKind::Copy => "copy",
        OpKind::Rearrange => "rearrange",
        OpKind::Version => "version",
        OpKind::MakeLink => "make_link",
        OpKind::Emit => "emit",
        OpKind::Nullify => "nullify",
        OpKind::AssertSup => "assert_sup",
        OpKind::EditLink => "edit_link",
        OpKind::ReadLink => "read_link",
        OpKind::FollowLink => "follow_link",
        OpKind::RetrieveV => "retrieve_v",
        OpKind::RetrieveDocVSpan => "retrieve_doc_v_span",
        OpKind::RetrieveDocVSpanSet => "retrieve_doc_v_span_set",
        OpKind::ShowOrigin => "show_origin",
        OpKind::ShowDeletions => "show_deletions",
        OpKind::Compare => "compare",
        OpKind::FindDocsContaining => "find_docs_containing",
        OpKind::Image => "image",
        OpKind::FindLinksV => "find_links_v",
        OpKind::FindLinksFtt => "find_links_ftt",
        OpKind::CountV => "count_v",
        OpKind::CountFtt => "count_ftt",
        OpKind::WindowV => "window_v",
        OpKind::WindowFtt => "window_ftt",
        OpKind::RetrieveEndsets => "retrieve_endsets",
        OpKind::Project => "project",
        OpKind::DiscoverableFrom => "discoverable_from",
        OpKind::DeleteOrphans => "delete_orphans",
        OpKind::InClaims => "in_claims",
        OpKind::OutClaims => "out_claims",
        OpKind::Unparseable => "unparseable",
    }
}

fn disposition_name(d: Disposition) -> &'static str {
    match d {
        Disposition::Permanent => "permanent",
        Disposition::Reorder => "reorder",
        Disposition::Retry => "retry",
        Disposition::Halt => "halt",
    }
}

fn fault_name(f: SpecFault) -> &'static str {
    match f {
        SpecFault::NotOrdinalLevel => "not_ordinal_level",
        SpecFault::NotLevelUniform => "not_level_uniform",
        SpecFault::StartNotZeroFree => "start_not_zero_free",
        SpecFault::StartTooShallow => "start_too_shallow",
    }
}

/// snake_case of every `RejectCode` variant — exhaustive, so a new code
/// cannot ship without a wire name.
fn code_name(c: RejectCode) -> &'static str {
    match c {
        RejectCode::Unauthenticated => "unauthenticated",
        RejectCode::Malformed => "malformed",
        RejectCode::Durability => "durability",
        RejectCode::TxnOverBudget => "txn_over_budget",
        RejectCode::Poisoned => "poisoned",
        RejectCode::HomeNotRegistered => "home_not_registered",
        RejectCode::DocNotRegistered => "doc_not_registered",
        RejectCode::SourceNotRegistered => "source_not_registered",
        RejectCode::ParentNotRegistered => "parent_not_registered",
        RejectCode::NotRegistered => "not_registered",
        RejectCode::OriginalNotResident => "original_not_resident",
        RejectCode::EndpointNotResident => "endpoint_not_resident",
        RejectCode::NotOwner => "not_owner",
        RejectCode::NotAnAccount => "not_an_account",
        RejectCode::Gate => "gate",
        RejectCode::DelegatorUnknown => "delegator_unknown",
        RejectCode::DuplicateId => "duplicate_id",
        RejectCode::NotAncestor => "not_ancestor",
        RejectCode::NotAuthorized => "not_authorized",
        RejectCode::NotAccountTier => "not_account_tier",
        RejectCode::NotTopDown => "not_top_down",
        RejectCode::NotNextForm => "not_next_form",
        RejectCode::NotValid => "not_valid",
        RejectCode::NotNode => "not_node",
        RejectCode::TooDeep => "too_deep",
        RejectCode::NotDescendantOfBootstrap => "not_descendant_of_bootstrap",
        RejectCode::NotFresh => "not_fresh",
        RejectCode::BadPosition => "bad_position",
        RejectCode::EmptyContent => "empty_content",
        RejectCode::Content => "content",
        RejectCode::EmptySource => "empty_source",
        RejectCode::BadSpan => "bad_span",
        RejectCode::DanglingSource => "dangling_source",
        RejectCode::EmptyResult => "empty_result",
        RejectCode::NotArranged => "not_arranged",
        RejectCode::OutOfBounds => "out_of_bounds",
        RejectCode::EmptyWidth => "empty_width",
        RejectCode::BadCutCount => "bad_cut_count",
        RejectCode::NotAscending => "not_ascending",
        RejectCode::EmptyContentSubspace => "empty_content_subspace",
        RejectCode::NotAPrincipal => "not_a_principal",
        RejectCode::NodeTierCrossOwner => "node_tier_cross_owner",
        RejectCode::NotHomeLink => "not_home_link",
        RejectCode::AlreadySeated => "already_seated",
        RejectCode::NotContentSubspace => "not_content_subspace",
        RejectCode::IllFormedSpec => "ill_formed_spec",
        RejectCode::SlotTooLarge => "slot_too_large",
        RejectCode::EmptyTypeResolution => "empty_type_resolution",
        RejectCode::ShapeViolation => "shape_violation",
        RejectCode::RetractionClass => "retraction_class",
        RejectCode::NonAddressDenotingType => "non_address_denoting_type",
        RejectCode::BadTarget => "bad_target",
        RejectCode::SelfSupersession => "self_supersession",
        RejectCode::IllFormedSuccessor => "ill_formed_successor",
        RejectCode::DcViolation => "dc_violation",
        RejectCode::NoSuchSubspace => "no_such_subspace",
        RejectCode::EmptySubspace => "empty_subspace",
        RejectCode::DepthIncompatible => "depth_incompatible",
        RejectCode::RangeNotPresent => "range_not_present",
        RejectCode::MalformedSpan => "malformed_span",
        RejectCode::NotALink => "not_a_link",
        RejectCode::BadRegion => "bad_region",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Leaf strictness: the dotted-decimal grammar admits exactly nonempty
    /// runs of digits joined by single dots. Magnitude is unbounded in kind
    /// — the carrier is a `BigUint` and a beyond-u64 component round-trips —
    /// with only the wire ENCODING capped (see
    /// [`tumbler_digit_and_depth_caps_admit_their_maximum`]).
    #[test]
    fn only_dot_joined_digit_runs_parse_as_tumblers() {
        let ok = p_tum(&Value::String("1.0.1".into())).map(|t| t.to_string());
        assert_eq!(ok.expect("'1.0.1' parses"), "1.0.1");
        // Beyond u64: parses through the BigUint path and renders back.
        let big = "18446744073709551616"; // 2^64
        let t = p_tum(&Value::String(big.into())).expect("a beyond-u64 component parses");
        assert_eq!(t.to_string(), big);
        for bad in ["", ".", "1..2", "1.", ".1", "1.-2", "1.+2", "1.a", "1 .2"] {
            assert!(p_tum(&Value::String(bad.into())).is_err(), "'{bad}' must not parse");
        }
    }

    /// A refusal names the offending text without copying it: the echoed
    /// value is wire-supplied and bounded only by the request body, and it
    /// is copied again by every field, element and region wrapper on the way
    /// out, so an unbounded echo makes a malformed frame cost a multiple of
    /// itself. The multi-byte case is the load-bearing one — the cut is on a
    /// character boundary, and a byte-index slice would panic here.
    #[test]
    fn a_refusal_names_the_offending_text_without_copying_it() {
        let long = "é".repeat(4096); // not digits, and not ASCII
        let e = p_tum(&Value::String(long.clone())).expect_err("not a dotted decimal");
        assert!(e.0.len() < 300, "the refusal is bounded, not a copy of the input: {}", e.0.len());
        assert!(e.0.contains("ééé"), "and still shows what it refused: {e}");
        assert!(e.0.contains(&long.len().to_string()), "naming the length it elided: {e}");
        // Short values are shown whole, so ordinary diagnostics are intact.
        let e = p_tum(&Value::String("1.a".into())).expect_err("not a decimal natural");
        assert!(e.0.contains("'a'"), "a short value is named in full: {e}");
    }

    /// Both ends of both tumbler wire caps. A component's digit run and a
    /// tumbler's depth each multiply against the whole link store on the
    /// query path — M8 clones both operands' endpoints per overlap test —
    /// so each is capped at the encoding, and each cap is checked at the
    /// value it admits as well as the one past it: a `>` that became a `>=`
    /// would refuse a tumbler the substrate can legitimately carry.
    #[test]
    fn tumbler_digit_and_depth_caps_admit_their_maximum() {
        let tum = |s: String| p_tum(&Value::String(s));
        // Magnitude: the longest admitted digit run parses and renders back
        // whole; one digit more is refused with the count named.
        let at_cap = "9".repeat(MAX_NAT_DIGITS);
        let t = tum(at_cap.clone()).expect("a component at the digit cap parses");
        assert_eq!(t.to_string(), at_cap, "and survives the round trip");
        let over = "9".repeat(MAX_NAT_DIGITS + 1);
        let e = tum(over).expect_err("one digit past the cap must not parse");
        assert!(e.0.contains("digit"), "the refusal names the digit cap: {e}");
        // The cap is per COMPONENT, so a tumbler of admitted components is
        // admitted whatever its total length.
        assert!(tum(format!("{at_cap}.{at_cap}")).is_ok(), "the cap is per component");

        // Depth: the same treatment on the other axis.
        let deep = vec!["1"; MAX_TUMBLER_COMPONENTS].join(".");
        assert_eq!(
            tum(deep).expect("a tumbler at the depth cap parses").len(),
            MAX_TUMBLER_COMPONENTS
        );
        let deeper = vec!["1"; MAX_TUMBLER_COMPONENTS + 1].join(".");
        let e = tum(deeper).expect_err("one component past the cap must not parse");
        assert!(e.0.contains("component"), "the refusal names the depth cap: {e}");
    }

    /// Both ends of the id cap. The id is the one frame field this daemon
    /// never interprets and M10 nonetheless RETAINS — the idempotency cache
    /// is keyed by it — so its length is the second factor in a retention
    /// bill nothing downstream bounds. The at-cap case is load-bearing: a
    /// `>` that became a `>=` would refuse a key a client legitimately sent.
    #[test]
    fn the_idempotency_id_meets_its_cap_at_both_ends() {
        let frame = |id: &str| format!(r#"{{"op":"fork","id":"{id}"}}"#).into_bytes();
        let at_cap = "k".repeat(MAX_REQ_ID_BYTES);
        let req = parse_request(&frame(&at_cap)).expect("an id at the cap parses");
        assert_eq!(req.id.map(|ReqId(b)| b.len()), Some(MAX_REQ_ID_BYTES));
        let over = "k".repeat(MAX_REQ_ID_BYTES + 1);
        // `Request` derives no Debug upstream, so unwrap the failure by hand.
        let e = match parse_request(&frame(&over)) {
            Err(e) => e,
            Ok(_) => panic!("one byte past the cap must not parse"),
        };
        assert!(e.0.contains("wire cap"), "the refusal names the cap: {e}");
    }

    /// Both ends of the wire-list cap, at [`p_list`] — the one door every
    /// attacker-sized array on the request surface passes through. The
    /// at-cap case is the load-bearing half: the cap IS M7's stored-slot
    /// budget, so refusing at it would refuse a query exactly as large as a
    /// slot that can be stored.
    #[test]
    fn a_wire_list_at_the_cap_parses_and_one_past_it_does_not() {
        let spans = |n: usize| {
            Value::Array(
                (0..n)
                    .map(|_| {
                        obj(vec![
                            ("start", Value::String("1.1".into())),
                            ("width", Value::String("0.1".into())),
                        ])
                    })
                    .collect(),
            )
        };
        assert_eq!(
            p_list(&spans(MAX_WIRE_LIST), p_span).expect("a list at the cap parses").len(),
            MAX_WIRE_LIST
        );
        let e = p_list(&spans(MAX_WIRE_LIST + 1), p_span)
            .expect_err("one element past the cap must not parse");
        assert!(e.0.contains("wire cap"), "the refusal names the cap: {e}");
    }

    /// Both ends of the insert-value cap, counted in VALUES rather than
    /// elements: one per-byte string mints one value per byte, so a single
    /// element can cross the cap on its own and an element-count check
    /// would not see it.
    #[test]
    fn insert_value_cap_counts_values_not_elements() {
        let forms = |n: usize| Value::Array(vec![Value::String("a".repeat(n))]);
        // `Val` derives no Debug upstream, so unwrap the failure by hand.
        let refusal = |v: &Value| match p_values(v) {
            Err(e) => e,
            Ok(vals) => panic!("{} values must not parse", vals.len()),
        };
        assert_eq!(
            p_values(&forms(MAX_INSERT_VALUES))
                .unwrap_or_else(|e| panic!("at the cap: {e}"))
                .len(),
            MAX_INSERT_VALUES
        );
        let e = refusal(&forms(MAX_INSERT_VALUES + 1));
        assert!(e.0.contains("cap on one insert"), "the refusal names the cap: {e}");
        // Split across two elements, the accumulator still sees it — the
        // reason the room asked is measured against what is already there
        // rather than against one element in isolation.
        let split = Value::Array(vec![
            Value::String("a".repeat(MAX_INSERT_VALUES)),
            Value::String("b".into()),
        ]);
        assert!(p_values(&split).is_err(), "the total is what is capped, not one element");
    }

    /// The cap refuses BEFORE the mint, not after. An element's whole
    /// contribution is added in one `extend`, so a check made afterwards has
    /// already paid the peak — one 8 MiB per-byte string mints 8.4M [`Val`]s,
    /// order 400 MB of live heap, for a frame that is then refused. What a
    /// test can see is that nothing was minted.
    #[test]
    fn an_over_cap_element_mints_nothing() {
        let mut out: Vec<Val> = Vec::new();
        let big = Value::String("a".repeat(MAX_INSERT_VALUES + 1));
        assert!(p_val_form(&big, &mut out).is_err(), "one element past the cap is refused");
        assert!(out.is_empty(), "and mints nothing: the refusal precedes the mint");
        // Hex is measured on its ENCODED length, so neither the decode nor
        // the values are built.
        let mut out: Vec<Val> = Vec::new();
        let hex = obj(vec![("hex", Value::String("ab".repeat(MAX_INSERT_VALUES + 1)))]);
        assert!(p_val_form(&hex, &mut out).is_err(), "the hex form is capped too");
        assert!(out.is_empty());
        // Both ends against a partly-filled accumulator: the room asked is
        // the element's, measured against what is already there.
        let mut out: Vec<Val> =
            (0..MAX_INSERT_VALUES - 1).map(|_| Val::new(vec![b'a'])).collect();
        assert!(
            p_val_form(&Value::String("ab".into()), &mut out).is_err(),
            "two more values do not fit with one slot left"
        );
        assert_eq!(out.len(), MAX_INSERT_VALUES - 1, "and the refused element mints nothing");
        p_val_form(&Value::String("a".into()), &mut out)
            .expect("the element that exactly fills the cap is admitted");
        assert_eq!(out.len(), MAX_INSERT_VALUES);
    }

    /// Span parse edges — every span on the wire goes through M1's
    /// `Span::new`, so no zero-width span and no ill-shaped object survives
    /// the trust boundary (wire.md §Value encodings).
    #[test]
    fn no_zero_width_or_ill_shaped_span_parses() {
        let span = |s: &str| p_span(&serde_json::from_str::<Value>(s).expect("test JSON"));
        let ok = span(r#"{"start":"1.1","width":"0.5"}"#).expect("a depth-2 content span parses");
        assert_eq!(
            (ok.start().to_string(), ok.width().to_string()),
            ("1.1".to_string(), "0.5".to_string())
        );
        for bad in [
            r#"{"start":"1.1","width":"0.0"}"#, // zero width (T12)
            r#"{"start":"1.1","width":"0"}"#,   // zero width, another depth
            r#"{"start":"1.1","width":"0.0.1"}"#, // action point past #start
            r#"{"start":"1.1"}"#,               // missing width
            r#"{"width":"0.5"}"#,               // missing start
            r#"{"start":"1.1","width":"0.5","extra":1}"#, // unknown key
            r#"{"start":"1.1","width":"0.5x"}"#, // not a dotted decimal
            r#"["1.1","0.5"]"#,                 // not an object
            r#""1.1+0.5""#,                     // not an object
        ] {
            assert!(span(bad).is_err(), "{bad} must not parse as a span");
        }
    }

    /// Value granularity at the leaf: per-byte forms mint one single-byte
    /// value per byte, atom forms one composite value; the canonical marshal
    /// coalesces maximal per-byte runs (UTF-8 judged on the whole run) and
    /// never coalesces atoms.
    #[test]
    fn value_forms_parse_per_byte_and_atoms_marshal_apart() {
        let mut vs: Vec<Val> = Vec::new();
        p_val_form(&Value::String("hé".into()), &mut vs).expect("a string value form parses");
        assert_eq!(vs.len(), 3, "'h' plus the two bytes of 'é'");
        assert!(vs.iter().all(|v| v.len() == 1));
        p_val_form(&obj(vec![("atom", Value::String("hé".into()))]), &mut vs)
            .expect("an atom value form parses");
        assert_eq!(vs.len(), 4);
        assert_eq!(vs[3].as_bytes(), "hé".as_bytes());
        // Canonical inverse: the run reassembles, the atom stays its own form.
        let canon = j_values(&vs);
        let expect: Value = serde_json::from_str(r#"["hé",{"atom":"hé"}]"#).unwrap();
        assert_eq!(canon, expect);
        // Empty per-byte forms are vacuous; empty atoms are inexpressible;
        // multi-key objects and non-string/object elements are malformed.
        let mut none: Vec<Val> = Vec::new();
        p_val_form(&Value::String(String::new()), &mut none).expect("\"\" is vacuous");
        p_val_form(&obj(vec![("hex", Value::String(String::new()))]), &mut none)
            .expect("an empty hex string is vacuous");
        assert!(none.is_empty());
        for bad in [
            obj(vec![("atom", Value::String(String::new()))]),
            obj(vec![("atom_hex", Value::String(String::new()))]),
            obj(vec![("atom", Value::String("a".into())), ("hex", Value::String("00".into()))]),
            Value::Bool(true),
        ] {
            assert!(p_val_form(&bad, &mut none).is_err(), "{bad} must not parse");
        }
        assert!(p_hex("abc").is_err()); // odd length
        assert!(p_hex("zz").is_err());
    }

    /// All three documented view values (wire.md §Value encodings:
    /// `"audit"`, `"active"`, `"default"`). The request fixtures carry only
    /// two, so the third's parse arm and its marshal arm are watched by
    /// nothing — and a typo in either makes a frame the document offers a
    /// client come back `unparseable`, which tells them their frame is
    /// malformed when the value is one wire.md invited.
    #[test]
    fn every_documented_view_value_round_trips() {
        for name in ["audit", "active", "default"] {
            let v = p_view(&Value::String(name.into()))
                .unwrap_or_else(|e| panic!("'{name}' is a documented view: {e}"));
            assert_eq!(j_view(v), Value::String(name.into()), "'{name}' must be its own inverse");
        }
        for bad in ["Audit", "", "all", "actives"] {
            assert!(p_view(&Value::String(bad.into())).is_err(), "'{bad}' must not parse");
        }
    }

    /// The one parse-side normalization [`JsonCodec::marshal_request`]'s
    /// precondition names rather than excludes: an empty span array IS the
    /// empty constraint (M8 documents the empty endset as exactly that
    /// zero), so it reads back under the canonical name and a
    /// `SlotSpec::Spans` over an empty endset round-trips EQUAL rather than
    /// identical. Nothing else pins that the two spellings meet.
    #[test]
    fn an_empty_slot_constraint_normalizes_onto_its_canonical_name() {
        assert!(
            matches!(p_slotspec(&Value::Array(vec![])), Ok(SlotSpec::Empty)),
            "an empty span array is the empty constraint, not an empty span list"
        );
        assert_eq!(
            j_slotspec(&SlotSpec::Spans(Endset::from_spans([]))),
            Value::Array(vec![]),
            "which is the form an empty Spans marshals as"
        );
        assert_eq!(j_slotspec(&SlotSpec::Empty), Value::String("empty".into()));
    }

    /// "Non-negative" is the word the wire uses (wire.md §Value encodings)
    /// and the word these parsers' own error messages use; a signed or
    /// fractional number is neither a natural nor a bounded integer. The
    /// failure this guards is not a refusal but a WRAP: the tempting fix
    /// when a client sends a signed value is `as_i64() as u64`, under
    /// which `-1` becomes 2^64-1 everywhere naturals and bounded integers
    /// are read — a `delete` of 2^64-1 positions, a slot index no link
    /// has, a principal that is the guest's own id.
    #[test]
    fn negative_and_fractional_numbers_are_not_integers() {
        let n = |s: &str| serde_json::from_str::<Value>(s).expect("test JSON");
        for bad in ["-1", "-7", "1.5", "-0.5", "1e3"] {
            assert!(p_u64(&n(bad)).is_err(), "{bad} is not a non-negative integer");
            assert!(p_usize(&n(bad)).is_err(), "{bad} is not a count");
            assert!(p_nat(&n(bad)).is_err(), "{bad} is not a natural");
        }
        assert_eq!(p_u64(&n("0")).expect("zero is non-negative"), 0);
        assert_eq!(p_nat(&n("7")).expect("the lenient integer form").to_string(), "7");
    }

    /// Marshal determinism in miniature: obj() sorts, so construction order
    /// cannot leak into bytes.
    #[test]
    fn obj_is_order_insensitive() {
        let a = obj(vec![("b", j_u64(2)), ("a", j_u64(1))]);
        let b = obj(vec![("a", j_u64(1)), ("b", j_u64(2))]);
        assert_eq!(to_bytes(a), to_bytes(b));
    }

    /// The duplicate-key rule [`obj`] states and `refuse_with` leans on: the
    /// LAST pair given wins, which is what lets `refuse_with` append `error`
    /// behind a caller's fields and be sure the field list cannot displace
    /// it.
    #[test]
    fn obj_keeps_the_last_of_duplicate_keys() {
        let v = obj(vec![("k", j_u64(1)), ("a", j_u64(9)), ("k", j_u64(2))]);
        assert_eq!(v["k"], j_u64(2), "the last pair given wins");
        assert_eq!(to_bytes(v), br#"{"a":9,"k":2}"#.to_vec(), "and the keys still sort");
    }
}
