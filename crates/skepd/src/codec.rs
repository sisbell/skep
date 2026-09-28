//! The one concrete [`Codec`]: JSON frames ↔ M10's typed `Request`/`Response`.
//!
//! The wire conventions are a cross-client contract, specified for client
//! authors in `skep/docs/wire.md` and pinned by the tests in
//! `tests/it/wire_doc.rs` (the doc's examples are asserted, not decorative).
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
//! What `marshal.rs` renders is the OPERATION CHANNEL: M10's `Response`s, the
//! daemon-originated rejections ([`credential_refused_reply`]), and the
//! `key_set` row. The transport's own shapes — `/health`, `/session`,
//! `/challenge`, `/changes` and its entries, the `{"error": …}` bodies,
//! the commit stream's payload — are built where their state lives, and
//! reach determinism by going through [`obj`] and [`to_bytes`] rather than
//! by living here.
//!
//! Parsing strings into `skep-address` values goes through M1's validating
//! front doors (`Tumbler::new`, `validate`, `Span::new`), so no malformed
//! address or zero-width span survives the trust boundary.

mod marshal;

use std::str::FromStr;

use serde_json::{Map, Value};
use skep_address::{validate, Address, Nat, Span, Tumbler};
use skep_arrangement::{Base, Run, Shot, ShotRun, VPos, VSpec};
use skep_content::Val;
use skep_discovery::{FourSet, SlotSpec};
use skep_febe::{
    Codec, Deposit, Op, OpKind, ParseError, Rejection, ReqId, Request, Response, SlotArg,
    SuccessorSpec, MAX_REQ_ID_BYTES,
};
use skep_identity::SigAlgRow;
use skep_kernel::Attestation;
use skep_links::{Endset, View, MAX_SLOT_SPANS};
use skep_namespace::PrincipalId;
use skep_retrieval::{RegionSpec, Spec};

use marshal::{j_attest, j_response, req_pairs};
pub(crate) use marshal::{credential_refused_reply, key_set_reply, op_name};

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
/// [`crate::limits`]'s request-body cap alone. The budget argument above
/// transfers to one query slot; it does not price a region set, whose cost
/// model is M6's rather than M8's. Anyone raising the body cap for a route
/// that carries these ops owes that number.
///
/// The transferred argument likewise prices a list of SPANS, which become
/// spans one for one. It does not price a list of V-SPECS — `copy`'s
/// `specs`, `make_link`'s three slots and `edit_link`'s successor — whose
/// elements RESOLVE against stored arrangement state: one spec becomes as
/// many spans as the source document has runs under it, so a list at this
/// cap expands by a factor this door cannot see and that grows with the
/// source's edit history. M7's own
/// [`RejectCode::SlotTooLarge`](skep_febe::RejectCode::SlotTooLarge) is the
/// evidence that a resolution can exceed its budget; whether that budget
/// is measured before the resolution is built, and what this cap should be
/// if it is not, are M7's and M5's.
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
///
/// PRIVATE, and that is the point: it is spent at [`wire_tumbler`] and
/// nowhere else, so a route that admits a tumbler goes through that door
/// rather than reassembling this budget beside another module's grammar.
const MAX_NAT_DIGITS: usize = 4096;

/// The most components one tumbler may carry on the wire. The same budget
/// as [`MAX_NAT_DIGITS`] on the other axis: a tumbler's components are
/// cloned together on every comparison, so depth multiplies exactly as
/// magnitude does. M3 caps a registered node at 32 components and every
/// other address is a registered parent extended by separators, a subspace
/// identifier and an ordinal — four fields at most — so a deep-node
/// element address is under forty components. 256 leaves that room over
/// several times without admitting a tumbler whose depth is the request's
/// only real content. Private for [`MAX_NAT_DIGITS`]'s reason, and spent at
/// the same door.
const MAX_TUMBLER_COMPONENTS: usize = 256;

/// The largest principal id `delegate` will REGISTER: `2^53 − 1`, the top of
/// the range a JSON number carries EXACTLY (AUTH-6.36's clause; AUTH-5.20).
/// Principal ids ride the wire as plain JSON numbers and are `u64`
/// server-side, and a JavaScript-backed client reads every number as a
/// double: past this value it ROUNDS, so such a client would hold a DIFFERENT
/// id from the one the board registered.
///
/// That was a client's own mistake to avoid while a client only ever met ids
/// it minted itself (AUTH-5.20's MUST binds the minting hand, and is unmoved).
/// It is the BOARD's to refuse since the setup act ADOPTS whatever principal
/// sits at `inc(X, 1)` (AUTH-5.87 op (1); the owner-of-address read,
/// AUTH-6.37): a squatter's `delegate` of that address under an id `≥ 2^53`
/// would seat a principal no JavaScript-backed frontend can name — its
/// `GET /challenge?principal=N` and its `POST /session` body would carry the
/// rounded number, a different principal — and the holder's agent space would
/// be unopenable from that client on every device, at a cell an adversary
/// chooses at zero cost. Refused here, no `delegate` off this wire registers
/// an id a client cannot say back.
///
/// A PARSE FAULT AND NO NEW TOKEN: spent at [`p_minted_id`], on `delegate`'s
/// `new_id` alone — the one field that mints an id — and answered as the
/// ordinary `unparseable` rejection. The fold, M3 and M10 are untouched:
/// `PrincipalId` stays a `u64`, and an `Op` assembled by hand past this bound
/// is this codec's caller's to answer for ([`JsonCodec::marshal_request`]).
const MAX_MINTED_PRINCIPAL_ID: u64 = (1 << 53) - 1;

// The most bytes one frame's idempotency `id` may carry is
// [`MAX_REQ_ID_BYTES`], imported above. This daemon never interprets the id;
// the bound is M10's, because the retention is M10's — the memo keeps the key
// for the life of its entry — and its budget is written where the number is.
// Refusing at parse is this codec's part: the client is told, and told which
// cap it passed.

/// The daemon's JSON codec — stateless; one instance serves every client.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    /// M10's seam, reading the frame AS PRESENTED — the round-trip oracle's
    /// door and every test's, and not the daemon's: a frame's `attest`
    /// member (admitted on the checked set alone — `insert`, `make_link`,
    /// `publish` — under a `SIG_ALGS` row's token) rides in
    /// [`Request::attest`] PARSED AND UNVERIFIED. M10's card makes that
    /// field the signature the daemon's write-path check ADMITTED, which
    /// `execute` hands the store and the kernel writes into the commit
    /// marker as it stands, so a request from this door is one to judge,
    /// not to execute. The daemon's own routes never execute one: they parse
    /// through `parse_daemon`, which takes the member out for the check and
    /// hands `execute` a request whose `attest` that check alone fills. A
    /// caller that executes what this returns owes the check itself, or
    /// clears the field.
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
    /// [`MAX_REQ_ID_BYTES`] per idempotency id,
    /// [`MAX_MINTED_PRINCIPAL_ID`] for a `delegate`'s `new_id` — carries no
    /// zero-byte `Val`, which `marshal::j_atom` renders as `{"atom": ""}` and
    /// [`p_val_form`] refuses by design (coarse granularity must be said, and
    /// a zero-byte atom says nothing), carries an `id`, if any, that is
    /// UTF-8, which a `ReqId` this codec parsed always is, and carries an
    /// `attest`, if any, only on an op of the checked set (`insert`,
    /// `make_link`, `publish`: the set `in_checked_set` states
    /// and the parse side admits the member on), under a marker tag a
    /// `SIG_ALGS` row names, which an `Attestation` this codec parsed always
    /// is. Under all of that, `parse(marshal_request(r))` reproduces `r` and
    /// re-marshaling the parse is byte-identical.
    ///
    /// Outside it, marshaling SUCCEEDS and yields a frame `parse` refuses:
    /// this is the parse side's trust-boundary obligation and this direction
    /// does not re-check it (one check, one owner). The upstream value types
    /// admit every violation — `Endset::from_spans` takes any span count,
    /// T0(a) leaves a component's magnitude unbounded by design, `Val::new`
    /// takes any bytes, `PrincipalId` is any `u64`, `ReqId`'s field is
    /// public, and `Request::attest` rides any op under any tag
    /// `Attestation::new` admits — so a caller assembling a `Request` by hand
    /// owes the whole precondition. A `Request` this codec produced satisfies
    /// it by construction, which is what makes the round-trip oracle sound.
    ///
    /// One normalization survives the precondition rather than being
    /// excluded by it: `SlotSpec::Spans` over an EMPTY endset marshals as
    /// `[]`, which [`p_slotspec`] deliberately reads back as
    /// `SlotSpec::Empty` — M8's same constraint under its canonical name. So
    /// for such an `r` the round trip is EQUAL and not identical, and
    /// re-marshaling gives `"empty"`. `parse` cannot mint that value, so a
    /// `Request` this codec produced is again unaffected.
    ///
    /// A non-UTF-8 `id` is the one violation of this precondition that
    /// neither round-trips nor is refused: it is rendered lossily rather
    /// than panicking, and the frame PARSES — to a DIFFERENT `ReqId`. That
    /// matters because `id` is an idempotency key M10 matches exactly: two
    /// distinct non-UTF-8 ids collapse onto one replacement string, so a
    /// retry can hit a memo entry it did not write, or miss the one it did.
    /// A `ReqId` this codec parsed is the UTF-8 bytes of the frame's `id`
    /// string and cannot be one.
    pub fn marshal_request(&self, req: &Request) -> Vec<u8> {
        let (name, mut pairs) = req_pairs(&req.op);
        if let Some(ReqId(bytes)) = &req.id {
            pairs.push(("id", Value::String(String::from_utf8_lossy(bytes).into_owned())));
        }
        // The `attest` member, where the request carries one (signed ops):
        // the tag lifted back to its `alg` token, the blob as hex. A tag no
        // row names, or an op outside the checked set, is outside the
        // precondition: the one renders a token `parse` refuses, the other a
        // member `parse` refuses as an unknown field.
        if let Some(a) = &req.attest {
            pairs.push(("attest", j_attest(a)));
        }
        pairs.push(("op", Value::String(name.into())));
        to_bytes(obj(pairs))
    }

    /// The daemon-level parse: the `key_set` frame — served by the daemon's
    /// own dispatcher because the identity slice rides beside the engine's
    /// `World` in this build (the authorized M10 row is unusable until the
    /// slice is seated; see the build report) — or the ordinary M10 frame.
    /// One grammar discipline for both: internally tagged, unknown fields
    /// refused.
    pub(crate) fn parse_daemon(&self, frame: &[u8]) -> Result<DaemonOp, ParseError> {
        let v: Value = match serde_json::from_slice(frame) {
            Ok(v) => v,
            Err(e) => return Err(ParseError { detail: Some(format!("invalid JSON: {e}")) }),
        };
        self.parse_daemon_value(v)
    }

    /// [`JsonCodec::parse_daemon`] over an already-decoded value (the
    /// `/op-at` envelope's frame).
    pub(crate) fn parse_daemon_value(&self, v: Value) -> Result<DaemonOp, ParseError> {
        if v.as_object().and_then(|m| m.get("op")).and_then(Value::as_str) == Some("key_set") {
            return parse_key_set(v).map_err(|e| ParseError { detail: Some(e.0) });
        }
        parse_value(v)
            .map(|mut request| {
                let presented = request.attest.take();
                DaemonOp::Febe { request: Box::new(request), presented }
            })
            .map_err(|e| ParseError { detail: Some(e.0) })
    }

    /// The transport's one never-silent obligation outside M10's dispatch
    /// (M10 §Codec): a frame that failed to parse still gets exactly one
    /// response. M10 classifies it — the code and its disposition come from
    /// the same table every other rejection goes through — and this crate
    /// marshals it like any other.
    pub fn unparseable(&self, e: ParseError) -> Response {
        Response::Rejected(Rejection::unparseable(e))
    }
}

/// One parsed daemon-level frame: an M10 request, or the `key_set` read the
/// daemon serves itself (AUTH-6.18–6.20). No `Debug`: M10's `Request`
/// carries none, and both consumers match rather than print. The request
/// rides boxed — it is an order of magnitude wider than the other arm, and
/// this enum sits on every dispatch path.
pub(crate) enum DaemonOp {
    /// An M10 request whose `attest` is EMPTY whatever the frame carried,
    /// and beside it the `attest` member the frame PRESENTED — unverified,
    /// the write-path check's to judge (signed ops). Split HERE, at the door,
    /// so that on the daemon's dispatch path `Request::attest` only ever
    /// holds what M10's own card says it holds: the signature the daemon's
    /// check ADMITTED, set by the write sequence that ran the check and by
    /// nothing else. A route that never judges `presented` then commits with
    /// the marker slot EMPTY — never with a blob nobody verified, which the
    /// kernel writes opaquely and a reader of the journal takes for an
    /// author's attestation this board ADMITTED.
    Febe { request: Box<Request>, presented: Option<Attestation> },
    KeySet { account: Address },
}

/// `{"op":"key_set","account":"<address>"}` (+ the optional idempotency
/// `id`, accepted and dropped — reads are never memoized), under the same
/// field discipline as every other frame.
fn parse_key_set(v: Value) -> PResult<DaemonOp> {
    let Value::Object(m) = v else {
        return Err(PErr("request frame must be a JSON object".into()));
    };
    let mut fields = Fields(m);
    let _ = fields.string("op")?;
    let _ = fields.req_id()?;
    let account = fields.addr("account")?;
    fields.finish()?;
    Ok(DaemonOp::KeySet { account })
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
    // The id is capped where it is minted, and before it is copied: M10
    // retains it for the life of a memoized write, so its LENGTH is the second
    // factor in a retention bill nothing downstream bounds (see
    // [`MAX_REQ_ID_BYTES`]).
    let id = fields.req_id()?;
    let op = parse_op(&name, &mut fields)?;
    // The optional `attest` member, admitted on the checked set
    // [`in_checked_set`] states and on no other op — left
    // in the map elsewhere, so `finish` refuses it by the unknown-field rule,
    // as a daemon that predates the member does (the design record §7.3 (ii)).
    let attest = fields.attest(op.kind())?;
    fields.finish()?;
    Ok(Request { id, op, attest })
}

/// `{"alg": <an ALGS token>, "sig": <hex>}` — the wire's `attest` object
/// (the design record §7.3 (ii)), lifted to the kernel's `Attestation`: the
/// token to the marker tag its `SIG_ALGS` row names (a token no row carries
/// is a GRAMMAR failure — the token set is an I2 frozen constant, so an
/// unknown one is refused as an unknown op is), the hex to the blob (empty
/// is refused: absence is the member's own — missing, or `null`, which
/// [`Fields::attest`] reads alike — never an empty blob). The blob's WIDTH
/// under the tag is the check's to judge, not the grammar's.
fn p_attest(v: &Value) -> PResult<Attestation> {
    let m = p_obj(v, &["alg", "sig"])?;
    let alg = field(m, "alg", p_string)?;
    let row = SigAlgRow::of_token(&alg)
        .ok_or_else(|| PErr(format!("field 'alg': unknown algorithm token '{}'", bounded(&alg))))?;
    let sig = field(m, "sig", |v| p_hex(p_str(v)?))?;
    Attestation::new(row.tag, sig).map_err(|e| PErr(format!("field 'sig': {e}")))
}

/// One request-envelope arm per `Op` variant. Field names are the wire
/// contract (wire.md §Operations); the one Rust-name departure is
/// `principal_prefix`, whose argument rides as `"principal"` because the
/// envelope key `"id"` is the idempotency slot.
fn parse_op(name: &str, fields: &mut Fields) -> PResult<Op> {
    Ok(match name {
        "create_new_document" => Op::CreateNewDocument {
            account: fields.addr("account")?,
            published: fields.published()?,
        },
        "delegate" => Op::Delegate {
            new_prefix: fields.tum("new_prefix")?,
            new_id: PrincipalId(fields.minted_id("new_id")?),
        },
        "register_node" => Op::RegisterNode { addr: fields.tum("addr")? },
        "fork" => Op::Fork { published: fields.published()? },
        "next_account_prefix" => Op::NextAccountPrefix { parent: fields.addr("parent")? },
        "principal_prefix" => Op::PrincipalPrefix { id: PrincipalId(fields.u64("principal")?) },
        "effective_owner" => Op::EffectiveOwner { addr: fields.addr("addr")? },
        "doc_metadata" => Op::DocMetadata { doc: fields.addr("doc")? },
        "insert" => Op::Insert {
            doc: fields.addr("doc")?,
            at: fields.vpos("at")?,
            values: fields.vals("values")?,
            deposit: fields.deposit()?,
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
        "version" => Op::Version {
            d_src: fields.addr("d_src")?,
            published: fields.published()?,
        },
        "publish" => Op::Publish { doc: fields.addr("doc")?, shot: fields.shot()? },
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
        "edition_claims" => Op::EditionClaims { target: fields.addr("target")? },
        // No argument (PUB-8.47): `finish` refuses any field beside `op` and
        // the idempotency `id`, as everywhere.
        "universal_grants" => Op::UniversalGrants,
        other => return Err(PErr(format!("unknown op '{}'", bounded(other)))),
    })
}

/// THE CHECKED SET — the op kinds the write-path check reaches, and so the
/// ops an ENTRY frame is composed for: `insert`, `make_link`, `publish` (the
/// owner's term, m2, the design record's round 5 rulings 2026-09-26; the
/// seam build's three — the record's thirteen publish-class-capable inputs
/// are the WIDENING lane's). The ONE statement of it: the codec admits a
/// request's `attest` member exactly on these, the check demands and
/// verifies one exactly on these, and `auth::entry::compose` has an arm
/// exactly for these. The acting hand ATTESTS; the check admits or refuses,
/// and signs nothing. The three must agree in both directions — a member the
/// codec admits and the check never demands is a signature parsed and
/// silently DROPPED, the commit landing with its marker slot empty; one the
/// check demands and the codec refuses is a write no signed session can make
/// on a claimed board — so a widening is one edit here and one arm in
/// `auth::entry::compose`, whose wildcard asserts it.
pub(crate) fn in_checked_set(kind: OpKind) -> bool {
    matches!(kind, OpKind::Insert | OpKind::MakeLink | OpKind::Publish)
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

    /// The frame's idempotency id, capped BEFORE the copy — the discipline
    /// [`room`] states and [`hex_values`] follows. A [`MAX_REQ_ID_BYTES`]
    /// cap enforced after the string has been copied out of the tree copies
    /// up to a whole request body to refuse 257 bytes.
    fn req_id(&mut self) -> PResult<Option<ReqId>> {
        let Some(v) = self.take_opt("id") else { return Ok(None) };
        let s = v
            .as_str()
            .ok_or_else(|| PErr("field 'id': expected a JSON string".into()))?;
        if s.len() > MAX_REQ_ID_BYTES {
            return Err(PErr(format!(
                "id is {} bytes, past the {MAX_REQ_ID_BYTES}-byte wire cap",
                s.len()
            )));
        }
        Ok(Some(ReqId(s.as_bytes().to_vec())))
    }

    fn u64(&mut self, k: &'static str) -> PResult<u64> {
        self.field(k, p_u64)
    }

    /// The optional top-level `attest` member — taken on an op of the checked
    /// set ([`in_checked_set`]), absent and explicit
    /// `null` alike reading `None`; on any other op it is not taken at all,
    /// so `finish` refuses it as the unknown field it is there. The checked
    /// set is ONE statement and it is the codec's — the wire grammar's —
    /// because what it states is which ops carry `attest` on the wire (M10's
    /// interface calls it skepd's `JsonCodec`'s); the composer (`auth/entry`)
    /// and the policy READ it from here.
    fn attest(&mut self, kind: OpKind) -> PResult<Option<Attestation>> {
        if !in_checked_set(kind) {
            return Ok(None);
        }
        match self.take_opt("attest") {
            None => Ok(None),
            Some(v) => p_attest(&v).map(Some).map_err(|e| PErr(format!("field 'attest': {e}"))),
        }
    }

    /// `delegate`'s `new_id` — the ONE principal id on the wire that MINTS,
    /// and so the one held to [`MAX_MINTED_PRINCIPAL_ID`] at this door. Every
    /// other id field only NAMES a principal: one some `delegate` registered
    /// is inside the range by this bound, and one nobody registered answers
    /// absent.
    fn minted_id(&mut self, k: &'static str) -> PResult<u64> {
        self.field(k, p_minted_id)
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

    fn regions(&mut self, k: &'static str) -> PResult<Vec<RegionSpec>> {
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

    /// The three-valued publication flag on the minting ops (PUB-8.16):
    /// `absent | true | false`, with absent and explicit `null` reading the
    /// same absence (`take_opt`'s rule) → `None`. Any non-boolean value is a
    /// parse fault, never silently coerced.
    fn published(&mut self) -> PResult<Option<bool>> {
        match self.take_opt("published") {
            None => Ok(None),
            Some(v) => v
                .as_bool()
                .map(Some)
                .ok_or_else(|| PErr("field 'published': expected true or false".into())),
        }
    }

    /// `insert`'s DEPOSIT DECLARATION (PUB-9.13's DECLARED horn, owner ruling
    /// 2026-09-05; PUB-2.63): THE FIELD's VALUE IS THE RECORD CLASS's TYPE
    /// (PUB-2.64; RES-249), an address string, and ABSENT — the field not
    /// sent — is the one spelling of `Undeclared`, an ordinary edit. So this
    /// field does not go through [`take_opt`](Self::take_opt): an explicit
    /// `null` is a declaration with nothing in it, and like the retired
    /// `true` / `false` and any other non-address it is a parse fault, never
    /// coerced to either arm. Which types the deposit class holds is not this
    /// parse's to know: any T4-valid address declares, and M5's door tests it
    /// (`published_target` for a type the class does not hold). Both arms are
    /// written out, which is where M5 asks a reader to see which one is
    /// declared.
    fn deposit(&mut self) -> PResult<Deposit> {
        match self.0.remove("deposit") {
            None => Ok(Deposit::Undeclared),
            Some(v) => p_addr(&v)
                .map(Deposit::Declared)
                .map_err(|e| PErr(format!("field 'deposit': {e}"))),
        }
    }

    /// Absent ≡ null ≡ ⊥ (start of the enumeration).
    fn cursor(&mut self, k: &'static str) -> PResult<Option<Address>> {
        self.opt_addr(k)
    }

    /// An optional address field: absent and explicit `null` alike read
    /// `None`; present, it must parse as an address.
    fn opt_addr(&mut self, k: &'static str) -> PResult<Option<Address>> {
        match self.take_opt(k) {
            None => Ok(None),
            Some(v) => {
                p_addr(&v).map(Some).map_err(|e| PErr(format!("field '{k}': {e}")))
            }
        }
    }

    /// The publish shot's own fields (wire v7.3, PUB-8.1): `base` and
    /// `base_extent` travel TOGETHER — a base without the extent its copy
    /// took is a base the composite cannot compose against (PUB-2.42), and
    /// an extent without a base measures nothing — so either both are
    /// present or neither is (the birth version, PUB-2.34); `draft` is
    /// optional; `runs` is the client-rendered arrangement, each run its
    /// origin, its start and its width.
    fn shot(&mut self) -> PResult<Shot> {
        let member = self.opt_addr("base")?;
        let extent = match self.take_opt("base_extent") {
            None => None,
            Some(v) => Some(p_nat(&v).map_err(|e| PErr(format!("field 'base_extent': {e}")))?),
        };
        let base = match (member, extent) {
            (Some(member), Some(extent)) => Some(Base { member, extent }),
            (None, None) => None,
            (Some(_), None) => {
                return Err(PErr("field 'base_extent': required beside 'base'".into()))
            }
            (None, Some(_)) => {
                return Err(PErr("field 'base_extent': carried without 'base'".into()))
            }
        };
        let draft = self.opt_addr("draft")?;
        let runs = self.field("runs", |v| p_list(v, p_shot_run))?;
        Ok(Shot { base, draft, runs })
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

/// A JSON string BORROWED from the tree — for a caller that only reads the
/// text, so the hex forms decode off the frame's own bytes rather than off a
/// copy of them. [`p_string`] is this plus the copy, for the callers that
/// keep the text past `field`'s closure.
fn p_str(v: &Value) -> PResult<&str> {
    v.as_str().ok_or_else(|| PErr("expected a JSON string".into()))
}

fn p_string(v: &Value) -> PResult<String> {
    p_str(v).map(str::to_owned)
}

fn p_u64(v: &Value) -> PResult<u64> {
    v.as_u64().ok_or_else(|| PErr("expected a non-negative JSON integer".into()))
}

fn p_usize(v: &Value) -> PResult<usize> {
    usize::try_from(p_u64(v)?).map_err(|_| PErr("integer exceeds this platform's usize".into()))
}

/// A principal id about to be REGISTERED, held to the wire's
/// exactly-representable range ([`MAX_MINTED_PRINCIPAL_ID`]). A PARSE FAULT
/// like every other malformed field — the ordinary `unparseable` rejection,
/// no new code and no new token — so the frame reaches no session gate, no
/// lock and no store, and nothing commits.
fn p_minted_id(v: &Value) -> PResult<u64> {
    let id = p_u64(v)?;
    if id > MAX_MINTED_PRINCIPAL_ID {
        return Err(PErr(format!(
            "{id} is past {MAX_MINTED_PRINCIPAL_ID} (2^53 - 1), the largest principal id a \
             JSON number carries exactly"
        )));
    }
    Ok(id)
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

/// A dotted-decimal tumbler off the wire, under both of this codec's tumbler
/// caps — THE bounded parse, and what makes [`MAX_NAT_DIGITS`]'s "this is
/// that place" true of every wire tumbler rather than of frames alone. A
/// route that takes one from a query string meets the door a frame's tumbler
/// meets, instead of reassembling it from this module's two constants and
/// another module's uncapped grammar. Both caps are applied BEFORE the
/// component they bound is converted (see [`p_nat_str`]). `Err` carries the
/// detail text; a caller wraps it in its own field name.
pub(crate) fn wire_tumbler(s: &str) -> Result<Tumbler, String> {
    let depth = s.split('.').count();
    if depth > MAX_TUMBLER_COMPONENTS {
        return Err(format!(
            "tumbler has {depth} components, past the \
             {MAX_TUMBLER_COMPONENTS}-component wire cap"
        ));
    }
    let comps = s.split('.').map(p_nat_str).collect::<PResult<Vec<Nat>>>().map_err(|e| e.0)?;
    Tumbler::new(comps).map_err(|e| format!("'{}': {e}", bounded(s)))
}

/// A dotted-decimal ADDRESS off the wire: [`wire_tumbler`]'s capped parse
/// refined by M1's `validate` — THE address door, as that function is the
/// tumbler's, so the two steps that make a wire address are composed once
/// and a caller adds only the field name its own grammar gives it. `Err`
/// carries the detail text.
///
/// The UNCAPPED twin is `write_path::classify::parse_dotted`, which
/// refines its own grammar the same way and states why a name that reached
/// a FILE is already past the budgets a client meets.
pub(crate) fn wire_address(s: &str) -> Result<Address, String> {
    validate(wire_tumbler(s)?).map_err(|e| format!("not a T4-valid address: {e}"))
}

/// [`wire_tumbler`] over a JSON string — the frame side's face of the one
/// bounded parse.
fn p_tum(v: &Value) -> PResult<Tumbler> {
    let s = v.as_str().ok_or_else(|| PErr("expected a dotted-decimal string".into()))?;
    wire_tumbler(s).map_err(PErr)
}

/// [`wire_address`] over a JSON string — the frame side's face, as [`p_tum`]
/// is [`wire_tumbler`]'s. The non-string fault is `p_tum`'s verbatim: the
/// two faces refuse the same shape for the same reason.
fn p_addr(v: &Value) -> PResult<Address> {
    let s = v.as_str().ok_or_else(|| PErr("expected a dotted-decimal string".into()))?;
    wire_address(s).map_err(PErr)
}

/// Guard which KEYS a sub-object may carry; unknown keys fail like unknown
/// envelope fields do.
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

/// One run of a publish shot (wire.md §Arrangement, `publish`): the origin
/// document, the run's start, and its width — through M5's own `Run::new`, so
/// no zero-width run and no start that is not a full element position
/// survives the trust boundary.
fn p_shot_run(v: &Value) -> PResult<ShotRun> {
    let m = p_obj(v, &["i_start", "origin", "width"])?;
    let origin = field(m, "origin", p_addr)?;
    let i_start = field(m, "i_start", p_addr)?;
    let width = field(m, "width", p_nat)?;
    // M5's verdict is a whole message already — the clause broken, under the
    // run's own prefix ("run: …") — so the codec adds no frame of its own.
    let run = Run::new(i_start, width).map_err(|e| PErr(e.to_string()))?;
    Ok(ShotRun { origin, run })
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

fn p_region(v: &Value) -> PResult<RegionSpec> {
    let m = p_obj(v, &["doc", "spans"])?;
    Ok(RegionSpec { doc: field(m, "doc", p_addr)?, spans: field(m, "spans", |v| p_list(v, p_span))? })
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
        let bytes = field(m, "hex", |v| p_hex(p_str(v)?))?;
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
        let bytes = field(m, "atom_hex", |v| p_hex(p_str(v)?))?;
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

/// The ASCII hex table, LOWERCASE — the decode side of [`hex_string`], and
/// the ONE mapping this crate holds from a hex byte to a nibble.
///
/// CASE IS POLICY and stays with each parser, which is the whole of what
/// the three differ by: [`hex_digit`] folds it and names the offending
/// character; [`parse_lower_hex`] REFUSES it, admitting only what
/// [`hex_string`] emits — the parse behind the nonce, the session token and
/// the published head's hashes, so an uppercase nonce is a syntax fault
/// whose nonce survives rather than a burned credential; and the session's
/// signature parser (`auth::session::parse_case_free_hex`) folds it, the
/// signature being decoded and never framed. None of them owns the table.
pub(crate) fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Exactly `N` bytes of LOWERCASE hex, or `None` — [`hex_string`]'s exact
/// inverse at a fixed width, and the parse of every value this crate reads
/// back only as its own emitter wrote it: the handshake nonce and the
/// session token (AUTH-4.15, AUTH-4.17), and the published head's hashes.
/// Each admits only what `hex_string` produced, so an uppercase value — or
/// a signed pair, which a radix parse would read — is refused rather than
/// normalized; what the refusal costs is stated on each caller. The REFUSAL
/// is this function's own, in the byte it hands [`hex_nibble`].
pub(crate) fn parse_lower_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut raw = [0u8; N];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        raw[i] = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Some(raw)
}

/// Lowercase hex — the encoding behind `{"hex"}`, `{"atom_hex"}`, and the
/// fuzz harness's reproduction form, so all three read the same bytes back.
/// `pub` because `crate::fuzz_support` re-exports it as its `hex`: this
/// module is private, so that re-export is the only public path to it, and a
/// build without `test-hooks` has none.
pub fn hex_string(b: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &byte in b {
        s.push(DIGITS[(byte >> 4) as usize] as char);
        s.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    s
}

/// One hex character, case FOLDED — the content forms' policy: `{"hex"}`
/// and `{"atom_hex"}` are decoded to bytes and never framed, so an
/// uppercase digit means what a lowercase one means.
fn hex_digit(c: u8) -> PResult<u8> {
    hex_nibble(c.to_ascii_lowercase())
        .ok_or_else(|| PErr(format!("invalid hex digit '{}'", c as char)))
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

#[cfg(test)]
mod tests;
