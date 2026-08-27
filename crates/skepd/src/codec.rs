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
//!   (content-resolved, the v1 meaning byte-for-byte) or
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
use skep_links::{Endset, Link, View};
use skep_namespace::PrincipalId;
use skep_retrieval::{CorrPair, DeliveryItem, Operand, Region, Spec, SpecFault};

/// The daemon's JSON codec — stateless; one instance serves every client.
#[derive(Clone, Copy, Default)]
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
    /// it: `parse(marshal_request(r))` reproduces `r`, and re-marshaling the
    /// parse is byte-identical. Wire invariant: a `ReqId` is the UTF-8 bytes
    /// of the frame's `id` string (parse can produce nothing else); an
    /// off-wire non-UTF-8 id is rendered lossily rather than panicking.
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

/// Serialize a finished `Value` tree. Infallible for trees this module
/// builds: string keys only, no foreign `Serialize` impls.
fn to_bytes(v: Value) -> Vec<u8> {
    serde_json::to_vec(&v).expect("serializing a serde_json::Value with string keys cannot fail")
}

/// Build a JSON object with keys sorted — THE determinism device. Every
/// JSON object this crate emits is constructed through it — wire responses,
/// transport-error bodies, and the sidecar's own file lines — so canonical
/// output is alphabetical-by-key under any serde_json map backend.
pub(crate) fn obj(pairs: Vec<(&'static str, Value)>) -> Value {
    let mut pairs = pairs;
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    let mut m = Map::new();
    for (k, v) in pairs {
        m.insert(k.to_string(), v);
    }
    Value::Object(m)
}

/// Render a tumbler dotted-decimal — the same encoding the conformance
/// goldens use ("1.1.0.1", zeros explicit, components canonical decimal).
/// That encoding is M1's own `Display`, so the wire form and the tumbler's
/// canonical text are one rendering rather than two that must be kept equal.
pub fn tumbler_string(t: &Tumbler) -> String {
    t.to_string()
}

// ── parse (wire → Request) ──────────────────────────────────────────────

/// Internal parse fault; becomes `ParseError::detail`.
struct PErr(String);

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
    let mut o = Obj(m);
    let name = o.string("op")?;
    let id = o.opt_string("id")?.map(|s| ReqId(s.into_bytes()));
    let op = parse_op(&name, &mut o)?;
    o.finish()?;
    Ok(Request { id, op })
}

/// One request-envelope arm per `Op` variant. Field names are the wire
/// contract (wire.md §Operations); the one Rust-name departure is
/// `principal_prefix`, whose argument rides as `"principal"` because the
/// envelope key `"id"` is the idempotency slot.
fn parse_op(name: &str, o: &mut Obj) -> PResult<Op> {
    Ok(match name {
        "create_new_document" => Op::CreateNewDocument { account: o.addr("account")? },
        "delegate" => Op::Delegate {
            new_prefix: o.tum("new_prefix")?,
            new_id: PrincipalId(o.u64("new_id")?),
        },
        "register_node" => Op::RegisterNode { addr: o.tum("addr")? },
        "fork" => Op::Fork,
        "next_account_prefix" => Op::NextAccountPrefix { parent: o.addr("parent")? },
        "principal_prefix" => Op::PrincipalPrefix { id: PrincipalId(o.u64("principal")?) },
        "insert" => Op::Insert {
            doc: o.addr("doc")?,
            at: o.vpos("at")?,
            values: o.vals("values")?,
        },
        "delete" => Op::Delete { doc: o.addr("doc")?, p: o.vpos("p")?, width: o.nat("width")? },
        "copy" => Op::Copy { doc: o.addr("doc")?, at: o.vpos("at")?, specs: o.vspecs("specs")? },
        "rearrange" => Op::Rearrange { doc: o.addr("doc")?, cuts: o.vposes("cuts")? },
        "version" => Op::Version { d_src: o.addr("d_src")? },
        "make_link" => Op::MakeLink {
            home: o.addr("home")?,
            from: o.slotarg("from")?,
            to: o.slotarg("to")?,
            ty: o.slotarg("ty")?,
        },
        "emit" => Op::Emit {
            home: o.addr("home")?,
            ty: o.endset("ty")?,
            from: o.addr("from")?,
            to: o.addrs("to")?,
        },
        "nullify" => Op::Nullify { home: o.addr("home")?, target: o.addr("target")? },
        "assert_sup" => Op::AssertSup {
            home: o.addr("home")?,
            old: o.addr("old")?,
            new: o.addr("new")?,
        },
        "edit_link" => Op::EditLink {
            original: o.addr("original")?,
            successor: o.successor("successor")?,
            d_s: o.addr("d_s")?,
            d_a: o.addr("d_a")?,
        },
        "read_link" => Op::ReadLink { a: o.addr("a")? },
        "follow_link" => Op::FollowLink { a: o.addr("a")?, slot: o.usize_("slot")? },
        "retrieve_v" => Op::RetrieveV { specs: o.specs("specs")? },
        "retrieve_doc_v_span" => Op::RetrieveDocVSpan { doc: o.addr("doc")? },
        "retrieve_doc_v_span_set" => Op::RetrieveDocVSpanSet { doc: o.addr("doc")? },
        "show_origin" => Op::ShowOrigin { doc: o.addr("doc")?, span: o.span("span")? },
        "show_deletions" => Op::ShowDeletions { d_a: o.addr("d_a")?, d_b: o.addr("d_b")? },
        "compare" => Op::Compare { rho1: o.regions("rho1")?, rho2: o.regions("rho2")? },
        "find_docs_containing" => Op::FindDocsContaining { regions: o.regions("regions")? },
        "image" => Op::Image { d: o.addr("d")?, region: o.spans("region")? },
        "find_links_v" => Op::FindLinksV { d: o.addr("d")?, region: o.spans("region")? },
        "find_links_ftt" => Op::FindLinksFtt { q: o.fourset("q")? },
        "count_v" => Op::CountV { d: o.addr("d")?, region: o.spans("region")? },
        "count_ftt" => Op::CountFtt { q: o.fourset("q")? },
        "window_v" => Op::WindowV {
            d: o.addr("d")?,
            region: o.spans("region")?,
            cur: o.cursor("cur")?,
            n: o.usize_("n")?,
        },
        "window_ftt" => Op::WindowFtt {
            q: o.fourset("q")?,
            cur: o.cursor("cur")?,
            n: o.usize_("n")?,
        },
        "retrieve_endsets" => Op::RetrieveEndsets { d: o.addr("d")?, region: o.spans("region")? },
        "project" => Op::Project { a: o.addr("a")?, slot: o.usize_("slot")?, d: o.addr("d")? },
        "discoverable_from" => Op::DiscoverableFrom { a: o.addr("a")?, d: o.addr("d")? },
        "delete_orphans" => Op::DeleteOrphans {
            d: o.addr("d")?,
            p: o.vpos("p")?,
            width: o.nat("width")?,
        },
        "in_claims" => Op::InClaims { y: o.addr("y")?, view: o.view("view")? },
        "out_claims" => Op::OutClaims { x: o.addr("x")?, view: o.view("view")? },
        other => return Err(PErr(format!("unknown op '{other}'"))),
    })
}

/// The request object being consumed: known fields are taken out; anything
/// left at [`Obj::finish`] is an unknown field and fails the parse.
struct Obj(Map<String, Value>);

impl Obj {
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
            Some(k) => Err(PErr(format!("unknown field '{k}'"))),
            None => Ok(()),
        }
    }

    fn field<T>(&mut self, k: &'static str, f: impl Fn(&Value) -> PResult<T>) -> PResult<T> {
        let v = self.take(k)?;
        f(&v).map_err(|e| PErr(format!("field '{k}': {}", e.0)))
    }

    fn string(&mut self, k: &'static str) -> PResult<String> {
        self.field(k, p_string)
    }

    fn opt_string(&mut self, k: &'static str) -> PResult<Option<String>> {
        match self.take_opt(k) {
            None => Ok(None),
            Some(v) => p_string(&v).map(Some).map_err(|e| PErr(format!("field '{k}': {}", e.0))),
        }
    }

    fn u64(&mut self, k: &'static str) -> PResult<u64> {
        self.field(k, p_u64)
    }

    fn usize_(&mut self, k: &'static str) -> PResult<usize> {
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
        self.field(k, p_val_forms)
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
                p_addr(&v).map(Some).map_err(|e| PErr(format!("field '{k}': {}", e.0)))
            }
        }
    }

    fn successor(&mut self, k: &'static str) -> PResult<SuccessorSpec> {
        self.field(k, p_successor)
    }
}

// ── leaf parsers, each through M1's validating constructors ──

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

fn p_nat_str(s: &str) -> PResult<Nat> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PErr(format!("'{s}' is not a decimal natural")));
    }
    Nat::from_str(s).map_err(|e| PErr(format!("'{s}': {e}")))
}

fn p_tum(v: &Value) -> PResult<Tumbler> {
    let s = v.as_str().ok_or_else(|| PErr("expected a dotted-decimal string".into()))?;
    let comps = s.split('.').map(p_nat_str).collect::<PResult<Vec<Nat>>>()?;
    Tumbler::new(comps).map_err(|e| PErr(format!("'{s}': {e}")))
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
        Some(k) => Err(format!("unknown field '{k}'")),
        None => Ok(()),
    }
}

fn need<'a>(m: &'a Map<String, Value>, k: &'static str) -> PResult<&'a Value> {
    m.get(k).ok_or_else(|| PErr(format!("missing field '{k}'")))
}

fn sub<T>(m: &Map<String, Value>, k: &'static str, f: impl Fn(&Value) -> PResult<T>) -> PResult<T> {
    f(need(m, k)?).map_err(|e| PErr(format!("{k}: {}", e.0)))
}

fn p_list<T>(v: &Value, f: impl Fn(&Value) -> PResult<T>) -> PResult<Vec<T>> {
    let arr = v.as_array().ok_or_else(|| PErr("expected a JSON array".into()))?;
    arr.iter()
        .enumerate()
        .map(|(i, x)| f(x).map_err(|e| PErr(format!("[{i}]: {}", e.0))))
        .collect()
}

fn p_span(v: &Value) -> PResult<Span> {
    let m = p_obj(v, &["start", "width"])?;
    let start = sub(m, "start", p_tum)?;
    let width = sub(m, "width", p_tum)?;
    Span::new(start, width).map_err(|e| PErr(format!("ill-formed span: {e}")))
}

fn p_vpos(v: &Value) -> PResult<VPos> {
    let m = p_obj(v, &["ordinal", "subspace"])?;
    Ok(VPos { subspace: sub(m, "subspace", p_nat)?, ordinal: sub(m, "ordinal", p_nat)? })
}

fn p_vspec(v: &Value) -> PResult<VSpec> {
    let m = p_obj(v, &["source", "span"])?;
    Ok(VSpec { source: sub(m, "source", p_addr)?, span: sub(m, "span", p_span)? })
}

/// A `make_link` endset slot (wire v5): a V-spec array (content-resolved,
/// the v1 form, unchanged meaning) or `{"addrs": [addresses…]}` — the names
/// recorded verbatim, the same addrs-object encoding as `edit_link`'s
/// successor `ty`.
fn p_slotarg(v: &Value) -> PResult<SlotArg> {
    match v {
        Value::Array(_) => Ok(SlotArg::Resolve(p_list(v, p_vspec)?)),
        Value::Object(_) => {
            let m = p_obj(v, &["addrs"])?;
            Ok(SlotArg::Addrs(sub(m, "addrs", |v| p_list(v, p_addr))?))
        }
        _ => Err(PErr("expected a v-spec array or {\"addrs\": [addresses…]}".into())),
    }
}

fn p_spec(v: &Value) -> PResult<Spec> {
    let m = p_obj(v, &["doc", "span"])?;
    Ok(Spec { doc: sub(m, "doc", p_addr)?, span: sub(m, "span", p_span)? })
}

fn p_region(v: &Value) -> PResult<Region> {
    let m = p_obj(v, &["doc", "spans"])?;
    Ok(Region { doc: sub(m, "doc", p_addr)?, spans: sub(m, "spans", |v| p_list(v, p_span))? })
}

/// The `values` array of `insert`: each element is one of the four write
/// forms (wire.md §Content values), contributing zero or more values that
/// concatenate in order.
fn p_val_forms(v: &Value) -> PResult<Vec<Val>> {
    let arr = v.as_array().ok_or_else(|| PErr("expected a JSON array".into()))?;
    let mut out = Vec::new();
    for (i, x) in arr.iter().enumerate() {
        p_val_form(x, &mut out).map_err(|e| PErr(format!("[{i}]: {}", e.0)))?;
    }
    Ok(out)
}

/// One element of `values`. The per-byte forms (`"str"`, `{"hex"}`) mint one
/// single-byte value per byte — the substrate's text discipline, under which
/// every interior byte stays addressable — and admit the vacuous `""`. The
/// atom forms (`{"atom"}`, `{"atom_hex"}`) mint ONE composite value of all
/// the bytes: coarse granularity must be said, never fallen into; a
/// zero-byte atom is not expressible.
fn p_val_form(v: &Value, out: &mut Vec<Val>) -> PResult<()> {
    let m = match v {
        Value::String(s) => {
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
        let bytes = sub(m, "hex", |v| p_hex(&p_string(v)?))?;
        out.extend(bytes.into_iter().map(|b| Val::new(vec![b])));
    } else if m.contains_key("atom") {
        let s = sub(m, "atom", p_string)?;
        if s.is_empty() {
            return Err(PErr("atom: a zero-byte atom is not expressible".into()));
        }
        out.push(Val::new(s.into_bytes()));
    } else {
        let bytes = sub(m, "atom_hex", |v| p_hex(&p_string(v)?))?;
        if bytes.is_empty() {
            return Err(PErr("atom_hex: a zero-byte atom is not expressible".into()));
        }
        out.push(Val::new(bytes));
    }
    Ok(())
}

fn p_hex(s: &str) -> PResult<Vec<u8>> {
    // `% 2`, not `is_multiple_of`: the workspace MSRV is 1.85 and
    // `u64::is_multiple_of` stabilized in 1.87 (clippy::incompatible_msrv).
    if s.len() % 2 != 0 {
        return Err(PErr("hex string has odd length".into()));
    }
    let b = s.as_bytes();
    (0..s.len() / 2).map(|i| Ok(hex_digit(b[2 * i])? * 16 + hex_digit(b[2 * i + 1])?)).collect()
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
        home: sub(m, "home", p_slotspec)?,
        from: sub(m, "from", p_slotspec)?,
        to: sub(m, "to", p_slotspec)?,
        ty: sub(m, "ty", p_slotspec)?,
    })
}

/// EditLink's successor: content V-specs for from/to; the type slot is
/// exactly one of `{"addrs": […]}` (address-denoting — the identical
/// encoding of `make_link`'s addrs form) or `{"resolve": […]}`
/// (content-resolved), mirroring M10's `SlotArg`.
fn p_successor(v: &Value) -> PResult<SuccessorSpec> {
    let m = p_obj(v, &["from", "to", "ty"])?;
    Ok(SuccessorSpec {
        from: sub(m, "from", |v| p_list(v, p_vspec))?,
        to: sub(m, "to", |v| p_list(v, p_vspec))?,
        ty: sub(m, "ty", p_successor_ty)?,
    })
}

fn p_successor_ty(v: &Value) -> PResult<SlotArg> {
    let m = p_obj(v, &["addrs", "resolve"])?;
    match (m.get("addrs"), m.get("resolve")) {
        (Some(a), None) => Ok(SlotArg::Addrs(p_list(a, p_addr).map_err(|e| PErr(format!("addrs: {}", e.0)))?)),
        (None, Some(r)) => Ok(SlotArg::Resolve(p_list(r, p_vspec).map_err(|e| PErr(format!("resolve: {}", e.0)))?)),
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
            vec![("doc", j_addr(doc)), ("at", j_vpos(at)), ("values", j_val_forms(values))],
        ),
        Op::Delete { doc, p, width } => (
            op_name(OpKind::Delete),
            vec![("doc", j_addr(doc)), ("p", j_vpos(p)), ("width", j_nat(width))],
        ),
        Op::Copy { doc, at, specs } => (
            op_name(OpKind::Copy),
            vec![("doc", j_addr(doc)), ("at", j_vpos(at)), ("specs", j_vspecs(specs))],
        ),
        Op::Rearrange { doc, cuts } => (
            op_name(OpKind::Rearrange),
            vec![("doc", j_addr(doc)), ("cuts", Value::Array(cuts.iter().map(j_vpos).collect()))],
        ),
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
        Op::RetrieveV { specs } => (
            op_name(OpKind::RetrieveV),
            vec![("specs", Value::Array(specs.iter().map(j_spec).collect()))],
        ),
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
            (op_name(OpKind::Image), vec![("d", j_addr(d)), ("region", j_span_list(region))])
        }
        Op::FindLinksV { d, region } => (
            op_name(OpKind::FindLinksV),
            vec![("d", j_addr(d)), ("region", j_span_list(region))],
        ),
        Op::FindLinksFtt { q } => (op_name(OpKind::FindLinksFtt), vec![("q", j_fourset(q))]),
        Op::CountV { d, region } => {
            (op_name(OpKind::CountV), vec![("d", j_addr(d)), ("region", j_span_list(region))])
        }
        Op::CountFtt { q } => (op_name(OpKind::CountFtt), vec![("q", j_fourset(q))]),
        Op::WindowV { d, region, cur, n } => (
            op_name(OpKind::WindowV),
            vec![
                ("d", j_addr(d)),
                ("region", j_span_list(region)),
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
            vec![("d", j_addr(d)), ("region", j_span_list(region))],
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
        Response::Endsets { pairs: ps, as_of } => (
            "endsets",
            vec![
                (
                    "pairs",
                    Value::Array(
                        ps.iter()
                            .map(|(slot, e)| {
                                obj(vec![("slot", j_usize(*slot)), ("endset", j_endset(e))])
                            })
                            .collect(),
                    ),
                ),
                ("as_of", j_seq(*as_of)),
            ],
        ),
        Response::Runs { runs, as_of } => (
            "runs",
            vec![
                ("runs", Value::Array(runs.iter().map(j_run).collect())),
                ("as_of", j_seq(*as_of)),
            ],
        ),
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
        // The in-band Result (⟨⟩ ≠ ⊥ is a defined FOLLOWLINK answer).
        Response::Follow { result, as_of } => (
            "follow",
            vec![
                (
                    "result",
                    match result {
                        Ok(set) => obj(vec![("ok", j_spanset(set))]),
                        Err(_) => obj(vec![("err", Value::String("invalid".into()))]),
                    },
                ),
                ("as_of", j_seq(*as_of)),
            ],
        ),
        Response::Deletions { rep, as_of } => (
            "deletions",
            vec![
                (
                    "rep",
                    obj(vec![
                        ("a_with_b", j_addrs(&rep.a_with_b)),
                        ("b_with_a", j_addrs(&rep.b_with_a)),
                    ]),
                ),
                ("as_of", j_seq(*as_of)),
            ],
        ),
        Response::Compare { rep, as_of } => (
            "compare",
            vec![
                ("pairs", Value::Array(rep.0.iter().map(j_corr).collect())),
                ("as_of", j_seq(*as_of)),
            ],
        ),
        Response::Orphans { report, as_of } => (
            "orphans",
            vec![("orphaned", j_addrs(&report.orphaned)), ("as_of", j_seq(*as_of))],
        ),
        Response::Claims { claims, as_of } => (
            "claims",
            vec![
                ("claims", Value::Array(claims.iter().map(j_claim).collect())),
                ("as_of", j_seq(*as_of)),
            ],
        ),
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

fn j_tum(t: &Tumbler) -> Value {
    Value::String(tumbler_string(t))
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

fn j_span_list(spans: &[Span]) -> Value {
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

fn j_vspec(v: &VSpec) -> Value {
    obj(vec![("source", j_addr(&v.source)), ("span", j_span(&v.span))])
}

fn j_vspecs(vs: &[VSpec]) -> Value {
    Value::Array(vs.iter().map(j_vspec).collect())
}

/// [`p_slotarg`]'s inverse: the Resolve form is the bare v-spec array (v4
/// bytes unchanged), the Addrs form the tagged object.
fn j_slotarg(s: &SlotArg) -> Value {
    match s {
        SlotArg::Resolve(v) => j_vspecs(v),
        SlotArg::Addrs(a) => obj(vec![("addrs", j_addrs(a))]),
    }
}

fn j_spec(s: &Spec) -> Value {
    obj(vec![("doc", j_addr(&s.doc)), ("span", j_span(&s.span))])
}

fn j_region(r: &Region) -> Value {
    obj(vec![("doc", j_addr(&r.doc)), ("spans", j_span_list(&r.spans))])
}

fn j_regions(rs: &[Region]) -> Value {
    Value::Array(rs.iter().map(j_region).collect())
}

/// The canonical rendering of a position-value sequence, and the one place
/// its rule lives: consecutive single-byte values accumulate into a run
/// rendered as ONE item (UTF-8 judged on the whole run, else `{"hex"}`); a
/// composite value flushes the run and renders as its own atom item, never
/// coalesced with a neighbor. Maximal runs are what make the rendering
/// injective — two distinct position-value sequences never render alike —
/// and what re-canonicalize the parse-side normalizations (element
/// boundaries between adjacent per-byte forms, one-byte atoms), so
/// `parse(marshal_request(r))` reproduces `r`.
///
/// `utf8` is the ONLY thing the two renderings differ by: a request
/// `values` element is the bare string, a delivery item is
/// `{"content": …}`.
struct Runs {
    out: Vec<Value>,
    run: Vec<u8>,
    utf8: fn(String) -> Value,
}

impl Runs {
    fn new(utf8: fn(String) -> Value) -> Runs {
        Runs { out: Vec::new(), run: Vec::new(), utf8 }
    }

    /// One position's value: a single-byte value joins the pending run, a
    /// composite one breaks it and becomes its own atom item.
    fn value(&mut self, v: &Val) {
        if let [b] = v.as_bytes() {
            self.run.push(*b);
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
        if self.run.is_empty() {
            return;
        }
        let item = match String::from_utf8(std::mem::take(&mut self.run)) {
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

/// The canonical `values` encoding — [`p_val_forms`]'s inverse, under
/// [`Runs`]' rule with the bare-string run form.
fn j_val_forms(vs: &[Val]) -> Value {
    let mut runs = Runs::new(Value::String);
    for v in vs {
        runs.value(v);
    }
    runs.finish()
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

fn hex_string(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
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

/// Delivery items — [`Runs`]' rule with the `{"content"}` run form, plus
/// link positions as `{"ref"}`. The item key names the granularity, so a
/// client always knows which world it is looking at.
fn j_items(items: &[DeliveryItem]) -> Value {
    let mut runs = Runs::new(|s| obj(vec![("content", Value::String(s))]));
    for it in items {
        match it {
            DeliveryItem::Content(v) => runs.value(v),
            DeliveryItem::Ref(a) => runs.item(obj(vec![("ref", j_addr(a))])),
        }
    }
    runs.finish()
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

fn j_corr(p: &CorrPair) -> Value {
    obj(vec![
        ("d1", j_addr(&p.d1)),
        ("u1", j_vpos(&p.u1)),
        ("d2", j_addr(&p.d2)),
        ("u2", j_vpos(&p.u2)),
        ("width", j_nat(&p.width)),
    ])
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
    /// runs of digits joined by single dots; magnitude is unbounded.
    #[test]
    fn tumbler_parse_edges() {
        let ok = p_tum(&Value::String("1.0.1".into())).map(|t| tumbler_string(&t));
        assert_eq!(ok.map_err(|e| e.0).unwrap(), "1.0.1");
        // Beyond u64: parses through the BigUint path and renders back.
        let big = "18446744073709551616"; // 2^64
        let t = p_tum(&Value::String(big.into())).map_err(|e| e.0).unwrap();
        assert_eq!(tumbler_string(&t), big);
        for bad in ["", ".", "1..2", "1.", ".1", "1.-2", "1.+2", "1.a", "1 .2"] {
            assert!(p_tum(&Value::String(bad.into())).is_err(), "'{bad}' must not parse");
        }
    }

    /// Value granularity at the leaf: per-byte forms mint one single-byte
    /// value per byte, atom forms one composite value; the canonical marshal
    /// coalesces maximal per-byte runs (UTF-8 judged on the whole run) and
    /// never coalesces atoms.
    #[test]
    fn value_forms_parse_per_byte_and_atoms_marshal_apart() {
        let mut vs: Vec<Val> = Vec::new();
        p_val_form(&Value::String("hé".into()), &mut vs).map_err(|e| e.0).unwrap();
        assert_eq!(vs.len(), 3, "'h' plus the two bytes of 'é'");
        assert!(vs.iter().all(|v| v.len() == 1));
        p_val_form(&obj(vec![("atom", Value::String("hé".into()))]), &mut vs)
            .map_err(|e| e.0)
            .unwrap();
        assert_eq!(vs.len(), 4);
        assert_eq!(vs[3].as_bytes(), "hé".as_bytes());
        // Canonical inverse: the run reassembles, the atom stays its own form.
        let canon = j_val_forms(&vs);
        let expect: Value = serde_json::from_str(r#"["hé",{"atom":"hé"}]"#).unwrap();
        assert_eq!(canon, expect);
        // Empty per-byte forms are vacuous; empty atoms are inexpressible;
        // multi-key objects and non-string/object elements are malformed.
        let mut none: Vec<Val> = Vec::new();
        p_val_form(&Value::String(String::new()), &mut none).map_err(|e| e.0).unwrap();
        p_val_form(&obj(vec![("hex", Value::String(String::new()))]), &mut none)
            .map_err(|e| e.0)
            .unwrap();
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

    /// Marshal determinism in miniature: obj() sorts, so construction order
    /// cannot leak into bytes.
    #[test]
    fn obj_is_order_insensitive() {
        let a = obj(vec![("b", j_u64(2)), ("a", j_u64(1))]);
        let b = obj(vec![("a", j_u64(1)), ("b", j_u64(2))]);
        assert_eq!(to_bytes(a), to_bytes(b));
    }
}
