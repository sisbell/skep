//! The rig: one fresh engine + operation surface per scenario, the session
//! and account plumbing, and the harness-owned type-registry document.
//!
//! Durability choice: `Durability::InMemory`. This instrument compares
//! OPERATION SEMANTICS, not durability — every scenario runs start-to-finish
//! in one process with no restart, so the journal would never be read back;
//! atomicity/isolation are identical under both modes (M2's contract), and
//! crash/recovery behavior belongs to the crash harness, not here. In-memory
//! also needs no temp directory, removing a whole class of environment
//! failures from a 263-scenario run.

use skep_address::{Address, Nat, Span};
use skep_arrangement::{Run, VPos, VSpec};
use skep_content::Val;
use skep_engine::{Engine, World};
use skep_febe::{Op, Operation, Request, Response, SessionId};
use skep_kernel::{CheckpointPolicy, Durability, KernelConfig};
use skep_links::Endset;
use skep_namespace::PrincipalId;

use std::collections::BTreeMap;

use crate::tum::{addr, span_elem_width, subspan, vspan};

/// One content-subspace deletion, captured at delete time (operator ruling
/// 10, round-3): the golden doc it left, the bytes removed, and the I-extent
/// runs those bytes occupied — imaged through `Op::Image` in the same commit
/// window, while the arrangement still spoke for them. Deleted content stays
/// findable through these spans (I-history), never by loosening V-queries.
pub struct DeletedRegion {
    pub doc: String,
    pub bytes: Vec<u8>,
    pub ispans: Vec<Span>,
}

pub struct Rig {
    // Held so the engine (and its kernel Arc) outlives the operation handle;
    // EngineStores owns its own Arc clone, but keeping the assembler visible
    // makes the ownership story auditable.
    _engine: Engine,
    op: Operation<World>,
    /// Bootstrap session — all delegations run under it (π₀'s prefix [1] is
    /// an ancestor of every prefix we mint).
    boot: SessionId,
    /// Per skep-account sessions: dotted account string → (session, id).
    sessions: BTreeMap<String, (SessionId, PrincipalId)>,
    /// Golden session labels ("A"/"B"/"C") → skep account addr string (a
    /// `sessions` key). Bound by `account` ops carrying a `session` field;
    /// ops carrying `session` route through the label's account session.
    labels: BTreeMap<String, String>,
    /// The session scenario ops execute under (switched by `account`).
    pub current_session: SessionId,
    /// The account new documents mint under.
    pub current_account: Address,
    next_principal: u64,
    /// The harness type-registry document: one content position per link
    /// type name (adaptation policy `type_registry`). Its address is harness
    /// infrastructure — never bound in the α-map.
    pub types_doc: Address,
    type_ordinals: BTreeMap<String, u64>,
    types_capacity: u64,
    /// Content deletions in execution order (see [`DeletedRegion`]).
    pub deleted: Vec<DeletedRegion>,
}

/// Rig construction failure — an environment/engine problem, surfaced as the
/// scenario verdict `error` (harness bug class), never as a finding.
pub type RigError = String;

impl Rig {
    pub fn new() -> Result<Rig, RigError> {
        let cfg = KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
        };
        let engine = Engine::open(cfg)
            .map_err(|e| format!("engine open: {e}"))?;
        let op = Operation::new(Box::new(engine.stores()));
        let boot = op.bootstrap_session();

        // Delegate the scenario's working account under node [1] — udanax's
        // DEFAULT_ACCOUNT analog. The α seed "1.1.0.1" ↦ this account is
        // installed by the runner.
        let node = addr(&[1]).ok_or("node [1] must validate")?;
        let prefix = match op.execute(
            boot,
            Request { id: None, op: Op::NextAccountPrefix { parent: node } },
        ) {
            Response::MaybeAddr { addr: Some(a), .. } => a,
            other => return Err(format!("next-account-prefix failed: {}", brief(&other))),
        };
        let account = match op.execute(
            boot,
            Request {
                id: None,
                op: Op::Delegate {
                    new_prefix: prefix.tumbler().clone(),
                    new_id: PrincipalId(1),
                },
            },
        ) {
            Response::AckAddr { addr, .. } => addr,
            other => return Err(format!("bootstrap delegate failed: {}", brief(&other))),
        };
        let session = op.open_session(PrincipalId(1));

        let mut rig = Rig {
            _engine: engine,
            op,
            boot,
            sessions: BTreeMap::new(),
            labels: BTreeMap::new(),
            current_session: session,
            current_account: account.clone(),
            next_principal: 2,
            types_doc: addr(&[1]).expect("placeholder, replaced below"),
            type_ordinals: BTreeMap::new(),
            types_capacity: 8,
            deleted: Vec::new(),
        };
        rig.sessions
            .insert(crate::tum::addr_str(&account), (session, PrincipalId(1)));

        // The type-registry document: `types_capacity` content positions,
        // each the identity of one link-type name (names are assigned to
        // ordinals on first use). Created through the same op surface the
        // scenarios use — the harness holds no back door.
        // Minted PRIVATE at the engine (PUB-8.16 `Some(false)`): the harness
        // drives M10 directly, with no daemon door, so each scenario
        // account's first document is born private and the goldens stay
        // byte-identical (PUB lane 0's verified promise).
        let tdoc = match rig.exec(Op::CreateNewDocument { account: account.clone(), published: Some(false) }) {
            Response::AckAddr { addr, .. } => addr,
            other => return Err(format!("types-doc create failed: {}", brief(&other))),
        };
        let vals: Vec<Val> = (0..rig.types_capacity).map(|i| Val::new(vec![b'T', i as u8])).collect();
        match rig.exec(Op::Insert {
            doc: tdoc.clone(),
            at: VPos { subspace: Nat::from(1u64), ordinal: Nat::from(1u64) },
            values: vals,
        }) {
            Response::AckAddr { .. } => {}
            other => return Err(format!("types-doc insert failed: {}", brief(&other))),
        }
        rig.types_doc = tdoc;
        Ok(rig)
    }

    /// Execute one request under the current session. No idempotency key —
    /// the harness replays a linear script.
    pub fn exec(&self, o: Op) -> Response {
        self.op.execute(self.current_session, Request { id: None, op: o })
    }

    /// The initially delegated account (α seed target).
    pub fn default_account(&self) -> Address {
        // The first session entry is the bootstrap-delegated account.
        self.current_account.clone()
    }

    /// `account` op support (adaptation `account_as_delegate`): make the
    /// named golden account current, delegating a fresh skep account (and
    /// principal + session) on first sight. Returns the skep account now
    /// current.
    pub fn switch_account(&mut self, existing: Option<Address>) -> Result<Address, String> {
        if let Some(a) = existing {
            let key = crate::tum::addr_str(&a);
            if let Some((s, _)) = self.sessions.get(&key) {
                self.current_session = *s;
                self.current_account = a.clone();
                return Ok(a);
            }
            // Bound address without a session — an account we minted via
            // create_node; open a session for its principal id if we know it.
            return Err(format!("account {key} has no session (not delegated by this rig)"));
        }
        let node = addr(&[1]).ok_or("node [1] must validate")?;
        self.delegate_under(&node, true)
    }

    /// Bind a golden session label to a skep account (the `account` op's
    /// session field does this; a label may be re-bound — ms_create_race's B
    /// switches from 1.1.0.1 to 1.1.0.2 mid-scenario). Two labels sharing an
    /// account share its session: M10 sessions carry only the principal
    /// binding, so the shared session is observably identical and the map
    /// stays one-session-per-account.
    pub fn bind_session_label(&mut self, label: &str, account: &Address) {
        self.labels
            .insert(label.to_string(), crate::tum::addr_str(account));
    }

    /// Route the working session/account to a golden session label. An
    /// unbound label (an op carries `session` before any `account` op bound
    /// it) binds to the CURRENT account — returns `true` so the caller can
    /// tag the implicit bind.
    pub fn route_session(&mut self, label: &str) -> Result<bool, String> {
        let implicit = if self.labels.contains_key(label) {
            false
        } else {
            let cur = crate::tum::addr_str(&self.current_account);
            self.labels.insert(label.to_string(), cur);
            true
        };
        let key = self.labels[label].clone();
        let Some((s, _)) = self.sessions.get(&key) else {
            return Err(format!("session label {label}: account {key} has no session"));
        };
        self.current_session = *s;
        let a = parse_account_addr(&key)
            .ok_or_else(|| format!("session label {label}: account {key} unparseable"))?;
        self.current_account = a;
        Ok(implicit)
    }

    /// Delegate the next account-tier prefix under `parent` to a fresh
    /// principal and open its session. `make_current` switches the working
    /// session to it (the `account` op does; `create_node` — udanax's
    /// sub-account mint — does not).
    ///
    /// The Delegate request runs under the session of the principal that
    /// OWNS `parent` (M3's ω check: only the owner may carve its prefix).
    /// Node [1] belongs to π₀ (the bootstrap session); a scenario account
    /// belongs to the principal this rig delegated it to.
    pub fn delegate_under(&mut self, parent: &Address, make_current: bool) -> Result<Address, String> {
        let owner_session = self
            .sessions
            .get(&crate::tum::addr_str(parent))
            .map(|(s, _)| *s)
            .unwrap_or(self.boot);
        let prefix = match self.op.execute(
            owner_session,
            Request { id: None, op: Op::NextAccountPrefix { parent: parent.clone() } },
        ) {
            Response::MaybeAddr { addr: Some(a), .. } => a,
            other => return Err(format!("next-account-prefix: {}", brief(&other))),
        };
        let id = PrincipalId(self.next_principal);
        self.next_principal += 1;
        let account = match self.op.execute(
            owner_session,
            Request {
                id: None,
                op: Op::Delegate { new_prefix: prefix.tumbler().clone(), new_id: id },
            },
        ) {
            Response::AckAddr { addr, .. } => addr,
            other => return Err(format!("delegate: {}", brief(&other))),
        };
        let session = self.op.open_session(id);
        self.sessions
            .insert(crate::tum::addr_str(&account), (session, id));
        if make_current {
            self.current_session = session;
            self.current_account = account.clone();
        }
        Ok(account)
    }

    /// The content V-spec denoting one link-type name (policy
    /// `type_registry`): position k of the types document, where k is the
    /// name's assigned ordinal (assigned on first use, stable thereafter).
    /// `None` when the fixed capacity is exhausted — surfaced as
    /// inexpressible by the caller.
    pub fn type_vspec(&mut self, name: &str) -> Option<VSpec> {
        let next = self.type_ordinals.len() as u64 + 1;
        let ord = *self.type_ordinals.entry(name.to_string()).or_insert(next);
        if ord > self.types_capacity {
            return None;
        }
        Some(VSpec { source: self.types_doc.clone(), span: vspan(1, ord, 1)? })
    }

    /// The I-space endset of one type name — for FTT type filters. Resolved
    /// through Op::Image on the types document (the sanctioned V→I surface).
    pub fn type_endset(&mut self, name: &str) -> Option<Endset> {
        let vs = self.type_vspec(name)?;
        match self.exec(Op::Image { d: vs.source.clone(), region: vec![vs.span.clone()] }) {
            Response::Runs { runs, .. } if !runs.is_empty() => {
                Some(Endset::from_spans(runs.iter().map(skep_arrangement::Run::iextent)))
            }
            _ => None,
        }
    }

    /// Is `a` inside the harness's own types document? Used to exclude
    /// harness infrastructure from comparisons (part of the `type_registry`
    /// policy — the types doc encodes type NAMES, which the golden encodes
    /// as unresolvable link-subspace specs; comparing the two rendered forms
    /// would compare encodings, not behavior).
    pub fn is_types_addr(&self, a: &Address) -> bool {
        skep_address::is_prefix(self.types_doc.tumbler(), a.tumbler())
    }

    /// Capture a content region's I-extents just before it is deleted
    /// (ruling 10): image the doomed V-region and remember (bytes, I-runs).
    /// An image failure is swallowed — the deletion proceeds regardless, and
    /// a later I-coverage search over the missing record simply fails to
    /// ground, surfacing as its own honest outcome.
    pub fn capture_deletion(&mut self, golden_doc: &str, d: &Address, ord: u64, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        let Some(span) = vspan(1, ord, bytes.len() as u64) else { return };
        let r = self.exec(Op::Image { d: d.clone(), region: vec![span] });
        if let Response::Runs { runs, .. } = r {
            let ispans: Vec<Span> = runs.iter().map(Run::iextent).collect();
            self.deleted.push(DeletedRegion { doc: golden_doc.to_string(), bytes, ispans });
        }
    }

    /// Every captured I-span of a document's deleted content — the
    /// I-coverage stand-in for a whole-extent query aimed at a doc whose
    /// current extent no longer holds what the golden searched.
    pub fn deleted_ispans_of(&self, golden_doc: &str) -> Vec<Span> {
        self.deleted
            .iter()
            .filter(|r| r.doc == golden_doc)
            .flat_map(|r| r.ispans.iter().cloned())
            .collect()
    }

    /// The deleted bytes of a document, latest deletion first — for
    /// re-locating a doc-aimed search's content in the docs that still hold
    /// it live.
    pub fn deleted_bytes_of(&self, golden_doc: &str) -> Vec<Vec<u8>> {
        self.deleted
            .iter()
            .rev()
            .filter(|r| r.doc == golden_doc)
            .map(|r| r.bytes.clone())
            .collect()
    }

    /// Locate `needle` inside any captured deletion and slice out its exact
    /// I-spans — the I-history reach for a search whose text no live V-space
    /// speaks anymore. First (newest-deletion-first) hit wins.
    pub fn locate_deleted(&self, needle: &[u8]) -> Option<Vec<Span>> {
        if needle.is_empty() {
            return None;
        }
        for rec in self.deleted.iter().rev() {
            let Some(p) = rec.bytes.windows(needle.len()).position(|w| w == needle) else {
                continue;
            };
            // Walk the record's runs, slicing the [p, p+len) byte window.
            let (mut off, mut remaining, mut cursor) = (p as u64, needle.len() as u64, Vec::new());
            for sp in &rec.ispans {
                let w = span_elem_width(sp).unwrap_or(0);
                if off >= w {
                    off -= w;
                    continue;
                }
                let take = (w - off).min(remaining);
                if let Some(sub) = subspan(sp, off, take) {
                    cursor.push(sub);
                } else {
                    cursor.clear();
                    break;
                }
                remaining -= take;
                off = 0;
                if remaining == 0 {
                    break;
                }
            }
            if remaining == 0 && !cursor.is_empty() {
                return Some(cursor);
            }
        }
        None
    }
}

/// Re-validate a stored dotted account string back to an `Address` (the
/// `sessions`/`labels` maps key by string; routing needs the value form).
fn parse_account_addr(s: &str) -> Option<Address> {
    let comps = crate::tum::parse_dotted(s)?;
    crate::tum::addr(&comps)
}

/// One-line rendering of a response for rig-internal error strings.
pub fn brief(r: &Response) -> String {
    match r {
        Response::Rejected(rej) => format!("Rejected({:?})", rej.code),
        Response::Ack { .. } => "Ack".into(),
        Response::AckAddr { .. } => "AckAddr".into(),
        Response::AckEdit { .. } => "AckEdit".into(),
        Response::MaybeAddr { .. } => "MaybeAddr".into(),
        _ => "Response".into(),
    }
}
