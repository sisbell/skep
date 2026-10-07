//! The rig: one fresh engine + operation surface per scenario, the session
//! and account plumbing, and the harness-owned types document.
//!
//! Every request reaches skep through one door, [`execute`] — the crate's
//! only call of `OperationSurface::execute`, which `tests/it/tidy.rs` holds
//! it to. M10 answers every request it is handed; a panic raised inside the
//! surface instead leaves the door as an [`EnginePanic`] naming the request,
//! so the runner reports a failure in skep, never a harness bug.
//!
//! Durability choice: `Durability::InMemory`. This instrument compares
//! OPERATION SEMANTICS, not durability — every scenario runs start-to-finish
//! in one process with no restart, so the journal would never be read back;
//! atomicity/isolation are identical under both modes (M2's contract), and
//! crash/recovery behavior belongs to the crash harness, not here. In-memory
//! also needs no temp directory, removing a whole class of environment
//! failures from a 263-scenario run.

use std::any::Any;
use std::collections::BTreeMap;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};

use skep_address::Address;
use skep_arrangement::VSpec;
use skep_content::Val;
use skep_engine::{Engine, World};
use skep_febe::{Deposit, Op, OpKind, OperationSurface, Request, Response, SessionId};
use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource};
use skep_links::{Endset, SlotArg};
use skep_namespace::PrincipalId;

use crate::tum::{addr, VPoint};

/// A panic raised inside skep's operation surface while it executed one
/// request: the payload such a panic resumes with once it leaves the rig's
/// door, so the runner reports skep, not the harness.
#[derive(Debug)]
pub struct EnginePanic {
    /// The kind of the request skep was executing.
    pub kind: OpKind,
    /// The panic's own message ([`panic_message`]).
    pub message: String,
}

/// One request through skep's operation surface: the crate's only call of
/// `OperationSurface::execute`. A panic inside it resumes as an
/// [`EnginePanic`] naming the request's kind.
fn execute(febe: &OperationSurface<World>, session: SessionId, op: Op) -> Response {
    let kind = op.kind();
    let req = Request::from(op);
    guard(kind, move || febe.execute(session, req))
}

/// `f`, with any panic it raises resumed as skep's [`EnginePanic`]. The
/// surface that panicked is never asked again: the panic unwinds out of the
/// scenario, whose rig is dropped with it.
fn guard(kind: OpKind, f: impl FnOnce() -> Response) -> Response {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(p) => resume_unwind(Box::new(EnginePanic { kind, message: panic_message(&*p) })),
    }
}

/// A panic payload's message: a `String` or `&str`, else a placeholder.
pub fn panic_message(payload: &(dyn Any + Send)) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_else(|| "panic with non-string payload".to_string())
}

/// The content positions the types document holds: one per link-type name
/// a scenario names (policy `types_document`).
const TYPES_CAPACITY: u64 = 8;

pub struct Rig {
    // Held so the engine (and its kernel Arc) outlives the command surface;
    // EngineStores owns its own Arc clone, but keeping the assembler visible
    // makes the ownership story auditable.
    _engine: Engine,
    febe: OperationSurface<World>,
    /// Bootstrap session — all delegations run under it (π₀'s prefix `[1]` is
    /// an ancestor of every prefix we mint).
    boot: SessionId,
    /// Per skep-account sessions: account → (session, principal).
    sessions: BTreeMap<Address, (SessionId, PrincipalId)>,
    /// Golden session labels ("A"/"B"/"C") → skep account (a `sessions`
    /// key). Bound by `account` ops carrying a `session` field; ops carrying
    /// `session` route through the label's account session.
    labels: BTreeMap<String, Address>,
    /// The session scenario ops execute under — always the session of
    /// `current_account`: after construction, [`Rig::make_current`] is the
    /// one writer of the pair.
    current_session: SessionId,
    /// The account new documents mint under (see
    /// [`Rig::create_private_document`]).
    current_account: Address,
    /// The account `Rig::new` delegated (see [`Rig::default_account`]).
    default_account: Address,
    next_principal: u64,
    /// The harness's types document: one content position per link type
    /// name (adaptation policy `types_document`). Its address is harness
    /// infrastructure — never bound in the α-map.
    types_doc: Address,
    type_ordinals: BTreeMap<String, u64>,
    /// Every rig account's HOME — its flagless first mint, born published
    /// (PUB-8.21), holding that account's setup grant (ruling 21). Harness
    /// infrastructure, like the types document: never bound in the α-map,
    /// excluded from every comparison through [`Rig::is_infra_addr`].
    homes: Vec<Address>,
}

/// Rig construction failure — an environment/engine problem, surfaced as the
/// scenario verdict `error` (harness bug class), never as a finding.
pub type RigError = String;

/// The GRANTS class type address (COMMONS DECISION 5 — `1.1.0.1.0.1.0.3.90`),
/// named here as a client names it, by value: the fold keys on the VALUE.
fn t_grant() -> Address {
    addr(&[1, 1, 0, 1, 0, 1, 0, 3, 90]).expect("the grants type address validates")
}

/// Node `[1]` — π₀'s node, under which the rig delegates every account.
fn node_one() -> Address {
    addr(&[1]).expect("[1] is a T4-valid node address")
}

impl Rig {
    /// The rig's SETUP GRANT for one account (ruling 21, exit B — the
    /// privash grant; PUB-1.31, PUB-5.8): mint the account's home flagless
    /// (its first mint, born published, PUB-8.21) and deposit there, under
    /// the account's own session, an ANY-PRINCIPAL account-rung grant —
    /// `ty` the grants class, `from` the account, `to` empty. Every document
    /// the account mints afterwards is then readable to every bound
    /// principal (the fold's coverage is containment, forward-inclusive),
    /// which is what the udanax corpus assumes: it has no publication state,
    /// so every cross-session read in a golden is a read of what skep calls
    /// an owned private draft. Through `make_link` — the harness holds no
    /// back door.
    fn setup_grant(
        febe: &OperationSurface<World>,
        session: SessionId,
        account: &Address,
    ) -> Result<Address, RigError> {
        let home = match execute(
            febe,
            session,
            Op::CreateNewDocument { account: account.clone(), published: None },
        ) {
            Response::AckAddr { addr, .. } => addr,
            other => return Err(format!("home mint failed: {}", brief(&other))),
        };
        match execute(
            febe,
            session,
            Op::MakeLink {
                home: home.clone(),
                from: SlotArg::Addrs(vec![account.clone()]),
                to: SlotArg::Addrs(vec![]),
                ty: SlotArg::Addrs(vec![t_grant()]),
                replaces: None,
            },
        ) {
            Response::AckAddr { .. } => Ok(home),
            other => Err(format!("setup grant failed: {}", brief(&other))),
        }
    }

    /// The harness's types document (policy `types_document`):
    /// [`TYPES_CAPACITY`] content positions, each the identity of one
    /// link-type name, names assigned to ordinals on first use
    /// ([`Rig::type_vspec`]). Minted PRIVATE (PUB-8.16 `Some(false)`) under
    /// the account's own session, through the same op surface the scenarios
    /// use — the harness holds no back door. It is the account's SECOND
    /// mint, after its home, so every scenario document's ordinal is
    /// shifted by both; the α-map is a bijection built from the acks, and
    /// absorbs the shift.
    fn types_document(
        febe: &OperationSurface<World>,
        session: SessionId,
        account: &Address,
    ) -> Result<Address, RigError> {
        let exec = |op: Op| execute(febe, session, op);
        let mint = Op::CreateNewDocument { account: account.clone(), published: Some(false) };
        let doc = match exec(mint) {
            Response::AckAddr { addr, .. } => addr,
            other => return Err(format!("types-doc create failed: {}", brief(&other))),
        };
        let values: Vec<Val> =
            (0..TYPES_CAPACITY).map(|i| Val::new(vec![b'T', i as u8])).collect();
        match exec(Op::Insert {
            doc: doc.clone(),
            at: VPoint::content(1).vpos(),
            values,
            deposit: Deposit::Undeclared,
        }) {
            Response::AckAddr { .. } => Ok(doc),
            other => Err(format!("types-doc insert failed: {}", brief(&other))),
        }
    }

    pub fn new() -> Result<Rig, RigError> {
        let cfg = KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
            // Consulted by nothing: an in-memory kernel frames no marker.
            salt: SaltSource::Os,
        };
        let engine = Engine::open(cfg).map_err(|e| format!("engine open: {e}"))?;
        let febe = OperationSurface::new(Box::new(engine.stores()));
        let boot = febe.bootstrap_session();

        // Delegate the scenario's working account under node [1] — udanax's
        // DEFAULT_ACCOUNT analog. The α seed "1.1.0.1" ↦ this account is
        // installed by the runner.
        let prefix = match execute(&febe, boot, Op::NextAccountPrefix { parent: node_one() }) {
            Response::MaybeAddr { addr: Some(a), .. } => a,
            other => return Err(format!("next-account-prefix failed: {}", brief(&other))),
        };
        let account = match execute(
            &febe,
            boot,
            Op::Delegate { new_prefix: prefix.tumbler().clone(), new_id: PrincipalId(1) },
        ) {
            Response::AckAddr { addr, .. } => addr,
            other => return Err(format!("bootstrap delegate failed: {}", brief(&other))),
        };
        let session = febe.open_session(PrincipalId(1));
        // The account's home and its setup grant come FIRST: the home must
        // be the account's doc 1 (the fold's residence pin, PUB-5.17). The
        // types document is its second mint.
        let home = Rig::setup_grant(&febe, session, &account)?;
        let types_doc = Rig::types_document(&febe, session, &account)?;
        Ok(Rig {
            _engine: engine,
            febe,
            boot,
            sessions: BTreeMap::from([(account.clone(), (session, PrincipalId(1)))]),
            labels: BTreeMap::new(),
            current_session: session,
            current_account: account.clone(),
            default_account: account,
            next_principal: 2,
            types_doc,
            type_ordinals: BTreeMap::new(),
            homes: vec![home],
        })
    }

    /// Execute one request under the current session, through the door
    /// ([`execute`]). No idempotency key — the harness replays a linear
    /// script.
    pub fn exec(&self, o: Op) -> Response {
        execute(&self.febe, self.current_session, o)
    }

    /// Create one scenario document: CREATENEWDOCUMENT in the current
    /// account, under the current session — its owner's — minted PRIVATE
    /// (PUB-8.16 `Some(false)`). The harness drives M10 directly, with no
    /// daemon door, so a private first mint keeps the goldens byte-identical
    /// (PUB lane 0's promise). Every scenario document is created here;
    /// `tests/it/tidy.rs` holds every other file to building no
    /// CREATENEWDOCUMENT request itself.
    pub fn create_private_document(&self) -> Response {
        self.exec(Op::CreateNewDocument {
            account: self.current_account.clone(),
            published: Some(false),
        })
    }

    /// The account `Rig::new` delegated: the image of udanax's default
    /// account, which the runner seeds into α. Fixed for the rig's life,
    /// whatever account later ops make current.
    pub fn default_account(&self) -> &Address {
        &self.default_account
    }

    /// Make `account` current, `session` its session — the one writer of
    /// the pair after construction, so the session `exec` runs under and
    /// the account a mint names never come apart.
    fn make_current(&mut self, account: Address, session: SessionId) {
        self.current_account = account;
        self.current_session = session;
    }

    /// `account` op support (adaptation `account_as_delegate`): make an
    /// account this rig delegated current again, under its own session.
    pub fn switch_to(&mut self, account: &Address) -> Result<(), String> {
        let Some(&(session, _)) = self.sessions.get(account) else {
            // α bound the golden account to an address no delegation of
            // this rig produced: no principal of the rig owns it.
            return Err(format!("account {account} has no session (not delegated by this rig)"));
        };
        self.make_current(account.clone(), session);
        Ok(())
    }

    /// `account` op support on first sight of a golden account: delegate a
    /// fresh skep account (and principal and session) under node `[1]` and
    /// make it current. Returns the account.
    pub fn delegate_account(&mut self) -> Result<Address, String> {
        let (account, session) = self.delegate(&node_one())?;
        self.make_current(account.clone(), session);
        Ok(account)
    }

    /// Bind a golden session label to a skep account (the `account` op's
    /// session field does this; a label may be re-bound — ms_create_race's B
    /// switches from 1.1.0.1 to 1.1.0.2 mid-scenario). Two labels sharing an
    /// account share its session: M10 sessions carry only the principal
    /// binding, so the shared session is observably identical and the map
    /// stays one-session-per-account.
    pub fn bind_session_label(&mut self, label: &str, account: &Address) {
        self.labels.insert(label.to_string(), account.clone());
    }

    /// Route the working session/account to a golden session label. An
    /// unbound label (an op carries `session` before any `account` op bound
    /// it) binds to the CURRENT account — returns `true` so the caller can
    /// tag the implicit bind.
    pub fn route_session(&mut self, label: &str) -> Result<bool, String> {
        let implicit = !self.labels.contains_key(label);
        let account = self
            .labels
            .entry(label.to_string())
            .or_insert_with(|| self.current_account.clone())
            .clone();
        let Some(&(session, _)) = self.sessions.get(&account) else {
            return Err(format!("session label {label}: account {account} has no session"));
        };
        self.make_current(account, session);
        Ok(implicit)
    }

    /// Delegate the next account-tier prefix under `parent` to a fresh
    /// principal and open its session, leaving the working session where it
    /// is — `create_node`'s sub-account mint (adaptation
    /// `create_node_as_delegate`).
    pub fn delegate_under(&mut self, parent: &Address) -> Result<Address, String> {
        self.delegate(parent).map(|(account, _)| account)
    }

    /// Delegate the next account-tier prefix under `parent` to a fresh
    /// principal; open its session and deposit its setup grant. Returns the
    /// account and its session.
    ///
    /// The Delegate request runs under the session of the principal that
    /// OWNS `parent` (M3's ω check: only the owner may carve its prefix).
    /// Node `[1]` belongs to π₀ (the bootstrap session); a scenario account
    /// belongs to the principal this rig delegated it to.
    fn delegate(&mut self, parent: &Address) -> Result<(Address, SessionId), String> {
        let owner_session = self.sessions.get(parent).map(|(s, _)| *s).unwrap_or(self.boot);
        let next = Op::NextAccountPrefix { parent: parent.clone() };
        let prefix = match execute(&self.febe, owner_session, next) {
            Response::MaybeAddr { addr: Some(a), .. } => a,
            other => return Err(format!("next-account-prefix: {}", brief(&other))),
        };
        let id = PrincipalId(self.next_principal);
        self.next_principal += 1;
        let delegate = Op::Delegate { new_prefix: prefix.tumbler().clone(), new_id: id };
        let account = match execute(&self.febe, owner_session, delegate) {
            Response::AckAddr { addr, .. } => addr,
            other => return Err(format!("delegate: {}", brief(&other))),
        };
        let session = self.febe.open_session(id);
        // Every rig-delegated account carries the setup grant (ruling 21),
        // deposited under ITS session — the owner of the home it goes in.
        let home = Rig::setup_grant(&self.febe, session, &account)?;
        self.homes.push(home);
        self.sessions.insert(account.clone(), (session, id));
        Ok((account, session))
    }

    /// The content V-spec denoting one link-type name (policy
    /// `types_document`): position k of the types document, where k is the
    /// name's assigned ordinal (assigned on first use, stable thereafter).
    /// `None` when the fixed capacity is exhausted — surfaced as
    /// inexpressible by the caller.
    pub fn type_vspec(&mut self, name: &str) -> Option<VSpec> {
        let next = self.type_ordinals.len() as u64 + 1;
        let ord = *self.type_ordinals.entry(name.to_string()).or_insert(next);
        if ord > TYPES_CAPACITY {
            return None;
        }
        Some(VSpec { source: self.types_doc.clone(), span: VPoint::content(ord).region(1).span()? })
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
    /// harness infrastructure from comparisons (part of the `types_document`
    /// policy — the types doc encodes type NAMES, which the golden encodes
    /// as unresolvable link-subspace specs; comparing the two rendered forms
    /// would compare encodings, not behavior).
    fn is_types_addr(&self, a: &Address) -> bool {
        skep_address::is_prefix(self.types_doc.tumbler(), a.tumbler())
    }

    /// Is `a` harness INFRASTRUCTURE — inside the types document, inside a
    /// rig account's home (the setup grant's residence, ruling 21), a rig
    /// account itself, or the grants class address? The `types_document`
    /// exclusion, widened to the setup grant: the grant's FROM endset is the
    /// account's subtree span, which M7's overlap (pure tumbler order, no
    /// level gate) counts as touching every content address under the
    /// account — so a FROM-constrained `find_links_ftt` over a rig account's
    /// content surfaces the grant link, which no golden can speak. Excluded
    /// before positional binding, exactly as the types document is.
    pub fn is_infra_addr(&self, a: &Address) -> bool {
        self.is_types_addr(a)
            || self.homes.iter().any(|h| skep_address::is_prefix(h.tumbler(), a.tumbler()))
            || self.sessions.contains_key(a)
            || *a == t_grant()
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a scenario document as every caller does. M3 refuses a mint
    /// whose session does not own the account it names (`NotOwner`), so this
    /// succeeds exactly when the session and the account are in step.
    fn mints(rig: &Rig) -> bool {
        matches!(rig.create_private_document(), Response::AckAddr { .. })
    }

    /// The session `exec` runs under and the account a mint names move
    /// together — through a delegation, a switch back, and a route by
    /// session label — and a pair out of step is refused, so the check
    /// discriminates. A sub-account delegation moves neither.
    #[test]
    fn the_session_and_the_account_move_together() {
        let mut rig = Rig::new().expect("the rig bootstraps");
        let first = rig.current_account.clone();
        assert!(mints(&rig));

        let second = rig.delegate_account().expect("a fresh account is delegated");
        assert_ne!(second, first);
        assert_eq!(rig.current_account, second);
        assert_eq!(rig.default_account(), &first, "the default account stays the first");
        assert!(mints(&rig));

        let sub = rig.delegate_under(&second).expect("a sub-account is delegated");
        assert_ne!(sub, second);
        assert_eq!(rig.current_account, second, "a sub-account delegation switches nothing");
        assert!(mints(&rig));

        rig.bind_session_label("B", &second);
        rig.switch_to(&first).expect("the first account has a session");
        assert_eq!(rig.current_account, first);
        assert!(mints(&rig));

        assert!(!rig.route_session("B").expect("label B is bound"), "an explicit bind");
        assert_eq!(rig.current_account, second);
        assert!(mints(&rig));

        rig.current_account = first;
        assert!(!mints(&rig), "a mint naming another principal's account is refused");
    }

    /// `doc`·0·1·1 — the first content element of a document.
    fn element_of(doc: &Address) -> Address {
        let local = [0u64, 1, 1].map(skep_address::Nat::from);
        let comps = doc.tumbler().iter().cloned().chain(local);
        let tumbler = skep_address::Tumbler::new(comps).expect("a nonempty tumbler");
        skep_address::validate(tumbler).expect("an element address")
    }

    /// Harness infrastructure is exactly the rig's own addresses — the
    /// types document and what it holds, every account's home, every
    /// account, the grants class — and never a scenario document or
    /// anything in one: a predicate wider than that would filter skep's
    /// real answers away before a comparison could see them.
    #[test]
    fn infrastructure_is_exactly_the_rigs_own_addresses() {
        let mut rig = Rig::new().expect("the rig bootstraps");
        let Response::AckAddr { addr: doc, .. } = rig.create_private_document() else {
            panic!("a scenario document is minted");
        };
        let types = rig.type_vspec("jump").expect("a types-document position").source;
        let first = rig.default_account().clone();
        let second = rig.delegate_account().expect("a second account");
        assert_eq!(rig.homes.len(), 2, "each account carries its home");
        let (homes, held, grants) = (rig.homes.clone(), element_of(&types), t_grant());
        for infra in [&types, &held, &homes[0], &homes[1], &first, &second, &grants] {
            assert!(rig.is_infra_addr(infra), "{infra} is infrastructure");
        }
        for scenario in [doc.clone(), element_of(&doc)] {
            assert!(!rig.is_infra_addr(&scenario), "{scenario} is the scenario's own");
        }
    }

    /// A panic inside the surface leaves the door as skep's own, naming the
    /// request's kind and carrying the panic's message.
    #[test]
    fn a_panic_inside_the_surface_resumes_as_skeps() {
        let payload = catch_unwind(|| guard(OpKind::Insert, || -> Response { panic!("boom") }))
            .expect_err("the panic propagates");
        let panic = payload.downcast::<EnginePanic>().expect("resumed as skep's panic");
        assert_eq!((panic.kind, panic.message.as_str()), (OpKind::Insert, "boom"));
    }
}
