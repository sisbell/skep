//! THE CEREMONIAL ROWS of `client.md` §4b.1: the key store's two —
//! `keygen`, `fingerprint` — beside the eight walks over
//! `skep_client::ceremony` — `claim`, `enroll`, `bind`, `recover`,
//! `rotate`, `retire`, `handoff`, `accept` — each reached from
//! [`Shell::call`] alone. A ceremonial row runs the library's walk over the
//! person of `person` — its PUBLIC moments the page's, its SECRET and
//! CONSENT ones the dev arm's — and answers when the walk ends, a halt the
//! walk met carried as the row's refusal under the armed name the row
//! spells.

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{json, Map, Value};
use skep_client::address::is_address_text;
use skep_client::board::Scope;
use skep_client::ceremony::claim::{self, ClaimOutcome, NotebookOptions};
use skep_client::ceremony::first_session::{first_session, FirstSessionReads};
use skep_client::ceremony::handshake::{handshake, key_face, Site};
use skep_client::ceremony::{accept, enroll, handoff, recover, retire, rotate};
use skep_client::derive::{origin_arm, principal_of, walk_to_set, KeyDiagnosis, Mode};
use skep_client::halt::Halt;
use skep_client::person::{LabelBox, Person, Public};
use skep_client::sheet::{render_inert, Label};
use skep_client::store::{Binding, KeyFacts, KeySelector, KeyStore, Purpose, StoreError};
use skep_identity::{encode_enroll, Enrollment};

use super::{optional, principal_arg, Shell};
use crate::person::BridgePerson;
use crate::refusal::{Name, Refusal};
use crate::sessions;

/// AUTH-5.42's statements at the device-name box, the notebook's venue.
fn device_box_statements() -> Vec<String> {
    vec![
        "This name is permanent and cannot be edited: fixing a typo costs a keypair.".to_string(),
        "It is a byline: this name appears beside every write you make with this key, forever.".to_string(),
        "It holds the DEVICE's name — never your own and never your organisation's; a display name is a separate, changeable label.".to_string(),
        "at this notebook it is readable by anything on the machine".to_string(),
    ]
}

/// The outstanding act of a key enrolled nowhere (AUTH-5.32), the line
/// `keygen` answers and `fingerprint` carries beside every UNBOUND key.
const OUTSTANDING_ACT: &str = "Where it ADDS a device: take this payload to a device already signed in, run `enroll` there, and bring its three facts back to `bind` here. Where it REPLACES a machine: `rotate` with the payload there instead, then `bind` here.";

/// The three facts as the bridge spells them.
fn facts_json(f: &skep_client::sheet::Facts) -> Value {
    json!({"principal": f.principal, "account": f.account, "origin": f.origin.as_str()})
}

/// The armed name of an `accept` halt, picked from its TEXT: the one place
/// the shell names a refusal off prose, because `skep-client`'s `accept`
/// reports its three armed cases — the address already seeded, not yet
/// delegated, the label refused at the box — only in the halt's words, so
/// this match stands on that walk's phrasing and the suite runs it against
/// the real walk's message.
fn accept_arm(h: &Halt) -> Option<Name> {
    let text = h.to_string();
    if text.contains("already holds a key set") {
        Some(Name::ALREADY_SEEDED)
    } else if text.contains("not yet delegated") {
        Some(Name::NOT_DELEGATED)
    } else if text.contains("refused at the box") {
        Some(Name::EMPTY_LABEL)
    } else {
        None
    }
}

impl Shell {
    /// A person for `walk` at the board `board_reference` names, the
    /// reference its moments carry; none for a walk that touches no board.
    fn person(&self, walk: &'static str, board_reference: Option<&str>) -> BridgePerson {
        BridgePerson::new(Arc::clone(&self.bus), Arc::clone(&self.pending), Arc::clone(&self.arm), walk, board_reference.map(str::to_string))
    }

    /// A walk's halt as the call's refusal: the abandonment where the page
    /// cancelled a moment or the arm left one, else the family's member —
    /// a halt's face under `armed` where the row diagnosed its armed name.
    fn walk_refusal(&self, person: &BridgePerson, h: Halt, armed: Option<Name>) -> Refusal {
        if person.abandoned {
            return Refusal::shell(Name::ABANDONED, json!({"halt": h.to_string()}));
        }
        match armed {
            Some(name) => Refusal::of_named(name, h),
            None => Refusal::from(h),
        }
    }

    /// The principal a ceremonial row runs as: the row's own where it names
    /// one, else the session mode's.
    fn principal_for(&self, args: &Value) -> Result<u64, Refusal> {
        Ok(optional(args, "principal", principal_arg)?.unwrap_or(self.session_mode.principal()))
    }

    /// Two anchor destinations under the shell's own directory for `walk`.
    fn anchor_out(&self, walk: &str) -> Vec<PathBuf> {
        vec![self.anchors.join(format!("{walk}-a")), self.anchors.join(format!("{walk}-b"))]
    }

    /// `keygen({label?})` → `{fingerprint, payload, outstanding}`: one
    /// device key into the store, its byline fixed at the box — a PUBLIC
    /// moment where no label is passed.
    pub(super) fn keygen(&self, args: &Value) -> Result<Value, Refusal> {
        let empty_label = |f: skep_client::sheet::LabelFault| Refusal::shell(Name::EMPTY_LABEL, json!({"cause": f.to_string()}));
        let label = match optional(args, "label", Value::as_str)? {
            Some(text) => Label::new(text).map_err(empty_label)?,
            None => {
                let mut person = self.person("keygen", None);
                let text = person
                    .label(Public(LabelBox { title: "name this device".into(), statements: device_box_statements(), default: None }))
                    .map_err(|_| Refusal::shell(Name::ABANDONED, json!({"moment": "the device-name box"})))?;
                Label::new(&text).map_err(empty_label)?
            }
        };
        let id = self.store.generate(Some(label.clone())).map_err(|e| Refusal::of_named(Name::STORE_UNWRITABLE, e.into()))?;
        let path = self.store.key_path(&id.0);
        let key = self.store.select(&KeySelector::Path(&path), Purpose::Read).map_err(|e| Refusal::of_named(Name::STORE_UNREADABLE, e.into()))?;
        let enrollment = Enrollment::new(key.public.clone(), false, Some(label.as_str().to_string())).map_err(|e| Refusal::shell(Name::EMPTY_LABEL, json!({"cause": e.to_string()})))?;
        self.say(format!("keygen: the key {} is written to the store under the byline `{}`", key.fingerprint, render_inert(label.as_str())));
        Ok(json!({"fingerprint": key.fingerprint.to_hex(), "payload": encode_enroll(&[enrollment]), "outstanding": OUTSTANDING_ACT}))
    }

    /// `fingerprint({select?, payload?})` → `[{fingerprint, label,
    /// bindings, unbound, payload}]`: the store's keys, or the one `select`
    /// names.
    pub(super) fn fingerprint(&self, args: &Value) -> Result<Value, Refusal> {
        let unreadable = |e: StoreError| Refusal::of_named(Name::STORE_UNREADABLE, e.into());
        let select = optional(args, "select", Value::as_str)?;
        let with_payload = optional(args, "payload", Value::as_bool)?.unwrap_or(false);
        let keys: Vec<KeyFacts> = match select {
            Some(select) => match self.store.select(&KeySelector::select(select), Purpose::Read) {
                Ok(k) => vec![k],
                Err(StoreError::Ambiguous { keys }) => {
                    let matches: Vec<Value> = keys.iter().map(|k| json!({"fingerprint": k.fingerprint.to_hex(), "label": k.label.as_deref().map(render_inert)})).collect();
                    return Err(Refusal::shell(Name::AMBIGUOUS, json!({"select": select, "matches": matches})));
                }
                Err(StoreError::NotFound { select }) => return Err(Refusal::shell(Name::NOT_FOUND, json!({"select": select}))),
                Err(e) => return Err(unreadable(e)),
            },
            None => self.store.list().map_err(unreadable)?,
        };
        let bindings = self.store.all_bindings().map_err(unreadable)?;
        let mut rows = Vec::new();
        for key in &keys {
            let bound: Vec<String> = bindings
                .iter()
                .filter_map(|binding| match binding {
                    Binding::Enrollment { origin, principal, account, fingerprint } if *fingerprint == key.fingerprint => Some(format!("{origin} principal {principal} account {account}")),
                    _ => None,
                })
                .collect();
            let payload = if with_payload {
                let e = Enrollment::new(key.public.clone(), key.anchor, key.label.clone()).map_err(|e| Refusal::shell(Name::EMPTY_LABEL, json!({"cause": e.to_string()})))?;
                Value::from(encode_enroll(&[e]))
            } else {
                Value::Null
            };
            rows.push(json!({
                "fingerprint": key.fingerprint.to_hex(),
                "label": key.label.as_deref().map(render_inert),
                "bindings": bound,
                "unbound": bound.is_empty(),
                "payload": payload,
            }));
        }
        Ok(Value::Array(rows))
    }

    /// `claim(board, {principal?, name?, paper?})`: the notebook walk run
    /// by the shell against the board, the anchors under the shell's own
    /// directory; `no_key` where the store holds no key at all — the
    /// notebook door is two calls, `keygen` then `claim` — and
    /// `already_claimed` where another store's claim stands.
    pub(super) fn claim(&self, args: &Value) -> Result<Value, Refusal> {
        let entry = self.board_entry(&args["board"])?;
        let principal = optional(args, "principal", principal_arg)?;
        let display_name = optional(args, "name", Value::as_str)?.map(str::to_string);
        let paper = optional(args, "paper", Value::as_bool)?.unwrap_or(false);
        if self.store.list().is_ok_and(|keys| keys.is_empty()) {
            let mode = Mode::of(&entry.board.health()?);
            return Err(Refusal::of_named(Name::NO_KEY, skep_client::store::arm4_face(&self.store, &[], mode)));
        }
        let opts = NotebookOptions {
            principal,
            display_name,
            anchor_out: self.anchor_out("claim"),
            paper,
            host_name: self.host_name.clone(),
            date: self.date.clone(),
        };
        let mut person = self.person("claim", Some(&entry.reference));
        match claim::notebook(&entry.board, &self.store, &mut person, &opts) {
            Ok(ClaimOutcome::Ours(c)) => Ok(json!({
                "account": c.account,
                "principal": c.principal,
                "fingerprint": c.fingerprint.to_hex(),
                "agent_space": c.agent_space,
                "display_name": c.display_name,
                "warnings": c.warnings,
            })),
            Ok(ClaimOutcome::Stranger { claimant }) => Err(Refusal::shell(Name::ALREADY_CLAIMED, json!({"claimant": claimant}))),
            Err(h) => Err(self.walk_refusal(&person, h, None)),
        }
    }

    /// `enroll(board, payload)` → the three facts: the hop's signed-in half
    /// run by the shell in its own full session as the mode's principal.
    pub(super) fn enroll(&self, args: &Value) -> Result<Value, Refusal> {
        let entry = self.board_entry(&args["board"])?;
        let payload = args["payload"].as_str().ok_or_else(|| Refusal::malformed("payload"))?;
        let opts = enroll::EnrollOptions { principal: self.principal_for(args)?, payload: format!("{payload}\n").into_bytes() };
        let mut person = self.person("enroll", Some(&entry.reference));
        match enroll::enroll(&entry.board, &self.store, &mut person, &opts) {
            Ok(e) => Ok(json!({
                "facts": facts_json(&e.facts),
                "fingerprints": e.fingerprints.iter().map(|f| f.to_hex()).collect::<Vec<_>>(),
                "reconciled": e.reconciled,
                "warnings": e.warnings,
            })),
            Err(h) => Err(self.walk_refusal(&person, h, None)),
        }
    }

    /// `bind(board, {principal, account, origin})` → `{}`: the three facts
    /// confirmed against the board, the key-set compare, the binding line
    /// appended, the first signed session run where one is owed. The
    /// whole-set compare against a genesis another hand wrote (the handoff
    /// landing's anchor files) is not reached here: the shell has no
    /// window for the files' pick, and the landing is taken as the hop's.
    pub(super) fn bind(&self, args: &Value) -> Result<Value, Refusal> {
        let entry = self.board_entry(&args["board"])?;
        let principal = principal_arg(&args["principal"]).ok_or_else(|| Refusal::malformed("principal"))?;
        let account = args["account"].as_str().ok_or_else(|| Refusal::malformed("account"))?.trim().to_string();
        let origin = args["origin"].as_str().ok_or_else(|| Refusal::malformed("origin"))?;
        if !is_address_text(&account) {
            return Err(Refusal::malformed("account"));
        }
        if origin != entry.origin.as_str() {
            return Err(Refusal::shell(Name::ORIGIN_DISAGREES, json!({"pasted": origin, "dialed": entry.origin.as_str()})));
        }
        let board = &entry.board;
        let health = board.health()?;
        origin_arm(board.signed(), &health).map_err(|h| Refusal::of_named(Name::ORIGIN_STATE, h))?;
        match principal_of(board, &account)? {
            Some(p) if p == principal => {}
            other => return Err(Refusal::shell(Name::ACCOUNT_DISAGREES, json!({"pasted_principal": principal, "seated": other, "account": account}))),
        }
        match board.principal_prefix(principal)? {
            Some(a) if a == account => {}
            other => return Err(Refusal::shell(Name::ACCOUNT_DISAGREES, json!({"pasted_account": account, "principal_prefix": other}))),
        }
        let key = sessions::signing_key(&self.store, &entry.origin, principal, || Mode::of(&health))?;
        let walk = walk_to_set(board, &account)?;
        let own = [(key.fingerprint, key.public.clone())];
        if let Err(h) = key_face(board, &walk, &key.fingerprint, &own, Site::Tail) {
            let name = match KeyDiagnosis::of(&walk.set, &key.fingerprint) {
                KeyDiagnosis::Retired { .. } => Name::RETIRED,
                _ => Name::NOT_ENROLLED,
            };
            return Err(Refusal::of_named(name, h));
        }
        let reads = FirstSessionReads::take(board, &account, &key.fingerprint, Some(&self.store))?;
        let mut warnings: Vec<String> = Vec::new();
        if reads.anything_owed() {
            let signer = sessions::signer(&self.store, &key.path)?;
            let session = handshake(board, Scope::Content, &*signer, principal, Site::Tail)?;
            let done = first_session(board, &reads, &session, &*signer, Some(&self.store));
            let _ = session.close();
            warnings.extend(done?.warnings);
        }
        let line = Binding::Enrollment { origin: entry.origin.clone(), principal, account: account.clone(), fingerprint: key.fingerprint };
        let mut out = Map::new();
        if let Err(w) = self.store.bind(&line) {
            out.insert("warning".into(), Value::from(w.to_string()));
        }
        if !warnings.is_empty() {
            out.insert("warnings".into(), json!(warnings));
        }
        Ok(Value::Object(out))
    }

    /// `recover(board, {principal, lost: [fp], stolen, anchorLost})` → the
    /// three facts: the device arm, or the loss arm; the import SECRET,
    /// the dev arm's.
    pub(super) fn recover(&self, args: &Value) -> Result<Value, Refusal> {
        let entry = self.board_entry(&args["board"])?;
        let lost = optional(args, "lost", |v| v.as_array()?.iter().map(|f| f.as_str().map(str::to_string)).collect::<Option<Vec<String>>>())?.unwrap_or_default();
        let stolen = optional(args, "stolen", Value::as_bool)?;
        let anchor_lost = optional(args, "anchorLost", Value::as_bool)?.unwrap_or(false);
        let opts = recover::RecoverOptions {
            principal: self.principal_for(args)?,
            anchor: None,
            lost,
            stolen,
            anchor_lost,
            anchor_out: self.anchor_out("recover"),
            paper: false,
            host_name: self.host_name.clone(),
            date: self.date.clone(),
        };
        let mut person = self.person("recover", Some(&entry.reference));
        match recover::recover(&entry.board, &self.store, &mut person, &opts) {
            Ok(r) => Ok(json!({
                "facts": facts_json(&r.facts),
                "enrolled": r.enrolled.iter().map(|f| f.to_hex()).collect::<Vec<_>>(),
                "retired": r.retired.iter().map(|f| f.to_hex()).collect::<Vec<_>>(),
                "containment": r.containment,
                "recovery_read": r.recovery_read,
                "warnings": r.warnings,
            })),
            Err(h) => Err(self.walk_refusal(&person, h, None)),
        }
    }

    /// `rotate(board, {principal, label?, payload?})` → the three facts.
    pub(super) fn rotate(&self, args: &Value) -> Result<Value, Refusal> {
        let entry = self.board_entry(&args["board"])?;
        let opts = rotate::RotateOptions {
            principal: self.principal_for(args)?,
            label: optional(args, "label", Value::as_str)?.map(str::to_string),
            payload: optional(args, "payload", Value::as_str)?.map(|p| format!("{p}\n").into_bytes()),
        };
        let mut person = self.person("rotate", Some(&entry.reference));
        match rotate::rotate(&entry.board, &self.store, &mut person, &opts) {
            Ok(r) => Ok(json!({
                "facts": facts_json(&r.facts),
                "old": r.old.to_hex(),
                "new": r.new.to_hex(),
                "trail": r.trail,
                "warnings": r.warnings,
            })),
            Err(h) => Err(self.walk_refusal(&person, h, None)),
        }
    }

    /// `retire(board, principal, fingerprint)` → `{}`: the preview and its
    /// typed confirmation the dev arm's.
    pub(super) fn retire(&self, args: &Value) -> Result<Value, Refusal> {
        let entry = self.board_entry(&args["board"])?;
        let fingerprint = args["fingerprint"].as_str().ok_or_else(|| Refusal::malformed("fingerprint"))?;
        let opts = retire::RetireOptions { principal: self.principal_for(args)?, fingerprint_prefix: fingerprint.to_string() };
        let mut person = self.person("retire", Some(&entry.reference));
        match retire::retire(&entry.board, &self.store, &mut person, &opts) {
            Ok(_) => Ok(json!({})),
            Err(h) => Err(self.walk_refusal(&person, h, None)),
        }
    }

    /// `handoff(board, {account, payload?})`: beat (a) alone without a
    /// payload, answering the address; the genesis with one, `{}`.
    pub(super) fn handoff(&self, args: &Value) -> Result<Value, Refusal> {
        let entry = self.board_entry(&args["board"])?;
        let account = args["account"].as_str().ok_or_else(|| Refusal::malformed("account"))?;
        let opts = handoff::HandoffOptions {
            principal: self.principal_for(args)?,
            account: account.to_string(),
            payload: optional(args, "payload", Value::as_str)?.map(|p| format!("{p}\n").into_bytes()),
            anchor: None,
        };
        let mut person = self.person("handoff", Some(&entry.reference));
        match handoff::handoff(&entry.board, &self.store, &mut person, &opts) {
            Ok(handoff::HandoffOutcome::Delegated { account, principal, already }) => Ok(json!({"address": account, "principal": principal, "already": already})),
            Ok(handoff::HandoffOutcome::Seeded { .. }) => Ok(json!({})),
            Err(h) => Err(self.walk_refusal(&person, h, None)),
        }
    }

    /// `accept(board, {address, label?, paper?, noAnchors?})` →
    /// `{payload}`: the recipient's beat; `no_address` where none is given.
    pub(super) fn accept(&self, args: &Value) -> Result<Value, Refusal> {
        let entry = self.board_entry(&args["board"])?;
        let Some(address) = optional(args, "address", Value::as_str)?.filter(|a| !a.trim().is_empty()) else {
            return Err(Refusal::shell(Name::NO_ADDRESS, json!({})));
        };
        let label = optional(args, "label", Value::as_str)?.map(str::to_string);
        let paper = optional(args, "paper", Value::as_bool)?.unwrap_or(false);
        let no_anchors = optional(args, "noAnchors", Value::as_bool)?.unwrap_or(false);
        let opts = accept::AcceptOptions {
            account: address.to_string(),
            label,
            anchor_out: self.anchor_out("accept"),
            paper,
            no_anchors,
            hosted: None,
            host_name: self.host_name.clone(),
            date: self.date.clone(),
        };
        let mut person = self.person("accept", Some(&entry.reference));
        match accept::accept(&entry.board, &self.store, &mut person, &opts) {
            Ok(a) => Ok(json!({"payload": a.record})),
            Err(h) => {
                let armed = accept_arm(&h);
                Err(self.walk_refusal(&person, h, armed))
            }
        }
    }
}
