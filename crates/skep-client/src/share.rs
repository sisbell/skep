//! SHARING AND PRIVASHING — the grant as this client composes and reads it,
//! behind `acting` (`docs/wire.md` §The read predicate, "A grant is an
//! ordinary `make_link`"; the PUB spec's part 05, the grant record and
//! §Privashing). The board already honours every record this module writes;
//! what it adds is the composing and the reading: a share is a grant-class
//! link homed in the issuer's OWN doc 1 (PUB-5.17), `from` the content
//! prefix — one document, or one account, covering every document the
//! issuer owns under it, those minted later included (PUB-5.9) — and `to`
//! the grantee account (PUB-5.1, PUB-5.5); a revocation is a later record of
//! the class whose `from` names the grant's own address (PUB-5.13,
//! PUB-5.15); a re-share after a revocation is a fresh grant beside the old
//! one, written with `replaces` naming the revocation it follows, since a
//! grant opens only where the state it replaces is its key's current one
//! (PUB-5.15 (iv)). PRIVASHING (PUB-5.108, Nelson's term) is the one other
//! form: a universal revocable grant on ONE draft — the grant's `to` EMPTY,
//! the ANY-PRINCIPAL value (PUB-5.7, PUB-5.8) — opening it to every account
//! on the board and never to a guest (PUB-5.109), reach until the owner
//! changes their mind.
//!
//! THE KEY and its state. A grant's key is the issuer, the prefix and the
//! grantee. Before any write, [`share`] and [`privash`] read the key's
//! current state off the issuer's own doc 1 ([`key_state`]): no record →
//! the EMPTY state, the grant sent with no `replaces`; a revocation the
//! latest → the grant sent with `replaces` naming it; a live grant the
//! latest → REFUSED as already shared, naming the grant, and nothing is
//! written — a duplicate would be deposited, acknowledged and honoured for
//! nothing. [`revoke`] refuses a record the caller did not issue and one
//! revoked already. [`Ledger::fold`] is the fold's own walk over a doc 1's
//! records, pure, so a test pins it with no board.
//!
//! NO RETRACT, AND NO AUTOMATIC RE-ISSUE. A share is withdrawn by revoking
//! it, never by retracting its record — the board refuses a `nullify` of a
//! grant-typed link (`nullify_not_revocation`), and this module offers no
//! retract. A write whose acknowledgement is lost is NEVER re-sent: the
//! module reads the key's state and reports what stands — the grant where it
//! landed, the transport halt where nothing did — because a blind re-issue
//! after an issuer's deliberate revocation would return a withdrawn share as
//! a third permanent record (the PUB spec's part 08, RES-246). A re-share
//! happens only on a fresh, explicit call.
//!
//! THE THREE READS. [`issued`], the grant-class links homed in the caller's
//! doc 1 with the `replaces` links beside them, each grant paired with its
//! revocation; [`held`], R78's discovery read — the grant-class links whose
//! `to` names the caller, over the ISSUERS' doc 1s, never the caller's own
//! records (PUB-5.17), each kept live only where no revocation names it;
//! [`privashed`], the board's universal set through `universal_grants`
//! (PUB-8.47), which keeps the wire's name: it is the board's read, not the
//! act. Every surface that shows a grant states the custody note (PUB-5.4);
//! [`agent_space_of`] is how a caller tells a grantee in an agent space.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::{json, Value};
use skep_address::{document_of, Address, Level};
use skep_identity::{entry_body_make_link, entry_body_make_link_replacing, entry_frame, unit_span, DocTerm, EntryBody, EntrySlot, LinkSlots};

use crate::address::{doc_1_of, first_child, parent_account, parse_address};
use crate::board::{acked_addr, answers, frames, Answer, Board, Rejection, Token};
use crate::halt::Halt;
use crate::sign::{sig_hex, Signer};

pub use crate::board::frames::{T_GRANT, T_REPLACES};

#[cfg(test)]
mod tests;

/// Who a grant opens its prefix to (PUB-5.4, PUB-5.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Grantee {
    /// One account, named by its address — principal-exact: the account
    /// alone, never its agents or its sub-accounts (PUB-5.5).
    Account(Address),
    /// Every account on the board and never a guest — the ANY-PRINCIPAL
    /// grant, the grant link's EMPTY `to` (PUB-5.7, PUB-5.8): the document
    /// is PRIVASHED (PUB-5.108), readable to every account until revoked.
    Privashed,
}

impl Grantee {
    /// The account, where the grantee is one.
    pub fn account(&self) -> Option<&Address> {
        match self {
            Grantee::Account(a) => Some(a),
            Grantee::Privashed => None,
        }
    }

    /// The grantee as a face and a JSON member spell it: the address, or
    /// `privashed`.
    pub fn text(&self) -> String {
        match self {
            Grantee::Account(a) => a.to_string(),
            Grantee::Privashed => "privashed".to_string(),
        }
    }

    /// The `to` slot's addresses: one, or none (PUB-5.8).
    fn to_addrs(&self) -> Vec<Address> {
        self.account().cloned().into_iter().collect()
    }
}

/// One grant record as it stands in the issuer's doc 1 (PUB-5.1,
/// PUB-5.15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The record's own address — the handle a revocation names.
    pub at: Address,
    /// The account that issued it: the owner of the doc 1 it is homed in.
    pub issuer: Address,
    /// The content prefix: one document, or one account (PUB-5.9, PUB-5.10).
    pub prefix: Address,
    /// Who it opens the prefix to.
    pub grantee: Grantee,
    /// The state the record was written to replace — the revocation a
    /// re-share follows (PUB-5.15 (iv)); `None` the EMPTY state.
    pub replaces: Option<Address>,
}

/// One revocation record (PUB-5.13): a grant-class link whose `from` names
/// the grant it withdraws.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    /// The record's own address.
    pub at: Address,
    /// The grant it revokes.
    pub revokes: Address,
    /// The account that wrote it — the grant's issuer, the one hand that
    /// can (PUB-5.13).
    pub issuer: Address,
}

/// What the fold makes of one grant record (PUB-5.15 (iv)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantState {
    /// Honoured and standing: the grantee reads the prefix.
    Live,
    /// Honoured once, then withdrawn by the record at `by` — the first
    /// revocation naming it, the only one that counts.
    Revoked {
        /// The revocation's address.
        by: Address,
    },
    /// Deposited and honoured for nothing: a duplicate of a grant that
    /// stood, a share replayed after its revocation, or a re-share naming a
    /// revocation a later record had passed.
    Inert,
}

/// A key's current state — the latest honoured record of one issuer over
/// one prefix for one grantee (PUB-5.15 (iv)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyState {
    /// No record of the key ever stood: a first share names it by sending no
    /// `replaces`.
    Empty,
    /// A grant stands: a share now would be a duplicate.
    Live(Grant),
    /// The latest record is a revocation: a re-share names it in
    /// `replaces`.
    Revoked(Revocation),
}

/// One privashed prefix as the board's universal set lists it (wire.md
/// §Grants): the covered prefix and the issuers who opened it to every
/// account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Privashed {
    /// The document or account every account on the board reads.
    pub prefix: Address,
    /// Who granted it, in address order.
    pub issuers: Vec<Address>,
}

/// THE ISSUER — a signed session's facts and its hand, taken as facts and
/// never as the ceremony's own session type: the session's token, the
/// account it acts as, and the signer it was opened with, whose entry
/// signature every record here carries on a claimed board (signed ops).
#[derive(Clone, Copy)]
pub struct Issuer<'a> {
    /// The signed session's token — what every write presents.
    pub token: &'a Token,
    /// The account the session acts as, `principal_prefix(principal)` — the
    /// records' home is its doc 1 (PUB-5.17).
    pub account: &'a str,
    /// The signer the session was opened with — the records' hand.
    pub signer: &'a dyn Signer,
}

/// Every refusal a share, a privash or a revoke can meet before or at the
/// board, each saying the act that would help; the board's other refusals
/// and every transport halt ride [`Refusal::Halt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A live grant stands for the key: nothing was written. Boxed: the
    /// grant is the family's one large member.
    AlreadyShared(Box<Grant>),
    /// The prefix is neither a document nor an account (PUB-5.10).
    NotAPrefix(Address),
    /// A privash over an account prefix: not available (the owner's v1
    /// ruling); privashing opens one draft.
    NotADocument(Address),
    /// A privash over a published document, which every reader has already.
    NotADraft(Address),
    /// The document is not registered at this board.
    NoSuchDocument(Address),
    /// The prefix is not the issuer's to share (PUB-5.3): a grant from any
    /// other hand opens nothing. `owner` where the board named one.
    NotOwner {
        /// The prefix asked.
        prefix: Address,
        /// The account the board names as its owner, where it did.
        owner: Option<Address>,
    },
    /// The grantee is no account on this board.
    NoSuchAccount(Address),
    /// The grantee is the issuer's own account.
    ToYourself(Address),
    /// No grant record stands at the address named.
    NotAGrant(Address),
    /// The record is homed in another account's doc 1: only its issuer
    /// revokes it (PUB-5.13).
    NotYours {
        /// The address named.
        grant: Address,
        /// The account whose doc 1 holds it, where the address says.
        issuer: Option<Address>,
    },
    /// The grant is revoked already.
    AlreadyRevoked {
        /// The grant.
        grant: Address,
        /// The revocation that withdrew it.
        by: Address,
    },
    /// The record was honoured for nothing, so there is nothing to revoke
    /// there.
    NotStanding(Address),
    /// `signed_session_required`: the session is bare.
    NeedsSignedSession,
    /// The board's other refusals verbatim, this library's own faults faced,
    /// and every transport halt.
    Halt(Halt),
}

impl From<Halt> for Refusal {
    fn from(h: Halt) -> Refusal {
        Refusal::Halt(h)
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::AlreadyShared(g) => write!(f, "{} is already shared with {}: the grant at {} stands, and a second record would open nothing; nothing was written — to withdraw the share, revoke that grant", g.prefix, g.grantee.text(), g.at),
            Refusal::NotAPrefix(a) => write!(f, "{a} is neither a document nor an account: a share covers one document, or one account with every document you own under it (PUB-5.10)"),
            Refusal::NotADocument(a) => write!(f, "privashing a whole account is not available: privashing opens ONE draft to every account on this board (PUB-5.108), and {a} is an account — name a document, or share the account with one account"),
            Refusal::NotADraft(a) => write!(f, "{a} is published already, so every reader has it; privashing is for a draft (PUB-5.108)"),
            Refusal::NoSuchDocument(a) => write!(f, "{a} is not registered at this board"),
            Refusal::NotOwner { prefix, owner } => {
                write!(f, "{prefix} is not yours to share")?;
                if let Some(o) = owner {
                    write!(f, " — it is {o}'s")?;
                }
                f.write_str(": only an owner shares what it owns (PUB-5.3), and a grant from any other hand opens nothing; nothing was written")
            }
            Refusal::NoSuchAccount(a) => write!(f, "{a} is no account on this board: a share names one account by its address (PUB-5.5)"),
            Refusal::ToYourself(a) => write!(f, "{a} is your own account: you read your own drafts already, and a share to yourself opens nothing"),
            Refusal::NotAGrant(a) => write!(f, "no grant of yours stands at {a}: the address names a revocation, or nothing"),
            Refusal::NotYours { grant, issuer } => {
                write!(f, "{grant} is not your record")?;
                if let Some(i) = issuer {
                    write!(f, " — it is homed in {i}'s doc 1")?;
                }
                f.write_str(": only the issuer revokes a share (PUB-5.13)")
            }
            Refusal::AlreadyRevoked { grant, by } => write!(f, "{grant} is revoked already, by the record at {by}; nothing was written"),
            Refusal::NotStanding(a) => write!(f, "{a} was honoured for nothing — a duplicate of a share that stands, or a re-share a later record passed — so there is nothing to revoke there; revoke the grant that stands for its key"),
            Refusal::NeedsSignedSession => f.write_str("a signed session is needed to share on a claimed board (signed_session_required)"),
            Refusal::Halt(h) => h.fmt(f),
        }
    }
}

impl std::error::Error for Refusal {}

// ── the pure half: the records, the ledger, the frames ───────────────────

/// One grant-class link of a doc 1 as read back: its address and the
/// addresses its FROM and TO slots name (PUB-5.15: a record is its typed
/// link and endsets alone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRecord {
    /// The link's own address.
    pub at: Address,
    /// The FROM slot's addresses.
    pub from: Vec<Address>,
    /// The TO slot's addresses — none at the ANY-PRINCIPAL grant.
    pub to: Vec<Address>,
}

/// THE LEDGER of one issuer's doc 1: every grant with the state the fold
/// gives it, in address order — the walk of PUB-5.15 (iv), pure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ledger {
    /// The issuer whose doc 1 the records are homed in.
    pub issuer: Address,
    /// The grants in address order, each with its state.
    pub grants: Vec<(Grant, GrantState)>,
}

/// The address order of a doc 1's records: tumbler order over the dotted
/// spelling, the order the link subspace mints in.
fn order_key(a: &Address) -> Vec<u64> {
    a.to_string().split('.').map(|c| c.parse().unwrap_or(u64::MAX)).collect()
}

/// What the classification test makes of one record (PUB-5.15): a GRANT,
/// whose FROM is a document or an account and whose TO names at most one
/// address; a SUPERSESSION, whose FROM names a record of the class homed in
/// the same doc 1; or neither.
enum Kind {
    Grant { prefix: Address, grantee: Grantee },
    Supersedes(Address),
    Neither,
}

fn kind_of(record: &LinkRecord, home: &Address, class: &[Address]) -> Kind {
    let [from] = record.from.as_slice() else { return Kind::Neither };
    match from.level() {
        Level::Document | Level::Account => match record.to.as_slice() {
            [] => Kind::Grant { prefix: from.clone(), grantee: Grantee::Privashed },
            [to] => Kind::Grant { prefix: from.clone(), grantee: Grantee::Account(to.clone()) },
            _ => Kind::Neither,
        },
        Level::Element if document_of(from).as_ref() == Some(home) && class.contains(from) => Kind::Supersedes(from.clone()),
        Level::Element | Level::Node => Kind::Neither,
    }
}

impl Ledger {
    /// Folds `records` — the grant-class links homed in `issuer`'s doc 1 —
    /// with `replaces`, each grant's named state read off the `replaces`
    /// link beside it, into every grant and its state, in address order.
    /// The walk is the fold's (wire.md §The read predicate; PUB-5.15 (iv)):
    /// a grant is honoured where the state it names is its key's current
    /// one — no `replaces` over an empty key, or the key's latest
    /// revocation — and is inert otherwise; a supersession withdraws the
    /// live grant it names and is nothing where it names anything else, a
    /// revocation among it; a record that is neither kind enters nowhere.
    pub fn fold(issuer: &Address, records: &[LinkRecord], replaces: &[(Address, Address)]) -> Ledger {
        let home = parse_address(&doc_1_of(&issuer.to_string())).expect("an account's doc 1 is an address");
        let mut records: Vec<&LinkRecord> = records.iter().collect();
        records.sort_by_key(|r| order_key(&r.at));
        let class: Vec<Address> = records.iter().map(|r| r.at.clone()).collect();
        let named: BTreeMap<String, &Address> = replaces.iter().map(|(g, s)| (g.to_string(), s)).collect();
        let mut grants: Vec<(Grant, GrantState)> = Vec::new();
        // The current state per key, `(prefix, grantee)` spelled as text.
        let mut keys: BTreeMap<(String, String), KeyState> = BTreeMap::new();
        for record in records {
            match kind_of(record, &home, &class) {
                Kind::Grant { prefix, grantee } => {
                    let key = (prefix.to_string(), grantee.text());
                    let replaces = named.get(&record.at.to_string()).map(|s| (*s).clone());
                    let grant = Grant { at: record.at.clone(), issuer: issuer.clone(), prefix, grantee, replaces: replaces.clone() };
                    let honoured = match keys.get(&key) {
                        None | Some(KeyState::Empty) => replaces.is_none(),
                        Some(KeyState::Revoked(r)) => replaces.as_ref() == Some(&r.at),
                        Some(KeyState::Live(_)) => false,
                    };
                    if honoured {
                        keys.insert(key, KeyState::Live(grant.clone()));
                        grants.push((grant, GrantState::Live));
                    } else {
                        grants.push((grant, GrantState::Inert));
                    }
                }
                Kind::Supersedes(of) => {
                    let Some((grant, state)) = grants.iter_mut().find(|(g, _)| g.at == of) else { continue };
                    if *state != GrantState::Live {
                        continue;
                    }
                    *state = GrantState::Revoked { by: record.at.clone() };
                    let key = (grant.prefix.to_string(), grant.grantee.text());
                    keys.insert(key, KeyState::Revoked(Revocation { at: record.at.clone(), revokes: of, issuer: issuer.clone() }));
                }
                Kind::Neither => {}
            }
        }
        Ledger { issuer: issuer.clone(), grants }
    }

    /// The key's current state: the latest honoured record over `prefix`
    /// for `grantee` — a live grant, the revocation that withdrew the last
    /// one, or nothing.
    pub fn key_state(&self, prefix: &Address, grantee: &Grantee) -> KeyState {
        let mut state = KeyState::Empty;
        for (grant, grant_state) in &self.grants {
            if grant.prefix != *prefix || grant.grantee != *grantee {
                continue;
            }
            match grant_state {
                GrantState::Live => state = KeyState::Live(grant.clone()),
                GrantState::Revoked { by } => state = KeyState::Revoked(Revocation { at: by.clone(), revokes: grant.at.clone(), issuer: self.issuer.clone() }),
                GrantState::Inert => {}
            }
        }
        state
    }

    /// The grant at `at`, with its state, where one stands.
    pub fn grant(&self, at: &Address) -> Option<&(Grant, GrantState)> {
        self.grants.iter().find(|(g, _)| g.at == *at)
    }
}

/// The GRANT's frame and the entry body its attest signs: a `make_link`
/// homed in `home`, the issuer's doc 1, `from` the prefix, `to` the grantee
/// or EMPTY at a privash, `ty` the grants class, with `replaces` where the
/// grant follows a revocation (wire.md §Links (writes)). The ONE place a
/// grant-class link with an empty `to` is composed, and it is composed so
/// for [`Grantee::Privashed`] alone.
pub(crate) fn grant_frame(home: &Address, prefix: &Address, grantee: &Grantee, replaces: Option<&Address>) -> (Value, EntryBody) {
    link_frame(home, std::slice::from_ref(prefix), &grantee.to_addrs(), replaces)
}

/// The REVOCATION's frame and the entry body its attest signs: a grant-class
/// link homed in `home`, `from` the grant's own address (PUB-5.13), `to` the
/// grant's own grantee — so a grantee's discovery read finds the withdrawal
/// beside the grant — and no `replaces`.
pub(crate) fn revocation_frame(home: &Address, grant: &Grant) -> (Value, EntryBody) {
    link_frame(home, std::slice::from_ref(&grant.at), &grant.grantee.to_addrs(), None)
}

/// A grant-class link's frame over address-form slots, and the body the
/// entry signature covers — the slots as the store will hold them, one unit
/// span per address (`skep_identity::entry_body_make_link`), and the
/// `replaces` row named or empty (`entry_body_make_link_replacing`).
fn link_frame(home: &Address, from: &[Address], to: &[Address], replaces: Option<&Address>) -> (Value, EntryBody) {
    let from_spans: Vec<_> = from.iter().map(unit_span).collect();
    let to_spans: Vec<_> = to.iter().map(unit_span).collect();
    let ty = parse_address(T_GRANT).expect("the grants class is an address");
    let ty_spans = [unit_span(&ty)];
    let slots = LinkSlots { from: EntrySlot(&from_spans), to: EntrySlot(&to_spans), ty: EntrySlot(&ty_spans) };
    let body = match replaces {
        Some(r) => entry_body_make_link_replacing(slots, r),
        None => entry_body_make_link(slots),
    };
    let from_text: Vec<String> = from.iter().map(ToString::to_string).collect();
    let to_text: Vec<String> = to.iter().map(ToString::to_string).collect();
    let replaces_text = replaces.map(ToString::to_string);
    let frame = frames::make_link_replacing(
        &home.to_string(),
        &from_text.iter().map(String::as_str).collect::<Vec<_>>(),
        &to_text.iter().map(String::as_str).collect::<Vec<_>>(),
        T_GRANT,
        replaces_text.as_deref(),
        None,
    );
    (frame, body)
}

/// The account whose AGENT SPACE holds `account` (AUTH-5.87: `X.1`, an
/// account's first sub-user, is reserved for its agents, `X.1.1`, `X.1.2`,
/// … beneath it) — `account` at or under some `X.1` — or `None` for a
/// person's account. The OUTERMOST such boundary names the owner: an agent
/// `X.1.1` is by address the first sub-user of `X.1` too, and `X.1` is
/// nobody's account but the space. No registry read answers whether an
/// account is an agent's; the layout does, and a grantee the layout places
/// in an agent space is one the custody note names (PUB-5.4).
pub fn agent_space_of(account: &Address) -> Option<Address> {
    let mut owner = None;
    let mut at = account.to_string();
    while let Some(parent) = parent_account(&at) {
        if first_child(&parent) == at {
            owner = Some(parent.clone());
        }
        at = parent;
    }
    owner.and_then(|o| parse_address(&o))
}

// ── the reads ────────────────────────────────────────────────────────────

/// The grant-class links homed in `account`'s doc 1 with the `replaces`
/// links beside them, folded (the issuer's own ledger); empty where the
/// account has no doc 1 yet.
fn ledger(board: &Board, token: Option<&Token>, account: &str) -> Result<Ledger, Halt> {
    let issuer = address_of(account)?;
    let home = doc_1_of(account);
    let mut records = Vec::new();
    for link in links(board, token, &frames::find_links_ftt_home(T_GRANT, &home))? {
        if let Some(record) = read_record(board, token, &link)? {
            records.push(record);
        }
    }
    let mut replaces = Vec::new();
    for link in links(board, token, &frames::find_links_ftt_home(T_REPLACES, &home))? {
        if let Some(record) = read_record(board, token, &link)? {
            if let ([grant], [state]) = (record.from.as_slice(), record.to.as_slice()) {
                replaces.push((grant.clone(), state.clone()));
            }
        }
    }
    Ok(Ledger::fold(&issuer, &records, &replaces))
}

/// Returns the key's current state off the issuer's own doc 1: the latest
/// honoured record of `issuer_account` over `prefix` for `grantee`
/// (PUB-5.15 (iv)) — what a share reads before it writes, and what a
/// surface says before the act where the latest record is a revocation.
///
/// # Errors
///
/// The reads' halts; the death signal under `token` as a halt.
pub fn key_state(board: &Board, token: Option<&Token>, issuer_account: &str, prefix: &Address, grantee: &Grantee) -> Result<KeyState, Halt> {
    Ok(ledger(board, token, issuer_account)?.key_state(prefix, grantee))
}

/// Returns the grant at `at` with its state, read off the doc 1 the
/// address lies in — the issuer's, whoever asks — or `None` where no grant
/// record stands there.
///
/// # Errors
///
/// The reads' halts; the death signal under `token` as a halt.
pub fn grant_at(board: &Board, token: Option<&Token>, at: &Address) -> Result<Option<(Grant, GrantState)>, Halt> {
    let Some(issuer) = issuer_of_record(at) else { return Ok(None) };
    Ok(ledger(board, token, &issuer.to_string())?.grant(at).cloned())
}

/// Returns what `account` has shared: every grant-class record homed in its
/// own doc 1, in address order, each with the state the fold gives it —
/// live, revoked by the record named, or inert (R57's issued-grants list;
/// PUB-5.17, PUB-5.18).
///
/// # Errors
///
/// The reads' halts; the death signal under `token` as a halt.
pub fn issued(board: &Board, token: Option<&Token>, account: &str) -> Result<Vec<(Grant, GrantState)>, Halt> {
    Ok(ledger(board, token, account)?.grants)
}

/// Returns what is shared WITH `account`: R78's discovery read — the
/// grant-class links whose `to` names the account, over the issuers' own doc
/// 1s and never the holder's records (PUB-5.17) — keeping each grant that is
/// one by the classification test (PUB-5.15), homed in its issuer's doc 1
/// over a prefix the registry owns to that issuer (PUB-5.9's coverage), and
/// withdrawn by no revocation.
///
/// # Errors
///
/// The reads' halts; the death signal under `token` as a halt.
pub fn held(board: &Board, token: &Token, account: &str) -> Result<Vec<Grant>, Halt> {
    let me = address_of(account)?;
    let mut grants = Vec::new();
    let mut revoked: Vec<Address> = Vec::new();
    for link in links(board, Some(token), &frames::find_links_ftt(T_GRANT, account))? {
        let Some(record) = read_record(board, Some(token), &link)? else { continue };
        let Some(issuer) = issuer_of_record(&record.at) else { continue };
        let [from] = record.from.as_slice() else { continue };
        match from.level() {
            Level::Document | Level::Account => {
                if record.to.as_slice() != [me.clone()] {
                    continue;
                }
                // Coverage is containment ∩ ownership (PUB-5.9): the registry
                // owns the prefix to the issuer, or the grant covers nothing.
                let owner = board.effective_owner(&from.to_string())?;
                if owner.map(|o| o.prefix) != Some(issuer.to_string()) {
                    continue;
                }
                grants.push(Grant { at: record.at.clone(), issuer, prefix: from.clone(), grantee: Grantee::Account(me.clone()), replaces: None });
            }
            Level::Element => revoked.push(from.clone()),
            Level::Node => {}
        }
    }
    let mut live = Vec::new();
    for grant in grants {
        if revoked.contains(&grant.at) {
            continue;
        }
        // A revocation written with another `to`, or none, is found from the
        // grant's own address in the issuer's doc 1. The four-set query
        // matches by span overlap, so an account-rung grant's `from` covers
        // every record address under the account: each hit is read, and only
        // one whose `from` names the grant exactly is its revocation.
        let home = doc_1_of(&grant.issuer.to_string());
        let mut withdrawn = false;
        for hit in links(board, Some(token), &frames::find_links_ftt_from(T_GRANT, &grant.at.to_string()))? {
            if crate::address::document_of(&hit).as_deref() != Some(home.as_str()) {
                continue;
            }
            if read_record(board, Some(token), &hit)?.is_some_and(|r| r.from.as_slice() == [grant.at.clone()]) {
                withdrawn = true;
                break;
            }
        }
        if withdrawn {
            continue;
        }
        // The state the grant was written to replace, off the `replaces`
        // link beside it — read the same way, exactly.
        let mut grant = grant;
        for hit in links(board, Some(token), &frames::find_links_ftt_from(T_REPLACES, &grant.at.to_string()))? {
            if crate::address::document_of(&hit).as_deref() != Some(home.as_str()) {
                continue;
            }
            if let Some(r) = read_record(board, Some(token), &hit)? {
                if let ([from], [to]) = (r.from.as_slice(), r.to.as_slice()) {
                    if *from == grant.at {
                        grant.replaces = Some(to.clone());
                        break;
                    }
                }
            }
        }
        live.push(grant);
    }
    live.sort_by_key(|g| order_key(&g.at));
    Ok(live)
}

/// Returns the board's PRIVASHED set: every prefix an unrevoked grant with an
/// empty `to` opens to every account, with its issuers — `universal_grants`,
/// the board's own read under the wire's name (PUB-8.47) — empty for a
/// guest, who is never a reader by privash (PUB-5.109).
///
/// # Errors
///
/// The read's halt; the board's refusal; the death signal under `token` as
/// a halt.
pub fn privashed(board: &Board, token: Option<&Token>) -> Result<Vec<Privashed>, Halt> {
    let v = answered(board, token, &frames::universal_grants(), "reading the privashed set")?;
    if let Some(r) = Rejection::of(&v) {
        return Err(r.refused(&v));
    }
    Ok(answers::universal_rows(&v)
        .into_iter()
        .filter_map(|(prefix, issuers)| Some(Privashed { prefix: parse_address(prefix)?, issuers: issuers.into_iter().filter_map(parse_address).collect() }))
        .collect())
}

// ── the writes ───────────────────────────────────────────────────────────

/// Shares `prefix` — one document, or one account with every document the
/// issuer owns under it, those minted later included (PUB-5.9) — with
/// `grantee`, one account (PUB-5.1, PUB-5.5): the key's state read first,
/// then ONE grant-class link homed in the issuer's doc 1, with `replaces`
/// naming the revocation it follows where one is the key's latest record,
/// and its entry signature on a claimed board. Never a duplicate: a live
/// grant for the key is refused, naming it. A lost acknowledgement is never
/// re-sent: the key's state is read again, and the grant answered where it
/// landed.
///
/// # Errors
///
/// In this order: [`Refusal::NoSuchAccount`], [`Refusal::ToYourself`];
/// [`Refusal::NotAPrefix`], [`Refusal::NoSuchDocument`],
/// [`Refusal::NotOwner`]; [`Refusal::AlreadyShared`]; the board's
/// [`Refusal::NeedsSignedSession`]; every other refusal and halt as
/// [`Refusal::Halt`], a lost acknowledgement whose read-back finds no grant
/// standing among them.
pub fn share(board: &Board, issuer: &Issuer<'_>, prefix: &Address, grantee: &Address) -> Result<Grant, Refusal> {
    let account = address_of(issuer.account)?;
    if grantee.level() != Level::Account {
        return Err(Refusal::NoSuchAccount(grantee.clone()));
    }
    if *grantee == account {
        return Err(Refusal::ToYourself(grantee.clone()));
    }
    match board.effective_owner(&grantee.to_string())? {
        Some(owner) if owner.prefix == grantee.to_string() => {}
        _ => return Err(Refusal::NoSuchAccount(grantee.clone())),
    }
    match prefix.level() {
        Level::Document => {
            let meta = metadata(board, issuer.token, prefix)?;
            if meta.owner != account.to_string() {
                return Err(Refusal::NotOwner { prefix: prefix.clone(), owner: parse_address(&meta.owner) });
            }
        }
        Level::Account => {
            if *prefix != account {
                return Err(Refusal::NotOwner { prefix: prefix.clone(), owner: None });
            }
        }
        Level::Node | Level::Element => return Err(Refusal::NotAPrefix(prefix.clone())),
    }
    grant(board, issuer, &account, prefix, Grantee::Account(grantee.clone()))
}

/// PRIVASHES `document` (PUB-5.108): opens ONE draft the issuer owns to
/// every account on this board, those that join later included and never a
/// guest (PUB-5.109) — the ANY-PRINCIPAL grant, a grant-class link with an
/// EMPTY `to` (PUB-5.7, PUB-5.8), composed here and nowhere else — with the
/// same read of the key's state, the same `replaces` and the same entry
/// signature as [`share`]. An account prefix is refused: privashing a whole
/// account is not available.
///
/// # Errors
///
/// In this order: [`Refusal::NotADocument`], [`Refusal::NotAPrefix`];
/// [`Refusal::NoSuchDocument`], [`Refusal::NotOwner`],
/// [`Refusal::NotADraft`]; [`Refusal::AlreadyShared`]; the board's
/// [`Refusal::NeedsSignedSession`]; every other refusal and halt as
/// [`Refusal::Halt`].
pub fn privash(board: &Board, issuer: &Issuer<'_>, document: &Address) -> Result<Grant, Refusal> {
    let account = address_of(issuer.account)?;
    match document.level() {
        Level::Document => {}
        Level::Account => return Err(Refusal::NotADocument(document.clone())),
        Level::Node | Level::Element => return Err(Refusal::NotAPrefix(document.clone())),
    }
    let meta = metadata(board, issuer.token, document)?;
    if meta.owner != account.to_string() {
        return Err(Refusal::NotOwner { prefix: document.clone(), owner: parse_address(&meta.owner) });
    }
    if meta.published {
        return Err(Refusal::NotADraft(document.clone()));
    }
    grant(board, issuer, &account, document, Grantee::Privashed)
}

/// REVOKES the grant at `grant` (PUB-5.13, PUB-5.14): ONE grant-class link
/// homed in the issuer's doc 1 whose `from` names the grant, with its entry
/// signature — the one way a share is withdrawn, never a retract of its
/// record. The grant must be the issuer's own and standing. A lost
/// acknowledgement is never re-sent: the record is read again, and the
/// revocation answered where it landed.
///
/// # Errors
///
/// In this order: [`Refusal::NotYours`]; [`Refusal::NotAGrant`];
/// [`Refusal::AlreadyRevoked`], [`Refusal::NotStanding`]; the board's
/// [`Refusal::NeedsSignedSession`]; every other refusal and halt as
/// [`Refusal::Halt`].
pub fn revoke(board: &Board, issuer: &Issuer<'_>, grant: &Address) -> Result<Revocation, Refusal> {
    let account = address_of(issuer.account)?;
    if issuer_of_record(grant).as_ref() != Some(&account) {
        return Err(Refusal::NotYours { grant: grant.clone(), issuer: issuer_of_record(grant) });
    }
    let standing = match ledger(board, Some(issuer.token), issuer.account)?.grant(grant) {
        None => return Err(Refusal::NotAGrant(grant.clone())),
        Some((_, GrantState::Revoked { by })) => return Err(Refusal::AlreadyRevoked { grant: grant.clone(), by: by.clone() }),
        Some((_, GrantState::Inert)) => return Err(Refusal::NotStanding(grant.clone())),
        Some((g, GrantState::Live)) => g.clone(),
    };
    let home = home_of(&account);
    let (mut frame, body) = revocation_frame(&home, &standing);
    if let Some(a) = attest(board, issuer, &account, &home, &body)? {
        frame["attest"] = a;
    }
    match board.op(Some(issuer.token), &frame) {
        Ok(Answer::Document(v)) => match acked_addr(&v) {
            Some(at) => Ok(Revocation { at: address_of(at)?, revokes: grant.clone(), issuer: account }),
            None => Err(refused_write(&v)),
        },
        Ok(Answer::Closed) => Err(closed("revoking").into()),
        Err(Halt::Dial(e)) => {
            // THE LOST ANSWER: read, never re-send.
            match ledger(board, Some(issuer.token), issuer.account)?.grant(grant) {
                Some((_, GrantState::Revoked { by })) => Ok(Revocation { at: by.clone(), revokes: grant.clone(), issuer: account }),
                _ => Err(nothing_landed(Halt::Dial(e), "the revocation")),
            }
        }
        Err(h) => Err(h.into()),
    }
}

/// The one grant write: the key's state, the frame with its `replaces` and
/// its attest, the answer — or, after a lost acknowledgement, the read-back.
fn grant(board: &Board, issuer: &Issuer<'_>, account: &Address, prefix: &Address, grantee: Grantee) -> Result<Grant, Refusal> {
    let replaces = match ledger(board, Some(issuer.token), issuer.account)?.key_state(prefix, &grantee) {
        KeyState::Live(g) => return Err(Refusal::AlreadyShared(Box::new(g))),
        KeyState::Revoked(r) => Some(r.at),
        KeyState::Empty => None,
    };
    let home = home_of(account);
    let (mut frame, body) = grant_frame(&home, prefix, &grantee, replaces.as_ref());
    if let Some(a) = attest(board, issuer, account, &home, &body)? {
        frame["attest"] = a;
    }
    let standing = |at: Address| Grant { at, issuer: account.clone(), prefix: prefix.clone(), grantee: grantee.clone(), replaces: replaces.clone() };
    match board.op(Some(issuer.token), &frame) {
        Ok(Answer::Document(v)) => match acked_addr(&v) {
            Some(at) => Ok(standing(address_of(at)?)),
            None => Err(refused_write(&v)),
        },
        Ok(Answer::Closed) => Err(closed("sharing").into()),
        Err(Halt::Dial(e)) => {
            // THE LOST ANSWER: read, never re-send (the module's doc).
            match ledger(board, Some(issuer.token), issuer.account)?.key_state(prefix, &grantee) {
                KeyState::Live(g) if g.replaces == replaces => Ok(g),
                _ => Err(nothing_landed(Halt::Dial(e), "the grant")),
            }
        }
        Err(h) => Err(h.into()),
    }
}

/// The `attest` member over `body` for a write homed in `home`: the entry
/// frame under `H.1`'s pair, the issuer's account and the home's row, signed
/// by the issuer's signer (signed ops; `skep_identity::entry_frame`, the one
/// composer). `None` on a board with no `H.1`, where the member is dropped
/// unread.
fn attest(board: &Board, issuer: &Issuer<'_>, account: &Address, home: &Address, body: &EntryBody) -> Result<Option<Value>, Halt> {
    let Some(term) = board.board_term()? else { return Ok(None) };
    let alg = issuer.signer.public_key().alg().to_string();
    let bytes = entry_frame(&alg, term, account, DocTerm::One(home), body);
    Ok(Some(json!({"alg": alg, "sig": sig_hex(&issuer.signer.sign(&bytes))})))
}

// ── the small reads and the faces ────────────────────────────────────────

/// A `doc_metadata` answer's terms for `doc` under the issuer's token.
fn metadata(board: &Board, token: &Token, doc: &Address) -> Result<answers::Metadata, Refusal> {
    let v = answered(board, Some(token), &frames::doc_metadata(&doc.to_string()), "reading the document")?;
    if let Some(r) = Rejection::of(&v) {
        return Err(match r.key() {
            "doc_not_registered" => Refusal::NoSuchDocument(doc.clone()),
            "withheld" => Refusal::NotOwner { prefix: doc.clone(), owner: None },
            _ => Refusal::Halt(r.refused(&v)),
        });
    }
    answers::metadata(&v).ok_or_else(|| shape_face("doc_metadata", &v).into())
}

/// A discovery's addresses under `token`; none where the home is not
/// registered — an account with no doc 1 yet has issued nothing.
fn links(board: &Board, token: Option<&Token>, frame: &Value) -> Result<Vec<String>, Halt> {
    let v = answered(board, token, frame, "reading the grants")?;
    if let Some(r) = Rejection::of(&v) {
        if r.key() == "doc_not_registered" {
            return Ok(Vec::new());
        }
        return Err(r.refused(&v));
    }
    Ok(answers::addrs(&v).into_iter().map(str::to_string).collect())
}

/// The link at `link` as a [`LinkRecord`]; `None` where no link is there, or
/// an address of it does not parse.
fn read_record(board: &Board, token: Option<&Token>, link: &str) -> Result<Option<LinkRecord>, Halt> {
    let v = answered(board, token, &frames::read_link(link), "reading a grant")?;
    let (Some(from), Some(to)) = (answers::link_slot_starts(&v, 0), answers::link_slot_starts(&v, 1)) else { return Ok(None) };
    let parsed = |starts: Vec<&str>| starts.into_iter().map(parse_address).collect::<Option<Vec<_>>>();
    Ok(match (parse_address(link), parsed(from), parsed(to)) {
        (Some(at), Some(from), Some(to)) => Some(LinkRecord { at, from, to }),
        _ => None,
    })
}

/// One frame answered as its document; the death signal faced.
fn answered(board: &Board, token: Option<&Token>, frame: &Value, during: &str) -> Result<Value, Halt> {
    match board.op(token, frame)? {
        Answer::Document(v) => Ok(v),
        Answer::Closed => Err(closed(during)),
    }
}

/// `text` as an address, else this library's own fault faced.
fn address_of(text: &str) -> Result<Address, Halt> {
    parse_address(text).ok_or_else(|| Halt::face(format!("`{text}` is no address"), "an account or a record address this library was handed does not parse", "this is a fault in this library or in the board's answer; nothing was written"))
}

/// An account's doc 1 as an address.
fn home_of(account: &Address) -> Address {
    parse_address(&doc_1_of(&account.to_string())).expect("an account's doc 1 is an address")
}

/// The account whose doc 1 a record address lies in — a link in `X.0.1`
/// is `X`'s — or `None` where the address lies in no doc 1.
fn issuer_of_record(at: &Address) -> Option<Address> {
    let home = crate::address::document_of(&at.to_string())?;
    let account = home.strip_suffix(".0.1")?;
    parse_address(account)
}

/// A write's refusal, dispatched on the one token (wire.md §Rejections):
/// the session's grade, this library's own frame faults, the rest verbatim.
fn refused_write(v: &Value) -> Refusal {
    let Some(r) = Rejection::of(v) else { return shape_face("make_link", v).into() };
    match r.key() {
        "signed_session_required" => Refusal::NeedsSignedSession,
        "not_owner" => own_fault("this session does not own its doc 1", &r),
        "doc_not_registered" => Refusal::Halt(Halt::face(
            "your account has no home document yet",
            format!("{}: the record is homed in your doc 1 (PUB-5.17), which is not registered", r.token()),
            "an account's first signed session mints its doc 1 (AUTH-2.109); open one, then share again",
        )),
        k if k.starts_with("attestation_") => own_fault("the record's attest", &r),
        _ => Refusal::Halt(r.refused(v)),
    }
}

/// A board refusal of this library's own frame: nothing a person can act on.
fn own_fault(what: &str, r: &Rejection) -> Refusal {
    Refusal::Halt(Halt::face(format!("the board refused {what}"), format!("{}: the frame this library composed is wrong in substance — its home, its slots or its attest", r.token()), "this is a fault in this library, not in your keys or your act; nothing was written"))
}

/// The death signal under the session, faced.
fn closed(during: &str) -> Halt {
    Halt::face(format!("the session ended while {during}"), "the board answered `Skepd-Session: closed` (wire.md §Sessions)", "open a session again and run this again: it reads what stands before it writes")
}

/// A lost acknowledgement whose read-back found nothing standing: the
/// transport halt, with the read's finding and the one act — run it again,
/// which reads first.
fn nothing_landed(dial: Halt, what: &str) -> Refusal {
    Refusal::Halt(Halt::face(format!("the board's answer to {what} was lost, and {what} is not standing"), format!("{dial}; the record was read back from the doc 1 and is not there — the write never landed, and it was not re-sent"), "run this again: it reads what stands before it writes, so nothing is written twice"))
}

/// An answer without the shape the wire promises.
fn shape_face(op: &str, v: &Value) -> Halt {
    Halt::face(format!("`{op}` answered a document this client cannot read"), crate::halt::clipped(&v.to_string(), 200).to_string(), "this board is not speaking the wire this client expects")
}
