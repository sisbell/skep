//! `skep share`, the fifteenth command, over `skep_client::share`.
//!
//! It is a draft or the caller's whole account shared with one account, a
//! draft privashed — opened to every account on the board and never a
//! guest (PUB-5.108, Nelson's term) — either revoked, a share made again
//! after a revoke, and the grants issued and held listed. The board honours
//! every record this command writes (wire.md §The read predicate);
//! the library composes and reads them, and this file is the talk, the
//! confirmation and the JSON. Five forms: `--doc <D> --to <account>`, the
//! default document grant; `--whole-account --to <account>`, the caller's
//! own account prefix, every draft under it including those written later
//! (PUB-5.9); `--doc <D> --privash`, the any-principal grant on one draft —
//! privashing a whole account is refused; `--revoke <grant>`, a privash
//! grant revoked the same way; and `--list`, which writes nothing and asks
//! nothing. Every usage form is refused before any socket opens (§2.3's
//! exit 2).
//!
//! The session is the command's own: the selected signing key (the file
//! `--key` or `SKEP_KEY` names, else the store's), a content-scoped signed
//! session opened as `skep session` opens its, and closed on every exit —
//! every record carries that key's entry signature on a claimed board — so
//! `SKEP_SESSION` is never read here: a token cannot sign.
//!
//! The statement precedes the act (PUB-5.29; PUB-5.14 at the revoke;
//! PUB-5.108–5.111 at the privash): before a share the command says on
//! stderr what the grant reaches — the document, or every draft under the
//! account including those written later — its history (every revision,
//! removed text included, from before the share), what revoking will not
//! take back (future delivery alone, never the record, never what the
//! grantee's client fetched — PUB-5.110), what it discloses beyond what it
//! reaches (a published fork or a copy by the grantee, permanently), that
//! the grantee is not notified, and the key-loss clause — only the issuer
//! can revoke, so a share outlives the loss of its keys (AUTH-5.72;
//! PUB-5.13, PUB-5.14); the custody note on every surface that shows a
//! grant (PUB-5.4); and, where the key's latest record is a revocation,
//! that this shares it again. A privash's statement is in the future tense
//! and in the tier's own words: every account on this board including
//! those that join later, never a guest; still a draft, changes
//! attributed; revoking stops future reads and takes back nothing fetched,
//! a document that links to or quotes it then showing a dead reference
//! (R59); history "everything this board retains", never "forever". Where
//! `--yes` does not stand for it, the command then asks a typed
//! confirmation at the terminal — the address the act names, or `no` —
//! through the terminal's `confirm_typed`, as the ceremonies do; off a
//! terminal the absence of `--yes` is a usage refusal. The confirm holds
//! for every write: a share, a privash and a revoke. No person door: the
//! command runs without a terminal under `--yes`.
//!
//! **After.** One JSON document goes on stdout — the grant with its
//! address, prefix, grantee (`privashed` for the any-principal grant) and
//! `replaces`; the revocation with the grant it revokes; or, for `--list`,
//! `{issued, held, privashed}`, the last the board's privashed set. The
//! grantee is echoed by address: this client holds no read of an account's
//! display name. The board's refusal and the library's are exit 1 with the
//! message, a halt exit 3.

use serde_json::{json, Value};
use skep_address::Address;
use skep_client::address::parse_address;
use skep_client::board::{Board, Scope, Token};
use skep_client::ceremony::handshake::{handshake, Session, Site};
use skep_client::dial::plaintext_non_loopback_warning;
use skep_client::halt::{Halt, Refused};
use skep_client::person::{Confirmation, Consent, Person};
use skep_client::share::{self, agent_space_of, Grant, GrantState, Grantee, Issuer, KeyState, Privashed, Refusal, Revocation};
use skep_client::sign::Signer;
use skep_client::store::{KeySelector, KeyStore, Purpose};

use super::{board_of, data_verbatim, has_terminal, key_named, principal_or_bound, select_key, store_of, talk, Stop};
use crate::args::{CommandLine, Usage};
use crate::terminal::Terminal;

/// The custody note every surface showing a grant states (PUB-5.4).
const CUSTODY_NOTE: &str = "a grant to an agent is a grant to whoever controls it, and its operator: an agent keeps no secret of its own";

/// What a share reaches: one document, or the caller's whole account.
enum Reach {
    /// `--doc <D>`.
    Document(Address),
    /// `--whole-account`: the session's own account prefix.
    WholeAccount,
}

/// The act the command line asks.
enum Act {
    /// A share with one account.
    Share {
        reach: Reach,
        grantee: Address,
    },
    /// One draft privashed.
    Privash {
        document: Address,
    },
    /// A grant revoked.
    Revoke {
        grant: Address,
    },
    /// The lists, writing nothing.
    List,
}

/// What the command line asks, judged whole before any socket opens.
///
/// §2.3's exit 2 is the flags' shape alone. It holds the act, and whether
/// `--yes` stands for the typed answer.
struct Asked {
    act: Act,
    consent: bool,
}

pub fn share(c: &CommandLine) -> Result<(), Stop> {
    let board = board_of(c)?;
    let store = store_of(c)?;
    let given = c.principal()?;
    let key_file = c.key_file()?;
    let asked = Asked::of(c)?;
    // The plaintext non-loopback warning, ahead of everything a signed
    // session needs (AUTH-4.53; §9 item 23: a warning, never a refusal).
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let principal = principal_or_bound(given, &store, &board)?;
    let key = select_key(key_file.as_deref(), &store, &board, principal, Purpose::Sign)?;
    let signer = store.signer(&KeySelector::Path(&key.path))?;
    // Content scope, as `skep session` opens its (RES-63): a grant is a
    // link write under this key, never a credential act.
    let session = handshake(&board, Scope::Content, &*signer, principal, Site::Session)?;
    talk(format!("acting as principal {principal} at account {} with key {}", session.account(), key_named(&key)));
    let outcome = run(&board, &session, &*signer, &asked);
    // The session is closed on every exit; a close the board refuses speaks
    // only where the run itself passed.
    match session.close() {
        Ok(_) => outcome,
        Err(h) => {
            outcome?;
            Err(h.into())
        }
    }
}

impl Asked {
    /// Reads the line whole, before any socket opens.
    ///
    /// Every address is parsed, the form found, the consent judged. The
    /// grammar's forms refuse two forms together ahead of this; what is left
    /// is which form, whether it is whole, and whether a terminal or `--yes`
    /// will answer for it.
    ///
    /// # Errors
    ///
    /// In this order: an address that is none; `--doc` with
    /// `--whole-account`, or no form; a share with neither `--to` nor
    /// `--privash`, `--to` with `--privash`, or `--privash` with
    /// `--whole-account`; `--yes` absent off a terminal at a write.
    fn of(c: &CommandLine) -> Result<Asked, Usage> {
        let doc = c.value("--doc").map(|d| address("--doc", d)).transpose()?;
        let whole = c.switch("--whole-account");
        let to = c.value("--to").map(|t| address("--to", t)).transpose()?;
        let privash = c.switch("--privash");
        let revoke = c.value("--revoke").map(|g| address("--revoke", g)).transpose()?;
        let consent = c.switch("--yes");
        let act = if c.switch("--list") {
            Act::List
        } else if let Some(grant) = revoke {
            Act::Revoke { grant }
        } else {
            let reach = match (doc, whole) {
                (Some(d), false) => Reach::Document(d),
                (None, true) => Reach::WholeAccount,
                // The grammar refuses the two together ahead of this; said
                // again rather than assumed.
                (Some(_), true) => return Err(Usage("`--doc` and `--whole-account` belong to two forms of `share`: give one".into())),
                (None, false) => {
                    return Err(Usage(
                        "one form is required: a share (--doc <D> or --whole-account, with --to <account> or --privash), --revoke <grant>, or --list".into(),
                    ))
                }
            };
            match (to, privash, &reach) {
                (Some(grantee), false, _) => Act::Share { reach, grantee },
                (None, true, Reach::Document(d)) => Act::Privash { document: d.clone() },
                (None, true, Reach::WholeAccount) => {
                    return Err(Usage(
                        "privashing a whole account is not available: --privash opens ONE draft to every account on this board, so give --doc <D> with it; to share your whole account, name one account with --to".into(),
                    ))
                }
                (Some(_), true, _) => return Err(Usage("`--to` and `--privash` belong to two forms of `share`: give one".into())),
                (None, false, _) => {
                    return Err(Usage(
                        "a share names its reader: --to <account>, or --privash to open the draft to every account on this board (never a guest)".into(),
                    ))
                }
            }
        };
        if !matches!(act, Act::List) && !consent && !has_terminal() {
            return Err(Usage(
                "--yes is required off a terminal: a share, a privash or a revoke is confirmed by a typed answer at the terminal, and --yes stands for it where stdin and stderr are not both one".into(),
            ));
        }
        Ok(Asked { act, consent })
    }
}

/// Returns the address `text` spells at `flag`.
///
/// # Errors
///
/// Returns the usage refusal naming both where `text` spells none.
fn address(flag: &str, text: &str) -> Result<Address, Usage> {
    parse_address(text).ok_or_else(|| Usage(format!("{flag}: '{text}' is not an address (the wire's dotted spelling)")))
}

/// Runs the act under the session.
///
/// The run is the key's state, the statement, the confirmation, the act,
/// the JSON.
///
/// # Errors
///
/// Returns a halt where the session's account cannot be spelled; a library
/// refusal ([`refused`]) where the key is already shared, the grant to
/// revoke is none, another's, revoked or not standing, or the library
/// refuses the act; the decline or the abandonment of the confirmation
/// ([`confirm`]); and the halt a read, or a write stdout refuses, comes to.
fn run(board: &Board, session: &Session<'_>, signer: &dyn Signer, asked: &Asked) -> Result<(), Stop> {
    let token = session.token();
    let account = parse_address(session.account()).ok_or_else(|| {
        Halt::face("the session's account cannot be spelled", session.account().to_string(), "this is a fault in the board's answer, not in your act; nothing was written")
    })?;
    let issuer = Issuer { token, account: session.account(), signer };
    match &asked.act {
        Act::List => list(board, token, &account),
        Act::Share { reach, grantee } => {
            let prefix = match reach {
                Reach::Document(d) => d.clone(),
                Reach::WholeAccount => account.clone(),
            };
            let before = share::key_state(board, Some(token), session.account(), &prefix, &Grantee::Account(grantee.clone()))?;
            if let KeyState::Live(g) = before {
                return Err(refused(Refusal::AlreadyShared(Box::new(g))));
            }
            say_share(reach, &prefix, grantee, &before);
            confirm(asked.consent, &format!("the share of {} with {grantee}", reach_named(reach, &prefix)), &grantee.to_string(), "share")?;
            let grant = share::share(board, &issuer, &prefix, grantee).map_err(refused)?;
            talk(format!("shared: {grantee} reads {} from now on; the grant is {}", reach_named(reach, &prefix), grant.at));
            data_verbatim(grant_json(&grant).to_string().as_bytes())?;
            Ok(())
        }
        Act::Privash { document } => {
            let before = share::key_state(board, Some(token), session.account(), document, &Grantee::Privashed)?;
            if let KeyState::Live(g) = before {
                return Err(refused(Refusal::AlreadyShared(Box::new(g))));
            }
            say_privash(document, &before);
            confirm(asked.consent, &format!("the privash of {document}"), &document.to_string(), "privash")?;
            let grant = share::privash(board, &issuer, document).map_err(refused)?;
            talk(format!("the draft is now privashed: every account on this board reads {document}, never a guest; the grant is {}", grant.at));
            data_verbatim(grant_json(&grant).to_string().as_bytes())?;
            Ok(())
        }
        Act::Revoke { grant: at } => {
            let Some((grant, state)) = share::grant_at(board, Some(token), at)? else { return Err(refused(Refusal::NotAGrant(at.clone()))) };
            if grant.issuer != account {
                return Err(refused(Refusal::NotYours { grant: at.clone(), issuer: Some(grant.issuer) }));
            }
            match state {
                GrantState::Revoked { by } => return Err(refused(Refusal::AlreadyRevoked { grant: at.clone(), by })),
                GrantState::Inert => return Err(refused(Refusal::NotStanding(at.clone()))),
                GrantState::Live => {}
            }
            say_revoke(&grant);
            confirm(asked.consent, &format!("the revocation of the grant {at}"), &at.to_string(), "revoke")?;
            let revocation = share::revoke(board, &issuer, at).map_err(refused)?;
            talk(keep_clause(&grant));
            data_verbatim(revocation_json(&revocation, &grant).to_string().as_bytes())?;
            Ok(())
        }
    }
}

/// Answers `--list`: what the account shared, and what is shared with it.
///
/// It also answers what any account on this board reads by privash — the
/// three reads, one JSON document, the custody note beside it (PUB-5.4).
///
/// # Errors
///
/// Returns the halt any of the three reads comes to, and the one a write
/// stdout refuses comes to.
fn list(board: &Board, token: &Token, account: &Address) -> Result<(), Stop> {
    let issued = share::issued(board, Some(token), &account.to_string())?;
    let held = share::held(board, token, &account.to_string())?;
    let privashed = share::privashed(board, Some(token))?;
    let live = issued.iter().filter(|(_, s)| *s == GrantState::Live).count();
    talk(format!(
        "{} grant record{} issued from {account}, {live} live; {} held; {} prefix{} privashed on this board",
        issued.len(),
        if issued.len() == 1 { "" } else { "s" },
        held.len(),
        privashed.len(),
        if privashed.len() == 1 { "" } else { "es" }
    ));
    talk(CUSTODY_NOTE);
    let v = json!({
        "issued": issued.iter().map(|(g, s)| issued_json(g, s)).collect::<Vec<_>>(),
        "held": held.iter().map(grant_json).collect::<Vec<_>>(),
        "privashed": privashed.iter().map(privashed_json).collect::<Vec<_>>(),
    });
    data_verbatim(v.to_string().as_bytes())?;
    Ok(())
}

/// Returns what a share reaches, as the talk names it.
fn reach_named(reach: &Reach, prefix: &Address) -> String {
    match reach {
        Reach::Document(d) => d.to_string(),
        Reach::WholeAccount => format!("everything under {prefix} that is yours"),
    }
}

/// Says the share gesture's statement (PUB-5.29) before the act.
///
/// It is in plain talk: the record at its rung, the history, the
/// revocation, the act with its repeated form, the arrival, the key-loss
/// clause, the custody note, and the re-share where the key's latest record
/// is a revocation. The grantee is echoed by address alone.
fn say_share(reach: &Reach, prefix: &Address, grantee: &Address, before: &KeyState) {
    let who = grantee.to_string();
    talk(format!("sharing with {who}"));
    match reach {
        Reach::Document(d) => talk(format!("this share goes on the public record, permanently: {who} may read {d} — the record names you both, and nothing removes it")),
        Reach::WholeAccount => talk(format!(
            "this share goes on the public record, permanently: {who} may read everything under {prefix} that is yours — every draft you have there now, every draft you write there later, and the records this board keeps for you under it"
        )),
    }
    talk("sharing a document shares its retained history: every revision, removed text included, with each commit's time and device, back to this board's floor — history from before this share included");
    talk(format!("revoking withdraws future delivery alone: it never removes the record, and it never takes back what {who}'s client has already fetched"));
    talk(format!(
        "{who} can publish what they read: a published fork discloses this draft's arrangement permanently, and revoking does not reach it; they need not publish — a private copy of their own, shared with every account, discloses the same, and only they can withdraw that; they can re-create the links homed in this document on a page of their own, which makes its link structure public at the documents those links name, permanently; and they can do that repeatedly, for as long as they hold access, the series showing how this draft was shaped"
    ));
    talk(format!("{who} is not notified: their client finds this grant by its own discovery read, at its next poll"));
    talk("only you can revoke this share, and only while you hold a key: if you lose every key, it stays shared, as it is, forever");
    talk(CUSTODY_NOTE);
    if let Some(owner) = agent_space_of(grantee) {
        talk(format!("{who} is in {owner}'s agent space: this share reaches whoever controls that agent, and its operator"));
    }
    if let KeyState::Revoked(r) = before {
        talk(format!(
            "you revoked this share before (the revocation at {}); this shares it again, as a fresh grant beside the old one — the earlier grant and its revocation stay on the record",
            r.at
        ));
    }
}

/// Says the privash's statement (PUB-5.108–5.111) before the act.
///
/// It is in the future tense, with PUB-5.29's clauses at any-principal:
/// every account on this board and never a guest, still a draft with
/// changes attributed, the record, the history as everything this board
/// retains, revoking and the dead reference (R59), the act, the arrival,
/// the key-loss clause, the custody note, and the re-privash where the
/// key's latest record is a revocation.
fn say_privash(document: &Address, before: &KeyState) {
    talk(format!("{document} will be privashed: every account on this board can read it, including accounts that join later — never a guest"));
    talk("it stays a draft you may keep changing, and readers see your changes as yours; to change it past recognition without that, privash a new draft and revoke this one");
    talk(format!("this goes on the public record, permanently: every account on this board, {document} — and your name is on it where theirs is not"));
    talk("sharing it shares its retained history: every revision, removed text included, with each commit's time and device — everything this board retains, never forever");
    talk("revoking stops future reads and takes back nothing already fetched; any document that links to or quotes it then shows a dead reference in its place — those who linked to it may complain to you, and that is a matter for private recourse");
    talk(
        "any account on this board can publish what it reads: a published fork discloses this draft's arrangement permanently, and revoking does not reach it; a private copy of their own shared with every account discloses the same, and only that account can withdraw it; any of them can re-create the links homed in this document on a page of their own, which makes its link structure public at the documents those links name, permanently; and any of them can do that repeatedly, for as long as this stands",
    );
    talk("nobody is notified: each client finds this by its own discovery read, at its next poll");
    talk("only you can revoke it, and only while you hold a key: if you lose every key, it stays privashed, as it is, forever");
    talk(format!("every account includes agents, and {CUSTODY_NOTE}"));
    if let KeyState::Revoked(r) = before {
        talk(format!("you revoked this before (the revocation at {}); this privashes it again, as a fresh grant beside the old one", r.at));
    }
}

/// Returns who a grant names, as the revoke's talk says it.
fn reader_named(grant: &Grant) -> String {
    match &grant.grantee {
        Grantee::Account(a) => a.to_string(),
        Grantee::Privashed => "every account on this board".to_string(),
    }
}

/// Says the revoke's statement before the act (PUB-5.14).
///
/// It names the second permanent record, and what the reader keeps
/// (PUB-5.110).
fn say_revoke(grant: &Grant) {
    let who = reader_named(grant);
    talk(format!("revoking deposits a second permanent public record here, naming {who}: the share and its withdrawal both stay on the record, permanently"));
    talk(format!(
        "it withdraws future delivery alone: {who} keeps what their client has already fetched, and whatever they re-inserted as their own bytes or published as a fork stays theirs — the board stops answering their reads of {} from the next read on",
        grant.prefix
    ));
    if grant.grantee == Grantee::Privashed {
        talk("any document that links to or quotes it then shows a dead reference in its place");
    }
    talk(CUSTODY_NOTE);
}

/// Returns what the reader keeps, said after the revocation landed (PUB-5.110).
fn keep_clause(grant: &Grant) -> String {
    format!(
        "revoked: {} reads {} no further from the next read; they keep what their client already fetched, and the share and this revocation both stand on the record",
        reader_named(grant),
        grant.prefix
    )
}

/// Asks the typed confirmation, where `--yes` did not stand for it.
///
/// It is asked at the terminal: the address the act names, or `no` — the
/// terminal's own `confirm_typed`, re-asked on a wrong answer as the
/// ceremonies re-ask a wrong row (AUTH-5.46), three asks in all, then
/// declined.
///
/// # Errors
///
/// Returns the decline ([`declined`]) on `no`, `n` or an empty answer, and
/// after the third wrong one; and a halt where the confirmation is not
/// answered, the act abandoned.
fn confirm(consent: bool, what: &str, expected: &str, act: &str) -> Result<(), Stop> {
    if consent {
        return Ok(());
    }
    let mut person = Terminal;
    for _ in 0..3 {
        let typed = person
            .confirm_typed(Consent(Confirmation { text: format!("CONFIRM {what}"), expected: expected.to_string() }))
            .map_err(|_| Halt::face(format!("the {act} was abandoned"), "the confirmation was not answered", "run it again when ready; nothing was written"))?;
        let typed = typed.trim();
        if typed == expected {
            return Ok(());
        }
        if typed.is_empty() || typed == "no" || typed == "n" {
            return Err(declined(act));
        }
        talk(format!("`{typed}` is not what this act names ({expected}); type that, or `no`"));
    }
    Err(declined(act))
}

/// Returns the decline, faced: nothing written.
fn declined(act: &str) -> Stop {
    Stop::Halt(Halt::face(format!("the {act} was declined: nothing was written"), "the typed answer was `no`", "run it again when ready"))
}

/// Returns the stop a library refusal comes to (§2.3's exit 1).
///
/// The exit is "the board refused": a halt the library faced keeps its own
/// code; every typed refusal is a verdict under a code named for it, its
/// detail the refusal's own words, the act that would help among them.
fn refused(r: Refusal) -> Stop {
    let code = match &r {
        Refusal::Halt(_) => "",
        Refusal::AlreadyShared(_) => "already_shared",
        Refusal::NotAPrefix(_) => "not_a_prefix",
        Refusal::NotADocument(_) => "not_a_document",
        Refusal::NotADraft(_) => "not_a_draft",
        Refusal::NoSuchDocument(_) => "doc_not_registered",
        Refusal::NotOwner { .. } | Refusal::NotYours { .. } => "not_owner",
        Refusal::NoSuchAccount(_) => "not_an_account",
        Refusal::ToYourself(_) => "to_yourself",
        Refusal::NotAGrant(_) => "not_a_grant",
        Refusal::AlreadyRevoked { .. } => "already_revoked",
        Refusal::NotStanding(_) => "not_standing",
        Refusal::NeedsSignedSession => "signed_session_required",
    };
    match r {
        Refusal::Halt(h) => Stop::Halt(h),
        other => Stop::Halt(Halt::Refused(Refused { status: 200, code: code.to_string(), detail: Some(other.to_string()), op: None, body: Value::Null })),
    }
}

/// Returns a grant as the JSON carries it.
///
/// It carries its address, issuer, prefix, grantee (`privashed` at the
/// any-principal grant) and `replaces`.
fn grant_json(g: &Grant) -> Value {
    json!({
        "kind": "grant",
        "at": g.at.to_string(),
        "issuer": g.issuer.to_string(),
        "prefix": g.prefix.to_string(),
        "grantee": g.grantee.text(),
        "replaces": g.replaces.as_ref().map(ToString::to_string),
    })
}

/// Returns an issued grant with its state.
///
/// The state is `live`, `revoked` with `revoked_by`, or `inert`.
fn issued_json(g: &Grant, state: &GrantState) -> Value {
    let mut v = grant_json(g);
    let (name, by) = match state {
        GrantState::Live => ("live", None),
        GrantState::Revoked { by } => ("revoked", Some(by.to_string())),
        GrantState::Inert => ("inert", None),
    };
    v["state"] = Value::from(name);
    v["revoked_by"] = by.map_or(Value::Null, Value::from);
    v
}

/// Returns a revocation as the JSON carries it, with the grant it withdrew.
fn revocation_json(r: &Revocation, g: &Grant) -> Value {
    json!({
        "kind": "revocation",
        "at": r.at.to_string(),
        "revokes": r.revokes.to_string(),
        "issuer": r.issuer.to_string(),
        "prefix": g.prefix.to_string(),
        "grantee": g.grantee.text(),
    })
}

/// Returns one privashed prefix with its issuers.
fn privashed_json(p: &Privashed) -> Value {
    json!({"prefix": p.prefix.to_string(), "issuers": p.issuers.iter().map(ToString::to_string).collect::<Vec<_>>()})
}
