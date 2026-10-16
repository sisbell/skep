//! SHARING AND PRIVASHING against the real daemon (`skep_client::share`;
//! wire.md §The read predicate, "A grant is an ordinary `make_link`";
//! PUB-5.1, PUB-5.13, PUB-5.15, PUB-5.108): three keyed sibling accounts
//! under the claimant — siblings read nothing of each other's — each with
//! its home and a signed session. A private draft of A's is withheld from B
//! until A shares it, withheld again at the next read after A revokes, and
//! read again after the re-share, whose record names the revocation it
//! follows; a second share while the first stands is refused and writes
//! nothing; a whole-account share reaches a draft A mints later; `issued`
//! and `held` list what stands; a document A does not own is refused before
//! any write, and the board's own answer to such a record is pinned beside
//! it; a privash opens a draft to a third account that was never named and
//! never to a guest, the board's privashed set lists it, its revocation
//! closes it, and a privash over an account prefix is refused; and a share
//! whose acknowledgement is lost is read back and never re-sent — one record
//! in the doc 1.

use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};
use skep_address::Address;
use skep_client::address::parse_address;
use skep_client::board::{acked_addr, frames, Answer, Board, Scope, Token};
use skep_client::ceremony::handshake::{handshake, Session, Site};
use skep_client::dial::{DialError, Dialer, Headers, PlainHttp, Request, RequestHead, Response, StreamedResponse};
use skep_client::share::{held, issued, privash, privashed, revoke, share, GrantState, Grantee, Issuer, Refusal, T_GRANT, T_REPLACES};
use skep_client::sign::{sig_hex, signer_from_seed, Signer};
use skep_client::store::FileStore;
use skep_client::Origin;
use skep_identity::{entry_body_empty, entry_body_make_link, entry_frame, unit_span, ContentFreeOp, DocTerm, EntryBody, EntrySlot, LinkSlots};
use skep_signature::HybridSigner;
use skepd::Skepd;

use crate::common::{board, claim, keygen, keyed_sub_account, spawn};

fn addr(text: &str) -> Address {
    parse_address(text).expect("an address")
}

/// One keyed sibling: its account, its principal, its signer.
struct Sibling {
    account: String,
    principal: u64,
    signer: HybridSigner,
}

/// A claimed permissive board with three keyed siblings under the claimant,
/// each with its home minted.
struct Rig {
    _sd: Skepd,
    board: Board,
    a: Sibling,
    b: Sibling,
    c: Sibling,
}

impl Rig {
    fn new(dir: &std::path::Path) -> Rig {
        let sd = spawn(&dir.join("board"), true);
        let board = board(sd.port());
        let store = FileStore::open(dir.join("store"));
        let fp = keygen(&store, "notebook");
        let anchors = dir.join("anchors");
        claim(&board, &store, &anchors);
        let owner = store.load(&store.key_path(&fp)).expect("the device key").signer();
        let mut siblings = Vec::new();
        for (n, seed, label) in [(2u64, 52u8, "a"), (3, 53, "b"), (4, 54, "c")] {
            let signer = signer_from_seed(&[seed; 32]);
            let principal = 700 + n;
            let account = keyed_sub_account(&board, &anchors, &owner, n, principal, &signer, label);
            siblings.push(Sibling { account, principal, signer });
        }
        let mut it = siblings.into_iter();
        let rig = Rig { _sd: sd, board, a: it.next().unwrap(), b: it.next().unwrap(), c: it.next().unwrap() };
        for who in [&rig.a, &rig.b, &rig.c] {
            let session = rig.session(who);
            rig.home(&session, who);
            session.close().expect("close");
        }
        rig
    }

    /// A CONTENT-scoped signed session as `who`, the scope the command opens.
    fn session(&self, who: &Sibling) -> Session<'_> {
        handshake(&self.board, Scope::Content, &who.signer, who.principal, Site::Session).expect("a content session")
    }

    /// The `attest` member over `body` for a write whose `doc` row is `doc`,
    /// under `who`'s account, signed by `who`'s key.
    fn attest(&self, who: &Sibling, doc: &Address, body: &EntryBody) -> Value {
        let term = self.board.board_term().expect("the board term read").expect("H.1 stands on a claimed board");
        let alg = Signer::public_key(&who.signer).alg();
        let frame = entry_frame(alg, term, &addr(&who.account), DocTerm::One(doc), body);
        json!({"alg": alg, "sig": sig_hex(&Signer::sign(&who.signer, &frame))})
    }

    /// `who`'s HOME minted from its own signed session with its attest — the
    /// account's first mint is its doc 1, born published.
    fn home(&self, session: &Session<'_>, who: &Sibling) -> Address {
        let account = addr(&who.account);
        let mut frame = json!({"op": "create_new_document", "account": who.account});
        frame["attest"] = self.attest(who, &account, &entry_body_empty(ContentFreeOp::CreateNewDocument));
        addr(acked_addr(&acked(session.op(&frame))).expect("the home's address"))
    }

    /// A private draft of `who`'s, a later flagless mint from its session.
    fn draft(&self, session: &Session<'_>) -> Address {
        let frame = frames::create_document(session.account(), false, None);
        addr(acked_addr(&acked(session.op(&frame))).expect("the draft's address"))
    }

    /// Whether `token`'s reader — a guest where `None` — may read `doc`: its
    /// `retrieve_doc_v_span_set` answered, or `withheld`.
    fn reads(&self, token: Option<&Token>, doc: &Address) -> bool {
        let Answer::Document(v) = self.board.op(token, &frames::span_set(&doc.to_string())).expect("the read") else { panic!("closed") };
        match v["resp"].as_str() {
            Some("span_set") => true,
            Some("rejected") => {
                assert_eq!(v["code"].as_str(), Some("withheld"), "{v}");
                false
            }
            _ => panic!("{v}"),
        }
    }

    /// The grant-class records homed in `who`'s doc 1, as the board lists
    /// them.
    fn records(&self, token: &Token, who: &Sibling) -> Vec<String> {
        let home = format!("{}.0.1", who.account);
        let Answer::Document(v) = self.board.op(Some(token), &frames::find_links_ftt_home(T_GRANT, &home)).expect("the read") else { panic!("closed") };
        v["addrs"].as_array().expect("addrs").iter().filter_map(Value::as_str).map(str::to_string).collect()
    }
}

/// An acked exchange's document.
fn acked(answer: Result<Answer, skep_client::Halt>) -> Value {
    match answer.expect("the exchange") {
        Answer::Document(v) => {
            assert!(matches!(v["resp"].as_str(), Some("ack" | "ack_addr")), "the board refused: {v}");
            v
        }
        Answer::Closed => panic!("the session was closed"),
    }
}

/// The issuer's facts off a session and its signer.
fn issuer<'a>(session: &'a Session<'_>, who: &'a Sibling) -> Issuer<'a> {
    Issuer { token: session.token(), account: session.account(), signer: &who.signer }
}

/// (i)–(vi): the share, the revoke, the re-share with its `replaces`, the
/// refused duplicate, the whole-account share reaching a later draft, and
/// the two lists; then the refusals around them.
#[test]
fn a_share_opens_a_draft_a_revoke_closes_it_and_a_reshare_names_the_revocation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rig = Rig::new(dir.path());
    let (a, b, c) = (rig.session(&rig.a), rig.session(&rig.b), rig.session(&rig.c));
    let issuer_a = issuer(&a, &rig.a);
    let b_account = addr(&rig.b.account);
    let d = rig.draft(&a);
    // (i) private: B, C and a guest read nothing; A reads its own.
    assert!(rig.reads(Some(a.token()), &d));
    assert!(!rig.reads(Some(b.token()), &d) && !rig.reads(Some(c.token()), &d) && !rig.reads(None, &d));
    let g1 = share(&rig.board, &issuer_a, &d, &b_account).expect("shared");
    assert_eq!((g1.prefix.clone(), g1.grantee.clone(), g1.replaces.clone(), g1.issuer.to_string()), (d.clone(), Grantee::Account(b_account.clone()), None, rig.a.account.clone()));
    assert!(g1.at.to_string().starts_with(&format!("{}.0.1.", rig.a.account)), "homed in A's doc 1: {}", g1.at);
    assert!(rig.reads(Some(b.token()), &d), "B reads by the grant");
    assert!(!rig.reads(Some(c.token()), &d) && !rig.reads(None, &d), "C and the guest still read nothing");
    // (vi) the lists.
    let listed = issued(&rig.board, Some(a.token()), &rig.a.account).expect("issued");
    assert_eq!(listed, vec![(g1.clone(), GrantState::Live)]);
    assert_eq!(held(&rig.board, b.token(), &rig.b.account).expect("held"), vec![g1.clone()]);
    assert!(held(&rig.board, c.token(), &rig.c.account).expect("held").is_empty());
    // (iv) a second share while live: refused, no second write.
    match share(&rig.board, &issuer_a, &d, &b_account) {
        Err(Refusal::AlreadyShared(g)) => assert_eq!(*g, g1),
        other => panic!("{other:?}"),
    }
    assert_eq!(rig.records(a.token(), &rig.a), vec![g1.at.to_string()], "one grant record in the doc 1");
    // (ii) the revoke: B reads nothing at its next read.
    let r1 = revoke(&rig.board, &issuer_a, &g1.at).expect("revoked");
    assert_eq!((r1.revokes.clone(), r1.issuer.to_string()), (g1.at.clone(), rig.a.account.clone()));
    assert!(!rig.reads(Some(b.token()), &d), "withdrawn at the next read");
    assert_eq!(issued(&rig.board, Some(a.token()), &rig.a.account).expect("issued"), vec![(g1.clone(), GrantState::Revoked { by: r1.at.clone() })]);
    assert!(held(&rig.board, b.token(), &rig.b.account).expect("held").is_empty(), "a revoked grant is not held");
    match revoke(&rig.board, &issuer_a, &g1.at) {
        Err(Refusal::AlreadyRevoked { grant, by }) => assert_eq!((grant, by), (g1.at.clone(), r1.at.clone())),
        other => panic!("{other:?}"),
    }
    // (iii) the re-share: a fresh grant beside the old one, `replaces` the
    // revocation — in the library's answer, and in the record's own
    // `replaces` link.
    let g2 = share(&rig.board, &issuer_a, &d, &b_account).expect("shared again");
    assert_eq!(g2.replaces, Some(r1.at.clone()), "the re-share names the revocation it follows");
    assert_ne!(g2.at, g1.at);
    assert!(rig.reads(Some(b.token()), &d), "B reads again");
    let Answer::Document(v) = rig.board.op(Some(a.token()), &frames::find_links_ftt_home(T_REPLACES, &format!("{}.0.1", rig.a.account))).expect("read") else { panic!() };
    let replaces_links: Vec<&str> = v["addrs"].as_array().expect("addrs").iter().filter_map(Value::as_str).collect();
    assert_eq!(replaces_links.len(), 1, "one `replaces` link beside the re-share: {v}");
    let Answer::Document(link) = rig.board.op(Some(a.token()), &frames::read_link(replaces_links[0])).expect("read") else { panic!() };
    assert_eq!(link["link"]["slots"][0][0]["start"].as_str(), Some(g2.at.to_string().as_str()), "from the re-share: {link}");
    assert_eq!(link["link"]["slots"][1][0]["start"].as_str(), Some(r1.at.to_string().as_str()), "to the revocation: {link}");
    assert_eq!(
        issued(&rig.board, Some(a.token()), &rig.a.account).expect("issued"),
        vec![(g1.clone(), GrantState::Revoked { by: r1.at.clone() }), (g2.clone(), GrantState::Live)]
    );
    // (v) the whole account: a draft minted AFTER the grant is readable.
    let g3 = share(&rig.board, &issuer_a, &addr(&rig.a.account), &b_account).expect("the account shared");
    assert_eq!(g3.prefix.to_string(), rig.a.account);
    let later = rig.draft(&a);
    assert!(rig.reads(Some(b.token()), &later), "a later draft under the account");
    assert!(!rig.reads(Some(c.token()), &later));
    assert_eq!(held(&rig.board, b.token(), &rig.b.account).expect("held"), vec![g2.clone(), g3.clone()]);
    // The refusals around the act, each before any write.
    let count = rig.records(a.token(), &rig.a).len();
    assert!(matches!(share(&rig.board, &issuer_a, &d, &addr(&rig.a.account)), Err(Refusal::ToYourself(_))));
    assert!(matches!(share(&rig.board, &issuer_a, &d, &addr("1.0.9")), Err(Refusal::NoSuchAccount(_))), "an account no registry row names");
    assert!(matches!(share(&rig.board, &issuer_a, &addr(&rig.b.account), &addr(&rig.c.account)), Err(Refusal::NotOwner { .. })), "another's account prefix");
    assert!(matches!(share(&rig.board, &issuer_a, &addr("1.0.1.2.0.9"), &b_account), Err(Refusal::NoSuchDocument(_))), "a document never minted");
    let issuer_b = issuer(&b, &rig.b);
    match revoke(&rig.board, &issuer_b, &g2.at) {
        Err(Refusal::NotYours { grant, issuer }) => assert_eq!((grant, issuer.map(|i| i.to_string())), (g2.at.clone(), Some(rig.a.account.clone()))),
        other => panic!("{other:?}"),
    }
    assert!(matches!(revoke(&rig.board, &issuer_a, &r1.at), Err(Refusal::NotAGrant(_))), "a revocation is no grant");
    assert_eq!(rig.records(a.token(), &rig.a).len(), count, "the refusals wrote nothing");
    for s in [a, b, c] {
        s.close().expect("close");
    }
}

/// (vii) A document A does not own: the library refuses before any write
/// (PUB-5.3), and the board's own answer to such a record — sent raw, as a
/// client that did not check would send it — is pinned beside it: the
/// board DEPOSITS AND ACKNOWLEDGES it, and it opens nothing (wire.md §The
/// read predicate: "issued by anyone but the document's owner, opens
/// nothing").
#[test]
fn a_grant_over_a_document_the_issuer_does_not_own_is_refused_and_the_board_honours_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rig = Rig::new(dir.path());
    let (a, b, c) = (rig.session(&rig.a), rig.session(&rig.b), rig.session(&rig.c));
    let issuer_a = issuer(&a, &rig.a);
    let d_b = rig.draft(&b);
    let c_account = addr(&rig.c.account);
    match share(&rig.board, &issuer_a, &d_b, &c_account) {
        Err(Refusal::NotOwner { prefix, .. }) => assert_eq!(prefix, d_b),
        other => panic!("{other:?}"),
    }
    assert!(rig.records(a.token(), &rig.a).is_empty(), "nothing written");
    // The board's own answer to the raw record.
    let home = addr(&format!("{}.0.1", rig.a.account));
    let (from, to, ty) = ([unit_span(&d_b)], [unit_span(&c_account)], [unit_span(&addr(T_GRANT))]);
    let body = entry_body_make_link(LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) });
    let mut frame = frames::make_link(&home.to_string(), &[&d_b.to_string()], &[&rig.c.account], T_GRANT, None);
    frame["attest"] = rig.attest(&rig.a, &home, &body);
    let Answer::Document(v) = a.op(&frame).expect("the exchange") else { panic!("closed") };
    assert!(acked_addr(&v).is_some(), "the board deposits and acknowledges a grant from a hand that is not the owner: {v}");
    assert!(!rig.reads(Some(c.token()), &d_b), "and it opens nothing: C's read stays withheld");
    assert!(held(&rig.board, c.token(), &rig.c.account).expect("held").is_empty(), "nor is it held: the registry owns the prefix to B, not A");
    assert_eq!(issued(&rig.board, Some(a.token()), &rig.a.account).expect("issued").len(), 1, "the record stands in A's doc 1, listed as A's");
    for s in [a, b, c] {
        s.close().expect("close");
    }
}

/// (viii) PRIVASH (PUB-5.108): A's draft opened to every account — C, never
/// granted by name, reads it; a guest does not (PUB-5.109); the board's
/// privashed set lists it to a bound principal and is empty to a guest; the
/// revocation closes it at the next read; and a privash over an account
/// prefix, or over a published document, is refused with nothing written.
#[test]
fn a_privash_opens_a_draft_to_every_account_and_never_a_guest_until_revoked() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rig = Rig::new(dir.path());
    let (a, c) = (rig.session(&rig.a), rig.session(&rig.c));
    let issuer_a = issuer(&a, &rig.a);
    let d = rig.draft(&a);
    assert!(!rig.reads(Some(c.token()), &d) && !rig.reads(None, &d));
    let g = privash(&rig.board, &issuer_a, &d).expect("privashed");
    assert_eq!((g.prefix.clone(), g.grantee.clone(), g.replaces.clone()), (d.clone(), Grantee::Privashed, None));
    assert!(rig.reads(Some(c.token()), &d), "every account reads a privashed draft");
    assert!(!rig.reads(None, &d), "never a guest");
    let set = privashed(&rig.board, Some(c.token())).expect("the privashed set");
    assert_eq!(set.iter().map(|p| (p.prefix.to_string(), p.issuers.iter().map(ToString::to_string).collect::<Vec<_>>())).collect::<Vec<_>>(), vec![(d.to_string(), vec![rig.a.account.clone()])]);
    assert!(privashed(&rig.board, None).expect("the guest's read").is_empty(), "the guest is answered no rows");
    assert_eq!(issued(&rig.board, Some(a.token()), &rig.a.account).expect("issued"), vec![(g.clone(), GrantState::Live)]);
    assert!(held(&rig.board, c.token(), &rig.c.account).expect("held").is_empty(), "a privash names nobody, so it is nobody's held grant");
    match privash(&rig.board, &issuer_a, &d) {
        Err(Refusal::AlreadyShared(standing)) => assert_eq!(*standing, g),
        other => panic!("{other:?}"),
    }
    let r = revoke(&rig.board, &issuer_a, &g.at).expect("revoked");
    assert!(!rig.reads(Some(c.token()), &d), "closed at the next read");
    assert!(privashed(&rig.board, Some(c.token())).expect("the set").is_empty(), "gone from the set");
    assert_eq!(issued(&rig.board, Some(a.token()), &rig.a.account).expect("issued"), vec![(g.clone(), GrantState::Revoked { by: r.at.clone() })]);
    // The re-privash names the revocation, as a share does.
    let again = privash(&rig.board, &issuer_a, &d).expect("privashed again");
    assert_eq!(again.replaces, Some(r.at.clone()));
    assert!(rig.reads(Some(c.token()), &d));
    // An account prefix, and a published document: refused, nothing written.
    let count = rig.records(a.token(), &rig.a).len();
    assert!(matches!(privash(&rig.board, &issuer_a, &addr(&rig.a.account)), Err(Refusal::NotADocument(_))), "privashing a whole account is not available");
    assert!(matches!(privash(&rig.board, &issuer_a, &addr(&format!("{}.0.1", rig.a.account))), Err(Refusal::NotADraft(_))), "the home is published already");
    assert!(matches!(privash(&rig.board, &issuer_a, &addr("1")), Err(Refusal::NotAPrefix(_))));
    assert_eq!(rig.records(a.token(), &rig.a).len(), count, "nothing written");
    a.close().expect("close");
    c.close().expect("close");
}

/// THE DROPPING DIALER: every request through the plain arm, and the first
/// `n` grant-class `make_link`s answered — after the daemon took them — as a
/// broken connection, the answer lost: `Dialer::exchange` answers
/// `DialError::Io` where the write landed.
struct Dropping {
    inner: PlainHttp,
    to_drop: AtomicUsize,
    grant_writes: AtomicUsize,
}

impl Dialer for Dropping {
    fn exchange(&self, origin: &Origin, req: &Request) -> Result<Response, DialError> {
        let resp = self.inner.exchange(origin, req)?;
        let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        let grant_write = req.path == "/op" && body["op"].as_str() == Some("make_link") && body["ty"]["addrs"][0].as_str() == Some(T_GRANT);
        if grant_write {
            self.grant_writes.fetch_add(1, Ordering::SeqCst);
            if self.to_drop.load(Ordering::SeqCst) > 0 {
                self.to_drop.fetch_sub(1, Ordering::SeqCst);
                return Err(DialError::Io("the connection broke after the write".into()));
            }
        }
        Ok(resp)
    }

    fn stream(&self, origin: &Origin, head: &RequestHead, body: &mut dyn Read, on_interim: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        self.inner.stream(origin, head, body, on_interim)
    }
}

/// (ix) THE LOST ANSWER: the share lands and its acknowledgement is lost;
/// the library sends nothing again — it reads the key's state and answers
/// the grant standing — and the doc 1 holds ONE grant record; the same for
/// a revocation. A lost answer where nothing landed is a halt naming it.
#[test]
fn a_share_whose_acknowledgement_is_lost_is_read_back_and_never_resent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rig = Rig::new(dir.path());
    let (a, b) = (rig.session(&rig.a), rig.session(&rig.b));
    let b_account = addr(&rig.b.account);
    let d = rig.draft(&a);
    let dropping = Arc::new(Dropping { inner: PlainHttp::new(), to_drop: AtomicUsize::new(1), grant_writes: AtomicUsize::new(0) });
    let lossy = Board::new(rig.board.dialed().clone(), dropping.clone());
    let issuer_a = Issuer { token: a.token(), account: a.account(), signer: &rig.a.signer };
    let g = share(&lossy, &issuer_a, &d, &b_account).expect("the grant read back as standing");
    assert_eq!((g.prefix.clone(), g.grantee.clone(), g.replaces.clone()), (d.clone(), Grantee::Account(b_account.clone()), None));
    assert_eq!(dropping.grant_writes.load(Ordering::SeqCst), 1, "the write was sent once and never re-sent");
    assert_eq!(rig.records(a.token(), &rig.a), vec![g.at.to_string()], "ONE grant record in the doc 1");
    assert!(rig.reads(Some(b.token()), &d), "and it stands");
    // The revocation's lost answer, read back the same way.
    dropping.to_drop.store(1, Ordering::SeqCst);
    let r = revoke(&lossy, &issuer_a, &g.at).expect("the revocation read back");
    assert_eq!(r.revokes, g.at);
    assert_eq!(dropping.grant_writes.load(Ordering::SeqCst), 2, "one revocation write, never re-sent");
    assert_eq!(rig.records(a.token(), &rig.a).len(), 2, "the grant and its revocation");
    assert!(!rig.reads(Some(b.token()), &d));
    // A lost answer where nothing landed: the dialer refuses before the
    // write; the read-back finds no grant and the halt names it.
    struct Refusing;
    impl Dialer for Refusing {
        fn exchange(&self, origin: &Origin, req: &Request) -> Result<Response, DialError> {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            if req.path == "/op" && body["op"].as_str() == Some("make_link") {
                return Err(DialError::Connect("refused".into()));
            }
            PlainHttp::new().exchange(origin, req)
        }
        fn stream(&self, origin: &Origin, head: &RequestHead, body: &mut dyn Read, on_interim: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
            PlainHttp::new().stream(origin, head, body, on_interim)
        }
    }
    let refusing = Board::new(rig.board.dialed().clone(), Refusing);
    match share(&refusing, &issuer_a, &d, &b_account) {
        Err(Refusal::Halt(h)) => {
            let text = h.to_string();
            assert!(text.contains("the board's answer to the grant was lost, and the grant is not standing") && text.contains("not re-sent"), "{text}");
            assert_eq!(h.exit_code(), 3);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(rig.records(a.token(), &rig.a).len(), 2, "nothing written");
    a.close().expect("close");
    b.close().expect("close");
}
