//! THE FEED CONSUMER against the daemon: `search.md` §4's invariants (i),
//! (ii) and (iii) — the published index fed by token-free reads alone, the
//! supplement by the session's, one principal's supplement answering no
//! other's session and the guest face searching the published index alone,
//! the state composed per face — and the `/events` stream as the loop's
//! input.

use std::time::Duration;

use skep_client::board::Scope;
use skep_client::ceremony::handshake::{handshake, Site};
use skep_client::search::{events, SearchOpts, State, Who};
use skep_client::sign::signer_from_seed;
use skep_client::Health;
use skep_search::{Kind, Standing};

use super::{session_ref, Fixture, CLAIMANT};
use crate::common::{keyed_sub_account, traced_board};

fn docs(answer: &skep_client::search::SearchAnswer) -> Vec<String> {
    answer.hits.iter().map(|h| h.doc.to_string()).collect()
}

/// §4 (i): "A PUBLISHED index … is built from token-free reads" — every read
/// that fed `published.index` carried no token, and the supplement's reads
/// carried the session's; a published edition's text, minted by the attested
/// shot, is found at its pinned member by the guest.
#[test]
fn the_published_index_is_fed_token_free_and_the_supplement_under_the_sessions_token() {
    let fx = Fixture::claimed();
    let signed = fx.signed(&fx.board);
    let (doc, member) = fx.published(&signed, "the published edition speaks of lighthouses");
    let token = fx.bare();
    let draft = fx.draft(&token, CLAIMANT, "a private draft about lanterns");
    signed.close().unwrap();
    let (traced, traces) = traced_board(fx.board.dialed().clone());
    let consumer = fx.consumer(&traced);
    consumer.poll().expect("the first build");
    {
        let traces = traces.lock().unwrap();
        let reads: Vec<_> = traces.iter().filter(|t| t.line == "POST /op retrieve_v" || t.line == "POST /op retrieve_doc_v_span_set" || t.line.starts_with("GET /changes")).collect();
        assert!(!reads.is_empty());
        assert!(reads.iter().all(|t| !t.token), "a read feeding the published index carried a token: {:?}", reads.iter().filter(|t| t.token).map(|t| &t.line).collect::<Vec<_>>());
    }
    let guest = consumer.search(Who::Guest, "lighthouses", &SearchOpts::default()).unwrap();
    assert_eq!(docs(&guest), [doc.to_string()]);
    assert_eq!((guest.hits[0].member.as_ref(), guest.hits[0].kind, guest.hits[0].standing.clone()), (Some(&member), Kind::Edition, Standing::Public));
    assert!(consumer.search(Who::Guest, "lanterns", &SearchOpts::default()).unwrap().hits.is_empty(), "the draft is no guest's");
    assert!(matches!(guest.state, State::Complete { .. }), "{:?}", guest.state);
    // The supplement: the claimant's session widens over its own account.
    let signed = fx.signed(&traced);
    traces.lock().unwrap().clear();
    consumer.widen(session_ref(&signed)).expect("widens");
    {
        let traces = traces.lock().unwrap();
        let drafts_pages: Vec<_> = traces.iter().filter(|t| t.line.contains("drafts=true")).collect();
        assert!(!drafts_pages.is_empty() && drafts_pages.iter().all(|t| t.token), "the supplement's pages ride the token: {:?}", drafts_pages.iter().map(|t| (&t.line, t.token)).collect::<Vec<_>>());
        let reads: Vec<_> = traces.iter().filter(|t| t.line == "POST /op retrieve_v").collect();
        assert!(!reads.is_empty() && reads.iter().all(|t| t.token), "the supplement's reads ride the token");
    }
    let mine = consumer.search(Who::Session(session_ref(&signed)), "lanterns", &SearchOpts::default()).unwrap();
    assert_eq!(docs(&mine), [draft.to_string()]);
    assert_eq!((mine.hits[0].kind, mine.hits[0].standing.clone()), (Kind::Draft, Standing::YoursToRead));
    // The pair: the edition from the published index and, from the
    // supplement, the STAGING DRAFT that holds the same words — "the contract
    // draws TWO HITS for a staging draft and the edition it publishes"
    // (`search.md` §3.1).
    let both = consumer.search(Who::Session(session_ref(&signed)), "lighthouses", &SearchOpts::default()).unwrap();
    assert!(both.hits.len() == 2 && both.hits.iter().any(|h| h.doc == doc && h.kind == Kind::Edition) && both.hits.iter().any(|h| h.kind == Kind::Draft), "{:?}", docs(&both));
    consumer.close().unwrap();
    signed.close().unwrap();
    drop(token);
}

/// §4 (ii): "A SUPPLEMENT never answers a query under another principal's
/// session"; (iii): "The guest face searches the published index alone …
/// `places` … included"; the state event composed per face. Two
/// sub-accounts, siblings to each other, each with its own key, draft and
/// session.
#[test]
fn one_principals_supplement_answers_no_others_session_and_the_guest_searches_the_published_alone() {
    let fx = Fixture::claimed();
    let owner = fx.device();
    let two = signer_from_seed(&[42; 32]);
    let three = signer_from_seed(&[43; 32]);
    let account_two = keyed_sub_account(&fx.board, &fx.anchors, &owner, 2, 777, &two, "two");
    let account_three = keyed_sub_account(&fx.board, &fx.anchors, &owner, 3, 778, &three, "three");
    // A keyed account takes signed sessions alone: each principal's draft is
    // written from its own.
    let session_two = handshake(&fx.board, Scope::Full, &two, 777, Site::Session).expect("two's session");
    let session_three = handshake(&fx.board, Scope::Full, &three, 778, Site::Session).expect("three's session");
    fx.home(&session_two, &two, &account_two);
    fx.home(&session_three, &three, &account_three);
    let draft_two = fx.draft(session_two.token(), &account_two, "marmalade for principal two");
    let draft_three = fx.draft(session_three.token(), &account_three, "quince for principal three");
    let consumer = fx.consumer(&fx.board);
    consumer.poll().unwrap();
    consumer.widen(session_ref(&session_two)).unwrap();
    consumer.widen(session_ref(&session_three)).unwrap();
    let as_two = Who::Session(session_ref(&session_two));
    let as_three = Who::Session(session_ref(&session_three));
    assert_eq!(docs(&consumer.search(as_two, "marmalade", &SearchOpts::default()).unwrap()), [draft_two.to_string()]);
    assert!(consumer.search(as_two, "quince", &SearchOpts::default()).unwrap().hits.is_empty(), "three's draft answers no query of two's");
    assert_eq!(docs(&consumer.search(as_three, "quince", &SearchOpts::default()).unwrap()), [draft_three.to_string()]);
    assert!(consumer.search(as_three, "marmalade", &SearchOpts::default()).unwrap().hits.is_empty());
    for word in ["marmalade", "quince"] {
        let guest = consumer.search(Who::Guest, word, &SearchOpts::default()).unwrap();
        assert!(guest.hits.is_empty() && guest.places.is_empty(), "the guest face searches the published index alone: {word}");
    }
    // `places` at the call's class: a label is its own principal's.
    assert_eq!(consumer.search(as_two, "marmalade for principal two", &SearchOpts::default()).unwrap().places.iter().map(|p| p.doc.to_string()).collect::<Vec<_>>(), [draft_two.to_string()]);
    assert!(consumer.search(as_three, "marmalade for principal two", &SearchOpts::default()).unwrap().places.is_empty());
    // The counts per account at the call's class: two's home from the
    // published part and two's draft from two's part; three sees the home
    // alone.
    let account_two_addr = skep_client::address::parse_address(&account_two).unwrap();
    assert_eq!(consumer.counts(as_two).get(&account_two_addr), Some(&2));
    assert_eq!(consumer.counts(as_three).get(&account_two_addr), Some(&1));
    assert_eq!(consumer.counts(Who::Guest).get(&account_two_addr), Some(&1));
    // The state per face: the files are two.
    assert!(matches!(consumer.state(as_two), State::Complete { .. }) && matches!(consumer.state(as_three), State::Complete { .. }) && matches!(consumer.state(Who::Guest), State::Complete { .. }));
    consumer.close().unwrap();
    let dir = fx.dir().board(&skep_search::Chain::from_bytes(fx.board.board_term().unwrap().unwrap().chain));
    assert!(dir.file("principal-777.index").is_file() && dir.file("principal-778.index").is_file(), "one supplement per (board, principal)");
    assert_eq!(dir.supplements().unwrap(), vec![777, 778]);
    session_two.close().unwrap();
    session_three.close().unwrap();
}

/// `client.md` §4e.2, §7; wire.md §The commit stream: `GET /events` on the
/// dialer's streamed form yields the committed head on connect, then each
/// commit's position — the shell's loop input, `poll` the reaction.
#[test]
fn the_events_stream_yields_the_head_then_each_commits_position() {
    let fx = Fixture::claimed();
    let health: Health = fx.board.health().unwrap();
    let mut stream = events(&fx.board);
    let stop = stream.stopper();
    let initial = stream.next().expect("the initial event").expect("no halt");
    // The announced position on connect — the committed head on a quiescent
    // board, at most the head where a commit's record is still in flight.
    assert!(initial <= health.log_position() && initial + 2 >= health.log_position(), "the head on connect: {initial} against {}", health.log_position());
    let token = fx.bare();
    let draft = fx.draft(&token, CLAIMANT, "a commit the stream announces");
    let head = fx.board.health().unwrap().log_position();
    assert!(head > initial);
    let mut seen = initial;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while seen < head {
        assert!(std::time::Instant::now() < deadline, "the stream did not reach the head: {seen} against {head}");
        let next = stream.next().expect("an event").expect("no halt");
        assert!(next > seen, "a strictly increasing sequence: {next} after {seen}");
        seen = next;
    }
    assert_eq!(seen, head, "the positions converge on the true head");
    let consumer = fx.consumer(&fx.board);
    consumer.poll().unwrap();
    assert_eq!(docs(&consumer.search(Who::Guest, "announces", &SearchOpts::default()).unwrap()), Vec::<String>::new(), "a draft, no guest's");
    stop.stop();
    drop(stream);
    drop(draft);
}
