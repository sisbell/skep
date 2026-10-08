//! THE DIRECTORY's PERSON ACTS against the daemon (`search.md` §5.5; sr-S1;
//! `client.md` §4e.4): the forget offer's test — "for each supplement in the
//! directory, AUTH-5.21's walk upward from `principal_prefix(n)` and ONE
//! `key_set` read at its terminus, orphaned where no fingerprint the store
//! holds stands in its `enrolled`" — read off the BOARD and never the
//! store's proxy, and the forget deleting the supplement and its places part.

use skep_client::board::Scope;
use skep_client::ceremony::handshake::{handshake, Site};
use skep_client::search::Orphan;
use skep_client::sign::{signer_from_seed, Signer};
use skep_search::Chain;

use super::{session_ref, Fixture, CLAIMANT};
use crate::common::{keyed_sub_account, recording_board};

/// §5.5: a supplement held AS a principal whose set holds no key of this
/// store is ORPHANED — here a sub-account another key opens — while the
/// claimant's own is not; the test reads the board, one `key_set` per
/// supplement at the walk's terminus; `forget` removes the two files.
#[test]
fn orphans_are_read_off_the_board_by_the_walk_and_one_key_set_and_forget_deletes_the_files() {
    let fx = Fixture::claimed();
    let owner = fx.device();
    let friend = signer_from_seed(&[55; 32]);
    let account = keyed_sub_account(&fx.board, &fx.anchors, &owner, 2, 777, &friend, "friend");
    let theirs = handshake(&fx.board, Scope::Full, &friend, 777, Site::Session).expect("the friend's session");
    fx.home(&theirs, &friend, &account);
    fx.draft(theirs.token(), &account, "the friend's draft");
    fx.draft(&fx.bare(), CLAIMANT, "the claimant's draft");
    let consumer = fx.consumer(&fx.board);
    consumer.poll().unwrap();
    let mine = fx.signed(&fx.board);
    consumer.widen(session_ref(&mine)).unwrap();
    consumer.widen(session_ref(&theirs)).unwrap();
    consumer.save().unwrap();
    let dir = fx.dir().board(&Chain::from_bytes(fx.board.board_term().unwrap().unwrap().chain));
    assert_eq!(dir.supplements().unwrap(), vec![1, 777]);
    // The store holds the claimant's key alone: 777's supplement is orphaned.
    let (rb, log) = recording_board(fx.board.dialed().clone());
    let reading = skep_client::search::Consumer::open(&rb, fx.dir()).unwrap();
    assert!(matches!(reading.state(skep_client::search::Who::Guest), skep_client::search::State::Busy), "the first consumer holds the lock");
    log.lock().unwrap().clear();
    let orphans = reading.orphans(&[fx.fp]).unwrap();
    assert_eq!(orphans, [Orphan { principal: 777, account: Some(account.clone()) }]);
    let lines = log.lock().unwrap().clone();
    assert_eq!(lines.iter().filter(|l| *l == "POST /op key_set").count(), 2, "one `key_set` read per supplement, at the walk's terminus: {lines:?}");
    assert_eq!(lines.iter().filter(|l| *l == "POST /op principal_prefix").count(), 2, "{lines:?}");
    // With the friend's key in the store too, nothing is orphaned.
    assert!(reading.orphans(&[fx.fp, Signer::fingerprint(&friend)]).unwrap().is_empty());
    // The forget: the person's act — the files gone, the mount gone.
    consumer.forget(777).unwrap();
    assert!(!dir.file("principal-777.index").is_file() && !dir.file("principal-777.places").is_file());
    assert!(dir.file("principal-1.index").is_file(), "the claimant's own stays");
    assert!(!consumer.mounted(777));
    consumer.close().unwrap();
    mine.close().unwrap();
    theirs.close().unwrap();
}
