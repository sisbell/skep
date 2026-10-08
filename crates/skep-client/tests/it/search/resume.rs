//! THE RESUME against the daemon (`search.md` §5.4; ITEM 1 RULED (a)):
//! `history_reclaimed` reached HONESTLY — the retention floor moved past the
//! saved `held` by the daemon's own checkpoints, through its `test-hooks`
//! seam (`Daemon::service_the_checkpoint_now`, the checkpoint thread's whole
//! act on the calling thread: the checkpoint, the feed's files compacted to
//! the reclaim floor), the journal's segment rotated first by bulk inserts
//! as the daemon's own `chain_at` suite rotates it — and the file KEPT, each
//! range resumed from the floor, the saved `H.k` re-read byte-equal.

use skep_client::search::{SearchOpts, State, Who};
use skep_search::{Chain, ChainAt, Class, Index};

use super::{Fixture, CLAIMANT};
use crate::common::insert_text;

/// §5.4: "`history_reclaimed` … KEEPS THE FILE — ITEM 1 RULED (a): each
/// range resumes from the `floor` the answer carries …, its `held` re-fixed
/// there …, and the state event says the index is complete from that floor
/// … the shell re-reads that `H.k` byte-equal" — §4b.2's
/// `resumed_from_the_floor {floor, held}`.
#[test]
fn history_reclaimed_on_the_daemon_keeps_the_file_and_resumes_from_the_floor() {
    let fx = Fixture::claimed();
    let token = fx.bare();
    let early = fx.draft(&token, CLAIMANT, "written before the floor rose");
    let held = {
        let consumer = fx.consumer(&fx.board);
        consumer.poll().unwrap();
        consumer.close().unwrap();
        let health = fx.board.health().unwrap();
        ChainAt { position: health.log_position(), chain: Chain::from_bytes(health.chain_head().unwrap()) }
    };
    let dir = fx.dir().board(&Chain::from_bytes(fx.board.board_term().unwrap().unwrap().chain));
    let file = dir.file("published.index");
    let saved = Index::load(&mut &std::fs::read(&file).unwrap()[..], Class::Guest).unwrap().1;
    assert_eq!(saved.ranges[0].held, held, "the saved pair is the `/health` pair read before the draining poll");
    assert!(saved.head.is_some(), "the file carries the newest `H.k` the feed delivered");
    // The floor rises past `held`: bulk inserts rotate the journal's segment,
    // then three checkpoints retain two and reclaim below the oldest kept.
    let bulk = "z".repeat(8192);
    let draft = fx.draft(&token, CLAIMANT, "bulk");
    for round in 0..3 {
        for _ in 0..3 {
            insert_text(&fx.board, &token, &draft.to_string(), 1, &bulk);
        }
        fx.sd.daemon().service_the_checkpoint_now();
        let _ = round;
    }
    let answer = fx.board.chain_at(held.position).unwrap();
    let floor = match answer {
        skep_client::board::ChainAtAnswer::HistoryReclaimed { floor } => floor.expect("the floor is known"),
        other => panic!("the saved position still answers: {other:?}"),
    };
    assert!(floor > held.position);
    let consumer = fx.consumer(&fx.board);
    assert_eq!(consumer.state(Who::Guest), State::ResumedFromTheFloor { floor, held });
    assert!(file.is_file(), "the file KEPT");
    assert!(std::fs::read_dir(dir.path()).unwrap().filter_map(Result::ok).all(|e| !e.file_name().to_string_lossy().contains(".aside.")), "nothing moved aside");
    consumer.poll().unwrap();
    let fresh = fx.draft(&token, CLAIMANT, "written after the floor rose");
    consumer.poll().unwrap();
    assert!(consumer.search(Who::Guest, "before", &SearchOpts::default()).unwrap().hits.is_empty(), "drafts are no guest's: the published index holds doc 1 and the heads alone");
    consumer.close().unwrap();
    let resumed = Index::load(&mut &std::fs::read(&file).unwrap()[..], Class::Guest).unwrap().1;
    assert_eq!(resumed.floor, Some(floor), "the file states its completeness");
    assert!(resumed.ranges[0].held.position >= floor, "`held` re-fixed at or past the floor: {:?}", resumed.ranges[0].held);
    drop((early, fresh));
}
