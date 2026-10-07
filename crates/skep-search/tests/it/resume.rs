//! THE RESUME at the public surface (`search.md` §5.4; ITEM 1 RULED (a) and
//! its riders; §8.3): the open's sequence — a saved file loaded, each
//! range's `held` and the newest head's `H.k` read off the header it hands
//! back, the wire's answer handed in as the shell fills it, and the verdict
//! judged with no board read and no file moved. Named by §5.4's words: an
//! equal chain resumes; `history_reclaimed` keeps the file and resumes from
//! the floor with the `H.k` re-read byte-equal, a different `H.k` taking the
//! diverged disposition; `beyond_head` and a different chain are FACED, the
//! file moved aside with its pair, then built fresh; `history_busy` retries.

use skep_search::{aside_name, ChainAnswer, Class, HeadRecord, Header, Index, RangeRecord, Resume};

use crate::{addr, at, chain, text_unit};

/// A supplement of principal 7 saved with two ranges and the newest head,
/// loaded back: the header the shell judges from.
fn opened() -> Header {
    let mut supplement = Index::new(Class::Principal(7));
    supplement.index(text_unit(Class::Principal(7), 1, b"a draft")).expect("admitted");
    let header = Header {
        board: chain(0xB0),
        floor: Some(10),
        ranges: vec![
            RangeRecord {
                under: None,
                held: at(900, 0xAA),
                refusals: Vec::new(),
                bare_rows: 0,
                grant: None,
            },
            RangeRecord {
                under: Some(addr(&[1, 0, 2])),
                held: at(850, 0xBB),
                refusals: Vec::new(),
                bare_rows: 0,
                grant: None,
            },
        ],
        head: Some(HeadRecord { member: addr(&[1, 1, 0, 1, 0, 2, 3]), at: at(512, 0x33) }),
    };
    let mut file = Vec::new();
    supplement.save(&header, &mut file).expect("saved");
    let (_, read) = Index::load(&mut &file[..], Class::Principal(7)).expect("loads");
    assert_eq!(read, header);
    read
}

/// §5.4: "an EQUAL chain resumes", per range; "`history_busy` is retry-class
/// and retried, never a rebuild".
#[test]
fn an_equal_chain_resumes_and_history_busy_retries() {
    let header = opened();
    let head = header.head.as_ref();
    let verdicts: Vec<Resume> = header
        .ranges
        .iter()
        .map(|range| Resume::judge(range.held, head, &ChainAnswer::Chain(range.held.chain)))
        .collect();
    assert_eq!(verdicts, [Resume::Equal, Resume::Equal]);
    assert_eq!(Resume::judge(header.ranges[0].held, head, &ChainAnswer::Busy), Resume::Busy);
}

/// §5.4, ITEM 1 (a) with rider 1: "`history_reclaimed` … KEEPS THE FILE" —
/// the shell re-reads the saved `H.k` byte-equal and each range resumes
/// from the floor the answer carries.
#[test]
fn history_reclaimed_keeps_the_file_and_resumes_from_the_floor_with_the_h_k_byte_equal() {
    let header = opened();
    let saved = header.head.as_ref().expect("the file carries its newest head");
    let reread = ChainAnswer::Reclaimed { floor: Some(2048), head: Some(saved.at) };
    for range in &header.ranges {
        assert_eq!(
            Resume::judge(range.held, Some(saved), &reread),
            Resume::FromTheFloor { floor: Some(2048) }
        );
    }
}

/// §5.4, riders 1 and 2: a DIVERGED history — the `H.k` re-read different
/// or gone — `beyond_head`, and a DIFFERENT chain are each FACED before
/// anything is rebuilt, the verdict carrying the saved pair, and the shell
/// moves the file aside under the file's own board's chain, then builds
/// fresh.
#[test]
fn a_diverged_history_beyond_head_or_a_different_chain_is_faced_and_the_file_moved_aside() {
    let header = opened();
    let saved = header.head.as_ref();
    let held = header.ranges[1].held;
    let different_head = ChainAnswer::Reclaimed { floor: Some(2048), head: Some(at(512, 0x34)) };
    assert_eq!(Resume::judge(held, saved, &different_head), Resume::Diverged { saved: held });
    let gone = ChainAnswer::Reclaimed { floor: Some(2048), head: None };
    assert_eq!(Resume::judge(held, saved, &gone), Resume::Diverged { saved: held });
    assert_eq!(
        Resume::judge(held, saved, &ChainAnswer::BeyondHead { head: 700 }),
        Resume::BeyondHead { saved: held, head: 700 }
    );
    assert_eq!(
        Resume::judge(held, saved, &ChainAnswer::Chain(chain(0xBC))),
        Resume::DifferentChain { saved: held, found: chain(0xBC) }
    );
    let aside = aside_name("principal-7.index", &header.board, 1);
    assert_eq!(aside, format!("principal-7.index.aside.{}.1", "b0".repeat(32)));
}
