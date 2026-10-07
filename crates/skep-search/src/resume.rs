//! THE RESUME (`search.md` §5.4; ITEM 1 RULED (a) with its two riders; §8.3):
//! at open the shell asks `GET /chain?at=<held>` for each saved `(position,
//! chain)` pair — token-blind, class-invariant, one read per distinct
//! position — and judges the answer. The judgment stands here as a PURE
//! FUNCTION over typed values the shell hands in, [`Resume::judge`]: what the
//! saved file holds (a range's `held`, the newest head's `H.k` pair off the
//! `Header`) against what the shell read from the board ([`ChainAnswer`] —
//! the chain, or the wire's `history_reclaimed`, `beyond_head` or
//! `history_busy`, modelled as an enum the shell fills, no wire type
//! linked). The crate reads no board, and no file moves here: the ASIDE is
//! the shell's rename, spelled by the `file` module's `aside_name`.
//!
//! The arms, as §5.4 states them:
//!
//! * an EQUAL chain RESUMES — [`Resume::Equal`];
//! * `history_reclaimed` — the position aged below the floor, a laptop asleep
//!   while a busy board checkpointed past `held` — KEEPS THE FILE: each range
//!   resumes FROM THE FLOOR the answer carries (ITEM 1 (a)), its `held`
//!   re-fixed there, and the one divergence the floor hides is checked by the
//!   wire's own below-floor check (rider 1): the shell re-reads the saved
//!   `H.k`, which survives reclamation as checkpoint state, and where its
//!   record names the saved pair byte-equal the file is trusted —
//!   [`Resume::FromTheFloor`]; where it reads different, gone, or superseded
//!   by an older newest head, the history DIVERGED — [`Resume::Diverged`] —
//!   and the file is the wire's evidence, moved aside;
//! * `beyond_head` or a DIFFERENT chain — a journal cut or restored below
//!   `held`, or re-chained after the fact, which the shell cannot tell apart
//!   — is FACED BEFORE ANYTHING IS REBUILT (rider 2): the state says this
//!   board's history no longer extends the one the index was built from at
//!   ⟨held⟩, the file with its saved pair is MOVED ASIDE as the wire's
//!   evidence of a re-chained journal, and the index is built fresh —
//!   [`Resume::BeyondHead`], [`Resume::DifferentChain`], each carrying the
//!   saved pair for the face;
//! * `history_busy` is retry-class and retried, never a rebuild —
//!   [`Resume::Busy`].
//!
//! `not_a_position` cannot arise, `held` being always a committed position,
//! and has no arm.

use crate::header::{Chain, ChainAt, HeadRecord};

/// What the shell read from the board for one saved pair: `GET
/// /chain?at=<held.position>`'s answer (wire.md §Reading history), and on
/// the reclaimed arm the `H.k` re-read it then makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainAnswer {
    /// `200 {"at": N, "chain": …}`: the chain's value as of the position.
    Chain(Chain),
    /// `410 history_reclaimed`: the position predates retained history. The
    /// floor the answer carried, "when known"; and the re-read of the saved
    /// `H.k` — the pair its record names NOW, or `None` where the member is
    /// gone or an older newest head stands in its place.
    Reclaimed {
        /// The oldest position still answerable, where the answer named one.
        floor: Option<u64>,
        /// The saved head's record as re-read, if it still stands.
        head: Option<ChainAt>,
    },
    /// `400 beyond_head`: the position exceeds the committed head.
    BeyondHead {
        /// The committed head the answer carried.
        head: u64,
    },
    /// `503 history_busy`: every reconstruction permit is in use.
    Busy,
}

/// The resume's verdict for one saved pair (§5.4), each aside arm carrying
/// the saved pair the face names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resume {
    /// The chain is equal: the range resumes from `held`.
    Equal,
    /// `history_reclaimed` and the `H.k` byte-equal (ITEM 1 (a), rider 1):
    /// the file is kept and the range resumes from the floor, its `held`
    /// re-fixed there; the state says the index is complete from that floor.
    FromTheFloor {
        /// The floor to resume from; `None` where the answer named none,
        /// and the shell resumes from the beginning.
        floor: Option<u64>,
    },
    /// `history_reclaimed` and the `H.k` different, gone or superseded: the
    /// history diverged below the floor; the file is moved aside as the
    /// evidence and the index built fresh, the loss stated.
    Diverged {
        /// The saved pair the face names.
        saved: ChainAt,
    },
    /// `beyond_head`: a journal cut or restored below `held`; faced, the file
    /// moved aside with its pair, the index built fresh.
    BeyondHead {
        /// The saved pair the face names.
        saved: ChainAt,
        /// The committed head the answer carried.
        head: u64,
    },
    /// A different chain at `held`: re-chained after the fact; faced, the
    /// file moved aside with its pair, the index built fresh.
    DifferentChain {
        /// The saved pair the face names.
        saved: ChainAt,
        /// The chain the board answered.
        found: Chain,
    },
    /// `history_busy`: retry-class, retried; never a rebuild.
    Busy,
}

impl Resume {
    /// THE JUDGMENT (§5.4): `held`, the range's saved pair; `head`, the
    /// file's newest `H.k` record, off the `Header`; `answer`, what the shell
    /// read. Pure: no board is read and no file is touched.
    pub fn judge(held: ChainAt, head: Option<&HeadRecord>, answer: &ChainAnswer) -> Resume {
        match *answer {
            ChainAnswer::Chain(found) if found == held.chain => Resume::Equal,
            ChainAnswer::Chain(found) => Resume::DifferentChain { saved: held, found },
            ChainAnswer::Reclaimed { floor, head: reread } => {
                // Rider 1: the saved `H.k`'s pair against its record as re-read,
                // byte-equal — position and chain alike.
                let stands = match (head, reread) {
                    (Some(saved), Some(now)) => saved.at == now,
                    _ => false,
                };
                if stands {
                    Resume::FromTheFloor { floor }
                } else {
                    Resume::Diverged { saved: held }
                }
            }
            ChainAnswer::BeyondHead { head } => Resume::BeyondHead { saved: held, head },
            ChainAnswer::Busy => Resume::Busy,
        }
    }
}

#[cfg(test)]
mod tests;
