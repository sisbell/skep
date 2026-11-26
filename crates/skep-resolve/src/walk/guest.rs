//! The guest-reading resolve answers a prefix with no mirror (REG-3.33).
//!
//! It scans every candidate binding, REG-3.24's word: every binding-typed
//! link in the binding home, by its class, each link read and each atom
//! fetched. The read is inside the design and outside the availability
//! claim, exactly as available as the root. It holds no positions, so no
//! record it reads can be judged as of one: every verdict it answers is
//! [`Verdict::UndeterminableHere`]. It is built to be priced
//! ([`GuestCost`]), never to be the hot-loop reader. A child of `walk`, it
//! renders its answer through the walk's own faces ([`face_of`]).
//!
//! **The binding home** (REG-2.5, REG-2.6, REG-2.8; R5 (g)) is read first,
//! off the board's one claim (AUTH-2.67, AUTH-2.68): the claimant's doc 1,
//! as the mirror takes it, on the unforked lineage the mirror reads — neither
//! reader builds a forked lineage's cut. Bindings are read from that home
//! alone: a binding-typed record any other account deposits in its own doc 1
//! is that account's content and no binding (REG-2.6), and is never read. A
//! board holding no claim binds no prefix, so every prefix is unregistered
//! there and no binding is scanned; a board serving two claims is refused,
//! since a board admits one.
//!
//! What it reads is folded into a [`Ledger`] — the rules alone — and never
//! into an [`Index`](crate::index::Index), whose one writer is the mirror's
//! gate. The binding home's candidate bindings are folded in that home's
//! link order, which is journal order within one home and so the folds' one
//! precondition. No verdict admits what this resolve answers from; the
//! binding home alone bounds it.

use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use skep_address::{document_of, Address};
use skep_identity::{doc_1_of, Enrolled};
use skep_registry::{commons_type, parse, t_binding, t_endpoint, Body, BodyKind};

use super::face_of;
use crate::board::{
    atom_of, content_extent, content_ordinal_in, retrieve_frame, runs_of, span_set_frame,
    v_ordinal_in, Board, BoardError, LinkSlots,
};
use crate::index::Ledger;
use crate::mirror::account_of_document;
use crate::origin::{NameResolver, Transports};
use crate::state::{BindingRecord, EndpointRecord, Judged, Resolution, Verdict};

/// What the guest-reading resolve cost (the investigation §3.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct GuestCost {
    /// Candidate bindings the scan listed in the binding home (REG-3.24).
    ///
    /// Each is a binding-typed link homed there (REG-2.5); a board with no
    /// claim has none.
    pub candidate_bindings_scanned: u64,
    /// Atoms read.
    pub atoms_read: u64,
    /// Wire reads made, every kind.
    pub reads: u64,
    /// Wall time.
    pub time: Duration,
}

/// Resolves `prefix` with no mirror, as a guest reader (REG-3.33).
///
/// The binding home is read first, off the board's one claim
/// (`binding_home`). Then every candidate binding in it (REG-3.24) — every
/// binding-typed link homed there, by its class (`window_ftt` over the
/// binding's type and that home, paged) — is read, its atom fetched at its
/// V-ordinal in the head and parsed, in the home's link order: journal order
/// within one home. Then the bound account's live key set is read, its
/// endpoint deposits by the same scan over its doc 1, and each honored
/// deposit's standing on the board's active view, as the board itself reads
/// it (REG-1.11).
///
/// The answer is the face and the cost. Every verdict beside a record is
/// [`Verdict::UndeterminableHere`]: no position is held to judge a record as
/// of. A board holding no claim answers every prefix
/// [`Resolution::Unregistered`], no binding scanned.
///
/// # Errors
///
/// A [`BoardError`] where the board refuses or cannot answer a read the
/// scan makes, and [`BoardError::Malformed`] where it serves what no board
/// admits: a class scan whose window does not advance, or two claims.
pub fn guest_resolve(
    board: &Board,
    prefix: &Address,
    names: &dyn NameResolver,
    transports: &Transports,
) -> Result<(Resolution, GuestCost), BoardError> {
    let t = Instant::now();
    let reads_before = board.reads().total();
    let mut cost = GuestCost::default();
    let finish = |cost: &mut GuestCost| {
        cost.reads = board.reads().total() - reads_before;
        cost.time = t.elapsed();
    };
    let Some(binding_home) = binding_home(board)? else {
        finish(&mut cost);
        return Ok((Resolution::Unregistered { prefix: prefix.clone() }, cost));
    };
    let mut ledger = Ledger::default();
    // Every candidate binding: every binding-typed link in the binding home,
    // by its class. A link the scan lists from another home is no candidate
    // (REG-2.6), and is neither counted nor read.
    let mut links = scan_class(board, t_binding(), Some(&binding_home))?;
    links.retain(|link| document_of(link).as_ref() == Some(&binding_home));
    cost.candidate_bindings_scanned = links.len() as u64;
    links.sort_unstable();
    for link in &links {
        let Some((home, atom, to)) = read_link(board, link, t_binding())? else { continue };
        let Some(text) = atom_at_head(board, &home, &atom)? else { continue };
        cost.atoms_read += 1;
        let Ok(record) = parse(BodyKind::Binding, text.as_bytes()) else { continue };
        let Body::Binding(b) = record.body else { continue };
        ledger.fold_binding(Judged {
            position: 0,
            link: link.clone(),
            home,
            record: BindingRecord::of(b, &to),
            verdict: Verdict::UndeterminableHere,
        });
    }
    let Some(standing) = ledger.standing(prefix) else {
        finish(&mut cost);
        return Ok((Resolution::Unregistered { prefix: prefix.clone() }, cost));
    };
    let Some(account) = standing.current.record.account.clone() else {
        finish(&mut cost);
        return Ok((Resolution::RetiredWithHistory { standing, successor: None }, cost));
    };
    // The account's live key set and its endpoint deposits.
    let keys = live_keys(board, &account)?;
    let home = doc_1_of(&account);
    let mut deposits = scan_class(board, t_endpoint(), Some(&home))?;
    deposits.sort_unstable();
    for link in &deposits {
        let Some((deposit_home, atom, _)) = read_link(board, link, t_endpoint())? else { continue };
        if deposit_home != home {
            continue;
        }
        let Some(text) = atom_at_head(board, &deposit_home, &atom)? else { continue };
        cost.atoms_read += 1;
        let Ok(record) = parse(BodyKind::Endpoint, text.as_bytes()) else { continue };
        let Body::Endpoint(e) = record.body else { continue };
        let honored = ledger.fold_endpoint(Judged {
            position: 0,
            link: link.clone(),
            home: deposit_home,
            record: EndpointRecord::of(e),
            verdict: Verdict::UndeterminableHere,
        });
        if honored && !board.stands_active(link, &home, t_endpoint(), &atom)? {
            ledger.nullify(link);
        }
    }
    let endpoint = ledger.current_endpoint(&home).cloned();
    let any_honored = ledger.any_honored_endpoint(&home);
    finish(&mut cost);
    Ok((face_of(standing, keys, endpoint, any_honored, names, transports), cost))
}

/// Returns the binding home: the doc 1 of the board's one claimant (REG-2.5).
///
/// Every link the claim's class scan lists is read as far as the claim's
/// type ([`Board::link_slots`]) and kept where it is claim-shaped
/// ([`claim_home`]); on the unforked lineage the claimant's doc 1 is the
/// binding home (R5 (g)). The answer is `None` where the board holds no
/// claim, so no prefix is bound there.
///
/// # Errors
///
/// A [`BoardError`] where the board refuses or cannot answer the scan or a
/// link's read, and [`BoardError::Malformed`] where two claim-shaped links
/// stand: a board admits one claim (AUTH-2.67, AUTH-2.68), and this reader
/// holds no positions to tell which came first.
fn binding_home(board: &Board) -> Result<Option<Address>, BoardError> {
    let claim = commons_type(&[3]);
    let mut links = scan_class(board, &claim, None)?;
    links.sort_unstable();
    links.dedup();
    let mut found: Option<(Address, Address)> = None;
    for link in links {
        let Some(slots) = board.link_slots(&link, &[&claim])? else { continue };
        let Some(home) = claim_home(&link, &slots) else { continue };
        if let Some((first, _)) = &found {
            return Err(BoardError::Malformed(format!("two claims, {first} and {link}: a board admits one")));
        }
        found = Some((link, home));
    }
    Ok(found.map(|(_, home)| home))
}

/// Returns the doc 1 the claim-shaped link at `link` stands in.
///
/// The shape is the claim's (AUTH-2.48), the claim arm's first two
/// conditions (AUTH-2.67): its type the claim's, its `to` empty, its `from`
/// exactly the account its home belongs to, and that home the account's
/// doc 1 (the home pin, AUTH-2.127). A link of any other shape honors no
/// claim, and answers `None`.
fn claim_home(link: &Address, slots: &LinkSlots) -> Option<Address> {
    slots.ty.as_ref()?;
    let home = document_of(link)?;
    let account = account_of_document(&home)?;
    let shaped = slots.to.is_empty() && slots.from == [account.clone()] && home == doc_1_of(&account);
    shaped.then_some(home)
}

/// The addresses a class scan's window asks for — and so exactly how many an
/// unexhausted window holds.
const WINDOW: NonZeroUsize = NonZeroUsize::new(256).expect("a window asks for one address or more");

/// Every link of type `ty` on the board — homed in `home` where given — by
/// the class scan's windows ([`Board::class_window`]) paged from no cursor to
/// the last; refused where a window is ([`BoardError::Malformed`]).
fn scan_class(board: &Board, ty: &Address, home: Option<&Address>) -> Result<Vec<Address>, BoardError> {
    let mut out = Vec::new();
    let mut cur: Option<Address> = None;
    loop {
        let window = board.class_window(ty, home, cur.as_ref(), WINDOW)?;
        cur = window.batch.last().cloned();
        out.extend(window.batch);
        if window.exhausted {
            return Ok(out);
        }
    }
}

/// A stored link of type `ty` — its home, from the link's own address, its
/// `from` atom and its `to`; `None` where no link stands there, or one of
/// another type ([`Board::link_slots`]).
fn read_link(board: &Board, link: &Address, ty: &Address) -> Result<Option<(Address, Address, Vec<Address>)>, BoardError> {
    let Some(slots) = board.link_slots(link, &[ty])? else { return Ok(None) };
    if slots.ty.is_none() {
        return Ok(None);
    }
    let Some(home) = document_of(link) else { return Ok(None) };
    let Some(atom) = slots.from.first().cloned() else { return Ok(None) };
    Ok(Some((home, atom, slots.to)))
}

/// An atom at the head of its home: the append-only guess, else the head's
/// whole image — an image whose runs do not all read locating nothing.
fn atom_at_head(board: &Board, home: &Address, addr: &Address) -> Result<Option<String>, BoardError> {
    let retrieve = |ordinal: u64| -> Result<Option<String>, BoardError> {
        Ok(atom_of(&board.op(&retrieve_frame(home, ordinal))?))
    };
    let image = |from: u64, width: u64| -> Result<Vec<(Address, u64)>, BoardError> {
        Ok(runs_of(&board.image(home, from, width, None)?).unwrap_or_default())
    };
    if let Some(n) = content_ordinal_in(home, addr) {
        let runs = image(n, 1)?;
        if runs.len() == 1 && runs[0].0 == *addr {
            return retrieve(n);
        }
    }
    let extent = content_extent(&board.op(&span_set_frame(home))?).unwrap_or(0);
    if extent == 0 {
        return Ok(None);
    }
    match v_ordinal_in(&image(1, extent)?, addr) {
        Some(ordinal) => retrieve(ordinal),
        None => Ok(None),
    }
}

/// The account's live key set ([`Board::key_set`]); `None` where the answer
/// is no key set — this reader could not read it.
fn live_keys(board: &Board, account: &Address) -> Result<Option<Vec<Enrolled>>, BoardError> {
    Ok(board.key_set(account)?.map(|answer| answer.enrolled))
}

#[cfg(test)]
mod tests;
