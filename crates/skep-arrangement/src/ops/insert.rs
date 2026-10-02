//! INSERT (ASN-0116; §3): fresh content placed in one composite — its mints,
//! its writes, its placement and its provenance — and the one insert a
//! published document admits, a declared deposit at a fresh position.

use skep_address::Address;
use skep_content::{ContentWrite, HasContent, Val};
use skep_kernel::{Seq, TxnError, WorldState};
use skep_namespace::{HasM3, M3Rec, M3State};

use super::{allocate_for_placement, head_lock_key, Vstream};
use crate::chain::{deposit_surface, published_target};
use crate::deposit::{deposit_class_types, Deposit};
use crate::error::InsertError;
use crate::ownership::{gate_write, Caller};
use crate::run::Run;
use crate::state::M5Rec;
use crate::vspace::VPos;
use crate::HasM5;

impl<W> Vstream<'_, W>
where
    W: WorldState + HasM5 + HasM3 + HasContent, // reads M3 (registration, mints) + M4 (writes) + M5
    W::Record: From<M5Rec> + From<M3Rec> + From<ContentWrite>, // stages M3Rec + ContentWrite + M5Rec
{
    /// INSERT (ASN-0116; §3): mint n fresh content addresses (M3), write
    /// their bytes (M4), splice the run at `at` (content subspace), record
    /// provenance — one M2 composite under
    /// `M3State::content_lock_key(doc)` and, for a declared deposit, the
    /// chain's head key (`head_lock_key`: the trunk's `version_lock_key`).
    /// Returns the inserted run's START address (the predicate-def identity
    /// for M9) and the commit `Seq`.
    ///
    /// Check order (which error wins): `DocNotRegistered` → `NotOwner` (the
    /// in-txn ω gate) → `PublishedTarget` (below) → `EmptyContent` →
    /// `NotContentSubspace` (`at.subspace ≠ s_C`) → `OutOfBounds` (the
    /// arrangement does not admit `at.ordinal` as a placement boundary —
    /// Valid(First)InsertionPosition, so ordinal = 1 when n_C = 0). Then,
    /// PER VALUE in the order given, `Mint` (the content mint) → `Content`
    /// (the byte write), with the FIRST value to fail deciding.
    ///
    /// Neither per-value verdict is one an honest request can earn on a
    /// correct store: `Mint(MintError::HomeNotRegistered)` cannot arrive past
    /// the gate above and is M3's own boundary discharge;
    /// `Mint(MintError::Gate)` is M3's defence against a corrupted frontier,
    /// which M3 states never fires on a live path; and
    /// `Content(AlreadyPresent)` cannot occur in production at all — M3 mints
    /// fresh and M5 writes once, which is the argument `stage_write` itself
    /// makes for keeping the guard. All three are defensive, as the shot's and
    /// VERSION's mints are.
    ///
    /// THE PUBLISHED TARGET, and the deposit that clears it (PUB-2.11,
    /// PUB-2.59, PUB-2.61; PUB-9.13's DECLARED horn, owner-ruled). When the
    /// document `doc` projects to (PUB-2.15) is PUBLISHED, an insert is an
    /// in-place edit (PUB-2.11's in-place advance) and refuses
    /// `PublishedTarget` — UNLESS `deposit` is [`Deposit::Declared`], the
    /// TYPE it carries is a member of [`deposit_class_types`], AND the
    /// insert is deposit-SHAPED: `at` names a fresh content position past the
    /// arranged extent, so the placement appends and disturbs no arrangement.
    /// The declaration exempts nothing by itself — the deposit class must
    /// hold its type and the shape must bear it out — and is never a bypass:
    /// a declaration naming a type the deposit class does not hold (the
    /// grant's, the edition claim's, any other address) refuses with the same
    /// code wherever it lands (PUB-2.11; RES-249, RES-261), a declared insert
    /// at an arranged position refuses with it too, and an UNDECLARED append
    /// refuses as well (the cost RES-209 item 5 named, closed). THE TEST IS A
    /// MEMBERSHIP COMPARE against a build-time set: it reads nothing, and
    /// what the bytes ARE it cannot tell — prose declared under a held type
    /// is admitted, a malformed record atom of the class it names, which is
    /// PUB-2.60's accepted residue. Into a PRIVATE document the declaration
    /// is inert, whatever it names — every insert is admitted there as
    /// before. A declared deposit whose fresh position lies past the append
    /// boundary clears this refusal and meets `OutOfBounds` below, so it is
    /// told its position is bad rather than that its target is published.
    /// `Caller::System` is NOT exempt (PUB-6.28): a rule fire never advances
    /// a published arrangement in place.
    ///
    /// So a published document admits exactly ONE insert: a deposit declared
    /// under a held type, at `[s_C, n_C + 1]` of the arrangement it lands
    /// in — the one position both fresh and inside the append boundary. A
    /// caller builds that position by asking [`deposit_surface`] for the
    /// arrangement and [`content_count`](crate::M5State::content_count) of it
    /// for `n_C`. A position read before another deposit landed there is no
    /// longer fresh, and the deposit carrying it is refused `PublishedTarget`
    /// like any in-place edit — the remedy being a fresh position, not the
    /// draft the refusal's face proposes.
    ///
    /// AN ACCOUNT'S HOME IS SUCH A TARGET. The flagless first mint into an
    /// empty account is born published — M3's own create path resolves that
    /// bit (PUB-8.21), not a flag the caller sent — so content enters doc 1
    /// only by a DECLARED deposit at a fresh position: the record atoms that
    /// accrete there outside the version discipline (PUB-2.4, PUB-2.60), its
    /// prose advancing by shots like any edition's (PUB-2.58). A client or
    /// fixture that mints a home and then inserts into it undeclared meets
    /// this refusal, and that is the rule working; the account's LATER
    /// flagless mints are private by default (PUB-1.1) and take an ordinary
    /// insert.
    ///
    /// WHICH ARRANGEMENT THE DEPOSIT LANDS IN (PUB-2.65, PUB-2.66; lane 3.2's
    /// ruling): the HEAD member's, ALONE — the version-chain reads' own answer
    /// ([`deposit_surface`]), which is the trunk head once the chain has one
    /// ([`trunk_head`](crate::trunk_head)), whichever address of the chain
    /// the caller named: the bare document, the head itself, or a pinned
    /// member, which never grows. It differs from the
    /// [`reading_surface`](crate::reading_surface) at exactly that pinned
    /// member, whose readers answer the member itself. `at` is therefore
    /// judged fresh against the HEAD's extent, and the placement record names
    /// the head.
    /// While the document has no member the deposit lands in its own
    /// arrangement, which is what its readers answer from until a head exists
    /// (PUB-2.66's memberless reading). The atom's IDENTITY is minted under
    /// the CONTENT CHAIN of the address the caller NAMED (`mint_content(doc)`)
    /// — the document's own for a bare address, a member's own for a member
    /// (PUB-2.52) — so the start returned lies under the named address's
    /// content chain whichever arrangement the deposit lands in; only the
    /// placement floats.
    ///
    /// COST, AND WHO OWNS IT. This op admits any `values` length: there is no
    /// analogue of COPY's [`MAX_PLACED_RUNS`](crate::MAX_PLACED_RUNS) here,
    /// and none is owed, because the size of an INSERT is the size of the
    /// request that carries it rather than a source document's fragmentation
    /// multiplied by a spec count. What `n` values cost is `2n + 1` staged
    /// records — a mint and a content write apiece, plus one placement — and
    /// `n` content addresses that are allocated permanently, M5 having no
    /// reclamation path. M2's `MAX_TXN_BYTES` refuses the transaction past its
    /// own ceiling, but it refuses AFTER the mints and writes are staged, so
    /// a caller that wants the refusal to arrive before that work owes its own
    /// cap: M10's codec sets one on the wire route (`MAX_INSERT_VALUES`), and
    /// a route that carries this op without one owes the number.
    ///
    /// J0/J1★ by construction: mint + write + place + provenance ride one
    /// transaction, each value through `allocate_for_placement` — J0's one
    /// step, shared with the shot's re-insert, whose own doc states why the
    /// placement it accumulates is never widened over addresses nobody
    /// allocated. INSERT's values are minted one after another under the held
    /// content key, so they are I-adjacent and INSERT places exactly ONE run,
    /// whose start is the first address minted.
    pub fn insert(
        &self,
        caller: Caller,
        doc: &Address,
        at: VPos,
        values: Vec<Val>,
        deposit: Deposit,
    ) -> Result<(Address, Seq), TxnError<InsertError>> {
        // The content chain's key, and — for a declared deposit, which reads
        // the version chain's frontier to find where it lands — the head's
        // (`head_lock_key`), so the landing decided inside cannot move under
        // it. Both are arithmetic on the request.
        let mut keys = vec![M3State::content_lock_key(doc)];
        let declared_type = match &deposit {
            Deposit::Undeclared => None,
            Deposit::Declared(ty) => {
                keys.push(head_lock_key(doc));
                Some(ty)
            }
        };
        // The attested arm (signed ops): `transact` itself where this handle
        // carries no attestation, else the same commit with its marker's
        // signature slot filled.
        self.kernel.transact_attested(&keys, self.attest, |stg| {
            gate_write(
                stg.working().m3(),
                caller,
                doc,
                InsertError::DocNotRegistered,
                InsertError::NotOwner,
            )?;
            // PUB-6.36 slot 5: on a registered, owned target, the
            // published-target refusal — cleared only by a deposit DECLARED
            // under a type the deposit class holds (PUB-2.11, RES-249/261) at
            // a FRESH position (PUB-2.59, PUB-9.13) of the arrangement the
            // deposit lands in: the HEAD member's, or the document's own
            // while it has none (PUB-2.66). Which arrangement the insert
            // lands in is decided with the refusal, one case at a time.
            let surface = {
                let world = stg.working();
                let m3 = world.m3();
                if !published_target(m3, doc) {
                    // Private: the declaration is inert, whatever it names,
                    // and the insert edits the arrangement named.
                    doc.clone()
                } else if let Some(ty) = declared_type {
                    // The CLASS TEST: a membership compare against M5's own
                    // build-time set, reading nothing. A declaration naming
                    // any other type answers as an undeclared append does.
                    if !deposit_class_types().contains(ty) {
                        return Err(InsertError::PublishedTarget);
                    }
                    // The chain's frontier, read under the head key pushed
                    // above — the one insert a published document admits.
                    let surface = deposit_surface(m3, doc);
                    if !world.m5().names_fresh_content_position(&surface, &at) {
                        return Err(InsertError::PublishedTarget);
                    }
                    surface
                } else {
                    return Err(InsertError::PublishedTarget);
                }
            };
            if values.is_empty() {
                return Err(InsertError::EmptyContent);
            }
            if !at.is_content() {
                return Err(InsertError::NotContentSubspace);
            }
            if !stg.working().m5().admits_content_boundary(&surface, &at.ordinal) {
                return Err(InsertError::OutOfBounds);
            }
            let mut runs: Vec<Run> = Vec::new();
            for value in values {
                allocate_for_placement::<_, InsertError>(stg, doc, value, &mut runs)?;
            }
            // The placement's start is the FIRST address minted: the
            // accumulator only ever widens a run rightwards or opens a new
            // one after it, so the first run's start is the first mint.
            let start = runs
                .first()
                .expect("EmptyContent guard ⇒ at least one value ⇒ at least one run")
                .i_start()
                .clone();
            stg.push(
                M5Rec::ContentPlace {
                    doc: surface,
                    at: at.ordinal,
                    runs,
                }
                .into(),
            );
            Ok(start)
        })
    }
}
