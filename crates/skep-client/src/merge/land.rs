//! The merge's landing — the merge record's §1.5.
//!
//! The landing is the one `publish` of the merged list from the head with
//! its signed body, the supersession claims riding it, then the claims'
//! read and the record in the journal with its link beside it, each step
//! idempotent by reading first (P4, P14); the draft landing, ONE
//! `set_arrangement` of the merged list into the draft (the landing lane's
//! rulings R1, R4, R5; skep #764); [`resume`], the residue walk that
//! completes what a lost acknowledgment left, writing nothing twice;
//! [`record_published`], the record of a landing the merger's own
//! publication made, written once and never a second shot; and
//! [`replaced`], the stretches of a draft a landing there replaces, read
//! before it.
//!
//! **The order, and what each step reads first.** The cap: `counts.m`
//! against the shot's run cap before any frame (decision 13; P13). The
//! shot's window parts ([`Answers`]; the `windows` module's doc): every
//! window of M answered through the publication family's one core before
//! anything is read first, the answered list checked against the cap
//! again, and a part with no answer, or an answer that fits nothing,
//! refused with nothing sent ([`Refusal::WindowPartsOwed`]). The twins: a
//! draft side's words a record names as published, read after the answers
//! and sent by reference (the twin fence, below). A journal named: checked
//! after the read-first steps, before the first write. The shot: the
//! trunk's next member, then the head's daughters, read for a member whose
//! first `placed` positions already hold the answered list —
//! else one `publish` from the head, its body every copied run's bytes
//! re-read through the side that holds them and every window signed by
//! address, the records read again just before the send so a part a record
//! names since its answer was given is refused again, nothing published
//! (PUB-3.108), and re-asked once under the same per-session `id` where the
//! acknowledgment was lost. A shot left naming no daughter — none composed,
//! or each one an active claim of the merger's own already names — whose
//! answered list the head, as the composition imaged it, holds whole is
//! refused [`Refusal::HeadHolds`] before its values are read, nothing sent:
//! it would mint a version identical to the head for good, as a merge
//! composed again on the head its own lost-acknowledged shot minted would.
//! The frame and
//! its body go through the publication composition's request builder
//! (`crate::publication::Request`) with one deposit list — `supersede`, the
//! daughters (the claim, below) — and no `links`, `retract` or `read_with`
//! entry, the document form — the merge's delta from a publication (the
//! link-sets design §5.5: "the walk's base the `base` it holds"), so a shot
//! naming no daughter signs today's body byte for byte through the one body
//! builder. Beside the runs and outside the body (wire.md §Arrangement,
//! `publish`), a shot that renders a draft side carries the draft's own
//! place of each of its words the shot re-mints or sends by reference and
//! of each part answered by its counterpart that the draft arranges, the
//! list cut where the draft cuts it ([`windows::kept_places`]; the link-sets
//! design §5.7 (viii)), so the one commit re-windows the draft onto the
//! published words. The draft
//! keeps only the words it held — those M holds beyond it stay out of it —
//! and the base it stood on: the shot sets `keep_base` wherever it names a
//! draft (skep #944), so the draft's recorded base and marker stand, the
//! draft stands behind the member, and a later merge from it composes
//! against its own base. A part answered by its counterpart is the
//! published words by reference — signed by value where they lie in the
//! document's own chain,
//! read through the window's own span, and by address elsewhere — a part
//! kept private is a window with no place, a part left out sent nowhere. A
//! daughter in the acknowledgment is reported at once
//! ([`Landed::AsDaughter`]): the head moved under a shot
//! naming no daughter, the library never re-runs, the embedder does with
//! `retries` one higher (decision 17). The record: the merger's current
//! record for the key, read by the landing itself as the composition reads
//! the prior records (the merge record's §1.5 (ii), §1.3's step 7) — the
//! links of the kind to each side of the key, kept to the merger's own
//! account, the newest by the order they were minted — standing where it
//! names this landing's member or draft, whatever position it names; else
//! the journal found or minted, the atom appended at its end, and the link
//! homed in the journal beside it, from the atom to the member and every
//! side besides the head under the kind, the record naming that newest
//! record in `replaces` (P20: a later record names the one it replaces).
//! The journal is a private draft, so the record and its link are private
//! writes, signed by no `attest`. A newer record of the key — an undo's, a
//! withdrawal's, a landing of it elsewhere — replaces this landing's, so a
//! landing after it writes its own. A merge composed again and landed in
//! the draft the newest record names, no take-back recorded between, is the
//! same landing (skep #790): its write lands under its own ids and no record
//! is written, the record keeping the first landing's position
//! (`Newest::naming`). A merge composed again over a fork or a draft side
//! whose text changed since is another key, the side's state a term of it
//! (`RecordKey`; skep #770), so its landing into the same draft writes a
//! record of its own, replacing none; a member that any record of the
//! merger's own of the merge names, its states ignored — a merge composed
//! again after its own shot re-windowed its draft side, which moves the
//! draft's state, or the same composition landed in a draft since — is that
//! record's landing, nothing written (`Newest::recording`). The
//! composition's `Merged::prior` is what the composition saw, under the
//! reader's currency, and never the landing's answer: a composition kept
//! across a take-back, or one made before its own landing, lands by the
//! board as it stands.
//!
//! **The twin fence, before and at the shot** (PUB-3.9; wire.md §The
//! publish shot and head-float). A draft side's word a correspondence
//! record names as published is sent by reference to the published words,
//! with the draft's place beside it, never as new words: [`windows::step`]
//! reads the records over M's draft-native runs and composes the list by
//! them (the `windows` module's doc, the twins), so a board's
//! `already_published` can only come of a publication of those words
//! landing between that read and the send, nothing committed. The records
//! are then read again and the list composed afresh
//! ([`windows::retwin`]): a member found holding it is this landing; else
//! the shot goes once more, signed again, under its own id. A second
//! `already_published` is [`Refusal::AlreadyPublished`], naming the draft
//! and the member the board names. Where the publication that landed moved
//! the draft onto the published words, the one re-send is refused
//! `kept_place_moved`, said as any change to the draft since the
//! composition.
//!
//! **The head, before the shot.** The shot is the landing's one public
//! write, and the one signed: it is preceded by the board's head
//! (`Board::board_head`; SP-14), `H.1`'s pair, which its `attest` signs
//! over, or none on a board no one has claimed, which takes it without one.
//! A claimed board serving no head record halts the shot with nothing sent,
//! the merge not landed. The head is read after the read-first steps and
//! the check of a journal named, so a [`resume`] that finds nothing landed
//! answers with no head read. The board's own
//! `attestation_invalid:board_unavailable` at the shot — a head owed past
//! that read — is faced the same, never as this library's fault. A shot sent
//! unsigned to a board read as no one's and refused `attestation_required`
//! met a claim that landed past that read, its head written, and was refused
//! before its transaction (wire.md §Credential refusals, a reorder): the head
//! is read again and the shot sent ONCE more, signed over that pair, under
//! its own id, its answer a signed frame's. A second read that finds no head
//! to sign over is faced as the head the board owes, nothing sent; a signed
//! shot refused `attestation_required` is this library's own fault. The
//! draft landing's stage and one write, and every write of the record, go
//! to private drafts, which take no `attest`, and read no head.
//!
//! **The journal, before the first write and at the record.** A merge
//! record is kept only in a private document: its atom is appended to its
//! journal as a plain insert, which a published document refuses, so a
//! journal takes a record only as a draft the merger's account owns,
//! readable and registered at this board (the merge record's decision 7),
//! and no record goes into a published document. A journal the caller names
//! is checked before the landing's first write — one `doc_metadata` at the
//! head, after the read-first steps and, at the shot, before the head's
//! read — and one this merger may not read (`withheld`), one this board
//! does not register or another account's is refused there as a halt
//! naming the journal and the check it fails, a published one of the
//! merger's own as [`Refusal::PublishedJournal`], with nothing sent (P13);
//! [`journal::check`] is that check alone, for a caller that says it before
//! it lands. A landing found standing makes no write before its record, and
//! no journal is checked there. At the record the journal's extent is read,
//! the end the atom is appended at: a journal that read answers `withheld`
//! or `doc_not_registered`, or a journal named whose atom the board refuses
//! `published_target` or `not_owner`, halts the record with nothing of it
//! written, faced as the landing standing with its record unwritten — never
//! as a refusal of the landing — for [`resume`] to record into a journal the
//! merger can write, or into the account's own. The account's own journal,
//! found or minted at the record, is this library's choice — a private
//! draft of the account's, read before it is taken (`journal`'s doc) — so
//! the board's refusal of its atom is this library's own fault. Its find is
//! a class scan, reissued while the board is busy; refused busy past the
//! bound, it leaves the landing standing with its record unwritten, as a
//! journal that cannot take the record does.
//!
//! **The draft landing is one write.** M is sent whole as one
//! `set_arrangement` of the draft (wire.md §Arrangement), TYPED against the
//! one position the merge was composed at — `Merged::as_of`, P, where every
//! side the composition fenced held the state it read (skep #762) — so an
//! edit made to the draft after the merge was composed is refused
//! `arrangement_moved` with nothing changed, and the draft holds M or what
//! it held, never a state between. The refusal is said off the draft as it stands, read
//! after it: where the change is this merge's own landing, made after the
//! composition — a composition landed again in a session holding no memo
//! of its write, the landing found by the draft's marker or, on a draft
//! with no recorded base, which carries none, as the landing standing by
//! its `set_arrangement` rows on the supplement (wire.md §The change feed;
//! **Finding a landing**, below) — it names that landing and its record,
//! written or not, with [`resume`] the way on where that landing placed M,
//! the draft read as of its position; else it names the draft that changed
//! and that nothing was merged. The frame
//! carries the head the merge composed on with its extent AS READ (`head`),
//! the same pair as the base to record where the board records a base for
//! the draft — read off the draft's `doc_metadata` as it stands, a recorded
//! base never cleared; a baseless draft and a fork get none, so the library
//! never sends a `base` the board refuses `no_base_to_record` (N4) — and the
//! merge the draft is to carry (`merge`, every side but the draft itself).
//! The board re-records the base on the head and sets the marker in the
//! same commit (R4); a newer version published since the
//! compose is not refused: the write lands against the head it composed on
//! and the ack names the trunk's current head as `head_moved`, which the
//! landing carries out (R5, "land and tell"). The write is sent where the
//! draft already holds M too, so the base and the marker are recorded. With
//! no draft named ([`Landing::Draft`]'s `into` none), a fresh draft is
//! staged from the head first — `stage {from: the head}`, two commits, the
//! state between a plain staged draft (R3) — and the write is typed against
//! the stage's own position; where a draft the merger's records of the key
//! name, read before the stage, still holds this composition's landing,
//! that landing is reported and nothing is staged (**A fresh landing found
//! standing**, below), so [`Landed::Draft`]'s `staged` is true only where
//! the call sent the stage. Every document M windows is read before the
//! stage ([`Writer::windows_readable`]), one the merger may not read
//! refused [`Refusal::WindowWithheld`] with nothing staged, so the one
//! write's source gate never leaves a staged draft standing empty. Where
//! none stands, a landing of the merge begun in a draft of the merger's and
//! never recorded — the one write landed, the record cut off — is found
//! before the stage, the mint a landing cut off would make twice (PUB-8.32,
//! resume-by-read): the rows of the merger's account's own drafts on the
//! supplement past the head's mint — the walk `under` `⟨account⟩.0`, so no
//! sub-account's row is served — each draft but the merge's own sides whose
//! `set_arrangement` row names the head and the sides, and that no record
//! of the merger's own of the merge stands for, read for the board's mark
//! ([`Writer::landing_begun`]). One the board still marks is refused
//! [`Refusal::LandingBegun`], at a landing and a resume alike, nothing
//! staged or written: the merge never lands twice, and the landing begun is
//! never finished unasked. A draft only staged, its one write never sent,
//! carries no row naming the merge and stands beside the next stage.
//! The record follows, its draft landing's position
//! the write's `at`. [`resume`] finds a landing in a draft named by that same
//! mark, at the position it marks, where the draft as of that position held
//! M — whatever was edited in it since, a landing standing until it is
//! taken back — never by the draft's words, which a withdrawal keeps: a
//! landing withdrawn or undone, its mark cleared, leaves nothing to resume
//! (R2), and a mark of the merge's head and sides whose landing placed
//! another list is another composition's. Nor is a landing found
//! by a marker the draft inherited when it was staged from a marked draft:
//! the stage copies the marker with the words, stamped at its own commit,
//! the draft's mint (P2), so a marker whose `at` is the draft's own `at` in
//! its `doc_metadata` marks no landing in it. A landing so found is
//! answered by the record of the key standing for it in that draft — the
//! draft's newest record of the key no take-back's record replaces, at or
//! before the mark's position (`Newest::standing_in`) — whatever the newest
//! record of the key names, a landing of the key in another draft since
//! included, and is recorded only where none stands. Where the list it
//! placed cannot be read back, the board having reclaimed the mark's
//! position since the draft was edited, it is answered where such a record
//! stands, and recorded never where none does.
//!
//! **Finding a landing** (skep #914). On every draft a landing stands from
//! its write until it is taken back, and when it is taken back the landing
//! it went over stands again; a restore or any other re-arrangement
//! neither ends one nor brings one back. A draft with a recorded base shows
//! it by its marker. A draft with none carries no marker, and the landing
//! standing is read off its `set_arrangement` rows on the supplement (the
//! `landings` module's doc): a row naming the merge is a landing, and a
//! later row naming none that leaves the draft exactly as it stood before
//! the standing landing — the two states read through `/op-at` and mapped
//! through one read of the records over both, as the undo maps what it
//! sends — is that landing's take-back, for good. With no plain row after
//! the newest landing nothing is read at a past position. Where a past
//! state the walk needs is one the board has reclaimed, no landing is
//! found standing, so nothing is reported or recorded on a landing that
//! cannot be judged, and `history_busy` past the bounded retries is
//! refused as itself ([`Refusal::HistoryBusy`]; SP-14). The list a
//! landing found placed is read as of its mark, and where the board has
//! reclaimed that position the draft as it stands holding M whole answers
//! for it; holding anything else, it tells nothing of that list, which the
//! draft's edits since may have changed, and the landing is one that
//! cannot be judged, never one that placed another list.
//!
//! **A fresh landing found standing** is answered where its draft marks
//! it. The drafts are every one the merger's own records of the key name
//! as landed in — for each, the newest such record no take-back's record
//! replaces — taken newest first, so a newer record, a landing of the key
//! elsewhere or a take-back of it, hides no landing standing in a draft an
//! older record names. Each is read as it stands, its `doc_metadata` and,
//! with no recorded base, its rows and the past states their walk needs,
//! and the position answered is that same mark's. The record names the
//! write that first landed the key in the draft, and a later landing of the
//! key there, the same landing (skep #790), moves the mark past it; a mark
//! below the record's position is an earlier merge's standing again — its
//! marker put back, or with no recorded base its landing beneath one taken
//! back. So where the draft marks none of this merge, or only such a one,
//! no landing of it stands there — taken back, whether or not the
//! take-back's record was written, the board's mark the fact and the record
//! its testimony. The key holds no choice, so the draft is read as of the
//! mark too, and a landing that placed another list than M is another
//! composition's of the key, never this one's: a merge composed with other
//! choices lands a draft of its own, never told its choices landed where
//! they did not. Where no draft holds this composition's landing, the
//! landing goes on to the stage, its record replacing the newest. A landing
//! that cannot be judged is never made twice: where a draft's mark cannot
//! be read, the walk of its rows needing a past state the board has
//! reclaimed, the position its record names is answered, and where the
//! list its mark's landing placed cannot be read back, the mark's.
//!
//! **The per-session ids.** Every write of a landing carries the id
//! `<stem>.<frame>`, its stem `merge:` and the SHA-256, in lowercase hex,
//! of the text naming the write — 70 bytes whatever the text, so a merge of
//! any number of sides lands under ids inside the 256-byte id cap skepd
//! holds at parse. An id is unique within its session: the board answers a
//! frame under an id it has acknowledged with that acknowledgment, never
//! judging the frame (wire.md §Correlation and idempotency), so the text
//! names all that makes a write another, and every write — the stage, the
//! one write into a draft, the shot, the journal's mint, the record's atom
//! and its link — is asked again once under its id where the transport lost
//! its answer (`send_write`), a lost acknowledgment within the session
//! answered by the board's memo and nothing applied twice. `<key>` is the key's text
//! (`RecordKey::text`). The shot's text is `<key>`, and `~` and the answers
//! it was given where any window part was answered, for `<stem>.publish`,
//! then the record's `<stem>.record` and `<stem>.link`; the draft
//! landing's names the key, the draft and the position the write is typed
//! against, `<key>:<draft>@<at>`, for `<stem>.draft`, `<stem>.record` and
//! `<stem>.link` — for a draft named, `<key>:<draft>@<at>~<link>` where the
//! landing follows a record (`Newest::follows`): `<link>` the merger's
//! newest record of the key, or the one that record replaces where it names
//! the draft as landed in, so a retry after the landing's own record is
//! written spells its first call's text; the stage's names the key and P,
//! the composition's position, `<key>@<P>`, or `<key>@<P>~<link>` where a
//! record of the merger's of the key stands, `<link>` the newest one's,
//! which the landing's record will replace, for `<stem>.stage`. The board
//! answers a second call over one composition from its ids — but a fresh
//! landing's past its one write, which finds that landing begun before it
//! stages — and a landing
//! composed after a take-back, landed into another draft, landed into its
//! draft again after a take-back recorded since, or landed fresh again
//! after its own landing was taken back, is a write of its own, which the
//! board judges: one typed against a position its draft has changed since
//! is refused `arrangement_moved`, nothing written. The one signed send of
//! a shot after a claim keeps its frame's id: the board never memoizes a
//! refusal, so it judges that id afresh (wire.md §Correlation and
//! idempotency), and only that id lets a second call over the composition
//! meet the write it made, never make another.
//!
//! **The claim rides the shot** (the merge record's §1.5 (i); the merge
//! bridge lane). The shot's `supersede` names every `Member` side — the
//! daughters the member takes in, in side order — and never a draft side or
//! a fork side: no public claim supersedes a private draft or another
//! account's fork. The board deposits one supersession claim per daughter in
//! the same commit, homed in the trunk, `old` the daughter and `new` the
//! member it mints, signed in the body as the publication composes it
//! (wire.md §The publish shot and head-float, the deposits). THE SKIP IS
//! READ BEFORE SIGNING: `in_claims{y: the daughter, view: active}` at each,
//! a daughter an active claim of the merger's own already names dropped from
//! the list and the body, as the board's plan drops it, so the body signed
//! is the body the board composes. A shot naming a daughter lands on the
//! trunk or not at all: where the head moved under the merge the board
//! refuses it whole, `supersede_refused` with `detail` `head_moved`, nothing
//! committed, answered as [`Refusal::SupersedeRefused`] naming the trunk's
//! head for the merge to be composed again on. After the shot the claims
//! are read back at the daughters ([`Writer::claims_standing`]) and written
//! into the record; a merger that loses the acknowledgment finds them with
//! the member ([`resume`]), since a landed shot carried them.
//!
//! [`Answers`]: super::Answers
//! [`windows::kept_places`]: super::windows::kept_places
//! [`windows::step`]: super::windows::step
//! [`windows::retwin`]: super::windows::retwin
//! [`journal::check`]: super::journal::check

use skep_address::Address;

use crate::board::{Board, Token};

use super::compose::Run;
use super::reads::{fence, runs_of, version_components, Merged, OnEnd, Reader, Refusal};
use super::record::{PartAnswer, RecordLanding};

use standing::walk;

mod draft;
mod faults;
mod landing;
mod records;
mod shot;
mod standing;
mod writer;

pub use landing::{Landed, Landing, Merger};
pub(crate) use faults::{own_fault_face, shape_face};
pub(super) use faults::{own_fault, Unwritten};
pub(super) use records::Unrecorded;
pub(super) use writer::{send_write, Asked, Stem, Writer};

/// The most bytes a shot's signed body may run to.
///
/// It is the frame routes' request-body cap, 8 MiB (wire.md §HTTP status
/// codes, `413 payload_too_large`), the parity the daemon holds a shot's
/// body to. The body is composed through the publication's request
/// builder and measured against it; a body past it is refused
/// [`Refusal::BodyOverBudget`] with its size, and a list whose copied
/// positions alone pass it, at four bytes each, is refused so before any
/// value is read.
pub const SHOT_BODY_BUDGET: usize = 8 * 1024 * 1024;

/// Lands a composed merge (the merge record's §7, `land`).
///
/// The shot is followed by the claim's read and the record, the draft
/// landing by the record alone, each step read first — the draft's one
/// write under a per-session id the board answers again — so a second call
/// over the same `merged` in one session writes nothing twice. In another
/// session the board holds no memo of the write into a draft named: typed
/// against the position its own landing moved the draft past, it is refused
/// `arrangement_moved`, nothing written, naming that landing and its
/// record, written or not, with [`resume`] the way on where that landing
/// placed M, whatever was edited in the draft since. A merge
/// composed again after an undo or a withdrawal lands as a write of its
/// own, in the same session or another: its ids name the position it was
/// composed at, and the take-back's record leaves no record standing for
/// it, so it writes its own. One composed again with no take-back between
/// and landed in the draft the standing record names lands its write under
/// its own ids and writes no record: the same landing (skep #790). A draft
/// landing reads the merger's newest record for the key before any write,
/// whatever the composition saw. With a draft named, the ids name the
/// record the landing follows, so the same `merged` landed again into its
/// draft after a take-back recorded since is a write of its own, which the
/// board judges: typed against the position the merge was composed at,
/// which the landing taken back moved the draft past, it is refused
/// `arrangement_moved` with nothing written. With no draft named, this
/// composition's landing standing in a draft the merger's records of the key
/// name — whatever landed or was taken back since in another — is the
/// answer, in any session, at the position its draft marks it (the module's
/// doc), with nothing staged and [`Landed::Draft`]'s `staged` false; a
/// take-back's record leaves the key open, so the same `merged` landed again
/// stages a draft of its own, the stage's id naming that record, its
/// `staged` true — and so does a take-back whose record went unwritten, the
/// draft marking no landing of the merge, and a draft holding another
/// composition's landing of the key: the board's mark and the list it
/// placed decide, never the record alone.
///
/// With no draft named and no draft the merger's records of the key name
/// holding this composition's landing, a
/// landing of the merge begun in a draft of the merger's — its one write
/// landed, no record of the merger's own of the merge naming the draft — is
/// refused [`Refusal::LandingBegun`] naming the draft, nothing staged or
/// written (PUB-8.32): the merge never lands twice, and the merger decides
/// whether to go on or to take it back. So a second call over the same
/// `merged` in one session, after its fresh landing's record went
/// unwritten, is refused naming the draft its first call staged.
///
/// # Errors
///
/// In this order:
///
/// - [`Refusal::OverCap`], before any frame, and again over the list the
///   answers leave;
/// - at the shot, the window parts' reads' refusals, then
///   [`Refusal::WindowPartsOwed`] where a part stands unanswered or an
///   answer fits nothing, nothing sent, then the draft side's records'
///   read's refusals;
/// - the reads' refusals, for a member already holding the answered list or
///   for the merger's records of the key at a draft landing, and, with no
///   draft named, for each draft those records name as landed in — its
///   `doc_metadata`, on a draft with no recorded base its rows and the past
///   states their walk needs, and its `image` as of its mark —
///   [`Refusal::HistoryBusy`] past the bounded retries among them, a past
///   state the board has reclaimed at the mark, or at the mark's `image`,
///   answering the record's landing as standing, never staged again (the
///   module's doc, **A fresh landing found standing**) — each as itself
///   (SP-14);
/// - with no draft named where none of those drafts holds this
///   composition's landing, the reads for a landing begun — the merge's head's
///   `doc_metadata`, the merger's drafts' rows on the supplement and each
///   draft's own reads (`Writer::landing_begun`) — each as itself, then
///   [`Refusal::LandingBegun`] where one stands, nothing staged or written;
///   then each window origin's `doc_metadata` (`Writer::windows_readable`),
///   [`Refusal::WindowWithheld`] naming the first the merger may not read,
///   beside its words in M, nothing staged;
/// - a journal named that cannot take the record, before the landing's
///   first write with nothing sent (P13): one this merger may not read, one
///   this board does not register or another account's, as
///   [`Refusal::Halt`] naming the journal and the check it fails; a
///   published one of the merger's own, as [`Refusal::PublishedJournal`];
///   the journal's `doc_metadata` read's other refusals and halts;
/// - the reads' refusals for the draft's `doc_metadata`, read as it stands,
///   and a draft minted after the composition's position, faced;
/// - at the shot, [`Refusal::OverCap`] over the list cut at a draft side's
///   kept places, nothing sent, and [`Refusal::BodyOverBudget`] where its
///   copied positions alone, four bytes each, pass [`SHOT_BODY_BUDGET`],
///   no value read;
/// - a claimed board serving no head record, as [`Refusal::Halt`] naming
///   `H.1`, before the shot, with nothing sent; and the `H.1` and `/health`
///   reads' halts (SP-14);
/// - the shot's: the skip reads' refusals at the daughters, then
///   [`Refusal::HeadHolds`] where no daughter is left and the head holds the
///   answered list whole, nothing sent, then the value
///   reads', [`Refusal::BodyOverBudget`] where the body their bytes compose
///   passes [`SHOT_BODY_BUDGET`], nothing sent,
///   [`Refusal::WindowPartsOwed`] naming a part a record names
///   since its answer was given (the re-read just before the send),
///   [`Refusal::WindowWithheld`],
///   [`Refusal::NeedsSignedSession`], [`Refusal::NoSuchDocument`], the
///   board's `not_owner` naming the draft side as [`Refusal::UnownedDraft`],
///   `supersede_refused` as [`Refusal::SupersedeRefused`] — at `head_moved`
///   the trunk's head named, the merge to compose again on it, nothing
///   committed and nothing re-sent —
///   `already_published` met once as the draft's records read again, a
///   member found holding the list they leave answered as the landing, else
///   the shot sent once more, the board's second as
///   [`Refusal::AlreadyPublished`], `publication_over_budget` verbatim as
///   [`Refusal::Halt`] (never the library's fault), `kept_place_moved` as
///   [`Refusal::Halt`] naming the draft that changed since the merge was
///   composed, nothing published,
///   `attestation_invalid:board_unavailable` faced as the head the board
///   owes, nothing landed, `attestation_required` at a shot sent unsigned
///   answered by its one signed re-send, a head the second read does not
///   find faced as the head the board owes, nothing landed, and a lost
///   acknowledgment as the dialer's halt after one re-ask, for [`resume`]
///   to complete — or the draft landing's: the
///   stage's refusals where a fresh draft is staged ([`Refusal::Unreadable`]
///   and [`Refusal::NoSuchDocument`] naming the head, the first never met at
///   a version member, which is published), then the one write's
///   — `arrangement_moved` as the board's verdict, [`Refusal::Halt`] with
///   `Refused` naming this merge's own landing where it moved the draft
///   after the composition, [`resume`] the way on where that landing placed
///   M, else the draft that changed after the merge was composed and that
///   nothing was merged, or the refusals of the draft's reads after it,
///   each as itself; [`Refusal::ForkBaseMoved`];
///   [`Refusal::BaseNotInChain`]; [`Refusal::WindowWithheld`];
///   [`Refusal::NeedsSignedSession`]; [`Refusal::NoSuchDocument`] naming
///   the draft; `source_not_registered`, `no_base_to_record` and
///   `base_extent_too_large` as the library's own faults, since it names
///   the head and the extent the merge read, and a base only where the
///   draft records one — and a lost acknowledgment as the dialer's halt
///   after one re-ask under the same id, for [`resume`] to complete;
/// - the claim's and the record's reads' refusals; the account's journal
///   not found for a board too busy to answer the find, past its bounded
///   reissues, a journal whose extent read answers `withheld` or
///   `doc_not_registered`, or a journal named whose atom the board refuses
///   as another account's or a published one, each faced as the landing
///   standing with its record unwritten, nothing of the record written, for
///   [`resume`] to record; then the record's writes', and
///   [`Refusal::NeedsSignedSession`] at its link.
///
/// At any step the library's own faults, the board's other refusals
/// verbatim and transport halts are [`Refusal::Halt`]; the death signal
/// under the merger's token is [`Refusal::SessionEnded`], its face naming
/// the step it met and [`resume`] as the way on.
///
/// # Panics
///
/// Panics if a landing that shoots answers none; the walk with `shoot` on
/// answers one on every path, so the `expect` never fires.
pub fn land(board: &Board, merged: &Merged, landing: Landing<'_>) -> Result<Landed, Refusal> {
    walk(board, merged, landing, true)
        .map(|landed| landed.expect("a landing that shoots answers a landing"))
}

/// Completes a landing whose acknowledgment was lost — the residue walk.
///
/// Where the shot landed and its acknowledgment was lost, the walk (the
/// merge record's §1.5, P14) finds the member whose first `placed`
/// positions equal M — the trunk's next member, else a daughter of the
/// head, which it reports as [`Landed::AsDaughter`] — or the landing the
/// board marks in the draft named, at the position it marks, where the
/// draft as of that position held M, whatever was edited in it since, and
/// completes the record, after the claims' read for the
/// trunk's member — a landed shot carried its claims, so the member is
/// found with them (the module's doc) — writing nothing twice: a member any
/// record of the merger's own of the merge names, and a landing the record
/// of the key standing in the draft named names (`Newest::standing_in`),
/// whatever the newest record of the key names, are answered with that
/// record. `None` where nothing landed, with nothing written: a shot
/// refused whole left nothing to find. The draft's mark is the marker
/// naming this merge, or on a draft with no recorded base the landing
/// standing by its rows where it names this merge (the module's doc,
/// **Finding a landing**), never the draft's
/// words: a landing withdrawn or undone, its mark cleared or taken back, is
/// no landing to resume, whatever the draft holds (R2); nor is a marker the
/// draft inherited when it was staged from a draft the merge landed in,
/// whose `at` is the draft's own mint (P2). A draft landing
/// reads the merger's newest record for the key first, as [`land`] does, so
/// the record it completes goes under the landing's own ids; for a fresh
/// landing, this composition's landing standing in a draft the merger's
/// records of the key name is the answer at the position that draft marks
/// it, read as [`land`] reads it; else a
/// landing of the merge begun in a draft of the merger's and never recorded
/// is refused [`Refusal::LandingBegun`], as [`land`] refuses it, and never
/// completed by a `resume` naming no draft; else `None`. It stages nothing,
/// so a draft landing it answers carries `staged` false. It reads no head
/// record: it sends no write but the record's, which a private journal
/// takes unsigned.
///
/// # Errors
///
/// As [`land`]'s but the check of a journal named, the head record's and the
/// shot's, the stage's and the draft's write's: it sends no write before
/// the record, so a journal it is given is met at the record alone. A
/// window part left unanswered at the shot is refused
/// [`Refusal::WindowPartsOwed`], never answered as no landing: a landing
/// is compared by the list its answers make (SP-14). A draft
/// named is read as it stands — its `doc_metadata`, on a draft with no
/// recorded base its rows and the past states their walk needs, and its
/// `image` as of the position the board marks the landing at, or as it
/// stands where the board has reclaimed that position — each refusal
/// answered as itself, never as no landing (SP-14), but a past state the
/// rows' walk needs that the board has reclaimed, which leaves no landing
/// found standing (the module's doc, **Finding a landing**), and a mark
/// whose list cannot be read back, that position reclaimed and the draft
/// not holding M as it stands, which is answered where a record of the key
/// stands for it and is no landing found where none does.
pub fn resume(
    board: &Board,
    merged: &Merged,
    landing: Landing<'_>,
) -> Result<Option<Landed>, Refusal> {
    walk(board, merged, landing, false)
}

/// Records a merge a publication of the merger's own landed (the merge
/// record's §1.5 (ii); the merge bridge lane).
///
/// `member` and `position` are the member and the commit position that
/// publication acknowledged — the editor's shot, composed through the
/// publication family from the draft the merge was landed in and carrying
/// the daughters as its `supersede`, or any shot of the merger's that
/// minted the member — and `merged` the composition the record describes.
/// No shot is sent: the claims are read at the daughters as the landing
/// reads them after its own shot (`Writer::claims_standing`), the
/// merger's newest record for the key is read, and the record is written
/// through the one record writer — `landed` the member at the position,
/// `claims` as read, `replaces` the newest — under the shot's per-session
/// ids (the module's doc), unless the newest record already names the
/// member as landed in, or any record of the merger's own of the merge,
/// its states ignored, does (`Newest::recording`), which is answered with
/// nothing written (P4, P14).
/// It never runs the shot landing's read-first: a member the person edited
/// before publishing holds other runs than M, which [`land`] with
/// [`Landing::Shot`] would read as no landing and shoot M again.
///
/// # Errors
///
/// A member outside `merged`'s document's chain, as the library's own fault
/// ([`Refusal::Halt`]), nothing read; then as [`land`]'s from the claims'
/// reads on — the record is this call's first write, so a journal named is
/// met at the record alone: the claims' and the record's reads' refusals, a
/// journal this merger may not read or this board does not register, or
/// one named that is another account's or published, faced as the landing
/// standing with its record unwritten, and the record's writes'.
///
/// `answers` are the window parts' answers the publication composed, kept
/// in the record so [`record::verify`](super::record::verify) reads the
/// member as answered.
/// The death signal under the merger's token is [`Refusal::SessionEnded`],
/// its way on this call made again: it reads the record first and writes
/// it once, where [`resume`] would read no landing in a member the person
/// edited before publishing.
pub fn record_published(
    board: &Board,
    merged: &Merged,
    merger: Merger<'_>,
    member: &Address,
    position: u64,
    journal: Option<&Address>,
    answers: &[PartAnswer],
) -> Result<Landed, Refusal> {
    if version_components(&merged.inputs.doc, member).is_none() {
        return Err(own_fault_face(
            "the member is no version of the merged document",
            format!("{member} lies outside the chain of {}", merged.inputs.doc),
        ));
    }
    let writer = Writer::new(board, merger, OnEnd::Rerun);
    let claims = writer.claims_standing(merged, member)?;
    let landed = RecordLanding::Member { member: member.clone(), position };
    let newest = writer.newest_record(merged)?;
    let record = match newest.naming(&landed).or_else(|| newest.recording(member)) {
        Some(link) => link.clone(),
        None => {
            let stem = Stem::of(&merged.key.text());
            writer.write_landing_record(merged, landed, &claims, &newest, &stem, journal, answers)?
        }
    };
    Ok(Landed::Member {
        address: member.clone(),
        position,
        claims,
        record,
        retries: merged.inputs.options.retries,
        answers: Vec::new(),
    })
}

/// One stretch of a draft that a landing into it replaces.
///
/// It is `width` positions of the draft from `ordinal`, as the draft stood
/// at the composition's position, whose first position's content is
/// `origin`'s from `i_start` (the owner's ruling of 2026-11-20; skep #770).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replaced {
    /// The stretch's first position in the draft, counted from 1.
    pub ordinal: u64,
    /// The positions it holds.
    pub width: u64,
    /// The document that minted its first position's content.
    pub origin: Address,
    /// That content's ordinal in `origin`'s content subspace.
    pub i_start: u64,
}

/// Returns each stretch of `into` that landing `merged` there replaces.
///
/// It reads `into`'s whole image at the head, held to the composition's
/// position as a composition holds a side that can change (the `reads`
/// module's doc): the draft's `doc_metadata` is read before the image and
/// again after it, and the image is answered only where the draft's text
/// changed neither between the two nor after `merged.as_of` — the state the
/// draft landing's one write is typed against, so exactly what the write
/// replaces. It answers each maximal stretch of that image whose content
/// M's runs carry none of, in order (`replaced_stretches`). Words M
/// carries at another place are not replaced, and an image M carries whole
/// answers none. An embedder reads it before a landing over an earlier
/// landing of the merge, to say what the landing takes out and that an undo
/// puts back.
///
/// # Errors
///
/// The reader's: `withheld` on the draft, [`Refusal::Unreadable`]; a draft
/// the board does not register, or one minted after the composition's
/// position, [`Refusal::NoSuchDocument`]; a draft whose text changed after
/// that position or between the two reads, [`Refusal::SideMoved`] naming it,
/// `at` the composition's position — a landing typed against it would be
/// refused `arrangement_moved`, and the way on is to compose again; a board
/// serving no `arranged_at`, faced; a draft in more pieces than `image`
/// answers, [`Refusal::TooFragmented`]; the death signal under the token,
/// [`Refusal::SessionEnded`]; an `image` run that is no content I-address,
/// a transport halt and the board's other refusals, [`Refusal::Halt`].
pub fn replaced(
    board: &Board,
    token: Option<&Token>,
    into: &Address,
    merged: &Merged,
) -> Result<Vec<Replaced>, Refusal> {
    let reader = Reader::new(board, token, OnEnd::Rerun);
    let (before, _) = fence(&reader, into)?;
    if before.at.is_some_and(|minted| minted > merged.as_of) {
        return Err(Refusal::NoSuchDocument(into.clone()));
    }
    let image = reader.imaged(into, None)?;
    let (after, _) = fence(&reader, into)?;
    let (before, after) = (before.arranged_at.position(), after.arranged_at.position());
    if before != after || after.is_some_and(|changed| changed > merged.as_of) {
        return Err(Refusal::SideMoved { side: into.clone(), at: merged.as_of, before, after });
    }
    let held = runs_of(&image.runs)?;
    let m: Vec<Run> = merged.composed.runs.iter().map(|p| p.run.clone()).collect();
    Ok(replaced_stretches(&held, &m))
}

/// Returns each maximal stretch of `held` whose content `m` carries none of.
///
/// The stretches are in order, each ordinal counted from 1 along `held`.
/// `held` is a draft's runs in V order and `m` the merged list's: a
/// position is carried where some run of `m` holds its I-address, wherever
/// in `m`. Stretches that meet across a run boundary are one.
pub(super) fn replaced_stretches(held: &[Run], m: &[Run]) -> Vec<Replaced> {
    let mut out: Vec<Replaced> = Vec::new();
    let mut ordinal = 1u64;
    for run in held {
        let mut carried: Vec<(u64, u64)> = m
            .iter()
            .filter(|r| r.origin == run.origin)
            .map(|r| (r.i_start.max(run.i_start), r.reach().min(run.reach())))
            .filter(|(lo, hi)| lo < hi)
            .collect();
        carried.sort_unstable();
        let mut cursor = run.i_start;
        let mut gaps: Vec<(u64, u64)> = Vec::new();
        for (lo, hi) in carried {
            if lo > cursor {
                gaps.push((cursor, lo));
            }
            cursor = cursor.max(hi);
        }
        if cursor < run.reach() {
            gaps.push((cursor, run.reach()));
        }
        for (lo, hi) in gaps {
            let at = ordinal + (lo - run.i_start);
            match out.last_mut() {
                Some(last) if last.ordinal + last.width == at => last.width += hi - lo,
                _ => out.push(Replaced {
                    ordinal: at,
                    width: hi - lo,
                    origin: run.origin.clone(),
                    i_start: lo,
                }),
            }
        }
        ordinal += run.width;
    }
    out
}
