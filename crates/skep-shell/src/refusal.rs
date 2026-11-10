//! The one refusal shape the page renders.
//!
//! It is `client.md` §4b.1's refusal column: "the armed set; anything else
//! is a `Halt {state, cause, act}` the page renders". Every refusal a call
//! answers is one value with a `kind` and one `name` token the page faces
//! on — never prose —
//!
//! * `refused` — the board's own verdict, carried back verbatim: the
//!   `rejected` document's code and detail, or a non-200's error, its `name`
//!   the one token `Rejection::key` dispatches on;
//! * `halt` — a halt's face, the state, its cause and the one act, its
//!   `name` the armed refusal the row spells where the shell diagnosed one
//!   and `halt` where the row arms none; the path a face about a file
//!   names beside its words is never rendered (§4b.3: a key file's path,
//!   the store's location, an anchor file's path are native);
//! * `blocked` — the handshake's `403 prefix_blocked` with its record and
//!   the ground read as a guest;
//! * `unreachable` — the board is not answering;
//! * `shell` — the shell's own refusal, with its detail.
//!
//! The names the shell spells — the shell's own refusals and the armed names
//! a halt's face takes — are [`Name`]'s constants and nothing else: its field
//! is private to this file, so a call site names a refusal only by a
//! constant declared here, and this list is the one the README and
//! `ARCHITECTURE.md` point to.

use std::fmt;

use serde_json::{json, Map, Value};
use skep_client::halt::{Blocked, Face, Halt, Refused};
use skep_client::DialError;

/// The refusal: the error every call answers.
///
/// A `Halt` converts into its member by `From`, so `?` carries a walk's halt
/// to the row's refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The board's own verdict, verbatim.
    Board(Refused),
    /// A halt's face, under the armed name the row spells where one does.
    Halt { name: Name, face: Face },
    /// The block.
    Blocked(Blocked),
    /// The board is not answering.
    Unreachable(DialError),
    /// The shell's own refusal.
    ///
    /// Its `detail` is an object whose members ride beside `kind` and `name`,
    /// never in their place; a detail of another type renders no member.
    Shell { name: Name, detail: Value },
}

/// A name the shell spells: one token, closed to the constants below.
///
/// The shell's own refusals come first, then the armed names a halt's face
/// takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Name(&'static str);

impl Name {
    // ── The shell's own: `Refusal::shell` ────────────────────────────────

    /// The pin's stale-reference refusal: "session ended".
    ///
    /// It answers a reference this shell holds no session under, issued or
    /// not.
    pub const SESSION_ENDED: Name = Name("session_ended");
    /// The call's session met the death signal.
    ///
    /// The reason its end carried rides beside it.
    pub const SESSION_DIED: Name = Name("session_died");
    /// A board reference this shell instance never issued.
    pub const UNKNOWN_BOARD: Name = Name("unknown_board");
    /// A call the bridge does not spell.
    pub const UNKNOWN_CALL: Name = Name("unknown_call");
    /// `fetch` through the dispatch: it streams, on its transport's own route.
    pub const STREAMED_CALL: Name = Name("streamed_call");
    /// A call's arguments are not the row's shape.
    pub const MALFORMED_ARGS: Name = Name("malformed_args");
    /// A row the library does not reach at this pin.
    ///
    /// The detail says where it stops.
    pub const NOT_REACHED: Name = Name("not_reached");
    /// A write frame in the guest form, refused without a dial.
    pub const WRITE_IN_GUEST_FORM: Name = Name("write_in_guest_form");
    /// A write under a bare session, refused without a dial.
    ///
    /// Its `resolve(send)` is refused so too. The bare session is the keyless
    /// session for reading alone (foundations §3.3 state 3: "the shell
    /// refuses every write in it"); the detail names the `op`, or the `act`.
    pub const WRITE_IN_BARE_SESSION: Name = Name("write_in_bare_session");
    /// A write while another shell holds the board's held store (§3c.3).
    ///
    /// ONE SHELL PER DATA DIRECTORY: until a second launch hands its address
    /// to the running client and exits, a shell finding the lock of a board's
    /// held store held by another shell over its data directory reads alone
    /// at that board — every write frame through `op`, `/op-at`'s too, every
    /// row of the publication and merge families and `history.restore`, and
    /// every ceremony that writes to the board — `claim`, `enroll`, `bind`,
    /// `recover`, `rotate`, `retire`, `handoff`, `accept` (skep #829: a
    /// second window runs no recovery while the first stands) — refused
    /// without a dial at the shell's one write door (`Shell::write_door`),
    /// nothing held and nothing sent, the writes the other window's to make.
    /// The detail names the `op`, or the `call`.
    pub const ANOTHER_WINDOW: Name = Name("another_window");
    /// A `publish` frame through `op` under a session, refused without a dial.
    ///
    /// A publication crosses as `publication.confirm` (`client.md` §4b.1's
    /// `op` row, decision 1 (b)): the shell composes the one request from
    /// the panel it holds, and the page composes no write (S-35 (a)); the
    /// detail names the `op`.
    pub const PUBLISH_IS_A_CALL: Name = Name("publish_is_a_call");
    /// A non-burst write while the own node stands stopped (§3c.4).
    ///
    /// One of the unholdable writes (`hold`'s `UNHOLDABLE_WRITES`) through
    /// `op`, `publication.confirm`'s send, `history.restore`'s write and the
    /// merge rows' — the landing's `stage` and `set_arrangement`, the shot,
    /// the undo's and the withdrawal's one write — refused at once at the
    /// shell's one write door (`Shell::write_door`) with the hold's cause as
    /// its token, never held and never dialed; the detail names the `op` —
    /// `publish` for the confirm and the landing's shot, `set_arrangement`
    /// for the restore, the undo and the withdrawal, `stage` for a
    /// composition that stages a fresh draft.
    pub const STOPPED: Name = Name("stopped");
    /// A non-burst write while the board's write path stands poisoned (§3c.4).
    ///
    /// The hold noted a `poisoned` answer and no `/health` read has said
    /// writes go since; the same writes and the detail as
    /// [`Name::STOPPED`]'s.
    pub const POISONED: Name = Name("poisoned");
    /// A non-burst write while the board's writes stand halted (§3c.4).
    ///
    /// The feed's last `/health` read answered `writes.halted` true; the same
    /// writes and the detail as [`Name::STOPPED`]'s.
    pub const HALTED: Name = Name("halted");
    /// A whole-draft write over a draft holding lines of the acting
    /// principal's the board has not kept (§3c.4, THE HELD-LINES GATE; the
    /// held store's shape (vi) item 4; skep #849, #854).
    ///
    /// `history.restore`, `merge.land`, `merge.undo`, `merge.withdraw` and
    /// `publication.confirm` each set a whole draft's arrangement — the
    /// draft the row writes, and for the shot every draft its `also` names
    /// — and such a write landing past the principal's held lines on that
    /// draft would land under words the person typed and the board has not
    /// kept, the lines then meeting a document that moved. So the write is
    /// refused at the shell's one write door (`Shell::write_door`) before
    /// any dial, nothing sent, while a line of the principal's stands held
    /// on the draft in ANY state — holding, sending, refused, moved,
    /// `head_unreadable`, `session_died`; the burst writes are not gated,
    /// a burst on such a draft held `behind` the standing lines as before.
    /// The detail names `doc`, the draft holding the lines, and `held`, how
    /// many stand on it. The page draws the slot inert ahead of the act with
    /// B3-S13's row rule — "⟨label⟩ holds words the board has not kept —
    /// resolve them where they are marked, then take this" — and this
    /// refusal is that rule's answer for a write that arrives anyway: an
    /// agent's, or a page that missed the state.
    pub const HELD_LINES: Name = Name("held_lines");
    /// A `merge.land` with a window part unanswered: the landing composes
    /// no answer the caller did not give (the merge record's §1.5), so it
    /// publishes nothing and names every part that needs one, each part's
    /// words, its pair, its origin and owner, the sides showing it as a
    /// placeholder and the answers it admits, beside the answers given and
    /// each default taken — `shapes`' `WindowPartsOwedRefusal`. It is the
    /// same refusal `skep merge --publish` prints, final in meaning.
    pub const WINDOW_PARTS_OWED: Name = Name("window_parts_owed");
    /// A `publication.count` or `publication.confirm` with no panel standing.
    ///
    /// None was opened under the session's board and principal, or it was
    /// cancelled, or it went with its session: the act is `publication.open`
    /// (§4b.1's `count` row); the detail names the `session`.
    pub const NO_PANEL: Name = Name("no_panel");
    /// A `publication.open` at the document form for a draft with no base.
    ///
    /// The board records no base for the draft in `doc`'s chain — its
    /// `doc_metadata` answers none, or one in another document's chain
    /// (`skep_client::publication::draft_base`; B3-S10): the shell never
    /// takes the chain's head in its place, since a draft begun from an
    /// older version would publish over the newer words. The detail names
    /// the `draft`, the `doc` and the `reason`: `no_record`, a draft minted
    /// by `create_new_document` or `fork` and never staged; `other_chain`,
    /// a base in another document's chain; `free_standing`, an alternative
    /// of a draft the board records no base for. The act is staging the
    /// draft with `stage` from the version it is to publish after, which
    /// records its base. A `publication.confirm` whose re-read finds the base
    /// gone answers it too. It is the one refusal of a base: every STANDING
    /// of a recorded base is told on the panel and refused never, a draft
    /// begun from the bare document whose first member now stands among them
    /// (`superseded_first`), which publishes beside that member.
    pub const BASE_UNRECORDED: Name = Name("base_unrecorded");
    /// A publication read met `withheld` on a document it needs.
    ///
    /// Brief 1's `Fault::Unreadable`; the detail names the `doc`.
    pub const UNREADABLE: Name = Name("unreadable");
    /// A publication read met `doc_not_registered` on a document it needs.
    ///
    /// Brief 1's `Fault::NoSuchDocument`; the detail names the `doc`.
    pub const NO_SUCH_DOCUMENT: Name = Name("no_such_document");
    /// A held run of the selection the draft no longer arranges whole.
    ///
    /// Brief 1's `Fault::SelectionNotArranged`, at the first enumeration —
    /// before any re-read can re-state it — or at a confirm over a
    /// selection the draft has wholly left, each run already re-stated
    /// absent, no empty version composed (PUB-3.108); the detail names the
    /// run's `index` in the selection.
    pub const SELECTION_NOT_ARRANGED: Name = Name("selection_not_arranged");
    /// A selection holding nothing but merge records, which no publication
    /// publishes: nothing in it to publish.
    ///
    /// Brief 1's `Fault::OnlyMergeRecords`, at the enumeration, nothing
    /// sent; the detail names the rendering `draft`.
    pub const ONLY_MERGE_RECORDS: Name = Name("only_merge_records");
    /// A board answer the publication's reader cannot read.
    ///
    /// Brief 1's `Fault::Shape`; the detail names the frame's `op` and the
    /// answer's `body`, clipped.
    pub const SHAPE: Name = Name("shape");
    /// A guest form's origin is not a canonical origin.
    pub const NOT_CANONICAL: Name = Name("not_canonical");
    /// A query past the bridge's bound.
    pub const QUERY_TOO_LONG: Name = Name("query_too_long");
    /// The board's feed thread has stopped: no search or listing is answered.
    pub const FEED_STOPPED: Name = Name("feed_stopped");
    /// The walk was abandoned.
    ///
    /// The page or the shell's stop cancelled a moment, or the dev arm left.
    pub const ABANDONED: Name = Name("abandoned");
    /// A secret or consent moment of the walk, refused with no one to answer.
    ///
    /// No person is present to answer it (`ArmConfig::Refuse`): nothing
    /// answered it, no arm and no page, and the walk was abandoned there —
    /// the detail names the `walk`, the `moment`, its `class` and, a
    /// confirmation's, its `text`, beside the walk's `halt`.
    pub const PERSON_REQUIRED: Name = Name("person_required");
    /// A label refused at the box.
    ///
    /// It is empty, holding a line break, or past its byte bound (AUTH-1.24's
    /// whole domain, one refusal with its `cause`; §4b.1's `keygen` row) —
    /// `keygen`'s, `fingerprint`'s where a stored key's label lies outside
    /// that domain, and `accept`'s box as a halt's armed name.
    pub const EMPTY_LABEL: Name = Name("empty_label");
    /// A `select` that matches more than one key of the store.
    pub const AMBIGUOUS: Name = Name("ambiguous");
    /// A `select` that matches no key of the store.
    pub const NOT_FOUND: Name = Name("not_found");
    /// A claim on a board another store's claim stands on.
    pub const ALREADY_CLAIMED: Name = Name("already_claimed");
    /// `bind`'s pasted origin is not the board's.
    pub const ORIGIN_DISAGREES: Name = Name("origin_disagrees");
    /// `bind`'s pasted account and principal are not a pair the board seats.
    pub const ACCOUNT_DISAGREES: Name = Name("account_disagrees");
    /// `accept` with no address.
    pub const NO_ADDRESS: Name = Name("no_address");
    /// A row that acts as the session's account, under a session that has none.
    ///
    /// The board answered the session no account: an attest signs as it, the
    /// publication and merge families and the restore take their hand from
    /// it, and `history.past` reads the correspondence records it owns.
    pub const NO_ACCOUNT: Name = Name("no_account");
    /// The held-burst store's file was written by a newer skep, or is damaged.
    ///
    /// It answers `held(session)`, and every act on the principal's held
    /// lines — P38's halt (§3c.3), its detail the `why` alone, one of `newer`
    /// (a newer `v`), `unknown_member` (an unknown header member, or a header
    /// off its spelling) or `damaged` (a line not read whole, the header's or
    /// a body line's), as `held::HaltWhy::token` spells them. The file's path
    /// crosses the bridge never (§4b.3; SP-15): the embedding app
    /// reads it natively (`Shell::halted_file`), and the page asks the shell
    /// to show the file by `held.show`.
    pub const STORE_HALTED: Name = Name("store_halted");
    /// `resolve(session, …)`: no held line of that ordinal stands.
    pub const NO_SUCH_HELD: Name = Name("no_such_held");
    /// `resolve(session, …)`: the line is `holding` or `sending`.
    ///
    /// It is not refused or moved — no act exists until the board answers,
    /// its head record reads again where the line holds `head_unreadable`, or
    /// the shell hands the line to the person under `answers_lost` (P10).
    /// Two drops are admitted all the same: of a line held `head_unreadable`,
    /// and of every line under a bare session, the keyless session's discard.
    /// It answers too a drop whose line was re-marked while the drop's read
    /// for its landing was out — a `send` of it — nothing dropped.
    pub const NOT_RESOLVABLE: Name = Name("not_resolvable");
    /// `resolve(session, …)`'s drop of a line whose answer was lost, refused.
    ///
    /// The line is a `sent` one handed over as `answers_lost`, and the read
    /// its drop makes first cannot tell whether its write landed (§3c.4; skep
    /// #866): nothing is dropped, since a drop never removes words the board
    /// may hold. The detail names `held`, the line's ordinal, and `why`:
    /// `unanswered` where the board gave the read no answer, or is not
    /// answering, so no read was made; `unread` where it answered the read
    /// with no page; `undecided` where a row could be the line's landing and
    /// the read could not confirm it; `stopped`, `poisoned` or `halted` where
    /// that hold stands at the board, a restart of a halted board rebuilding
    /// what its journal holds, so no read is made. The drop is asked again
    /// once the board answers and takes writes, and a line `undecided` leaves
    /// by `send`, whose dial the board judges by its typed state.
    pub const LANDING_UNREAD: Name = Name("landing_unread");
    /// A burst whose frame passes the board's frame cap, refused at the act.
    ///
    /// The frame passes it as sent or as a resend's attest would carry it —
    /// one the board answers `413` unread at every send — and the burst is
    /// never held.
    pub const FRAME_TOO_LARGE: Name = Name("frame_too_large");
    /// A burst the principal's held queue has no room for.
    ///
    /// Its standing frames and their anchors, or its lines, hold the queue's
    /// budget already, or its ordinals are spent — the burst refused, and
    /// kept nowhere. Its detail names the bytes held, the burst's frame's and
    /// its anchors' (`held_bytes`, `frame_bytes`, `anchor_bytes`) against
    /// `cap`, and the lines held (`held_lines`) against `line_cap`.
    pub const HELD_FULL: Name = Name("held_full");
    /// A held line handed to the person at its deadline, no landing found.
    ///
    /// Its first failed send stood `hold`'s `HAND_OVER_DEADLINE`, two
    /// minutes, past, whatever the failure — a lost answer (a timeout, a
    /// garbled answer, the board's handler panicking), a reissue-class answer
    /// at its count, a `durability` hold, the board's refusal of it as typed
    /// against an older state, shifted or not — and the read found no
    /// landing, so the shell stopped resending it: the line is a refused run
    /// under this token, its `sent` kept, until `resolve` sends it again or
    /// drops it (§3c.4), a drop of a `sent` line reading for its landing
    /// first ([`Name::LANDING_UNREAD`]; skep #866). Its detail names `last`,
    /// the last failure's token — the held cause, or the board's — and
    /// `elapsed_ms`, the milliseconds since the line's first failed send.
    pub const ANSWERS_LOST: Name = Name("answers_lost");
    /// `answer(id, …)` or `cancel(id)` where no moment of that id waits.
    pub const NO_SUCH_MOMENT: Name = Name("no_such_moment");
    /// A follower write whose `after` names no burst its session keeps.
    ///
    /// No burst of that `id` reached the session's table within a second of
    /// the follower: the session sent none under it, or its table let it go,
    /// keeping its newest answered bursts (`shell/follow.rs`; §3c.6). The
    /// detail names the `after`.
    pub const NO_SUCH_BURST: Name = Name("no_such_burst");
    /// A follower write not sent: its burst, or the shell's stop, stood in
    /// its way (§3c.6).
    ///
    /// Nothing of it was written and it is held nowhere, a link write being
    /// none of the held kinds: the page takes off the mark it drew. The
    /// detail names the `after` and `why`: `burst` where the burst was not
    /// acked — held, with the hold's `cause`, or refused, with the refusal's
    /// name as `cause`; `ahead` where a follower of the same burst before it
    /// was not acked, a chord's writes being one step (D6 BM-69); `ack` where
    /// the burst's ack names no I-address its pieces resolve against; `stop`
    /// where the shell's stop came before the burst's answer.
    pub const NOT_FOLLOWED: Name = Name("not_followed");
    /// A `merge.land` or a `merge.undo` with no composition standing, or a
    /// `merge.withdraw` of a draft carrying no merge.
    ///
    /// None was composed under the session's board and principal, it was
    /// landed or taken back, or it went with its session (the family's one
    /// session rule; `client.md` §4b.1's merge row, "`no_merge` at `land`
    /// with nothing composed"); at the withdrawal the draft carries no marker
    /// (`skep_client::merge::Refusal::NoMerge`). The detail names the
    /// `session`, or the `draft`.
    pub const NO_MERGE: Name = Name("no_merge");
    /// A side whose base the merge library cannot read (`client.md` §4b.1's
    /// merge row, `BaseUnknown{side}`).
    ///
    /// The detail names the `side` and the `reason`: `base_unknown` — a
    /// member of another document, a draft of another account's, a draft the
    /// board records no base for or whose base lies in another chain
    /// (`skep_client::merge::Refusal::BaseUnknown`); `bare_source` with the
    /// `source` — a draft staged from the bare document, before its first
    /// version, whose base is history the board does not serve
    /// (`Refusal::BareSource`); `draft_base_disagrees` with `named` and
    /// `served` (`Refusal::DraftBaseDisagrees`, never met by this shell,
    /// which names no base).
    pub const BASE_UNKNOWN: Name = Name("base_unknown");
    /// Two drafts off one head: no merge shape
    /// (`skep_client::merge::Refusal::TwoDrafts`); the way out is to shoot
    /// one.
    pub const TWO_DRAFTS: Name = Name("two_drafts");
    /// The merged list holds more runs than one publication may carry.
    ///
    /// `skep_client::merge::Refusal::OverCap`, met at `merge.compose` with
    /// nothing landed (the merge record's decision 13, "refuse with count";
    /// B3-S11's cap face at the act), and at `history.past` and
    /// `history.restore` where the state, mapped through the records, is in
    /// more runs than one write may name, nothing sent; the detail names `n`,
    /// the runs, and the `cap`.
    pub const OVER_CAP: Name = Name("over_cap");
    /// A row's draft that is another account's, or a published document.
    ///
    /// The draft `merge.compose` is to land into (`into`), read off its
    /// `doc_metadata` before anything is composed — the page's member,
    /// UNTRUSTED (skep #799) — or the one an undo or a withdrawal is to
    /// take a merge out of, or a restore to set, as the library's read or
    /// the board refuses it (`not_owner`, `published_target`;
    /// `skep_client::merge::Refusal::{NotOwner, UnownedDraft, Published}`),
    /// and a published document `history.past` is asked to read, refused
    /// before any read at a position as the restore refuses it; the detail
    /// names the `addr`, and `published` true where the document is
    /// published.
    pub const NOT_OWNER: Name = Name("not_owner");
    /// Nothing to undo on the draft the composition landed in.
    ///
    /// `skep_client::merge::Refusal::NothingToUndo`, nothing sent; the
    /// detail names the `draft` and `why`: `inherited` (the marker came with
    /// the draft's staging), `published` with the `version` (the merge was
    /// published from the draft; the way back is the revert), `taken_back`
    /// (an undo or a withdrawal already took it out).
    pub const NOTHING_TO_UNDO: Name = Name("nothing_to_undo");
    /// A refusal of the merge library with no name of its own here.
    ///
    /// Each crosses as typed data under this one name, its `arm` the
    /// library's arm in snake case and the arm's members beside it
    /// (`shell/merge.rs`'s `merge_refusal`, which the refusals of
    /// `history.past` and `history.restore` cross through too): `too_fragmented
    /// {doc, runs_seen}`, `history_busy`, `history_reclaimed {at, floor}`,
    /// `beyond_head {at, head}`, `not_a_position {at, nearest}`, `not_past
    /// {draft, at, current}` (a past state's `at` at or past `current`, the
    /// draft's position), `fork_base_moved {fork, source, head}`,
    /// `base_not_in_chain {into, head}`, `window_withheld {origin}`,
    /// `needs_signed_session`, `fork_base_named {fork, base}`,
    /// `supersede_refused {index, detail, head}`, `published_journal {journal}`
    /// (a published document named as the merge journal, which keeps a record
    /// only private; nothing sent), `already_published {draft, member}` (the
    /// shot sent again met the twin fence again; nothing published).
    pub const MERGE_REFUSED: Name = Name("merge_refused");

    // ── The halts' armed names: `Refusal::named`, `Refusal::of_named` ────

    /// A halt the row arms no name for.
    pub const HALT: Name = Name("halt");
    /// The key store holds no key for (this board, the principal).
    pub const NO_KEY: Name = Name("no_key");
    /// The key store cannot be read.
    ///
    /// It is the shell's own data directory, its act and never a page act
    /// (`client.md` §4b.1).
    pub const STORE_UNREADABLE: Name = Name("store_unreadable");
    /// The key store cannot be written.
    ///
    /// It is the shell's own data directory, its act and never a page act
    /// (`client.md` §4b.1, §3.7).
    pub const STORE_UNWRITABLE: Name = Name("store_unwritable");
    /// The origin the shell signs for is not among the board's signed origins.
    ///
    /// It is the origin state of AUTH-5.24 and AUTH-5.36.
    pub const ORIGIN_STATE: Name = Name("origin_state");
    /// The principal holds no account at the board.
    ///
    /// `principal_prefix` answered none (AUTH-5.67 (2)); the pre-check's other
    /// halts, its walk's among them, take this name too.
    pub const NOT_REGISTERED: Name = Name("not_registered");
    /// The key stands in the retired list.
    pub const RETIRED: Name = Name("retired");
    /// The key stands in neither list.
    pub const NOT_ENROLLED: Name = Name("not_enrolled");
    /// The handshake halted after a pre-check that passed; or a publication
    /// read met `scan_busy` or `history_busy` past the library's bounded
    /// reissues (brief 1's `Fault::Busy`, the shell's own refusal, its detail
    /// the `call`).
    pub const BUSY: Name = Name("busy");
    /// `accept` at an address that already holds a key set.
    pub const ALREADY_SEEDED: Name = Name("already_seeded");
    /// `accept` at an address not yet delegated.
    pub const NOT_DELEGATED: Name = Name("not_delegated");
    /// The attest a signed session's write needs could not be composed.
    ///
    /// Nothing was sent.
    pub const ATTEST_NOT_COMPOSED: Name = Name("attest_not_composed");
    /// A signed session's write whose signature could not be made.
    ///
    /// The signature names the board's head record (`H.1`), which stands and
    /// cannot be read, or which a claimed board serves none of (SP-14): the
    /// face's cause says which, and why. Nothing was sent unsigned; a burst is
    /// held under this cause until the record reads again.
    pub const HEAD_UNREADABLE: Name = Name("head_unreadable");

    /// Returns the token.
    pub fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl Refusal {
    /// Returns the shell's own refusal named `name`, with its detail object.
    ///
    /// The detail's members render beside `kind` and `name`, never in their
    /// place.
    pub fn shell(name: Name, detail: Value) -> Refusal {
        Refusal::Shell { name, detail }
    }

    /// Returns the board's verdict on a non-200 answer.
    ///
    /// It holds its status, the error document's `error` as the code
    /// (`http_error` where the body names none), its `detail` and `op` where
    /// they ride, and the body whole — read as `skep-client` reads every
    /// non-200 it does not answer as a value.
    pub fn board(status: u16, body: Value) -> Refusal {
        Refusal::Board(Refused {
            status,
            code: body["error"].as_str().unwrap_or("http_error").to_string(),
            detail: body["detail"].as_str().map(str::to_string),
            op: body["op"].as_str().map(str::to_string),
            body,
        })
    }

    /// Returns the refusal for arguments that are not the row's shape.
    ///
    /// `what` says which member.
    pub fn malformed(what: impl Into<String>) -> Refusal {
        Refusal::shell(Name::MALFORMED_ARGS, json!({"what": what.into()}))
    }

    /// Returns a halt the row arms no name for.
    pub fn halt(face: Face) -> Refusal {
        Refusal::Halt { name: Name::HALT, face }
    }

    /// Returns a halt under the armed name the row spells.
    pub fn named(name: Name, face: Face) -> Refusal {
        Refusal::Halt { name, face }
    }

    /// Converts `h` as `From<Halt>` does, a halt's face taking `name`.
    pub fn of_named(name: Name, h: Halt) -> Refusal {
        match h {
            Halt::Halt(face) => Refusal::Halt { name, face },
            other => Refusal::from(other),
        }
    }

    /// Returns the one token the page faces on.
    pub fn name(&self) -> &str {
        match self {
            Refusal::Board(r) => match (r.code.as_str(), r.detail.as_deref()) {
                ("credential_refused" | "registry_refused", Some(detail)) => detail,
                (code, _) => code,
            },
            Refusal::Halt { name, .. } | Refusal::Shell { name, .. } => name.as_str(),
            Refusal::Blocked(_) => "blocked",
            Refusal::Unreachable(_) => "unreachable",
        }
    }

    /// Returns the value the page renders.
    ///
    /// A board's verdict carries its `site` beside the body — every member
    /// the wire names (wire.md §Rejections), each as the board fills it and
    /// absent where the code carries none: `addr`, `operand` and `fault` as
    /// strings, `index`, `region`, `slot`, `as_of` and `current` as numbers
    /// — so the page reads a refusal's site off the value, typed as the
    /// shell declares it (`shapes`' `RefusedByBoard`), and never off the
    /// body (skep #713). A halt is its face's three words, never the path
    /// the face names beside them (§4b.3; SP-15).
    pub fn to_value(&self) -> Value {
        let name = self.name();
        match self {
            Refusal::Board(r) => {
                let mut site = Map::new();
                for member in ["addr", "operand", "fault"] {
                    if let Some(text) = r.body["site"][member].as_str() {
                        site.insert(member.into(), Value::from(text));
                    }
                }
                for member in ["index", "region", "slot", "as_of", "current"] {
                    if let Some(n) = r.body["site"][member].as_u64() {
                        site.insert(member.into(), Value::from(n));
                    }
                }
                json!({
                    "kind": "refused",
                    "name": name,
                    "status": r.status,
                    "code": r.code,
                    "detail": r.detail,
                    "op": r.op,
                    "site": Value::Object(site),
                    "body": r.body,
                })
            }
            Refusal::Halt { face, .. } => json!({
                "kind": "halt",
                "name": name,
                "state": face.state,
                "cause": face.cause,
                "act": face.act,
            }),
            Refusal::Blocked(b) => json!({
                "kind": "blocked",
                "name": name,
                "record": b.record,
                "named_by": b.named_by,
                "ground": b.ground,
            }),
            Refusal::Unreachable(d) => json!({
                "kind": "unreachable",
                "name": name,
                "text": d.to_string(),
            }),
            Refusal::Shell { detail, .. } => {
                let mut out = Map::new();
                out.insert("kind".into(), Value::from("shell"));
                out.insert("name".into(), Value::from(name));
                if let Value::Object(members) = detail {
                    for (k, v) in members {
                        out.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                }
                Value::Object(out)
            }
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Board(r) => write!(f, "{r}"),
            Refusal::Halt { name, face } => write!(f, "{name}: {face}"),
            Refusal::Blocked(b) => write!(f, "{b}"),
            Refusal::Unreachable(d) => write!(f, "unreachable: {d}"),
            Refusal::Shell { name, detail } => write!(f, "{name}: {detail}"),
        }
    }
}

impl std::error::Error for Refusal {}

/// The family's member as the row carries it.
///
/// Each halt maps to its member: the board's verdict verbatim, a halt's face
/// under `halt`, the block, the unreachable board.
impl From<Halt> for Refusal {
    fn from(h: Halt) -> Refusal {
        match h {
            Halt::Refused(r) => Refusal::Board(r),
            Halt::Halt(face) => Refusal::halt(face),
            Halt::Blocked(b) => Refusal::Blocked(b),
            Halt::Dial(d) => Refusal::Unreachable(d),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks that every refusal names one token and renders under its kind.
    ///
    /// Every member names one token — the board's key, the armed name, the
    /// block, the unreachable board, the shell's code — and renders under its
    /// kind with the member's own fields, a halt's face as its three words
    /// and never the path it names, which its `Display` alone prints.
    #[test]
    fn every_refusal_names_one_token_and_renders_under_its_kind() {
        let board = Refusal::Board(Refused { status: 200, code: "credential_refused".into(), detail: Some("signed_session_required".into()), op: Some("publish".into()), body: json!({"resp": "rejected"}) });
        assert_eq!(board.name(), "signed_session_required");
        assert_eq!(board.to_value()["kind"], "refused");
        let plain = Refusal::Board(Refused { status: 503, code: "write_busy".into(), detail: None, op: None, body: Value::Null });
        assert_eq!(plain.name(), "write_busy");
        let face = Face { state: "s".into(), cause: "c".into(), act: "a".into(), path: None };
        let named = Refusal::named(Name::NO_KEY, face.clone());
        assert_eq!((named.name(), named.to_value()["state"].as_str()), ("no_key", Some("s")));
        assert_eq!(named.to_string(), format!("no_key: {face}"), "a halt renders as its name and its face");
        assert_eq!(Refusal::from(Halt::Halt(face)).name(), "halt");
        // A face about a file: its value the three words, its path in the
        // shell's own line alone.
        let placed = Refusal::of_named(Name::NO_KEY, Halt::face_at("/a/store", "s", "c", "a"));
        assert_eq!(placed.to_value(), json!({"kind": "halt", "name": "no_key", "state": "s", "cause": "c", "act": "a"}));
        assert!(placed.to_string().contains("\n  path: /a/store\n"), "{placed}");
        let blocked = Refusal::Blocked(Blocked { record: "1.0.1.0.7.1".into(), named_by: "http://x".into(), ground: None });
        assert_eq!((blocked.name(), blocked.to_value()["record"].as_str()), ("blocked", Some("1.0.1.0.7.1")));
        let dial = Refusal::from(Halt::Dial(DialError::Connect("refused".into())));
        assert_eq!((dial.name(), dial.to_value()["kind"].as_str()), ("unreachable", Some("unreachable")));
        let shell = Refusal::shell(Name::SESSION_ENDED, json!({"session": "s-1"}));
        let v = shell.to_value();
        assert_eq!((v["kind"].as_str(), v["name"].as_str(), v["session"].as_str()), (Some("shell"), Some("session_ended"), Some("s-1")));
    }

    /// Checks that a shell refusal's detail never overwrites its token.
    ///
    /// A shell refusal's `kind` and `name` are its own, whatever its detail
    /// holds: a detail naming either rides beside them, never in their place,
    /// and a detail of no object renders no member.
    #[test]
    fn a_shell_refusals_detail_never_overwrites_its_token() {
        let v = Refusal::shell(Name::SESSION_ENDED, json!({"kind": "x", "name": "y", "session": "s-1"})).to_value();
        assert_eq!(v, json!({"kind": "shell", "name": "session_ended", "session": "s-1"}));
        assert_eq!(Refusal::shell(Name::SESSION_ENDED, json!("a string")).to_value(), json!({"kind": "shell", "name": "session_ended"}));
    }

    /// Checks that a non-200 is the board's verdict under its own status.
    ///
    /// The error is its token, the members it carries kept in the body; a
    /// body that names no error is `http_error`.
    #[test]
    fn a_non_200_is_the_boards_verdict_under_its_status() {
        let r = Refusal::board(400, json!({"error": "beyond_head", "head": 12}));
        let v = r.to_value();
        assert_eq!((r.name(), v["kind"].as_str(), v["status"].as_u64(), v["body"]["head"].as_u64()), ("beyond_head", Some("refused"), Some(400), Some(12)));
        assert_eq!(v["site"], json!({}), "a code that names no site carries an empty one");
        let named = Refusal::board(200, json!({"error": "credential_refused", "detail": "retired", "op": "publish"}));
        assert_eq!((named.name(), named.to_value()["op"].as_str()), ("retired", Some("publish")));
        assert_eq!(Refusal::board(502, Value::Null).name(), "http_error");
    }

    /// Checks that a verdict's site rides the value beside its body.
    ///
    /// `site.addr` and `site.index` are read off the `rejected` document
    /// where the code names them (`already_published`'s member,
    /// `kept_place_moved`'s entry) and left out where it does not, so the
    /// page reads the site off the refusal and never off its body.
    #[test]
    fn a_verdicts_site_rides_the_value_beside_its_body() {
        let body = json!({"resp": "rejected", "code": "kept_place_moved", "disposition": "permanent", "op": "publish", "site": {"index": 1}});
        let r = skep_client::board::Rejection::of(&body).expect("a rejected document");
        let v = Refusal::from(r.refused(&body)).to_value();
        assert_eq!(v["site"], json!({"index": 1}), "{v}");
        let body = json!({"resp": "rejected", "code": "already_published", "disposition": "permanent", "op": "publish", "site": {"addr": "1.0.1.0.2.3"}});
        let r = skep_client::board::Rejection::of(&body).expect("a rejected document");
        let v = Refusal::from(r.refused(&body)).to_value();
        assert_eq!((v["site"]["addr"].as_str(), v["site"].get("index")), (Some("1.0.1.0.2.3"), None), "{v}");
    }

    /// Checks that a verdict's name is the token its rejection dispatches on.
    ///
    /// It is wire.md §Rejections' "key client behavior on the token, never on
    /// prose", the law over the families: `credential_refused` and
    /// `registry_refused` with a detail named by it, without one by their
    /// code, and any other code by itself, its detail prose (the mutant that
    /// drops a family from `name` faces `registry_refused` where the walk keys
    /// on its detail).
    #[test]
    fn a_verdicts_name_is_the_token_its_rejection_dispatches_on() {
        for code in ["credential_refused", "registry_refused", "out_of_bounds"] {
            for detail in [Some("a_token"), None] {
                let mut v = json!({"resp": "rejected", "code": code, "disposition": "permanent", "op": "insert"});
                if let Some(detail) = detail {
                    v["detail"] = json!(detail);
                }
                let r = skep_client::board::Rejection::of(&v).expect("a rejected document");
                assert_eq!(Refusal::from(r.refused(&v)).name(), r.key(), "{v}");
            }
        }
    }
}
