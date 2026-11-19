//! skep-client — the library every acting client embeds.
//!
//! The design is `client.md` (the skep-ux-design repo): what a person's own
//! client — the `skep` command, the bundled app's shell, the attendant —
//! needs to claim a board, open a signed session, keep its keys and check
//! what a board holds for it, and nothing a frontend needs. The modules are
//! §1.1's table, one each, listed bottom-up; `ARCHITECTURE.md` §The client
//! draws how they fit and the rules that cross them.
//!
//! The reading half, in every build — all a daemon embedding the dialer
//! takes:
//!
//! * [`origin`] — the canonical web origin, this crate's own reproduction of
//!   the daemon's grammar (AUTH-4.2; AUTH RES-61) under a vector-agreement
//!   test over the daemon's own admitted and refused strings (P5).
//! * [`address`] — the address grammar over the wire's dotted spelling: an
//!   account's parent, first child, doc 1 and its four well-known documents
//!   (the slots `MAILBOX_SLOT`, `BIO_SLOT`, `LINK_PAGE_SLOT` and
//!   `POLICY_SLOT`, at `well_known_of`), the document an address lies in,
//!   the parse into
//!   `skep_address`'s `Address`, and the namespace's principal depth every
//!   walk upward from a board-named account is held to.
//! * `hex` (private) — lowercase hex, the one spelling every hex this crate
//!   emits takes.
//! * [`dial`] — the one outbound dialer (`Dialer`) and its plain-HTTP arm:
//!   one `TcpStream` per request, `Connection: close`, `Content-Length`
//!   checked, no redirects, no proxy environment (wire.md §Transport), a
//!   frame exchange held to a deadline and its target and headers checked
//!   before any connection opens; the streamed form for the blob routes and
//!   `/events`; `https://` behind the `tls` feature. A dialer behind a
//!   reference, a box or an `Arc` is one, so a shell shares one between its
//!   boards and the resolver.
//! * [`halt`] — the one error family: `Halt`, `Refused`, `Blocked`, `Dial`,
//!   with §2.3's exit codes as the binary's mapping (AUTH-5.66).
//! * [`board`] — `Board { dialed, signed, dialer, term }`: the wire's
//!   endpoints, every token-bearing dial but the close through one `authed`
//!   exchange, the one reader of `Skepd-Session: closed` beside the close
//!   (P28), the token-free reads through `Board::guest`, `op_at`, `changes`
//!   and `changes_key`, which halt on that signal — save a read that hands
//!   `Board::op` no token, as the merge's reads as a guest, the feed
//!   consumer's document reads for the published index, and the grant reads
//!   and the deposit's ordinal read where no token is given do — and
//!   `H.1`'s pair read once per board (signed-ops D13); its child `frames`
//!   spells every frame this crate sends and the frames it lends an
//!   embedder: the reads, the paged link search (`window_four`,
//!   `window_ftt`, with the mail type `T_MAIL`), the line read
//!   (`line_numbers`) and the read by identity (`retrieve_i`) among them,
//!   the creation of a well-known document, slot named
//!   (`create_well_known_document`; the mailbox's, `create_mailbox`, which
//!   no code of the crate sends), and the copy by identity (`copy`) and
//!   the link whose `from` is content (`make_link_spec`, with the marks
//!   type `T_MARKS`) a mark of a draft is made of; its
//!   child `answers`
//!   decodes the read answers the crate reads but the registry reads',
//!   which `Board` decodes itself, and an envelope member a caller reads in
//!   place. Beside those the crate lends an embedder readers no code of its
//!   own calls, each of an answer the embedder dialed for itself:
//!   `merge_marker`, a draft's merge marker off a `doc_metadata` answer;
//!   `homes`, the count by home's rows; `line_numbers`, the line read's
//!   numbers; `whole_image`, a document's whole image; `history`, the
//!   retracted-links
//!   read's window; and `link_page`, a windowed link read's page, with the
//!   two tests of where a link's stored slots lie that a reader of such a
//!   search keeps by, `LinkValue::to_at_or_under` and
//!   `LinkValue::typed_at_or_under`, and `ToFilter` over the first.
//!   `Rejection::key` is the one token a refusal is dispatched on (wire.md
//!   §Rejections).
//! * [`derive`](mod@derive) — the pure derivations over board reads: the
//!   mode off `/health`'s pair (AUTH-5.86), AUTH-5.65's pre-check, the
//!   three-state key diagnosis at the set AUTH-5.21's walk reaches
//!   (AUTH-4.30 (i)), the principal of an address (AUTH-6.37), the address
//!   test that tells a hired agent's account (`derive::hirer_of`;
//!   AUTH-5.87), AUTH-5.66's `closed` predicate, and — behind `acting` —
//!   `derive::records`, the one
//!   admitted read of an account's credential records (AUTH-5.68,
//!   AUTH-2.113).
//! * [`text`] — the minimal changes that make one text into another,
//!   `minimal_changes`: the two matched as `difflib` matches them, by lines
//!   and then by the words of the lines that changed, a stretch too small
//!   to keep between two changes written again with them, and each change
//!   cut to what differs by `shared`, the trim. A function of two texts,
//!   which reads no board: an embedder that edits a draft's text writes
//!   the changes alone, so what stands between two of them keeps its
//!   identity (skep #1079). Its child `text::diff` plans a text's change by
//!   identity from two whole images (skep #1091): the stretches that stay,
//!   moved and stand again, the spans gone and the positions new,
//!   `Identity::of`, and over two line tables the edit script, its hunks
//!   and the notes a diff of two texts cannot make, `Identity::lines` — a
//!   moved block told as moved and a re-typed one as re-typed.
//!
//! Behind the default-on `acting` feature — everything that signs or holds a
//! key:
//!
//! * [`sign`] — the `Signer` seam over `skep_signature::HybridSigner`, and
//!   the bytes a signer signs: the session payload under `SESSION_TAG` /
//!   `SESSION_TAG_V2` (AUTH-6.4) and a credential record's `record` frame,
//!   `RecordFrame`, its rows named.
//! * [`sheet`] — the key file's one JSON spelling, its size bound and its
//!   refusals, `KeyFileError` (§3.2), the byline `Label` and its domain
//!   (AUTH-1.24), the `Seed` every secret is born into and the `SeedText`
//!   the sheet shows it as, each wiped on drop (AUTH-5.54 step 3), the R42
//!   grouping (AUTH-5.1) and the sheet's field list (AUTH-5.38).
//! * [`store`] — the `KeyStore` seam and `FileStore` (§3), the seed's
//!   custodian: a lookup answers a key's public facts and a stored key signs
//!   through `KeyStore::signer` alone (§3a); the halts the store's refusals
//!   render as (AUTH-5.67); and `Unappended`, the warning a binding line
//!   that cannot be appended answers (§3.7).
//! * [`person`] — the `Person` seam: the human moments in three classes,
//!   secret, consent and public, as types — a secret payload printing no key
//!   material; behind `test-hooks`, `person::scripted`, the scripted person
//!   a test drives.
//! * [`verify`] — the reader's verifier: `skep_identity`'s signature-filtered
//!   key table built over the admitted read under the board's claim, with
//!   this crate's signature check handed in, and a committed signature
//!   judged against the set that table opens as of the entry's base
//!   (AUTH-2.94; D14), a pure function of its caller's reads.
//! * [`resolve`] — the registry over this crate's dialer:
//!   `skep_resolve::Transport` over a `Dialer`, and the dial a registry
//!   mirror opens through, for an `https` root and an `http` one alike
//!   (REG-3.2); `root_hint`, a registry board's root-hint line read off the
//!   board as a guest (REG-3.39); and `resolve_address`, a cross-board
//!   address resolved to the board it lives on — its node field the prefix,
//!   its local form the prefix swapped for `1` (REG-1.63) — off a mirror of
//!   the registry kept under the caller's directory and read to the
//!   registry's head at every call (REG-3.7, REG-3.10), its answer a named
//!   state (REG-3.80).
//! * [`ceremony`] — the ceremonies in two layers: the compositions every
//!   walk runs over (P28) — `handshake`, `deposit`, `registry_record`,
//!   `registration`, `policy`, `first_session`, `backup`, `payload`,
//!   `preview`, `enumerate`, `trail`, `import`, `reads` — and the walks over
//!   them — `claim`, `enroll`, `recover`, `retire`, `rotate`, `handoff`,
//!   `accept`, `hire`, `console`. A walk
//!   names compositions and never another walk. `hire` is the owner's side
//!   of the hire ceremony (AUTH-5.58): an agent's account made beneath the
//!   owner's agent space, its first key record composed by the owner
//!   beside a custody pair, its home minted, and only then its principal.
//!   `registry_record` is the
//!   registry record an account deposits in its own doc 1 (REG-1.86),
//!   composed by `skep_registry`'s encoder and signed by a key of the
//!   home's account: a node account's endpoint, naming the deposit it
//!   replaces (REG-1.9, REG-1.10); and a registrar's binding, its three
//!   answers on a request's thread and its approval link, with the reads a
//!   door's console is built from (REG-2.18; REG-4.79; REG-4.123).
//!   `policy` is a door's admission policy (REG-4.131): well-known document
//!   5 of the door's account read as a chain of versions, the version
//!   standing at a position, a door with none, and the next version
//!   published from a file checked first. `console` is the registrar's
//!   console (REG-4.107): the queue read with the approval's check, the
//!   approval written in order and resumed by reading, the refused and the
//!   denied answers, and the unattended hand's pass over the queue.
//!   `registration` is an applicant's registration request (REG-4.67): the
//!   keys a door asks for made with no board and no account — the device
//!   key named or generated, the backup moment's node arm over the pairs
//!   the request generates — and the request that carries them, framed,
//!   signed once by the device key and checked; composed here, and written
//!   by another hand. At the module's root, beside the one composer of an
//!   `attest`, stands `create_well_known_document`: an account's document
//!   created at one of its well-known slots, signed where the slot's
//!   document is published (`well_known_frame`), and safe to repeat.
//! * [`share`] — the grant as this client composes and reads it (PUB-5.1,
//!   PUB-5.15): `share`, one document or one account opened to one account;
//!   `privash`, one draft opened to every account on the board and never a
//!   guest (PUB-5.108, Nelson's term); `revoke`; and the three lists —
//!   `issued`, `held` (R78's discovery read) and `privashed` (the board's
//!   universal set). Each write reads the state it acts on first — the
//!   key's for a grant, the grant's for a revocation — and sends no
//!   duplicate; a lost acknowledgement is read back, never re-sent. Beside
//!   the ceremonies and naming none: a grant is no credential.
//!
//! Behind the default-off `search` feature — the shell's half of search
//! (`client.md` §4e; the index itself is `skep-search`'s):
//!
//! * `search` — the feed consumer over `/changes` (one read per changed
//!   document per poll, in parts past the delivery budget, at the class the
//!   index takes), the index directory beside the key store (the modes, the
//!   lock, the save by rename, the aside), the resume at open, the session's
//!   triggers (widen, narrow, the refresh, the forget), the document index
//!   the plane reads, the state event's ten arms as a typed enum, the bridge
//!   call that composes the pair, and the jump's landing rule. A library API
//!   an embedder calls — the shell, skep-shell, is its embedder — and
//!   nothing in it assumes a page or a webview.
//!
//! Behind the default-off `merge` feature — merging versions, the editor's
//! act on a daughter (the design's merge record):
//!
//! * `merge` — the merge as a library: the pure core, `compose_runs` over
//!   the base's and the sides' run lists under the one rule; `compose`, the
//!   reads over a board in the record's order, writing nothing; `land` and
//!   `resume`, the one `publish` of the merged list from the head with its
//!   signed body, the claim's read, the record in a merge journal with its
//!   public link, and the draft landing; `verify`, the record's testimony
//!   recomputed; the record kind and the journal. The surfaces — the
//!   command, the attendant's call, the agent tool — are not this crate's:
//!   the command is skep-cli's `skep merge`.
//! * `history` — the restore, a draft's past state made current (B3-S7):
//!   `past`, the state read at a position through the merge's reader and
//!   mapped through the correspondence records so published words come back
//!   as published; `restore`, the one `set_arrangement` of it, no base and
//!   no merge, typed against the read. Behind `merge` because it rides that
//!   module's reader and write; the command is skep-cli's `skep restore`.
//!
//! No async runtime, no HTTP crate, no argument-parsing crate (§1.1's
//! dependency paragraph). The fence (§1.1): this crate reads no content save
//! credential records — those the admitted read names, and the one a
//! deposit reads back — the endpoint records of the home an endpoint is
//! deposited into, the takedown record a block names, and `H.1`'s pair;
//! `Board::op` is a general frame pipe for its embedders. The fence is a
//! statement about the default build: the `search` module, off by default,
//! is §4e's consumer and makes its reads only where an embedder turns the
//! feature on, as the frontend's shell does.

#![forbid(unsafe_code)]

pub mod address;
pub mod board;
pub mod derive;
pub mod dial;
pub mod halt;
pub mod origin;
pub mod text;

mod hex;

#[cfg(feature = "acting")]
pub mod ceremony;
#[cfg(feature = "acting")]
pub mod person;
#[cfg(feature = "acting")]
pub mod publication;
#[cfg(feature = "acting")]
pub mod resolve;
#[cfg(feature = "acting")]
pub mod share;
#[cfg(feature = "acting")]
pub mod sheet;
#[cfg(feature = "acting")]
pub mod sign;
#[cfg(feature = "acting")]
pub mod store;
#[cfg(feature = "acting")]
pub mod verify;

#[cfg(feature = "search")]
pub mod search;

#[cfg(feature = "merge")]
pub mod history;
#[cfg(feature = "merge")]
pub mod merge;

pub use board::{Board, Health, KeySet, Token};
pub use dial::{DialError, Dialer, PlainHttp, Request, Response};
pub use halt::{Blocked, Face, Halt, Refused};
pub use origin::{NotCanonical, Origin};

/// The auto-traits this crate promises without saying so.
///
/// A shell holds a `Board` across threads, and a halt crosses to whichever
/// thread reports it. A private field that revoked either would compile here
/// and break an embedder's build naming nothing — so it fails to compile
/// here instead.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Board>();
    assert_send_sync::<Halt>();
    assert_send_sync::<PlainHttp>();
    assert_send_sync::<Origin>();
};

/// The acting half's promises of the same kind.
///
/// A shell signs on whichever thread holds its board, so the signer a stored
/// key yields, the store that yields it and the session it opens cross
/// threads as the board does.
#[cfg(feature = "acting")]
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Box<dyn sign::Signer>>();
    assert_send_sync::<store::FileStore>();
    assert_send_sync::<ceremony::handshake::Session<'static>>();
};

/// The search half's promises (`search.md` §5.6).
///
/// The consumer stands between the feed thread that writes and the bridge's
/// search thread that reads, so it and every value that crosses its lock owe
/// `Send + Sync`.
#[cfg(feature = "search")]
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_send<T: Send>() {}
    assert_send_sync::<search::Consumer<'static>>();
    // The stream's reader lives on the one thread that loops over it, and
    // moves there.
    assert_send::<search::Events<'static>>();
    assert_send_sync::<search::Stop>();
    assert_send_sync::<search::SearchDir>();
    assert_send_sync::<search::State>();
    assert_send_sync::<search::SearchAnswer>();
    assert_send_sync::<search::Place>();
    assert_send_sync::<search::Landing>();
    assert_send_sync::<search::QueryTooLong>();
    assert_send_sync::<search::Poll>();
    assert_send_sync::<search::Orphan>();
};
