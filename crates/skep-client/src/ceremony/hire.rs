//! `hire` — the owner's side of the hire ceremony (AUTH-5.58, steps 2–7).
//!
//! An owner makes an agent's account beneath the space for their agents,
//! writes its first key record — the agent's one working key, carried in as
//! `--payload`, beside a custody pair the owner keeps — mints its home, and
//! only then prints its principal. The agent's own side is step 1,
//! `skep keygen --payload` on the agent's host, and no part of this walk.
//! The walk runs in AUTH-5.58's order, which is the rule's own ("MUST run as
//! this ordered path"), and every state resumes by reading (step 7; P4):
//!
//! * **The door.** The paste is read as a canonical record ahead of any
//!   read (P13; AUTH-2.130). Its tests are step 4's, below.
//! * **H0, the reads.** The owner's key (§3.5's lookup) and AUTH-5.65's
//!   pre-check at the owner's account `X`; `X` holds a set of its own (a
//!   topic reserves no agent space and no hire lands beneath it, AUTH-5.87)
//!   and is no agent's (an agent holds no agent space; its sub-hire is the
//!   owner's client's act); the space at `inc(X, 1)` holds no set of its
//!   own — where it does, no agent space stands at this account and the
//!   walk is unavailable there for good (AUTH-5.87's cells test; I3); the
//!   account a re-hire replaces (`--replaces`) is an agent of this space;
//!   and step 7's reads — a genesis already standing beneath this space for
//!   the payload's key, or a prefix an earlier run delegated and never
//!   seeded.
//! * **Step 2.** The hire's standing statements, ahead of every write:
//!   AUTH-5.78's copy verbatim from PUB-5.72, AUTH-5.79's guard mapping,
//!   AUTH-5.80's two statements scoped by the board's venue, the clause on
//!   the owner's later disavowal (AUTH RES-204), and on the anchored arm
//!   AUTH-5.44's hire line. Then, where the space for the owner's agents is
//!   not yet reserved, the account's own setup act (`first_session`, as
//!   every walk that owes AUTH-5.90 (iii)'s order runs it; AUTH-5.87's
//!   sentence said). Then the `delegate` of the next unallocated child
//!   beneath the agent space, from a session as the agent space — its
//!   principal one `effective_owner` read (AUTH-6.37), opened by reference
//!   under the owner's own key (AUTH-4.30 (i)) — under a client-minted
//!   `new_id` persisted before the frame and read back on resume
//!   (`delegate_persisted`; AUTH-5.19, AUTH-5.20).
//! * **Step 3.** The anchored arm, the default: the backup moment for the
//!   custody pair (`Venue::Hire`), each artifact carrying the agent's
//!   address and principal (AUTH-5.38), its two label boxes naming what the
//!   sheets must read apart from. The anchorless arm (`--anchorless`): the
//!   choice's site — AUTH-5.62's ruled sentence, its costs (i)–(iii) each
//!   naming loss beside compromise, (iv) supervision, the venue's own
//!   clause, AUTH-5.78's copy a second time — taken by a typed answer; no
//!   pair, no moment, and step 5 does not run.
//! * **Step 4.** The paste's tests, each ahead of the consent: the anchor
//!   flag, exactly one device-flagged entry (AUTH RES-211), a label that is
//!   not empty, and at a re-hire the payload's key against the
//!   predecessor's `enrolled` and `retired` lists; then the comparison
//!   beat, the owner's own act. A refusal here writes no genesis and says
//!   what the `delegate` left: the prefix stands, recoverable, and a re-run
//!   resumes at it. Only then the genesis — the owner's own composition
//!   (`DepositKind::Enroll`), never the arriving bytes: the payload's entry
//!   re-emitted member for member beside the pair's two anchor-flagged
//!   entries, three on the anchored arm and that one alone on the
//!   anchorless — homed in the agent space's doc 1, the agent's genesis
//!   registry (AUTH-2.62), signed by the owner's hand, from the session
//!   step 2 opened.
//! * **Step 5** (anchored). The agent's doc 1 minted, born published, from
//!   a session as the agent opened by the custody anchor the moment
//!   re-imported — never a fresh import — idempotent by reading; the
//!   material and the session dropped when the mint ends.
//! * **Step 6.** Only then the agent's principal, the hire's own `new_id`,
//!   for the owner to carry to the agent's host as its `SKEP_PRINCIPAL`
//!   (AUTH-5.61). On the anchorless arm no session as the agent can be
//!   opened here, so the principal is answered with the order the agent's
//!   own first session owes: the doc-1 mint first.
//! * **Step 7, the resume.** A re-run reads before it acts. A prefix an
//!   earlier run delegated and never seeded is resumed, and no second is
//!   delegated. A genesis that stands with the agent's doc 1 minted, or on
//!   the anchorless arm, is the hire standing whole: nothing is written and
//!   the principal is answered again. A genesis that stands beside a
//!   custody pair with the agent's doc 1 absent is a run that died between
//!   steps 4 and 5, its custody material dropped with it: the walk stops,
//!   writes nothing, answers no principal and names the act left.
//!
//! The roster is AUTH-5.91's read of the agent space's doc 1 — the genesis
//! link's `to` the agent's address, its record carrying the label — and
//! nothing is written for it. PUB-5.39's standing grant is the agent's own
//! to issue, and the attendant's side of the ceremony is not this walk's.

use std::path::PathBuf;

use skep_identity::{Enrollment, Fingerprint, PublicKey};
use skep_signature::HybridSigner;

use super::say;
use crate::address::{doc_1_of, parent_account};
use crate::board::{Board, Health, KeySet, KeySetAnswer, Scope};
use crate::ceremony::backup::{backup_moment_holding, hire_keep_line, AnchorArtifact, BackupOptions, Replaced, Venue};
use crate::ceremony::deposit::{deposit, Deposit, DepositHalt, DepositKind, DepositOutcome};
use crate::ceremony::enumerate::enroll_links_homed;
use crate::ceremony::first_session::{delegate_persisted, document_present, first_session, mint_home, Delegated, FirstSessionReads};
use crate::ceremony::handshake::{handshake, key_face, Site};
use crate::ceremony::payload::{compare_hire_payload, labelled, parse_payload, payload_text, refuse_anchor_flagged_at_hire, the_one_device_entry};
use crate::ceremony::reads::A4Cell;
use crate::derive::records::credential_records;
use crate::derive::{precheck, principal_of, Mode};
use crate::halt::{Face, Halt};
use crate::person::{Confirmation, Consent, Person};
use crate::sheet::{render_inert, Facts};
use crate::sign::Signer;
use crate::store::{arm4_face, Binding, FileStore, KeySelector, KeyStore, Purpose, StoreError};

/// The command's inputs.
#[derive(Debug, Clone)]
pub struct HireOptions {
    /// The owner's principal, whose store key opens the owner's sessions.
    ///
    /// The key is §3.5's lookup for (board, principal): its binding, else
    /// the store's lone device key.
    pub principal: u64,
    /// `--payload <file|->`: the agent's key record, one device-flagged entry.
    ///
    /// It is what `skep keygen --payload` printed on the agent's host.
    pub payload: Vec<u8>,
    /// `--anchorless`: the custody pair declined (AUTH-5.58 step 3).
    pub anchorless: bool,
    /// `--replaces <address>`: the agent's account this hire replaces.
    pub replaces: Option<String>,
    /// `--anchor-out`, once per custody anchor.
    pub anchor_out: Vec<PathBuf>,
    /// `--paper`: the sheets printed besides, and the re-type asked.
    pub paper: bool,
    /// The machine's host name, for the label boxes' per-run default.
    pub host_name: String,
    /// The date, for the same per-run default.
    pub date: String,
}

/// What the walk answers: the agent's coordinates, and what it wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hired {
    /// The agent's account, its principal and the board's origin.
    ///
    /// The principal is the hire's own `new_id`: the one coordinate the
    /// agent cannot derive, which the owner carries to its host as its
    /// `SKEP_PRINCIPAL` (AUTH-5.58 step 6).
    pub facts: Facts,
    /// The space the agent sits beneath, `inc(X, 1)`.
    ///
    /// Its doc 1 holds the hire's record, which the roster reads
    /// (AUTH-5.91).
    pub agent_space: String,
    /// The agent's working key, as the payload named it.
    pub key: Fingerprint,
    /// The working key's label, committed by the genesis.
    pub label: Option<String>,
    /// The custody pair this run exported — public facts alone.
    ///
    /// It is empty on the anchorless arm, and where the hire already stood.
    pub anchors: Vec<AnchorArtifact>,
    /// Whether the agent's set holds no custody pair.
    pub anchorless: bool,
    /// Whether this run minted the agent's doc 1 (step 5).
    pub minted_home: bool,
    /// Whether the hire already stood whole: this run wrote nothing.
    pub already: bool,
    /// The warnings the walk raised.
    pub warnings: Vec<String>,
}

/// AUTH-5.78's copy, each clause verbatim from PUB-5.72, the authority.
///
/// They are, in the copy's own order: the depth-and-permanence sentence
/// with the publish clause as ruled, the repetition clause, the reach
/// clause, the onward tier clause with its publish half and its disclosure
/// half, and the standing machinery clause. The copy is made once per
/// standing moment: ahead of the `delegate`, and at the anchorless choice
/// beside AUTH-5.62's costs.
pub const HIRE_COPY: [(&str, &str); 7] = [
    (
        "AUTH-5.78",
        "this agent can read every draft of yours under you — every revision, removed text included, back to this board's floor — and unlike a share, this cannot be revoked: the account stays under you permanently. The agent can publish its own documents, which may quote what it reads. Quotes stay linked to your originals. Nothing but this rule stops it from restating what it reads in its own words — and whatever it publishes is public forever.",
    ),
    (
        "AUTH-5.78 (repetition)",
        "it can do this repeatedly, at machine rate, for as long as the account stands, and the series shows how your draft was shaped and how much of it existed over that time",
    ),
    (
        "AUTH-5.78 (reach)",
        "it does not have to publish anything to do this: it can keep its own copy of what it reads private and share that copy with every account on this board, and only it can withdraw that share",
    ),
    (
        "AUTH-5.78 (onward tier)",
        "it can create further accounts beneath itself, permanently and under your prefix, keyed to whoever it chooses; each gets a permanent public home document here and its enrollment is a permanent public record here; whoever it keys reads every draft of yours this agent reads, and you cannot remove them",
    ),
    (
        "AUTH-5.78 (onward tier, publish)",
        "whoever it keys can also PUBLISH under your prefix: what they publish is permanent public history here, counted under your account and shown as published by them, a delegate under you — and no rail setting of yours reaches those mints; you see them after the fact, in the supervision feed",
    ),
    (
        "AUTH-5.78 (onward tier, disclosure)",
        "whoever it keys can do with your drafts everything this agent can: publish forks of them, keep private copies shared with every account on this board, and re-create their links on a public page — each disclosing how your draft is laid out, repeatedly, for as long as the account stands — and nothing of yours takes any of it back.",
    ),
    (
        "AUTH-5.78 (standing machinery)",
        "this agent can leave standing machinery on this board — rules it registers that keep writing at other people's documents after its keys are gone, publicly and permanently — and nothing of yours stops it.",
    ),
];

/// Says AUTH-5.78's copy, clause by clause.
fn hire_copy(person: &mut dyn Person) {
    for (rule, clause) in HIRE_COPY {
        say(person, rule, clause);
    }
}

/// Returns the reader class of a permanent public record at this venue.
///
/// AUTH-5.80 scopes its two statements as AUTH-5.85 scopes its sibling: at
/// the hosted tiers the reader class is the board's readers and its
/// mirrors; at a notebook it is the machine the board runs on, where no
/// mirror holds the board.
fn reader_class(cell: &A4Cell) -> &'static str {
    match cell {
        A4Cell::LoopbackNotebook => {
            "at this notebook the reader class is this machine: no mirror holds this board and it can never be made public, and \
             anything running on this machine reads it"
        }
        A4Cell::BindOverrideNotebook => {
            "at this notebook the reader class is this machine and every party its bind-override admits: no mirror holds this board"
        }
        A4Cell::Served | A4Cell::HandoffRecipient { .. } => "at this board the reader class is the board's readers and its mirrors",
    }
}

/// Says the hire's standing statements, ahead of every write.
///
/// AUTH-5.58 step 2: AUTH-5.78's copy, AUTH-5.79's guard mapping, AUTH-5.80's
/// two statements scoped by venue, and the clause on the owner's later
/// disavowal (AUTH RES-204), whose string is this walk's. Beside them, what
/// the arm this run takes will ask of the owner: on the anchored arm
/// AUTH-5.44's hire line, said here once ahead of the first permanent write
/// and again by the backup moment where the sheets stand; on the anchorless
/// arm that the choice's costs are stated at its site. At a re-hire the
/// account being replaced is named.
fn standing_statements(person: &mut dyn Person, cell: &A4Cell, anchorless: bool, replaced: Option<&Replaced>) {
    say(
        person,
        "AUTH-5.58 step 2",
        "THE HIRE'S STANDING STATEMENTS, ahead of every write: hiring makes a permanent account under your own, and what that account \
         can do, and what no act of yours takes back, is stated here once.",
    );
    hire_copy(person);
    say(
        person,
        "AUTH-5.79",
        "WHICH GUARD reaches which form: what this agent reads it can turn public by its own act in FOUR forms. The two MINT forms — a \
         version-fork of your draft born published, and a fresh document created from its bytes — are keyed on the mint's resolved \
         publication state: \"the rail can stop this where you set it\" (a rail set `mint-published: no` refuses both, the flagless \
         version of a published source included). The two MINT-FREE forms — the re-insert of what it read into a published home it \
         already owns, its doc 1 above all, and a copy of your draft's runs into such a home, disclosing its arrangement rather than \
         its bytes — mint nothing, are reachable by NO rail setting and show in no read of its mints: \"only this sentence stops \
         this, ever\". The board's gate on public, permanent writes does not stand in for this mapping: an agent signs every write, so \
         every form above passes it. This command sets no rail: one is set where the agent's own runtime takes one.",
    );
    let readers = reader_class(cell);
    say(
        person,
        "AUTH-5.80 (home)",
        format!("\"this agent's home document is public from birth, and every edit it makes there — including what it later removes — is public history.\" — {readers}."),
    );
    say(
        person,
        "AUTH-5.80 (record)",
        format!(
            "\"hiring this agent writes a permanent record in the home document of the space for this account's agents — its name and \
             its keys — and that record stands there forever, whether or not this agent ever writes anything.\" — {readers}."
        ),
    );
    say(
        person,
        "AUTH-5.58 step 2 (disavowal)",
        "this agent's first key record is written and signed by YOUR key. If you ever disavow what that key wrote over a span that \
         covers this hire — after its theft, say — this record reads as DISAVOWED wherever a reader shows it, while the board's \
         reading of the keys is untouched and the agent's account stands exactly as it was: a disavowal un-hires nothing.",
    );
    if let Some(replaced) = replaced {
        say(
            person,
            "AUTH-5.58 step 3 (re-hire)",
            format!(
                "RE-HIRE: this hire REPLACES {}. That account never goes away — stopped, it stands inert under its own custody sheets; \
                 unstopped, it is live — so this one is named apart from it: its sheets at the two boxes below, and its working \
                 key's label on the agent's host, which you are shown before you commit it. A payload key that already stands in \
                 that account's set is no fresh key and is refused.",
                replaced.account
            ),
        );
    }
    if anchorless {
        say(
            person,
            "AUTH-5.58 step 3",
            "`--anchorless` DECLINES the custody pair. The pair is the default, and what declining it costs is stated at the choice — \
             after the agent's account is delegated and ahead of its first key record — where it takes a typed answer.",
        );
    } else {
        say(
            person,
            "AUTH-5.44 (hire)",
            format!(
                "THE CUSTODY PAIR: this hire makes two anchor sheets for this agent, fresh for it, yours to keep and never on the \
                 agent's host (AUTH-5.62) — a sixth agent is a twelfth sheet. Of them: {}",
                hire_keep_line("sheets", None)
            ),
        );
    }
}

/// Says the anchorless choice at its site, and takes its typed answer.
///
/// AUTH-5.58 step 3 is the carrier of AUTH-5.62's ruled sentence for an
/// owner-run hire: every choice that leaves an account without an enrolled
/// anchor says, at the choice, what only an anchor session could do here
/// and what a device key alone can do after. Beside it the three costs,
/// each naming loss beside compromise; (iv) supervision, a statement and no
/// cost; the venue's own clause — the shipping venue's at a notebook, the
/// hosted tiers' at a served board; and AUTH-5.78's copy, which that rule
/// places at this moment too. The flag is the decline and the clause its
/// confirmation, taken by a typed answer and never by the flag alone.
///
/// # Errors
///
/// An abandoned or declined confirmation halts; the caller says what the
/// `delegate` left.
fn anchorless_choice(person: &mut dyn Person, cell: &A4Cell, health: &Health, agent: &str) -> Result<(), Halt> {
    say(
        person,
        "AUTH-5.62",
        format!(
            "THE ANCHORLESS CHOICE (`--anchorless`), at {agent} — WHAT ONLY AN ANCHOR SESSION COULD DO HERE AND WHAT A DEVICE KEY ALONE \
             CAN DO AFTER: only a session an anchor of this account opened lets YOU act as this agent at all — to mint its home for \
             it, to stop it by retiring its working key, to re-key it after a loss or a leak — and a set born with no anchor can never \
             gain one, since a later anchor enrollment needs an anchor session too (AUTH-3.20/3.22). After this write the working key \
             alone does everything this account can do, for whoever holds it or a copy of it: it enrolls further keys and retires \
             itself out, and nothing of yours outranks it."
        ),
    );
    say(
        person,
        "AUTH-5.62 (i)",
        "(i) COMPROMISE of the working key is a PERMANENT TAKEOVER: its holder enrolls a key of their own and retires the working key, \
         and a retired key never re-enters the set (AUTH-2.98). LOSS takes the same account from the agent as finally: the working key \
         is the one artifact here with no backup, so a failed disk under its file is as terminal as an attacker, and the likelier \
         arrival.",
    );
    say(
        person,
        "AUTH-5.62 (ii)",
        "(ii) the one act that stops or re-keys an agent does not exist for this account: retiring its only key is refused \
         (`would_empty`), and enrolling a replacement takes a session only the working key opens — after a COMPROMISE the compromised \
         host's, and after a LOSS no party's at all.",
    );
    say(
        person,
        "AUTH-5.62 (iii)",
        "(iii) what remains is a LIVE principal inside your own prefix, in every mode — under another party's keys after a COMPROMISE, \
         under nobody's after a LOSS — and no read of this board tells it from a healthy agent.",
    );
    say(
        person,
        "AUTH-5.62 (iv)",
        "(iv) SUPERVISION — a statement, not a cost: your account contains this agent's, so you read this agent's drafts by the rule, \
         from your own session, from the first byte, on this arm and the anchored arm alike, and no act of the agent's takes that back. \
         What you cannot do on this arm is open a session AS the agent.",
    );
    let venue = match cell {
        A4Cell::LoopbackNotebook | A4Cell::BindOverrideNotebook => {
            let bare = if Mode::of(health) == Mode::ClaimedPermissive {
                "this board's local trust is ON, so any party on this machine binds as YOU with no key at all, reading every draft you \
                 have written and writing as you"
            } else {
                "wherever this board's local trust is on, any party on this machine binds as YOU with no key at all, reading every \
                 draft you have written and writing as you"
            };
            format!(
                "AT THIS VENUE: on a notebook the agent's host is YOUR machine, so the compromise a custody pair is kept against takes \
                 the BOARD as well — {bare}. A pair here would counterweight a compromise of the working key and never the machine's; \
                 that is said now, at the choice, and not first at a recovery."
            )
        }
        A4Cell::Served | A4Cell::HandoffRecipient { .. } => "AT THIS VENUE: on a hosted board an agent whose key file sits in a container stays signable by the party that runs that \
             container, and the custody pair you are declining is the ONLY counterweight to that host (AUTH-4.56): declined, nothing \
             of yours outranks what the host can sign as this agent."
            .to_string(),
    };
    say(person, "AUTH-5.62 (venue)", venue);
    hire_copy(person);
    let typed = person
        .confirm_typed(Consent(Confirmation {
            text: format!("CONFIRM THE ANCHORLESS HIRE at {agent} — type `anchorless` to accept these costs, or `no`"),
            expected: "anchorless".into(),
        }))
        .map_err(|_| Halt::face("the anchorless choice was abandoned", "the person left at the choice", "run `skep hire` again when ready"))?;
    if typed.trim() != "anchorless" {
        return Err(Halt::face(
            "the anchorless choice was not confirmed",
            "the typed answer was not `anchorless`",
            "run `skep hire` again without `--anchorless` to take the custody pair, or confirm the choice",
        ));
    }
    Ok(())
}

/// Returns `h` as a halt that stops the hire before its genesis.
///
/// AUTH-5.58 step 2: the `delegate` ahead of the genesis is the recoverable
/// state. The face says what that write left — the prefix standing, keyless,
/// which a re-run resumes at by reading — and, where this run exported a
/// pair, that its sheets name that account and open nothing. A halt that is
/// no face — a refusal, a transport fault, a block — passes as it came.
fn before_the_genesis(h: Halt, agent: &str, pair_exported: bool) -> Halt {
    let Halt::Halt(face) = h else { return h };
    let sheets = if pair_exported {
        " The two custody sheets this run exported name that account and open nothing, ever: destroy them, or keep them plainly \
         marked dead and never beside a live pair — a re-run makes a fresh pair."
    } else {
        ""
    };
    Halt::Halt(Face {
        state: format!("{} — the hire stops before its first key record", face.state),
        cause: format!(
            "{}; no genesis was written. {agent} stands delegated beneath your agent space and holds no key — a permanent prefix, and \
             recoverable: `skep hire` run again resumes at this same address by reading, and delegates no second.{sheets}",
            face.cause
        ),
        act: face.act,
        path: face.path,
    })
}

/// Returns the halt of a hire that died between its genesis and its mint.
///
/// The owner's ruling for the state AUTH-5.58 does not price: the genesis
/// stands beside a custody pair, the agent's doc 1 is absent, and the
/// custody material the dead run held was dropped with it. The walk stops,
/// writes nothing and answers no principal — the order is genesis, the
/// owner's mint, and only then `SKEP_PRINCIPAL` (AUTH-5.61) — and names the
/// act left; it never re-imports a sheet on its own.
fn unminted_stop(agent: &str, home: &str) -> Halt {
    Halt::face(
        format!("the hire of {agent} stopped between its first key record and its doc-1 mint, and this run writes nothing"),
        format!(
            "`key_set({agent})` holds this payload's key beside a custody pair, and {home} is NOT yet minted: an earlier run wrote the \
             genesis and ended before AUTH-5.58 step 5, and the custody material it held was dropped with it. The order is the \
             genesis, then the owner's mint of the agent's doc 1, and only then its principal (AUTH-5.61) — an agent woken first \
             puts its own first write in the born-published slot — so no principal is answered here"
        ),
        format!(
            "the act left is the mint of {home} from a session AS this agent, opened by a CUSTODY ANCHOR from its sheet: this command \
             never re-imports a sheet on its own. No command of this version performs that mint alone — `skep recover --anchor <sheet>` \
             at the principal the sheet names, answered \"an agent's\", opens that session, mints the home and then RETIRES the agent's \
             working key (the stop), after which `skep hire --replaces {agent}` hires its replacement"
        ),
    )
}

/// The account a re-hire replaces, as H0 read it.
struct Predecessor {
    account: String,
    /// The labels its first key record carries, anchors first.
    labels: Vec<String>,
}

/// Reads the account `--replaces` names (AUTH-5.58 steps 3 and 4).
///
/// It is an agent of this space — a child of `space` holding a set of its
/// own — and its first key record's labels are read for the boxes' copy,
/// by the admitted read, priced before it runs (AUTH-5.68).
///
/// # Errors
///
/// An address that is no child of the agent space, or that holds no set,
/// halts; and the reads' errors.
fn predecessor(board: &Board, person: &mut dyn Person, space: &str, address: &str, own: &[(Fingerprint, PublicKey)]) -> Result<Predecessor, Halt> {
    if parent_account(address).as_deref() != Some(space) {
        return Err(Halt::face(
            format!("{address} is no agent of yours: it is not a child of your agent space {space}"),
            "`--replaces` names the agent's account this hire replaces, and your agents are the children of the space for them \
             (AUTH-5.87; AUTH-5.58 step 3)",
            format!("name the account being replaced, `{space}.<n>`, or leave `--replaces` out for a first hire"),
        ));
    }
    let keyed = matches!(board.key_set(address)?, KeySetAnswer::Set(set) if !set.is_empty());
    if !keyed {
        return Err(Halt::face(
            format!("{address} holds no key set: no hire stands there to replace"),
            "`key_set` answers it no account, or an empty set — a prefix delegated and never seeded is resumed by a re-run, and is \
             no predecessor (AUTH-5.58 step 7)",
            "leave `--replaces` out, or name the hired agent's account",
        ));
    }
    say(
        person,
        "AUTH-5.68 (cost)",
        format!("reading the credential records of {address}, the account this hire replaces, for the labels its sheets and its key carry — a discovery, then per record two frames and a bisection over /op-at"),
    );
    let records = credential_records(board, address, own)?;
    let mut entries: Vec<&Enrollment> = records.genesis().map(|g| g.enrolled.iter().collect()).unwrap_or_default();
    entries.sort_by_key(|e| !e.anchor);
    let labels = entries.iter().filter_map(|e| e.label().map(str::to_string)).collect();
    Ok(Predecessor { account: address.to_string(), labels })
}

/// Refuses a payload key that stands in the predecessor's set.
///
/// AUTH-5.58 step 4's re-hire test, AUTH-5.64's own fetch test taken
/// against the account being replaced: a payload fingerprint standing in
/// its `enrolled` or its `retired` list is not a fresh key (I4, AUTH-2.98)
/// — a replacement host provisioned from the same image serves the
/// predecessor's working key, and every other test passes it, since the
/// successor has no set yet. Untested, the genesis would latch the old
/// fingerprint into the new account. The set is read where the test runs.
///
/// # Errors
///
/// A key found in either list halts; and the read's errors.
fn fresh_against(board: &Board, replaced: &Predecessor, entry: &Enrollment) -> Result<(), Halt> {
    let set = match board.key_set(&replaced.account)? {
        KeySetAnswer::Set(set) => set,
        KeySetAnswer::NotAnAccount => KeySet::default(),
    };
    let fp = Fingerprint::of(&entry.key);
    let list = if set.enrolled(&fp).is_some() {
        "enrolled"
    } else if set.retired(&fp).is_some() {
        "retired"
    } else {
        return Ok(());
    };
    Err(Halt::face(
        format!("the payload's key {fp} is NOT A FRESH KEY: it stands {list} at {}, the account this hire replaces", replaced.account),
        "AUTH-5.58 step 4's re-hire test (AUTH-5.64's fetch test; I4, AUTH-2.98): a replacement host provisioned from the same image \
         or backup serves its predecessor's working key, and committed here the genesis would latch that fingerprint into the new \
         account — whoever holds its private half would own the successor from its birth",
        "generate a NEW key on a clean host — `skep keygen --label <name> --payload` there — and run `skep hire --replaces` again \
         with its record",
    ))
}

/// A hire's genesis found standing beneath the agent space.
struct Standing {
    account: String,
    set: KeySet,
}

/// Returns the agent beneath `space` whose set enrolls a payload key.
///
/// Step 7's first read, made off the board and never off the store: the
/// genesis records homed in the agent space's doc 1 name every agent of
/// the space (AUTH-5.91's read), and the one whose set enrolls this
/// payload's key is this hire, written by an earlier run. `except` is the
/// account a re-hire replaces, whose set step 4's own test reads.
///
/// # Errors
///
/// The reads' errors.
fn standing_hire(board: &Board, space: &str, payload: &[Fingerprint], except: Option<&str>) -> Result<Option<Standing>, Halt> {
    let mut seen: Vec<String> = Vec::new();
    for (_, subject) in enroll_links_homed(board, &doc_1_of(space))? {
        if seen.contains(&subject) || Some(subject.as_str()) == except || parent_account(&subject).as_deref() != Some(space) {
            continue;
        }
        seen.push(subject.clone());
        let KeySetAnswer::Set(set) = board.key_set(&subject)? else { continue };
        if payload.iter().any(|fp| set.enrolled(fp).is_some()) {
            return Ok(Some(Standing { account: subject, set }));
        }
    }
    Ok(None)
}

/// A prefix an earlier run of this store left beneath the agent space.
enum Pending {
    /// The `delegate` committed and no genesis stands: resumed, never a
    /// second.
    Delegated { account: String, principal: u64 },
    /// The `new_id` was persisted and its `delegate` never landed.
    ///
    /// It is sent again under the same id where the address is still the
    /// frontier (AUTH-5.19).
    Unsent { account: String, principal: u64 },
}

/// Returns what the store's persist-first lines say of this agent space.
///
/// §4.3's rule: a line is a cache and never a source, so each is read back
/// by `principal_prefix` (AUTH-5.19) and the account's set off the board. A
/// line whose `delegate` committed at its address, the account holding no
/// key, is a hire stopped before its genesis — step 2's recoverable state.
/// A store whose bindings cannot be read answers none, and the `delegate`
/// goes out under a fresh `new_id`.
///
/// # Errors
///
/// The reads' errors.
fn pending_prefix(board: &Board, store: &FileStore, space: &str) -> Result<Option<Pending>, Halt> {
    let lines: Vec<(u64, String)> = store
        .all_bindings()
        .unwrap_or_default()
        .into_iter()
        .rev()
        .filter_map(|b| match b {
            Binding::Enrollment { origin, principal, account, .. } if origin == *board.dialed() && parent_account(&account).as_deref() == Some(space) => Some((principal, account)),
            _ => None,
        })
        .collect();
    let mut unsent = None;
    let mut seen: Vec<&str> = Vec::new();
    for (principal, account) in &lines {
        if seen.contains(&account.as_str()) {
            continue;
        }
        seen.push(account);
        match board.principal_prefix(*principal)? {
            Some(seated) if seated == *account => {
                let keyless = matches!(board.key_set(account)?, KeySetAnswer::Set(set) if set.is_empty());
                if keyless {
                    return Ok(Some(Pending::Delegated { account: account.clone(), principal: *principal }));
                }
            }
            None if unsent.is_none() => unsent = Some(Pending::Unsent { account: account.clone(), principal: *principal }),
            _ => {}
        }
    }
    Ok(unsent)
}

/// Answers a hire found standing (step 7), writing nothing.
///
/// # Errors
///
/// The paste's tests; a seat the board does not answer for; the doc-1
/// read's halts; and the stop where the genesis stands beside a custody
/// pair and the agent's doc 1 is not minted.
fn answer_standing(board: &Board, person: &mut dyn Person, standing: Standing, space: &str, entries: &[Enrollment], asked_anchorless: bool) -> Result<Hired, Halt> {
    refuse_anchor_flagged_at_hire(entries)?;
    let entry = the_one_device_entry(entries)?;
    let agent = standing.account;
    let home = doc_1_of(&agent);
    let anchorless = !standing.set.has_anchor();
    if !anchorless && !document_present(board, &home)? {
        return Err(unminted_stop(&agent, &home));
    }
    let Some(principal) = principal_of(board, &agent)? else {
        return Err(Halt::face(format!("{agent} holds a key set and the board answers no seat for it"), "`effective_owner` names no principal at an account `key_set` answers for", "this is a fault in the board; nothing was written"));
    };
    say(
        person,
        "AUTH-5.58 step 7",
        format!("this hire already stands: `key_set({agent})` enrolls the payload's key, read off the board — nothing is delegated, written or minted again"),
    );
    if anchorless {
        say(
            person,
            "AUTH-5.61",
            format!(
                "{agent} is ANCHORLESS, permanently — a set born with no anchor can never gain one{}. No session as it can be opened \
                 from here, so its doc 1 is the agent's own to mint: the first act of its first session, the flag affirmative, ahead of \
                 anything else it writes.",
                if asked_anchorless { "" } else { ", so this run's custody pair is not made" }
            ),
        );
    } else if asked_anchorless {
        say(person, "AUTH-5.58 step 7", format!("this run asked for the anchorless arm, and the genesis that stands at {agent} holds a custody pair: the pair stands, and its two sheets are the ones the earlier run exported"));
    }
    Ok(Hired {
        facts: Facts { account: agent, principal, origin: board.dialed().clone() },
        agent_space: space.to_string(),
        key: Fingerprint::of(&entry.key),
        label: entry.label().map(str::to_string),
        anchors: Vec::new(),
        anchorless,
        minted_home: false,
        already: true,
        warnings: Vec::new(),
    })
}

/// Runs the walk.
///
/// # Errors
///
/// In the walk's order: a paste that is not UTF-8 or no canonical record;
/// arm 4's fork and the store's refusals; the pre-check and the owner's key
/// face; an owner's account that opens by reference, or is an agent's; an
/// agent space that holds a set of its own; `--replaces` naming no agent of
/// this space; a hire found standing whose doc 1 is not minted, and the
/// paste's tests where one stands whole; the setup act's halts, and an agent
/// space it could not reserve; the handshake as the agent space; a frontier
/// that names no child, or that another session took; the `delegate`'s
/// halts. Past the `delegate`, each saying what it left: the backup moment
/// abandoned, or the anchorless choice unconfirmed; an anchor-flagged entry,
/// device-flagged entries that are not exactly one, an empty label, a key
/// that stands in the predecessor's set; the comparison declined or
/// abandoned; and the genesis's halts. Past the genesis: the custody
/// anchor's session and the mint's halts, each naming the state a re-run
/// stops at.
///
/// # Panics
///
/// Panics if `Enrollment::new` refuses a label the anchor box admitted; the
/// box admits only labels it takes, so the `expect` never fires.
pub fn hire(board: &Board, store: &FileStore, person: &mut dyn Person, opts: &HireOptions) -> Result<Hired, Halt> {
    // The paste, read as a canonical record at the door — ahead of any read
    // (P13). Its tests are step 4's, in the rule's order.
    let text = payload_text(&opts.payload)?;
    let entries = parse_payload(&text)?;
    let payload_fps: Vec<Fingerprint> = entries.iter().map(|e| Fingerprint::of(&e.key)).collect();
    // H0: the owner's key and account.
    let key = match store.select(&KeySelector::Board { origin: board.dialed(), principal: Some(opts.principal) }, Purpose::Sign) {
        Ok(key) => key,
        Err(StoreError::NoSelection { keys }) => return Err(arm4_face(store, &keys, Mode::of(&board.health()?))),
        Err(e) => return Err(e.into()),
    };
    let device = store.signer(&KeySelector::Path(&key.path))?;
    let pre = precheck(board, opts.principal, &key.fingerprint)?;
    let own = [(key.fingerprint, key.public.clone())];
    key_face(board, &pre.walk, &key.fingerprint, &own, Site::Hire)?;
    let owner = pre.account.clone();
    if pre.walk.by_reference() {
        return Err(Halt::face(
            format!("{owner} holds no key set of its own, and no hire lands beneath it"),
            format!(
                "it opens by reference to the set at {}: a topic holds no set and reserves no agent space, and the holder's agents are \
                 at that account's own agent space, working on a topic by grant (AUTH-5.87)",
                pre.walk.set_account
            ),
            format!("hire from the account whose set this is — {}, with its own `--principal`", pre.walk.set_account),
        ));
    }
    let setup = FirstSessionReads::take(board, &owner, &key.fingerprint, Some(store))?;
    if let Some(above) = &setup.hired_by {
        return Err(Halt::face(
            format!("{owner} is itself a hired agent's account, and an agent holds no agent space"),
            format!("its first child is its first worker (AUTH-5.63), and an agent's sub-hire is a hire it proposes and its owner's client performs, landing as a sibling beneath the agent space of {above} (AUTH-5.87)"),
            format!("run `skep hire` as the owner, at {above}"),
        ));
    }
    let space = setup.agent_space.clone();
    let space_home = doc_1_of(&space);
    // AUTH-5.87's cells test: the space is the owner's agents' exactly while
    // its own set is empty; any genesis there ended it, permanently.
    if matches!(board.key_set(&space)?, KeySetAnswer::Set(set) if !set.is_empty()) {
        return Err(Halt::face(
            format!("no agent space stands at {owner}: {space} holds a key set of its own"),
            "a NON-EMPTY `key_set` at the first sub-account is the signal that the account was handed away — seeded before this \
             account came to you, given away on purpose, or seized under a stolen key — and that set never re-empties (AUTH-5.87's \
             cells test; I3), so no hire can ever land beneath it",
            "the hire door at this account is closed for good; agents already hired beneath that space keep their own sets and \
             custody sheets, and a new agent needs another account of yours",
        ));
    }
    let cell = A4Cell::venue(board, &pre.health);
    let replaced = match &opts.replaces {
        Some(address) => Some(predecessor(board, person, &space, address.trim(), &own)?),
        None => None,
    };
    // Step 7's reads, ahead of every write: a genesis an earlier run of this
    // hire wrote, then a prefix one delegated and never seeded.
    if setup.agent_space_home_present {
        if let Some(standing) = standing_hire(board, &space, &payload_fps, replaced.as_ref().map(|r| r.account.as_str()))? {
            return answer_standing(board, person, standing, &space, &entries, opts.anchorless);
        }
    }
    let pending = pending_prefix(board, store, &space)?;

    // Step 2: the standing statements, ahead of every write.
    let venue_replaced = replaced.as_ref().map(|r| Replaced { account: r.account.clone(), labels: r.labels.clone() });
    standing_statements(person, &cell, opts.anchorless, venue_replaced.as_ref());
    let mut warnings = Vec::new();
    // The space for the owner's agents, where its reservation is still owed:
    // the account's own setup act, in its pinned order (AUTH-5.87).
    let space_principal = match setup.agent_space_principal.filter(|_| setup.agent_space_home_present) {
        Some(principal) => principal,
        None => {
            say(person, "AUTH-5.87", format!("the space for your agents is not yet reserved at {owner}: this account's own setup act runs first — creating your account also creates a space for your agents beneath it, and its home"));
            let as_owner = handshake(board, Scope::Content, &*device, opts.principal, Site::Hire)?;
            let done = first_session(board, &setup, &as_owner, &*device, Some(store));
            let _ = as_owner.close();
            let done = done?;
            warnings.extend(done.warnings.clone());
            match (done.setup_stopped_seeded, done.setup_skipped, done.agent_space_principal) {
                (false, None, Some(principal)) => principal,
                (true, ..) => {
                    return Err(Halt::face(
                        format!("no agent space stands at {owner}: {space} was seeded by another hand"),
                        "the setup act met a first sub-account already holding a set of its own, and adopts nothing (AUTH-5.87's residue cell; AUTH-5.90 (iii))",
                        "the hire door at this account is closed for good",
                    ))
                }
                (_, Some(diagnosis), _) => {
                    return Err(Halt::face(
                        format!("the space for your agents could not be reserved: this key stands {diagnosis} in the set that opens {space}"),
                        "the setup act is sent not at all where its key is not enrolled there (P13)",
                        "run `skep hire` with a key enrolled at your account",
                    ))
                }
                (false, None, None) => return Err(Halt::face(format!("{space} has no seat after the setup act"), "the setup act answered no principal for the agent space", "run `skep hire` again: the setup act resumes by reading")),
            }
        }
    };
    // The session as the agent space, by reference under the owner's own key
    // (AUTH-4.30 (i)) — the `delegate`'s and the genesis's one session, full:
    // a genesis is a credential deposit. Every halt below closes it on its
    // drop.
    let as_space = handshake(board, Scope::Full, &*device, space_principal, Site::Hire)?;
    let (agent, agent_principal) = match pending {
        Some(Pending::Delegated { account, principal }) => {
            say(
                person,
                "AUTH-5.58 step 7",
                format!(
                    "resuming at {account}: an earlier run delegated it and wrote no key record — found by reading, no second prefix \
                     is delegated. Any custody sheet that run exported names this account and opens nothing: destroy it, or keep it \
                     plainly marked dead."
                ),
            );
            (account, principal)
        }
        unsent => {
            let Some(frontier) = board.next_account_prefix(&space)?.filter(|f| parent_account(f).as_deref() == Some(space.as_str())) else {
                return Err(Halt::face(
                    format!("the board names no next account beneath {space}"),
                    "`next_account_prefix` answered no child of the agent space: the space is full to the namespace's depth, or this is a fault in the board",
                    "nothing was written",
                ));
            };
            let cached = match unsent {
                Some(Pending::Unsent { account, principal }) if account == frontier => Some(principal),
                _ => None,
            };
            let id = format!("hire.delegate.{frontier}");
            match delegate_persisted(board, &as_space, Some(store), cached, &frontier, &key.fingerprint, &id, &mut warnings)? {
                Delegated::Committed { principal, .. } => {
                    say(person, "AUTH-5.58 step 2", format!("{frontier} is delegated beneath your agent space — a permanent prefix under your own, and no key record yet"));
                    (frontier, principal)
                }
                Delegated::Seated(_) => {
                    return Err(Halt::face(
                        format!("{frontier} was taken while this walk ran: another session as your agent space delegated it first"),
                        "the `delegate` answered `not_authorized` at an address that is now a seat — a second run of `skep hire` under a key of your set",
                        "nothing of this run was written there; run `skep hire` again: it reads the frontier afresh, and resumes that address only where its run wrote no key record",
                    ))
                }
                Delegated::NotAuthorized => {
                    return Err(Halt::face(
                        format!("`delegate` of {frontier} was refused `not_authorized`"),
                        "the session as the agent space does not own it, or the address is not its next delegable child",
                        "run `skep hire` again; nothing was written",
                    ))
                }
            }
        }
    };
    let facts = Facts { account: agent.clone(), principal: agent_principal, origin: board.dialed().clone() };

    // Step 3: the custody pair, or its decline at the choice's site.
    let custody: Option<(Vec<AnchorArtifact>, HybridSigner)> = if opts.anchorless {
        anchorless_choice(person, &cell, &pre.health, &agent).map_err(|h| before_the_genesis(h, &agent, false))?;
        None
    } else {
        let venue = Venue::Hire { facts: facts.clone(), replaces: venue_replaced.clone() };
        let moment = BackupOptions {
            labels: Vec::new(),
            destinations: opts.anchor_out.clone(),
            paper: opts.paper,
            store: Some(store.root().to_path_buf()),
            host_name: opts.host_name.clone(),
            date: opts.date.clone(),
        };
        let (outcome, held) = backup_moment_holding(person, &venue, &moment).map_err(|h| before_the_genesis(h, &agent, true))?;
        Some((outcome.anchors, held))
    };
    let pair_exported = custody.is_some();

    // Step 4: the paste's tests, each ahead of the consent, then the
    // comparison beat — the owner's own act.
    let tested = (|| -> Result<&Enrollment, Halt> {
        refuse_anchor_flagged_at_hire(&entries)?;
        let entry = the_one_device_entry(&entries)?;
        labelled(entry)?;
        if let Some(replaced) = &replaced {
            say(
                person,
                "AUTH-5.58 step 4",
                format!("the account this hire replaces, {}, carries {}: where the label below reads like one of them, answer `no` and have it recomposed", replaced.account, if replaced.labels.is_empty() { "no label this board serves".to_string() } else { replaced.labels.iter().map(|l| format!("`{}`", render_inert(l))).collect::<Vec<_>>().join(", ") }),
            );
            fresh_against(board, replaced, entry)?;
        }
        if !compare_hire_payload(person, entry, opts.anchorless)? {
            return Err(Halt::face(
                "the comparison was declined",
                "the typed answer was not the first group of the fingerprint shown",
                "compare with the agent's host over the channel the record came by — or have it recomposed there — and run `skep hire` again",
            ));
        }
        Ok(entry)
    })();
    let entry = tested.map_err(|h| before_the_genesis(h, &agent, pair_exported))?;

    // The genesis: the owner's own composition, never the arriving bytes —
    // the pair's two anchor-flagged entries, each under the label its box
    // fixed, and the payload's entry member for member as parsed; that one
    // alone on the anchorless arm. Signed by the owner's hand, homed in the
    // agent space's doc 1, from the session step 2 opened.
    let (anchors, material) = match custody {
        Some((anchors, held)) => (anchors, Some(held)),
        None => (Vec::new(), None),
    };
    let mut record: Vec<Enrollment> = anchors.iter().map(|a| Enrollment::new(a.public.clone(), true, Some(a.label.as_str().to_string())).expect("a label the box admitted")).collect();
    record.push(entry.clone());
    let id = format!("hire.genesis.{agent}");
    let genesis = deposit(board, as_space.token(), &Deposit { home: &space_home, subject: &agent, kind: DepositKind::Enroll(record), hand: Some(&*device), id: &id });
    match genesis {
        Ok(DepositOutcome::Deposited { .. }) => {}
        Ok(DepositOutcome::Committed { reason }) => say(person, "AUTH-5.17", format!("the first key record stands: {reason}")),
        Err(DepositHalt::NotGenesisRegistry(h)) => {
            return Err(Halt::face(
                format!("{agent} was given its first keys by another hand, and they are not this record's"),
                format!("{h}"),
                format!("read who holds it — `skep verify`, or the agent space's doc 1 at {space_home} — before any other act; the sheets this run exported open nothing"),
            ))
        }
        Err(other) => return Err(before_the_genesis(other.into(), &agent, pair_exported)),
    }
    let _ = as_space.close();
    say(
        person,
        "AUTH-5.58 step 4",
        format!(
            "the first key record of {agent} is written in {space_home}, your own composition under your own hand: {}. It is the row a \
             roster reads — nothing more is written for it (AUTH-5.91).",
            if anchors.is_empty() { "the agent's one working key and nothing else".to_string() } else { "the agent's working key and the two custody anchors, three entries".to_string() }
        ),
    );

    // Step 5 (anchored): the agent's doc 1, from a session as the agent
    // opened by the custody anchor the moment re-imported — the material and
    // the session dropped when the mint ends, whichever way it ends.
    let home = doc_1_of(&agent);
    let minted_home = match material {
        Some(anchor) => {
            let minted = (|| -> Result<bool, Halt> {
                let as_agent = handshake(board, Scope::Content, &anchor, agent_principal, Site::Hire)?;
                let minted = FirstSessionReads::take(board, &agent, &Signer::fingerprint(&anchor), None).and_then(|reads| mint_home(board, &reads, &as_agent, &anchor));
                let _ = as_agent.close();
                minted
            })();
            drop(anchor);
            let minted = minted.map_err(|h| after_the_genesis(h, &agent, &home))?;
            say(person, "AUTH-5.58 step 5", format!("{home} is {} — the agent's home, born published — and the custody anchor's material and its session are dropped", if minted { "minted" } else { "already minted, read and not minted again" }));
            minted
        }
        None => false,
    };

    // Step 6: only now the principal.
    if anchors.is_empty() {
        say(
            person,
            "AUTH-5.61",
            format!(
                "ANCHORLESS: no session as this agent can be opened from here, so {home} is NOT minted. The order the agent's own side \
                 owes is its principal, then its own first working-key session, whose FIRST act must be that mint — the flag \
                 affirmative, ahead of anything else it writes: an agent that writes first puts its content in the born-published \
                 slot."
            ),
        );
    }
    say(
        person,
        "AUTH-5.58 step 6",
        format!(
            "the agent's principal is {agent_principal} — the hire's own id, which lives nowhere but here and on the board: carry it to \
             the agent's host as its `SKEP_PRINCIPAL`, beside this board's origin and the agent's own key store. An agent's program \
             takes those three as settings and runs no `skep bind`; its first signed session proves its key (AUTH-5.65)."
        ),
    );
    Ok(Hired {
        facts,
        agent_space: space,
        key: Fingerprint::of(&entry.key),
        label: entry.label().map(str::to_string),
        anchors,
        anchorless: opts.anchorless,
        minted_home,
        already: false,
        warnings,
    })
}

/// Returns `h` as a halt met past the genesis and short of the mint.
///
/// The genesis stands and the agent's doc 1 does not: the state a re-run
/// stops at (`unminted_stop`), said by the run that met it, its own cause
/// kept. A halt that is no face passes as it came.
fn after_the_genesis(h: Halt, agent: &str, home: &str) -> Halt {
    let Halt::Halt(face) = h else { return h };
    let Halt::Halt(stop) = unminted_stop(agent, home) else { return Halt::Halt(face) };
    Halt::Halt(Face {
        state: format!("{} — the first key record of {agent} is written and its doc 1 is NOT minted", face.state),
        cause: format!("{}; the custody material this run held is dropped, and no principal is answered", face.cause),
        act: stop.act,
        path: face.path,
    })
}
