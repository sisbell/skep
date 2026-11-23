//! `skep merge`, the fourteenth command, over `skep_client::merge`.
//!
//! Its design is the merge record,
//! `_designs/CLIENT/2026-10-14-reconciling-versions-design.md` in the
//! skep-ux-design repository, §6 "The CLI and the agent adapter";
//! `client.md` §2.1 lists the thirteen it stands beside, none touching
//! content — this one does, which is why the library's `merge` feature is
//! on for this crate alone. The board, the document and one side are named
//! — an alternative member; a draft, read at the board's head, whose base
//! the library derives from the base the board records it was staged from
//! (`doc_metadata`'s `base`), up the bases the board recorded for each
//! member on its line, never from an address (`--base` names it only to be
//! checked, and one the board's records do not derive is refused), the
//! report's `sides` carrying the position the draft was read at, which a
//! verifier reads the draft and its recorded base as of, and a fork or a
//! draft side carrying its state, `arranged`, the position its text last
//! changed at when the merge was composed; or another
//! account's fork of the document, whose base is derived so from where the
//! board records it standing — the base it records for a fork its owner
//! staged (`doc_metadata`'s `base`), which each landing into it moves to
//! the head, else its source (`doc_metadata`'s `source`) — a document of
//! the owner's own account given as `--fork` refused `fork_of_owner`, the
//! owner's draft being the `--draft` side — a side begun from the bare
//! document before its first version, a draft or a fork unpublished or a
//! member published beside version 1, composing over the document's own
//! arrangement from before that version, the report's `base` the document
//! itself — and the head where the feed walk should not supply it; the
//! command composes the merge under the rules — every read at one board
//! position, the report's `as_of` — and prints the `Merged` report as one
//! JSON document on stdout, exit 0. With `--publish` it lands the merge as
//! the document's next version with its record — every window part of the
//! merged text answered by name first (`--window`, `--leave-out`,
//! `--keep-private`), this command answering none for the person: with a
//! part unanswered it publishes nothing and refuses, exit 1, every part and
//! the answers it admits said (`owed_block`; the merge record's §1.5
//! and §6) — and a `--draft` side's own words taken from the draft in the
//! same commit, so it reads them as published, words a record already names
//! as published sent by reference to them, and a draft changed since the
//! composition refused with nothing published (the library's `land` doc);
//! with `--into` it lands the
//! merged list in a draft as one `set_arrangement` typed against that
//! position — refused whole where the draft changed since, the draft's base
//! re-recorded on the head and the merge marked beside it where the board
//! records a base for it; with `--new` it stages a fresh draft from the head
//! and lands there — or, where the merger's own landing of the key already
//! stands in a draft, reports that landing and stages nothing, its `fresh`
//! false, and where a fork or a draft side moved since the merger's own landing
//! of the merge, so the key is another, lands in the draft the merger's newest
//! record of the merge names, found with the states ignored (`landed_draft`),
//! its `fresh` false, and where
//! the merge landed in a draft of the merger's that no record of theirs
//! names — a landing cut off before its record — lands nothing and stages
//! nothing, refused `landing_begun` naming the draft, exit 1, for `--into`
//! that draft to land it with its record or `--undo` it; and the report then
//! carries the landing, naming a newer version published since where the
//! board tells one. A `--resolve ⟨gap⟩=⟨choice⟩` settles a gap the rules
//! left open — at a `moves` gap with spots, one set of words two sides
//! placed at two places, `order:⟨side⟩` or `keep:⟨side⟩` takes that side's
//! placement (CM-I33). Every choice names a gap by its number in the report
//! printed with no `--resolve`, which no choice renumbers: `order:⟨side⟩` at
//! the spine's `moves` gap orders the merge by that side and leaves every
//! other gap its number, and a choice naming a gap that order removes is
//! applied nowhere and listed under `ignored` (skep #1155); `--journal`
//! names the merge journal (decision 7), `--kind` the record kind's type
//! address (decision 9's row is interim and unpinned, so the caller names
//! it). The board's refusal is exit 1, a halt exit 3. A `withheld` refusal —
//! a document the merger may not read, or an origin a write's run windows —
//! names the document, the second the positions of its words in the list the
//! write sends too, and the command says beside it what the run did: nothing
//! composed; the merge composed, and nothing published or merged; nothing
//! taken back or out.
//!
//! **The journal.** A merge record is kept only in a private document: a
//! journal is a private document of the merger's own, a published one is
//! refused before any write, no publication publishes a merge record, and
//! what a merge makes public is its version and, at a published daughter,
//! the claim riding its shot. A `--journal` that cannot take the record is
//! refused before the landing's or the take-back's first write, nothing
//! written: one the merger may not read, one the board does not register or
//! another account's as the library's halt naming the journal and the
//! check it fails, exit 3; a published one as the board's refusal under
//! `published_target`, exit 1 — "⟨J⟩ is published, and a merge record is
//! kept only in a private document — nothing was merged and nothing was
//! written. Name a private document of yours with --journal, or leave
//! --journal out to use your private journal.", the take-backs saying
//! nothing was taken back or out. The composition's talk says the fact
//! before any landing flag is acted on, where `--journal` names a published
//! document: the refusal's first clause, then "— landing this merge there
//! is refused". A run whose landing already stands writes its record first
//! and checks no journal before it; a journal met failing there, or a board
//! too busy to answer the find of the account's own journal with no
//! `--journal` named, leaves the merge standing with its record unwritten,
//! exit 3.
//!
//! **The two take-backs** (skep #783), each with `--kind` and nothing of
//! the composition's: `--undo ⟨S⟩` puts the draft back as it stood before
//! the merge landed in it — its words and its base restored, the merge
//! taken out and the merge it carried before put back where it carried one
//! (skep #964), in one write typed against the landing's position, or the
//! latest write that put the landing's marker back where only a take-back
//! and its undo moved the words since, so a draft changed since is refused
//! with nothing changed — and `--withdraw ⟨S⟩` takes the merge out and
//! keeps the words, the draft's next version then an ordinary one. Each
//! prints one JSON document carrying the act, the draft, the write's
//! position, the replacing record's link and the case, the undo's with the
//! base restored and the marker the draft carries again; where there is
//! nothing to undo or take out the library's reason is the refusal, exit 1,
//! and nothing was sent.
//!
//! The session is the command's own: the selected signing key (the file
//! `--key` or `SKEP_KEY` names, else the store's), a content-scoped signed
//! session opened as `skep session` opens its, and closed on every exit —
//! the shot is signed by that key, so `SKEP_SESSION` is never read here: a
//! token cannot sign. The record and its link go into the merger's private
//! journal, unsigned. The library's refusals come to their stops through
//! the renderer the commands share (`commands.rs`'s `refused`, under a
//! `Step`), the take-backs' `history_reclaimed` worded here
//! ([`refused_taking_out`]).
//!
//! **A daughter is reported, never retried (decision 17).** Where the head
//! moved under the merge the shot lands as the head's daughter, the report
//! says so under `landed.daughter`, the talk says to run again with
//! `--retries` one higher, and the command runs nothing again.
//!
//! **Who resolves (decisions 1–5).** A `--resolve` is the merger's, and the
//! record keeps who the merger was — `person` where stdin and stderr are
//! both a terminal, `agent` where they are not. This is the one place the
//! command tells the two apart; it is no person door and runs without a
//! terminal.
//!
//! The report's members take the record's §4 names where they coincide
//! (`doc`, `base`, `sides`, `gaps`, `values`, `record`); the report adds
//! `head`, `runs` (M as `origin`, `i_start`, `width`, `side`, `family`),
//! `counts`, `cap`, `over_cap`, `prior`, `ignored`, `deduped` (each place
//! the merge kept once, words both sides added alike at one spot, the merge
//! record's §5 case (g): `{gap, kept, dropped}`, the sides whose copy M
//! holds and every other side's runs, which stay in that side with any link
//! on them, the talk naming each), `as_of` — the one
//! position the composition stands at, where every side that can change
//! held the state it was read in — `landed`, and to
//! each gap a `default` — its placement as this run composed it, in
//! `--resolve`'s own spelling, so a merger copies it and varies it. A draft
//! landing's `landed` carries the draft, the write's `position`, the
//! `record`, `head_moved` (the newer head told, else null) and `fresh`
//! (whether this run staged the draft, as the library's landing answers it:
//! false for `--into` and for a landing found standing) — and, where the
//! landing goes over the merger's own landing of the merge with a moved
//! side, `replaced`: each stretch of the draft as it stood at the
//! composition's position that the landing replaced, `{ordinal, width,
//! origin, i_start}`, `[]` where the merge carries all it held, the talk
//! naming them and the `--undo` that puts them back (the owner's ruling of
//! 2026-11-20). For `--into` that landing is the one standing in the draft
//! named, read by the draft's mark — its marker, or with no recorded base
//! the landing standing by its `set_arrangement` rows, which a restore or
//! any other re-arrangement neither ends nor brings back (skep #914) —
//! whatever the merge landed in since (`standing_landing`); for `--new` it
//! is the one the merger's newest record of the merge names, in the draft
//! it lands in. `--json` is every command's flag and changes nothing here:
//! the report is JSON always.

use serde_json::{json, Value};
use skep_address::Address;
use skep_client::address::parse_address;
use skep_client::board::{Board, Scope};
use skep_client::ceremony::handshake::{handshake, Session, Site};
use skep_client::dial::plaintext_non_loopback_warning;
use skep_client::halt::{Halt, Refused};
use skep_client::merge::{
    compose, head_of, journal, land, landed_draft, replaced, standing_landing, undo, unwithdraw,
    withdraw, Answers, Choice, Family, Flag, Gap, GapId, GapKind, Inputs, Landed, Landing, Merged,
    Merger, Misfit, Options, Placement, Record, RecordLanding, Refusal, Replaced, Resolution,
    ResolvedBy, Side, SideIx, SideState, Undone, Unwithdrawn, WindowPart, Withdrawn,
};
use skep_client::publication::OriginAnswer;
use skep_client::sheet::render_inert;
use skep_client::sign::Signer;
use skep_client::store::{KeySelector, KeyStore, Purpose};

use super::{
    board_of, data_verbatim, has_terminal, journal_published, key_named, principal_or_bound,
    refused, select_key, store_of, talk, Step, Stop,
};
use crate::args::{CommandLine, Usage};

/// How the merge lands, where a landing flag is given.
enum Land {
    /// `--publish`: one shot from the head, the record beside it, under
    /// the caller's answers at the merged text's window parts.
    Publish(Box<Answers>),
    /// `--into ⟨draft⟩`: the merged list set as this draft's whole
    /// arrangement in one write, typed against the composition's position.
    Into(Address),
    /// `--new`: a fresh draft staged from the head, then the same write.
    ///
    /// Where the merger's own landing of the key stands in a draft, the
    /// library reports it and stages nothing.
    New,
}

impl Land {
    /// Returns the step a refusal of this landing answers.
    fn step(&self) -> Step {
        match self {
            Land::Publish(_) => Step::Publish,
            Land::Into(_) | Land::New => Step::Draft,
        }
    }
}

/// What the command line asks, judged whole before any socket opens.
///
/// §2.3's exit 2 is the flags' shape alone.
struct Asked {
    /// The act: a composition with its landing, or a take-back.
    act: Act,
    kind: Address,
    journal: Option<Address>,
}

/// The act the line asks.
enum Act {
    /// Compose, and land where a landing flag is given.
    Merge {
        doc: Address,
        side: Side,
        base: Option<Address>,
        head: Option<Address>,
        options: Options,
        landing: Option<Land>,
    },
    /// `--undo ⟨S⟩`: the draft back as it stood before the merge landed.
    Undo(Address),
    /// `--undo ⟨S⟩ --withdrawal ⟨P⟩`: a withdrawal taken back (skep #870).
    ///
    /// The merge the withdrawal at P took out of the draft is put back as
    /// it stood.
    Unwithdraw(Address, u64),
    /// `--withdraw ⟨S⟩`: the merge taken out, the words kept.
    Withdraw(Address),
}

pub fn merge(c: &CommandLine) -> Result<(), Stop> {
    let board = board_of(c)?;
    let store = store_of(c)?;
    let given = c.principal()?;
    let key_file = c.key_file()?;
    // Who the merger is, read off the std streams and nothing else: a person
    // at a terminal, an agent anywhere else (the module's doc).
    let by = if has_terminal() { ResolvedBy::Person } else { ResolvedBy::Agent };
    let asked = Asked::of(c, &by)?;
    // The plaintext non-loopback warning, ahead of everything a signed
    // session needs (AUTH-4.53; §9 item 23: a warning, never a refusal).
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let principal = principal_or_bound(given, &store, &board)?;
    let key = select_key(key_file.as_deref(), &store, &board, principal, Purpose::Sign)?;
    let signer = store.signer(&KeySelector::Path(&key.path))?;
    // Content scope, as `skep session` opens its (RES-63): the shot, the
    // draft landing, the take-backs and the record are content writes under
    // this session, and the shot is signed by this key.
    let session = handshake(&board, Scope::Content, &*signer, principal, Site::Session)?;
    talk(format!(
        "merging as principal {principal} at account {} with key {}",
        session.account(),
        key_named(&key)
    ));
    let outcome = run(&board, &session, &*signer, &asked);
    // The session is closed on every exit (`skep session` alone leaves its
    // open, on purpose); a close the board refuses speaks only where the
    // run itself passed — the run's own stop is the one that matters.
    match session.close() {
        Ok(_) => outcome,
        Err(h) => {
            outcome?;
            Err(h.into())
        }
    }
}

/// Runs the act under the session: the head, the composition and the
/// landing, or a take-back with no composition.
///
/// The landing is made where one is asked, and the report goes on stdout.
///
/// # Errors
///
/// Returns a halt where no head is named and none is on the feed; a library
/// refusal ([`refused`]) from the feed's read, the composition, the landing,
/// the undo or the withdrawal; and the halt a write stdout refuses comes to.
fn run(
    board: &Board,
    session: &Session<'_>,
    signer: &dyn Signer,
    asked: &Asked,
) -> Result<(), Stop> {
    let token = session.token();
    let merger = Merger { token, account: session.account(), signer };
    let Act::Merge { doc, side, base, head, options, landing } = &asked.act else {
        let report = match &asked.act {
            Act::Undo(draft) => {
                talk(format!("taking the merge back out of {draft} at {}", board.dialed()));
                let undone = undo(board, merger, draft, &asked.kind, None, asked.journal.as_ref())
                    .map_err(|r| refused_taking_out(draft, r, Step::Undo))?;
                say_undone(&undone);
                undone_value(&undone)
            }
            Act::Unwithdraw(draft, withdrawal) => {
                talk(format!("putting the merge back into {draft} at {}", board.dialed()));
                let unwithdrawn = unwithdraw(board, merger, draft, &asked.kind, *withdrawal, None, asked.journal.as_ref())
                    .map_err(|r| refused_unwithdrawing(draft, *withdrawal, r))?;
                say_unwithdrawn(&unwithdrawn, *withdrawal);
                unwithdrawn_value(&unwithdrawn, *withdrawal)
            }
            Act::Withdraw(draft) => {
                talk(format!("taking the merge out of {draft} at {}", board.dialed()));
                let withdrawn = withdraw(board, merger, draft, &asked.kind, asked.journal.as_ref())
                    .map_err(|r| refused_taking_out(draft, r, Step::Withdraw))?;
                say_withdrawn(&withdrawn);
                withdrawn_value(&withdrawn)
            }
            Act::Merge { .. } => unreachable!("the composition is matched above"),
        };
        data_verbatim(report.to_string().as_bytes())?;
        return Ok(());
    };
    let head = match head {
        Some(h) => h.clone(),
        None => head_of(board, Some(token), doc).map_err(|r| refused(r, Step::Compose))?.ok_or_else(|| {
            Halt::face(
                format!("no head version of {doc} is on the feed"),
                "no publish row under the document names a trunk version: it has no version yet, or its rows lie below the feed's retention floor",
                "name the head with --head <D.h>, or publish the document's first version",
            )
        })?,
    };
    talk(format!(
        "merging {} with {head}, the head of {doc}, at {}",
        side_named(side, base.as_ref()),
        board.dialed()
    ));
    let inputs = Inputs {
        doc: doc.clone(),
        head,
        base: base.clone(),
        sides: vec![side.clone()],
        options: options.clone(),
        kind: asked.kind.clone(),
    };
    let merged = compose(board, Some(token), &inputs).map_err(|r| refused(r, Step::Compose))?;
    say_composed(&merged);
    // A published `--journal` said before any landing flag is acted on: the
    // landing's own check refuses it below, and a landing found standing
    // checks none. Every other answer of the check is the landing's to say.
    if let Some(journal) = &asked.journal {
        let checked = journal::check(board, &merger, journal);
        if let Err(Refusal::PublishedJournal { journal }) = checked {
            talk(format!("{} — landing this merge there is refused", journal_published(&journal)));
        }
    }
    let mut report = report_of(&merged);
    if let Some(landing) = landing {
        let journal = asked.journal.clone();
        let step = landing.step();
        // The draft holding the merger's own earlier landing of the merge,
        // its states ignored, where its record is of another key — a fork or
        // a draft side moved since it. `--into` reads the landing standing
        // in the draft it names, whatever the merge landed in since; `--new`
        // the merger's newest record of the merge, and lands in its draft,
        // never a fresh one. A landing there says what it replaces.
        let earlier = match landing {
            Land::Publish(_) => None,
            Land::Into(into) => {
                standing_landing(board, Some(token), &asked.kind, into, session.account())
                    .map_err(|r| refused(r, step))?
                    .filter(|record| {
                        record.key() != merged.key
                            && record.key().stateless() == merged.key.stateless()
                    })
                    .map(|_| into.clone())
            }
            Land::New => {
                landed_draft(board, Some(token), &asked.kind, &merged.key, session.account())
                    .map_err(|r| refused(r, step))?
                    .filter(|record| record.key() != merged.key)
                    .and_then(|record| match record.landed {
                        Some(RecordLanding::Draft { draft, .. }) => Some(draft),
                        _ => None,
                    })
            }
        };
        let into = match landing {
            Land::Into(into) => Some(into.clone()),
            Land::New => earlier.clone(),
            Land::Publish(_) => None,
        };
        let stretches = earlier
            .as_ref()
            .map(|draft| replaced(board, Some(token), draft, &merged))
            .transpose()
            .map_err(|r| refused(r, step))?;
        let landing = match landing {
            Land::Publish(answers) => Landing::Shot { merger, draft: None, answers: (**answers).clone(), journal },
            Land::Into(_) | Land::New => Landing::Draft { merger, into, journal },
        };
        let landed = land(board, &merged, landing).map_err(|r| match r {
            // The command's own refusal, in its words: the board was never
            // asked, and the parts' words are this command's to say (SP-10).
            Refusal::WindowPartsOwed { parts, misfits, given } => Stop::Refusal(owed_block(&merged, &parts, &misfits, &given)),
            other => refused(other, step),
        })?;
        say_landed(&merged, &landed, stretches.as_deref(), &asked.kind);
        report["landed"] = landed_value(&merged, &landed, stretches.as_deref());
    }
    data_verbatim(report.to_string().as_bytes())?;
    Ok(())
}

impl Asked {
    /// Reads the line whole, before any socket opens.
    ///
    /// Every address is parsed, every count a count, every `--resolve` in
    /// its grammar; `by` is who each resolution is by.
    ///
    /// # Errors
    ///
    /// In this order: `--undo` or `--withdraw` no address; `--kind` (or
    /// `SKEP_MERGE_KIND`, required at every act, a variable that is not
    /// UTF-8 text refused too) and `--journal` no address; then, at a
    /// composition, `--doc` absent or no address; no side, two sides, a
    /// side no address, or `--base` no address; `--head` no address;
    /// `--retries` no count; a `--resolve` outside its grammar; a
    /// `--window`, `--leave-out` or `--keep-private` no address; `--into` no
    /// address. The three landings apart — `--publish`, `--into`, `--new` —
    /// and the two take-backs apart from them, the sides, `--doc`, `--base`,
    /// `--head` and each other are the grammar's forms, refused ahead of
    /// this.
    fn of(c: &CommandLine, by: &ResolvedBy) -> Result<Asked, Usage> {
        let withdrawal = match c.value("--withdrawal") {
            Some(p) => Some(p.parse::<u64>().map_err(|_| Usage(format!("--withdrawal takes a position, the `position` a withdrawal answered, not `{p}`")))?),
            None => None,
        };
        let taken_out = match (c.value("--undo"), c.value("--withdraw")) {
            (Some(s), _) => Some(match withdrawal {
                Some(p) => Act::Unwithdraw(address("--undo", s)?, p),
                None => Act::Undo(address("--undo", s)?),
            }),
            (None, Some(s)) => Some(Act::Withdraw(address("--withdraw", s)?)),
            (None, None) => None,
        };
        let kind = match c.merge_kind()? {
            Some(k) => address("--kind", &k)?,
            None => return Err(Usage("--kind <address> (or SKEP_MERGE_KIND) is required: the merge record kind's type address, which the caller names while its row is unpinned".into())),
        };
        let journal = c.value("--journal").map(|j| address("--journal", j)).transpose()?;
        if let Some(act) = taken_out {
            return Ok(Asked { act, kind, journal });
        }
        let doc = match c.value("--doc") {
            Some(d) => address("--doc", d)?,
            None => {
                return Err(Usage(
                    "--doc <D> is required: the document whose versions are merged".into(),
                ))
            }
        };
        let (side, base) = match (c.value("--alternative"), c.value("--draft"), c.value("--fork")) {
            (Some(a), None, None) => (Side::Member(address("--alternative", a)?), None),
            // A draft's base is the board's to serve (`doc_metadata`'s
            // `base`, read by the library); `--base` names it only to be
            // checked — the library refuses one the board's record does not
            // derive (`DraftBaseDisagrees`) and a draft the board records no
            // base for (`BaseUnknown`, the merge record's decision 15).
            (None, Some(s), None) => (
                Side::Draft { at: address("--draft", s)?, position: None },
                c.value("--base").map(|b| address("--base", b)).transpose()?,
            ),
            (None, None, Some(f)) => (Side::Fork(address("--fork", f)?), None),
            (None, None, None) => {
                return Err(Usage("one side is required: --alternative <D.k.m>, --draft <S> [--base <D.k>], or --fork <F>".into()))
            }
            // The grammar's forms refuse two sides ahead of this; said again
            // rather than assumed.
            _ => return Err(Usage("one side alone: --alternative, --draft or --fork".into())),
        };
        let head = c.value("--head").map(|h| address("--head", h)).transpose()?;
        let retries = match c.value("--retries") {
            None => 0,
            Some(n) => {
                n.parse::<u32>().map_err(|_| Usage(format!("--retries: '{n}' is not a count")))?
            }
        };
        let resolutions = c
            .values("--resolve")
            .iter()
            .map(|text| resolution(text, by))
            .collect::<Result<Vec<_>, _>>()?;
        let options = Options {
            dedup: !c.switch("--no-dedup"),
            retype: c.switch("--retype"),
            resolutions,
            retries,
        };
        let answers = Answers {
            window: addresses(c, "--window")?,
            leave_out: addresses(c, "--leave-out")?,
            keep_private: addresses(c, "--keep-private")?,
        };
        let landing = match c.value("--into") {
            Some(into) => Some(Land::Into(address("--into", into)?)),
            None if c.switch("--publish") => Some(Land::Publish(Box::new(answers))),
            None if c.switch("--new") => Some(Land::New),
            None => None,
        };
        Ok(Asked { act: Act::Merge { doc, side, base, head, options, landing }, kind, journal })
    }
}

/// Returns the addresses a repeated `flag` spells, in order.
///
/// # Errors
///
/// As [`address`].
fn addresses(c: &CommandLine, flag: &str) -> Result<Vec<Address>, Usage> {
    c.values(flag).iter().map(|text| address(flag, text)).collect()
}

/// Returns the address `text` spells at `flag`.
///
/// # Errors
///
/// Returns the usage refusal naming both where `text` spells none.
fn address(flag: &str, text: &str) -> Result<Address, Usage> {
    parse_address(text).ok_or_else(|| {
        Usage(format!("{flag}: '{text}' is not an address (the wire's dotted spelling)"))
    })
}

/// Parses one `--resolve ⟨gap⟩=⟨choice⟩` in its grammar.
///
/// The gap is its number as the report counts it, from 1, the same in every
/// run, whatever the other choices; the choice is `order:⟨side⟩,⟨side⟩…`,
/// `after:⟨address⟩`, `before:⟨address⟩`, `keep:⟨side⟩`, `both` or `omit`, a
/// side its index as the report numbers it.
///
/// # Errors
///
/// Returns a usage refusal naming the grammar where `text` is outside it.
fn resolution(text: &str, by: &ResolvedBy) -> Result<Resolution, Usage> {
    let malformed = || {
        Usage(format!(
            "--resolve: '{text}' is not <gap>=<choice> — the gap's number as the report counts it, `=`, then one of order:<side>,<side>..., \
             after:<address>, before:<address>, keep:<side>, both, omit"
        ))
    };
    let (gap, choice) = text.split_once('=').ok_or_else(malformed)?;
    let gap = gap.parse::<u32>().ok().filter(|g| *g >= 1).ok_or_else(malformed)?;
    let side = |s: &str| s.parse::<u8>().ok().map(SideIx);
    let choice = match choice.split_once(':') {
        None => match choice {
            "both" => Choice::KeepBoth,
            "omit" => Choice::Omit,
            _ => return Err(malformed()),
        },
        Some(("order", sides)) => {
            let sides: Vec<SideIx> = sides
                .split(',')
                .map(side)
                .collect::<Option<Vec<_>>>()
                .filter(|s| !s.is_empty())
                .ok_or_else(malformed)?;
            Choice::Order(sides)
        }
        Some(("after", a)) => Choice::After(parse_address(a).ok_or_else(malformed)?),
        Some(("before", a)) => Choice::Before(parse_address(a).ok_or_else(malformed)?),
        Some(("keep", s)) => Choice::KeepOnly(side(s).ok_or_else(malformed)?),
        Some(_) => return Err(malformed()),
    };
    Ok(Resolution { gap: GapId(gap), choice, by: by.clone() })
}

/// Returns the side as the talk names it.
fn side_named(side: &Side, base: Option<&Address>) -> String {
    match (side, base) {
        (Side::Member(a), _) => format!("the alternative {a}"),
        (Side::Draft { at, .. }, Some(b)) => format!("the draft {at} (staged from {b})"),
        (Side::Draft { at, .. }, None) => format!("the draft {at}"),
        (Side::Fork(f), _) => format!("the fork {f}"),
    }
}

/// Returns the stop a take-back's refusal comes to (§2.3's exit 1).
///
/// It is [`refused`]'s, but a pre-landing position the board has reclaimed
/// — `history_reclaimed` at the undo's read of the state before the merge —
/// whose detail says what it means here: the state before the merge is no
/// longer on this board, and nothing was sent; the library's own words
/// advise composing again, which is no act of the undo's. `step` is the
/// take-back's, [`Step::Undo`] or [`Step::Withdraw`].
fn refused_taking_out(draft: &Address, r: Refusal, step: Step) -> Stop {
    match r {
        Refusal::HistoryReclaimed { at, floor } => Stop::Halt(Halt::Refused(Refused {
            status: 200,
            code: "history_reclaimed".to_string(),
            detail: Some(format!(
                "the state before the merge is no longer on this board: {draft} as of position {at} is reclaimed{} — nothing was sent; the merge stays as it is, or take it out and keep the words with --withdraw",
                floor.map(|f| format!(" (the oldest position it answers is {f})")).unwrap_or_default()
            )),
            op: None,
            body: Value::Null,
        })),
        other => refused(other, step),
    }
}

/// Returns the stop a withdrawal's undo's refusal comes to (§2.3's exit 1).
///
/// It is [`refused`]'s at [`Step::Undo`], but a position the board has
/// reclaimed — `history_reclaimed` at the read of the draft at the
/// withdrawal or before it — whose detail says what it means here: the
/// state before the withdrawal is no longer on this board, and nothing was
/// sent (skep #870).
fn refused_unwithdrawing(draft: &Address, withdrawal: u64, r: Refusal) -> Stop {
    match r {
        Refusal::HistoryReclaimed { at, floor } => Stop::Halt(Halt::Refused(Refused {
            status: 200,
            code: "history_reclaimed".to_string(),
            detail: Some(format!(
                "the state before the withdrawal at position {withdrawal} is no longer on this board: {draft} as of position {at} is reclaimed{} — nothing was sent; the merge stays out of the draft, its words kept",
                floor.map(|f| format!(" (the oldest position it answers is {f})")).unwrap_or_default()
            )),
            op: None,
            body: Value::Null,
        })),
        other => refused(other, Step::Undo),
    }
}

/// Says the talk after a withdrawal's undo.
///
/// The merge the withdrawal took out stands in the draft again, its marker
/// as it stood, and the record's link is named where one was written.
fn say_unwithdrawn(unwithdrawn: &Unwithdrawn, withdrawal: u64) {
    let Unwithdrawn { draft, position, record } = unwithdrawn;
    talk(format!(
        "put the merge back into {draft} at position {position}: the withdrawal at position {withdrawal} is undone, and the draft carries the merge as it did before it{}",
        match record {
            Some(link) => format!("; the record's link is {link}"),
            None => "; no record of the withdrawal stood, so none was written".to_string(),
        }
    ));
}

/// Returns a withdrawal's undo as the report carries it.
///
/// It is an undo, its case `withdrawal` with the withdrawal's position,
/// nothing restored.
fn unwithdrawn_value(unwithdrawn: &Unwithdrawn, withdrawal: u64) -> Value {
    json!({
        "act": "undo",
        "draft": unwithdrawn.draft.to_string(),
        "position": unwithdrawn.position,
        "record": unwithdrawn.record.as_ref().map(ToString::to_string),
        "case": "withdrawal",
        "withdrawal": withdrawal,
        "restored": Value::Null,
    })
}

/// Says the talk after an undo: the draft is back to how it stood before
/// the merge, its base — where the board records one — taken back.
///
/// The merge is taken out, or the one the draft carried before it stands
/// again where the undo put its marker back (skep #964), and the record's
/// link is named where one was written.
fn say_undone(undone: &Undone) {
    let Undone { draft, position, record, restored, marker } = undone;
    let base = match restored {
        Some((base, extent)) => format!(", its base is {base} at {extent} positions again"),
        None => format!("; {draft} records no base, so none moved"),
    };
    let merge = match marker {
        None => format!(", and the merge is taken out{}", record_said(record.as_ref())),
        Some(earlier) => format!(
            ", and the merge it carried then stands in it again{}{}",
            earlier.at.map(|at| format!(", marked at position {at}")).unwrap_or_default(),
            match record {
                Some(link) => format!("; the record's link is {link}"),
                None => "; no record was written: the merge standing again keeps the record that stood, where one stood".to_string(),
            }
        ),
    };
    talk(format!("took the merge back out of {draft} at position {position}: the draft is back to how it stood before the merge{base}{merge}"));
}

/// Says the talk after a withdrawal: the merge is taken out, the words
/// stay as they are, the draft's next version is an ordinary one, and the
/// record's link where one was written.
fn say_withdrawn(withdrawn: &Withdrawn) {
    let Withdrawn { draft, position, record } = withdrawn;
    talk(format!(
        "took the merge out of {draft} at position {position}: the words stay as they are, and the draft's next version is an ordinary one{}",
        record_said(record.as_ref())
    ));
}

/// Returns the record's clause of a take-back's talk.
fn record_said(record: Option<&Address>) -> String {
    match record {
        Some(link) => format!("; the record's link is {link}"),
        None => "; no record of the landing stood, so none was written".to_string(),
    }
}

/// Returns an undo as the report carries it.
///
/// It is the act, the draft, the write's position, the replacing record's
/// link (else null), the case — `marker` where the undo went by the
/// draft's base record and marker, `feed` where by the draft's own feed
/// row — the base restored as `{at, extent}` (else null), and the marker
/// the draft carries again as `doc_metadata` serves it, `{sides, head,
/// head_copied, at}`, where the undo put one back (else null; skep #964).
fn undone_value(undone: &Undone) -> Value {
    json!({
        "act": "undo",
        "draft": undone.draft.to_string(),
        "position": undone.position,
        "record": undone.record.as_ref().map(ToString::to_string),
        "case": if undone.restored.is_some() { "marker" } else { "feed" },
        "restored": undone.restored.as_ref().map(|(base, extent)| json!({"at": base.to_string(), "extent": extent.to_string()})),
        "marker": undone.marker.as_ref().map(|m| json!({"sides": m.sides, "head": m.head, "head_copied": m.head_copied.map(|n| n.to_string()), "at": m.at})),
    })
}

/// Returns a withdrawal as the report carries it.
///
/// It is the act, the draft, the write's position, the replacing record's
/// link (else null) and the case, `marker`: a withdrawal goes by the marker
/// alone.
fn withdrawn_value(withdrawn: &Withdrawn) -> Value {
    json!({
        "act": "withdraw",
        "draft": withdrawn.draft.to_string(),
        "position": withdrawn.position,
        "record": withdrawn.record.as_ref().map(ToString::to_string),
        "case": "marker",
    })
}

/// Says the talk after the composition.
///
/// It names the base and the counts, each place the merge kept once
/// ([`dedup_lines`]), each unsettled gap in the copy's register ("⟨n⟩
/// places need a choice"), the resolutions not applied, and the cap where
/// the list passes it.
fn say_composed(merged: &Merged) {
    let counts = merged.composed.counts;
    let gaps = &merged.composed.gaps;
    let unsettled: Vec<&Gap> = gaps.iter().filter(|g| !g.settled).collect();
    talk(format!(
        "composed over the base {}: {} runs from the head's {} and the side's {}, {} gap{}",
        merged.key.base,
        counts.m,
        counts.a,
        counts.b,
        gaps.len(),
        if gaps.len() == 1 { "" } else { "s" }
    ));
    for line in dedup_lines(&merged.record) {
        talk(line);
    }
    if !unsettled.is_empty() {
        let named: Vec<String> = unsettled
            .iter()
            .map(|g| format!("gap {} ({}, default {})", g.id.0, kind_name(g.kind), default_of(g)))
            .collect();
        talk(format!(
            "{} place{} a choice: {} — resolve each with --resolve <gap>=<choice>, or land nothing and the alternative stands",
            unsettled.len(),
            if unsettled.len() == 1 { " needs" } else { "s need" },
            named.join("; ")
        ));
    }
    if !merged.composed.ignored.is_empty() {
        let ids: Vec<String> =
            merged.composed.ignored.iter().map(|r| r.gap.0.to_string()).collect();
        talk(format!(
            "not applied: the resolution of gap {} — it names no gap of this report, a gap the rules settled, or a choice its kind cannot take",
            ids.join(", ")
        ));
    }
    if counts.m > merged.cap {
        talk(format!(
            "{} is in more pieces than one publication can carry — {}, where {} is the most; publishing this merge is not offered",
            merged.inputs.doc, counts.m, merged.cap
        ));
    }
}

/// Says the talk after a landing.
///
/// It says what landed, or the daughter and the re-run; at the shot, each
/// window part's answer, every default taken and every place kept once (the
/// merge record's §1.5, the lines of §6); at a draft landing,
/// the draft — the fresh one staged where the library answers it `staged` —
/// and, where the board told a newer head, that a newer version was
/// published since the merge was composed and the merge landed against the
/// head it composed on, so a merge composed again includes it; and, where
/// the landing went over the merger's earlier landing of the merge, the
/// stretches it replaced, `stretches`, and the `--undo` under `kind` that
/// puts them back.
fn say_landed(merged: &Merged, landed: &Landed, stretches: Option<&[Replaced]>, kind: &Address) {
    match landed {
        Landed::Member { address, position, claims, record, answers, .. } => {
            talk(published_line(merged, address, claims.len()));
            for part in answers {
                talk(answered_line(part));
            }
            for line in default_lines(merged).into_iter().chain(dedup_lines(&merged.record)) {
                talk(line);
            }
            talk("no links were published with this version — the links on its words stay where they were made".to_string());
            talk(format!(
                "published {address} at position {position}, the next version of {}; the record's link is {record}{}",
                merged.inputs.doc,
                if claims.is_empty() { String::new() } else { format!("; the claim{} marking the side{} superseded by it: {}", if claims.len() == 1 { "" } else { "s" }, if claims.len() == 1 { "" } else { "s" }, claims.len()) }
            ));
        }
        Landed::AsDaughter { address, position } => {
            talk(format!(
                "the head of {} moved under the merge: the shot landed as the daughter {address} at position {position}, and no record was \
                 written. Nothing is retried here — run this again with --retries {} to merge against the new head",
                merged.inputs.doc,
                merged.inputs.options.retries + 1
            ));
        }
        Landed::Draft { into, position, record, head_moved, staged } => {
            talk(format!(
                "landed in the draft {into} at position {position}{}; the record's link is {record}",
                if *staged {
                    format!(", a fresh draft staged from {}", merged.inputs.head)
                } else {
                    String::new()
                }
            ));
            if let Some(newer) = head_moved {
                talk(format!(
                    "a newer version of {} was published since this merge was composed: {newer} — the merge landed against {}, the head it was composed on; merge again to include {newer}",
                    merged.inputs.doc, merged.inputs.head
                ));
            }
            if let Some(stretches) = stretches {
                talk(replaced_line(into, merged.as_of, stretches, kind));
            }
        }
    }
}

/// Returns the line naming what a landing replaced in `draft`.
///
/// The landing went over an earlier landing of the merge, and `stretches`
/// are positions of `draft` as it stood at `as_of`.
fn replaced_line(draft: &Address, as_of: u64, stretches: &[Replaced], kind: &Address) -> String {
    if stretches.is_empty() {
        return format!("this landing replaced nothing of {draft}: the merge carries all it held at position {as_of}");
    }
    let named: Vec<String> = stretches
        .iter()
        .map(|r| match r.width {
            1 => format!("ordinal {}", r.ordinal),
            w => format!("ordinals {}–{}", r.ordinal, r.ordinal + w - 1),
        })
        .collect();
    let n = stretches.len();
    format!(
        "this landing replaced {n} stretch{} of {draft} as it stood at position {as_of} — the earlier landing's words and any edits made in it since: {}; skep merge --undo {draft} --kind {kind} puts them back",
        if n == 1 { "" } else { "es" },
        named.join(", ")
    )
}

/// Returns the report: the merge record's §7 `Merged`.
///
/// Its members are as the module's doc lists them: the record's own JSON
/// where the names coincide, M with each run's side and family, every gap
/// with its `default`, each place kept once, the counts against the cap,
/// the prior record, the unlanded record; `landed` null until a landing
/// fills it.
fn report_of(merged: &Merged) -> Value {
    let record = merged.record.to_value();
    let runs: Vec<Value> = merged
        .composed
        .runs
        .iter()
        .zip(&merged.families)
        .map(|(placed, family)| {
            json!({
                "origin": placed.run.origin.to_string(),
                "i_start": placed.run.address_at(0).map(|a| a.to_string()),
                "width": placed.run.width.to_string(),
                "side": placed.side.map(|s| s.0),
                "family": family_name(*family),
            })
        })
        .collect();
    let gaps: Vec<Value> = record["gaps"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .zip(&merged.composed.gaps)
        .map(|(mut g, gap)| {
            g["default"] = Value::from(default_of(gap));
            g
        })
        .collect();
    let counts = merged.composed.counts;
    json!({
        "doc": merged.inputs.doc.to_string(),
        "head": merged.inputs.head.to_string(),
        "base": merged.key.base.to_string(),
        "sides": record["sides"].clone(),
        "runs": runs,
        "gaps": gaps,
        "counts": {"a": counts.a, "b": counts.b, "m": counts.m},
        "cap": merged.cap,
        "over_cap": counts.m > merged.cap,
        "values": record["values"].clone(),
        "deduped": deduped_value(&merged.record),
        "ignored": merged.composed.ignored.iter().map(|r| r.gap.0).collect::<Vec<_>>(),
        "prior": merged.prior.as_ref().map_or(Value::Null, prior_of),
        "record": record,
        "as_of": merged.as_of,
        "landed": Value::Null,
    })
}

/// Returns the standing record for the key, as the report carries it.
///
/// It is the composition's current record, the trunk owner's records
/// current over another account's — so the owner's where the merger is not
/// the owner and both stand — and it carries its link, homed in the journal
/// holding it, its key and where it landed. It is what the composition saw,
/// never what a landing answers: a landing reads the merger's own newest
/// record for the key as it lands.
fn prior_of(prior: &Record) -> Value {
    let key = prior.key();
    let states: Vec<Value> = key
        .states
        .iter()
        .map(|(at, state)| {
            let mut v = json!({"at": at.to_string()});
            match state {
                SideState::At(q) => v["arranged"] = json!(q),
                SideState::Unarranged => v["arranged"] = Value::Null,
                SideState::Unrecorded => {}
            }
            v
        })
        .collect();
    json!({
        "link": prior.link.as_ref().map(ToString::to_string),
        "key": {
            "doc": key.doc.to_string(),
            "base": key.base.to_string(),
            "sides": key.sides.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "states": states,
        },
        "landed": prior.to_value()["landed"].clone(),
    })
}

/// Returns the landing as the report carries it.
///
/// A draft landing carries the draft, the write's position, the record,
/// `head_moved` — the newer head the board told, else null — and `fresh`,
/// whether this run staged the draft: the library's `staged`; and, over the
/// merger's earlier landing of the merge, `replaced`, each of `stretches`.
fn landed_value(merged: &Merged, landed: &Landed, stretches: Option<&[Replaced]>) -> Value {
    match landed {
        Landed::Member { address, position, claims, record, retries, answers } => json!({
            "member": address.to_string(),
            "position": position,
            "claims": claims.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "record": record.to_string(),
            "retries": retries,
            "answers": answers.iter().map(part_value).collect::<Vec<_>>(),
        }),
        Landed::AsDaughter { address, position } => json!({
            "daughter": address.to_string(),
            "position": position,
            "retries": merged.inputs.options.retries,
        }),
        Landed::Draft { into, position, record, head_moved, staged } => {
            let mut v = json!({
                "draft": into.to_string(),
                "position": position,
                "record": record.to_string(),
                "head_moved": head_moved.as_ref().map(ToString::to_string),
                "fresh": staged,
            });
            if let Some(stretches) = stretches {
                v["replaced"] = stretches
                    .iter()
                    .map(|r| json!({"ordinal": r.ordinal, "width": r.width, "origin": r.origin.to_string(), "i_start": r.i_start}))
                    .collect();
            }
            v
        }
    }
}

/// Returns the stop's words for the shot's window-part refusal.
///
/// The lines are the merge record's §6, the command's own: one line for a
/// part a record named after its answer was given, else the head and one
/// line per part with its pair, its origin and its answers; one line per
/// answer that fits nothing or names words another answers; then the
/// answers that stand and the defaults taken, nothing being published.
fn owed_block(merged: &Merged, parts: &[WindowPart], misfits: &[Misfit], given: &[WindowPart]) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.extend(parts.iter().filter(|p| p.named_since).map(named_since_line));
    let owed: Vec<&WindowPart> = parts.iter().filter(|p| !p.named_since).collect();
    if !owed.is_empty() {
        let n = owed.len();
        lines.push(if n == 1 {
            "nothing was published — 1 passage in this merge needs your answer, and this command never answers for you:".to_string()
        } else {
            format!("nothing was published — {n} passages in this merge need your answer, and this command never answers for you:")
        });
        lines.extend(owed.iter().map(|part| owed_line(merged, part)));
    }
    lines.extend(misfits.iter().map(misfit_line));
    lines.extend(given.iter().map(standing_line).filter(|line| !line.is_empty()));
    lines.extend(default_lines(merged));
    lines.join("\n")
}

/// Returns the line of a part a record named since its answer was given (§6).
fn named_since_line(part: &WindowPart) -> String {
    let v = part.version.as_ref().map(ToString::to_string).unwrap_or_default();
    format!("nothing was published — {}’s words were published in {v} after you answered; answer for them again: --window {v} or --leave-out {v}", part.origin)
}

/// Returns a part's line of the refusal, in the command's words (§6).
fn owed_line(merged: &Merged, part: &WindowPart) -> String {
    let words = quoted(part.words.as_deref(), "a passage you cannot read");
    let side = sides_clause(merged, part);
    let doc = &merged.inputs.doc;
    let next = next_version(merged);
    match (&part.version, &part.owner) {
        (Some(version), owner) => {
            let by = owner.as_ref().map(|o| format!(" by {o}")).unwrap_or_default();
            let here = match part.after.as_deref() {
                None => "at the start of the merged text".to_string(),
                Some("") => "after a passage you cannot read".to_string(),
                Some(after) => format!("after “{}”", render_inert(after)),
            };
            let span = part.counterpart.as_ref().map(|s| format!("{}.{}+{}", s.chain, s.first, s.width)).unwrap_or_default();
            let j = part.counterpart.as_ref().and_then(|c| c.document()).map_or_else(|| version.to_string(), |e| version_name(&e, version));
            format!("{words} — already published in {version}{by}{side} — here: {here}; published: {version} {span} — answer --window {version} to window them from version {j}, or --leave-out {version} to leave them out")
        }
        (None, None) => {
            let origin = &part.origin;
            format!(
                "{words} — words of {origin}, which is private{side} — answer --keep-private {origin}, and readers of version {next} meet a placeholder here: they see that a private passage of {origin} stands here, whose it is, how long it is and where in {origin} it was written, never what it says; version {next} keeps it so for good, and only a later version fills it, once those words of {origin} are published — or --leave-out {origin}; or publish those words of {origin} first, then run this again"
            )
        }
        (None, Some(owner)) => {
            let origin = &part.origin;
            format!("{words} — written by {owner} in {origin}, which readers of {doc} cannot read; they would see a placeholder here — ask {owner} to publish those words, then run this again; or answer --leave-out {origin}, or --keep-private {origin} to publish the placeholder knowingly")
        }
    }
}

/// Returns the line of an answer that fits nothing (§6).
fn misfit_line(misfit: &Misfit) -> String {
    let flag = |f: &Flag| match f {
        Flag::Window => "--window",
        Flag::LeaveOut => "--leave-out",
        Flag::KeepPrivate => "--keep-private",
    };
    match misfit {
        Misfit::TwoAnswers { first, second, key } => format!("{} {key} and {} {key} both answer the same words — give one", flag(first), flag(second)),
        Misfit::FitsNothing { flag: Flag::Window, key, .. } => format!("--window {key} answers nothing here — no words in this merge are published in {key}"),
        Misfit::FitsNothing { flag: f, key, published_in } => match published_in.first() {
            Some(v) => format!("{} {key} answers nothing here — {key}’s words in this merge are already published in {v}; answer --window {v} or --leave-out {v}", flag(f)),
            None => format!("{} {key} answers nothing here — this merge asks nothing about {key}’s words", flag(f)),
        },
    }
}

/// Returns an answer that stands beside a refusal, as the flag it is (§1.5:
/// the refusal names each answer given).
fn standing_line(part: &WindowPart) -> String {
    let words = quoted(part.words.as_deref(), "a passage you cannot read");
    match part.answer {
        Some(OriginAnswer::Counterpart) => format!("your answer stands: --window {} for {words}", part.version.as_ref().map(ToString::to_string).unwrap_or_default()),
        Some(OriginAnswer::KeepPrivate) => format!("your answer stands: --keep-private {} for {words}", part.origin),
        Some(OriginAnswer::Drop) => format!("your answer stands: --leave-out {} for {words}", part.version.as_ref().unwrap_or(&part.origin)),
        Some(OriginAnswer::PublishFirst) | None => String::new(),
    }
}

/// Returns the line that names one answer after the publication (§6).
fn answered_line(part: &WindowPart) -> String {
    let words = quoted(part.words.as_deref(), "a passage you cannot read");
    match part.answer {
        Some(OriginAnswer::Counterpart) => format!("windowed from {}: {words} — the same words, now in this version too", part.version.as_ref().map(ToString::to_string).unwrap_or_default()),
        Some(OriginAnswer::Drop) => format!("left out: {words} — its words stay in {}; this command does not ask about them again", part.origin),
        Some(OriginAnswer::KeepPrivate) => format!("kept private, behind a placeholder: {words}"),
        Some(OriginAnswer::PublishFirst) | None => format!("answered: {words}"),
    }
}

/// Returns the line a publication's first says (§6).
fn published_line(merged: &Merged, member: &Address, claims: usize) -> String {
    let doc = &merged.inputs.doc;
    let version = version_name(&doc.to_string(), member);
    let daughter = merged.inputs.sides.iter().find_map(|s| match s {
        Side::Member(a) => Some(a),
        _ => None,
    });
    match daughter {
        Some(side) if claims > 0 => format!("published version {version} of {doc}, with its claim that version {} is superseded by it", version_name(&doc.to_string(), side)),
        _ => format!("published version {version} of {doc}"),
    }
}

/// Returns the lines naming every default the merge takes (§1.5, as the
/// reveal lists them: kind, where, as placed).
fn default_lines(merged: &Merged) -> Vec<String> {
    merged.composed.gaps.iter().filter(|g| !g.settled).map(default_line).collect()
}

/// Returns the line naming one gap's default: its kind, where, as placed.
///
/// A gap is where its anchors put it; a `moves` gap has none. One with
/// spots — one set of words two sides placed at two places (CM-I33) — is
/// at each side's place, and a spine's is no place but the side's order the
/// spine took.
fn default_line(g: &Gap) -> String {
    let at = |after: &Option<Address>, before: &Option<Address>| match (after, before) {
        (Some(after), _) => format!("after {after}"),
        (None, Some(before)) => format!("before {before}"),
        (None, None) => "at the document's start".to_string(),
    };
    let place = match (g.kind, &g.placed) {
        _ if !g.spots.is_empty() => {
            g.spots.iter().map(|s| format!("side {} {}", s.side.0, at(&s.after, &s.before))).collect::<Vec<_>>().join(", ")
        }
        (GapKind::Moves, Placement::Order(sides)) => {
            let sides: Vec<String> = sides.iter().map(|s| s.0.to_string()).collect();
            format!("in side {}'s order", sides.join(","))
        }
        _ => at(&g.after, &g.before),
    };
    format!("left at its default: gap {} ({}) {place}, placed {}", g.id.0, kind_name(g.kind), default_of(g))
}

/// Returns the lines naming each place the merge kept once (the merge
/// record's §5, case (g); `Record::deduped`).
///
/// Words both sides added alike at one spot are kept as one side has them,
/// and the other side's copy stays in that side with any link on it. A
/// side is named by its place, side 0 the head, and its copy by the address
/// the record's `sides` holds for it, or by its number where they hold
/// none.
fn dedup_lines(record: &Record) -> Vec<String> {
    let named = |side: &SideIx| if side.0 == 0 { "the head" } else { "the side" };
    let address = |side: &SideIx| {
        record
            .sides
            .get(usize::from(side.0))
            .map_or_else(|| format!("side {}", side.0), |s| s.address().to_string())
    };
    record
        .deduped()
        .iter()
        .map(|d| {
            let kept: Vec<&str> = d.kept.iter().map(named).collect();
            let mut dropped: Vec<&SideIx> = Vec::new();
            for (side, _) in &d.dropped {
                if !dropped.contains(&side) {
                    dropped.push(side);
                }
            }
            let stays: Vec<String> = dropped.iter().map(|side| format!("{}'s copy stays in {}", named(side), address(side))).collect();
            format!(
                "gap {}: matching words were added on both sides — kept once, as {} {} them; {}, and any links on it stay there, not carried into the merge",
                d.gap.0,
                kept.join(" and "),
                if kept.len() == 1 { "has" } else { "have" },
                stays.join("; ")
            )
        })
        .collect()
}

/// Returns each place the merge kept once as the report carries it,
/// `deduped`: `{gap, kept, dropped}`, each dropped run spelled as the
/// record spells a gap's runs.
fn deduped_value(record: &Record) -> Value {
    record
        .deduped()
        .iter()
        .map(|d| {
            let dropped: Vec<Value> = d
                .dropped
                .iter()
                .map(|(side, run)| json!({"side": side.0, "i_start": run.address_at(0).map(|a| a.to_string()), "width": run.width.to_string()}))
                .collect();
            json!({"gap": d.gap.0, "kept": d.kept.iter().map(|s| s.0).collect::<Vec<u8>>(), "dropped": dropped})
        })
        .collect()
}

/// Returns the sides' placeholder clause of a part's line: where one or
/// two published sides of the merge show the part as a placeholder.
fn sides_clause(merged: &Merged, part: &WindowPart) -> String {
    let doc = merged.inputs.doc.to_string();
    let names: Vec<String> = part.sides.iter().map(|side| version_name(&doc, side)).collect();
    match names.as_slice() {
        [] => String::new(),
        [one] => format!("; version {one} shows a placeholder here"),
        many => format!("; versions {} show a placeholder here", many.join(" and ")),
    }
}

/// Returns `words` quoted and rendered inert, or `fallback` where this
/// merger may not read them: a quoted text is another hand's, so it is
/// rendered one line and inert before the line is composed (SP-15).
fn quoted(words: Option<&str>, fallback: &str) -> String {
    match words {
        Some(words) => format!("“{}”", render_inert(words)),
        None => fallback.to_string(),
    }
}

/// Returns a member's version in the document `doc`: the components after
/// it, the address itself where none follow.
fn version_name(doc: &str, member: &Address) -> String {
    let member = member.to_string();
    member.strip_prefix(&format!("{doc}.")).map_or(member.clone(), ToString::to_string)
}

/// Returns the version the shot mints, the head's last component plus one.
fn next_version(merged: &Merged) -> String {
    let head = merged.inputs.head.to_string();
    let doc = merged.inputs.doc.to_string();
    let Some(version) = head.strip_prefix(&format!("{doc}.")) else { return head };
    version.rsplit_once('.').map_or_else(
        || version.parse::<u64>().map_or_else(|_| version.to_string(), |k| (k + 1).to_string()),
        |(prefix, last)| last.parse::<u64>().map_or_else(|_| version.to_string(), |k| format!("{prefix}.{}", k + 1)),
    )
}

/// Returns a window part as the report carries it.
fn part_value(part: &WindowPart) -> Value {
    json!({
        "words": part.words.as_deref().map(render_inert),
        "origin": part.origin.to_string(),
        "version": part.version.as_ref().map(ToString::to_string),
        "answer": part.answer.map(|a| match a {
            OriginAnswer::PublishFirst => "publish_first",
            OriginAnswer::Drop => "leave_out",
            OriginAnswer::KeepPrivate => "keep_private",
            OriginAnswer::Counterpart => "window",
        }),
    })
}

/// Returns a gap's placement as this run composed it.
///
/// It is spelled as a `--resolve` choice the core takes back: the sides'
/// order where sides were placed, `after:`/`before:` the anchor where one
/// stands, the one side's order where the gap lies at an end of M, `omit`
/// where nothing was placed.
fn default_of(gap: &Gap) -> String {
    let order = |sides: &[SideIx]| {
        format!("order:{}", sides.iter().map(|s| s.0.to_string()).collect::<Vec<_>>().join(","))
    };
    let own_sides = || {
        let mut sides: Vec<SideIx> = Vec::new();
        for (side, _) in &gap.runs {
            if !sides.contains(side) {
                sides.push(*side);
            }
        }
        order(&sides)
    };
    match &gap.placed {
        Placement::Order(sides) => order(sides),
        Placement::After => gap.after.as_ref().map_or_else(own_sides, |a| format!("after:{a}")),
        Placement::Before => gap.before.as_ref().map_or_else(own_sides, |b| format!("before:{b}")),
        Placement::Omitted => "omit".to_string(),
    }
}

/// Returns a gap's kind as the record spells it.
fn kind_name(kind: GapKind) -> &'static str {
    match kind {
        GapKind::Order => "order",
        GapKind::Anchor => "anchor",
        GapKind::Corner => "corner",
        GapKind::Cut => "cut",
        GapKind::Collision => "collision",
        GapKind::Moves => "moves",
    }
}

/// Returns a run's family as the report spells it.
fn family_name(family: Family) -> &'static str {
    match family {
        Family::Own => "own",
        Family::Window => "window",
        Family::DraftNative => "draft",
    }
}

#[cfg(test)]
mod tests {
    use skep_client::merge::{Flag, Spot};

    use super::*;

    /// One window part, its words and pair as a test names them.
    fn part(version: Option<&str>, named_since: bool) -> WindowPart {
        let span = skep_client::publication::ISpan { chain: "1.0.1.0.69.0.1".to_string(), first: 1, width: 5 };
        WindowPart {
            key: skep_client::publication::PartKey { run: 1, part: 0 },
            words: Some("quote".to_string()),
            after: Some("the cat".to_string()),
            ordinal: 8,
            origin: parse_address("1.0.1.0.69").expect("an address"),
            owner: None,
            span,
            record: version.map(|_| parse_address("1.0.1.0.69.0.2.1").expect("an address")),
            counterpart: None,
            version: version.map(|v| parse_address(v).expect("an address")),
            sides: Vec::new(),
            admits: Vec::new(),
            answer: None,
            named_since,
        }
    }

    /// A part a record named after its answer was given says the version
    /// that published it and the two answers it takes (§6); the wording the
    /// run cannot stage over a real daemon, a record landing between one
    /// process's two reads.
    #[test]
    fn a_part_named_since_its_answer_says_the_version_that_published_it() {
        let line = named_since_line(&part(Some("1.0.1.0.64.1"), true));
        assert_eq!(line, "nothing was published — 1.0.1.0.69’s words were published in 1.0.1.0.64.1 after you answered; answer for them again: --window 1.0.1.0.64.1 or --leave-out 1.0.1.0.64.1");
    }

    /// A passage's words are rendered one line and inert before a line
    /// quotes them (SP-15): a newline or an escape in a document's words
    /// cannot forge a line of the terminal's.
    #[test]
    fn a_quoted_passage_cannot_forge_a_line() {
        assert_eq!(quoted(Some("a\nb\x1b[31m"), "unread"), "“a<U+000A>b<U+001B>[31m”");
        assert_eq!(quoted(None, "a passage you cannot read"), "a passage you cannot read");
    }

    /// A default's line says where the gap stands (§1.5): a `moves` gap
    /// with spots at each side's place for the one set of words, a spine's
    /// `moves` gap in the order of the side the spine took and never "at
    /// the document's start", and every other gap by its anchor (the
    /// mutants that keep the anchors' line for a `moves` gap say the start).
    #[test]
    fn a_default_line_names_each_sides_place_and_no_place_for_the_spines_order() {
        let a = |s: &str| parse_address(s).expect("an address");
        let gap = |kind: GapKind, after: Option<Address>, placed: Placement, spots: Vec<Spot>| Gap {
            id: GapId(2),
            kind,
            after,
            before: None,
            runs: vec![(SideIx(0), skep_client::merge::Run::new(a("1.0.1.0.1"), 20, 3))],
            placed,
            settled: false,
            resolved_by: None,
            spots,
        };
        let spots = vec![
            Spot { side: SideIx(0), after: Some(a("1.0.1.0.1.0.1.4")), before: Some(a("1.0.1.0.1.0.1.5")) },
            Spot { side: SideIx(1), after: None, before: Some(a("1.0.1.0.1.0.1.1")) },
        ];
        assert_eq!(
            default_line(&gap(GapKind::Moves, None, Placement::Order(vec![SideIx(0)]), spots)),
            "left at its default: gap 2 (moves) side 0 after 1.0.1.0.1.0.1.4, side 1 before 1.0.1.0.1.0.1.1, placed order:0"
        );
        assert_eq!(
            default_line(&gap(GapKind::Moves, None, Placement::Order(vec![SideIx(1)]), Vec::new())),
            "left at its default: gap 2 (moves) in side 1's order, placed order:1"
        );
        assert_eq!(
            default_line(&gap(GapKind::Cut, Some(a("1.0.1.0.1.0.1.4")), Placement::After, Vec::new())),
            "left at its default: gap 2 (cut) after 1.0.1.0.1.0.1.4, placed after:1.0.1.0.1.0.1.4"
        );
        assert_eq!(
            default_line(&gap(GapKind::Corner, None, Placement::After, Vec::new())),
            "left at its default: gap 2 (corner) at the document's start, placed order:0"
        );
    }

    /// A place the merge kept once is said and reported (§5, case (g)): the
    /// gap, the head whose copy M holds, and the side's address, where its
    /// copy and any link on it stay; `deduped` spells the dropped run as the
    /// record spells a gap's; a record whose dedup kept nothing once says
    /// and reports nothing (the mutants that name the wrong side or leave
    /// the place unsaid).
    #[test]
    fn a_place_kept_once_names_the_copy_kept_and_where_the_other_stays() {
        use skep_client::merge::{Role, Run, RunCounts, SideAt, ValueLog};
        let a = |s: &str| parse_address(s).expect("an address");
        let doc = a("1.0.1.0.1");
        let gap = Gap {
            id: GapId(2),
            kind: GapKind::Order,
            after: Some(a("1.0.1.0.1.0.1.7")),
            before: None,
            runs: vec![
                (SideIx(0), Run::new(doc.clone(), 8, 6)),
                (SideIx(1), Run::new(doc.clone(), 17, 6)),
            ],
            placed: Placement::Order(vec![SideIx(0)]),
            settled: true,
            resolved_by: Some(ResolvedBy::Rule),
            spots: Vec::new(),
        };
        let mut record = Record {
            doc: doc.clone(),
            base: a("1.0.1.0.1.1"),
            sides: vec![
                SideAt::Member { at: a("1.0.1.0.1.2"), role: Role::Head },
                SideAt::Member { at: a("1.0.1.0.1.1.1"), role: Role::Alternative },
            ],
            landed: None,
            claims: Vec::new(),
            runs: RunCounts { a: 2, b: 3, m: 3 },
            retries: 0,
            gaps: vec![gap],
            values: ValueLog { dedup: true, retype: false, applied: vec![GapId(2)] },
            answers: Vec::new(),
            replaces: None,
            by: "skep-client".into(),
            link: None,
        };
        assert_eq!(
            dedup_lines(&record),
            ["gap 2: matching words were added on both sides — kept once, as the head has them; the side's copy stays in 1.0.1.0.1.1.1, and any links on it stay there, not carried into the merge"]
        );
        assert_eq!(
            deduped_value(&record),
            json!([{"gap": 2, "kept": [0], "dropped": [{"side": 1, "i_start": "1.0.1.0.1.0.1.17", "width": "6"}]}])
        );
        record.values.applied.clear();
        assert_eq!(
            (dedup_lines(&record), deduped_value(&record)),
            (Vec::<String>::new(), json!([]))
        );
    }

    /// Each misfit keeps its command's words (§6): an answer that fits
    /// nothing, one naming words already published, one naming words a
    /// second answer also names.
    #[test]
    fn a_misfit_says_which_answer_fits_nothing_or_names_the_same_words_twice() {
        let key = parse_address("1.0.1.0.64.1").expect("an address");
        let origin = parse_address("1.0.1.0.69").expect("an address");
        assert_eq!(misfit_line(&Misfit::FitsNothing { flag: Flag::Window, key: key.clone(), published_in: vec![] }), "--window 1.0.1.0.64.1 answers nothing here — no words in this merge are published in 1.0.1.0.64.1");
        assert_eq!(misfit_line(&Misfit::FitsNothing { flag: Flag::KeepPrivate, key: origin.clone(), published_in: vec![key.clone()] }), "--keep-private 1.0.1.0.69 answers nothing here — 1.0.1.0.69’s words in this merge are already published in 1.0.1.0.64.1; answer --window 1.0.1.0.64.1 or --leave-out 1.0.1.0.64.1");
        assert_eq!(misfit_line(&Misfit::FitsNothing { flag: Flag::LeaveOut, key: origin.clone(), published_in: vec![] }), "--leave-out 1.0.1.0.69 answers nothing here — this merge asks nothing about 1.0.1.0.69’s words");
        assert_eq!(misfit_line(&Misfit::TwoAnswers { first: Flag::Window, second: Flag::LeaveOut, key: key.clone() }), "--window 1.0.1.0.64.1 and --leave-out 1.0.1.0.64.1 both answer the same words — give one");
    }
}
