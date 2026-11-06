//! `skep merge`, the fourteenth command, over `skep_client::merge`.
//!
//! Its design is the merge record,
//! `_designs/CLIENT/2026-10-14-reconciling-versions-design.md` in the
//! skep-ux-design repository, §6 "The CLI and the agent adapter";
//! `client.md` §2.1 lists the thirteen it stands beside, none touching
//! content — this one does, which is why the library's `merge` feature is
//! on for this crate alone. The board, the document and one side are named
//! — an alternative member; a draft, read at the board's head, whose base is
//! the member the board records it was staged from (`doc_metadata`'s
//! `base`, read by the library; `--base` names it only to be checked, and
//! one the board's record does not derive is refused), the report's `sides`
//! carrying the position the draft was read at, which a verifier reads the
//! draft and its recorded base as of; or a fork of one of the document's
//! published versions, whose base is the source the board serves for it
//! (`doc_metadata`'s `source`) — a draft staged from, or a fork taken from,
//! the bare document before its first version is refused with that reason —
//! and the head where the feed walk should not supply it; the
//! command composes the merge under the rules — every read at one board
//! position, the report's `as_of` — and prints the `Merged` report as one
//! JSON document on stdout, exit 0. With `--publish` it lands the merge as
//! the document's next version with its record; with `--into` it lands the
//! merged list in a draft as ONE `set_arrangement` typed against that
//! position — refused whole where the draft changed since, the draft's base
//! re-recorded on the head and the merge marked beside it; with `--new` it
//! stages a fresh draft from the head and lands there; and the report then
//! carries the landing, naming a newer version published since where the
//! board tells one. A `--resolve ⟨gap⟩=⟨choice⟩` settles a gap the rules
//! left open; `--journal` names the merge journal (decision 7), `--kind`
//! the record kind's type address (decision 9's row is interim and
//! unpinned, so the caller names it). The board's refusal is exit 1, a halt
//! exit 3. A `withheld` refusal — a document the merger may not read, or an
//! origin a write's run windows — names the document, and the command says
//! beside it what the run did: nothing composed; the merge composed, and
//! nothing published or merged; nothing taken back or out. A journal the
//! merger may not read, or one the board does not register, is met at the
//! record, after the landing or the take-back: the library's halt says the
//! act stands with its record unwritten, exit 3.
//!
//! **The two take-backs** (skep #783), each with `--kind` and nothing of
//! the composition's: `--undo ⟨S⟩` puts the draft back as it stood before
//! the merge landed in it — its words and its base restored, the merge
//! taken out, in one write typed against the landing's position, so a
//! draft changed since is refused with nothing changed — and `--withdraw
//! ⟨S⟩` takes the merge out and keeps the words, the draft's next version
//! then an ordinary one. Each prints one JSON document carrying the act,
//! the draft, the write's position, the replacing record's link and the
//! case; where there is nothing to undo or take out the library's reason
//! is the refusal, exit 1, and nothing was sent.
//!
//! The session is the command's own: the selected signing key (the file
//! `--key` or `SKEP_KEY` names, else the store's), a content-scoped signed
//! session opened as `skep session` opens its, and closed on every exit —
//! the shot and the record's link are signed by that key, so `SKEP_SESSION`
//! is never read here: a token cannot sign. The library's refusals come to
//! their stops through the renderer the commands share (`commands.rs`'s
//! `refused`, under a `Step`), the take-backs' `history_reclaimed` worded
//! here ([`refused_taking_out`]).
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
//! `counts`, `cap`, `over_cap`, `prior`, `ignored`, `as_of` — the one
//! position every read of the composition was made at — `landed`, and to
//! each gap a `default` — its placement as this run composed it, in
//! `--resolve`'s own spelling, so a merger copies it and varies it. A draft
//! landing's `landed` carries the draft, the write's `position`, the
//! `record`, `head_moved` (the newer head told, else null) and `fresh`
//! (whether this run staged the draft). `--json` is every command's flag
//! and changes nothing here: the report is JSON always.

use serde_json::{json, Value};
use skep_address::Address;
use skep_client::address::parse_address;
use skep_client::board::{Board, Scope};
use skep_client::ceremony::handshake::{handshake, Session, Site};
use skep_client::dial::plaintext_non_loopback_warning;
use skep_client::halt::{Halt, Refused};
use skep_client::merge::{
    compose, head_of, land, undo, withdraw, Choice, Family, Gap, GapId, GapKind, Inputs, Landed,
    Landing, Merged, Merger, Options, Placement, Record, RecordLanding, Refusal, Resolution,
    ResolvedBy, Side, SideIx, Undone, Withdrawn,
};
use skep_client::sign::Signer;
use skep_client::store::{KeySelector, KeyStore, Purpose};

use super::{
    board_of, data_verbatim, has_terminal, key_named, principal_or_bound, refused, select_key,
    store_of, talk, Step, Stop,
};
use crate::args::{CommandLine, Usage};

/// How the merge lands, where a landing flag is given.
enum Land {
    /// `--publish`: one shot from the head, the record beside it.
    Publish,
    /// `--into ⟨draft⟩`: the merged list set as this draft's whole
    /// arrangement in one write, typed against the composition's position.
    Into(Address),
    /// `--new`: a fresh draft staged from the head, then the same write.
    New,
}

impl Land {
    /// Returns the step a refusal of this landing answers.
    fn step(&self) -> Step {
        match self {
            Land::Publish => Step::Publish,
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
    // Content scope, as `skep session` opens its (RES-63): the shot and the
    // record's link are content writes under this key.
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
/// Returns a halt where no head is named and none is on the feed, and the
/// halt the feed's read comes to; a library refusal ([`refused`]) from the
/// composition, the landing, the undo or the withdrawal; and the halt a
/// write stdout refuses comes to.
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
                let undone = undo(board, merger, draft, &asked.kind, asked.journal.as_ref())
                    .map_err(|r| refused_taking_out(draft, r, Step::Undo))?;
                say_undone(&undone);
                undone_value(&undone)
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
        None => head_of(board, Some(token), doc)?.ok_or_else(|| {
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
    let mut report = report_of(&merged);
    if let Some(landing) = landing {
        let journal = asked.journal.clone();
        let step = landing.step();
        let landing = match landing {
            Land::Publish => Landing::Shot { merger, draft: None, journal },
            Land::Into(into) => Landing::Draft { merger, into: Some(into.clone()), journal },
            Land::New => Landing::Draft { merger, into: None, journal },
        };
        let landed = land(board, &merged, landing).map_err(|r| refused(r, step))?;
        let fresh = matches!(asked.act, Act::Merge { landing: Some(Land::New), .. })
            && staged_here(&merged, &landed);
        say_landed(&merged, &landed, fresh);
        report["landed"] = landed_value(&merged, &landed, fresh);
    }
    data_verbatim(report.to_string().as_bytes())?;
    Ok(())
}

/// Returns whether a `--new` landing staged its draft in this run.
///
/// The library stages nothing where the standing record for the key already
/// names a draft landing, and reports that landing instead (its `Landing`
/// doc); the standing record is the composition's `prior`, so a landing
/// into the draft it names was found, not staged.
fn staged_here(merged: &Merged, landed: &Landed) -> bool {
    let Landed::Draft { into, .. } = landed else { return false };
    let standing = merged.prior.as_ref().and_then(|p| match &p.landed {
        Some(RecordLanding::Draft { draft, .. }) => Some(draft),
        _ => None,
    });
    standing != Some(into)
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
    /// `--retries` no count; a `--resolve` outside its grammar; `--into` no
    /// address. The three landings apart — `--publish`, `--into`, `--new` —
    /// and the two take-backs apart from them, the sides, `--doc`, `--base`,
    /// `--head` and each other are the grammar's forms, refused ahead of
    /// this.
    fn of(c: &CommandLine, by: &ResolvedBy) -> Result<Asked, Usage> {
        let taken_out = match (c.value("--undo"), c.value("--withdraw")) {
            (Some(s), _) => Some(Act::Undo(address("--undo", s)?)),
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
        let landing = match c.value("--into") {
            Some(into) => Some(Land::Into(address("--into", into)?)),
            None if c.switch("--publish") => Some(Land::Publish),
            None if c.switch("--new") => Some(Land::New),
            None => None,
        };
        Ok(Asked { act: Act::Merge { doc, side, base, head, options, landing }, kind, journal })
    }
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
/// The gap is its number as the report counts it, from 1; the choice is
/// `order:⟨side⟩,⟨side⟩…`, `after:⟨address⟩`, `before:⟨address⟩`,
/// `keep:⟨side⟩`, `both` or `omit`, a side its index as the report numbers
/// it.
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

/// Says the talk after an undo: the draft is back to how it stood before
/// the merge, its base — where the board records one — and the merge are
/// taken back, and the record's link where one was written.
fn say_undone(undone: &Undone) {
    let Undone { draft, position, record, restored } = undone;
    talk(format!(
        "took the merge back out of {draft} at position {position}: the draft is back to how it stood before the merge{}, and the merge is taken out{}",
        match restored {
            Some((base, extent)) => format!(", its base is {base} at {extent} positions again"),
            None => format!("; {draft} records no base, so none moved"),
        },
        record_said(record.as_ref())
    ));
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
/// row — and the base restored as `{at, extent}` (else null).
fn undone_value(undone: &Undone) -> Value {
    json!({
        "act": "undo",
        "draft": undone.draft.to_string(),
        "position": undone.position,
        "record": undone.record.as_ref().map(ToString::to_string),
        "case": if undone.restored.is_some() { "marker" } else { "feed" },
        "restored": undone.restored.as_ref().map(|(base, extent)| json!({"at": base.to_string(), "extent": extent.to_string()})),
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
/// It names the base and the counts, each unsettled gap in the copy's
/// register ("⟨n⟩ places need a choice"), the resolutions not applied, and
/// the cap where the list passes it.
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

/// Says the talk after a landing: what landed, or the daughter and the
/// re-run; at a draft landing the draft — the fresh one staged where `fresh`
/// — and, where the board told a newer head, that a newer version was
/// published since the merge was composed and the merge landed against the
/// head it composed on, so a merge composed again includes it.
fn say_landed(merged: &Merged, landed: &Landed, fresh: bool) {
    match landed {
        Landed::Member { address, position, claims, record, .. } => {
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
        Landed::Draft { into, position, record, head_moved } => {
            talk(format!(
                "landed in the draft {into} at position {position}{}; the record's link is {record}",
                if fresh {
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
        }
    }
}

/// Returns the report: the merge record's §7 `Merged`.
///
/// Its members are as the module's doc lists them: the record's own JSON
/// where the names coincide, M with each run's side and family, every gap
/// with its `default`, the counts against the cap, the prior record, the
/// unlanded record; `landed` null until a landing fills it.
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
        "ignored": merged.composed.ignored.iter().map(|r| r.gap.0).collect::<Vec<_>>(),
        "prior": merged.prior.as_ref().map_or(Value::Null, prior_of),
        "record": record,
        "as_of": merged.as_of,
        "landed": Value::Null,
    })
}

/// Returns the standing record for the key, as the report carries it.
///
/// It carries its public link, its key and where it landed.
fn prior_of(prior: &Record) -> Value {
    let key = prior.key();
    json!({
        "link": prior.link.as_ref().map(ToString::to_string),
        "key": {
            "doc": key.doc.to_string(),
            "base": key.base.to_string(),
            "sides": key.sides.iter().map(ToString::to_string).collect::<Vec<_>>(),
        },
        "landed": prior.to_value()["landed"].clone(),
    })
}

/// Returns the landing as the report carries it.
///
/// A draft landing carries the draft, the write's position, the record,
/// `head_moved` — the newer head the board told, else null — and `fresh`,
/// whether this run staged the draft.
fn landed_value(merged: &Merged, landed: &Landed, fresh: bool) -> Value {
    match landed {
        Landed::Member { address, position, claims, record, retries } => json!({
            "member": address.to_string(),
            "position": position,
            "claims": claims.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "record": record.to_string(),
            "retries": retries,
        }),
        Landed::AsDaughter { address, position } => json!({
            "daughter": address.to_string(),
            "position": position,
            "retries": merged.inputs.options.retries,
        }),
        Landed::Draft { into, position, record, head_moved } => json!({
            "draft": into.to_string(),
            "position": position,
            "record": record.to_string(),
            "head_moved": head_moved.as_ref().map(ToString::to_string),
            "fresh": fresh,
        }),
    }
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
