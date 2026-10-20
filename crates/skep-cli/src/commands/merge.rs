//! `skep merge`, the fourteenth command, over `skep_client::merge`.
//!
//! Its design is the merge record,
//! `_designs/CLIENT/2026-10-14-reconciling-versions-design.md` in the
//! skep-ux-design repository, §6 "The CLI and the agent adapter";
//! `client.md` §2.1 lists the thirteen it stands beside, none touching
//! content — this one does, which is why the library's `merge` feature is
//! on for this crate alone. The board, the document and one side are named
//! — an alternative member, a draft with the member it was staged from, or
//! a fork of one of the document's published versions, whose base is the
//! source the board serves for it (`doc_metadata`'s `source`; a fork taken
//! from the bare document before its first version is refused with that
//! reason) — and the head where the feed walk should not supply it; the
//! command composes the merge under the rules and prints the `Merged`
//! report as one JSON document on stdout, exit 0. With `--publish` it lands
//! the merge as the document's next version with its record, with `--into`
//! it lands the merged list in a draft, and the report then carries the
//! landing. A `--resolve ⟨gap⟩=⟨choice⟩` settles a gap the rules left open;
//! `--journal` names the merge journal (decision 7), `--kind` the record
//! kind's type address (decision 9's row is interim and unpinned, so the
//! caller names it). The board's refusal is exit 1, a halt exit 3.
//!
//! The session is the command's own: the selected signing key (the file
//! `--key` or `SKEP_KEY` names, else the store's), a content-scoped signed
//! session opened as `skep session` opens its, and closed on every exit —
//! the shot and the record's link are signed by that key, so `SKEP_SESSION`
//! is never read here: a token cannot sign.
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
//! `counts`, `cap`, `over_cap`, `prior`, `ignored`, `as_of`, `landed`, and
//! to each gap a `default` — its placement as this run composed it, in
//! `--resolve`'s own spelling, so a merger copies it and varies it.
//! `--json` is every command's flag and changes nothing here: the report
//! is JSON always.

use serde_json::{json, Value};
use skep_address::Address;
use skep_client::address::parse_address;
use skep_client::board::{Board, Scope};
use skep_client::ceremony::handshake::{handshake, Session, Site};
use skep_client::dial::plaintext_non_loopback_warning;
use skep_client::halt::{Halt, Refused};
use skep_client::merge::{
    compose, head_of, land, Choice, Family, Gap, GapId, GapKind, Inputs, Landed, Landing, Merged,
    Merger, Options, Placement, Record, Refusal, Resolution, ResolvedBy, Side, SideIx,
};
use skep_client::sign::Signer;
use skep_client::store::{KeySelector, KeyStore, Purpose};

use super::{
    board_of, data_verbatim, has_terminal, key_named, principal_or_bound, select_key, store_of,
    talk, Stop,
};
use crate::args::{CommandLine, Usage};

/// How the merge lands, where a landing flag is given.
enum Land {
    /// `--publish`: one shot from the head, the record beside it.
    Publish,
    /// `--into ⟨draft⟩`: the merged list landed in this draft by identity.
    Into(Address),
}

/// What the command line asks, judged whole before any socket opens.
///
/// §2.3's exit 2 is the flags' shape alone.
struct Asked {
    doc: Address,
    side: Side,
    base: Option<Address>,
    head: Option<Address>,
    kind: Address,
    journal: Option<Address>,
    options: Options,
    landing: Option<Land>,
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

/// Runs the merge under the session: the head, the composition, the landing.
///
/// The landing is made where one is asked, and the report goes on stdout.
///
/// # Errors
///
/// Returns a halt where no head is named and none is on the feed, and the
/// halt the feed's read comes to; a library refusal ([`refused`]) from the
/// composition or the landing; and the halt a write stdout refuses comes
/// to.
fn run(
    board: &Board,
    session: &Session<'_>,
    signer: &dyn Signer,
    asked: &Asked,
) -> Result<(), Stop> {
    let token = session.token();
    let head = match &asked.head {
        Some(h) => h.clone(),
        None => head_of(board, Some(token), &asked.doc)?.ok_or_else(|| {
            Halt::face(
                format!("no head version of {} is on the feed", asked.doc),
                "no publish row under the document names a trunk version: it has no version yet, or its rows lie below the feed's retention floor",
                "name the head with --head <D.h>, or publish the document's first version",
            )
        })?,
    };
    talk(format!(
        "merging {} with {head}, the head of {}, at {}",
        side_named(&asked.side, asked.base.as_ref()),
        asked.doc,
        board.dialed()
    ));
    let inputs = Inputs {
        doc: asked.doc.clone(),
        head,
        base: asked.base.clone(),
        sides: vec![asked.side.clone()],
        options: asked.options.clone(),
        kind: asked.kind.clone(),
    };
    let merged = compose(board, Some(token), &inputs).map_err(refused)?;
    say_composed(&merged);
    let mut report = report_of(&merged);
    if let Some(landing) = &asked.landing {
        let merger = Merger { token, account: session.account(), signer };
        let journal = asked.journal.clone();
        let landing = match landing {
            Land::Publish => Landing::Shot { merger, draft: None, journal },
            Land::Into(into) => Landing::Draft { merger, into: into.clone(), journal },
        };
        let landed = land(board, &merged, landing).map_err(refused)?;
        say_landed(&merged, &landed);
        report["landed"] = landed_value(&merged, &landed);
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
    /// In this order: `--doc` absent or no address; no side, two sides,
    /// `--draft` without `--base`, a side no address, or `--base` no
    /// address; `--head`, `--kind` (or `SKEP_MERGE_KIND`, required, a
    /// variable that is not UTF-8 text refused too), `--journal` no address;
    /// `--retries` no count; a `--resolve` outside its grammar; `--into` no
    /// address.
    fn of(c: &CommandLine, by: &ResolvedBy) -> Result<Asked, Usage> {
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
            (None, Some(s), None) => {
                // The library refuses an unbased draft (`BaseUnknown`, the
                // merge record's decision 15); the command refuses the form
                // first.
                let Some(b) = c.value("--base") else {
                    return Err(Usage("--base <D.k> is required with --draft <S>: the version the draft was staged from, which no read of the board answers".into()));
                };
                (Side::Draft { at: address("--draft", s)?, position: None }, Some(address("--base", b)?))
            }
            (None, None, Some(f)) => (Side::Fork(address("--fork", f)?), None),
            (None, None, None) => {
                return Err(Usage("one side is required: --alternative <D.k.m>, --draft <S> --base <D.k>, or --fork <F>".into()))
            }
            // The grammar's forms refuse two sides ahead of this; said again
            // rather than assumed.
            _ => return Err(Usage("one side alone: --alternative, --draft or --fork".into())),
        };
        let head = c.value("--head").map(|h| address("--head", h)).transpose()?;
        let kind = match c.merge_kind()? {
            Some(k) => address("--kind", &k)?,
            None => return Err(Usage("--kind <address> (or SKEP_MERGE_KIND) is required: the merge record kind's type address, which the caller names while its row is unpinned".into())),
        };
        let journal = c.value("--journal").map(|j| address("--journal", j)).transpose()?;
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
            None => None,
        };
        Ok(Asked { doc, side, base, head, kind, journal, options, landing })
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

/// Returns the stop a library refusal comes to (§2.3's exit 1).
///
/// The exit is "the board refused": a halt the library faced keeps its own
/// code; every typed refusal is the board's verdict under the wire code the
/// refusal is named for, its detail the refusal's own words — the side
/// whose base cannot be read, the second draft, a fork's bare source and a
/// base named for a fork, which the library refuses before any image, among
/// them, under their own names.
fn refused(r: Refusal) -> Stop {
    let code = match &r {
        Refusal::Halt(_) => "",
        Refusal::BaseUnknown(_) => "base_unknown",
        Refusal::BareSource { .. } => "bare_source",
        Refusal::ForkBaseNamed { .. } => "fork_base_named",
        Refusal::TwoDrafts => "two_drafts",
        Refusal::Unreadable(_) | Refusal::WindowWithheld(_) => "withheld",
        Refusal::NoSuchDocument(_) => "doc_not_registered",
        Refusal::TooFragmented { .. } => "image_too_large",
        Refusal::HistoryBusy => "history_busy",
        Refusal::OverCap { .. } => "too_many_runs",
        Refusal::NeedsSignedSession => "signed_session_required",
    };
    match r {
        Refusal::Halt(h) => Stop::Halt(h),
        other => Stop::Halt(Halt::Refused(Refused {
            status: 200,
            code: code.to_string(),
            detail: Some(other.to_string()),
            op: None,
            body: Value::Null,
        })),
    }
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

/// Says the talk after a landing: what landed, or the daughter and the re-run.
fn say_landed(merged: &Merged, landed: &Landed) {
    match landed {
        Landed::Member { address, position, claims, record, .. } => {
            talk(format!(
                "published {address} at position {position}, the next version of {}; the record's link is {record}{}",
                merged.inputs.doc,
                if claims.is_empty() { String::new() } else { format!("; claims standing at the side: {}", claims.len()) }
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
        Landed::Draft { into, ops, record } => {
            talk(format!(
                "landed in the draft {into} in {ops} edit{}; the record's link is {record}",
                if *ops == 1 { "" } else { "s" }
            ));
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
fn landed_value(merged: &Merged, landed: &Landed) -> Value {
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
        Landed::Draft { into, ops, record } => json!({
            "draft": into.to_string(),
            "ops": ops,
            "record": record.to_string(),
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
