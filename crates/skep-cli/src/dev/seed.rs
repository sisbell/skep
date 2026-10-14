//! THE SEED — `skep-dev seed`'s run, in order. THE INPUTS as the `skep`
//! command finds them: the origin (`--board`), the store (`--dir`), the
//! principal (`--principal`, else the store's one binding at the board),
//! the key under `Purpose::Sign` (`--key`, else the store's lookup), the
//! account off the bindings line, checked against `principal_prefix`; the
//! corpus (`--repo` / `SKEP_SEARCH_CORPUS`, `--pin`, `--from`) and the
//! shapes' counts. THE CHECKS before any write, each a halt (exit 3): an
//! unclaimed board — "claim first"; `writes.halted`; a claimant that is not
//! the account this store binds here; the handshake's own pre-check. THE
//! CUT: `documents + drafts + 1` documents of the one rule — the editions,
//! the drafts past the tier, the second account's one. THE MANIFEST beside
//! the key store, then ONE content-scoped signed session for every write of
//! the claimant's, and the shapes, serially, every write under its envelope
//! id and recorded after its ack:
//!
//! 1. EDITIONS — one staging draft D for the run; per cut document the
//!    per-byte insert into D at D's next fresh ordinal, the attested mint of
//!    the edition E, the `image` of the stretch, and the shot naming
//!    `draft: D` with the stretch's run → `E.1`, which a guest reads.
//! 2. LINKS — every backticked `.md` cite in an edition's bytes
//!    ([`cites`]): the from-end the cite's own span as a V-spec, the home
//!    the citing edition, the to-end the cut document holding the named
//!    section where the cite names one, else the cited file's first cut
//!    document, address-form, typed the citation class; a cite naming a
//!    file outside the set — unresolved, ambiguous or not in the cut — lands
//!    with a GHOST `to`, `<account>.0.<m>` past the account's last mint by
//!    [`GHOST_GAP`], one per distinct name, never minted.
//! 3. VERSIONS — every k-th document from the first, rotated APPENDED (the
//!    cut's next paragraph, the following document's first, as a second
//!    value run after the edition's own), REMOVED (the last paragraph
//!    holding a cite, else the last — a link floats), CHANGED (one sentence
//!    replaced between two reference runs); `base` the birth version with
//!    `base_extent` its extent, the ack `E.2`. The FIRST edition is always
//!    among them, and its shot carries THE WINDOW: [`WINDOW_WIDTH`]
//!    positions of the first draft W between its own run and the appended
//!    one — W is not the frame's draft, so the run stays a window a guest
//!    meets as `withheld` and the claimant reads; W is minted and filled
//!    just ahead of that shot.
//! 4. DRAFTS — the remaining drafts, the cut's documents past the tier,
//!    minted flagless and filled from the signed session, no attest.
//! 5. THE SECOND ACCOUNT — keyless, top-level: `next_account_prefix` under
//!    the node and `delegate` from a bare principal-0 session, its home from
//!    a bare session as the new principal, one draft holding the document
//!    past the drafts; the one place the claimant's signed session does not
//!    reach, so on a board that refuses bare sessions (ENFORCING) it is
//!    skipped, said once, and the JSON says so.
//!
//! Then the reads for the report — the positions before and after, the
//! reclaim floor — and ONE JSON object on stdout, always; TALK on stderr:
//! the mode line, the corpus, the manifest's line ([`manifest_line`]: a new
//! seed, every write held, or a resume and the one write a resume cannot
//! see), a progress line per hundred editions and at the last, one line per
//! phase as it ends, the first refusal of each transient token the writer
//! retries, the retries, the floor, the reopen warning. A second run under
//! the same key finds every write recorded, writes nothing — said as it
//! opens the manifest — and answers the same object with
//! `already_seeded: true`.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_client::address::parent_account;
use skep_client::board::{frames, Token};
use skep_client::derive::Mode;
use skep_client::dial::plaintext_non_loopback_warning;
use skep_client::store::{KeySelector, KeyStore, Purpose};
use skep_client::Halt;
use skep_corpus::{Corpus, Cut, Error as CorpusError, Sourced};

use crate::args::dev::DevLine;
use crate::board::{Placed, Run, VSpec, Writer, CITATION_TYPE};
use crate::manifest::{path_for, Header, Manifest, TOOL};
use crate::shared::{board_of, data, principal_or_bound, select_key, store_of, Stop};
use crate::terminal::talk;

/// The window's width: B1-S7's "240 positions".
pub const WINDOW_WIDTH: u64 = 240;

/// What the changed arm puts in a sentence's place.
pub const CHANGED_SENTENCE: &str = "This sentence stands changed in the second version.";

/// How far past the account's last mint the ghosts begin, so the drafts this
/// run lands after the links, and whatever the person mints next, occupy
/// none of them.
pub const GHOST_GAP: u64 = 1 << 20;

/// The versions' arms, in rotation.
const ARMS: [&str; 3] = ["appended", "removed", "changed"];

/// The id the second account's step is recorded under — the seed's LAST
/// record, every skip arm's included, so a manifest holding it holds every
/// write of the seed.
const LAST_STEP: &str = "account";

/// What the run found in the manifest, said as it opens it, before the
/// session: a new seed; a seed whose every write is recorded ([`LAST_STEP`]),
/// so the run writes nothing; or a seed to RESUME — with the one write a
/// resume cannot see: the one the run before had in flight when it stopped,
/// which may stand on the board unrecorded and is made again under this
/// run's session, where its envelope id holds nothing (wire.md §Correlation
/// and idempotency: an `id` holds on its session alone).
fn manifest_line(manifest: &Manifest) -> String {
    let path = manifest.path().display();
    if manifest.is_new() {
        format!("manifest: {path} — a new seed of this board; each write is recorded there after the board's ack")
    } else if manifest.recorded(LAST_STEP).is_some() {
        format!(
            "manifest: {path} records every write of this seed ({} lines): this run writes nothing",
            manifest.held()
        )
    } else {
        format!(
            "manifest: {path} holds {} lines of this seed: the run resumes after them. A write the run before this one had in flight \
             when it stopped may stand on the board unrecorded; it is made again here, and a mint or a shot then lands twice — an \
             envelope id holds within one session alone (wire.md §Correlation and idempotency). Where the board's exact shape \
             matters, seed a fresh board instead",
            manifest.held()
        )
    }
}

/// A phase's elapsed seconds, as its end line says them.
fn phase_secs(seconds: &BTreeMap<&'static str, Duration>, phase: &str) -> f64 {
    seconds.get(phase).copied().unwrap_or_default().as_secs_f64()
}

/// `skep-dev seed`.
pub fn seed(c: &DevLine) -> Result<(), Stop> {
    let started = Instant::now();
    // THE INPUTS — every usage refusal ahead of any socket.
    let board = board_of(c)?;
    let repo = c.repo()?;
    if !repo.is_dir() {
        return Err(crate::args::Usage(format!(
            "--repo (or SKEP_SEARCH_CORPUS): {} is not a directory",
            repo.display()
        ))
        .into());
    }
    let pin = c.pin().to_string();
    let from = c.from().map(str::to_string);
    let documents = c.documents()?;
    let every = c.versions()?;
    let drafts = c.drafts()?;
    let store = store_of(c)?;
    let given = c.principal()?;
    let key_file = c.key_file()?;
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    // THE CORPUS, judged before the board is dialed.
    let corpus = Corpus::open(&repo, &pin).map_err(|e| corpus_halt(e, &pin))?;
    let corpus = match &from {
        Some(subtree) => corpus.under(subtree),
        None => corpus,
    };
    // THE CHECKS (§2.4): the mode line as `skep health` says it, then each halt.
    let health = board.health()?;
    let mode = Mode::of(&health);
    talk(format!(
        "mode {} (claimant {}, local_trust {}) — derived from the pair, no mode field (AUTH-5.86)",
        mode.name(),
        health.claimant().unwrap_or("null"),
        health.local_trust()
    ));
    let Some(claimant) = health.claimant().map(str::to_string) else {
        return Err(Halt::face(
            "this board is unclaimed",
            "/health answers auth.claimant null: every write but the claim's own would refuse claim_first, and this tool never claims — the claim is a person door",
            format!("claim first — `skep claim --board {} --dir {}` at a terminal — then run again", board.dialed(), store.root().display()),
        )
        .into());
    };
    if health.body["writes"]["halted"].as_bool() == Some(true) {
        return Err(Halt::face(
            "this board has stopped accepting writes",
            "/health answers writes.halted true: the write path's halt, or the kernel's poison — every write answers `poisoned` until a restart",
            "read the board's operator stream for the cause, restart it (RUNBOOK.md §5), then run again",
        )
        .into());
    }
    let principal = principal_or_bound(given, &store, &board)?;
    let key = select_key(key_file.as_deref(), &store, &board, principal, Purpose::Sign)?;
    let bound = store.enrollment_for(board.dialed(), principal)?;
    let Some((account, _)) = bound else {
        return Err(Halt::face(
            format!("claimed by {claimant}; no key in this store is bound to it"),
            format!("the store at {} holds no bindings line for principal {principal} at {}", store.root().display(), board.dialed()),
            "run from the store that claimed this board, or `skep bind` the claim's three facts into this one",
        )
        .into());
    };
    if claimant != account {
        return Err(Halt::face(
            format!("claimed by {claimant}; no key in this store is bound to it"),
            format!("this store's binding for principal {principal} at {} names account {account}, and the board's claimant is {claimant}", board.dialed()),
            "pass --principal for the account that claimed this board, or seed the board this store claimed",
        )
        .into());
    }
    let seated = board.principal_prefix(principal)?;
    if seated.as_deref() != Some(account.as_str()) {
        return Err(Halt::face(
            format!("the board does not seat principal {principal} at {account}"),
            format!("principal_prefix({principal}) answers {}, and the store's binding names {account}", seated.as_deref().unwrap_or("null")),
            "check --principal and the store's bindings file; this tool writes nothing under an account the board does not seat for the key",
        )
        .into());
    }
    let signer = store.signer(&KeySelector::Path(&key.path))?;
    // THE CUT: the editions, the drafts past the tier, the second account's one.
    let wanted = documents + drafts + 1;
    let cut = corpus.cut_sourced(wanted).map_err(|e| cut_halt(e, documents, drafts))?;
    let bytes: u64 =
        cut.documents.iter().take(documents).map(|s| s.document.bytes.len() as u64).sum();
    talk(format!(
        "corpus: {} at {} under {}{}: {documents} documents ({bytes} bytes) as editions, {drafts} drafts past the tier, one document for the second account; every {every}th document a second version",
        repo.display(),
        pin,
        corpus.rule(),
        from.as_deref().map(|f| format!(" from `{f}`")).unwrap_or_default()
    ));
    // THE MANIFEST, keyed by H.1's chain.
    let term = board.board_term()?.ok_or_else(|| Halt::face("this board has no H.1", "the head document's first member is not readable on a claimed board: its journal is damaged below H.1", "restore the board (RUNBOOK.md §2)"))?;
    let chain: String = term.chain.iter().map(|b| format!("{b:02x}")).collect();
    let header = Header {
        chain: chain.clone(),
        board: board.dialed().as_str().to_string(),
        account: account.clone(),
        principal,
        pin: pin.clone(),
        cut: corpus.rule().to_string(),
        from: from.clone(),
        documents,
        versions: every,
        drafts,
    };
    let manifest = Manifest::open(path_for(store.root(), &chain), header)?;
    talk(manifest_line(&manifest));
    let before = health.log_position();
    // THE SESSION, then the shapes.
    let mut w = Writer::open(&board, signer, principal)?;
    if manifest.is_new() {
        // No manifest: a board holding documents past doc 1 is not fresh,
        // and no probe guesses what landed there (§5.1 arm (c), the one read).
        let second = format!("{account}.0.2");
        if w.registered(&second)? {
            let file = if manifest.is_torn() { "holds no complete line" } else { "does not exist" };
            return Err(Halt::face(
                "this board holds documents past doc 1, and no manifest records a seed",
                format!(
                    "{second} is registered, and {} {file}: another run, or another hand, wrote here — a run of this tool stopped inside its first write leaves a board so",
                    manifest.path().display()
                ),
                "seed a FRESH board (a new data directory, claimed anew), or restore the manifest beside this store; this tool never guesses what another run landed",
            )
            .into());
        }
    }
    let mut run = Seed {
        w,
        manifest,
        account: account.clone(),
        cut,
        documents,
        every,
        drafts,
        wrote: false,
        next_ordinal: 1,
        seconds: BTreeMap::new(),
    };
    // Each phase said as it ends — what it holds now, this run's writes and
    // the manifest's together, and its seconds — so no phase past the
    // editions runs silent at the 10^4 tier.
    let staging = run.staging()?;
    let editions = run.editions()?;
    let links = run.links(&editions)?;
    talk(format!(
        "links: {} in all, {} of them naming files outside the set (ghosts: {}) ({:.1} s)",
        links.addresses.len(),
        links.outside,
        links.ghosts.len(),
        phase_secs(&run.seconds, "links")
    ));
    let versions = run.versions(&editions)?;
    let window = versions.first().and_then(|v| {
        v.window.as_deref().map(|draft| {
            format!(", the window — {WINDOW_WIDTH} positions of {draft} — in {}", v.member)
        })
    });
    talk(format!(
        "versions: {} in all{} ({:.1} s)",
        versions.len(),
        window.unwrap_or_default(),
        phase_secs(&run.seconds, "versions")
    ));
    let draft_addrs = run.drafts()?;
    talk(format!(
        "drafts: {} in all ({:.1} s)",
        draft_addrs.len(),
        phase_secs(&run.seconds, "drafts")
    ));
    let second = run.second_account(mode)?;
    let account_secs = phase_secs(&run.seconds, "account");
    match second["skipped"].as_str() {
        Some(why) => talk(format!("second account: skipped — {why} ({account_secs:.1} s)")),
        None => talk(format!(
            "second account: {}, principal {}, its home {} and one draft {} ({account_secs:.1} s)",
            second["account"].as_str().unwrap_or("?"),
            second["principal"],
            second["home"].as_str().unwrap_or("?"),
            second["draft"].as_str().unwrap_or("?")
        )),
    }
    // THE READS FOR THE REPORT.
    let after = board.health()?.log_position();
    let floor = run.w.reclaim_floor()?;
    let retries = run.w.retries;
    talk(format!(
        "retries: write_busy {}, durability {}, board_unavailable {}",
        retries.write_busy, retries.durability, retries.board_unavailable
    ));
    talk(format!("floor: /chain?at=0 answers {floor} (the journal's reclaim floor; 0 while genesis is retained)"));
    talk(format!("this board now holds {after} commits; its next open replays them"));
    let Seed { w, manifest, wrote, seconds, .. } = run;
    w.close()?;
    let total = started.elapsed();
    let secs = |d: Duration| (d.as_secs_f64() * 1000.0).round() / 1000.0;
    let tier = match documents {
        1_000 => Value::String("10^3".into()),
        10_000 => Value::String("10^4".into()),
        _ => Value::Null,
    };
    let object = json!({
        "tool": TOOL,
        "board": board.dialed().as_str(),
        "account": account,
        "principal": principal,
        "corpus": {"repo": repo.display().to_string(), "pin": pin, "cut": corpus.rule(), "from": from, "tier": tier, "documents": documents, "bytes": bytes},
        "staging": {"drafts": [staging]},
        "editions": {"count": editions.len(), "first": editions.first().map(|e| e.0.clone()), "last": editions.last().map(|e| e.0.clone()), "members": editions.len() + versions.len()},
        "links": {
            "count": links.addresses.len(),
            "type": CITATION_TYPE,
            "home": "citing",
            "from": "span",
            "to": "section-or-first-document",
            "outside": {"rule": "ghost", "count": links.outside, "ghosts": links.ghosts},
            "first": links.addresses.first(),
        },
        "versions": {"count": versions.len(), "rule": format!("every {every}th"), "difference": "rotated", "members": versions.iter().map(|v| v.member.clone()).collect::<Vec<_>>(), "arms": versions.iter().map(|v| v.arm).collect::<Vec<_>>()},
        "drafts": {"count": draft_addrs.len(), "addresses": draft_addrs},
        "window": versions.first().map(|v| json!({"edition": v.edition, "member": v.member, "draft": v.window, "width": WINDOW_WIDTH})),
        "second_account": second,
        "positions": {"before": before, "after": after},
        "floor": floor,
        "retries": {"write_busy": retries.write_busy, "durability": retries.durability, "board_unavailable": retries.board_unavailable},
        "seconds": {
            "editions": secs(seconds.get("editions").copied().unwrap_or_default()),
            "links": secs(seconds.get("links").copied().unwrap_or_default()),
            "versions": secs(seconds.get("versions").copied().unwrap_or_default()),
            "drafts": secs(seconds.get("drafts").copied().unwrap_or_default()),
            "account": secs(seconds.get("account").copied().unwrap_or_default()),
            "total": secs(total),
        },
        "manifest": manifest.path().display().to_string(),
        "already_seeded": !wrote,
    });
    data(object.to_string())?;
    Ok(())
}

/// The halt a corpus that cannot be opened is.
fn corpus_halt(e: CorpusError, pin: &str) -> Halt {
    Halt::face(
        format!("the corpus cannot be read at {pin}"),
        e.to_string(),
        "pass --pin a commit the repository holds, or --repo (SKEP_SEARCH_CORPUS) a checkout holding it; a dev command that silently seeds nothing is no command",
    )
}

/// The halt a corpus too short for the shapes is.
fn cut_halt(e: CorpusError, documents: usize, drafts: usize) -> Halt {
    match e {
        CorpusError::Short { cut, wanted } => Halt::face(
            format!("the corpus yields {cut} documents under the rule, and this run needs {wanted}"),
            format!("{documents} editions, {drafts} drafts past the tier and the second account's one document are cut by one rule from the paragraph source; the source ran out"),
            format!("pass --documents at most {}, fewer --drafts, or a larger corpus (--from a wider subtree)", cut.saturating_sub(drafts + 1)),
        ),
        other => Halt::face("the corpus cannot be cut", other.to_string(), "check the repository and the pin"),
    }
}

/// One edition landed: the document and its first member.
type Edition = (String, String);

/// What the links phase landed.
struct Links {
    addresses: Vec<String>,
    outside: usize,
    ghosts: BTreeMap<String, String>,
}

/// One second version landed.
struct Version {
    edition: String,
    member: String,
    arm: &'static str,
    /// The draft the shot windows, on the first edition.
    window: Option<String>,
}

/// The run: the session, the manifest, the cut, the counts, and whether a
/// write was made.
struct Seed<'b> {
    w: Writer<'b>,
    manifest: Manifest,
    account: String,
    cut: Cut,
    documents: usize,
    every: usize,
    drafts: usize,
    wrote: bool,
    /// The staging draft's next fresh content ordinal — the plan's own
    /// arithmetic, advanced for every stretch whether landed now or before.
    next_ordinal: u64,
    seconds: BTreeMap<&'static str, Duration>,
}

impl Seed<'_> {
    /// The write recorded under `id`, or made by `perform` and recorded with
    /// `item` — the address under `addr` where the write mints one.
    fn step(
        &mut self,
        id: &str,
        perform: impl FnOnce(&mut Writer<'_>) -> Result<(Option<String>, Value), Halt>,
    ) -> Result<Option<String>, Halt> {
        if let Some(v) = self.manifest.recorded(id) {
            return Ok(v["addr"].as_str().map(str::to_string));
        }
        let (addr, mut item) = perform(&mut self.w)?;
        if let Some(a) = &addr {
            item["addr"] = Value::String(a.clone());
        }
        self.manifest.record(id, item)?;
        self.wrote = true;
        Ok(addr)
    }

    /// The address a step recorded, which a later phase leans on.
    fn landed(&self, id: &str) -> Result<String, Halt> {
        self.manifest.recorded(id).and_then(|v| v["addr"].as_str()).map(str::to_string).ok_or_else(
            || {
                Halt::face(
                    format!("the manifest holds no address for `{id}`"),
                    "a later shape leans on a write an earlier one should have recorded",
                    "move the manifest aside and seed a fresh board; this tool never guesses",
                )
            },
        )
    }

    fn timed<T>(
        &mut self,
        phase: &'static str,
        body: impl FnOnce(&mut Self) -> Result<T, Halt>,
    ) -> Result<T, Halt> {
        let t = Instant::now();
        let out = body(self)?;
        *self.seconds.entry(phase).or_default() += t.elapsed();
        Ok(out)
    }

    fn document(&self, index: usize) -> &Sourced {
        &self.cut.documents[index]
    }

    /// The staging draft D.
    fn staging(&mut self) -> Result<String, Halt> {
        let account = self.account.clone();
        let d = self.step("staging:mint", |w| {
            Ok((Some(w.mint_draft(&account, "staging:mint")?), json!({})))
        })?;
        self.landed_or(d, "staging:mint")
    }

    fn landed_or(&self, addr: Option<String>, id: &str) -> Result<String, Halt> {
        match addr {
            Some(a) => Ok(a),
            None => self.landed(id),
        }
    }

    /// EDITIONS: the five steps per cut document.
    fn editions(&mut self) -> Result<Vec<Edition>, Halt> {
        self.timed("editions", |s| {
            let staging = s.landed("staging:mint")?;
            let mut out = Vec::with_capacity(s.documents);
            let started = Instant::now();
            for i in 0..s.documents {
                let name = s.document(i).document.name.clone();
                let bytes = s.document(i).document.bytes.clone();
                let n = bytes.len() as u64;
                let at = s.next_ordinal;
                s.next_ordinal += n;
                let (d, b) = (staging.clone(), bytes.clone());
                s.step(&format!("{name}:draft"), |w| {
                    w.insert(None, &d, at, &b, &format!("{name}:draft"))?;
                    Ok((None, json!({"at": at, "len": n})))
                })?;
                let edition = s.step(&format!("{name}:edition"), |w| {
                    Ok((Some(w.mint_edition(&format!("{name}:edition"))?), json!({})))
                })?;
                let edition = s.landed_or(edition, &format!("{name}:edition"))?;
                let (e, d) = (edition.clone(), staging.clone());
                let member = s.step(&format!("{name}:shot"), |w| {
                    let runs = w.image(&d, at, n)?;
                    let placed = placed_values(runs, &bytes)?;
                    Ok((
                        Some(w.shot(&e, &d, None, &placed, &format!("{name}:shot"))?),
                        json!({"edition": e}),
                    ))
                })?;
                let member = s.landed_or(member, &format!("{name}:shot"))?;
                out.push((edition, member));
                if (i + 1) % 100 == 0 || i + 1 == s.documents {
                    talk(format!(
                        "editions: {} of {} landed ({:.1} s)",
                        i + 1,
                        s.documents,
                        started.elapsed().as_secs_f64()
                    ));
                }
            }
            Ok(out)
        })
    }

    /// LINKS from the cites, with the ghosts.
    fn links(&mut self, editions: &[Edition]) -> Result<Links, Halt> {
        self.timed("links", |s| {
            let resolver = Resolver::new(&s.cut.sources);
            let mut first_document: HashMap<String, usize> = HashMap::new();
            for (i, sourced) in s.cut.documents.iter().take(s.documents).enumerate() {
                for p in &sourced.paragraphs {
                    first_document.entry(p.file.clone()).or_insert(i);
                }
            }
            let last_mint: u64 = editions.last().and_then(|(e, _)| e.rsplit('.').next()?.parse().ok()).unwrap_or(1);
            let mut ghosts: BTreeMap<String, String> = BTreeMap::new();
            let mut outside = 0usize;
            let mut addresses = Vec::new();
            for i in 0..s.documents {
                let name = s.document(i).document.name.clone();
                let bytes = s.document(i).document.bytes.clone();
                for (j, cite) in cites(&bytes).into_iter().enumerate() {
                    let id = format!("{name}:link:{}", j + 1);
                    let to = match target(&s.cut, s.documents, &first_document, &resolver, &cite) {
                        Target::Document(k) => editions[k].0.clone(),
                        Target::Ghost(file) => {
                            outside += 1;
                            let ghost_id = format!("ghost:{file}");
                            let next = ghosts.len() as u64;
                            let account = s.account.clone();
                            let g = s.step(&ghost_id, |_| Ok((Some(format!("{account}.0.{}", last_mint + GHOST_GAP + next)), json!({"name": file}))))?;
                            let g = s.landed_or(g, &ghost_id)?;
                            ghosts.entry(file.clone()).or_insert(g).clone()
                        }
                    };
                    // The from-end's SOURCE is the edition's birth member, not the
                    // bare address: `image` on a bare published address answers
                    // the trunk HEAD (head-float) where the store resolves a
                    // V-spec against the address named, and the two must agree
                    // for the signature to hold; a version address answers its
                    // own member everywhere.
                    let (home, member) = editions[i].clone();
                    let (h, t, from, width) = (home.clone(), to.clone(), cite.offset as u64 + 1, cite.len as u64);
                    let link = s.step(&id, |w| {
                        let addr = w.link(&h, VSpec { source: &member, from, width }, &t, &id)?;
                        Ok((Some(addr), json!({"home": h, "source": member, "to": t, "from": {"ordinal": from, "width": width}, "cite": cite.path, "section": cite.section})))
                    })?;
                    addresses.push(s.landed_or(link, &id)?);
                }
            }
            Ok(Links { addresses, outside, ghosts })
        })
    }

    /// VERSIONS: every k-th document from the first, the arms rotated, the
    /// first edition's shot carrying the window.
    fn versions(&mut self, editions: &[Edition]) -> Result<Vec<Version>, Halt> {
        self.timed("versions", |s| {
            let staging = s.landed("staging:mint")?;
            let chosen: Vec<usize> = (0..s.documents).step_by(s.every).collect();
            let mut out = Vec::with_capacity(chosen.len());
            for (k, &i) in chosen.iter().enumerate() {
                let arm = ARMS[k % 3];
                let name = s.document(i).document.name.clone();
                let bytes = s.document(i).document.bytes.clone();
                let n = bytes.len() as u64;
                let (edition, birth) = editions[i].clone();
                let shot_id = format!("{name}:version:shot");
                // The window rides the first edition's shot: its draft W first.
                let window = if i == 0 { Some(s.draft(s.documents)?) } else { None };
                let member = match arm {
                    "appended" => {
                        let next = s.cut.documents[i + 1].paragraphs.first().map(|p| &s.cut.documents[i + 1].document.bytes[p.offset..p.offset + p.len]).unwrap_or_default();
                        let stretch = [b"\n\n".as_slice(), next].concat();
                        let m = stretch.len() as u64;
                        let at = s.next_ordinal;
                        s.next_ordinal += m;
                        let (d, st) = (staging.clone(), stretch.clone());
                        s.step(&format!("{name}:version:insert"), |w| {
                            w.insert(None, &d, at, &st, &format!("{name}:version:insert"))?;
                            Ok((None, json!({"at": at, "len": m})))
                        })?;
                        let (e, d, b, win) = (edition.clone(), staging.clone(), birth.clone(), window.clone());
                        s.step(&shot_id, |w| {
                            let mut placed = placed_values(w.image(&e, 1, n)?, &bytes)?;
                            if let Some(win) = &win {
                                placed.extend(w.image(win, 1, WINDOW_WIDTH)?.into_iter().map(|run| Placed { run, bytes: None }));
                            }
                            placed.extend(placed_values(w.image(&d, at, m)?, &stretch)?);
                            let member = w.shot(&e, &d, Some((&b, n)), &placed, &shot_id)?;
                            Ok((Some(member), json!({"edition": e, "arm": arm, "appended": {"len": m}, "window": win})))
                        })?
                    }
                    "removed" => {
                        let (start, end) = dropped_range(s.document(i), &cites(&bytes));
                        let (e, d, b) = (edition.clone(), staging.clone(), birth.clone());
                        s.step(&shot_id, |w| {
                            let mut placed = Vec::new();
                            if start > 0 {
                                placed.extend(placed_values(w.image(&e, 1, start as u64)?, &bytes[..start])?);
                            }
                            if end < bytes.len() {
                                placed.extend(placed_values(w.image(&e, end as u64 + 1, (bytes.len() - end) as u64)?, &bytes[end..])?);
                            }
                            let member = w.shot(&e, &d, Some((&b, n)), &placed, &shot_id)?;
                            Ok((Some(member), json!({"edition": e, "arm": arm, "dropped": {"offset": start, "len": end - start}})))
                        })?
                    }
                    _ => {
                        let (a, len) = sentence_to_change(&bytes);
                        let stretch = CHANGED_SENTENCE.as_bytes().to_vec();
                        let m = stretch.len() as u64;
                        let at = s.next_ordinal;
                        s.next_ordinal += m;
                        let (d, st) = (staging.clone(), stretch.clone());
                        s.step(&format!("{name}:version:insert"), |w| {
                            w.insert(None, &d, at, &st, &format!("{name}:version:insert"))?;
                            Ok((None, json!({"at": at, "len": m})))
                        })?;
                        let (e, d, b) = (edition.clone(), staging.clone(), birth.clone());
                        s.step(&shot_id, |w| {
                            let mut placed = Vec::new();
                            if a > 0 {
                                placed.extend(placed_values(w.image(&e, 1, a as u64)?, &bytes[..a])?);
                            }
                            placed.extend(placed_values(w.image(&d, at, m)?, &stretch)?);
                            if a + len < bytes.len() {
                                placed.extend(placed_values(w.image(&e, (a + len) as u64 + 1, (bytes.len() - a - len) as u64)?, &bytes[a + len..])?);
                            }
                            let member = w.shot(&e, &d, Some((&b, n)), &placed, &shot_id)?;
                            Ok((Some(member), json!({"edition": e, "arm": arm, "replaced": {"offset": a, "len": len}, "with": CHANGED_SENTENCE})))
                        })?
                    }
                };
                let member = s.landed_or(member, &shot_id)?;
                out.push(Version { edition, member, arm, window });
            }
            Ok(out)
        })
    }

    /// One draft past the tier: the cut's document `index`, minted flagless
    /// and filled from the signed session.
    fn draft(&mut self, index: usize) -> Result<String, Halt> {
        let name = format!("draft-{:05}", index + 1);
        let account = self.account.clone();
        let mint_id = format!("{name}:mint");
        let addr = self.step(&mint_id, |w| {
            Ok((Some(w.mint_draft(&account, &mint_id)?), json!({"document": index + 1})))
        })?;
        let addr = self.landed_or(addr, &mint_id)?;
        let bytes = self.document(index).document.bytes.clone();
        let (a, insert_id) = (addr.clone(), format!("{name}:insert"));
        self.step(&insert_id, |w| {
            w.insert(None, &a, 1, &bytes, &insert_id)?;
            Ok((None, json!({"len": bytes.len()})))
        })?;
        Ok(addr)
    }

    /// DRAFTS: the ten past the tier — the first already landed ahead of the
    /// window's shot.
    fn drafts(&mut self) -> Result<Vec<String>, Halt> {
        self.timed("drafts", |s| (0..s.drafts).map(|j| s.draft(s.documents + j)).collect())
    }

    /// THE SECOND ACCOUNT, keyless and top-level, from bare sessions on a
    /// permissive board; skipped where the board refuses them — the phase's
    /// line says which, recorded now or before. Recorded under [`LAST_STEP`]
    /// whichever arm it takes, the seed's last record.
    fn second_account(&mut self, mode: Mode) -> Result<Value, Halt> {
        self.timed("account", |s| {
            if let Some(v) = s.manifest.recorded(LAST_STEP) {
                let mut v = v.clone();
                v.as_object_mut().map(|m| m.remove("id"));
                return Ok(v);
            }
            let skipped = |why: &str| json!({"skipped": why});
            if mode == Mode::Enforcing {
                let v = skipped("ENFORCING: the board refuses bare sessions, and a keyless account opens no signed session");
                s.manifest.record(LAST_STEP, v.clone())?;
                s.wrote = true;
                return Ok(v);
            }
            let Some(node) = s.w.bare(0)? else {
                let v = skipped("the board refused a bare session as principal 0");
                s.manifest.record(LAST_STEP, v.clone())?;
                s.wrote = true;
                return Ok(v);
            };
            let parent = parent_account(&s.account).unwrap_or_else(|| s.account.rfind(".0.").map(|at| s.account[..at].to_string()).unwrap_or_else(|| "1".to_string()));
            let (prefix, new_id) = match s.manifest.recorded("account:delegate") {
                Some(v) => (v["addr"].as_str().unwrap_or_default().to_string(), v["principal"].as_u64().unwrap_or(2)),
                None => {
                    let prefix = s.w.board().next_account_prefix(&parent)?.ok_or_else(|| Halt::face(format!("next_account_prefix({parent}) answers null"), "the node admits no further top-level account", "this board cannot hold the second account; nothing more was written"))?;
                    let mut new_id = 2u64;
                    while s.w.board().principal_prefix(new_id)?.is_some() {
                        new_id += 1;
                        if new_id > 1_000 {
                            return Err(Halt::face("no free principal id under 1000", "every id probed is registered", "this board is not a fresh dev board; seed another"));
                        }
                    }
                    (prefix, new_id)
                }
            };
            let (p, t) = (prefix.clone(), node.clone());
            let delegated = s.step("account:delegate", |w| {
                let v = w.write_as(&t, frames::delegate(&p, new_id, None), "account:delegate")?;
                let addr = skep_client::board::acked_addr(&v).map(str::to_string).ok_or_else(|| Halt::face("delegate answered no address", v.to_string(), "this board is not speaking the wire this tool expects"))?;
                Ok((Some(addr), json!({"principal": new_id})))
            })?;
            let account2 = s.landed_or(delegated, "account:delegate")?;
            let Some(token) = s.w.bare(new_id)? else {
                return Err(Halt::face(format!("the board refused a bare session as principal {new_id}"), "the account was delegated, and its principal's bare session is refused on a board that honoured principal 0's", "run again on a permissive board"));
            };
            let home = s.mint_as(&token, &account2, "account:home")?;
            let draft = s.mint_as(&token, &account2, "account:draft:mint")?;
            let bytes = s.document(s.documents + s.drafts).document.bytes.clone();
            let (d, tk) = (draft.clone(), token.clone());
            s.step("account:draft:insert", |w| {
                w.insert(Some(&tk), &d, 1, &bytes, "account:draft:insert")?;
                Ok((None, json!({"len": bytes.len()})))
            })?;
            let v = json!({"account": account2, "principal": new_id, "home": home, "draft": draft});
            s.manifest.record(LAST_STEP, v.clone())?;
            s.wrote = true;
            Ok(v)
        })
    }

    /// A flagless mint into `account` from `token`'s bare session.
    fn mint_as(&mut self, token: &Token, account: &str, id: &str) -> Result<String, Halt> {
        let (t, a) = (token.clone(), account.to_string());
        let addr = self.step(id, |w| {
            let v = w.write_as(&t, json!({"op": "create_new_document", "account": a}), id)?;
            let addr = skep_client::board::acked_addr(&v).map(str::to_string).ok_or_else(|| {
                Halt::face(
                    "the mint answered no address",
                    v.to_string(),
                    "this board is not speaking the wire this tool expects",
                )
            })?;
            Ok((Some(addr), json!({})))
        })?;
        self.landed_or(addr, id)
    }
}

/// `runs` as `image` answered them over `bytes`' positions, in V-order,
/// each placed with the bytes at its positions — the runs the commit copies
/// in.
fn placed_values(runs: Vec<Run>, bytes: &[u8]) -> Result<Vec<Placed>, Halt> {
    let mut at = 0usize;
    let mut out = Vec::with_capacity(runs.len());
    for run in runs {
        let end = at + run.width as usize;
        if end > bytes.len() {
            return Err(Halt::face(
                "image answered more positions than the stretch holds",
                format!("{} positions over {} bytes", end, bytes.len()),
                "this is a board fault; nothing more was written",
            ));
        }
        out.push(Placed { run, bytes: Some(bytes[at..end].to_vec()) });
        at = end;
    }
    if at != bytes.len() {
        return Err(Halt::face(
            "image answered fewer positions than the stretch holds",
            format!("{at} positions over {} bytes", bytes.len()),
            "this is a board fault; nothing more was written",
        ));
    }
    Ok(out)
}

// ── THE CITES ──────────────────────────────────────────────────────────────

/// One backticked `.md` cite in a document's bytes: the token's byte range
/// inside the ticks, the path it names, and the section after `§` where
/// one is inside the ticks (`` `client.md §1.2` ``).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cite {
    pub offset: usize,
    pub len: usize,
    pub path: String,
    pub section: Option<String>,
}

/// Every cite in `bytes`, in order: a backticked token on one line whose
/// first word ends in `.md`, alone or followed by `§` and a section.
pub fn cites(bytes: &[u8]) -> Vec<Cite> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'`' {
            i += 1;
            continue;
        }
        let Some(rel) = bytes[i + 1..].iter().position(|&b| b == b'`' || b == b'\n') else { break };
        let j = i + 1 + rel;
        if bytes[j] == b'\n' {
            i = j + 1;
            continue;
        }
        if let Some(cite) = cite_of(&bytes[i + 1..j], i + 1) {
            out.push(cite);
        }
        i = j + 1;
    }
    out
}

/// The cite a backticked token is, where it is one.
fn cite_of(token: &[u8], offset: usize) -> Option<Cite> {
    let text = std::str::from_utf8(token).ok()?;
    let (path, rest) = match text.split_once(char::is_whitespace) {
        Some((p, r)) => (p, r.trim()),
        None => (text, ""),
    };
    if path.len() <= 3 || !path.ends_with(".md") {
        return None;
    }
    let section = if rest.is_empty() {
        None
    } else {
        let s = rest.strip_prefix('§')?.trim();
        (!s.is_empty()).then(|| s.to_string())
    };
    Some(Cite { offset, len: token.len(), path: path.to_string(), section })
}

/// The tier's `.md` files a cite's name is resolved against: the exact path
/// where the name holds a directory, else the one file of that basename.
pub struct Resolver {
    paths: Vec<String>,
    by_basename: HashMap<String, Vec<usize>>,
}

impl Resolver {
    pub fn new(paths: &[String]) -> Resolver {
        let mut by_basename: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, p) in paths.iter().enumerate() {
            let base = p.rsplit('/').next().unwrap_or(p).to_string();
            by_basename.entry(base).or_default().push(i);
        }
        Resolver { paths: paths.to_vec(), by_basename }
    }

    /// The file `name` names, or none where it names no tracked file, or
    /// several.
    pub fn resolve(&self, name: &str) -> Option<&str> {
        if let Some(p) = self.paths.iter().find(|p| *p == name) {
            return Some(p);
        }
        if name.contains('/') {
            return None;
        }
        match self.by_basename.get(name).map(Vec::as_slice) {
            Some([one]) => Some(&self.paths[*one]),
            _ => None,
        }
    }
}

/// A link's to-end: a cut document, or a ghost for an outside name.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Document(usize),
    Ghost(String),
}

/// Whether `heading` opens `section`: the section's text, then the end or a
/// character that is no letter or digit — `1.2` opens `1.2 The second` and
/// not `1.23 …`.
fn opens_section(heading: &str, section: &str) -> bool {
    heading
        .strip_prefix(section)
        .is_some_and(|rest| rest.is_empty() || !rest.starts_with(|c: char| c.is_alphanumeric()))
}

/// The to-end of a cite: the document holding the named section's heading
/// where the cite names one and the heading is in the cut, else the cited
/// file's first cut document; a ghost where the name resolves to no file of
/// the set.
fn target(
    cut: &Cut,
    documents: usize,
    first_document: &HashMap<String, usize>,
    resolver: &Resolver,
    cite: &Cite,
) -> Target {
    let Some(file) = resolver.resolve(&cite.path) else { return Target::Ghost(cite.path.clone()) };
    let Some(&first) = first_document.get(file) else { return Target::Ghost(cite.path.clone()) };
    if let Some(section) = &cite.section {
        for (i, sourced) in cut.documents.iter().take(documents).enumerate() {
            if sourced.paragraphs.iter().any(|p| {
                p.file == file && p.heading.as_deref().is_some_and(|h| opens_section(h, section))
            }) {
                return Target::Document(i);
            }
        }
    }
    Target::Document(first)
}

// ── THE VERSIONS' CHOICES ──────────────────────────────────────────────────

/// The bytes the removed arm drops: the last paragraph holding a cite, else
/// the last paragraph — with the blank line before it (after it, for the
/// first) — or, where the document is one paragraph, its last sentence.
pub fn dropped_range(sourced: &Sourced, cites: &[Cite]) -> (usize, usize) {
    let bytes = &sourced.document.bytes;
    let paragraphs = &sourced.paragraphs;
    let holds_cite = |p: &skep_corpus::Paragraph| {
        cites.iter().any(|c| c.offset >= p.offset && c.offset < p.offset + p.len)
    };
    let chosen =
        paragraphs.iter().rposition(holds_cite).unwrap_or(paragraphs.len().saturating_sub(1));
    if paragraphs.len() > 1 {
        let p = &paragraphs[chosen];
        return if chosen > 0 { (p.offset - 2, p.offset + p.len) } else { (0, p.len + 2) };
    }
    let boundaries = sentence_boundaries(bytes);
    match boundaries.iter().rev().find(|&&b| b + 1 < bytes.len()) {
        Some(&b) => (b + 1, bytes.len()),
        None => match bytes.iter().rposition(|&b| b == b'\n') {
            Some(nl) => (nl, bytes.len()),
            None => (floor_char_boundary(bytes, bytes.len() / 2), bytes.len()),
        },
    }
}

/// The sentence the changed arm replaces: the second sentence where the
/// document has one — after the first boundary's whitespace, through the
/// second — else the first, else the first line.
pub fn sentence_to_change(bytes: &[u8]) -> (usize, usize) {
    let boundaries = sentence_boundaries(bytes);
    match boundaries.as_slice() {
        [first, second, ..] => {
            let mut a = first + 1;
            while a < *second && (bytes[a] == b' ' || bytes[a] == b'\n') {
                a += 1;
            }
            (a, second + 1 - a)
        }
        [only] => (0, only + 1),
        [] => (0, bytes.iter().position(|&b| b == b'\n').unwrap_or(bytes.len())),
    }
}

/// The byte indices of the periods that end a sentence: a `.` followed by a
/// space, a line break or the end.
fn sentence_boundaries(bytes: &[u8]) -> Vec<usize> {
    (0..bytes.len())
        .filter(|&i| {
            bytes[i] == b'.'
                && (i + 1 == bytes.len() || bytes[i + 1] == b' ' || bytes[i + 1] == b'\n')
        })
        .collect()
}

/// `at` or the nearest character boundary below it, where `bytes` is UTF-8.
fn floor_char_boundary(bytes: &[u8], mut at: usize) -> usize {
    while at > 0 && std::str::from_utf8(bytes).is_ok_and(|t| !t.is_char_boundary(at)) {
        at -= 1;
    }
    at
}
