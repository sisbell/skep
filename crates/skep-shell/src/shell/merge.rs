//! The merge rows of `client.md` §4b.1 — `merge.compose`, `merge.land`,
//! `merge.undo`, `merge.withdraw` — and the compositions they stand on,
//! each reached from [`Shell::call`] alone: THE MERGE BRIDGE LANE, the
//! bridge of B3-S11's THE MERGE SCENE over `skep_client::merge` (the merge
//! record, `_designs/CLIENT/2026-10-14-reconciling-versions-design.md`
//! §1.5 and §7, in the skep-ux-design repository).
//!
//! THE FAMILY runs the merge library for the page: the page composes no
//! write. Every write this family makes is the library's — the landing's
//! one `set_arrangement` into the draft (`stage` first at a fresh one), the
//! shot, the record, the undo's and the withdrawal's one write each —
//! signed by the session's hand as the publication family's are; and every
//! answer is DATA with a code or a kind, never a string a person reads (the
//! strings `ux/copy.md`'s and the UI lane's).
//!
//! **`merge.compose`** — `{doc, alternative, into?}`, THE DRAFT SIDE
//! `{doc, draft, into?}`, or THE FORK `{doc, fork, into?}` — composes the
//! merge of the trunk's head with a daughter of the person's own, with a
//! draft of the family behind the head, or with a fork of one of the
//! document's versions — a document outside the chain the board records
//! standing on that version, another account's `stage` of it by its
//! recorded base, which each landing into it moves to the head, or its
//! `version` of it by its `source` (the merge record's §1.2 shape (4)) —
//! and LANDS it: M as the whole arrangement of `into` by the library's one
//! write, typed against the composition's read of the draft, the draft's
//! recorded base re-recorded to the head and the merge marked beside it; a
//! newer version published since compose is never refused, the write
//! landing on the head used and `head_moved` told (LAND AND TELL); a draft
//! changed since the compose's read refused `arrangement_moved`, the
//! board's verdict, nothing landed. `into` IS THE PAGE's: the draft
//! "continue in" lands at where it holds nothing unpublished, a level draft
//! of the family staged from the head where one stands, else none — a FRESH
//! draft staged from the head first, two commits (R3) — decided before the
//! act off the feed rows the page holds and followed here, never decided
//! afresh; read as UNTRUSTED input, its `doc_metadata` read before anything
//! is composed and a published draft or another account's refused
//! `not_owner` (skep #799). At the fork side `into` may name the fork
//! itself, its owner's: a fork its owner staged takes M at any head, its
//! recorded base moving to the head and the merge marked beside it, as a
//! draft does; a fork a `version` minted, which the board records no base
//! for, takes M only where its source is the head it was composed on —
//! written with no base and no marker — else the library's landing refuses
//! `fork_base_moved` with nothing written, the way on a fresh draft staged
//! from the head. The head is the trunk's head as the board stands, read up
//! the trunk from where the side starts — the trunk member a daughter's
//! address, a draft side's recorded base, or a fork's recorded base, else
//! its source, lies under — by the library's head read
//! (`skep_client::publication::standing`): the members past it by doubling,
//! then a binary search, which needs no feed walk and meets no retention
//! floor. A draft side the owner's account staged from the bare document,
//! or a fork of any account taken from it, starts at `doc` itself: its head
//! is read up from `doc`'s first member, and where no version stands yet
//! the side is refused `base_unknown` with `reason` `bare_source` naming
//! `doc`, nothing to merge onto. A board answering every member the
//! doubling asks refuses the row `shape` naming `doc_metadata` after 64
//! reads, nothing composed or landed (SP-17). Another account's draft
//! staged from the bare document, and a draft or a fork lying in no member
//! of `doc`'s chain, is refused before that read as the library refuses it,
//! `base_unknown` with `reason` `base_unknown`. A fork of `doc`'s owner's
//! own account — the owner's draft, which is the draft side, its words
//! re-minted at the shot — is refused by the composition, `base_unknown`
//! with `reason` `fork_of_owner`, nothing landed.
//! Where a side starts names no base: the library derives the base from
//! the bases the board recorded up the side's line, so a side begun before
//! the document's first version — a daughter published beside version 1,
//! or a draft or a fork still unpublished — composes over the document's
//! own arrangement from before that version, the report's `base` `doc`
//! itself, and the texts written apart meet in an `order` gap.
//! THE RE-OPEN: where the mark of the landing standing in `into` — its
//! marker, or on a draft the board records no base for, which carries
//! none, the landing standing by its `set_arrangement` rows, which stands
//! until it is taken back (skep #914; `Shell::standing_mark`) — names this
//! daughter — or, at the draft side, this draft, at the fork side this
//! fork, or no side where `into` is the fork itself, landed in itself — the
//! draft already carries this merge: the report with NOTHING LANDED,
//! composed on the mark's head, the side read as compose read it — a
//! daughter being immutable, a draft side at the mark's position where a
//! write under it landed since (by `/op-at`), else its image as it stands,
//! which is the same, or, where
//! a write under it landed between the composition and its landing, at the
//! position the person's own record of that landing names for it (the merge
//! record's §4, "for a draft read at N"; skep #1127): the record naming
//! `into` as landed in at the mark's `at`, where its key is another than
//! the composition's so read — a landing no record of theirs names there
//! staying as read at the mark's position — and a
//! fork as it stands, in the state the draft's landing composed it from —
//! and each unsettled gap's state read off the draft as it stands, settled
//! by the merger where the draft holds another of the gap's choices than
//! its default — every run removed whole, a side's runs removed whole, or
//! the sides' runs reordered whole — `placed` that choice (`edit_choice`);
//! an edit that holds none of them — inside a run's words, a side's runs
//! split or interleaved with another's — settles nothing, nor does any
//! edit at a spine's `moves` gap, whose runs tell no side's order of the
//! spine from another's. The report carries that reading and the
//! composition stands as composed, each gap read again off the words a
//! landing publishes (**`merge.land`**). At a `moves` gap with spots — one
//! identity two sides placed apart (CM-I33) — words the draft holds at
//! exactly one other holding side's spot, and neither at the default's nor
//! where the composition lays the default's words — after the left anchor
//! where the other side's move parts the default's (R4 i) — each spot read
//! by the anchors the draft still holds, are that side's
//! placement chosen: the merge is composed again with it, settled by the
//! merger, and the other gaps are read off the draft over that
//! composition, a gap the words raise at their new spot among them; words
//! at no holder's spot, or gone, settle nothing. The landing the mark
//! names is recorded first where no record of the person's names it and
//! that landing placed M — `into` read as of the mark's position, whatever
//! was edited in it since — by the library's `resume` naming `into` — a
//! record-only completion, no
//! write of the landing's sent again — so a landing cut off before its
//! record is recorded once when its draft is named: among them a landing
//! a `merge.compose` made whose record could not be written after its
//! write, which that call answered as the library's halt naming the draft,
//! or as `session_died`, leaving no composition standing; a fork landed in
//! itself, composed as it stands on the base its landing moved to the head,
//! is no longer the composition that landed, and nothing of it is recorded
//! there. The merger is the one
//! composing, `person` at the editor and `agent` with no person present
//! ([`Surface`]), since the
//! re-open reads the draft and not the hand that edited it. A fork arranged
//! since the landing is no re-open (the owner's rulings of 2026-11-20; skep
//! #770): the fork's state as composed — its `arranged_at` — is tested
//! against the state the person's own record of that landing keeps, where
//! one stands, else against the mark's `at`, and a fork that moved is
//! composed again on the trunk's head as it stands and landed over `into`,
//! `outcome` `landed`, replacing the earlier landing's words and any edits
//! made in `into` since: the report's `replaced` names each stretch it
//! replaced, positions of `into` as of the report's `as_of`, which
//! `merge.undo` puts back. At a fork landed in itself the fork's changes
//! are edits in the draft landed in, and it re-opens. The person's record
//! of the landing is read once at a re-open, for the draft side's position
//! and the fork's state alike, through the links of the kind to `into`
//! (`skep_client::merge::landing_record`): the record of theirs standing
//! for the landing the mark marks, whatever the merge landed in since —
//! never their newest record of the merge, which names another draft once
//! the merge lands there — and never another account's; a daughter's
//! re-open and a fork's landed in itself read none. THE MERGED ARM:
//! a daughter an active supersession claim of the person's own already
//! names, read by one `in_claims` at the daughter, is answered `merged`,
//! naming the member the claim's `new` names, NOTHING LANDED, and where no
//! record of the person's names that merge — another account's record of
//! the kind naming it stands for none — the record is written then through
//! the library's `record_published`, the resume of a stop between the shot
//! and its record (P14): every gap read off the member's image as THE
//! RE-OPEN reads a draft, and the record written only where the member
//! verifies against it (`skep_client::merge::verify` answering `Equal`).
//! A member that does not — edited past its gaps' choices, or holding window
//! parts its shot answered, which no read recovers — is answered with
//! `record_link` null and `unrecorded` naming why (`merge_refused` with
//! `member_differs` and the first position it differs at, `unreadable`
//! naming a document the verification could not read), nothing written: no
//! record claims what the member does not hold. A standing landing of
//! the person's own of the merge is read before a fresh draft is asked
//! for, as the library's landing reads it — this composition's landing
//! standing in a draft their own records of the key name, each draft's
//! newest such record that no take-back's record replaces, newest first,
//! so a landing of the key in another draft since, or the undo of one,
//! hides none — never the composition's `prior`, which can be another
//! account's, else their newest record of the merge with the states ignored
//! that names a draft landing no take-back of theirs replaces
//! (`skep_client::merge::landed_draft`), where its key is another than the
//! composition's — a fork or a draft side moved since that landing: that
//! draft is read as `into` is, refused `not_owner` where it is published or
//! another account's. Found by the key, it is the re-open, at the position
//! the library answers it at: the board's mark of that landing, or the
//! position its record names where the walk of a draft with no recorded
//! base needs a past state the board has reclaimed — a landing the library
//! cannot judge is never made a second time; found with the states ignored,
//! the call goes on as one naming that draft as `into` — the re-open where
//! its marker names the side — else the landing goes into it, a fork moved
//! since the landing over it among them, naming what it replaced, a record
//! of its own written. A record of the composition's own key whose draft no
//! longer holds its landing — taken back with the take-back's record
//! unwritten, or another hand's landing standing over it — names no draft
//! to land in: the page asked for a fresh draft, and the merge lands in one
//! (the merge record's decision 16), never over another landing or the
//! person's own words. The library is handed `into` none only where neither
//! read found a draft to land in (the survey §5 item 2). Where no draft a
//! record of the person's names still holds this composition's landing —
//! none written, or each taken back, its take-back's record written or not
//! — a landing of the merge begun in a draft of theirs and never recorded —
//! cut off between its one write and its record — is the library's refusal
//! at the first read, `merge_refused` with `landing_begun` naming the
//! `draft` and the `position`, nothing staged or written, so the merge
//! never lands twice (PUB-8.32): the way on is that draft named as `into`,
//! whose re-open records the landing — save where the board has reclaimed
//! the landing's position and the draft as it stands no longer holds the
//! merged list, a landing that cannot be judged and is recorded never —
//! then `merge.undo` to take it back, refused `merge_refused`
//! `history_reclaimed` where the board has reclaimed the state before the
//! landing, or, where the draft records a base, `merge.withdraw` to take it
//! out keeping its words. A landing of the person's own made between that
//! read and the landing — on another device, or by `skep merge --new`
//! naming the same kind — is the library's answer, found standing with
//! nothing staged: `fresh` is the library's `staged`, never whether `into`
//! was named. So another account's record of the kind never decides where a
//! merge lands.
//!
//! **`merge.land`** — `{resolutions?, answers?}` — publishes the merge from
//! the draft the standing composition landed in, THE SHOT CARRYING THE
//! SUPERSESSION CLAIM, then the record: ONE PATH for the shot, the
//! publication family's — the panel the page opened over the draft at the
//! composition's document, standing or held, with the switches and answers
//! it last sent, or one this row opens over the whole draft (every private
//! row OFF, the draft side named `also` so its words re-mint as the
//! document's own; at the fork side none, the fork's own words staying
//! windows onto its origin, each part asked), confirmed by the family's one
//! composition, signature and send (`Shell::confirm_standing`), under the
//! answers the call names, each keyed `⟨run⟩.⟨part⟩` as the panel keys
//! them. A panel of the draft that mints an edition or publishes into
//! another document is no landing's panel
//! (`shell/publication.rs`, **The landing**): the row is refused
//! `other_panel`, nothing composed or sent, that panel, the family's
//! standing one and the composition as they stood, no `resolutions` the
//! call named kept. The way on is `publication.cancel` of that panel — a held
//! one re-opened first in its own form, `publication.open` naming the draft
//! and the `doc` or `mint` the refusal names and no other member, since an
//! open passing another is refused the same (`shell/publication.rs`, **The
//! panels**) — then `merge.land` again; confirming it instead publishes the
//! draft as a document of its own, whose base no longer lies in the trunk's
//! chain, and the row is then refused `base_unrecorded`. The
//! landing goes on only over a draft that still carries the composition's
//! merge (skep #992): the draft's marker — read past that refusal where the
//! page's panel stands, by the open where the row opens its own — must name
//! the composition's side, or no side where a fork landed in itself, its
//! head and its position, the composition's own landing
//! (`Composition::marks`), before any panel is keyed on it. A draft
//! carrying another merge — another hand's landing since the compose, on
//! another device or by `skep merge`, or the same side composed on another
//! head — or another landing of this merge — another hand's, or this
//! hand's earlier one standing again — or carrying none, a withdrawal
//! since, is refused `no_merge` naming the draft: the page's panel, standing
//! or held, made the standing one as the page left it and keyed on nothing,
//! the panel the row opened dropped, nothing sent and no record written. The
//! composition is dropped with it, the draft no longer carrying it, so a
//! later `merge.undo` answers `no_merge` and never takes another hand's
//! landing back — save where the marker the draft carries is the one
//! a later landing of this session's in it set an earlier composition
//! aside at, put back by another device's undo: that composition
//! stands again, its merge the draft's (**The compositions**).
//! The marker so tested is the one the panel is keyed on, and
//! the shot sends only under the panel it is handed, so the record written
//! after the acknowledgment names the merge the member holds. A panel the
//! page opened under another merge marker than the draft now carries, before
//! the compose or over an earlier merge, is first keyed on the draft as it
//! stands (`Shell::landing_panel`; `shell/publication.rs`, **The landing**),
//! so the landing answers as it would over a panel opened on this draft and
//! marker. The landing answers no window part for its caller: a part with no
//! answer refuses the row `window_parts_owed` (the merge record's §1.5),
//! nothing sent, every part named whole by the library's one refusal
//! (`owed_parts`), the same the `skep merge --publish` refusal comes from.
//! So the claim is composed in one place, the panel's read of the marker at
//! the open, at a confirm that finds the draft's base or its marker moved or
//! at that keying (`shell/publication.rs`, **The claim**), and rides only
//! where the marker's head is the trunk's head as read there; never at the
//! draft or fork side, whose side is no member of the document's chain for a
//! claim to supersede. After the acknowledgment THE MERGE RECORD, the
//! library's `record_published` —
//! the member and position the board acknowledged, the claims read back at
//! the daughter, the window parts' answers beside it, written once in the
//! account's merge journal with its link beside it, or the standing one
//! answered — never a second shot; a record that cannot be written after
//! the acknowledgment leaves the member standing, answered with `record`
//! null, `unrecorded` the refusal and `claims` empty, the claims the shot
//! filed standing all the same. The answer is the landing with the
//! acknowledgment's data, the answers as given, each private row OFF named
//! with its count, each gap left at its default, each place the merge kept
//! once (**Kept once**), the panel's
//! re-statement, or its typed refusal: the race, `supersede_refused` with
//! `head_moved`, crosses as the board answered it, nothing re-sent, the
//! composition gone, to be made again on the head it names (skep #806).
//! `resolutions`, `{⟨gap⟩: ⟨choice⟩}`, are UNTRUSTED: each gap id and
//! choice checked against the composition the shell holds, before the door
//! (`checked_resolutions`) — a gap of the report the rules left unsettled,
//! named once (never one they settled, `resolved_by` `rule`: an `anchor`
//! gap, or an `order` gap kept once, whose placement is no merger's to
//! record), a side among the gap's runs, an anchor the gap names, at a
//! `moves` gap with spots only the side whose placement the composition
//! took, since the draft holds the words where it holds them, and at a
//! spine's `moves` gap — one with no spots, a side's reorder the spine did
//! not take (R4 iii) — none, its runs the base material each side moved,
//! which tell no side's order of the spine from another's — anything else
//! refused `malformed_args`, nothing landed. A resolution changes no words,
//! so it records only a choice the draft holds as it stands: past the
//! marker's test each is read off the words the shot publishes
//! (`draft_holds`) — the draft's image where the panel takes the whole
//! draft as it stands, the row's own or the page's keyed on another marker,
//! else the panel's selection as the draft arranges it, in the draft's
//! order (`selected_image`) — some of each listed side's words still there,
//! in the listed order, a word two sides placed alike read once, under the
//! first side listed, none of a side left out or omitted but the words a
//! listed side lays, and at a gap with spots the words within the spot of
//! the side named, or where the composition lays them, in that side's
//! order; one the draft
//! does not hold is refused `malformed_args` naming `resolutions`, nothing
//! sent, the way on an edit of the draft to the choice first. A checked
//! choice stands with the composition for the calls after it — a
//! re-statement, or a refusal of the shot the composition outlives,
//! answered in its place — and is read off the draft again at each, a
//! choice a call names at its gap taking its place; a re-open and a new
//! compose stand a composition that carries none. Every other gap the rules
//! left unsettled is read off the same words as THE RE-OPEN reads the draft
//! (`settle_by_edit`), whether or not the draft was composed again since
//! its edits: settled where they hold another of its choices, at that
//! choice, else left at its default. A `moves` gap with spots no choice
//! names is read over the whole draft as the re-open reads it
//! (`spots_edited`): where its words stand at one other holder's spot alone,
//! neither at the default's nor where the composition lays them, or no
//! longer stand within the spot of the holder whose placement the merger's
//! edit took nor where the composition lays them,
//! the row is refused `merge_refused` with `gap_edited` naming the `gap`,
//! nothing keyed or sent, the composition as it stood and the panel the row
//! opened dropped — only a composition places those words, and composing
//! again reads them. The shot's record settles each gap a choice names, or
//! the words settle, as the merger's, `resolved_by` `person` at the editor
//! and `agent` with no person present ([`Surface`]).
//!
//! **Kept once** (the merge record's §5, case (g)): words two sides added
//! alike at one spot are kept once, the earlier side's copy, the value
//! rule's dedup settling the `order` gap where one copy is left. Both
//! answers name each such place in `deduped`, the library's
//! `Record::deduped` of the composition — `merge.compose`'s report at every
//! outcome and `merge.land`'s acknowledgment: the gap, the sides whose copy
//! M holds, and every other side's runs, which stay in their side with any
//! link on them and are carried into no merge.
//!
//! **`merge.undo`** takes the standing composition's landing back out of
//! the draft by the library's `undo`, one `set_arrangement` typed per
//! surface (R6 with P3; [`Surface`]) — while the session that landed it
//! stands, the marker the draft carried before the landing put back as it
//! stood and answered as `marker` (skep #964), and the composition a later
//! landing set aside for the landing standing again — that marker, or on a
//! draft with no recorded base, whose undo puts none back, the landing its
//! rows leave standing (skep #914) — standing again, so the next
//! `merge.undo` takes that landing back (skep #981). It takes back that
//! landing alone (skep #1050): the library's undo takes back the landing
//! standing in the draft — the one its marker names where the board
//! records a base for the draft, else the one standing by its
//! `set_arrangement` rows, which stands until it is taken back, the landing
//! it went over then standing again (the library's `baseless_landing`;
//! skep #914) — so that landing is read first, after the door, and must be
//! the composition's own (`Composition::marks`): its side, its head and its
//! position. Another hand's landing since, on another device or by `skep
//! merge` — of another merge, or of this one landed again — the same side
//! marked on another head, and this hand's earlier landing of the merge
//! standing again, another device having taken the one composed back, are
//! refused `no_merge` naming the draft, the composition dropped and nothing
//! sent — or, where another device's undo put back the marker of an
//! earlier landing of this session's that a later one set aside, the
//! composition of that landing standing again, so the next `merge.undo`
//! takes it back; a draft carrying no landing goes to the library, which
//! answers it. At the editor it is typed
//! against THE EDITOR's OWN LAST ACK on the draft, as every burst is
//! typed: the position of the principal's latest arrangement write on it
//! that this shell acknowledged, a burst's or a `set_arrangement`'s, never
//! a link's (`Holds::last_arranged`), or the landing's position — or the
//! latest write that put the landing's marker back, where only a take-back
//! and its undo moved the words since — where that is later. So the
//! person's own later changes, taken back first on the editor's stack,
//! never leave it refused, and a change since by another hand refuses it
//! `arrangement_moved`, nothing wiped. With no person present it is typed
//! against the landing's position, or that put-back's, alone, as
//! `skep merge` types its own: an agent has no stack that takes its own
//! later changes back first, so any change since, the agent's own among
//! them, refuses it `arrangement_moved`, nothing wiped, where the editor's
//! rule would land it over those changes and take them back with the merge.
//! **`merge.withdraw`** — `{draft}` —
//! takes the merge out of any marked draft and keeps its words, in any
//! session, by the library's `withdraw`, the standing composition taken
//! aside; **`merge.undo`** with `{draft, withdrawal}` takes that withdrawal
//! back by the library's `unwithdraw`, typed as the undo is — against the
//! withdrawal's position, or the editor's own last ack where that is later
//! — the marker put back as it stood and the composition taken aside
//! standing again, so the next `merge.undo` takes the landing back (skep
//! #870); where another hand took the withdrawal back first, the library
//! answers `nothing_to_undo` with `remarked`, nothing sent, and the
//! composition taken aside stands again all the same where the draft's
//! marker is its landing's. Each replaces the landing's record where one
//! stands, the withdrawal's undo writing the landing's again. Every one of
//! the family's whole-draft writes — a draft landing, an undo, a withdrawal
//! and its undo — is noted as the principal's latest arrangement write on
//! the draft (`Holds::note_arranged`), the editor's own last ack the next
//! undo is typed against at the editor, and the session as the writer of
//! its row, the write standing out at the board until then
//! (`hold::WriteOut`; skep #1000).
//!
//! **The compositions** ([`Merges`]): one per (board, principal), the
//! latest composed standing — a second compose replaces it, there being no
//! re-open of a composition as there is of a panel: the re-open is the
//! marker's, the board's — recording the session it was composed under and
//! dying with it, dropped by the bus's watcher at `session-died` as the
//! panels are, saying nothing: a composition's state crosses in its calls'
//! answers alone, and the contract names no event for the family. `land`
//! and `undo` with nothing standing answer `no_merge` naming the session,
//! save where a composition a later landing set aside stands again, its
//! draft carrying its landing as read then (below); `land` over a draft
//! that no longer carries the standing composition's landing, and `undo`
//! over one whose latest landing is another, drop it, answering `no_merge`
//! naming the draft (**`merge.land`**, **`merge.undo`**; skep #992, #1050).
//! A composition stands for one landing, known by its draft and the
//! position the board marks it at (`Composition::marks`): a draft's marker,
//! or on a draft with no recorded base, which carries none, the landing
//! standing by its `set_arrangement` rows (`Shell::standing_mark`; skep
//! #914) — one mark, which the re-open, the set-aside, the stand-again and
//! the undo's gate read alike, save a walk of the rows that needs a past
//! state the board has reclaimed: the land side reads it as no landing
//! standing, as the library's land side does, and the undo's gate refuses
//! it as the library's undo does. A landing into the draft the standing
//! composition stands in, over the mark of that composition's own landing
//! as the compose read it there — its side among the mark's sides, or no
//! side where a fork landed in itself, its head the mark's and its position
//! the mark's `at` — sets the composition aside by the mark's `at`, and
//! whichever undo puts that landing back stands it again
//! (`Merges::stand_again`): this session's, which stands it as it answers,
//! or another device's, which this session meets as `land` or `undo` finds
//! the draft carrying that landing and not the standing composition's, the
//! refusal naming the draft and the composition set aside then standing —
//! or, where no composition stands to meet it, as `land` or `undo` reads
//! each draft a composition is set aside in, after the door, and goes on
//! with the first composition its draft's mark stands again
//! (`Shell::standing_or_set_aside`). So while the session lasts, undo after
//! undo takes the draft's merges back a landing at a time, whichever device
//! takes a step (skep #981). Over any other mark — another hand's landing,
//! of another merge or of this one, or one the draft's stage copied while
//! the composition stood in the draft it came from — nothing is set aside,
//! so the undo that puts it back leaves nothing standing and the next
//! `undo` answers `no_merge`.
//!
//! **The door.** Every row meets the shell's one write door before any
//! read it makes (`Shell::write_door`, through `Shell::signed`), with the
//! write it is about to make: `compose` with the landing's first write —
//! `stage` where no `into` is named and a fresh draft may be staged,
//! `set_arrangement` into the draft named — and over that draft whole;
//! `land` with `publish`, over the draft the composition landed in and, at
//! the draft side, the side the shot names `also` — a fork, which the shot
//! names nowhere, is not asked ([`Form::also`]); `undo` and `withdraw` with
//! `set_arrangement`, each over the draft it sets whole. So under a stopped
//! node, a poisoned write path or halted writes each row is refused
//! `stopped`, `poisoned` or `halted` naming that op, nothing read and
//! nothing dialed (skep #850), and over a draft holding lines of the
//! principal's the board has not kept — in any state — each whole-draft
//! write is refused `held_lines` naming the draft and the count, nothing
//! dialed (§3c.4, THE HELD-LINES GATE; skep #849): the held lines would
//! otherwise land on an arrangement the landing, the undo or the withdrawal
//! rewrote under them, and come back as a move the person never made. A
//! composition that lands into the draft a record of the person's own names
//! in a fresh one's place (skep #790) asks the door for that draft before
//! the landing's write, since the named draft was asked and that one was
//! not. The two re-opens past the door — the shot's restart re-open, the
//! record after the acknowledgment — are not refused at it again.
//!
//! **The refusals** cross as typed data: the library's own by name where
//! the contract names one — `unreadable {doc}`, `no_such_document {doc}`,
//! `base_unknown {reason, …}` (the members each reason names, `side` beside
//! all but `base_disagrees`), `two_drafts`, `over_cap {n, cap}`,
//! `not_owner {addr}`, `no_merge`, `nothing_to_undo {draft, why}` — the
//! rest under `merge_refused {arm, …}`, a window withheld in the text the
//! line rule reads between two sides' changes among them, `arm`
//! `line_text_withheld {doc, after, before}` and never a side's
//! `unreadable` (skep #1174); the board's verdicts verbatim,
//! `arrangement_moved` with its `site.as_of` and `site.current` among them;
//! the death signal met at a read or a write under the session's token —
//! the library's `SessionEnded` arm — ends the session, `session_died`; the
//! compose's head read's faults cross as the publication family's do
//! (`Shell::fault`), `busy` and `shape` among them; every other halt
//! crosses as itself.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Mutex;

use serde_json::{json, Map, Value};
use skep_address::{validate, Address, Nat, Tumbler};
use skep_client::address::{account_of, doc_1_of, document_of};
use skep_client::board::{frames, merge_marker, ChangesAnswer, ChangesQuery, MergeMarker, Rejection};
use skep_client::halt::Halt;
use skep_client::merge::{self as lib, Family, Gap, GapId, GapKind, Misfit, NoUndo, Placement, ResolvedBy, Role, Run, SideAt, SideIx, SideState, WindowPart};
use skep_client::publication::{Run as SelectionRun, Standing};
use skep_client::sheet::render_inert;

use super::history::marker_json;
use super::publication::{address_arg, answer_json, clipped, ispan_json, left_private_json, via_name, Confirmation, OpenArgs, Signed};
use super::{optional, Shell, Write, Writer};
use crate::refusal::{Name, Refusal};
use crate::sessions::SessionEntry;
use crate::wire::bounded_address;

/// Returns the merge record kind's type address this shell names for
/// `account`: the account's own doc 1.
///
/// The kind is the record's class and its link's type slot
/// (`Inputs::kind`), which the journal and every record of the account are
/// found by. The merge record's decision 9 names a commons row for it,
/// interim and UNPINNED — no row of the vocabulary table, which every
/// registry-row literal in shipped code is held to (skepd's R7) — so this
/// shell names a type of the person's own instead: their doc 1, resident
/// once the account is claimed, one address per account on every device,
/// so a record this shell writes on one device is found on every other.
/// The `skep merge` command names its kind by `--kind`; one naming this
/// account's doc 1 reads and writes the same journal.
fn merge_kind(account: &str) -> Option<Address> {
    bounded_address(&doc_1_of(account))
}

/// The surface a merge is made through, as the shell's arm says.
///
/// It is the editor — a person at the page, under the dev arm — or an
/// agent, where no person is present (`ArmConfig::Refuse`, the arm
/// `skep-mcp` opens the shell with). It decides the two things a merge owes
/// its merger: who a gap the merger settles is recorded as settled by
/// (the merge record §4's `resolved_by`), and the position a take-back is
/// typed against (R6 with P3, the undo's `as_of` per surface).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Surface {
    /// A person at the page.
    ///
    /// A gap the person settles is `person`'s, and a take-back is typed
    /// against the editor's own last arrangement ack on the draft where that
    /// is later than the library's own position, so the person's later
    /// changes, taken back first on the editor's stack, never leave it
    /// refused.
    Editor,
    /// An agent, with no person present.
    ///
    /// A gap the agent settles is `agent`'s, and a take-back is typed
    /// against the landing's position, or the withdrawal's, as `skep merge`
    /// types its own: any change since, the agent's own among them, refuses
    /// it `arrangement_moved`, nothing wiped.
    Agent,
}

impl Surface {
    /// Returns who a gap this surface's merger settles is recorded as
    /// settled by.
    fn settler(self) -> ResolvedBy {
        match self {
            Surface::Editor => ResolvedBy::Person,
            Surface::Agent => ResolvedBy::Agent,
        }
    }
}

/// Where the family reads the mark of a draft's landing
/// (`Shell::standing_mark`), which decides what a walk of a draft's rows
/// answers where it needs a past state the board has reclaimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MarkRead {
    /// At the land side — `merge.compose`'s re-open and set-aside — which
    /// reads that walk as no landing standing, as the library's own land
    /// side reads it (skep #914): the compose lands as in a draft no landing
    /// stands in, recording nothing it cannot judge.
    Land,
    /// At `merge.undo`'s gate, which refuses that walk `history_reclaimed`
    /// as the library's undo refuses it, nothing sent.
    Undo,
}

/// Which form a composition took: the daughter, the draft side or the fork.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Form {
    /// A daughter of the trunk's chain, the person's own.
    Daughter(Address),
    /// A draft of the family behind the head, the merge's side.
    Draft(Address),
    /// A fork of a version of the trunk's chain, the merge's side: a
    /// document outside the chain the board records standing on that
    /// version — another account's `stage` of the member, its recorded
    /// base, which each landing into it moves to the head, or its `version`
    /// of one, its `source` (the merge record's §1.2 shape (4)).
    Fork(Address),
}

impl Form {
    fn side(&self) -> &Address {
        match self {
            Form::Daughter(a) | Form::Draft(a) | Form::Fork(a) => a,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Form::Daughter(_) => "daughter",
            Form::Draft(_) => "draft",
            Form::Fork(_) => "fork",
        }
    }

    /// Returns the side as the merge library names it, a draft read as it
    /// stands.
    fn library_side(&self) -> lib::Side {
        match self {
            Form::Daughter(d) => lib::Side::Member(d.clone()),
            Form::Draft(d) => lib::Side::Draft { at: d.clone(), position: None },
            Form::Fork(f) => lib::Side::Fork(f.clone()),
        }
    }

    /// Returns the draft side the landing's shot re-mints as the
    /// document's own words: the draft at the draft side, none at the
    /// others.
    ///
    /// A daughter's words are the document's already, and a fork's stay
    /// windows onto the fork's own origin, each part asked at the landing.
    fn also(&self) -> Option<&Address> {
        match self {
            Form::Draft(d) => Some(d),
            Form::Daughter(_) | Form::Fork(_) => None,
        }
    }

    /// Returns whether a re-open in `draft` goes by the person's own record.
    ///
    /// It does at a draft side, whose record keeps the position the side
    /// was composed at (`Shell::as_landed`), and at a fork landed in another
    /// draft, whose record keeps the fork's state as composed
    /// (`fork_moved`). A daughter is immutable, and a fork landed in itself
    /// re-opens whatever its state.
    fn reopens_by_record(&self, draft: &Address) -> bool {
        match self {
            Form::Daughter(_) => false,
            Form::Draft(_) => true,
            Form::Fork(fork) => fork != draft,
        }
    }
}

/// One composition the shell holds: the library's, and where it stands.
#[derive(Debug, Clone)]
struct Composition {
    /// The session it was composed under; it dies with it.
    session: String,
    form: Form,
    merged: lib::Merged,
    /// The draft M stands in — landed by the composition, or already
    /// carrying it at a re-open.
    into: Address,
    /// The position the board marks the composition's landing at in `into`:
    /// the landing's write, or at a re-open the mark's `at` — the draft's
    /// marker, or on a draft with no recorded base the landing standing by
    /// its rows (`Shell::standing_mark`).
    ///
    /// The board names a landing by its draft and this position: two
    /// landings of one merge in one draft share their head and their sides
    /// (`Composition::marks`).
    at: Option<u64>,
    /// The merger's choices `merge.land` named, by the index of the gap each
    /// settles in `merged`'s gaps: the placement each asks.
    ///
    /// Each was checked against the gaps (`checked_resolutions`) and is read
    /// off the draft again at every landing call while it stands
    /// (`draft_holds`). The gaps keep their placements as composed, and the
    /// shot's record is settled from them under these choices
    /// (`settle_resolutions`), then by the words the shot publishes
    /// (`settle_by_edit`). Empty at a compose and at a re-open.
    chosen: BTreeMap<usize, Placement>,
}

impl Composition {
    /// Returns whether `marker`, read on `draft`, marks this composition's
    /// landing.
    ///
    /// It does where `draft` is the one the composition stands in and the
    /// marker names its side ([`names_side`]), its head and its position
    /// (`Composition::at`) — no side where the side is the draft itself, a
    /// fork landed in itself, since a landing marks every side but the draft
    /// it lands in. The position tells this landing from another landing of
    /// the same merge in the draft, another hand's or the same hand's
    /// earlier one standing again, which share its head and sides. It is the
    /// test by which `merge.land` lands only over a draft that still carries
    /// this landing (`Shell::carried`; skep #992), by which `merge.undo`
    /// takes back only this landing (skep #1050), and by which a later
    /// landing in the draft sets this composition aside
    /// (`Merges::stand_over`).
    fn marks(&self, draft: &Address, marker: &MergeMarker) -> bool {
        self.into == *draft
            && names_side(self.form.side(), draft, marker)
            && marker.head == self.merged.inputs.head.to_string()
            && marker.at == self.at
    }
}

/// Returns whether `marker`, read on `draft`, names `side` among its sides.
///
/// It names it where its sides hold it, or holds none where `side` is
/// `draft` itself — a fork landed in itself, since a landing marks every
/// side but the draft it lands in. It is the one test of a marker's side:
/// THE RE-OPEN's (`reopening`) and [`Composition::marks`]'.
fn names_side(side: &Address, draft: &Address, marker: &MergeMarker) -> bool {
    if side == draft {
        marker.sides.is_empty()
    } else {
        marker.sides.contains(&side.to_string())
    }
}

/// Returns the mark THE RE-OPEN goes on from.
///
/// It is `marker`, the mark of the landing standing in `draft` — its merge
/// marker, or on a draft with no recorded base the landing standing by its
/// rows (`Shell::standing_mark`) — where it names `side` (`names_side`)
/// and a head that is a trunk member of `doc`.
fn reopening(doc: &Address, side: &Address, draft: &Address, marker: Option<&MergeMarker>) -> Option<MergeMarker> {
    marker.filter(|m| names_side(side, draft, m) && bounded_address(&m.head).is_some_and(|h| is_trunk_member(doc, &h))).cloned()
}

/// Returns a record's fork side's state, `None` where it names no fork.
fn fork_state(record: &lib::Record) -> Option<SideState> {
    record.sides.iter().find_map(|s| match s {
        SideAt::Fork { arranged, .. } => Some(*arranged),
        SideAt::Member { .. } | SideAt::Draft { .. } => None,
    })
}

/// Returns the draft landing a record names, `None` where it names none.
///
/// It is the draft landed in and the position of the write that first
/// landed the record's key there (the merge record's §4, `landed`).
fn draft_landing(record: &lib::Record) -> Option<(&Address, u64)> {
    match &record.landed {
        Some(lib::RecordLanding::Draft { draft, position }) => Some((draft, *position)),
        Some(lib::RecordLanding::Member { .. }) | None => None,
    }
}

/// Returns whether the fork a composition reads moved since its landing.
///
/// It is THE RE-OPEN's test at the fork side, of the landing `marker` marks
/// in `draft` (the module doc; skep #770). The state recorded is the fork
/// side's in `landed`, the person's own record of that landing
/// (`Shell::reopened_by`), where one stands naming `draft` as landed in;
/// else none is recorded (`Unrecorded`), and the fork has moved where it
/// was arranged past the marker's `at`. The state now is the composition's
/// own, read at its position. A daughter, a draft side and a fork landed in
/// itself never move: the fork's changes since are edits in the draft
/// landed in.
fn fork_moved(form: &Form, merged: &lib::Merged, draft: &Address, marker: &MergeMarker, landed: Option<&lib::Record>) -> bool {
    let Form::Fork(fork) = form else { return false };
    let Some(now) = fork_state(&merged.record).filter(|_| fork != draft) else { return false };
    let recorded = landed.filter(|r| draft_landing(r).is_some_and(|(d, _)| d == draft)).and_then(fork_state).unwrap_or(SideState::Unrecorded);
    recorded.moved(now, marker.at)
}

/// The key of a composition set aside.
///
/// It is the family's key — board reference and principal — with the
/// draft and a position on it: the withdrawal's, or the `at` of the marker
/// a later landing replaced, a draft and an `at` naming one marker stamp.
type SetAside = ((String, u64), String, u64);

/// The compositions the shell holds, by (board reference, principal).
///
/// `withdrawn` holds the standing composition a withdrawal took aside, by
/// the same key with the draft and the withdrawal's position, until that
/// withdrawal's undo stands it again (skep #870). `replaced` holds the
/// standing composition a later landing in its draft replaced, by the same
/// key with the draft and the `at` of its marker as that landing's compose
/// read it, until an undo that puts the marker back — this session's or
/// another device's — stands it again (skep #981). Where `standing` and
/// `replaced` are both held, `standing` is locked first.
#[derive(Debug, Default)]
pub(super) struct Merges {
    standing: Mutex<BTreeMap<(String, u64), Composition>>,
    withdrawn: Mutex<BTreeMap<SetAside, Composition>>,
    replaced: Mutex<BTreeMap<SetAside, Composition>>,
}

impl Merges {
    fn standing(&self, key: &(String, u64)) -> Option<Composition> {
        self.standing.lock().expect("the compositions' lock").get(key).cloned()
    }

    fn stand(&self, key: (String, u64), composition: Composition) {
        self.standing.lock().expect("the compositions' lock").insert(key, composition);
    }

    fn take(&self, key: &(String, u64)) -> Option<Composition> {
        self.standing.lock().expect("the compositions' lock").remove(key)
    }

    /// Stands `composition`, landed in its draft over `marker`.
    ///
    /// `marker` is the mark of the landing standing in that draft as its
    /// compose read it before the landing (`Shell::standing_mark`). The
    /// composition it replaces is set aside by the mark's `at` where the
    /// mark is that composition's own landing in that draft
    /// (`Composition::marks`), for whichever undo puts the landing back to
    /// stand it again ([`Merges::stand_again`]).
    fn stand_over(&self, key: (String, u64), composition: Composition, marker: Option<&MergeMarker>) {
        let mut standing = self.standing.lock().expect("the compositions' lock");
        let draft = composition.into.clone();
        let Some(earlier) = standing.insert(key.clone(), composition) else {
            return;
        };
        if let Some(at) = marker.filter(|m| earlier.marks(&draft, m)).and_then(|m| m.at) {
            self.replaced.lock().expect("the compositions' lock").insert((key, draft.to_string(), at), earlier);
        }
    }

    /// Replaces the standing composition with the one `marker` marks, if any.
    ///
    /// The standing composition's landing is no longer the one `draft`
    /// carries, so it is taken out. `marker` is the mark of the landing
    /// standing in `draft` as read (`Shell::standing_mark`): put back by an
    /// undo — the session's own, or another device's — or left by another
    /// hand's landing, or none. A mark and a draft name one landing by the
    /// mark's `at`, so where it marks the composition a later landing of
    /// this session's in `draft` set aside at that `at`
    /// ([`Merges::stand_over`]), that composition stands in place of the one
    /// taken out: the draft carries its landing again, and the next
    /// `merge.undo` takes that landing back (skep #981). Else none stands.
    fn stand_again(&self, key: &(String, u64), draft: &Address, marker: Option<&MergeMarker>) {
        let mut standing = self.standing.lock().expect("the compositions' lock");
        standing.remove(key);
        let Some((marker, at)) = marker.and_then(|m| m.at.map(|at| (m, at))) else {
            return;
        };
        let earlier = self.replaced.lock().expect("the compositions' lock").remove(&(key.clone(), draft.to_string(), at));
        if let Some(earlier) = earlier.filter(|c| c.marks(draft, marker)) {
            standing.insert(key.clone(), earlier);
        }
    }

    /// Returns the drafts compositions under `key` are set aside in by a
    /// later landing ([`Merges::stand_over`]), each once.
    fn set_aside_in(&self, key: &(String, u64)) -> Vec<Address> {
        let replaced = self.replaced.lock().expect("the compositions' lock");
        let mut drafts: Vec<Address> = replaced.iter().filter(|((k, _, _), _)| k == key).map(|(_, c)| c.into.clone()).collect();
        drafts.dedup();
        drafts
    }

    /// Stands again, where none stands under `key`, the composition a later
    /// landing set aside in `draft` whose landing `marker` marks, answering
    /// the composition that then stands.
    ///
    /// `marker` is the mark of the landing standing in `draft` as read: put
    /// back by undos made while no composition stood here to meet them. One
    /// standing already is answered as it stands, a composition being the
    /// session's latest; none where `marker` marks no composition set aside
    /// at its `at`, which stays aside.
    fn stand_set_aside(&self, key: &(String, u64), draft: &Address, marker: Option<&MergeMarker>) -> Option<Composition> {
        let mut standing = self.standing.lock().expect("the compositions' lock");
        if let Some(composition) = standing.get(key) {
            return Some(composition.clone());
        }
        let (marker, at) = marker.and_then(|m| m.at.map(|at| (m, at)))?;
        let mut replaced = self.replaced.lock().expect("the compositions' lock");
        let set_aside = (key.clone(), draft.to_string(), at);
        let earlier = replaced.get(&set_aside).filter(|c| c.marks(draft, marker))?.clone();
        replaced.remove(&set_aside);
        standing.insert(key.clone(), earlier.clone());
        Some(earlier)
    }

    /// Takes `composition` aside at the withdrawal at `position` of `draft`.
    fn set_aside(&self, key: (String, u64), draft: &Address, position: u64, composition: Composition) {
        self.withdrawn.lock().expect("the compositions' lock").insert((key, draft.to_string(), position), composition);
    }

    /// Takes back the composition set aside at the withdrawal at `position`.
    fn put_back(&self, key: &(String, u64), draft: &Address, position: u64) -> Option<Composition> {
        self.withdrawn.lock().expect("the compositions' lock").remove(&(key.clone(), draft.to_string(), position))
    }

    /// Stands again the composition set aside at the withdrawal at
    /// `position` of `draft`, where `marker`, read on the draft, marks its
    /// landing: the withdrawal taken back by another hand (skep #870).
    ///
    /// Else the composition stays aside.
    fn stand_withdrawn(&self, key: &(String, u64), draft: &Address, position: u64, marker: &MergeMarker) {
        let set_aside = (key.clone(), draft.to_string(), position);
        let mut withdrawn = self.withdrawn.lock().expect("the compositions' lock");
        let Some(composition) = withdrawn.remove(&set_aside) else { return };
        if !composition.marks(draft, marker) {
            withdrawn.insert(set_aside, composition);
            return;
        }
        drop(withdrawn);
        self.stand(key.clone(), composition);
    }

    /// Drops every composition that stood under `session_reference`.
    ///
    /// Set aside or not, the session died with it (the family's one session
    /// rule).
    pub(super) fn ended(&self, session_reference: &str) {
        self.standing.lock().expect("the compositions' lock").retain(|_, c| c.session != session_reference);
        self.withdrawn.lock().expect("the compositions' lock").retain(|_, c| c.session != session_reference);
        self.replaced.lock().expect("the compositions' lock").retain(|_, c| c.session != session_reference);
    }
}

// ── address arithmetic over the trunk ─────────────────────────────────────

/// Returns a member's version components after the trunk `doc`'s.
///
/// `None` where `a` is not under `doc`, is `doc` itself, or lies in one of
/// its subspaces.
pub(super) fn version_components(doc: &Address, a: &Address) -> Option<Vec<Nat>> {
    let doc: Vec<Nat> = doc.tumbler().iter().cloned().collect();
    let comps: Vec<Nat> = a.tumbler().iter().cloned().collect();
    let version = comps.strip_prefix(doc.as_slice())?;
    if version.is_empty() || version.contains(&Nat::from(0u32)) {
        return None;
    }
    Some(version.to_vec())
}

/// Returns whether `a` is a trunk member of `doc` — one version component.
pub(super) fn is_trunk_member(doc: &Address, a: &Address) -> bool {
    version_components(doc, a).is_some_and(|v| v.len() == 1)
}

/// Returns whether `a` is a daughter of `doc`'s chain — a member under a
/// trunk member, two or more version components — which a published chain
/// makes published by construction.
pub(super) fn is_daughter(doc: &Address, a: &Address) -> bool {
    version_components(doc, a).is_some_and(|v| v.len() >= 2)
}

/// Returns the trunk member after `head`: its last component plus one.
pub(super) fn next_trunk_member(head: &Address) -> Option<Address> {
    with_last(head, |n| n.checked_add(1))
}

/// Returns the trunk member before `member`, where it is not the first.
fn trunk_member_before(member: &Address) -> Option<Address> {
    with_last(member, |n| (n > 1).then(|| n - 1))
}

/// Returns `a` with its last component mapped by `f`.
fn with_last(a: &Address, f: impl FnOnce(u64) -> Option<u64>) -> Option<Address> {
    let mut comps: Vec<Nat> = a.tumbler().iter().cloned().collect();
    let last = u64::try_from(comps.last()?).ok()?;
    *comps.last_mut()? = Nat::from(f(last)?);
    validate(Tumbler::new(comps).ok()?).ok()
}

/// Returns the trunk member `a` lies under: `doc` and the first version
/// component.
fn trunk_member_above(doc: &Address, a: &Address) -> Option<Address> {
    let first = version_components(doc, a)?.into_iter().next()?;
    let comps = doc.tumbler().iter().cloned().chain(std::iter::once(first));
    validate(Tumbler::new(comps).ok()?).ok()
}

/// Returns where a draft side's head read starts: the trunk member of `doc`
/// the base the board records for it (`base`) lies under, or `doc` itself
/// where the draft was staged from the bare document.
///
/// It is the head read's start at the draft side (`client.md` §4b.1's merge
/// row), decided off the draft's one `doc_metadata` read. It is answered
/// for a draft of any account that lies under a member, the composition
/// refusing another account's draft itself; a draft staged from `doc`
/// itself — before its first version (wire.md §Namespace, `stage`), whether
/// or not one stands since — starts at `doc` where it is of `doc`'s owner's
/// account, the account `doc` lies in (`skep-namespace`'s
/// `effective_owner_prefix`). The start names no base: the library derives
/// that from the bases the board recorded (`skep_client::merge::compose`).
///
/// # Errors
///
/// `BaseUnknown`, the merge library's own refusal of the side, as its read
/// of the side decides it (the owner tested before the base): where no
/// base is recorded, the base lies in another document's chain, or the bare
/// document is another account's draft's base.
fn draft_start(doc: &Address, draft: &Address, base: Option<&Address>) -> Result<Address, lib::Refusal> {
    let the_owners = account_of(&draft.to_string()).is_some_and(|a| account_of(&doc.to_string()).as_deref() == Some(a.as_str()));
    match base {
        Some(b) if b == doc && the_owners => Ok(doc.clone()),
        _ => base.and_then(|b| trunk_member_above(doc, b)).ok_or_else(|| lib::Refusal::BaseUnknown(lib::Side::Draft { at: draft.clone(), position: None })),
    }
}

/// Returns where a fork's head read starts: the trunk member of `doc` its
/// anchor lies under, or `doc` itself where the fork was taken from the
/// bare document.
///
/// `anchor` is where the board records the fork standing, off its one
/// `doc_metadata` read: its recorded base (`base`) where the board records
/// one — a fork another account staged, moved to the head by each landing
/// into it — else its source (`source`), as the library reads the fork's
/// anchor (`skep_client::merge::compose`; the owner's ruling of 2026-11-19,
/// skep #1106). It is answered for a fork of any account, the composition
/// refusing one of `doc`'s owner's own account itself, `fork_of_owner` —
/// the owner's draft is the draft side — as it refuses another account's
/// draft at the draft side. A fork taken from `doc` itself — before its
/// first version, whether or not one stands since — starts at `doc`.
///
/// # Errors
///
/// `BaseUnknown`, the merge library's own refusal of the side: where the
/// board records neither a base nor a source — a document `fork` or
/// `create_new_document` minted — or the anchor lies in another document's
/// chain.
fn fork_start(doc: &Address, fork: &Address, anchor: Option<&Address>) -> Result<Address, lib::Refusal> {
    match anchor {
        Some(a) if a == doc => Ok(doc.clone()),
        _ => anchor.and_then(|a| trunk_member_above(doc, a)).ok_or_else(|| lib::Refusal::BaseUnknown(lib::Side::Fork(fork.clone()))),
    }
}

// ── the reads the rows make themselves ────────────────────────────────────

/// What one `doc_metadata` of a draft or a fork tells the family.
struct DraftFacts {
    published: bool,
    owner: String,
    base: Option<Address>,
    /// The document it was born sharing, where the board serves one: the
    /// member a `version` or a `stage` copied, or the bare document where
    /// that had no version yet.
    source: Option<Address>,
    marker: Option<MergeMarker>,
}

impl Shell {
    /// Reads a draft's facts off one `doc_metadata`: its publication bit,
    /// its owner, its recorded base, its source and its merge marker.
    ///
    /// # Errors
    ///
    /// `metadata_read`'s, then `shape` where the answer is no `doc_metadata`
    /// answer this shell reads.
    fn draft_facts(&self, session: &SessionEntry, draft: &Address) -> Result<DraftFacts, Refusal> {
        let v = self.metadata_read(session, draft)?;
        let shape = || Refusal::shell(Name::SHAPE, json!({"op": "doc_metadata", "body": clipped(&v.to_string(), 200)}));
        let marker = merge_marker(&v).ok_or_else(shape)?;
        let published = v["published"].as_bool().ok_or_else(shape)?;
        let owner = v["owner"].as_str().ok_or_else(shape)?.to_string();
        let base = v["base"].as_str().and_then(bounded_address);
        let source = v["source"].as_str().and_then(bounded_address);
        Ok(DraftFacts { published, owner, base, source, marker })
    }

    /// Reads the draft the landing goes into, UNTRUSTED (skep #799).
    ///
    /// # Errors
    ///
    /// `draft_facts`'s; then `not_owner` naming it where it is published or
    /// another account's.
    fn landing_target(&self, session: &SessionEntry, account: &str, into: &Address) -> Result<DraftFacts, Refusal> {
        let facts = self.draft_facts(session, into)?;
        if facts.published || facts.owner != account {
            return Err(Refusal::shell(Name::NOT_OWNER, json!({"addr": into.to_string()})));
        }
        Ok(facts)
    }

    /// Returns the mark of the landing standing in `draft`, `facts` its one
    /// `doc_metadata` read.
    ///
    /// It is the draft's merge marker where the board records a base for
    /// it. A draft with no recorded base carries no marker, and its mark is
    /// the landing standing by its `set_arrangement` rows, which stands from
    /// its write until it is taken back, the landing it went over then
    /// standing again (the library's `baseless_landing`; skep #914). It is
    /// the one mark the family reads a draft's landing by: THE RE-OPEN, a
    /// landing's set-aside (`Merges::stand_over`), the stand-again after an
    /// undo (`Merges::stand_again`) and `merge.undo`'s gate read it alike,
    /// save where the walk needs a past state the board has reclaimed, which
    /// `read` decides ([`MarkRead`]).
    ///
    /// # Errors
    ///
    /// On a draft with no recorded base, `baseless_landing`'s, through
    /// `merge_refusal`: the feed's halts, `session_died`, and where a plain
    /// row follows a landing the reads of the draft's past states and their
    /// records — `merge_refused` with `history_busy`, or with
    /// `history_reclaimed` at [`MarkRead::Undo`], `unreadable` or
    /// `no_such_document` naming the document a read was refused at, a
    /// halt's face for the rest.
    fn standing_mark(&self, session: &SessionEntry, draft: &Address, facts: DraftFacts, read: MarkRead) -> Result<Option<MergeMarker>, Refusal> {
        match facts.base {
            Some(_) => Ok(facts.marker),
            None => match lib::baseless_landing(&session.board, Some(&session.token), draft) {
                Err(lib::Refusal::HistoryReclaimed { .. }) if read == MarkRead::Land => Ok(None),
                walked => walked.map_err(|r| self.merge_refusal(session, r)),
            },
        }
    }

    /// Returns the surface this shell's merges are made through: the
    /// editor where a person is present, else an agent ([`Surface`]).
    fn surface(&self) -> Surface {
        if self.arm.person_present() {
            Surface::Editor
        } else {
            Surface::Agent
        }
    }

    /// Returns the caller's own last ack a take-back of `draft`'s merge is
    /// typed against, where its surface has one (R6 with P3).
    ///
    /// It is the editor's: the principal's latest arrangement write on the
    /// draft this shell acknowledged (`Holds::last_arranged`), the library
    /// taking it where it is later than the landing's position or the
    /// withdrawal's. An agent has none, so the library types the take-back
    /// against that position alone.
    fn own_ack(&self, session: &SessionEntry, draft: &Address) -> Option<u64> {
        match self.surface() {
            Surface::Editor => self.holds.last_arranged(session, &draft.to_string()),
            Surface::Agent => None,
        }
    }

    /// Returns the trunk's head as the board stands, read up from `start`.
    ///
    /// `start` is where `side` starts (`draft_start`, `fork_start`): the
    /// trunk member of `doc` it lies under, or `doc` itself, whose head is
    /// read up from its first member where one stands. The read is the
    /// library's head read (`skep_client::publication::standing` under the
    /// session's publisher): the members past a trunk member by doubling,
    /// then a binary search between the last that answered and the first
    /// that did not, that member itself where the one after it is not
    /// registered. A board answering every member the doubling asks is
    /// refused after 64 reads and read no further (SP-17).
    ///
    /// # Errors
    ///
    /// The read's faults as `Shell::fault` maps them for `merge.compose`:
    /// `unreadable` naming the member read, `busy`, `session_died`, the
    /// board's other verdicts verbatim, `unreachable`, and `shape` naming
    /// `doc_metadata` for an answer that is no `doc_metadata` answer (SP-14)
    /// or once the doubling is spent; at `doc` with no version standing,
    /// `base_unknown` with `reason` `bare_source` naming `doc` — the
    /// library's `BareSource` of `side`, nothing to merge onto; and a face
    /// naming the shell behind the library where the read of a trunk member
    /// answers the standing of the bare document, which no read of one
    /// answers.
    fn trunk_head(&self, session: &SessionEntry, signed: &Signed, doc: &Address, start: &Address, side: &lib::Side) -> Result<Address, Refusal> {
        let publisher = signed.publisher(session);
        let read = |from: &Address| skep_client::publication::standing(&publisher, doc, from).map_err(|f| self.fault(session, "merge.compose", f));
        let behind = || {
            Refusal::from(Halt::face(
                "the head read answered a trunk member as the bare document",
                "`skep_client::publication::standing` of a trunk member answers `AtHead` or `Behind` on every path",
                "report it: the shell's merge row is behind the library",
            ))
        };
        let from = match read(start)? {
            Standing::AtHead => return Ok(start.clone()),
            Standing::Behind { head } => return Ok(head),
            Standing::First if start == doc => {
                return Err(self.merge_refusal(session, lib::Refusal::BareSource { side: side.clone(), source: doc.clone(), hop: None }));
            }
            Standing::SupersededFirst { first } if start == doc => first,
            Standing::First | Standing::SupersededFirst { .. } => return Err(behind()),
        };
        match read(&from)? {
            Standing::AtHead => Ok(from),
            Standing::Behind { head } => Ok(head),
            Standing::First | Standing::SupersededFirst { .. } => Err(behind()),
        }
    }

    /// Returns the member an active supersession claim of `account`'s own
    /// names as the daughter's successor, with the claims so naming it, by
    /// one `in_claims` at the daughter — THE MERGED ARM's read.
    ///
    /// # Errors
    ///
    /// `unreadable` and `no_such_document` naming the daughter, the board's
    /// other verdicts verbatim, `unreachable`, `session_died`.
    fn own_claim_naming(&self, session: &SessionEntry, daughter: &Address, account: &str) -> Result<Option<(Address, Vec<Address>)>, Refusal> {
        let text = daughter.to_string();
        let v = self.family_read(session, &frames::in_claims(&text))?;
        if let Some(r) = Rejection::of(&v) {
            return Err(match r.key() {
                "withheld" => Refusal::shell(Name::UNREADABLE, json!({"doc": text})),
                "doc_not_registered" => Refusal::shell(Name::NO_SUCH_DOCUMENT, json!({"doc": text})),
                _ => Refusal::from(r.refused(&v)),
            });
        }
        let mut member = None;
        let mut claims = Vec::new();
        for row in v["claims"].as_array().into_iter().flatten() {
            let active = row["active"].as_bool().unwrap_or(true);
            let owned = row["home"].as_str().and_then(account_of).as_deref() == Some(account);
            if !active || !owned {
                continue;
            }
            if let (Some(new), Some(claim)) = (row["new"].as_str().and_then(bounded_address), row["claim"].as_str().and_then(bounded_address)) {
                member.get_or_insert(new);
                claims.push(claim);
            }
        }
        Ok(member.map(|m| (m, claims)))
    }

    /// Returns whether a write under `draft` landed after position `since`.
    ///
    /// It is read off the drafts supplement: the test that tells a re-open's
    /// side read from its image as it stands, which equals the marker's
    /// state, from one read at the marker's position. A write that landed
    /// before `since`, between the composition and its landing, is in both
    /// reads: the landing's record names the position such a side was
    /// composed at (`Shell::as_landed`).
    ///
    /// A floor the feed no longer answers below is read as moved: the side
    /// is then read at the marker's position, which the board answers or
    /// refuses by name. The page asked holds one row, the answer's whole
    /// question being whether any row stands.
    ///
    /// # Errors
    ///
    /// The feed's halts, and `session_died` where the read met the death
    /// signal.
    fn moved_since(&self, session: &SessionEntry, draft: &Address, since: u64) -> Result<bool, Refusal> {
        let text = draft.to_string();
        let mut limit = Some(1);
        loop {
            match session.board.changes(Some(&session.token), &ChangesQuery { since, under: Some(&text), drafts: true, limit })? {
                ChangesAnswer::Page(page) => return Ok(!page.changes.is_empty()),
                ChangesAnswer::HistoryReclaimed { .. } => return Ok(true),
                ChangesAnswer::TooLarge { fits } => limit = Some(fits),
                ChangesAnswer::Closed => return Err(self.died(session)),
                // An answer this shell does not read: the side is read at
                // the marker's position, which the board answers by name.
                _ => return Ok(true),
            }
        }
    }

    /// Maps the merge library's refusal to the shell's (the module doc, **The
    /// refusals**), the session ended where the library answers its end.
    pub(super) fn merge_refusal(&self, session: &SessionEntry, r: lib::Refusal) -> Refusal {
        use lib::Refusal as R;
        let s = |a: &Address| a.to_string();
        let other = |arm: &str, members: Value| {
            let mut detail = json!({"arm": arm});
            if let Value::Object(members) = members {
                for (k, v) in members {
                    detail[k] = v;
                }
            }
            Refusal::shell(Name::MERGE_REFUSED, detail)
        };
        match r {
            R::Unreadable(doc) => Refusal::shell(Name::UNREADABLE, json!({"doc": s(&doc)})),
            R::LineTextWithheld { doc, after, before } => other(
                "line_text_withheld",
                json!({"doc": s(&doc), "after": after.as_ref().map(s), "before": before.as_ref().map(s)}),
            ),
            R::NoSuchDocument(doc) => Refusal::shell(Name::NO_SUCH_DOCUMENT, json!({"doc": s(&doc)})),
            R::BaseUnknown(side) => Refusal::shell(Name::BASE_UNKNOWN, json!({"side": s(side.address()), "reason": "base_unknown"})),
            R::ForkOfOwner { fork } => Refusal::shell(Name::BASE_UNKNOWN, json!({"side": s(&fork), "reason": "fork_of_owner"})),
            R::BareSource { side, source, hop } => {
                let mut detail = json!({"side": s(side.address()), "reason": "bare_source", "source": s(&source)});
                if let Some(hop) = hop {
                    detail["hop"] = json!(s(&hop));
                }
                Refusal::shell(Name::BASE_UNKNOWN, detail)
            }
            R::HopUnrecorded { side, hop } => Refusal::shell(Name::BASE_UNKNOWN, json!({"side": s(side.address()), "reason": "hop_unrecorded", "hop": s(&hop)})),
            R::DraftBaseDisagrees { side, named, served } => Refusal::shell(Name::BASE_UNKNOWN, json!({"side": s(side.address()), "reason": "draft_base_disagrees", "named": s(&named), "served": s(&served)})),
            R::NamedBaseDisagrees { named, served } => Refusal::shell(Name::BASE_UNKNOWN, json!({"reason": "base_disagrees", "named": s(&named), "served": s(&served)})),
            R::ForkBaseNamed { fork, base } => other("fork_base_named", json!({"fork": s(&fork), "base": s(&base)})),
            R::TwoDrafts => Refusal::shell(Name::TWO_DRAFTS, json!({})),
            R::OverCap { runs, cap } => Refusal::shell(Name::OVER_CAP, json!({"n": runs, "cap": cap})),
            R::NotOwner { draft } | R::UnownedDraft { draft } => Refusal::shell(Name::NOT_OWNER, json!({"addr": s(&draft)})),
            R::Published { doc } => Refusal::shell(Name::NOT_OWNER, json!({"addr": s(&doc), "published": true})),
            R::PublishedJournal { journal } => other("published_journal", json!({"journal": s(&journal)})),
            R::AlreadyPublished { draft, member } => other("already_published", json!({"draft": s(&draft), "member": s(&member)})),
            R::HeadHolds { head } => other("head_holds", json!({"head": s(&head)})),
            R::BodyOverBudget { bytes, budget } => other("body_over_budget", json!({"bytes": bytes, "budget": budget})),
            R::LandingBegun { draft, position } => other("landing_begun", json!({"draft": s(&draft), "position": position})),
            R::NothingToUndo { draft, why } => {
                let mut detail = json!({"draft": s(&draft)});
                match why {
                    NoUndo::Inherited => detail["why"] = json!("inherited"),
                    NoUndo::Published { version } => {
                        detail["why"] = json!("published");
                        detail["version"] = json!(s(&version));
                    }
                    NoUndo::TakenBack => detail["why"] = json!("taken_back"),
                    NoUndo::Remarked => detail["why"] = json!("remarked"),
                }
                Refusal::shell(Name::NOTHING_TO_UNDO, detail)
            }
            R::NoMerge { draft } => Refusal::shell(Name::NO_MERGE, json!({"draft": s(&draft)})),
            R::NoWithdrawal { draft, at } => Refusal::shell(Name::NO_MERGE, json!({"draft": s(&draft), "withdrawal": at})),
            R::NotPast { draft, at, current } => other("not_past", json!({"draft": s(&draft), "at": at, "current": current})),
            R::TooFragmented { doc, runs_seen } => other("too_fragmented", json!({"doc": s(&doc), "runs_seen": runs_seen})),
            R::HistoryBusy => other("history_busy", json!({})),
            R::HistoryReclaimed { at, floor } => other("history_reclaimed", json!({"at": at, "floor": floor})),
            R::BeyondHead { at, head, .. } => other("beyond_head", json!({"at": at, "head": head})),
            R::NotAPosition { at, nearest, .. } => other("not_a_position", json!({"at": at, "nearest": nearest})),
            R::SideMoved { side, at, before, after } => other("side_moved", json!({"side": s(&side), "at": at, "before": before, "after": after})),
            R::ForkBaseMoved { fork, source, head } => other("fork_base_moved", json!({"fork": s(&fork), "source": s(&source), "head": s(&head)})),
            R::BaseNotInChain { into, head } => other("base_not_in_chain", json!({"into": s(&into), "head": s(&head)})),
            R::WindowWithheld { origin, positions } => {
                let positions: Vec<Value> = positions.iter().map(|&(ordinal, width)| json!({"ordinal": ordinal, "width": width})).collect();
                other("window_withheld", json!({"origin": s(&origin), "positions": positions}))
            }
            R::NeedsSignedSession => other("needs_signed_session", json!({})),
            R::SupersedeRefused { index, cause } => {
                let head = match &cause {
                    lib::SupersedeCause::HeadMoved { head } => head.as_ref().map(ToString::to_string),
                    _ => None,
                };
                other("supersede_refused", json!({"index": index, "detail": cause.token(), "head": head}))
            }
            R::WindowPartsOwed { parts, misfits, given } => Refusal::shell(Name::WINDOW_PARTS_OWED, owed_detail(&parts, &given, &misfits, json!([]), json!([]))),
            R::SessionEnded(_) => self.died(session),
            R::Halt(h) => Refusal::from(h),
        }
    }

    /// Returns `marker` where it marks the standing composition's landing.
    ///
    /// `marker` is read on the draft the composition stands in: its merge
    /// marker as `merge.land` read it before any panel is keyed on it (the
    /// module doc, **`merge.land`**; skep #992), or the landing `merge.undo`
    /// would take back (`Shell::standing_mark`) — that marker, or, on a draft
    /// the board records no base for, the landing standing by its rows (skep
    /// #1050, #914; the library's `baseless_landing`). It marks the landing
    /// where it names the composition's side, its head and its position
    /// (`Composition::marks`).
    ///
    /// # Errors
    ///
    /// Returns `no_merge` naming the draft where `marker` marks another
    /// merge, another landing of this one — another hand's, or this hand's
    /// earlier one standing again — or is none, the composition `key` names
    /// taken out: the draft no longer carries its landing. Where `marker` is
    /// the one a later landing of this session's in the draft set an earlier
    /// composition aside at — put back by another device's undo — that
    /// composition stands in its place (`Merges::stand_again`), the draft
    /// carrying its landing.
    fn carried<'m>(&self, key: &(String, u64), composition: &Composition, marker: Option<&'m MergeMarker>) -> Result<&'m MergeMarker, Refusal> {
        match marker.filter(|m| composition.marks(&composition.into, m)) {
            Some(marker) => Ok(marker),
            None => {
                self.merges.stand_again(key, &composition.into, marker);
                Err(Refusal::shell(Name::NO_MERGE, json!({"draft": composition.into.to_string()})))
            }
        }
    }

    /// Returns the composition a row acts on: the one standing under `key`,
    /// else one a later landing set aside whose landing stands again.
    ///
    /// A composition a later landing of this session's set aside
    /// ([`Merges::stand_over`]) stands again where its draft carries its
    /// landing again as `mark` reads it — the row's own read of a draft's
    /// mark, the undo's the landing standing (`Shell::standing_mark`), the
    /// landing's the draft's marker: put back by undos another device made
    /// while no composition stood here to meet them (skep #981). With
    /// nothing set aside nothing is read and the door is not asked. Else the
    /// door is asked with `write`, the row's write, before any read, each
    /// draft a composition is set aside in is read in turn, and the first
    /// whose mark is a set-aside composition's own landing stands it again
    /// (`Merges::stand_set_aside`).
    ///
    /// # Errors
    ///
    /// In this order: `no_merge` naming the session where none stands and
    /// none is set aside; the door's; a draft's read's, each answered as
    /// itself (SP-14), `session_died` among them; `no_merge` naming the
    /// session where no draft's mark stands a composition again.
    fn standing_or_set_aside(&self, session: &SessionEntry, key: &(String, u64), write: Write<'_>, mark: impl Fn(&Address) -> Result<Option<MergeMarker>, Refusal>) -> Result<Composition, Refusal> {
        if let Some(composition) = self.merges.standing(key) {
            return Ok(composition);
        }
        let none = || Refusal::shell(Name::NO_MERGE, json!({"session": session.reference}));
        let aside = self.merges.set_aside_in(key);
        if aside.is_empty() {
            return Err(none());
        }
        self.write_door(Writer::Session(session), &write)?;
        for draft in &aside {
            if let Some(composition) = self.merges.stand_set_aside(key, draft, mark(draft)?.as_ref()) {
                return Ok(composition);
            }
        }
        Err(none())
    }

    // ── The rows ─────────────────────────────────────────────────────────

    /// Answers `merge.compose(session, {doc, alternative, into?})`, THE
    /// DRAFT SIDE's `merge.compose(session, {doc, draft, into?})` or THE
    /// FORK's `merge.compose(session, {doc, fork, into?})`, with the report
    /// (the module doc; `shapes`' `MergeReport`).
    ///
    /// # Errors
    ///
    /// In this order:
    ///
    /// 1. `malformed_args` naming an optional member present in another
    ///    form — `alternative`, `draft`, `fork`, `into` — then `doc` where
    ///    it is no bare document address; then the side's: `alternative`
    ///    where it is no daughter of `doc`'s chain, `into` where it is the
    ///    draft side itself, `fork` where it lies in `doc`'s own tree —
    ///    `doc`, a member of its chain or an address within either —
    ///    `alternative, draft or fork` where none is given, `draft` where
    ///    `alternative` and `draft` are, and `fork` where it is given
    ///    beside either;
    /// 2. `malformed_args` naming `session`, then `session_ended`; the
    ///    write door's, in its order — `write_in_bare_session`, then
    ///    `another_window`, naming the call; `stopped`, `poisoned` or
    ///    `halted` where a hold stands at the board, naming `stage` where no
    ///    `into` is named, else `set_arrangement`; `held_lines` naming `into`
    ///    and the lines of the principal's standing on it the board has not
    ///    kept — nothing read at any of the four; `store_unreadable`,
    ///    `no_account`;
    /// 3. at a daughter, the `in_claims` read's: `unreadable`,
    ///    `no_such_document`, the board's verdicts, `unreachable`,
    ///    `session_died`; then the merged arm's composition and record, as
    ///    step 5's and `merge.land`'s record;
    /// 4. `into`'s read, as step 3's reads, and `not_owner` naming it where
    ///    it is published or another account's; where the board records no
    ///    base for it, the walk of its rows for the landing standing in it
    ///    (`Shell::standing_mark`), its refusals as `merge.undo`'s walk's but
    ///    a past state the board has reclaimed, which reads as no landing
    ///    standing;
    ///    at the draft side the draft's
    ///    read, and `base_unknown` with `reason` `base_unknown` where the
    ///    board records no base for it in `doc`'s chain, or where another
    ///    account's draft was staged from `doc` itself (`draft_start`); at
    ///    the fork side the fork's read, `unreadable` where the session may
    ///    not read it, and `base_unknown` with `reason` `base_unknown` where
    ///    the board records it neither a base nor a source, or where its
    ///    recorded base, else its source, lies in no member of `doc`'s chain
    ///    (`fork_start`); then, where no re-open stands or the fork moved
    ///    since the landing re-opened, the head read's (`trunk_head`):
    ///    `unreadable`, `busy`, `session_died`, the board's
    ///    verdicts, `unreachable`, and `shape` naming `doc_metadata` for an
    ///    answer it cannot read or where the board answers every member the
    ///    read asks; and, for a draft or a fork begun from `doc` itself while
    ///    no version of it stands, `base_unknown` with `reason` `bare_source`
    ///    naming `source` (`doc` itself) — nothing to merge onto: publish the
    ///    draft, which lands version 1 — nothing composed;
    /// 5. the composition's (`skep_client::merge::compose`): `base_unknown`
    ///    with its reason — `fork_of_owner` where the fork side is of
    ///    `doc`'s owner's own account, the owner's draft being the draft
    ///    side, `hop_unrecorded` naming the `hop` on the side's line the
    ///    board records no base for, `bare_source` with the `hop` where the
    ///    board serves no count of the document's arrangement from before
    ///    its first version (an older board), `base_unknown` —
    ///    `two_drafts`, `unreadable`, `no_such_document`, `merge_refused`
    ///    with its arm — `side_moved` where a side changed while the
    ///    composition read it, `line_text_withheld` naming the `doc` and
    ///    the pair's anchors where the text the line rule reads between two
    ///    changes holds a window onto a document the session may not
    ///    read, whatever the switches, nothing composed — the board's
    ///    verdicts verbatim; at a re-open at the
    ///    draft side or of a fork landed in another draft, the read of the
    ///    person's own record of the landing the marker marks, through the
    ///    links of the kind to `into` (`skep_client::merge::landing_record`):
    ///    `unreadable` or `no_such_document` naming `into`, a halt's face,
    ///    `session_died`; at the draft side, where that record names the
    ///    landing under another key, the composition again at the position
    ///    it names for the side, as above, `merge_refused` with
    ///    `history_reclaimed` where the board no longer answers that
    ///    position; at a re-open but of a fork landed in itself,
    ///    the landing's record read and, where none of the person's names it
    ///    and `into` holds M, written (`skep_client::merge::resume` naming
    ///    `into`): `unreadable`,
    ///    `no_such_document`, `merge_refused` with its arm, a halt's face —
    ///    the board too busy to find the person's journal, the landing
    ///    standing with its record unwritten — and `session_died`, nothing
    ///    landed; where the fork moved since, the composition
    ///    again, as above, then the read of what the landing replaces
    ///    (`skep_client::merge::replaced`): `unreadable`,
    ///    `no_such_document`, `merge_refused` with its arm — `side_moved`
    ///    where `into` changed since the composition — a halt's face,
    ///    `session_died`; then `over_cap` where M passes the cap, nothing
    ///    landed;
    /// 6. where no `into` is named, the read of the person's own landing of
    ///    this composition standing in a draft their records of the key name
    ///    (`skep_client::merge::resume`) — with none standing,
    ///    `merge_refused` with `landing_begun` naming the `draft`
    ///    and the `position` where the merge landed in a draft of the
    ///    person's that no record of theirs names, nothing staged or written
    ///    — then, where none stands, of the merge with the states
    ///    ignored (`landed_draft`): a halt's face, `session_died`; where
    ///    the first answers a draft, that draft's `doc_metadata` read, as
    ///    `into`'s in step 4, `not_owner` among them, then the re-open's read
    ///    of its image (`Shell::whole_draft`), as step 3's reads, nothing
    ///    landed; where the second names a draft landing under another key,
    ///    that draft's read, as `into`'s in step 4, `not_owner` among them,
    ///    and, where its marker names the side, the composition on the
    ///    marker's head and the re-open's reads as in step 5, the person's
    ///    record of the landing the marker marks read through that draft;
    ///    where the landing goes into that draft in a fresh one's place, the
    ///    read of what it replaces, as step 5's, `merge_refused` with
    ///    `side_moved` where the draft changed since the composition, then
    ///    the write door's again for it, `held_lines` among them, nothing
    ///    landed; then the landing's
    ///    (`skep_client::merge::land`): the board's
    ///    `arrangement_moved` verbatim, nothing landed; `merge_refused`
    ///    with `landing_begun` for a landing begun since that first read,
    ///    `fork_base_moved`, `base_not_in_chain`, `window_withheld` or
    ///    `needs_signed_session`; `not_owner`; a halt's face — the board too
    ///    busy to find the person's journal, the landing standing with its
    ///    record unwritten; and
    ///    `session_died` where a read or the write met the death signal.
    pub(super) fn merge_compose(&self, args: &Value) -> Result<Value, Refusal> {
        // The row's own members first, each refused in another form before
        // the session is looked up — the order every row keeps.
        let alternative = optional(args, "alternative", address_arg)?;
        let draft = optional(args, "draft", address_arg)?;
        let fork = optional(args, "fork", address_arg)?;
        let into = optional(args, "into", address_arg)?;
        let doc = address_arg(&args["doc"]).ok_or_else(|| Refusal::malformed("doc"))?;
        let doc_text = doc.to_string();
        if document_of(&doc_text).as_deref() != Some(doc_text.as_str()) {
            return Err(Refusal::malformed("doc"));
        }
        // One side of the three, a second named by the later in that order.
        let form = match (alternative, draft, fork) {
            (Some(a), None, None) => {
                if !is_daughter(&doc, &a) {
                    return Err(Refusal::malformed("alternative"));
                }
                Form::Daughter(a)
            }
            (None, Some(d), None) => {
                // NEVER the behind draft itself (B3-S11's THE DRAFT SIDE):
                // it stands beside the new one untouched.
                if into.as_ref() == Some(&d) {
                    return Err(Refusal::malformed("into"));
                }
                Form::Draft(d)
            }
            (None, None, Some(f)) => {
                // A fork lies outside the trunk's own tree: `doc` itself, a
                // member of its chain or an address within either is none.
                // `into` may name the fork itself, for its owner.
                if document_of(&f.to_string()).as_deref() == Some(doc_text.as_str()) {
                    return Err(Refusal::malformed("fork"));
                }
                Form::Fork(f)
            }
            (None, None, None) => return Err(Refusal::malformed("alternative, draft or fork")),
            (Some(_), Some(_), None) => return Err(Refusal::malformed("draft")),
            (_, _, Some(_)) => return Err(Refusal::malformed("fork")),
        };
        let session = self.session(&args["session"])?;
        // The one write door, over the landing's first write: `stage` where a
        // fresh draft may be staged, `set_arrangement` into the draft named,
        // which is asked for its held lines.
        let first_write = if into.is_some() { "set_arrangement" } else { "stage" };
        let signed = self.signed(&session, Write::call("merge.compose", first_write).over(into.iter().map(ToString::to_string)))?;
        let key = Self::family_key(&session);
        let kind = merge_kind(&signed.account).ok_or_else(|| Refusal::shell(Name::NO_ACCOUNT, json!({})))?;
        // THE MERGED ARM: a daughter a claim of the person's own already
        // names, nothing composed into a draft and nothing landed.
        if let Form::Daughter(daughter) = &form {
            if let Some((member, claims)) = self.own_claim_naming(&session, daughter, &signed.account)? {
                return self.merged_arm(&session, &signed, &doc, daughter, &member, claims, &kind);
            }
        }
        // `into`, UNTRUSTED: read before anything is composed, with the mark
        // of the landing standing in it (`Shell::standing_mark`) — the
        // re-open's, and the one the composition standing in it is set aside
        // by (skep #981).
        let mut over = match &into {
            Some(into) => {
                let facts = self.landing_target(&session, &signed.account, into)?;
                self.standing_mark(&session, into, facts, MarkRead::Land)?
            }
            None => None,
        };
        // Where the head read starts: the trunk member a daughter's address
        // lies under, a draft side's recorded base's, or a fork's recorded
        // base's, else its source's, or `doc` itself for a side begun from
        // it — else the library's own refusal of the side, before the head
        // is read. It finds the head, never the base, which the library
        // derives from the bases the board recorded up the side's line.
        let start = match &form {
            Form::Daughter(d) => trunk_member_above(&doc, d).ok_or_else(|| lib::Refusal::BaseUnknown(lib::Side::Member(d.clone()))),
            Form::Draft(d) => draft_start(&doc, d, self.draft_facts(&session, d)?.base.as_ref()),
            Form::Fork(f) => {
                let facts = self.draft_facts(&session, f)?;
                fork_start(&doc, f, facts.base.as_ref().or(facts.source.as_ref()))
            }
        };
        let start = start.map_err(|r| self.merge_refusal(&session, r))?;
        // THE RE-OPEN: the mark on `into` naming this side (`names_side`),
        // composed on the head the mark names; else the trunk's head as it
        // stands.
        let reopen = into.as_ref().and_then(|into| reopening(&doc, form.side(), into, over.as_ref()));
        let head = match &reopen {
            Some(m) => bounded_address(&m.head).expect("filtered to a trunk member"),
            None => self.trunk_head(&session, &signed, &doc, &start, &form.library_side())?,
        };
        let mut merged = self.composed(&session, &doc, &form, head, reopen.as_ref(), &kind)?;
        let merger = lib::Merger { token: &session.token, account: &signed.account, signer: &*signed.signer };
        // What a landing over an earlier landing of the merge replaces, where
        // a fork moved since it (the owner's ruling of 2026-11-20).
        let mut replaced = None;
        if let (Some(marker), Some(into)) = (&reopen, &into) {
            // The person's own record of the landing, read once: a draft
            // side composed again as it names it where a write landed under
            // the side between the composition and its landing, a fork's
            // state tested against the one it keeps.
            let landed = self.reopened_by(&session, &signed.account, &kind, &form, into, marker)?;
            merged = self.as_landed(&session, &form, merged, into, marker, landed.as_ref())?;
            if !fork_moved(&form, &merged, into, marker, landed.as_ref()) {
                // The landing the marker names gets its record where none of
                // the person's names it and `into` still holds the merge: a
                // record-only completion, the landing's write never sent
                // again, so a landing cut off before its record and named as
                // `into` is recorded once (PUB-8.32). A fork landed in itself
                // is composed as it stands, its base moved to the head by
                // that landing, so its composition is no longer the one that
                // landed, and none is recorded of it.
                if !matches!(&form, Form::Fork(f) if f == into) {
                    lib::resume(&session.board, &merged, lib::Landing::Draft { merger, into: Some(into.clone()), journal: None }).map_err(|r| self.merge_refusal(&session, r))?;
                }
                return self.reopened(&session, key, form, merged, into, marker.at);
            }
            // The moved fork: composed again on the trunk's head as it
            // stands, and landed over `into`.
            let head = self.trunk_head(&session, &signed, &doc, &start, &form.library_side())?;
            if head != merged.inputs.head {
                merged = self.composed(&session, &doc, &form, head, None, &kind)?;
            }
            replaced = Some(self.replaced(&session, into, &merged)?);
        }
        if merged.composed.counts.m > merged.cap {
            return Err(Refusal::shell(Name::OVER_CAP, json!({"n": merged.composed.counts.m, "cap": merged.cap})));
        }
        // A fresh draft asked for while a record of the person's own
        // names a draft landing of the merge (the survey §5 item 2),
        // read as the library's landing reads it: this composition's
        // landing standing in a draft their own records of the key
        // name, whatever landed or was taken back in another since, by
        // `lib::resume` with no draft named, which writes nothing — never
        // the composition's `prior`, which is read under the reader's
        // currency and can be another account's record of the kind —
        // else their newest record of the merge with the states ignored
        // that names a draft landing no take-back of theirs replaces
        // (`lib::landed_draft`), where its key is another than the
        // composition's: a fork or a draft side moved since that landing.
        // That draft is read as `into` is, untrusted. Found by the key, it
        // is the re-open at the position the library answers: its mark's,
        // or its record's where the walk of a draft with no recorded base
        // needs a past state the board has reclaimed — a landing the
        // library cannot judge is never made a second time, and no second
        // read of the mark here overrules it. A record of the composition's
        // own key whose draft no longer holds its landing — taken back with
        // the take-back's record unwritten, or another landing standing
        // over it — names no draft to land in: the page asked for a fresh
        // draft, and the landing goes to one (the merge record's decision
        // 16). Found with the states ignored, the call goes on as one naming
        // it: its marker naming the side re-opens it; else, or at a fork
        // moved since, it is landed into, naming what it replaces. The
        // library is handed `into` none only where neither read found a
        // draft to land in — one landed since is the library's answer,
        // nothing staged, which its `staged` says, and a landing of the
        // merge begun in a draft of the person's and never recorded is the
        // library's refusal naming it, nothing staged. `over` is the mark of
        // the landing standing in the draft the landing goes into, read
        // here, which the composition standing in it is set aside by (skep
        // #981).
        let mut landing_into = into.clone();
        if landing_into.is_none() {
            if let Some(standing) = lib::resume(&session.board, &merged, lib::Landing::Draft { merger, into: None, journal: None }).map_err(|r| self.merge_refusal(&session, r))? {
                let lib::Landed::Draft { into: prior, position, .. } = standing else {
                    return Err(Refusal::from(Halt::face(
                        "the draft landing answered no draft",
                        "`skep_client::merge::resume` with a draft landing answers `Landed::Draft` or none on every path",
                        "report it: the shell's merge row is behind the library",
                    )));
                };
                self.landing_target(&session, &signed.account, &prior)?;
                return self.reopened(&session, key, form, merged, &prior, Some(position));
            } else if let Some(prior) = self.landed_draft(&session, &signed.account, &kind, &merged)?.filter(|record| record.key() != merged.key).as_ref().and_then(draft_landing).map(|(draft, _)| draft.clone()) {
                let facts = self.landing_target(&session, &signed.account, &prior)?;
                let mark = self.standing_mark(&session, &prior, facts, MarkRead::Land)?;
                if let Some(marker) = reopening(&doc, form.side(), &prior, mark.as_ref()) {
                    let head = bounded_address(&marker.head).expect("filtered to a trunk member");
                    let composed = if head == merged.inputs.head && !matches!(form, Form::Draft(_)) { merged.clone() } else { self.composed(&session, &doc, &form, head, Some(&marker), &kind)? };
                    // The record the re-open goes by, read through `prior`
                    // as at a named `into`: the newest record of the merge,
                    // which found `prior`, need not stand for the landing
                    // its marker marks — after an undo whose record went
                    // unwritten put an earlier landing's marker back, it
                    // names the later landing.
                    let landed = self.reopened_by(&session, &signed.account, &kind, &form, &prior, &marker)?;
                    let composed = self.as_landed(&session, &form, composed, &prior, &marker, landed.as_ref())?;
                    if !fork_moved(&form, &composed, &prior, &marker, landed.as_ref()) {
                        return self.reopened(&session, key, form, composed, &prior, marker.at);
                    }
                }
                // Landed over whatever stands in `prior` — the merge's
                // earlier landing with a moved fork, another merge's landing,
                // the person's own edits — the landing names what it replaces.
                replaced = Some(self.replaced(&session, &prior, &merged)?);
                over = mark;
                landing_into = Some(prior);
            }
        }
        // The person's own record's draft landed into in a fresh one's place
        // (skep #790) is a draft the door has not asked for its held lines:
        // asked now, before the landing's write, as the named draft was.
        if let Some(prior) = landing_into.as_ref().filter(|prior| into.as_ref() != Some(*prior)) {
            self.write_door(Writer::Session(&session), &Write::call("merge.compose", "set_arrangement").over([prior.to_string()]))?;
        }
        // The write out until its position is noted, let go before a death
        // at it ends the session (`hold::WriteOut`; skep #1000).
        let out = self.holds.write_out(&session);
        let landed = out.noted(lib::land(&session.board, &merged, lib::Landing::Draft { merger, into: landing_into, journal: None }), |landed| {
            if let lib::Landed::Draft { into, position, .. } = landed {
                self.holds.note_arranged(&session, &into.to_string(), *position);
            }
        });
        let lib::Landed::Draft { into: landed_in, position, record, head_moved, staged } = landed.map_err(|r| self.merge_refusal(&session, r))? else {
            return Err(Refusal::from(Halt::face("the draft landing answered no draft", "`skep_client::merge::land` with a draft landing answers `Landed::Draft` on every path", "report it: the shell's merge row is behind the library")));
        };
        let composition = Composition { session: session.reference.clone(), form, merged, into: landed_in.clone(), at: Some(position), chosen: BTreeMap::new() };
        let mut extra = json!({"into": landed_in.to_string(), "position": position, "fresh": staged, "head_moved": head_moved.map(|h| h.to_string()), "record_link": record.to_string()});
        if let Some(replaced) = replaced {
            extra["replaced"] = replaced.iter().map(replaced_json).collect();
        }
        let answer = report_json(&composition.merged, &composition.form, "landed", extra);
        self.merges.stand_over(key, composition, over.as_ref());
        Ok(answer)
    }

    /// Composes `form`'s merge on `head` (`skep_client::merge::compose`).
    ///
    /// At THE RE-OPEN — `reopen` the marker it re-opens — a draft side is
    /// read as its landing left it: at the marker's position where a write
    /// under it landed since, else its image as it stands, the same state.
    /// That is the side as compose read it but where a write under it landed
    /// between the composition and its landing, which the re-open composes
    /// again by the landing's record (`Shell::as_landed`). A fork is read as
    /// it stands, its state recorded beside it, which the re-open tests
    /// against the landing's (`fork_moved`).
    ///
    /// # Errors
    ///
    /// The drafts supplement's, at a draft side re-opened
    /// (`Shell::moved_since`); the composition's, through `merge_refusal`.
    fn composed(&self, session: &SessionEntry, doc: &Address, form: &Form, head: Address, reopen: Option<&MergeMarker>, kind: &Address) -> Result<lib::Merged, Refusal> {
        let side = match form {
            Form::Daughter(d) => lib::Side::Member(d.clone()),
            Form::Draft(d) => {
                let position = match reopen.and_then(|m| m.at) {
                    Some(at) if self.moved_since(session, d, at)? => Some(at),
                    _ => None,
                };
                lib::Side::Draft { at: d.clone(), position }
            }
            Form::Fork(f) => lib::Side::Fork(f.clone()),
        };
        let inputs = lib::Inputs { doc: doc.clone(), head, base: None, sides: vec![side], options: lib::Options::default(), kind: kind.clone() };
        lib::compose(&session.board, Some(&session.token), &inputs).map_err(|r| self.merge_refusal(session, r))
    }

    /// Returns a re-opened merge with its draft side as the landing read it.
    ///
    /// `merged` is the re-open's composition on the marker's head, its draft
    /// side read at the marker's position (`Shell::composed`), and `landed`
    /// the person's own record the re-open goes by (`Shell::reopened_by`).
    /// A write that landed under the side between the composition and its
    /// landing is in that read and was never in the composition
    /// (`client.md` §4b.1's merge row, the side read as compose read it;
    /// skep #1127). The record of the landing `marker` marks — the one
    /// naming `draft` as landed in at the marker's `at` — keeps the side's
    /// state as composed, a term of its key, and the position the side was
    /// read at beside it (the merge record's §4, "for a draft read at N"):
    /// where that key is another than `merged`'s, the merge is composed
    /// again over `merged`'s own inputs with the side read at that
    /// position. Every other composition is answered as given: a
    /// daughter's and a fork's; one whose key is the record's, the side
    /// unwritten between the two; and one whose landing no record of the
    /// person's names at the marker's `at` — a landing cut off before its
    /// record, or one the record of an earlier landing of the key in the
    /// draft stands for — since nothing names the position it was composed
    /// at.
    ///
    /// # Errors
    ///
    /// The composition's at the position the record names, through
    /// `merge_refusal`: `merge_refused` with `history_reclaimed` among them,
    /// where the board no longer answers that position.
    fn as_landed(&self, session: &SessionEntry, form: &Form, merged: lib::Merged, draft: &Address, marker: &MergeMarker, landed: Option<&lib::Record>) -> Result<lib::Merged, Refusal> {
        let Form::Draft(side) = form else { return Ok(merged) };
        let composed_at = landed.filter(|r| draft_landing(r).is_some_and(|(d, at)| d == draft && Some(at) == marker.at)).filter(|r| r.key() != merged.key).and_then(|r| {
            r.sides.iter().find_map(|s| match s {
                SideAt::Draft { at, position, .. } if at == side => *position,
                SideAt::Draft { .. } | SideAt::Member { .. } | SideAt::Fork { .. } => None,
            })
        });
        let Some(position) = composed_at else { return Ok(merged) };
        let inputs = lib::Inputs { sides: vec![lib::Side::Draft { at: side.clone(), position: Some(position) }], ..merged.inputs };
        lib::compose(&session.board, Some(&session.token), &inputs).map_err(|r| self.merge_refusal(session, r))
    }

    /// Returns the person's record a re-open of `marker`'s landing goes by.
    ///
    /// It is their own record of the landing `marker` marks in `draft`
    /// (`skep_client::merge::landing_record`): found through the links of
    /// the kind to `draft`, another account's never read as theirs, the one
    /// standing for that marker whatever the merge landed in since — never
    /// their newest record of the merge, which a landing in another draft
    /// takes over. It is read where the form's re-open goes by one
    /// (`Form::reopens_by_record`): once for the re-open, the draft side's
    /// position (`Shell::as_landed`) and the fork's state (`fork_moved`)
    /// both read off it.
    ///
    /// # Errors
    ///
    /// `landing_record`'s refusals, through `merge_refusal`.
    fn reopened_by(&self, session: &SessionEntry, account: &str, kind: &Address, form: &Form, draft: &Address, marker: &MergeMarker) -> Result<Option<lib::Record>, Refusal> {
        if !form.reopens_by_record(draft) {
            return Ok(None);
        }
        lib::landing_record(&session.board, Some(&session.token), kind, draft, marker, account).map_err(|r| self.merge_refusal(session, r))
    }

    /// Returns the person's own newest record of a draft landing of the
    /// merge.
    ///
    /// The record is found with its states ignored, names the draft it
    /// landed in, and no take-back of theirs replaces it
    /// (`skep_client::merge::landed_draft`): where its key is another than
    /// the composition's — a fork or a draft side moved since that landing —
    /// the draft a call naming no `into` goes on with where no landing of
    /// this composition stands. The re-open there goes by that draft's own
    /// record of the landing its marker marks (`Shell::reopened_by`), never
    /// by this one.
    ///
    /// # Errors
    ///
    /// `landed_draft`'s refusals, through `merge_refusal`.
    fn landed_draft(&self, session: &SessionEntry, account: &str, kind: &Address, merged: &lib::Merged) -> Result<Option<lib::Record>, Refusal> {
        lib::landed_draft(&session.board, Some(&session.token), kind, &merged.key, account).map_err(|r| self.merge_refusal(session, r))
    }

    /// Returns each stretch of `draft` that landing `merged` there replaces.
    ///
    /// It is `skep_client::merge::replaced`'s answer.
    ///
    /// # Errors
    ///
    /// `replaced`'s refusals, through `merge_refusal`.
    fn replaced(&self, session: &SessionEntry, draft: &Address, merged: &lib::Merged) -> Result<Vec<lib::Replaced>, Refusal> {
        lib::replaced(&session.board, Some(&session.token), draft, merged).map_err(|r| self.merge_refusal(session, r))
    }

    /// Answers the re-open: the report with nothing landed, each unsettled
    /// gap's state read off `into` as it stands (the module doc).
    ///
    /// Where `into` holds a gap with spots' words at another holding side's
    /// spot (`holders_moved`), the merge is composed again over `merged`'s
    /// own inputs with that side's placement chosen, settled by the merger,
    /// and every other gap is read off the one image over that composition
    /// (`settle_by_edit`). The report carries that reading; the composition
    /// stands as composed, so `merge.land` reads each gap again off the
    /// words its shot publishes and `keep_both` asks a gap's default. `at`
    /// is the position of the mark re-opened, the landing the composition
    /// stands for (`Composition::at`).
    ///
    /// # Errors
    ///
    /// The draft's image read's (`whole_draft`); the composition's again,
    /// through `merge_refusal`, where a holder's placement was moved.
    fn reopened(&self, session: &SessionEntry, key: (String, u64), form: Form, merged: lib::Merged, into: &Address, at: Option<u64>) -> Result<Value, Refusal> {
        let (merged, image) = self.held_in(session, merged, into)?;
        let mut read = merged.clone();
        settle_by_edit(&mut read, &image, self.surface());
        let position = at.unwrap_or(merged.as_of);
        let answer = report_json(&read, &form, "reopened", json!({"into": into.to_string(), "position": position, "fresh": false, "head_moved": Value::Null}));
        self.merges.stand(key, Composition { session: session.reference.clone(), form, merged, into: into.clone(), at, chosen: BTreeMap::new() });
        Ok(answer)
    }

    /// Returns `merged` composed as `doc`'s image holds its gaps with spots,
    /// beside that image.
    ///
    /// Where the image holds a gap with spots' words at another holding
    /// side's spot (`holders_moved`), the merge is composed again over
    /// `merged`'s own inputs with that side's placement chosen, settled by
    /// the merger; every other gap stands as composed, for the caller to read
    /// off the image (`settle_by_edit`). `doc` is the draft a re-open reads,
    /// or the member the merged arm records.
    ///
    /// # Errors
    ///
    /// The image read's (`whole_draft`); the composition's again, through
    /// `merge_refusal`, where a holder's placement was moved.
    fn held_in(&self, session: &SessionEntry, mut merged: lib::Merged, doc: &Address) -> Result<(lib::Merged, Vec<SelectionRun>), Refusal> {
        let image = self.whole_draft(session, doc)?;
        let laid = MergedList::of(&merged.composed.runs);
        let moved = holders_moved(&merged.record.gaps, &image, &laid, &self.surface().settler());
        if !moved.is_empty() {
            let mut inputs = merged.inputs.clone();
            inputs.options.resolutions.extend(moved);
            merged = lib::compose(&session.board, Some(&session.token), &inputs).map_err(|r| self.merge_refusal(session, r))?;
        }
        Ok((merged, image))
    }

    /// Answers THE MERGED ARM: the member a claim of the person's own names
    /// the daughter superseded by, and the record of that merge — the
    /// person's own standing one, or written now through the library's
    /// `record_published` where none of theirs names it (the module doc).
    ///
    /// The record written is the member's testimony: every gap read off the
    /// member's image as THE RE-OPEN reads a draft (`held_in`,
    /// `settle_by_edit`), and the record written only where the member
    /// verifies against it (`skep_client::merge::verify` answering `Equal`)
    /// — a member edited past its gaps' choices, or holding window parts the
    /// shot answered, which no read recovers, is answered with no record,
    /// `unrecorded` naming why, so no record claims what the member does not
    /// hold.
    ///
    /// # Errors
    ///
    /// The composition's, as `merge.compose`'s step 5; where no record of
    /// the person's names the member, the member's image read's and the
    /// composition's again where a holder's placement moved (`held_in`), the
    /// member's `doc_metadata` read's, the verification's, through
    /// `merge_refusal`, and the record's, as `merge.land`'s record.
    fn merged_arm(&self, session: &SessionEntry, signed: &Signed, doc: &Address, daughter: &Address, member: &Address, claims: Vec<Address>, kind: &Address) -> Result<Value, Refusal> {
        // The head the merge was composed on: the member's predecessor on
        // the trunk, or the trunk member a daughter member lies under.
        let head = if is_trunk_member(doc, member) { trunk_member_before(member) } else { trunk_member_above(doc, member) };
        let Some(head) = head.filter(|h| is_trunk_member(doc, h)) else {
            return Err(Refusal::shell(Name::MERGE_REFUSED, json!({"arm": "claim_names_no_member", "member": member.to_string()})));
        };
        let inputs = lib::Inputs { doc: doc.clone(), head, base: None, sides: vec![lib::Side::Member(daughter.clone())], options: lib::Options::default(), kind: kind.clone() };
        let mut merged = lib::compose(&session.board, Some(&session.token), &inputs).map_err(|r| self.merge_refusal(session, r))?;
        // The person's own standing record naming the member: the
        // composition's `prior` only where its link lies in their account,
        // exactly. The claim's home is the trunk, theirs, and the currency
        // puts the trunk owner's records first, so a `prior` whose link lies
        // elsewhere is another account's record of the kind, standing where
        // the person holds none.
        let own = |p: &&lib::Record| p.link.as_ref().and_then(|l| account_of(&l.to_string())).is_some_and(|a| a == signed.account);
        let standing = merged.prior.as_ref().filter(own).filter(|p| matches!(&p.landed, Some(lib::RecordLanding::Member { member: m, .. }) if m == member)).map(|p| (p.link.clone(), p.to_value()));
        // The record: the standing one, its body the report's, else written
        // now — the resume of a stop between the shot and its record — with
        // the gaps as the member holds them, where the member verifies.
        let (record_link, claims, body, unrecorded) = match standing {
            Some((link, body)) => (link, claims, Some(body), None),
            None => {
                let (held, image) = self.held_in(session, merged, member)?;
                merged = held;
                settle_by_edit(&mut merged, &image, self.surface());
                let position = self.metadata_read(session, member)?["at"].as_u64().unwrap_or(merged.as_of);
                let mut testimony = merged.record.clone();
                testimony.landed = Some(lib::RecordLanding::Member { member: member.clone(), position });
                match lib::verify(&session.board, Some(&session.token), &testimony).map_err(|r| self.merge_refusal(session, r))? {
                    lib::Verdict::Equal => {
                        let merger = lib::Merger { token: &session.token, account: &signed.account, signer: &*signed.signer };
                        // The answers the shot was given are not known here,
                        // so none are recorded: a member holding answered
                        // window parts verifies against none and is never
                        // recorded here.
                        match lib::record_published(&session.board, &merged, merger, member, position, None, &[]).map_err(|r| self.merge_refusal(session, r))? {
                            lib::Landed::Member { record, claims, .. } => (Some(record), claims, None, None),
                            _ => (None, claims, None, None),
                        }
                    }
                    // The member holds otherwise than the record would say:
                    // the residue named, no record written.
                    lib::Verdict::Differs { at } => {
                        let why = Refusal::shell(Name::MERGE_REFUSED, json!({"arm": "member_differs", "member": member.to_string(), "at": at}));
                        (None, claims, None, Some(why))
                    }
                    lib::Verdict::Unreadable(doc) => (None, claims, None, Some(Refusal::shell(Name::UNREADABLE, json!({"doc": doc.to_string()})))),
                    lib::Verdict::SideMoved { side, .. } => {
                        let why = Refusal::shell(Name::MERGE_REFUSED, json!({"arm": "side_moved", "side": side.to_string()}));
                        (None, claims, None, Some(why))
                    }
                }
            }
        };
        let form = Form::Daughter(daughter.clone());
        let mut extra = json!({"member": member.to_string(), "claims": claims.iter().map(ToString::to_string).collect::<Vec<_>>(), "record_link": record_link.map(|l| l.to_string())});
        if let Some(body) = body {
            extra["record"] = body;
        }
        if let Some(unrecorded) = unrecorded {
            extra["unrecorded"] = unrecorded.to_value();
        }
        Ok(report_json(&merged, &form, "merged", extra))
    }

    /// Answers `merge.land(session, {resolutions?, answers?})` with the
    /// landing, the panel's re-statement or its typed refusal (the module
    /// doc; `shapes`' `MergeLanded`).
    ///
    /// # Errors
    ///
    /// In this order: `malformed_args` naming `resolutions` where it is
    /// present and no object, naming `answers` where it is present and no
    /// object of strings; `malformed_args` naming `session`, then
    /// `session_ended`; `no_merge` naming the session where no composition
    /// stands under its board and principal and none is set aside — where
    /// one is, the write door's as below, naming `publish` and no draft, then
    /// each such draft's marker read's, as the marker read's below, and
    /// `no_merge` naming the session where none stands again
    /// (`Shell::standing_or_set_aside`); `malformed_args` naming
    /// `resolutions` where a gap id names no gap of the composition, one
    /// another id names too, one the rules settled (`resolved_by` `rule`) or
    /// a spine's `moves` gap, or a choice is none the gap admits
    /// (`checked_resolutions`); the write door's, in its order —
    /// `write_in_bare_session`, `another_window`, `stopped`, `poisoned` or
    /// `halted` naming `publish`, `held_lines` naming the draft the
    /// composition landed in or the draft side and the lines of the
    /// principal's standing on it — nothing read at any; `store_unreadable`,
    /// `no_account`; `other_panel` naming the draft the composition landed
    /// in and the panel's `doc` or `mint` where the family's panel of that
    /// draft, standing or held, publishes into another document than the
    /// composition's or mints an edition — nothing read, every panel and the
    /// composition as they stood, the panel to be cancelled before the row
    /// lands (`publication.cancel`, a held panel re-opened first by
    /// `publication.open` naming the draft and that `doc` or `mint` alone);
    /// where a panel stands or is held, the draft's marker read's —
    /// `unreadable` or `no_such_document` naming the draft, the board's
    /// verdicts verbatim, `unreachable`, `session_died`, `shape` naming
    /// `doc_metadata` — then
    /// `no_merge` naming the draft where the marker marks no merge of the
    /// composition's or the draft carries none, the composition dropped and
    /// nothing keyed (skep #992); or, where the shell opens one, the panel's
    /// open's (`publication.open`'s steps 4 to 6), then `no_merge` naming the
    /// draft as above, the panel opened dropped; then, where a gap stands
    /// that the rules did not settle, the draft's image read's where a panel
    /// stands or is held (`Shell::whole_draft`) — `unreadable` or
    /// `no_such_document` naming the draft, the board's verdicts verbatim,
    /// `unreachable`, `session_died`, `shape` — then `malformed_args` naming
    /// `resolutions` where the words the shot would publish do not hold a
    /// choice standing, the call's or an earlier call's (`draft_holds`),
    /// then `merge_refused` with `gap_edited` naming the `gap` where the
    /// draft holds a `moves` gap with spots' words elsewhere than the
    /// composition placed them (`spots_edited`), each nothing keyed, the
    /// composition as it stood and the panel opened dropped; then the
    /// standing panel's keying's on the draft as it stands
    /// (`Shell::landing_panel`);
    /// `malformed_args` naming `answers` where one is no `⟨run⟩.⟨part⟩` of a
    /// part the panel holds or one the part does not admit; the words' reads
    /// of the window parts' refusal
    /// and acknowledgment; then `publication.confirm`'s from
    /// `write_in_bare_session` on — the door asked again over the panel's
    /// drafts, a draft the page's panel names `also` among them, nothing
    /// composed — and `window_parts_owed` where a window part is unanswered
    /// when the shot would be composed, every part named, nothing sent. The
    /// record's refusal after an acknowledgment is no error: the member
    /// stands, and the answer carries it as `unrecorded`.
    pub(super) fn merge_land(&self, args: &Value) -> Result<Value, Refusal> {
        let resolutions = optional(args, "resolutions", |v| v.as_object().cloned())?;
        let raw_answers = optional(args, "answers", |v| v.as_object().filter(|m| m.values().all(Value::is_string)).cloned())?.unwrap_or_default();
        let session = self.session(&args["session"])?;
        let key = Self::family_key(&session);
        // The composition standing, or one set aside whose landing its draft
        // carries again, read by its marker as this row's gate reads it.
        let mut composition = self.standing_or_set_aside(&session, &key, Write::call("merge.land", "publish"), |draft| self.draft_marker(&session, draft))?;
        // The merger's choices: the call's own, checked against the
        // composition before the door, over those an earlier call of the
        // composition named, a choice the call names at a gap taking the
        // earlier one's place.
        let named = resolutions.as_ref().map(|r| checked_resolutions(&composition.merged.record.gaps, r)).transpose()?;
        let mut chosen = composition.chosen.clone();
        chosen.extend(named.iter().flatten().map(|(ix, placed)| (*ix, placed.clone())));
        let into = composition.into.clone();
        // The one write door, over the shot's drafts: the draft the
        // composition landed in and, at the draft side, the side the shot
        // names `also`; the panel's own `also` drafts are asked again as the
        // shot is confirmed (`Shell::confirm_standing`).
        let side = composition.form.also().cloned();
        let signed = self.signed(&session, Write::call("merge.land", "publish").over(std::iter::once(&into).chain(side.as_ref()).map(ToString::to_string)))?;
        // The panel: the page's over the draft at the composition's document,
        // standing or held, or one opened here over the whole draft, the
        // draft side named `also`; a panel of the draft in another form
        // refuses. Either is keyed only on a marker that marks the
        // composition's merge, tested before any keying: the page's panel
        // against the marker read now — keyed on the draft as it stands,
        // below, where it was read under another — and the opened one
        // against the marker its open read.
        let doc = composition.merged.inputs.doc.clone();
        let (mut state, keyed) = match self.publications.stood_for(&key, &into, &doc, &session.reference)? {
            Some(state) => {
                let read = self.draft_marker(&session, &into)?;
                let marker = self.carried(&key, &composition, read.as_ref())?.clone();
                (state, Some(marker))
            }
            None => {
                let also = side.iter().cloned().collect();
                let (state, _) = self.open_panel(
                    &session,
                    &signed,
                    OpenArgs {
                        draft: into.clone(),
                        also: Some(also),
                        doc: Some(doc.clone()),
                        mint: None,
                        claim: Some(false),
                        selection: None,
                        notes: None,
                        readable_drafts: None,
                        published: None,
                        merge_landing: true,
                    },
                )?;
                self.carried(&key, &composition, state.marker())?;
                (state, None)
            }
        };
        // The words the shot publishes (the module doc), read where a choice
        // stands or a gap the rules did not settle: the draft's image where
        // the panel takes the whole draft as it stands — the one the row
        // opened, whose open read it, or the page's keyed below on another
        // marker — else the panel's selection as the draft arranges it;
        // beside them the whole draft, which a gap with spots is read over.
        // The choices are read off them first, and stand with the
        // composition once the draft holds them, so a re-statement carries
        // them to the next call, which reads them again; every other gap is
        // read off them as the re-open reads the draft.
        let rules_alone = composition.merged.record.gaps.iter().all(|g| g.resolved_by == Some(ResolvedBy::Rule));
        let words = if chosen.is_empty() && rules_alone {
            None
        } else {
            Some(match &keyed {
                Some(marker) => {
                    let draft = self.whole_draft(&session, &into)?;
                    let selected = (!state.whole() || state.marker() == Some(marker)).then(|| selected_image(&draft, &state.inputs.selection));
                    Words { whole: Cow::Owned(draft), selected }
                }
                None => Words { whole: Cow::Borrowed(state.inputs.selection.as_slice()), selected: None },
            })
        };
        if let Some(words) = &words {
            let gaps = &composition.merged.record.gaps;
            let laid = MergedList::of(&composition.merged.composed.runs);
            if !chosen.iter().all(|(ix, placed)| gaps.get(*ix).is_some_and(|gap| draft_holds(gap, placed, words.published(), &laid))) {
                return Err(Refusal::malformed("resolutions"));
            }
            if let Some(gap) = spots_edited(gaps, &chosen, &words.whole, &laid) {
                return Err(Refusal::shell(Name::MERGE_REFUSED, json!({"arm": "gap_edited", "gap": gap.0})));
            }
        }
        if named.is_some() {
            composition.chosen = chosen;
            self.merges.stand(key.clone(), composition.clone());
        }
        settle_resolutions(&mut composition.merged, &composition.chosen, self.surface());
        if let Some(words) = words {
            settle_by_edit(&mut composition.merged, words.published(), self.surface());
        }
        match &keyed {
            Some(marker) => {
                if let Some(restated) = self.landing_panel(&session, &signed, &key, &mut state, &doc, side.as_ref(), marker)? {
                    return Ok(restated);
                }
            }
            None => self.publications.stand(key.clone(), state.clone()),
        }
        let switches = state.switches.clone();
        let mut answers = state.answers.clone();
        // The caller's answers, in the panel's form. The landing composes no
        // answer of its own at any window part (the module doc).
        answers.extend(Self::bound_answers(&state, &raw_answers)?);
        let merger = lib::Merger { token: &session.token, account: &signed.account, signer: &*signed.signer };
        let given = lib::given_parts(&session.board, &composition.merged, merger, &into, &state.enumeration.windows, &answers).map_err(|r| self.merge_refusal(&session, r))?;
        let part_answers = lib::part_answers(&state.enumeration.windows, &answers);
        let left_private = left_private_json(&state, &answers, &switches);
        let defaults: Vec<Value> = composition.merged.record.gaps.iter().filter(|g| !g.settled).map(default_json).collect();
        let deduped = deduped_json(&composition.merged.record);
        match self.confirm_standing(&session, &key, &state, switches, answers, "merge.land")? {
            Confirmation::Acknowledged { session: current, ack } => {
                // The record's two writes go into a private journal and sign
                // nothing, so the call's own hand, taken at its door, serves:
                // nothing is read past the acknowledgment that could answer
                // the landing as an error.
                let merger = lib::Merger { token: &current.token, account: &signed.account, signer: &*signed.signer };
                let recorded = lib::record_published(&current.board, &composition.merged, merger, &ack.member, ack.at, None, &part_answers);
                self.merges.take(&key);
                self.acknowledged(&current, &key, &into, &ack);
                let daughter = !is_trunk_member(&composition.merged.inputs.doc, &ack.member);
                let mut v = json!({
                    "outcome": "landed",
                    "member": ack.member.to_string(),
                    "at": ack.at,
                    "via": via_name(ack.via),
                    "claim": ack.claim,
                    "supersede": ack.supersede.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "daughter": daughter,
                    "record": Value::Null,
                    "claims": Vec::<Value>::new(),
                    "retries": composition.merged.inputs.options.retries,
                    "answers": given.iter().map(window_part_json).collect::<Vec<_>>(),
                    "left_private": left_private,
                    "defaults": defaults,
                    "deduped": deduped,
                });
                match recorded {
                    Ok(lib::Landed::Member { record, claims, retries, .. }) => {
                        v["record"] = json!(record.to_string());
                        v["claims"] = json!(claims.iter().map(ToString::to_string).collect::<Vec<_>>());
                        v["retries"] = json!(retries);
                    }
                    Ok(_) => {}
                    Err(r) => v["unrecorded"] = self.merge_refusal(&current, r).to_value(),
                }
                Ok(v)
            }
            // The parts that need an answer: the same refusal, every part
            // named, as `skep merge --publish` makes — no panel or page reading of its own.
            Confirmation::Owed(owed) => {
                let merger = lib::Merger { token: &session.token, account: &signed.account, signer: &*signed.signer };
                let parts = lib::owed_parts(&session.board, &composition.merged, merger, &into, &state.enumeration.windows, &owed).map_err(|r| self.merge_refusal(&session, r))?;
                Err(Refusal::shell(Name::WINDOW_PARTS_OWED, owed_detail(&parts, &given, &[], left_private, Value::Array(defaults))))
            }
            Confirmation::Answered(answer) => {
                // The race: the composition made again on the head the
                // refusal names.
                if answer["arm"] == "supersede_refused" && answer["detail"] == "head_moved" {
                    self.merges.take(&key);
                }
                Ok(answer)
            }
        }
    }

    /// Answers `merge.undo(session)` with `{draft, position, record,
    /// restored, marker}` (the module doc; `shapes`' `Undone`).
    ///
    /// The undo is typed against the landing's position — or the latest
    /// write that put its marker back, where only a take-back and its undo
    /// moved the words since — or, at the editor, the principal's latest
    /// arrangement write on the draft the hold noted where that is later,
    /// the library taking the latest; with no person present, against the
    /// landing's or the put-back's alone (`Shell::own_ack`). `marker` is the
    /// marker the draft carries again, the one it carried before the
    /// landing, or null — always null on a draft with no recorded base,
    /// which carries none, whatever landing its rows leave standing (the
    /// library's `baseless_landing` reads it). The composition goes with its
    /// landing; where a later landing set one aside for the landing standing
    /// again — `marker`, or on a draft with no recorded base the landing its
    /// rows leave standing, read after the undo — that one stands in its
    /// place, so the next `merge.undo(session)` takes that landing back (skep
    /// #981). With `{draft, withdrawal}` it is the withdrawal's undo instead
    /// ([`Shell::merge_unwithdraw`]).
    ///
    /// The undo takes back the composition's own landing alone (skep #1050):
    /// the landing the library's undo takes back — the draft's marker where
    /// the board records a base for it, else the landing standing by its
    /// rows (the library's `baseless_landing`; skep #914) — is read first and
    /// must be the composition's own, its side, its head and its position
    /// (`Composition::marks`).
    ///
    /// # Errors
    ///
    /// In this order: `malformed_args` naming `session`, then
    /// `session_ended`; the withdrawal's undo's where `draft` or
    /// `withdrawal` is named; `no_merge` naming the session where no
    /// composition stands and none is set aside — where one is, the write
    /// door's as below, naming `set_arrangement` and no draft, then each such
    /// draft's reads, as the draft's reads below, and `no_merge` naming the
    /// session where none stands again (`Shell::standing_or_set_aside`); the
    /// write door's, in its order —
    /// `write_in_bare_session`,
    /// `another_window`, `stopped`, `poisoned` or `halted` naming
    /// `set_arrangement`, `held_lines` naming the draft the composition
    /// landed in and the lines of the principal's standing on it — nothing
    /// read at any; `store_unreadable`, `no_account`; the draft's
    /// `doc_metadata` read's — `unreadable` or `no_such_document` naming it,
    /// the board's verdicts verbatim, `unreachable`, `session_died`, `shape`
    /// naming `doc_metadata` — and, where the board records no base for it,
    /// the library's walk of its rows (`skep_client::merge::baseless_landing`),
    /// mapped as the library's refusals are: the feed's halts as a halt's
    /// face, `session_died`, and where a plain row follows a landing the
    /// reads of the draft's past states and their records — `merge_refused`
    /// with `history_reclaimed` or `history_busy`, `unreadable` or
    /// `no_such_document` naming the document a read was refused at, a
    /// halt's face for the rest; then `no_merge` naming the draft where the
    /// landing the undo would take back is another than the composition's —
    /// another merge's, or another landing of this merge — the composition
    /// dropped and nothing sent (skep #1050); the library's
    /// (`skep_client::merge::undo`): `unreadable`,
    /// `no_such_document`, `not_owner`, `nothing_to_undo` with its reason,
    /// `no_merge` naming the draft, `merge_refused` with `history_reclaimed`,
    /// `over_cap` where the state before the landing, mapped through the
    /// records, is in more runs than one write may name, the board's
    /// `arrangement_moved` verbatim, a halt's face, and `session_died`.
    pub(super) fn merge_undo(&self, args: &Value) -> Result<Value, Refusal> {
        let session = self.session(&args["session"])?;
        if !args["draft"].is_null() || !args["withdrawal"].is_null() {
            return self.merge_unwithdraw(&session, args);
        }
        let key = Self::family_key(&session);
        // The composition standing, or one set aside whose landing its draft
        // carries again, read by the landing standing as this row's gate
        // reads it.
        let composition = self.standing_or_set_aside(&session, &key, Write::call("merge.undo", "set_arrangement"), |draft| {
            let facts = self.draft_facts(&session, draft)?;
            self.standing_mark(&session, draft, facts, MarkRead::Undo)
        })?;
        // The one write door, over the draft the undo sets whole.
        let signed = self.signed(&session, Write::call("merge.undo", "set_arrangement").over([composition.into.to_string()]))?;
        let merger = lib::Merger { token: &session.token, account: &signed.account, signer: &*signed.signer };
        let kind = merge_kind(&signed.account).ok_or_else(|| Refusal::shell(Name::NO_ACCOUNT, json!({})))?;
        // The composition's own landing alone is taken back (skep #1050):
        // the one the library's undo takes back — the draft's marker where
        // the board records a base for it, else the landing standing by its
        // rows (skep #914) — must mark the composition's landing, else
        // `no_merge` naming the draft, the composition dropped and nothing
        // sent. A draft carrying no landing goes to the library, which
        // answers it.
        let facts = self.draft_facts(&session, &composition.into)?;
        if let Some(latest) = self.standing_mark(&session, &composition.into, facts, MarkRead::Undo)? {
            self.carried(&key, &composition, Some(&latest))?;
        }
        // The editor's own last ack on the draft, an agent's none (P3).
        let own_ack = self.own_ack(&session, &composition.into);
        let out = self.holds.write_out(&session);
        let undone = out.noted(lib::undo(&session.board, merger, &composition.into, &kind, own_ack, None), |undone| self.holds.note_arranged(&session, &undone.draft.to_string(), undone.position));
        let undone = undone.map_err(|r| self.merge_refusal(&session, r))?;
        // The landing standing again: the marker the undo put back, or on a
        // draft with no recorded base, whose undo goes by its rows and puts
        // no marker back, the landing those rows leave standing. A read that
        // fails stands nothing again, the undo, which landed, answered all
        // the same — a session's end at it ending the session, as at every
        // read of the family's.
        let standing = match &undone.restored {
            Some(_) => undone.marker.clone(),
            None => lib::baseless_landing(&session.board, Some(&session.token), &undone.draft).unwrap_or_else(|r| {
                if matches!(r, lib::Refusal::SessionEnded(_)) {
                    self.died(&session);
                }
                None
            }),
        };
        self.merges.stand_again(&key, &undone.draft, standing.as_ref());
        Ok(json!({
            "draft": undone.draft.to_string(),
            "position": undone.position,
            "record": undone.record.map(|r| r.to_string()),
            "restored": undone.restored.map(|(base, extent)| json!({"base": base.to_string(), "extent": extent})),
            "marker": undone.marker.as_ref().map(marker_json),
        }))
    }

    /// Answers `merge.withdraw(session, {draft})` with `{draft, position,
    /// record}` (the module doc; `shapes`' `Withdrawn`).
    ///
    /// # Errors
    ///
    /// In this order: `malformed_args` naming `draft`; `malformed_args`
    /// naming `session`, then `session_ended`; the write door's, in its
    /// order — `write_in_bare_session`, `another_window`, `stopped`,
    /// `poisoned` or `halted` naming `set_arrangement`, `held_lines` naming
    /// `draft` and the lines of the principal's standing on it — nothing
    /// read at any; `store_unreadable`, `no_account`; the library's
    /// (`skep_client::merge::withdraw`): `unreadable`, `no_such_document`,
    /// `not_owner`, `no_merge` naming the draft, `over_cap` where the
    /// draft's words are in more runs than one write may name, the board's
    /// `arrangement_moved` verbatim, a halt's face, and `session_died`.
    pub(super) fn merge_withdraw(&self, args: &Value) -> Result<Value, Refusal> {
        let draft = address_arg(&args["draft"]).ok_or_else(|| Refusal::malformed("draft"))?;
        let session = self.session(&args["session"])?;
        let key = Self::family_key(&session);
        // The one write door, over the draft the withdrawal sets whole.
        let signed = self.signed(&session, Write::call("merge.withdraw", "set_arrangement").over([draft.to_string()]))?;
        let merger = lib::Merger { token: &session.token, account: &signed.account, signer: &*signed.signer };
        let kind = merge_kind(&signed.account).ok_or_else(|| Refusal::shell(Name::NO_ACCOUNT, json!({})))?;
        let out = self.holds.write_out(&session);
        let withdrawn = out.noted(lib::withdraw(&session.board, merger, &draft, &kind, None), |withdrawn| self.holds.note_arranged(&session, &draft.to_string(), withdrawn.position));
        let withdrawn = withdrawn.map_err(|r| self.merge_refusal(&session, r))?;
        // The standing composition goes aside, for the withdrawal's undo to
        // stand again (skep #870).
        if self.merges.standing(&key).is_some_and(|c| c.into == draft) {
            if let Some(composition) = self.merges.take(&key) {
                self.merges.set_aside(key, &draft, withdrawn.position, composition);
            }
        }
        Ok(json!({"draft": withdrawn.draft.to_string(), "position": withdrawn.position, "record": withdrawn.record.map(|r| r.to_string())}))
    }

    /// Answers `merge.undo(session, {draft, withdrawal})`, a withdrawal's undo.
    ///
    /// The answer is `{draft, position, record, restored}`, `restored` null
    /// (skep #870; the module doc; `shapes`' `Undone`).
    ///
    /// `withdrawal` is the `position` a `merge.withdraw` answered. The undo
    /// is the library's `unwithdraw`, typed against the withdrawal's
    /// position or, at the editor, the principal's latest arrangement write
    /// on the draft the hold noted where that is later; with no person
    /// present, against the withdrawal's alone (`Shell::own_ack`). The
    /// composition the withdrawal took aside in this session stands again,
    /// so the next `merge.undo(session)` takes the landing back — and so it
    /// does where the library answers `nothing_to_undo` with `remarked` and
    /// the draft's marker, read then, is that composition's landing: the
    /// withdrawal taken back by another hand first (skep #870).
    ///
    /// # Errors
    ///
    /// In this order: `malformed_args` naming `draft`, then `withdrawal`;
    /// the write door's, in its order — `write_in_bare_session`,
    /// `another_window`, `stopped`, `poisoned` or `halted` naming
    /// `set_arrangement`, `held_lines` naming `draft` and the lines of the
    /// principal's standing on it — nothing read at any;
    /// `store_unreadable`, `no_account`; the library's
    /// (`skep_client::merge::unwithdraw`): `unreadable`,
    /// `no_such_document`, `not_owner`, `merge_refused` with
    /// `history_reclaimed`, `no_merge` naming the draft and the withdrawal
    /// where the position names no withdrawal of it, `nothing_to_undo` with
    /// `remarked` or `published`, `over_cap`, the board's
    /// `arrangement_moved` verbatim, a halt's face, and `session_died`.
    pub(super) fn merge_unwithdraw(&self, session: &SessionEntry, args: &Value) -> Result<Value, Refusal> {
        let draft = address_arg(&args["draft"]).ok_or_else(|| Refusal::malformed("draft"))?;
        let withdrawal = args["withdrawal"].as_u64().ok_or_else(|| Refusal::malformed("withdrawal"))?;
        let key = Self::family_key(session);
        // The one write door, over the draft the undo sets whole.
        let signed = self.signed(session, Write::call("merge.undo", "set_arrangement").over([draft.to_string()]))?;
        let merger = lib::Merger { token: &session.token, account: &signed.account, signer: &*signed.signer };
        let kind = merge_kind(&signed.account).ok_or_else(|| Refusal::shell(Name::NO_ACCOUNT, json!({})))?;
        // The editor's own last ack on the draft, an agent's none (P3).
        let own_ack = self.own_ack(session, &draft);
        let out = self.holds.write_out(session);
        let undone = out.noted(lib::unwithdraw(&session.board, merger, &draft, &kind, withdrawal, own_ack, None), |undone| self.holds.note_arranged(session, &draft.to_string(), undone.position));
        let undone = match undone {
            Ok(undone) => undone,
            Err(r @ lib::Refusal::NothingToUndo { why: NoUndo::Remarked, .. }) => {
                // The merge may stand in the draft again, the withdrawal
                // taken back by another hand: where the draft's marker marks
                // the landing of the composition this withdrawal took aside,
                // that composition stands again, so the next `merge.undo`
                // takes the landing back. A read that fails stands nothing,
                // the library's answer answered all the same.
                if let Ok(Some(marker)) = self.draft_marker(session, &draft) {
                    self.merges.stand_withdrawn(&key, &draft, withdrawal, &marker);
                }
                return Err(self.merge_refusal(session, r));
            }
            Err(r) => return Err(self.merge_refusal(session, r)),
        };
        if let Some(composition) = self.merges.put_back(&key, &draft, withdrawal) {
            self.merges.stand(key, composition);
        }
        Ok(json!({
            "draft": undone.draft.to_string(),
            "position": undone.position,
            "record": undone.record.map(|r| r.to_string()),
            "restored": Value::Null,
        }))
    }
}

// ── the resolutions, and the gaps' state at a re-open ─────────────────────

/// The draft's words a landing reads its gaps off (the module doc,
/// **`merge.land`**): the draft as it stands and the words its shot
/// publishes from it.
struct Words<'a> {
    /// The draft's whole image, which a gap with spots is read over
    /// (`spots_edited`).
    whole: Cow<'a, [SelectionRun]>,
    /// The panel's selection cut from `whole` in the draft's order
    /// (`selected_image`), `None` where the shot publishes the whole draft.
    selected: Option<Vec<SelectionRun>>,
}

impl Words<'_> {
    /// Returns the words the shot publishes, which the choices and every
    /// other gap are read off (`draft_holds`, `settle_by_edit`).
    fn published(&self) -> &[SelectionRun] {
        self.selected.as_deref().unwrap_or(&self.whole)
    }
}

/// Returns the caller's `resolutions` checked as UNTRUSTED input against the
/// composition's `gaps` (the module doc; SP-18): the placement each asks, by
/// the index of the gap it names.
///
/// Each is `⟨gap id⟩: ⟨choice⟩` — `keep_both` (the gap's placement as
/// composed, [`kept`]), `omit`, `{order: [sides]}` (each a side among the
/// gap's runs, none twice), `{keep_only: side}`, `{after: anchor}` or
/// `{before: anchor}` (the gap's own anchor) — naming each gap once, at a
/// gap the rules left unsettled. A gap the rules settled, `resolved_by`
/// `rule` — an `anchor` gap, or an `order` gap the value rule's dedup kept
/// once — takes none: its placement is the rules', which the library's own
/// composition never lets a resolution move, and a record naming a merger
/// there would say the merger placed it. A spine's `moves` gap takes none
/// either: its runs are the base material each side moved, so no reading of
/// the draft can show which side's order of the spine it holds
/// (`draft_holds`). At a `moves` gap with spots (CM-I33) the one choice is
/// `{order: [side]}` or `{keep_only: side}` naming the side whose placement
/// the composition took, a confirmation: the words are where the draft
/// holds them, and another holder's placement is reached by moving them to
/// its spot and composing again (`holders_moved`). Nothing is settled here:
/// a choice is recorded only where the draft holds it (`draft_holds`,
/// `settle_resolutions`).
///
/// # Errors
///
/// `malformed_args` naming `resolutions` at the first that fails its check
/// — a gap named twice (`"1"` and `"01"` name one), a gap the rules
/// settled, a spine's `moves` gap, and at a gap with spots every choice but
/// its confirmation, among them.
pub(super) fn checked_resolutions(gaps: &[Gap], resolutions: &Map<String, Value>) -> Result<BTreeMap<usize, Placement>, Refusal> {
    let malformed = || Refusal::malformed("resolutions");
    let mut chosen = BTreeMap::new();
    for (gap, choice) in resolutions {
        let id: u32 = gap.parse().map_err(|_| malformed())?;
        let ix = gaps.iter().position(|g| g.id.0 == id).ok_or_else(malformed)?;
        let gap = &gaps[ix];
        if gap.resolved_by == Some(ResolvedBy::Rule) || (gap.kind == GapKind::Moves && gap.spots.is_empty()) {
            return Err(malformed());
        }
        let sides: Vec<u8> = gap.runs.iter().map(|(s, _)| s.0).collect();
        let side_of = |v: &Value| v.as_u64().and_then(|n| u8::try_from(n).ok()).filter(|n| sides.contains(n)).map(SideIx);
        let anchor_of = |v: &Value, anchor: &Option<Address>| v.as_str().and_then(bounded_address).filter(|a| anchor.as_ref() == Some(a)).map(|_| ());
        let placed = match choice {
            Value::String(s) if s == "keep_both" => None,
            Value::String(s) if s == "omit" => Some(Placement::Omitted),
            Value::Object(o) if o.len() == 1 => {
                if let Some(order) = o.get("order") {
                    let order: Vec<SideIx> = order.as_array().ok_or_else(malformed)?.iter().map(side_of).collect::<Option<_>>().ok_or_else(malformed)?;
                    if order.is_empty() || order.iter().enumerate().any(|(k, s)| order[..k].contains(s)) {
                        return Err(malformed());
                    }
                    Some(Placement::Order(order))
                } else if let Some(side) = o.get("keep_only") {
                    Some(Placement::Order(vec![side_of(side).ok_or_else(malformed)?]))
                } else if let Some(after) = o.get("after") {
                    anchor_of(after, &gap.after).ok_or_else(malformed)?;
                    Some(Placement::After)
                } else if let Some(before) = o.get("before") {
                    anchor_of(before, &gap.before).ok_or_else(malformed)?;
                    Some(Placement::Before)
                } else {
                    return Err(malformed());
                }
            }
            _ => return Err(malformed()),
        };
        if !gap.spots.is_empty() && placed.as_ref() != Some(&gap.placed) {
            return Err(malformed());
        }
        if chosen.insert(ix, placed.unwrap_or_else(|| kept(gap))).is_some() {
            return Err(malformed());
        }
    }
    Ok(chosen)
}

/// Returns the placement `keep_both` confirms at `gap`: its placement as
/// composed, spelled as the merge record re-states it (`Record::options`).
///
/// A gap of one side placed by an anchor is that side's order, the same
/// words at the same place, which the record re-states as itself wherever
/// the gap lies — at an end of M, over an empty spine — where an anchor's
/// placement is re-stated by the anchor that stands, or not at all; a gap
/// that holds no runs, a collision no side filled, places nothing,
/// `omitted`. Every other gap keeps the placement it was composed with.
fn kept(gap: &Gap) -> Placement {
    let (Placement::After | Placement::Before) = gap.placed else { return gap.placed.clone() };
    let mut sides: Vec<SideIx> = Vec::new();
    for (side, _) in &gap.runs {
        if !sides.contains(side) {
            sides.push(*side);
        }
    }
    match sides.len() {
        0 => Placement::Omitted,
        1 => Placement::Order(sides),
        _ => gap.placed.clone(),
    }
}

/// Settles each gap `chosen` names at the placement it asks (the module
/// doc) — the merger's resolutions, or the choices the draft's words hold
/// (`settle_by_edit`) — in the record as the merger's who acts through
/// `surface`: `person` at the editor, `agent` with no person present.
fn settle_resolutions(merged: &mut lib::Merged, chosen: &BTreeMap<usize, Placement>, surface: Surface) {
    for (ix, placed) in chosen {
        for gaps in [&mut merged.record.gaps, &mut merged.composed.gaps] {
            if let Some(g) = gaps.get_mut(*ix) {
                g.placed = placed.clone();
                g.settled = true;
                g.resolved_by = Some(surface.settler());
            }
        }
    }
}

/// Returns whether `image` holds `placed` at `gap` (the module doc,
/// **`merge.land`**): the words a landing's shot publishes, or the draft as
/// it stands, read for a choice the merger names or an edit made.
///
/// `m` is the merged list of the composition `gap` is one of. A gap with no
/// spots is read off the image alone (`runs_hold`). At a `moves` gap with
/// spots (CM-I33) the order of one holder holds where every run of that
/// holder's stands, in that holder's order, and the words lie within its
/// spot (`spot_holds`) — or, where `placed` is the gap's own placement,
/// within the spot `m` lays them at (`MergedList::spot`), which a holder's
/// own spot misses where the other side's move parts its anchors and the
/// composition lays the words after the left one (R4 i) — and an omission
/// never, the library leaving the words where a holder placed them.
pub(super) fn draft_holds(gap: &Gap, placed: &Placement, image: &[SelectionRun], m: &MergedList) -> bool {
    if gap.spots.is_empty() {
        return runs_hold(gap, placed, image);
    }
    let Placement::Order(sides) = placed else { return false };
    let [side] = sides.as_slice() else { return false };
    let Some(spot) = gap.spots.iter().find(|s| s.side == *side) else { return false };
    let (mut words, mut prev): (Option<(u64, u64)>, Option<u64>) = (None, None);
    for (_, run) in gap.runs.iter().filter(|(s, _)| s == side) {
        let Some((first, last)) = held_ordinals(image, run) else { return false };
        // The holder's runs come in its own order (`Gap::runs`).
        if prev.is_some_and(|p| p >= first) {
            return false;
        }
        prev = Some(first);
        words = Some(words.map_or((first, last), |(lo, hi)| (lo.min(first), hi.max(last))));
    }
    let laid = if placed == &gap.placed { m.spot(gap) } else { None };
    words.is_some_and(|words| spot_holds(image, spot, words) || laid.is_some_and(|laid| spot_holds(image, &laid, words)))
}

/// Returns whether `image` holds `placed` at `gap`, a gap with no spots.
///
/// It is `draft_holds`' reading off the runs alone. A run stands where the
/// image holds any of its words, an edit inside them included, and is gone
/// where it holds none; standing runs are ordered by their first ordinals
/// (`first_ordinal`). The library lays a word two sides
/// placed alike once, where the first side laid takes it, and lists it under
/// each side that keeps it (`Gap::runs`): so each listed side's runs are read
/// less the words a side listed before it lays (`Run::without`). An order of
/// sides holds where every such run of a listed side stands, their first
/// ordinals rising side by side in the listed order, each side's runs in the
/// gap's order, and every run of a side left out is gone, save the words a
/// listed side lays; an omission where every run of the gap is gone; a
/// placement `after` or `before` the gap's own anchor, which lays the runs
/// as the landing did, where every run stands, in the gap's order. At a
/// spine's `moves` gap nothing holds: its runs are only the base material
/// each side moved, and no reading of them off the draft tells one side's
/// order of the spine from another's.
fn runs_hold(gap: &Gap, placed: &Placement, image: &[SelectionRun]) -> bool {
    if gap.kind == GapKind::Moves {
        return false;
    }
    let gone = |run: &Run| first_ordinal(image, run).is_none();
    // The runs taken in turn, each standing, their first ordinals rising.
    let rising = |runs: Vec<&Run>| -> bool {
        let firsts: Option<Vec<u64>> = runs.into_iter().map(|run| first_ordinal(image, run)).collect();
        firsts.is_some_and(|firsts| firsts.windows(2).all(|w| w[0] < w[1]))
    };
    match placed {
        Placement::Omitted => gap.runs.iter().all(|(_, run)| gone(run)),
        Placement::After | Placement::Before => rising(gap.runs.iter().map(|(_, run)| run).collect()),
        Placement::Order(sides) => {
            // Each listed side's runs less the words a side before it lays:
            // the library lays a word once (`Run::without`).
            let (mut laid, mut listed): (Vec<&Run>, Vec<Run>) = (Vec::new(), Vec::new());
            for s in sides {
                let own: Vec<&Run> = gap.runs.iter().filter(|(side, _)| side == s).map(|(_, run)| run).collect();
                listed.extend(own.iter().flat_map(|run| run.without(laid.iter().copied())));
                laid.extend(own);
            }
            let mut left_out = gap.runs.iter().filter(|(side, _)| !sides.contains(side)).flat_map(|(_, run)| run.without(laid.iter().copied()));
            rising(listed.iter().collect()) && left_out.all(|run| gone(&run))
        }
    }
}

/// Returns the first ordinal at which `image` holds any of `run`'s words,
/// `None` where it holds none (`held_ordinals`).
///
/// It is the one reading of a run, a choice's at the landing and an edit's
/// at the re-open and the landing alike (`draft_holds`, `edit_choice`): the
/// run stands where this is some, an edit inside its words included, and
/// the standing runs are ordered by it.
fn first_ordinal(image: &[SelectionRun], run: &Run) -> Option<u64> {
    held_ordinals(image, run).map(|(first, _)| first)
}

/// Returns the lowest and the highest ordinal at which `image` holds any
/// position of `run`, `None` where it holds none of them.
///
/// The image's runs are laid from ordinal 1 in their order, so the first
/// of the image's runs holding any of them gives the lowest, and the last
/// the highest.
fn held_ordinals(image: &[SelectionRun], run: &Run) -> Option<(u64, u64)> {
    let mut at = 1u64;
    let mut held: Option<(u64, u64)> = None;
    for r in image {
        if r.origin == run.origin {
            let (lo, hi) = (r.i_start.max(run.i_start), r.reach().min(run.reach()));
            if lo < hi {
                let (first, last) = (at.saturating_add(lo - r.i_start), at.saturating_add(hi - 1 - r.i_start));
                held = Some(held.map_or((first, last), |(lowest, _)| (lowest, last)));
            }
        }
        at = at.saturating_add(r.width);
    }
    held
}

/// Returns the ordinal at which `image` first holds the content position
/// of `origin` at the ordinal `i`, `None` where it holds it nowhere.
///
/// The image's runs are laid from ordinal 1 in their order.
fn ordinal_in(image: &[SelectionRun], origin: &Address, i: u64) -> Option<u64> {
    let mut at = 1u64;
    for r in image {
        if r.origin == *origin && i >= r.i_start && i < r.reach() {
            return Some(at + (i - r.i_start));
        }
        at = at.saturating_add(r.width);
    }
    None
}

/// Returns the ordinal at which `image` holds the position `anchor` names.
///
/// `None` where it holds it nowhere, or `anchor` names no content position.
fn anchored(image: &[SelectionRun], anchor: &Address) -> Option<u64> {
    let doc = skep_address::document_of(anchor)?;
    let field = anchor.element_field()?;
    if field.len() != 2 || field[0] != skep_address::content_subspace() {
        return None;
    }
    ordinal_in(image, &doc, u64::try_from(&field[1]).ok()?)
}

/// Returns whether `spot` holds the words `image` lays from ordinal `first`
/// to `last` (CM-I33): after its `after` anchor and before its `before`.
///
/// Each anchor is read where the image holds the content position it
/// names (`anchored`); one the image no longer holds bounds nothing, as an
/// end of the document does. It is the one reading of a spot — a holder's
/// own, or the one the composition lays its words at (`MergedList::spot`)
/// — for the words' holder (`moved_to`) and a holder's placement
/// (`draft_holds`) alike.
fn spot_holds(image: &[SelectionRun], spot: &lib::Spot, (first, last): (u64, u64)) -> bool {
    let at = |anchor: &Address| anchored(image, anchor);
    spot.after.as_ref().and_then(at).is_none_or(|p| p < first) && spot.before.as_ref().and_then(at).is_none_or(|p| p > last)
}

/// The merged list M as a composition lays it.
///
/// It is held in the publication family's spelling, and a `moves` gap with
/// spots' placement is read against it beside the draft (CM-I33). A
/// holder's spot is read off its own sequence, so where the other side
/// moved a position out from between the spot's anchors the spine parts
/// them, and the composition lays the holder's words after the left anchor
/// (R4 i) — outside its own spot, and possibly inside another holder's.
/// The draft holding the words where M lays them holds the composition's
/// placement, whichever spot it reads as (`MergedList::spot`).
pub(super) struct MergedList(Vec<SelectionRun>);

impl MergedList {
    /// Returns the merged list a composition's `runs` lay.
    pub(super) fn of(runs: &[lib::PlacedRun]) -> MergedList {
        MergedList(runs.iter().map(|p| SelectionRun::new(p.run.origin.clone(), p.run.i_start, p.run.width)).collect())
    }

    /// Returns the spot M lays the words of `gap`'s placed holder at.
    ///
    /// It is the anchors M holds nearest before the words and nearest after
    /// them, of every `after` and `before` the gap's spots name, as a `Spot`
    /// of that holder (CM-I33). The spots' anchors are the base positions
    /// every holder keeps, so it is read as a holder's own spot is
    /// (`spot_holds`): where M holds no named anchor on one side of the
    /// words, that side is open, as an end of the document is. `None` at a
    /// gap with no spots, at one placed by no one holder, and where M holds
    /// none of that holder's words.
    fn spot(&self, gap: &Gap) -> Option<lib::Spot> {
        if gap.spots.is_empty() {
            return None;
        }
        let Placement::Order(placed) = &gap.placed else { return None };
        let [holder] = placed.as_slice() else { return None };
        let mut words: Option<(u64, u64)> = None;
        for (_, run) in gap.runs.iter().filter(|(side, _)| side == holder) {
            let (first, last) = held_ordinals(&self.0, run)?;
            words = Some(words.map_or((first, last), |(lo, hi)| (lo.min(first), hi.max(last))));
        }
        let (first, last) = words?;
        let mut after: Option<(u64, &Address)> = None;
        let mut before: Option<(u64, &Address)> = None;
        for anchor in gap.spots.iter().flat_map(|s| s.after.iter().chain(&s.before)) {
            let Some(at) = anchored(&self.0, anchor) else { continue };
            if at < first && after.is_none_or(|(nearest, _)| at > nearest) {
                after = Some((at, anchor));
            }
            if at > last && before.is_none_or(|(nearest, _)| at < nearest) {
                before = Some((at, anchor));
            }
        }
        Some(lib::Spot { side: *holder, after: after.map(|(_, a)| a.clone()), before: before.map(|(_, a)| a.clone()) })
    }
}

/// Returns the words of `draft`'s image that `selection` holds, in the
/// draft's order: each of its runs cut to the positions some run of the
/// selection holds by identity (the module doc, **`merge.land`**).
///
/// It is what a shot of `selection` publishes from the draft, its runs
/// placed where the draft arranges them and laid in the draft's order,
/// whatever order the selection names them in
/// (`skep_client::publication::place_selection`).
pub(super) fn selected_image(draft: &[SelectionRun], selection: &[SelectionRun]) -> Vec<SelectionRun> {
    let mut out = Vec::new();
    for r in draft {
        let mut held: Vec<(u64, u64)> = selection.iter().filter(|s| s.origin == r.origin).map(|s| (r.i_start.max(s.i_start), r.reach().min(s.reach()))).filter(|(lo, hi)| lo < hi).collect();
        held.sort_unstable();
        let mut cut: Vec<(u64, u64)> = Vec::new();
        for (lo, hi) in held {
            match cut.last_mut() {
                Some(last) if last.1 >= lo => last.1 = last.1.max(hi),
                _ => cut.push((lo, hi)),
            }
        }
        out.extend(cut.into_iter().map(|(lo, hi)| SelectionRun::new(r.origin.clone(), lo, hi - lo)));
    }
    out
}

/// Returns the holder's placement the draft's image now holds at each
/// unsettled `moves` gap with spots among `gaps`, where it is another
/// side's than the default's (`moved_to`), as the resolution of the merger
/// `by` names (CM-I33; the module doc, THE RE-OPEN).
///
/// `m` is the merged list of the composition `gaps` are.
pub(super) fn holders_moved(gaps: &[Gap], image: &[SelectionRun], m: &MergedList, by: &ResolvedBy) -> Vec<lib::Resolution> {
    gaps.iter()
        .filter(|g| !g.settled)
        .filter_map(|gap| moved_to(gap, image, m).map(|side| lib::Resolution { gap: gap.id, choice: lib::Choice::Order(vec![side]), by: by.clone() }))
        .collect()
}

/// Returns the other holder at whose spot a `moves` gap with spots' words
/// stand in `image` (CM-I33), `None` where they stand at the default's, at
/// no holder's or at more than one other's, and at every other gap.
///
/// The gap's words are one identity whoever holds them, so they are found
/// by the default holder's runs, and they stand at a holder's spot where
/// they lie whole after its `after` anchor and before its `before` in the
/// image (`spot_holds`); words not whole there, gone or cut, stand at no
/// spot. A spot is read by the anchors the draft still holds: one it no
/// longer holds bounds nothing, as an end of the document does. The words
/// stand at the default where the default holder's own spot holds them, or
/// the spot `m`, the composition's merged list, lays them at
/// (`MergedList::spot`): a default its spot's anchors parted in the spine
/// is laid after the left one (R4 i), which another holder's spot can
/// hold. The words are a holder's placement only where its spot is the one
/// other holder's that holds them and the default's does not: a deleted
/// neighbour leaves the default's spot open, and the words stand at the
/// default.
fn moved_to(gap: &Gap, image: &[SelectionRun], m: &MergedList) -> Option<SideIx> {
    if gap.spots.is_empty() {
        return None;
    }
    let Placement::Order(placed) = &gap.placed else { return None };
    let [default] = placed.as_slice() else { return None };
    let mut words: Option<(u64, u64)> = None;
    for (_, run) in gap.runs.iter().filter(|(side, _)| side == default) {
        let first = ordinal_in(image, &run.origin, run.i_start)?;
        let last = ordinal_in(image, &run.origin, run.reach().saturating_sub(1))?;
        words = Some(words.map_or((first, last), |(lo, hi)| (lo.min(first), hi.max(last))));
    }
    let words = words?;
    let holds = |spot: &lib::Spot| spot_holds(image, spot, words);
    if gap.spots.iter().any(|s| s.side == *default && holds(s)) || m.spot(gap).is_some_and(|laid| holds(&laid)) {
        return None;
    }
    match gap.spots.iter().filter(|s| s.side != *default && holds(s)).map(|s| s.side).collect::<Vec<SideIx>>().as_slice() {
        [side] => Some(*side),
        _ => None,
    }
}

/// Returns the first `moves` gap with spots among `gaps` whose words the
/// whole draft's image holds elsewhere than the composition placed them, a
/// gap no choice in `chosen` names (the module doc, **`merge.land`**).
///
/// `m` is the merged list of the composition `gaps` are. The words are read
/// over the whole draft as THE RE-OPEN reads them: at an unsettled gap they
/// stand elsewhere where they lie at one other holder's spot alone and
/// neither at the default's spot nor where `m` lays them (`moved_to`), and
/// at a gap the merger settled where the holder's placement it took no
/// longer holds them (`draft_holds`). Only a composition places the words
/// at another holder's spot, so a landing over either would record a
/// placement the draft no longer holds, and composing again reads the gap
/// as the draft holds it. A gap a choice names is read by that choice
/// (`draft_holds`); words gone, or at no holder's spot, leave an unsettled
/// gap at its default.
pub(super) fn spots_edited(gaps: &[Gap], chosen: &BTreeMap<usize, Placement>, whole: &[SelectionRun], m: &MergedList) -> Option<GapId> {
    gaps.iter()
        .enumerate()
        .filter(|(ix, g)| !g.spots.is_empty() && !chosen.contains_key(ix))
        .find(|(_, g)| if g.settled { g.resolved_by != Some(ResolvedBy::Rule) && !draft_holds(g, &g.placed, whole, m) } else { moved_to(g, whole, m).is_some() })
        .map(|(_, g)| g.id)
}

/// Returns the choice `image` holds at `gap` in place of its default,
/// `None` where the default still holds or the image holds none of the
/// gap's choices (the module doc, THE RE-OPEN).
///
/// The candidates are read off the runs as a landing's choice is
/// (`first_ordinal`): the omission where every run of the gap is gone, else
/// the order of the sides with a run standing, each side placed by the
/// lowest first ordinal among the words it alone lists — a word two sides
/// placed alike is listed under each that keeps it (`Gap::runs`) — or among
/// its runs where it lists none alone; then each side alone, which is the
/// reading where the sides list the same words in two orders. The first
/// candidate the image holds is the gap's choice (`runs_hold`) — every run
/// of a listed side standing, the listed sides' runs rising side after side,
/// and every run of a side left out gone, save the words a listed side lays —
/// so an edit that interleaves two sides' runs, reorders one side's own, or
/// leaves some of a side's runs and not others holds none. At a gap of one
/// side placed `after` or `before`, its runs standing in order hold the
/// default, so the one choice read there is the omission. A `moves` gap is
/// read by none: one with spots by where its words stand (`moved_to`),
/// which the re-open composes again, and a spine's by nothing the draft
/// holds (`runs_hold`). The shell composes the head and one side, so a gap
/// holds two sides at most and at most three candidates are read.
pub(super) fn edit_choice(gap: &Gap, image: &[SelectionRun]) -> Option<Placement> {
    if gap.kind == GapKind::Moves || runs_hold(gap, &gap.placed, image) {
        return None;
    }
    let mut sides: Vec<SideIx> = Vec::new();
    for (side, _) in &gap.runs {
        if !sides.contains(side) {
            sides.push(*side);
        }
    }
    // A side's lowest first ordinal, among the words it alone lists where it
    // lists any.
    let lowest = |s: SideIx| -> Option<u64> {
        let others: Vec<&Run> = gap.runs.iter().filter(|(side, _)| *side != s).map(|(_, run)| run).collect();
        let own: Vec<&Run> = gap.runs.iter().filter(|(side, _)| *side == s).map(|(_, run)| run).collect();
        let alone: Vec<Run> = own.iter().flat_map(|run| run.without(others.iter().copied())).collect();
        let read: Vec<&Run> = if alone.is_empty() { own } else { alone.iter().collect() };
        read.into_iter().filter_map(|run| first_ordinal(image, run)).min()
    };
    let mut standing: Vec<(SideIx, u64)> = sides.iter().filter_map(|&s| Some((s, lowest(s)?))).collect();
    standing.sort_by_key(|&(_, first)| first);
    let read = if standing.is_empty() { Placement::Omitted } else { Placement::Order(standing.into_iter().map(|(side, _)| side).collect()) };
    std::iter::once(read).chain(sides.into_iter().map(|s| Placement::Order(vec![s]))).find(|candidate| runs_hold(gap, candidate, image))
}

/// Settles each gap the rules left unsettled where `image` holds another
/// of its choices than its default (`edit_choice`), `placed` that choice
/// (the module doc, THE RE-OPEN and **`merge.land`**).
///
/// The reading is of the words, not of the hand that edited them, so the
/// merger reading them — composing at the re-open, publishing at the
/// landing — is the one recorded, who acts through `surface`: `person` or
/// `agent` (`settle_resolutions`). A gap whose default still holds, one the
/// image holds none of the choices of, and a `moves` gap stand as
/// composed, unsettled at the default.
fn settle_by_edit(merged: &mut lib::Merged, image: &[SelectionRun], surface: Surface) {
    let read: BTreeMap<usize, Placement> = merged.record.gaps.iter().enumerate().filter(|(_, g)| !g.settled).filter_map(|(ix, g)| Some((ix, edit_choice(g, image)?))).collect();
    settle_resolutions(merged, &read, surface);
}

// ── The shapes, as the page reads them ───────────────────────────────────

/// Returns one window part as `window_parts_owed` and `merge.land`'s
/// acknowledgment answer it (`shapes`' `WindowPart`), its words rendered
/// inert as a label is.
fn window_part_json(p: &WindowPart) -> Value {
    json!({
        "run": p.key.run,
        "part": p.key.part,
        "words": p.words.as_deref().map(render_inert),
        "after": p.after.as_deref().map(render_inert),
        "ordinal": p.ordinal,
        "origin": p.origin.to_string(),
        "owner": p.owner,
        "span": ispan_json(&p.span),
        "record": p.record.as_ref().map(ToString::to_string),
        "counterpart": p.counterpart.as_ref().map(ispan_json),
        "version": p.version.as_ref().map(ToString::to_string),
        "sides": p.sides.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "admits": p.admits.iter().copied().map(answer_json).collect::<Vec<_>>(),
        "answer": p.answer.map(answer_json),
        "named_since": p.named_since,
    })
}

/// Returns one answer the shot's window step could not place as
/// `window_parts_owed` names it (`shapes`' `WindowMisfit`).
fn misfit_json(m: &Misfit) -> Value {
    let flag = |f: &lib::Flag| match f {
        lib::Flag::Window => "window",
        lib::Flag::LeaveOut => "leave_out",
        lib::Flag::KeepPrivate => "keep_private",
    };
    match m {
        Misfit::FitsNothing { flag: f, key, published_in } => json!({"flag": flag(f), "key": key.to_string(), "published_in": published_in.iter().map(ToString::to_string).collect::<Vec<_>>()}),
        Misfit::TwoAnswers { first, second, key } => json!({"flag": flag(first), "second": flag(second), "key": key.to_string(), "published_in": Vec::<String>::new()}),
    }
}

/// Returns the `window_parts_owed` detail: the parts that need an answer,
/// the answers that stand beside them, what fits nothing, and each default
/// the landing takes (`shapes`' `WindowPartsOwedRefusal`).
fn owed_detail(parts: &[WindowPart], given: &[WindowPart], misfits: &[Misfit], left_private: Value, defaults: Value) -> Value {
    json!({
        "parts": parts.iter().map(window_part_json).collect::<Vec<_>>(),
        "answers": given.iter().map(window_part_json).collect::<Vec<_>>(),
        "misfits": misfits.iter().map(misfit_json).collect::<Vec<_>>(),
        "left_private": left_private,
        "defaults": defaults,
    })
}

/// Returns one gap left at its default (`shapes`' `MergeDefault`).
///
/// A gap with spots names them, and a `line` gap a removal meets names
/// that removal, as the report's gap does.
pub(super) fn default_json(g: &Gap) -> Value {
    let v = gap_json(g);
    let mut default = json!({"id": v["id"], "kind": v["kind"], "after": v["after"], "before": v["before"], "placed": v["placed"]});
    for member in ["spots", "removed"] {
        if let Some(named) = v.get(member) {
            default[member] = named.clone();
        }
    }
    default
}

/// Returns the report as `merge.compose` answers it (`shapes`' `MergeReport`).
///
/// Its `gaps` and `deduped` are `merged`'s, so at the merged arm, whose
/// `extra` carries the standing record's body as `record`, they name the
/// composition made now.
fn report_json(merged: &lib::Merged, form: &Form, outcome: &str, extra: Value) -> Value {
    let mut v = json!({
        "outcome": outcome,
        "doc": merged.inputs.doc.to_string(),
        "head": merged.inputs.head.to_string(),
        "base": merged.record.base.to_string(),
        "side": form.side().to_string(),
        "form": form.name(),
        "sides": merged.record.sides.iter().map(side_json).collect::<Vec<_>>(),
        "runs": merged.composed.runs.iter().zip(&merged.families).map(|(p, f)| run_json(&p.run, p.side, *f)).collect::<Vec<_>>(),
        "gaps": merged.record.gaps.iter().map(gap_json).collect::<Vec<_>>(),
        "counts": {"a": merged.composed.counts.a, "b": merged.composed.counts.b, "m": merged.composed.counts.m},
        "cap": merged.cap,
        "over_cap": merged.composed.counts.m > merged.cap,
        "record": merged.record.to_value(),
        "as_of": merged.as_of,
        "deduped": deduped_json(&merged.record),
    });
    if let Value::Object(members) = extra {
        for (k, value) in members {
            v[k] = value;
        }
    }
    v
}

/// Returns one side of the record as the report carries it.
///
/// It is `shapes`' `MergeSide`: a fork and a draft with `arranged`, their
/// state, `null` where the board kept none or the record keeps none.
fn side_json(side: &SideAt) -> Value {
    let arranged = |state: &SideState| match state {
        SideState::At(q) => json!(q),
        SideState::Unarranged | SideState::Unrecorded => Value::Null,
    };
    match side {
        SideAt::Member { at, role } => json!({"at": at.to_string(), "role": role.as_str(), "position": Value::Null}),
        SideAt::Fork { at, arranged: state } => json!({"at": at.to_string(), "role": Role::Fork.as_str(), "position": Value::Null, "arranged": arranged(state)}),
        SideAt::Draft { at, position, arranged: state } => json!({"at": at.to_string(), "role": Role::Draft.as_str(), "position": position, "arranged": arranged(state)}),
    }
}

/// Returns one stretch a landing replaced (`shapes`' `ReplacedStretch`).
fn replaced_json(r: &lib::Replaced) -> Value {
    json!({"ordinal": r.ordinal, "width": r.width, "origin": r.origin.to_string(), "i_start": r.i_start})
}

fn run_json(run: &Run, side: Option<SideIx>, family: Family) -> Value {
    let family = match family {
        Family::Own => "own",
        Family::Window => "window",
        Family::DraftNative => "draft_native",
    };
    json!({"origin": run.origin.to_string(), "i_start": run.i_start, "width": run.width, "side": side.map(|s| s.0), "family": family})
}

/// Returns one gap of the report (`shapes`' `MergeGap`).
///
/// A `moves` gap with spots carries `spots`, each holder's `GapSpot`
/// (CM-I33), and a `line` gap another side's removal meets carries
/// `removed`, each removal's `GapRemoved` (skep #1176); every other gap
/// carries neither.
pub(super) fn gap_json(g: &Gap) -> Value {
    let kind = match g.kind {
        GapKind::Order => "order",
        GapKind::Anchor => "anchor",
        GapKind::Corner => "corner",
        GapKind::Cut => "cut",
        GapKind::Collision => "collision",
        GapKind::Moves => "moves",
        GapKind::Line => "line",
    };
    let placed = match &g.placed {
        Placement::Order(sides) => Value::from(sides.iter().map(|s| s.0).collect::<Vec<u8>>()),
        Placement::After => Value::from("after"),
        Placement::Before => Value::from("before"),
        Placement::Omitted => Value::from("omitted"),
    };
    let resolved_by = match &g.resolved_by {
        None => Value::Null,
        Some(ResolvedBy::Rule) => Value::from("rule"),
        Some(ResolvedBy::Person) => Value::from("person"),
        Some(ResolvedBy::Agent) => Value::from("agent"),
        Some(ResolvedBy::Answer(a)) => Value::from(format!("answer:{a}")),
    };
    let mut gap = json!({
        "id": g.id.0,
        "kind": kind,
        "after": g.after.as_ref().map(ToString::to_string),
        "before": g.before.as_ref().map(ToString::to_string),
        "runs": g.runs.iter().map(gap_run_json).collect::<Vec<_>>(),
        "placed": placed,
        "settled": g.settled,
        "resolved_by": resolved_by,
    });
    if !g.spots.is_empty() {
        gap["spots"] = g.spots.iter().map(|s| json!({"side": s.side.0, "after": s.after.as_ref().map(ToString::to_string), "before": s.before.as_ref().map(ToString::to_string)})).collect();
    }
    if !g.removed.is_empty() {
        gap["removed"] = g.removed.iter().map(|s| json!({"side": s.side.0, "after": s.after.as_ref().map(ToString::to_string), "before": s.before.as_ref().map(ToString::to_string)})).collect();
    }
    gap
}

/// Returns one run at a gap with its side (`shapes`' `GapRun`).
fn gap_run_json((side, run): &(SideIx, Run)) -> Value {
    json!({"side": side.0, "i_start": run.address_at(0).map(|a| a.to_string()), "width": run.width})
}

/// Returns each place the merge kept once, as both answers carry it
/// (`shapes`' `MergeDedup`; the module doc, **Kept once**).
///
/// It is the record's `Record::deduped`, each place's dropped runs spelled
/// as a gap's.
fn deduped_json(record: &lib::Record) -> Value {
    let kept = |d: &lib::Deduped| d.kept.iter().map(|s| s.0).collect::<Vec<u8>>();
    record.deduped().iter().map(|d| json!({"gap": d.gap.0, "kept": kept(d), "dropped": d.dropped.iter().map(gap_run_json).collect::<Vec<_>>()})).collect()
}
