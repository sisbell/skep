# Adjudication decisions — append-only ledger

Rulings and investigation findings from conformance adjudication. Settled
questions are settled: a future worksheet cites this ledger instead of
re-litigating. Allowlist entries in ../allowlist.toml carry the same
rulings in machine form.

## 2026-08-15 — run-2 docket (81 divergences, worksheet of this date)

**Rulings (operator):**

1. **udanax-malformed-vspanset** (ALLOWLIST, 20 scenarios) — udanax's
   two-subspace RETRIEVEDOCVSPANSET reply is malformed; widths track
   nothing. Skep well-formed per M5/M6.
2. **udanax-no-subspace-confinement** (ALLOWLIST, 1) — skep enforces the
   content/link subspace boundary (ASN-0047/0116, S3★ routing); udanax
   does not.
3. **dense-v-space** (ALLOWLIST, 3) — AFFIRMED with reason: monotonicity/
   contiguity is load-bearing. Skep's V-space is dense (ordinal ∈ [1,n+1]);
   udanax's sparse insert-past-extent is not supported; authors insert in
   final order.
4. **udanax-lenient-rearrange** (ALLOWLIST, 4) — strictly-ascending cuts
   per ASN-0084/0119.
5. **asn-0131-whole-endsets-no-clipping** (ALLOWLIST, 4) — the spec
   litigated and rejected udanax's clip-to-region endset reporting before
   the code existed.
6. **udanax-degenerate-type-filter + i-coverage-permanence** (ALLOWLIST, 2).
7. **udanax-degenerate-homedoc-filter** (ALLOWLIST, no_match + _multiple's
   filtered ops) — udanax's own goldens' notes say "expected: 0".
8. **allocation-layout-fragmentation** (ALLOWLIST, 1) — udanax interleaves
   link allocation into content I-space; skep's separated gap-free
   frontiers merge the run. Both truthful per ASN-0122.
9. **golden-recording-defect** (EXCLUDE-as-allowlist, 1 + the bert
   OPERATION_FAILED inexpressibles) — recording client crashes captured in
   the goldens.
10. **Post-delete search findability** — RULED: deleted content must remain
    findable (it persists as the document's history). Mechanism: I-coverage
    reach (R / spanfilade / FindLinksFtt), NOT loosening current-V queries.
    skep already satisfies this for FINDDOCSCONTAINING (R is append-only);
    the harness must translate udanax-style document searches to I-coverage
    queries (round 3). Design note: skep's findability-history is provenance
    R, implicit — no explicit VERSION fork required. A convenience
    search-history op for M10 is optional future work (recorded in
    drift-reconciliation).

**Pre-registered class:** `udanax-compare-fanout-underreport` — ASN-0122
verifies the reference COMPARE is a width-budgeted merge, not a join
("self-comparison reports only the diagonal"); fan-out divergences where
skep reports MORE pairs take this class.

**Investigation findings (evidence in worksheet-2026-08-15, git history):**

- **Zero skep bugs found** across five investigations covering all 81
  divergences.
- Transclusion coverage (E3/K): NO skep bug — positive evidence
  (pre-delete find_documents through shared content AGREED). Apparent
  misses were harness world-construction gaps + udanax's filter defect.
- Version isolation (I-exception): NO skep bug — harness register mis-aim;
  the correctly-aimed probes are positive isolation evidence (source
  unchanged after version edits; v2 exact).
- retrieve_endsets (E1), COMPARE fragmentation (G), dense V-space (C):
  designed divergences, spec citations above.
- Harness defect classes identified for round 3: symbolic doc-name
  registry; compare window grounding; delete-span boundary whitespace;
  greedy-cover trailing-space fencepost; `target:` field variant;
  post-delete I-coverage translation (ruling 10); world-construction
  expansions (create_multiple_targets transclusions, vcopy destinations);
  whole-doc endset defaults distorting follow_link extents.
- Golden defect classes: bert crash-banner recordings; duplicated
  find_links results; udanax filter fields ignored (type, homedocids);
  malformed two-subspace vspanset replies.

## 2026-08-15 — run-3 docket (37 divergences, worksheet run3)

**Rulings (operator): "go with our spec" — confirmed across the board.**

11. **asn-0114/0131-recorded-not-resolved** — FOLLOWLINK and RETRIEVEENDSETS
    report the RECORDED endset (content-space spans), never a resolution
    into any document's V-space. Udanax's bundled resolution (one link,
    many answers; orphans answering empty) is the defect ASN-0114 documents.
    Harness renders follow results by content identity (bytes once per
    recorded I-span) and compares endsets by coverage translation; residue
    takes this class. NO skep change.
12. **udanax-clamps-oversized-ops** (extends ruling 3's bounds family) —
    udanax clamps oversized delete/copy widths; skep rejects OutOfBounds
    per admission discipline.
13. Ruled-class extensions at new ops are mechanical: subspace-confinement
    DELETE, ruling-10 finds, empty-document acceptance, malformed-vspanset
    variant signature ("0","0.N").

**Verdict on the spec (operator, after runs 1–3):** where spec and udanax
collide, the spec is presumed correct — every adjudication to date upheld
it (udanax defects self-documented; substantive divergences pre-argued in
the ASNs). Standing exceptions: D1 (known spec contradiction, open) and
M9 (no external ground truth exists).

**Still open from run 3:** T4 investigation (find_documents partial after
delete — possible harness query construction or R/COPY gap); T2/T5–T8
harness round-4 items.

**T4 CLOSED (2026-08-15): designed divergence, no bug anywhere.**
14. **asn-0124-present-tense-containment** — FINDDOCSCONTAINING is
    present-tense by the ASN's central design fact ("not content-once-held");
    skep implements the spec's recommended monotone-R + present-tense-filter
    mechanism (M6 FD-SOUND). Udanax's never-pruned spanfilade returned the
    emptied document — contradicting its own scenario author's comment
    ("Should only find source, not empty target"), the third self-documented
    udanax defect. Coexists with ruling 10: content/link findability is
    identity-permanent; document containment is an arrangement fact.
**FINAL investigation tally, runs 1–3: every divergence class explained.
Confirmed skep bugs: ZERO.**

## 2026-08-15 — runs 4–6 closure and final ruling

**Run history:** run 4 (175/34/17/37): render-by-identity + endset coverage
translation mandated by ruling 11; op-index entry drift identified. Run 5
(184/45→48/8→4/27): signature-match allowlist key added (`expected_matches`,
survives op-index shifts); α-lift equality; wider grounding; the
pre-registered fan-out class ARRIVED (`internal_transclusion_identity` —
ASN-0122's predicted under-reporting observed in the wild) and its entry
applied. Run 6 (185/47/3/28): the harness caught and removed its own
fabrication (a padded ghost byte masking the carryover family) and
surfaced the final class rather than forcing agreement.

15. **version-link-carryover** (ALLOWLIST, 3 scenarios — the final ruling;
    divergent → 0). What udanax does: CREATENEWVERSION copies the source's
    TOTAL V-extent, giving the version an arrangement entry for the link's
    V-position — fork-time link membership. Green's own source labels the
    routine "a kluge not yet kluged" (ASN-0123 records it as Green
    deviation 2 with the instruction "don't ship the kluge"). What skep
    does: V2b content-only snapshot + CL-OWN (one arranger per link) +
    REFRACTION — "a link to one version is a link to all versions" by
    shared content addresses, computed at query time, total, bidirectional,
    and covering links created AFTER the fork (which udanax's fork-time
    copy misses). The only observable skep lacks: the link in the version's
    own link-subspace enumeration — membership vs reachability, same
    family as rulings 11/14. Ownership teeth: green has no link deletion,
    so dual arrangers never conflict there; skep has nullify/supersession,
    so singular arrangement is load-bearing. Link-subspace versioning
    remains open as ASN-0123 OQ3, a separate mechanism.

**FINAL: 263 scenarios — 188 pass equivalent (185 + the 3 now allowlisted),
47+3 allowlisted, 0 divergent, 28 inexpressible (annotated), 0 errors.
Fifteen rulings, zero skep bugs, three udanax defects self-documented in
its own goldens, four designed divergences pre-argued in the ASNs.**

**Corpus extension (same date):** 34 new goldens recorded from live
udanax-green (263→297; multisession 8, links_nary 5, links_crossdoc 3,
compare_fanout 4, provenance_ops 4, depth_scale 4, boundary 6; all
quadruple-verified deterministic; manifest + anomalies A1–A23 in
udanax-test-harness/golden/MANIFEST-NEW.md). Pre-registered classes for
the sweep, from the anomalies: green-no-snapshot-isolation (readers see
uncommitted writes; READ_ONLY writes acked and discarded — skep's M2
isolation will diverge by design); green-followlink-multispan-corruption
(reply corrupt for multi-span/multi-doc endsets — ASN-0114 vindicated
again); green-fanout-identical-rows (both-sided fan-out answers N
identical rows, no off-diagonal entries); green-nplaces-version-depth
(chains abort at level 8); no-origin-op (absence recorded).

## 2026-08-16 — run-7 docket: the 34-golden extension (all 21 adjudicated)

16. **descoped-bert-enforcement** (ALLOWLIST) — green's bert layer rejects
    opens (conflict/foreign/malformed) and silently discards READ_ONLY
    writes (acked-then-dropped, its own recorded defect); skep descoped
    per-handle access control by design (ownership/auth lives in M3 +
    session principals; open→noop adaptation). Scenarios probing bert
    enforcement diverge at the adaptation boundary, not the engine. The
    "guarded"/"uarded!" scare investigated: NO truncation — skep executed
    character-perfectly the two writes green discarded. Covers
    boundary_foreign_and_malformed_opens + the ms_* open-rejection ops.
17. **depth2-vspan-gate** (ALLOWLIST) — skep's V-positions are depth-2
    [subspace, ordinal]; nested/degenerate read spans green tolerates are
    rejected MalformedSpan. NOTE for future work: the depth-2 restriction
    was assessed cosmetic (D-SEQ) in the design phase — relaxation is
    possible if ever wanted; until then the gate is the spec.
    Covers boundary_deep_vaddress_reads, boundary_exact_extent_reads.
18. Pre-registered classes confirmed with data: **asn-0122-fanout-family**
    (growth_doubling, fanout pair, depth_edit_marathon — green answers N
    identical rows / arbitrary merge pairings; skep's join enumerates the
    relation) and **green-followlink-multispan-corruption** (nary_* and
    crossdoc_* — green duplicates last spans, drops second-doc spans,
    empties wrong docids exactly as MANIFEST-NEW recorded; skep honest;
    composite with whole-endsets and malformed-vspanset per scenario).
    prov_identity_after_delete = ruling 14 (present-tense). far_position =
    ruling 3 cascade.

**Run-7 final: 297 scenarios — 209 pass-equivalent, 71 allowlisted,
0 divergent, 29 inexpressible, 0 errors. Multisession result: 4 of 8
concurrency recordings PASS outright (interleaved inserts, committed
visibility mechanics); the rest diverge only at the bert adaptation
boundary. Skep bugs found: still ZERO.**

## 2026-09-05 — PUB round 1, delta 2: one publication definition

19. **D1 — one publication definition; the draft-homed credential cell reads
    AUTH-2.66's own order; no golden moves.** (Owner ruling D1, 2026-09-05;
    kickoff lane 2.2.) The daemon's two publication reads — the AUTH fold's
    `FoldCtx::is_published` (skepd's `WorldCtx`, until now the constant
    `true` of AUTH-2.117) and the RES-26 publish gate's read (until now
    `is_published_v1`, the doc-1 equality compare) — both answer
    `D ∉ exception_set` and nothing else: the engine's derived membership
    index over M3's per-document publication bit (PUB-7.5, PUB-7.7), seeded
    at load and folded on every document-minting record, with the gate
    projecting a version member to its document ahead of the read
    (PUB-2.15). THE CELL THAT FLIPS: a credential record deposited in a
    DRAFT-homed document answers `unpublished` (AUTH-2.66 item 3, ahead of
    the per-kind arm) where it answered `not_doc_one`; the unparseable-record
    variant in a draft home answers `unpublished` too (item 3 precedes the
    payload parse). The home pin's own cells — `not_doc_one`, and
    `malformed_payload` ahead of it (AUTH-2.127) — stand on a published
    non-doc-1 home, doc 1's version. The drift sweep's claim-2 patch (doc
    1's versions read unpublished under the equality compare, so bare
    sessions wrote into them) is discharged by the projection; no interim
    `prefix_contains` patch ships. Conformance goldens: none moves — no
    recorded scenario exercises a credential deposit or the publish gate.

## 2026-09-05 — PUB round 1, lane 3.1 close-out: private documents are versionless

20. **pub-2.9-private-versionless** (ALLOWLIST, 15 scenarios; owner ruling
    2026-09-05, lane 3.1 close-out.) Lane 3.1 — the three write-path
    refusals in the crates (`PublishedTarget` on the in-place arrangement
    edits, `PrivateVersionOfPublished` and `PrivateSourceVersionless` on
    `version`) — made PUB-2.9 real: a `version` on a PRIVATE source the
    caller OWNS is REFUSED at the write path. PRIVATE DOCUMENTS ARE
    VERSIONLESS; the version chain is publication's own instrument
    (PUB-2.9). PUB-2.19 states the same fact from the landing side: on a
    private source the caller owns there is no chain under the document to
    append to — private history is the pool. And PUB-2.10 is the guarantee
    the two refusals buy together: "every version address that exists
    names a PUBLISHED state, forever." The udanax corpus versions private
    documents freely — udanax has no publication state, so every document
    it versions is, in skep's terms, an owned private draft — and fifteen
    goldens now diverge at their `create_version` op (one at its
    `open_document` conflict-copy op) with `Rejected(PrivateSourceVersionless)`.
    RULED: these divergences are INTENDED — the spec forbids what udanax
    did — and the frozen set grows by EXACTLY these fifteen, class
    `pub-2.9-private-versionless`. No golden is regenerated. No scenario is
    re-keyed to a published source: a version of a published-born document
    would test a different program from the one the golden recorded, and
    the divergence is the finding. The fifteen, each with its
    first-disagreement op (0-based, from `target/conformance/summary.md`):
    - allocation_independence/version_insert_allocation_independence — op 3
      `version_1`
    - allocation_independence/version_link_allocation_independence — op 3
      `version_1`
    - compare_fanout/fanout_version_and_copy_routes — op 4 `create_version`
    - content/insert_vspace_mapping — op 4 `create_version`
    - depth_scale/depth_version_chain_4 — op 4 `create_version`
    - depth_scale/depth_version_chain_7 — op 4 `create_version`
    - documents/conflict_copy — op 3 `open_document` (the CONFLICT_COPY is
      a cross-owner-shaped version of the caller's OWN private draft; the
      PUB-2.9 refusal, not PUB-2.7's, is the one it meets)
    - edgecases/version_immediately — op 1 `create_version`
    - interactions/transitive_link_discovery — op 2 `create_version`
    - interactions/version_add_link_check_original — op 2 `create_version`
    - interactions/version_transcluded_linked_content — op 5 `create_version`
    - multisession/ms_version_race — op 7 `create_version`
    - versions/version_address_allocation — op 2 `create_version`
    - versions/version_preserves_transclusion — op 5 `create_version`
    - versions/version_with_links — op 5 `create_version`
    Count: fifteen scenarios, one WHOLE-SCENARIO entry each in
    ../allowlist.toml (no op index — the run-7 form) and fifteen names added
    under `[allowlisted]` in ../ratchet.toml. Whole-scenario because the
    runner needs every disagreed op covered, and every op after the refused
    `version` is that refusal's cascade: the version address never mints,
    so the ops that name it answer DocNotRegistered / SourceNotRegistered /
    HomeNotRegistered or reference a never-bound golden address, probes of
    it answer empty, and a second `version` of the same private source
    meets the same refusal (version_address_allocation's ops 3–5,
    ms_version_race's ops 8–9, the two allocation_independence
    `version_2`s). Skep bugs found: none — the refusal is the rule working.

**Recorded at close-out, NOT ruled (agent, 2026-09-05):** seventeen more
scenarios meet the same refusal at their `create_version` op and are
INEXPRESSIBLE from there rather than divergent — the version never mints,
so a later op naming it (`version`, `v1`, `v2`, `version2`, `parent`,
`version_before`, or a TO endset inside it) has nothing to ground on, and
the runner's verdict order puts inexpressible ahead of divergent. Sixteen
passed before lane 3.1; the seventeenth, createnewversion_text_vs_links,
was allowlisted (ruling 15) and keeps that line. They are parked under
`[pending]` in ../ratchet.toml — exempt from enforcement, reported on
every gate run — for the owner's disposition, ruling 20 naming exactly
fifteen: content/compare_multispan_specsets, content/vcopy_from_version,
discovery/find_documents_versions, identity/identity_through_rearrange_pivot,
identity/identity_through_rearrange_swap,
interactions/compare_versions_with_different_links,
provenance/createnewversion_text_vs_links, versions/both_versions_modified,
versions/compare_versions, versions/create_version,
versions/cross_version_vcopy, versions/delete_from_original_check_version,
versions/modify_original_after_version,
versions/multiple_versions_same_source,
versions/version_delete_preserves_original,
versions/version_insert_in_middle, versions/version_of_empty_document.

**Lane 3.1 tally: 297 scenarios — 0 divergent, 0 errors; 85 allowlisted
(run-7's 71, less createnewversion_text_vs_links now inexpressible, plus
the 15 ruled here); 46 inexpressible (the 29 frozen + the 17 pending); 166
pass. Twenty rulings.**

20a. **pub-2.9-private-versionless — addendum: the seventeen PENDING
    scenarios are INEXPRESSIBLE** (INEXPRESSIBLE, 17 scenarios; owner
    disposition 2026-09-05 of lane 3.1's `[pending]` block.) The close-out
    found seventeen scenarios beyond ruling 20's fifteen that the PUB-2.9
    refusal reaches: each `create_version`s an owned PRIVATE draft, the
    version never mints (`Rejected(PrivateSourceVersionless)` at that op),
    and a later op naming it — `version`, `v1`, `version2`,
    `version_before`, `doc2` (that golden's own name for its version), or
    a TO endset defaulted into it — has nothing to ground on:
    INEXPRESSIBLE, not divergent, under the harness's own classes (the
    runner's verdict order puts inexpressible ahead of divergent). The
    owner RULES: the seventeen are INEXPRESSIBLE for the same reason
    ruling 20 allowlists the fifteen (PUB-2.9; PUB-2.10; PUB-2.19) —
    udanax versions private documents, skep does not, and a scenario whose
    later ops depend on that version cannot be expressed against skep.
    Frozen as such: the seventeen names move from `[pending]` into
    `[inexpressible]` in ../ratchet.toml (29 → 46) and the `[pending]`
    block is dissolved; no golden regenerated, no re-key to a published
    source, no allowlist entry (an inexpressible verdict is not an allowed
    disagreement). The seventeen, each with the op the refusal meets and
    the first op the harness cannot ground (0-based, from
    `target/conformance/summary.md` and report.jsonl):
    - content/compare_multispan_specsets — refused op 2; op 3 `insert`
      into `doc2`
    - content/vcopy_from_version — refused op 2; op 3 `insert` into
      `version`
    - discovery/find_documents_versions — refused op 2 (ops 3–4 refuse
      again); op 5 `insert` into `version2`
    - identity/identity_through_rearrange_pivot — refused op 2; op 5
      `contents` of `version_before`
    - identity/identity_through_rearrange_swap — refused op 2; op 5
      `contents` of `version_before`
    - interactions/compare_versions_with_different_links — refused op 2;
      op 4 `create_link` on `version`, nothing to ground the TO endset
    - provenance/createnewversion_text_vs_links — refused op 4; op 5
      `vspanset` of `version`
    - versions/both_versions_modified — refused op 2; op 4 `insert` into
      `version`
    - versions/compare_versions — refused op 2; op 3 `insert` into
      `version`
    - versions/create_version — refused op 5; op 10 `retrieve_contents`
      of `version`
    - versions/cross_version_vcopy — refused op 2; op 3 `insert` into
      `version`
    - versions/delete_from_original_check_version — refused op 2; op 5
      `retrieve_contents` of `version`
    - versions/modify_original_after_version — refused op 2; op 5
      `retrieve_contents` of `version`
    - versions/multiple_versions_same_source — refused op 2 (op 4 refuses
      again); op 3 `insert` into `v1`
    - versions/version_delete_preserves_original — refused op 2; op 3
      `delete` in `version`
    - versions/version_insert_in_middle — refused op 2; op 3 `insert`
      into `version`
    - versions/version_of_empty_document — refused op 1; op 2 `insert`
      into `version`
    createnewversion_text_vs_links (ruling 15, allowlisted) is now
    INEXPRESSIBLE for the same reason and moves: its `[allowlisted]` line
    in ../ratchet.toml is removed and it is listed under `[inexpressible]`.
    Ruling 15's entry gains its one-line note HERE, this ledger being
    append-only: of ruling 15's three version-link-carryover scenarios,
    link_to_transcluded_then_version and version_copies_link_subspace
    remain allowlisted; createnewversion_text_vs_links is inexpressible
    from this addendum, and its ruling-15 `[[allow]]` entry in
    ../allowlist.toml stands but no longer decides its verdict. Skep bugs
    found: none — the refusal is the rule working.

**Disposition tally (2026-09-05): 297 scenarios — 0 divergent, 0 errors,
0 pending; 85 allowlisted; 46 inexpressible (run-7's 29 + the 17 ruled
here); 166 pass. Twenty rulings and one addendum.**

## 2026-09-06 — PUB round 2, lane 3.3: the read-surface sweep; the rig's setup grant

21. **The rig's setup grant — exit B, the privash grant** (RIG SETUP, no
    allowlist entry, no golden regenerated; owner ruling 2026-09-06, lane
    3.3 §6; PUB-1.31, PUB-5.8.) Lane 3.3 made the read predicate real on
    every read surface: `readable(doc, principal) = published ∨ subtree ∨
    grant` (PUB-1.31), consulted per document argument, a REGISTERED
    private draft answering `Withheld` to a reader outside its owner's
    subtree who holds no grant. The udanax corpus has no publication
    state: every document a golden creates is, in skep's terms, an owned
    private draft, and every cross-session read in a multisession golden
    — session B reading, linking to, comparing against what session A
    wrote — is a read of another account's draft. Fourteen goldens went
    red at exactly those reads. RULED: the rig grants what udanax assumed.
    In `Rig::new` and at every account-delegating site (`switch_account`,
    `create_node`'s sub-account mint — one path, `delegate_under`), the
    rig mints the account's home FLAGLESS (its first mint, born published,
    PUB-8.21, the fold's residence pin PUB-5.17) and deposits there, under
    the account's own session and through the ordinary `make_link`, an
    ANY-PRINCIPAL account-rung grant: `ty` = `1.1.0.1.0.1.0.3.90` (the
    grants class, COMMONS DECISION 5), `from` = the account, `to` = empty
    (PUB-5.8's universal form). Coverage is containment, forward-
    inclusive, so every document the account mints afterwards is readable
    to every bound principal — the rig's sessions are all principals — and
    the fourteen answer as recorded. Not exit A (the goldens re-keyed to
    published sources): a version of a published-born document tests a
    different program from the one the golden recorded, and a re-keyed
    corpus would no longer be udanax's. The grant is HARNESS
    INFRASTRUCTURE, like the types document: its home is never bound in
    the α-map, and `Rig::is_infra_addr` (the `type_registry` exclusion,
    widened) drops the rig homes, the rig accounts and the grants class
    from every address-set comparison, count and endset comparison before
    positional binding. Byte-diff class found and absorbed: the grant's
    FROM endset is the account's SUBTREE span, and M7's overlap is pure
    tumbler order, so the grant link surfaces in every FROM-constrained
    (or unconstrained) `find_links_ftt` over a rig account's content — the
    traversal macros' per-hop query and the general handler both. Neither
    an address nor a position any golden compares moves: scenario
    documents shift one ordinal further (the home is doc 1, the types
    document doc 2) exactly as they already shifted for the types
    document, and the α-map — a bijection built from the acks — absorbs
    the shift. The 297 verdicts are to be byte-identical; the fifteen
    `pub-2.9-private-versionless` and the seventeen inexpressible are
    unchanged (a version of a private draft is refused whatever the
    grant); `report_is_deterministic` and the ratchet are green with NO
    new allowlist entry. RAN AND CLOSED at lane 3.3's close (skep
    91124d0): the 297 verdicts byte-identical, gate-full 1,081 green, the
    ratchet green, no new allowlist entry. Skep bugs found: none — the
    withheld answers were the predicate working. Recorded, not ruled: the setup grant is the
    corpus's assumption made explicit, not a skep behavior; a golden that
    ever reads as the GUEST would meet the predicate unaided.

## 2026-10-07 — CONFORMANCE round 2: the oracle reads every recorded answer

**Recorded, NOT ruled (agent, 2026-10-07):** a read the harness plays now
compares every answer its recording holds, or names the one it cannot
reach: a read that compares nothing ends INEXPRESSIBLE with the unread
keys named (`not read: …`), and `not-compared` is left to a read whose
recording kept no answer. Until now such an answer was silently passed
over, and a scenario could pass with its answer never checked. Readers
now reach the shapes no reader did — a vspanset's `poom_empty` and
`<role>_vspan_count`; find_links' `{success, links}` reply; a compare
over `positions` with an `"i_j"` identity map; retrieve_endsets'
`{source, target, type}` SpecSet reply and its bare FROM list; per-
document `A_content` snapshot replies; a lone recorded array beside a
prose `expected` (rearrange/double_pivot); a `{link_id}` content item.
Whole-document reads now ask skep for everything its own extent reports,
never only as much as the recording says exists, and the grounding
pre-pass no longer undoes past a delete whose removed bytes it never knew
(or a write it could not place) — such a seed was the probe it was read
from. One verdict moves:

- bert/bert_failure_leaves_ispace_corruption — PASS → DIVERGENT at op 3
  (`retrieve_vspanset`, `poom_empty: true`). Green acked op 2's insert
  into a READ_ONLY-opened document (`succeeded: true`) and left its POOM
  empty — the acked-then-dropped write ruling 16
  (descoped-bert-enforcement) names; skep has no bert layer, so the
  twelve bytes are arranged and the vspanset holds one span. The scenario
  passed only because nothing read `poom_empty`. Parked under `[pending]`
  in ../ratchet.toml — exempt from enforcement, reported on every gate
  run — for the owner's disposition: ruling 16's class is the one it
  meets, and its allowlist entry is the owner's to write.

Inside scenarios already frozen inexpressible, ops moved without moving a
verdict: endsets/endsets_after_source_delete op 4 now disagrees where it
agreed against a seed equal to its own probe; rearrange/double_pivot op 5
now disagrees — its recorded `after_first` is read, and the description-
only pivot before it was never expressible, so skep's document was never
pivoted — while op 7 agrees against its recorded array where it disagreed
with the prose beside it; endsets/endsets_after_version op 4 now reads its
answer and meets the never-bound version skep refused to mint at op 2
(`Rejected(PrivateSourceVersionless)`, PUB-2.9); the unread replies of
links/delete_middle_link_check_gap_closure,
links/multiple_orphaned_links_same_content, provenance/delete_then_recopy
and rearrange/swap_with_links are named; versions/version_copies_what op 4
binds its link over a loud placeholder seed, now that the pre-pass, like
the play pass, leaves its unresolvable `parent` insert unplaced.

Also from this round: ../allowlist.toml and ../ratchet.toml name every
scenario by its key, `category/name` — the golden's directory and its
name — because the corpus carries two `find_documents_basic`. The frozen
`[inexpressible]` line that read `find_documents_basic` is
`identity/find_documents_basic`; discovery/find_documents_basic passes.
internal/insert_rearrange_insert_iaddress_gap passes — CONFORMANCE round 1
read the recording client's three crash forms as one — and its
`[inexpressible]` line is trimmed under the ratchet's free-shrink rule.

**Tally (2026-10-07): 297 scenarios — 0 errors; 166 pass, 85 allowlisted,
45 inexpressible, 1 pending (divergent).**

## 2026-10-07 — CONFORMANCE round 2: one word per concept in the report

**Recorded, NOT ruled (agent, 2026-10-07):** the report says one thing per
word, each word as the corpus means it. No verdict moves; the tally is
unchanged. What a reader of earlier reports, and of this ledger, meets
under a new name:

- Adaptation tags. `type_registry` is `types_document` — ruling 21's
  "`type_registry` exclusion" is the `types_document` exclusion; the
  harness's types document is no M7 type registry — and
  `threeset-marker→registry` is `threeset-marker→types-document`.
  `args-from-label`, `doc-from-label`, `position-from-label` and
  `delete-text-from-label` are `args-from-op-name`, `doc-from-op-name`,
  `position-from-op-name` and `delete-text-from-op-name`: they read the
  golden's `op` field, never its `label` field. `allowlist-grant:width`
  and `allowlist-grant:count` are `allowlist-adjusted:width` and
  `allowlist-adjusted:count`: an allowlist entry declares an adjustment,
  and a grant is PUB's. A bare find_links or find_documents aimed by the
  scenario's source-role document is tagged `doc-from-source-role`, where
  it read `doc-from-register`. `empty-as-absent` is gone; it never fired —
  skep's RETRIEVEV and extent reads answer emptiness with an empty
  delivery or ⟨⟩ (M6 R6, ASN-0113), never a refusal.
- Report keys. Each op's `"label"` is `"op"`, the golden's `op` field; a
  scenario's `"first_failure"` is `"first_finding"`, its op under `"op"`
  too.
- Notes. An address α never bound reads "never bound" ("never-bound doc
  …"); a reference the shadow cannot ground reads "resolves to nothing".
- The standing analyses name their rulings: the two-subspace vspanset
  shape, ruling 1 (udanax-malformed-vspanset); version link carryover,
  ruling 15 (version-link-carryover); delete_all_with_links' downstream
  link findability, ruling 10 (ruling-10-i-coverage-findability).
- summary.md's inexpressible section heads "(first inexpressible op)".

**Tally (2026-10-07): 297 scenarios — 0 errors; 166 pass, 85 allowlisted,
45 inexpressible, 1 pending (divergent).**

## 2026-10-07 — CONFORMANCE round 2: a refused version names nothing

**Recorded, NOT ruled (agent, 2026-10-07):** `version` names the last
version the scenario made, and nothing before one exists. A version skep
refuses to make — a private source is versionless, PUB-2.9 — therefore
leaves every later reference to it ungroundable, the class rulings 20 and
20a freeze. Until now an unbound `version` resolved to the scenario's
SECOND DOCUMENT, and find_links and find_documents re-aimed a document
field that named nothing at the bare search: ops naming a refused version
were played against some other document — a write landed in it, a read
read it, a search searched it — and some agreed. Every such op is now
INEXPRESSIBLE, the reference named ("document reference `version` resolves
to nothing"). A compare that names no document reads the harness's
original/version default: after a version the recording made, that
version — one skep refused leaves the compare inexpressible, never compared
with the original itself — and, in a scenario whose recording made no
version, the scenario's first two documents (policy
`compare-default:second-document`, the pair the version-less scripts
compared). And the grounding pre-pass never seeds a version: a seed there
minted a plain document under the version's golden address holding the
very answer its probe expected. Six verdicts move, each ALLOWLISTED →
INEXPRESSIBLE:

- content/insert_vspace_mapping — op 9 (`compare_versions`, naming no
  document) against the version refused at op 4; it compared the original
  with itself.
- interactions/link_to_transcluded_then_version — op 8 (the version's
  contents, read from `source`) and op 10 (`find_links from: version`,
  which agreed searching `source`), against the version refused at op 6.
- interactions/version_add_link_check_original — op 5 (`find_links from:
  version`, which searched `original`), against the version refused at
  op 2.
- interactions/version_transcluded_linked_content — op 6 (an insert into
  the version, written into `doc`), op 9 (the version's contents, which
  agreed reading `doc`) and op 12 (`find_links from: version`, which agreed
  searching `doc`), against the version refused at op 5; op 8 now agrees,
  `doc` no longer carrying the version's suffix.
- versions/version_preserves_transclusion — op 6 (`compare_versions` of
  `version` and `source`, which agreed comparing `doc`, the version's
  source), against the version refused at op 5.
- versions/version_with_links — op 6 (`find_links doc: version`, which
  searched `target`), against the version refused at op 5.

Each references a version skep refused under PUB-2.9 — ruling 20a's class —
and stood allowlisted through ruling 20's or ruling 15's entries, which
also covered disagreements the re-aim manufactured. Moved from
`[allowlisted]` to `[pending]` in ../ratchet.toml — exempt from
enforcement, reported on every gate run — for the owner's disposition:
ruling 20a's `[inexpressible]` freeze is the one they meet.

Inside scenarios already frozen inexpressible, ops moved without moving a
verdict: content/compare_multispan_specsets ops 6–7 and
content/vcopy_from_version op 10 (compares against a refused version) and
op 7 (its contents); interactions/compare_versions_with_different_links
op 9 and provenance/createnewversion_text_vs_links op 7 (`find_links from:
version` — the latter agreed searching the register's document);
versions/version_copies_what ops 6, 8, 9 and 10 (a search naming the
unbound `parent`, and the refused version's vspanset, contents and links).
allocation_independence/all_operations_interleaved no longer seeds its
version 1.1.0.1.0.1.3 with "AABBB". edgecases/compare_disjoint_documents,
edgecases/vcopy_single_char, internal/ispan_consolidation_bulk,
internal/ispan_consolidation_fragmented and internal/ispan_partial_overlap
pass as they did, their compares now tagged
`compare-default:second-document`.

**Tally (2026-10-07): 297 scenarios — 0 errors; 166 pass, 79 allowlisted,
45 inexpressible, 7 pending (1 divergent, 6 inexpressible).**
