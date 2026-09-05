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
