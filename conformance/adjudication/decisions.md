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
