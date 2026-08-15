# Adjudication worksheet — conformance run 2 (2026-08-15)

263 scenarios: 147 pass · 81 divergent · 35 inexpressible · 0 errors.
The 81 divergences classify into 12 clusters, each proposed for one of four
dispositions:

- **ALLOWLIST** — udanax is wrong or loose, skep follows the spec; entry with
  citation goes to allowlist.toml.
- **EXCLUDE** — the golden itself is defective (recording artifact); scenario
  marked golden-defect, not compared.
- **INVESTIGATE** — genuinely open; could be a real skep bug. These are the
  priority queue.
- **ROUND-3** — harness grounding artifact; fix the instrument, not a ruling.

Rule on each cluster by writing a disposition on its RULING line.

---

## A. udanax malformed two-subspace vspanset — 20 scenarios
**Proposed: ALLOWLIST** (`udanax-malformed-vspanset`)
When a document occupies both subspaces, udanax's RETRIEVEDOCVSPANSET reply
degenerates to `[("0","0.1"), ("1","1")]` — widths track neither text length
nor link count (single-subspace docs record well-formed spans; harness
standing analysis in summary.md lays out the evidence). Skep's replies are
well-formed per M5/M6. This is a udanax reply-marshaling bug captured in its
own goldens.
Scenarios: the 20 listed under "Standing analysis" in summary.md
(insert_link_allocation_independence, delete_all_with_links,
retrieve_vspan_with_links, the link_poom trio, the links/delete_* family,
copy_link_to_text_subspace, multiple_text_insertions_with_links, …).
**RULING:**

## B. text insert into the link subspace — 1 scenario
**Proposed: ALLOWLIST** (`udanax-no-subspace-confinement`)
`links/insert_text_at_link_subspace`: udanax accepted text at 2.x; skep
rejects `NotContentSubspace` — the subspace-confinement invariant
(ASN-0047/ASN-0116).
**RULING:**

## C. out-of-bounds insert/vcopy accepted by udanax — 3 scenarios  [SPOT-CHECKED 2026-08-15]
**Finding: confirmed real, designed divergence. Proposed: ALLOWLIST**
(`dense-v-space`)
Verified against `isanextensionnd_checks_left_or_right`: the golden's own
comment says the 1.7 insert "Creates gap [1.4, 1.7)" — **udanax's V-space is
sparse** (insert beyond extent, leave holes, fill later); **skep's is dense
by design** (ASN-0116 admission ordinal ∈ [1, n+1]; M5 contiguity
maintenance), so the rejection is the spec working, not a harness off-by-one.
NOTE when ruling: this is the weightiest semantic commitment in the
allowlist — skep cannot express "hole now, fill later"; sparse-insertion
workflows must insert in final order.
**RULING:**

## D. non-ascending pivot cuts — 4 scenarios
**Proposed: ALLOWLIST** (`udanax-lenient-rearrange`)
The `pivot_v3_*` family probes cut orderings udanax tolerated; skep's
`NotAscending` is ASN-0084/0119's strictly-ascending discipline. These
goldens exist to document udanax's leniency.
**RULING:**

## E1. retrieve_endsets slot2 population — 4 scenarios  [INVESTIGATED 2026-08-15]
**Finding: designed divergence — ASN-0131 explicitly rejects udanax's
clip-to-region semantics. Proposed: ALLOWLIST**
(`asn-0131-whole-endsets-no-clipping`)
Three-layer agreement: ASN-0131 digest chooses overlap-match, "surfaced
spans are reported at full recorded extent — never clipped to the region"
[forced], and whole-endset surfacing ("all its spans, including those
pointing outside the region"); skep-discovery handle.rs states the contract
("identity withheld, whole endsets, pinned output order"); the goldens show
udanax clipping — endsets_after_source_insert queries the source span and
records `target: []` for a link whose to-end exists but lies outside the
region. Udanax reports the region's slice; skep reports the link's grip.
One entry covers all four scenarios (and explains round-1's slot-width
mismatches).
**RULING:**

## E2. typed find after endpoint removal — 2 scenarios
**Proposed: ALLOWLIST** (`i-coverage-permanence` / degenerate udanax filter)
`find_links_by_type`, `search_type_filter_with_removed_endpoints`: udanax's
type filter recorded always-empty (its own defect, per harness analysis),
and skep's spanfilade discovers by permanent I-coverage after deletion —
the D8 family. Skep finding the link is the design.
**RULING:**

## E3. find_links coming up short — 6 scenarios  [INVESTIGATED 2026-08-15]
**Finding: no skep coverage bug found; three sub-causes.**
Per-op traces (report.jsonl) + golden field inspection:
- `find_links_homedocids_no_match` (+ the filtered ops of `_multiple`):
  **udanax's homedocid filter is ignored — its own goldens say so**: the
  recording notes read "(expected: 0 — doc3 has no links)" / "(expected: 1)"
  while udanax returned everything. Skep implements the filter the scenario
  author intended. **Proposed: ALLOWLIST** (`udanax-degenerate-homedoc-
  filter`), citing the goldens' own notes.
- `endsets_transcluded_source`, `version_transcluded_linked_content`,
  `_multiple` op 11, `overlapping_links_different_targets`: **harness
  world-construction/parse gaps** (vcopy destination collapsed to one doc;
  bare `target:` field variant unparsed; text-located span covering both
  'bank' occurrences). **Proposed: ROUND-3.**
- `link_home_document_content_deleted`: see K — the post-delete question.
Positive evidence: `delete_all_transcluded_content`'s PRE-delete
find_documents AGREED — skep discovery through transcluded content works.
**RULING:**

## E4. follow_link/traverse resolution — 13 scenarios
**Proposed: ROUND-3 first, then re-adjudicate the residue**
Two sub-patterns: (a) follow returns the WHOLE document where the golden
recorded just the linked span (`link_chain`, `bidirectional_explicit_links`,
star_hub pair, traverse macros' "no link resolvable") — consistent with the
harness's bare-create_link whole-doc endset convention, i.e. instrument
grounding; (b) duplicated segments through transclusions ("AABBAABB",
"DEFEFDEF", `partial_vcopy_of_linked_span`) — follow across shared I-content
rendering every V-occurrence; possibly real FOLLOWLINK semantics to
adjudicate per ASN-0114 once (a) is fixed and the residue is clean.
**RULING:**

## F. recording defects — 1 scenario (+ the bert inexpressibles)
**Proposed: EXCLUDE** (`golden-recording-defect`)
`bert/insert_without_write_token` recorded the client's own
OPERATION_SUCCEEDED banner as document content. The recording client
crashed/desynced; udanax never meaningfully ran it.
**RULING:**

## G. COMPARE correspondence tuples — 5 scenarios  [INVESTIGATED 2026-08-15]
**Finding: one designed divergence, four harness gaps. No skep COMPARE bug.**
- `insert_link_insert_iaddress_gap`: **ALLOWLIST**
  (`allocation-layout-fragmentation`). The golden's own comment documents the
  udanax mechanism ("CREATELINK modifies POOM enfilade"): udanax interleaves
  link allocation into the content I-stream, splitting ABC/DEF into two
  correspondence runs; skep's subspace-separated, gap-free frontiers keep
  ABCDEF contiguous — one maximal run. Both reports are truthful about their
  own I-layout (ASN-0122: correspondence is address equality; maximal-run
  coalescing along the successor). The predicted class-3 allocation-slack
  divergence, realized.
- `compare_multispan_specsets`: harness answered compare_partial with the
  FULL window — the descriptive operand `"shared (13-18)"` was never
  grounded (actual tuple equals the recorded compare_full). **ROUND-3.**
- `vcopy_preserves_identity`, `identity_mixed_sources`, `cross_version_
  vcopy`: world-construction gaps (missing "Copied:"-style prefixes /
  ungrounded vcopies shift or empty the runs). **ROUND-3.**
- Standing note for future runs: ASN-0122 verifies the udanax reference
  COMPARE under-reports fan-out (its pairing is a width-budgeted merge, not
  a join — "self-comparison reports only the diagonal"). Any fan-out compare
  scenario that diverges with skep reporting MORE pairs is udanax's
  documented bug; pre-registered as allowlist class
  (`udanax-compare-fanout-underreport`).
**RULING:**

## H. individual oddities — 2 scenarios  [INVESTIGATED 2026-08-15]
**Finding: both harness. Proposed: ROUND-3.**
- `vcopy_from_multiple_documents`: greedy substring-cover grounding matched
  "Source A " (trailing space, 9 chars) where the recording copied 8 — the
  +1 widths follow. Fencepost in the cover heuristic.
- `insert_text_check_both_link_positions`: the `link_at_2_1_before` probe was
  register-aimed at the wrong doc (setup created doc2 last) — read an empty
  link subspace. The scenario's semantic question (is a link's V-position
  displaced by content inserts?) has the same answer in both systems
  (no — subspace independence), per the golden's own interpretation lines;
  should pass once the symbolic-doc registry lands. Its op 5 also shows the
  golden duplicated-result defect (link listed twice).
**RULING:**

## I. content-text mismatches — 14 scenarios  [exception INVESTIGATED 2026-08-15]
**Proposed: ROUND-3 (grounding boundaries) — exception RESOLVED, also ROUND-3.**
Dominant pattern is whitespace: the harness's text-located delete spans miss
the boundary space udanax included. Instrument, not semantics.
The pulled-out exception, `versions/multiple_versions_same_source`, is NOT a
version-isolation bug: the golden addresses docs symbolically (`doc: "v1"`)
and the harness's register fallback aimed the v1 retrieval at v2 — skep
correctly answered the question it was actually asked. The scenario's
agreeing ops are positive isolation evidence (source unchanged after both
version edits; v2 exact). Round-3 item: a symbolic doc-name registry
(source/v1/doc1 labels → bound addresses), which should also repair other
`doc-from-register` mis-aims.
**RULING:**

## J. vspan width/scope oddities — 2 scenarios
**Proposed: ROUND-3**
`insert_vspace_mapping` (0.7 vs 0.5 — likely grounded insert shorter than
recorded) and `retrieve_vspan_empty` (33-char span from an "empty" doc —
scope register pointing at the wrong document).
**RULING:**

## K. find_documents under-reporting — 5 scenarios  [INVESTIGATED 2026-08-15]
**Finding: no R/coverage bug found; one real semantic ruling needed.**
- `identity_multi_document_sharing`: harness expanded
  `create_multiple_targets` as five bare creates — **no transclusion ever
  happened in skep's world**; skep correctly found 1 doc. **ROUND-3.**
- `delete_all_transcluded_content`, `delete_transcluded_content_spanfilade_
  cleanup`, `link_home_document_content_deleted` (E3's last), and kin:
  pre-delete queries AGREE; post-delete the harness re-grounds the search
  region from the now-empty extent (empty region → []). **ROUND-3** for the
  grounding — **but underneath sits the one real adjudication:**

  **The post-delete search semantics.** Udanax's search reaches deleted
  content (its docispan search runs over the document's I-span history), so
  links/documents remain findable after their content leaves the view. Skep's
  V-region queries (FindLinksV/FindDocsContaining over a doc region) cannot
  NAME deleted content — the V-positions are gone — while the I-based paths
  (FindLinksFtt four-set; R is append-only, M8 has a survival module and
  pre-edit link-survival tests) retain full reach. Options:
  (a) rule the difference DESIGNED — V-queries are presentation-scoped,
  I-reach is served by Ftt/R paths; allowlist the scenarios with that note;
  (b) rule that M10's udanax-style search ops should translate doc searches
  to I-based queries (a harness/adaptation change, arguably truer to what
  the goldens mean by "search this document").
- `find_documents_empty_document`: **ALLOWLIST** — udanax errors on empty
  docs; skep's registered-empty semantics accept (spec'd, registry gate).
**RULING (post-delete semantics, a or b):**
**RULING (empty-document):**

---

### Suggested processing order
1. **E3 + K** (transclusion coverage — the only cluster that could be a
   deep skep bug in core value territory).
2. **E1, G** (spec-text adjudications — read two ASN statements, rule).
3. **A–D, E2, F** (one-word rulings; the evidence is assembled).
4. **Round 3** of the harness for E4(a), I, J — then re-run and re-visit
   E4(b), I's version case, H.
