# Adjudication worksheet — run 3 (2026-08-15, post-rulings)

263 scenarios: 157 pass · 30 allowlisted · 37 divergent · 39 inexpressible.
Settled classes cite ../adjudication/decisions.md and are not reopened.

## T-A. Ruled classes surfacing at new ops — extend entries (no new ruling)

- `delete_link_subspace` op9: DELETE aimed at link positions →
  `NotContentSubspace` — **settled class udanax-no-subspace-confinement**
  (ruling 2; DELETE is content-subspace-only, same invariant as INSERT).
- `delete_text_before_link` op9: post-delete find returns the link —
  **settled ruling 10** (i-coverage findability).
- `find_documents_empty_document`: **settled** (run-2 K ruling: registered-
  empty accepted) — entry was never written; write it.
- `multiple_text_insertions_with_links` op10 / `text_insert_preserves_link_
  vpositions` op10 / `insert_text_check_link_positions` op7: malformed-
  vspanset VARIANTS — the degenerate pair is `("0","0.N")`, not always
  `("0","0.1")`; widen the signature, extend entries (**settled ruling 1**).
- NEW MICRO-RULING NEEDED: `delete_width_larger_than_content` op4 and
  `copy_link_to_text_subspace` op8 — udanax CLAMPS oversized delete/copy
  widths; skep rejects `OutOfBounds`. Same bounds family as ruling 3
  (dense-v-space) but a distinct behavior (clamp vs reject). Proposed:
  ALLOWLIST class `udanax-clamps-oversized-ops` under ruling 3's rationale.
  **RULING:**

## T1. follow-link through transclusion renders every occurrence — 5  ⚠ adjudicate
`"AABB"` expected, `"AABBAABB"` returned; `"DEF"` → `"DEFEFDEF"`. A followed
endset is I-spans; rendering them requires I→V projection, and shared
content projects to EVERY arrangement (source + each transclusion) — the
harness retrieves all of them. Udanax's follow returned one V-occurrence.
Question to rule: what does "follow" yield — the content once (by identity),
or its occurrences? Likely resolution: the harness renders bytes once per
I-span (dedupe by I), matching both udanax and the content-identity reading;
check ASN-0114's statement before ruling whether any skep-side surface
should also change.
**RULING:**

## T2. traverse macros — 3: harness hop resolution still unfixed. ROUND-4.

## T3. endset presentation coordinates — 1  ⚠ adjudicate
`endsets_transcluded_source` op4: udanax reports the touching span in the
QUERY document's coordinates (doc2, the transcluder); skep/harness renders
the source doc's. ASN-0131 matches by I-address; what coordinate space the
surfaced spans present in (I-space? query-doc V?) needs the ASN's text.
**RULING:**

## T4. find_documents partial after delete — 2  ⚠ INVESTIGATE FIRST (possible real gap)
`delete_all_transcluded_content` / `_spanfilade_cleanup`: post-delete,
i-coverage search finds the DELETED source (doc1) but NOT the still-arranged
transcluder (doc2) — backwards from any harness-artifact story. Pre-delete
both were found. Suspects: the harness's captured-I-coverage query built
from doc1 only vs docs_containing over R missing COPY-target placements
(J1★ fires on COPY, so R should have them). One hand trace: what I-region
did the harness send, and what does docs_containing return for it live.
**RULING:**

## T5. world prefix gaps — 5 (Copied:/Prefix:/Link doc: still unbuilt). ROUND-4.
## T6. vspan width residue — 5 grounding (off-by-space widths, scope
   mis-aims: insert_vspace_mapping, retrieve_vspan_empty,
   createnewversion 34v33, version_copies 15v14, createlink_check 13v5). ROUND-4.
## T7. compare residue — 2: same prefix-world gaps as T5. ROUND-4.
## T8 residue. `insert_vs_append_docispan`, `version_transcluded_linked_
   content`, `follow_link` wrong-end, `overlapping_links_different_targets`
   width, `delete_all_with_links` op6, `insert_text_check_both_link_
   positions` op6 (golden recorded the client's raw SpecSet repr —
   golden-defect candidate). ROUND-4 / next sheet.
