# MANIFEST-NEW — new golden categories, recorded 2026-08-15

Recorded by Roger Gregory against the udanax-green backend in this tree
(`backend/build/backend --test-mode` for single-session categories,
`backend/build/backenddaemon` with a fresh data directory per run for
multisession). Runner: `febe/generate_new_golden.py`; scenario sources:
`febe/scenarios/{multisession_golden,links_nary,links_crossdoc,
compare_fanout,provenance_ops,depth_scale,boundary}.py` (plus shared
helpers in `febe/scenarios/recording.py`). No existing scenario, golden,
client, or backend file was modified.

**Discipline.** Every scenario was recorded twice from a fresh backend and
kept only when the two recordings agreed byte-for-byte; a later full
re-record (a third and fourth execution of every scenario) reproduced all
34 goldens identically. Zero nondeterministic recordings. Every op carries
the explicit docid/handle string it was issued against, spans as
`{start, width}` dicts, V-addresses as strings, and the full recorded
answer; mutating scenarios carry `probe` ops (vspanset + contents) as
their own checkpoints. Backend failure replies (`?`) are recorded in-line
as `"error": "request failed (?)"` — they are results, not omissions.

## Scenario inventory (34 goldens + 2 crash probes)

### multisession/ (8) — two or three TCP sessions, one daemon
- `ms_open_conflict_matrix` — A holds a doc open read-write; B attempts all
  four mode/conflict opens, then read-write again after A closes.
- `ms_shared_doc_interleaved_inserts` — second writer refused at
  CONFLICT_FAIL, forks via CONFLICT_COPY; interleaved inserts probed from
  both sessions; committed state after both close.
- `ms_reader_while_writer` — B's held read-only handle observed at every
  stage of A's insert/delete cycle.
- `ms_committed_visibility` — B commits in stages, A observes each stage;
  A's attempt to write into B's document.
- `ms_create_race` — interleaved create_document under one account, two
  accounts, and a third session C.
- `ms_version_race` — back-to-back create_version of one doc from two
  sessions; independent edits; cross-compares.
- `ms_delete_while_reader_holds` — B reads the deleted V-region through a
  held handle while and after A deletes.
- `ms_link_across_sessions` — B finds, follows, and endset-queries A's
  link while A still holds both docs open, and after commit.

### links_nary/ (5) — populated third endsets and n-ary shapes
- `nary_type_content_span` — third endset = a 21-char content span of a
  real document; follow/endsets/find_links (incl. sub-span filter) on the
  type slot; contents of the followed three-endset read back.
- `nary_multispan_from_to` — FROM and TO each with two spans;
  find_links by each span separately.
- `nary_type_two_docs` — third endset with content spans from two docs.
- `nary_empty_endset_shapes` — create_link with an empty specset in each
  slot in turn (all accepted); follow of every end of each.
- `nary_link_to_link` — second link whose TO endset is the first link's
  V-position (local 2.1); link addresses read back as content.

### links_crossdoc/ (3) — endsets spanning two documents
- `crossdoc_from_two_docs` — FROM spans docs P and Q, home P; queried from
  P's, Q's, and target R's side; which doc gains the 2.x entry.
- `crossdoc_to_two_docs` — TO spans T1 and T2; queried from each side.
- `crossdoc_home_elsewhere` — home doc in no endset; home-filter probes
  with the home set serialized the way the backend parses it (spanset).

### compare_fanout/ (4) — COMPARE vs multiplicity
- `fanout_multiplicity_ladder` — one source span transcluded 1..4 times
  into one dest; compare after each copy; reversed and self compares.
- `fanout_self_repetition` — internal repetition by self-vcopy; equal,
  identical, and asymmetric windows.
- `fanout_overlapping_windows` — two docs holding overlapping windows of
  one source; overlap then doubled in one of them.
- `fanout_version_and_copy_routes` — same content reaching a dest via a
  version route and a direct route; compares against both ancestors.

### provenance_ops/ (4) — the origin/deletion query surface
- `prov_request_surface` — bare probe of every in-range request code
  outside the live dispatch (4,6,7,8,9,15,17,19,20,21,23,24,25,26,29,31,
  32,33,37): all answer `?`; liveness create_document after.
- `prov_identity_after_delete` — find_documents and compare over a deleted
  span, then after re-inserting the identical text at the same position.
- `prov_origin_chain` — find_documents from each hop of a 3-doc
  transclusion chain; retrieve_endsets on pure transclusion; dump_state.
- `prov_dumpstate_delete_trace` — DUMPSTATE before/after delete and after
  an internal re-copy.

### depth_scale/ (4 recorded, 1 crash probe)
- `depth_version_chain_4` — 4-level chain, edit at every level, pairwise
  compares (level4×level0, level4×level3, level2×level1).
- `depth_version_chain_7` — 7-level chain: the deepest that survives;
  compares level7×level0 and level7×level6.
- `depth_version_chain_limit_probe` — **no golden: backend aborts** (see
  anomaly A18).
- `depth_edit_marathon` — 104 interleaved inserts/deletes/self-vcopies/
  pivots on one doc; probes every 10 ops, compares against a pre-marathon
  version every 26; final extent 101 chars; zero errors.
- `depth_transclusion_chain` — 4-hop chain A→B→C→D→E with identity
  compares back to A at each hop and find_documents membership.

### boundary/ (6 recorded, 1 crash probe)
- `boundary_single_char_lifecycle` — 1-char doc: insert, exact-span read,
  delete to empty, re-insert, reopen.
- `boundary_exact_extent_reads` — reads at position 1, exact last
  position, full extent, past-end, overhang, and both empty subspaces.
- `boundary_far_position_insert` — inserts at 1.100 and 1.1000000 of a
  3-char doc; reads across the gap; delete spanning the gap.
- `boundary_deep_vaddress_reads` — retrievals at nested local addresses
  (1.1.1, 1.3.1, 1.1.1.1.1) of a flat doc.
- `boundary_deep_vaddress_insert_probe` — **no golden: backend aborts**
  (see anomaly A19).
- `boundary_growth_doubling` — self-vcopy doubling 32→2048 chars with a
  tail read at each doubling and a compare of the halves.
- `boundary_foreign_and_malformed_opens` — opens of never-created,
  foreign-account, node-address, and bogus-version docids; insert and
  delete through a READ_ONLY handle.

## Green anomalies

Numbered for adjudication; every item cites its recording.

**Sessions and access**
- A1. Cross-session bert IS enforced: while A holds a doc read-write, B's
  READ_ONLY/CONFLICT_FAIL and READ_WRITE/CONFLICT_FAIL opens both answer
  `?` (`ms_open_conflict_matrix` ops 7-8). Readers are locked out during
  writes unless they fork.
- A2. Read-write open is account-gated even with nobody holding the doc:
  B (account 1.1.0.2) cannot rw-open A's closed doc
  (`ms_open_conflict_matrix` final op), and A cannot rw-open B's closed
  doc (`ms_committed_visibility`, the "A writes into B's document" open).
  Read-only opens of another account's closed doc succeed.
- A3. CONFLICT_COPY does not share — it FORKS: B's copy-open of A's doc
  materializes a new document under B's OWN account
  (1.1.0.2.0.1/1.1.0.2.0.2), carrying content identity; divergent edits
  never merge back (`ms_shared_doc_interleaved_inserts`: original commits
  "CCAAAA", B's fork holds "DAAAABBBB"; `ms_open_conflict_matrix` ops
  9-14).
- A4. No snapshot isolation for a held read handle: B's READ_ONLY handle
  sees A's uncommitted inserts and deletes live, at every probe
  (`ms_reader_while_writer`, `ms_delete_while_reader_holds`). After a
  delete, B's read of the old V-span [1.3,0.4] answers the SHIFTED
  content "GHIJ" — positions renumber immediately under the reader.
- A5. Allocation counters are global per account across sessions:
  interleaved creates yield strictly sequential ordinals regardless of
  session (`ms_create_race`), and version ordinals race to .1/.2/.3
  (`ms_version_race`).
- A6. Writes through a READ_ONLY handle are acknowledged and silently
  discarded — both insert and delete return success, and the document is
  unchanged (`boundary_foreign_and_malformed_opens`, last three ops).
- A7. OPEN validates nothing: never-created docs, docs under nonexistent
  accounts, bare node addresses, and bogus versions all "open"
  successfully, failing only at first retrieval with `?`
  (`boundary_foreign_and_malformed_opens`).

**Links**
- A8. A third endset carrying content spans is fully first-class: follow
  returns the span, find_links filters by it including sub-spans, and
  retrieve_endsets on the type document reports the usage
  (`nary_type_content_span`). By contrast the corpus's marker-style
  JUMP_TYPE three-endset is UNFOLLOWABLE — follow end 3 answers `?`
  (`nary_empty_endset_shapes` links 2-3, `nary_link_to_link`,
  `ms_link_across_sessions` where the stock client renders it as []).
- A9. FOLLOWLINK's reply is corrupted for multi-span and multi-doc
  endsets: a 2-span single-doc endset follows back as THREE spans (last
  span duplicated) (`nary_multispan_from_to`); an endset spanning two
  docs follows back as the first doc's spans plus one EMPTY vspec bearing
  the FIRST doc's id — the second doc's spans are dropped
  (`nary_type_two_docs` end 3, `crossdoc_from_two_docs` end "from",
  `crossdoc_to_two_docs` end "to"). Storage is correct: retrieve_endsets
  and find_links from the second doc's side both answer properly.
- A10. find_links returns the same link TWICE when the query hits the
  second span of a multi-span endset (`nary_multispan_from_to`, "by
  second from-span" and "by second to-span").
- A11. Empty FROM, TO, or THREE endsets are all accepted by create_link;
  the empty end simply fails to follow (`nary_empty_endset_shapes`).
- A12. Links are addressable content: reading local 2.1 returns the
  link's own global address; a link TO another link's 2.x position is
  accepted and findable (`nary_link_to_link`).
- A13. Only the HOME document gains a link-subspace entry; non-home
  endset documents' vspansets are untouched (`crossdoc_from_two_docs`
  probes of Q and R; `crossdoc_home_elsewhere` probes of A and B).
- A14. The home filter of FINDLINKSFROMTOTHREE is ignored even when the
  home set is serialized exactly as the backend parses it: home spans
  covering the true home, a wrong doc, or a degenerate width all return
  the link (`crossdoc_home_elsewhere`). Confirms bug 015 at the do-layer.
  Separately, `client.py find_links` serializes homedocids as bare
  addresses while the backend reads a spanset of (start,width) pairs
  (get2fe.c getspanset), so any non-empty homedocids list from the stock
  client under-feeds the parser and HANGS the session — client-level
  defect, documented here, worked around in the recording.
- A15. A linked document's vspanset degenerates to
  `[{start "0", width "0.1"}, {start "1", width "1"}]` — the recorded
  shape of bug 011, reproduced identically in every linked-doc probe.

**Compare**
- A16. Fan-out on ONE side is fully reported: N transclusions of a span
  compare against the single source as exactly N pairs, in both
  directions (`fanout_multiplicity_ladder` 1→1, 2→2, 3→3, 4→4;
  `fanout_overlapping_windows` doubled-DEF case; identity survives 4
  transclusion hops as one clean pair each, `depth_transclusion_chain`).
  The under-reporting lives elsewhere: when BOTH windows contain N
  occurrences of the same identity, green answers N IDENTICAL full-width
  rows and never enumerates the off-diagonal occurrence pairings —
  self-compare at multiplicity 4 yields the row 1.1+0.32↔1.1+0.32 four
  times (`fanout_multiplicity_ladder` last op), identical windows over
  "XYZXYZ" yield the same row twice, and the halves of a doubled doc
  yield two identical rows (`fanout_self_repetition`).
- A17. At scale the halves of a 2048-char doubling-built doc share full
  identity but compare fragments it into 256 pairs
  (`boundary_growth_doubling`) — pairing granularity follows the
  underlying I-run structure, not maximal runs.

**Depth and boundaries**
- A18. Version chains die at level 8: the level-8 docid (14 digits) plus
  a 2-digit local address exceeds NPLACES=16, and the first INSERT into
  the level-8 version aborts the backend — after acking, since INSERT
  replies before doinsert runs (fns.c). Reproduced at the identical op in
  both runs (`depth_version_chain_limit_probe`, no golden; partial at
  /tmp/xanadu-newgolden/partials/). Level 7 (exactly 16 digits) works and
  is recorded (`depth_version_chain_7`).
- A19. Insert at a NESTED local V-address (1.1.1) aborts the backend
  outright — first level of nesting, nothing exotic. Also acked before
  dying. Reproduced identically twice
  (`boundary_deep_vaddress_insert_probe`, no golden). Reads at the same
  nested addresses are safe and answer [] (`boundary_deep_vaddress_reads`).
- A20. Far-position inserts (bug 010 territory): insert at 1.100 of a
  3-char doc is accepted; the vspanset then claims width 0.102 while only
  6 chars are retrievable — the extent counts the hole, contents skip it;
  the far content keeps its V-position (read at [1.100,0.3] answers
  "FAR"), the gap reads empty, and a delete spanning content and gap
  arithmetic-checks out (`boundary_far_position_insert`).
- A21. Reads clip silently: past-end reads answer [], overhanging and
  over-wide windows answer the truncated content with no error
  (`boundary_exact_extent_reads`).
- A22. find_documents reports the DELETING document as still containing
  the deleted identity — before and after re-inserting identical text
  (`prov_identity_after_delete`) — while compare_versions over the same
  deleted window answers ZERO pairs and the re-inserted text does NOT
  pair with the version's copy (new I-addresses). The two provenance
  oracles contradict each other; DUMPSTATE shows why: the granfilade
  text leaf still holds the full "ABCDEF" after deleting CD
  (`prov_dumpstate_delete_trace`). Finding 057's stale spanfilade, now
  visible through the public query surface.
- A23. The 104-op edit marathon ran with ZERO errors and zero divergence
  from a naive text-model mirror across interleaved inserts, deletes,
  internal transclusions, and pivots; the ten original characters remain
  traceable by compare throughout (3, then 10, 10, 9 surviving runs at
  ops 26/52/78/104) (`depth_edit_marathon`).

## Probed-but-absent capabilities (category 5)

- The live dispatch (init.c, `init(1)` = safe mode, verified in both
  `be.c` and `bed.c`) installs exactly 21 requests: 0,1,2,3,5,10,11,12,
  13,14,16,18,22,27,28,30,34,35,36,38,39.
- There is NO docispan query, NO origin-reporting op, and NO deletion
  history op on the FEBE surface. `find_documents` is membership-only:
  every hop of a transclusion chain returns the identical docid set with
  no origin distinction (`prov_origin_chain`).
- FINDNUMOFLINKSFROMTOTHREE (29), FINDNEXTNLINKSFROMTOTHREE (31),
  NAVIGATEONHT (9), and SOURCEUNIXCOMMAND (21) exist in the code but are
  nulled in safe mode; SETDEBUG (15), SHOWENFILADES (17), EXAMINE (20),
  DUMPGRANFWIDS (23), JUSTEXIT (24), IOINFO (25),
  SETMAXIMUMSETUPSIZE (32), PLAYWITHALLOC (33) are declared but never
  installed. All of these answer `?` (recorded, `prov_request_surface`).
- Request codes >= 40 are rejected by validrequest() with NO reply at
  all — be.c:111 resets input to stdin — so a conforming client hangs.
  Established from source; deliberately not probed live.
- DUMPSTATE (39) is the only surface exposing I-addresses and is where
  deleted-content provenance survives (`prov_dumpstate_delete_trace`).

## Not recorded, and why

- `depth_version_chain_limit_probe` — backend abort at the level-8
  insert (A18). Crash, not a golden; deterministic across two runs.
- `boundary_deep_vaddress_insert_probe` — backend abort at the 1.1.1
  insert (A19). Crash, not a golden; deterministic across two runs.
- find_links with a non-empty homedocids list through the STOCK client —
  unrecordable as-is: the session hangs on a wire-format mismatch (A14).
  Recorded instead with correct spanset serialization in
  `crossdoc_home_elsewhere`.
- Nothing else was attempted and abandoned; there were zero
  nondeterministic recordings.
