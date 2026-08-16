# Adjudication worksheet — run 7, the 34-golden extension (2026-08-15)

297 scenarios: 197 pass · 50 allowlisted · 21 divergent (all pending) · 29 inexpressible.
The 263-corpus ratchet held. Pre-registered classes (decisions.md corpus-extension
note): green-no-snapshot-isolation, green-followlink-multispan-corruption,
green-fanout-identical-rows, green-nplaces-version-depth, no-origin-op — plus the
standing rulings (dense-v-space, clamps, present-tense, recorded-not-resolved).

## boundary/boundary_deep_vaddress_reads
- op6 `retrieve_contents`: exp=success (golden recorded no error)
  act=Rejected(MalformedSpan)
**RULING:**

## boundary/boundary_exact_extent_reads
- op10 `retrieve_contents`: exp=success (golden recorded no error)
  act=Rejected(MalformedSpan)
**RULING:**

## boundary/boundary_far_position_insert
- op3 `insert`: exp=success (golden recorded no error)
  act=Rejected(OutOfBounds)
- op4 `observe`: exp=vspanset [("1.1", "0.102")] | content ["ABCFAR"]
  act=[("1.1", "0.3")] | ["ABC"]
- op5 `retrieve_contents`: exp=["FAR"]
  act=[]
- op7 `retrieve_contents`: exp=["ABCFAR"]
  act=["ABC"]
- op8 `insert`: exp=success (golden recorded no error)
  act=Rejected(OutOfBounds)
- op9 `observe`: exp=vspanset [("1.1", "0.1000001")] | content ["ABCFARXL"]
  act=[("1.1", "0.3")] | ["ABC"]
- op10 `delete`: exp=success (golden recorded no error)
  act=Rejected(OutOfBounds)
- op11 `observe`: exp=vspanset [("1.1", "0.999901")] | content ["ARXL"]
  act=[("1.1", "0.3")] | ["A"]
**RULING:**

## boundary/boundary_foreign_and_malformed_opens
- op16 `observe`: exp=content ["guarded"]
  act=["uarded!"]
**RULING:**

## boundary/boundary_growth_doubling
- op21 `compare_versions`: exp=[(1, 1025, 128), (1, 1025, 128), (1, 1025, 128), (1, 1025, 128), (1, 1025, 128), (1, 1025,
  act=[(1, 1025, 32), (1, 1057, 32), (1, 1089, 32), (1, 1121, 32), (1, 1153, 32), (1, 1185, 32),
**RULING:**

## compare_fanout/fanout_multiplicity_ladder
- op19 `compare_versions`: exp=[(1, 1, 32), (1, 1, 32), (1, 1, 32), (1, 1, 32)]
  act=[(1, 1, 8), (1, 9, 8), (1, 17, 8), (1, 25, 8), (9, 1, 8), (9, 9, 8), (9, 17, 8), (9, 25, 8
**RULING:**

## compare_fanout/fanout_self_repetition
- op6 `compare_versions`: exp=[(1, 1, 6), (1, 1, 6)]
  act=[(1, 1, 3), (1, 4, 3), (4, 1, 3), (4, 4, 3)]
- op10 `compare_versions`: exp=[(1, 7, 6), (1, 7, 6)]
  act=[(1, 7, 3), (1, 10, 3), (4, 7, 3), (4, 10, 3)]
**RULING:**

## depth_scale/depth_edit_marathon
- op37 `compare_versions`: exp=[(1, 4, 6), (15, 2, 1), (25, 1, 1)]
  act=[(1, 1, 1), (2, 4, 5), (15, 9, 1), (16, 2, 1), (25, 1, 1)]
- op69 `compare_versions`: exp=[(1, 5, 1), (3, 2, 1), (4, 1, 1), (8, 7, 1), (46, 8, 1), (49, 5, 1), (50, 7, 1), (52, 6, 1
  act=[(1, 7, 1), (3, 5, 1), (4, 8, 1), (8, 6, 1), (22, 2, 1), (35, 1, 1), (46, 5, 1), (49, 6, 2
- op100 `compare_versions`: exp=[(3, 6, 1), (6, 2, 1), (10, 6, 1), (18, 5, 1), (35, 2, 1), (52, 5, 1), (55, 1, 1), (60, 8,
  act=[(3, 5, 1), (6, 8, 1), (10, 6, 1), (18, 2, 1), (35, 1, 1), (52, 5, 1), (55, 6, 1), (60, 5,
- op132 `compare_versions`: exp=[(7, 6, 1), (8, 1, 1), (14, 5, 1), (43, 6, 1), (60, 8, 1), (63, 6, 1), (68, 2, 1), (68, 5,
  act=[(7, 5, 1), (8, 8, 1), (14, 6, 1), (43, 1, 1), (60, 5, 1), (63, 6, 1), (68, 5, 2), (87, 2,
**RULING:**

## links_crossdoc/crossdoc_from_two_docs
- op10 `observe`: exp=vspanset [("0", "0.1"), ("1", "1")]
  act=[("1.1", "0.11"), ("2.1", "0.1")]
- op13 `follow_link`: exp=1.1.0.1.0.1: []
  act=1.1.0.1.0.1: [("1.1", "0.5")]
- op16 `retrieve_endsets`: exp=slot1:cov[1.0.1.0.2.0.1.1+5]
  act=slot1:cov[1.0.1.0.2.0.1.1+5, 1.0.1.0.3.0.1.9+5]
- op17 `retrieve_endsets`: exp=slot1:cov[1.0.1.0.3.0.1.9+5]
  act=slot1:cov[1.0.1.0.2.0.1.1+5, 1.0.1.0.3.0.1.9+5]
**RULING:**

## links_crossdoc/crossdoc_home_elsewhere
- op12 `observe`: exp=vspanset [("0", "0.1"), ("1", "1")]
  act=[("1.1", "0.10"), ("2.1", "0.1")]
- op20 `find_links`: exp=["1.1.0.1.0.3.0.2.1"]
  act=[]
- op21 `find_links`: exp=["1.1.0.1.0.3.0.2.1"]
  act=[]
**RULING:**

## links_crossdoc/crossdoc_to_two_docs
- op10 `observe`: exp=vspanset [("0", "0.1"), ("1", "1")]
  act=[("1.1", "0.14"), ("2.1", "0.1")]
- op14 `follow_link`: exp=1.1.0.1.0.2: []
  act=1.1.0.1.0.2: [("1.1", "0.5")]
- op16 `retrieve_endsets`: exp=slot2:cov[1.0.1.0.3.0.1.1+5]
  act=slot2:cov[1.0.1.0.3.0.1.1+5, 1.0.1.0.4.0.1.1+6]
- op17 `retrieve_endsets`: exp=slot2:cov[1.0.1.0.4.0.1.1+6]
  act=slot2:cov[1.0.1.0.3.0.1.1+5, 1.0.1.0.4.0.1.1+6]
**RULING:**

## links_nary/nary_empty_endset_shapes
- op6 `create_link`: exp=success (golden recorded no error)
  act=Rejected(EmptyTypeResolution)
- op7 `observe`: exp=vspanset [("0", "0.1"), ("1", "1")]
  act=[("1.1", "0.6")]
- op8 `follow_link`: exp=1.1.0.1.0.1: spans
  act=1.1.0.1.0.1: NotALink
- op9 `follow_link`: exp=1.1.0.1.0.2: spans
  act=1.1.0.1.0.2: NotALink
- op12 `observe`: exp=vspanset [("0", "0.1"), ("1", "1")]
  act=[("1.1", "0.6"), ("2.1", "0.1")]
- op17 `observe`: exp=vspanset [("0", "0.1"), ("1", "1")]
  act=[("1.1", "0.6"), ("2.1", "0.2")]
**RULING:**

## links_nary/nary_link_to_link
- op7 `observe`: exp=vspanset [("0", "0.1"), ("1", "1")]
  act=[("1.1", "0.9"), ("2.1", "0.1")]
- op9 `create_link`: exp=success (golden recorded no error)
  act=Rejected(IllFormedSpec)
- op10 `observe`: exp=vspanset [("0", "0.1"), ("1", "1")]
  act=[("1.1", "0.9"), ("2.1", "0.1")]
- op11 `follow_link`: exp=1.1.0.1.0.1: spans
  act=1.1.0.1.0.1: NotALink
- op12 `follow_link`: exp=1.1.0.1.0.1: spans
  act=1.1.0.1.0.1: NotALink
- op14 `find_links`: exp=["1.1.0.1.0.1.0.2.1", "1.1.0.1.0.1.0.2.2"]
  act=["1.1.0.1.0.1.0.2.1"]
- op15 `find_links`: exp=["1.1.0.1.0.1.0.2.2"]
  act=[]
- op16 `retrieve_endsets`: exp=success (golden recorded no error)
  act=Rejected(BadRegion)
**RULING:**

## links_nary/nary_multispan_from_to
- op7 `observe`: exp=vspanset [("0", "0.1"), ("1", "1")]
  act=[("1.1", "0.18"), ("2.1", "0.1")]
- op8 `follow_link`: exp=1.1.0.1.0.1: [("1.1", "0.3"), ("1.9", "0.5"), ("1.9", "0.5")]
  act=1.1.0.1.0.1: [("1.1", "0.3"), ("1.9", "0.5")]
- op9 `follow_link`: exp=1.1.0.1.0.2: [("1.1", "0.5"), ("1.12", "0.5"), ("1.12", "0.5")]
  act=1.1.0.1.0.2: [("1.1", "0.5"), ("1.12", "0.5")]
**RULING:**

## links_nary/nary_type_content_span
- op10 `observe`: exp=vspanset [("0", "0.1"), ("1", "1")]
  act=[("1.1", "0.16"), ("2.1", "0.1")]
**RULING:**

## links_nary/nary_type_two_docs
- op15 `follow_link`: exp=1.1.0.1.0.1: []
  act=1.1.0.1.0.1: [("1.1", "0.8")]
- op18 `retrieve_endsets`: exp=slot3:cov[1.0.1.0.2.0.1.1+8]
  act=slot3:cov[1.0.1.0.2.0.1.1+8, 1.0.1.0.3.0.1.1+9]
- op19 `retrieve_endsets`: exp=slot3:cov[1.0.1.0.3.0.1.1+9]
  act=slot3:cov[1.0.1.0.2.0.1.1+8, 1.0.1.0.3.0.1.1+9]
**RULING:**

## multisession/ms_committed_visibility
- op16 `open_document`: exp=failure: "request failed (?)"
  act=skep has no bert/open layer (access control descoped); nothing rejected
**RULING:**

## multisession/ms_link_across_sessions
- op9 `observe`: exp=vspanset [("0", "0.1"), ("1", "1")]
  act=[("1.1", "0.14"), ("2.1", "0.1")]
**RULING:**

## multisession/ms_open_conflict_matrix
- op6 `open_document`: exp=failure: "request failed (?)"
  act=skep has no bert/open layer (access control descoped); nothing rejected
- op7 `open_document`: exp=failure: "request failed (?)"
  act=skep has no bert/open layer (access control descoped); nothing rejected
- op15 `open_document`: exp=failure: "request failed (?)"
  act=skep has no bert/open layer (access control descoped); nothing rejected
**RULING:**

## multisession/ms_shared_doc_interleaved_inserts
- op6 `open_document`: exp=failure: "request failed (?)"
  act=skep has no bert/open layer (access control descoped); nothing rejected
**RULING:**

## provenance_ops/prov_identity_after_delete
- op10 `find_documents`: exp=["1.1.0.1.0.1", "1.1.0.1.0.1.1"]
  act=["1.1.0.1.0.1.1"]
- op17 `find_documents`: exp=["1.1.0.1.0.1", "1.1.0.1.0.1.1"]
  act=["1.1.0.1.0.1.1"]
**RULING:**
