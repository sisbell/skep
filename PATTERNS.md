# Patterns: the rules the code keeps

This file holds skep's rules of MECHANISM: what every site of a kind must
do, and what one component does for all of them. Each rule has a number
so a brief can cite it and a check can hold a change to it. A rule that
turns out wrong is changed here, with the reason in the commit, not
worked around.

The rules of LAYOUT stay in `ARCHITECTURE.md` §Rules that hold across
files and are not repeated here: crate dependencies point down; inside
`skepd` imports point down; the daemon writes only its own files; tests
live beside the code they test. What `AGENTS.md` binds (where a test
module lives) and what `CONTRIBUTING.md` binds (commits, issues, doc
comments) stay theirs too.

A rule gets in when it already binds more than one site: two or more
callers, files or crates that must keep it today, or a class of three or
more issues that one mechanism would close. A cluster of same-kind issues
is one investigation; its record ends with the rule's sentence; the
change that builds the component lands the rule, the component and its
test in one commit, and the issues it closes are listed on the rule. A
discipline one module keeps for itself is that module's doc comment, not
a pattern, until a second site must keep it.

Each rule is one bullet: what must hold; **Holds it**, the component, by
crate and module; **Checked by**, the test that enforces it, or "no test
yet" and what one would check; **Closed**, the issues the component
closed, and "open:" the ones the rule would close when its remaining
sites move. Skep's prefix is `SP-`; `P-n` and `D-n` are the design
repository's, `FP-n` the frontend's, and a bullet that descends from one
says "from" it at its end.

## Files and their tails

- **SP-1 Durable before acknowledged.** A write is on disk, synced,
  before anything is answered, installed or named over it: the journal
  appends and syncs before it installs the root readers load; a blob is
  synced before it is named and leased before it is answered; a held
  line is synced before `held` is answered; a file is synced before its
  rename. A crash after an answer loses nothing the answer promised.
  **Holds it:** `skep_kernel::journal` (the writer's commit), `skep_blobs::store` (the finish), `skep_shell::held`, `skep_util::file` (`publish`, `write_once`), `skep_core::commits::sidecar` (the record between a commit and its ack).
  **Checked by:** `crates/skepd/tests/it/hazard.rs` (`e_acked_writes_survive_sigkill`, `e_blob_acked_puts_survive_sigkill`, `g_disk_exhaustion_stops_acks_before_durability`); `crates/skep-blobs/tests/it/finish.rs` (`a_failure_at_each_step_of_the_finish_leaves_what_the_order_promises`); `crates/skep-shell/src/held/tests.rs` (`an_appends_line_is_on_disk_before_its_answer`).
  **Closed:** #3, #27, #545.
- **SP-2 A whole file lands by a rename, never a write in place.** A file
  that is replaced whole is written to a temp beside its name, synced,
  renamed onto the name, the directory synced; a kill at any step leaves
  the name whole or absent, never half. A name that stands is never
  written over: what must move aside takes the first free name.
  **Holds it:** `skep_util::file` (`publish` for a new file; `publish_by` for a rewrite through the caller's twin — the blob logs' and the daemon's `<name>.compact`, the file left standing where the directory's sync fails past the rename), `skep_kernel::checkpoint` (the temp and the rename), `skep_kernel::journal::scan` (the keep's names), `skep_blobs::store` (the install and the finish), `skep_shell::held` (the aside), `skep_client::search::directory` (the save and the aside), `skep_resolve::mirror::base`, `skep_provision::whole`.
  **Checked by:** `crates/skep-util/src/file/tests.rs` (`publish_at_each_step_of_a_kill_leaves_the_name_whole_or_absent`); `crates/skep-blobs/src/jsonl/tests.rs` (`a_compaction_that_fails_before_its_rename_leaves_the_log_as_it_was`); `crates/skep-blobs/tests/it/reopen.rs` (`a_half_written_compaction_twin_is_never_read_in_place_of_its_log`); `crates/skep-core/src/commits/tests.rs` (`a_landing_cut_between_its_rewrites_leaves_the_region_to_walk_again`); `crates/skep-shell/src/held/tests.rs` (`a_misplaced_file_is_moved_aside_without_overwriting`).
  **Closed:** #16, #27, #418, #431.
- **SP-3 Every line file goes through one tail module, and a torn line
  is only ever a file's tail.** A file a process writes line by line and
  reads back after a crash, a kill or a refused write — a log, a store's
  listing, a held queue, a bindings file — is read, appended, written
  once, published, removed and listed through the one tail module: a
  line and its newline are one write where the last whole line ends; a
  write that fails is cut back to the whole lines, and where the cut
  fails too the file takes no append until it is rewritten whole; a
  crash's tail, the bytes of one line with no newline, is cut off or
  closed by a mark at the next write, so no line is ever written after
  bytes no reader reads. The parse of a line, the policy for a whole
  line that does not read, what is kept beside the file, every word
  said and the directory's lock stay the caller's, and the modes are
  handed in.
  **Holds it:** `skep_util::file` (`read_lines`, `LineReader`, `Appender` with `cut`, `append_by_telling` and `sync_handle`, `write_once`, `publish` and `publish_by`, `keep_beside`, `remove`, `stale`); its callers `skep_client::store` (the key files, the bindings file), `skep_client::ceremony::backup` and `skep_client::ceremony::import` (the anchor files), `skep_client::ceremony::recover::loss` (the removals), `skep_shell::held`, `skep_blobs::jsonl` (the two blob logs), `skep_core::commits::sidecar` (the commit log) and `skep_core::commits::feed::derived` (the four derived files and the attest store), `skep_cli::dev::manifest`; `skep_client::search::directory` keeps a save of its own.
  **Checked by:** `crates/skep-util/src/file/tests.rs` (`every_torn_tail_is_cut_at_the_next_append_and_reported`, `a_failed_append_is_cut_back_to_the_whole_lines`, `remove_answers_gone_absent_or_the_failure`, `write_once_makes_a_new_file_and_removes_what_a_failed_write_made`); `crates/skep-client/src/store/tests.rs` (`an_unfinished_key_file_is_named_by_the_listing_and_swept_by_the_next_generation`, `a_bindings_file_in_another_encoding_is_faced_as_the_bindings_files_own`); `crates/skep-shell/src/held/tests.rs` (`a_file_with_no_whole_header_line_is_read_as_fresh_and_headed_by_the_next_line`, `a_held_file_the_compaction_cannot_remove_is_kept_and_appended_on`); `crates/skep-blobs/src/jsonl/tests.rs` (`a_failed_append_is_cut_back_off_the_file`, `a_failed_cut_back_stops_the_log_until_a_compaction`), `crates/skep-core/src/commits/feed/window/tests.rs` (`the_cursor_names_each_lines_byte_and_stops_at_a_torn_line`); the callers held to the module by a source check in each crate's `tests/it/tidy.rs` — `skep-blobs`, `skep-core`, `skep-cli` — refusing an `OpenOptions` append or a `create_new` outside the module, a test module or the test-hooks gate (the blob store allowing its hard-link probe alone); `skep-client` and `skep-shell` have no such check yet.
  **Closed:** #418, #419, #545, #584, #585, #587, #589, #610, #611, #619, #623. From P38.
- **SP-4 The journal halts on damage and cuts only a crash's tail.** The
  journal is the truth, so its open destroys nothing unsaid: a tail that
  one interrupted append leaves is cut and said once; a tail that is not
  a crash's, an intact marker committing nothing, a frame that does not
  decode, a run longer than one transaction, is refused as damage until
  the operator accepts the cut by name, and then every byte the cut
  takes is kept beside the journal first, durably, and no position the
  tail claimed is handed out again. Every refusal precedes the cut.
  **Holds it:** `skep_kernel::journal::scan` (the classes, the keep, the cut), `skep_kernel::kernel` (the open's order, the floor), skepd `tools` (the inventory refuses a damaged copy).
  **Checked by:** `crates/skep-kernel/src/journal/scan/tests.rs` (`a_keep_that_fails_cuts_nothing_and_leaves_no_copy`, `an_intact_frame_no_torn_write_leaves_is_counted_where_the_tail_holds_it`); `crates/skep-kernel/src/kernel/tests.rs` (`a_chain_break_halts_the_open_and_the_history_read_and_cuts_nothing`); `crates/skep-kernel/tests/it/hazard.rs` (`a_torn_journal_tail_recovers_to_the_exact_boundary`).
  **Closed:** #409, #486, #487, #488, #490, #491, #503.
- **SP-5 A derived or honest-null log keeps what it cuts, says it, and
  serves.** A log the journal can rebuild, or whose loss is a null
  answer, never halts the board: whole lines its open cannot trust are
  kept beside the file under one naming rule, durably, before they are
  cut; the cut is said as a failure with the file, the last trusted
  position and the bytes; a kept file is named by the open that kept it,
  by every later open, by the inventory and by the standing line until
  the operator removes it; and the log serves.
  **Holds it:** `skep_util::file` (`keep_beside`: the kept file's name `{file}.cut-{byte}`, never over a standing name, written, synced, the directory synced, a half-saved kept file left standing; `Appender::cut` at the open after the keep), its callers `skep_core::commits::sidecar`, `skep_core::commits::feed::derived`, `skep_core::commits::feed::attest` and `skep_blobs::jsonl` (each wording its own line), skepd `tools` (the kept files listed) and `server` (the standing line).
  **Checked by:** `crates/skep-core/src/commits/sidecar/tests.rs` (`dropped_lines_are_kept_beside_the_file_under_the_next_free_name`, `a_cut_past_a_damaged_line_names_the_whole_lines_it_takes`); `crates/skep-blobs/tests/it/reopen.rs` (`a_damaged_lease_log_is_cut_and_the_open_answers_the_whole_lines_it_took`); `crates/skepd/tests/it/open.rs` (`the_open_says_the_bytes_it_cut_off_a_torn_tail_once_and_nothing_after_a_clean_close`).
  **Closed:** #414, #424, #429, #441, #484, #489. From P22.
- **SP-6** merged into SP-3: every line file goes through one tail module.
- **SP-7 Every file is born owner-only through one builder.** Every
  directory and file a process makes is `0700` or `0600` on unix, the
  mode set at creation so the umask cannot loosen it, through one
  builder per crate where the crate makes many; and a program refuses
  to start on a data directory other users can read, naming the
  directory, the mode found and the act that fixes it, repairing nothing.
  **Holds it:** `skep_kernel::journal::segment` and `skep_blobs::blobs` (`dir_builder`, `file_options`), `skep_util::file` (every file it makes at the mode its caller hands in — the daemon's line files, the blob logs, the client's and the shell's files), `skep_client::search::directory`, `skep_provision::statedir`, skepd `main` (the loose-directory refusal).
  **Checked by:** `crates/skep-kernel/tests/it/tidy.rs` (`every_entry_the_library_makes_is_born_through_one_home_for_its_modes`); `crates/skep-kernel/tests/it/modes.rs` and `crates/skep-blobs/tests/it/modes.rs`; `crates/skepd/tests/it/modes.rs` (`every_directory_and_file_the_board_creates_is_owner_only_under_a_loose_umask`, `a_loose_data_directory_is_refused_before_the_open_and_a_tight_one_admitted`); `crates/skep-client/src/store/tests.rs` (`generate_writes_once_under_the_modes`).
  **Closed:** #283.
- **SP-8 A refusal decidable by reading runs before the first write, and
  a halt cuts nothing.** An open or a start judges everything a read
  alone can judge, the command line, a held port, a link at a name it
  acts on, a log of another build, before it touches the directory, and
  a refusal made after the first write names what that write left.
  **Holds it:** `skep_kernel::kernel` (the open's order), `skep_blobs::store` (the two read-only doors), skepd `server` (the start's order) and `skep_core::auth::blocked` (the list read first), `skep_provision::args` and `skep_provision::statedir` (a start refuses what would fail later).
  **Checked by:** `crates/skepd/tests/it/open.rs` (`a_misspelled_variable_stops_the_start_before_the_directory_is_touched`, `a_link_under_blobs_is_refused_before_the_engines_open_touches_the_directory`, `a_held_port_refuses_in_milliseconds_with_the_bind_line_and_creates_no_directory`); `crates/skep-blobs/tests/it/reopen.rs` (`a_link_at_a_name_open_acts_on_fails_the_open_and_touches_nothing`).
  **Closed:** #245, #381, #408, #484, #485. From P13.

## What is said, and by whom

- **SP-9 One door to the operator's stream.** Every line the daemon's
  crates write to stderr goes through the notice door: prefixed with the
  program's name, timed on its head line, carrying its class word; put
  on a bounded queue one thread writes in order, so a write never fails
  the work the notice is about and never waits on it; a line a full
  queue cannot take is dropped and counted on the next. No `eprintln!`,
  which panics on a lost reader, stands on the daemon's path.
  **Holds it:** `skep_util::notice` (`emit`, `emit_lines`, `drain`, `set_sink`); its callers in `skepd`, `skep_core` and `skep_media`; `skep_blobs` and `skep_kernel` write none (SP-10).
  **Checked by:** `crates/skep-util/src/notice/tests.rs` (`a_failing_write_fails_no_door_and_stops_no_later_line`, `a_sink_that_never_takes_a_byte_blocks_no_door`, `a_drain_gives_up_on_a_sink_that_takes_no_line_for_its_bound`); `crates/skepd/tests/it/open.rs` (`the_binarys_lines_survive_a_lost_reader_and_the_daemon_serves_on`, `every_line_of_a_served_open_carries_a_class_word_the_door_spells`); no test yet holds the three crates to the door — one would refuse an `eprintln!` or a `stderr()` handle under their `src/` outside the binary's own exit lines.
  **Closed:** #175, #245, #303, #311, #404, #411; open: #472, #473.
- **SP-10 A library answers facts; the program that embeds it says
  them.** A crate below a program writes no stream: what its open found,
  repaired, cut, kept and freed, and what each act did, is answered as
  figures and names, and the embedder says them once, in its own words.
  **Holds it:** `skep_kernel` (the recovery and the landing's figures), `skep_blobs` (the open's account, each log's reading, the inspection), `skep_util::file` (every append, removal and listing answered), `skep_search` (every refusal a disposition), `skep_corpus` and `skep_resolve` (every outcome a named value); the sayers: skepd `server`, `skep_shell::hold`, `skep_cli::terminal`.
  **Checked by:** `crates/skep-blobs/tests/it/reopen.rs` (`the_inspection_reads_the_stores_as_they_stand_and_writes_nothing`, `what_the_open_found_absent_it_answers_made`); `crates/skep-kernel/tests/it/hazard.rs` (`a_torn_tails_cut_is_reported_as_the_bytes_above_the_last_committed_marker`); `crates/skepd/tests/it/open.rs` (`the_open_says_its_directory_first_and_its_recovery_with_the_kernels_figures`); `crates/skep-identity/tests/it/tidy.rs` (`src_reads_no_world_but_its_ctx`) for one crate.
  **Closed:** #188, #299, #378, #379, #387, #424.
- **SP-11 A standing condition is said at its edges.** A bound that
  refuses, a failure that recurs, a thread that dies or a bad state that
  stands is said once as it begins, once as it clears after a hold-down,
  and never per request or per tick; while it stands, one line at a
  cadence names every standing state with its position or file, and
  nothing is said on a healthy board.
  **Holds it:** `skep_util::permits` (`EdgeTracker`), held by skepd `history`, `server`, `server::scan` and `server::listen`, by `skep_media::pools` and by `skep_core::auth::session`; the standing line in skepd `server`; `skep_core::commits::head` (a refused head once per cause); `skep_media::gate` (the floor's refusal and its lift); `skep_shell::feed` (`Outage`, the stream once per outage); `skep_provision::rates`; `skep_cli::dev::board` (a stall as it begins).
  **Checked by:** `crates/skepd/tests/it/edges.rs` (`no_edge_pair_takes_the_unclassed_door_and_the_write_pool_has_one_door` and its ten siblings); `crates/skep-util/src/permits/tests.rs` (`the_first_refusal_is_the_failure_edge_and_later_ones_inside_the_episode_are_none`); `crates/skepd/tests/it/standing.rs` (`each_tick_says_one_line_carrying_every_standing_clause_and_none_once_the_states_clear`); `crates/skepd/tests/it/volume.rs` (`a_write_refused_at_a_full_volume_is_said_once_and_again_after_a_landed_commit`).
  **Closed:** #290, #292, #295, #297, #301, #375, #400, #403, #410; open: #546, #460, #557.
- **SP-12 A failure in the process's own keeping is said to its
  operator or its person, whatever the caller is answered.** An I/O
  failure in the board's own files, a thread's death, a removal the
  volume refuses: each is said where the operator or the person reads,
  once, with its cause; a refusal answered to a client or a page is
  never the only record of it.
  **Holds it:** `skep_core::commits` (a storage failure said with its file), `skep_core::commits::feed::derived` (a stopped file said once), skepd `server::listen` (a thread's death with its consequence), `skep_util::file` (every failure answered for the caller to say), `skep_client::store` (an unappended binding line is a warning carrying the line), `skep_shell::sessions` (a key store a death cannot list said on `Talk` with its file).
  **Checked by:** `crates/skepd/tests/it/volume.rs` (`a_write_refused_for_a_cause_but_room_is_refused_durability_and_said_by_its_own_line`); `crates/skepd/tests/it/threads.rs` (`the_kernels_halt_is_said_once_at_the_write_paths_door_and_health_says_halted`, `the_pruners_death_is_said_once_and_the_standing_line_names_it`); `crates/skep-client/src/store/tests.rs` (`a_read_only_store_warns_with_the_line`); `crates/skep-shell/src/shell/tests/ceremonies.rs` (`a_self_retirement_is_the_own_hands_arm_though_the_store_cannot_be_listed`).
  **Closed:** #290, #399, #428, #619; open: #500, #501, #497, #493, #620, #550, #552.
- **SP-13 Every failure names its file, its act and the position it is
  about.** An I/O error reads the file as it stands within the data
  directory, the act that failed and the OS's cause, composed where the
  fact is known and carried whole; a refusal about history names the
  position it refused; and a client is never handed the directory's path.
  **Holds it:** `skep_blobs::blobs` (the file, the act, the cause), `skep_kernel::error` (the file and the act), `skep_core::commits::sidecar` and `skep_core::commits::feed::derived` (the file and the last trusted position), skepd `server::reply` (no path to a client), `skep_client::store` (a halt names the path).
  **Checked by:** `crates/skep-blobs/tests/it/reopen.rs` (`an_open_refused_at_a_log_names_the_log_and_its_act_and_keeps_the_kind`); `crates/skepd/tests/it/volume.rs` (`a_refused_open_names_its_file_and_keeps_the_kind`); `crates/skep-core/src/commits/feed/tests.rs` (`a_derived_cut_says_it_is_re_derived_and_a_failure_names_its_file`); `crates/skep-client/src/store/tests.rs` (`a_file_cut_short_in_the_store_halts_its_listing_naming_the_file_to_move`).
  **Closed:** #292, #386, #422, #428; open: #423, #492, #505, #536, #555, #565, #566, #592, #593, #596.
- **SP-14 A failure is never read as an absence.** Not-found is absent;
  every other failure is answered as itself: a size that cannot be read
  is not "no file", a setting given badly is not a setting absent, a
  directory that cannot be read is not "no board", a free space that
  cannot be read is not zero, a file in another encoding is not missing.
  **Holds it:** `skep_blobs::store` (the open's acts and the size read), `skep_util::file` (`remove`), `skep_cli::args` (a setting refused), `skep_client::store` (the bindings file's read), `skep_media::gate` (a free-space read refused binds the floor), `skep_kernel::checkpoint` (a base that cannot be read), skepd `tools`, `skep_corpus` (an error per cause), `skep_shell::sessions` (a death's listing of its key store refused, its fork left unsaid and never read as a store holding no keys).
  **Checked by:** `crates/skep-blobs/tests/it/blobs.rs` (`an_unreadable_size_is_a_failure_never_an_absence`); `crates/skep-cli/tests/it/cli.rs` (`a_refused_setting_is_never_read_as_an_absent_one`); `crates/skep-util/src/file/tests.rs` (`remove_answers_gone_absent_or_the_failure`); `crates/skep-kernel/src/checkpoint/tests.rs` (`a_base_that_cannot_be_read_says_so_rather_than_looking_damaged`); `crates/skep-shell/src/shell/tests/ceremonies.rs` (`another_hands_retirement_is_answered_own_unknown_where_the_store_cannot_be_listed`).
  **Closed:** #35, #126, #401, #405, #416, #504, #583, #589; open: #478, #498, #594, #596.
- **SP-15 No secret reaches a line, an answer or the page.** A token, a
  seed, a key, an invite code, a person's address and the data
  directory's path are written to no log, no error, no page and no
  tool result; a reference minted per process stands in for a token,
  a log keeps sizes and routes, and a value that holds a secret shows
  none of it in its debug form.
  **Holds it:** `skep_shell::refs`, `skep_shell::log` and `skep_shell::person`, `skep_provision` (the log and every `Debug`), `skep_mcp::log`, `skep_cli::args` (a token is never an argv value), skepd `server::reply` (no directory path to a client).
  **Checked by:** `crates/skep-shell/src/shell/tests/modes.rs` (`a_paper_claim_hands_the_page_no_seed_and_no_path`); `crates/skep-shell/src/shell/tests/door.rs` (`a_shells_options_print_no_seed`); `crates/skep-mcp/tests/it/mcp.rs` (`no_session_token_and_no_key_seed_reaches_a_tool_result_or_a_log_line`); `crates/skep-provision/src/flow/status_map/tests.rs` (`the_maps_debug_shows_no_token`).
  **Closed:** #244, #329, #331, #354, #361, #382, #422, #517, #541; open: #592.
- **SP-16 A secret lives in a type that wipes on drop.** A seed, a
  signing key and every text a rendering makes of one are born into a
  value that overwrites itself when dropped, and leave it only as the
  signer derived from it; a copy in a plain string or a JSON value is a
  copy left in freed memory.
  **Holds it:** `skep_signature::signer` and `skep_signature::kdf`, `skep_client::sheet` (`Seed`, `SeedText`), `skep_client::sign`, `skep_client::store` (the seed leaves only as the signer).
  **Checked by:** `crates/skep-client/src/sheet/tests.rs` (`the_seed_and_the_sheets_text_of_it_wipe_on_drop`); no test yet holds the key file's export and read or the CLI's drawing — one would read the freed pages after each.
  **Closed:** #88, #249, #261, #445; open: #598, #599, #600, #601.

## What comes in from outside

- **SP-17 A stranger's bytes are read under a bound on size and on
  wait.** Every read from another process, a socket, a page or a file
  another hand may have written is read no further than a cap its
  reader names and no longer than a deadline, and a reply past either
  is refused by name, never held in memory whole or waited on forever.
  **Holds it:** `skep_http::read` (`Limits`), skepd `server::http` (the head cap, the body cap, the deadlines) and `skep_core::limits`, `skep_client::dial` (the answer cap, the exchange's deadline), `skep_resolve::http` (the answer cap, the page budget), `skep_shell::wire` and `skep_shell::held` (the frame cap, the line bound), `skep_mcp` (the fetch cap, a line's size and pace), `skep_util::file` (`LineReader`'s bound), `skep_provision::urlform` (three fields), `skep_cli::commands` (the payload cap).
  **Checked by:** `crates/skep-http/src/read/tests.rs` (`t5_a_body_past_the_callers_cap_is_too_large_and_one_at_it_is_read`); `crates/skep-client/src/dial/tests.rs` (`an_answer_past_the_cap_is_read_no_further`, `a_trickling_board_is_cut_off_at_the_exchanges_deadline`); `crates/skepd/tests/it/fuzz_http.rs` (`http_slow_loris_read_timeout_fires`); `crates/skepd/tests/it/wire_doc.rs` (`doc_states_the_largest_single_answer_the_three_deadlines_and_the_head_cap`).
  **Closed:** #82, #259, #302, #318, #334, #357; open: #473, #533, #535, #549.
- **SP-18 A stranger's value passes one check at the door and is typed
  after it.** A name, an address, a code, a flag's value or a record
  body is checked once, at the entry it arrives by, and carried as a
  type its rule's one constructor makes, so what keeps or uses it checks
  nothing again and no other string of its shape can stand in; no name
  reaches a path out of its root. A body is admitted only as its own
  canonical re-encoding, and a second parser of it is held to the
  owner's vector set, never derived from the owner's parser.
  **Holds it:** `skep_blobs::blobs` (every name at the store's entry points and at open), `skep_provision::name`, `skep_provision::domain`, `skep_provision::mail_address` and `skep_provision::invite_code`, `skep_client::address` and `skep_client::origin`, `skep_shell::wire` (a document address in one spelling), `skep_cli::args`, `skep_registry::body` and `skep_media::cell` (the canonical rule and the vector sets), `skep_identity` (the canonical record).
  **Checked by:** `crates/skep-blobs/tests/it/blobs.rs` (`every_entry_point_answers_a_malformed_name_as_absent_and_touches_nothing`); `crates/skep-cli/src/args/tests.rs` (`a_command_line_parses_and_each_malformed_part_is_refused`); `crates/skep-provision/src/mail_address/tests.rs` (`the_rules_words_name_its_bound_and_every_special`); `crates/skep-registry/tests/it/body.rs` and `crates/skepd/tests/it/vectors.rs` (the vector sets).
  **Closed:** #32, #34, #53, #56, #58, #65, #250, #350, #362, #369; open: #425, #440. From P35.
- **SP-19 A refusal is for a stranger's input; a panic is the code's own
  bug.** Bytes from outside are parsed into a documented answer or a
  named refusal on every input, and never unwrapped, indexed or printed
  into a panic; a panic is a broken precondition the code's own caller
  owes, caught at one hook that says it once and names the payload only
  where the code wrote it as a literal.
  **Holds it:** `skep_febe` (every failure a typed rejection), `skep_core::codec` (any bytes, a documented shape), `skep_blobs` (errors carry only answers; a precondition panics), `skep_corpus` (an error, never a panic), `skep_cli::shared` (every stop a code; no print macro), `skep_mcp` and `skep_shell` (page and board input), skepd `main` (the panic hook).
  **Checked by:** `crates/skepd/tests/it/fuzz_codec.rs` (`a_mutated_frame_never_panics_and_answers_one_documented_shape`); `crates/skepd/tests/it/fuzz_envelope.rs` (`envelope_parsers_answer_documented_shapes`); `crates/skep-cli/tests/it/tidy.rs` (`no_stream_is_written_by_a_print_macro`); `crates/skep-blobs/tests/it/finish.rs` (`a_finish_short_of_the_declared_length_stops_as_its_callers_bug_and_names_nothing`).
  **Closed:** #21, #57, #132, #202, #229, #230, #240, #241, #329, #554; open: #558.
- **SP-20 What reaches a terminal or a log from outside is rendered
  inert.** Every byte a board, a reply, a page or a file chose is
  rendered line by line, every control and bidi character shown as its
  name, before stderr, a log line or a label sees it, through one writer
  per program, so a stranger's bytes act on no terminal and forge no line.
  **Holds it:** `skep_cli::terminal` (`write_inert`, the one writer of stderr; `c0_inert` on stdout), `skep_client::sheet` (`render_inert`), `skep_mcp::log` (every line), `skep_shell::sessions` and `skep_shell::shell::ceremony` (the faces).
  **Checked by:** `crates/skep-cli/tests/it/tidy.rs` (`stderr_is_written_inert_by_write_inert_and_clear_alone`); `crates/skep-cli/tests/it/hostile.rs` (`a_board_s_bytes_reach_the_terminal_inert_never_as_commands`); `crates/skep-mcp/tests/it/startup.rs` (`a_boards_text_reaches_the_log_inert`); `crates/skep-client/src/sheet/tests.rs` (`a_label_renders_inert`).
  **Closed:** #137, #517, #541. From AUTH-5.2.

## The world, the wire and the figures

- **SP-21 Nothing in the world is overwritten.** Content is written once
  and addressed forever; a link, a version and a journal entry are
  appended; a removal, a retraction and a retirement are new records,
  and what they remove stays readable as removed. A fold that meets an
  address twice refuses, on every build.
  **Holds it:** `skep_content` (the write-once map), `skep_links::state` (a fresh address asserted at the one insertion), `skep_arrangement` (the provenance relation keeps every removed address), `skep_namespace` (the position map and the publication bit written once), `skep_kernel::journal` (append-only segments), `skep_identity` (a retired key stays in its set).
  **Checked by:** `crates/skep-namespace/tests/it/publication.rs` (`the_bit_is_immutable_and_recovers_by_checkpoint_and_replay`); `crates/skep-content/tests/it/recovery.rs` (`the_slice_refuses_a_body_naming_one_address_twice`); `crates/skep-kernel/tests/it/golden.rs` (the journal's bytes pinned).
  **Closed:** #156, #281, #284. From D4.
- **SP-22 Who may read is asked at one door.** Each crate that answers a
  read asks the reader's predicate in one place, bound once per request
  off the snapshot it answers from; every other read takes the
  predicate as its caller's and projects a link to its home before
  asking, since the predicate answers about a document.
  **Holds it:** `skep_febe::operation::door`, `skep_discovery::home`, `skep_retrieval::query` (the two doors), `skep_media::door` (the seam), `skep_engine::readable` (the one definition).
  **Checked by:** `crates/skep-febe/tests/it/tidy.rs` (`only_the_door_asks_the_worlds_own_predicate`); `crates/skep-discovery/tests/it/tidy.rs` (`only_home_projects_a_home_or_asks_the_readers_predicate`).
  **Closed:** #77, #145.
- **SP-23 A read's cost is counted in one place and stated where its
  caller reads it.** Every budget is a constant one module compares
  against, refusing before the work it bounds and never after it; a
  bound that cuts an answer says so on the answer; and what each read
  walks is stated once in the crate's own doc, which the pool that
  bounds it links by name.
  **Holds it:** `skep_retrieval::budget` (`Count`), `skep_discovery::budget` and the crate doc's cost section, skepd `server::scan` (the class-scan pool's card), `skep_search` (every bound a flag on the answer), `skep_shell::attest` and `skep_shell::wire` (the board's budgets pinned to the board's constants), `skep_blobs::lease` (a principal's reads at its own leases' cost).
  **Checked by:** `crates/skep-retrieval/tests/it/tidy.rs` (`only_budget_compares_a_count_to_a_budget`); `crates/skep-discovery/tests/it/tidy.rs` (`the_cost_statement_names_every_read_this_crate_publishes`).
  **Closed:** #48, #63, #72, #74, #110, #150, #200, #203, #406. From P29.
- **SP-24 The wire document is the contract, and a test reads it.** What
  the daemon answers is what the wire document states, in the same
  commit; every rejection is a classified code the document names,
  lowered through one table with no wildcard arm; a client keys on one
  token and no other; the examples, the figures, the rows and the
  declarations the document and the shell carry are read back by tests.
  **Holds it:** the wire document, `docs/wire.md`; skepd `server::reply` and `skep_core::codec` (what the daemon answers), `skep_febe::reject` (the classification and the lowering), `skep_client::board` (the one dispatch token), `skep_shell::shapes` (the declarations), `skep_signature` (the frozen rules).
  **Checked by:** `crates/skepd/tests/it/wire_doc.rs` (`doc_request_examples_are_canonical_and_complete`, `doc_error_examples_match_their_fixtures` and twenty-one siblings); `crates/skep-signature/tests/it/wire_doc.rs`; `crates/skep-kernel/tests/it/docs.rs` (`the_docs_restate_the_segment_ceiling_as_the_constant_sets_it`); `crates/skep-client/src/board/tests.rs` (`a_rejection_keys_on_the_one_token_the_wire_dispatches_on`).
  **Closed:** #20, #211, #302, #305; open: #469, #567, #570, #575, #581.
- **SP-25 A figure is spelled once, and every text that states it is
  held to its constant.** A default, a cap, a port, a directory's name,
  a row's address and a program's name are each one constant, `pub`
  where another crate reads it; a help, a README table, the runbook and
  the wire document render it from the constant or are read back
  against it by a test, so a moved figure is a red test, not a drift.
  **Holds it:** `skep_cli::args` (every default, every `SKEP_*` variable), `skep_provision::args`, `skep_mcp` (its settings table), skepd `limits`, `skep_core::limits` and `skep_media::limits` (each bound `pub` for its reader; the store directory's one spelling), `skep_kernel` (the segment ceiling), `skep_registry::rows` (one table, one address apiece), `skep_util::notice` (the program's name).
  **Checked by:** `crates/skep-cli/src/args/tests.rs` (`every_default_the_helps_state_is_its_constant`, `the_readmes_settings_table_is_the_grammars`); `crates/skep-cli/tests/it/tidy.rs` (`every_skep_variable_is_named_in_args_alone`); `crates/skep-mcp/tests/it/tidy.rs` (`every_variable_the_source_reads_is_a_row_of_the_readmes_settings`); `crates/skepd/tests/it/runbook_doc.rs` (`runbook_quotes_the_figures_the_constants_supply`); `crates/skep-provision/src/args/tests.rs` (`every_default_is_its_named_constant`).
  **Closed:** #49, #72, #93, #326, #358, #390, #412, #417, #470; open: #506.
- **SP-26 Every JSON object the daemon writes is built through one
  key-sorting builder.** An object on the wire, in a log line or in a
  feed file is built through the builder that sorts its keys and keeps
  the last of a duplicate, so the bytes of an object never depend on the
  order a site named its members in.
  **Holds it:** `skep_util::json` (`obj`); its callers in `skepd`, `skep_core` and `skep_media`.
  **Checked by:** `crates/skep-util/src/json/tests.rs` (`obj_is_order_insensitive`, `obj_keeps_the_last_of_duplicate_keys`); `crates/skepd/tests/it/wire_doc.rs` (`doc_states_the_writes_member_and_the_health_examples_keys_are_the_daemons_in_its_order`).
  **Closed:** none yet.
- **SP-27 Every bounded pool is one permit type.** A bound on concurrent
  work is a counting pool whose permit returns its slot on drop, taken
  before the lock or the body it protects, refused by a retry-class name
  past the pool, and counted into the worker minimum; a permit is a slot
  of the pool that minted it, so no bound can spend another's.
  **Holds it:** `skep_util::permits` (`Permits`, `Permit`), held by skepd `history` (reconstructions), `server::scan` (class scans) and `server` (writes), and by `skep_media::pools` (fetches, uploads).
  **Checked by:** `crates/skep-util/src/permits/tests.rs` (`a_pool_hands_out_exactly_its_count_and_a_drop_returns_one_slot`); `crates/skepd/tests/it/write_pool.rs` (`parked_writers_hold_their_permits_and_the_one_past_the_pool_is_refused_before_the_lock`); `crates/skepd/tests/it/wire_doc.rs` (`doc_states_the_write_permit_pool_and_its_token`).
  **Closed:** #87, #293.

## The builds and the checks

- **SP-28 A test seam is a feature, off in every shipped build.** Every
  hold, fault door, override, fake and scripted stand-in a suite drives
  compiles only under a default-off feature, hidden from the docs, and
  the full gate builds each library and binary without it; the seam is
  reached through doors of the same standing, never a `cfg(test)` branch
  in shipped code.
  **Holds it:** the `test-hooks` feature of `skep_kernel`, `skep_blobs`, `skep_media`, `skep_core`, `skepd`, `skep_client`, `skep_signature`, `skep_content`, `skep_arrangement`, `skep_namespace` and `skep_provision`; the gate script `scripts/gate-full.sh`.
  **Checked by:** `crates/skep-kernel/tests/it/tidy.rs` (`every_test_hook_compiles_only_under_test_hooks`) and the same test in `crates/skep-blobs/tests/it/tidy.rs`, `crates/skep-media/tests/it/tidy.rs`, `crates/skep-core/tests/it/tidy.rs` and `crates/skepd/tests/it/tidy.rs`; `crates/skep-client/tests/it/tidy.rs` (`the_scripted_person_compiles_only_under_test_hooks`); `crates/skep-signature/tests/it/tidy.rs` (`hooks_rs_lists_every_test_hook_and_nothing_else`).
  **Closed:** #26, #37, #92, #180, #325, #510.
- **SP-29 A source check that finds nothing fails.** A test that reads
  the source for a rule asserts it found the lines the rule is about, so
  a reader gone blind, a renamed file or a moved marker fails rather than
  passing a clean tree; a check that passes with its fix removed is not
  a check.
  **Holds it:** every `tidy` check that reads source: `skep_conformance`, `skep_discovery`, `skep_links`, `skep_febe`, `skep_retrieval`, `skep_coordination`, `skep_identity`, `skep_arrangement`, `skep_cli`.
  **Checked by:** the checks' own control inputs — `crates/skep-identity/tests/it/tidy.rs` (`the_module_map_readers_see_the_forms_src_does_not_spell`, `the_purity_readers_see_the_world_in_every_form`); `crates/skep-coordination/tests/it/tidy.rs` (`the_order_readers_see_the_forms_src_does_not_spell`).
  **Closed:** #22, #117, #130, #282.

## Classes with no rule

Each is a cluster of three or more issues that no component closes
today. The rule is the owner's, by an investigation; this list names
the class, its issues and the question a rule would have to answer.

- **A lock held across I/O.** #89, #206 (closed); #475, #499, #534,
  #616 (open). The one decided site is the PUT's arm (`ARCHITECTURE.md`
  §Rules, "The PUT takes no `Serial`"), and the notice door's queue is
  one answer for one kind of write. The question: which I/O may a lock
  of the write path be held across, the journal's own barrier being held
  by design, and where each other read, unlink or dial moves: before the
  lock, after it, or onto a thread of its own.
- **A read that re-reads the whole.** #48, #63, #110, #291, #406,
  #407, #432, #526 (closed); #462, #466, #467, #468, #474, #476, #553,
  #576 (open). The question: which whole-store walks want an index of
  their own, which a line that carries its classification, and what each
  costs at the open and at the write.
- **A pass that stops at one bad entry.** #236, #415 (closed); #480,
  #494, #495, #586 (open). The question: when a pass over many entries
  meets one it cannot read or remove, does it go on, and what does it
  answer for the entry it passed over — a listing policy the key store,
  the pruner and the open would share.
- **A held write's state, said to no one who can act.** #550, #531,
  #532, #551, #607, #608, #609 (open). The question: who is told of a
  held burst's state and its board's, in which words, and which answer
  each word promises.
