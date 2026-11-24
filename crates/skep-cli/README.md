# skep-cli — the `skep` command, and the dev binary `skep-dev`

The command over `skep-client` (`client.md` §1.2, §2), twenty-five commands:
`keygen`, `claim`, `session`, `fingerprint`, `verify`, `health`, `bind`,
the ceremonies `enroll`, `recover`, `retire`, `rotate`, `handoff`,
`accept`, `merge` — the editor's act on a daughter over the library's
`merge` feature (the design's merge record, §6), the one command that
touches content: it composes the merge and prints the report as one JSON
document, `--publish` lands it as the next version with its record, every
window part of the merged text answered by name first (`--window`,
`--leave-out`, `--keep-private` — it answers none for you, and refuses,
exit 1, naming every part where one is owed, publishing nothing), a
`--draft` side's own words taken from the draft in the same commit so it
reads them as published, its base unchanged, so a later merge from it
composes against the base it was staged from (a draft changed since the
composition refused with nothing published), `--into` sets a draft's whole
text to it in one write, what the draft held replaced, `--new` lands it in
a fresh draft staged from the head or finds this composition's landing
standing in a draft of yours and says so, `--resolve ⟨gap⟩=⟨choice⟩`
settles a gap the rules left open by its number in the report, `--undo
⟨S⟩` puts a draft back as it stood before the merge landed in it (with
`--withdrawal ⟨P⟩` a withdrawal taken back) and `--withdraw ⟨S⟩` takes the
merge out keeping the words — a `--publish` whose head already holds the
merged list refused `head_holds` and a landing of this merge begun in a
draft and never recorded refused `landing_begun`, each exit 1, nothing
written, its words naming this command's own way on, and a landing
stopped with its record unwritten naming the run that writes it — the record kept only
in a private document
— a published `--journal` said by the composition's talk and refused
before any write, exit 1 — a daughter is reported and never retried,
another account's fork of the document (`--fork`) is merged from where the board records
it standing — its recorded base, which a landing into it moves, else its source — every
side's base derived up the bases the board recorded
and never from an address — a side begun from the bare document before its
first version merged over the document's arrangement from before that
version, the report's `base` the document itself — and a side whose base
the board does not serve — a draft of another account, a line through a
member the board records no base for — is refused with the reason, as is a
`--fork` of the document owner's own account (`fork_of_owner`: the owner's
draft goes as `--draft`) — and `share`, over the
library's `share` module: a draft (`--doc`) or the caller's whole account
(`--whole-account`, every draft under it, those written later included)
shared with ONE account (`--to`); a draft PRIVASHED (`--privash`, Nelson's
term: opened to every account on the board and never a guest, until
revoked); a share revoked (`--revoke`, the reader keeping what it
fetched); a share made again after a revoke, naming the revocation it
follows; and `--list`, what you shared, what is shared with you and what
is privashed on the board. The share gesture's statement is said on stderr
before the act — what the grant reaches, its history, what revoking will
not take back, what the reader can disclose, that only you can revoke it
and a lost key leaves it standing, the custody note for an agent — then a
typed confirmation at a terminal, or `--yes` off one, required there; the
grant, the revocation or the lists come back as one JSON document on
stdout. And `restore`, over the library's `history` module (B3-S7): a
draft put back as it stood at an earlier position (`--draft`, `--at`),
its state read as of that position and set as the draft's whole
arrangement in one write, words a publication since made public coming
back as the published words they became, a merge the draft carries left
standing and said beside the withdrawal that takes it out; refused where
the draft changed between the read and the write; the statement before
the act on stderr, then one JSON document on stdout naming the position
that puts the restore back. And `hint`, over the library's `resolve`
module (REG-3.2): a registry's root hint printed as one line on stdout —
the line a reader is given to find this registry, a setting the reader
can change — its origins in the order given (`--board`, then each
`--also`, a further origin written as given and never dialed), then
`realm:` and the fingerprint of the key set the board's claimant enrolled
at its genesis, never the set the account holds now, read off the board
as a guest — no key, no session, no store — by the read a registry
mirror's realm check makes, so a mirror opened from the line passes that
check; `--fork` adds a forked lineage's fork point and is never inferred;
an unclaimed board, and a claim that names no genesis record, are halts
naming the board, exit 3, and no refusal prints anything on stdout. And
`resolve`, over the same module (REG-3.7, REG-3.80): the board a
cross-board address lives on. The address (`--address`) is one global
tumbler; its node field is the prefix the registry binds, resolved whole,
and the rest is read at that board. The registry is the one the root hint
names — `--root-hint`, or `SKEP_ROOT_HINT`, the line `hint` prints;
required, with no default — read as a guest into a mirror kept beside the
key store, `<store>/registry/<genesis>/`, the hint's genesis fingerprint
naming the directory so two registries keep two copies; every run reads
the registry to its head before it answers, a held copy checked against
the root and resumed, and nothing is answered from a copy alone (REG-3.10).
BOUND prints one line on stdout, the origin of the endpoint member to dial
and then the address in that board's local form, the prefix swapped for
`1` (REG-1.63; a bare prefix prints the origin alone), exit 0. Every other
named state — UNREGISTERED, RETIRED-WITH-HISTORY, BOUND-BUT-UNREACHABLE,
unreachable-by-policy, THE DIAL NOT MADE, THE HOP NOT MADE — is a halt
under the face's own name, exit 3, with nothing on stdout; `--json` puts
the face and its facts on stdout as one object at every state. A root that
did not answer is exit 4 and one that refused exit 1; a copy that does not
read, a root that does not answer for the copy held and a root of another
realm than the hint's are halts naming the mirror's directory, exit 3.
The command dials no org's board, so BOUND-BUT-DISCLAIMED and the
live-enforcement face, read at that dial, are not answered. And
`deposit`, over the library's `first_session` and `registry_record`
compositions (REG-1.9): a registered board's node account tells the
registry where its board is. `--account` names the node account, on the
board that account is on (`--board`: the registry's), and each `--origin`
an origin the board answers at, in the order a reader tries them — a
canonical origin, written as given and never dialed. The session is the
command's own, content-scoped, as the principal the board seats at the
account (`--principal`, where given, must be that one), under the
selected key: one of the node account's own set, the board owner's, never
the service that hosts the board, which holds no such key and signs
nothing (REG-4.120). The account's home page is read first, as a guest:
missing, this session mints it, born published; published, the run
resumes at the deposit; a draft, the run halts naming its act, an
out-of-band report, before any session opens (REG-1.52). The endpoint
then names, in `replaces`, the deposit current in that home — the latest
that stood, a nullified one included, and none on the account's first —
so a reader holds the new one current, and the one it replaces stays in
the home (REG-1.10). Stdout carries `endpoint <address>`, and under it
`replaces <address>` where it names one. No person door. And `hire`, the
library's `hire` walk (AUTH-5.58, the owner's side): an owner hires an
agent. The agent's key is made on the agent's own host, `skep keygen
--payload` there, and its one-entry record comes to this command as
`--payload`. The command first says what the agent will be able to do
under the owner's account, and what no act of the owner's takes back.
It then makes the agent's account, the next one beneath the space for the
owner's agents, and with it two custody sheets for the owner to keep,
exported to `--anchor-out` (one directory per sheet) and under `--paper`
printed too; the owner names each sheet at its box. The owner compares
the fingerprint the command shows with the one the agent's host shows and
types its first group. Only then is the agent's first key record
written — the owner's own record, holding the agent's key and the two
sheets' keys, signed by the owner's key, in the home page of the space
for the owner's agents — and the agent's home page made, from a session
one of the two sheets opens. Last, stdout carries the agent's `account`,
`principal` and `origin`, and under them `key <fingerprint>`: the
principal is the number the agent's program takes as its
`SKEP_PRINCIPAL`, beside the board and its own key store. An agent's
program takes those as settings and never runs `skep bind`, which refuses
at an agent's account. `--anchorless` hires with no custody sheets: what
that costs is stated after the account is made and ahead of the key
record, and taken by a typed answer; the agent's home page is then the
agent's own to make, the first act of its first session. `--replaces
<address>` names the agent's account this one replaces: a key that
account ever held is refused, and the sheets' boxes show its labels so
the new ones are named apart. A record carrying an anchor-flagged entry,
more or fewer than one device key, or a key with no label is refused
after the account is made and before the key record: the account stands
empty, and running the command again resumes at it and makes no second.
A run that ended after the key record and before the agent's home page
is not resumed: the command stops, writes nothing, prints no principal
and names the act left. The owner's key is the store's for the board and
principal, and a key file (`--key`, `SKEP_KEY`) is refused. After a second
hire the store holds a line for an agent's account beside the owner's
own, so the owner's later commands name `--principal`. A person door. And
`register`, the library's `registration` composition (REG-4.67): an
applicant asks a registry for its org's place in it. The command runs on
the applicant's own device, with no board and no account: it reads no
board, opens no connection and writes nothing to any board. It makes the
keys the registry's door asks for and prints the request that carries
them. `--door <identifier>` is required and names the one door the
request is for — one quoted string as the registry publishes it,
`realm:<64 lowercase hex> door:<address>`, with `fork:<address>` between
the two on a forked lineage — and it is checked for its form alone,
before anything is asked, made or written; whether a door answers to it
is that door's check. A request is a fresh registration's: two pairs of
anchor sheets, the org's own root pair and its node pair, four sheets,
each named at its box (the default names the pair and the sheet), written
to its `--anchor-out` directory, read back and verified before anything
is printed. `--existing-board` is for an org that already has its board:
the request then makes the node pair alone, two sheets, the org root's
pair being the one that board has. The sheets are filed across the pairs:
each place holds one sheet of each pair, never both sheets of one — the
command says so twice, and says when both sheets of a pair land in one
directory; with `--existing-board` the two new sheets go one to each
place the org root's own sheets already occupy. One device key serves
every board, so the store's own device key is named and no second is
made; `--key` names it where the store holds several, which is otherwise
a halt listing them. A fresh registration over a store that holds none
makes one, under `--label` or the box's answer, after the sheets are
verified. With `--existing-board` none is ever made: the key is taken as
the one the board's own key set holds, which the command says it has not
checked, and a store that holds none halts before anything is asked.
`--label` beside a key that is named is refused. `--anchor-label`,
`--anchor-out` and `--paper` are the backup moment's, four labels and
four directories at most in the order org root a, org root b, node a,
node b, and two, node a and node b, with `--existing-board`. Stdout
carries the request, one line of JSON signed once by the device key — to
pipe, copy or redirect whole, never edited; there is no `--out`. After
it, stderr shows each key's name beside its fingerprint, for the
comparison with whoever approves the request, the fingerprints the
request's thread is found by, and that the request serves its one door
and its sheets belong to that one application: where it ends without an
account they are destroyed and fresh ones made for any other door — with
`--existing-board` the two node sheets alone, never the org root's own.
A run that stops short says what it leaves behind. A person door. And the
registrar's four, over the library's `console` walk and `policy`
composition (REG-4.107, REG-4.131): a registry's door answered by its
registrar, on the registry's own board (`--board`), whose claimant is the
door's account. Each names a request by its LINK ADDRESS, the address of
the link the intake home wrote it under, as `review` prints it. `review`
is the queue read (REG-4.78): the requests a home the door's policy admits
wrote at this door, each judged by the approval's check, read as a guest —
no key, no session, no store — from the board's records alone, writing
nothing. Stdout carries three blocks, each headed by its name and its
count: `WAITING`, the requests no answer stands for; `APPROVED AND NOT
COLLECTED`, the approved requests whose node account has no home page
yet; and `CLOSED`, the refused, the denied and the approved and collected.
Each request is one line — its link address, its kind (`fresh` or
`board-carries-on`), its time in UTC as the board testifies it, where it
stands (`passes`, `fails:` with the fault, or its answer) and `no name
given` — and under it each of its keys, its label beside its fingerprint
in groups, for the comparison with the applicant out of band. Stderr says
the door's identifier, the policy version standing, and each record of a
request's type that is no request. It takes no flag of its own, and is no
person door. `approve <request>` is an officer's approval, at a door whose
policy is `open` admission alone: at `n-vouches` and `invitation-only` it
refuses before any write, naming the mode. The approval's check is run
again on the request. Where it passes, the officer is shown the request's
keys and types the first 8 hex of its device key's fingerprint, and the
approval is written whole and in order — the org's node account, made
from principal 0's signed session, its number written to the key store
first; its first key record, the request's own node record word for
word, from the registrar's own session, and with it the approval link
from that record to the request; the binding of the next prefix to the
account, read back until a guest's resolution finds it; and the approved
answer on the request's thread — each act said on stderr. Where it fails,
the request is answered refused, with its fault (`not-this-door`,
`freshness-spent`, `enrolment-not-honored`), and nothing else is written;
that is exit 0 too. Stdout carries `approved <request>`, then `prefix`,
`account`, `principal` and `answer` lines, or `refused <request>`, then
`fault` and `answer`. A run that stopped part way is resumed by running
it again: every act is found by reading before it is made, and none is
made twice. Two consoles of one registrar — an officer's and the
unattended hand — may take one request at once: the registration is the
first key record by journal order that names the request's node keys, so
the run that finds another's ahead of its own, or finds the thread
answered, sends no answer, retires a prefix it bound, says which on
stderr and prints `yielded <request>` (REG-4.86). A person door. `approve --auto` is the unattended hand (REG-4.108): it
takes no request and answers the whole queue, approving what passes the
check and refusing what fails it, and denies nothing. It runs in the
foreground until SIGINT or SIGTERM, reading the queue every 10 seconds; it
needs no terminal, so it runs in a container, its key the registrar's
labeled device key (`--key`, `SKEP_KEY`, or the store's own lookup) and
its key store the folder it is handed (`--dir`, `SKEP_KEYSTORE`). It
refuses to start unless the policy standing is `open` admission approved
by `auto`, and stops, saying why, when a later version withdraws that. It
catches both signals itself, and each only sets a flag read between two
requests: an approval under way runs to its end, and the process then
exits 0, saying it stopped. A kill inside an act is safe, since every act
resumes by reading. Stdout carries one line an act — `approved <request>
<prefix> <account> <principal> <answer>`, `refused <request> <fault>
<answer>` or `yielded <request>`; a board that does not answer is said
and read again at the next pass. `deny <request> --clause <n>` is an officer's denial (REG-4.99),
at every admission mode and never the unattended hand's: `<n>` is the
position, counted from 1, of a ground in the policy version standing, and
the answer cites that version's address and that position and nothing
else. The officer is shown the clause's words and types the first 8 hex of
the request's device-key fingerprint. A clause past the version's
grounds, an address that names no request on this door's queue, a request
already answered and one whose approval is begun are each refused before
any write, the last two read again after the confirmation. Stdout carries `denied <request>`, then `policy`, `clause` and
`answer` lines. A person door. `set-policy <file>` publishes the door's
policy (REG-4.131): the policy is well-known document 5 of the door's
account, and each version of it one publication. `<file>` is the policy
as every reader parses it, one JSON object in its canonical form of at
most 16 KiB (16,384 bytes); it is read and judged first, ahead of the door
and of any socket, so a file that would stand as no policy — too long, or
one the parser refuses, a trailing newline among its causes — is refused
naming its cause, and nothing is written. The officer is told what the
version says and that a published version is permanent and public, and
types `publish`; the document is created where the door has none, and the
file is published as its next version, its text the file's bytes. Where
the version standing already holds exactly those bytes nothing is
published and nothing is asked, so a run cut after its publication is
answered by the next. Stdout carries `policy <version address>`. A person
door. A door with no policy — document 5 absent, created and holding no
version, or its standing version one the parser refuses — is shut:
`review` says so and lists nothing, and `approve`, `approve --auto` and
`deny` refuse before any write. At `approve`, `deny` and `set-policy` the
principal is the one the board seats at its claimant where `--principal`
is omitted; each approval leaves the new node account's line in the
registrar's key store, so that store's other commands at this board name
`--principal`. Flag
parsing by hand, one file
per command, a `Person` over the terminal, stdout DATA and stderr TALK,
§2.3's exit codes (0 done, 1 the board refused, 2 usage, 3 halt and
surface, 4 transport).

`skep --help` lists each command's flags, and Settings, below, every
value the two programs run with — its variable, its default and where it
is read. The person doors, which refuse without a controlling terminal,
and how the files fit are in the workspace's `ARCHITECTURE.md` §The
command.

Beside it the crate builds `skep-dev`, a dev binary over the same
plumbing with two verbs. `skep-dev seed` dials a RUNNING board the
person started per `RUNBOOK.md` §3 and claimed with `skep claim`, opens
one content-scoped signed session under the person's key, and fills the
board from a git checkout of prose at a pinned commit (`--repo`, or
`SKEP_SEARCH_CORPUS`; `--pin`, by default the search budgets' commit):
the documents `skep-corpus` cuts (`--documents`; `--from` a subtree) as
editions a guest reads, the backticked `.md` cites among them as citation
links — a ghost document where the cited file is outside the set — a
second version of every k-th document (`--versions`; a paragraph
appended, a paragraph removed, a sentence changed, in rotation), drafts
past the tier (`--drafts`) with the first windowed by the first edition,
and a keyless second account with a draft the claimant cannot read. One
JSON object on stdout; a manifest beside the key store
(`<store>-seed/<chain>.jsonl`) makes a second run add nothing and a
killed run resume. The first run fixes the seed: the manifest's header
records the board, the account, the principal, the pin, the cut rule,
`--from` and the three counts, and a later run naming any other is
refused, naming each difference — a different seed takes a fresh board. A
resume makes again the one write the killed run had in flight — an
envelope id holds within one session alone — so a mint or a shot that
had landed lands twice, which the resumed run says as it opens the
manifest; where the board's exact shape matters, seed a fresh board
instead. A run that stops inside a write names it ahead of its halt, and
whether its frame was in flight — its answer never read, or `poisoned`,
which the board's restart may land; the resume names it again as it makes
it, so the two runs' stderr join on its envelope id. A manifest write
that fails — at a full volume — halts showing the lines it would have
appended, whole, and the run after it cuts a torn last line away before
its first record. On stderr the seed
also names the board, the session's principal, account and key — the
fingerprint the board testifies each write by — each stall the board's
`write_busy` puts it through (as it begins, then at most once per ten
seconds), and at its end the frames sent and retried, the commits landed
since the run read its position, and the manifest lines this run
recorded.

`skep-dev serve` is THE DEV PROVIDER: the shell's core (`skep-shell`)
served to a page in a browser over loopback HTTP and server-sent events —
`POST /bridge/<call>` for the forty-four calls of `skep-shell`'s
`CALLS`, `client.md` §4b.1's thirty-two — the publication family's four,
the merge family's four, `history.restore` and `held.show` among them —
the notebook's three acts, `node.start` (the door's act), `node.stop` and
`node.restart`, `publication.standing`, the read
of a draft's standing, `history.past`,
the read of a draft's past state, `places`, the document index's listing,
`text.replace`, the text edit of a draft, `text.edit`, several of them
in one call, `text.move`, whole lines of a draft moved by identity,
`text.mark`, a private copy of a draft's content by identity to diff
against, `text.diff`, what changed in a draft since such a document, told
by identity, and
`changes`, the change feed's page
(`{result}` or `{refused}` back, HTTP 200 either way;
a 4xx is the provider's own refusal), `GET /bridge/events` for every
event of §4b.2 (`event:` and `data:` lines, a `:ka` comment every fifteen
seconds), `POST /bridge/answer` and `/bridge/cancel` for a moment's two
answers, `GET /bridge/log` (every call the page made and every dial the
provider made), `GET /bridge/shapes` (the TypeScript declarations), `POST
/bridge/script` (the next answer of a call armed as a canned result or a
named refusal, served once — `fetch`'s as a refusal alone; an event fired
by hand), and `POST /bridge/fetch`, which streams a blob's bytes. ONE
page origin is admitted (`--page-origin`, required): every request's
`Origin` must equal it, `Host` must name the listen address
(`--listen`), the peer must be loopback, and the per-run secret must ride
the `Skep-Provider` header, or the event stream's URL as
`?provider=<secret>`, since an `EventSource` sends no custom header
(unverified here); the CORS answer names the one origin and never `*`.
The secret is `--secret`, one or more of `A-Z a-z 0-9 - . _ ~` — the
characters the page's URL and header carry unchanged — a fixed one
keeping the page's URL across restarts; else one is generated anew each
run. Either way it is printed once on stdout, its one carrier, no stderr
line naming it; and a command line is visible to every user of this
machine (`ps`), so where others use it, let the provider generate the
secret. The session is `--session bare` as the principal (`--principal`)
on the permissive board — the keyless session, which reads alone: every
write in it is refused `write_in_bare_session` before any dial, and its
held lines wait for a session that writes — or `--session signed` with the
dev key in `--dir`, which writes; `~/.skep` is never consulted, a key file
(`--key`, `SKEP_KEY`) is refused, and a bare run without `--dir` takes a
throwaway directory under the system temp dir. `--script <file>` answers
the SECRET and CONSENT
moments from a script (`skep-shell`'s grammar), read once, at start —
an edit to it takes a restart, as the arm's start line says; absent, the
auto arm answers and says so on stderr. The board is `--board`, a daemon
already running, or — in a build with the `dev-hooks` feature, which no
shipped build enables — `--own --data-dir <dir> [--port <p>]`, the daemon
run in-process with its test hooks and its fault doors at `POST
/bridge/fault/<door>` (`write_busy`, `scan_busy`, `fetch_busy`,
`release`, `refuse_next_head`, `hold_feed_walk`, `release_feed_walk`,
`media_free_space`, `panic_checkpoint_thread`, `halt_writes`, `poison`).
`--own` starts the daemon at launch, a claimed notebook's launch;
`--own --unstarted` leaves it unstarted for the notebook door's act, the
bridge's `node.start`, and a claim's cancel or close stops it again while
its board is unclaimed. Either way the bridge's `node.stop` stops it and
`node.restart` stops it and starts it again — the act that clears a
halted, poisoned or silent notebook — and the shell starts and stops it
through one keeper, every start at the port the first one bound, so the
board's origin stands, and each start and stop said on stderr.
The provider stops cleanly when stdin closes — Ctrl-D at a terminal —
saying why it stopped and what the run came to (the connections accepted,
the refusals by kind; every pending moment cancelled, so a call still
waiting on one answers `abandoned`, sessions closed, the index saved — the
stop's seconds once it completes — the in-process daemon stopped, the
throwaway store removed), exit 0; an interrupt (Ctrl-C) ends it with
none of that: its sessions live at the board until it restarts, and a
throwaway store stays in place. Exit 2 is usage, exit 3 a halt before
serving. A request the provider refuses itself — a page from another
origin, a wrong host, no secret — is said on its stderr the first time
each kind is met, with the route it was met at, since a browser shows the
page an origin refusal only as a CORS failure, and every one is counted
to the stop.

The twenty-five commands stand: the dev binary is no command of `skep`, and
the sidecar image, built `--no-default-features --bin skep`, holds none of
it and no `skepd` (the default build neither: `dev-hooks` alone links the
daemon, which `scripts/gate-full.sh`'s isolation line and
`tests/it/serve.rs` hold).

## Settings

Every value the two programs run with, each read once per run: a change
takes the next run, and nothing re-reads one mid-run. A flag beats its
variable; a variable set empty is unset, and one whose value is not UTF-8
text is refused; a flag given an empty value, or another flag where its
value stands, is refused. Each refusal is exit 2, before any socket opens.
`src/args.rs`'s unit tests hold every flag below to the grammar that takes
it and every default to its constant, and `tests/it/tidy.rs` holds every
variable the source reads to a row here.

### `skep`

| setting | variable | default | checked | read at | what it sets |
|---|---|---|---|---|---|
| `--board` | `SKEP_BOARD` | none | a canonical origin, as the command reads it | every command but `keygen`, `fingerprint`, `register`, which reads no board, and `resolve`, whose registry is the root hint's; asked at `accept` where absent | the board; the store keys each binding by the origin as written, so `localhost` is another board than `127.0.0.1` |
| `--dir` | `SKEP_KEYSTORE` | `~/.skep`, under `HOME`, else `USERPROFILE` | the home an absolute path, else refused | every command but `health`, `hint`, `review`, `claim --hosted` and `session --close` | the key store: `keys/` (each file 0600, the directory 0700), `bindings` and `lock`; `resolve`'s registry mirror in `registry/<genesis>/` under it (the directories 0700, `feed.jsonl`, `fetched.jsonl` and `lock` 0600), which no reader of the store's keys or bindings opens; `skep-dev seed`'s manifest in `<store>-seed/` beside it |
| `--key` | `SKEP_KEY` | none | the file, as the command reads it; an anchor's file refused where the key signs | `session`, `verify`, `bind`, `fingerprint`, `merge`, `share`, `restore`, `deposit`, `register`, `approve`, `deny`, `set-policy`, `accept --reprint`; refused at `enroll`, `retire` and `hire` | one key file, bypassing the store's lookup; at `fingerprint`, the one key listed; at `register`, the device key the request is signed by, where the store holds several; at `approve --auto`, the registrar's labeled device key the unattended hand signs with |
| `--principal` | `SKEP_PRINCIPAL` (`skep-mcp` reads it too) | the store's one binding at the board; at `bind`, the reply's; at `claim`, `1`; at `deposit`, the one the board seats at `--account`; at `approve`, `deny` and `set-policy`, the one the board seats at its claimant | an integer from 0 to 2^53 − 1, as the command reads it | `session`, `verify`, `enroll`, `recover`, `retire`, `rotate`, `handoff`, `hire`, `merge`, `share`, `restore`, `bind`, `claim`, `deposit`, `approve`, `deny`, `set-policy` | the principal; at `claim`, the new account's id; at `hire`, the owner's, never the agent's, which the command prints |
| `--json` | — | off | — | `verify`, `health`, `fingerprint`, `resolve`; at `merge`, `share` and `restore` the answer is one JSON document always, and the flag changes nothing; at `hint` the answer is the one line always | one JSON document on stdout |
| `--root-hint` | `SKEP_ROOT_HINT` | none: required at `resolve` (the hint a build ships with is decided at launch, REG-3.72) | one root-hint line as the resolver reads it — one or more canonical origins, `realm:<64 hex>`, and on a forked lineage `fork:<address>` — before any socket opens and before the mirror's directory is made | `resolve` | the registry an address is resolved through: its roots in the order they are tried, and its realm (REG-3.2); the line `skep hint` prints |
| `--kind` | `SKEP_MERGE_KIND` | none: required at `merge` | an address, as the command reads it, before any socket opens | `merge` | the merge record kind's type address — the kind's commons row is interim and unpinned (the merge record's decision 9), so the caller names it |
| — | `SKEP_SESSION` | none | a session token, 32 lowercase hex | `session --close -` alone; never at `merge`, `share` or `restore`, whose sessions are their own — a token cannot sign the shot or the grant, nor name the account the restore's reads judge by | the token to end; stdin is then not read |
| — | `HOME`, else `USERPROFILE` | — | an absolute path | where `--dir` and `SKEP_KEYSTORE` are absent | where the default store lives |
| — | `COMPUTERNAME`, `HOSTNAME` | `this-machine` | — | at an anchor's name box | the box's default name, beside today's date: the first that answers of the two, `/etc/hostname` and `hostname` on `PATH`, cut at its first dot and lowercased |

`--version`'s commit is the build's `SKEP_GIT_SHA`, compiled in:
`unknown` where the build set none, as a developer's own `cargo build`
does; `scripts/release-pack.sh` sets it for a release, and the
Dockerfile's builder from its `REVISION` build argument. `tls` is on by
default; the sidecar image builds `--no-default-features --bin skep`
without it, and an `https://` board is then a transport halt that names
the feature.

### `skep-dev`

| setting | variable | default | checked | read at | what it sets |
|---|---|---|---|---|---|
| `--board` | `SKEP_BOARD` | none | a canonical origin, before any socket opens | `seed`; `serve` without `--own` | the board dialed |
| `--dir` | `SKEP_KEYSTORE` | at `seed`, `~/.skep`; at `serve`, none — required under `--session signed`, else a throwaway under the system temp dir, removed at the clean stop | as `skep`'s | `seed`, `serve` | the key store; at `seed`, its manifest beside it |
| `--key` | `SKEP_KEY` | none | the file, an anchor's refused | `seed`; refused at `serve` | one key file, bypassing the store's lookup |
| `--principal` | `SKEP_PRINCIPAL` | at `seed`, the store's one binding at the board; at `serve`, `1` | an integer from 0 to 2^53 − 1 | `seed`, `serve` | the principal the session opens as |
| `--repo` | `SKEP_SEARCH_CORPUS` (`skep-search`'s budgets read it too) | none: required | a directory, then the corpus readable at the pin, before any socket opens | `seed`, through `git` on `PATH` | the checkout the corpus is cut from |
| `--pin` | — | `b17656e9` | the corpus readable at it | `seed` | the commit read |
| `--from` | — | the whole set (`cut-v1`) | — | `seed` | a subtree the cut reads alone, the rule then `cut-v2` |
| `--documents` | — | `1000` | a count of at least one | `seed` | the documents cut as editions |
| `--versions` | — | `20` | a count of at least one | `seed` | a second version of every k-th document |
| `--drafts` | — | `10` | a count of at least one | `seed` | the drafts past the tier, the first windowed |
| `--page-origin` | — | none: required | a canonical origin | `serve` | the one page origin admitted |
| `--session` | — | none: required | `bare` or `signed` | `serve` | the session mode |
| `--listen` | — | `8742` | a port from 1 to 65535 | `serve` | the provider's loopback port |
| `--secret` | — | one generated anew each run | one or more of `A-Z a-z 0-9 - . _ ~` | `serve` | the admission secret |
| `--script` | — | the auto arm | read and parsed once, at start | `serve` | the dev arm's answers |
| `--own` | — | off | a `dev-hooks` build; never beside `--board` | `serve` | the daemon run in-process |
| `--data-dir` | — | none: required with `--own` | — | `serve --own` | the in-process daemon's board directory |
| `--port` | — | `8642`; `0` a free port, named on stderr | a port | `serve --own` | the in-process daemon's port |
| `--no-local-trust` | — | local trust on | — | `serve --own` | local trust off |
| `--unstarted` | — | off: the daemon starts at launch | beside `--own` alone, with a `--port` that names the board before it starts (never `0` or `80`) | `serve --own` | the in-process daemon left unstarted until the bridge's `node.start` |
| — | `TMPDIR` | the system temp dir | — | `serve` without `--dir` | where the throwaway store is made |

Not settings: the pins, carded constants a rebuild alone moves, each
stated once at its home — the payload cap (`MAX_PAYLOAD_BYTES`,
`src/commands.rs`) and the echo bound (`CLIPPED_CHARS`, `src/shared.rs`);
`skep-client`'s dial bounds (`CONNECT_TIMEOUT`, `IO_TIMEOUT`); the seed's
insert frame and its retry (`INSERT_CHUNK`, `WRITE_BUSY_BACKOFF_FIRST`,
`WRITE_BUSY_BACKOFF_CAP`, `WRITE_BUSY_PATIENCE`, `STALL_SAID_EVERY`,
`src/dev/board.rs`); and the provider's socket timeouts, request caps and
keep-alive (`src/dev/serve/http.rs`), its accept pause (`ACCEPT_PAUSE`,
`src/dev/serve.rs`) and its loopback-only bind.
