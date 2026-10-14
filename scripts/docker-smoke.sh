#!/usr/bin/env bash
# docker-smoke — THE HOSTED IMAGE's PROOF ON ONE MACHINE, run by hand and
# never by a gate: the gate of record is `cargo nextest` (gate-full.sh), and
# Docker is no part of it. This script builds the three targets of the one
# Dockerfile, runs the image the way the README's operator section runs it,
# and asserts what the sealed rules say a published port gives and
# withholds — every assertion is a rule's own, cited where it is made.
#
# THE ORACLE (the rerun record's §6.1): on an UNCLAIMED board a bare
# `POST /session {"principal":0}` with no Origin header answers 200 iff the
# daemon saw a LOOPBACK peer — `bare_bind_allowed` (AUTH-4.26) reduces to
# `peer.is_loopback()` there, the peer read off the socket at accept
# (AUTH-4.14). So a 401 through the published port proves the port is a
# Remote peer (row A1), a 200 from a sidecar inside the container's network
# namespace proves the same rule's other reading (row A2), and a 401 after
# the claim proves ENFORCING (row A3). FAIL rule: any published or proxied
# position answering 200 — the runtime made the peer look loopback, and the
# image must not be exposed on it.
#
#   scripts/docker-smoke.sh [IMAGE] [CLI_IMAGE]
#
# IMAGE is the release tag (default skep-hosted; the debug tag is
# IMAGE:debug, so pass a bare repository name); CLI_IMAGE the sidecar's
# (default skep-cli). Everything this script makes is named skep-smoke-*
# and removed on every exit path; the one host port it publishes is on
# 127.0.0.1; it touches no container, volume or image it did not make. It
# needs docker, curl, jq, git, sed and cargo (the claim's payload is made on
# the host by the `skep` command, as a person makes it on their device).
# PASS/FAIL per step; exit 0 only with no FAIL. The cells this machine
# cannot settle are printed as TO TEST at the end, never asserted.
set -uo pipefail
cd "$(dirname "$0")/.."

IMAGE="${1:-skep-hosted}"
DEBUG_IMAGE="${IMAGE}:debug"
CLI_IMAGE="${2:-skep-cli}"
SERVE=skep-smoke-serve   # the serving run: the baked bind, one port published on 127.0.0.1
CLAIM=skep-smoke-claim   # the claim run: loopback-bound, nothing published
PROBE=skep-smoke-probe   # a throwaway debug-tag container for one probe
BIND=skep-smoke-bind     # the refused start over a 0755 bind mount
VOLUME=skep-smoke-vol
WORK=target/skep-smoke   # the host's throwaway: the key store, the payload, the logs
BODY="$WORK/body.json"   # the last answer's body
PORT=""                  # the published host port, chosen below

FAILS=0
pass() { printf 'PASS     %s\n' "$*"; }
fail() { printf 'FAIL     %s\n' "$*"; FAILS=$((FAILS + 1)); }
note() { printf '         %s\n' "$*"; }
to_test() { printf 'TO TEST  %s\n' "$*"; }
# The last body, one line, for a FAIL's record.
body() { tr -d '\n' < "$BODY" 2>/dev/null | head -c 600; echo; }

teardown() {
  docker rm -f "$SERVE" "$CLAIM" "$PROBE" "$BIND" >/dev/null 2>&1
  docker volume rm -f "$VOLUME" >/dev/null 2>&1
}
trap teardown EXIT
teardown # a stale run's leftovers, if any

# ── 0. the preconditions ──────────────────────────────────────────────────
echo "== 0. preconditions"
docker info >/dev/null 2>&1 || { echo "docker does not answer: start the daemon and run this again"; exit 2; }
for tool in curl jq git sed cargo; do
  command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required"; exit 2; }
done
mkdir -p "$WORK"
REVISION=$(git rev-parse HEAD)
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
PLATFORM=$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')
note "images $IMAGE, $DEBUG_IMAGE, $CLI_IMAGE; platform $PLATFORM; revision $REVISION; version $VERSION"

# ── 1. the builds ─────────────────────────────────────────────────────────
# The release tag, the debug tag (the :debug runtime through RUNTIME, read
# off the Dockerfile's own RUNTIME_DEBUG line so the digest is written once)
# and the sidecar target. The version label is the crate's, the revision
# the checkout's.
echo "== 1. build"
build() { # build <tag> <log> <docker build args...>
  local tag="$1" log="$2"; shift 2
  local t0; t0=$(date +%s)
  if docker build -t "$tag" --build-arg REVISION="$REVISION" --build-arg VERSION="$VERSION" "$@" . > "$log" 2>&1; then
    pass "built $tag in $(( $(date +%s) - t0 )) s"
  else
    fail "docker build $tag (the log: $log)"; tail -n 30 "$log"
  fi
}
RUNTIME_DEBUG=$(sed -n 's/^ARG RUNTIME_DEBUG=//p' Dockerfile)
[ -n "$RUNTIME_DEBUG" ] && pass "the Dockerfile names the :debug runtime: ${RUNTIME_DEBUG%%@*}@…${RUNTIME_DEBUG##*sha256:}" || fail "the Dockerfile has no RUNTIME_DEBUG line"
build "$IMAGE" "$WORK/build-release.log"
build "$DEBUG_IMAGE" "$WORK/build-debug.log" --build-arg RUNTIME="$RUNTIME_DEBUG"
build "$CLI_IMAGE" "$WORK/build-cli.log" --target skep-cli
[ "$FAILS" -eq 0 ] || { echo "a build failed; nothing to run"; exit 1; }
label=$(docker inspect -f '{{index .Config.Labels "org.opencontainers.image.version"}}' "$IMAGE")
[ "$label" = "$VERSION" ] && pass "the version label is the crate's ($label)" || fail "the version label is $label, the crate's version $VERSION"
# The binaries name the commit the images were built from, as the revision
# label does: the builder compiles REVISION's first twelve characters in as
# SKEP_GIT_SHA, the length scripts/release-pack.sh names a release by.
COMMIT=${REVISION:0:12}
line=$(docker run --rm "$CLI_IMAGE" skep --version 2>&1)
[ "$line" = "skep $VERSION ($COMMIT)" ] && pass "skep --version in $CLI_IMAGE names the commit ($line)" || fail "skep --version in $CLI_IMAGE answered '$line', not 'skep $VERSION ($COMMIT)'"
line=$(docker run --rm "$IMAGE" --version 2>&1)
[ "$line" = "skepd $VERSION ($COMMIT)" ] && pass "skepd --version in $IMAGE names the commit ($line)" || fail "skepd --version in $IMAGE answered '$line', not 'skepd $VERSION ($COMMIT)'"
for img in "$IMAGE" "$DEBUG_IMAGE" "$CLI_IMAGE"; do
  note "$img: $(docker image inspect -f '{{.Size}}' "$img" | awk '{printf "%.1f MB", $1/1000000}'), user $(docker image inspect -f '{{.Config.User}}' "$img")"
done

# ── the HTTP helpers, against the published port ──────────────────────────
# One request, curl: the status on stdout, the body in $BODY.
http() { # http <method> <path> [json body]
  local method="$1" path="$2" data="${3:-}"
  if [ -n "$data" ]; then
    curl -s -o "$BODY" -w '%{http_code}' --max-time 10 -X "$method" \
      -H 'Content-Type: application/json' --data "$data" "http://127.0.0.1:$PORT$path"
  else
    curl -s -o "$BODY" -w '%{http_code}' --max-time 10 -X "$method" "http://127.0.0.1:$PORT$path"
  fi
}
# The last body against a jq predicate.
expect_json() { # expect_json <description> <jq boolean expression>
  if [ "$(jq -r "$2" "$BODY" 2>/dev/null)" = "true" ]; then pass "$1"; else fail "$1 — the body: $(body)"; fi
}
wait_health() { # the daemon answers GET /health within 60 s (the open takes a moment; the port is bound before it)
  local i
  for i in $(seq 1 120); do
    if [ "$(http GET /health 2>/dev/null)" = "200" ]; then return 0; fi
    sleep 0.5
  done
  return 1
}
# A free port on the host's loopback for the published side: 8642 where it
# is free (the README's rehearsal line, the configured origin then one of
# the bound port's own loopback defaults), else one the OS picks.
pick_port() {
  if ! nc -z -w 1 127.0.0.1 8642 >/dev/null 2>&1; then echo 8642; return; fi
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])' 2>/dev/null || echo 18642
}
# The serving run: the README's run line with the port published on
# 127.0.0.1 and the origin the smoke dials (AUTH-4.8: the origin a signed
# session would sign; this script holds no key and signs nothing, so the
# value only keeps the claim's warning silent).
run_serving() {
  docker run -d --init --name "$SERVE" --read-only --cap-drop ALL --security-opt no-new-privileges \
    --ulimit nofile=1024:1024 -p "127.0.0.1:$PORT:8642" -e "SKEPD_ORIGIN=http://127.0.0.1:$PORT" \
    -v "$VOLUME:/var/lib/skepd" "$IMAGE" >/dev/null
}
# The debug tag's shell over the same volume, one command.
dbg() { docker run --rm -v "$VOLUME:/var/lib/skepd" --entrypoint /busybox/sh "$DEBUG_IMAGE" -c "$1" 2>&1; }

# ── 2. the serving run ────────────────────────────────────────────────────
echo "== 2. the serving run (the baked bind, the port published on 127.0.0.1)"
docker volume create "$VOLUME" >/dev/null
PORT=$(pick_port)
note "the published port is 127.0.0.1:$PORT; the configured origin http://127.0.0.1:$PORT"
run_serving && pass "docker run (the serving run)" || { fail "docker run (the serving run)"; exit 1; }
if wait_health; then pass "GET /health answers 200 through the published port"; else fail "no GET /health within 60 s"; docker logs "$SERVE" 2>&1 | tail -n 20; exit 1; fi

# ── 3. the health answer (wire.md §The other endpoints) ───────────────────
echo "== 3. GET /health on the unclaimed board"
http GET /health >/dev/null
expected_origins=$(jq -cn --arg p "$PORT" '["http://127.0.0.1:8642","http://[::1]:8642","http://localhost:8642",("http://127.0.0.1:" + $p)] | unique')
expect_json "auth.local_trust == false (the baked SKEPD_LOCAL_TRUST=false; AUTH-4.57 pin (i))" '.auth.local_trust == false'
expect_json "auth.claimant == null (unclaimed)" '.auth.claimant == null'
expect_json "auth.origins is the three loopback defaults at 8642 plus the configured origin" "(.auth.origins | sort) == $expected_origins"
expect_json "auth.signed_origins == auth.origins (the bare set, unclaimed)" '.auth.signed_origins == .auth.origins'
expect_json "media.uploads == true (the daemon's default, not baked off)" '.media.uploads == true'
expect_json "writes.halted == false" '.writes.halted == false'
expect_json "chain_head is sixty-four zeros at log_position 0 (a fresh world)" '.chain_head == ("0" * 64) and .log_position == 0'
expect_json "ok == true" '.ok == true'
expect_json "the auth object is its four members and nothing of the bind" '(.auth | keys) == ["claimant","local_trust","origins","signed_origins"]'

# ── 4. the user and the volume (row C), the read-only rootfs, no shell ────
echo "== 4. the user, the volume and the rootfs"
# `docker top` wants a PID column in what it asks ps for; USER renders the
# numeric uid where the image has no passwd entry for it, which is this one.
top=$(docker top "$SERVE" -eo user,pid,comm 2>/dev/null | awk '$3 == "skepd" {print $1}' | sort -u)
[ "$top" = "10001" ] && pass "the serving daemon runs as uid 10001 (docker top)" || fail "docker top shows user '$top' for skepd"
uid=$(dbg 'id -u')
[ "$uid" = "10001" ] && pass "the debug tag's shell runs as uid 10001" || fail "id -u in the debug tag: $uid"
mode=$(dbg 'stat -c "%a %u:%g" /var/lib/skepd/board')
[ "$mode" = "700 10001:10001" ] && pass "/var/lib/skepd/board is 700 10001:10001, created by the daemon one level below the mount" || fail "stat of board/: $mode"
loose=$(dbg 'find /var/lib/skepd/board -type f ! -perm 600; find /var/lib/skepd/board -type d ! -perm 700')
[ -z "$loose" ] && pass "every file under board/ is 600 and every directory 700" || fail "loose entries under board/: $loose"
note "the volume's root: $(dbg 'stat -c "%a %u:%g" /var/lib/skepd') (the image's install -d, as the runtime populated it)"
note "board/ holds: $(dbg 'ls /var/lib/skepd/board' | tr '\n' ' ')"
if docker run --rm --read-only --entrypoint /busybox/sh "$DEBUG_IMAGE" -c 'echo x > /usr/local/bin/x' >/dev/null 2>&1; then
  fail "a write outside the volume succeeded under --read-only"
else
  pass "a write outside the volume fails under --read-only"
fi
if docker run --rm --entrypoint /bin/sh "$IMAGE" -c true >/dev/null 2>&1; then
  fail "the release image has a shell"
else
  pass "the release image has no shell (docker run --entrypoint /bin/sh fails)"
fi

# ── 5. ROW A1 — the published port is a Remote peer ───────────────────────
# (a) The oracle: wire.md §Sessions — every handshake failure of the
#     credential answers the one 401 `{"error":"session_rejected"}`; §HTTP
#     status codes, the 401 row. On an unclaimed board this reduces to the
#     peer's loopback-ness alone (AUTH-4.26), so a 401 IS the proof.
# (b) A guest write: wire.md §Sessions — "write operations are rejected
#     with code `unauthenticated` (permanent)", at HTTP 200.
# (c) A guest read: reads run at guest class; `next_account_prefix` answers
#     `maybe_addr` with `1.0.1` on a board with no residue (wire.md
#     §Namespace; §The claim ceremony and credentials).
# (d) `GET /` and `GET /dump`: wire.md §HTTP status codes, the 404 row —
#     "including `/dump` on a build without `observe` and `/` on a build
#     without `client`" (AUTH-4.57 (e); the build line's --no-default-features).
echo "== 5. row A1: through the published port, unclaimed"
st=$(http POST /session '{"principal":0}')
[ "$st" = "401" ] && expect_json "A1 (a): the oracle answers 401 session_rejected — the published port is a Remote peer" '.error == "session_rejected"' || fail "A1 (a): the oracle answered $st, not 401 — FAIL RULE: the runtime made the peer look loopback — $(body)"
st=$(http POST /op '{"op":"register_node","addr":"1.2"}')
[ "$st" = "200" ] && expect_json "A1 (b): a guest write is rejected unauthenticated (permanent) at HTTP 200" '.resp == "rejected" and .code == "unauthenticated" and .disposition == "permanent"' || fail "A1 (b): POST /op answered $st — $(body)"
st=$(http POST /op '{"op":"next_account_prefix","parent":"1"}')
[ "$st" = "200" ] && expect_json "A1 (c): a guest read answers maybe_addr 1.0.1 (reads are open; no residue)" '.resp == "maybe_addr" and .addr == "1.0.1"' || fail "A1 (c): POST /op answered $st — $(body)"
st=$(http GET /)
[ "$st" = "404" ] && expect_json "A1 (d): GET / is 404 no_such_endpoint (no client in the image)" '.error == "no_such_endpoint"' || fail "A1 (d): GET / answered $st — $(body)"
st=$(http GET /dump)
[ "$st" = "404" ] && expect_json "A1 (d): GET /dump is 404 no_such_endpoint (no observe in the image)" '.error == "no_such_endpoint"' || fail "A1 (d): GET /dump answered $st — $(body)"

# ── 6. THE CLAIM REHEARSAL — rows A2 and A3 ───────────────────────────────
# The payload, made ON THE HOST as a person makes it on their device:
# `skep keygen --payload` prints the one-key record as its first DATA line
# (anchorless — a throwaway board; `--label` answers the device-name box, so
# no terminal is needed; only `--anchors` is a person door). The key store is
# a throwaway under target/.
echo "== 6. the claim rehearsal (rows A2 and A3)"
STORE="$WORK/store"; rm -rf "$STORE"; mkdir -p "$STORE"
if cargo run -q -p skep-cli --bin skep -- keygen --payload --label skep-smoke --dir "$STORE" > "$WORK/keygen.out" 2> "$WORK/keygen.err"; then
  head -n 1 "$WORK/keygen.out" > "$WORK/payload.enroll"
  chmod 644 "$WORK/payload.enroll"
  [ -s "$WORK/payload.enroll" ] && pass "a one-key record made on the host ($(wc -c < "$WORK/payload.enroll" | tr -d ' ') bytes)" || fail "skep keygen printed no record"
else
  fail "skep keygen --payload failed: $(tail -n 3 "$WORK/keygen.err")"
fi
# The serving run stops; the CLAIM RUN starts on the same volume, loopback-
# bound, nothing published (AUTH-4.57 (a), (f): claimed on loopback before
# the override is set, before any party can reach the port).
docker rm -f "$SERVE" >/dev/null 2>&1
docker run -d --init --name "$CLAIM" --read-only --cap-drop ALL --security-opt no-new-privileges \
  --ulimit nofile=1024:1024 -e SKEPD_BIND=127.0.0.1 -e "SKEPD_ORIGIN=http://127.0.0.1:$PORT" \
  -v "$VOLUME:/var/lib/skepd" "$IMAGE" >/dev/null && pass "docker run (the claim run: SKEPD_BIND=127.0.0.1, no port published)" || fail "docker run (the claim run)"
# A probe from INSIDE the claim run's network namespace: the debug tag's
# busybox wget, joined with --network container:<claim run>.
side_wget() { docker run --rm --network "container:$CLAIM" --entrypoint /busybox/wget "$DEBUG_IMAGE" "$@"; }
up=1
for i in $(seq 1 60); do
  if side_wget -q -T 5 -O - http://127.0.0.1:8642/health > "$WORK/side-health.json" 2>/dev/null; then up=0; break; fi
  sleep 1
done
[ "$up" -eq 0 ] && pass "the claim run answers GET /health inside its namespace" || { fail "the claim run never answered inside its namespace"; docker logs "$CLAIM" 2>&1 | tail -n 20; }
# ROW A2: the oracle from inside the namespace answers 200 — a loopback
# peer by construction (the other reading of AUTH-4.26's one rule).
if side_wget -q -T 5 -O - --header='Content-Type: application/json' --post-data='{"principal":0}' \
     http://127.0.0.1:8642/session > "$WORK/side-session.json" 2> "$WORK/side-session.err" \
   && jq -e '.session | type == "string"' "$WORK/side-session.json" >/dev/null 2>&1; then
  pass "A2: the oracle from the sidecar's position answers 200 with a session — a loopback peer by construction"
else
  fail "A2: the oracle from inside the namespace did not answer a session: $(tr -d '\n' < "$WORK/side-session.err" | head -c 300) $(tr -d '\n' < "$WORK/side-session.json" | head -c 300)"
fi
# THE DARK CLAIM: the sidecar in the claim run's namespace, the record on a
# read-only mount (AUTH-5.55 step 8's cascade, every session bare; the
# rerun's §3.1 recipe). Its stdout is DATA: the claimant, the three facts,
# the two acts.
if docker run --rm --network "container:$CLAIM" -v "$PWD/$WORK/payload.enroll:/payload:ro" "$CLI_IMAGE" \
     skep claim --board http://127.0.0.1:8642 --hosted /payload > "$WORK/claim.out" 2> "$WORK/claim.err"; then
  pass "skep claim --hosted exited 0 in the claim run's namespace"
else
  fail "skep claim --hosted failed: $(tail -n 5 "$WORK/claim.err" | tr '\n' ' ')"
fi
for line in "claimant 1.0.1" "account 1.0.1" "principal 1" "origin http://127.0.0.1:8642"; do
  grep -qxF "$line" "$WORK/claim.out" && pass "the claim's stdout carries '$line'" || fail "the claim's stdout lacks '$line': $(tr '\n' '|' < "$WORK/claim.out" | head -c 400)"
done
note "the claim's stderr (the operator's log): $(grep -c . "$WORK/claim.err") lines; the first: $(head -n 1 "$WORK/claim.err" | head -c 160)"
# ROW A2's second half: from a THIRD container on the same bridge, the
# claim run's bridge address refuses — the claim run binds loopback. (macOS
# cannot route to the bridge from the host, so the probe is a container's.)
CLAIM_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CLAIM")
if docker run --rm --name "$PROBE" --entrypoint /busybox/wget "$DEBUG_IMAGE" -q -T 5 -O - "http://$CLAIM_IP:8642/health" > /dev/null 2> "$WORK/probe.err"; then
  fail "A2: the claim run ANSWERED at its bridge address $CLAIM_IP:8642 — it is not loopback-bound"
else
  if grep -qi "refused" "$WORK/probe.err"; then
    pass "A2: connection refused at the claim run's bridge address $CLAIM_IP:8642 (loopback-bound)"
  else
    fail "A2: the probe at $CLAIM_IP:8642 failed otherwise: $(tr -d '\n' < "$WORK/probe.err" | head -c 200)"
  fi
fi
# The claim run stops; the SERVING RUN again, on the baked bind, the same
# volume — the board now claimed, ENFORCING.
docker rm -f "$CLAIM" >/dev/null 2>&1
run_serving && pass "docker run (the serving run again, the baked bind)" || fail "docker run (the serving run again)"
wait_health && pass "GET /health answers again through the published port" || { fail "no GET /health within 60 s after the claim"; docker logs "$SERVE" 2>&1 | tail -n 20; }
# ROW A3: through the published port, claimed and ENFORCING.
echo "== row A3: through the published port, claimed"
st=$(http POST /session '{"principal":0}')
[ "$st" = "401" ] && expect_json "A3: the oracle is STILL 401 session_rejected (ModeRefused: ENFORCING)" '.error == "session_rejected"' || fail "A3: the oracle answered $st — $(body)"
http GET /health >/dev/null
expect_json "A3: auth.claimant == \"1.0.1\"" '.auth.claimant == "1.0.1"'
expect_json "A3: auth.local_trust == false" '.auth.local_trust == false'
expect_json "A3: auth.signed_origins == [the configured origin] alone, once claimed" "(.auth.signed_origins) == [\"http://127.0.0.1:$PORT\"]"
expect_json "A3: auth.origins still carries the bare set (the three defaults ∪ configured)" "(.auth.origins | sort) == $expected_origins"
st=$(http POST /op '{"op":"register_node","addr":"1.2"}')
[ "$st" = "200" ] && expect_json "A3: a guest write is still unauthenticated (permanent)" '.resp == "rejected" and .code == "unauthenticated" and .disposition == "permanent"' || fail "A3: POST /op answered $st — $(body)"
st=$(http GET /)
[ "$st" = "404" ] && expect_json "A3: GET / is still 404 no_such_endpoint" '.error == "no_such_endpoint"' || fail "A3: GET / answered $st — $(body)"

# ── 7. the start line ─────────────────────────────────────────────────────
# The operator stream (stderr) of the serving run: no --node-prefix on the
# alpha's boards, so the start line says a hosted board must supply one —
# EXPECTED, not a failure (the rerun's §6.2); the `auth:` line names the
# baked variable as the flag's source; the serving line (stdout) echoes
# the baked bind.
echo "== 7. the start line"
docker logs "$SERVE" > "$WORK/serve.log" 2>&1
grep -qF "a hosted board must supply one" "$WORK/serve.log" && pass "the start line says 'a hosted board must supply one' (no --node-prefix: expected while the alpha has no registry)" || fail "no 'a hosted board must supply one' line in the serving run's log"
grep -F " auth: " "$WORK/serve.log" | grep -qF "(--local-trust off, SKEPD_LOCAL_TRUST=false)" && pass "the auth: line names SKEPD_LOCAL_TRUST=false as the flag's source" || fail "the auth: line does not name SKEPD_LOCAL_TRUST=false: $(grep -F ' auth: ' "$WORK/serve.log" | head -c 300)"
grep -F " auth: " "$WORK/serve.log" | grep -qF "CLAIMED-ENFORCING" && pass "the auth: line says CLAIMED-ENFORCING" || fail "the auth: line does not say CLAIMED-ENFORCING"
grep -qF "skepd: serving http://0.0.0.0:8642/" "$WORK/serve.log" && pass "the serving line reads http://0.0.0.0:8642/ — the baked bind's one echo" || fail "the serving line does not read http://0.0.0.0:8642/: $(grep -F 'skepd: serving' "$WORK/serve.log" | head -c 200)"
note "the serving run's log: $(grep -c . "$WORK/serve.log") lines, kept at $WORK/serve.log"

# ── 8. row C's second half: a 0755 bind mount is refused with the one line ──
# The daemon refuses at start a data directory with any group or other bit
# set, repairing nothing (RUNBOOK.md Start step 3 item 2; modes.rs). A host
# directory at 0755 mounted AS the data directory must exit 1 with that one
# line — asserted here where the runtime shows the mount's mode as the
# host's, else TO TEST (Docker Desktop's file sharing may re-map modes).
echo "== 8. a 0755 bind mount"
BINDDIR="$WORK/bind-0755"; rm -rf "$BINDDIR"; mkdir -p "$BINDDIR"; chmod 755 "$BINDDIR"
seen=$(docker run --rm -v "$PWD/$BINDDIR:/mnt" --entrypoint /busybox/stat "$DEBUG_IMAGE" -c '%a' /mnt 2>/dev/null)
if [ "$seen" = "755" ]; then
  out=$(docker run --rm --init --name "$BIND" --read-only --cap-drop ALL --security-opt no-new-privileges \
    -v "$PWD/$BINDDIR:/var/lib/skepd/board" -e "SKEPD_ORIGIN=http://127.0.0.1:$PORT" "$IMAGE" 2>&1); code=$?
  want="skepd: the data directory /var/lib/skepd/board is mode 755: other users of this machine can read the board; chmod 700 /var/lib/skepd/board and start again"
  if [ "$code" -eq 1 ] && [ "$out" = "$want" ]; then
    pass "C: a 0755 bind mount as the data directory is refused, exit 1, with the one line"
  else
    fail "C: the 0755 bind mount answered exit $code: $(echo "$out" | head -c 300)"
  fi
else
  to_test "a 0755 bind mount refused with the one line: this runtime shows the mount as mode '$seen', not 755"
fi

# ── 9. the cells this machine cannot settle ───────────────────────────────
echo "== 9. TO TEST (printed, never asserted)"
to_test "Docker Engine on Linux with userland-proxy: false — the published port's peer under the kernel's NAT alone (row A1's other runtime; expect 401)"
to_test "Docker Desktop's host networking (row B3) — a developer's (B) rehearsal, undetermined"
to_test "Podman rootless, pasta and slirp4netns — the port handlers' peer (expect 401 published) and the fresh volume's owner mapping (expect board/ 700 10001:10001)"
to_test "--read-only with no --tmpfs across a long run — the daemon writes nowhere but the data directory (no temp_dir in its crates); a checkpoint, a compaction and a pruner pass under it"
to_test "the linux/amd64 image on the VM — built here under emulation, never run here"

# ── 10. teardown (the trap) and the verdict ───────────────────────────────
echo "== 10. verdict"
if [ "$FAILS" -eq 0 ]; then
  echo "PASS: every asserted step passed on $PLATFORM; the TO TEST cells above are the other machines'"
else
  echo "FAIL: $FAILS step(s) failed on $PLATFORM"
fi
exit "$FAILS"
