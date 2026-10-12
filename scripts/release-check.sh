#!/usr/bin/env bash
# release-check — A DOWNLOAD, CHECKED: one release archive against the
# SHA256SUMS file the release page carries; then the archive opened in a
# temporary directory and its four binaries run — `--version` from each —
# held to ONE version and ONE commit, the version being the one the
# archive's own name carries. The person's one command on a download; the
# pack script's last step against its own output; each release job's, per
# platform.
#
#   scripts/release-check.sh ARCHIVE SHA256SUMS
#
# ARCHIVE is the path of a skep-<version>-<triple>.tar.gz; SHA256SUMS a
# path, or an https:// URL where curl is on PATH (the release page's file —
# without curl, download it and pass the path). Needs bash, tar, and
# sha256sum or shasum, and nothing of the repository: a person without a
# checkout runs this file alone. Prints what each step found; exit 0 only
# when every line agrees, else the first disagreement named and exit 1
# (2 for a usage error).
set -uo pipefail

pass() { printf 'PASS     %s\n' "$*"; }
fail() { printf 'FAIL     %s\n' "$*" >&2; exit 1; }

[ $# -eq 2 ] || { echo "usage: scripts/release-check.sh ARCHIVE SHA256SUMS" >&2; exit 2; }
ARCHIVE=$1
SUMS=$2
[ -f "$ARCHIVE" ] || fail "no archive at $ARCHIVE"
NAME=$(basename "$ARCHIVE")
STEM=${NAME%.tar.gz}
[ "$STEM" != "$NAME" ] || fail "$NAME is not a .tar.gz"
case $STEM in
  skep-*-*) ;;
  *) fail "$NAME is not named skep-<version>-<triple>.tar.gz" ;;
esac

TMP=$(mktemp -d) || exit 1
trap 'rm -rf "$TMP"' EXIT

# SHA256SUMS: a path, or a URL fetched with curl where curl exists.
case $SUMS in
  http://*|https://*)
    command -v curl >/dev/null 2>&1 || fail "SHA256SUMS is a URL and curl is not on PATH: download it and pass its path"
    curl -fsSL "$SUMS" -o "$TMP/SHA256SUMS" || fail "could not download $SUMS"
    SUMS="$TMP/SHA256SUMS"
    ;;
esac
[ -f "$SUMS" ] || fail "no SHA256SUMS at $SUMS"

# The checksum tool, detected and never assumed: sha256sum (coreutils)
# where it is, else shasum (perl, on every macOS).
if command -v sha256sum >/dev/null 2>&1; then
  SUM="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SUM="shasum -a 256"
else
  fail "neither sha256sum nor shasum is on PATH"
fi

# THE ARCHIVE's LINE in SHA256SUMS — `<hex>  <name>`, or `<hex> *<name>` in
# the binary-mode spelling — compared to the file's own hash, both printed
# where they differ. A file naming this archive twice with two hashes is
# refused: it says two things.
EXPECTED=$(awk -v n="$NAME" '{ f = $2; sub(/^\*/, "", f); if (f == n) print $1 }' "$SUMS" | sort -u)
[ -n "$EXPECTED" ] || fail "SHA256SUMS has no line for $NAME"
[ "$(printf '%s\n' "$EXPECTED" | wc -l | tr -d ' ')" -eq 1 ] || fail "SHA256SUMS carries different hashes for $NAME"
ACTUAL=$($SUM "$ARCHIVE" | awk '{ print $1 }')
[ -n "$ACTUAL" ] || fail "$SUM gave no hash for $ARCHIVE"
[ "$ACTUAL" = "$EXPECTED" ] || fail "checksum mismatch for $NAME: SHA256SUMS says $EXPECTED, the file hashes to $ACTUAL"
pass "$NAME hashes to $ACTUAL, the SHA256SUMS line"

# UNPACKED to the temporary directory: the one top-level directory is the
# archive's own name, which a renamed archive fails.
tar -xzf "$ARCHIVE" -C "$TMP" || fail "could not unpack $NAME"
[ -d "$TMP/$STEM" ] || fail "$NAME does not unpack to a directory named $STEM"

# THE FOUR, each run: `<binary> <version> (<commit>)` on stdout, exit 0,
# the name its own, and every line's version and commit the first line's.
# A commit of `unknown` is a build that set no SKEP_GIT_SHA, which no
# release build is.
VERSION=""
COMMIT=""
for b in skepd skep skep-mcp skep-provision; do
  bin="$TMP/$STEM/$b"
  [ -x "$bin" ] || fail "$STEM holds no executable $b"
  if ! line=$("$bin" --version 2>"$TMP/stderr"); then
    fail "$b --version did not exit 0: $(cat "$TMP/stderr")"
  fi
  [[ "$line" =~ ^([^[:space:]]+)\ ([^[:space:]]+)\ \((.+)\)$ ]] || fail "$b --version answered '$line', not '<binary> <version> (<commit>)'"
  name=${BASH_REMATCH[1]}
  v=${BASH_REMATCH[2]}
  c=${BASH_REMATCH[3]}
  [ "$name" = "$b" ] || fail "$b names itself '$name'"
  if [ -z "$VERSION" ]; then
    VERSION=$v
    COMMIT=$c
  fi
  [ "$v" = "$VERSION" ] || fail "$b is version $v where skepd is version $VERSION"
  [ "$c" = "$COMMIT" ] || fail "$b was built from commit $c where skepd was built from $COMMIT"
  pass "$line"
done
[ "$COMMIT" != "unknown" ] || fail "the binaries name no commit: built with SKEP_GIT_SHA unset"

# THE NAME: the archive is named for the version its binaries carry.
case $STEM in
  "skep-$VERSION-"*) pass "$NAME is named for version $VERSION, the binaries' own" ;;
  *) fail "$NAME is not named for version $VERSION, which its binaries carry" ;;
esac

pass "$NAME: version $VERSION, commit $COMMIT, four binaries agreeing"
