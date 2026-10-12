#!/usr/bin/env bash
# release-pack — ONE PLATFORM's RELEASE ARCHIVE, built from the tree it runs
# in: the four binaries a person downloads — `skepd`, `skep`, `skep-mcp` and
# `skep-provision` (the development tools ship to no one, so `skep-dev` stays
# out) — each answering `--version` with the crate version and the commit
# built from, stripped, beside a README and the two license texts, in
# `skep-<version>-<triple>.tar.gz`; the archive's SHA-256 line appended to
# `SHA256SUMS` beside it; and the archive then checked as a download is
# checked (release-check.sh), which is this script's last step. The release
# workflow runs it once per platform on a pushed tag; a person runs it by
# hand for the host.
#
#   scripts/release-pack.sh [TRIPLE] VERSION
#
# TRIPLE is the Rust target triple (aarch64-apple-darwin, …), the host's
# where omitted; VERSION is the release's (0.1.0) and must be the
# workspace's — a tag names the version the crates already carry, never one
# they do not. Everything lands under target/release-pack/. Needs cargo (the
# toolchain rust-toolchain.toml names, which rustup installs on first use),
# git, tar, and sha256sum or shasum. Exit 0 only once the archive is built
# AND checked.
set -uo pipefail
cd "$(dirname "$0")/.."

case $# in
  1) TRIPLE=$(rustc -vV | sed -n 's/^host: //p'); VERSION=$1 ;;
  2) TRIPLE=$1; VERSION=$2 ;;
  *) echo "usage: scripts/release-pack.sh [TRIPLE] VERSION" >&2; exit 2 ;;
esac
[ -n "$TRIPLE" ] || { echo "release-pack: rustc names no host triple" >&2; exit 1; }

# The version must be the workspace's ([workspace.package] in Cargo.toml,
# which every crate inherits): the binaries print that version, the archive
# is named for this one, and the check below holds the two to each other —
# so a version that lies is refused here, before any build is paid for.
WORKSPACE_VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
if [ "$VERSION" != "$WORKSPACE_VERSION" ]; then
  echo "release-pack: version $VERSION is not the workspace's ($WORKSPACE_VERSION in Cargo.toml)" >&2
  exit 1
fi

# THE COMMIT, compiled into each binary's version line through the one
# variable the four parsers read at build time (`option_env!`): the short
# hash of the tree built. A developer's own build sets none and prints
# `unknown`; a release names its commit. A tree with uncommitted changes is
# still named by its commit, without them — said, never refused, so a
# rehearsal on a working tree runs.
SKEP_GIT_SHA=$(git rev-parse --short=12 HEAD) || { echo "release-pack: not a git tree" >&2; exit 1; }
export SKEP_GIT_SHA
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "release-pack: NOTE the tree has uncommitted changes; commit $SKEP_GIT_SHA names it without them" >&2
fi

# STRIPPED by the release profile's own `strip`, set from the environment
# rather than by a line in Cargo.toml: a developer's `cargo build --release`
# stays as it is, no `strip` tool need be on the runner's PATH, and rustc
# strips at link in each platform's own way (on macOS through Apple's
# strip, which keeps the linker's ad-hoc signature valid).
export CARGO_PROFILE_RELEASE_STRIP=symbols

# THE FOUR BUILDS, one per crate and never one `cargo build` for all:
# Cargo unifies features across one build, and `skep` links the signer
# (skep-signature's `sign`, through skep-client's acting half) where the
# daemon's own build holds no signer and only verifies (RUNBOOK.md §3,
# step 1). Each at its default features: `skepd` with `observe` (a notebook
# may want /dump; the hosted image is the `--no-default-features` build,
# the Dockerfile's), `skep` with `tls` (a hosted board is dialed over
# https://), `skep-mcp` as it is, and `skep-provision` with none: its
# `test-hooks` fakes, which only the crate's own tests turn on, are never
# built, so the shipped binary refuses the fake flags as unknown arguments.
# `--bin skep` keeps `skep-dev` out.
build() {
  cargo build --release --target "$TRIPLE" "$@" || { echo "release-pack: cargo build $* failed" >&2; exit 1; }
}
build -p skepd
build -p skep-cli --bin skep
build -p skep-mcp
build -p skep-provision

OUT=target/release-pack
NAME="skep-$VERSION-$TRIPLE"
BIN="target/$TRIPLE/release"
rm -rf "$OUT/$NAME" && mkdir -p "$OUT/$NAME" || exit 1
for b in skepd skep skep-mcp skep-provision; do
  cp "$BIN/$b" "$OUT/$NAME/$b" || { echo "release-pack: no $BIN/$b" >&2; exit 1; }
done
cp LICENSE-MIT LICENSE-APACHE "$OUT/$NAME/" || exit 1

# THE ARCHIVE's README: what the four are, the kept notebook's recipe
# cited to the RUNBOOK and not restated, the Windows sentence, where the
# checksums are, the license line.
cat > "$OUT/$NAME/README" <<EOF
skep $VERSION for $TRIPLE, built from commit $SKEP_GIT_SHA
https://github.com/sisbell/skep

Four binaries:

  skepd     the daemon: one process over one board directory, the board
            served over HTTP on loopback. For a notebook you keep, run it
            as RUNBOOK.md says — Start, step 2, under a service unit from
            section 9 — at https://github.com/sisbell/skep/blob/v$VERSION/RUNBOOK.md
  skep      the command over the daemon: the device key (keygen), the
            claim that makes a board yours, sessions, verify, health,
            bind, and the key ceremonies (enroll, recover, retire, rotate,
            handoff, accept).
  skep-mcp  the MCP adapter: an agent harness on stdio on one side, the
            daemon's HTTP wire on the other.
  skep-provision
            the service behind a hosted board's sign-up: run on a host
            that serves boards for other people, as RUNBOOK.md §10 says —
            never on a notebook.

Each answers --version with this version and commit:
skepd $VERSION ($SKEP_GIT_SHA). There is no Windows archive: skepd does
not build for Windows at this release (the blob store reads the volume's
free space through statvfs, which is Unix-only).

Checksums: the SHA256SUMS file on the release page,
https://github.com/sisbell/skep/releases/tag/v$VERSION, carries this
archive's SHA-256 line; check it with \`sha256sum -c\` or \`shasum -a 256
-c\`, or with scripts/release-check.sh from the repository, which also
runs the four binaries' --version and holds them to one version and one
commit. macOS: these binaries are not signed or notarized, so a copy a
browser downloaded is quarantined and refused at launch — download with
curl, or clear the attribute (xattr -d com.apple.quarantine <file>).

License: MIT OR Apache-2.0, at your option; the texts are LICENSE-MIT and
LICENSE-APACHE beside this file.
EOF

# One tar.gz named for the directory it holds. COPYFILE_DISABLE keeps
# macOS's bsdtar from adding ._* resource-fork entries.
( cd "$OUT" && COPYFILE_DISABLE=1 tar -czf "$NAME.tar.gz" "$NAME" ) || { echo "release-pack: tar failed" >&2; exit 1; }
rm -rf "$OUT/$NAME"

# THE CHECKSUM LINE, `<hex>  <name>`, appended to SHA256SUMS — the tool
# detected, never assumed: sha256sum (coreutils) where it is, else shasum
# (perl, on every macOS). A stale line for this same archive, from an
# earlier run into the same directory, is dropped first, so the file names
# each archive once.
if command -v sha256sum >/dev/null 2>&1; then
  SUM="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SUM="shasum -a 256"
else
  echo "release-pack: neither sha256sum nor shasum is on PATH" >&2; exit 1
fi
if [ -f "$OUT/SHA256SUMS" ]; then
  grep -v " $NAME.tar.gz\$" "$OUT/SHA256SUMS" > "$OUT/SHA256SUMS.new"
  mv "$OUT/SHA256SUMS.new" "$OUT/SHA256SUMS" || exit 1
fi
( cd "$OUT" && $SUM "$NAME.tar.gz" >> SHA256SUMS ) || { echo "release-pack: $SUM failed" >&2; exit 1; }

echo "$OUT/$NAME.tar.gz"
# THE ROUND TRIP: the archive checked exactly as a person checks a download.
scripts/release-check.sh "$OUT/$NAME.tar.gz" "$OUT/SHA256SUMS"
