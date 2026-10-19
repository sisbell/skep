# skep-corpus

The prose corpus a dev board is seeded from and the search budgets are
measured over: a git repository read at one pinned commit through `git`
alone, and the one deterministic rule that cuts its prose into documents
of 1–10 KiB.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **The records tier**, `in_tier` — every file tracked at the pin whose
  basename is not `_context.*` and whose extension is not an image's or a
  video's; `Corpus::tier` lists it with sizes, `Corpus::records` reads it
  as one document per file. The set the search index's ceiling was sized
  on (`search.md` §7.3).
- **The cut**, `Corpus::cut` — `cut-v1`: the tier's `.md` files in
  `ls-tree` order, split at blank lines into paragraphs, each capped at
  8 KiB on a character boundary, joined in order into documents whose
  targets cycle through 1..10 KiB and never pass 10 KiB. Deterministic:
  every run cuts the same documents, and the first `n` of any cut are the
  first `n` of every longer one.
- **The subtree**, `Corpus::under` — `cut-v2`: the same rule with the
  paragraph source restricted to the `.md` files under one path, so a
  caller can put a chosen part of the prose in the first documents. The
  rule's name follows the source, so a cache keyed by it never mixes the
  two.
- **The sources**, `Corpus::cut_sourced` — each cut document with the
  paragraphs it was joined from: the file each came from, its byte range
  in the document, and the heading it opens where it is one. What the dev
  board's seeding tool reads to anchor a citation's link, choose a
  version's paragraph and send a cited section to the document holding
  it.

The repository's path and the pin are the callers' — the budgets suite
reads its `SKEP_SEARCH_CORPUS`, the seeding tool its `--repo` and `--pin`
— and the crate reads no environment variable of its own. Every `git` it
runs starts without the repository-local variables git lists
(`GIT_LOCAL_VARIABLES`: `GIT_DIR` and its kin, which a hook exports and
`git -C` does not override), so the repository read is the one handed
in; `Corpus::open` judges the repository, then the pin, before anything
is read. It reads the pin, never the working tree (`git ls-tree` for the
tier, `git cat-file --batch` for the bytes), copies nothing of the
repository anywhere, and depends on nothing but `std` and a `git` on the
path. Every failure is an `Error` a caller renders. The rules that hold
across its files are in the workspace's `ARCHITECTURE.md` §The corpus
crate.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
