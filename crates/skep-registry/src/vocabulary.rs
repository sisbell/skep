//! THE VOCABULARY — every link type this build names in the commons, spelled
//! ONCE as one table: each row's path under the ghost home document's type
//! subspace `1.1.0.1.0.1.0.3`, its name, its purpose in a line and the shape
//! of its endsets (commons-seeding §1 to §4; commons-map, the allocation
//! ledger, where the two disagree). The daemon writes one named section and
//! one `defines` link per row into the registry document `1.1.0.1.0.1` at
//! every open — every row on a fresh board, the missing ones on an upgraded
//! or interrupted one — and a client reads a type's name by the `defines`
//! link whose `to` is the type's address, so any board answers "what is
//! `3.13` called?" to a guest.
//!
//! WHAT THE TABLE HOLDS: every address the build pins in code — the
//! credential kinds `3.1` to `3.3`, `replaces` `3.12`, the edition class
//! `3.14`, the journal designation `3.22`, endorse `3.42`, the registry's
//! twelve rows `3.55` to `3.59` as `rows.rs` spells them, the rail record
//! `3.60`, the steward's classification `3.61`, the two media cell kinds
//! `3.88` and `3.89`, the grant `3.90` and the consumption marker `3.91` —
//! the two designations the map pins and no code names yet, the file
//! metadata family's parent `3.27` with its sub-rows `3.27.1` to `3.27.3` and
//! mode's two values, and the tree designation `3.28`; the core set the
//! seeding plan curates (`3.5` to `3.21` with their subtypes, `3.30`, `3.40`
//! to `3.45`, `3.50` the meta-type) with `3.4` correction in the plan's own
//! slot; `3.70` layout, the presentation tier's first; Nelson's literary
//! set `3.100` to `3.105` — title, author, counterpart, quote, jump with its
//! one subtype modal, certification — as Literary Machines 4/52 to 4/55
//! lists them (the owner, 2026-10-21); and the link-sets rows the commons
//! seeding round pinned (the owner, 2026-10-27) — `3.23` inline, the
//! emphasis family's parent, with its seven sub-types `3.23.1` to `3.23.7`,
//! `3.24` the held removal, `3.71` read-with beside layout, and `3.102.1`
//! the correspondence record, a subtype under counterpart. WHAT IT DOES
//! NOT: the reserved ordinals of `3.22` to
//! `3.29` and `3.46` to `3.49` beyond the built ones, `3.51` to `3.54` (the
//! registry-machinery reserve, unallocated), `3.87` (reserved for the proxy
//! kind), the test-only `3.90.1`, and every range the map marks
//! unallocated — nothing is named at an ordinal nobody allocated.
//!
//! THE ENDSETS ARE SAID BY ROLE (the commons map's standing rule THE
//! ENDSETS, BY ROLE — F5, the owner 2026-10-27; the `3.27` family's rule
//! generalized): `from` holds what a link brings of its own — its text or
//! atom, or the account or prefix that speaks; `to` holds what it is about.
//! A link with one side empties the slot it has no content for: a MARK —
//! formatting, a designation, a lifted takedown, a policy link — has an
//! empty `from` and its matter in `to`; a SAYING with no subject — an
//! endpoint, a targetless binding — has an empty `to`. The claim `3.3`
//! stands as built (`from` the claimant, `to` empty), the rule's one named
//! exception. So the heading, the paragraph family, lang, the inline family
//! and the held removal each say "from: empty; to: …", as the `3.27`
//! family already did. A board seeded under an earlier wording keeps its
//! old section text: a reopen writes only the rows it lacks.
//!
//! THE NAMES are the seeding plan's words where the plan has one and the
//! code's doc-comment word where the code names a type the plan does not
//! (the credential kinds, `replaces`, the designations, the records, the
//! cell kinds, the marker); where the two differ the code's wins. A name is
//! one lowercase token — letters, digits and hyphens — so the first line of
//! a section is the name and nothing else, which is what a client shows.
//!
//! THE ORDER is path order, ascending in the tumbler order (T1). The daemon
//! writes the sections and the links in that order with one row taken
//! ahead of the rest: the meta-type `defines` `3.50`, so its own link, typed
//! by itself, stands before any link it types.
//!
//! THE ADDRESSES are spelled through [`commons_type`], the one spelling of
//! the type subspace in this crate: a row is an element at positive
//! ordinals, T4-valid by construction, and the registry's twelve are held
//! equal to [`crate::rows()`]'s by the unit suite beside this file.

use std::sync::LazyLock;

use skep_address::Address;

use crate::rows::commons_type;

/// One type the commons names: a row of [`vocabulary`].
///
/// It is the type's address, the path the address is spelled from, the
/// name a client shows, the purpose in one line and the shape of a link of
/// the type — the four things the daemon writes into the type's section
/// ([`Definition::section`]) and nothing more. The fields are public and
/// the type is `Clone` so a suite can read a row off the table and a
/// reader can carry one; every `&'static Definition` this crate hands out
/// is one of [`vocabulary`]'s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Definition {
    /// The type's address: the ghost home document's subspace-3 element at
    /// the row's ordinals.
    pub address: Address,
    /// The row's path under `1.1.0.1.0.1.0.3`: one ordinal for a type, the
    /// type's then the subtype's for a subtype (`[14, 2]` for `3.14.2`).
    pub ordinals: &'static [u32],
    /// The type's name: one lowercase token.
    pub name: &'static str,
    /// What a link of the type says, in one sentence.
    pub purpose: &'static str,
    /// The shape of a link of the type: what its `from` and `to` name.
    pub endsets: &'static str,
}

impl Definition {
    /// Returns the section the daemon writes for this type.
    ///
    /// It is four lines, each ended by a newline: the name alone on the
    /// first, the type's address on the second, the purpose on the third and
    /// the endset shape on the fourth. A client that retrieves the span a
    /// `defines` link's `from` covers reads the name off the first line;
    /// the daemon finds a section a crash or a refusal left unlinked by
    /// these exact bytes, which no two rows share (the address line is the
    /// row's own).
    pub fn section(&self) -> String {
        format!("{}\n{}\n{}\n{}\n", self.name, self.address, self.purpose, self.endsets)
    }
}

/// The table's spelling of one row — what [`vocabulary`] builds a
/// [`Definition`] from.
struct Spelling {
    ordinals: &'static [u32],
    name: &'static str,
    purpose: &'static str,
    endsets: &'static str,
}

/// The rows, in path order.
const SPELLINGS: [Spelling; 119] = [
    // ── the credential kinds (AUTH-7.1 horn B) ───────────────────────────
    Spelling {
        ordinals: &[1],
        name: "enroll",
        purpose: "An enrollment record: the keys enrolled for an account, deposited into a \
                  doc 1 — the account's own for a holder's act, its delegator's for the first \
                  seeding.",
        endsets: "from: the record's positions in the home's own space; to: the subject account.",
    },
    Spelling {
        ordinals: &[2],
        name: "retire",
        purpose: "A retirement record: the keys retired from an account, deposited into the \
                  account's own doc 1 and no other.",
        endsets: "from: the record's positions in the home's own space; to: the subject account.",
    },
    Spelling {
        ordinals: &[3],
        name: "claim",
        purpose: "The board's claim: the first top-level account with a key set claims the \
                  board, once and permanently.",
        endsets: "from: the claiming account; to: empty.",
    },
    // ── the core set (commons-seeding §3); 3.4 the plan's own slot for correction ──
    Spelling {
        ordinals: &[4],
        name: "correction",
        purpose: "A correction, supplied by anyone to anything, saving a whole new alternative version (LM 4/53).",
        endsets: "from: the correction's text; to: the passage corrected.",
    },
    Spelling {
        ordinals: &[5],
        name: "comment",
        purpose: "A comment on a passage.",
        endsets: "from: the comment's text; to: the passage commented on.",
    },
    Spelling {
        ordinals: &[5, 1],
        name: "question",
        purpose: "A comment that asks a question of a passage.",
        endsets: "from: the question's text; to: the passage asked about.",
    },
    Spelling {
        ordinals: &[5, 2],
        name: "answer",
        purpose: "A comment that answers a question.",
        endsets: "from: the answer's text; to: the question answered.",
    },
    Spelling {
        ordinals: &[5, 3],
        name: "suggestion",
        purpose: "A comment that suggests a change to a passage.",
        endsets: "from: the suggestion's text; to: the passage it would change.",
    },
    Spelling {
        ordinals: &[5, 4],
        name: "note",
        purpose: "A comment that notes something about a passage.",
        endsets: "from: the note's text; to: the passage noted.",
    },
    Spelling {
        ordinals: &[5, 5],
        name: "criticism",
        purpose: "A comment that criticizes a passage.",
        endsets: "from: the criticism's text; to: the passage criticized.",
    },
    Spelling {
        ordinals: &[5, 6],
        name: "support",
        purpose: "A comment that supports a passage.",
        endsets: "from: the supporting text; to: the passage supported.",
    },
    Spelling {
        ordinals: &[5, 7],
        name: "clarification",
        purpose: "A comment that clarifies a passage.",
        endsets: "from: the clarifying text; to: the passage clarified.",
    },
    Spelling {
        ordinals: &[5, 8],
        name: "analysis",
        purpose: "A comment that analyzes a passage.",
        endsets: "from: the analysis; to: the passage analyzed.",
    },
    Spelling {
        ordinals: &[5, 9],
        name: "review",
        purpose: "A comment that reviews a passage or a document.",
        endsets: "from: the review's text; to: the passage or document reviewed.",
    },
    Spelling {
        ordinals: &[5, 10],
        name: "rebuttal",
        purpose: "A comment that rebuts a passage.",
        endsets: "from: the rebuttal's text; to: the passage rebutted.",
    },
    Spelling {
        ordinals: &[6],
        name: "footnote",
        purpose: "A footnote: a note set apart from the passage it annotates.",
        endsets: "from: the note's text; to: the passage annotated.",
    },
    Spelling {
        ordinals: &[6, 1],
        name: "end",
        purpose: "A footnote placed at the end of the text.",
        endsets: "from: the note's text; to: the passage annotated.",
    },
    Spelling {
        ordinals: &[6, 2],
        name: "margin",
        purpose: "A footnote placed in the margin beside its passage.",
        endsets: "from: the note's text; to: the passage annotated.",
    },
    Spelling {
        ordinals: &[6, 3],
        name: "popup",
        purpose: "A footnote shown on demand, over its passage.",
        endsets: "from: the note's text; to: the passage annotated.",
    },
    Spelling {
        ordinals: &[7],
        name: "memo",
        purpose: "A memo about a passage or a document.",
        endsets: "from: the memo's text; to: what the memo is about.",
    },
    Spelling {
        ordinals: &[8],
        name: "translation",
        purpose: "A translation of a passage into another language.",
        endsets: "from: the translated text; to: the original.",
    },
    Spelling {
        ordinals: &[9],
        name: "alternative",
        purpose: "An alternative to a passage: another text that stands in its place.",
        endsets: "from: the alternative text; to: the passage it stands in for.",
    },
    Spelling {
        ordinals: &[9, 1],
        name: "draft",
        purpose: "An alternative that is a draft of the passage.",
        endsets: "from: the draft's text; to: the passage drafted.",
    },
    Spelling {
        ordinals: &[9, 2],
        name: "revision",
        purpose: "An alternative that revises the passage.",
        endsets: "from: the revised text; to: the passage revised.",
    },
    Spelling {
        ordinals: &[9, 3],
        name: "branch",
        purpose: "An alternative that branches from the passage.",
        endsets: "from: the branch's text; to: the passage branched from.",
    },
    Spelling {
        ordinals: &[10],
        name: "expansion",
        purpose: "An expansion of a passage: more where the passage says less.",
        endsets: "from: the expanded text; to: the passage expanded.",
    },
    Spelling {
        ordinals: &[10, 1],
        name: "detail",
        purpose: "An expansion that gives the passage's detail.",
        endsets: "from: the detail's text; to: the passage detailed.",
    },
    Spelling {
        ordinals: &[10, 2],
        name: "definition",
        purpose: "An expansion that defines a term the passage uses.",
        endsets: "from: the definition's text; to: the term defined.",
    },
    Spelling {
        ordinals: &[10, 3],
        name: "full",
        purpose: "An expansion that gives the passage in full.",
        endsets: "from: the full text; to: the passage it fills out.",
    },
    Spelling {
        ordinals: &[10, 4],
        name: "zoom",
        purpose: "An expansion that zooms into a part of the passage.",
        endsets: "from: the zoomed text; to: the part zoomed into.",
    },
    Spelling {
        ordinals: &[11],
        name: "threading",
        purpose: "A thread: the next item of a trail through the docuverse.",
        endsets: "from: the next item; to: the item before it.",
    },
    Spelling {
        ordinals: &[12],
        name: "replaces",
        purpose: "The authority successor: a record replaces the state it names, minted \
                  beside the record in one transaction.",
        endsets: "from: the replacing record; to: the address of the state it replaces.",
    },
    Spelling {
        ordinals: &[13],
        name: "citation",
        purpose: "A citation: a passage cites another.",
        endsets: "from: the citing passage; to: the passage cited.",
    },
    Spelling {
        ordinals: &[14],
        name: "edition",
        purpose: "An edition relation: a document is an edition of another, read by the \
                  audit-view edition-claim lookup with its subtypes.",
        endsets: "from: the edition; to: the document, or a version of it, that it is an \
                  edition of.",
    },
    Spelling {
        ordinals: &[14, 1],
        name: "abridged",
        purpose: "An edition that abridges its original.",
        endsets: "from: the abridged edition; to: the document abridged.",
    },
    Spelling {
        ordinals: &[14, 2],
        name: "expanded",
        purpose: "An edition that expands its original.",
        endsets: "from: the expanded edition; to: the document expanded.",
    },
    Spelling {
        ordinals: &[14, 3],
        name: "translated",
        purpose: "An edition that translates its original.",
        endsets: "from: the translated edition; to: the document translated.",
    },
    Spelling {
        ordinals: &[14, 4],
        name: "revised",
        purpose: "An edition that revises its original.",
        endsets: "from: the revised edition; to: the document revised.",
    },
    Spelling {
        ordinals: &[14, 5],
        name: "annotated",
        purpose: "An edition that annotates its original.",
        endsets: "from: the annotated edition; to: the document annotated.",
    },
    Spelling {
        ordinals: &[15],
        name: "mail",
        purpose: "Mail: a message sent to an account.",
        endsets: "from: the message's text; to: the recipient account.",
    },
    Spelling {
        ordinals: &[15, 1],
        name: "urgent",
        purpose: "Mail marked urgent.",
        endsets: "from: the message's text; to: the recipient account.",
    },
    Spelling {
        ordinals: &[15, 2],
        name: "invitation",
        purpose: "Mail that invites its recipient.",
        endsets: "from: the invitation's text; to: the recipient account.",
    },
    Spelling {
        ordinals: &[15, 3],
        name: "request",
        purpose: "Mail that asks something of its recipient.",
        endsets: "from: the request's text; to: the recipient account.",
    },
    Spelling {
        ordinals: &[15, 4],
        name: "broadcast",
        purpose: "Mail sent to many recipients at once.",
        endsets: "from: the message's text; to: the recipient accounts.",
    },
    Spelling {
        ordinals: &[16],
        name: "mention",
        purpose: "A mention of an account or a document in a passage.",
        endsets: "from: the mentioning passage; to: the account or document mentioned.",
    },
    Spelling {
        ordinals: &[17],
        name: "dedication",
        purpose: "A dedication of a work to an account.",
        endsets: "from: the dedicated work; to: the account it is dedicated to.",
    },
    Spelling {
        ordinals: &[18],
        name: "assignment",
        purpose: "An assignment of material to an account.",
        endsets: "from: the material assigned; to: the assignee account.",
    },
    Spelling {
        ordinals: &[18, 1],
        name: "review",
        purpose: "An assignment to review the material.",
        endsets: "from: the material to review; to: the reviewer's account.",
    },
    Spelling {
        ordinals: &[18, 2],
        name: "task",
        purpose: "An assignment of a task.",
        endsets: "from: the task's material; to: the account assigned.",
    },
    Spelling {
        ordinals: &[18, 3],
        name: "approval",
        purpose: "An assignment to approve the material.",
        endsets: "from: the material to approve; to: the approver's account.",
    },
    Spelling {
        ordinals: &[19],
        name: "acknowledgment",
        purpose: "An acknowledgment of an account's part in a work.",
        endsets: "from: the acknowledging passage; to: the account acknowledged.",
    },
    Spelling {
        ordinals: &[20],
        name: "heading",
        purpose: "A heading over a passage; its level rides as a parameter span.",
        endsets: "from: empty; to: the heading's text; its level a parameter span in the type slot.",
    },
    Spelling {
        ordinals: &[21],
        name: "paragraph",
        purpose: "A paragraph: a run of text classed as one unit.",
        endsets: "from: empty; to: the paragraph's text.",
    },
    Spelling {
        ordinals: &[21, 1],
        name: "numbered",
        purpose: "A numbered paragraph.",
        endsets: "from: empty; to: the paragraph's text.",
    },
    Spelling {
        ordinals: &[21, 2],
        name: "blockquote",
        purpose: "A paragraph quoted as a block.",
        endsets: "from: empty; to: the quoted text.",
    },
    Spelling {
        ordinals: &[21, 3],
        name: "code",
        purpose: "A paragraph of code, set as written.",
        endsets: "from: empty; to: the code's text.",
    },
    Spelling {
        ordinals: &[21, 4],
        name: "list",
        purpose: "A paragraph that is a list.",
        endsets: "from: empty; to: the list's text.",
    },
    Spelling {
        ordinals: &[21, 5],
        name: "note",
        purpose: "A paragraph set apart as a note.",
        endsets: "from: empty; to: the note's text.",
    },
    Spelling {
        ordinals: &[21, 6],
        name: "definition",
        purpose: "A paragraph that defines a term.",
        endsets: "from: empty; to: the definition's text.",
    },
    Spelling {
        ordinals: &[21, 7],
        name: "example",
        purpose: "A paragraph that gives an example.",
        endsets: "from: empty; to: the example's text.",
    },
    Spelling {
        ordinals: &[21, 8],
        name: "warning",
        purpose: "A paragraph set apart as a warning.",
        endsets: "from: empty; to: the warning's text.",
    },
    // ── the structural extension (3.22–3.29): the built ones — the marks
    //    among them say their endsets by role (the module doc's rule) ──────
    Spelling {
        ordinals: &[22],
        name: "journal-designation",
        purpose: "The journal designation: a typed self-link marking a document as a role's \
                  journal, the consumption journal first.",
        endsets: "from: the journal itself; to: the journal itself; homed in the journal.",
    },
    // The emphasis family (the link-sets rows, pinned 2026-10-27): the
    // catalog's `2.22 inline` restored at a new number, its seven styles the
    // sub-types — the third ruled exception to the parameters rule.
    Spelling {
        ordinals: &[23],
        name: "inline",
        purpose: "The emphasis family's parent: the catalog's inline text styles restored at a \
                  new number, each a style under this one; a link typed at the parent itself is \
                  written by nothing.",
        endsets: "from: empty; to: the span styled.",
    },
    Spelling {
        ordinals: &[23, 1],
        name: "emphasis",
        purpose: "Emphasis (italic): a one-sided mark on the span it styles.",
        endsets: "from: empty; to: the span styled.",
    },
    Spelling {
        ordinals: &[23, 2],
        name: "strong",
        purpose: "Strong (bold): the chord's type, a one-sided mark on the span it styles.",
        endsets: "from: empty; to: the span styled.",
    },
    Spelling {
        ordinals: &[23, 3],
        name: "code",
        purpose: "Inline code: a one-sided mark on the span it styles.",
        endsets: "from: empty; to: the span styled.",
    },
    Spelling {
        ordinals: &[23, 4],
        name: "mark",
        purpose: "Highlighted text: in the family and off the formatting line, offered in its \
                  set's own row.",
        endsets: "from: empty; to: the span styled.",
    },
    Spelling {
        ordinals: &[23, 5],
        name: "strikethrough",
        purpose: "Deleted or struck text: a one-sided mark on the span it styles.",
        endsets: "from: empty; to: the span styled.",
    },
    Spelling {
        ordinals: &[23, 6],
        name: "subscript",
        purpose: "Subscript: a one-sided mark on the span it styles.",
        endsets: "from: empty; to: the span styled.",
    },
    Spelling {
        ordinals: &[23, 7],
        name: "superscript",
        purpose: "Superscript: a one-sided mark on the span it styles.",
        endsets: "from: empty; to: the span styled.",
    },
    Spelling {
        ordinals: &[24],
        name: "held-removal",
        purpose: "The held removal: a published mark taken off in a draft, written at the chord \
                  and retracted at the next publication of its words, its own retraction the \
                  chord's undo; no picker lists it.",
        endsets: "from: empty; to: the published mark, by address.",
    },
    Spelling {
        ordinals: &[27],
        name: "file-metadata",
        purpose: "The file-metadata family's parent: a tree's statements about a document — \
                  its path, its mode, a symlink — each a kind under this one, homed in the \
                  tree; a link typed at the parent itself is written by nothing.",
        endsets: "from: the name's text in the tree's journal, or empty for a bare fact; to: \
                  the document the statement is about.",
    },
    Spelling {
        ordinals: &[27, 1],
        name: "path",
        purpose: "A tree's statement of a document's path.",
        endsets: "from: the path's text in the tree's journal; to: the document.",
    },
    Spelling {
        ordinals: &[27, 2],
        name: "mode",
        purpose: "A tree's statement of a document's mode, the parent of its two values; a link typed at the parent itself is written by nothing.",
        endsets: "from: empty; to: the document.",
    },
    Spelling {
        ordinals: &[27, 2, 1],
        name: "executable",
        purpose: "The mode executable (git 100755).",
        endsets: "from: empty; to: the document.",
    },
    Spelling {
        ordinals: &[27, 2, 2],
        name: "regular",
        purpose: "The mode regular (git 100644), written only to undo executable.",
        endsets: "from: empty; to: the document.",
    },
    Spelling {
        ordinals: &[27, 3],
        name: "symlink",
        purpose: "A tree's statement that a path is a symlink to a target, both texts in the tree's journal.",
        endsets: "from: the symlink's own path text; to: its target's text.",
    },
    Spelling {
        ordinals: &[28],
        name: "tree-designation",
        purpose: "The tree designation: an account's doc 1 names a tree's journal, the \
                  document that holds the tree's snapshots and its file metadata.",
        endsets: "from: the account's doc 1; to: the tree's journal.",
    },
    // ── lang, and the social set (3.40–3.45) ─────────────────────────────
    Spelling {
        ordinals: &[30],
        name: "lang",
        purpose: "The language of a passage; the language code rides as a parameter span.",
        endsets: "from: empty; to: the passage.",
    },
    Spelling {
        ordinals: &[40],
        name: "follow",
        purpose: "An account follows another.",
        endsets: "from: the following account; to: the account followed.",
    },
    Spelling {
        ordinals: &[41],
        name: "block",
        purpose: "An account blocks another.",
        endsets: "from: the blocking account; to: the account blocked.",
    },
    Spelling {
        ordinals: &[42],
        name: "endorse",
        purpose: "An endorsement of an account by another; the succession pair's \
                  endorsement half.",
        endsets: "from: the endorsing account; to: the account endorsed.",
    },
    Spelling {
        ordinals: &[42, 1],
        name: "expertise",
        purpose: "An endorsement of an account's expertise.",
        endsets: "from: the endorsing account; to: the account endorsed.",
    },
    Spelling {
        ordinals: &[42, 2],
        name: "trust",
        purpose: "An endorsement of trust in an account.",
        endsets: "from: the endorsing account; to: the account endorsed.",
    },
    Spelling {
        ordinals: &[42, 3],
        name: "collaboration",
        purpose: "An endorsement of an account as a collaborator.",
        endsets: "from: the endorsing account; to: the account endorsed.",
    },
    Spelling {
        ordinals: &[43],
        name: "like",
        purpose: "An account likes a passage.",
        endsets: "from: the account; to: the passage liked.",
    },
    Spelling {
        ordinals: &[44],
        name: "bookmark",
        purpose: "An account bookmarks a passage.",
        endsets: "from: the account; to: the passage bookmarked.",
    },
    Spelling {
        ordinals: &[44, 1],
        name: "reading-list",
        purpose: "A bookmark on an account's reading list.",
        endsets: "from: the account; to: the passage to read.",
    },
    Spelling {
        ordinals: &[44, 2],
        name: "reference",
        purpose: "A bookmark kept for reference.",
        endsets: "from: the account; to: the passage referred to.",
    },
    Spelling {
        ordinals: &[45],
        name: "tag",
        purpose: "An account tags a passage; the tag's word rides as a parameter span.",
        endsets: "from: the account; to: the passage tagged.",
    },
    // ── the meta-type (3.50) ─────────────────────────────────────────────
    Spelling {
        ordinals: &[50],
        name: "defines",
        purpose: "The meta-type: a section of this registry defines a link type. The first \
                  type seeded, and the type of its own definition.",
        endsets: "from: the type's section in this document; to: the type's address.",
    },
    // ── the registry's twelve rows (REG-1.14, REG-1.15), as rows.rs spells them
    Spelling {
        ordinals: &[55],
        name: "binding",
        purpose: "The binding — the registration record: a registrar binds a prefix to a \
                  node account by a signed deposit into its own doc 1.",
        endsets: "from: the record's atom; to: the account bound, or empty for a targetless \
                  binding.",
    },
    Spelling {
        ordinals: &[56],
        name: "endpoint",
        purpose: "The endpoint: an org's origins, deposited signed into its node account's \
                  doc 1.",
        endsets: "from: the record's atom; to: empty.",
    },
    Spelling {
        ordinals: &[57],
        name: "takedown-record",
        purpose: "The takedown record's kind: the operator's serving-layer instrument, which \
                  reads two ways, each a row under this one; no deposit rides the kind itself.",
        endsets: "from and to: as the two rows under it state.",
    },
    Spelling {
        ordinals: &[57, 1],
        name: "takedown",
        purpose: "The takedown record's own base reading: the instrument itself.",
        endsets: "from: the record's atom; to: as the registry's rules state.",
    },
    Spelling {
        ordinals: &[57, 2],
        name: "lifted",
        purpose: "Lifted: the takedown record's reversal, a link alone.",
        endsets: "from: empty; to: the takedown record lifted.",
    },
    Spelling {
        ordinals: &[58],
        name: "policy-link",
        purpose: "The policy link's kind: the link naming an org's published policy document, \
                  and the records that ride under it, five readings each a row under this \
                  one; no deposit rides the kind itself.",
        endsets: "from and to: as the five rows under it state.",
    },
    Spelling {
        ordinals: &[58, 1],
        name: "policy",
        purpose: "The policy link's own reading: the link itself, naming the published policy \
                  document, a link alone.",
        endsets: "from: empty; to: the policy document.",
    },
    Spelling {
        ordinals: &[58, 2],
        name: "disavowal",
        purpose: "The disavowal, the one type of it: an author's in their own doc 1, or an \
                  officer's at the policy home.",
        endsets: "from: the record's atom; to: as the registry's rules state.",
    },
    Spelling {
        ordinals: &[58, 3],
        name: "expulsion-ground",
        purpose: "An expulsion's ground record.",
        endsets: "from: the record's atom; to: as the registry's rules state.",
    },
    Spelling {
        ordinals: &[58, 4],
        name: "succession-ground",
        purpose: "A succession's ground record.",
        endsets: "from: the record's atom; to: as the registry's rules state.",
    },
    Spelling {
        ordinals: &[58, 5],
        name: "succession-policy",
        purpose: "The org-chosen succession policy.",
        endsets: "from: the record's atom; to: as the registry's rules state.",
    },
    Spelling {
        ordinals: &[59],
        name: "successor-of",
        purpose: "The succession claim at the fork's seat: an account's seat passes to its \
                  successor, a link alone.",
        endsets: "from: the account whose seat passes; to: the account that succeeds it.",
    },
    // ── the agentic tier (3.60–3.69): the built ones ─────────────────────
    Spelling {
        ordinals: &[60],
        name: "rail-record",
        purpose: "The rail record: the hirer's signed record naming a brief and the publish \
                  reach it grants an agent under it.",
        endsets: "from: the agent's account; to: the brief.",
    },
    Spelling {
        ordinals: &[61],
        name: "steward-classification",
        purpose: "The steward's classification: its decision about a document it serves, \
                  homed in its own published doc 1 and reversible by supersession.",
        endsets: "from: the classification's record; to: the document classified.",
    },
    // ── the presentation tier (3.70–3.79): layout (LM 4/54) ─────────────
    Spelling {
        ordinals: &[70],
        name: "layout",
        purpose: "Layout, typography and epigraphy instructions for showing a text — recommendations a reader may ignore (LM 4/54).",
        endsets: "from: the instructions; to: the content they are for.",
    },
    Spelling {
        ordinals: &[71],
        name: "read-with",
        purpose: "Read this document with that set: a reader's instruction, nothing the daemon \
                  checks, one per document and set — from the document to the set, against \
                  the tier's stylesheet-to-content direction.",
        endsets: "from: the document's bare address; to: the set's address.",
    },
    // ── the media range (3.80–3.89): the two cell kinds ──────────────────
    Spelling {
        ordinals: &[88],
        name: "blind-cell",
        purpose: "The blind cell's kind: the type member of a cell standing for a document \
                  whose bytes the board does not hold, a commitment in their place.",
        endsets: "none: a cell's type member, not a link's type.",
    },
    Spelling {
        ordinals: &[89],
        name: "picture-cell",
        purpose: "The picture cell's kind: the type member of a reference cell naming a \
                  picture's bytes by hash and size, which the blob store holds.",
        endsets: "none: a cell's type member, not a link's type.",
    },
    // ── the commerce range (3.90–3.99): the built ones ───────────────────
    Spelling {
        ordinals: &[90],
        name: "grant",
        purpose: "A sharing grant: a content prefix shared with an account, or with any \
                  principal.",
        endsets: "from: the content prefix shared; to: the grantee account, or empty for \
                  any principal.",
    },
    Spelling {
        ordinals: &[91],
        name: "consumption-marker",
        purpose: "The consumption marker: the owner's accepted or declined exit from an \
                  offer, the value a parameter and never a subtype.",
        endsets: "from: the value, offer_accepted or offer_declined; to: the offer link.",
    },
    // ── Nelson's literary set (3.100–3.109; LM 4/52 to 4/55) ────────────
    Spelling {
        ordinals: &[100],
        name: "title",
        purpose: "The title: a link from the title's principal appearance to the whole document (LM 4/52).",
        endsets: "from: the title's text; to: the document.",
    },
    Spelling {
        ordinals: &[101],
        name: "author",
        purpose: "The author: a link from the author's name to the whole document; made from outside a document, a claim that the author is really someone else (LM 4/52).",
        endsets: "from: the author's name; to: the document.",
    },
    Spelling {
        ordinals: &[102],
        name: "counterpart",
        purpose: "A counterpart: correspondences between two equivalent documents, sections or passages (LM 4/53).",
        endsets: "from: the one passage; to: its counterpart.",
    },
    Spelling {
        ordinals: &[102, 1],
        name: "correspondence",
        purpose: "The correspondence record: the publish shot's own record that a draft run's \
                  identity became the member's, minted by the shot alone and homed in the \
                  draft; no picker lists it and no user act writes it.",
        endsets: "from: the run's draft-native span; to: the member's span it became, both of \
                  one width.",
    },
    Spelling {
        ordinals: &[103],
        name: "quote",
        purpose: "A quotation: a passage acknowledged as having its origin elsewhere, a bridge to the original (LM 4/53 to 4/54).",
        endsets: "from: the quotation; to: the original.",
    },
    Spelling {
        ordinals: &[104],
        name: "jump",
        purpose: "A plain jump from one place to another, followed and come back from (LM 4/54).",
        endsets: "from: the place jumped from; to: the place jumped to.",
    },
    Spelling {
        ordinals: &[104, 1],
        name: "modal",
        purpose: "A jump distinguished in some way as to type (LM 4/54).",
        endsets: "from: the place jumped from; to: the place jumped to.",
    },
    Spelling {
        ordinals: &[105],
        name: "certification",
        purpose: "A certification: a link that certifies and authenticates stored material, or an alternative version its certifier proposes (LM 4/55).",
        endsets: "from: the certifier's statement; to: the material certified.",
    },
];

/// Returns the vocabulary: every type the commons names, in path order.
///
/// It is the one table (`SPELLINGS`) read through one function, built at
/// the first read — each row's address spelled through [`commons_type`] —
/// so a reader hands back a borrow of one process-wide value and a row is
/// never rebuilt per consult. The daemon walks it at every open; a client
/// that links this crate walks it to name a type without a board.
pub fn vocabulary() -> &'static [Definition] {
    static ROWS: LazyLock<Vec<Definition>> = LazyLock::new(|| {
        SPELLINGS
            .iter()
            .map(|s| Definition {
                address: commons_type(s.ordinals),
                ordinals: s.ordinals,
                name: s.name,
                purpose: s.purpose,
                endsets: s.endsets,
            })
            .collect()
    });
    &ROWS
}

/// Returns the row whose address IS `a`, else `None` — by equality, never by
/// prefix: an address beneath a row or above one is no row of the table.
pub fn definition_at(a: &Address) -> Option<&'static Definition> {
    vocabulary().iter().find(|d| d.address == *a)
}

/// Returns the meta-type `defines`: `1.1.0.1.0.1.0.3.50`.
///
/// It is the type of every definition link the daemon writes — from a
/// type's section in the registry document to the type's address — and of
/// its own: the bootstrap row, seeded first (commons-seeding §2). Held, the
/// table's own row.
pub fn defines_type() -> &'static Address {
    static ADDR: LazyLock<&'static Address> = LazyLock::new(|| {
        &vocabulary()
            .iter()
            .find(|d| d.ordinals == [50])
            .expect("the table holds the meta-type's row")
            .address
    });
    &ADDR
}

#[cfg(test)]
mod tests;
