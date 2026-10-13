//! THE STRINGS TABLE (the deployment notes §4 step 1 and §12): every
//! person-facing sentence of this program, each row naming its id — a row of
//! the deployment notes' table (`D-1` … `D-9`, §4 step 1 and §12 — each DRAFT
//! there, carried here as written, the notes' `skep.host` the configured
//! suffix and its ⟨the owner's address⟩ the `--reply-to` address); `DRAFT`,
//! words this crate wrote where no ruled text exists, each for the notes' §12
//! and the copy inventory; `RULED`, ruled words carried verbatim; and
//! `RULED-SUBSTANCE / DRAFT-WORDING`, a ruled sentence the notes give as a
//! bullet, put in this crate's words. A `{slot}` in a row's words —
//! `{suffix}`, `{owner_address}`, `{status_url}`, `{origin}`, `{principal}`
//! or `{account}` — is filled where the row is shown ([`fill`]).
//!
//! What is filled depends on where. The pages (`pages`) show the sign-up
//! page's rows, the claim form's, the status page's and the answers to a
//! request no page takes, every one with the site's two slots filled — the
//! suffix and the owner's address (`Site::fill`) — and D-7's page the status
//! URL beside them; the reply (`reply`) composes its rows for the page and
//! the mail alike, filling its own four; the follow-up mail's subject is the
//! sender's (`sender`), and names none. A row shown where a slot it names is
//! not filled is the showing code's bug, which [`fill`] catches in every
//! debug build — every test build — so the test that renders the row goes
//! red.

/// One row of the strings table: where its words come from, and the words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Words {
    /// `D-1` … `D-9`, `DRAFT`, `RULED`, or `RULED-SUBSTANCE / DRAFT-WORDING`.
    pub id: &'static str,
    /// The words, slots unfilled.
    pub text: &'static str,
}

impl Words {
    /// The slots this row names: each `{name}` in its words, in order; a
    /// `{` that no `}` closes names none.
    fn slots(self) -> impl Iterator<Item = &'static str> {
        self.text.split('{').skip(1).filter_map(|after| after.split_once('}').map(|(slot, _)| slot))
    }
}

// The sign-up page — no ruled string exists for it.

/// The sign-up page's lead.
pub const SIGNUP_LEAD: Words = Words { id: "DRAFT", text: "Leave your email address to ask for a board of your own under {suffix}. An invitation, when one is sent, comes to this address." };
/// What is kept, said where the address is asked for.
pub const SIGNUP_KEPT: Words = Words { id: "DRAFT", text: "Your address is kept in a file on this service's machine, read by the people who run it, for the invitation alone." };
/// The address field's label.
pub const ADDRESS_LABEL: Words = Words { id: "DRAFT", text: "Your email address" };
/// The sign-up form's button.
pub const SIGNUP_BUTTON: Words = Words { id: "DRAFT", text: "Sign up" };
/// The address refused by the rule.
pub const SIGNUP_REFUSED: Words = Words { id: "DRAFT", text: "That is not an email address. Check it and send it again." };
/// The address could not be written down.
pub const SIGNUP_FAILED: Words = Words { id: "DRAFT", text: "Your address could not be kept just now. Try again later." };
/// The thanks page.
pub const THANKS: Words = Words { id: "DRAFT", text: "Thank you: your address is kept. An invitation, when one is sent, comes to it." };

// The claim form.

/// The claim form's lead.
pub const CLAIM_LEAD: Words = Words { id: "D-1", text: "A board of your own at a name under {suffix}. Your keys stay on your device: this page makes none." };
/// The name field's label.
pub const NAME_LABEL: Words = Words { id: "D-2", text: "Your board's name" };
/// The name field's help.
pub const NAME_HELP: Words = Words { id: "D-2", text: "one label: letters, digits and hyphens; it becomes ⟨name⟩.{suffix}" };
/// The record field's label.
pub const RECORD_LABEL: Words = Words { id: "D-3", text: "Your record" };
/// The record field's help.
pub const RECORD_HELP: Words = Words {
    id: "D-3",
    text: "On your own device run `skep keygen --anchors --anchor-out <a> --anchor-out <b>` (two papers, kept apart) or `skep keygen --payload`, and paste the one line it printed. Paste only what it printed: it holds no private key.",
};
/// The invite field's label.
pub const INVITE_LABEL: Words = Words { id: "D-9", text: "Your invite code" };
/// The claim form's button.
pub const CLAIM_BUTTON: Words = Words { id: "DRAFT", text: "Make my board" };

// A claim post's refusals, each shown on the form again.

/// The name refused: taken, or not one label.
pub const NAME_REFUSED: Words = Words { id: "D-4", text: "That name is taken, or is not one label of letters, digits and hyphens. Choose another." };
/// The record refused: not a record `skep keygen` printed.
pub const RECORD_REFUSED: Words = Words { id: "D-5", text: "This is not a record skep keygen printed. Paste the whole line, exactly as printed." };
/// The record refused: a preview-kind key.
pub const PREVIEW_REFUSED: Words =
    Words { id: "D-6", text: "This record names a preview key. A hosted board enrolls the production kind alone: make the record again with a client that generates it." };
/// The invite code refused: not in the file, or spent.
pub const INVITE_REFUSED: Words = Words { id: "DRAFT", text: "That invite code is not one this service issued, or it has been used. Check the link your invitation came with." };

// The status page.

/// While the post waits or its steps run.
pub const BEING_MADE: Words = Words { id: "D-7", text: "Your board is being made. Keep this page open: it shows your board when it is live." };
/// The status URL, shown with D-7.
pub const STATUS_URL: Words = Words { id: "DRAFT", text: "This page's own address, to come back to: {status_url}" };
/// The post failed; or the service was busy — the queue full, or four
/// posts already looking at what stands — or could not judge the post.
pub const FAILED: Words = Words { id: "D-8", text: "Your board could not be made. Nothing stands under your name; try again later, or write to {owner_address}." };

// THE REPLY — "Your board is live." (the notes §4: "The customer's reply,
// the one carrier", cs6-S2), composed by `reply` for the page and the mail
// alike: the four ruled strings, the three facts, the two acts, the status
// URL last. Of the four, the `local_trust` clause (AUTH-4.52's reach,
// the notes' third bullet) has NO ROW: this service never shows it — its
// `/health` guard refuses `local_trust: true` as a failed step (D-8), so no
// reply it renders can carry the clause, and no words are written for it.

/// The reply's heading: the notes' own name for the message (§4 step 5).
pub const LIVE: Words = Words { id: "DRAFT", text: "Your board is live." };
/// THE OPERATOR SENTENCE, create-org keyed (AUTH-5.43's create-org sibling;
/// AUTH-5.54 (a); AUTH-4.54) — ALWAYS shown.
pub const OPERATOR: Words = Words {
    id: "RULED-SUBSTANCE / DRAFT-WORDING",
    text: "The party that runs this board can write as you here, visibly and permanently; it can read what you write before you publish it; and on this board it can retire your keys and continue as you. You are this board's own claimant, and the board is portable: it can move with you to another host.",
};
/// THE ANCHORLESS SENTENCE (AUTH-5.62; AUTH-5.16's second arm; AUTH-5.32's
/// hop) — shown IFF the record carried no anchor-flagged entry.
pub const ANCHORLESS: Words = Words {
    id: "RULED-SUBSTANCE / DRAFT-WORDING",
    text: "Your record named no anchor key, so this account has no paper tier: `skep recover` will never be available on it. While a device of yours is signed in, `skep enroll` run from it adds another — the one way this account gains a device.",
};
/// THE PUBLIC-VENUE STATEMENT (AUTH-5.85; PUB-5.25's string with the claim
/// door's parenthetical) — ALWAYS shown, VERBATIM as the notes quote it,
/// its lowercase opening and its want of a closing period included.
pub const PUBLIC_VENUE: Words = Words {
    id: "RULED",
    text: "every edit to this page, including what you later remove, is public history — and the records this page holds (your keys, your claim, the grants you issue) stand as records of their own, so removing the text one names does not remove it: the record stays in force, and the version you removed it from remains readable",
};
/// THE THREE FACTS (AUTH-5.76's channel), as the `skep` command spells them
/// (`print_facts`), the origin the PUBLIC one.
pub const FACTS: Words = Words { id: "RULED", text: "account {account}\nprincipal {principal}\norigin {origin}" };
/// THE FIRST ACT (AUTH-4.58's detection): the `skep` command's own format
/// string (`skep claim --hosted`'s fifth DATA line), the public origin in
/// the dialed one's place — held to that line by `reply`'s suite, which
/// reads it back from `skep-cli`.
pub const FIRST_ACT: Words = Words {
    id: "RULED",
    text: "first act: from the device that generated the payload run `skep verify --board {origin} --principal {principal} --payload <the record it printed>` (or `--anchor <a> --anchor <b>`): the genesis record compared entry for entry, fingerprint and anchor flag, against what that device composed — it confirms the keys on the board, and it cannot tell you the board will open a session for you",
};
/// THE SECOND ACT, with AUTH-5.87's sentence: the `skep` command's own line
/// (`skep claim --hosted`'s sixth), its `<origin>` filled with the public
/// origin — held to that line by `reply`'s suite, which reads it back from
/// `skep-cli`.
pub const SECOND_ACT: Words = Words {
    id: "RULED",
    text: "second act: in your first signed session the setup act runs — `skep claim --board {origin} --dir <store>` from that device performs it: creating your account also creates a space for your agents beneath it, and its home",
};
/// The status URL, last in the reply.
pub const REPLY_STATUS_URL: Words = Words { id: "DRAFT", text: "This reply stays at {status_url}" };
/// The follow-up mail's subject.
pub const MAIL_SUBJECT: Words = Words { id: "DRAFT", text: "Your board is live" };

// The answers to a request no page takes.

/// A request no page takes, or a status token this program does not hold
/// (404).
pub const NOT_FOUND: Words = Words { id: "DRAFT", text: "There is no page here." };
/// A body the form decoder refused, or a request outside the subset (400).
pub const BAD_FORM: Words = Words { id: "DRAFT", text: "This form could not be read. Go back and send it again." };
/// A body past the cap (413).
pub const TOO_LARGE: Words = Words { id: "DRAFT", text: "This form is too large to read. Go back and check what you pasted: a record is one line." };

/// A ROW's WORDS with its slots filled. A slot the row names and the caller
/// does not supply is the showing code's bug — the row shown where that
/// slot is not known — caught in every debug build, so the test that
/// renders the row goes red; a release build shows the slot as written
/// rather than end the thread that renders the row — a connection thread or
/// a worker, neither of which is ever made again.
pub fn fill(words: Words, slots: &[(&str, &str)]) -> String {
    debug_assert!(words.slots().all(|named| slots.iter().any(|(slot, _)| *slot == named)), "{words:?} is shown where a slot it names is not filled");
    let mut text = words.text.to_owned();
    for (slot, value) in slots {
        text = text.replace(&format!("{{{slot}}}"), value);
    }
    text
}

#[cfg(test)]
mod tests;
