//! The strings table: every person-facing sentence of this program.
//!
//! It follows the deployment notes §4 step 1 and §12, each row naming its id
//! — a row of the deployment notes' table (`D-1` … `D-9`, §4 step 1 and §12
//! — each `DRAFT` there, carried here as written, the notes' `skep.host` the
//! configured suffix and its ⟨the owner's address⟩ the `--reply-to`
//! address); `DRAFT`, words this crate wrote where no settled text exists,
//! each for the notes' §12 and the copy inventory; `RULED`, settled words
//! carried verbatim; and `RULED-SUBSTANCE / DRAFT-WORDING`, a settled
//! sentence the notes give as a bullet, put in this crate's words. A
//! `{slot}` in a row's words — `{suffix}`, `{owner_address}`,
//! `{status_url}`, `{origin}`, `{principal}` or `{account}` — is filled where
//! the row is shown ([`fill`]).
//!
//! What is filled depends on where. The pages (`pages`) show the sign-up
//! page's rows, the claim form's, the status page's and the answers to a
//! request no page takes, every one with the site's two slots filled — the
//! suffix and the owner's address (`Site::fill`) — and D-7's page the status
//! URL beside them; the reply (`reply`) composes its rows for the page and
//! the mail alike, filling its own four; the follow-up mail's subject is the
//! sender's (`sender`), and names none. A row shown where a slot it names is
//! not filled is the showing code's bug, which [`fill`] catches in every
//! debug build — every test build but a `--release` one — so the test that
//! renders the row goes red.

/// One row of the strings table: where its words come from, and the words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Words {
    /// `D-1` … `D-9`, `DRAFT`, `RULED`, or `RULED-SUBSTANCE / DRAFT-WORDING`.
    pub id: &'static str,
    /// The words, slots unfilled.
    pub text: &'static str,
}

impl Words {
    /// Returns the slots this row names: each `{name}` in its words, in order.
    ///
    /// A `{` that no `}` closes names none.
    fn slots(self) -> impl Iterator<Item = &'static str> {
        self.text.split('{').skip(1).filter_map(|after| after.split_once('}').map(|(slot, _)| slot))
    }
}

// The sign-up page — no settled string exists for it.

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

/// The name refused: no name of the grammar, taken, or held.
///
/// It is held by a post in flight.
pub const NAME_REFUSED: Words = Words { id: "D-4", text: "That name is taken, or is not one label of letters, digits and hyphens. Choose another." };
/// The record refused: not a record `skep keygen` printed.
pub const RECORD_REFUSED: Words = Words { id: "D-5", text: "This is not a record skep keygen printed. Paste the whole line, exactly as printed." };
/// The record refused: a preview-kind key.
pub const PREVIEW_REFUSED: Words =
    Words { id: "D-6", text: "This record names a preview key. A hosted board enrolls the production kind alone: make the record again with a client that generates it." };
/// The invite code refused: malformed, not in the file, spent, or held.
///
/// It is held where another post holds it.
pub const INVITE_REFUSED: Words = Words { id: "DRAFT", text: "That invite code is not one this service issued, or it has been used. Check the link your invitation came with." };

// The status page.

/// While the post waits or its steps run.
pub const BEING_MADE: Words = Words { id: "D-7", text: "Your board is being made. Keep this page open: it shows your board when it is live." };
/// The status URL, shown with D-7.
pub const STATUS_URL: Words = Words { id: "DRAFT", text: "This page's own address, to come back to: {status_url}" };
/// The post failed, or the service was busy or could not judge or admit it.
///
/// The service is busy with the queue full, or with four posts already
/// looking at what stands.
pub const FAILED: Words = Words { id: "D-8", text: "Your board could not be made. Nothing stands under your name; try again later, or write to {owner_address}." };

// The reply — "Your board is live." (the notes §4: "The customer's reply,
// the one carrier"), composed by `reply` for the page and the mail alike:
// the four settled strings, the three facts, the two acts, the status URL
// last. Of the four, the `local_trust` clause (AUTH-4.52's reach, the notes'
// third bullet) has no row: this service never shows it — its `/health`
// guard refuses `local_trust: true` as a failed step (D-8), so no reply it
// renders can carry the clause, and no words are written for it.

/// The reply's heading: the notes' own name for the message (§4 step 5).
pub const LIVE: Words = Words { id: "DRAFT", text: "Your board is live." };
/// The operator sentence, create-org keyed: always shown.
///
/// It is AUTH-5.43's create-org sibling (AUTH-5.54 (a); AUTH-4.54).
pub const OPERATOR: Words = Words {
    id: "RULED-SUBSTANCE / DRAFT-WORDING",
    text: "The party that runs this board can write as you here, visibly and permanently; it can read what you write before you publish it; and on this board it can retire your keys and continue as you. You are this board's own claimant, and the board is portable: it can move with you to another host.",
};
/// The anchorless sentence, shown iff the record has no anchor-flagged entry.
///
/// It is AUTH-5.62's sentence (AUTH-5.16's second arm; AUTH-5.32's hop).
pub const ANCHORLESS: Words = Words {
    id: "RULED-SUBSTANCE / DRAFT-WORDING",
    text: "Your record named no anchor key, so this account has no paper tier: `skep recover` will never be available on it. While a device of yours is signed in, `skep enroll` run from it adds another — the one way this account gains a device.",
};
/// The public-venue statement, always shown, verbatim as the notes quote it.
///
/// It is PUB-5.25's string with the claim door's parenthetical (AUTH-5.85),
/// its lowercase opening and its want of a closing period included.
pub const PUBLIC_VENUE: Words = Words {
    id: "RULED",
    text: "every edit to this page, including what you later remove, is public history — and the records this page holds (your keys, your claim, the grants you issue) stand as records of their own, so removing the text one names does not remove it: the record stays in force, and the version you removed it from remains readable",
};
/// The three facts (AUTH-5.76's channel), as the `skep` command spells them.
///
/// They are its `print_facts` lines, the origin the public one.
pub const FACTS: Words = Words { id: "RULED", text: "account {account}\nprincipal {principal}\norigin {origin}" };
/// The first act (AUTH-4.58's detection): the `skep` command's own string.
///
/// It is the format string of `skep claim --hosted`'s fifth data line, the
/// public origin in the dialed one's place — held to that line by `reply`'s
/// suite, which reads it back from `skep-cli`.
pub const FIRST_ACT: Words = Words {
    id: "RULED",
    text: "first act: from the device that generated the payload run `skep verify --board {origin} --principal {principal} --payload <the record it printed>` (or `--anchor <a> --anchor <b>`): the genesis record compared entry for entry, fingerprint and anchor flag, against what that device composed — it confirms the keys on the board, and it cannot tell you the board will open a session for you",
};
/// The second act, with AUTH-5.87's sentence: the `skep` command's own line.
///
/// It is `skep claim --hosted`'s sixth, its `<origin>` filled with the
/// public origin — held to that line by `reply`'s suite, which reads it back
/// from `skep-cli`.
pub const SECOND_ACT: Words = Words {
    id: "RULED",
    text: "second act: in your first signed session the setup act runs — `skep claim --board {origin} --dir <store>` from that device performs it: creating your account also creates a space for your agents beneath it, and its home",
};
/// The status URL, last in the reply, with how long it stands.
///
/// The status map is memory, and a restart ends every status page.
pub const REPLY_STATUS_URL: Words = Words { id: "DRAFT", text: "Keep a copy: until this service next restarts, this reply stays at {status_url}" };
/// The follow-up mail's subject.
pub const MAIL_SUBJECT: Words = Words { id: "DRAFT", text: "Your board is live" };

// The answers to a request no page takes.

/// A request no page takes (404).
pub const NOT_FOUND: Words = Words { id: "DRAFT", text: "There is no page here." };
/// A status token this process does not hold (404).
///
/// It is most often one from before the service's last restart, which ended
/// its post's page. The row says what a board made under it may stand as,
/// and the person's next act, for a stop cut between a board's snippet and
/// its invite's spend leaves the board standing under the name and the
/// invite issued.
pub const STATUS_GONE: Words = Words {
    id: "DRAFT",
    text: "This page is not held here — most often because the service that showed it has restarted since. A board that went live stands at its name, https://⟨name⟩.{suffix}, and its reply came by mail where this service sends mail. A post that had not gone live leaves your invite to post again; but if the name you chose then meets \"That name is taken\", the board under it may be yours: write to {owner_address} before you choose another name.",
};
/// A body the form decoder refused, or a request outside the subset (400).
pub const BAD_FORM: Words = Words { id: "DRAFT", text: "This form could not be read. Go back and send it again." };
/// A body past the cap (413).
pub const TOO_LARGE: Words = Words { id: "DRAFT", text: "This form is too large to read. Go back and check what you pasted: a record is one line." };

/// Returns a row's words with its slots filled.
///
/// A release build shows a slot the row names and the caller does not
/// supply as written rather than panic: on a page a panic costs the request
/// its page, the connection closed unanswered, and in the mail — its reply
/// and its subject, rendered on a worker past its steps' catch — it would
/// end the worker, which is never made again.
///
/// # Panics
///
/// Panics in every debug build where the row names a slot the caller does
/// not supply: the showing code's bug — the row shown where that slot is not
/// known — so the test that renders the row goes red.
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
