//! THE REPLY, "Your board is live." (the deployment notes §4, "The
//! customer's reply, the one carrier"; cs6-S2): ONE FUNCTION ([`text`])
//! renders it for the status page and the follow-up mail alike, from the
//! board's public origin, the anchorless fact and the status URL — so
//! the page and the mail cannot say two things.
//!
//! IN ORDER, each row the strings table's (`strings`): the heading; THE FOUR
//! RULED STRINGS by condition — the operator sentence ALWAYS; the
//! anchorless sentence IFF the record carried no anchor-flagged entry, the
//! FORM's own parse of it and never a DATA line (the sidecar's reply carries
//! none); the `local_trust` clause NEVER, for this service's guard refuses a
//! `true` pair as a failed step and this function takes no such input; the
//! public-venue statement ALWAYS, verbatim — then THE THREE FACTS, the
//! account `1.0.1`, the principal `1` and the PUBLIC origin (AUTH-4.57 (b)),
//! never the sidecar's dialed one; then THE TWO ACTS, composed here from the
//! `skep` command's own format strings with the public origin substituted —
//! `skep verify …` with the read's limit in the reply's own words
//! (AUTH-4.58), and the setup act `skep claim --board <origin> --dir
//! <store>` with AUTH-5.87's sentence — because the sidecar's two act lines
//! embed the dialed origin and a literal `<origin>`, neither fit to show a
//! person; and THE STATUS URL last.

use crate::sidecar::{ACCOUNT, PRINCIPAL};
use crate::strings::{fill, ANCHORLESS, FACTS, FIRST_ACT, LIVE, OPERATOR, PUBLIC_VENUE, REPLY_STATUS_URL, SECOND_ACT};

/// THE LIVE REPLY's TEXT: plain text, its paragraphs separated by a blank
/// line, for the page (`pages::paragraphs`) and the mail's body alike.
pub fn text(origin: &str, anchorless: bool, status_url: &str) -> String {
    let principal = PRINCIPAL.to_string();
    let slots = [("origin", origin), ("principal", principal.as_str()), ("account", ACCOUNT), ("status_url", status_url)];
    let mut blocks = vec![fill(LIVE, &slots), fill(OPERATOR, &slots)];
    if anchorless {
        blocks.push(fill(ANCHORLESS, &slots));
    }
    blocks.push(fill(PUBLIC_VENUE, &slots));
    blocks.push(fill(FACTS, &slots));
    blocks.push(fill(FIRST_ACT, &slots));
    blocks.push(fill(SECOND_ACT, &slots));
    blocks.push(fill(REPLY_STATUS_URL, &slots));
    let mut text = blocks.join("\n\n");
    text.push('\n');
    text
}

#[cfg(test)]
mod tests;
