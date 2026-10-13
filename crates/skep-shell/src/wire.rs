//! THE WIRE's SHARED FACTS: what the composer (`attest`), the held store
//! (`held`), the hold's door (`hold`) and the call log the shell keeps
//! (`shell`) each read of the board's wire and none of them owns — the
//! board's frame cap and how a frame is measured against it, the tumbler
//! component budget and an address read within it, and a document address
//! in its one spelling. A leaf: it names no other module of the crate.

use std::io;

use serde_json::Value;
use skep_address::{Address, Level};
use skep_client::address::{is_address_text, parse_address};

/// THE BOARD's FRAME CAP — the most bytes one `/op` body may carry: skepd's
/// `body_cap("POST", "/op")`, its `MAX_REQUEST_BODY`, refused `413` on the
/// declared length before a byte is read. Two budgets are this number: a
/// burst whose frame the board takes at no send never enters the hold
/// (`hold`'s `Burst::admit`), and a shot's body is built under it — the
/// parity the daemon's own composer holds a shot's body to (`auth/entry.rs`'s
/// `MAX_SHOT_BODY_BYTES`), answering a longer one
/// `attestation_invalid:frame_too_large`. Pinned equal to the board's by the
/// suite.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// The most components one tumbler may carry, an address or a width —
/// skepd's codec's `MAX_TUMBLER_COMPONENTS`, refused at the board's parse,
/// `malformed`; counted here before a component is converted or collected.
/// The codec's constant is private, so the suite pins this one by the
/// board's behaviour: an address at it parsed, one past it refused.
pub const MAX_TUMBLER_COMPONENTS: usize = 256;

/// Whether `text` splits into at most [`MAX_TUMBLER_COMPONENTS`]
/// components — counted without converting or collecting one.
pub fn within_components(text: &str) -> bool {
    text.split('.').nth(MAX_TUMBLER_COMPONENTS).is_none()
}

/// `text` as an address — within [`MAX_TUMBLER_COMPONENTS`], counted before
/// a component is converted, each a decimal natural, and T4-valid — or
/// `None`.
pub fn bounded_address(text: &str) -> Option<Address> {
    within_components(text).then(|| parse_address(text)).flatten()
}

/// `text` as a DOCUMENT address in its ONE spelling — dotted decimal
/// naturals, no sign and no leading zero (`is_address_text`) — within
/// [`MAX_TUMBLER_COMPONENTS`], T4-valid and of the document level, or
/// `None`. The one spelling, because the hold keys a document's lines by
/// its text and reads its rows `under` that text, and a trunk is split by
/// text (`attest`'s `trunk_text`): two spellings of one document would be
/// two documents to the hold, and a `00` is no `0` to a split.
pub fn document_address(text: &str) -> Option<Address> {
    is_address_text(text).then(|| bounded_address(text)).flatten().filter(|a| a.level() == Level::Document)
}

/// The length of `v`'s compact JSON text — the bytes a value carries on the
/// wire, as the shell counts a call's for its log and measures a frame
/// against the board's cap — counted as it is written and never kept.
pub fn json_len(v: &Value) -> usize {
    /// A writer that keeps nothing but the count.
    struct Count(usize);
    impl io::Write for Count {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, v).expect("a `Value` has string keys and finite numbers, and the count's writer never fails");
    count.0
}
