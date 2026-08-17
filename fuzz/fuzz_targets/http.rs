//! Target 2 — the owned HTTP/1.1 layer: arbitrary bytes over a real socket
//! to the shared daemon. The oracle: a non-empty answer must be one
//! well-formed HTTP response (`check_http_response`); an empty answer is a
//! clean close. Both helpers are the tier-1 test's.
#![no_main]

use libfuzzer_sys::fuzz_target;

use skepd::fuzz_support::{check_http_response, http_raw_exchange};

fuzz_target!(|data: &[u8]| {
    if let Ok(resp) = http_raw_exchange(skep_fuzz::daemon_port(), data) {
        if !resp.is_empty() {
            check_http_response(&resp).expect("daemon emitted a malformed HTTP response");
        }
    }
});
