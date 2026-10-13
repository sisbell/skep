//! THE SUFFIX's GRAMMAR, at every byte and at each label's ends, and its
//! value, `Domain::parse`, admitting exactly the domains the grammar does,
//! each kept as given and shown whole by its `Display` and its `Debug`.
//! (The flag that takes one, and the refusal naming it, are `args`' suite.)

use super::*;

/// THE SUFFIX's GRAMMAR, the daemon's own for the host every origin
/// closes: `a<c>b.host` is a domain iff `c` is a lowercase letter, a digit,
/// a dot or a hyphen, for every byte `c`; and a label empty, or beginning
/// or ending with a hyphen — at either end of the suffix or inside it — is
/// refused, as the empty suffix is; a domain admitted is kept as given, and
/// no secret: its `Display` and its `Debug` show it whole.
#[test]
fn the_suffix_is_lowercase_labels_none_empty_and_no_hyphen_at_either_end() {
    for b in 0..=255u8 {
        let admitted = b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-';
        assert_eq!(Domain::parse(&format!("a{}b.host", char::from(b))).is_some(), admitted, "{b:#04x}");
    }
    for bad in ["", ".", ".skep.host", "skep.host.", "skep..host", "-skep.host", "skep-.host", "skep.-host", "skep.host-"] {
        assert!(Domain::parse(bad).is_none(), "{bad:?}");
    }
    for good in ["skep.host", "a-b.c-d", "x", "1.2"] {
        let domain = Domain::parse(good).unwrap_or_else(|| panic!("{good:?}"));
        assert_eq!((domain.as_str(), domain.to_string(), format!("{domain:?}")), (good, good.to_owned(), format!("Domain({good:?})")));
    }
}
