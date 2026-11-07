//! A caught panic, named by the site its hook noted.
//!
//! It is what a catch's line says of the panic it contained (`operations.md`
//! §1.1 row 41; §4 row 26). A catch holds a panic's payload and nothing
//! more: the site is on the hook's info alone, and the hook is the
//! program's — a library never sets it, since that process-global belongs
//! to whoever embeds the library. So the two meet in one slot per thread.
//! The hook notes the site there ([`note_site`]), at the panic, on the
//! panicking thread, before any catch; [`catch`] runs its body under
//! `catch_unwind` and, at an unwind, takes the slot's site and the payload
//! where it is a `&'static str` into one [`Caught`], which a catch's line
//! renders `a panic at {site}`, then `: {literal}` where there is one. A
//! site is spelled one way, by [`site_of`], on the hook's line and the
//! catch's alike.
//!
//! **A caught panic names the site its hook noted, and never another.**
//! [`catch`] empties the slot before its body runs and takes it once the
//! body ends, so no site outlives the catch it was noted for: an unwind no
//! hook noted — a `resume_unwind`, which runs none, or a panic under a hook
//! that notes nothing, an embedder's own until it calls [`note_site`] —
//! reads `an unknown location`, never an earlier panic's site.
//!
//! **Only a literal rides.** A formatted payload's text may be made from a
//! request's or a record's values and may span lines, so a [`Caught`]
//! keeps none of it, and nothing of `operations.md` §1's never list rides
//! a catch's line; the site is the code's own, and identifies the panic.
//!
//! Here by the rule of membership: `skepd`'s binary notes the site in its
//! hook, and the cell index's walk (`skep-media`), the change feed's walk
//! (`skep-core`) and `skepd`'s worker loop each catch the panic and say it.

use std::cell::Cell;
use std::fmt;
use std::panic::{self, Location, UnwindSafe};

/// The words a site reads where no location is known.
const UNKNOWN_SITE: &str = "an unknown location";

thread_local! {
    /// The site this thread's hook noted, until a catch takes it.
    static SITE: Cell<Option<String>> = const { Cell::new(None) };
}

/// Returns a panic's site as a line names it.
///
/// It is the location as std spells it, `file:line:column`, or `an unknown
/// location` where the hook's info carries none.
pub fn site_of(location: Option<&Location<'_>>) -> String {
    location.map_or_else(|| UNKNOWN_SITE.to_string(), |at| at.to_string())
}

/// Notes a panic's site for the catch its unwind meets on this thread.
///
/// A panic hook calls it with its info's `location()`, at the panic and
/// before any catch, so a catch's line names the site the hook's line does.
/// It never panics, since a panic inside a hook aborts the process: where
/// this thread's locals are torn down already, the site goes unnoted, and
/// the catch reads `an unknown location`.
pub fn note_site(location: Option<&Location<'_>>) {
    let site = site_of(location);
    let _ = SITE.try_with(|slot| slot.set(Some(site)));
}

/// Runs `f`, and answers its unwind as the panic it caught.
///
/// The slot is emptied before `f` runs and taken once it ends, so the site
/// a [`Caught`] carries is the one a hook noted for the unwind it caught,
/// and `an unknown location` where none did; the payload rides only where
/// it is a `&'static str`. Unwind safety is the caller's to argue, where it
/// wraps `f` in `AssertUnwindSafe`, as `catch_unwind` asks.
///
/// # Errors
///
/// The [`Caught`] where `f` unwinds.
pub fn catch<R>(f: impl FnOnce() -> R + UnwindSafe) -> Result<R, Caught> {
    let _ = SITE.try_with(Cell::take);
    let ended = panic::catch_unwind(f);
    let site = SITE.try_with(Cell::take).ok().flatten();
    ended.map_err(|payload| {
        let literal = payload.downcast_ref::<&'static str>().copied();
        Caught { site, literal }
    })
}

/// A panic [`catch`] caught: the site its hook noted, and its literal.
///
/// It renders as a catch's line carries it — `a panic at {site}`, then
/// `: {literal}` where the payload was a `&'static str` — the site reading
/// `an unknown location` where no hook noted one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caught {
    site: Option<String>,
    literal: Option<&'static str>,
}

impl fmt::Display for Caught {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a panic at {}", self.site.as_deref().unwrap_or(UNKNOWN_SITE))?;
        match self.literal {
            Some(literal) => write!(f, ": {literal}"),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks that a caught panic names the site noted for it and a literal.
    ///
    /// The body plays the hook's part, noting its site before it panics,
    /// since this suite's process runs std's own hook, which notes nothing.
    /// A literal payload follows the site; a formatted one, whose text a
    /// value made, leaves the site alone.
    #[test]
    fn a_caught_panic_names_the_site_noted_for_it_and_a_literal_alone() {
        let at = Location::caller();
        let literal = catch(|| {
            note_site(Some(at));
            panic!("the walk died");
        });
        let literal = literal.expect_err("the body panics");
        assert_eq!(literal.to_string(), format!("a panic at {at}: the walk died"));
        let n = std::hint::black_box(7);
        let formatted = catch(|| {
            note_site(Some(at));
            panic!("formatted at {n}");
        });
        let formatted = formatted.expect_err("the body panics");
        assert_eq!(formatted.to_string(), format!("a panic at {at}"), "no formatted text rides");
    }

    /// Checks that an unwind no hook noted reads an unknown location.
    ///
    /// A panic nothing noted; a `resume_unwind`, which runs no hook, under a
    /// site noted before the catch began; and a panic after a catch that
    /// took a site: each reads `an unknown location`, never an older site.
    #[test]
    fn an_unwind_no_hook_noted_reads_an_unknown_location_never_an_older_site() {
        let unnoted = catch(|| panic!("no hook noted it")).expect_err("the body panics");
        assert_eq!(unnoted.to_string(), "a panic at an unknown location: no hook noted it");
        note_site(Some(Location::caller()));
        let resumed = catch(|| panic::resume_unwind(Box::new("resumed"))).expect_err("an unwind");
        assert_eq!(resumed.to_string(), "a panic at an unknown location: resumed");
        let at = Location::caller();
        let first = catch(|| {
            note_site(Some(at));
            panic!("the first");
        });
        let second = catch(|| panic!("the second"));
        let (first, second) = (first.expect_err("panics"), second.expect_err("panics"));
        assert_eq!(first.to_string(), format!("a panic at {at}: the first"));
        assert_eq!(second.to_string(), "a panic at an unknown location: the second");
    }

    /// Checks that a body that returns answers its value, and a site's words.
    ///
    /// No unwind is no [`Caught`]; `site_of` spells a location as std does,
    /// `file:line:column`, and a missing one `an unknown location`.
    #[test]
    fn a_body_that_returns_answers_its_value_and_a_site_reads_as_std_spells_it() {
        assert_eq!(catch(|| 7), Ok(7));
        let at = Location::caller();
        assert_eq!(site_of(Some(at)), format!("{}:{}:{}", at.file(), at.line(), at.column()));
        assert_eq!(site_of(None), "an unknown location");
    }
}
