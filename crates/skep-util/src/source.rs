//! Where a setting's value in force CAME FROM — the daemon's default, a
//! flag on the command line, or a variable of the environment — carried
//! beside the value on the option types an operator builds, so the open's
//! report names each setting with its source (`operations.md` §1 THE OPEN's
//! REPORT: "every setting in force with its source (the default, the flag,
//! the variable …)"; §1.1 rows 8, 19 and m14).
//!
//! The parse is the one place that knows which arm set a setting, and it
//! loses that knowledge at the `unwrap_or` that resolves the value — so a
//! line that said "(the default)" for an upload switch the environment set
//! was true of nothing but the line. The member travels with the value from
//! the parse to the line, and the line composes its own words from it: the
//! enum carries no setting's name, since the words a source is spelled by
//! are the SETTING's — `--no-uploads`, `SKEPD_UPLOADS=false`,
//! `--node-prefix` — and each line knows its own.
//!
//! Here rather than in either crate by the rule of membership: both
//! `skepd` (its session-layer options) and `skep-media` (its upload
//! setting) carry it, and it has no subject of its own.

/// Which arm of the parse set a setting's value in force. `Copy`, and
/// `Default` is the default's own arm, so an option type built from its
/// defaults carries `Default` on every member until the parse says
/// otherwise — a caller that sets a value and names no source is read as
/// the default's, which is what its line then says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Source {
    /// Neither a flag nor a variable named the setting: the daemon's own
    /// default stands.
    #[default]
    Default,
    /// A flag on the command line set it — the last flag of its pair where
    /// both were given, which is the parse's own rule.
    Flag,
    /// A variable of the environment set it, and no flag overrode it.
    Env,
}

impl Source {
    /// The source as a line spells it, given the setting's own two names:
    /// `the default`; or `flag`, the flag as the operator typed it
    /// (`--no-uploads`); or `variable`, the variable with the value it
    /// carried (`SKEPD_UPLOADS=false`) or its bare name where the line
    /// already says the value (`SKEPD_NODE_PREFIX`). Each site hands in the
    /// words that are true of its setting, so one enum serves every line
    /// and spells no setting itself.
    pub fn words<'a>(self, flag: &'a str, variable: &'a str) -> &'a str {
        match self {
            Source::Default => "the default",
            Source::Flag => flag,
            Source::Env => variable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default's arm is the enum's `Default`, so an option type built
    /// from its defaults names the default's source on every member.
    #[test]
    fn the_default_arm_is_the_enums_default() {
        assert_eq!(Source::default(), Source::Default);
    }

    /// The words are the setting's: the default's own phrase, else whichever
    /// of the two names the site handed in for the arm that set it.
    #[test]
    fn a_source_spells_the_default_or_the_settings_own_name() {
        assert_eq!(Source::Default.words("--uploads", "SKEPD_UPLOADS=true"), "the default");
        assert_eq!(Source::Flag.words("--no-uploads", "SKEPD_UPLOADS=false"), "--no-uploads");
        assert_eq!(Source::Env.words("--no-uploads", "SKEPD_UPLOADS=false"), "SKEPD_UPLOADS=false");
        assert_eq!(Source::Env.words("--node-prefix", "SKEPD_NODE_PREFIX"), "SKEPD_NODE_PREFIX");
    }
}
