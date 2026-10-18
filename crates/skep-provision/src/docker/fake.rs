//! The scripted fake: a [`Docker`] answered from a script the test writes.
//!
//! It is compiled under `test-hooks` alone, so no shipped build holds it. The
//! script has one line per call it expects, each with the exit code and the
//! stdout (and, where wanted, the stderr) the call answers.
//!
//! **The order is strict per name and free across names.** A call is
//! answered by the first unconsumed line under its own name — the lines
//! without a name (the reload, the listing) are one name among them —
//! because the pool makes boards for different names at once, and which
//! name's call lands first is the scheduler's; a name's own calls still come
//! in the order its lines are written.
//!
//! It records every call in the order received — the method, the name, the
//! input it carries — in memory and, where it was opened from a file (the
//! binary's `--docker-fake <script>`), as one line per call in its calls
//! file, the sibling `<script>.calls`, which a suite driving the built binary
//! reads after it, the input's length there in the input's place; a call
//! whose line that file cannot take is left out of both, as `run`'s errors
//! say. A call the script did not expect — another method than the next line
//! under its name, or a call under a name with no line left — is answered
//! with exit [`UNEXPECTED`] and a stderr saying so, recorded as unexpected,
//! and leaves the script where it was; `FakeDocker::assert_done` then fails
//! the test, as does a script line left uncalled.
//!
//! **The script's line.** Its fields are tab-separated: the method as the
//! trait spells it, the name (`-` for the reload and the listing, which name
//! none), the exit code, then optionally the stdout and the stderr, in which
//! `\n` is a line break, `\t` a tab and `\\` a backslash (`line` writes one).
//! A blank line, or one beginning `#`, is no call.

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
#[cfg(test)]
use std::{
    panic::{RefUnwindSafe, UnwindSafe},
    sync::OnceLock,
};

use super::{Call, Docker};
use crate::name::Name;
use crate::process::Exit;

/// The pause a unit suite puts on the fake.
///
/// It is called with every call's method and name once the call is answered
/// and recorded, and is free to block — the test's way to pause a worker
/// inside one call while another name's flow runs on. It is called with no
/// lock of the fake's held, so a pause in one call pauses no other. It is
/// unwind-safe, as a suite catches the fake's own panics.
#[cfg(test)]
type Pause = Box<dyn Fn(&'static str, Option<&str>) + Send + Sync + UnwindSafe + RefUnwindSafe>;

/// The exit code a call the script did not expect answers.
///
/// It is Docker's own code for an error of the `docker` command itself, as
/// this crate knows Docker (unverified here) — a code every step reads as a
/// failure.
pub const UNEXPECTED: i32 = 125;

/// One script line: the call it expects and what that call answers.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ScriptLine {
    /// The method expected, as the trait spells it.
    method: String,
    /// The name expected, `None` for the reload and the listing.
    name: Option<String>,
    /// The exit code answered.
    code: i32,
    /// The stdout answered.
    stdout: Vec<u8>,
    /// The stderr answered.
    stderr: Vec<u8>,
}

/// One call the fake received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Called {
    /// The method called.
    pub method: &'static str,
    /// The name it named, `None` for the reload and the listing.
    pub name: Option<String>,
    /// The input it carried, where it carried any.
    ///
    /// It is the sidecar's record, on the child's stdin.
    pub input: Option<Vec<u8>>,
    /// Whether the script's next line under its name expected it.
    pub expected: bool,
}

impl Called {
    /// Returns the call as `<method> <name>`.
    ///
    /// It is `<method>` alone for the reload and the listing — the form a test
    /// lists the expected sequence in.
    #[cfg(test)]
    fn said(&self) -> String {
        match &self.name {
            Some(name) => format!("{} {name}", self.method),
            None => self.method.to_owned(),
        }
    }
}

/// The fake.
///
/// It holds the script left to answer, the calls received, the calls file
/// they are written to where it was opened from a file, and a unit suite's
/// pause.
pub struct FakeDocker {
    script: Mutex<VecDeque<ScriptLine>>,
    calls: Mutex<Vec<Called>>,
    calls_file: Option<PathBuf>,
    #[cfg(test)]
    pause: OnceLock<Pause>,
}

/// The script left, the calls received and the calls file.
///
/// The pause is a closure.
impl std::fmt::Debug for FakeDocker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeDocker").field("script", &self.script).field("calls", &self.calls).field("calls_file", &self.calls_file).finish_non_exhaustive()
    }
}

impl FakeDocker {
    /// Parses the fake over a script's text.
    ///
    /// # Errors
    ///
    /// A line of fewer than three or more than five tab-separated fields, or
    /// whose exit code is no number, named by its line number.
    pub fn parse(script: &str) -> Result<FakeDocker, String> {
        let mut lines = VecDeque::new();
        for (i, text) in script.lines().enumerate() {
            if text.trim().is_empty() || text.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = text.split('\t').collect();
            if fields.len() < 3 || fields.len() > 5 {
                return Err(format!("script line {}: three to five TAB-separated fields, not {}", i + 1, fields.len()));
            }
            let code = fields[2].parse().map_err(|_| format!("script line {}: `{}` is no exit code", i + 1, fields[2]))?;
            lines.push_back(ScriptLine {
                method: fields[0].to_owned(),
                name: (fields[1] != "-").then(|| fields[1].to_owned()),
                code,
                stdout: unescape(fields.get(3).copied().unwrap_or("")).into_bytes(),
                stderr: unescape(fields.get(4).copied().unwrap_or("")).into_bytes(),
            });
        }
        Ok(FakeDocker {
            script: Mutex::new(lines),
            calls: Mutex::new(Vec::new()),
            calls_file: None,
            #[cfg(test)]
            pause: OnceLock::new(),
        })
    }

    /// Sets the pause.
    ///
    /// `pause` is called with every call's method and name once the call is
    /// answered and recorded, and may block there.
    ///
    /// # Panics
    ///
    /// Panics where a pause is already set: it is set once.
    #[cfg(test)]
    pub fn pause(&self, pause: impl Fn(&'static str, Option<&str>) + Send + Sync + UnwindSafe + RefUnwindSafe + 'static) {
        assert!(self.pause.set(Box::new(pause)).is_ok(), "the pause is set once");
    }

    /// Opens the fake over the script file at `path`.
    ///
    /// It is the binary's `--docker-fake <script>`, and it writes every call
    /// it receives to its calls file, [`calls_path`]`(path)`, emptied first.
    ///
    /// # Errors
    ///
    /// The script file cannot be read, its text is no script, or the calls
    /// file cannot be written.
    pub fn open(path: &Path) -> io::Result<FakeDocker> {
        let text = std::fs::read_to_string(path)?;
        let mut fake = FakeDocker::parse(&text).map_err(io::Error::other)?;
        let calls_file = calls_path(path);
        std::fs::write(&calls_file, b"")?;
        fake.calls_file = Some(calls_file);
        Ok(fake)
    }

    /// Returns every call received, in order.
    #[cfg(test)]
    pub fn calls(&self) -> Vec<Called> {
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Returns every call received, each as `Called::said` spells it.
    #[cfg(test)]
    pub fn said(&self) -> Vec<String> {
        self.calls().iter().map(Called::said).collect()
    }

    /// Returns the calls the script did not expect.
    #[cfg(test)]
    pub fn unexpected(&self) -> Vec<Called> {
        self.calls().into_iter().filter(|c| !c.expected).collect()
    }

    /// Returns the script's lines not yet called.
    #[cfg(test)]
    fn left(&self) -> Vec<ScriptLine> {
        self.script.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect()
    }

    /// Asserts the script is done: every call expected, every line called.
    ///
    /// # Panics
    ///
    /// Panics, failing the test, on a call the script did not expect, or on a
    /// script line left uncalled.
    #[cfg(test)]
    pub fn assert_done(&self) {
        let unexpected: Vec<String> = self.unexpected().iter().map(Called::said).collect();
        assert!(unexpected.is_empty(), "calls the script did not expect: {unexpected:?}; every call: {:?}", self.said());
        let left: Vec<String> = self.left().iter().map(|s| format!("{} {}", s.method, s.name.as_deref().unwrap_or("-"))).collect();
        assert!(left.is_empty(), "script lines never called: {left:?}; every call: {:?}", self.said());
    }
}

/// Returns a call's method name, as the trait and the script spell it.
fn method(call: &Call<'_>) -> &'static str {
    match call {
        Call::VolumeCreate(_) => "volume_create",
        Call::VolumeInspect(_) => "volume_inspect",
        Call::ContainerInspect(_) => "container_inspect",
        Call::RunClaim(_) => "run_claim",
        Call::SidecarClaim(..) => "sidecar_claim",
        Call::RunLogs(_) => "run_logs",
        Call::RmForce(_) => "rm_force",
        Call::RunServing(_) => "run_serving",
        Call::VolumeRm(_) => "volume_rm",
        Call::Health(_) => "health",
        Call::CaddyReload => "caddy_reload",
        Call::LabelledVolumes => "labelled_volumes",
    }
}

/// Returns the board a call is about, where it names one.
fn name<'a>(call: &Call<'a>) -> Option<&'a Name> {
    match *call {
        Call::VolumeCreate(n)
        | Call::VolumeInspect(n)
        | Call::ContainerInspect(n)
        | Call::RunClaim(n)
        | Call::SidecarClaim(n, _)
        | Call::RunLogs(n)
        | Call::RmForce(n)
        | Call::RunServing(n)
        | Call::VolumeRm(n)
        | Call::Health(n) => Some(n),
        Call::CaddyReload | Call::LabelledVolumes => None,
    }
}

/// Returns a script file's calls file: `<script>.calls`.
pub fn calls_path(script: &Path) -> PathBuf {
    let mut path = script.as_os_str().to_owned();
    path.push(".calls");
    PathBuf::from(path)
}

/// Returns one script line: the call expected and its answer, escaped.
#[cfg(test)]
pub fn line(method: &str, name: Option<&str>, code: i32, stdout: &str, stderr: &str) -> String {
    format!("{method}\t{}\t{code}\t{}\t{}\n", name.unwrap_or("-"), escape(stdout), escape(stderr))
}

/// Returns a field's text as the script carries it.
///
/// A backslash, a line break and a tab are escaped.
#[cfg(test)]
fn escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('\n', "\\n").replace('\t', "\\t")
}

/// Undoes a script field's escapes: `\n`, `\t`, `\\`.
///
/// Any other backslash is kept as written.
fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

impl Docker for FakeDocker {
    /// Answers one call from the script's next line under the call's name.
    ///
    /// That line answers where it expects this call, else [`UNEXPECTED`]
    /// does; either way the call is recorded, with the input the call
    /// carries.
    ///
    /// # Errors
    ///
    /// Where the fake was opened from a file, a calls file that cannot be
    /// opened or appended to — an expected call's script line then consumed,
    /// and the call left out of the calls recorded in memory.
    fn run(&self, call: Call<'_>) -> io::Result<Exit> {
        let input = call.input();
        let method = method(&call);
        let name = name(&call).map(Name::to_string);
        let mut script = self.script.lock().unwrap_or_else(|e| e.into_inner());
        let at = script.iter().position(|s| s.name == name);
        let hit = at.filter(|&i| script[i].method == method);
        let expected = hit.is_some();
        let exit = match hit {
            Some(i) => {
                let matched = script.remove(i).expect("`position` found the line, in range");
                Exit { code: Some(matched.code), stdout: matched.stdout, stderr: matched.stderr }
            }
            None => {
                let shown = name.as_deref().unwrap_or("-");
                let next = at.map_or_else(|| format!("nothing more under {shown}"), |i| format!("{} {shown}", script[i].method));
                let stderr = format!("docker-fake: unexpected call {method} {shown}; the script expected {next}\n");
                Exit { code: Some(UNEXPECTED), stdout: Vec::new(), stderr: stderr.into_bytes() }
            }
        };
        drop(script);
        if let Some(calls_file) = &self.calls_file {
            let mut line = format!("{method}\t{}\t{}", name.as_deref().unwrap_or("-"), exit.said());
            if let Some(bytes) = input {
                line.push_str(&format!("\tstdin={}", bytes.len()));
            }
            if !expected {
                line.push_str("\tunexpected");
            }
            line.push('\n');
            OpenOptions::new().append(true).open(calls_file)?.write_all(line.as_bytes())?;
        }
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).push(Called { method, name: name.clone(), input: input.map(<[u8]>::to_vec), expected });
        #[cfg(test)]
        if let Some(pause) = self.pause.get() {
            pause(method, name.as_deref());
        }
        Ok(exit)
    }
}
