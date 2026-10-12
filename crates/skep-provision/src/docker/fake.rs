//! THE SCRIPTED FAKE — `test-hooks` alone, so no shipped build holds it: a
//! [`Docker`] answered from a SCRIPT the test writes, one line per call it
//! expects, in order, each with the exit code and the stdout (and, where
//! wanted, the stderr) the call answers. It RECORDS every call in order —
//! the method, the name, the sidecar's stdin — in memory and, where it was
//! opened from a file (the binary's `--docker-fake <script>`), as one line
//! per call in the sibling file `<script>.calls`, which a suite driving the
//! built binary reads after it. A call the script did not expect — another
//! method or another name than the script's next line, or any call once the
//! script is spent — is answered with exit [`UNEXPECTED`] and a stderr
//! saying so, recorded as unexpected, and leaves the script where it was;
//! `FakeDocker::assert_done` then fails the test, as does a script line
//! left uncalled.
//!
//! THE SCRIPT's LINE: TAB-separated fields — the method as the trait spells
//! it, the name (`-` for the reload, which names none), the exit code, then
//! optionally the stdout and the stderr, in which `\n` is a line break, `\t`
//! a tab and `\\` a backslash (`line` writes one). A blank line, or one
//! beginning `#`, is no call.

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::{Call, Docker, Exit};
use crate::record::Name;

/// The exit code a call the script did not expect answers: Docker's own
/// code for an error of the `docker` command itself, as this crate knows
/// Docker (UNVERIFIED HERE) — a code every step reads as a failure.
pub const UNEXPECTED: i32 = 125;

/// One scripted answer: the call it expects and what that call answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// The method expected, as the trait spells it.
    pub method: String,
    /// The name expected, `None` for the reload.
    pub name: Option<String>,
    /// The exit code answered.
    pub code: i32,
    /// The stdout answered.
    pub stdout: Vec<u8>,
    /// The stderr answered.
    pub stderr: Vec<u8>,
}

/// One call the fake received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Called {
    /// The method called.
    pub method: &'static str,
    /// The name it named, `None` for the reload.
    pub name: Option<String>,
    /// What it carried on stdin — the sidecar's record — where it carried
    /// anything.
    pub stdin: Option<Vec<u8>>,
    /// Whether the script's next line expected it.
    pub expected: bool,
}

impl Called {
    /// The call as `<method> <name>` — `<method>` alone for the reload —
    /// the form a test lists the expected sequence in.
    #[cfg(test)]
    pub fn said(&self) -> String {
        match &self.name {
            Some(name) => format!("{} {name}", self.method),
            None => self.method.to_owned(),
        }
    }
}

/// THE FAKE: the script left to answer, the calls received, and where they
/// are recorded on disk, where anywhere.
#[derive(Debug)]
pub struct FakeDocker {
    script: Mutex<VecDeque<Step>>,
    calls: Mutex<Vec<Called>>,
    record: Option<PathBuf>,
}

impl FakeDocker {
    /// The fake over a script's text.
    pub fn parse(script: &str) -> Result<FakeDocker, String> {
        let mut steps = VecDeque::new();
        for (i, text) in script.lines().enumerate() {
            if text.trim().is_empty() || text.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = text.split('\t').collect();
            if fields.len() < 3 || fields.len() > 5 {
                return Err(format!("script line {}: three to five TAB-separated fields, not {}", i + 1, fields.len()));
            }
            let code = fields[2].parse().map_err(|_| format!("script line {}: `{}` is no exit code", i + 1, fields[2]))?;
            steps.push_back(Step {
                method: fields[0].to_owned(),
                name: (fields[1] != "-").then(|| fields[1].to_owned()),
                code,
                stdout: unescape(fields.get(3).copied().unwrap_or("")).into_bytes(),
                stderr: unescape(fields.get(4).copied().unwrap_or("")).into_bytes(),
            });
        }
        Ok(FakeDocker { script: Mutex::new(steps), calls: Mutex::new(Vec::new()), record: None })
    }

    /// The fake over the script file at `path`, recording every call it
    /// receives to [`calls_path`]`(path)`, emptied first — the binary's
    /// `--docker-fake <script>`.
    pub fn open(path: &Path) -> io::Result<FakeDocker> {
        let text = std::fs::read_to_string(path)?;
        let mut fake = FakeDocker::parse(&text).map_err(io::Error::other)?;
        let record = calls_path(path);
        std::fs::write(&record, b"")?;
        fake.record = Some(record);
        Ok(fake)
    }

    /// Every call received, in order.
    #[cfg(test)]
    pub fn calls(&self) -> Vec<Called> {
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Every call received, each as `Called::said` spells it.
    #[cfg(test)]
    pub fn said(&self) -> Vec<String> {
        self.calls().iter().map(Called::said).collect()
    }

    /// The calls the script did not expect.
    #[cfg(test)]
    pub fn unexpected(&self) -> Vec<Called> {
        self.calls().into_iter().filter(|c| !c.expected).collect()
    }

    /// The script's lines not yet called.
    #[cfg(test)]
    pub fn left(&self) -> Vec<Step> {
        self.script.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect()
    }

    /// FAILS THE TEST on a call the script did not expect, or on a script
    /// line left uncalled.
    #[cfg(test)]
    pub fn assert_done(&self) {
        let unexpected: Vec<String> = self.unexpected().iter().map(Called::said).collect();
        assert!(unexpected.is_empty(), "calls the script did not expect: {unexpected:?}; every call: {:?}", self.said());
        let left: Vec<String> = self.left().iter().map(|s| format!("{} {}", s.method, s.name.as_deref().unwrap_or("-"))).collect();
        assert!(left.is_empty(), "script lines never called: {left:?}; every call: {:?}", self.said());
    }

    /// One call answered: the script's next line where it expects this
    /// call, else [`UNEXPECTED`]; either way recorded.
    fn answer(&self, call: Call<'_>, stdin: Option<&[u8]>) -> io::Result<Exit> {
        let method = method(&call);
        let name = name(&call).map(Name::to_string);
        let mut script = self.script.lock().unwrap_or_else(|e| e.into_inner());
        let expected = script.front().is_some_and(|s| s.method == method && s.name == name);
        let exit = if expected {
            let step = script.pop_front().expect("the front was read");
            Exit { code: Some(step.code), stdout: step.stdout, stderr: step.stderr }
        } else {
            let next = script.front().map_or_else(|| "nothing more".to_owned(), |s| format!("{} {}", s.method, s.name.as_deref().unwrap_or("-")));
            let stderr = format!("docker-fake: unexpected call {method} {}; the script expected {next}\n", name.as_deref().unwrap_or("-"));
            Exit { code: Some(UNEXPECTED), stdout: Vec::new(), stderr: stderr.into_bytes() }
        };
        drop(script);
        if let Some(record) = &self.record {
            let mut line = format!("{method}\t{}\t{}", name.as_deref().unwrap_or("-"), exit.said());
            if let Some(bytes) = stdin {
                line.push_str(&format!("\tstdin={}", bytes.len()));
            }
            if !expected {
                line.push_str("\tunexpected");
            }
            line.push('\n');
            OpenOptions::new().append(true).open(record)?.write_all(line.as_bytes())?;
        }
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).push(Called { method, name, stdin: stdin.map(<[u8]>::to_vec), expected });
        Ok(exit)
    }
}

/// A call's method name, as the trait and the script spell it.
pub fn method(call: &Call<'_>) -> &'static str {
    match call {
        Call::VolumeCreate(_) => "volume_create",
        Call::VolumeInspect(_) => "volume_inspect",
        Call::ContainerInspect(_) => "container_inspect",
        Call::RunClaim(_) => "run_claim",
        Call::SidecarClaim(_) => "sidecar_claim",
        Call::RmForce(_) => "rm_force",
        Call::RunServing(_) => "run_serving",
        Call::VolumeRm(_) => "volume_rm",
        Call::Health(_) => "health",
        Call::CaddyReload => "caddy_reload",
    }
}

/// The board a call is about, where it names one.
pub fn name<'a>(call: &Call<'a>) -> Option<&'a Name> {
    match *call {
        Call::VolumeCreate(n)
        | Call::VolumeInspect(n)
        | Call::ContainerInspect(n)
        | Call::RunClaim(n)
        | Call::SidecarClaim(n)
        | Call::RmForce(n)
        | Call::RunServing(n)
        | Call::VolumeRm(n)
        | Call::Health(n) => Some(n),
        Call::CaddyReload => None,
    }
}

/// Where a script file's calls are recorded: `<script>.calls`.
pub fn calls_path(script: &Path) -> PathBuf {
    let mut path = script.as_os_str().to_owned();
    path.push(".calls");
    PathBuf::from(path)
}

/// ONE SCRIPT LINE: the call expected and its answer, escaped.
#[cfg(test)]
pub fn line(method: &str, name: Option<&str>, code: i32, stdout: &str, stderr: &str) -> String {
    format!("{method}\t{}\t{code}\t{}\t{}\n", name.unwrap_or("-"), escape(stdout), escape(stderr))
}

/// A field's text as the script carries it: a backslash, a line break and
/// a tab escaped.
#[cfg(test)]
fn escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('\n', "\\n").replace('\t', "\\t")
}

/// A script field's escapes undone: `\n`, `\t`, `\\`; any other backslash
/// kept as written.
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
    fn volume_create(&self, name: &Name) -> io::Result<Exit> {
        self.answer(Call::VolumeCreate(name), None)
    }

    fn volume_inspect(&self, name: &Name) -> io::Result<Exit> {
        self.answer(Call::VolumeInspect(name), None)
    }

    fn container_inspect(&self, name: &Name) -> io::Result<Exit> {
        self.answer(Call::ContainerInspect(name), None)
    }

    fn run_claim(&self, name: &Name) -> io::Result<Exit> {
        self.answer(Call::RunClaim(name), None)
    }

    fn sidecar_claim(&self, name: &Name, record: &[u8]) -> io::Result<Exit> {
        self.answer(Call::SidecarClaim(name), Some(record))
    }

    fn rm_force(&self, name: &Name) -> io::Result<Exit> {
        self.answer(Call::RmForce(name), None)
    }

    fn run_serving(&self, name: &Name) -> io::Result<Exit> {
        self.answer(Call::RunServing(name), None)
    }

    fn volume_rm(&self, name: &Name) -> io::Result<Exit> {
        self.answer(Call::VolumeRm(name), None)
    }

    fn health(&self, name: &Name) -> io::Result<Exit> {
        self.answer(Call::Health(name), None)
    }

    fn caddy_reload(&self) -> io::Result<Exit> {
        self.answer(Call::CaddyReload, None)
    }
}
