//! THE REPORT TABLE (`search.md` §7: "TIMING TESTS THAT REPORT, never assert
//! — each pin below is a number the test prints beside its measurement and
//! the lane's report compares, with WHAT A MISS WOULD CHANGE stated so the
//! owner rules on a number and not on a surprise"). One shape for every row
//! — `row | tier | pin | measured | WITHIN or MISSED` — printed by each
//! budget test behind the one marker `BUDGET |`, so the lane's report and the
//! shell's and the UX's citations grep a row by its name. A MISS is a word on
//! the line and never a failed test: the two rows the design ASSERTS (M7's
//! tree, the fuzzy flag) assert through their own `assert!`s and not through
//! this table.

// A fixture module: the rows take what they need of this surface, and a
// helper no row calls yet is no fault.
#![allow(dead_code)]

use std::fmt;
use std::time::Duration;

/// The marker every row starts with.
pub const MARKER: &str = "BUDGET";

/// The verdict a row prints last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The measurement is within the pin.
    Within,
    /// The measurement misses the pin — reported, the design's "what a miss
    /// would change" being the owner's decision and not a gate's.
    Missed,
    /// The row has no pin: the number is reported.
    Reported,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Verdict::Within => "WITHIN",
            Verdict::Missed => "MISSED",
            Verdict::Reported => "REPORTED",
        })
    }
}

/// One row of the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The row's name — §7.1's `M` and `what`, as `m1-build`, `save-bytes-per-hour`.
    pub row: String,
    /// The tier — `10^3`, `10^4`, `records`, or `-` where the row has none.
    pub tier: String,
    /// The pin as the design states it, or `-` where it states none.
    pub pin: String,
    /// The measurement, with its unit.
    pub measured: String,
    /// The verdict.
    pub verdict: Verdict,
}

impl Row {
    /// The row's one line.
    pub fn line(&self) -> String {
        format!(
            "{MARKER} | {} | {} | {} | {} | {}",
            self.row, self.tier, self.pin, self.measured, self.verdict
        )
    }

    /// Print the row.
    pub fn print(&self) {
        println!("{}", self.line());
    }
}

/// A row pinned at most `pin` of time: WITHIN where `measured <= pin`.
pub fn at_most(row: &str, tier: &str, pin: Duration, measured: Duration) -> Row {
    Row {
        row: row.into(),
        tier: tier.into(),
        pin: format!("<= {}", time(pin)),
        measured: time(measured),
        verdict: if measured <= pin { Verdict::Within } else { Verdict::Missed },
    }
}

/// A row pinned at most `pin` times a base quantity: WITHIN where the ratio
/// holds; `measured` is the ratio, printed beside the two quantities.
pub fn at_most_ratio(
    row: &str,
    tier: &str,
    pin: f64,
    numerator: u64,
    denominator: u64,
    what: &str,
) -> Row {
    let ratio =
        if denominator == 0 { f64::INFINITY } else { numerator as f64 / denominator as f64 };
    Row {
        row: row.into(),
        tier: tier.into(),
        pin: format!("<= {pin}x {what}"),
        measured: format!("{ratio:.3}x ({} over {})", bytes(numerator), bytes(denominator)),
        verdict: if ratio <= pin { Verdict::Within } else { Verdict::Missed },
    }
}

/// A row with no pin: the measurement reported.
pub fn reported(row: &str, tier: &str, measured: impl Into<String>) -> Row {
    Row {
        row: row.into(),
        tier: tier.into(),
        pin: "-".into(),
        measured: measured.into(),
        verdict: Verdict::Reported,
    }
}

/// A row whose verdict the caller judged.
pub fn judged(row: &str, tier: &str, pin: &str, measured: impl Into<String>, within: bool) -> Row {
    Row {
        row: row.into(),
        tier: tier.into(),
        pin: pin.into(),
        measured: measured.into(),
        verdict: if within { Verdict::Within } else { Verdict::Missed },
    }
}

/// A duration in the unit that reads: `µs` under a millisecond, `ms` under a
/// second, `s` above.
pub fn time(d: Duration) -> String {
    let us = d.as_secs_f64() * 1e6;
    if us < 1_000.0 {
        format!("{us:.1} us")
    } else if us < 1_000_000.0 {
        format!("{:.3} ms", us / 1_000.0)
    } else {
        format!("{:.3} s", us / 1_000_000.0)
    }
}

/// A byte count with thousands separators and its binary multiple.
pub fn bytes(n: u64) -> String {
    let digits = n.to_string();
    let mut grouped = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(c);
    }
    let human = if n >= 1 << 30 {
        format!("{:.2} GiB", n as f64 / (1u64 << 30) as f64)
    } else if n >= 1 << 20 {
        format!("{:.2} MiB", n as f64 / (1u64 << 20) as f64)
    } else if n >= 1 << 10 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    };
    format!("{grouped} B ({human})")
}

/// A count with thousands separators.
pub fn count(n: u64) -> String {
    bytes(n).split(' ').next().expect("the grouped digits").to_string()
}

/// A sample of timings: the percentiles a latency row reports.
#[derive(Debug, Clone, Default)]
pub struct Sample(Vec<Duration>);

impl Sample {
    pub fn new() -> Sample {
        Sample(Vec::new())
    }

    pub fn push(&mut self, d: Duration) {
        self.0.push(d);
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The `q`-th percentile, nearest-rank: `q` in `0.0..=1.0`.
    pub fn percentile(&self, q: f64) -> Duration {
        if self.0.is_empty() {
            return Duration::ZERO;
        }
        let mut sorted = self.0.clone();
        sorted.sort();
        let rank = ((q * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
        sorted[rank - 1]
    }

    pub fn p50(&self) -> Duration {
        self.percentile(0.5)
    }

    pub fn p99(&self) -> Duration {
        self.percentile(0.99)
    }

    pub fn max(&self) -> Duration {
        self.0.iter().copied().max().unwrap_or(Duration::ZERO)
    }

    pub fn mean(&self) -> Duration {
        if self.0.is_empty() {
            return Duration::ZERO;
        }
        self.0.iter().sum::<Duration>() / self.0.len() as u32
    }

    pub fn total(&self) -> Duration {
        self.0.iter().sum()
    }

    /// The summary a latency row prints beside its p99.
    pub fn summary(&self) -> String {
        format!(
            "p50 {} / p99 {} / max {} over {} samples",
            time(self.p50()),
            time(self.p99()),
            time(self.max()),
            self.len()
        )
    }
}

/// One line that is not a row — a fact the report carries beside the rows
/// (the board's time, the corpus's shape, a constant's verdict), behind the
/// same marker so it is collected with them.
pub fn note(text: impl fmt::Display) {
    println!("{MARKER} | note | {text}");
}
