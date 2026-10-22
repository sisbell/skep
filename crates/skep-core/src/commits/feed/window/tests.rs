use super::*;

/// A file of position-ordered lines: entries at the given positions, with a
/// fence line wherever a `(position, true)` stands, each line padded so no
/// two have one length and a probe lands anywhere in a line.
fn file_of(dir: &Path, lines: &[(u64, bool)]) -> std::path::PathBuf {
    let path = dir.join("lines.log");
    let mut out = String::new();
    for (i, (p, fence)) in lines.iter().enumerate() {
        let pad = "x".repeat(i % 7);
        if *fence {
            out.push_str(&format!("{{\"covered\":{p},\"pad\":\"{pad}\"}}\n"));
        } else {
            out.push_str(&format!("{{\"at\":{p},\"pad\":\"{pad}\"}}\n"));
        }
    }
    std::fs::write(&path, out).expect("the file");
    path
}

/// The positions a cursor placed above `since` reads, in order.
fn read_above(path: &Path, since: u64) -> Vec<u64> {
    let mut cursor = Cursor::open_above(path, since).expect("the cursor");
    let mut out = Vec::new();
    while let Some((_, line)) = cursor.next_line().expect("a read") {
        out.push(position_of(&line).expect("a position"));
    }
    out
}

/// The search places the cursor at the first line above the fence, for
/// every fence, over entries and fences alike — a fence line at a position
/// is read as that position — and a fence at or above every line reads
/// nothing.
#[test]
fn the_cursor_starts_at_the_first_line_above_the_fence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let lines: Vec<(u64, bool)> =
        [1, 2, 5, 9, 9, 12, 30, 31, 200, 201, 4_096, 4_097, 10_000, 10_000]
            .iter()
            .enumerate()
            .map(|(i, &p)| (p, i == 4 || i == 13))
            .collect();
    let path = file_of(dir.path(), &lines);
    let positions: Vec<u64> = lines.iter().map(|(p, _)| *p).collect();
    for since in [0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 29, 30, 31, 199, 4_096, 9_999, 10_000, 20_000]
    {
        let want: Vec<u64> = positions.iter().copied().filter(|&p| p > since).collect();
        assert_eq!(read_above(&path, since), want, "since {since}");
    }
}

/// The byte each line begins at is the line's own, and the read stops at a
/// torn last line — one ended by no newline — as the next open's cut
/// would stop it, wherever the search's probes land.
#[test]
fn the_cursor_names_each_lines_byte_and_stops_at_a_torn_line() {
    let dir = tempfile::tempdir().expect("tempdir");
    let lines: Vec<(u64, bool)> = (1..=40).map(|p| (p * 3, false)).collect();
    let path = file_of(dir.path(), &lines);
    let text = std::fs::read_to_string(&path).expect("read");
    let starts: Vec<u64> = std::iter::once(0)
        .chain(text.match_indices('\n').map(|(i, _)| i as u64 + 1))
        .take(lines.len())
        .collect();
    let mut cursor = Cursor::open_above(&path, 60).expect("the cursor");
    let mut seen = Vec::new();
    while let Some((offset, line)) = cursor.next_line().expect("a read") {
        seen.push((offset, position_of(&line).expect("a position")));
    }
    let want: Vec<(u64, u64)> = starts
        .iter()
        .zip(&lines)
        .filter(|(_, (p, _))| *p > 60)
        .map(|(o, (p, _))| (*o, *p))
        .collect();
    assert_eq!(seen, want, "each line at its own byte");
    // Torn: the last line loses its newline and half its bytes.
    let torn = &text[..text.len() - 6];
    std::fs::write(&path, torn).expect("tear");
    let whole: Vec<u64> = lines.iter().map(|(p, _)| *p).take(lines.len() - 1).collect();
    for since in [0, 60, 115, 117, 118, 120] {
        let want: Vec<u64> = whole.iter().copied().filter(|&p| p > since).collect();
        assert_eq!(
            read_above(&path, since),
            want,
            "since {since}: the torn line is read by nobody"
        );
    }
}

/// An empty file, a one-line file and a file with no newline at all each
/// place the cursor where it reads what stands above the fence, which may
/// be nothing.
#[test]
fn the_edges_an_empty_a_one_line_and_an_unterminated_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("lines.log");
    std::fs::write(&path, "").expect("empty");
    assert_eq!(read_above(&path, 0), Vec::<u64>::new());
    std::fs::write(&path, "{\"at\":7}\n").expect("one line");
    assert_eq!(read_above(&path, 0), [7]);
    assert_eq!(read_above(&path, 6), [7]);
    assert_eq!(read_above(&path, 7), Vec::<u64>::new());
    std::fs::write(&path, "{\"at\":7}").expect("unterminated");
    assert_eq!(read_above(&path, 0), Vec::<u64>::new(), "a torn only line is read by nobody");
}

/// A line's position is its entry's `at`, or a fence's `covered`,
/// `min_since` or `floor`; anything else names none.
#[test]
fn a_lines_position_is_its_entry_or_its_fence() {
    assert_eq!(position_of(b"{\"at\":12,\"op\":\"insert\"}"), Some(12));
    assert_eq!(position_of(b"{\"covered\":40}"), Some(40));
    assert_eq!(position_of(b"{\"min_since\":2047}"), Some(2047));
    assert_eq!(position_of(b"{\"floor\":2048}"), Some(2048));
    assert_eq!(position_of(b"{\"alg\":1,\"at\":9,\"sig\":\"ab\"}"), Some(9));
    assert_eq!(position_of(b"not json"), None);
    assert_eq!(position_of(b"{\"other\":1}"), None);
    assert_eq!(position_of(b"[1]"), None);
}
