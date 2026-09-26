use quantification_core::config::MarkerStyle;
use quantification_core::fingerprint::marker_checksum;
use quantification_core::ledger::{Commit, CommitKind, CommitOutcome, Ledger, Proposal, framing};
use quantification_core::splice::{splice_into, splice_ledger, spliced_len};
use quantification_core::stage1::{Unit, split_span};

const UNICODE: MarkerStyle = MarkerStyle::Unicode;
const ASCII: MarkerStyle = MarkerStyle::Ascii;
const POISON: u8 = 0x00;

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("spliced output is valid utf-8")
}

fn oracle(style: MarkerStyle, commit: &Commit, anchor: &[u8]) -> String {
    let (open, sep, close) = framing(style);
    let (prefix, suffix) = commit.kind.core(style);
    format!(
        "{open}{prefix}{}{suffix}{sep}{:04x}{close}",
        commit.count,
        marker_checksum(anchor)
    )
}

fn line(text: &[u8], len: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    for i in 0..len {
        bytes.push(text[i % text.len()]);
    }
    bytes
}

fn span_of(parts: &[&[u8]]) -> Vec<u8> {
    let mut span = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            span.extend_from_slice(b"\\n");
        }
        span.extend_from_slice(part);
    }
    span
}

fn commits_of(units: &[Unit], style: MarkerStyle, groups: &[(usize, usize)]) -> Vec<Commit> {
    let mut ledger = Ledger::new(units, style);
    for (start, end) in groups {
        let _ = ledger.try_commit(Proposal::run(*start..*end, CommitKind::ExactRun));
    }
    ledger.commits().to_vec()
}

#[test]
fn a_multi_commit_span_produces_the_pinned_output_bytes() {
    let body = line(b"x", 40);
    let span = span_of(&[b"head", &body, &body, &body, &body, &body, b"tail"]);
    let units = split_span(&span);
    assert_eq!(units.len(), 7);
    let commits = commits_of(&units, UNICODE, &[(1, 6)]);
    assert_eq!(commits.len(), 1);
    let mut out = Vec::new();
    splice_into(&span, UNICODE, &commits, &mut out);
    let expect = format!(
        "head\\n{}{}\\ntail",
        text(&body),
        oracle(UNICODE, &commits[0], &body)
    );
    assert_eq!(text(&out), expect);
    assert_eq!(out.len(), spliced_len(span.len(), UNICODE, &commits));
    assert_eq!(
        out.len(),
        "head\\ntail".len() + 2 + body.len() + oracle(UNICODE, &commits[0], &body).len()
    );
}

#[test]
fn two_commits_in_one_span_are_emitted_in_anchor_offset_order() {
    let first = line(b"a", 50);
    let second = line(b"b", 50);
    let span = span_of(&[&first, &first, &first, b"mid", &second, &second, &second]);
    let units = split_span(&span);
    let commits = commits_of(&units, UNICODE, &[(4, 7), (0, 3)]);
    let mut out = Vec::new();
    splice_into(&span, UNICODE, &commits, &mut out);
    let expect = format!(
        "{}{}\\nmid\\n{}{}",
        text(&first),
        oracle(UNICODE, &commits[0], &first),
        text(&second),
        oracle(UNICODE, &commits[1], &second)
    );
    assert_eq!(text(&out), expect);
    assert!(commits[0].anchor.start < commits[1].anchor.start);
    assert_eq!(out.len(), spliced_len(span.len(), UNICODE, &commits));
}

#[test]
fn a_commit_at_the_very_start_and_at_the_very_end_of_the_buffer() {
    let head = line(b"h", 44);
    let tail = line(b"t", 44);
    let mut buffer = Vec::new();
    for _ in 0..3 {
        buffer.extend_from_slice(&head);
        buffer.extend_from_slice(b"\\n");
    }
    buffer.extend_from_slice(b"\\nbetween\\n");
    for _ in 0..3 {
        buffer.extend_from_slice(&tail);
        buffer.extend_from_slice(b"\\n");
    }
    let units = split_span(&buffer);
    assert_eq!(units.len(), 7);
    let commits = commits_of(&units, UNICODE, &[(0, 3), (4, 7)]);
    let mut out = Vec::new();
    splice_into(&buffer, UNICODE, &commits, &mut out);
    let expect = format!(
        "{}{}\\n\\nbetween\\n{}{}\\n",
        text(&head),
        oracle(UNICODE, &commits[0], &head),
        text(&tail),
        oracle(UNICODE, &commits[1], &tail)
    );
    assert_eq!(text(&out), expect);
    assert_eq!(commits[0].removed.start, 0);
    assert_eq!(buffer.len() - commits[1].removed.end, 2);
    assert!(out.ends_with(b"\\n"));
}

#[test]
fn no_commits_is_a_byte_for_byte_passthrough() {
    for span in [
        span_of(&[b"only", b"one", b"line"]),
        br#"{\"k\":\"v\"}"#.to_vec(),
        Vec::new(),
    ] {
        let units = split_span(&span);
        let ledger = Ledger::new(&units, ASCII);
        assert!(ledger.commits().is_empty());
        let mut out = vec![POISON; 128];
        let spliced = splice_ledger(&span, &ledger, &mut out);
        assert_eq!(spliced, &span[..]);
        assert_eq!(out.len(), span.len());
        assert_eq!(spliced_len(span.len(), ASCII, ledger.commits()), span.len());
    }
}

#[test]
fn a_leading_bom_is_copied_verbatim_and_offsets_stay_absolute() {
    let body = line(b"z", 48);
    let mut buffer = vec![0xef, 0xbb, 0xbf];
    buffer.extend_from_slice(b"{\\\"content\\\":\\\"");
    let span_start = buffer.len();
    for _ in 0..4 {
        buffer.extend_from_slice(&body);
        buffer.extend_from_slice(b"\\n");
    }
    buffer.extend_from_slice(b"\\\"}");
    let units = split_span(&buffer[span_start..])
        .iter()
        .map(|unit| Unit {
            range: unit.range.start + span_start..unit.range.end + span_start,
            eligible: unit.eligible,
        })
        .collect::<Vec<_>>();
    let mut ledger = Ledger::new(&units, ASCII);
    let commit = match ledger.try_commit(Proposal::run(0..4, CommitKind::ExactRun)) {
        CommitOutcome::Committed(commit) => commit,
        other => panic!("expected a commit, got {other:?}"),
    };
    assert_eq!(commit.anchor.start, span_start);
    let mut out = Vec::new();
    splice_ledger(&buffer, &ledger, &mut out);
    assert_eq!(&out[..3], &[0xef, 0xbb, 0xbf]);
    assert_eq!(&out[3..span_start], &buffer[3..span_start]);
    let spliced = &out[span_start..];
    assert!(spliced.starts_with(&body[..]));
    assert!(spliced.ends_with(b"\\n\\\"}"));
    assert!(text(&out).contains(&oracle(ASCII, &commit, &body)));
    assert_eq!(
        out.len(),
        spliced_len(buffer.len(), ASCII, std::slice::from_ref(&commit))
    );
}

#[test]
fn a_poisoned_reused_buffer_never_leaks_a_stale_byte() {
    let body = line(b"q", 44);
    let long = span_of(&[
        &body, &body, &body, &body, &body, &body, &body, &body, &body, &body,
    ]);
    let short = span_of(&[&body, &body, &body]);
    let mut out = Vec::new();
    let long_len = splice_ledger(&long, &Ledger::new(&split_span(&long), UNICODE), &mut out).len();
    assert_eq!(long_len, long.len());
    out.clear();
    out.resize(out.capacity().min(4096), POISON);
    assert!(out.iter().all(|&b| b == POISON));
    let units = split_span(&short);
    let mut ledger = Ledger::new(&units, UNICODE);
    assert!(matches!(
        ledger.try_commit(Proposal::run(0..3, CommitKind::ExactRun)),
        CommitOutcome::Committed(_)
    ));
    let short_out = splice_ledger(&short, &ledger, &mut out);
    let short_len = short_out.len();
    assert!(short_len < long_len);
    assert_eq!(short_len, 44 + 26);
    assert!(
        short_out.iter().all(|&byte| byte != POISON),
        "a stale buffer byte reached the output"
    );
    assert!(short_out.starts_with(&body[..]));
    assert_eq!(
        spliced_len(short.len(), UNICODE, ledger.commits()),
        short_len
    );
}

#[test]
fn the_output_equals_the_input_everywhere_outside_the_patched_ranges() {
    let mut seed = 0x1234_5678u64;
    let mut next = move || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) as usize
    };
    let mut spliced_commits = 0;
    for _case in 0..64 {
        let lines = 3 + next() % 12;
        let width = 44 + next() % 20;
        let alphabet = line(b"abcdefgh", 1 + next() % 4);
        let parts: Vec<Vec<u8>> = (0..lines)
            .map(|i| line(&alphabet, width + (i % 2) * 7))
            .collect();
        let borrowed: Vec<&[u8]> = parts.iter().map(|part| part.as_slice()).collect();
        let buffer = span_of(&borrowed);
        let units = split_span(&buffer);
        let mut groups = Vec::new();
        let mut at = 0;
        while at + 3 <= units.len() {
            let end = (at + 3 + next() % 4).min(units.len());
            groups.push((at, end));
            at = end;
        }
        let commits = commits_of(&units, UNICODE, &groups);
        spliced_commits += commits.len();
        let mut out = Vec::new();
        splice_into(&buffer, UNICODE, &commits, &mut out);
        assert_eq!(out.len(), spliced_len(buffer.len(), UNICODE, &commits));
        let mut cursor = 0;
        let mut read = 0;
        for commit in &commits {
            let copied = commit.removed.start - read;
            assert_eq!(
                &out[cursor..cursor + copied],
                &buffer[read..commit.removed.start]
            );
            cursor += copied;
            let anchor = &buffer[commit.anchor.clone()];
            assert_eq!(&out[cursor..cursor + anchor.len()], anchor);
            cursor += anchor.len();
            let marker = oracle(UNICODE, commit, anchor);
            assert_eq!(&out[cursor..cursor + marker.len()], marker.as_bytes());
            cursor += marker.len();
            read = commit.removed.end;
        }
        let tail = buffer.len() - read;
        assert_eq!(&out[cursor..cursor + tail], &buffer[read..]);
        assert_eq!(cursor + tail, out.len());
    }
    assert!(spliced_commits > 32, "only {spliced_commits} commits");
}

#[test]
fn record_joiners_stay_outside_the_marker() {
    let big = {
        let mut bytes = b"{".to_vec();
        bytes.extend(std::iter::repeat_n(b'm', 16_000));
        bytes.push(b'}');
        bytes
    };
    let mut buffer = vec![b'['];
    for i in 0..5 {
        if i > 0 {
            buffer.push(b',');
        }
        buffer.extend_from_slice(&big);
    }
    buffer.push(b']');
    let units = split_span(&buffer);
    assert_eq!(units.len(), 5);
    let commits = commits_of(&units, UNICODE, &[(1, 4)]);
    assert_eq!(commits.len(), 1);
    let mut out = Vec::new();
    splice_into(&buffer, UNICODE, &commits, &mut out);
    let expect = format!(
        "[{},{}{},{}]",
        text(&big),
        text(&big),
        oracle(UNICODE, &commits[0], &big),
        text(&big)
    );
    assert_eq!(out.len(), 3 * big.len() + 4 + 26);
    assert_eq!(text(&out), expect);
}

#[test]
#[should_panic(expected = "commits must be ascending, disjoint and in bounds")]
fn commits_out_of_emit_order_are_refused() {
    let first = line(b"a", 50);
    let second = line(b"b", 50);
    let span = span_of(&[&first, &first, &first, &second, &second, &second]);
    let units = split_span(&span);
    let mut commits = commits_of(&units, UNICODE, &[(0, 3), (3, 6)]);
    assert_eq!(commits.len(), 2);
    commits.reverse();
    let mut out = Vec::new();
    splice_into(&span, UNICODE, &commits, &mut out);
}

#[test]
fn a_reused_buffer_is_reused_not_reallocated() {
    let span = span_of(&[b"a", b"b", b"c"]);
    let units = split_span(&span);
    let ledger = Ledger::new(&units, UNICODE);
    let mut out = Vec::new();
    let capacity = {
        let first = splice_ledger(&span, &ledger, &mut out);
        assert_eq!(first, &span[..]);
        out.capacity()
    };
    for _ in 0..64 {
        assert_eq!(splice_ledger(&span, &ledger, &mut out), &span[..]);
    }
    assert_eq!(out.capacity(), capacity);
}
