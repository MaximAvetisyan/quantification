use std::ops::Range;
use std::path::Path;

use quantification_core::config::{MAX_LINE_BYTES, MAX_RECORD_BYTES, MarkerStyle};
use quantification_core::stage1::{Unit, carries_marker, joiner, split_span, split_span_counted};

const UNICODE: MarkerStyle = MarkerStyle::Unicode;

const SEPARATOR: &[u8; 3] = br"},{";
const CONTENT_KEY: &[u8] = b"\"content\":\"";
const NEWLINE_ESCAPE: &[u8; 2] = br"\n";
const U000A_UPPER: &[u8; 6] = br"\u000A";
const U000A_LOWER: &[u8; 6] = br"\u000a";
const PRE: &[u8; 5] = br"pre\n";
const POST: &[u8; 6] = br"\npost";

fn record(len: usize) -> Vec<u8> {
    let mut bytes = vec![b'x'; len];
    bytes[0] = b'{';
    *bytes.last_mut().unwrap() = b'}';
    bytes
}

fn array(records: &[Vec<u8>]) -> Vec<u8> {
    let mut line = vec![b'['];
    for (i, rec) in records.iter().enumerate() {
        if i > 0 {
            line.push(b',');
        }
        line.extend_from_slice(rec);
    }
    line.push(b']');
    line
}

fn comma_joined(rec: &[u8], count: usize) -> Vec<u8> {
    let mut line = Vec::new();
    for i in 0..count {
        if i > 0 {
            line.push(b',');
        }
        line.extend_from_slice(rec);
    }
    line
}

fn padded_shape(index: usize, len: usize) -> Vec<u8> {
    const SHAPES: [&[u8]; 3] = [
        br#"{"lvl":"info","msg":"heartbeat"}"#,
        br#"{"lvl":"warn","msg":"slow disk 42"}"#,
        br#"{"lvl":"info","msg":"retry ok"}"#,
    ];
    let shape = SHAPES[index % SHAPES.len()];
    let mut bytes = shape[..shape.len() - 1].to_vec();
    bytes.extend(std::iter::repeat_n(b'p', len - shape.len()));
    bytes.push(b'}');
    bytes
}

fn ranges(units: &[Unit]) -> Vec<Range<usize>> {
    units.iter().map(|u| u.range.clone()).collect()
}

fn lengths(units: &[Unit]) -> Vec<usize> {
    units.iter().map(|u| u.range.len()).collect()
}

fn flags(units: &[Unit]) -> Vec<bool> {
    units.iter().map(|u| u.eligible).collect()
}

fn joiner_lengths(span: &[u8], units: &[Unit]) -> Vec<usize> {
    (0..units.len())
        .map(|i| joiner(units, i, span.len()).len())
        .collect()
}

fn boundary_run(bytes: &[u8]) -> usize {
    let mut at = 0;
    while at < bytes.len() && bytes[at] == b'\\' {
        let len = if bytes.get(at + 1) == Some(&b'u') {
            6
        } else {
            2
        };
        if at + len > bytes.len() {
            break;
        }
        let unit = &bytes[at..at + len];
        if unit != NEWLINE_ESCAPE && unit != U000A_UPPER && unit != U000A_LOWER {
            break;
        }
        at += len;
    }
    at
}

fn reassemble(span: &[u8], units: &[Unit]) -> Vec<u8> {
    let first = units.first().map_or(0, |unit| unit.range.start);
    let mut out = span[..first].to_vec();
    for (index, unit) in units.iter().enumerate() {
        out.extend_from_slice(&span[unit.range.clone()]);
        out.extend_from_slice(&span[joiner(units, index, span.len())]);
    }
    out
}

fn assert_gap(span: &[u8], gap: &Range<usize>) {
    let bytes = &span[gap.clone()];
    let run = boundary_run(bytes);
    assert!(
        run == bytes.len() || (run == 0 && (bytes.is_empty() || bytes == b",")),
        "gap is not whole line-boundary escape units or one separator: {bytes:?}"
    );
}

fn assert_units(span: &[u8], units: &[Unit]) {
    for (i, unit) in units.iter().enumerate() {
        assert!(unit.range.start < unit.range.end, "empty unit at {i}");
        assert!(unit.range.end <= span.len(), "unit past span end at {i}");
        assert_gap(span, &joiner(units, i, span.len()));
    }
    assert_eq!(reassemble(span, units), span);
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn fixture_content(name: &str) -> Vec<u8> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/edges");
    let path = dir.join(name);
    let file = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let at = find(&file, CONTENT_KEY).expect("content key");
    let body = &file[at + CONTENT_KEY.len()..];
    let mut i = 0;
    while i < body.len() {
        if body[i] == b'\\' {
            i += if body.get(i + 1) == Some(&b'u') { 6 } else { 2 };
        } else if body[i] == b'"' {
            return body[..i].to_vec();
        } else {
            i += 1;
        }
    }
    panic!("unterminated content string in {}", path.display());
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const TOKENS: [&[u8]; 8] = [
    br"\n",
    br"\\",
    br"\u000A",
    br"\u000a",
    br"},{",
    b"{\"k\":",
    b",",
    "\u{2192}".as_bytes(),
];

fn generate(rng: &mut Rng, budget: usize) -> Vec<u8> {
    let mut out = Vec::new();
    while out.len() < budget {
        match rng.below(13) {
            0..=3 => out.extend_from_slice(TOKENS[rng.below(TOKENS.len())]),
            4..=5 => out.extend(std::iter::repeat_n(b'x', 1 + rng.below(48))),
            6 => out.extend(std::iter::repeat_n(
                b'y',
                MAX_LINE_BYTES + 1 + rng.below(4096),
            )),
            7 => {
                for i in 0..4 + rng.below(60) {
                    if i > 0 {
                        out.extend_from_slice(SEPARATOR);
                    }
                    out.extend(std::iter::repeat_n(b'r', 2 + rng.below(40)));
                }
            }
            8 => out.truncate(out.len().saturating_sub(1 + rng.below(40))),
            _ => out.push(TOKENS[rng.below(TOKENS.len())][0]),
        }
    }
    out
}

#[test]
fn under_cap_line_with_separators_stays_one_eligible_unit() {
    let line = array(&[
        br#"{"id":1,"st":"ok"}"#.to_vec(),
        br#"{"id":2,"st":"ok"}"#.to_vec(),
        br#"{"id":3,"st":"ok"}"#.to_vec(),
    ]);
    assert!(find(&line, SEPARATOR).is_some());
    assert!(line.len() <= MAX_LINE_BYTES);
    let span = [PRE.as_slice(), line.as_slice(), POST.as_slice()].concat();
    let units = split_span(&span, UNICODE);
    assert_eq!(
        units,
        vec![
            Unit {
                range: 0..PRE.len() - 2,
                eligible: true
            },
            Unit {
                range: PRE.len()..PRE.len() + line.len(),
                eligible: true
            },
            Unit {
                range: PRE.len() + line.len() + 2..span.len(),
                eligible: true
            },
        ]
    );
    assert_eq!(&span[units[1].range.clone()], &line);
    assert_units(&span, &units);
}

#[test]
fn line_exactly_at_cap_is_not_segmented() {
    let mut line = array(&[record(8), record(8)]);
    while line.len() < MAX_LINE_BYTES {
        line.insert(1, b'x');
    }
    assert_eq!(line.len(), MAX_LINE_BYTES);
    assert!(find(&line, SEPARATOR).is_some());
    let units = split_span(&line, UNICODE);
    assert_eq!(lengths(&units), vec![MAX_LINE_BYTES]);
    assert_eq!(flags(&units), vec![true]);
    assert_units(&line, &units);
}

#[test]
fn normative_head_middle_tail_ranges() {
    let rec = record(MAX_RECORD_BYTES);
    let line = array(&[
        rec.clone(),
        rec.clone(),
        rec.clone(),
        rec.clone(),
        rec.clone(),
    ]);
    assert!(line.len() > MAX_LINE_BYTES);
    let span = [PRE.as_slice(), line.as_slice(), POST.as_slice()].concat();
    let base = PRE.len();
    let units = split_span(&span, UNICODE);
    assert_eq!(units.len(), 7);
    assert_eq!(
        lengths(&units),
        vec![
            PRE.len() - 2,
            rec.len() + 1,
            rec.len(),
            rec.len(),
            rec.len(),
            rec.len() + 1,
            POST.len() - 2
        ]
    );
    assert_eq!(
        flags(&units),
        vec![true, false, true, true, true, false, true]
    );
    assert_eq!(units[1].range, base..base + rec.len() + 1);
    assert_eq!(&span[units[5].range.clone()][rec.len()..], b"]");
    for i in 1..5 {
        assert_eq!(&span[joiner(&units, i, span.len())], b",");
    }
    assert_units(&span, &units);
}

#[test]
fn one_byte_head_unit_is_kept() {
    let rec = record(MAX_RECORD_BYTES);
    let line = [SEPARATOR.as_slice(), comma_joined(&rec, 5).as_slice()].concat();
    assert!(line.len() > MAX_LINE_BYTES);
    let span = [PRE.as_slice(), line.as_slice(), POST.as_slice()].concat();
    let base = PRE.len();
    let units = split_span(&span, UNICODE);
    assert_eq!(units.len(), 8);
    assert_eq!(
        lengths(&units),
        vec![
            PRE.len() - 2,
            1,
            rec.len() + 1,
            rec.len(),
            rec.len(),
            rec.len(),
            rec.len(),
            POST.len() - 2
        ]
    );
    assert_eq!(
        flags(&units),
        vec![true, true, false, true, true, true, true, true]
    );
    assert_eq!(units[1].range, base..base + 1);
    assert_eq!(&span[units[1].range.clone()], b"}");
    assert_eq!(&span[units[0].range.clone()], b"pre");
    assert_units(&span, &units);
}

#[test]
fn one_byte_tail_unit_is_kept() {
    let filler = vec![b'x'; MAX_LINE_BYTES + 64];
    for extra in [&b""[..], &b"z"[..]] {
        let mut line = filler.clone();
        line.extend_from_slice(SEPARATOR);
        line.extend_from_slice(extra);
        assert!(line.len() > MAX_LINE_BYTES);
        let span = [PRE.as_slice(), line.as_slice(), POST.as_slice()].concat();
        let units = split_span(&span, UNICODE);
        assert_eq!(units.len(), 4);
        assert_eq!(
            lengths(&units),
            vec![
                PRE.len() - 2,
                filler.len() + 1,
                1 + extra.len(),
                POST.len() - 2
            ]
        );
        assert_eq!(flags(&units), vec![true, false, true, true]);
        let mut expect = vec![b'{'];
        expect.extend_from_slice(extra);
        assert_eq!(&span[units[2].range.clone()], &expect[..]);
        assert_eq!(&span[joiner(&units, 1, span.len())], b",");
        assert_eq!(&span[joiner(&units, 2, span.len())], NEWLINE_ESCAPE);
        assert_units(&span, &units);
    }
}

#[test]
fn over_cap_line_without_separator_is_one_ineligible_unit() {
    let line = vec![b'x'; MAX_LINE_BYTES + 7];
    let span = [PRE.as_slice(), line.as_slice(), POST.as_slice()].concat();
    let units = split_span(&span, UNICODE);
    assert_eq!(
        units,
        vec![
            Unit {
                range: 0..PRE.len() - 2,
                eligible: true
            },
            Unit {
                range: PRE.len()..PRE.len() + line.len(),
                eligible: false
            },
            Unit {
                range: PRE.len() + line.len() + 2..span.len(),
                eligible: true
            },
        ]
    );
    assert_eq!(&span[joiner(&units, 1, span.len())], NEWLINE_ESCAPE);
    assert_units(&span, &units);
}

#[test]
fn over_cap_records_stay_ineligible_verbatim() {
    let rec = record(MAX_RECORD_BYTES + 2);
    let line = comma_joined(&rec, 5);
    assert!(line.len() > MAX_LINE_BYTES);
    let units = split_span(&line, UNICODE);
    assert_eq!(units.len(), 5);
    assert_eq!(lengths(&units), vec![rec.len(); 5]);
    assert_eq!(flags(&units), vec![false; 5]);
    assert_units(&line, &units);
}

#[test]
fn record_cap_threshold_max_minus_one_max_plus_one() {
    for len in [MAX_RECORD_BYTES - 1, MAX_RECORD_BYTES, MAX_RECORD_BYTES + 1] {
        let rec = record(len);
        let line = comma_joined(&rec, 8);
        assert!(line.len() > MAX_LINE_BYTES);
        let units = split_span(&line, UNICODE);
        assert_eq!(units.len(), 8);
        assert_eq!(lengths(&units), vec![len; 8]);
        let expected = len <= MAX_RECORD_BYTES;
        assert_eq!(flags(&units), vec![expected; 8]);
        assert_eq!(line.len(), 8 * len + 7);
        assert_units(&line, &units);
    }
}

#[test]
fn multi_separator_byte_for_byte_reassembly() {
    for count in [20usize, 64] {
        let records: Vec<Vec<u8>> = (0..count)
            .map(|i| padded_shape(i, 4000 + 100 * i))
            .collect();
        let line = array(&records);
        assert!(line.len() > MAX_LINE_BYTES);
        let units = split_span(&line, UNICODE);
        assert_eq!(units.len(), count);
        assert!(units.iter().all(|unit| unit.eligible));
        let gaps = joiner_lengths(&line, &units);
        assert_eq!(gaps[..count - 1], vec![1; count - 1]);
        assert_eq!(gaps[count - 1], 0);
        assert_units(&line, &units);
    }
}

#[test]
fn span_splits_on_two_byte_newline_unit() {
    let span = br"alpha\nbeta\ngamma";
    let units = split_span(span, UNICODE);
    assert_eq!(ranges(&units), vec![0..5, 7..11, 13..18]);
    assert_eq!(flags(&units), vec![true, true, true]);
    assert_eq!(&span[joiner(&units, 0, span.len())], NEWLINE_ESCAPE);
    assert_eq!(&span[joiner(&units, 1, span.len())], NEWLINE_ESCAPE);
    assert!(joiner(&units, 2, span.len()).is_empty());
    assert_units(span, &units);
}

#[test]
fn span_splits_on_six_byte_u000a_unit() {
    for boundary in [U000A_UPPER, U000A_LOWER] {
        let span = [b"alpha".as_slice(), boundary, b"beta"].concat();
        let units = split_span(&span, UNICODE);
        assert_eq!(ranges(&units), vec![0..5, 11..15]);
        assert_eq!(&span[joiner(&units, 0, span.len())], boundary);
        assert_eq!(joiner_lengths(&span, &units), vec![6, 0]);
        assert_units(&span, &units);
    }
}

#[test]
fn boundary_forms_split_identically() {
    let mixed = br"a\n\u000Ab";
    let plain = br"a\n\nb";
    let mixed_units = split_span(mixed, UNICODE);
    let plain_units = split_span(plain, UNICODE);
    assert_eq!(ranges(&mixed_units), vec![0..1, 9..10]);
    assert_eq!(ranges(&plain_units), vec![0..1, 5..6]);
    assert_eq!(&mixed[mixed_units[1].range.clone()], b"b");
    assert_eq!(&plain[plain_units[1].range.clone()], b"b");
    assert_eq!(flags(&mixed_units), flags(&plain_units));
    assert_eq!(joiner_lengths(mixed, &mixed_units), vec![8, 0]);
    assert_eq!(&mixed[joiner(&mixed_units, 0, mixed.len())], br"\n\u000A");
    assert_eq!(joiner_lengths(plain, &plain_units), vec![4, 0]);

    let span = br"a\u000A\u000ab";
    let units = split_span(span, UNICODE);
    assert_eq!(ranges(&units), vec![0..1, 13..14]);
    assert_eq!(joiner_lengths(span, &units), vec![12, 0]);
    assert_eq!(&span[joiner(&units, 0, span.len())], br"\u000A\u000a");
    assert_units(span, &units);
    assert_units(mixed, &mixed_units);
    assert_units(plain, &plain_units);
}

#[test]
fn boundary_unit_alone_yields_no_units() {
    assert_eq!(split_span(U000A_UPPER, UNICODE), vec![]);
    assert_eq!(split_span(U000A_LOWER, UNICODE), vec![]);
    assert_eq!(split_span(br"\u000A\u000a", UNICODE), vec![]);
    assert_eq!(split_span(NEWLINE_ESCAPE, UNICODE), vec![]);
}

#[test]
fn escaped_backslash_does_not_open_a_line() {
    let span = br"a\\nb";
    let units = split_span(span, UNICODE);
    assert_eq!(ranges(&units), vec![0..span.len()]);
    assert_units(span, &units);
}

#[test]
fn escaped_unicode_escape_is_not_a_boundary() {
    for span in [
        &br"a\u005Cn"[..],
        &br"a\u000Bn"[..],
        &br"a\tn"[..],
        &br"a\\n"[..],
        &br"a\u0041n"[..],
    ] {
        assert_eq!(ranges(&split_span(span, UNICODE)), vec![0..span.len()]);
        assert_units(span, &split_span(span, UNICODE));
    }
}

#[test]
fn boundary_after_escaped_backslash_splits() {
    let span = br"a\\\u000Ab";
    let units = split_span(span, UNICODE);
    assert_eq!(ranges(&units), vec![0..3, 9..10]);
    assert_eq!(&span[units[0].range.clone()], br"a\\");
    assert_eq!(&span[joiner(&units, 0, span.len())], U000A_UPPER);
    assert_units(span, &units);
}

#[test]
fn truncated_escapes_never_split() {
    for span in [
        &br"\"[..],
        &br"\u"[..],
        &br"a\"[..],
        &br"a\\"[..],
        &br"a\u"[..],
        &br"a\u0"[..],
        &br"a\u000"[..],
    ] {
        assert_eq!(ranges(&split_span(span, UNICODE)), vec![0..span.len()]);
        assert_units(span, &split_span(span, UNICODE));
    }
    let span = br"a\nb\";
    let units = split_span(span, UNICODE);
    assert_eq!(ranges(&units), vec![0..1, 3..5]);
    assert_eq!(&span[joiner(&units, 0, span.len())], NEWLINE_ESCAPE);
    assert_eq!(&span[units[1].range.clone()], br"b\");
    assert_units(span, &units);
}

#[test]
fn blank_lines_fold_into_the_joiner() {
    for (span, gap) in [
        (&br"a\n\nb"[..], 4),
        (&br"a\u000A\nb"[..], 8),
        (&br"a\n\u000ab"[..], 8),
        (&br"a\u000a\n\u000Ab"[..], 14),
    ] {
        let units = split_span(span, UNICODE);
        assert_eq!(ranges(&units), vec![0..1, span.len() - 1..span.len()]);
        assert_eq!(joiner_lengths(span, &units), vec![gap, 0]);
        assert!(boundary_run(&span[joiner(&units, 0, span.len())]) > 0);
        assert_units(span, &units);
    }
}

#[test]
fn long_line_under_line_cap_stays_one_eligible_unit() {
    let line = vec![b'x'; MAX_RECORD_BYTES * 2];
    let span = [line.as_slice(), br"\n", line.as_slice()].concat();
    let units = split_span(&span, UNICODE);
    assert_eq!(lengths(&units), vec![line.len(); 2]);
    assert_eq!(flags(&units), vec![true, true]);
    assert_units(&span, &units);
}

#[test]
fn over_cap_line_hands_off_to_stage1b_inside_a_span() {
    let rec = record(MAX_RECORD_BYTES);
    let line = comma_joined(&rec, 5);
    assert!(line.len() > MAX_LINE_BYTES);
    let mut span = br"first\n".to_vec();
    span.extend_from_slice(&line);
    span.extend_from_slice(br"\nlast");
    let units = split_span(&span, UNICODE);
    assert_eq!(units.len(), 7);
    assert_eq!(units[0].range, 0..5);
    assert_eq!(units[6].range, span.len() - 4..span.len());
    assert_eq!(flags(&units), vec![true; 7]);
    assert_eq!(
        lengths(&units),
        vec![5, 16384, 16384, 16384, 16384, 16384, 4]
    );
    assert_units(&span, &units);
}

#[test]
fn fixture_newlines_u000a_only() {
    let span = fixture_content("newlines-u000a-only.json");
    assert_eq!(span.len(), 186);
    assert!(find(&span, SEPARATOR).is_none());
    let units = split_span(&span, UNICODE);
    assert_eq!(units.len(), 4);
    assert_eq!(lengths(&units), vec![42; 4]);
    assert_eq!(flags(&units), vec![true; 4]);
    assert_eq!(joiner_lengths(&span, &units), vec![6, 6, 6, 0]);
    for i in 0..3 {
        let gap = joiner(&units, i, span.len());
        let bytes = &span[gap.clone()];
        assert!(bytes == U000A_UPPER || bytes == U000A_LOWER, "gap {gap:?}");
    }
    assert_units(&span, &units);
}

#[test]
fn fixture_stage1b_record_len_16383() {
    let span = fixture_content("stage1b-record-len-16383.json");
    assert_eq!(span.len(), 5 * 16383 + 6);
    let units = split_span(&span, UNICODE);
    assert_eq!(lengths(&units), vec![16384, 16383, 16383, 16383, 16384]);
    assert_eq!(flags(&units), vec![true; 5]);
    assert_eq!(&span[units[0].range.clone()][..1], b"[");
    assert_eq!(&span[units[4].range.clone()][16383..], b"]");
    assert_units(&span, &units);
}

#[test]
fn fixture_stage1b_record_len_16384() {
    let span = fixture_content("stage1b-record-len-16384.json");
    assert_eq!(span.len(), 5 * 16384 + 6);
    let units = split_span(&span, UNICODE);
    assert_eq!(lengths(&units), vec![16385, 16384, 16384, 16384, 16385]);
    assert_eq!(flags(&units), vec![false, true, true, true, false]);
    assert_units(&span, &units);
}

#[test]
fn fixture_stage1b_record_len_16385() {
    let span = fixture_content("stage1b-record-len-16385.json");
    assert_eq!(span.len(), 5 * 16385 + 6);
    let units = split_span(&span, UNICODE);
    assert_eq!(lengths(&units), vec![16386, 16385, 16385, 16385, 16386]);
    assert_eq!(flags(&units), vec![false; 5]);
    assert_units(&span, &units);
}

#[test]
fn fixture_stage1b_no_separator_overcap() {
    let span = fixture_content("stage1b-no-separator-overcap.json");
    assert_eq!(span.len(), 131_072);
    assert!(find(&span, SEPARATOR).is_none());
    let units = split_span(&span, UNICODE);
    assert_eq!(
        units,
        vec![Unit {
            range: 0..span.len(),
            eligible: false,
        }]
    );
    assert_units(&span, &units);
}

#[test]
fn fixture_single_line_tool_dump_overcap() {
    let span = fixture_content("single-line-tool-dump-overcap.json");
    assert_eq!(span.len(), 128_001);
    assert!(span.len() > MAX_LINE_BYTES);
    let units = split_span(&span, UNICODE);
    assert_eq!(units.len(), 3072);
    assert_eq!(units[0].range, 0..41);
    assert_eq!(units[3071].range.len(), 40);
    assert_eq!(units[3071].range.end, span.len());
    assert!(flags(&units).into_iter().all(|flag| flag));
    let gaps = joiner_lengths(&span, &units);
    assert_eq!(gaps[..3071], vec![1; 3071]);
    assert_eq!(gaps[3071], 0);
    assert_units(&span, &units);
}

#[test]
fn fixture_single_line_tool_dump_small_stays_one_line() {
    let span = fixture_content("single-line-tool-dump-small.json");
    assert_eq!(span.len(), 151);
    assert!(span.len() <= MAX_LINE_BYTES);
    assert_eq!(find(&span, SEPARATOR), Some(24));
    let units = split_span(&span, UNICODE);
    assert_eq!(
        units,
        vec![Unit {
            range: 0..span.len(),
            eligible: true,
        }]
    );
    assert_units(&span, &units);
}

#[test]
fn empty_span_yields_no_units() {
    assert_eq!(split_span(b"", UNICODE), vec![]);
    assert_eq!(reassemble(b"", &[]), b"");
}

#[test]
#[should_panic(expected = "units must be ascending and disjoint")]
fn joiner_rejects_overlapping_units() {
    let units = vec![
        Unit {
            range: 0..10,
            eligible: true,
        },
        Unit {
            range: 4..8,
            eligible: true,
        },
    ];
    let _ = joiner(&units, 0, 12);
}

#[test]
fn property_units_and_joiners_reassemble_generated_spans() {
    let mut rng = Rng(0x5eed_1234_abcd_0001);
    let (mut records, mut u_boundaries, mut n_boundaries) = (0, 0, 0);
    for case in 0..48 {
        let budget = match case % 4 {
            0 => 1 + rng.below(64),
            1 => 1 + rng.below(4096),
            2 => MAX_LINE_BYTES + rng.below(8192),
            _ => 3 * MAX_LINE_BYTES + rng.below(16384),
        };
        let span = generate(&mut rng, budget);
        let units = split_span(&span, UNICODE);
        assert_eq!(reassemble(&span, &units), span, "reassembly case {case}");
        assert_units(&span, &units);
        for index in 0..units.len() {
            let gap = joiner(&units, index, span.len());
            let bytes = &span[gap];
            if bytes.is_empty() {
                continue;
            }
            if bytes == b"," {
                records += 1;
                continue;
            }
            assert_eq!(
                boundary_run(bytes),
                bytes.len(),
                "unexpected joiner {bytes:?}"
            );
            if bytes
                .windows(6)
                .any(|w| w == U000A_UPPER || w == U000A_LOWER)
            {
                u_boundaries += 1;
            }
            if bytes.windows(2).any(|w| w == NEWLINE_ESCAPE) {
                n_boundaries += 1;
            }
        }
    }
    assert!(records > 0, "generator never reached stage 1b");
    assert!(u_boundaries > 0, "generator never split a \\u000A boundary");
    assert!(n_boundaries > 0, "generator never split a \\n boundary");
}

#[test]
fn record_split_count_is_the_number_of_over_cap_lines() {
    let short = record(64);
    let over = comma_joined(&record(MAX_RECORD_BYTES), 5);
    assert!(over.len() > MAX_LINE_BYTES);
    let span = [
        short.as_slice(),
        br"\n",
        over.as_slice(),
        br"\n",
        over.as_slice(),
    ]
    .concat();
    let split = split_span_counted(&span, UNICODE);
    assert_eq!(split.record_splits, 2);
    assert_eq!(split.units, split_span(&span, UNICODE));
    assert_eq!(split_span_counted(&short, UNICODE).record_splits, 0);
    assert_eq!(
        split_span_counted(b"", UNICODE).units,
        Vec::<Unit>::new(),
        "an empty span has no units and no splits"
    );
    assert_eq!(
        split_span_counted(b"plain", UNICODE).units,
        vec![Unit {
            range: 0..5,
            eligible: true
        }]
    );
}

#[test]
fn a_well_formed_marker_line_is_never_eligible() {
    const ASCII_MARKERS: [&str; 5] = [
        "[... x200 identical c5f3 ...]",
        "[... x20 rows, ws-equal c5f3 ...]",
        "[... block x12 c5f3 ...]",
        "[... templated block x3 c5f3 ...]",
        "[... x50 rows, template 0abc ...]",
    ];
    const UNICODE_MARKERS: [&str; 5] = [
        "\u{27ea}\u{d7}200 identical \u{b7}c5f3\u{27eb}",
        "\u{27ea}\u{d7}20 rows, ws-equal \u{b7}c5f3\u{27eb}",
        "\u{27ea}block \u{d7}12 \u{b7}c5f3\u{27eb}",
        "\u{27ea}templated block \u{d7}3 \u{b7}c5f3\u{27eb}",
        "\u{27ea}\u{d7}50 rows, template \u{b7}0abc\u{27eb}",
    ];
    for (at, marker) in ASCII_MARKERS
        .iter()
        .chain(UNICODE_MARKERS.iter())
        .enumerate()
    {
        let carrier = format!("2026-08-25T10:00:00Z INFO hc 10.0.0.1 ok{marker}");
        let span = format!("{carrier}\\n2026-08-25T10:00:01Z INFO hc 10.0.0.2 ok").into_bytes();
        let style = if at < ASCII_MARKERS.len() {
            MarkerStyle::Ascii
        } else {
            MarkerStyle::Unicode
        };
        assert_eq!(
            flags(&split_span(&span, style)),
            vec![false, true],
            "{marker} rides its anchor's last line"
        );
        assert_eq!(
            flags(&split_span(&span, MarkerStyle::Auto)),
            vec![false, true]
        );
    }
}

#[test]
fn a_marker_shaped_line_that_is_not_well_formed_stays_eligible() {
    const LOOKALIKES: [&str; 9] = [
        "[... truncation of a long line ...",
        "[... x identical c5f3 ...]",
        "[... x200 identical c5f3 ..",
        "[... x200 identical c5f3 ... ]",
        "[... x200 identical C5F3 ...]",
        "[... x200 identical c5f ...]",
        "[... x200 identical c5f3g ...]",
        "[... x200 rows, templatee c5f3 ...]",
        "[... x200 identical \u{b7}c5f3 ...]",
    ];
    for line in LOOKALIKES {
        let span = line.as_bytes().to_vec();
        assert_eq!(
            flags(&split_span(&span, MarkerStyle::Ascii)),
            vec![true],
            "{line}"
        );
    }
    const UNICODE_LOOKALIKE: &str = "\u{27ea}\u{d7}200 identical \u{b7}\u{27eb}";
    assert_eq!(
        flags(&split_span(
            UNICODE_LOOKALIKE.as_bytes(),
            MarkerStyle::Unicode
        )),
        vec![true]
    );
    assert_eq!(
        flags(&split_span(
            ASCII_MARKER_IN_UNICODE_SPAN.as_bytes(),
            MarkerStyle::Unicode
        )),
        vec![true],
        "an ascii marker in a unicode span is not one of ours"
    );
    assert_eq!(
        flags(&split_span(
            UNICODE_MARKER_IN_ASCII_SPAN.as_bytes(),
            MarkerStyle::Ascii
        )),
        vec![true],
        "a unicode marker in an ascii span is not one of ours"
    );
}

const ASCII_MARKER_IN_UNICODE_SPAN: &str = "[... x200 identical c5f3 ...]";
const UNICODE_MARKER_IN_ASCII_SPAN: &str = "\u{27ea}\u{d7}200 identical \u{b7}c5f3\u{27eb}";

#[test]
fn a_record_that_carries_a_marker_is_never_eligible() {
    const PLAIN: &[u8] = br#"{"id":1,"state":"ok"}"#;
    const MARKED: &[u8] = br#"{"id":1,"state":"ok"}[... x200 identical c5f3 ...]"#;
    let mut over = Vec::new();
    let mut chunks = 0;
    while over.len() <= MAX_LINE_BYTES {
        for record in [MARKED, PLAIN, PLAIN] {
            if !over.is_empty() {
                over.push(b',');
            }
            over.extend_from_slice(record);
        }
        chunks += 1;
    }
    let records = split_span(&over, MarkerStyle::Ascii);
    assert!(records.len() > 3, "the dump is segmented into records");
    let mut ineligible = 0;
    for unit in &records {
        let bytes = &over[unit.range.clone()];
        assert_eq!(
            unit.eligible,
            !carries_marker(bytes, MarkerStyle::Ascii),
            "eligibility is exactly the absence of a well-formed marker: {bytes:?}"
        );
        if !unit.eligible {
            ineligible += 1;
            assert!(
                find(bytes, MARKED).is_some(),
                "the marked record rides the unit that carries it"
            );
        }
    }
    assert_eq!(ineligible, chunks, "one ineligible record per chunk");
    assert_eq!(
        flags(&split_span(&over, MarkerStyle::Unicode)),
        vec![true; records.len()],
        "an ascii marker is not a unicode one"
    );
}
