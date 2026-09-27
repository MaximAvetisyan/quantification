use quantification_core::config::{
    MAX_BLOCK_LINES, MAX_LINE_BYTES, MAX_RECORD_BYTES, MIN_BLOCK_LINES, MIN_GROUP_SIZE_DEFAULT,
    MarkerStyle,
};
use quantification_core::detect::blocks::{Scratch as BlockScratch, repeated_blocks};
use quantification_core::detect::exact::exact_runs;
use quantification_core::detect::templ::{
    Forms, Scratch as TemplScratch, Template, TemplateId, template_groups,
};
use quantification_core::detect::templ_blocks::{
    Scratch as Stage7Scratch, templated_blocks as stage7,
};
use quantification_core::detect::wsruns::ws_runs;
use quantification_core::fingerprint::fingerprint;
use quantification_core::ledger::{
    Commit, CommitKind, CommitOutcome, Ledger, Proposal, StageStats, marker_len, profitable,
};
use quantification_core::mask::mask;
use quantification_core::render::render;
use quantification_core::stage1::{Unit, split_span};
use quantification_core::wsnorm::{Column, normalize};

const UNICODE: MarkerStyle = MarkerStyle::Unicode;

fn new_ledger<'a>(units: &'a [Unit]) -> Ledger<'a> {
    Ledger::new(units, UNICODE)
}

fn span_with(sep: &[u8], lines: &[&[u8]]) -> Vec<u8> {
    let mut span = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            span.extend_from_slice(sep);
        }
        span.extend_from_slice(line);
    }
    span
}

fn lines_span(lines: &[&[u8]]) -> Vec<u8> {
    span_with(br"\n", lines)
}

fn join(lines: &[Vec<u8>]) -> Vec<u8> {
    let borrowed: Vec<&[u8]> = lines.iter().map(|line| line.as_slice()).collect();
    lines_span(&borrowed)
}

fn push_line(span: &mut Vec<u8>, line: &[u8]) {
    if !span.is_empty() {
        span.extend_from_slice(br"\n");
    }
    span.extend_from_slice(line);
}

fn apply(span: &[u8], ledger: &Ledger<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut at = 0;
    for commit in ledger.commits() {
        out.extend_from_slice(&span[at..commit.anchor.start]);
        out.extend_from_slice(&span[commit.anchor.clone()]);
        out.extend_from_slice(&render(
            ledger.marker_style(),
            commit.kind,
            commit.count,
            &span[commit.anchor.clone()],
        ));
        at = commit.removed.end;
    }
    out.extend_from_slice(&span[at..]);
    out
}

fn assert_removal_invariant(units: &[Unit], commit: &Commit) {
    let members = &units[commit.first..commit.last + 1];
    let gaps: usize = members
        .windows(2)
        .map(|pair| pair[1].range.start - pair[0].range.end)
        .sum();
    let member_bytes: usize = members.iter().map(|unit| unit.range.len()).sum();
    assert_eq!(
        commit.removed,
        members[0].range.start..members[members.len() - 1].range.end
    );
    assert_eq!(commit.removed.len(), member_bytes + gaps);
    let anchor_units = members
        .iter()
        .take_while(|unit| unit.range.end <= commit.anchor.end)
        .count();
    assert!(commit.anchor.start >= commit.removed.start);
    assert!(commit.anchor.end <= commit.removed.end);
    assert_eq!(members.len() % anchor_units, 0);
    assert_eq!(commit.count, (members.len() / anchor_units - 1) as u64);
    assert!(profitable(
        UNICODE,
        commit.kind,
        commit.count,
        commit.anchor.len(),
        commit.removed.len()
    ));
}

fn marker(count: u64, anchor: &[u8]) -> Vec<u8> {
    render(UNICODE, CommitKind::TemplatedBlock, count, anchor)
}

fn has(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Handoff {
    stats: StageStats,
    forms: Forms,
    degraded: bool,
}

fn six(span: &[u8], ledger: &mut Ledger<'_>) -> Handoff {
    six_with(span, ledger, &mut TemplScratch::default())
}

fn column_of(span: &[u8], ledger: &Ledger<'_>) -> Column {
    let mut column = Column::default();
    let mut line = Vec::new();
    column.build(span, ledger.units(), &mut line);
    column
}

fn six_with(span: &[u8], ledger: &mut Ledger<'_>, scratch: &mut TemplScratch) -> Handoff {
    let column = column_of(span, ledger);
    let Some(forms) = Forms::build(&column, ledger.units(), scratch) else {
        return Handoff {
            stats: StageStats::default(),
            forms: Forms::default(),
            degraded: true,
        };
    };
    let stats = template_groups(&forms, ledger, MIN_GROUP_SIZE_DEFAULT);
    Handoff {
        stats,
        forms,
        degraded: false,
    }
}

fn seven(
    handoff: &Handoff,
    ledger: &mut Ledger<'_>,
    max: u32,
    scratch: &mut Stage7Scratch,
) -> StageStats {
    stage7(
        (!handoff.degraded).then_some(&handoff.forms),
        ledger,
        max,
        scratch,
    )
}

fn earlier_stages_refuse(span: &[u8], units: &[Unit]) {
    let mut exact = new_ledger(units);
    let mut ws = new_ledger(units);
    let mut blocks = new_ledger(units);
    assert_eq!(
        exact_runs(span, &mut exact, MIN_GROUP_SIZE_DEFAULT),
        StageStats::default()
    );
    assert_eq!(
        ws_runs(&column_of(span, &ws), &mut ws, MIN_GROUP_SIZE_DEFAULT),
        StageStats::default()
    );
    let column = column_of(span, &blocks);
    let forms = Forms::build(&column, units, &mut TemplScratch::default());
    assert_eq!(
        repeated_blocks(
            &column,
            forms.as_ref(),
            &mut blocks,
            MIN_BLOCK_LINES,
            MAX_BLOCK_LINES,
            &mut BlockScratch::default()
        ),
        StageStats::default()
    );
}

fn uuid(index: usize) -> String {
    format!("{index:08x}-0000-4000-8000-{index:012x}")
}

fn get(index: usize) -> Vec<u8> {
    format!(
        r"2026-08-26T10:00:{index:02}Z INFO svc 10.0.0.{index} GET /v1/users id={} took {index}ms",
        uuid(index)
    )
    .into_bytes()
}

fn response(index: usize) -> Vec<u8> {
    format!(
        r"2026-08-26T10:00:{index:02}Z INFO svc 10.0.0.{index} <- 200 bytes {} took {index}ms",
        4000 + index
    )
    .into_bytes()
}

fn pool(index: usize) -> Vec<u8> {
    format!(
        r"2026-08-26T10:00:{index:02}Z INFO pool 10.0.0.{index} conns {index} idle 0 took {index}ms"
    )
    .into_bytes()
}

fn header(group: usize, index: usize) -> Vec<u8> {
    format!(
        r"2026-08-26T10:00:{index:02}Z INFO worker boot phase node 10.1.{index}.{} id={} ok",
        group % 256,
        uuid(group)
    )
    .into_bytes()
}

fn request(index: usize) -> Vec<u8> {
    format!(
        r"2026-08-26T10:00:{index:02}Z INFO gateway 10.0.0.{index} POST /v2/checkout id={} bytes {}",
        uuid(index),
        900 + index
    )
    .into_bytes()
}

fn reply(index: usize) -> Vec<u8> {
    format!(
        r"2026-08-26T10:00:{index:02}Z INFO gateway 10.0.0.{index} <- 201 receipt 00-{index} status 7ms"
    )
    .into_bytes()
}

fn access_burst(entries: usize) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut lines = Vec::new();
    for index in 0..entries {
        lines.push(get(index));
        lines.push(response(index));
        lines.push(pool(index));
    }
    (join(&lines), lines)
}

fn frame(method: &str, line: usize, index: usize) -> Vec<u8> {
    format!("at com.example.Svc.{method}(Svc.java:{line}) pc=0x00007f8e4a2b{index:08x}")
        .into_bytes()
}

fn stack_trace(index: usize) -> Vec<Vec<u8>> {
    vec![
        frame("handle", 412, index),
        frame("run", 118, index),
        frame("main", 57, index),
    ]
}

fn stack_span(traces: usize) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut lines = Vec::new();
    for index in 0..traces {
        lines.extend(stack_trace(index));
    }
    (join(&lines), lines)
}

fn interleaved(pairs: usize) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut lines = Vec::new();
    for index in 0..pairs {
        lines.push(request(index));
        lines.push(reply(index));
    }
    (join(&lines), lines)
}

fn generated_span(groups: usize) -> Vec<u8> {
    let mut span = Vec::new();
    for group in 0..groups {
        for index in 0..3 {
            push_line(&mut span, &header(group, index));
        }
        for index in 0..2 {
            push_line(&mut span, &request(group + index));
            push_line(&mut span, &reply(group + index));
        }
    }
    span
}

fn hand_forms(parts: &[(&[u8], u64)]) -> Forms {
    let mut bytes = Vec::new();
    let mut units = Vec::new();
    for (part, id) in parts {
        let masked = bytes.len()..bytes.len() + part.len();
        bytes.extend_from_slice(part);
        units.push(Template {
            masked,
            id: TemplateId(*id),
            hash: fingerprint(part),
        });
    }
    Forms { bytes, units }
}

fn hand_templated(parts: &[(&[u8], u64)], degraded: bool) -> Handoff {
    Handoff {
        stats: StageStats::default(),
        forms: hand_forms(parts),
        degraded,
    }
}

fn tag(mut n: usize) -> String {
    let mut out = String::new();
    for _ in 0..4 {
        out.push((b'a' + (n % 26) as u8) as char);
        n /= 26;
    }
    out
}

fn filler_record(index: usize) -> Vec<u8> {
    format!(
        r#"{{"tenant":"{}","slot":"{}","note":"idle"}}"#,
        tag(index),
        "z".repeat(120)
    )
    .into_bytes()
}

fn pair_record(role: usize, index: usize) -> Vec<u8> {
    if role == 0 {
        format!(r#"{{"seq":{index},"ip":"10.0.0.{index}","took":"{index}ms"}}"#).into_bytes()
    } else {
        format!(r#"{{"status":{index},"peer":"10.0.1.{index}","bytes":{index}}}"#).into_bytes()
    }
}

fn record_pair(index: usize) -> Vec<Vec<u8>> {
    vec![pair_record(0, index), pair_record(1, index)]
}

fn record_dump() -> (Vec<u8>, Vec<Unit>, usize, Vec<Vec<u8>>) {
    let mut records: Vec<Vec<u8>> = (0..200).map(filler_record).collect();
    for index in 0..3 {
        records.extend(record_pair(index));
    }
    let mut wall = format!(
        r#"{{"tenant":"wall","blob":"{}"}}"#,
        "z".repeat(MAX_RECORD_BYTES)
    );
    wall.push('}');
    records.push(wall.into_bytes());
    for index in 3..6 {
        records.extend(record_pair(index));
    }
    records.extend((1000..1200).map(filler_record));
    let wall = (0..records.len())
        .find(|index| records[*index].len() > MAX_RECORD_BYTES)
        .expect("a wall record");
    let mut span = vec![b'['];
    for (index, record) in records.iter().enumerate() {
        if index > 0 {
            span.push(b',');
        }
        span.extend_from_slice(record);
    }
    span.push(b']');
    assert!(span.len() > MAX_LINE_BYTES);
    let units = split_span(&span, UNICODE);
    assert_eq!(units.len(), records.len());
    assert!(!units[wall].eligible);
    (span, units, wall, records)
}

#[test]
fn an_access_log_burst_collapses_into_one_whole_block_anchor() {
    let (span, lines) = access_burst(3);
    let units = split_span(&span, UNICODE);
    assert_eq!(units.len(), 9);
    earlier_stages_refuse(&span, &units);

    let mut ledger = new_ledger(&units);
    let handoff = six(&span, &mut ledger);
    assert!(!handoff.degraded);
    assert_eq!(handoff.stats, StageStats::default());
    assert_eq!(handoff.forms.len(), 9);
    for role in 0..3 {
        for copy in 1..3 {
            assert_eq!(
                handoff.forms.masked(role),
                handoff.forms.masked(role + copy * 3),
                "role {role} copy {copy}"
            );
        }
        assert_ne!(
            handoff.forms.masked(role),
            handoff.forms.masked((role + 1) % 3)
        );
    }
    assert_eq!(
        handoff.forms.masked(0),
        b"<ts> INFO svc <ip> GET /v<num>/users id=<uuid> took <dur>"
    );
    assert_eq!(
        handoff.forms.masked(1),
        b"<ts> INFO svc <ip> <- <num> bytes <num> took <dur>"
    );
    assert_eq!(
        handoff.forms.masked(2),
        b"<ts> INFO pool <ip> conns <num> idle <num> took <dur>"
    );

    let stats = seven(
        &handoff,
        &mut ledger,
        MAX_BLOCK_LINES,
        &mut Stage7Scratch::default(),
    );
    assert_eq!(stats.templated_blocks, 1);
    assert_eq!(stats.groups_collapsed, 1);
    assert_eq!(stats.exact_runs, 0);
    assert_eq!(stats.ws_runs, 0);
    assert_eq!(stats.block_repeats, 0);
    assert_eq!(stats.template_groups, 0);
    assert_eq!(stats.record_splits, 0);
    assert_eq!(ledger.commits().len(), 1);
    let commit = &ledger.commits()[0];
    assert_eq!(commit.kind, CommitKind::TemplatedBlock);
    assert_eq!((commit.first, commit.last, commit.count), (0, 8, 2));
    assert_eq!(commit.anchor, units[0].range.start..units[2].range.end);
    let anchor = &span[commit.anchor.clone()];
    assert_eq!(anchor, join(&lines[..3]));
    assert_eq!(
        anchor.len(),
        lines[..3].iter().map(|line| line.len() + 2).sum::<usize>() - 2
    );
    assert_eq!(
        commit.removed.len(),
        lines.iter().map(|line| line.len()).sum::<usize>() + 16
    );
    assert_eq!(marker_len(UNICODE, commit.kind, commit.count), 32);
    let mut expected = anchor.to_vec();
    expected.extend_from_slice(&marker(2, anchor));
    assert_eq!(apply(&span, &ledger), expected);
    assert_eq!(ledger.residual().count(), 0);
    assert_removal_invariant(&units, commit);
}

#[test]
fn a_stack_trace_differing_only_in_addresses_collapses() {
    let (span, lines) = stack_span(3);
    let units = split_span(&span, UNICODE);
    assert_eq!(units.len(), 9);
    earlier_stages_refuse(&span, &units);

    let mut ledger = new_ledger(&units);
    let handoff = six(&span, &mut ledger);
    assert_eq!(handoff.stats, StageStats::default());
    for role in 0..3 {
        for copy in 1..3 {
            assert_eq!(
                handoff.forms.masked(role),
                handoff.forms.masked(role + copy * 3),
                "role {role} copy {copy}"
            );
        }
        assert_ne!(
            handoff.forms.masked(role),
            handoff.forms.masked((role + 1) % 3)
        );
    }
    for (index, unit) in units.iter().enumerate() {
        assert_eq!(
            handoff.forms.masked(index),
            &mask(&normalize(&span[unit.range.clone()]))[..],
            "unit {index}"
        );
    }
    assert_eq!(
        handoff.forms.masked(0),
        b"at com.example.Svc.handle(Svc.java:<num>) pc=<num>x<hex>"
    );

    let stats = seven(
        &handoff,
        &mut ledger,
        MAX_BLOCK_LINES,
        &mut Stage7Scratch::default(),
    );
    assert_eq!(stats.templated_blocks, 1);
    let commit = &ledger.commits()[0];
    assert_eq!((commit.first, commit.last, commit.count), (0, 8, 2));
    let anchor = &span[commit.anchor.clone()];
    assert_eq!(anchor, join(&lines[..3]));
    for (index, line) in lines.iter().enumerate() {
        let address = String::from_utf8_lossy(&line[line.len() - 16..]).into_owned();
        if index < 3 {
            assert!(has(anchor, address.as_bytes()), "address {address} missing");
        } else {
            assert!(!has(anchor, address.as_bytes()), "address {address} leaked");
        }
    }
    assert_removal_invariant(&units, commit);
    let mut expected = anchor.to_vec();
    expected.extend_from_slice(&marker(2, anchor));
    assert_eq!(apply(&span, &ledger), expected);
}

#[test]
fn an_interleaved_request_response_pair_collapses_at_period_two() {
    let (span, lines) = interleaved(3);
    let units = split_span(&span, UNICODE);
    assert_eq!(units.len(), 6);
    let mut ledger = new_ledger(&units);
    let handoff = six(&span, &mut ledger);
    assert_eq!(handoff.stats, StageStats::default());
    for index in 0..3 {
        assert_eq!(handoff.forms.id(2 * index), handoff.forms.id(0));
        assert_eq!(handoff.forms.id(2 * index + 1), handoff.forms.id(1));
    }
    assert_ne!(handoff.forms.id(0), handoff.forms.id(1));
    assert_eq!(handoff.forms.id(0), handoff.forms.id(2));

    let stats = seven(
        &handoff,
        &mut ledger,
        MAX_BLOCK_LINES,
        &mut Stage7Scratch::default(),
    );
    assert_eq!(stats.templated_blocks, 1);
    let commit = &ledger.commits()[0];
    assert_eq!(commit.kind, CommitKind::TemplatedBlock);
    assert_eq!((commit.first, commit.last, commit.count), (0, 5, 2));
    assert_eq!(commit.anchor, units[0].range.start..units[1].range.end);
    let anchor = &span[commit.anchor.clone()];
    assert_eq!(anchor, join(&lines[..2]));
    assert_eq!(
        commit.removed.len(),
        lines.iter().map(|line| line.len()).sum::<usize>() + 10
    );
    assert_eq!(marker_len(UNICODE, commit.kind, commit.count), 32);
    let mut expected = anchor.to_vec();
    expected.extend_from_slice(&marker(2, anchor));
    assert_eq!(apply(&span, &ledger), expected);
    assert_removal_invariant(&units, commit);
}

#[test]
fn the_minimum_period_of_one_fires_on_a_single_adjacent_pair() {
    let lines = [get(1), get(2)];
    let span = join(&lines);
    let units = split_span(&span, UNICODE);
    assert_eq!(units.len(), 2);
    let mut ledger = new_ledger(&units);
    let handoff = six(&span, &mut ledger);
    assert_eq!(handoff.stats, StageStats::default());
    assert_eq!(handoff.forms.id(0), handoff.forms.id(1));
    assert!(!handoff.forms.is_empty());

    let mut work = Stage7Scratch::default();
    let stats = seven(&handoff, &mut ledger, MAX_BLOCK_LINES, &mut work);
    assert_eq!(stats.templated_blocks, 1);
    assert_eq!(ledger.commits().len(), 1);
    let commit = &ledger.commits()[0];
    assert_eq!(commit.kind, CommitKind::TemplatedBlock);
    assert_eq!((commit.first, commit.last, commit.count), (0, 1, 1));
    assert_eq!(commit.anchor, units[0].range.clone());
    let anchor = &span[commit.anchor.clone()];
    assert_eq!(anchor, get(1));
    assert_eq!(commit.removed.len(), get(1).len() * 2 + 2);
    assert_eq!(marker_len(UNICODE, commit.kind, 1), 32);
    assert_eq!(marker_len(UNICODE, commit.kind, 10), 33);
    assert_eq!(work.work().verifications, 1);
    let marker = marker(1, anchor);
    assert_eq!(marker.len(), 32);
    assert!(marker.starts_with("\u{27ea}templated block \u{d7}1 \u{b7}".as_bytes()));
    assert!(marker.ends_with("\u{27eb}".as_bytes()));
    assert_eq!(
        marker,
        "\u{27ea}templated block \u{d7}1 \u{b7}1701\u{27eb}".as_bytes()
    );
    let mut expected = anchor.to_vec();
    expected.extend_from_slice(&marker);
    assert_eq!(apply(&span, &ledger), expected);
    assert_eq!(ledger.residual().count(), 0);
    assert_removal_invariant(&units, commit);
}

#[test]
fn the_anchor_is_the_entire_raw_first_occurrence_with_its_values() {
    let (span, lines) = interleaved(2);
    let units = split_span(&span, UNICODE);
    let mut ledger = new_ledger(&units);
    let handoff = six(&span, &mut ledger);
    seven(
        &handoff,
        &mut ledger,
        MAX_BLOCK_LINES,
        &mut Stage7Scratch::default(),
    );
    let commit = &ledger.commits()[0];
    let anchor = &span[commit.anchor.clone()];
    assert_eq!(anchor, join(&lines[..2]));
    assert!(anchor.starts_with(b"2026-08-26T10:00:00Z"));
    assert!(has(anchor, b"10.0.0.0"));
    assert!(has(anchor, uuid(0).as_bytes()));
    assert!(has(anchor, b"bytes 900"));
    assert!(has(anchor, b"receipt 00-0"));
    let masked = [
        handoff.forms.masked(0).to_vec(),
        br"\n".to_vec(),
        handoff.forms.masked(1).to_vec(),
    ]
    .concat();
    assert_ne!(anchor, masked.as_slice());
    assert!(!has(&masked, b"10.0.0.0"));
    assert!(!has(&masked, uuid(0).as_bytes()));
    let spliced = apply(&span, &ledger);
    assert!(spliced.starts_with(anchor));
    assert!(!has(&spliced, &lines[2]));
    assert!(!has(&spliced, &lines[3]));
    assert_eq!(spliced.len(), anchor.len() + 32);
    assert_removal_invariant(&units, commit);
}

#[test]
fn a_join_is_rejected_when_the_ids_match_but_the_masked_bytes_differ() {
    let lines = [get(1), reply(0), get(2), reply(1)];
    let span = join(&lines);
    let units = split_span(&span, UNICODE);
    assert_eq!(units.len(), 4);
    let masked: Vec<Vec<u8>> = lines.iter().map(|line| mask(&normalize(line))).collect();
    let agreeing: Vec<(&[u8], u64)> = masked
        .iter()
        .zip([7u64, 9, 7, 9])
        .map(|(form, id)| (form.as_slice(), id))
        .collect();
    let collided: Vec<(&[u8], u64)> = vec![
        (masked[0].as_slice(), 7),
        (masked[1].as_slice(), 9),
        (b"gamma three", 7),
        (b"delta four", 9),
    ];
    let collided = hand_templated(&collided, false);
    assert_eq!(collided.forms.id(0), collided.forms.id(2));
    assert_eq!(collided.forms.id(1), collided.forms.id(3));
    assert_ne!(collided.forms.masked(0), collided.forms.masked(2));
    assert!(!collided.forms.same(0, 2));
    let mut ledger = new_ledger(&units);
    let mut work = Stage7Scratch::default();
    let stats = seven(&collided, &mut ledger, MAX_BLOCK_LINES, &mut work);
    assert_eq!(stats, StageStats::default());
    assert_eq!(ledger.commits().len(), 0);
    assert_eq!(ledger.residual().count(), 4);
    assert_eq!(apply(&span, &ledger), span);
    assert_eq!(work.work().verifications, 1);
    assert_eq!(work.work().compares, 5);

    let agreeing = hand_templated(&agreeing, false);
    assert!(agreeing.forms.same(0, 2));
    assert!(agreeing.forms.same(1, 3));
    let mut ledger = new_ledger(&units);
    let mut work = Stage7Scratch::default();
    assert_eq!(
        seven(&agreeing, &mut ledger, MAX_BLOCK_LINES, &mut work).templated_blocks,
        1
    );
    let commit = &ledger.commits()[0];
    assert_eq!((commit.first, commit.last, commit.count), (0, 3, 1));
    assert_eq!(&span[commit.anchor.clone()], join(&lines[..2]));
    assert_eq!(work.work().verifications, 1);
    assert_removal_invariant(&units, commit);
}

#[test]
fn a_below_threshold_block_stays_verbatim() {
    let narrow = lines_span(&[b"a 1", b"a 2"]);
    let units = split_span(&narrow, UNICODE);
    assert_eq!(units.len(), 2);
    let mut ledger = new_ledger(&units);
    let handoff = six(&narrow, &mut ledger);
    assert_eq!(mask(&normalize(b"a 1")), b"a <num>");
    assert_eq!(handoff.forms.masked(0), handoff.forms.masked(1));
    let mut work = Stage7Scratch::default();
    assert_eq!(
        seven(&handoff, &mut ledger, MAX_BLOCK_LINES, &mut work),
        StageStats::default()
    );
    assert!(!profitable(UNICODE, CommitKind::TemplatedBlock, 1, 3, 8));
    assert_eq!(ledger.commits().len(), 0);
    assert!(ledger.is_free(0..2));
    assert_eq!(apply(&narrow, &ledger), narrow);
    assert_eq!(work.work().verifications, 1);
    assert!(work.reserved() >= 2);

    let lines = [get(1), get(2)];
    let wide = join(&lines);
    let wide_units = split_span(&wide, UNICODE);
    let mut wide_ledger = new_ledger(&wide_units);
    let handoff = six(&wide, &mut wide_ledger);
    assert_eq!(
        seven(&handoff, &mut wide_ledger, MAX_BLOCK_LINES, &mut work).templated_blocks,
        1
    );
    assert!(work.reserved() >= wide_units.len());
}

#[test]
fn a_degraded_stage_six_makes_stage_seven_a_no_op() {
    let lines = [get(1), reply(0), get(2), reply(1)];
    let span = join(&lines);
    let units = split_span(&span, UNICODE);
    let masked: Vec<Vec<u8>> = lines.iter().map(|line| mask(&normalize(line))).collect();
    let parts: Vec<(&[u8], u64)> = masked
        .iter()
        .zip([7u64, 9, 7, 9])
        .map(|(form, id)| (form.as_slice(), id))
        .collect();
    let mut control = new_ledger(&units);
    let mut work = Stage7Scratch::default();
    assert_eq!(
        seven(
            &hand_templated(&parts, false),
            &mut control,
            MAX_BLOCK_LINES,
            &mut work
        )
        .templated_blocks,
        1
    );
    assert!(work.work().verifications > 0);
    assert!(work.reserved() >= 4);

    let mut ledger = new_ledger(&units);
    let handoff = six(&span, &mut ledger);
    assert!(!handoff.degraded);
    let mut fresh = Stage7Scratch::default();
    let stats = seven(
        &hand_templated(&parts, true),
        &mut ledger,
        MAX_BLOCK_LINES,
        &mut fresh,
    );
    assert_eq!(stats, StageStats::default());
    assert_eq!(
        fresh.work(),
        quantification_core::detect::blocks::Work::default()
    );
    assert_eq!(fresh.reserved(), 0);
    assert_eq!(ledger.commits().len(), 0);
    assert_eq!(apply(&span, &ledger), span);
    assert_ne!(apply(&span, &control), span);
}

#[test]
fn the_leftmost_start_wins_then_the_longest_candidate() {
    let mut lines: Vec<Vec<u8>> = Vec::new();
    for index in 0..3 {
        lines.push(request(index));
        lines.push(reply(index));
    }
    lines.push(pool(7));
    lines.push(request(4));
    lines.push(reply(4));
    lines.push(pool(7));
    let span = join(&lines);
    let units = split_span(&span, UNICODE);
    assert_eq!(units.len(), 10);
    let mut ledger = new_ledger(&units);
    let handoff = six(&span, &mut ledger);
    assert_eq!(handoff.stats, StageStats::default());
    assert_eq!(
        seven(
            &handoff,
            &mut ledger,
            MAX_BLOCK_LINES,
            &mut Stage7Scratch::default()
        )
        .templated_blocks,
        1
    );
    let commit = &ledger.commits()[0];
    assert_eq!((commit.first, commit.last, commit.count), (0, 5, 2));
    assert_eq!(commit.anchor, units[0].range.start..units[1].range.end);
    assert!(!ledger.is_committed(6));
    assert!(!ledger.is_committed(7));
    assert_removal_invariant(&units, commit);

    let tail = &lines[4..];
    let tail_span = join(tail);
    let tail_units = split_span(&tail_span, UNICODE);
    let mut tail_ledger = new_ledger(&tail_units);
    let handoff = six(&tail_span, &mut tail_ledger);
    assert_eq!(
        seven(
            &handoff,
            &mut tail_ledger,
            MAX_BLOCK_LINES,
            &mut Stage7Scratch::default()
        )
        .templated_blocks,
        1
    );
    let commit = &tail_ledger.commits()[0];
    assert_eq!((commit.first, commit.last, commit.count), (0, 5, 1));
    assert_eq!(
        commit.anchor,
        tail_units[0].range.start..tail_units[2].range.end
    );
    assert_eq!(&tail_span[commit.anchor.clone()], join(&tail[..3]));
    assert_removal_invariant(&tail_units, commit);
}

#[test]
fn a_templated_block_never_straddles_a_committed_region() {
    let (span, _) = interleaved(4);
    let units = split_span(&span, UNICODE);
    assert_eq!(units.len(), 8);
    let mut ledger = new_ledger(&units);
    assert!(matches!(
        ledger.try_commit(Proposal::run(1..3, CommitKind::ExactRun)),
        CommitOutcome::Committed(_)
    ));
    let handoff = six(&span, &mut ledger);
    assert_eq!(handoff.forms.id(1), handoff.forms.id(3));
    assert_eq!(handoff.forms.id(3), handoff.forms.id(5));
    assert_eq!(
        seven(
            &handoff,
            &mut ledger,
            MAX_BLOCK_LINES,
            &mut Stage7Scratch::default()
        )
        .templated_blocks,
        1
    );
    assert_eq!(
        ledger
            .commits()
            .iter()
            .map(|commit| (commit.kind, commit.first, commit.last, commit.count))
            .collect::<Vec<_>>(),
        [
            (CommitKind::ExactRun, 1, 2, 1),
            (CommitKind::TemplatedBlock, 3, 6, 1)
        ]
    );
    assert!(!ledger.is_committed(0));
    assert_eq!(
        ledger
            .residual()
            .map(|(index, _)| index)
            .collect::<Vec<_>>(),
        [0, 7]
    );
    for commit in ledger.commits() {
        assert_removal_invariant(&units, commit);
    }
}

fn hexed(role: &str, run: usize, gap: &str) -> Vec<u8> {
    format!("{role}{gap}{}", "9".repeat(run)).into_bytes()
}

#[test]
fn a_two_unit_anchor_head_that_would_glue_to_a_template_equal_neighbour_is_refused() {
    let walled: Vec<Vec<u8>> = vec![
        hexed("a", 16, "  "),
        hexed("a", 16, " "),
        hexed("b", 98, " "),
        hexed("a", 16, " "),
        hexed("b", 98, " "),
    ];
    let span = join(&walled);
    let units = split_span(&span, UNICODE);
    assert_eq!(units.len(), 5);
    let mut ledger = new_ledger(&units);
    let handoff = six(&span, &mut ledger);
    assert_eq!(handoff.stats, StageStats::default());
    for (index, role) in [(0usize, b'a'), (1, b'a'), (2, b'b'), (3, b'a'), (4, b'b')] {
        let mut form = vec![role];
        form.extend_from_slice(b" <hex>");
        assert_eq!(handoff.forms.masked(index), form, "unit {index}");
    }
    for (left, right) in [(0, 1), (1, 3), (2, 4)] {
        assert!(
            handoff.forms.same(left, right),
            "{left} and {right} mask equal"
        );
    }
    assert!(!handoff.forms.same(0, 2));
    assert!(!profitable(UNICODE, CommitKind::TemplatedBlock, 1, 19, 39));
    assert!(profitable(
        UNICODE,
        CommitKind::TemplatedBlock,
        1,
        18 + 2 + 100,
        18 + 2 + 100 + 2 + 18 + 2 + 100
    ));
    assert_eq!(
        seven(
            &handoff,
            &mut ledger,
            MAX_BLOCK_LINES,
            &mut Stage7Scratch::default()
        ),
        StageStats::default(),
        "a profitable two-unit candidate is refused because its anchor head would glue"
    );
    assert_eq!(ledger.commits().len(), 0);
    assert_eq!(apply(&span, &ledger), span);

    let mut free = walled.clone();
    free[0] = hexed("c", 16, "  ");
    let span = join(&free);
    let units = split_span(&span, UNICODE);
    let mut ledger = new_ledger(&units);
    let handoff = six(&span, &mut ledger);
    assert_eq!(
        seven(
            &handoff,
            &mut ledger,
            MAX_BLOCK_LINES,
            &mut Stage7Scratch::default()
        )
        .templated_blocks,
        1,
        "the same candidate commits once the neighbour masks differently"
    );
    let commit = &ledger.commits()[0];
    assert_eq!((commit.first, commit.last, commit.count), (1, 4, 1));
    assert_removal_invariant(&units, commit);
}

#[test]
fn an_over_cap_record_wall_splits_templated_blocks() {
    let (span, units, wall, records) = record_dump();
    let mut ledger = new_ledger(&units);
    let handoff = six(&span, &mut ledger);
    assert_eq!(handoff.stats.template_groups, 0);
    let stats = seven(
        &handoff,
        &mut ledger,
        MAX_BLOCK_LINES,
        &mut Stage7Scratch::default(),
    );
    assert_eq!(stats.templated_blocks, 2);
    assert_eq!(
        ledger
            .commits()
            .iter()
            .map(|commit| (commit.first, commit.last, commit.count))
            .collect::<Vec<_>>(),
        [(200, 205, 2), (207, 212, 2)]
    );
    assert!(!ledger.is_committed(wall));
    assert!(ledger.is_free(wall..wall + 1));
    let removed: usize = records[200..206].iter().map(|record| record.len()).sum();
    let mut spliced_len = span.len();
    for commit in ledger.commits() {
        assert!(commit.first > wall || commit.last < wall);
        assert_eq!(commit.removed.len(), removed + 5);
        spliced_len = spliced_len - commit.removed.len() + commit.anchor.len() + 32;
        assert_removal_invariant(&units, commit);
    }
    assert_eq!(apply(&span, &ledger).len(), spliced_len);
}

#[test]
fn a_span_whose_table_filled_in_stage_six_passes_through_stage_seven() {
    let count = 200_000;
    let mut span = Vec::new();
    for index in 0..count {
        push_line(&mut span, format!("{} row 7 42", tag(index)).as_bytes());
    }
    let units = split_span(&span, UNICODE);
    assert_eq!(units.len(), count);
    let mut ledger = new_ledger(&units);
    let handoff = six(&span, &mut ledger);
    assert!(handoff.degraded);
    assert_eq!(handoff.stats, StageStats::default());
    assert!(handoff.forms.is_empty());
    let mut work = Stage7Scratch::default();
    let stats = seven(&handoff, &mut ledger, MAX_BLOCK_LINES, &mut work);
    assert_eq!(stats, StageStats::default());
    assert_eq!(
        work.work(),
        quantification_core::detect::blocks::Work::default()
    );
    assert_eq!(work.reserved(), 0);
    assert_eq!(ledger.commits().len(), 0);
    assert_eq!(ledger.residual().count(), count);
    assert_eq!(apply(&span, &ledger), span);
}

#[test]
fn templated_blocks_are_deterministic_over_a_generated_span() {
    let span = generated_span(40);
    let units = split_span(&span, UNICODE);
    assert_eq!(units.len(), 280);
    let mut first = new_ledger(&units);
    let mut second = new_ledger(&units);
    let mut other = TemplScratch::with_capacity(0);
    let left = six(&span, &mut first);
    let right = six_with(&span, &mut second, &mut other);
    assert_eq!(left.forms, right.forms);
    assert_eq!(left.stats, right.stats);
    assert_eq!(left.stats.template_groups, 40);
    assert_eq!(left.stats.groups_collapsed, 40);
    let mut wide = Stage7Scratch::with_capacity(units.len());
    let mut narrow = Stage7Scratch::default();
    let left_stats = seven(&left, &mut first, MAX_BLOCK_LINES, &mut wide);
    let right_stats = seven(&right, &mut second, MAX_BLOCK_LINES, &mut narrow);
    assert_eq!(left_stats, right_stats);
    assert_eq!(left_stats.templated_blocks, 40);
    assert_eq!(left_stats.groups_collapsed, 40);
    assert_eq!(left_stats.exact_runs, 0);
    assert_eq!(left_stats.ws_runs, 0);
    assert_eq!(left_stats.block_repeats, 0);
    assert_eq!(left_stats.template_groups, 0);
    assert_eq!(left_stats.record_splits, 0);
    assert_eq!(first.commits(), second.commits());
    assert_eq!(apply(&span, &first), apply(&span, &second));
    assert_eq!(wide.reserved(), units.len());
    assert!(narrow.reserved() >= units.len());
    for commit in first.commits() {
        assert_removal_invariant(&units, commit);
    }
    let again = seven(&left, &mut first, MAX_BLOCK_LINES, &mut wide);
    assert_eq!(again, StageStats::default());
    assert_eq!(first.commits(), second.commits());
}

#[test]
fn empty_single_unit_and_over_cap_spans_commit_nothing() {
    let mut work = Stage7Scratch::default();
    let empty: &[u8] = b"";
    let units = split_span(empty, UNICODE);
    let mut ledger = new_ledger(&units);
    let handoff = six(empty, &mut ledger);
    assert_eq!(
        seven(&handoff, &mut ledger, MAX_BLOCK_LINES, &mut work),
        StageStats::default()
    );
    let single = br"only one line 2026-08-26T10:00:00Z 10.0.0.1";
    let units = split_span(single, UNICODE);
    let mut ledger = new_ledger(&units);
    let handoff = six(single, &mut ledger);
    assert_eq!(
        seven(&handoff, &mut ledger, MAX_BLOCK_LINES, &mut work),
        StageStats::default()
    );
    let wall = vec![b'z'; MAX_LINE_BYTES + 1];
    let units = split_span(&wall, UNICODE);
    assert_eq!(units.len(), 1);
    assert!(!units[0].eligible);
    let mut ledger = new_ledger(&units);
    let handoff = six(&wall, &mut ledger);
    assert_eq!(handoff.forms.len(), 1);
    assert_eq!(
        seven(&handoff, &mut ledger, MAX_BLOCK_LINES, &mut work),
        StageStats::default()
    );
    assert!(ledger.is_free(0..1));
    assert_eq!(
        work.work(),
        quantification_core::detect::blocks::Work::default()
    );
}

fn uses_token(source: &str, banned: &str) -> bool {
    source
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|word| word == banned)
}

#[test]
fn the_templ_blocks_module_has_no_forbidden_determinism_inputs() {
    let source = include_str!("../src/detect/templ_blocks.rs");
    let uses = |banned: &str| uses_token(source, banned);
    assert!(
        uses_token("fn f() { rand(); }", "rand"),
        "a real use is seen"
    );
    assert!(
        uses_token("fn f() { std::env::var(\"X\"); }", "env"),
        "a real use is seen"
    );
    assert!(
        !uses_token("let brand = 1;", "rand"),
        "the scan is not a substring match"
    );
    assert!(
        !uses_token("fn f() { let brand = 1; }", "rand"),
        "the scan is not a substring match"
    );
    for banned in [
        "HashMap",
        "RandomState",
        "BTreeMap",
        "SystemTime",
        "Instant",
        "env",
        "rand",
        "f32",
        "f64",
        "sort_by",
        "sort_unstable",
    ] {
        assert!(!uses(banned), "stage seven must not use {banned}");
    }
    assert!(source.contains("windowed_blocks"));
    assert!(source.contains("CommitKind::TemplatedBlock"));
    assert!(source.contains("MIN_PERIOD: usize = 1"));
    assert!(!source.contains("Proposal::"));
    assert!(!source.contains("mask_into"));
    assert!(!source.contains("normalize_into"));
    assert!(!source.contains("span"));
}
