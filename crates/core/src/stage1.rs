use std::ops::Range;

use crate::config::{MAX_LINE_BYTES, MarkerStyle};
use crate::ledger::{CommitKind, framing};
use crate::stage1b::segment_line;

const KINDS: [CommitKind; 5] = [
    CommitKind::ExactRun,
    CommitKind::WsRun,
    CommitKind::Block,
    CommitKind::TemplateGroup,
    CommitKind::TemplatedBlock,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unit {
    pub range: Range<usize>,
    pub eligible: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Split {
    pub units: Vec<Unit>,
    pub record_splits: usize,
}

pub fn joiner(units: &[Unit], index: usize, end: usize) -> Range<usize> {
    let unit = &units[index];
    let stop = match units.get(index + 1) {
        Some(next) => {
            assert!(
                unit.range.end <= next.range.start,
                "units must be ascending and disjoint"
            );
            next.range.start
        }
        None => end,
    };
    unit.range.end..stop
}

pub fn split_span(span: &[u8], style: MarkerStyle) -> Vec<Unit> {
    split_span_counted(span, style).units
}

pub fn split_span_counted(span: &[u8], style: MarkerStyle) -> Split {
    let mut units = Vec::new();
    let mut record_splits = 0usize;
    let mut start = 0;
    let mut at = 0;
    while at < span.len() {
        match escape_at(span, at) {
            Some(len) => {
                if is_line_boundary(span, at, len) {
                    if start < at {
                        push_line(span, start..at, style, &mut units, &mut record_splits);
                    }
                    start = at + len;
                }
                at += len;
            }
            None => at += 1,
        }
    }
    if start < span.len() {
        push_line(
            span,
            start..span.len(),
            style,
            &mut units,
            &mut record_splits,
        );
    }
    Split {
        units,
        record_splits,
    }
}

pub fn carries_marker(unit: &[u8], style: MarkerStyle) -> bool {
    let ascii = matches!(style, MarkerStyle::Ascii | MarkerStyle::Auto);
    let unicode = matches!(style, MarkerStyle::Unicode | MarkerStyle::Auto);
    (ascii && scans(unit, MarkerStyle::Ascii)) || (unicode && scans(unit, MarkerStyle::Unicode))
}

fn scans(unit: &[u8], style: MarkerStyle) -> bool {
    let open = framing(style).0.as_bytes();
    let mut at = 0;
    while let Some(found) = find(unit, open, at) {
        if KINDS.iter().any(|kind| shape(unit, found, *kind, style)) {
            return true;
        }
        at = found + 1;
    }
    false
}

fn find(unit: &[u8], needle: &[u8], at: usize) -> Option<usize> {
    let first = *needle.first()?;
    let found = unit.get(at..)?.iter().position(|byte| *byte == first)?;
    let start = at + found;
    unit[start..].starts_with(needle).then_some(start)
}

fn shape(unit: &[u8], at: usize, kind: CommitKind, style: MarkerStyle) -> bool {
    let (open, sep, close) = framing(style);
    let (prefix, suffix) = kind.core(style);
    let mut at = at + open.len();
    if !unit[at..].starts_with(prefix.as_bytes()) {
        return false;
    }
    at += prefix.len();
    let count = count_digits(unit, at);
    if count == 0 || !unit[at + count..].starts_with(suffix.as_bytes()) {
        return false;
    }
    at += count + suffix.len();
    if !unit[at..].starts_with(sep.as_bytes()) {
        return false;
    }
    at += sep.len();
    unit.len() >= at + 4
        && unit[at..at + 4].iter().all(|byte| is_checksum(*byte))
        && unit[at + 4..].starts_with(close.as_bytes())
}

fn count_digits(unit: &[u8], at: usize) -> usize {
    let mut run = 0;
    while unit.get(at + run).is_some_and(u8::is_ascii_digit) {
        run += 1;
    }
    run
}

fn is_checksum(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn escape_at(span: &[u8], at: usize) -> Option<usize> {
    if span[at] != b'\\' || at + 1 >= span.len() {
        return None;
    }
    Some(if span[at + 1] == b'u' { 6 } else { 2 }.min(span.len() - at))
}

fn is_line_boundary(span: &[u8], at: usize, len: usize) -> bool {
    if len == 2 {
        return span[at + 1] == b'n';
    }
    len == 6 && matches!(&span[at + 2..at + 6], b"000A" | b"000a")
}

fn push_line(
    span: &[u8],
    range: Range<usize>,
    style: MarkerStyle,
    units: &mut Vec<Unit>,
    splits: &mut usize,
) {
    let line = &span[range.clone()];
    if line.len() > MAX_LINE_BYTES {
        *splits += 1;
        units.extend(segment_line(line, range.start, style));
    } else {
        units.push(Unit {
            range,
            eligible: !carries_marker(line, style),
        });
    }
}
