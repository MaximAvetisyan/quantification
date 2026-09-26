use std::ops::Range;

use crate::config::MAX_LINE_BYTES;
use crate::stage1b::segment_line;

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

pub fn split_span(span: &[u8]) -> Vec<Unit> {
    split_span_counted(span).units
}

pub fn split_span_counted(span: &[u8]) -> Split {
    let mut units = Vec::new();
    let mut record_splits = 0usize;
    let mut start = 0;
    let mut at = 0;
    while at < span.len() {
        match escape_at(span, at) {
            Some(len) => {
                if is_line_boundary(span, at, len) {
                    if start < at {
                        push_line(span, start..at, &mut units, &mut record_splits);
                    }
                    start = at + len;
                }
                at += len;
            }
            None => at += 1,
        }
    }
    if start < span.len() {
        push_line(span, start..span.len(), &mut units, &mut record_splits);
    }
    Split {
        units,
        record_splits,
    }
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

fn push_line(span: &[u8], range: Range<usize>, units: &mut Vec<Unit>, splits: &mut usize) {
    let line = &span[range.clone()];
    if line.len() > MAX_LINE_BYTES {
        *splits += 1;
        units.extend(segment_line(line, range.start));
    } else {
        units.push(Unit {
            range,
            eligible: true,
        });
    }
}
