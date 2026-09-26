use std::ops::Range;

use crate::config::MAX_LINE_BYTES;
use crate::stage1b::segment_line;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unit {
    pub range: Range<usize>,
    pub eligible: bool,
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
    let mut units = Vec::new();
    let mut start = 0;
    let mut at = 0;
    while at < span.len() {
        match escape_at(span, at) {
            Some(len) => {
                if is_line_boundary(span, at, len) {
                    if start < at {
                        push_line(span, start..at, &mut units);
                    }
                    start = at + len;
                }
                at += len;
            }
            None => at += 1,
        }
    }
    if start < span.len() {
        push_line(span, start..span.len(), &mut units);
    }
    units
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

fn push_line(span: &[u8], range: Range<usize>, units: &mut Vec<Unit>) {
    let line = &span[range.clone()];
    if line.len() > MAX_LINE_BYTES {
        units.extend(segment_line(line, range.start));
    } else {
        units.push(Unit {
            range,
            eligible: true,
        });
    }
}
