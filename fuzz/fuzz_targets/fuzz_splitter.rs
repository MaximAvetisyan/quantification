#![no_main]
use std::ops::Range;

use libfuzzer_sys::fuzz_target;
use quantification_core::config::MarkerStyle;
use quantification_core::stage1::{Unit, joiner, split_span};

fuzz_target!(|data: &[u8]| {
    for style in [MarkerStyle::Ascii, MarkerStyle::Unicode] {
        check(data, style);
    }
    assert_eq!(
        ranges(&split_span(data, MarkerStyle::Ascii)),
        ranges(&split_span(data, MarkerStyle::Unicode)),
        "the marker style may change eligibility, never the unit ranges"
    );
});

fn ranges(units: &[Unit]) -> Vec<Range<usize>> {
    units.iter().map(|unit| unit.range.clone()).collect()
}

fn check(data: &[u8], style: MarkerStyle) {
    let units = split_span(data, style);
    let mut out = Vec::new();
    let mut at = 0;
    for (index, unit) in units.iter().enumerate() {
        let stop = joiner(&units, index, data.len()).end;
        assert!(at <= unit.range.start, "unit overlaps its predecessor");
        assert!(unit.range.end <= stop, "unit overlaps its successor");
        let gap = &data[unit.range.end..stop];
        assert!(
            gap.is_empty() || gap == b"," || is_boundary_run(gap),
            "a gap is empty, a record comma, or nothing but line boundaries: {gap:?}"
        );
        assert!(
            !has_boundary(&data[unit.range.clone()]),
            "a unit is one line and holds no line boundary: {:?}",
            unit.range
        );
        out.extend_from_slice(&data[at..unit.range.start]);
        out.extend_from_slice(&data[unit.range.clone()]);
        at = unit.range.end;
    }
    out.extend_from_slice(&data[at..]);
    assert_eq!(out, data, "units and gaps must tile the span");
}

fn escaped_len(data: &[u8], at: usize) -> usize {
    if data.get(at + 1) == Some(&b'u') {
        6
    } else {
        2
    }
    .min(data.len() - at)
}

fn boundary_at(data: &[u8], at: usize) -> Option<usize> {
    if data.get(at) != Some(&b'\\') {
        return None;
    }
    let len = escaped_len(data, at);
    let boundary = match len {
        2 => data[at + 1] == b'n',
        6 => matches!(&data[at + 2..at + 6], b"000A" | b"000a"),
        _ => false,
    };
    boundary.then_some(len)
}

fn is_boundary_run(gap: &[u8]) -> bool {
    let mut at = 0;
    let mut seen = 0;
    while at < gap.len() {
        let Some(len) = boundary_at(gap, at) else {
            return false;
        };
        at += len;
        seen += 1;
    }
    seen > 0
}

fn has_boundary(line: &[u8]) -> bool {
    let mut at = 0;
    while at < line.len() {
        if boundary_at(line, at).is_some() {
            return true;
        }
        at += if line[at] == b'\\' {
            escaped_len(line, at)
        } else {
            1
        };
    }
    false
}
