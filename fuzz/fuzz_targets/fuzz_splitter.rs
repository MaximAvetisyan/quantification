#![no_main]
use libfuzzer_sys::fuzz_target;
use quantification_core::stage1::split_span;

const BOUNDARIES: [&[u8]; 3] = [br"\n", br"\u000A", br"\u000a"];

fuzz_target!(|data: &[u8]| {
    let units = split_span(data);
    let mut out = Vec::new();
    let mut at = 0;
    for (index, unit) in units.iter().enumerate() {
        let stop = units
            .get(index + 1)
            .map_or(data.len(), |next| next.range.start);
        assert!(at <= unit.range.start, "unit overlaps its predecessor");
        assert!(unit.range.end <= stop, "unit overlaps its successor");
        assert!(
            joiner(&data[unit.range.end..stop]),
            "units are joined by separators"
        );
        out.extend_from_slice(&data[at..unit.range.start]);
        out.extend_from_slice(&data[unit.range.clone()]);
        at = unit.range.end;
    }
    out.extend_from_slice(&data[at..]);
    assert_eq!(out, data, "units and joiners must rebuild the span");
});

fn joiner(gap: &[u8]) -> bool {
    if gap == b"," {
        return true;
    }
    let mut at = 0;
    while at < gap.len() {
        let Some(boundary) = BOUNDARIES.iter().find(|unit| gap[at..].starts_with(unit)) else {
            return false;
        };
        at += boundary.len();
    }
    at == gap.len()
}
