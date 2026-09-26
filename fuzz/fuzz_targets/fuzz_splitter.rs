#![no_main]
use libfuzzer_sys::fuzz_target;
use quantification_core::stage1::split_span;

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
        out.extend_from_slice(&data[at..unit.range.end]);
        out.extend_from_slice(&data[unit.range.end..stop]);
        at = stop;
    }
    out.extend_from_slice(&data[at..]);
    assert_eq!(out, data, "units and joiners must rebuild the span");
});
