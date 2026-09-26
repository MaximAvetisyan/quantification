#![no_main]
use libfuzzer_sys::fuzz_target;

use quantification_core::config::ScopePolicy;
use quantification_core::locator::{locate, locate_as, Located, Span, SpanClass};
use quantification_core::sniff::Schema;

const POLICIES: [ScopePolicy; 2] = [ScopePolicy::UserContent, ScopePolicy::UserAndTools];
const SCHEMAS: [Schema; 4] = [
    Schema::Chat,
    Schema::Responses,
    Schema::Messages,
    Schema::Text,
];

fuzz_target!(|data: &[u8]| {
    for schema in SCHEMAS {
        for policy in POLICIES {
            let pinned = locate_as(data, schema, policy);
            check(data, &pinned, schema, policy);
            let auto = locate(data, policy);
            check(data, &auto, auto.schema.unwrap_or(Schema::Text), policy);
            if auto.schema.is_some() {
                assert_eq!(
                    fingerprint(&auto),
                    fingerprint(&locate(data, policy)),
                    "auto-detect must be deterministic"
                );
            }
        }
    }
});

fn fingerprint(located: &Located) -> Vec<(usize, usize, SpanClass)> {
    located
        .spans
        .iter()
        .map(|s| (s.start, s.end, s.class))
        .collect()
}

fn check(data: &[u8], located: &Located, schema: Schema, policy: ScopePolicy) {
    if located.degraded() {
        assert!(
            located.spans.is_empty(),
            "a degraded result must carry no spans: {:?}",
            located.noop_reason
        );
        return;
    }
    let json = schema != Schema::Text;
    let bom = usize::from(data.starts_with(&[0xEF, 0xBB, 0xBF])) * 3;
    let mut last = 0usize;
    for span in &located.spans {
        check_span(data, span, json, bom, last);
        last = span.end;
    }
    for span in &located.spans {
        assert!(
            span.class == SpanClass::User || policy == ScopePolicy::UserAndTools,
            "a tool span escaped the {policy:?} policy"
        );
    }
}

fn check_span(data: &[u8], span: &Span, json: bool, bom: usize, last: usize) {
    assert!(span.start < span.end, "empty span in {span:?}");
    assert!(span.end <= data.len(), "span out of bounds in {span:?}");
    assert!(span.start >= last, "spans must ascend and stay disjoint");
    assert!(span.start >= bom, "a BOM is never part of a span");
    if json {
        assert!(span.start > 0 && span.end < data.len(), "span {span:?} is not interior");
        assert_eq!(data[span.start - 1], b'"', "span {span:?} is not a string interior");
        assert_eq!(data[span.end], b'"', "span {span:?} is not a string interior");
        let raw = &data[span.start..span.end];
        let mut at = 0usize;
        while at < raw.len() {
            match raw[at] {
                b'\\' => at += 2,
                b'"' => panic!("unescaped quote inside span {span:?}"),
                0..=0x1F => panic!("raw control byte inside span {span:?}"),
                _ => at += 1,
            }
        }
    }
}
