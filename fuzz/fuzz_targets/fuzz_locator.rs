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
const KEYS: [&[u8]; 10] = [
    b"messages",
    b"input",
    b"role",
    b"content",
    b"type",
    b"text",
    b"output",
    b"system",
    b"tool_use_id",
    b"max_tokens",
];
const DEPTH_CAP: usize = 96;
const RANGE_CAP: usize = 1024;

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
    check_last_wins(data, located, schema, bom);
}

fn check_last_wins(data: &[u8], located: &Located, schema: Schema, bom: usize) {
    if schema == Schema::Text || located.spans.is_empty() {
        return;
    }
    let body = data.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(data);
    let Some(shadowed) = shadowed_ranges(body) else {
        return;
    };
    for span in &located.spans {
        for range in &shadowed {
            assert!(
                !(span.start - bom >= range.0 && span.end - bom <= range.1),
                "span {span:?} reported inside a shadowed key value {:?}",
                range
            );
        }
    }
}

fn shadowed_ranges(body: &[u8]) -> Option<Vec<(usize, usize)>> {
    let mut out = Vec::new();
    let mut at = 0usize;
    value(&mut at, body, 0, &mut out)?;
    Some(out)
}

fn value(
    at: &mut usize,
    d: &[u8],
    depth: usize,
    out: &mut Vec<(usize, usize)>,
) -> Option<(usize, usize)> {
    if depth > DEPTH_CAP {
        return None;
    }
    ws(d, at);
    let start = *at;
    match d.get(*at)? {
        b'{' => {
            *at += 1;
            members(at, d, depth + 1, out)?;
        }
        b'[' => {
            *at += 1;
            elements(at, d, depth + 1, out)?;
        }
        b'"' => *at = string_end(d, *at)? + 1,
        _ => {
            while d
                .get(*at)
                .is_some_and(|b| !matches!(b, b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r'))
            {
                *at += 1;
            }
        }
    }
    Some((start, *at))
}

fn members(at: &mut usize, d: &[u8], depth: usize, out: &mut Vec<(usize, usize)>) -> Option<()> {
    let mut last: [Option<(usize, usize)>; 10] = [None; 10];
    loop {
        ws(d, at);
        if d.get(*at) == Some(&b'}') {
            *at += 1;
            return Some(());
        }
        if d.get(*at) != Some(&b'"') {
            return None;
        }
        let close = string_end(d, *at)?;
        let id = KEYS.iter().position(|key| *key == &d[*at + 1..close]);
        *at = close + 1;
        ws(d, at);
        if d.get(*at) != Some(&b':') {
            return None;
        }
        *at += 1;
        let range = value(at, d, depth, out)?;
        if let Some(id) = id
            && let Some(previous) = last[id].replace(range)
            && out.len() < RANGE_CAP
        {
            out.push(previous);
        }
        ws(d, at);
        match d.get(*at)? {
            b',' => *at += 1,
            b'}' => {
                *at += 1;
                return Some(());
            }
            _ => return None,
        }
    }
}

fn elements(at: &mut usize, d: &[u8], depth: usize, out: &mut Vec<(usize, usize)>) -> Option<()> {
    ws(d, at);
    if d.get(*at) == Some(&b']') {
        *at += 1;
        return Some(());
    }
    loop {
        value(at, d, depth, out)?;
        ws(d, at);
        match d.get(*at)? {
            b',' => *at += 1,
            b']' => {
                *at += 1;
                return Some(());
            }
            _ => return None,
        }
    }
}

fn ws(d: &[u8], at: &mut usize) {
    while d
        .get(*at)
        .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
    {
        *at += 1;
    }
}

fn string_end(d: &[u8], at: usize) -> Option<usize> {
    let mut j = at + 1;
    while j < d.len() {
        match d[j] {
            b'\\' => j += 2,
            b'"' => return Some(j),
            0..=0x1F => return None,
            _ => j += 1,
        }
    }
    None
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
