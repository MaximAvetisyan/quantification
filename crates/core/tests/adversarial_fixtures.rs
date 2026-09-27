#![allow(dead_code)]

use quantification_core::fingerprint::{FingerprintTable, fingerprint};

pub const SEED: u64 = 0x0AD5_1E4D_5EED_0001;

const PREFIX: &[u8] = br#"{"model":"m","messages":[{"role":"user","content":""#;
const SUFFIX: &[u8] = br#""}]}"#;
const TAG_WIDTH: usize = 6;
const BODY_REPEATS: usize = 20;
const ALPHABET: &[u8; 8] = b"abcdefgh";

pub struct Case {
    pub name: &'static str,
    pub payload: Vec<u8>,
}

pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    pub fn letters(&mut self, out: &mut Vec<u8>, len: usize) {
        for _ in 0..len {
            out.push(b'a' + self.below(26) as u8);
        }
    }
}

pub fn chat(span: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(span.len() + PREFIX.len() + SUFFIX.len());
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(span);
    out.extend_from_slice(SUFFIX);
    out
}

pub fn tag(out: &mut Vec<u8>, index: usize) {
    let mut rest = index;
    for _ in 0..TAG_WIDTH {
        out.push(b'a' + (rest % 26) as u8);
        rest /= 26;
    }
}

pub fn newline(out: &mut Vec<u8>, count: usize) {
    match count % 4 {
        1 => out.extend_from_slice(br"\u000A"),
        2 => out.extend_from_slice(br"\u000a"),
        _ => out.extend_from_slice(br"\n"),
    }
}

pub fn periodic_body(out: &mut Vec<u8>) {
    for _ in 0..BODY_REPEATS {
        out.extend_from_slice(ALPHABET);
    }
}

pub fn unique_lines(lines: usize) -> Vec<u8> {
    let mut span = Vec::with_capacity(lines * 11);
    for index in 0..lines {
        span.extend_from_slice(b"hc ");
        tag(&mut span, index);
        newline(&mut span, index);
    }
    chat(&span)
}

pub fn giant_line(bytes: usize) -> Vec<u8> {
    let mut rng = Rng::new(SEED);
    let mut span = Vec::with_capacity(bytes + 8);
    span.extend_from_slice(b"hc ");
    while span.len() < bytes {
        let room = 4096.min(bytes - span.len());
        rng.letters(&mut span, room);
    }
    newline(&mut span, 0);
    chat(&span)
}

pub fn periodic_units(lines: usize, period: usize) -> Vec<u8> {
    let mut rng = Rng::new(SEED);
    let mut span = Vec::with_capacity(lines * 200);
    for index in 0..lines {
        span.extend_from_slice(b"hc ");
        periodic_body(&mut span);
        span.push(b' ');
        tag(&mut span, index % period);
        span.push(b' ');
        rng.letters(&mut span, 7);
        newline(&mut span, index);
    }
    chat(&span)
}

pub fn nested_arrays(levels: usize, per_level: usize) -> Vec<u8> {
    let mut span = Vec::new();
    for level in 0..levels {
        for _ in 0..per_level {
            span.extend_from_slice(br#"[[{\"hc "#);
            tag(&mut span, level);
            span.push(b' ');
            span.extend_from_slice(ALPHABET);
            span.extend_from_slice(br#"\""#);
            newline(&mut span, level);
        }
        span.extend_from_slice(b"}],");
    }
    for step in 0..2 * levels * per_level {
        span.push(b']');
        if step % 1000 == 999 {
            newline(&mut span, step);
        }
    }
    span.push(b'}');
    chat(&span)
}

pub fn deep_envelope(depth: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(
        br#"{"messages":[{"role":"user","content":"hc deep nesting payload","pad":"#,
    );
    out.extend(std::iter::repeat_n(b'[', depth));
    out.extend_from_slice(br#"{"k":"v"}"#);
    out.extend(std::iter::repeat_n(b']', depth));
    out.extend_from_slice(br#"}]}"#);
    out
}

pub fn tiny_messages(count: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(count * 46);
    out.extend_from_slice(br#"{"messages":["#);
    for index in 0..count {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(br#"{"role":""#);
        out.extend_from_slice(if index % 2 == 0 {
            b"user".as_slice()
        } else {
            b"assistant".as_slice()
        });
        out.extend_from_slice(br#"","content":""#);
        tag(&mut out, index % 26);
        out.extend_from_slice(br#""}"#);
    }
    out.extend_from_slice(br#"]}"#);
    out
}

pub fn collision_neighbors(groups: usize) -> Vec<u8> {
    let mut span = Vec::with_capacity(groups * 120);
    for group in 0..groups {
        for member in 0..3 {
            span.extend_from_slice(b"hc ");
            tag(&mut span, group);
            span.extend_from_slice(b" bytes=");
            span.push(b'0' + member as u8);
            newline(&mut span, group * 3 + member);
        }
        for member in 0..3 {
            span.extend_from_slice(b"hc ");
            tag(&mut span, group);
            span.push(if member == 0 { b'a' } else { b'b' });
            tag(&mut span, member);
            newline(&mut span, groups * 3 + group * 3 + member);
        }
    }
    chat(&span)
}

pub fn neighbor_line(group: usize, member: usize) -> Vec<u8> {
    let mut line = Vec::new();
    line.extend_from_slice(b"hc ");
    tag(&mut line, group);
    line.push(if member == 0 { b'a' } else { b'b' });
    tag(&mut line, member);
    line
}

pub fn dense_records(records: usize, unique: bool) -> Vec<u8> {
    let mut span = Vec::with_capacity(records * 12);
    span.push(b'[');
    for index in 0..records {
        if index > 0 {
            span.push(b',');
        }
        span.extend_from_slice(br#"{\"k\":0}"#);
        if unique {
            span.pop();
            for shift in 0..8 {
                span.push(b'0' + (index / 10usize.pow(shift) % 10) as u8);
            }
            span.push(b'}');
        }
    }
    span.push(b']');
    chat(&span)
}

pub fn record(index: usize, unique: bool) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(br#"{\"k":"#);
    if unique {
        for shift in 0..8 {
            out.push(b'0' + (index / 10usize.pow(shift) % 10) as u8);
        }
    } else {
        out.push(b'0');
    }
    out.extend_from_slice(br#"\"}"#);
    out
}

pub fn same_slot_keys(wanted: usize, slots: usize) -> Vec<Vec<u8>> {
    let mut rng = Rng::new(SEED);
    let mut out: Vec<Vec<u8>> = Vec::with_capacity(wanted);
    while out.len() < wanted {
        let mut key = b"k".to_vec();
        rng.letters(&mut key, 24);
        if (fingerprint(&key) as u64 as usize) & (slots - 1) == 0 {
            out.push(key);
        }
    }
    out
}

pub fn table_for(key_bytes: usize) -> FingerprintTable {
    FingerprintTable::for_keys(key_bytes)
}

pub fn cases(
    unique: usize,
    giant: usize,
    periodic: usize,
    nested: usize,
    tiny: usize,
) -> Vec<Case> {
    vec![
        Case {
            name: "adversarial/unique-lines",
            payload: unique_lines(unique),
        },
        Case {
            name: "adversarial/giant-line",
            payload: giant_line(giant),
        },
        Case {
            name: "adversarial/periodic-units",
            payload: periodic_units(periodic, 129),
        },
        Case {
            name: "adversarial/nested-arrays",
            payload: nested_arrays(nested, 3),
        },
        Case {
            name: "adversarial/deep-envelope-at-cap",
            payload: deep_envelope(60),
        },
        Case {
            name: "adversarial/deep-envelope-over-cap",
            payload: deep_envelope(96),
        },
        Case {
            name: "adversarial/tiny-messages",
            payload: tiny_messages(tiny),
        },
        Case {
            name: "adversarial/collision-neighbors",
            payload: collision_neighbors(200),
        },
        Case {
            name: "adversarial/dense-records",
            payload: dense_records(9_000, false),
        },
        Case {
            name: "adversarial/dense-records-unique",
            payload: dense_records(9_000, true),
        },
    ]
}

pub fn suite() -> Vec<Case> {
    cases(9_000, 200_000, 1_200, 500, 20_000)
}

pub fn bench_suite() -> Vec<Case> {
    cases(200_000, 4 << 20, 40_000, 40_000, 1_000_000)
}

pub fn gate_suite() -> Vec<Case> {
    vec![
        Case {
            name: "adversarial/unique-lines",
            payload: unique_lines(64),
        },
        Case {
            name: "adversarial/giant-line",
            payload: giant_line(20_000),
        },
        Case {
            name: "adversarial/periodic-units",
            payload: periodic_units(300, 129),
        },
        Case {
            name: "adversarial/nested-arrays",
            payload: nested_arrays(100, 2),
        },
        Case {
            name: "adversarial/deep-envelope-at-cap",
            payload: deep_envelope(60),
        },
        Case {
            name: "adversarial/deep-envelope-over-cap",
            payload: deep_envelope(96),
        },
        Case {
            name: "adversarial/tiny-messages",
            payload: tiny_messages(32),
        },
        Case {
            name: "adversarial/collision-neighbors",
            payload: collision_neighbors(4),
        },
        Case {
            name: "adversarial/dense-records",
            payload: dense_records(9_000, false),
        },
        Case {
            name: "adversarial/dense-records-unique",
            payload: dense_records(9_000, true),
        },
    ]
}
