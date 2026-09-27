use quantification_core::config::MarkerStyle;
use quantification_core::stage1::split_span;
use quantification_core::wsnorm::{next_byte, normalize, normalize_into};

const UNICODE: MarkerStyle = MarkerStyle::Unicode;

const GOLDEN: [(&[u8], &[u8]); 22] = [
    (b"", b""),
    (b" ", b""),
    (b"   ", b""),
    (br"\t", b""),
    (br"\t\t", b""),
    (br"\t \r", b""),
    (br"\t a \t", b"a"),
    (br"a\tb", b"a b"),
    (br"a\t\tb", b"a b"),
    (br"a   b", b"a b"),
    (br"a \t\r b", b"a b"),
    (br"a\nb", b"a b"),
    (br"a\rb", b"a b"),
    (br"a\tb\nc\rd", b"a b c d"),
    (br"a\u000Ab", br"a\u000Ab"),
    (br"a\u000ab", br"a\u000ab"),
    (br" \u000A ", br"\u000A"),
    (br"\u000A\t\u000A", br"\u000A \u000A"),
    (br"a\\nb", br"a\\nb"),
    (b"a\"b", b"a\"b"),
    (br"a\u0041b", br"a\u0041b"),
    (br"a \u0041 b", br"a \u0041 b"),
];

fn assert_norm(input: &[u8], expect: &[u8]) {
    assert_eq!(normalize(input), expect, "input {input:?}");
    let mut scratch = b"stale".to_vec();
    normalize_into(input, &mut scratch);
    assert_eq!(scratch, expect, "scratch input {input:?}");
}

#[test]
fn golden_vectors() {
    for (input, expect) in GOLDEN {
        assert_norm(input, expect);
    }
}

#[test]
fn u000a_is_not_a_collapse_source() {
    for boundary in [&br"\u000A"[..], &br"\u000a"[..]] {
        let input = [br"a\t", boundary, b" b"].concat();
        let expect = [b"a ", boundary, b" b"].concat();
        assert_norm(&input, &expect);
    }
    for collapse in [&br"\t"[..], &br"\r"[..], &b" "[..], &br"\n"[..]] {
        let input = [b"a", collapse, b"b"].concat();
        assert_norm(&input, b"a b");
    }
}

#[test]
fn mixed_boundary_forms_split_into_equal_ws_lines() {
    let n_form = br"2026-08-26T10:00:00Z\tINFO\thc  10.0.0.1 ok\n2026-08-26T10:00:01Z\tINFO\thc  10.0.0.1 ok";
    let u_form = br"2026-08-26T10:00:00Z\tINFO\thc  10.0.0.1 ok\u000A2026-08-26T10:00:01Z\tINFO\thc  10.0.0.1 ok";
    let forms = |span: &[u8]| {
        split_span(span, UNICODE)
            .iter()
            .map(|unit| normalize(&span[unit.range.clone()]))
            .collect::<Vec<Vec<u8>>>()
    };
    let a = forms(n_form);
    assert_eq!(a.len(), 2);
    assert_eq!(a[0], b"2026-08-26T10:00:00Z INFO hc 10.0.0.1 ok");
    assert_eq!(a[1], b"2026-08-26T10:00:01Z INFO hc 10.0.0.1 ok");
    assert_eq!(forms(u_form), a);
}

#[test]
fn other_escape_units_stay_literal() {
    for input in [
        &br"\u0009"[..],
        &br"\u000D"[..],
        &br"\u0041"[..],
        &br"\\"[..],
        &br"\"[..],
        &br"\"[..],
        &br"\u"[..],
        &br"\u0"[..],
        &b"a\\"[..],
        &br"\x"[..],
        &b"\t"[..],
        &b"\r"[..],
        &br"a \x20 b"[..],
    ] {
        assert_norm(input, input);
    }
}

#[test]
fn raw_whitespace_bytes_stay_literal() {
    assert_norm(b"a\tb", b"a\tb");
    assert_norm(b"a\rb", b"a\rb");
    assert_norm(b"a\nb", b"a\nb");
    assert_norm(b"\ta\t", b"\ta\t");
}

#[test]
fn non_ascii_bytes_survive() {
    assert_norm("héllo → wörld".as_bytes(), "héllo → wörld".as_bytes());
    assert_norm("  \\t→\\r ".as_bytes(), "→".as_bytes());
    assert_norm("\u{2192}\u{2192}".as_bytes(), "\u{2192}\u{2192}".as_bytes());
}

#[test]
fn transform_is_idempotent_and_trims_collapsed_space() {
    for (input, expect) in GOLDEN {
        let once = normalize(input);
        assert_eq!(normalize(&once), once, "input {input:?}");
        assert_eq!(once, expect, "input {input:?}");
        if !once.is_empty() {
            assert_ne!(once[0], b' ', "leading space in {input:?}");
            assert_ne!(once[once.len() - 1], b' ', "trailing space in {input:?}");
            assert!(
                !once.windows(2).any(|w| w == b"  "),
                "double space in {input:?}"
            );
        }
    }
}

fn naive(raw: &[u8], from: usize, byte: u8) -> usize {
    (from..=raw.len())
        .find(|at| raw.get(*at) == Some(&byte))
        .unwrap_or(raw.len())
}

#[test]
fn the_word_scan_finds_a_byte_at_every_offset_of_the_word() {
    let filler: Vec<u8> = (0..40u8).map(|at| b'a' + at % 26).collect();
    for len in 0..24usize {
        for target in [b' ', b'\\', b'q', 0u8] {
            for offset in 0..8usize {
                let mut raw = filler[..len].to_vec();
                raw.resize(len.max(offset + 1), b'z');
                raw[offset] = target;
                for from in 0..=raw.len() {
                    assert_eq!(
                        next_byte(&raw, from, target),
                        naive(&raw, from, target),
                        "byte {target:?} at {offset} of a {len}-byte run, from {from}"
                    );
                }
            }
        }
    }
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const TOKENS: [&[u8]; 13] = [
    br"\t",
    br"\n",
    br"\r",
    b" ",
    br"\u000A",
    br"\u000a",
    br"\\",
    b"\"",
    br"\u0041",
    b"ab",
    b"x",
    b"0",
    "→".as_bytes(),
];

#[test]
fn property_generated_spans_collapse_deterministically() {
    let mut rng = Rng(0x5eed_1234_abcd_0303);
    let (mut tabs, mut runs, mut boundaries) = (0, 0, 0);
    for case in 0..200 {
        let mut input = Vec::new();
        while input.len() < 1 + rng.below(200) {
            input.extend_from_slice(TOKENS[rng.below(TOKENS.len())]);
        }
        let out = normalize(&input);
        assert_eq!(normalize(&out), out, "case {case}");
        assert!(out.len() <= input.len(), "case {case} grew");
        if out.is_empty() {
            continue;
        }
        assert_ne!(out[0], b' ', "case {case}");
        assert_ne!(out[out.len() - 1], b' ', "case {case}");
        assert!(!out.windows(2).any(|w| w == b"  "), "case {case}");
        if out.len() < input.len() {
            runs += 1;
        }
        if input.windows(2).any(|w| w == br"\t") {
            tabs += 1;
        }
        if input.windows(6).any(|w| w == br"\u000A" || w == br"\u000a") {
            boundaries += 1;
        }
    }
    assert!(tabs > 0, "generator never emitted a \\t escape unit");
    assert!(runs > 0, "generator never produced a collapse");
    assert!(boundaries > 0, "generator never emitted a \\u000A boundary");
}
