use quantification_core::mask::{MASK_LIST, Mask, mask, mask_into};
use quantification_core::wsnorm::normalize;

const PRIORITY: [(&[u8], &[u8]); 4] = [
    (
        b"2026-08-26T10:00:00Z 10.0.0.1 123e4567-e89b-12d3-a456-426614174000 0123456789abcdef 12ms 42",
        b"<ts> <ip> <uuid> <hex> <dur> <num>",
    ),
    (b"12345678901234567ms", b"<hex>ms"),
    (b"2026-08-26", b"<ts>"),
    (b"10.0.0.1:8080", b"<ip>:<num>"),
];

const TS: [(&[u8], &[u8]); 12] = [
    (b"2026-08-26T10:00:00Z", b"<ts>"),
    (b"2026-08-26t10:00:00z", b"<ts>"),
    (b"2026-08-26 10:00:00", b"<ts>"),
    (b"2026-08-26T10:00:00", b"<ts>"),
    (b"2026-08-26T10:00:00.123456789+02:00", b"<ts>"),
    (b"2026-08-26T10:00:00.5+0200", b"<ts>"),
    (b"2026-08-26T10:00:00-05:30", b"<ts>"),
    (b"2026-08-26", b"<ts>"),
    (b"Aug 26 10:00:01 host app: msg", b"<ts> host app: msg"),
    (b"Jan  1 00:00:00", b"<ts>"),
    (b"2026-08-26T10:00:00,123", b"<ts>,<num>"),
    (b"20260826T100000Z", b"<num>T<num>Z"),
];

const IP: [(&[u8], &[u8]); 12] = [
    (b"10.0.0.1", b"<ip>"),
    (b"0.0.0.0", b"<ip>"),
    (b"255.255.255.255", b"<ip>"),
    (b"1.2.3.4.5", b"<ip>.<num>"),
    (b"256.1.1.1", b"<num>.<num>"),
    (b"999.1.1.1", b"<num>.<num>"),
    (b"1.2.3", b"<num>.<num>"),
    (b"1234.1.1.1", b"<num>.<num>"),
    (b"::1", b"<ip>"),
    (b"fe80::", b"<ip>"),
    (b"2001:0db8:0000:0000:0000:ff00:0042:8329", b"<ip>"),
    (b"::ffff:192.168.1.1", b"<ip>"),
];

const IP_REJECTED: [&[u8]; 6] = [
    b"12:30:45",
    b"1:2:3:4:5:6:7",
    b"::",
    b":::",
    b"fe80:1",
    b"2026-08-26",
];

const UUID: [(&[u8], &[u8]); 4] = [
    (b"123e4567-e89b-12d3-a456-426614174000", b"<uuid>"),
    (b"123E4567-E89B-12D3-A456-426614174000", b"<uuid>"),
    (b"550e8400-e29b-41d4-a716-446655440000", b"<uuid>"),
    (b"123e4567e89b12d3a456426614174000", b"<hex>"),
];

const UUID_REJECTED: [&[u8]; 5] = [
    b"123e4567-e89b-12d3",
    b"123e4567-e89b-12d3-a456-42661417400",
    b"123e4567-e89b-12d3-a456-4266141740000",
    b"123e456-e89b-12d3-a456-426614174000",
    b"123e45678e89b12d3a456426614174000",
];

const HEX: [(&[u8], &[u8]); 6] = [
    (b"0123456789abcde", b"<num>abcde"),
    (b"0123456789abcdef", b"<hex>"),
    (b"deadBEEF0123456789abcdef", b"<hex>"),
    (b"0xdeadbeefcafebabe", b"<num>x<hex>"),
    (b"0123456789abcdef0123456789abcdef01234567", b"<hex>"),
    (b"0x1F", b"<num>x<num>F"),
];

const DUR: [(&[u8], &[u8]); 10] = [
    (b"5ms", b"<dur>"),
    (b"100us", b"<dur>"),
    (b"3ns", b"<dur>"),
    (b"2s", b"<dur>"),
    (b"10m", b"<dur>"),
    (b"1h", b"<dur>"),
    (b"1.5s", b"<dur>"),
    (b"1.5.3", b"<num>.<num>"),
    (b"1m30s", b"<dur><dur>"),
    (b"5msg", b"<dur>g"),
];

const DUR_REJECTED: [&[u8]; 4] = [b"5", b"5u", b"ms", b"1.5"];

const NUM: [(&[u8], &[u8]); 7] = [
    (b"42", b"<num>"),
    (b"007", b"<num>"),
    (b"3.14", b"<num>"),
    (b".5", b".<num>"),
    (b"v1.2", b"v<num>"),
    (b"size=-1", b"size=-<num>"),
    (
        "a\u{2192} 12 -> 13".as_bytes(),
        "a\u{2192} <num> -> <num>".as_bytes(),
    ),
];

const ESCAPES: [(&[u8], &[u8]); 6] = [
    (br"a\tb 42", br"a\tb <num>"),
    (br"\u0031", br"\u0031"),
    (br"\u0041", br"\u0041"),
    (br"\u000A", br"\u000A"),
    (b"a\\\"b 42", b"a\\\"b <num>"),
    (br"10.0.0.1 \u0031 42", br"<ip> \u0031 <num>"),
];

const ALL: &[&[(&[u8], &[u8])]] = &[&PRIORITY, &TS, &IP, &UUID, &HEX, &DUR, &NUM, &ESCAPES];

fn assert_goldens(goldens: &[(&[u8], &[u8])]) {
    for (input, expect) in goldens {
        assert_eq!(mask(input), *expect, "input {input:?}");
        let mut scratch = b"stale".to_vec();
        mask_into(input, &mut scratch);
        assert_eq!(scratch, *expect, "scratch input {input:?}");
    }
}

#[test]
fn frozen_mask_list_and_placeholders() {
    assert_eq!(
        MASK_LIST,
        [
            Mask::Ts,
            Mask::Ip,
            Mask::Uuid,
            Mask::Hex,
            Mask::Dur,
            Mask::Num
        ]
    );
    let placeholders: Vec<&[u8]> = MASK_LIST.iter().map(|m| m.placeholder()).collect();
    assert_eq!(
        placeholders,
        vec![
            &b"<ts>"[..],
            b"<ip>",
            b"<uuid>",
            b"<hex>",
            b"<dur>",
            b"<num>"
        ]
    );
    for placeholder in placeholders {
        assert!(
            placeholder
                .iter()
                .all(|b| b.is_ascii_lowercase() || matches!(b, b'<' | b'>')),
            "placeholder {placeholder:?} is not [a-z<>]"
        );
        assert!(!placeholder.iter().any(u8::is_ascii_digit));
    }
}

#[test]
fn golden_mask_vectors() {
    for group in ALL {
        assert_goldens(group);
    }
}

fn has(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn rejected_forms_never_produce_their_placeholder() {
    for input in IP_REJECTED {
        assert!(!has(&mask(input), b"<ip>"), "input {input:?}");
    }
    for input in UUID_REJECTED {
        assert!(!has(&mask(input), b"<uuid>"), "input {input:?}");
    }
    for input in DUR_REJECTED {
        assert!(!has(&mask(input), b"<dur>"), "input {input:?}");
    }
    assert_eq!(mask(br"\u0031"), br"\u0031");
}

#[test]
fn escape_units_are_opaque_to_masks() {
    for (input, expect) in [
        (&br"\u0031 42"[..], &br"\u0031 <num>"[..]),
        (&br"42 \u0031"[..], &br"<num> \u0031"[..]),
        (&br"\u0031\u0032 5ms"[..], &br"\u0031\u0032 <dur>"[..]),
        (&br"a\\b 10.0.0.1"[..], &br"a\\b <ip>"[..]),
        (b"\\\" 2026-08-26T10:00:00Z", b"\\\" <ts>"),
        (b"a\\\\", b"a\\\\"),
        (&br"\u00"[..], &br"\u00"[..]),
    ] {
        assert_eq!(mask(input), *expect, "input {input:?}");
    }
}

#[test]
fn leftmost_longest_resolution() {
    for (input, expect) in [
        (&b"1.2.3.4.5"[..], &b"<ip>.<num>"[..]),
        (&b"2026-08-26T10:00:00.123456789+02:00"[..], &b"<ts>"[..]),
        (&b"5ms"[..], &b"<dur>"[..]),
        (&b"5m"[..], &b"<dur>"[..]),
        (&b"3.14"[..], &b"<num>"[..]),
        (&b"3."[..], &b"<num>."[..]),
        (&b"0123456789abcdef0123456789abcdef"[..], &b"<hex>"[..]),
    ] {
        assert_eq!(mask(input), *expect, "input {input:?}");
    }
}

#[test]
fn masking_is_idempotent_and_never_rematches_a_placeholder() {
    for group in ALL {
        for (input, expect) in *group {
            let once = mask(input);
            assert_eq!(&once, expect, "input {input:?}");
            assert_eq!(mask(&once), once, "input {input:?}");
        }
    }
    for placeholder in MASK_LIST.iter().map(|m| m.placeholder()) {
        assert_eq!(mask(placeholder), placeholder.to_vec());
    }
    let line = b"took 5<num> and <ts> at 1.2.3.4 for 12ms";
    let once = mask(line);
    assert_eq!(once, b"took <num><num> and <ts> at <ip> for <dur>");
    assert_eq!(mask(&once), once);
}

#[test]
fn ws_normalized_input_groups_near_duplicates() {
    let span = br"2026-08-26T10:00:00Z INFO hc 10.0.0.1 took 12ms\n2026-08-26T10:00:01Z INFO hc 10.0.0.2 took 13ms\n2026-08-26T10:00:02Z WARN hc 10.0.0.1 took 12ms";
    let mut forms = Vec::new();
    for line in quantification_core::stage1::split_span(span) {
        let ws = normalize(&span[line.range.clone()]);
        forms.push(mask(&ws));
    }
    assert_eq!(forms.len(), 3);
    assert_eq!(forms[0], b"<ts> INFO hc <ip> took <dur>");
    assert_eq!(forms[1], forms[0]);
    assert_ne!(forms[2], forms[0]);
    assert_eq!(forms[2], b"<ts> WARN hc <ip> took <dur>");
}

#[test]
fn mask_into_clears_its_output() {
    let mut out = Vec::new();
    mask_into(b"42", &mut out);
    assert_eq!(out, b"<num>");
    mask_into(b"", &mut out);
    assert!(out.is_empty());
    mask_into(br"a\tb", &mut out);
    assert_eq!(out, br"a\tb");
    mask_into(b"7", &mut out);
    assert_eq!(out, b"<num>");
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

const TOKENS: [&[u8]; 14] = [
    b"2026-08-26T10:00:00Z",
    b"Aug 26 10:00:01",
    b"10.0.0.1",
    b"fe80::1",
    b"123e4567-e89b-12d3-a456-426614174000",
    b"0123456789abcdef",
    b"12ms",
    b"42",
    b"1.5.3",
    b" ",
    b":",
    b"-",
    b"x",
    br"\u0031",
];

#[test]
fn property_generated_lines_mask_idempotently() {
    let known: Vec<Vec<u8>> = MASK_LIST.iter().map(|m| m.placeholder().to_vec()).collect();
    let mut rng = Rng(0x5eed_1234_abcd_0505);
    let mut placeholders = 0usize;
    for case in 0..400 {
        let mut line = Vec::new();
        while line.len() < 1 + rng.below(120) {
            line.extend_from_slice(TOKENS[rng.below(TOKENS.len())]);
        }
        let once = mask(&line);
        assert_eq!(mask(&once), once, "case {case}");
        let mut at = 0;
        while let Some(open) = once[at..].iter().position(|b| *b == b'<') {
            let start = at + open;
            let close = once[start..]
                .iter()
                .position(|b| *b == b'>')
                .map(|p| start + p + 1)
                .expect("unterminated placeholder");
            let found = &once[start..close];
            assert!(known.contains(&found.to_vec()), "case {case} {found:?}");
            placeholders += 1;
            at = close;
        }
    }
    assert!(placeholders > 0, "generator never produced a placeholder");
}
