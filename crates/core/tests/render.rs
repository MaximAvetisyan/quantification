use quantification_core::config::MarkerStyle;
use quantification_core::fingerprint::marker_checksum;
use quantification_core::ledger::{CommitKind, decimal_width, framing, marker_len};
use quantification_core::render::{render, render_into, resolve_style};
use quantification_core::wsnorm::normalize;

const UNICODE: MarkerStyle = MarkerStyle::Unicode;
const ASCII: MarkerStyle = MarkerStyle::Ascii;
const KINDS: [CommitKind; 5] = [
    CommitKind::ExactRun,
    CommitKind::WsRun,
    CommitKind::Block,
    CommitKind::TemplateGroup,
    CommitKind::TemplatedBlock,
];
const ANCHOR: &[u8] = b"2026-08-26T10:00:00Z INFO hc 10.0.0.1 ok";
const COUNTS: [u64; 9] = [0, 1, 9, 10, 99, 100, 199, 1000, 12_345];

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("markers are valid utf-8")
}

#[test]
fn every_kind_and_style_is_pinned() {
    let expect = [
        (
            UNICODE,
            CommitKind::ExactRun,
            "\u{27ea}\u{d7}200 identical \u{b7}0751\u{27eb}",
        ),
        (
            UNICODE,
            CommitKind::WsRun,
            "\u{27ea}\u{d7}200 rows, ws-equal \u{b7}0751\u{27eb}",
        ),
        (
            UNICODE,
            CommitKind::Block,
            "\u{27ea}block \u{d7}200 \u{b7}0751\u{27eb}",
        ),
        (
            UNICODE,
            CommitKind::TemplateGroup,
            "\u{27ea}\u{d7}200 rows, template \u{b7}0751\u{27eb}",
        ),
        (
            UNICODE,
            CommitKind::TemplatedBlock,
            "\u{27ea}templated block \u{d7}200 \u{b7}0751\u{27eb}",
        ),
        (ASCII, CommitKind::ExactRun, "[... x200 identical 0751 ...]"),
        (
            ASCII,
            CommitKind::WsRun,
            "[... x200 rows, ws-equal 0751 ...]",
        ),
        (ASCII, CommitKind::Block, "[... block x200 0751 ...]"),
        (
            ASCII,
            CommitKind::TemplateGroup,
            "[... x200 rows, template 0751 ...]",
        ),
        (
            ASCII,
            CommitKind::TemplatedBlock,
            "[... templated block x200 0751 ...]",
        ),
    ];
    assert_eq!(expect.len(), KINDS.len() * 2);
    for (style, kind, want) in expect {
        assert_eq!(
            text(&render(style, kind, 200, ANCHOR)),
            want,
            "{style:?} {kind:?}"
        );
    }
}

#[test]
fn rendered_length_equals_marker_len() {
    for style in [UNICODE, ASCII] {
        for kind in KINDS {
            for count in COUNTS {
                let marker = render(style, kind, count, ANCHOR);
                assert_eq!(marker.len(), marker_len(style, kind, count), "{count}");
                assert_eq!(
                    marker.len(),
                    framing(style).0.len()
                        + framing(style).2.len()
                        + kind.core(style).0.len()
                        + kind.core(style).1.len()
                        + framing(style).1.len()
                        + 4
                        + decimal_width(count)
                );
            }
        }
    }
}

#[test]
fn checksum_is_the_low_four_hex_of_the_raw_anchor_bytes() {
    for (anchor, want) in [
        (ANCHOR, "0751"),
        (b"", "94c2"),
        (b"a", "4e1f"),
        (b"a  b", "a753"),
        (b"a b", "2c4c"),
        (b"line one\\n", "b0d7"),
        ("caf\u{e9} \\\\u0041".as_bytes(), "9ac6"),
    ] {
        assert_eq!(
            format!("{:04x}", marker_checksum(anchor)),
            want,
            "{anchor:?}"
        );
        let marker = text(&render(UNICODE, CommitKind::ExactRun, 3, anchor));
        assert!(
            marker.ends_with(&format!(" \u{b7}{want}\u{27eb}")),
            "{anchor:?} => {marker}"
        );
        assert_eq!(
            marker.len(),
            render(UNICODE, CommitKind::ExactRun, 3, b"").len()
        );
    }
}

#[test]
fn a_ws_equal_anchor_hashes_its_own_bytes_not_the_normalized_form() {
    let padded = text(&render(ASCII, CommitKind::WsRun, 7, b"a  b"));
    let single = text(&render(ASCII, CommitKind::WsRun, 7, b"a b"));
    assert_eq!(normalize(b"a  b"), normalize(b"a b"));
    assert_ne!(padded, single);
    assert!(padded.contains("a753"));
    assert!(single.contains("2c4c"));
}

#[test]
fn counts_render_as_plain_decimal() {
    for (count, want) in [
        (1u64, "1"),
        (9, "9"),
        (10, "10"),
        (199, "199"),
        (12_345, "12345"),
        (u64::MAX, "18446744073709551615"),
    ] {
        let marker = text(&render(UNICODE, CommitKind::ExactRun, count, ANCHOR));
        assert_eq!(
            marker,
            format!("\u{27ea}\u{d7}{want} identical \u{b7}0751\u{27eb}")
        );
        assert_eq!(want.len(), decimal_width(count));
    }
}

#[test]
fn auto_resolves_to_ascii_only_for_an_all_ascii_span() {
    for span in [&b""[..], &b"plain"[..], b"\\u0041 \\n", &b"ascii only"[..]] {
        assert_eq!(resolve_style(MarkerStyle::Auto, span), ASCII, "{span:?}");
    }
    for span in [
        "caf\u{e9}".as_bytes(),
        b"mixed \xc3\xa9",
        "\u{27ea} marker text".as_bytes(),
    ] {
        assert_eq!(resolve_style(MarkerStyle::Auto, span), UNICODE, "{span:?}");
    }
}

#[test]
fn a_forced_style_ignores_the_span_bytes() {
    for span in [&b"plain"[..], "caf\u{e9}".as_bytes()] {
        assert_eq!(resolve_style(ASCII, span), ASCII);
        assert_eq!(resolve_style(UNICODE, span), UNICODE);
    }
}

#[test]
fn markers_are_valid_in_any_json_string() {
    for style in [UNICODE, ASCII] {
        for kind in KINDS {
            for count in COUNTS {
                let marker = render(style, kind, count, ANCHOR);
                assert!(std::str::from_utf8(&marker).is_ok());
                for &byte in &marker {
                    assert_ne!(byte, b'"', "{style:?} {kind:?}");
                    assert_ne!(byte, b'\\', "{style:?} {kind:?}");
                    assert!(byte >= 0x20, "{style:?} {kind:?} control byte");
                }
                let mut interior = Vec::new();
                interior.extend_from_slice(br"\u0041");
                interior.extend_from_slice(&marker);
                interior.extend_from_slice(br"\u0041");
                assert_eq!(interior.iter().filter(|&&b| b == b'\\').count(), 2);
                assert_eq!(&interior[6..6 + marker.len()], &marker[..]);
            }
        }
    }
}

#[test]
fn render_into_appends_without_disturbing_the_prefix() {
    let mut out = b"pre:".to_vec();
    render_into(&mut out, ASCII, CommitKind::Block, 12, ANCHOR);
    assert_eq!(&out[..4], b"pre:");
    let expected = render(ASCII, CommitKind::Block, 12, ANCHOR);
    assert_eq!(&out[4..], &expected[..]);
    let second = render(UNICODE, CommitKind::WsRun, 1, b"x");
    render_into(&mut out, UNICODE, CommitKind::WsRun, 1, b"x");
    assert_eq!(
        text(&out),
        format!("pre:{}{}", text(&expected), text(&second))
    );
    assert_eq!(out.len(), 4 + expected.len() + second.len());
}

#[test]
#[should_panic(expected = "resolve Auto with resolve_style before rendering")]
fn auto_is_refused_by_the_renderer() {
    let _ = render(MarkerStyle::Auto, CommitKind::ExactRun, 1, ANCHOR);
}

fn uses_token(source: &str, banned: &str) -> bool {
    source
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|word| word == banned)
}

#[test]
fn render_path_has_no_forbidden_determinism_inputs() {
    let source = include_str!("../src/render.rs");
    let uses = |banned: &str| uses_token(source, banned);
    assert!(
        uses_token("fn f() { rand(); }", "rand"),
        "a real use is seen"
    );
    assert!(
        uses_token("fn f() { std::env::var(\"X\"); }", "env"),
        "a real use is seen"
    );
    assert!(
        !uses_token("let brand = 1;", "rand"),
        "the scan is not a substring match"
    );
    assert!(
        !uses_token("fn f() { let brand = 1; }", "rand"),
        "the scan is not a substring match"
    );
    for banned in [
        "HashMap",
        "RandomState",
        "BTreeMap",
        "SystemTime",
        "Instant",
        "env",
        "random",
        "f32",
        "f64",
        "format",
    ] {
        assert!(!uses(banned), "{banned} in the renderer");
    }
}
