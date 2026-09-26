use std::path::Path;

use quantification_core::sniff::{CANDIDATE_ORDER, SNIFF_PREFIX_BYTES, Schema, sniff};

fn fixture(rel: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

const SCHEMAS: [(&str, Schema); 7] = [
    ("schemas/chat-minified.json", Schema::Chat),
    ("schemas/chat-pretty.json", Schema::Chat),
    ("schemas/messages-minified.json", Schema::Messages),
    ("schemas/messages-pretty.json", Schema::Messages),
    ("schemas/responses-minified.json", Schema::Responses),
    ("schemas/responses-pretty.json", Schema::Responses),
    ("schemas/text-plain.txt", Schema::Text),
];

#[test]
fn every_schema_fixture_sniffs_to_its_schema() {
    for (name, want) in SCHEMAS {
        assert_eq!(sniff(&fixture(name)), Some(want), "{name}");
    }
}

#[test]
fn shape_fixtures_sniff_to_their_schema() {
    for (name, want) in [
        ("shapes/anthropic-system-top.json", Schema::Messages),
        ("shapes/anthropic-tool-result.json", Schema::Messages),
        ("shapes/chat-content-null.json", Schema::Chat),
        ("shapes/chat-mixed-parts.json", Schema::Chat),
        (
            "shapes/responses-function-call-output.json",
            Schema::Responses,
        ),
        ("shapes/responses-input-string.json", Schema::Responses),
    ] {
        assert_eq!(sniff(&fixture(name)), Some(want), "{name}");
    }
}

#[test]
fn edge_fixtures_sniff_to_their_schema() {
    for name in [
        "edges/bom-chat.json",
        "edges/dup-keys-last-wins.json",
        "edges/escaped-structural-keys.json",
        "edges/newlines-u000a-only.json",
        "edges/prior-markers.json",
        "edges/profitability-below-threshold.json",
        "edges/single-line-tool-dump-small.json",
        "edges/single-line-tool-dump-overcap.json",
        "edges/stage1b-no-separator-overcap.json",
        "edges/stage1b-record-len-16383.json",
        "edges/stage1b-record-len-16384.json",
        "edges/stage1b-record-len-16385.json",
    ] {
        assert_eq!(sniff(&fixture(name)), Some(Schema::Chat), "{name}");
    }
}

#[test]
fn chat_wins_the_messages_input_overlap() {
    let payload = fixture("shapes/sniff-overlap-chat-responses.json");
    assert_eq!(sniff(&payload), Some(Schema::Chat));
    assert!(find(&payload, b"\"messages\"").is_some());
    assert!(find(&payload, b"\"input\"").is_some());
}

#[test]
fn candidate_order_is_the_documented_fixed_order() {
    assert_eq!(
        CANDIDATE_ORDER,
        [
            Schema::Chat,
            Schema::Responses,
            Schema::Messages,
            Schema::Text
        ]
    );
}

#[test]
fn anthropic_markers_move_messages_ahead_of_chat() {
    assert_eq!(sniff(br#"{"messages":[]}"#), Some(Schema::Chat));
    assert_eq!(
        sniff(br#"{"messages":[],"max_tokens":1}"#),
        Some(Schema::Messages)
    );
    assert_eq!(
        sniff(br#"{"messages":[],"system":"s"}"#),
        Some(Schema::Messages)
    );
    assert_eq!(
        sniff(br#"{"messages":[],"max_tokens":null}"#),
        Some(Schema::Messages)
    );
}

#[test]
fn responses_needs_input_and_the_absence_of_messages() {
    assert_eq!(sniff(br#"{"input":[]}"#), Some(Schema::Responses));
    assert_eq!(sniff(br#"{"input":"x"}"#), Some(Schema::Responses));
    assert_eq!(sniff(br#"{"input":[],"messages":[]}"#), Some(Schema::Chat));
    assert_eq!(
        sniff(br#"{"input":[],"max_tokens":1}"#),
        Some(Schema::Responses)
    );
}

#[test]
fn nested_keys_never_look_like_root_keys() {
    assert_eq!(sniff(br#"{"a":{"messages":[]}}"#), None);
    assert_eq!(sniff(br#"{"a":[{"messages":[]}]}"#), None);
    assert_eq!(sniff(br#"{"text":"messages"}"#), None);
}

#[test]
fn escaped_root_keys_are_decoded_before_matching() {
    assert_eq!(sniff(br#"{"messages":[]}"#), Some(Schema::Chat));
    assert_eq!(sniff(br#"{"\u006Dessages":[]}"#), Some(Schema::Chat));
    assert_eq!(
        sniff(br#"{"messages":[],"max_tokens":1}"#),
        Some(Schema::Messages)
    );
    assert_eq!(
        sniff(br#"{"max_tokens":1,"messages":[]}"#),
        Some(Schema::Messages)
    );
    assert_eq!(sniff(br#"{"meessages":[]}"#), None);
    assert_eq!(sniff(br#"{"messages ":[]}"#), None);
}

#[test]
fn key_bytes_lookalike_inside_strings_do_not_decide_the_schema() {
    assert_eq!(sniff(br#"{"model":"messages","max_tokens":1}"#), None);
    assert_eq!(sniff(br#"{"a":"messages","b":"max_tokens"}"#), None);
}

#[test]
fn a_truncated_document_still_sniffs_and_is_left_to_the_locator() {
    assert_eq!(sniff(b"{\"messages\":"), Some(Schema::Chat));
    assert_eq!(
        sniff(b"{\"model\":\"gpt-4o\",\"messages\":[{\"role\":\"user\""),
        Some(Schema::Chat)
    );
}

#[test]
fn a_json_schema_needs_an_object_root() {
    assert_eq!(sniff(b"[]"), None);
    assert_eq!(sniff(b"\"messages\":[]"), None);
    assert_eq!(sniff(b"junk{\"messages\":[]}"), Some(Schema::Text));
    assert_eq!(
        sniff(b"\xEF\xBB\xBF\xEF\xBB\xBF{\"messages\":[]}"),
        Some(Schema::Text)
    );
    assert_eq!(sniff(b"\n  {\"messages\":[]}"), Some(Schema::Chat));
}

#[test]
fn json_shaped_payloads_without_known_keys_are_unknown() {
    for payload in [
        &b"{}"[..],
        b"{\"foo\":[1,2,3]}",
        b"[{\"role\":\"user\",\"content\":\"x\"}]",
        br#""just a string""#,
    ] {
        assert_eq!(sniff(payload), None, "{payload:?}");
    }
}

#[test]
fn text_is_the_last_resort_and_bom_is_skipped() {
    assert_eq!(sniff(b"2026-08-25T13:00:01Z INFO ok"), Some(Schema::Text));
    assert_eq!(sniff(b"  \n\tplain text"), Some(Schema::Text));
    assert_eq!(sniff(b""), Some(Schema::Text));
    assert_eq!(sniff(b"\xEF\xBB\xBFplain text"), Some(Schema::Text));
    assert_eq!(
        sniff(b"\xEF\xBB\xBF{\"messages\":[{\"role\":\"user\",\"content\":\"x\"}]}"),
        Some(Schema::Chat)
    );
    assert_eq!(sniff(b"\xEF\xBB"), Some(Schema::Text));
}

#[test]
fn the_prefix_is_bounded() {
    assert_eq!(SNIFF_PREFIX_BYTES, 65_536);
    let mut payload = b"{".to_vec();
    payload.extend(std::iter::repeat_n(b' ', SNIFF_PREFIX_BYTES));
    payload.extend_from_slice(br#""messages":[]}"#);
    assert_eq!(sniff(&payload), None);
    let mut inside = b"{".to_vec();
    inside.extend(std::iter::repeat_n(b' ', SNIFF_PREFIX_BYTES - 12));
    inside.extend_from_slice(br#""messages":[]}"#);
    assert_eq!(sniff(&inside), Some(Schema::Chat));
}

#[test]
fn sniff_is_deterministic_and_never_panics_on_truncation() {
    let full = fixture("schemas/chat-pretty.json");
    for end in 0..=full.len() {
        let _ = sniff(&full[..end]);
    }
    assert_eq!(sniff(&full), sniff(&full));
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
