use std::path::Path;

use quantification_core::config::{JSON_DEPTH_CAP, MAX_SPAN_BYTES, ScopePolicy};
use quantification_core::locator::{NoopReason, Span, SpanClass, locate, locate_as, locate_into};
use quantification_core::sniff::Schema;

const BOTH: [ScopePolicy; 2] = [ScopePolicy::UserContent, ScopePolicy::UserAndTools];

fn fixture(rel: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn slice(payload: &[u8], span: &Span) -> String {
    String::from_utf8(payload[span.start..span.end].to_vec()).expect("span is utf-8")
}

fn classes(payload: &[u8], policy: ScopePolicy) -> Vec<(String, SpanClass)> {
    let located = locate(payload, policy);
    assert!(!located.degraded(), "{policy:?} degraded");
    located
        .spans
        .iter()
        .map(|span| (slice(payload, span), span.class))
        .collect()
}

fn spans_of(payload: &[u8], policy: ScopePolicy) -> Vec<String> {
    classes(payload, policy)
        .into_iter()
        .map(|(text, _)| text)
        .collect()
}

#[test]
fn every_w0_fixture_is_located_without_degradation() {
    for name in [
        "schemas/chat-minified.json",
        "schemas/chat-pretty.json",
        "schemas/messages-minified.json",
        "schemas/messages-pretty.json",
        "schemas/responses-minified.json",
        "schemas/responses-pretty.json",
        "schemas/text-plain.txt",
        "shapes/anthropic-system-top.json",
        "shapes/anthropic-tool-result.json",
        "shapes/chat-content-null.json",
        "shapes/chat-mixed-parts.json",
        "shapes/responses-function-call-output.json",
        "shapes/responses-input-string.json",
        "shapes/sniff-overlap-chat-responses.json",
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
        let payload = fixture(name);
        for policy in BOTH {
            let located = locate(&payload, policy);
            assert!(
                !located.degraded(),
                "{name} {policy:?}: {:?}",
                located.noop_reason
            );
            assert!(located.schema.is_some(), "{name} {policy:?}");
        }
    }
}

#[test]
fn schema_fixtures_locate_exactly_one_user_span() {
    for (name, first_line) in [
        (
            "schemas/chat-minified.json",
            "2026-08-25T10:00:01Z INFO hc 10.0.0.1 ok",
        ),
        (
            "schemas/chat-pretty.json",
            "2026-08-25T10:00:01Z INFO hc 10.0.0.1 ok",
        ),
        (
            "schemas/messages-minified.json",
            "2026-08-25T12:00:01Z INFO api 10.2.0.1 ok",
        ),
        (
            "schemas/messages-pretty.json",
            "2026-08-25T12:00:01Z INFO api 10.2.0.1 ok",
        ),
        (
            "schemas/responses-minified.json",
            "2026-08-25T11:00:01Z INFO db 10.1.0.1 ok",
        ),
        (
            "schemas/responses-pretty.json",
            "2026-08-25T11:00:01Z INFO db 10.1.0.1 ok",
        ),
        (
            "schemas/text-plain.txt",
            "2026-08-25T13:00:01Z INFO worker 10.3.0.1 ok",
        ),
    ] {
        let payload = fixture(name);
        let located = classes(&payload, ScopePolicy::UserContent);
        assert_eq!(located.len(), 1, "{name}");
        assert_eq!(located[0].1, SpanClass::User, "{name}");
        assert!(located[0].0.starts_with(first_line), "{name}");
    }
}

#[test]
fn shape_fixtures_locate_the_normative_eligible_spans() {
    let payload = fixture("shapes/anthropic-system-top.json");
    assert_eq!(
        spans_of(&payload, ScopePolicy::UserContent),
        vec![
            r"2026-08-25T17:00:01Z INFO usr 10.7.0.1 ok\n2026-08-25T17:00:02Z INFO usr 10.7.0.2 ok"
        ]
    );

    let payload = fixture("shapes/chat-mixed-parts.json");
    assert_eq!(
        spans_of(&payload, ScopePolicy::UserContent),
        vec![
            r"2026-08-25T14:00:01Z INFO mix 10.4.0.1 ok\n2026-08-25T14:00:02Z INFO mix 10.4.0.2 ok\n2026-08-25T14:00:03Z INFO mix 10.4.0.3 ok"
        ]
    );

    let payload = fixture("shapes/responses-input-string.json");
    assert_eq!(
        spans_of(&payload, ScopePolicy::UserContent),
        vec![
            r"2026-08-25T15:00:01Z GET /health 10.5.0.1 200\n2026-08-25T15:00:02Z GET /health 10.5.0.2 200\n2026-08-25T15:00:03Z GET /health 10.5.0.3 500\n2026-08-25T15:00:04Z GET /health 10.5.0.4 200"
        ]
    );

    let payload = fixture("shapes/chat-content-null.json");
    assert_eq!(
        spans_of(&payload, ScopePolicy::UserContent),
        Vec::<String>::new()
    );

    let payload = fixture("shapes/sniff-overlap-chat-responses.json");
    assert_eq!(
        spans_of(&payload, ScopePolicy::UserContent),
        vec![
            r"2026-08-25T18:00:01Z INFO chat 10.8.0.1 ok\n2026-08-25T18:00:02Z INFO chat 10.8.0.2 ok"
        ]
    );
}

#[test]
fn responses_function_call_output_is_tool_class() {
    let payload = fixture("shapes/responses-function-call-output.json");
    assert_eq!(
        classes(&payload, ScopePolicy::UserContent),
        vec![("summarize the rows".to_string(), SpanClass::User)]
    );
    assert_eq!(
        classes(&payload, ScopePolicy::UserAndTools),
        vec![
            (
                r#"{\"rows\":[{\"id\":1,\"st\":\"ok\"},{\"id\":2,\"st\":\"ok\"},{\"id\":3,\"st\":\"ok\"}]}"#.to_string(),
                SpanClass::Tool
            ),
            ("summarize the rows".to_string(), SpanClass::User),
        ]
    );
}

#[test]
fn anthropic_tool_result_is_tool_class_under_a_user_role() {
    let payload = fixture("shapes/anthropic-tool-result.json");
    assert_eq!(
        classes(&payload, ScopePolicy::UserContent),
        vec![("and summarize".to_string(), SpanClass::User)]
    );
    assert_eq!(
        classes(&payload, ScopePolicy::UserAndTools),
        vec![
            (
                r"2026-08-25T20:00:01Z INFO tool 10.10.0.1 ok\n2026-08-25T20:00:02Z INFO tool 10.10.0.2 ok".to_string(),
                SpanClass::Tool
            ),
            ("and summarize".to_string(), SpanClass::User),
        ]
    );
}

#[test]
fn tool_result_parts_are_tool_class_too() {
    let payload = br#"{"max_tokens":8,"messages":[{"role":"user","content":[{"type":"tool_result","content":[{"type":"text","text":"rows A"},{"type":"image","source":{}},{"type":"text","text":"rows B"}]}]}]}"#;
    assert_eq!(
        classes(payload, ScopePolicy::UserContent),
        Vec::<(String, SpanClass)>::new()
    );
    assert_eq!(
        classes(payload, ScopePolicy::UserAndTools),
        vec![
            ("rows A".to_string(), SpanClass::Tool),
            ("rows B".to_string(), SpanClass::Tool),
        ]
    );
}

#[test]
fn tool_result_content_string_is_never_rewritten_under_user_content() {
    let payload = br#"{"max_tokens":8,"messages":[{"role":"user","content":[{"type":"tool_result","content":"rows"}]}]}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserContent),
        Vec::<String>::new()
    );
    assert_eq!(
        classes(payload, ScopePolicy::UserAndTools),
        vec![("rows".to_string(), SpanClass::Tool)]
    );
}

#[test]
fn chat_tool_result_blocks_have_no_eligible_string() {
    let payload =
        br#"{"messages":[{"role":"user","content":[{"type":"tool_result","content":"rows"}]}]}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserAndTools),
        Vec::<String>::new()
    );
}

#[test]
fn edge_fixtures_locate_exactly_one_user_span() {
    for name in [
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
        let payload = fixture(name);
        let located = locate(&payload, ScopePolicy::UserContent);
        assert_eq!(located.spans.len(), 1, "{name}");
        assert_eq!(located.spans[0].class, SpanClass::User, "{name}");
        let text = slice(&payload, &located.spans[0]);
        assert!(!text.is_empty(), "{name}");
        assert!(!text.starts_with('"') && !text.ends_with('"'), "{name}");
    }
}

#[test]
fn duplicate_keys_are_last_occurrence_wins() {
    let payload = fixture("edges/dup-keys-last-wins.json");
    assert_eq!(
        spans_of(&payload, ScopePolicy::UserContent),
        vec![
            r"2026-08-25T21:00:01Z INFO dup 10.11.0.1 ok\n2026-08-25T21:00:02Z INFO dup 10.11.0.2 ok"
        ]
    );
    assert!(!payload.windows(9).any(|w| w == b"ignored"));
    assert!(!locate(&payload, ScopePolicy::UserContent).degraded());
}

#[test]
fn duplicate_keys_keep_the_last_value_of_every_key() {
    let payload = br#"{"messages":[{"role":"user","content":"a","content":"b"},{"role":"tool","role":"user","content":"c"}]}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserContent),
        vec!["b".to_string(), "c".to_string()]
    );
    let payload = br#"{"input":[{"type":"message","role":"user","content":"x","content":"y"}]}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserContent),
        vec!["y".to_string()]
    );
    let payload =
        br#"{"input":[{"type":"function_call_output","output":"a","call_id":"c","output":"b"}]}"#;
    assert_eq!(
        classes(payload, ScopePolicy::UserAndTools),
        vec![("b".to_string(), SpanClass::Tool)]
    );
}

#[test]
fn duplicate_nested_part_keys_keep_the_last_value() {
    let payload = br#"{"messages":[{"role":"user","content":[{"type":"image_url","type":"text","text":"keep"}]}]}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserContent),
        vec!["keep".to_string()]
    );
    let payload = br#"{"messages":[{"role":"user","content":[{"type":"text","text":"drop","text":"keep"}]}]}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserContent),
        vec!["keep".to_string()]
    );
}

const TOOL_RESULT_PARTS: &str =
    r#"[{"type":"tool_result","content":[{"type":"text","text":"INNER"}]}]"#;

fn anthropic_message(role: &str, members: &str) -> Vec<u8> {
    format!(r#"{{"max_tokens":8,"messages":[{{"role":"{role}",{members}}}]}}"#).into_bytes()
}

fn user_message(members: &str) -> Vec<u8> {
    anthropic_message("user", members)
}

#[test]
fn a_duplicate_key_drops_the_whole_shadowed_value_subtree() {
    for (later, want) in [
        (r#""LATER""#, vec!["LATER"]),
        ("null", vec![]),
        (r#"{"text":"LATER"}"#, vec![]),
        ("[]", vec![]),
        (r#"[{"type":"text","text":"LATER"}]"#, vec!["LATER"]),
        (r#"{"type":"text","text":"LATER"}"#, vec![]),
    ] {
        let payload = user_message(&format!(
            r#""content":{TOOL_RESULT_PARTS},"content":{later}"#
        ));
        let want: Vec<String> = want.iter().map(|s| (*s).to_string()).collect();
        for policy in BOTH {
            assert_eq!(spans_of(&payload, policy), want, "{later} {policy:?}");
        }
    }
}

#[test]
fn a_duplicate_chat_content_drops_the_shadowed_parts() {
    let payload = br#"{"messages":[{"role":"user","content":[{"type":"text","text":"INNER"}],"content":"LATER"}]}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserContent),
        vec!["LATER".to_string()]
    );
    let payload =
        br#"{"messages":[{"role":"user","content":[{"type":"text","text":"INNER"}],"content":[{"type":"text","text":"MID"}],"content":"LAST"}]}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserContent),
        vec!["LAST".to_string()]
    );
}

#[test]
fn a_duplicate_key_drops_the_shadowed_subtree_at_any_depth() {
    let payload = user_message(
        r#""content":[{"type":"tool_result","content":[{"type":"text","text":"X"}],"content":"LATER"}]"#,
    );
    assert_eq!(
        spans_of(&payload, ScopePolicy::UserContent),
        Vec::<String>::new()
    );
    assert_eq!(
        classes(&payload, ScopePolicy::UserAndTools),
        vec![("LATER".to_string(), SpanClass::Tool)]
    );
    let payload = user_message(
        r#""content":[{"type":"tool_result","content":[{"type":"text","text":"X"}]}],"content":[{"type":"text","text":"A","text":"B"}]"#,
    );
    for policy in BOTH {
        assert_eq!(
            spans_of(&payload, policy),
            vec!["B".to_string()],
            "{policy:?}"
        );
    }
}

#[test]
fn a_duplicate_key_keeps_the_spans_of_other_members_and_siblings() {
    let payload =
        br#"{"max_tokens":8,"messages":[{"role":"tool","content":"drop","content":"keep"}]}"#;
    assert_eq!(
        classes(payload, ScopePolicy::UserAndTools),
        vec![("keep".to_string(), SpanClass::Tool)]
    );
    let payload = br#"{"messages":[{"role":"user","content":[{"type":"text","text":"drop"}],"content":"later"},{"role":"user","content":"sibling"}]}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserContent),
        vec!["later".to_string(), "sibling".to_string()]
    );
    let payload = br#"{"messages":[{"role":"user","content":"first"},{"role":"user","content":[{"type":"text","text":"drop"}],"content":"later"}]}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserContent),
        vec!["first".to_string(), "later".to_string()]
    );
}

#[test]
fn an_assistant_duplicate_never_leaks_the_shadowed_tool_span() {
    let payload = anthropic_message(
        "assistant",
        &format!(r#""content":{TOOL_RESULT_PARTS},"content":"LATER""#),
    );
    for policy in BOTH {
        assert_eq!(
            spans_of(&payload, policy),
            Vec::<String>::new(),
            "{policy:?}"
        );
    }
    let payload = anthropic_message("assistant", &format!(r#""content":{TOOL_RESULT_PARTS}"#));
    assert_eq!(
        spans_of(&payload, ScopePolicy::UserContent),
        Vec::<String>::new()
    );
    assert_eq!(
        classes(&payload, ScopePolicy::UserAndTools),
        vec![("INNER".to_string(), SpanClass::Tool)]
    );
}

#[test]
fn duplicate_root_messages_keep_only_the_last_array() {
    let payload = br#"{"max_tokens":8,"messages":[{"role":"user","content":"A"}],"messages":[{"role":"user","content":"B"}]}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserContent),
        vec!["B".to_string()]
    );
    let payload = br#"{"max_tokens":8,"messages":[{"role":"user","content":[{"type":"tool_result","content":[{"type":"text","text":"INNER"}]}]}],"messages":[{"role":"user","content":"B"}]}"#;
    assert_eq!(
        classes(payload, ScopePolicy::UserAndTools),
        vec![("B".to_string(), SpanClass::User)]
    );
    let payload = br#"{"max_tokens":8,"messages":[{"role":"user","content":"A"}],"messages":"B"}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserContent),
        Vec::<String>::new()
    );
    let payload = br#"{"messages":[{"role":"user","content":"A"}],"x":{"messages":[{"role":"user","content":"B"}]},"messages":[{"role":"user","content":"C"}]}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserContent),
        vec!["C".to_string()]
    );
}

#[test]
fn duplicate_keys_never_mix_two_candidate_values() {
    let payload = br#"{"messages":[{"role":"user","content":[{"type":"text","text":"part"}],"content":"plain","content":[{"type":"text","text":"part2"}]}]}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserContent),
        vec!["part2".to_string()]
    );
    let payload = br#"{"input":"first","a":1,"input":"second"}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserContent),
        vec!["second".to_string()]
    );
}

#[test]
fn escaped_structural_keys_match_their_decoded_form() {
    let payload = fixture("edges/escaped-structural-keys.json");
    assert_eq!(
        spans_of(&payload, ScopePolicy::UserContent),
        vec![
            r"2026-08-25T22:00:01Z INFO esc 10.12.0.1 ok\n2026-08-25T22:00:02Z INFO esc 10.12.0.2 ok"
        ]
    );
    let payload = br#"{"messages":[{"\u0072ole":"user","\u0063ontent":"decoded"}]}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserContent),
        vec!["decoded".to_string()]
    );
    let payload = br#"{"\u006Dessages":[{"ro\u006Ce":"user","content":"ok"}]}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserContent),
        vec!["ok".to_string()]
    );
    let payload = br#"{"max_token\u0073":8,"messages":[{"role":"user","content":"ok"}]}"#;
    assert_eq!(
        locate(payload, ScopePolicy::UserContent).schema,
        Some(Schema::Messages)
    );
}

#[test]
fn string_values_stay_raw_escaped_bytes() {
    let payload = br#"{"messages":[{"role":"user","content":"a\\b\"c\td\u0041e"}]}"#;
    let spans = spans_of(payload, ScopePolicy::UserContent);
    assert_eq!(spans, vec![r#"a\\b\"c\td\u0041e"#.to_string()]);
    let at = find(payload, br#""content":""#).unwrap() + 11;
    assert_eq!(&payload[at..at + spans[0].len()], spans[0].as_bytes());
}

#[test]
fn bom_offsets_are_absolute_in_the_original_buffer() {
    let payload = fixture("edges/bom-chat.json");
    assert_eq!(&payload[..3], &[0xEF, 0xBB, 0xBF]);
    let located = locate(&payload, ScopePolicy::UserContent);
    assert_eq!(located.spans.len(), 1);
    let span = located.spans[0];
    let text = slice(&payload, &span);
    let post = &payload[3..];
    let expected = find(post, text.as_bytes()).expect("span bytes in the post-BOM buffer");
    assert_eq!(span.start, 3 + expected);
    assert!(span.start >= 3, "the BOM is never part of a span");
    assert_eq!(payload[span.start - 1], b'"');
    assert_eq!(payload[span.end], b'"');
}

#[test]
fn text_payloads_are_one_span_and_skip_the_bom() {
    let payload = b"\xEF\xBB\xBFplain text body";
    let located = locate(payload, ScopePolicy::UserContent);
    assert_eq!(located.schema, Some(Schema::Text));
    assert_eq!(located.spans.len(), 1);
    assert_eq!(located.spans[0].start, 3);
    assert_eq!(located.spans[0].end, payload.len());
    assert_eq!(located.spans[0].class, SpanClass::User);
    assert!(!locate(b"", ScopePolicy::UserContent).degraded());
    assert_eq!(locate(b"", ScopePolicy::UserContent).spans.len(), 0);
}

#[test]
fn scope_policy_selects_classes() {
    let payload = br#"{"messages":[{"role":"user","content":"u"},{"role":"tool","content":"t"},{"role":"assistant","content":"a"},{"role":"system","content":"s"}]}"#;
    assert_eq!(
        classes(payload, ScopePolicy::UserContent),
        vec![("u".to_string(), SpanClass::User)]
    );
    assert_eq!(
        classes(payload, ScopePolicy::UserAndTools),
        vec![
            ("u".to_string(), SpanClass::User),
            ("t".to_string(), SpanClass::Tool)
        ]
    );
}

#[test]
fn tool_role_parts_follow_the_owning_message_role() {
    let payload = br#"{"messages":[{"role":"tool","content":[{"type":"text","text":"t1"},{"type":"text","text":"t2"}]}]}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserContent),
        Vec::<String>::new()
    );
    assert_eq!(
        classes(payload, ScopePolicy::UserAndTools),
        vec![
            ("t1".to_string(), SpanClass::Tool),
            ("t2".to_string(), SpanClass::Tool)
        ]
    );
}

#[test]
fn role_matching_is_exact_and_case_sensitive() {
    for role in ["User", "USER", " users", "users", "User "] {
        let payload = format!(r#"{{"messages":[{{"role":"{role}","content":"x"}}]}}"#);
        assert_eq!(
            spans_of(payload.as_bytes(), ScopePolicy::UserAndTools),
            Vec::<String>::new(),
            "{role}"
        );
    }
    for role in ["Tool", "TOOL", " tool"] {
        let payload = format!(r#"{{"messages":[{{"role":"{role}","content":"x"}}]}}"#);
        assert_eq!(
            spans_of(payload.as_bytes(), ScopePolicy::UserAndTools),
            Vec::<String>::new(),
            "{role}"
        );
    }
    assert_eq!(
        spans_of(
            br#"{"messages":[{"content":"no role"}]}"#,
            ScopePolicy::UserAndTools
        ),
        Vec::<String>::new()
    );
    assert_eq!(
        spans_of(
            br#"{"messages":[{"role":7,"content":"numeric role"}]}"#,
            ScopePolicy::UserAndTools
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_message_without_role_is_never_eligible() {
    let payload = br#"{"messages":[{"content":"x"},{"role":"user","content":"y"}]}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserContent),
        vec!["y".to_string()]
    );
}

#[test]
fn system_spans_are_never_eligible() {
    let payload =
        br#"{"max_tokens":8,"system":"sys","messages":[{"role":"system","content":"s"}]}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserAndTools),
        Vec::<String>::new()
    );
    let payload = br#"{"system":[{"type":"text","text":"sys"}],"messages":[]}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserAndTools),
        Vec::<String>::new()
    );
}

#[test]
fn assistant_and_other_keys_never_contribute_spans() {
    let payload = br#"{"messages":[{"role":"assistant","content":"a","name":"n","tool_calls":[{"function":{"arguments":"{\"x\":1}"}}]}]}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserAndTools),
        Vec::<String>::new()
    );
}

#[test]
fn responses_input_string_is_user_class() {
    let payload = br#"{"input":"hello logs"}"#;
    assert_eq!(
        classes(payload, ScopePolicy::UserContent),
        vec![("hello logs".to_string(), SpanClass::User)]
    );
    assert_eq!(
        spans_of(br#"{"input":[]}"#, ScopePolicy::UserContent),
        Vec::<String>::new()
    );
}

#[test]
fn responses_message_items_follow_chat_rules() {
    let payload = br#"{"input":[{"type":"message","role":"user","content":"plain"},{"type":"message","role":"assistant","content":[{"type":"text","text":"skip"}]},{"type":"function_call","arguments":"{}"},{"type":"item_reference","ref":"r"}]}"#;
    assert_eq!(
        classes(payload, ScopePolicy::UserContent),
        vec![("plain".to_string(), SpanClass::User)]
    );
}

#[test]
fn function_call_output_output_is_tool_class_only() {
    let payload = br#"{"input":[{"type":"function_call_output","output":"rows"},{"type":"function_call_output","call_id":"c","output":"other"}]}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserContent),
        Vec::<String>::new()
    );
    assert_eq!(
        classes(payload, ScopePolicy::UserAndTools),
        vec![
            ("rows".to_string(), SpanClass::Tool),
            ("other".to_string(), SpanClass::Tool)
        ]
    );
    assert_eq!(
        spans_of(
            br#"{"input":[{"type":"function_call","output":"no"}]}"#,
            ScopePolicy::UserAndTools
        ),
        Vec::<String>::new()
    );
}

#[test]
fn function_call_output_role_does_not_reclassify() {
    let payload = br#"{"input":[{"type":"function_call_output","role":"user","output":"rows"}]}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserContent),
        Vec::<String>::new()
    );
    assert_eq!(
        classes(payload, ScopePolicy::UserAndTools),
        vec![("rows".to_string(), SpanClass::Tool)]
    );
}

#[test]
fn spans_are_ascending_disjoint_and_interior_to_the_buffer() {
    let payload = fixture("schemas/chat-pretty.json");
    let located = locate(&payload, ScopePolicy::UserContent);
    let mut last = 0usize;
    for span in &located.spans {
        assert!(span.start < span.end);
        assert!(span.start >= last);
        assert!(span.end <= payload.len());
        last = span.end;
    }
    assert_eq!(
        &payload[located.spans[0].start - 1..located.spans[0].start],
        b"\""
    );
    assert_eq!(
        &payload[located.spans[0].end..located.spans[0].end + 1],
        b"\""
    );
}

#[test]
fn many_messages_locate_in_byte_order() {
    let mut doc = String::from(r#"{"messages":["#);
    for i in 0..50 {
        if i > 0 {
            doc.push(',');
        }
        doc.push_str(&format!(r#"{{"role":"user","content":"line {i}"}}"#));
    }
    doc.push_str("]}");
    let located = locate(doc.as_bytes(), ScopePolicy::UserContent);
    assert_eq!(located.spans.len(), 50);
    for (i, span) in located.spans.iter().enumerate() {
        assert_eq!(slice(doc.as_bytes(), span), format!("line {i}"));
    }
}

#[test]
fn empty_string_values_produce_no_span() {
    let payload = br#"{"messages":[{"role":"user","content":""}]}"#;
    assert_eq!(
        spans_of(payload, ScopePolicy::UserContent),
        Vec::<String>::new()
    );
    assert!(!locate(payload, ScopePolicy::UserContent).degraded());
}

#[test]
fn oversized_spans_are_passed_through() {
    let over = vec![b'a'; MAX_SPAN_BYTES + 1];
    let mut doc = b"{\"messages\":[{\"role\":\"user\",\"content\":\"".to_vec();
    doc.extend_from_slice(&over);
    doc.extend_from_slice(b"\"}]}");
    let located = locate(&doc, ScopePolicy::UserContent);
    assert!(located.spans.is_empty());
    assert!(!located.degraded());
    assert_eq!(MAX_SPAN_BYTES, 33_554_432);
}

#[test]
fn the_span_cap_boundary_is_exact() {
    let mut doc = b"{\"messages\":[{\"role\":\"user\",\"content\":\"".to_vec();
    let at = doc.len();
    doc.extend_from_slice(&vec![b'a'; MAX_SPAN_BYTES]);
    doc.extend_from_slice(b"\"}]}");
    let located = locate(&doc, ScopePolicy::UserContent);
    assert_eq!(located.spans.len(), 1);
    assert_eq!(located.spans[0].start, at);
    assert_eq!(located.spans[0].end, at + MAX_SPAN_BYTES);
}

#[test]
fn oversized_text_spans_are_passed_through() {
    let over = vec![b'a'; MAX_SPAN_BYTES + 1];
    let located = locate(&over, ScopePolicy::UserContent);
    assert_eq!(located.schema, Some(Schema::Text));
    assert!(located.spans.is_empty());
    assert!(!located.degraded());
    let mut exact = vec![0xEF, 0xBB, 0xBF];
    exact.extend_from_slice(&vec![b'a'; MAX_SPAN_BYTES]);
    let located = locate(&exact, ScopePolicy::UserContent);
    assert_eq!(located.spans.len(), 1);
    assert_eq!(located.spans[0].start, 3);
    assert_eq!(located.spans[0].end, exact.len());
    assert!(!locate(b"", ScopePolicy::UserContent).degraded());
}

fn malformed(payload: &[u8]) {
    for policy in BOTH {
        for schema in [Schema::Chat, Schema::Responses, Schema::Messages] {
            let located = locate_as(payload, schema, policy);
            assert!(located.degraded(), "{payload:?} {schema:?} {policy:?}");
            assert_eq!(
                located.noop_reason,
                Some(NoopReason::Malformed),
                "{payload:?}"
            );
            assert!(located.spans.is_empty(), "partial span set for {payload:?}");
        }
    }
}

#[test]
fn malformed_documents_degrade_to_whole_request_pass_through() {
    for payload in [
        &b"{"[..],
        b"{\"messages\":[{\"role\":\"user\",\"content\":\"aaa\"}",
        b"{\"messages\":[{\"role\":\"user\",\"content\":\"aaa\"}]",
        b"{\"messages\":[{\"role\":\"user\",\"content\":\"aaa\"}]} trailing",
        b"{\"messages\":[{\"role\":\"user\",\"content\":\"aaa\"}]}{\"messages\":[{\"role\":\"user\",\"content\":\"bbb\"}]}",
        b"{\"messages\":[{\"role\":\"user\",\"content\":\"aaa\"}],",
        b"{\"messages\":[],}",
        b"{\"messages\":[,]}",
        b"{\"messages\":[1,]}",
        b"{'messages':[]}",
        b"{messages:[]}",
        b"{\"messages\":[{\"role\":\"user\",\"content\":5,}]}",
        b"{\"messages\":[{\"role\":\"user\",\"content\":\"aa\"}]} {",
        b"{\"messages\":[{\"role\":\"user\",\"content\":tru}]}",
        b"{\"messages\":[{\"role\":\"user\",\"content\":-}]}",
        b"{\"messages\":[{\"role\":\"user\",\"content\":\"unterminated}]}",
    ] {
        malformed(payload);
    }
}

#[test]
fn a_truncated_document_never_emits_a_partial_span_set() {
    let full =
        br#"{"messages":[{"role":"user","content":"kept?"},{"role":"tool","content":"tool"}]}"#;
    assert_eq!(spans_of(full, ScopePolicy::UserAndTools).len(), 2);
    for end in 1..full.len() {
        let truncated = &full[..end];
        let located = locate(truncated, ScopePolicy::UserAndTools);
        assert!(
            located.degraded(),
            "{end} {:?}",
            String::from_utf8_lossy(truncated)
        );
        assert!(located.spans.is_empty(), "{end} kept a partial span set");
    }
}

#[test]
fn raw_control_characters_are_rejected() {
    for raw in [
        &b"{\"messages\":[{\"role\":\"user\",\"content\":\"a\nb\"}]}"[..],
        &b"{\"messages\":[{\"role\":\"user\",\"content\":\"a\tb\"}]}"[..],
        &b"{\"messages\":[{\"role\":\"user\",\"content\":\"a\x00b\"}]}"[..],
        &b"{\"messages\":[{\"ro\nle\":\"user\",\"content\":\"x\"}]}"[..],
    ] {
        malformed(raw);
    }
    let ok = b"{\"messages\":[{\"role\":\"user\",\"content\":\"a\\nb\\tc\\u0009d\"}]}";
    assert_eq!(
        spans_of(ok, ScopePolicy::UserContent),
        vec![r"a\nb\tc\u0009d".to_string()]
    );
}

#[test]
fn depth_beyond_the_cap_degrades() {
    assert_eq!(JSON_DEPTH_CAP, 64);
    let at_cap = format!(
        "{}{}",
        "[".repeat(JSON_DEPTH_CAP),
        "]".repeat(JSON_DEPTH_CAP)
    );
    assert_eq!(
        locate_into(
            at_cap.as_bytes(),
            Schema::Chat,
            ScopePolicy::UserContent,
            &mut Vec::new()
        ),
        None
    );
    let over = format!(
        "{}{}",
        "[".repeat(JSON_DEPTH_CAP + 1),
        "]".repeat(JSON_DEPTH_CAP + 1)
    );
    malformed(over.as_bytes());
    let mixed = format!(
        r#"{{"messages":[{}{}]}}"#,
        "[".repeat(JSON_DEPTH_CAP),
        "]".repeat(JSON_DEPTH_CAP)
    );
    malformed(mixed.as_bytes());
}

#[test]
fn a_valid_document_without_eligible_spans_is_not_degraded() {
    for payload in [
        &b"{\"messages\":[]}"[..],
        &b"{\"messages\":\"not an array\"}"[..],
        b"{\"messages\":[{\"role\":\"assistant\",\"content\":\"a\"}]}",
        b"{\"input\":[]}",
        b"{\"input\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":\"a\"}]}",
        b"{\"max_tokens\":1,\"messages\":[{\"role\":\"system\",\"content\":\"a\"}]}",
    ] {
        let located = locate(payload, ScopePolicy::UserContent);
        assert!(!located.degraded(), "{payload:?}");
        assert!(located.spans.is_empty(), "{payload:?}");
    }
}

#[test]
fn unknown_schema_passes_through_with_a_noop_reason() {
    for payload in [&b"{}"[..], b"{\"foo\":\"bar\"}", b"[1,2,3]", b"\"scalar\""] {
        let located = locate(payload, ScopePolicy::UserContent);
        assert_eq!(located.schema, None, "{payload:?}");
        assert_eq!(
            located.noop_reason,
            Some(NoopReason::UnknownSchema),
            "{payload:?}"
        );
        assert!(located.spans.is_empty());
    }
    assert_eq!(NoopReason::Malformed.as_str(), "malformed");
    assert_eq!(NoopReason::UnknownSchema.as_str(), "unknown_schema");
}

#[test]
fn locate_into_reuses_the_callers_buffer() {
    let payload = br#"{"messages":[{"role":"user","content":"a"},{"role":"tool","content":"b"}]}"#;
    let mut out = vec![locate(payload, ScopePolicy::UserContent).spans[0]; 4];
    assert_eq!(
        locate_into(payload, Schema::Chat, ScopePolicy::UserAndTools, &mut out),
        None
    );
    assert_eq!(out.len(), 2);
    assert_eq!(out[1].class, SpanClass::Tool);
    assert_eq!(
        locate_into(b"{", Schema::Chat, ScopePolicy::UserContent, &mut out),
        Some(NoopReason::Malformed)
    );
    assert!(out.is_empty());
    assert_eq!(
        locate_into(payload, Schema::Text, ScopePolicy::UserContent, &mut out),
        None
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].end, payload.len());
}

#[test]
fn pinned_schema_ignores_the_sniff() {
    let payload = br#"{"max_tokens":8,"messages":[{"role":"user","content":"x"}]}"#;
    let pinned = locate_as(payload, Schema::Responses, ScopePolicy::UserContent);
    assert_eq!(pinned.spans.len(), 0);
    assert!(!pinned.degraded());
    let auto = locate(payload, ScopePolicy::UserContent);
    assert_eq!(auto.schema, Some(Schema::Messages));
    assert_eq!(auto.spans.len(), 1);
}

#[test]
fn deterministic_across_repeated_runs() {
    let payloads: Vec<Vec<u8>> = [
        "schemas/chat-pretty.json",
        "shapes/anthropic-tool-result.json",
        "shapes/responses-function-call-output.json",
        "edges/bom-chat.json",
    ]
    .iter()
    .map(|name| fixture(name))
    .collect();
    for payload in &payloads {
        for policy in BOTH {
            let first = locate(payload, policy);
            for _ in 0..8 {
                let again = locate(payload, policy);
                assert_eq!(again.spans.len(), first.spans.len());
                for (a, b) in again.spans.iter().zip(first.spans.iter()) {
                    assert_eq!((a.start, a.end, a.class), (b.start, b.end, b.class));
                }
            }
        }
    }
}
