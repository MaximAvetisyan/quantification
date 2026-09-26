#![no_main]
use libfuzzer_sys::fuzz_target;

use quantification_core::sniff::{sniff, Schema};

fuzz_target!(|data: &[u8]| {
    let body = data.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(data);
    let first = body
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
        .map(|at| body[at]);
    let schema = sniff(data);
    assert_eq!(schema, sniff(data), "sniff must be deterministic");
    match schema {
        Some(Schema::Text) => assert!(
            !matches!(first, Some(b'{' | b'[' | b'"')),
            "text must not be JSON-shaped: {first:?}"
        ),
        Some(_) => assert_eq!(first, Some(b'{'), "a JSON schema needs an object root"),
        None => assert!(
            matches!(first, None | Some(b'{' | b'[' | b'"')),
            "only JSON-shaped payloads may stay unknown"
        ),
    }
});
