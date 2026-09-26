#![no_main]
use libfuzzer_sys::fuzz_target;

use quantification_core::config::{RawOptions, resolve};
use quantification_core::ledger::{Commit, marker_len};
use quantification_core::pipeline::Compressor;

const UNICODE_OPEN: &[u8] = "\u{27ea}".as_bytes();
const ASCII_OPEN: &[u8] = b"[... ";

fuzz_target!(|data: &[u8]| {
    let options = resolve(&RawOptions::default()).expect("the default options resolve");
    let mut compressor = Compressor::new();
    let mut out = Vec::new();
    compressor.compress(data, &options, &mut out);
    let commits = compressor.commits().to_vec();
    check_spliced(data, &out, &commits);
    if commits.is_empty() {
        assert_eq!(
            out, data,
            "a payload with no commits is a byte-for-byte pass-through"
        );
    }
    if json(data) {
        assert!(json(&out), "the output must parse when the input does");
    }

    let mut twice = Vec::new();
    compressor.compress(&out, &options, &mut twice);
    let mut thrice = Vec::new();
    compressor.compress(&twice, &options, &mut thrice);
    assert_eq!(
        thrice, twice,
        "recompression must reach a fixed point within two passes"
    );
    assert!(
        twice.len() <= out.len(),
        "a recompression must never grow the payload"
    );
});

fn check_spliced(input: &[u8], out: &[u8], commits: &[Commit]) {
    let mut cursor = 0;
    let mut read = 0;
    for commit in commits {
        assert!(
            commit.removed.start >= read && commit.removed.end <= input.len(),
            "commit ranges must ascend, stay disjoint and stay in bounds"
        );
        assert!(
            commit.removed.start <= commit.anchor.start && commit.anchor.end <= commit.removed.end,
            "the anchor is a sub-range of the range it replaces"
        );
        let copied = commit.removed.start - read;
        assert_eq!(
            &out[cursor..cursor + copied],
            &input[read..commit.removed.start],
            "the bytes before a patched range are copied verbatim"
        );
        cursor += copied;
        let anchor = &input[commit.anchor.clone()];
        assert_eq!(&out[cursor..cursor + anchor.len()], anchor);
        cursor += anchor.len();
        let rest = &out[cursor..];
        assert!(
            rest.starts_with(ASCII_OPEN) || rest.starts_with(UNICODE_OPEN),
            "a marker must follow every anchor"
        );
        let len = marker_len(commit.style, commit.kind, commit.count);
        assert!(rest.len() >= len, "the marker must fit");
        let marker = &rest[..len];
        assert!(
            std::str::from_utf8(marker).is_ok()
                && !marker
                    .iter()
                    .any(|byte| matches!(byte, b'"' | b'\\' | 0..=0x1F | 0x7F)),
            "a marker is valid utf-8 with no quote, backslash or control byte: {:?}",
            String::from_utf8_lossy(marker)
        );
        cursor += len;
        read = commit.removed.end;
    }
    let tail = input.len() - read;
    assert_eq!(&out[cursor..cursor + tail], &input[read..]);
    assert_eq!(cursor + tail, out.len());
}

fn json(bytes: &[u8]) -> bool {
    let body = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    let mut at = 0;
    let mut depth = 0;
    value(body, &mut at, &mut depth) && ws(body, &mut at) && at == body.len()
}

fn ws(bytes: &[u8], at: &mut usize) -> bool {
    while matches!(bytes.get(*at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        *at += 1;
    }
    true
}

fn value(bytes: &[u8], at: &mut usize, depth: &mut usize) -> bool {
    if *depth >= 64 {
        return false;
    }
    *depth += 1;
    ws(bytes, at);
    let ok = match bytes.get(*at) {
        Some(b'{') => object(bytes, at, depth),
        Some(b'[') => array(bytes, at, depth),
        Some(b'"') => string(bytes, at),
        Some(b't') => keyword(bytes, at, "true"),
        Some(b'f') => keyword(bytes, at, "false"),
        Some(b'n') => keyword(bytes, at, "null"),
        Some(b'-' | b'0'..=b'9') => number(bytes, at),
        _ => false,
    };
    *depth -= 1;
    ok
}

fn keyword(bytes: &[u8], at: &mut usize, word: &str) -> bool {
    let end = *at + word.len();
    if bytes.get(*at..end) == Some(word.as_bytes()) {
        *at = end;
        return true;
    }
    false
}

fn number(bytes: &[u8], at: &mut usize) -> bool {
    if bytes.get(*at) == Some(&b'-') {
        *at += 1;
    }
    if !digits(bytes, at) {
        return false;
    }
    if bytes.get(*at) == Some(&b'.') {
        *at += 1;
        if !digits(bytes, at) {
            return false;
        }
    }
    if matches!(bytes.get(*at), Some(b'e' | b'E')) {
        *at += 1;
        if matches!(bytes.get(*at), Some(b'+' | b'-')) {
            *at += 1;
        }
        if !digits(bytes, at) {
            return false;
        }
    }
    true
}

fn digits(bytes: &[u8], at: &mut usize) -> bool {
    let start = *at;
    while matches!(bytes.get(*at), Some(b'0'..=b'9')) {
        *at += 1;
    }
    *at > start
}

fn string(bytes: &[u8], at: &mut usize) -> bool {
    if bytes.get(*at) != Some(&b'"') {
        return false;
    }
    *at += 1;
    loop {
        match bytes.get(*at) {
            None => return false,
            Some(b'"') => {
                *at += 1;
                return true;
            }
            Some(b'\\') => {
                *at += 1;
                match bytes.get(*at) {
                    Some(b'u') => {
                        if bytes
                            .get(*at + 1..*at + 5)
                            .is_none_or(|hex| !hex.iter().all(u8::is_ascii_hexdigit))
                        {
                            return false;
                        }
                        *at += 5;
                    }
                    Some(escape)
                        if escape.is_ascii_alphabetic()
                            || matches!(escape, b'\\' | b'/' | b'"') =>
                    {
                        *at += 1;
                    }
                    _ => return false,
                }
            }
            Some(0..=0x1F) => return false,
            Some(_) => *at += 1,
        }
    }
}

fn object(bytes: &[u8], at: &mut usize, depth: &mut usize) -> bool {
    *at += 1;
    ws(bytes, at);
    if bytes.get(*at) == Some(&b'}') {
        *at += 1;
        return true;
    }
    loop {
        ws(bytes, at);
        if !string(bytes, at) {
            return false;
        }
        ws(bytes, at);
        if bytes.get(*at) != Some(&b':') {
            return false;
        }
        *at += 1;
        if !value(bytes, at, depth) {
            return false;
        }
        ws(bytes, at);
        match bytes.get(*at) {
            Some(b',') => *at += 1,
            Some(b'}') => {
                *at += 1;
                return true;
            }
            _ => return false,
        }
    }
}

fn array(bytes: &[u8], at: &mut usize, depth: &mut usize) -> bool {
    *at += 1;
    ws(bytes, at);
    if bytes.get(*at) == Some(&b']') {
        *at += 1;
        return true;
    }
    loop {
        if !value(bytes, at, depth) {
            return false;
        }
        ws(bytes, at);
        match bytes.get(*at) {
            Some(b',') => *at += 1,
            Some(b']') => {
                *at += 1;
                return true;
            }
            _ => return false,
        }
    }
}
