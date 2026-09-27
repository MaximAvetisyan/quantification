use crate::config::MarkerStyle;
use crate::fingerprint::marker_checksum;
use crate::ledger::{CommitKind, decimal_width, framing, marker_len};

const HEX: &[u8; 16] = b"0123456789abcdef";

pub fn resolve_style(requested: MarkerStyle, span: &[u8]) -> MarkerStyle {
    match requested {
        MarkerStyle::Auto => {
            if span.is_ascii() {
                MarkerStyle::Ascii
            } else {
                MarkerStyle::Unicode
            }
        }
        forced => forced,
    }
}

pub fn render(style: MarkerStyle, kind: CommitKind, count: u64, anchor: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(marker_len(style, kind, count));
    render_into(&mut out, style, kind, count, anchor);
    out
}

pub fn render_into(
    out: &mut Vec<u8>,
    style: MarkerStyle,
    kind: CommitKind,
    count: u64,
    anchor: &[u8],
) {
    assert_ne!(
        style,
        MarkerStyle::Auto,
        "resolve Auto with resolve_style before rendering"
    );
    let start = out.len();
    let (open, sep, close) = framing(style);
    let (prefix, suffix) = kind.core(style);
    out.extend_from_slice(open.as_bytes());
    out.extend_from_slice(prefix.as_bytes());
    write_count(out, count);
    out.extend_from_slice(suffix.as_bytes());
    out.extend_from_slice(sep.as_bytes());
    write_checksum(out, marker_checksum(anchor));
    out.extend_from_slice(close.as_bytes());
    assert_eq!(out.len() - start, marker_len(style, kind, count));
}

fn write_count(out: &mut Vec<u8>, count: u64) {
    let mut buf = [0u8; 20];
    let mut at = buf.len();
    let mut rest = count;
    loop {
        at -= 1;
        buf[at] = b'0' + (rest % 10) as u8;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    debug_assert_eq!(buf.len() - at, decimal_width(count));
    out.extend_from_slice(&buf[at..]);
}

fn write_checksum(out: &mut Vec<u8>, checksum: u16) {
    out.extend_from_slice(&checksum_hex(checksum));
}

pub fn checksum_hex(checksum: u16) -> [u8; 4] {
    let mut out = [0; 4];
    for (at, shift) in [12, 8, 4, 0].into_iter().enumerate() {
        out[at] = HEX[(checksum >> shift) as usize & 0xf];
    }
    out
}
