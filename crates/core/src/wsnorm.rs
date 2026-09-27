use std::ops::Range;

use crate::fingerprint::fingerprint;
use crate::stage1::Unit;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Column {
    pub bytes: Vec<u8>,
    pub start: Vec<usize>,
    pub len: Vec<usize>,
    pub hash: Vec<u128>,
    pub span_bytes: usize,
}

impl Column {
    pub fn with_capacity(span_bytes: usize, unit_bytes: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(span_bytes),
            start: Vec::with_capacity(unit_bytes),
            len: Vec::with_capacity(unit_bytes),
            hash: Vec::with_capacity(unit_bytes),
            span_bytes: 0,
        }
    }

    pub fn reserved(&self) -> (usize, usize) {
        (self.bytes.capacity(), self.start.capacity())
    }

    pub fn build(&mut self, span: &[u8], units: &[Unit], line: &mut Vec<u8>) {
        self.bytes.clear();
        self.start.clear();
        self.len.clear();
        self.hash.clear();
        self.span_bytes = span.len();
        for unit in units {
            normalize_into(&span[unit.range.clone()], line);
            self.start.push(self.bytes.len());
            self.len.push(line.len());
            self.hash.push(fingerprint(line));
            self.bytes.extend_from_slice(line);
        }
    }

    pub fn len(&self) -> usize {
        self.start.len()
    }

    pub fn is_empty(&self) -> bool {
        self.start.is_empty()
    }

    pub fn range(&self, unit: usize) -> Range<usize> {
        self.start[unit]..self.start[unit] + self.len[unit]
    }

    pub fn get(&self, unit: usize) -> &[u8] {
        &self.bytes[self.range(unit)]
    }

    pub fn block(&self, start: usize, len: usize) -> &[u8] {
        &self.bytes[self.start[start]..self.start[start + len - 1] + self.len[start + len - 1]]
    }
}

pub fn normalize(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    normalize_into(raw, &mut out);
    out
}

pub fn normalize_into(raw: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(raw);
    let buf = out.as_mut_slice();
    let mut pending = false;
    let mut at = 0;
    let mut end = 0;
    while at < raw.len() {
        let start = at;
        at = plain_run(raw, at);
        if at > start {
            if pending {
                if end > 0 {
                    buf[end] = b' ';
                    end += 1;
                }
                pending = false;
            }
            if end < start {
                move_bytes(buf, end, start, at - start);
                end += at - start;
            } else {
                end = at;
            }
            continue;
        }
        let (len, collapse) = unit(raw, at);
        if collapse {
            pending = true;
        } else {
            if pending && end > 0 {
                buf[end] = b' ';
                end += 1;
            }
            pending = false;
            move_bytes(buf, end, at, len);
            end += len;
        }
        at += len;
    }
    out.truncate(end);
}

fn move_bytes(buf: &mut [u8], to: usize, from: usize, len: usize) {
    if len > 8 {
        buf.copy_within(from..from + len, to);
        return;
    }
    for at in 0..len {
        buf[to + at] = buf[from + at];
    }
}

pub fn next_byte(raw: &[u8], from: usize, byte: u8) -> usize {
    let mut at = from;
    while at + 8 <= raw.len() {
        let word = u64::from_le_bytes(raw[at..at + 8].try_into().expect("eight bytes"));
        let hits = has_byte(word, byte);
        if hits != 0 {
            return at + hits.trailing_zeros() as usize / 8;
        }
        at += 8;
    }
    while at < raw.len() && raw[at] != byte {
        at += 1;
    }
    at
}

fn plain_run(raw: &[u8], at: usize) -> usize {
    let mut at = at;
    while at + 8 <= raw.len() {
        let word = u64::from_le_bytes(raw[at..at + 8].try_into().expect("eight bytes"));
        let hits = has_byte(word, b'\\') | has_byte(word, b' ');
        if hits != 0 {
            return at + hits.trailing_zeros() as usize / 8;
        }
        at += 8;
    }
    while at < raw.len() && raw[at] != b'\\' && raw[at] != b' ' {
        at += 1;
    }
    at
}

const LOW: u64 = u64::from_ne_bytes([0x01; 8]);
const HIGH: u64 = u64::from_ne_bytes([0x80; 8]);

fn has_byte(word: u64, byte: u8) -> u64 {
    let spread = u64::from_ne_bytes([byte; 8]);
    let hits = word ^ spread;
    hits.wrapping_sub(LOW) & !hits & HIGH
}

fn unit(raw: &[u8], at: usize) -> (usize, bool) {
    if raw[at] != b'\\' || at + 1 >= raw.len() {
        return (1, raw[at] == b' ');
    }
    if raw[at + 1] == b'u' {
        return (6.min(raw.len() - at), false);
    }
    (2, matches!(raw[at + 1], b't' | b'n' | b'r'))
}
