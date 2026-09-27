pub fn normalize(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    normalize_into(raw, &mut out);
    out
}

pub fn normalize_into(raw: &[u8], out: &mut Vec<u8>) {
    out.clear();
    let mut pending = false;
    let mut at = 0;
    while at < raw.len() {
        let start = at;
        at = plain_run(raw, at);
        if at > start {
            if pending {
                if !out.is_empty() {
                    out.push(b' ');
                }
                pending = false;
            }
            push(out, &raw[start..at]);
            continue;
        }
        let (len, collapse) = unit(raw, at);
        if collapse {
            pending = true;
        } else {
            if pending && !out.is_empty() {
                out.push(b' ');
            }
            pending = false;
            push(out, &raw[at..at + len]);
        }
        at += len;
    }
}

fn push(out: &mut Vec<u8>, bytes: &[u8]) {
    if bytes.len() > 8 {
        out.extend_from_slice(bytes);
        return;
    }
    for &byte in bytes {
        out.push(byte);
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
