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
        let (len, collapse) = unit(raw, at);
        if collapse {
            pending = true;
        } else {
            if pending && !out.is_empty() {
                out.push(b' ');
            }
            pending = false;
            out.extend_from_slice(&raw[at..at + len]);
        }
        at += len;
    }
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
