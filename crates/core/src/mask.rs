pub const HEX_MIN_RUN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mask {
    Ts,
    Ip,
    Uuid,
    Hex,
    Dur,
    Num,
}

pub const MASK_LIST: [Mask; 6] = [
    Mask::Ts,
    Mask::Ip,
    Mask::Uuid,
    Mask::Hex,
    Mask::Dur,
    Mask::Num,
];

impl Mask {
    pub fn placeholder(self) -> &'static [u8] {
        match self {
            Self::Ts => b"<ts>",
            Self::Ip => b"<ip>",
            Self::Uuid => b"<uuid>",
            Self::Hex => b"<hex>",
            Self::Dur => b"<dur>",
            Self::Num => b"<num>",
        }
    }

    fn at(self, line: &[u8], at: usize) -> Option<usize> {
        match self {
            Self::Ts => ts_at(line, at),
            Self::Ip => ip_at(line, at),
            Self::Uuid => uuid_at(line, at),
            Self::Hex => hex_at(line, at),
            Self::Dur => dur_at(line, at),
            Self::Num => num_at(line, at),
        }
    }
}

pub fn mask(ws_line: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ws_line.len());
    mask_into(ws_line, &mut out);
    out
}

pub fn mask_into(ws_line: &[u8], out: &mut Vec<u8>) {
    out.clear();
    let mut at = 0;
    while at < ws_line.len() {
        if let Some(len) = escape_unit(ws_line, at) {
            out.extend_from_slice(&ws_line[at..at + len]);
            at += len;
        } else if let Some((found, len)) = hit(ws_line, at) {
            out.extend_from_slice(found.placeholder());
            at += len;
        } else {
            out.push(ws_line[at]);
            at += 1;
        }
    }
}

fn hit(line: &[u8], at: usize) -> Option<(Mask, usize)> {
    MASK_LIST
        .iter()
        .find_map(|mask| mask.at(line, at).map(|len| (*mask, len)))
}

fn escape_unit(line: &[u8], at: usize) -> Option<usize> {
    if line[at] != b'\\' || at + 1 >= line.len() {
        return None;
    }
    Some(if line[at + 1] == b'u' {
        6.min(line.len() - at)
    } else {
        2
    })
}

fn digits(line: &[u8], at: usize) -> usize {
    let mut run = 0;
    while line.get(at + run).is_some_and(u8::is_ascii_digit) {
        run += 1;
    }
    run
}

fn hex_run(line: &[u8], at: usize) -> usize {
    let mut run = 0;
    while line.get(at + run).is_some_and(u8::is_ascii_hexdigit) {
        run += 1;
    }
    run
}

fn take(line: &[u8], at: usize, byte: u8) -> Option<usize> {
    (line.get(at) == Some(&byte)).then_some(1)
}

fn spaces(line: &[u8], at: usize) -> usize {
    let mut run = 0;
    while line.get(at + run) == Some(&b' ') {
        run += 1;
    }
    run
}

fn group(line: &[u8], at: usize, len: usize, sep: Option<u8>) -> Option<usize> {
    if at + len > line.len() || !line[at..at + len].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let end = at + len;
    match sep {
        Some(byte) => {
            take(line, end, byte)?;
            Some(end + 1 - at)
        }
        None => Some(end - at),
    }
}

fn ts_at(line: &[u8], at: usize) -> Option<usize> {
    let iso = iso_at(line, at);
    let syslog = syslog_at(line, at);
    match (iso, syslog) {
        (Some(iso), Some(syslog)) => Some(iso.max(syslog)),
        (iso, syslog) => iso.or(syslog),
    }
}

fn iso_at(line: &[u8], at: usize) -> Option<usize> {
    let date = date_at(line, at)?;
    match time_at(line, at + date) {
        Some(time) => Some(date + time),
        None => Some(date),
    }
}

fn date_at(line: &[u8], at: usize) -> Option<usize> {
    let year = group(line, at, 4, Some(b'-'))?;
    let month = group(line, at + year, 2, Some(b'-'))?;
    let day = group(line, at + year + month, 2, None)?;
    Some(year + month + day)
}

fn time_at(line: &[u8], at: usize) -> Option<usize> {
    if !matches!(line.get(at), Some(b'T' | b't' | b' ')) {
        return None;
    }
    let start = at;
    let mut at = start + 1;
    let hour = group(line, at, 2, Some(b':'))?;
    let minute = group(line, at + hour, 2, Some(b':'))?;
    let second = group(line, at + hour + minute, 2, None)?;
    at += hour + minute + second;
    if line.get(at) == Some(&b'.') {
        let frac = digits(line, at + 1);
        if frac > 0 {
            at += 1 + frac;
        }
    }
    match line.get(at) {
        Some(b'Z' | b'z') => at += 1,
        Some(b'+' | b'-') => {
            let offset = group(line, at + 1, 2, None)?;
            let mut end = at + 1 + offset;
            if take(line, end, b':') == Some(1) {
                end += 1;
            }
            let tail = group(line, end, 2, None)?;
            at = end + tail;
        }
        _ => {}
    }
    Some(at - start)
}

fn syslog_at(line: &[u8], at: usize) -> Option<usize> {
    let start = at;
    let month = line.get(at..at + 3)?;
    if !month[0].is_ascii_uppercase()
        || !month[1].is_ascii_lowercase()
        || !month[2].is_ascii_lowercase()
    {
        return None;
    }
    let after_month = spaces(line, at + 3);
    if after_month == 0 {
        return None;
    }
    let day = digits(line, at + 3 + after_month);
    if day == 0 || day > 2 {
        return None;
    }
    let after_day = spaces(line, at + 3 + after_month + day);
    if after_day == 0 {
        return None;
    }
    let at = at + 3 + after_month + day + after_day;
    let hour = group(line, at, 2, Some(b':'))?;
    let minute = group(line, at + hour, 2, Some(b':'))?;
    let second = group(line, at + hour + minute, 2, None)?;
    Some(at + hour + minute + second - start)
}

fn ip_at(line: &[u8], at: usize) -> Option<usize> {
    ipv4_at(line, at).or_else(|| ipv6_at(line, at))
}

fn ipv4_at(line: &[u8], start: usize) -> Option<usize> {
    let mut at = start;
    for octet in 0..4 {
        let run = digits(line, at);
        if run == 0 || run > 3 {
            return None;
        }
        if run == 3 {
            let value = 100 * (line[at] - b'0') as usize
                + 10 * (line[at + 1] - b'0') as usize
                + (line[at + 2] - b'0') as usize;
            if value > 255 {
                return None;
            }
        }
        at += run;
        if octet < 3 {
            take(line, at, b'.')?;
            at += 1;
        }
    }
    Some(at - start)
}

fn ipv6_at(line: &[u8], start: usize) -> Option<usize> {
    let mut at = start;
    let mut groups = 0usize;
    let mut singles = 0usize;
    let mut compressed = false;
    if line.get(at) == Some(&b':') {
        if line.get(at + 1) != Some(&b':') {
            return None;
        }
        at += 2;
        compressed = true;
    }
    while at < line.len() {
        let run = hex_run(line, at);
        if run == 0 || run > 4 || line.get(at + run) == Some(&b'.') {
            let len = ipv4_at(line, at)?;
            at += len;
            groups += 2;
            break;
        }
        at += run;
        groups += 1;
        match line.get(at) {
            None => break,
            Some(b':') => {
                at += 1;
                if line.get(at) == Some(&b':') {
                    if compressed {
                        return None;
                    }
                    at += 1;
                    compressed = true;
                } else {
                    singles += 1;
                }
            }
            Some(_) => break,
        }
    }
    if groups == 0 || groups > 8 {
        return None;
    }
    if compressed {
        if groups + singles > 7 {
            return None;
        }
    } else if singles != 7 {
        return None;
    }
    Some(at - start)
}

fn uuid_at(line: &[u8], start: usize) -> Option<usize> {
    let mut at = start;
    for (index, len) in [8usize, 4, 4, 4, 12].into_iter().enumerate() {
        if hex_run(line, at) != len {
            return None;
        }
        at += len;
        if index < 4 {
            take(line, at, b'-')?;
            at += 1;
        }
    }
    Some(at - start)
}

fn hex_at(line: &[u8], at: usize) -> Option<usize> {
    let run = hex_run(line, at);
    (run >= HEX_MIN_RUN).then_some(run)
}

fn dur_at(line: &[u8], at: usize) -> Option<usize> {
    let int = digits(line, at);
    if int == 0 {
        return None;
    }
    let mut end = at + int;
    if line.get(end) == Some(&b'.') {
        let frac = digits(line, end + 1);
        if frac > 0 {
            end += 1 + frac;
            if let Some(len) = dur_unit(line, end) {
                return Some(end + len - at);
            }
        }
    }
    dur_unit(line, end).map(|len| end + len - at)
}

fn dur_unit(line: &[u8], at: usize) -> Option<usize> {
    for two in [&b"ns"[..], &b"us"[..], &b"ms"[..]] {
        if line.get(at..at + 2) == Some(two) {
            return Some(2);
        }
    }
    match line.get(at) {
        Some(b's' | b'm' | b'h') => Some(1),
        _ => None,
    }
}

fn num_at(line: &[u8], at: usize) -> Option<usize> {
    let int = digits(line, at);
    if int == 0 {
        return None;
    }
    let mut end = at + int;
    if line.get(end) == Some(&b'.') {
        let frac = digits(line, end + 1);
        if frac > 0 {
            end += 1 + frac;
        }
    }
    Some(end - at)
}
