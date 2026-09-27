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
    pub const fn placeholder(self) -> &'static [u8] {
        match self {
            Self::Ts => b"<ts>",
            Self::Ip => b"<ip>",
            Self::Uuid => b"<uuid>",
            Self::Hex => b"<hex>",
            Self::Dur => b"<dur>",
            Self::Num => b"<num>",
        }
    }
}

const HEX: u8 = 1;
const DIGIT: u8 = 2;
const STOP: u8 = 4;

const CLASS: [u8; 256] = classes();

const fn classes() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut at = 0;
    while at < 256 {
        let byte = at as u8;
        table[at] = if byte.is_ascii_digit() {
            HEX | DIGIT | STOP
        } else if byte.is_ascii_hexdigit() {
            HEX | STOP
        } else if byte.is_ascii_uppercase() || byte == b':' || byte == b'\\' {
            STOP
        } else {
            0
        };
        at += 1;
    }
    table
}

struct Probe {
    digit: usize,
    hex: usize,
}

impl Probe {
    fn at(line: &[u8], at: usize) -> Self {
        let mut hex = 0;
        let mut digit = 0;
        for &byte in &line[at..] {
            let class = CLASS[byte as usize];
            if class & HEX == 0 {
                break;
            }
            if class & DIGIT != 0 && digit == hex {
                digit = hex + 1;
            }
            hex += 1;
        }
        Self { digit, hex }
    }
}

const SHORTEST: [(Mask, usize); 6] = [
    (Mask::Ts, 10),
    (Mask::Ip, 3),
    (Mask::Uuid, 36),
    (Mask::Hex, 16),
    (Mask::Dur, 2),
    (Mask::Num, 1),
];

const fn growth() -> usize {
    let mut at = 0;
    let mut worst = 1;
    while at < SHORTEST.len() {
        let (mask, consumed) = SHORTEST[at];
        let placeholder = mask.placeholder().len();
        let whole = placeholder / consumed;
        let need = if placeholder % consumed == 0 {
            whole
        } else {
            whole + 1
        };
        if need > worst {
            worst = need;
        }
        at += 1;
    }
    worst
}

const GROWTH: usize = growth();

pub const fn mask_bound(len: usize) -> usize {
    len * GROWTH + 8
}

pub fn mask(ws_line: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(mask_bound(ws_line.len()));
    mask_into(ws_line, &mut out);
    out
}

pub fn mask_into(ws_line: &[u8], out: &mut Vec<u8>) {
    let len = mask_len(ws_line, out);
    out.truncate(len);
}

fn mask_len(ws_line: &[u8], out: &mut Vec<u8>) -> usize {
    let bound = mask_bound(ws_line.len());
    if out.len() < bound {
        out.resize(bound, 0);
    }
    let (buf, len) = (out.as_mut_slice(), ws_line.len());
    let mut at = 0;
    let mut end = 0;
    while at < len {
        if CLASS[ws_line[at] as usize] & STOP == 0 {
            buf[end] = ws_line[at];
            end += 1;
            at += 1;
            continue;
        }
        if let Some(unit) = escape_unit(ws_line, at) {
            end = copy(buf, end, &ws_line[at..at + unit]);
            at += unit;
            continue;
        }
        let probe = Probe::at(ws_line, at);
        match hit(ws_line, at, &probe) {
            Some((mask, hit_len)) => {
                end = copy(buf, end, mask.placeholder());
                at += hit_len;
            }
            None => {
                buf[end] = ws_line[at];
                end += 1;
                at += 1;
            }
        }
    }
    end
}

fn copy(buf: &mut [u8], at: usize, bytes: &[u8]) -> usize {
    if bytes.len() > 8 {
        buf[at..at + bytes.len()].copy_from_slice(bytes);
        return at + bytes.len();
    }
    let mut end = at;
    for &byte in bytes {
        buf[end] = byte;
        end += 1;
    }
    end
}

fn hit(line: &[u8], at: usize, probe: &Probe) -> Option<(Mask, usize)> {
    let lower = |skip: usize| line.get(at + skip).is_some_and(u8::is_ascii_lowercase);
    if probe.digit == 4
        && line.get(at + 4) == Some(&b'-')
        && let Some(len) = iso_at(line, at)
    {
        return Some((Mask::Ts, len));
    }
    if line[at].is_ascii_uppercase()
        && lower(1)
        && lower(2)
        && let Some(len) = syslog_at(line, at)
    {
        return Some((Mask::Ts, len));
    }
    let ip_shape = match probe.digit {
        0 => probe.hex <= 4 && line.get(at + probe.hex) == Some(&b':'),
        1..=4 => true,
        _ => false,
    };
    if ip_shape && let Some(len) = ip_at(line, at, probe) {
        return Some((Mask::Ip, len));
    }
    if probe.hex == 8
        && let Some(len) = uuid_at(line, at)
    {
        return Some((Mask::Uuid, len));
    }
    if probe.hex >= HEX_MIN_RUN {
        return Some((Mask::Hex, probe.hex));
    }
    if probe.digit > 0
        && matches!(
            line.get(at + probe.digit),
            Some(b'.' | b'n' | b'u' | b'm' | b's' | b'h')
        )
        && let Some(len) = dur_at(line, at, probe)
    {
        return Some((Mask::Dur, len));
    }
    if probe.digit > 0 {
        return num_at(line, at, probe).map(|len| (Mask::Num, len));
    }
    None
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

fn iso_at(line: &[u8], at: usize) -> Option<usize> {
    let month = group(line, at + 5, 2, Some(b'-'))?;
    let day = group(line, at + 5 + month, 2, None)?;
    let date = 5 + month + day;
    match time_at(line, at + date) {
        Some(time) => Some(date + time),
        None => Some(date),
    }
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

fn ip_at(line: &[u8], at: usize, probe: &Probe) -> Option<usize> {
    ipv4_at(line, at, probe.digit).or_else(|| ipv6_at(line, at, probe))
}

fn ipv4_at(line: &[u8], start: usize, first: usize) -> Option<usize> {
    let mut at = start;
    let mut run = first;
    for octet in 0..4 {
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
            run = digits(line, at);
        }
    }
    Some(at - start)
}

fn ipv6_at(line: &[u8], start: usize, probe: &Probe) -> Option<usize> {
    let mut at = start;
    let mut groups = 0usize;
    let mut singles = 0usize;
    let mut compressed = false;
    let mut run = 0usize;
    let mut shared = false;
    if line.get(at) == Some(&b':') {
        if line.get(at + 1) != Some(&b':') {
            return None;
        }
        at += 2;
        compressed = true;
    } else {
        run = probe.hex;
        shared = true;
    }
    while at < line.len() {
        if !shared {
            run = hex_run(line, at);
        }
        shared = false;
        if run == 0 || run > 4 || line.get(at + run) == Some(&b'.') {
            let len = ipv4_at(line, at, digits(line, at))?;
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
    take(line, start + 8, b'-')?;
    let mut at = start + 9;
    for _ in 0..3 {
        if hex_run(line, at) != 4 {
            return None;
        }
        at += 4;
        take(line, at, b'-')?;
        at += 1;
    }
    if hex_run(line, at) != 12 {
        return None;
    }
    Some(at + 12 - start)
}

fn dur_at(line: &[u8], at: usize, probe: &Probe) -> Option<usize> {
    let mut end = at + probe.digit;
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

fn num_at(line: &[u8], at: usize, probe: &Probe) -> Option<usize> {
    let mut end = at + probe.digit;
    if line.get(end) == Some(&b'.') {
        let frac = digits(line, end + 1);
        if frac > 0 {
            end += 1 + frac;
        }
    }
    Some(end - at)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WITNESS: [(&[u8], Mask); 6] = [
        (b"2026-08-26", Mask::Ts),
        (b"::1", Mask::Ip),
        (b"123e4567-e89b-12d3-a456-426614174000", Mask::Uuid),
        (b"0123456789abcdef", Mask::Hex),
        (b"5s", Mask::Dur),
        (b"5", Mask::Num),
    ];

    #[test]
    fn the_growth_bound_is_the_worst_paired_placeholder_ratio() {
        assert_eq!(
            SHORTEST.iter().map(|(entry, _)| *entry).collect::<Vec<_>>(),
            MASK_LIST.to_vec(),
            "every mask in the frozen list is paired with its shortest form"
        );
        for (index, (input, entry)) in WITNESS.iter().enumerate() {
            let (_, consumed) = SHORTEST[index];
            assert_eq!(*entry, SHORTEST[index].0, "input {input:?}");
            assert_eq!(input.len(), consumed, "input {input:?}");
            assert_eq!(mask(input), entry.placeholder(), "input {input:?}");
            assert!(
                entry.placeholder().len() <= GROWTH * consumed,
                "input {input:?} needs a larger bound"
            );
        }
        let worst = SHORTEST
            .iter()
            .map(|(entry, consumed)| entry.placeholder().len().div_ceil(*consumed))
            .max()
            .expect("a mask in the frozen list");
        assert_eq!(GROWTH, worst);
        for len in 0..64usize {
            assert!(mask_bound(len) >= len, "bound for {len} bytes");
        }
    }
}
