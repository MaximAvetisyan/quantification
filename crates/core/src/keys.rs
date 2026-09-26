pub(crate) const KEY_COUNT: usize = 10;

pub(crate) const K_MESSAGES: u8 = 0;
pub(crate) const K_INPUT: u8 = 1;
pub(crate) const K_ROLE: u8 = 2;
pub(crate) const K_CONTENT: u8 = 3;
pub(crate) const K_TYPE: u8 = 4;
pub(crate) const K_TEXT: u8 = 5;
pub(crate) const K_OUTPUT: u8 = 6;
pub(crate) const K_SYSTEM: u8 = 7;
pub(crate) const K_TOOL_USE_ID: u8 = 8;
pub(crate) const K_MAX_TOKENS: u8 = 9;

pub(crate) const NO_KEY: u8 = u8::MAX;

pub(crate) const ALL_KEYS: [u8; KEY_COUNT] = [
    K_MESSAGES,
    K_INPUT,
    K_ROLE,
    K_CONTENT,
    K_TYPE,
    K_TEXT,
    K_OUTPUT,
    K_SYSTEM,
    K_TOOL_USE_ID,
    K_MAX_TOKENS,
];

const _: () = assert!(ALL_KEYS[0] == 0 && ALL_KEYS[KEY_COUNT - 1] == KEY_COUNT as u8 - 1);

pub(crate) const NAMES: [&[u8]; KEY_COUNT] = [
    b"messages",
    b"input",
    b"role",
    b"content",
    b"type",
    b"text",
    b"output",
    b"system",
    b"tool_use_id",
    b"max_tokens",
];

const MAX_NAME: usize = 11;
const MAX_DECODED: usize = MAX_NAME + 1;

pub(crate) fn key_id(raw: &[u8]) -> u8 {
    if !raw.contains(&b'\\') {
        return plain(raw);
    }
    let mut buf = [0u8; MAX_DECODED];
    match decode(raw, &mut buf) {
        Some(len) => plain(&buf[..len]),
        None => NO_KEY,
    }
}

fn plain(raw: &[u8]) -> u8 {
    for (index, name) in NAMES.iter().enumerate() {
        if *name == raw {
            return index as u8;
        }
    }
    NO_KEY
}

fn decode(raw: &[u8], out: &mut [u8; MAX_DECODED]) -> Option<usize> {
    let mut len = 0usize;
    let mut at = 0usize;
    while at < raw.len() {
        if raw[at] != b'\\' {
            *out.get_mut(len)? = raw[at];
            len += 1;
            at += 1;
            continue;
        }
        let esc = *raw.get(at + 1)?;
        at += 2;
        let ch = match esc {
            b'"' => b'"',
            b'\\' => b'\\',
            b'/' => b'/',
            b'b' => 0x08,
            b'f' => 0x0C,
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            b'u' => {
                let hi = hex4(raw, at)?;
                at += 4;
                let lo = if (0xD800..0xDC00).contains(&hi)
                    && raw.len() >= at + 6
                    && raw[at] == b'\\'
                    && raw[at + 1] == b'u'
                {
                    let low = hex4(raw, at + 2)?;
                    at += 6;
                    Some(low)
                } else {
                    None
                };
                match lo {
                    Some(low) if (0xDC00..0xE000).contains(&low) => {
                        let cp = 0x1_0000 + ((hi - 0xD800) << 10) + (low - 0xDC00);
                        put_utf8(&mut len, out, cp)?;
                        continue;
                    }
                    _ => {}
                }
                if (0xD800..0xE000).contains(&hi) {
                    0
                } else {
                    hi as u8
                }
            }
            other => other,
        };
        *out.get_mut(len)? = ch;
        len += 1;
    }
    Some(len)
}

fn hex4(raw: &[u8], at: usize) -> Option<u32> {
    let mut cp = 0u32;
    for k in 0..4 {
        cp = (cp << 4) | hex(*raw.get(at + k)?)? as u32;
    }
    Some(cp)
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn put_utf8(len: &mut usize, out: &mut [u8; MAX_DECODED], cp: u32) -> Option<()> {
    let quad = cp.to_be_bytes();
    for b in quad {
        *out.get_mut(*len)? = b;
        *len += 1;
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROLE: u8 = K_ROLE;
    const CONTENT: u8 = K_CONTENT;

    #[test]
    fn plain_keys_match() {
        assert_eq!(key_id(b"messages"), K_MESSAGES);
        assert_eq!(key_id(b"input"), K_INPUT);
        assert_eq!(key_id(b"role"), ROLE);
        assert_eq!(key_id(b"content"), CONTENT);
        assert_eq!(key_id(b"type"), K_TYPE);
        assert_eq!(key_id(b"text"), K_TEXT);
        assert_eq!(key_id(b"output"), K_OUTPUT);
        assert_eq!(key_id(b"system"), K_SYSTEM);
        assert_eq!(key_id(b"tool_use_id"), K_TOOL_USE_ID);
        assert_eq!(key_id(b"max_tokens"), K_MAX_TOKENS);
    }

    #[test]
    fn unknown_and_near_miss_keys_do_not_match() {
        for raw in [
            &b""[..],
            b"rol",
            b"roles",
            b"Role",
            b"ROLE",
            b"content ",
            b"conte",
            b"\0role",
        ] {
            assert_eq!(key_id(raw), NO_KEY, "{raw:?}");
        }
    }

    #[test]
    fn simple_escapes_decode_before_comparison() {
        assert_eq!(key_id(br"rol\u0065"), ROLE);
        assert_eq!(key_id(br"co\u006etent"), CONTENT);
        assert_eq!(key_id(br"conten\u0074"), CONTENT);
        assert_eq!(key_id(br"co\u006Etent"), CONTENT);
        assert_eq!(key_id(b"\\\"tool_use_id\\\""), NO_KEY);
    }

    #[test]
    fn surrogate_pairs_decode_to_utf8_and_never_match() {
        assert_eq!(key_id(br"\ud835\udd35"), NO_KEY);
        assert_eq!(key_id(br"rol\ud835\udd35"), NO_KEY);
        assert_eq!(key_id(br"\ud835"), NO_KEY);
        assert_eq!(key_id(br"rol\ud835e"), NO_KEY);
    }

    #[test]
    fn overlong_and_truncated_escapes_are_inert() {
        assert_eq!(key_id(br"\u0072ole\u0072ole\u0072ole"), NO_KEY);
        assert_eq!(key_id(br"\u00"), NO_KEY);
        assert_eq!(key_id(br"\uZZZZ"), NO_KEY);
        assert_eq!(key_id(br"\"), NO_KEY);
        assert_eq!(key_id(b"role\\"), NO_KEY);
    }

    #[test]
    fn unknown_escape_never_matches() {
        assert_eq!(key_id(br"rol\x65"), NO_KEY);
        assert_eq!(key_id(br"rol\zole"), NO_KEY);
    }
}
