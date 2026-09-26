use crate::keys::{K_INPUT, K_MAX_TOKENS, K_MESSAGES, K_SYSTEM, NO_KEY, key_id};

pub const SNIFF_PREFIX_BYTES: usize = 65_536;

pub const CANDIDATE_ORDER: [Schema; 4] = [
    Schema::Chat,
    Schema::Responses,
    Schema::Messages,
    Schema::Text,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Schema {
    Chat,
    Responses,
    Messages,
    Text,
}

impl Schema {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Responses => "responses",
            Self::Messages => "messages",
            Self::Text => "text",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "chat" => Some(Self::Chat),
            "responses" => Some(Self::Responses),
            "messages" => Some(Self::Messages),
            "text" => Some(Self::Text),
            _ => None,
        }
    }
}

pub fn sniff(payload: &[u8]) -> Option<Schema> {
    let data = strip_bom(payload);
    let end = data.len().min(SNIFF_PREFIX_BYTES);
    let keys = root_keys(&data[..end]);
    let has = |k: u8| keys & (1 << k) != 0;
    let anthropic = has(K_MAX_TOKENS) || has(K_SYSTEM);
    let first = first_byte(data);
    let object = first == Some(b'{');
    let text = !matches!(first, Some(b'{' | b'[' | b'"'));
    CANDIDATE_ORDER
        .into_iter()
        .find(|&candidate| accept(candidate, object, &has, anthropic, text))
}

fn accept(
    candidate: Schema,
    object: bool,
    has: &impl Fn(u8) -> bool,
    anthropic: bool,
    text: bool,
) -> bool {
    match candidate {
        Schema::Chat => object && has(K_MESSAGES) && !anthropic,
        Schema::Responses => object && has(K_INPUT) && !has(K_MESSAGES),
        Schema::Messages => object && has(K_MESSAGES) && anthropic,
        Schema::Text => text,
    }
}

pub(crate) fn strip_bom(payload: &[u8]) -> &[u8] {
    if payload.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &payload[3..]
    } else {
        payload
    }
}

pub(crate) fn bom_len(payload: &[u8]) -> usize {
    payload.len() - strip_bom(payload).len()
}

fn first_byte(data: &[u8]) -> Option<u8> {
    data.iter()
        .copied()
        .find(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
}

fn root_keys(data: &[u8]) -> u32 {
    let mut keys = 0u32;
    let mut depth = 0usize;
    let mut at = 0usize;
    let mut start = 0usize;
    let mut end = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut pending = false;
    while at < data.len() {
        let b = data[at];
        if pending && !in_string {
            pending = false;
            if b == b':' && depth == 1 {
                let id = key_id(&data[start..end]);
                if id != NO_KEY {
                    keys |= 1 << id;
                }
            }
        }
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
                end = at;
            }
            at += 1;
            continue;
        }
        match b {
            b'{' | b'[' => depth += 1,
            b'}' | b']' => depth = depth.saturating_sub(1),
            b'"' => {
                in_string = true;
                start = at + 1;
                pending = depth == 1;
            }
            _ => {}
        }
        at += 1;
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{ALL_KEYS, NAMES};

    #[test]
    fn candidate_order_is_frozen() {
        assert_eq!(
            CANDIDATE_ORDER,
            [
                Schema::Chat,
                Schema::Responses,
                Schema::Messages,
                Schema::Text
            ]
        );
    }

    #[test]
    fn key_mask_covers_every_structural_key() {
        for key in ALL_KEYS {
            assert_ne!(key_id(NAMES[key as usize]), NO_KEY);
        }
    }

    #[test]
    fn as_str_and_parse_roundtrip() {
        for s in CANDIDATE_ORDER {
            assert_eq!(Schema::parse(s.as_str()), Some(s));
        }
        assert_eq!(Schema::parse("AUTO"), None);
        assert_eq!(Schema::parse("Chat"), None);
        assert_eq!(Schema::parse(""), None);
    }
}
