use serde::Deserialize;

use quantification_core::api::{
    ContentType, MarkerStyle, RawOptions, Request, ResolveError, ScopePolicy,
};
use quantification_core::config::resolve;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub payload: String,
    pub content_type: Option<String>,
    pub options: Option<Options>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    scope_policy: Option<String>,
    min_group_size: Option<u32>,
    normalize_ws: Option<bool>,
    template_dedup: Option<bool>,
    marker_style: Option<String>,
    reversible: Option<bool>,
}

pub struct Query(Vec<(String, String)>);

impl Query {
    pub fn parse(raw: Option<&str>) -> Self {
        let mut pairs = Vec::new();
        for item in raw.unwrap_or_default().split('&').filter(|i| !i.is_empty()) {
            let (key, value) = item.split_once('=').unwrap_or((item, ""));
            pairs.push((decode(key), decode(value)));
        }
        Self(pairs)
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(found, _)| found == key)
            .map(|(_, value)| value.as_str())
    }

    fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|(key, _)| key.as_str())
    }
}

const KEYS: [&str; 7] = [
    "content_type",
    "scope_policy",
    "min_group_size",
    "normalize_ws",
    "template_dedup",
    "marker_style",
    "reversible",
];

pub fn request(query: &Query) -> Result<Request, String> {
    for key in query.keys() {
        if !KEYS.contains(&key) {
            return Err(format!("unknown query parameter {key}"));
        }
    }
    Ok(Request {
        content_type: pin(query.get("content_type"), "content_type")?,
        options: RawOptions {
            scope_policy: query.get("scope_policy").map(policy).transpose()?,
            min_group_size: query.get("min_group_size").map(group_size).transpose()?,
            normalize_ws: query
                .get("normalize_ws")
                .map(flag_key("normalize_ws"))
                .transpose()?,
            template_dedup: query
                .get("template_dedup")
                .map(flag_key("template_dedup"))
                .transpose()?,
            marker_style: query.get("marker_style").map(style).transpose()?,
            reversible: query
                .get("reversible")
                .map(flag_key("reversible"))
                .transpose()?,
        },
    })
}

pub fn scope(query: &Query) -> Result<ScopePolicy, String> {
    for key in query.keys() {
        if key != "scope_policy" {
            return Err(format!(
                "unknown query parameter {key}; /v1/detect takes scope_policy only"
            ));
        }
    }
    let raw = RawOptions {
        scope_policy: query.get("scope_policy").map(policy).transpose()?,
        ..RawOptions::default()
    };
    resolve(&raw)
        .map(|options| options.scope_policy)
        .map_err(resolve_message)
}

pub fn resolve_message(error: ResolveError) -> String {
    match error {
        ResolveError::UnsupportedScopePolicy(policy) => {
            format!("scope_policy={} is reserved", policy.as_str())
        }
        ResolveError::MinGroupSizeBelowTwo(size) => {
            format!("min_group_size={size} is below the minimum of 2")
        }
    }
}

pub fn only_envelope(query: &Query) -> Result<(), String> {
    for key in query.keys() {
        if key != "envelope" {
            return Err(format!(
                "{key} belongs in the envelope body on ?envelope=json, not in the query"
            ));
        }
    }
    Ok(())
}

impl Envelope {
    pub fn request(&self) -> Result<Request, String> {
        let options = self.options.clone().unwrap_or_default();
        Ok(Request {
            content_type: pin(self.content_type.as_deref(), "content_type")?,
            options: RawOptions {
                scope_policy: options.scope_policy.as_deref().map(policy).transpose()?,
                min_group_size: options.min_group_size,
                normalize_ws: options.normalize_ws,
                template_dedup: options.template_dedup,
                marker_style: options.marker_style.as_deref().map(style).transpose()?,
                reversible: options.reversible,
            },
        })
    }
}

fn pin(value: Option<&str>, key: &str) -> Result<Option<ContentType>, String> {
    match value {
        None => Ok(None),
        Some(value) => ContentType::parse(value)
            .map(Some)
            .ok_or_else(|| invalid(key, value, "one of chat, responses, messages, text")),
    }
}

fn policy(value: &str) -> Result<ScopePolicy, String> {
    ScopePolicy::parse(value).ok_or_else(|| {
        invalid(
            "scope_policy",
            value,
            "one of user_content, user_and_tools (all_messages and explicit_paths are reserved)",
        )
    })
}

fn style(value: &str) -> Result<MarkerStyle, String> {
    MarkerStyle::parse(value)
        .ok_or_else(|| invalid("marker_style", value, "one of auto, ascii, unicode"))
}

fn group_size(value: &str) -> Result<u32, String> {
    value
        .parse()
        .map_err(|_| invalid("min_group_size", value, "an integer >= 2"))
}

fn flag_key(key: &'static str) -> impl Fn(&str) -> Result<bool, String> + Copy {
    move |value| match value {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(invalid(key, other, "true or false")),
    }
}

fn invalid(key: &str, value: &str, expected: &str) -> String {
    format!("{key}={value} is not accepted; expected {expected}")
}

fn decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        out.push(match bytes[at] {
            b'+' => {
                at += 1;
                b' '
            }
            b'%' if at + 2 < bytes.len() => match (nibble(bytes[at + 1]), nibble(bytes[at + 2])) {
                (Some(high), Some(low)) => {
                    at += 3;
                    high << 4 | low
                }
                _ => {
                    at += 1;
                    b'%'
                }
            },
            byte => {
                at += 1;
                byte
            }
        });
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error(query: &str) -> String {
        request(&Query::parse(Some(query))).unwrap_err()
    }

    #[test]
    fn an_empty_query_is_every_default() {
        let parsed = Query::parse(None);
        assert_eq!(request(&parsed).unwrap(), Request::default());
        assert_eq!(
            request(&Query::parse(Some(""))).unwrap(),
            Request::default()
        );
    }

    #[test]
    fn every_option_reaches_raw_options() {
        let parsed = Query::parse(Some(
            "content_type=chat&scope_policy=user_and_tools&min_group_size=7&normalize_ws=false&template_dedup=false&marker_style=unicode&reversible=true",
        ));
        assert_eq!(
            request(&parsed).unwrap(),
            Request {
                content_type: Some(ContentType::Chat),
                options: RawOptions {
                    scope_policy: Some(ScopePolicy::UserAndTools),
                    min_group_size: Some(7),
                    normalize_ws: Some(false),
                    template_dedup: Some(false),
                    marker_style: Some(MarkerStyle::Unicode),
                    reversible: Some(true),
                },
            }
        );
    }

    #[test]
    fn reserved_scope_policies_survive_parsing_for_the_core_to_reject() {
        let parsed = Query::parse(Some("scope_policy=all_messages"));
        assert_eq!(
            request(&parsed).unwrap().options.scope_policy,
            Some(ScopePolicy::AllMessages)
        );
        assert!(
            scope(&Query::parse(Some("scope_policy=explicit_paths")))
                .expect_err("reserved")
                .contains("reserved")
        );
    }

    #[test]
    fn garbage_values_are_refused() {
        assert!(error("min_group_size=abc").contains("min_group_size"));
        assert!(error("min_group_size=-1").contains("min_group_size"));
        assert!(error("marker_style=zzz").contains("marker_style"));
        assert!(error("normalize_ws=yes").contains("true or false"));
        assert!(error("scope_policy=everyone").contains("scope_policy"));
        assert!(error("content_type=xml").contains("content_type"));
        assert!(error("nope=1").contains("unknown query parameter"));
    }

    #[test]
    fn percent_and_plus_are_decoded() {
        let parsed = Query::parse(Some("marker_style=%61scii&scope_policy=user%5Fcontent"));
        let request = request(&parsed).unwrap();
        assert_eq!(request.options.marker_style, Some(MarkerStyle::Ascii));
        assert_eq!(request.options.scope_policy, Some(ScopePolicy::UserContent));
        assert!(error("marker_style=%zz").contains("marker_style"));
    }

    #[test]
    fn the_first_of_a_repeated_key_wins() {
        let parsed = Query::parse(Some("min_group_size=5&min_group_size=9"));
        assert_eq!(parsed.get("min_group_size"), Some("5"));
        assert_eq!(request(&parsed).unwrap().options.min_group_size, Some(5));
    }

    #[test]
    fn the_envelope_path_refuses_query_options() {
        let parsed = Query::parse(Some("envelope=json&min_group_size=5"));
        assert_eq!(parsed.get("envelope"), Some("json"));
        assert!(only_envelope(&parsed).is_err());
        assert!(only_envelope(&Query::parse(Some("envelope=json"))).is_ok());
    }

    #[test]
    fn the_envelope_body_maps_onto_raw_options() {
        let envelope: Envelope = serde_json::from_str(
            r#"{"payload":"hi","content_type":"messages","options":{"scope_policy":"user_and_tools","min_group_size":4,"normalize_ws":false,"template_dedup":false,"marker_style":"ascii","reversible":true}}"#,
        )
        .unwrap();
        assert_eq!(
            envelope.request().unwrap(),
            Request {
                content_type: Some(ContentType::Messages),
                options: RawOptions {
                    scope_policy: Some(ScopePolicy::UserAndTools),
                    min_group_size: Some(4),
                    normalize_ws: Some(false),
                    template_dedup: Some(false),
                    marker_style: Some(MarkerStyle::Ascii),
                    reversible: Some(true),
                },
            }
        );
    }

    #[test]
    fn the_envelope_refuses_typos_and_bad_values() {
        assert!(serde_json::from_str::<Envelope>(r#"{"payload":"hi","nope":1}"#).is_err());
        assert!(serde_json::from_str::<Envelope>(r#"{"paylaod":"hi"}"#).is_err());
        assert!(serde_json::from_str::<Envelope>(r#"{"payload":7}"#).is_err());
        assert!(
            serde_json::from_str::<Envelope>(r#"{"payload":"hi","options":{"min_group_size":-1}}"#)
                .is_err()
        );
        let envelope: Envelope =
            serde_json::from_str(r#"{"payload":"hi","options":{"marker_style":"zzz"}}"#).unwrap();
        assert!(envelope.request().is_err());
    }
}
