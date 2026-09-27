use crate::compressor::v1::{CompressRequest, MarkerStyle, ScopePolicy};
use quantification_core::config::{self, RawOptions, ResolveError, ResolvedOptions};

impl From<ScopePolicy> for config::ScopePolicy {
    fn from(value: ScopePolicy) -> Self {
        match value {
            ScopePolicy::UserContent => Self::UserContent,
            ScopePolicy::UserAndTools => Self::UserAndTools,
            ScopePolicy::AllMessages => Self::AllMessages,
            ScopePolicy::ExplicitPaths => Self::ExplicitPaths,
        }
    }
}

impl From<config::ScopePolicy> for ScopePolicy {
    fn from(value: config::ScopePolicy) -> Self {
        match value {
            config::ScopePolicy::UserContent => Self::UserContent,
            config::ScopePolicy::UserAndTools => Self::UserAndTools,
            config::ScopePolicy::AllMessages => Self::AllMessages,
            config::ScopePolicy::ExplicitPaths => Self::ExplicitPaths,
        }
    }
}

impl From<MarkerStyle> for config::MarkerStyle {
    fn from(value: MarkerStyle) -> Self {
        match value {
            MarkerStyle::Auto => Self::Auto,
            MarkerStyle::Ascii => Self::Ascii,
            MarkerStyle::Unicode => Self::Unicode,
        }
    }
}

impl From<config::MarkerStyle> for MarkerStyle {
    fn from(value: config::MarkerStyle) -> Self {
        match value {
            config::MarkerStyle::Auto => Self::Auto,
            config::MarkerStyle::Ascii => Self::Ascii,
            config::MarkerStyle::Unicode => Self::Unicode,
        }
    }
}

pub fn to_raw_options(request: &CompressRequest) -> RawOptions {
    let options = request.options.unwrap_or_default();
    RawOptions {
        scope_policy: ScopePolicy::try_from(request.scope_policy)
            .ok()
            .map(Into::into),
        min_group_size: Some(options.min_group_size),
        normalize_ws: options.normalize_ws,
        template_dedup: options.template_dedup,
        marker_style: MarkerStyle::try_from(options.marker_style)
            .ok()
            .map(Into::into),
        reversible: options.reversible,
    }
}

pub fn resolve(request: &CompressRequest) -> Result<ResolvedOptions, ResolveError> {
    config::resolve(&to_raw_options(request))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compressor::v1::{ContentType, Options, compressor_server::CompressorServer};
    use prost::Message;
    use tonic::server::NamedService;

    fn request(options: Options) -> CompressRequest {
        CompressRequest {
            payload: b"[]".to_vec(),
            content_type: ContentType::Auto as i32,
            scope_policy: ScopePolicy::UserContent as i32,
            options: Some(options),
        }
    }

    fn roundtrip(options: Options) -> Options {
        Options::decode(options.encode_to_vec().as_slice()).unwrap()
    }

    #[test]
    fn omitted_bools_resolve_to_defaults() {
        let options = roundtrip(Options::default());
        assert_eq!(options.normalize_ws, None);
        assert_eq!(options.template_dedup, None);
        assert_eq!(options.reversible, None);
        let resolved = resolve(&request(options)).unwrap();
        assert!(resolved.normalize_ws);
        assert!(resolved.template_dedup);
        assert!(!resolved.reversible);
    }

    #[test]
    fn explicit_false_presence_survives_the_wire_and_resolves_false() {
        let explicit = Options {
            normalize_ws: Some(false),
            template_dedup: Some(false),
            ..Options::default()
        };
        assert_ne!(
            explicit.encode_to_vec(),
            Options::default().encode_to_vec(),
            "an explicit false must occupy the wire, so absent is not explicit false"
        );
        let options = roundtrip(explicit);
        assert_eq!(options.normalize_ws, Some(false));
        assert_eq!(options.template_dedup, Some(false));
        assert_eq!(options.reversible, None);
        let resolved = resolve(&request(options)).unwrap();
        assert!(!resolved.normalize_ws);
        assert!(!resolved.template_dedup);
        assert!(!resolved.reversible);
    }

    #[test]
    fn reversible_true_absent_or_false_all_resolve() {
        for wire in [None, Some(false), Some(true)] {
            let options = roundtrip(Options {
                reversible: wire,
                ..Options::default()
            });
            assert_eq!(options.reversible, wire);
            assert_eq!(
                resolve(&request(options)).unwrap().reversible,
                wire.unwrap_or(false)
            );
        }
        let resolved = resolve(&request(roundtrip(Options {
            reversible: Some(true),
            ..Options::default()
        })))
        .expect("reversible=true resolves");
        assert!(resolved.reversible);
        assert!(resolved.options_echo().ends_with(r#""reversible":true}"#));
    }

    #[test]
    fn explicit_true_is_not_omitted() {
        let options = roundtrip(Options {
            normalize_ws: Some(true),
            ..Options::default()
        });
        assert_eq!(options.normalize_ws, Some(true));
        assert!(resolve(&request(options)).unwrap().normalize_ws);
    }

    #[test]
    fn absent_options_message_resolves_to_defaults() {
        let mut request = request(Options::default());
        request.options = None;
        let resolved = resolve(&request).unwrap();
        assert!(resolved.normalize_ws);
        assert_eq!(resolved.min_group_size, 3);
        assert_eq!(resolved.marker_style, config::MarkerStyle::Auto);
    }

    #[test]
    fn reserved_scope_policy_rejected() {
        let mut request = request(Options::default());
        request.scope_policy = ScopePolicy::AllMessages as i32;
        assert_eq!(
            resolve(&request),
            Err(ResolveError::UnsupportedScopePolicy(
                config::ScopePolicy::AllMessages
            ))
        );
    }

    #[test]
    fn min_group_size_one_rejected() {
        let request = request(Options {
            min_group_size: 1,
            ..Options::default()
        });
        assert_eq!(
            resolve(&request),
            Err(ResolveError::MinGroupSizeBelowTwo(1))
        );
    }

    #[test]
    fn wire_numbers_and_names_pinned() {
        assert_eq!(ScopePolicy::UserContent as i32, 0);
        assert_eq!(ScopePolicy::UserAndTools as i32, 1);
        assert_eq!(ScopePolicy::AllMessages as i32, 2);
        assert_eq!(ScopePolicy::ExplicitPaths as i32, 3);
        assert_eq!(MarkerStyle::Auto as i32, 0);
        assert_eq!(MarkerStyle::Ascii as i32, 1);
        assert_eq!(MarkerStyle::Unicode as i32, 2);
        assert_eq!(ContentType::Auto as i32, 0);
        assert_eq!(ContentType::Chat as i32, 1);
        assert_eq!(ContentType::Responses as i32, 2);
        assert_eq!(ContentType::Messages as i32, 3);
        assert_eq!(ContentType::Text as i32, 4);
        assert_eq!(
            ScopePolicy::from_str_name("EXPLICIT_PATHS"),
            Some(ScopePolicy::ExplicitPaths)
        );
        assert_eq!(
            MarkerStyle::from_str_name("MARKER_STYLE_UNICODE"),
            Some(MarkerStyle::Unicode)
        );
        assert_eq!(
            ContentType::from_str_name("CONTENT_TYPE_MESSAGES"),
            Some(ContentType::Messages)
        );
        assert_eq!(MarkerStyle::from_str_name("UNICODE"), None);
        assert_eq!(ContentType::from_str_name("MESSAGES"), None);
    }

    #[test]
    fn enum_conversions_roundtrip() {
        for policy in [
            ScopePolicy::UserContent,
            ScopePolicy::UserAndTools,
            ScopePolicy::AllMessages,
            ScopePolicy::ExplicitPaths,
        ] {
            let core: config::ScopePolicy = policy.into();
            assert_eq!(ScopePolicy::from(core), policy);
        }
        for style in [MarkerStyle::Auto, MarkerStyle::Ascii, MarkerStyle::Unicode] {
            let core: config::MarkerStyle = style.into();
            assert_eq!(MarkerStyle::from(core), style);
        }
    }

    #[test]
    fn stats_wire_fields_pinned() {
        let stats = crate::compressor::v1::Stats {
            record_splits: 7,
            restore_ids: vec!["abc:12".to_string()],
            ..Default::default()
        };
        let decoded =
            crate::compressor::v1::Stats::decode(stats.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded.record_splits, 7);
        assert_eq!(decoded.restore_ids, vec!["abc:12".to_string()]);
    }

    #[test]
    fn service_codegen_present() {
        assert_eq!(
            <CompressorServer<()> as NamedService>::NAME,
            "compressor.v1.Compressor"
        );
    }
}
