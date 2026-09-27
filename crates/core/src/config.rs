pub const MIN_GROUP_SIZE_DEFAULT: u32 = 3;
pub const MIN_BLOCK_LINES: u32 = 2;
pub const MAX_BLOCK_LINES: u32 = 64;
pub const MAX_LINE_BYTES: usize = 65_536;
pub const MAX_RECORD_BYTES: usize = 16_384;
pub const MAX_SPAN_BYTES: usize = 33_554_432;
pub const JSON_DEPTH_CAP: usize = 64;
pub const REQUEST_BODY_LIMIT: usize = 67_108_864;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopePolicy {
    UserContent,
    UserAndTools,
    AllMessages,
    ExplicitPaths,
}

impl ScopePolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserContent => "user_content",
            Self::UserAndTools => "user_and_tools",
            Self::AllMessages => "all_messages",
            Self::ExplicitPaths => "explicit_paths",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "user_content" => Some(Self::UserContent),
            "user_and_tools" => Some(Self::UserAndTools),
            "all_messages" => Some(Self::AllMessages),
            "explicit_paths" => Some(Self::ExplicitPaths),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkerStyle {
    Auto,
    Ascii,
    Unicode,
}

impl MarkerStyle {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Ascii => "ascii",
            Self::Unicode => "unicode",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(Self::Auto),
            "ascii" => Some(Self::Ascii),
            "unicode" => Some(Self::Unicode),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RawOptions {
    pub scope_policy: Option<ScopePolicy>,
    pub min_group_size: Option<u32>,
    pub normalize_ws: Option<bool>,
    pub template_dedup: Option<bool>,
    pub marker_style: Option<MarkerStyle>,
    pub reversible: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedOptions {
    pub scope_policy: ScopePolicy,
    pub min_group_size: u32,
    pub normalize_ws: bool,
    pub template_dedup: bool,
    pub marker_style: MarkerStyle,
    pub reversible: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolveError {
    UnsupportedScopePolicy(ScopePolicy),
    UnsupportedReversible,
    MinGroupSizeBelowTwo(u32),
}

pub fn resolve(raw: &RawOptions) -> Result<ResolvedOptions, ResolveError> {
    let scope_policy = match raw.scope_policy {
        None | Some(ScopePolicy::UserContent) => ScopePolicy::UserContent,
        Some(ScopePolicy::UserAndTools) => ScopePolicy::UserAndTools,
        Some(reserved @ (ScopePolicy::AllMessages | ScopePolicy::ExplicitPaths)) => {
            return Err(ResolveError::UnsupportedScopePolicy(reserved));
        }
    };
    let min_group_size = match raw.min_group_size {
        None | Some(0) => MIN_GROUP_SIZE_DEFAULT,
        Some(1) => return Err(ResolveError::MinGroupSizeBelowTwo(1)),
        Some(n) => n,
    };
    if raw.reversible == Some(true) {
        return Err(ResolveError::UnsupportedReversible);
    }
    Ok(ResolvedOptions {
        scope_policy,
        min_group_size,
        normalize_ws: raw.normalize_ws.unwrap_or(true),
        template_dedup: raw.template_dedup.unwrap_or(true),
        marker_style: raw.marker_style.unwrap_or(MarkerStyle::Auto),
        reversible: raw.reversible.unwrap_or(false),
    })
}

impl ResolvedOptions {
    pub fn options_echo(&self) -> String {
        format!(
            "{{\"scope_policy\":\"{}\",\"min_group_size\":{},\"normalize_ws\":{},\"template_dedup\":{},\"marker_style\":\"{}\",\"reversible\":{}}}",
            self.scope_policy.as_str(),
            self.min_group_size,
            self.normalize_ws,
            self.template_dedup,
            self.marker_style.as_str(),
            self.reversible,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consts_are_pinned() {
        assert_eq!(MIN_GROUP_SIZE_DEFAULT, 3);
        assert_eq!(MIN_BLOCK_LINES, 2);
        assert_eq!(MAX_BLOCK_LINES, 64);
        assert_eq!(MAX_LINE_BYTES, 65_536);
        assert_eq!(MAX_RECORD_BYTES, 16_384);
        assert_eq!(MAX_SPAN_BYTES, 33_554_432);
        assert_eq!(JSON_DEPTH_CAP, 64);
        assert_eq!(REQUEST_BODY_LIMIT, 67_108_864);
    }

    #[test]
    fn default_resolve_is_pinned() {
        let resolved = resolve(&RawOptions::default()).unwrap();
        assert_eq!(
            resolved,
            ResolvedOptions {
                scope_policy: ScopePolicy::UserContent,
                min_group_size: 3,
                normalize_ws: true,
                template_dedup: true,
                marker_style: MarkerStyle::Auto,
                reversible: false,
            }
        );
        assert_eq!(
            resolved.options_echo(),
            "{\"scope_policy\":\"user_content\",\"min_group_size\":3,\"normalize_ws\":true,\"template_dedup\":true,\"marker_style\":\"auto\",\"reversible\":false}"
        );
    }

    #[test]
    fn min_group_size_resolution() {
        let r = |n| {
            resolve(&RawOptions {
                min_group_size: n,
                ..RawOptions::default()
            })
        };
        assert_eq!(r(None).unwrap().min_group_size, 3);
        assert_eq!(r(Some(0)).unwrap().min_group_size, 3);
        assert_eq!(r(Some(1)), Err(ResolveError::MinGroupSizeBelowTwo(1)));
        assert_eq!(r(Some(2)).unwrap().min_group_size, 2);
        assert_eq!(r(Some(u32::MAX)).unwrap().min_group_size, u32::MAX);
    }

    #[test]
    fn implemented_policies_resolve() {
        let raw = |p| RawOptions {
            scope_policy: Some(p),
            ..RawOptions::default()
        };
        assert_eq!(
            resolve(&raw(ScopePolicy::UserContent))
                .unwrap()
                .scope_policy,
            ScopePolicy::UserContent
        );
        assert_eq!(
            resolve(&raw(ScopePolicy::UserAndTools))
                .unwrap()
                .scope_policy,
            ScopePolicy::UserAndTools
        );
    }

    #[test]
    fn reserved_policies_rejected() {
        let raw = |p| RawOptions {
            scope_policy: Some(p),
            ..RawOptions::default()
        };
        assert_eq!(
            resolve(&raw(ScopePolicy::AllMessages)),
            Err(ResolveError::UnsupportedScopePolicy(
                ScopePolicy::AllMessages
            ))
        );
        assert_eq!(
            resolve(&raw(ScopePolicy::ExplicitPaths)),
            Err(ResolveError::UnsupportedScopePolicy(
                ScopePolicy::ExplicitPaths
            ))
        );
    }

    #[test]
    fn overrides_flow_through() {
        let raw = RawOptions {
            scope_policy: Some(ScopePolicy::UserAndTools),
            min_group_size: Some(7),
            normalize_ws: Some(false),
            template_dedup: Some(false),
            marker_style: Some(MarkerStyle::Unicode),
            reversible: Some(false),
        };
        let resolved = resolve(&raw).unwrap();
        assert_eq!(
            resolved,
            ResolvedOptions {
                scope_policy: ScopePolicy::UserAndTools,
                min_group_size: 7,
                normalize_ws: false,
                template_dedup: false,
                marker_style: MarkerStyle::Unicode,
                reversible: false,
            }
        );
        assert_eq!(
            resolved.options_echo(),
            "{\"scope_policy\":\"user_and_tools\",\"min_group_size\":7,\"normalize_ws\":false,\"template_dedup\":false,\"marker_style\":\"unicode\",\"reversible\":false}"
        );
    }

    #[test]
    fn reversible_true_is_rejected_and_false_resolves() {
        assert_eq!(
            resolve(&RawOptions {
                reversible: Some(true),
                ..RawOptions::default()
            }),
            Err(ResolveError::UnsupportedReversible)
        );
        let off = resolve(&RawOptions {
            reversible: Some(false),
            ..RawOptions::default()
        })
        .unwrap();
        assert!(!off.reversible);
        assert!(off.options_echo().ends_with(r#""reversible":false}"#));
    }

    #[test]
    fn scope_policy_parse_roundtrip() {
        for p in [
            ScopePolicy::UserContent,
            ScopePolicy::UserAndTools,
            ScopePolicy::AllMessages,
            ScopePolicy::ExplicitPaths,
        ] {
            assert_eq!(ScopePolicy::parse(p.as_str()), Some(p));
        }
    }

    #[test]
    fn marker_style_parse_roundtrip() {
        for s in [MarkerStyle::Auto, MarkerStyle::Ascii, MarkerStyle::Unicode] {
            assert_eq!(MarkerStyle::parse(s.as_str()), Some(s));
        }
    }

    #[test]
    fn garbage_tokens_rejected() {
        for s in ["", "USER_CONTENT", "user-content", "autot", "unicod"] {
            assert_eq!(ScopePolicy::parse(s), None);
            assert_eq!(MarkerStyle::parse(s), None);
        }
    }
}
