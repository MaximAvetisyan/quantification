use crate::config::resolve;
use crate::pipeline;
use crate::sniff;
use crate::splice;

pub use crate::config::{MarkerStyle, RawOptions, ResolveError, ScopePolicy};
pub use crate::locator::NoopReason;
pub use crate::pipeline::{ALGO_VERSION, Clock, MonotonicClock, Stats};
pub use crate::sniff::Schema as ContentType;

pub const STRICT_VALIDATE: bool = cfg!(feature = "strict_validate");

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Request {
    pub content_type: Option<ContentType>,
    pub options: RawOptions,
}

impl Request {
    pub fn pinned(content_type: ContentType) -> Self {
        Self {
            content_type: Some(content_type),
            ..Self::default()
        }
    }

    pub fn with_options(mut self, options: RawOptions) -> Self {
        self.options = options;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApiError {
    Options(ResolveError),
    ContentTypeMismatch {
        pinned: ContentType,
        sniffed: Option<ContentType>,
    },
    Malformed,
}

impl ApiError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Options(_) => "invalid_options",
            Self::ContentTypeMismatch { .. } => "content_type_mismatch",
            Self::Malformed => "malformed",
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Options(error) => write!(f, "invalid_options: {error:?}"),
            Self::ContentTypeMismatch { pinned, sniffed } => write!(
                f,
                "content_type_mismatch: pinned {} but the payload sniffs as {}",
                pinned.as_str(),
                sniffed.map_or("no known schema", ContentType::as_str)
            ),
            Self::Malformed => f.write_str("malformed"),
        }
    }
}

pub struct Compressor {
    inner: pipeline::Compressor,
}

impl Default for Compressor {
    fn default() -> Self {
        Self::new()
    }
}

impl Compressor {
    pub fn new() -> Self {
        Self {
            inner: pipeline::Compressor::new(),
        }
    }

    pub fn with_clock(clock: impl Clock + 'static) -> Self {
        Self {
            inner: pipeline::Compressor::with_clock(clock),
        }
    }

    pub fn compress(
        &mut self,
        payload: &[u8],
        request: &Request,
        out: &mut Vec<u8>,
    ) -> Result<Stats, ApiError> {
        let options = resolve(&request.options).map_err(ApiError::Options)?;
        if let Some(pinned) = request.content_type {
            let sniffed = sniff::sniff(payload);
            if mismatch(pinned, sniffed) {
                return Err(ApiError::ContentTypeMismatch { pinned, sniffed });
            }
        }
        if let Some(problem) = strict(payload, request.content_type).err() {
            return Err(match request.content_type {
                Some(pinned) => ApiError::ContentTypeMismatch {
                    pinned,
                    sniffed: sniff::sniff(payload),
                },
                None => problem,
            });
        }
        let stats = match request.content_type {
            Some(schema) => self.inner.compress_as(payload, schema, &options, out),
            None => self.inner.compress(payload, &options, out),
        };
        if let (Some(pinned), Some(NoopReason::Malformed)) =
            (request.content_type, stats.noop_reason)
        {
            return Err(ApiError::ContentTypeMismatch {
                pinned,
                sniffed: sniff::sniff(payload),
            });
        }
        Ok(stats)
    }
}

pub fn reserve(out: &mut Vec<u8>, input_len: usize) {
    out.reserve(splice::spliced_len(input_len, &[]));
}

fn mismatch(pinned: ContentType, sniffed: Option<ContentType>) -> bool {
    match (pinned, sniffed) {
        (ContentType::Text, _) => false,
        (ContentType::Chat | ContentType::Messages, Some(found)) => {
            !matches!(found, ContentType::Chat | ContentType::Messages)
        }
        (ContentType::Responses, Some(found)) => found != ContentType::Responses,
        (_, None) => true,
    }
}

#[cfg(not(feature = "strict_validate"))]
fn strict(_payload: &[u8], _pinned: Option<ContentType>) -> Result<(), ApiError> {
    Ok(())
}

#[cfg(feature = "strict_validate")]
fn strict(payload: &[u8], pinned: Option<ContentType>) -> Result<(), ApiError> {
    let text = match pinned {
        Some(schema) => schema == ContentType::Text,
        None => sniff::sniff(payload) == Some(ContentType::Text),
    };
    if text {
        return Ok(());
    }
    let data = sniff::strip_bom(payload);
    let mut parser = Parser {
        data,
        at: 0,
        depth: 0,
    };
    parser.value().map_err(|()| ApiError::Malformed)?;
    parser.ws();
    if parser.at == data.len() {
        Ok(())
    } else {
        Err(ApiError::Malformed)
    }
}

#[cfg(feature = "strict_validate")]
struct Parser<'a> {
    data: &'a [u8],
    at: usize,
    depth: usize,
}

#[cfg(feature = "strict_validate")]
impl Parser<'_> {
    fn ws(&mut self) {
        while matches!(self.data.get(self.at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn byte(&self) -> Result<u8, ()> {
        self.data.get(self.at).copied().ok_or(())
    }

    fn value(&mut self) -> Result<(), ()> {
        self.ws();
        match self.byte()? {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => self.string(),
            b't' => self.literal(b"true"),
            b'f' => self.literal(b"false"),
            b'n' => self.literal(b"null"),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(()),
        }
    }

    fn literal(&mut self, want: &[u8]) -> Result<(), ()> {
        if self.data.get(self.at..self.at + want.len()) != Some(want) {
            return Err(());
        }
        self.at += want.len();
        Ok(())
    }

    fn object(&mut self) -> Result<(), ()> {
        if self.depth >= crate::config::JSON_DEPTH_CAP {
            return Err(());
        }
        self.depth += 1;
        self.at += 1;
        self.ws();
        if self.byte()? == b'}' {
            self.at += 1;
            self.depth -= 1;
            return Ok(());
        }
        loop {
            self.ws();
            if self.byte()? != b'"' {
                return Err(());
            }
            self.string()?;
            self.ws();
            if self.byte()? != b':' {
                return Err(());
            }
            self.at += 1;
            self.value()?;
            self.ws();
            match self.byte()? {
                b',' => self.at += 1,
                b'}' => {
                    self.at += 1;
                    self.depth -= 1;
                    return Ok(());
                }
                _ => return Err(()),
            }
        }
    }

    fn array(&mut self) -> Result<(), ()> {
        if self.depth >= crate::config::JSON_DEPTH_CAP {
            return Err(());
        }
        self.depth += 1;
        self.at += 1;
        self.ws();
        if self.byte()? == b']' {
            self.at += 1;
            self.depth -= 1;
            return Ok(());
        }
        loop {
            self.value()?;
            self.ws();
            match self.byte()? {
                b',' => self.at += 1,
                b']' => {
                    self.at += 1;
                    self.depth -= 1;
                    return Ok(());
                }
                _ => return Err(()),
            }
        }
    }

    fn string(&mut self) -> Result<(), ()> {
        self.at += 1;
        loop {
            match self.byte()? {
                b'"' => {
                    self.at += 1;
                    return Ok(());
                }
                b'\\' => {
                    self.at += 1;
                    match self.byte()? {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => self.at += 1,
                        b'u' => {
                            self.at += 1;
                            self.hex4()?;
                        }
                        _ => return Err(()),
                    }
                }
                0..=0x1F => return Err(()),
                _ => self.at += 1,
            }
        }
    }

    fn hex4(&mut self) -> Result<(), ()> {
        for _ in 0..4 {
            if !self.byte()?.is_ascii_hexdigit() {
                return Err(());
            }
            self.at += 1;
        }
        Ok(())
    }

    fn number(&mut self) -> Result<(), ()> {
        if self.byte()? == b'-' {
            self.at += 1;
        }
        match self.byte()? {
            b'0' => self.at += 1,
            b'1'..=b'9' => {
                self.at += 1;
                while matches!(self.data.get(self.at), Some(b'0'..=b'9')) {
                    self.at += 1;
                }
            }
            _ => return Err(()),
        }
        if self.data.get(self.at) == Some(&b'.') {
            self.at += 1;
            self.digits()?;
        }
        if matches!(self.data.get(self.at), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.data.get(self.at), Some(b'+' | b'-')) {
                self.at += 1;
            }
            self.digits()?;
        }
        self.ws();
        match self.data.get(self.at) {
            None | Some(b',' | b'}' | b']') => Ok(()),
            _ => Err(()),
        }
    }

    fn digits(&mut self) -> Result<(), ()> {
        let start = self.at;
        while matches!(self.data.get(self.at), Some(b'0'..=b'9')) {
            self.at += 1;
        }
        if self.at == start {
            return Err(());
        }
        Ok(())
    }
}
