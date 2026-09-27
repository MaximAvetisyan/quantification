use tiktoken_rs::CoreBPE;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Baseline {
    O200kBase,
    Cl100kBase,
    BytesPerFour,
}

impl Baseline {
    pub const CANDIDATES: [Baseline; 2] = [Self::O200kBase, Self::Cl100kBase];
    pub const ALL: [Baseline; 3] = [Self::O200kBase, Self::Cl100kBase, Self::BytesPerFour];
    pub const DEFAULT_SPEC: &'static str = "o200k_base,cl100k_base";

    pub fn as_str(self) -> &'static str {
        match self {
            Self::O200kBase => "o200k_base",
            Self::Cl100kBase => "cl100k_base",
            Self::BytesPerFour => "bytes/4",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name.trim() {
            "o200k_base" => Some(Self::O200kBase),
            "cl100k_base" => Some(Self::Cl100kBase),
            "bytes/4" | "bytes4" | "bytes_per_4" => Some(Self::BytesPerFour),
            _ => None,
        }
    }

    pub fn real(self) -> bool {
        !matches!(self, Self::BytesPerFour)
    }
}

pub fn parse_spec(spec: &str) -> Result<Vec<Baseline>, String> {
    let mut out = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let baseline =
            Baseline::parse(part).ok_or_else(|| format!("unknown tokenizer baseline `{part}`"))?;
        if !out.contains(&baseline) {
            out.push(baseline);
        }
    }
    if out.is_empty() {
        return Err("no tokenizer baseline was requested".to_string());
    }
    Ok(out)
}

pub struct Counter {
    baseline: Baseline,
    bpe: Option<CoreBPE>,
}

impl Counter {
    pub fn load(baseline: Baseline) -> Result<Self, String> {
        let bpe = match baseline {
            Baseline::O200kBase => Some(
                tiktoken_rs::o200k_base().map_err(|e| format!("o200k_base is unavailable: {e}"))?,
            ),
            Baseline::Cl100kBase => Some(
                tiktoken_rs::cl100k_base()
                    .map_err(|e| format!("cl100k_base is unavailable: {e}"))?,
            ),
            Baseline::BytesPerFour => None,
        };
        Ok(Self { baseline, bpe })
    }

    pub fn baseline(&self) -> Baseline {
        self.baseline
    }

    pub fn count(&self, bytes: &[u8]) -> Option<Count> {
        Some(Count {
            baseline: self.baseline,
            tokens: match &self.bpe {
                Some(bpe) => bpe.encode_ordinary(std::str::from_utf8(bytes).ok()?).len() as u64,
                None => bytes.len().div_ceil(4) as u64,
            },
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Count {
    pub baseline: Baseline,
    pub tokens: u64,
}

pub fn all_available() -> bool {
    Baseline::CANDIDATES
        .iter()
        .all(|baseline| Counter::load(*baseline).is_ok())
}

pub fn unavailable() -> String {
    unavailable_note(all_available()).to_string()
}

pub fn unavailable_note(every_real_baseline_loaded: bool) -> &'static str {
    if every_real_baseline_loaded {
        "every real tokenizer baseline loaded; bytes/4 is a proxy and is never a DESIGN.md 12 \
         measurement"
    } else {
        "a real tokenizer baseline is unavailable: the DESIGN.md 12 success metric is NOT \
         MEASURED for it, and the bytes/4 proxy does not substitute for it"
    }
}
