use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::process::{Command, ExitStatus, Stdio};

use quantification_core::config::{ResolvedOptions, ScopePolicy};
use quantification_core::locator::locate;
use quantification_core::pipeline::Compressor;

use crate::corpus::{Payload, Stratum, build};

const MARKER_PREAMBLE: &str = "Some log lines were replaced by a marker of the form \
\"⟪ ... ⟫\", which means N consecutive identical or template-equal lines were omitted and \
only the first line of the group is kept verbatim. Answer from what is present, and say so \
when the payload no longer holds a line.";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskClass {
    RowLookup,
    CountAggregate,
    AnomalySpotting,
    Summarization,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Agreement {
    Exact,
    Facts,
}

impl TaskClass {
    pub const ALL: [TaskClass; 4] = [
        Self::RowLookup,
        Self::CountAggregate,
        Self::AnomalySpotting,
        Self::Summarization,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::RowLookup => "row_lookup",
            Self::CountAggregate => "count_aggregate",
            Self::AnomalySpotting => "anomaly_spotting",
            Self::Summarization => "summarization",
        }
    }

    pub fn agreement(self) -> Agreement {
        match self {
            Self::RowLookup | Self::CountAggregate => Agreement::Exact,
            Self::AnomalySpotting | Self::Summarization => Agreement::Facts,
        }
    }

    pub fn threshold_permille(self) -> u16 {
        match self {
            Self::RowLookup | Self::CountAggregate => 750,
            Self::AnomalySpotting | Self::Summarization => 900,
        }
    }

    pub fn gate_label(self) -> &'static str {
        match self {
            Self::RowLookup | Self::CountAggregate => {
                "extraction/counting class, provisional >= 75% parity"
            }
            Self::AnomalySpotting | Self::Summarization => {
                "summarization/anomaly class, provisional >= 90% parity"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderSpec {
    pub id: &'static str,
    pub model: &'static str,
    pub endpoint: &'static str,
    pub key_env: &'static str,
}

pub const OPENAI: ProviderSpec = ProviderSpec {
    id: "openai",
    model: "gpt-4o-mini",
    endpoint: "https://api.openai.com/v1/chat/completions",
    key_env: "OPENAI_API_KEY",
};

pub const ANTHROPIC: ProviderSpec = ProviderSpec {
    id: "anthropic",
    model: "claude-sonnet-4-5",
    endpoint: "https://api.anthropic.com/v1/messages",
    key_env: "ANTHROPIC_API_KEY",
};

pub const PROVIDERS: [ProviderSpec; 2] = [OPENAI, ANTHROPIC];

pub const PROVIDER_COMMAND_ENV: &str = "QUANT_EVAL_PROVIDER_CMD";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelError {
    pub provider: &'static str,
    pub reason: String,
}

impl ModelError {
    pub fn new(provider: &'static str, reason: impl Into<String>) -> Self {
        Self {
            provider,
            reason: reason.into(),
        }
    }
}

pub trait ModelProvider {
    fn spec(&self) -> ProviderSpec;
    fn complete(&self, prompt: &str) -> Result<String, ModelError>;
}

type Transport = Box<dyn Fn(&str) -> Result<String, ModelError> + Send + Sync>;

pub struct Injected {
    spec: ProviderSpec,
    call: Transport,
}

impl Injected {
    pub fn new(
        spec: ProviderSpec,
        call: impl Fn(&str) -> Result<String, ModelError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            spec,
            call: Box::new(call),
        }
    }

    pub fn command(spec: ProviderSpec, argv: Vec<String>) -> Self {
        Self::new(spec, move |prompt| run_command(&spec, &argv, prompt))
    }
}

impl ModelProvider for Injected {
    fn spec(&self) -> ProviderSpec {
        self.spec
    }

    fn complete(&self, prompt: &str) -> Result<String, ModelError> {
        (self.call)(prompt)
    }
}

fn run_command(spec: &ProviderSpec, argv: &[String], prompt: &str) -> Result<String, ModelError> {
    let Some((program, args)) = argv.split_first() else {
        return Err(ModelError::new(spec.id, "the provider command is empty"));
    };
    let mut child = Command::new(program)
        .args(args)
        .env("QUANT_EVAL_PROVIDER_ID", spec.id)
        .env("QUANT_EVAL_MODEL", spec.model)
        .env("QUANT_EVAL_ENDPOINT", spec.endpoint)
        .env("QUANT_EVAL_KEY_ENV", spec.key_env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| ModelError::new(spec.id, format!("cannot spawn {program}: {e}")))?;
    let mut stdin = child.stdin.take().expect("a piped stdin");
    let mut stdout = child.stdout.take().expect("a piped stdout");
    let mut answer = Vec::new();
    let mut status: Option<ExitStatus> = None;
    let mut read_error: Option<String> = None;
    let mut write_error: Option<String> = None;
    std::thread::scope(|scope| {
        let writer = scope.spawn(move || stdin.write_all(prompt.as_bytes()));
        if let Err(e) = stdout.read_to_end(&mut answer) {
            read_error = Some(e.to_string());
        }
        status = child.wait().ok();
        write_error = match writer.join() {
            Ok(Err(e)) if e.kind() != std::io::ErrorKind::BrokenPipe => Some(e.to_string()),
            Ok(_) => None,
            Err(_) => Some("the prompt writer panicked".to_string()),
        };
    });
    let Some(status) = status else {
        return Err(ModelError::new(
            spec.id,
            format!("{program} could not be waited for"),
        ));
    };
    if !status.success() {
        return Err(ModelError::new(
            spec.id,
            format!("{program} exited with {status}"),
        ));
    }
    if let Some(e) = read_error {
        return Err(ModelError::new(
            spec.id,
            format!("cannot read the answer from {program}: {e}"),
        ));
    }
    if let Some(e) = write_error {
        return Err(ModelError::new(
            spec.id,
            format!("cannot write the prompt to {program}: {e}"),
        ));
    }
    String::from_utf8(answer).map_err(|e| ModelError::new(spec.id, e.to_string()))
}

pub struct TaskCase {
    pub id: String,
    pub class: TaskClass,
    pub question: String,
    pub facts: Vec<String>,
    pub payload: Vec<u8>,
    pub compressed: Vec<u8>,
}

pub struct PromptPair {
    pub baseline: String,
    pub compressed: String,
}

pub fn prompt(question: &str, payload: &[u8]) -> String {
    let mut out = String::with_capacity(payload.len() + 512);
    out.push_str(MARKER_PREAMBLE);
    out.push_str("\n\n<payload>\n");
    out.push_str(&String::from_utf8_lossy(payload));
    out.push_str("\n</payload>\n\n<question>\n");
    out.push_str(question);
    out.push_str("\n</question>\n");
    out
}

pub fn prompts(case: &TaskCase) -> PromptPair {
    PromptPair {
        baseline: prompt(&case.question, &case.payload),
        compressed: prompt(&case.question, &case.compressed),
    }
}

pub fn normalize(answer: &str) -> String {
    answer
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .flat_map(|word| word.chars().map(|c| c.to_ascii_lowercase()))
        .collect()
}

pub fn covers(case: &TaskCase, answer: &str) -> bool {
    let haystack = normalize(answer);
    case.facts.iter().all(|fact| {
        if fact.chars().all(|c| c.is_ascii_digit()) {
            return answer
                .split(|c: char| !c.is_ascii_digit())
                .any(|token| token == fact);
        }
        let needle = normalize(fact);
        !needle.is_empty() && haystack.contains(&needle)
    })
}

pub fn parity(case: &TaskCase, baseline: &str, compressed: &str) -> bool {
    if !covers(case, baseline) || !covers(case, compressed) {
        return false;
    }
    match case.class.agreement() {
        Agreement::Exact => normalize(baseline) == normalize(compressed),
        Agreement::Facts => true,
    }
}

pub struct Outcome {
    pub task: String,
    pub class: TaskClass,
    pub baseline: Result<String, ModelError>,
    pub compressed: Result<String, ModelError>,
}

impl Outcome {
    pub fn parity(&self, case: &TaskCase) -> Option<bool> {
        match (&self.baseline, &self.compressed) {
            (Ok(baseline), Ok(compressed)) => Some(parity(case, baseline, compressed)),
            _ => None,
        }
    }
}

pub struct ClassScore {
    pub class: TaskClass,
    pub scored: usize,
    pub not_scored: usize,
    pub parity_permille: u16,
    pub threshold_permille: u16,
    pub meets_gate: bool,
}

pub struct ModelScore {
    pub spec: ProviderSpec,
    pub outcomes: Vec<Outcome>,
    pub classes: Vec<ClassScore>,
}

impl ModelScore {
    pub fn overall_permille(&self) -> u16 {
        let mut scored: Vec<u16> = self
            .classes
            .iter()
            .filter(|class| class.scored > 0)
            .map(|class| class.parity_permille)
            .collect();
        crate::metric::median(&mut scored)
    }

    pub fn meets_every_gate(&self) -> bool {
        self.classes.iter().all(|class| class.meets_gate)
    }

    pub fn errors(&self) -> Vec<&ModelError> {
        self.outcomes
            .iter()
            .flat_map(|o| [&o.baseline, &o.compressed])
            .filter_map(|r| r.as_ref().err())
            .collect()
    }
}

pub fn score(spec: ProviderSpec, cases: &[TaskCase], outcomes: Vec<Outcome>) -> ModelScore {
    let classes = TaskClass::ALL
        .iter()
        .map(|&class| {
            let mut scored = 0usize;
            let mut parity = 0usize;
            let mut not_scored = 0usize;
            for (outcome, case) in outcomes.iter().zip(cases) {
                if outcome.class != class {
                    continue;
                }
                match outcome.parity(case) {
                    Some(true) => parity += 1,
                    Some(false) => {}
                    None => not_scored += 1,
                }
                scored += 1;
            }
            let parity_permille = (parity * 1000).checked_div(scored).unwrap_or(0) as u16;
            ClassScore {
                class,
                scored,
                not_scored,
                parity_permille,
                threshold_permille: class.threshold_permille(),
                meets_gate: scored > 0 && parity_permille >= class.threshold_permille(),
            }
        })
        .collect();
    ModelScore {
        spec,
        outcomes,
        classes,
    }
}

pub fn run(provider: &dyn ModelProvider, cases: &[TaskCase]) -> ModelScore {
    let outcomes = cases
        .iter()
        .map(|case| {
            let pair = prompts(case);
            Outcome {
                task: case.id.clone(),
                class: case.class,
                baseline: provider.complete(&pair.baseline),
                compressed: provider.complete(&pair.compressed),
            }
        })
        .collect();
    score(provider.spec(), cases, outcomes)
}

pub fn command_providers(command: &str) -> Vec<Injected> {
    let argv: Vec<String> = command.split_whitespace().map(str::to_string).collect();
    PROVIDERS
        .iter()
        .map(|spec| Injected::command(*spec, argv.clone()))
        .collect()
}

pub fn build_cases(options: &ResolvedOptions) -> Vec<TaskCase> {
    let mut compressor = Compressor::new();
    let mut out = Vec::new();
    let mut cases = Vec::new();
    for (name, schema, target) in [
        (
            "chat",
            quantification_core::sniff::Schema::Chat,
            crate::corpus::LOG_HEAVY_TARGET,
        ),
        (
            "text",
            quantification_core::sniff::Schema::Text,
            crate::corpus::LOG_HEAVY_SMALL,
        ),
    ] {
        let payload = Payload {
            name: format!("log_heavy/{name}"),
            stratum: Stratum::LogHeavy,
            bytes: build(schema, target, crate::corpus::SEED ^ 0x7A5C),
        };
        compressor.compress(&payload.bytes, options, &mut out);
        let compressed = out.clone();
        let facts = facts_of(&log_text(&payload.bytes, options.scope_policy));
        for class in TaskClass::ALL {
            let (question, wanted) = question_for(class, &facts);
            cases.push(TaskCase {
                id: format!("{name}/{}", class.as_str()),
                class,
                question,
                facts: wanted,
                payload: payload.bytes.clone(),
                compressed: compressed.clone(),
            });
        }
    }
    cases
}

pub fn log_text(payload: &[u8], policy: ScopePolicy) -> String {
    let span = locate(payload, policy)
        .spans
        .first()
        .map(|span| &payload[span.start..span.end])
        .unwrap_or(payload);
    unescape(&String::from_utf8_lossy(span))
}

pub fn unescape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('u') => {
                let hex: String = chars.by_ref().take(4).collect();
                match u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    Some(decoded) => out.push(decoded),
                    None => out.push_str(&hex),
                }
            }
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

fn facts_of(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let completed = lines
        .iter()
        .find(|line| line.contains("request completed"))
        .and_then(|line| field(line, "path"))
        .unwrap_or_default();
    let warns = lines
        .iter()
        .filter(|line| line.contains(" WARN "))
        .count()
        .to_string();
    let trace = lines
        .iter()
        .find(|line| line.contains("at parseRow"))
        .copied()
        .unwrap_or_default();
    let function = trace
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();
    vec![
        completed,
        warns,
        function,
        paren(trace).unwrap_or_default(),
        "orders".to_string(),
        "cache miss".to_string(),
        "query".to_string(),
    ]
}

fn question_for(class: TaskClass, facts: &[String]) -> (String, Vec<String>) {
    match class {
        TaskClass::RowLookup => (
            "Report only the value of the path field of the first line that says \
             `request completed`."
                .to_string(),
            vec![facts[0].clone()],
        ),
        TaskClass::CountAggregate => (
            "Report only the number of lines that carry the level WARN.".to_string(),
            vec![facts[1].clone()],
        ),
        TaskClass::AnomalySpotting => (
            "Report only the failing Go function name and the source file it is in, one per \
             line, nothing else."
                .to_string(),
            vec![facts[2].clone(), facts[3].clone()],
        ),
        TaskClass::Summarization => (
            "In at most two sentences, summarise what this log is about: name the recurring \
             components and the request handler."
                .to_string(),
            vec![facts[4].clone(), facts[5].clone(), facts[6].clone()],
        ),
    }
}

fn field(line: &str, key: &str) -> Option<String> {
    let at = line.find(&format!("{key}="))? + key.len() + 1;
    let at = at + usize::from(line[at..].starts_with('\\'));
    let end = at + 1 + line[at + 1..].find('"')?;
    Some(line[at..end].to_string())
}

fn paren(line: &str) -> Option<String> {
    let start = line.find('(')? + 1;
    let end = line[start..].find(')')? + start;
    Some(line[start..end].to_string())
}

pub fn task_table(score: &ModelScore) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "| task class | agreement | tasks | parity | provisional gate | verdict |"
    );
    let _ = writeln!(out, "|---|---|---|---|---|---|");
    for class in &score.classes {
        let _ = writeln!(
            out,
            "| {} | {:?} | {} scored, {} unscored | {} | >= {}% | {} |",
            class.class.as_str(),
            class.class.agreement(),
            class.scored,
            class.not_scored,
            crate::metric::percent(class.parity_permille),
            class.threshold_permille / 10,
            if class.scored == 0 || class.not_scored == class.scored {
                "NOT MEASURED: no model answered"
            } else if class.meets_gate {
                "meets the provisional gate"
            } else {
                "below the provisional gate"
            }
        );
    }
    out
}
