use quantification_eval::corpus::{Payload, Stratum, full};
use quantification_eval::metric::{measure, options, summarize};
use quantification_eval::report;
use quantification_eval::tasks::{self, ModelScore, PROVIDER_COMMAND_ENV, PROVIDERS};
use quantification_eval::tokens::{self, Baseline, Counter};

const JSON_ENV: &str = "QUANT_EVAL_JSON";
const VERDICT: &str = "M4 REPORT-ONLY: non-blocking, never gates acceptance (DESIGN.md 4.5, 12)";

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let spec = flag(&argv, "--tokenizer")
        .or_else(|| std::env::var("QUANT_EVAL_TOKENIZERS").ok())
        .unwrap_or_else(|| Baseline::DEFAULT_SPEC.to_string());
    let baselines = tokens::parse_spec(&spec).unwrap_or_else(|e| {
        eprintln!("{e}; known baselines: o200k_base, cl100k_base, bytes/4");
        std::process::exit(2);
    });
    let strata = strata(&argv);
    let payloads: Vec<Payload> = full()
        .into_iter()
        .filter(|p| strata.contains(&p.stratum))
        .collect();
    let (counters, mut unavailable) = load(&baselines);
    let eval = measure(&payloads, &counters, &options());
    if !eval.unavailable.is_empty() {
        unavailable.extend(eval.unavailable.iter().cloned());
    }
    print!("{}", report::token_report(&eval));
    let token_json = report::token_json(&eval);
    println!("\ntokenizer section: {}", tokens::unavailable());
    let (measured, reason, scores) = task_eval();
    println!();
    print!("{}", report::task_report(measured, &reason, &scores));
    let task_json = report::task_json(measured, &reason, &scores);
    if let Ok(path) = std::env::var(JSON_ENV) {
        let token_path = report::write_report(&format!("{path}.tokens.json"), &token_json);
        let task_path = report::write_report(&format!("{path}.tasks.json"), &task_json);
        println!(
            "\nreports: {} {}",
            token_path.display(),
            task_path.display()
        );
    }
    println!("\nverdict: {VERDICT}");
    if argv.iter().any(|arg| arg == "--enforce") {
        for baseline in Baseline::CANDIDATES {
            let Some(summary) = summarize(&eval, baseline, Stratum::LogHeavy) else {
                continue;
            };
            if !summary.meets_target {
                eprintln!(
                    "--enforce: {} median {} is below the provisional target",
                    baseline.as_str(),
                    summary.median_permille
                );
                std::process::exit(1);
            }
        }
    }
}

fn flag(argv: &[String], name: &str) -> Option<String> {
    let at = argv.iter().position(|a| a == name)?;
    argv.get(at + 1).cloned()
}

fn strata(argv: &[String]) -> Vec<Stratum> {
    match flag(argv, "--corpus").as_deref() {
        Some("log_heavy") => vec![Stratum::LogHeavy],
        Some("golden") => vec![Stratum::Golden],
        Some("adversarial") => vec![Stratum::Adversarial],
        Some("all") | None => Stratum::ALL.to_vec(),
        Some(other) => {
            eprintln!("unknown --corpus `{other}`; known: log_heavy, golden, adversarial, all");
            std::process::exit(2);
        }
    }
}

fn load(baselines: &[Baseline]) -> (Vec<Counter>, Vec<(Baseline, String)>) {
    let mut counters = Vec::new();
    let mut unavailable = Vec::new();
    for baseline in baselines {
        match Counter::load(*baseline) {
            Ok(counter) => counters.push(counter),
            Err(reason) => unavailable.push((*baseline, reason)),
        }
    }
    (counters, unavailable)
}

fn task_eval() -> (bool, String, Vec<ModelScore>) {
    let cases = tasks::build_cases(&options());
    let command = std::env::var(PROVIDER_COMMAND_ENV).unwrap_or_default();
    if command.trim().is_empty() {
        return (
            false,
            format!(
                "no provider was called. The model call is an injectable interface: {PROVIDER_COMMAND_ENV} \
                 must name a command that reads a prompt on stdin and writes the completion on stdout \
                 ({} provider models are declared, DESIGN.md 12 requires at least two). No \
                 credentials are present in this environment, and the task suite itself is unratified \
                 (DESIGN.md 13.5), so the parity gates are unmeasured rather than passed.",
                PROVIDERS.len()
            ),
            Vec::new(),
        );
    }
    let providers = tasks::command_providers(&command);
    let scores: Vec<ModelScore> = providers
        .iter()
        .map(|provider| tasks::run(provider, &cases))
        .collect();
    (true, format!("measured over {command}"), scores)
}
