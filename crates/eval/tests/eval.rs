use quantification_eval::corpus::{self, Stratum};
use quantification_eval::metric::{
    self, MEDIAN_TARGET_PERMILLE, measure, options, permille, summarize,
};
use quantification_eval::report;
use quantification_eval::tasks::{
    self, Agreement, ModelError, ModelProvider, PROVIDERS, TaskCase, TaskClass, build_cases, run,
};
use quantification_eval::tokens::{self, Baseline, Counter};

fn counters(baselines: &[Baseline]) -> Vec<Counter> {
    baselines
        .iter()
        .map(|baseline| Counter::load(*baseline).unwrap_or_else(|e| panic!("{e}")))
        .collect()
}

fn real_counters() -> Vec<Counter> {
    counters(&Baseline::CANDIDATES)
}

fn log_heavy() -> Vec<corpus::Payload> {
    corpus::log_heavy()
}

struct Oracle {
    spec: tasks::ProviderSpec,
    honest: bool,
}

impl ModelProvider for Oracle {
    fn spec(&self) -> tasks::ProviderSpec {
        self.spec
    }

    fn complete(&self, prompt: &str) -> Result<String, ModelError> {
        Ok(answer(prompt, self.honest))
    }
}

fn unescape(raw: &str) -> String {
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
                    None => out.push_str(&format!("\\u{hex}")),
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

fn payload_of(prompt: &str) -> String {
    let raw = prompt
        .split_once("<payload>\n")
        .and_then(|(_, rest)| rest.split_once("\n</payload>"))
        .map(|(payload, _)| payload)
        .unwrap_or_default();
    unescape(raw)
}

fn question_of(prompt: &str) -> String {
    prompt
        .rsplit_once("<question>\n")
        .map(|(_, question)| question.to_string())
        .unwrap_or_default()
}

fn answer(prompt: &str, honest: bool) -> String {
    let payload = payload_of(prompt);
    let lines: Vec<&str> = payload.lines().collect();
    let question = question_of(prompt);
    if question.contains("level WARN") {
        let warns = lines.iter().filter(|l| l.contains(" WARN ")).count();
        return if honest {
            format!("{warns}")
        } else {
            "0".to_string()
        };
    }
    if question.contains("path field") {
        if !honest {
            return "unknown path".to_string();
        }
        return lines
            .iter()
            .find(|l| l.contains("request completed"))
            .and_then(|l| l.split("path=\"").nth(1))
            .and_then(|l| l.split('"').next())
            .unwrap_or_default()
            .to_string();
    }
    if question.contains("Go function name") {
        let line = lines
            .iter()
            .find(|l| l.contains("at parseRow"))
            .copied()
            .unwrap_or_default();
        if !honest {
            return "no failure found".to_string();
        }
        let function = line.split_whitespace().nth(1).unwrap_or_default();
        let file = line
            .split_once('(')
            .and_then(|(_, rest)| rest.split_once(')'))
            .map(|(file, _)| file)
            .unwrap_or_default();
        return format!("{function}\n{file}");
    }
    if !honest {
        return "nothing of note".to_string();
    }
    let mut said = Vec::new();
    for (needle, word) in [
        ("/v1/orders", "orders"),
        ("cache miss", "cache miss"),
        ("db.query", "query"),
    ] {
        if payload.contains(needle) {
            said.push(word);
        }
    }
    format!("the log covers {}", said.join(", "))
}

#[test]
fn the_log_heavy_corpus_spans_every_schema_and_is_reproducible() {
    let corpus = log_heavy();
    assert_eq!(corpus.len(), 8, "two sizes per schema");
    for schema in [
        quantification_core::sniff::Schema::Chat,
        quantification_core::sniff::Schema::Responses,
        quantification_core::sniff::Schema::Messages,
        quantification_core::sniff::Schema::Text,
    ] {
        assert!(
            corpus.iter().filter(|p| p.schema() == Some(schema)).count() == 2,
            "no log-heavy payload for {schema:?}"
        );
    }
    for payload in &corpus {
        assert!(
            std::str::from_utf8(&payload.bytes).is_ok(),
            "{} is not utf-8: a tokenizer cannot encode it",
            payload.name
        );
        assert_eq!(payload.stratum, Stratum::LogHeavy);
    }
    let again = log_heavy();
    for (at, payload) in corpus.iter().enumerate() {
        assert_eq!(
            payload.bytes, again[at].bytes,
            "the corpus is not reproducible"
        );
    }
    assert!(corpus.iter().all(|p| p.bytes.len() > 100_000));
}

#[test]
fn the_full_corpus_reuses_the_golden_fixtures_and_the_adversarial_generators() {
    let full = corpus::full();
    assert!(full.len() > corpus::log_heavy().len() + 30);
    assert!(full.iter().any(|p| p.name.starts_with("golden/schemas/")));
    assert!(full.iter().any(|p| p.name == "adversarial/unique-lines"));
    for name in [
        "adversarial/unique-lines",
        "adversarial/giant-line",
        "adversarial/periodic-units",
        "adversarial/nested-arrays",
        "adversarial/deep-envelope-over-cap",
        "adversarial/tiny-messages",
        "adversarial/collision-neighbors",
        "adversarial/dense-records",
        "adversarial/dense-records-unique",
    ] {
        assert!(full.iter().any(|p| p.name == name), "{name} is not reused");
    }
    assert_eq!(
        full.iter()
            .filter(|p| p.stratum == Stratum::Adversarial)
            .count(),
        10,
        "the W4.4 adversarial suite is in the corpus by construction"
    );
}

#[test]
fn every_requested_real_tokenizer_baseline_loads_and_counts_text() {
    assert!(
        tokens::all_available(),
        "a real tokenizer baseline is unavailable in this environment"
    );
    let sample = "tiktoken is great!";
    for baseline in Baseline::CANDIDATES {
        let counter = Counter::load(baseline).expect("the baseline loads");
        let count = counter
            .count(sample.as_bytes())
            .expect("utf-8 is encodable");
        assert_eq!(
            count.tokens,
            6,
            "{} tokenizes the canonical sample",
            baseline.as_str()
        );
        assert_eq!(count.baseline, baseline);
        assert!(baseline.real());
    }
    let o200k = Counter::load(Baseline::O200kBase).expect("o200k");
    let cl100k = Counter::load(Baseline::Cl100kBase).expect("cl100k");
    assert_eq!(
        o200k.count(sample.as_bytes()).map(|c| c.tokens),
        cl100k.count(sample.as_bytes()).map(|c| c.tokens),
        "the two baselines agree on the sample length"
    );
    assert_ne!(
        tiktoken_rs::o200k_base()
            .expect("o200k")
            .encode_ordinary(sample),
        tiktoken_rs::cl100k_base()
            .expect("cl100k")
            .encode_ordinary(sample),
        "the two baselines are two encoders, not one measurement under two names"
    );
    let proxy = Counter::load(Baseline::BytesPerFour).expect("the proxy loads");
    assert_eq!(
        proxy.count(b"12345678").map(|c| c.tokens),
        Some(2),
        "the proxy is bytes/4"
    );
    assert!(!Baseline::BytesPerFour.real());
    assert!(
        o200k.count(&[0xff, 0xfe]).is_none(),
        "invalid utf-8 is not encoded"
    );
}

#[test]
fn the_success_metric_is_measured_with_a_real_tokenizer() {
    let eval = measure(&log_heavy(), &real_counters(), &options());
    assert_eq!(eval.measurements.len(), 8);
    for baseline in Baseline::CANDIDATES {
        let summary = summarize(&eval, baseline, Stratum::LogHeavy)
            .unwrap_or_else(|| panic!("{} produced no measurement", baseline.as_str()));
        assert_eq!(summary.cases, 8);
        for m in &eval.measurements {
            let count = m.count(baseline).expect("every payload is encodable");
            assert!(
                count.tokens_in > count.tokens_out,
                "{}: {} did not shrink",
                m.name,
                baseline.as_str()
            );
            assert_eq!(
                count.reduction_permille,
                permille(count.tokens_in, count.tokens_out)
            );
        }
        println!(
            "{} median {} (min {}, max {}) over {} log-heavy payloads",
            baseline.as_str(),
            metric::percent(summary.median_permille),
            metric::percent(summary.min_permille),
            metric::percent(summary.max_permille),
            summary.cases
        );
        assert!(
            summary.meets_target,
            "{} median {} is below the provisional {}% target",
            baseline.as_str(),
            metric::percent(summary.median_permille),
            MEDIAN_TARGET_PERMILLE / 10
        );
        assert!(!m_degrades(&eval), "a log-heavy payload degraded");
    }
}

fn m_degrades(eval: &metric::Eval) -> bool {
    eval.measurements.iter().any(|m| m.stats.degraded)
}

#[test]
fn every_detector_commits_on_the_log_heavy_corpus() {
    let eval = measure(
        &log_heavy(),
        &counters(&[Baseline::BytesPerFour]),
        &options(),
    );
    let total =
        |f: fn(&metric::Measurement) -> u64| -> u64 { eval.measurements.iter().map(f).sum() };
    assert!(total(|m| m.stats.exact_runs) > 0, "no exact run anywhere");
    assert!(total(|m| m.stats.ws_runs) > 0, "no ws-equal run anywhere");
    assert!(
        total(|m| m.stats.block_repeats) > 0,
        "no repeated block anywhere"
    );
    assert!(
        total(|m| m.stats.template_groups) > 0,
        "no template group anywhere"
    );
    assert!(
        total(|m| m.stats.templated_blocks) > 0,
        "no templated block anywhere"
    );
    assert!(
        total(|m| m.stats.record_splits) > 0,
        "no stage-1b split anywhere"
    );
    for schema in [
        quantification_core::sniff::Schema::Chat,
        quantification_core::sniff::Schema::Responses,
        quantification_core::sniff::Schema::Messages,
    ] {
        let touched = eval
            .measurements
            .iter()
            .filter(|m| m.schema == Some(schema))
            .map(metric::compressors_touched)
            .sum::<u64>();
        assert!(touched > 0, "{schema:?} committed no group at all");
    }
}

#[test]
fn the_bytes4_proxy_is_never_presented_as_a_section_12_measurement() {
    let eval = measure(
        &log_heavy(),
        &counters(&[Baseline::BytesPerFour]),
        &options(),
    );
    let summary = summarize(&eval, Baseline::BytesPerFour, Stratum::LogHeavy)
        .expect("the proxy still counts bytes");
    assert!(!summary.baseline.real());
    let text = report::token_report(&eval);
    assert!(text.contains("NOT A SECTION 12 MEASUREMENT"), "{text}");
    let json = report::token_json(&eval);
    assert!(json.contains("\"blocking\": false"));
    assert!(json.contains("\"real\":false"));
    assert!(
        !json.contains("\"meets_target\":true"),
        "the proxy must not claim the target: {json}"
    );
}

#[test]
fn a_missing_tokenizer_is_reported_as_not_measured() {
    let eval = measure(&log_heavy(), &[], &options());
    assert!(eval.baselines.is_empty());
    for m in &eval.measurements {
        assert_eq!(m.counts.len(), 0);
    }
    let text = report::token_report(&eval);
    assert!(text.contains("NOT MEASURED"), "{text}");
    assert!(tokens::unavailable_note(false).contains("NOT MEASURED"));
    assert!(tokens::unavailable_note(true).contains("never a DESIGN.md 12 measurement"));
    let json = report::token_json(&eval);
    assert!(json.contains("\"summaries\": ["), "{json}");
}

#[test]
fn the_measurement_is_reproducible() {
    let first = measure(&log_heavy(), &counters(&[Baseline::O200kBase]), &options());
    let second = measure(&log_heavy(), &counters(&[Baseline::O200kBase]), &options());
    let reductions = |eval: &metric::Eval| -> Vec<(String, u16)> {
        eval.measurements
            .iter()
            .map(|m| {
                (
                    m.name.clone(),
                    m.count(Baseline::O200kBase)
                        .expect("a count")
                        .reduction_permille,
                )
            })
            .collect()
    };
    assert_eq!(reductions(&first), reductions(&second));
    assert_eq!(
        metric::median(&mut [100, 500, 300, 200]),
        250,
        "an even count averages the two middles"
    );
    assert_eq!(metric::median(&mut [100, 500, 300]), 300);
    assert_eq!(metric::median(&mut []), 0);
}

#[test]
fn the_corpus_strata_are_reported_separately() {
    let eval = measure(&corpus::full(), &real_counters(), &options());
    for stratum in Stratum::ALL {
        for baseline in Baseline::CANDIDATES {
            let summary = summarize(&eval, baseline, stratum)
                .unwrap_or_else(|| panic!("{stratum:?} has no {} measurement", baseline.as_str()));
            assert!(summary.cases > 0);
        }
    }
    let text = report::token_report(&eval);
    for stratum in Stratum::ALL {
        assert!(
            text.contains(stratum.as_str()),
            "{stratum:?} missing from the report"
        );
    }
    assert!(text.contains("REFERENCE CORPUS IS UNRATIFIED") || text.contains("unratified"));
    assert!(text.contains("REPORTING-ONLY"));
}

#[test]
fn the_four_task_classes_carry_ground_truth_and_two_providers_are_declared() {
    let cases = build_cases(&options());
    assert_eq!(cases.len(), 8, "four classes over two payloads");
    for class in TaskClass::ALL {
        let mine: Vec<&TaskCase> = cases.iter().filter(|c| c.class == class).collect();
        assert_eq!(mine.len(), 2, "{} has no task", class.as_str());
        for case in mine {
            assert!(!case.question.is_empty());
            assert!(!case.facts.is_empty(), "{} has no ground truth", case.id);
            assert!(
                case.facts.iter().all(|f| !f.is_empty()),
                "{} carries an empty fact",
                case.id
            );
            assert_ne!(
                case.payload, case.compressed,
                "{} did not compress",
                case.id
            );
            assert!(case.compressed.len() < case.payload.len());
        }
    }
    assert_eq!(TaskClass::ALL.len(), 4);
    assert_eq!(
        PROVIDERS.len(),
        2,
        "DESIGN.md 12 requires at least two models"
    );
    let ids: Vec<&str> = PROVIDERS.iter().map(|p| p.id).collect();
    assert_eq!(ids, ["openai", "anthropic"]);
    for spec in PROVIDERS {
        assert!(spec.endpoint.starts_with("https://"));
        assert!(!spec.model.is_empty());
    }
}

#[test]
fn the_provisional_parity_thresholds_are_the_design_numbers() {
    assert_eq!(TaskClass::RowLookup.threshold_permille(), 750);
    assert_eq!(TaskClass::CountAggregate.threshold_permille(), 750);
    assert_eq!(TaskClass::AnomalySpotting.threshold_permille(), 900);
    assert_eq!(TaskClass::Summarization.threshold_permille(), 900);
    assert_eq!(TaskClass::RowLookup.agreement(), Agreement::Exact);
    assert_eq!(TaskClass::CountAggregate.agreement(), Agreement::Exact);
    assert_eq!(TaskClass::AnomalySpotting.agreement(), Agreement::Facts);
    assert_eq!(TaskClass::Summarization.agreement(), Agreement::Facts);
}

#[test]
fn answer_parity_is_scored_per_class() {
    let case = TaskCase {
        id: "row_lookup/1".to_string(),
        class: TaskClass::RowLookup,
        question: "Report only the value of the path field of the first line that says \
                   `request completed`."
            .to_string(),
        facts: vec!["/srv/app/handlers.go".to_string()],
        payload: Vec::new(),
        compressed: Vec::new(),
    };
    assert!(tasks::parity(
        &case,
        "/srv/app/handlers.go",
        "/srv/app/handlers.go"
    ));
    assert!(tasks::parity(
        &case,
        "/srv/app/handlers.go.",
        " /srv/app/handlers.go "
    ));
    assert!(
        !tasks::parity(
            &case,
            "the path is /srv/app/handlers.go",
            "/srv/app/handlers.go"
        ),
        "an exact-class answer that is not the value alone is not parity: the questions say \
         \"report only\", and a loose reading would hide a regression"
    );
    assert!(
        !tasks::parity(&case, "/srv/app/handlers.go", "the path is unknown"),
        "a compressed answer that lost the value is not parity"
    );
    assert!(
        !tasks::parity(&case, "unknown", "/srv/app/handlers.go"),
        "a baseline answer that is wrong is not parity either"
    );
    let facts = TaskCase {
        id: "summarization/1".to_string(),
        class: TaskClass::Summarization,
        question: "Summarise".to_string(),
        facts: vec!["orders".to_string(), "cache miss".to_string()],
        payload: Vec::new(),
        compressed: Vec::new(),
    };
    assert!(tasks::parity(
        &facts,
        "orders handler, many cache misses",
        "the orders handler and its cache misses"
    ));
    assert!(
        !tasks::parity(&facts, "orders handler", "the cache misses"),
        "both answers must carry every expected fact"
    );
    assert_eq!(tasks::normalize("A: 42 (ms)!"), "a42ms");
}

fn parity_of(score: &tasks::ModelScore, class: TaskClass) -> u16 {
    score
        .classes
        .iter()
        .find(|c| c.class == class)
        .unwrap_or_else(|| panic!("no {class:?} class"))
        .parity_permille
}

#[test]
fn an_injected_provider_is_scored_per_class_and_per_model() {
    let cases = build_cases(&options());
    for spec in PROVIDERS {
        for honest in [true, false] {
            let oracle = Oracle { spec, honest };
            let score = run(&oracle, &cases);
            assert_eq!(score.outcomes.len(), cases.len());
            assert_eq!(score.classes.len(), 4);
            assert!(score.errors().is_empty());
            for class in &score.classes {
                assert_eq!(
                    class.scored,
                    2,
                    "{} was not scored twice",
                    class.class.as_str()
                );
                assert_eq!(class.not_scored, 0);
            }
            if honest {
                assert_eq!(
                    parity_of(&score, TaskClass::RowLookup),
                    1000,
                    "{}: the row lookup answer survives compaction",
                    spec.id
                );
                assert_eq!(
                    parity_of(&score, TaskClass::AnomalySpotting),
                    1000,
                    "{}: the panic trace survives compaction",
                    spec.id
                );
                assert_eq!(
                    parity_of(&score, TaskClass::Summarization),
                    1000,
                    "{}: the anchors keep the summary facts",
                    spec.id
                );
                assert_eq!(
                    parity_of(&score, TaskClass::CountAggregate),
                    500,
                    "{}: counting is the class that loses, and these numbers come from a stub \
                     oracle, not from a model",
                    spec.id
                );
            } else {
                for class in TaskClass::ALL {
                    assert_eq!(
                        parity_of(&score, class),
                        0,
                        "{} scored a wrong answer as parity in {}",
                        spec.id,
                        class.as_str()
                    );
                }
                assert_eq!(score.overall_permille(), 0, "{} lying parity", spec.id);
            }
            assert!(
                !score.meets_every_gate(),
                "{}: the counting class is below its provisional gate",
                spec.id
            );
        }
    }
}

#[test]
fn a_full_parity_score_meets_every_provisional_gate() {
    let cases: Vec<TaskCase> = TaskClass::ALL
        .iter()
        .map(|class| TaskCase {
            id: format!("synthetic/{}", class.as_str()),
            class: *class,
            question: "q".to_string(),
            facts: vec!["answer".to_string()],
            payload: Vec::new(),
            compressed: Vec::new(),
        })
        .collect();
    let good: Vec<tasks::Outcome> = cases
        .iter()
        .map(|case| tasks::Outcome {
            task: case.id.clone(),
            class: case.class,
            baseline: Ok("answer".to_string()),
            compressed: Ok("answer".to_string()),
        })
        .collect();
    let perfect = tasks::score(PROVIDERS[0], &cases, good);
    assert_eq!(perfect.overall_permille(), 1000);
    assert!(
        perfect.meets_every_gate(),
        "{}",
        tasks::task_table(&perfect)
    );
    let half: Vec<tasks::Outcome> = cases
        .iter()
        .map(|case| tasks::Outcome {
            task: case.id.clone(),
            class: case.class,
            baseline: Ok("answer".to_string()),
            compressed: if case.class == TaskClass::Summarization {
                Ok("something else".to_string())
            } else {
                Ok("answer".to_string())
            },
        })
        .collect();
    let mixed = tasks::score(PROVIDERS[0], &cases, half);
    assert!(!mixed.meets_every_gate());
    assert!(
        !mixed
            .classes
            .iter()
            .any(|c| c.class == TaskClass::Summarization && c.meets_gate)
    );
    assert!(
        mixed
            .classes
            .iter()
            .any(|c| c.class == TaskClass::RowLookup && c.meets_gate)
    );
}

#[test]
fn a_compression_that_destroys_the_answer_costs_parity() {
    let cases = build_cases(&options());
    let oracle = Oracle {
        spec: PROVIDERS[0],
        honest: true,
    };
    let score = run(&oracle, &cases);
    println!("{}", tasks::task_table(&score));
    for (outcome, case) in score.outcomes.iter().zip(&cases) {
        println!(
            "  {} parity={:?} baseline={:?} compressed={:?}",
            outcome.task,
            outcome.parity(case),
            outcome.baseline.as_ref().map(|a| a.replace('\n', " | ")),
            outcome.compressed.as_ref().map(|a| a.replace('\n', " | "))
        );
    }
    assert_eq!(
        parity_of(&score, TaskClass::CountAggregate),
        500,
        "one payload loses the WARN count to compaction, which is the extraction and counting \
         class DESIGN.md 12 puts at 75%; the other is the plain-text payload, whose single unit \
         barely compresses"
    );
    let chat = score
        .outcomes
        .iter()
        .find(|o| o.task == "chat/count_aggregate")
        .expect("the chat counting task");
    assert_ne!(
        chat.baseline.as_ref().ok(),
        chat.compressed.as_ref().ok(),
        "the counting answer changed when the payload was compressed"
    );
    assert_eq!(
        parity_of(&score, TaskClass::AnomalySpotting),
        1000,
        "the panic trace survives compaction, so the anomaly class keeps parity"
    );
}

#[test]
fn a_failing_provider_call_is_not_scored_as_parity() {
    let cases = build_cases(&options());
    let broken = tasks::Injected::new(PROVIDERS[0], |prompt: &str| {
        Err(ModelError::new(
            PROVIDERS[0].id,
            format!("no route for {} bytes", prompt.len()),
        ))
    });
    let score = run(&broken, &cases);
    for class in &score.classes {
        assert_eq!(class.scored, 2);
        assert_eq!(class.not_scored, 2);
        assert_eq!(class.parity_permille, 0);
        assert!(
            !class.meets_gate,
            "an unanswered class must not meet its gate"
        );
    }
    assert_eq!(score.errors().len(), 16);
    let table = tasks::task_table(&score);
    assert!(table.contains("NOT MEASURED"), "{table}");
}

#[test]
fn the_command_transport_pipes_the_prompt_and_reports_a_missing_program() {
    let echo = tasks::Injected::command(
        PROVIDERS[0],
        vec!["/bin/sh".to_string(), "-c".to_string(), "cat".to_string()],
    );
    let answer = echo.complete("prompt body").expect("the echo answers");
    assert_eq!(answer, "prompt body");
    let big = "x".repeat(4 << 20);
    assert_eq!(
        echo.complete(&big)
            .expect("a prompt larger than a pipe buffer"),
        big,
        "the transport must not deadlock on a payload-sized prompt"
    );
    let failing = tasks::Injected::command(
        PROVIDERS[1],
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "exit 3".to_string(),
        ],
    );
    let error = failing
        .complete("x")
        .expect_err("a non-zero exit must fail");
    assert!(error.reason.contains("exited with"), "{}", error.reason);
    let missing = tasks::Injected::command(
        PROVIDERS[0],
        vec!["/nonexistent/quant-eval-provider".to_string()],
    );
    let error = missing
        .complete("x")
        .expect_err("a missing program must fail");
    assert_eq!(error.provider, "openai");
    assert!(error.reason.contains("cannot spawn"), "{}", error.reason);
    let empty = tasks::Injected::command(PROVIDERS[1], Vec::new());
    assert!(empty.complete("x").is_err());
    let providers = tasks::command_providers("/bin/sh -c cat");
    assert_eq!(providers.len(), 2);
    assert_eq!(providers[1].spec().id, "anthropic");
}

#[test]
fn the_task_report_says_not_measured_when_no_provider_was_called() {
    let text = report::task_report(false, "no provider was called", &[]);
    assert!(text.contains("NOT MEASURED"), "{text}");
    assert!(text.contains("no model was called"), "{text}");
    assert!(text.contains("REPORTING-ONLY"), "{text}");
    for class in TaskClass::ALL {
        assert!(text.contains(class.as_str()), "{} missing", class.as_str());
        assert!(text.contains(class.gate_label()));
    }
    let json = report::task_json(false, "no provider was called", &[]);
    assert!(json.contains("\"measured\": false"));
    assert!(json.contains("\"blocking\": false"));
    assert!(json.contains("\"models\": []"), "{json}");
    assert!(json.starts_with("{\n") && json.ends_with("}\n"));
}

#[test]
fn the_prompt_pair_carries_the_same_question_over_both_payloads() {
    let cases = build_cases(&options());
    let case = &cases[0];
    let pair = tasks::prompts(case);
    assert!(pair.baseline.contains(&case.question));
    assert!(pair.compressed.contains(&case.question));
    assert!(pair.baseline.len() > pair.compressed.len());
    let question_of = |prompt: &str| {
        prompt
            .rsplit_once("<question>\n")
            .map(|(_, q)| q.to_string())
            .expect("a question block")
    };
    assert_eq!(question_of(&pair.baseline), question_of(&pair.compressed));
    assert!(pair.compressed.contains("xN") || pair.compressed.contains('\u{27ea}'));
}

#[test]
fn the_json_reports_are_shaped_for_a_ci_report() {
    let eval = measure(&log_heavy(), &real_counters(), &options());
    let json = report::token_json(&eval);
    assert!(json.starts_with("{\n") && json.ends_with("}\n"));
    assert!(json.contains("\"harness\": \"w4.6-token-reduction\""));
    assert!(json.contains("\"blocking\": false"));
    assert!(json.contains("\"target_permille\": 400"));
    assert!(!json.contains(",\n]"), "trailing comma: {json}");
    assert!(!json.contains(",\n}"), "trailing comma: {json}");
    assert!(json.contains("\"baseline\":\"o200k_base\""));
    let text = report::token_report(&eval);
    assert!(text.contains("tokenizer baseline"));
    assert!(text.contains("meets the provisional target"));
}
