#[path = "adversarial_fixtures.rs"]
mod fixtures;
#[path = "determinism_harness.rs"]
mod harness;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use harness::Case;
use quantification_core::config::resolve;
use quantification_core::fingerprint::fingerprint;
use quantification_core::pipeline::Compressor;
use quantification_core::sniff::{Schema, sniff};

const CORPUS: &[&str] = &[
    "schemas/chat-minified.json",
    "schemas/chat-pretty.json",
    "schemas/messages-minified.json",
    "schemas/messages-pretty.json",
    "schemas/responses-minified.json",
    "schemas/responses-pretty.json",
    "schemas/text-plain.txt",
    "shapes/anthropic-system-top.json",
    "shapes/anthropic-tool-result.json",
    "shapes/chat-content-null.json",
    "shapes/chat-mixed-parts.json",
    "shapes/responses-function-call-output.json",
    "shapes/responses-input-string.json",
    "shapes/sniff-overlap-chat-responses.json",
    "edges/bom-chat.json",
    "edges/dup-keys-last-wins.json",
    "edges/escaped-structural-keys.json",
    "edges/newlines-u000a-only.json",
    "edges/prior-markers.json",
    "edges/profitability-below-threshold.json",
    "edges/single-line-tool-dump-overcap.json",
    "edges/single-line-tool-dump-small.json",
    "edges/stage1b-no-separator-overcap.json",
    "edges/stage1b-record-len-16383.json",
    "edges/stage1b-record-len-16384.json",
    "edges/stage1b-record-len-16385.json",
];

const SCHEMAS: [Schema; 4] = [
    Schema::Chat,
    Schema::Responses,
    Schema::Messages,
    Schema::Text,
];
const LEGS: [&str; 3] = ["baseline", "avx2", "neon"];
const GATE_CHILD: &str = "gate_child_writes_the_corpus_outputs";
const REPORT_ENV: &str = "QUANT_GATE_REPORT";
const ISA_DIGEST_ENV: &str = "QUANT_ISA_DIGEST";
const ISA_DIR_ENV: &str = "QUANT_ISA_DIR";
const FUZZ_CHILD: &str = "fuzz_child_writes_the_input_digests";
const FUZZ_DIR_ENV: &str = "QUANT_FUZZ_CORPUS";
const FUZZ_REPORT_ENV: &str = "QUANT_FUZZ_REPORT";
const SOAK_TOTAL_ENV: &str = "QUANT_SOAK_TOTAL";
const SOAK_CHUNKS_ENV: &str = "QUANT_SOAK_CHUNKS";
const SOAK_CHUNK_ENV: &str = "QUANT_SOAK_CHUNK";
const SOAK_DIR_ENV: &str = "QUANT_SOAK_DIR";
const SOAK_DEFAULT: usize = 200_000;

fn defaults() -> quantification_core::config::ResolvedOptions {
    resolve(&quantification_core::config::RawOptions::default()).expect("the default options")
}

fn corpus() -> Vec<Case> {
    let mut out = harness::cases(CORPUS);
    for case in fixtures::gate_suite() {
        out.push(Case {
            name: case.name.to_string(),
            payload: case.payload,
        });
    }
    out
}

fn digest(bytes: &[u8]) -> String {
    format!("{:032x}", fingerprint(bytes))
}

fn fold(into: &mut String, cases: &[Case], outputs: &[Vec<u8>]) {
    for (case, out) in cases.iter().zip(outputs) {
        let _ = writeln!(into, "{} {}", case.name, digest(out));
    }
}

fn env_usize(name: &str, fallback: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(fallback)
}

fn read_report(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn read_text(path: &Path) -> String {
    String::from_utf8(read_report(path)).expect("a utf-8 report")
}

fn dir_env(name: &str) -> PathBuf {
    PathBuf::from(
        std::env::var(name).unwrap_or_else(|_| panic!("{name} must name the report directory")),
    )
}

#[test]
fn the_gate_corpus_covers_every_schema_and_is_not_vacuous() {
    let cases = corpus();
    assert!(
        cases.len() >= CORPUS.len() + 10,
        "the golden corpus and the adversarial cases are both in the gate corpus"
    );
    for schema in SCHEMAS {
        assert!(
            cases
                .iter()
                .any(|case| sniff(&case.payload) == Some(schema)),
            "no {schema:?} payload in the gate corpus"
        );
    }
    assert!(
        cases
            .iter()
            .any(|case| case.name.starts_with("adversarial/")),
        "the adversarial cases are missing from the gate corpus"
    );
    let first = harness::compress_all(&cases);
    for _ in 0..8 {
        assert_eq!(
            harness::compress_all(&cases),
            first,
            "the corpus is not stable"
        );
    }
    let golden_changed = (0..CORPUS.len())
        .filter(|at| first[*at] != cases[*at].payload)
        .count();
    assert!(
        golden_changed >= 8,
        "only {golden_changed} of {} golden fixtures change: the gate would be vacuous",
        CORPUS.len()
    );
    let adversarial = &cases[CORPUS.len()..];
    let adversarial_changed = adversarial
        .iter()
        .enumerate()
        .filter(|(at, case)| first[CORPUS.len() + at] != case.payload)
        .count();
    assert!(
        adversarial_changed >= 3,
        "only {adversarial_changed} of {} adversarial cases change: the gate is half empty",
        adversarial.len()
    );
    println!(
        "gate corpus: {} entries, {golden_changed} golden and {adversarial_changed} adversarial compress",
        cases.len()
    );
}

#[test]
fn gate_child_writes_the_corpus_outputs() {
    let Ok(path) = std::env::var(REPORT_ENV) else {
        return;
    };
    let cases = corpus();
    let report = harness::report_bytes(&cases, &harness::compress_all(&cases));
    std::fs::write(path, report).expect("the child writes its report");
}

#[test]
fn gate_outputs_are_identical_in_fresh_processes_under_varied_threads_and_locales() {
    harness::assert_fresh_processes_agree(GATE_CHILD, REPORT_ENV, &corpus(), 8);
}

#[test]
#[ignore = "the DESIGN.md 5.8 quick gate: 1000 runs, driven by CI"]
fn gate_outputs_are_byte_stable_over_1000_runs() {
    let cases = corpus();
    let first = harness::compress_all(&cases);
    let start = std::time::Instant::now();
    for run in 0..1000u32 {
        let outputs = harness::compress_all(&cases);
        for (at, (out, want)) in outputs.iter().zip(&first).enumerate() {
            assert_eq!(out, want, "run {run} of {} differs", cases[at].name);
        }
    }
    let elapsed = start.elapsed();
    println!(
        "1000 runs over {} entries ({} bytes) in {elapsed:?}",
        cases.len(),
        cases.iter().map(|case| case.payload.len()).sum::<usize>()
    );
    let changed = first
        .iter()
        .enumerate()
        .filter(|(at, out)| *out != &cases[*at].payload)
        .count();
    assert!(
        changed >= 8,
        "only {changed} entries compress: the gate is vacuous"
    );
}

#[test]
#[ignore = "the DESIGN.md 5.8 nightly soak: 200000 runs, driven by CI in chunks"]
fn nightly_soak_chunk_is_byte_stable() {
    let dir = dir_env(SOAK_DIR_ENV);
    let total = env_usize(SOAK_TOTAL_ENV, SOAK_DEFAULT);
    let chunks = env_usize(SOAK_CHUNKS_ENV, 1).max(1);
    let chunk = env_usize(SOAK_CHUNK_ENV, 0);
    assert!(chunk < chunks, "chunk {chunk} of {chunks}");
    let cases = corpus();
    let reference = harness::compress_all(&cases);
    let mut reference_digest = String::new();
    fold(&mut reference_digest, &cases, &reference);
    let runs = total / chunks + usize::from(chunk < total % chunks);
    let start = std::time::Instant::now();
    let mut mismatches = 0usize;
    let mut fold_digest = String::new();
    for run in 0..runs {
        let outputs = harness::compress_all(&cases);
        for (at, (out, want)) in outputs.iter().zip(&reference).enumerate() {
            if out != want {
                mismatches += 1;
                println!("run {run} of {} differs", cases[at].name);
            }
        }
        if run % 16 == 0 {
            fold(&mut fold_digest, &cases, &outputs);
        }
    }
    let mut report = String::new();
    let _ = writeln!(report, "chunk {chunk}");
    let _ = writeln!(report, "chunks {chunks}");
    let _ = writeln!(report, "runs {runs}");
    let _ = writeln!(report, "mismatches {mismatches}");
    let _ = writeln!(report, "entries {}", cases.len());
    let _ = writeln!(report, "reference {}", digest(reference_digest.as_bytes()));
    let _ = writeln!(report, "observed {}", digest(fold_digest.as_bytes()));
    let _ = writeln!(report, "elapsed_s {}", start.elapsed().as_secs());
    std::fs::create_dir_all(&dir).expect("the soak dir");
    std::fs::write(dir.join(format!("soak-{chunk:03}.report")), report)
        .expect("the chunk writes its report");
    assert_eq!(
        mismatches, 0,
        "chunk {chunk} saw {mismatches} differing runs"
    );
    println!(
        "chunk {chunk} of {chunks}: {runs} runs in {:?}",
        start.elapsed()
    );
}

#[test]
#[ignore = "the aggregate half of the nightly soak, driven by CI"]
fn the_soak_chunks_add_up_to_the_whole_run_count() {
    let dir = dir_env(SOAK_DIR_ENV);
    let total = env_usize(SOAK_TOTAL_ENV, SOAK_DEFAULT);
    let chunks = env_usize(SOAK_CHUNKS_ENV, 1).max(1);
    let mut runs = 0usize;
    let mut mismatches = 0usize;
    let mut references = Vec::new();
    let mut observed = Vec::new();
    let mut entries = Vec::new();
    for chunk in 0..chunks {
        let path = dir.join(format!("soak-{chunk:03}.report"));
        let text = read_text(&path);
        let field = |key: &str| -> String {
            text.lines()
                .find_map(|line| line.strip_prefix(&format!("{key} ")))
                .unwrap_or_else(|| panic!("{} has no {key} line", path.display()))
                .to_string()
        };
        assert_eq!(field("chunk"), chunk.to_string());
        assert_eq!(field("chunks"), chunks.to_string());
        runs += field("runs").parse::<usize>().expect("a run count");
        mismatches += field("mismatches")
            .parse::<usize>()
            .expect("a mismatch count");
        references.push(field("reference"));
        observed.push(field("observed"));
        entries.push(field("entries"));
    }
    assert_eq!(
        runs, total,
        "{runs} runs over {chunks} chunks is not {total}"
    );
    assert_eq!(
        mismatches, 0,
        "{mismatches} runs differed from the reference"
    );
    for (what, folds) in [("reference", &references), ("observed", &observed)] {
        assert!(
            folds.iter().all(|fold| *fold == folds[0]),
            "the chunks disagree on the {what} corpus: {folds:?}"
        );
    }
    assert!(
        entries.iter().all(|count| *count == entries[0]),
        "the chunks disagree on the corpus: {entries:?}"
    );
    println!(
        "{runs} runs over {chunks} chunks, {} entries, reference {}",
        entries[0], references[0]
    );
}

#[test]
fn isa_child_writes_the_corpus_digest() {
    let Ok(path) = std::env::var(ISA_DIGEST_ENV) else {
        return;
    };
    let cases = corpus();
    let mut out = String::new();
    fold(&mut out, &cases, &harness::compress_all(&cases));
    std::fs::write(path, out).expect("the child writes its digest");
}

#[cfg(target_arch = "x86_64")]
fn available(leg: &str) -> bool {
    match leg {
        "baseline" => true,
        "avx2" => std::arch::is_x86_feature_detected!("avx2"),
        _ => false,
    }
}

#[cfg(target_arch = "aarch64")]
fn available(leg: &str) -> bool {
    match leg {
        "baseline" => true,
        "neon" => std::arch::is_aarch64_feature_detected!("neon"),
        _ => false,
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn available(leg: &str) -> bool {
    panic!("an unknown host architecture has no leg to run, {leg} cannot");
}

#[test]
fn the_isa_legs_of_this_host_are_reported() {
    let mut reported = Vec::new();
    for leg in LEGS {
        let available = available(leg);
        println!(
            "leg {leg}: {}",
            if available {
                "AVAILABLE on this host"
            } else {
                "UNAVAILABLE on this host"
            }
        );
        reported.push(leg);
    }
    assert_eq!(reported, LEGS, "every leg of the matrix is reported");
    assert!(available("baseline"), "the baseline leg runs everywhere");
}

#[test]
#[ignore = "the DESIGN.md 5.9 CPU-feature matrix, one build per leg, driven by CI"]
fn the_available_isa_legs_agree_byte_for_byte() {
    let dir = dir_env(ISA_DIR_ENV);
    let cases = corpus();
    let mut ran: Vec<(&str, String)> = Vec::new();
    let mut missing: Vec<(&str, String)> = Vec::new();
    for leg in LEGS {
        let body = dir.join(format!("{leg}.txt"));
        let reason = dir.join(format!("{leg}.unavailable"));
        match (body.exists(), reason.exists()) {
            (true, false) => ran.push((leg, read_text(&body))),
            (false, true) => missing.push((leg, read_text(&reason))),
            _ => panic!(
                "leg {leg} neither ran nor said why it could not: the matrix must report an unavailable leg, never skip it"
            ),
        }
    }
    assert!(!ran.is_empty(), "no leg of the matrix ran");
    for (leg, fold) in ran.iter().skip(1) {
        assert_eq!(
            fold, &ran[0].1,
            "the {leg} build diverges from the {} build",
            ran[0].0
        );
    }
    for (leg, fold) in &ran {
        let names: Vec<&str> = fold
            .lines()
            .map(|line| line.split(' ').next().expect("a corpus name"))
            .collect();
        assert_eq!(
            names,
            cases
                .iter()
                .map(|case| case.name.as_str())
                .collect::<Vec<_>>(),
            "the {leg} digest must cover the whole gate corpus"
        );
    }
    for (leg, reason) in &missing {
        println!("leg {leg}: UNAVAILABLE: {reason}");
    }
    for (leg, fold) in &ran {
        let build = dir.join(format!("{leg}.build"));
        println!(
            "leg {leg}: ran, {}{}",
            fold.lines().count(),
            if build.exists() {
                format!(", build: {}", read_text(&build).replace('\n', " "))
            } else {
                String::new()
            }
        );
    }
    println!(
        "isa matrix: {} of {} legs ran and agree, {} reported unavailable",
        ran.len(),
        LEGS.len(),
        missing.len()
    );
}

fn fuzz_inputs(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut targets: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| entry.expect("a corpus target dir").path())
        .collect();
    targets.sort();
    for target in targets {
        if !target.is_dir() {
            continue;
        }
        let mut files: Vec<PathBuf> = std::fs::read_dir(&target)
            .unwrap_or_else(|e| panic!("{}: {e}", target.display()))
            .map(|entry| entry.expect("a corpus file").path())
            .collect();
        files.sort();
        out.extend(files);
    }
    out
}

#[test]
fn fuzz_child_writes_the_input_digests() {
    let (Ok(dir), Ok(path)) = (std::env::var(FUZZ_DIR_ENV), std::env::var(FUZZ_REPORT_ENV)) else {
        return;
    };
    let mut out = String::new();
    let mut compressor = Compressor::new();
    let mut bytes = Vec::new();
    for file in fuzz_inputs(&PathBuf::from(dir)) {
        let input = read_report(&file);
        compressor.compress(&input, &defaults(), &mut bytes);
        let _ = writeln!(
            out,
            "{} {} {} {}",
            file.display(),
            input.len(),
            bytes.len(),
            digest(&bytes)
        );
    }
    std::fs::write(path, out).expect("the child writes its report");
}

#[test]
#[ignore = "the DESIGN.md 5.8 fuzz determinism leg, driven by CI nightly"]
fn every_retained_fuzz_input_is_byte_equal_in_two_fresh_processes() {
    let dir = dir_env(FUZZ_DIR_ENV);
    let inputs = fuzz_inputs(&dir);
    assert!(!inputs.is_empty(), "{} holds no input", dir.display());
    let reports = harness::report_dir("fuzz-determinism");
    let mut written: Vec<PathBuf> = Vec::new();
    for leg in ["process-a", "process-b"] {
        let path = reports.join(format!("{leg}-{}.report", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let _ = harness::run_child(
            FUZZ_CHILD,
            &[
                (FUZZ_DIR_ENV, dir.to_str().expect("a utf-8 corpus dir")),
                (FUZZ_REPORT_ENV, path.to_str().expect("a utf-8 report path")),
            ],
        );
        written.push(path);
    }
    let first = read_text(&written[0]);
    assert_eq!(
        first,
        read_text(&written[1]),
        "two fresh processes disagree over {} retained fuzz inputs",
        inputs.len()
    );
    let mut compressor = Compressor::new();
    let mut bytes = Vec::new();
    let mut compressed = 0usize;
    for (at, line) in first.lines().enumerate() {
        let mut fields = line.split(' ');
        let (file, len, out_len, out_digest) = (
            fields.next().expect("a file"),
            fields.next().expect("an input length"),
            fields.next().expect("an output length"),
            fields.next().expect("an output digest"),
        );
        assert!(fields.next().is_none(), "four fields per line");
        let input = read_report(Path::new(file));
        compressor.compress(&input, &defaults(), &mut bytes);
        assert_eq!(input.len().to_string(), len, "line {at}");
        assert_eq!(bytes.len().to_string(), out_len, "line {at}");
        assert_eq!(digest(&bytes), out_digest, "line {at}");
        if bytes != input {
            compressed += 1;
        }
    }
    assert_eq!(
        first.lines().count(),
        inputs.len(),
        "every retained input is reported exactly once"
    );
    println!(
        "{} retained fuzz inputs, {compressed} of which compress, byte-equal in two fresh processes",
        inputs.len()
    );
}
