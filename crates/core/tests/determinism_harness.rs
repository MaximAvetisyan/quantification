#![allow(dead_code)]

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;

use quantification_core::config::{RawOptions, ResolvedOptions, resolve};
use quantification_core::pipeline::Compressor;

pub struct Case {
    pub name: String,
    pub payload: Vec<u8>,
}

pub fn defaults() -> ResolvedOptions {
    resolve(&RawOptions::default()).expect("the default options resolve")
}

pub fn root(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

pub fn fixture(rel: &str) -> Vec<u8> {
    let path = root(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

pub fn cases(rels: &[&str]) -> Vec<Case> {
    rels.iter()
        .map(|rel| Case {
            name: (*rel).to_string(),
            payload: fixture(rel),
        })
        .collect()
}

pub fn compress_all(cases: &[Case]) -> Vec<Vec<u8>> {
    let mut compressor = Compressor::new();
    let mut out = Vec::new();
    cases
        .iter()
        .map(|case| {
            compressor.compress(&case.payload, &defaults(), &mut out);
            out.clone()
        })
        .collect()
}

pub fn seed_fingerprint() -> String {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u8(0);
    format!("{:016x}", hasher.finish())
}

pub const PROFILES: [(&str, &[(&str, &str)]); 3] = [
    (
        "profile-a",
        &[
            ("RUST_BACKTRACE", "0"),
            ("RAYON_NUM_THREADS", "1"),
            ("RUST_TEST_THREADS", "1"),
            ("LC_ALL", "C"),
            ("LANG", "C"),
            ("TZ", "UTC"),
        ],
    ),
    (
        "profile-b",
        &[
            ("RUST_BACKTRACE", "full"),
            ("RAYON_NUM_THREADS", "8"),
            ("RUST_TEST_THREADS", "4"),
            ("LC_ALL", "C.UTF-8"),
            ("LANG", "C.UTF-8"),
            ("TZ", "Pacific/Auckland"),
        ],
    ),
    (
        "profile-c",
        &[
            ("RAYON_NUM_THREADS", "3"),
            ("RUST_TEST_THREADS", "2"),
            ("LC_ALL", "tr_TR.UTF-8"),
            ("LANG", "tr_TR.UTF-8"),
            ("TZ", "Asia/Kolkata"),
        ],
    ),
];

pub fn report_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("quantification-gate-{tag}"));
    std::fs::create_dir_all(&dir).expect("the report dir");
    dir
}

pub struct Report {
    pub seed: String,
    pub entries: Vec<(String, Vec<u8>)>,
}

pub fn report_bytes(cases: &[Case], outputs: &[Vec<u8>]) -> Vec<u8> {
    let mut report = format!("seed {}\n", seed_fingerprint()).into_bytes();
    for (case, out) in cases.iter().zip(outputs) {
        report.extend_from_slice(case.name.as_bytes());
        report.push(b'\n');
        report.extend_from_slice(out.len().to_string().as_bytes());
        report.push(b'\n');
        report.extend_from_slice(out);
        report.push(b'\n');
    }
    report
}

pub fn parse_report(bytes: &[u8]) -> Report {
    let line = |from: &mut usize| -> String {
        let rest = &bytes[*from..];
        let end = rest
            .iter()
            .position(|byte| *byte == b'\n')
            .expect("a line end");
        let text = String::from_utf8(rest[..end].to_vec()).expect("a utf-8 line");
        *from += end + 1;
        text
    };
    let mut at = 0usize;
    let seed = line(&mut at)
        .strip_prefix("seed ")
        .expect("the seed line")
        .to_string();
    let mut entries = Vec::new();
    while at < bytes.len() {
        let name = line(&mut at);
        let len: usize = line(&mut at).parse().expect("a byte count");
        let payload = bytes[at..at + len].to_vec();
        at += len;
        assert_eq!(bytes[at], b'\n', "an entry terminator");
        at += 1;
        entries.push((name, payload));
    }
    Report { seed, entries }
}

pub fn run_child(test: &str, env: &[(&str, &str)]) -> Vec<u8> {
    let out = Command::new(std::env::current_exe().expect("the test binary path"))
        .arg("--exact")
        .arg(test)
        .arg("--nocapture")
        .envs(env.iter().copied())
        .output()
        .expect("the child process runs");
    assert!(
        out.status.success(),
        "child {test} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

pub fn assert_fresh_processes_agree(
    child: &str,
    report_env: &str,
    cases: &[Case],
    min_changed: usize,
) {
    let in_process = compress_all(cases);
    let dir = report_dir(child);
    let mut parsed = Vec::new();
    for (name, env) in PROFILES {
        let path = dir.join(format!("{name}-{}.report", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let _ = run_child(
            child,
            &[
                &[(report_env, path.to_str().expect("a utf-8 report path"))],
                env,
            ]
            .concat(),
        );
        let report = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        parsed.push((name, parse_report(&report)));
    }
    for pair in parsed.windows(2) {
        assert_ne!(
            pair[0].1.seed, pair[1].1.seed,
            "the fresh processes must carry different RandomState seeds"
        );
    }
    for (name, report) in &parsed {
        assert_eq!(
            report.entries.len(),
            cases.len(),
            "{name} covers the corpus"
        );
        for (at, (entry_name, bytes)) in report.entries.iter().enumerate() {
            assert_eq!(entry_name, &cases[at].name, "{name} entry {at}");
            assert_eq!(
                bytes, &in_process[at],
                "{name} differs from the in-process run on {}",
                cases[at].name
            );
        }
    }
    for pair in parsed.windows(2) {
        assert_eq!(
            pair[0].1.entries, pair[1].1.entries,
            "two fresh processes disagree on the corpus"
        );
    }
    let changed = parsed[0]
        .1
        .entries
        .iter()
        .enumerate()
        .filter(|(at, (_, bytes))| bytes != &cases[*at].payload)
        .count();
    assert!(
        changed >= min_changed,
        "only {changed} of {} entries changed: the cross-process check is vacuous",
        cases.len()
    );
    println!(
        "{} entries byte-equal in {} fresh processes with differing RandomState seeds, {changed} of them compressed",
        cases.len(),
        parsed.len()
    );
}
