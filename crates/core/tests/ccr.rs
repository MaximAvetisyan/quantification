use std::path::{Path, PathBuf};

use quantification_core::api::{Compressor, Request};
use quantification_core::ccr::{RestoreId, Shared};
use quantification_core::config::{MarkerStyle, RawOptions, ResolvedOptions, ScopePolicy, resolve};
use quantification_core::fingerprint::marker_checksum;
use quantification_core::ledger::{Commit, marker_len};
use quantification_core::pipeline::{self, Stats};
use quantification_core::render;

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

const TTL_NS: u64 = 3_600 * 1_000_000_000;
const MAX_BYTES: usize = 64 * 1024 * 1024;

fn root(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

fn fixture(rel: &str) -> Vec<u8> {
    let path = root(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn corpus() -> Vec<(String, Vec<u8>)> {
    CORPUS
        .iter()
        .map(|name| (name.to_string(), fixture(name)))
        .collect()
}

fn reversible() -> ResolvedOptions {
    resolve(&RawOptions {
        reversible: Some(true),
        ..RawOptions::default()
    })
    .expect("reversible=true resolves")
}

fn plain() -> ResolvedOptions {
    resolve(&RawOptions {
        reversible: Some(false),
        ..RawOptions::default()
    })
    .expect("the default options resolve")
}

struct Run {
    compressed: Vec<u8>,
    stats: Stats,
    commits: Vec<Commit>,
}

fn compress_with(store: Option<&Shared>, payload: &[u8], options: &ResolvedOptions) -> Run {
    let mut compressor = pipeline::Compressor::new();
    if let Some(store) = store {
        compressor.set_sink(Box::new(store.clone()));
    }
    let mut out = Vec::new();
    let stats = compressor.compress(payload, options, &mut out);
    Run {
        compressed: out,
        stats,
        commits: compressor.commits().to_vec(),
    }
}

fn store() -> Shared {
    Shared::new(TTL_NS, MAX_BYTES)
}

fn request() -> Request {
    Request::default().with_options(RawOptions {
        reversible: Some(true),
        ..RawOptions::default()
    })
}

fn group(line: &str, count: usize) -> String {
    std::iter::repeat_n(line, count)
        .collect::<Vec<_>>()
        .join(r"\n")
}

fn chat(content: &str) -> Vec<u8> {
    format!(r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"{content}"}}]}}"#)
        .into_bytes()
}

fn reconstruct(compressed: &[u8], commits: &[Commit], ids: &[String], store: &Shared) -> Vec<u8> {
    assert_eq!(ids.len(), commits.len(), "one id per committed group");
    let mut out = compressed.to_vec();
    let mut shift: isize = 0;
    for (commit, id) in commits.iter().zip(ids) {
        let region = commit.anchor.len() + marker_len(commit.style, commit.kind, commit.count);
        let start = (commit.anchor.start as isize + shift) as usize;
        let end = start + region;
        let original = store
            .restore(Some(&out), id)
            .expect("every returned id restores");
        assert!(
            end <= out.len(),
            "the anchor and its marker are inside the compressed output"
        );
        out.splice(start..end, original.iter().copied());
        shift += original.len() as isize - commit.removed.len() as isize;
    }
    out
}

fn ids_of(run: &Run) -> Vec<RestoreId> {
    run.stats
        .restore_ids
        .iter()
        .map(|id| RestoreId::parse(id).expect("an id of the normative format"))
        .collect()
}

// ---------------------------------------------------------------- the identity property

#[test]
fn restore_is_the_identity_over_the_corpus() {
    let store = store();
    let mut collapsed = 0;
    let mut restored = 0;
    for (name, payload) in corpus() {
        let run = compress_with(Some(&store), &payload, &reversible());
        assert_eq!(
            run.stats.restore_ids.len() as u64,
            run.stats.groups_collapsed,
            "{name}: one restore_id per committed group"
        );
        if run.stats.groups_collapsed == 0 {
            assert_eq!(run.compressed, payload, "{name}: a pass-through");
        } else {
            collapsed += 1;
            restored += run.stats.restore_ids.len();
        }
        assert_eq!(
            reconstruct(
                &run.compressed,
                &run.commits,
                &run.stats.restore_ids,
                &store
            ),
            payload,
            "{name}: every stored original puts the payload back byte for byte"
        );
    }
    assert!(
        collapsed >= 12,
        "the corpus must really collapse: {collapsed}"
    );
    assert!(restored >= 12, "the corpus must really store: {restored}");
}

#[test]
fn restore_is_the_identity_over_generated_shapes() {
    let store = store();
    let mut payloads: Vec<(String, Vec<u8>)> = Vec::new();
    let log = "2026-08-25T10:00:{ss}Z INFO hc 10.0.0.{ip} took {dur}ms ok";
    for count in [3usize, 4, 5, 9, 33] {
        let lines: Vec<String> = (0..count)
            .map(|at| {
                log.replace("{ss}", &format!("{at:02}"))
                    .replace("{ip}", &format!("{}", at % 8 + 1))
                    .replace("{dur}", &format!("{}", 10 * at))
            })
            .collect();
        payloads.push((format!("log burst {count}"), chat(&lines.join(r"\n"))));
    }
    let block: Vec<String> = (0..8)
        .map(|at| format!("at {at} the worker parked the lease and returned"))
        .collect();
    let twice = block
        .iter()
        .chain(block.iter())
        .cloned()
        .collect::<Vec<_>>();
    payloads.push(("a repeated block".to_string(), chat(&twice.join(r"\n"))));
    let records: Vec<String> = (0..12)
        .map(|at| format!(r#"{{"id":{at},"name":"worker-{at}","state":"done"}}"#))
        .collect();
    payloads.push((
        "a single line record dump".to_string(),
        format!(
            r#"{{"messages":[{{"role":"tool","content":"{}"}}]}}"#,
            records.join(",")
        )
        .into_bytes(),
    ));
    payloads.push((
        "a unicode span".to_string(),
        format!(
            r#"{{"messages":[{{"role":"user","content":"{}"}}]}}"#,
            group(
                "2026-08-25T10:00:01Z WARN café 中文 \u{27ea} not a marker",
                4
            )
        )
        .into_bytes(),
    ));
    payloads.push((
        "two messages each with a run".to_string(),
        format!(
            r#"{{"messages":[{{"role":"user","content":"{}"}},{{"role":"user","content":"{}"}}]}}"#,
            group(
                "ERROR timeout while connecting to the primary database shard",
                4
            ),
            group(
                "WARN retrying the secondary replica after a slow handshake",
                5
            )
        )
        .into_bytes(),
    ));
    for (name, payload) in payloads {
        let run = compress_with(Some(&store), &payload, &reversible());
        assert_eq!(
            reconstruct(
                &run.compressed,
                &run.commits,
                &run.stats.restore_ids,
                &store
            ),
            payload,
            "{name}"
        );
    }
}

// ---------------------------------------------------------------- the id and its order

#[test]
fn the_ids_are_the_normative_format_and_parse_back() {
    let store = store();
    let payload = chat(&format!(
        "{}{}",
        group(
            "ERROR timeout while connecting to the primary database shard",
            4
        ),
        group(
            "WARN retrying the secondary replica after a slow handshake",
            4
        )
    ));
    let run = compress_with(Some(&store), &payload, &reversible());
    assert_eq!(run.stats.restore_ids.len(), 2);
    for (id, commit) in run.stats.restore_ids.iter().zip(&run.commits) {
        let parsed = RestoreId::parse(id).expect("the normative format parses back");
        assert_eq!(
            parsed.to_string(),
            *id,
            "the id round trips through its format"
        );
        let original = &payload[commit.removed.clone()];
        assert_eq!(parsed.len, original.len());
        assert_eq!(
            parsed,
            RestoreId::of(original),
            "the id is the xxh3-128 of the removed range and its byte length"
        );
        assert!(id.contains(':'));
        assert_eq!(id.split(':').next().expect("the hash half").len(), 32);
        assert!(
            id.split(':')
                .next()
                .expect("the hash half")
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }
}

#[test]
fn one_id_per_committed_group_in_marker_output_order() {
    let store = store();
    let mut lines: Vec<String> = Vec::new();
    for (at, run) in [
        (
            4usize,
            "ERROR timeout while connecting to the primary database shard",
        ),
        (5, "2026-08-25T10:00:01Z INFO hc 10.0.0.1 took 10ms ok"),
        (
            3,
            "WARN retrying the secondary replica after a slow handshake",
        ),
        (6, "GET /v1/orders 200 12ms upstream=primary db=replica-3"),
    ] {
        lines.push(group(run, at));
    }
    let payload = chat(&lines.join(r"\n"));
    let run = compress_with(Some(&store), &payload, &reversible());
    assert!(
        run.stats.groups_collapsed >= 3,
        "the fixture must really collapse: {}",
        run.stats.groups_collapsed
    );
    assert_eq!(
        run.stats.restore_ids.len() as u64,
        run.stats.groups_collapsed,
        "one id per committed group"
    );
    let expected: Vec<RestoreId> = run
        .commits
        .iter()
        .map(|commit| RestoreId::of(&payload[commit.removed.clone()]))
        .collect();
    assert_eq!(
        ids_of(&run),
        expected,
        "the ids are in commit (anchor byte offset) order, not any other order"
    );
    let anchors: Vec<usize> = run
        .commits
        .iter()
        .map(|commit| commit.anchor.start)
        .collect();
    assert!(
        anchors.windows(2).all(|pair| pair[0] < pair[1]),
        "the commits themselves are ascending: {anchors:?}"
    );
    let markers: Vec<usize> = run
        .compressed
        .windows(4)
        .enumerate()
        .filter(|(_, window)| {
            *window
                == render::checksum_hex(marker_checksum(&payload[run.commits[0].anchor.clone()]))
        })
        .map(|(at, _)| at)
        .collect();
    assert!(!markers.is_empty(), "the first marker is in the output");
    for (id, commit) in run.stats.restore_ids.iter().zip(&run.commits) {
        let found = run
            .compressed
            .windows(id.len())
            .any(|window| window == id.as_bytes());
        assert!(!found, "an id is metadata, never written into the payload");
        assert!(commit.removed.start <= commit.anchor.start);
    }
}

// ---------------------------------------------------------------- misses

#[test]
fn a_tampered_id_is_a_miss_never_wrong_bytes() {
    let store = store();
    let line = "ERROR timeout while connecting to the primary database shard";
    let payload = chat(&group(line, 4));
    let run = compress_with(Some(&store), &payload, &reversible());
    let id = run.stats.restore_ids[0].clone();
    assert_eq!(
        store.restore(Some(&run.compressed), &id),
        Some(payload[run.commits[0].removed.clone()].to_vec())
    );
    let (hash, len) = id.split_once(':').expect("one colon");
    let tampered = [
        String::new(),
        String::from("garbage"),
        format!("{id} "),
        format!(" {id}"),
        format!("{id}\n"),
        format!("{id}:0"),
        id.replace(':', ""),
        format!("{}:{}", &hash[..31], len),
        format!("{hash}0:{len}"),
        format!("{hash}:{}", len.parse::<usize>().expect("a length") + 1),
        format!("{hash}:{}", len.parse::<usize>().expect("a length") - 1),
        format!("{}:{}", hash.to_uppercase(), len),
        "00000000000000000000000000000000:0".to_string(),
    ];
    for wrong in tampered {
        assert_eq!(
            store.restore(Some(&run.compressed), &wrong),
            None,
            "{wrong} must be a miss"
        );
    }
    let other_payload = chat(&group(line, 5));
    let other = compress_with(Some(&store), &other_payload, &reversible());
    assert_ne!(other.stats.restore_ids[0], id);
    assert_eq!(
        store.restore(Some(&run.compressed), &other.stats.restore_ids[0]),
        Some(other_payload[other.commits[0].removed.clone()].to_vec()),
        "each id addresses its own original, whichever payload is presented"
    );
    assert_eq!(
        store.restore(Some(&other.compressed), &id),
        Some(payload[run.commits[0].removed.clone()].to_vec()),
        "an id from another payload is a different id, not a different original"
    );
    assert_eq!(
        store.restore(Some(b"{\"unrelated\":true}"), &id),
        Some(payload[run.commits[0].removed.clone()].to_vec()),
        "a payload that carries no marker is context, never an admission requirement: the id \
         addresses its own original"
    );
    assert_eq!(
        store.restore(Some(b"[... x2 identical wxyz ...]"), &id),
        Some(payload[run.commits[0].removed.clone()].to_vec()),
        "another response's marker over the same range is not a miss either"
    );
}

#[test]
fn a_returned_id_always_restores_its_own_response() {
    let store = store();
    let option_sets: Vec<(ScopePolicy, MarkerStyle, ResolvedOptions)> =
        [ScopePolicy::UserContent, ScopePolicy::UserAndTools]
            .into_iter()
            .flat_map(|policy| {
                [MarkerStyle::Ascii, MarkerStyle::Unicode, MarkerStyle::Auto]
                    .into_iter()
                    .map(move |style| {
                        let options = resolve(&RawOptions {
                            reversible: Some(true),
                            scope_policy: Some(policy),
                            marker_style: Some(style),
                            ..RawOptions::default()
                        })
                        .expect("resolve");
                        (policy, style, options)
                    })
            })
            .collect();
    let (mut restored, mut runs) = (0usize, 0usize);
    for (name, payload) in corpus() {
        let responses: Vec<(ScopePolicy, MarkerStyle, Run)> = option_sets
            .iter()
            .map(|(policy, style, options)| {
                (
                    *policy,
                    *style,
                    compress_with(Some(&store), &payload, options),
                )
            })
            .collect();
        for (policy, style, run) in &responses {
            assert_eq!(
                run.stats.restore_ids.len(),
                run.commits.len(),
                "{name} {policy:?} {style:?}: one id per committed group"
            );
        }
        for (policy, style, run) in &responses {
            for (id, commit) in run.stats.restore_ids.iter().zip(&run.commits) {
                let original = &payload[commit.removed.clone()];
                assert_eq!(
                    store.restore(Some(&run.compressed), id).as_deref(),
                    Some(original),
                    "{name} {policy:?} {style:?}: {id} does not restore its own response"
                );
                restored += 1;
            }
        }
        for (policy, style, run) in &responses {
            runs += 1;
            assert_eq!(
                reconstruct(
                    &run.compressed,
                    &run.commits,
                    &run.stats.restore_ids,
                    &store
                ),
                payload,
                "{name} {policy:?} {style:?}: reversibility is the identity after every sibling \
                 option set re-stored the same originals"
            );
        }
    }
    assert!(restored >= 100, "only {restored} ids were restored");
    assert_eq!(runs, corpus().len() * option_sets.len());
}

#[test]
fn the_marker_checksum_is_not_the_storage_key() {
    let mut anchors: Vec<(u16, String)> = Vec::new();
    let mut pair: Option<(String, String)> = None;
    for at in 0..4096 {
        let line = format!("ERROR timeout while connecting to the primary database shard {at}");
        let checksum = marker_checksum(line.as_bytes());
        if let Some((_, other)) = anchors.iter().find(|(seen, _)| *seen == checksum) {
            pair = Some((other.clone(), line));
            break;
        }
        anchors.push((checksum, line));
    }
    let (first, second) = pair.expect("two anchors sharing four hex digits exist");
    let content = format!("{}\\n{}", group(&first, 4), group(&second, 4));
    let payload = chat(&content);
    let store = store();
    let run = compress_with(Some(&store), &payload, &reversible());
    assert_eq!(run.stats.restore_ids.len(), 2, "two committed groups");
    let shared = render::checksum_hex(marker_checksum(first.as_bytes()));
    assert_eq!(
        marker_checksum(second.as_bytes()),
        marker_checksum(first.as_bytes()),
        "the two anchors share the four hex digits"
    );
    assert_eq!(
        run.compressed
            .windows(4)
            .filter(|window| *window == shared)
            .count(),
        2,
        "both markers carry the same four hex digits: {}",
        String::from_utf8_lossy(&run.compressed)
    );
    assert_ne!(
        run.stats.restore_ids[0], run.stats.restore_ids[1],
        "the same four hex digits, two different storage keys"
    );
    assert_eq!(
        store.restore(Some(&run.compressed), &run.stats.restore_ids[0]),
        Some(group(&first, 4).into_bytes())
    );
    assert_eq!(
        store.restore(Some(&run.compressed), &run.stats.restore_ids[1]),
        Some(group(&second, 4).into_bytes())
    );
    assert_eq!(store.len(), 2, "two independent entries");
}

#[test]
fn a_shared_original_is_one_entry_and_two_ids() {
    let store = store();
    let line = "ERROR timeout while connecting to the primary database shard";
    let payload = format!(
        r#"{{"messages":[{{"role":"user","content":"{}"}},{{"role":"user","content":"{}"}}]}}"#,
        group(line, 4),
        group(line, 4)
    )
    .into_bytes();
    let run = compress_with(Some(&store), &payload, &reversible());
    assert_eq!(run.stats.restore_ids.len(), 2);
    assert_eq!(
        run.stats.restore_ids[0], run.stats.restore_ids[1],
        "two groups, one original, one id"
    );
    assert_eq!(store.len(), 1, "the content addressed store holds it once");
    assert_eq!(
        reconstruct(
            &run.compressed,
            &run.commits,
            &run.stats.restore_ids,
            &store
        ),
        payload
    );
}

// ---------------------------------------------------------------- determinism and gates

#[test]
fn reversible_changes_no_output_byte() {
    let store = store();
    for (name, payload) in corpus() {
        let on = compress_with(Some(&store), &payload, &reversible());
        let off = compress_with(Some(&store), &payload, &plain());
        let unwired = compress_with(None, &payload, &reversible());
        assert_eq!(on.compressed, off.compressed, "{name}");
        assert_eq!(on.compressed, unwired.compressed, "{name}");
        assert_eq!(
            on.stats.groups_collapsed, off.stats.groups_collapsed,
            "{name}"
        );
        assert_eq!(on.stats.record_splits, off.stats.record_splits, "{name}");
        assert_eq!(on.stats.bytes_out, off.stats.bytes_out, "{name}");
        assert!(off.stats.restore_ids.is_empty());
        assert!(
            unwired.stats.restore_ids.is_empty(),
            "{name}: nothing stored"
        );
        assert!(on.stats.options_echo.ends_with(r#""reversible":true}"#));
        assert!(off.stats.options_echo.ends_with(r#""reversible":false}"#));
    }
}

#[test]
fn an_unwired_store_reports_no_id_and_stores_nothing() {
    let payload = chat(&group(
        "ERROR timeout while connecting to the primary database shard",
        4,
    ));
    let run = compress_with(None, &payload, &reversible());
    assert_eq!(run.stats.groups_collapsed, 1);
    assert!(run.stats.restore_ids.is_empty());
    let mut out = Vec::new();
    let stats = Compressor::new()
        .compress(&payload, &request(), &mut out)
        .expect("reversible=true resolves");
    assert!(stats.restore_ids.is_empty());
    assert_eq!(out, run.compressed);
}

#[test]
fn the_bound_and_the_ttl_decide_which_restores_succeed_and_nothing_else() {
    let line = "ERROR timeout while connecting to the primary database shard";
    let payload = chat(&format!(
        "{}\\n{}",
        group(line, 4),
        group(
            "WARN retrying the secondary replica after a slow handshake",
            4
        )
    ));
    let roomy = store();
    let run = compress_with(Some(&roomy), &payload, &reversible());
    assert_eq!(run.stats.restore_ids.len(), 2);

    let tiny = Shared::new(TTL_NS, 1);
    let bounded = compress_with(Some(&tiny), &payload, &reversible());
    assert_eq!(
        bounded.compressed, run.compressed,
        "the bound never changes an output byte"
    );
    assert!(bounded.stats.restore_ids.is_empty(), "nothing fits");
    for id in &run.stats.restore_ids {
        assert_eq!(
            roomy.restore(Some(&run.compressed), id),
            Some(removed(&payload, &run, id))
        );
        assert_eq!(tiny.restore(Some(&run.compressed), id), None);
    }

    let expiring = Shared::new(0, MAX_BYTES);
    let stale = compress_with(Some(&expiring), &payload, &reversible());
    assert!(
        stale.stats.restore_ids.is_empty(),
        "a zero ttl stores nothing"
    );
    assert_eq!(stale.compressed, run.compressed);
}

fn removed(payload: &[u8], run: &Run, id: &str) -> Vec<u8> {
    let commit = run
        .commits
        .iter()
        .find(|commit| RestoreId::of(&payload[commit.removed.clone()]).to_string() == id)
        .expect("a committed group");
    payload[commit.removed.clone()].to_vec()
}

#[test]
fn the_public_api_hands_the_store_the_committed_ranges() {
    let store = store();
    let line = "ERROR timeout while connecting to the primary database shard";
    let payload = chat(&group(line, 4));
    let mut out = Vec::new();
    let stats = Compressor::new()
        .with_sink(store.clone())
        .compress(&payload, &request(), &mut out)
        .expect("reversible=true resolves");
    assert_eq!(stats.restore_ids.len(), 1);
    assert_eq!(stats.groups_collapsed, 1);
    assert_eq!(
        store.restore(Some(&out), &stats.restore_ids[0]),
        Some(group(line, 4).into_bytes()),
        "the stored original is the range the marker replaced"
    );
}

#[test]
fn a_forced_marker_style_still_restores() {
    let store = store();
    let payload = chat(&group(
        "ERROR timeout while connecting to the primary database shard",
        4,
    ));
    for style in [MarkerStyle::Auto, MarkerStyle::Ascii, MarkerStyle::Unicode] {
        let options = resolve(&RawOptions {
            reversible: Some(true),
            marker_style: Some(style),
            ..RawOptions::default()
        })
        .expect("resolve");
        let run = compress_with(Some(&store), &payload, &options);
        assert_eq!(run.stats.restore_ids.len(), 1, "{style:?}");
        assert_eq!(
            reconstruct(
                &run.compressed,
                &run.commits,
                &run.stats.restore_ids,
                &store
            ),
            payload,
            "{style:?}"
        );
    }
}

#[test]
fn a_degenerate_payload_stores_nothing() {
    let store = store();
    for payload in [
        &b""[..],
        &b"   "[..],
        &b"null"[..],
        &b"{}"[..],
        &b"[]"[..],
        &b"{\"foo\":1}"[..],
    ] {
        let run = compress_with(Some(&store), payload, &reversible());
        assert!(run.stats.restore_ids.is_empty());
        assert_eq!(run.compressed, *payload);
    }
    assert!(store.is_empty());
    assert_eq!(store.bytes(), 0);
}
