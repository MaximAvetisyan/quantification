#![cfg(feature = "ccr")]

use std::collections::BTreeMap;
use std::sync::Arc;

use quantification_core::ccr::{self, RestoreId, Sink};
use quantification_core::config::{MarkerStyle, RawOptions, ResolvedOptions, resolve};
use quantification_core::ledger::marker_len;
use quantification_core::pipeline::Compressor;
use quantification_server::{CCR_ENABLED, RestoreStore};

const CORPUS: usize = 512;
const TTL_NS: u64 = 3_600 * 1_000_000_000;
const MAX_BYTES: usize = 64 * 1024 * 1024;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn flag(&mut self) -> bool {
        self.below(2) == 0
    }
}

fn stamp(rng: &mut Rng, salt: usize) -> String {
    format!(
        "2026-08-2{}T{:02}:{:02}:{:02}Z",
        3 + rng.below(3),
        salt % 24,
        rng.below(60),
        rng.below(60)
    )
}

fn uuid(rng: &mut Rng) -> String {
    format!(
        "{:08x}-1111-2222-3333-{:012x}",
        rng.next() as u32,
        rng.below(1 << 40)
    )
}

fn log_line(rng: &mut Rng, kind: usize, entry: usize) -> String {
    let tail = match kind % 4 {
        0 => format!("GET /v1/users?id={entry} status=200"),
        1 => format!("<- 200 bytes {} upstream=primary", 4000 + entry),
        2 => format!("pool conns {entry} idle 0 queue={}", rng.below(8)),
        _ => format!(
            "worker node 10.0.{}.{} parked lease {}ms",
            rng.below(4),
            entry % 251,
            5 * entry
        ),
    };
    format!(
        "{} INFO hc 10.0.0.{} {} id={} took {}ms",
        stamp(rng, entry),
        1 + entry % 250,
        tail,
        uuid(rng),
        3 * entry
    )
}

fn record_line(entry: usize, len: usize) -> String {
    let head = format!("{{\\\"id\\\":{entry},\\\"name\\\":\\\"worker-{entry}\\\",\\\"pad\\\":\\\"");
    let tail = "\\\",\\\"state\\\":\\\"ok\\\"}";
    let padding = len - head.len() - tail.len();
    let mut out = head;
    out.extend(std::iter::repeat_n('p', padding));
    out.push_str(tail);
    out
}

fn record_dump(record_len: usize, records: usize, copies: usize) -> String {
    let mut out = String::from("[");
    let mut at = 0;
    for _ in 0..copies {
        for _ in 0..records {
            if at > 0 {
                out.push(',');
            }
            out.push_str(&record_line(at, record_len));
            at += 1;
        }
    }
    out.push(']');
    out
}

const NEWLINES: [&str; 3] = [r"\n", r"\u000A", r"\u000a"];
const PADS: [&str; 4] = ["", "  ", r"\t", r" \t "];
const PRIOR: [&str; 2] = [
    "\u{27ea}\u{d7}200 identical \u{b7}c5f3\u{27eb}",
    "[... x50 rows, template 0abc ...]",
];

fn span(rng: &mut Rng, shape: usize) -> String {
    let nl = NEWLINES[rng.below(NEWLINES.len())];
    match shape {
        0 => {
            let mut lines = Vec::new();
            for entry in 0..3 + rng.below(24) {
                lines.push(log_line(rng, entry % 4, entry));
            }
            if rng.flag() {
                let previous = lines.clone();
                for line in previous {
                    lines.push(line);
                }
            }
            lines.join(nl)
        }
        1 => {
            let body = format!(
                "{} ERROR timeout while connecting to the primary database shard",
                stamp(rng, 1)
            );
            vec![body; 3 + rng.below(20)].join(nl)
        }
        2 => {
            let body = format!(
                "{} WARN retrying the secondary replica after a slow handshake id={}",
                stamp(rng, 2),
                uuid(rng)
            );
            let lines: Vec<String> = (0..3 + rng.below(10))
                .map(|_| {
                    let pad = PADS[rng.below(PADS.len())];
                    format!("{pad}{body}{pad}")
                })
                .collect();
            lines.join(nl)
        }
        3 => {
            let period = 2 + rng.below(4);
            let mut lines = Vec::new();
            for copy in 0..2 + rng.below(4) {
                for step in 0..period {
                    lines.push(format!(
                        "{} trace step {step} of {period} at 10.0.0.{} shard={} took {}ms",
                        stamp(rng, copy),
                        1 + rng.below(250),
                        rng.below(4),
                        7 * copy + step
                    ));
                }
            }
            lines.join(nl)
        }
        4 => {
            if rng.below(4) == 0 {
                record_dump(120 + rng.below(300), 200, 1 + rng.below(2))
            } else {
                record_dump(64 + rng.below(60), 2 + rng.below(6), 1 + rng.below(4))
            }
        }
        5 => {
            let marker = PRIOR[rng.below(PRIOR.len())];
            let body = format!("{} INFO hc 10.0.0.7 prior marker line", stamp(rng, 3));
            let mut lines = vec![format!("{body}{marker}"); 2 + rng.below(5)];
            lines.push(log_line(rng, 1, 40));
            lines.join(nl)
        }
        6 => {
            let body = format!(
                "{} INFO caf\u{e9} \u{4e2d}\u{6587} took {}ms",
                stamp(rng, 4),
                3
            );
            vec![body; 3 + rng.below(8)].join(nl)
        }
        _ => {
            let body = format!("{} NOTE unique {:016x}", stamp(rng, 5), rng.next());
            let lines: Vec<String> = (0..3 + rng.below(8)).map(|_| body.clone()).collect();
            lines.join(nl)
        }
    }
}

fn payloads(count: usize) -> Vec<Vec<u8>> {
    let mut rng = Rng(0x5ec0_1de5_0f11_0001);
    (0..count)
        .map(|_| {
            let mut slots = Vec::new();
            for _ in 0..1 + rng.below(3) {
                let shape = rng.below(8);
                slots.push(span(&mut rng, shape));
            }
            if rng.below(6) == 0 {
                return slots[0].clone().into_bytes();
            }
            let messages: Vec<String> = slots
                .iter()
                .map(|content| {
                    let role = ["user", "user", "user", "tool", "assistant"][rng.below(5)];
                    format!(r#"{{"role":"{role}","content":"{content}"}}"#)
                })
                .collect();
            let body = format!(
                r#"{{"model":"quantification-test","messages":[{}]}}"#,
                messages.join(",")
            );
            let mut payload = Vec::new();
            if rng.below(8) == 0 {
                payload.extend_from_slice(&[0xef, 0xbb, 0xbf]);
            }
            payload.extend_from_slice(body.as_bytes());
            payload
        })
        .collect()
}

fn reversible() -> ResolvedOptions {
    resolve(&RawOptions {
        reversible: Some(true),
        ..RawOptions::default()
    })
    .expect("reversible=true resolves")
}

fn plain(marker_style: MarkerStyle) -> ResolvedOptions {
    resolve(&RawOptions {
        reversible: Some(false),
        marker_style: Some(marker_style),
        ..RawOptions::default()
    })
    .expect("the default options resolve")
}

fn reversible_style(marker_style: MarkerStyle) -> ResolvedOptions {
    resolve(&RawOptions {
        reversible: Some(true),
        marker_style: Some(marker_style),
        ..RawOptions::default()
    })
    .expect("reversible=true resolves")
}

struct Handle(Arc<dyn RestoreStore>);

impl Sink for Handle {
    fn store(&mut self, original: &[u8], marker: &[u8], checksum: [u8; 4]) -> Option<RestoreId> {
        self.0.store_committed(original, marker, checksum)
    }
}

struct Run {
    compressed: Vec<u8>,
    commits: Vec<(std::ops::Range<usize>, std::ops::Range<usize>, u8)>,
    ids: Vec<String>,
}

fn compress(payload: &[u8], options: &ResolvedOptions, store: &Arc<dyn RestoreStore>) -> Run {
    let mut compressor = Compressor::new();
    compressor.set_sink(Box::new(Handle(store.clone())));
    let mut out = Vec::new();
    let stats = compressor.compress(payload, options, &mut out);
    Run {
        compressed: out,
        commits: compressor
            .commits()
            .iter()
            .map(|commit| {
                (
                    commit.removed.clone(),
                    commit.anchor.clone(),
                    marker_len(commit.style, commit.kind, commit.count) as u8,
                )
            })
            .collect(),
        ids: stats.restore_ids,
    }
}

fn reconstruct(run: &Run, payload: &[u8], store: &Arc<dyn RestoreStore>) -> Vec<u8> {
    assert_eq!(
        run.ids.len(),
        run.commits.len(),
        "one id per committed group"
    );
    let mut out = run.compressed.clone();
    let mut shift: isize = 0;
    for ((removed, anchor, marker), id) in run.commits.iter().zip(&run.ids) {
        let start = (anchor.start as isize + shift) as usize;
        let end = start + anchor.len() + *marker as usize;
        let original = store
            .restore_verified(&run.compressed, id)
            .unwrap_or_else(|| panic!("{id} does not restore"));
        assert_eq!(
            &original,
            &payload[removed.clone()],
            "{id} is not the range the marker replaced"
        );
        assert_eq!(
            RestoreId::of(&original).to_string(),
            *id,
            "{id} is not the normative id of its own bytes"
        );
        assert!(
            end <= out.len(),
            "the anchor and marker are inside the output"
        );
        out.splice(start..end, original.iter().copied());
        shift += original.len() as isize - removed.len() as isize;
    }
    out
}

const UNICODE_HEAD: &str = "\u{27ea}\u{d7}2 identical";

fn ccr_enabled() -> bool {
    CCR_ENABLED
}

fn fresh() -> Arc<dyn RestoreStore> {
    Arc::new(ccr::Shared::new(TTL_NS, MAX_BYTES))
}

#[test]
fn restore_is_the_identity_for_every_id_a_response_returns() {
    assert!(
        ccr_enabled(),
        "this file only compiles with the ccr feature"
    );
    let (mut collapsed, mut stored, mut bytes) = (0usize, 0usize, 0usize);
    for (at, payload) in payloads(CORPUS).iter().enumerate() {
        let store = fresh();
        let run = compress(payload, &reversible(), &store);
        let plain_store = fresh();
        let off = compress(payload, &plain(MarkerStyle::Auto), &plain_store);
        assert_eq!(
            run.compressed, off.compressed,
            "payload {at}: reversible=true changed an output byte"
        );
        assert_eq!(run.commits.len(), off.commits.len(), "payload {at}");
        let style = [MarkerStyle::Ascii, MarkerStyle::Unicode, MarkerStyle::Auto][at % 3];
        let styled = compress(payload, &reversible_style(style), &plain_store);
        let forced = compress(payload, &plain(style), &plain_store);
        assert_eq!(
            styled.compressed, forced.compressed,
            "payload {at}: reversible=true and a forced marker style disagree"
        );
        if run.commits.is_empty() {
            assert_eq!(run.compressed, *payload, "payload {at}: a pass-through");
            assert!(run.ids.is_empty(), "payload {at}: an id without a group");
            continue;
        }
        collapsed += 1;
        stored += run.ids.len();
        bytes += payload.len();
        assert_eq!(
            reconstruct(&run, payload, &store),
            *payload,
            "payload {at}: restoring every returned id does not put the input back"
        );
    }
    assert_eq!(payloads(CORPUS).len(), CORPUS);
    assert!(
        collapsed * 2 >= CORPUS,
        "only {collapsed} of {CORPUS} payloads collapse"
    );
    assert!(stored >= 300, "only {stored} spans were stored");
    assert!(bytes > 500_000, "the corpus is only {bytes} bytes");
}

#[test]
fn an_id_stored_under_two_marker_styles_stops_restoring_the_first_response() {
    let store = fresh();
    let run = "ERROR timeout while connecting to the primary shard";
    let block = std::iter::repeat_n(run, 3).collect::<Vec<_>>().join(r"\n");
    let payload =
        format!(r#"{{"messages":[{{"role":"user","content":"A header line\n{block}"}}]}}"#)
            .into_bytes();
    let ascii = compress(&payload, &reversible_style(MarkerStyle::Ascii), &store);
    let unicode = compress(&payload, &reversible_style(MarkerStyle::Unicode), &store);
    assert_eq!(
        ascii.ids, unicode.ids,
        "one removed range, one content address"
    );
    assert_eq!(ascii.ids.len(), 1);
    assert!(
        ascii
            .compressed
            .windows(b"[... x2 identical".len())
            .any(|window| window == b"[... x2 identical"),
        "the forced ascii style writes the ascii marker"
    );
    assert!(
        unicode
            .compressed
            .windows(UNICODE_HEAD.len())
            .any(|window| window == UNICODE_HEAD.as_bytes()),
        "the forced unicode style writes the unicode marker for the same removed range"
    );
    assert_ne!(
        unicode.compressed, ascii.compressed,
        "the same removed range is marked twice, in two styles"
    );
    assert_eq!(
        store.restore_verified(&ascii.compressed, &ascii.ids[0]),
        None,
        "the entry now carries the second response's marker, so the first response's id misses"
    );
    assert_eq!(
        store.restore_verified(&unicode.compressed, &unicode.ids[0]),
        Some(payload[unicode.commits[0].0.clone()].to_vec()),
        "the second response restores, and the entry is not corrupt"
    );
    assert_eq!(
        store.restore_verified(b"", &ascii.ids[0]),
        Some(payload[ascii.commits[0].0.clone()].to_vec()),
        "without a payload the pre-check is skipped: the stored bytes are the right ones"
    );
    assert_eq!(
        reconstruct(&unicode, &payload, &store),
        payload,
        "and the second response is still exactly reversible"
    );
}

#[test]
fn on_a_shared_store_every_restore_miss_is_an_id_another_response_re_stored() {
    let store = fresh();
    let mut seen: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let (mut collapsed, mut restored, mut whole) = (0usize, 0usize, 0usize);
    for payload in payloads(CORPUS) {
        let mut responses = Vec::new();
        for style in [MarkerStyle::Ascii, MarkerStyle::Unicode] {
            let run = compress(&payload, &reversible_style(style), &store);
            if !run.commits.is_empty() {
                responses.push(run);
            }
        }
        if responses.is_empty() {
            continue;
        }
        collapsed += 1;
        let mut every = true;
        for run in &responses {
            for ((removed, _, _), id) in run.commits.iter().zip(&run.ids) {
                let entry = seen.entry(id.clone()).or_default();
                entry.0 += 1;
                match store.restore_verified(&run.compressed, id) {
                    Some(original) => {
                        entry.1 += 1;
                        restored += 1;
                        assert_eq!(
                            original,
                            payload[removed.clone()],
                            "{id} restored the wrong bytes"
                        );
                    }
                    None => {
                        every = false;
                        assert_eq!(
                            store.restore_verified(b"", id).as_deref(),
                            Some(&payload[removed.clone()][..]),
                            "{id} is not a shadowed id: the entry itself is gone or wrong"
                        );
                    }
                }
            }
        }
        if every {
            whole += 1;
        }
    }
    let shadowed: Vec<&String> = seen
        .iter()
        .filter(|(_, (uses, hits))| uses > hits)
        .map(|(id, _)| id)
        .collect();
    assert!(
        collapsed * 2 >= CORPUS,
        "only {collapsed} of {CORPUS} payloads collapse"
    );
    assert!(restored > 300, "only {restored} restores");
    assert!(
        !shadowed.is_empty(),
        "the shared store never shadowed an id: the pin above would be vacuous"
    );
    for id in &shadowed {
        let (uses, hits) = seen[*id];
        assert!(hits > 0, "{id} misses everywhere");
        assert_eq!(uses - hits, 1, "{id} misses in more than one response");
    }
    assert!(whole < collapsed, "no response was shadowed at all");
}
