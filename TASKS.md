# Implementation Plan — quantification v1

Derived from DESIGN.md rev 6. Tasks are grouped into waves: everything in a
wave has its dependencies satisfied by earlier waves only, so tasks within a
wave run **in parallel** (`∥`). Each task names its normative sections and
exit criteria. Gates M1–M4 are blocking milestones.

## Wave 0 — foundations (all four parallel)

- **W0.1 Workspace scaffold** — cargo workspace, `crates/{core,proto,server}`,
  CI skeleton (fmt, clippy, nextest, cargo-deny). Exit: `cargo build` green.
- **W0.2 Config & frozen constants** — all §7 parameters; option parsing,
  resolution, `options_echo` canonical serialization (§6.2). Exit: defaults
  pinned by unit tests.
- **W0.3 Golden corpus bootstrap** — §12 fixture list incl. single-line JSON
  dumps (stage 1b), `\u000A`-only newlines, duplicate/escaped structural
  keys, BOM, prior-marker payloads, stage-1b boundary cases. Grows forever.
- **W0.4 Fuzz scaffold** — cargo-fuzz targets stubbed for sniff / locator /
  splitter. Exit: one clean run each.

### W0 verification (2026-09-17)

- W0.1 licensing fix: workspace packages are explicitly unpublished;
  `deny.toml` exempts private packages only. No license was assigned.
  cargo-deny 0.20.2 reports `licenses ok`, `advisories ok`, `sources ok`.
  Explicit versions now accompany both local path dependencies; full workspace
  `cargo deny check` passes (unused license-allowance warnings only).
  Optional separate fuzz-manifest audit finds libfuzzer-sys's declared NCSA
  license outside the existing allowlist; no license policy was broadened.
- Baseline `cargo build --workspace` and `cargo test --workspace` pass
  (9 config tests). W0.2 defaults/option resolution are covered; this is
  not evidence for any Wave 1 functionality.
- W0.4 fuzz exit: one clean `cargo fuzz run` per stub target
  (fuzz_sniff / fuzz_locator / fuzz_splitter, 200 runs each, exit 0,
  zero crashes). Toolchain deviation: nightly could not be installed
  (static.rust-lang.org connection timeout, retried); fallback ran on
  stable 1.98.0 with `RUSTC_BOOTSTRAP=1` and `-s none` (no ASan, which
  stable cannot enable). The `.github/workflows/fuzz.yml` nightly+ASan
  configuration is unchanged and must be exercised when nightly is
  reachable; stub coverage stays shallow until targets are wired in W1.

## Wave 0.5 — go/no-go spike (sequential, blocks Wave 1)

- **S1 Locator perf spike** (§8) — throwaway escape-aware scanner vs the
  400 MB/s floor on real escaped-heavy payloads.
  **Gate M1**: pass ⇒ continue; fail ⇒ redesign §4.1 before anything else.

### S1 verification (2026-09-17)

- Escape-aware locator scanner (`crates/core/src/s1/locator.rs`, throwaway,
  exported under `quantification_core::locator`) measured on 8 MiB
  escaped-heavy chat/tool JSON fixtures (`s1/benches.rs`: trace lines with
  `\"`/`\\`/`\u000A`/`\t` escapes; single-line tool dumps mixing `\n` and
  `\u000A`), warm, pinned core (`taskset -c 2`, i7-9700K, 4.6 GHz):
  escaped_chat_lines 8 389 356 B, p50 5.61 ms = 1496 MB/s, p99 5.64 ms;
  escaped_tool_dumps 8 390 630 B, p50 5.82 ms = 1443 MB/s, p99 5.84 MB/s.
  Three repeat pinned runs agree within 0.1%. **Gate M1 passes**: ≥3.6× the
  §8 400 MB/s go/no-go floor on both fixtures, within the ≤20 ms locate
  budget with headroom. Warm-cache, single-span payloads (1 eligible span
  per 8 MiB); fuzz wiring and 200k-run soak remain W0.4/W4.2 scope.
- Correctness examples (`crates/core/examples/s1_correctness.rs`, 17 checks
  green): role classification (assistant excluded, tool vs user), truncated
  document pass-through, malformed degradation, whitespace/BOM tolerance,
  8 MiB span boundaries. Workspace tests (9) and `cargo fmt`/`clippy`
  --all-targets clean. Spike modules are additive; no Wave 1 code.

## Wave 1 — core primitives (all six parallel; deps W0 + M1)

- **W1.1 Schema sniff + span locator** (§4.1) — eligibility map, degradation
  routing, depth/span caps, BOM skip, decoded-key matching, last-wins keys.
  Exit: locator fixtures green; hot loop allocation-free (asserted).
- **W1.2 Unit splitter** (§4.4 stages 1+1b) — line split; normative record
  segmentation `u_head`/`u_i`/`u_tail`; caps. Exit: property test — units +
  joiners reassemble to the original span byte-for-byte.
  Status: **complete** (2026-09-26). Stage 1
  (`quantification_core::stage1::split_span`) walks the raw escaped bytes one
  escape unit at a time (2-byte simple escapes, 6-byte `\uXXXX`, truncated
  tails tolerated) and cuts a line at each **line-boundary escape unit**: the
  2-byte `\n` plus the 6-byte `\u000A`/`\u000a` (§4.2; the four hex bytes must
  be `000A` or `000a` — no other variants exist). The boundary test lives
  inside that escape-unit walk, never a second substring scan, so `\u005Cn`
  does not split, `\\` followed by `\u000A` does, and a truncated trailing `\`
  never does. A boundary unit belongs to neither line, so it becomes joiner
  bytes (6 for the `\u` form) — the removal rule's joining
  **line-boundary escape units** are exactly those gaps, never part of a
  member; adjacent boundaries concatenate — `a\n\u000Ab`
  yields one 8-byte joiner, `a\u000A\u000Ab` one 12-byte joiner, and a span
  that is just `\u000A` yields zero units. Lines over `max_line_bytes` are
  handed to stage 1b, the last line without a trailing separator is included,
  blank lines fold into the joiner, and every unit range is absolute within
  the span. Stage 1b (`stage1b::segment_line`, crate-private — every test
  drives it through `split_span`) keeps the literal §4.4 ranges `u_head` /
  `u_i` / `u_tail` on literal `},{` with **no edge special-casing**: 1-byte
  units are kept symmetrically (a line starting `},{` keeps the bare `}`; a
  line ending `},{` keeps the trailing `{`), empty units are discarded, and
  no-separator lines plus over-cap records stay verbatim. `eligible` is
  `len <= max_record_bytes`; an under-cap line never reaches stage 1b and stays
  one eligible unit. `Unit { range, eligible }` carries no joiner —
  `stage1::joiner` derives the gap from the distance to the next unit, so no
  duplicated state can drift, and it asserts its precondition (units ascending
  and disjoint, i.e. valid only on the *unfiltered* list — W2 must re-derive
  `removed_bytes` from committed units instead of reusing this joiner, pinned
  by a `should_panic` test). `reassemble` is a test/reassembly helper, so it
  lives in the integration test and (as an independent oracle) in the fuzz
  target rather than in the public API.
  Tests: 30 integration tests in `crates/core/tests/stage1_split.rs`
  (workspace total 39 = 9 config + 30 splitter). Exit criterion met: the
  property test asserts units + joiners reassemble to the original span
  byte-for-byte over 48 deterministic pseudo-random spans (no new deps; LCG
  in the test; it self-checks that stage 1b and both boundary forms were
  actually reached), and every joiner is proven to be a whole run of
  line-boundary escape units or the single `,` separator, so no boundary can
  land mid-escape. Goldens cover the seven W0.3 edge fixtures (record-len
  16383/16384/16385, no-separator overcap, single-line tool dump
  overcap/small, `newlines-u000a-only.json` = 4 units / three 6-byte joiners /
  all eligible / no stage-1b handoff at 186 B), plus the `max_line_bytes`
  boundary, the `max_record_bytes` ±1 boundary, mixed and truncated escape
  forms, and the bracket-carrying `u_head`/`u_tail` — those stay verbatim
  because they carry the `[`/`]` and so rarely memcmp-equal their siblings
  (§4.4), with `eligible` decided by the cap alone (a 16385-byte head is
  ineligible, a 1-byte `}` is eligible).
  Fuzz (W0.4 target, now wired): `fuzz/fuzz_targets/fuzz_splitter.rs` calls
  `split_span` on arbitrary bytes and asserts that units + gaps rebuild the
  input byte-for-byte and that units are ascending and disjoint. One clean run
  on 2026-09-26: 200 000 runs, exit 0, zero crashes, 90 edges / 407 features,
  largest input 558 KB, seeded with a 557 KB over-cap `},{` line so stage 1b
  is actually fuzzed (the plain `-runs=200` protocol run is clean too).
  Toolchain deviation: nightly is still unreachable (static.rust-lang.org
  connection timeout), so the run used the documented W0.4 fallback — stable
  1.98.0 with `RUSTC_BOOTSTRAP=1` and `cargo fuzz run --sanitizer none` (no
  ASan, which stable cannot enable). The nightly+ASan CI configuration is
  unchanged and must be exercised when nightly is reachable; the 200k soak
  and corpus minimization stay W4.2/W4.5 scope.
  Deviations from DESIGN: none outstanding — §4.2's `\u000A` line boundaries
  and §4.4's literal ranges are both implemented as written, and DESIGN.md is
  not amended. Plain byte loops only; `memchr` is deliberately not added and
  stays a W4.3 bench item.
- **W1.3 WS-normalization transform** (§4.2) — escape-unit collapse, trim.
  Exit: golden vectors incl. mixed `\n` / `\u000A`.
  Status: **complete** (2026-09-26). `wsnorm::normalize_into(raw, &mut out)`
  is the transform (allocation-free, reuses the caller's scratch buffer so W2
  detectors normalize without a per-line allocation) and `wsnorm::normalize(raw)`
  is the owning wrapper. One left-to-right walk over the raw escaped bytes:
  every position is consumed as a whole escape unit (2-byte simple escape, or
  6-byte `\uXXXX` clamped to what is left, matching stage 1's walk), the
  collapse sources `\t` / `\n` / `\r` and the literal space each set a
  *pending* flag, and the flag emits exactly one space only when a
  non-collapsing unit follows **and** the output is non-empty — that single
  mechanism gives both run collapse and edge trimming, with no second pass.
  A pending flag is therefore dropped at a leading/trailing edge and kept
  between literals. Pinned consequences (goldens): `\u000A` / `\u000a` /
  `\u0009` / `\u0041` and every other escape unit stay literal byte-for-byte
  (so `\u000A` inside a line is *not* a collapse source — it is a line
  boundary cut by stage 1), a raw TAB/CR/LF byte is literal (only escape
  units collapse, per §4.2), `\\` followed by `n` stays `\\n` (the `\\` unit is
  not a collapse source), truncated tails (`\`, `\u`, `\u0`, `a\`) stay
  literal, and `\n`/`\r` collapse even though stage 1 removes them first
  (a stage-1b record or any other input slice still transforms correctly).
  The transform is idempotent and never grows the input, both asserted over
  the 22-vector golden table and over 200 LCG-generated spans.
  Cross-check against W1.2: a span whose lines are separated by `\n` and the
  same span with `\u000A` / `\u000a` separators produce *equal* ws-normalized
  per-line forms. Tests: 8 integration tests in `crates/core/tests/wsnorm.rs`
  (core total 47 = 9 config unit + 30 splitter + 8 ws-normalization).
  Deviations from DESIGN: none — §4.2 bullet 3 is implemented as written and
  DESIGN.md is not amended. No new dependencies.
- **W1.4 Hashing facade** — xxh3-128/64 fixed-seed wrappers; open-address
  fingerprint table, length→hash→memcmp order, hard caps (§4.4.2, §7).
- **W1.5 Mask automata** (§4.6) — six masks, priority order,
  leftmost-longest. Exit: golden mask vectors.
- **W1.6 Proto crate** (§6.2) — corrected .proto compiles; tonic codegen;
  shared types. Independent of core.

## Wave 2 — detectors & output (deps W1)

- **W2.1 Commit ledger + profitability gate** (§4.4) — removal rule (member
  union + joiners), anchor-offset emit ordering, stats counters. Deps:
  W1.2, W1.4. Defines the interface every detector commits through.
- **W2.2 Stage 3 exact runs** ∥ **W2.3 Stage 4 ws-runs** ∥
  **W2.4 Stage 5 repeated blocks** (ws-normalized domain) ∥
  **W2.5 Stage 6 template groups** — all after W2.1
  (W2.4 also needs W1.3; W2.5 also needs W1.5).
- **W2.6 Renderer / marker grammar** (§4.5) — exact pinned shapes + CCCC
  checksum. Parallel with W2.2–W2.5 (consumes commit ledger only).
- **W2.7 Splicer** (§4.5) — copy buffer + patch recorded ranges; buffer-
  reuse robustness hook for §12 poisoned-buffer test. Parallel with detectors.
- **W2.8 Stage 7 templated blocks** — after W2.4 + W2.5 (template-id scan,
  min period 1).
- **W2.9 Pipeline orchestration + Stats assembly** (§3, §4.5) — after
  W2.2–W2.8. **Gate M2**: chat golden outputs byte-stable ×1000.

## Wave 3 — API & transports (deps W2.9)

- **W3.1 Library API** — `crates/core` public surface, options resolution
  echo, `strict_validate` flag (§4.1). Sequential first.
- **W3.2 HTTP/axum** (§6.1) ∥ **W3.3 gRPC/tonic unary** (§6.2) ∥
  **W3.4 CCR store + Restore** (§9, flag-gated) — all parallel behind W3.1;
  W3.2 implements `X-Stats-*` naming verbatim.

## Wave 4 — verification & perf (overlaps Waves 2–3 where noted)

- **W4.1 Property tests** (§12) — R3 parse validity, splice exactness,
  idempotence, marker escape-safety, restore identity. After W2.9.
- **W4.2 Determinism CI gate** (§5) — 1000× PR / 200k nightly soak / fuzz
  double-run / CPU-feature matrix (baseline vs AVX2 vs NEON). After W2.9.
- **W4.3 Criterion benches + nightly perf gate** (§8 per-stage budgets);
  measure the 8 MiB splice copy explicitly. After W2.9. **Gate M3**:
  ≥100 MB/s p50 aggregate.
- **W4.4 Adversarial perf fixtures** (§12) — unique floods, giant line,
  periodic patterns, collision pressure, maximal-density `},{`. Parallel
  with W4.3.
- **W4.5 Continuous fuzzing** (§12) — live from W1 onward; triage weekly.
- **W4.6 Offline eval harness** (§12) — tokenizer-based success metric +
  task-quality parity suite. Parallel from W2.9 onward (external models
  needed); **Gate M4** non-blocking until corpus/task suite ratified (§13).

## Critical path

```
W0.1 → S1(M1) → W1.1 → W2.1 → W2.9(M2) → W3.x → W4.3(M3)
secondary pole: W1.5 → W2.5 → W2.8 → W2.9
```

## Suggested staffing split (parallel tracks)

| Track | Waves | Notes |
|---|---|---|
| A | W0.1, W0.2, W1.4, W2.1, W2.7, W3.1 | ledger/splicer spine |
| B | W0.4, S1, W1.1, W2.9, W3.2/W3.3, W4.2 | locator + integration |
| C | W0.3, W1.3, W1.5, W2.5, W2.8, W4.6 | normalization/masking line |
| D | W1.6, W1.2, W2.2–W2.4, W2.6, W3.4, W4.1/W4.3/W4.4 | units + detectors |
