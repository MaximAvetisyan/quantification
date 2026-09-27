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
  Status: **complete** (2026-09-26). The normative locator is
  `quantification_core::locator`, the sniff is
  `quantification_core::sniff`; the S1 spike is untouched and still reachable as
  the perf harness under `quantification_core::spike` (its `s1/` path, benches
  and examples are unchanged apart from that re-export). Public API, frozen for
  W3.1/W3.3:
  `sniff::Schema {Chat, Responses, Messages, Text}` (+ `as_str`/`parse`, the
  fixed `CANDIDATE_ORDER`, `SNIFF_PREFIX_BYTES`),
  `sniff::sniff(&[u8]) -> Option<Schema>`,
  `locator::locate(&[u8], ScopePolicy) -> Located` (sniffs, then locates),
  `locator::locate_as(&[u8], Schema, ScopePolicy) -> Located` (caller-pinned
  content type — the hook W3.1's `422` rule and W3.3's proto enum need),
  `locator::locate_into(&[u8], Schema, ScopePolicy, &mut Vec<Span>) ->
  Option<NoopReason>` (caller-owned output buffer, allocation-free),
  `Located { schema: Option<Schema>, spans: Vec<Span>, noop_reason:
  Option<NoopReason> }` + `degraded()`, `Span { start, end, class:
  SpanClass{User,Tool} }` (private bookkeeping fields), `NoopReason
  {Malformed, UnknownSchema}` + `as_str()` → `"malformed"` /
  `"unknown_schema"`. W3.3 must map the proto `ContentType` enum (left
  unmapped by W1.6) onto `sniff::Schema`: `AUTO` ⇒ `sniff`, `CHAT` ⇒
  `locate_as(.., Schema::Chat, ..)`, etc.; Stats map as `degraded =
  noop_reason.is_some()` and `noop_reason = noop_reason.map(|r| r.as_str())`.
  **BOM offset contract (pinned, previously unpinned per the S1 review): span
  offsets are absolute byte offsets into the buffer exactly as passed in.** A
  leading `EF BB BF` occupies bytes 0..3, is never part of any span, and the
  splicer (W2.7) can therefore copy the input buffer and patch recorded ranges
  with no coordinate shift; `content_type=text` yields the single span
  `3..len` on a BOM payload. Asserted by
  `bom_offsets_are_absolute_in_the_original_buffer` (the span is located by
  index inside the post-BOM slice and its start is proved to be that index
  `+ 3`, with quotes on both sides). Sniff: one escape-aware pass over at most
  `SNIFF_PREFIX_BYTES = 64 KiB` collecting **root** (depth-1) keys, then the
  fixed candidate order decides. Frozen discriminators (§4.1 leaves them to the
  sniff): `Chat` = object root with `messages` and no Anthropic marker;
  `Responses` = object root with `input` and no `messages`; `Messages` =
  object root with `messages` and an Anthropic marker; `Text` = first non-ws
  byte is not `{ [ "` (so a chat↔Responses overlap resolves to Chat, per the
  fixture README). The Anthropic marker is a root `max_tokens` or root
  `system` (`max_tokens` is required by the Messages API; `system` is its
  top-level prompt) — `max_tokens` is therefore a tenth structural key, decoded
  like the other nine but never eligibility-relevant. A JSON-shaped payload
  with no candidate stays `None` ⇒ `noop_reason="unknown_schema"` (§3
  pass-through), not text. Locator: one pass, no tree, nothing unescaped — a
  string state machine (`\"`, `\\`, any 2-byte escape, `\uXXXX` consumed
  opaquely, raw control byte `< 0x20` ⇒ malformed) drives a fixed 64-frame
  state stack (`json_depth_cap`; depth 64 accepted, 65 degrades) carrying the
  bounded message-object state machine; spans are `(byte_start, byte_end)` of
  string *interiors* only, raw escaped bytes end-to-end. Eligibility map
  implemented exactly as the §4.1 table: chat `messages[i].content` +
  `content[j].text` where `type=="text"`; Responses root `input` string,
  `input[i]` message items as in chat, and `function_call_output.output`;
  Messages `messages[i].content`, `type=="text"` parts, and `tool_result`
  blocks whose `content` is a string or `[{type:"text",text}]` parts. Class is
  resolved bottom-up at container close: a part/block frame decides
  `type=="text"` / `type=="tool_result"`, the message frame resolves `role`
  (exact, case-sensitive) and the `function_call_output` item type, and the
  W0.2 `ScopePolicy` filters at the same point (`user_content` ⇒ `User` spans
  only, `user_and_tools` adds `Tool`). Frozen readings: `tool_result` ⇒ `Tool`
  regardless of the enclosing role, per the normative table's "regardless of
  enclosing message role"; the schemas do not borrow each other's keys (a
  Responses-pinned payload ignores `messages`, a Chat/Messages-pinned payload
  ignores root `input`, and root `system` is never eligible anywhere). Also
  frozen: an empty string value yields no span, a value longer than
  `max_span_bytes` is passed through (not a degrade) — on **both** paths, the
  `Schema::Text` whole-buffer span included, which the W1 review found
  uncapped — string escapes and number literals are consumed leniently (`\u`
  with non-hex or truncated bytes is opaque, so it can never produce a wrong
  range), and every one of the 26 W0.3
  fixtures is re-validated as a whole document. Duplicate object keys are
  **last occurrence wins** for both scalars (`role`, `type`) and candidate
  values, now at **any depth** and for the **whole shadowed subtree** (the W1
  review found the previous handling only dropped spans keyed on the innermost
  enclosing `(frame, key)`, so a candidate value nested behind an *additional*
  object member survived — an Anthropic `tool_result` whose `content` is a
  `[{type:"text",text}]` array, i.e. a Tool span under an assistant message that
  R4 forbids). The mechanism is a per-frame *frame id*: every container push
  takes the next id (`u32`, monotonic, so frame slots can be reused without
  aliasing), each span records the id of the frame that read it, and a key's
  value records `(enter, leave]` — the id interval its container value occupied
  (`enter` at the key, `leave` at the container's close, so every id in the
  subtree is inside the interval because a container's whole subtree is
  contiguous in push order). On a duplicate key every span from the frame's own
  output index onwards whose `read` is `(frame, key)` **or** whose frame id lies
  in that interval is dropped, which reaches arbitrarily deep shadowed values
  while leaving the spans of intervening members and of sibling frames (whose
  ids are outside the interval) untouched; scalar duplicates are covered by the
  `read` test alone. Not an error, not a degrade. Six regression tests
  (`a_duplicate_key_drops_the_whole_shadowed_value_subtree`,
  `a_duplicate_chat_content_drops_the_shadowed_parts`,
  `a_duplicate_key_drops_the_shadowed_subtree_at_any_depth`,
  `a_duplicate_key_keeps_the_spans_of_other_members_and_siblings`,
  `an_assistant_duplicate_never_leaks_the_shadowed_tool_span`,
  `duplicate_root_messages_keep_only_the_last_array`) pin the later value as a
  string / null / object / array / parts array, triple duplicates, the
  assistant-role shape, a depth-3 `content` duplicate and a duplicate root
  `messages`, all under both policies. Both S1-review defects are fixed and
  pinned by test: (a) every
  failure path clears the output vector, so a document truncated *after* a
  valid prefix can never emit a partial span set
  (`a_truncated_document_never_emits_a_partial_span_set` walks all 60-odd
  prefixes of a two-message payload), and (b) `run()` requires a fully closed
  root document — trailing bytes, a second document, or an unclosed container
  all degrade. Degradation covers every §4.1 acceptance-envelope trigger:
  unquoted identifiers, raw control characters (in keys or values), truncated
  documents/strings, trailing commas, typo'd `true`/`false`/`null` (only those
  three literals are matched exactly — number scanning is **lenient by design**,
  any run of `[0-9.eE+-]` containing a digit is accepted, so `01` or `1e` are
  not a degrade), depth > cap ⇒ whole-request
  pass-through with `degraded=true`, `noop_reason="malformed"`, zero spans.
  §5 on the hot path: integer-only, no `HashMap`/`RandomState`, no clock, RNG,
  env or float anywhere in the three new modules; the frame stack, the key
  decode buffer and the number scan are all fixed-size stack state, so the only
  allocation is the caller's output `Vec`. Tests: 7 unit tests in `keys.rs`, 4
  in `sniff.rs`, 48 integration tests in `crates/core/tests/locator.rs` (all
  W0.3 fixtures across `schemas/`, `shapes/`, `edges/` — chat/messages/
  responses minified+pretty, text-plain, content-null, mixed-parts,
  function-call-output, input-string, anthropic-system-top, anthropic-tool-result,
  sniff-overlap, bom-chat, dup-keys-last-wins, escaped-structural-keys,
  newlines-u000a-only, prior-markers, profitability-below-threshold and the
  single-line/stage-1b dumps — plus the eligibility map, both scope policies,
  exact role matching, caps, the seven nested/duplicate last-wins regressions
  and the text-path span cap, and 17 malformed/degradation vectors × 3 schemas ×
  2 policies), 16 in `crates/core/tests/sniff.rs`, and
  `crates/core/tests/locator_alloc.rs`, whose counting global allocator
  **asserts the hot loop allocates zero times** across six measured calls (a
  400-message/16 000-line payload under both policies and all three schemas,
  plus a >1 MB single-span payload and the text degenerate case) with the
  output vector pre-sized so even a growth would be counted. Core total 143
  (23 lib unit + 8 fingerprint + 48 locator + 1 locator-alloc + 9 mask +
  16 sniff + 30 splitter + 8 ws); workspace total 153. Fuzz (W0.4 targets, now
  wired to the real code): `fuzz_sniff` asserts the candidate invariant
  (a JSON schema requires an object root, `Text` requires a non-JSON first
  byte, unknown requires a JSON-shaped payload) and determinism;
  `fuzz_locator` runs every payload through all four pinned schemas and both
  policies and asserts the invariants R3 depends on — spans ascending and
  disjoint, in bounds, never covering the BOM, always delimited by quotes with
  no unescaped `"` or raw control byte inside (the splicer can therefore never
  produce invalid JSON), no `Tool` span under `user_content`, no span at all
  when degraded, byte-identical repeat runs, and — added by the W1 review, since
  the nested-shadow leak is exactly the class a black-box fuzzer misses — the
  **last-wins invariant**: a small independent lenient JSON walker in the target
  collects the value range of every non-final occurrence of the ten structural
  keys, and no reported span may fall inside one. The walker's key set is a
  subset of the locator's (it matches raw key bytes, the locator also matches
  decoded ones), so the check can only miss violations, never invent them; it
  bails out (no assertion) on documents it cannot parse or nesting past
  `DEPTH_CAP = 96`. It is not vacuous: replayed against the pre-fix locator it
  crashes on the exact `tool_result`-parts payload above
  (`artifacts/fuzz_locator/crash-0412dbb8…`, verified by reverting
  `locator.rs` and re-running the target), and is clean against the fix. One
  clean run each on
  2026-09-26, corpus seeded with all 26 W0.3 fixtures plus Anthropic-tool-result,
  Responses `function_call_output`, duplicate-key and BOM seeds: 200 000 runs,
  exit 0, zero crashes, 411 coverage points / 1416 features on the locator;
  re-run after the W1-review last-wins fix and the new invariant (same stable
  fallback, the corpus as found on disk, 1 584 seed files): 200 000 runs,
  exit 0, zero crashes, 519 coverage points / 1908 features.
  Toolchain deviation: nightly is still unreachable (static.rust-lang.org
  connection timeout), so both runs used the documented W0.4 fallback — stable
  1.98.0 with `RUSTC_BOOTSTRAP=1` and `cargo fuzz run --sanitizer none` (no
  ASan, which stable cannot enable). The nightly+ASan CI configuration is
  unchanged and must be exercised when nightly is reachable; corpus
  minimization stays W4.5 scope. Throughput sanity check (not a gate): the same
  8 MiB escaped-heavy S1 fixtures that the spike measured at 1495/1441 MB/s
  locate in 5.34 ms / 5.58 ms p50 = **1571 / 1501 MB/s** (pinned core, warm,
  `--release`), i.e. ≈3.9× the §8 400 MB/s floor; the W1-review last-wins
  rewrite leaves that path untouched (those fixtures have no duplicate keys, so
  `drop_key` never runs; the added state is one `u32` per span and 8 bytes per
  frame slot) and the figure was not re-measured. `fuzz/Cargo.lock`: the earlier
  claim that it "was left unstaged" was wrong — it was byte-identical to HEAD
  and simply **stale** (no `twox-hash` entry, which W1.4 added to core), so
  `cargo metadata --locked --manifest-path fuzz/Cargo.toml` failed and CI's
  `fuzz.yml` silently re-resolved the fuzz graph on every run. It is now
  regenerated and committed (only the `twox-hash 2.1.4` entry and core's
  dependency edge are added; no unrelated version churn), `cargo metadata
  --locked` succeeds and `cargo check` in `fuzz/` is clean. `fuzz/corpus/` is
  now **git-ignored** rather than committed: it holds ~2 500 libfuzzer-mutation
  artifacts (several >100 KB) of which only the 26 W0.3-derived seeds carry
  meaning, and those are already versioned as `crates/core/tests/fixtures/` and
  re-validated by the workspace suite — so the deterministic gate loses no
  coverage, while a committed corpus would freeze thousands of machine-named
  blobs that every run rewrites anyway. Deviations from DESIGN: none — §4.1's
  eligibility map, last-wins, decoded-key and acceptance-envelope rules are
  implemented as written and DESIGN.md is not amended; the sniff
  discriminators, `SNIFF_PREFIX_BYTES`, the BOM offset contract, the
  lenient-escape/number reading and the empty/oversized-span rules above are
  resolutions of details §4.1 explicitly leaves to the implementation, frozen
  here because §4.1/§5.7 freeze behavior per release. No new dependencies.
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
  drives it through `split_span`; the W1 review also made the module itself
  private, `mod stage1b`, since it exposed nothing publicly) keeps the literal
  §4.4 ranges `u_head` / `u_i` / `u_tail` on literal `},{` with **no edge
  special-casing**: 1-byte units are kept symmetrically (a line starting `},{`
  keeps the bare `}`; a line ending `},{` keeps the trailing `{`), empty units
  are discarded, and no-separator lines plus over-cap records stay verbatim.
  `eligible` is `len <= max_record_bytes`; an under-cap line never reaches
  stage 1b and stays one eligible unit. `Unit { range, eligible }` carries no
  joiner — `stage1::joiner` derives the gap from the distance to the next
  unit, so no duplicated state can drift, and it asserts its precondition
  (units ascending and disjoint, i.e. valid only on the *unfiltered* list — W2
  must re-derive `removed_bytes` from committed units instead of reusing this
  joiner, pinned by a `should_panic` test). `reassemble` is a test/reassembly
  helper, so it lives in the integration test and (as an independent oracle)
  in the fuzz target rather than in the public API. Added by the W1 review:
  `stage1::split_span_counted(span) -> Split { units, record_splits }` is the
  same walk, so §6.1's `X-Stats-Record-Splits` and §6.2's
  `Stats.record_splits = 18` are computable (W2.9); `split_span` is exactly its
  `units`, and `record_splits` counts **over-cap lines handed to stage 1b**
  (the §6.2 wording "over-cap lines re-segmented"), not records or separator
  cuts —
  frozen here because both readings are defensible and §5.7 freezes behaviour
  per release.
  Tests: 31 integration tests in `crates/core/tests/stage1_split.rs`
  (workspace total 40 = 9 config + 31 splitter). Exit criterion met: the
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
  Status: **complete** (2026-09-26). `fingerprint::fingerprint(bytes) -> u128`
  is xxh3-128 through the fixed seed `HASH_SEED = 0` (§5.1; frozen per
  release) and `fingerprint::marker_checksum(bytes) -> u16` is the low 16 bits
  of xxh3-64 over the same seed, i.e. exactly the §4.5 `CCCC` source (W2.6
  renders the four hex chars). `FingerprintTable` is a hand-rolled
  open-address table with linear probing over `(byte length, u128 hash)` keys
  plus the representative's key range and unit index; it never iterates, so
  there is no iteration-order dependency to leak into output, and it uses no
  `HashMap`/`RandomState` and no floats (§5.1). Every lookup is verified in the
  normative order **byte-length → fingerprint → memcmp**, and the W1 review made
  that the *literal* implementation (the probe tested `hash` before `len`; the
  two are observationally equivalent, but §4.4.2 names the order as the
  contract): it compares
  `len` first, then `hash`, then the key bytes, and a length-equal /
  hash-equal / bytes-different candidate is *rejected* and the probe
  continues, so such a pair coexists in the table (linear probing requires it)
  and a later real match is still found. Keys live in a caller-owned buffer
  (`keys: &[u8]` + a `Range`), so the same table serves all three comparison
  domains of §4.4: raw bytes for stage 3, a ws-normalized arena for stages
  4/5, a masked-form arena for stages 6/7. `insert` returns
  `Insert::{New, Duplicate(rep), Full}`; `find`/`insert_hashed`/`find_hashed`
  also accept a caller-supplied fingerprint so residual fingerprints are never
  recomputed — `insert_hashed`/`find_hashed` are `pub(crate)` since the W1
  review, because §4.4.2's "verified by memcmp" guarantee is only as strong as
  its call sites and nothing outside the module needs them. Caps are frozen in
  code: `for_keys(key_bytes)` pre-sizes to
  `key_bytes / 16` slots (smallest plausible unit), clamped to
  `MIN_SLOTS = 64` and `MAX_SLOTS = 262_144` (§7's "pre-sized from span
  bytes; hard cap"); growth doubles below the cap at a 75% load factor and
  rehashes in slot order, and at the cap `insert` returns `Full` and
  `is_full()` reports it, which is the §7 signal for W2 to degrade a
  pathological unique-line flood to pass-through with bounded memory
  (≈12 MiB worst case, independent of span size). The cap is not exotic: the
  75% load factor on `MAX_SLOTS` binds at **196 608 stored units** (the
  196 609th `insert` returns `Full`), which at the 16-bytes-per-unit sizing is
  ~3 MiB of keys, so *ordinary* large spans of unique lines reach it too — W2
  must treat `Full`/`is_full()` as a routine pass-through trigger, not a
  corner case.
  Tests: 5 unit tests in `fingerprint.rs` (the crate-private probe returns the
  rejecting stage, which pins the order: `Absent` / `Hash` / `Length` /
  `Memcmp` for constructed single-entry tables, plus memcmp-separated
  coexistence, duplicate-representative, `low 16 bits` of xxh3-64, and
  all-entries-still-findable across every growth step) and 8 integration tests
  in `crates/core/tests/fingerprint.rs` (fixed-seed golden vectors for
  xxh3-128/xxh3-64, 1000 distinct fingerprints, pre-sizing/clamping table,
  hard-cap saturation with no growth past `MAX_SLOTS` and no entry loss,
  insertion-order independence, raw-domain and ws-domain grouping over real
  stage-1 units, and zero-length keys). Core total 60
  (9 config + 5 fingerprint unit + 8 fingerprint + 30 splitter + 8 ws).
  Dependency: `twox-hash`, required as **`^2.1.2`** (`default-features = false`,
  features `std`, `xxhash3_128`, `xxhash3_64`) and pinned to **2.1.4** by both
  the workspace `Cargo.lock` and `fuzz/Cargo.lock` (the W1.1 block previously
  claimed a flat "2.1.2"), chosen over hand-rolling XXH3 and over
  `xxhash-rust`, whose BSD-2-Clause is outside the `deny.toml` allow list.
  MIT, no transitive dependencies (`rand`/`serde` are optional and off), and
  its runtime SSE2/AVX2/NEON dispatch is bit-exact for xxh3, which §5.9
  explicitly accepts; the scalar path is the reference. `Cargo.lock` is
  committed here because the new dependency requires it — note the file also
  picks up the W1.6 proto entries, which that commit left out of
  `fuzz/Cargo.lock` (see the W1.1 block: that omission was a stale file, not a
  staged/unstaged split, and is now fixed and committed).
  Deviations from DESIGN: none. DESIGN.md is not amended; the only judgement
  calls are the frozen numbers §7 leaves open (`16` bytes per unit, the
  `64`/`262_144` slot bounds, the 75% load factor — and the resulting
  196 608-unit cap W2 must handle) and `CCCC` using the same
  fixed seed as the fingerprints.
- **W1.5 Mask automata** (§4.6) — six masks, priority order,
  leftmost-longest. Exit: golden mask vectors.
  Status: **complete** (2026-09-26). `MASK_LIST` is the frozen
  `{ts} {ip} {uuid} {hex} {dur} {num}` order and `Mask::placeholder()` returns
  the §4.6 placeholders `<ts> <ip> <uuid> <hex> <dur> <num>`, all `[a-z<>]`
  only. `mask(ws_line)` / `mask_into(ws_line, out)` consume a **ws-normalized
  line** (§4.2 / W1.3) in one left-to-right pass and allocate nothing on the
  scratch path: at each position the six masks are tried in listed priority
  order and the first match wins, taking that mask's longest match at that
  position, so the resolution rule is *leftmost, then priority, then
  longest*; the masked range is emitted as the placeholder and the scan
  resumes after it, so nothing is ever re-scanned. No regex engine, no
  backtracking, integer comparisons only (§4.6). Escape units are opaque:
  a complete `\uXXXX` (or any 2-byte escape, truncated tails included, clamped
  exactly as stage 1 clamps) is copied verbatim, so `{num}` never eats the
  digits of `\u0031` and the §4.2 rule that obliquely-encoded escapes are
  invisible to masking holds. The masked form is a plain byte string that
  stage 6 fingerprints and stage 7 memcmps; it is never emitted (the anchor
  stays the original escaped bytes, §4.6/§4.5).
  Informal §4.6 patterns resolved and frozen (as golden vectors): `{ts}` =
  `\d{4}-\d{2}-\d{2}` with an optional `T|t|space` time
  `\d{2}:\d{2}:\d{2}`, optional `.\d+` fraction and optional `Z|z|+hh:mm|-hhmm`
  offset, **or** the syslog `Xyz dd hh:mm:ss` form (any upper+2 lower month
  letters, 1–2 digit day, one or more spaces, so it also works on
  un-normalized input); `{ip}` = dotted quad with 1–3 digit octets ≤255, or
  IPv6 with 1–4 hex-digit groups, at most one `::`, an optional trailing IPv4
  (`::ffff:192.168.1.1`), 8 groups when uncompressed and ≥1 compressed group
  otherwise (`::` alone and zone ids are not matched); `{uuid}` = 8-4-4-4-12
  hex groups exactly, case-insensitive (a 32-hex dashless id is `{hex}`, as
  the priority order requires); `{hex}` = a maximal run of ≥`HEX_MIN_RUN = 16`
  hex chars, case-insensitive; `{dur}` = `\d+([.]\d+)?` plus `ns|us|ms|s|m|h`
  (2-char units tried before 1-char, `u` alone is not a unit);
  `{num}` = `\d+([.]\d+)?` with no sign and no exponent. Consequence pinned
  by test: at one position priority beats the lower-priority mask, so
  `12345678901234567ms` is `<hex>ms` (`{hex}` is 4, `{dur}` is 5) while
  `5ms` is `<dur>` and `1.2.3.4.5` is `<ip>.<num>`.
  Tests: 9 integration tests in `crates/core/tests/mask.rs` (frozen list and
  placeholder charset, 61 golden vectors grouped per mask, rejected forms
  never producing their placeholder, escape-unit opacity, leftmost-longest
  resolution, idempotence of the mask list over its own output for every
  golden plus 400 LCG-generated lines, and a ws-normalized stage-1 span whose
  masked forms memcmp-equal across near-duplicate lines and differ on a real
  field change). Core total 69 (14 lib unit + 8 fingerprint + 9 mask +
  30 splitter + 8 ws).
  Deviations from DESIGN: none — the §4.6 table is implemented as written and
  DESIGN.md is not amended. The pattern details above are the resolutions of
  §4.6's explicitly informal column, frozen here because §4.6 freezes the
  list per release. No new dependencies.
- **W1.6 Proto crate** (§6.2) — corrected .proto compiles; tonic codegen;
  shared types. Independent of core.
  Status: **complete** (2026-09-26; status block added by the W1 review, which
  found the task had none). `crates/proto` builds the corrected
  `compressor/v1/compressor.proto` in `build.rs` with tonic/prost codegen and
  converts between the generated types and `quantification_core::config`
  (`RawOptions`/`ResolvedOptions`, `ScopePolicy`, `MarkerStyle`, `Stats`).
  Tests: 10 unit tests (`wire_numbers_and_names_pinned`,
  `enum_conversions_roundtrip`, `omitted_bools_resolve_to_defaults`,
  `explicit_true_is_not_omitted`,
  `explicit_false_survives_wire_and_resolves_false`,
  `min_group_size_one_rejected`, `reserved_scope_policy_rejected`,
  `stats_wire_fields_pinned`, `service_codegen_present`). Three deviations
  from §6.2 as written are recorded here rather than in DESIGN.md, which this
  wave did not amend:
  (a) **`MarkerStyle` values are `MARKER_STYLE_AUTO` / `MARKER_STYLE_ASCII` /
  `MARKER_STYLE_UNICODE`** (and `ContentType` symmetrically
  `CONTENT_TYPE_*`) because proto3 C++ scoping forbids two enums in the same
  package from both defining the bare value `AUTO` — `ScopePolicy` and
  `MarkerStyle` collided, and the collision is a codegen error, not a
  warning. Wire numbers are unchanged (`0`/`1`/`2`) and pinned by
  `wire_numbers_and_names_pinned`, so the wire contract §6.2 specifies is
  intact and only the JSON/text names differ. **DESIGN.md §6.2 should be
  amended to match**: §6.2's block is the normative source for the enum
  spellings, §5.7 freezes *behaviour* rather than identifiers, and the
  alternative (freezing the §6.2 spelling as-is) would mean shipping a proto
  that its own design document says should not compile. Open item for W3.3:
  gRPC clients must send `MARKER_STYLE_*`; the generated `from_str_name`
  rejects the bare `UNICODE`, which the test pins.
  (b) `Options.normalize_ws`, `Options.reversible` and
  `Options.template_dedup` are `optional bool`, not plain `bool`. proto3
  scalars have no presence, so a default-true option would be
  indistinguishable from "caller asked for false"; `optional` restores
  presence. This is wire-identical for the encodings §6.1/§6.2 can produce
  (the value is still a `bool` on the wire) and preserves §6.1's default-true
  semantics end to end; the conversion layer resolves absent ⇒ §7 default
  (pinned by `omitted_bools_resolve_to_defaults` and the explicit-true/false
  wire tests).
  (c) **§6.2 pins `rpc Restore(RestoreRequest) returns (RestoreResponse)` but
  defines no message bodies**, so `RestoreRequest { bytes payload = 1; string
  restore_id = 2; }` and `RestoreResponse { bytes original = 1; }` were
  invented here (the field names mirror §9's "compressed + id → original" and
  §6.1's `/v1/restore`). **W3.3 and W3.4 inherit this shape** and must either
  adopt it or amend it in DESIGN.md before either ships; the HTTP side
  (§6.1) is unpinned by DESIGN.md in the same way. Deviations from DESIGN
  overall: these three, recorded here; §6.2's
  `CompressRequest`/`CompressResponse`/`Stats` bodies, all field numbers and
  the unary-only service shape are as written.

## Wave 2 — detectors & output (deps W1)

- **W2.1 Commit ledger + profitability gate** (§4.4) — removal rule (member
  union + joiners), anchor-offset emit ordering, stats counters. Deps:
  W1.2, W1.4. Defines the interface every detector commits through.
  Status: **complete** (2026-09-26). The ledger is
  `quantification_core::ledger`; a detector never touches bytes, it proposes a
  group and the ledger answers with a `Commit` or a rejection reason. Public
  API, frozen for W2.2–W2.9:
  `CommitKind {ExactRun, WsRun, Block, TemplateGroup, TemplatedBlock}` +
  `core(style) -> (prefix, suffix)` (the §4.5 `CORE` halves, both styles) and
  the §6.2 counter mapping; `framing(style) -> (OPEN, SEP, CLOSE)`;
  `decimal_width(u64) -> usize`; `marker_len(style, kind, count) -> usize`
  (exact rendered width, the 4 hex checksum bytes included);
  `profitable(style, kind, count, anchor_bytes, removed_bytes) -> bool`, the
  one normative gate all five detectors share, strict `<`;
  `removal_range(&[Unit], Range<usize>) -> Range<usize>` (the normative
  removal rule); `Proposal {group, anchor_units, count, kind}` with
  `Proposal::new(..)`, `Proposal::run(group, kind)` (line groups, stages
  3/4/6) and `Proposal::repeat(group, anchor_units, kind)` (block groups,
  stages 5/7);
  `Commit {kind, first, last, count, anchor, removed}` + `members()`;
  `CommitOutcome {Committed(Commit), InvalidGroup, InvalidAnchor,
  InvalidCount, Ineligible, Overlapped, BelowThreshold}`;
  `Ledger::new(&[Unit], MarkerStyle)`, `units()`, `marker_style()`,
  `commits()` (already in emit order), `is_committed(unit)`,
  `is_free(group)`, `residual() -> impl Iterator<Item = (usize, &Unit)>`,
  `try_commit(Proposal) -> CommitOutcome`; `StageStats {groups_collapsed,
  exact_runs, ws_runs, block_repeats, template_groups, templated_blocks,
  record_splits}` (plain data + `bump(kind)` + `merge(&StageStats)`, filled by
  the W2.9 pipeline; no clock, no I/O — elapsed timings stay W2.9). Frozen
  semantics: (a) **the removal range is derived from indices into the
  immutable full unit list**, never from a filtered residual, so the W1.2
  joiner hazard cannot inflate `removed_bytes` — `removal_range(a..b)` is
  `units[a].range.start..units[b-1].range.end`, which *is* the member union
  plus the inter-member joiners (the line-boundary escape runs resp. the
  single `,` bytes) and nothing else; the joiners of surviving neighbours
  stay outside it, so a marker replaces exactly that range and the
  neighbours remain one line/record apart. (b) Anchor = the first member for
  stages 3/4/6 (`anchor_units = 1`) and the whole first occurrence for stages
  5/7 (`anchor_units = L`); `anchor ⊆ removed` always, so W2.7 emits
  `anchor bytes + marker` over `removed` — the anchor is a sub-range of the
  range it replaces, not a separate edit. (c) Check order in `try_commit`:
  `InvalidGroup` → `InvalidAnchor` → `InvalidCount` → `Ineligible` (a
  member with `eligible == false`, i.e. an over-cap record, can never be
  committed) → `Overlapped` → `BelowThreshold`; a rejected proposal claims
  nothing, so a below-threshold group stays verbatim *and* remains available
  to later stages. (d) **Overlap ownership** is per unit
  (`claimed: Vec<bool>` over the full list): any claimed member rejects the
  whole proposal, which is exactly the §4.4 "earlier-stage commitments own
  their lines and win all overlaps" rule and also makes a residual run that
  straddles a committed region impossible to express. (e) **Emit ordering** is
  maintained structurally: a commit is inserted at
  `commits.partition_point(|c| c.anchor.start < new.anchor.start)`, so
  `commits()` is ascending by anchor byte offset whatever the discovery
  order — no sort at the end, no hash-table iteration anywhere. (f)
  **The marker count is the number of copies omitted, not the group size.**
  DESIGN.md:493 glosses the grammar as `⟪… ×N⟫` ≈ "N omitted identical rows",
  and §4.7's information-loss table puts the count on the *destroyed* side
  ("first copy verbatim + count" kept / "every other copy in full"
  destroyed); §1's worked example agrees (one literal line plus
  `...(x200 more)...` ⇒ `⟪×200 rows, template⟫`, i.e. 201 total). Hence
  `Proposal::run` derives `count = group.len() - 1` for stages 3/4/6 and
  `Proposal::repeat` derives `count = copies - 1` for stages 5/7
  (`copies = group.len() / anchor_units`) — the `-1` is applied where the
  count is **derived**, not at render time, so the §4.4 gate prices the
  exact decimal width of the count actually emitted (a 200-copy run emits
  `×199`, a 10-member run `×9`, an 11-member run `×10`); `count == 0` and
  `anchor_units == 0` are rejected, so a 2-member run is `N = 1` and commits
  whenever it is profitable. (g) `MarkerStyle::Auto` is refused by
  `Ledger::new` — the caller (W2.9) resolves auto/ascii per span first,
  because the gate's `marker_bytes` depends on the style. Tests: 38
  integration tests in `crates/core/tests/ledger.rs` (core total 182 =
  23 lib unit + 8 fingerprint + 38 ledger + 48 locator + 1 locator-alloc +
  9 mask + 16 sniff + 31 splitter + 8 ws; workspace total 192, of which
  proto/server 10). Exit criteria met:
  removal-rule ranges are pinned for `\n`/2-byte, 6-byte `\u000A`/`\u000a`,
  concatenated-boundary and `,` joiners, for multi-member and single-member
  groups, for groups at the very start and the very end of a span, and for a
  span that mixes line units and stage-1b record units in one group sequence;
  an `assert_removal_invariant` helper re-derives every range as
  Σ member bytes + Σ inter-member gaps and runs over each commit;
  the threshold is exercised at exact equality (11 + 26 = 37 = removed ⇒
  `BelowThreshold`, both unicode and the 32-byte ascii `ws-equal` shape) and
  one byte either side; `decimal_width` is pinned against
  `u64::to_string().len()` for 0/1/9/10/99/100/999/1000/9999/10000/10^6/
  `u64::MAX` and `marker_len` is pinned for all ten kind×style shapes (with
  the width carry at 10, 100 and 1000); the omitted-count semantics are
  pinned on the rendered marker *bytes* (assembled in-test from the frozen
  `framing`/`core`/`decimal_width`/`CCCC` pieces) for 2-, 10-, 11- and
  200-member exact runs and for block groups of 2×3 and 3×2 units —
  `⟪×1 identical ·4141⟫`, `⟪×9 identical ·72bf⟫`, `⟪×10 identical ·72bf⟫`,
  `⟪×199 identical ·72bf⟫`, `⟪block ×1 ·1c69⟫`, `⟪block ×2 ·0e13⟫` and
  their ascii twins (`[... x1 identical 4141 ...]`, `[... x9 identical
  72bf ...]`, `[... x10 identical 72bf ...]`, `[... x199 identical 72bf
  ...]`, `[... block x1 1c69 ...]`, `[... block x2 0e13 ...]`); the gate is
  pinned on the *emitted* count's width at the decimal carry: a 10-member run
  of 1-byte lines commits (1 + 26 < 28) exactly where pricing `N = 10` would
  have rejected it, an 11-member run emits the 2-digit `×10`
  (1 + 27 < 29), and `marker_len(10) - marker_len(9) == 1`; emit order is
  asserted for a back-to-front discovery order and for three orderings of
  the same span;
  overlap rejection covers a proposal overlapping from the left, the right,
  both sides, a span crossing a committed region, an adjacent (legal)
  neighbour commit, and `is_committed`/`is_free`/`residual` afterwards. The
  hazard W1.2 warned about is pinned numerically rather than by panic: after
  `6..9` commits, the residual joiner of the unit before the committed region
  measures 98 bytes where the honest gap is 2, and a proposal spanning the
  committed region is `Overlapped` while `3..6` still measures exactly
  3×30 + 2×2. A source-scan test asserts the module contains no `HashMap`,
  `RandomState`, `BTreeMap`, clock, env, RNG, float or sort
  (`ledger_path_has_no_forbidden_determinism_inputs`), matching §5.1–§5.5;
  the ledger is integer-only and allocation happens once per span
  (`claimed`) plus once per commit (`Vec::insert`). Deviations from DESIGN:
  none — §4.4's removal rule, strict profitability gate, stage ordering,
  anchor-offset emit order and the §6.2 counter set are implemented as
  written and DESIGN.md is not amended. The readings frozen in (a)–(g) above
  resolve points §4.4/§4.5 leave to the implementation, frozen here because
  §5.7 freezes behaviour per release. (f) is no longer a judgement call: it is
  pinned to DESIGN.md:493, which §4.7's table and §1's worked example both
  corroborate, so the `N`-includes-the-anchor reading the first W2.1 commit
  froze is corrected — W2.2–W2.8 inherit the omitted-copy convention for free
  by calling `Proposal::run` / `Proposal::repeat` instead of counting
  themselves. No new dependencies.
- **W2.2 Stage 3 exact runs** ∥ **W2.3 Stage 4 ws-runs** ∥
  **W2.4 Stage 5 repeated blocks** (ws-normalized domain) ∥
  **W2.5 Stage 6 template groups** — all after W2.1
  (W2.4 also needs W1.3; W2.5 also needs W1.5).
  Status (W2.2): **complete** (2026-09-26). Stage 3 is
  `quantification_core::detect::exact::exact_runs(span: &[u8], ledger: &mut
  Ledger, min_group_size: u32) -> StageStats` (module `detect::exact`, the
  only content of `detect/mod.rs` so far). `span` is the **eligible span's raw
  escaped bytes** and `ledger` is the W2.1 ledger over the **full** stage-1/1b
  unit list of that span — indices, not filtered offsets, so W2.1's
  `removal_range` derivation and its W1.2 joiner hazard stay inapplicable. The
  returned `StageStats` holds only this stage's commits (`exact_runs` ==
  `groups_collapsed`, all other counters 0) and W2.9 merges it into §6.2's
  `Stats` with `StageStats::merge`; the caller resolves `min_group_size` from
  the options (§7) and the marker style first (`Ledger::new` refuses `Auto`,
  so W2.6's `resolve_style` must precede it). Algorithm — integer-only,
  allocation-free, one linear pass: walk the unit list in ascending index order
  (the only order available, so leftmost-first and §5.4's "first occurrence in
  byte order wins" hold by construction, with no hash table anywhere on the
  path) and extend a maximal run while the candidate unit is (a) unclaimed
  (`Ledger::is_committed`, hence a residual run can never straddle an earlier
  stage's committed region), (b) `eligible` — an over-cap record is a verbatim
  wall that is never grouped, never hashed and breaks the run on both sides —
  and (c) equal to the run head in the §4.4 stage-3 comparison domain, **raw
  bytes**, verified in the normative order byte-length → xxh3-128 → `memcmp`
  (`fingerprint::fingerprint`, so §4.4.2's order is the literal code, not a
  table probe). Runs shorter than `min_group_size.max(2)` are not proposed;
  a proposed run is the **maximal** run and the decision is left entirely to
  `Ledger::try_commit(Proposal::run(group, CommitKind::ExactRun))`, so the
  §4.4 gate prices anchor + marker (with the exact decimal width of the
  emitted omitted-copy count) against the removal-rule range, and a
  `BelowThreshold` group claims nothing, stays verbatim and stays available to
  stages 4–7. Frozen readings: (a) a rejected run is **skipped whole**
  (`at = end`), never re-proposed as a shorter sub-range — a sub-range has
  strictly smaller `removed_bytes` and a no-larger marker, so it can never be
  more profitable, and skipping keeps the group whole for the later stages;
  (b) candidates are compared against the run **head**, which is equivalent to
  comparing against the previous unit (byte equality is transitive) and keeps
  the work linear in span bytes; (c) **no `FingerprintTable`**: stage 3 only
  asks "is this adjacent unit the same as the last one", so §7's table cap and
  W1.4's `Full`/`is_full()` ⇒ pass-through signal are not reachable from here
  (W2.4/W2.5 own the table); (d) `walk_runs(ledger, min_group_size, kind,
  same)` is `pub(crate)` and is the shared run walker — the comparison closure
  is the only difference between stage 3 and stage 4, which is what keeps the
  two stages' residual, ordering and minimum-size rules literally identical.
  Tests: 14 integration tests in `crates/core/tests/detect_exact.rs` (core total
  207 = 23 lib unit + 8 fingerprint + 38 ledger + 48 locator + 1 locator-alloc +
  9 mask + 11 render + 16 sniff + 31 splitter + 8 ws + 14 exact runs; workspace
  total 217). Exit criteria met: a 5×40-byte run commits as one `ExactRun`
  (count 4, anchor = the first line's range, `removed` = `5*40 + 2*4`); a
  below-threshold run (3×4-byte lines) claims nothing while the 3×40-byte run
  behind it commits, `is_free(0..3)` and `residual() == [0,1,2]` hold, a second
  call is a no-op, and the same shape with 20-byte lines commits — so the
  rejection is the gate, not a grouping failure; the count width is priced at
  the carry (ten 1-byte lines commit with count 9 because `1 + 26 < 28` while
  `profitable(.., 10, 1, 28)` is false, eleven 1-byte lines commit with the
  two-digit count 10, `marker_len(10) - marker_len(9) == 1`); the raw domain
  refuses to merge padding variants that stage 4 will merge (a 3×`\t` run and a
  3×double-space run commit as two groups, never one), and raw-identical lines
  commit with the same result on a second ledger, with a source assertion that
  the module contains neither `normalize_ws` nor `normalize` at all; an
  over-cap record in the middle of a 401-record dump splits two runs, stays
  unclaimed and free, and leaves the bracket-carrying `u_head`/`u_tail`
  verbatim; the removal rule is exercised in one span over `\n`, 6-byte
  `\u000A` and `,` joiners (removed lengths `3*40+2*2`, `3*40+2*6`,
  `398*200+397`, every commit re-derived as Σ member bytes + Σ inter-member
  gaps, and the surviving neighbours' joiners proven to stay outside every
  removed range); overlap and adjacency are exercised against a pre-committed
  `2..4` block (with `min_group_size` 2 the residual runs `0..2` and `4..6`
  commit, giving three anchor-ordered commits and no group crossing the claimed
  region; with 3 they commit nothing and leave `[0,1,4,5]`); empty, single-unit
  and single-over-cap-line spans commit nothing without panicking; determinism
  is checked over a 400-line LCG span (two ledgers ⇒ identical `commits()` and
  byte-identical spliced output assembled in-test from anchor bytes + the
  frozen marker bytes, and a re-run on a committed ledger changes nothing);
  determinism inputs are source-scanned. Deviations from DESIGN: none — §4.4's
  stage-3 rule, the §4.4 stage ordering, comparison domain, removal rule and
  profitability gate are implemented as written and DESIGN.md is not amended.
  The readings in (a)–(d) resolve points §4.4 leaves to the implementation,
  frozen here because §5.7 freezes behaviour per release. No new dependencies.
  Status (W2.3): **complete** (2026-09-26). Stage 4 is
  `quantification_core::detect::wsruns::ws_runs(span: &[u8], ledger: &mut
  Ledger, min_group_size: u32, scratch: &mut Scratch) -> StageStats`, plus
  `wsruns::Scratch` (`#[derive(Default)]`, `Scratch::with_capacity(head, next)`
  and `Scratch::reserved() -> (usize, usize)` for introspection). `span`,
  `ledger` and `min_group_size` are W2.2's arguments unchanged, so the two
  stages differ in exactly one thing: the comparison. Stage 4's comparison
  domain is the §4.2 **ws-normalized** form of each unit, produced by
  `wsnorm::normalize_into` (W1.3) into the two caller-owned `Scratch` buffers,
  and the equality claim is verified in the same normative order — normalized
  byte-length → xxh3-128 of the normalized form → `memcmp` of the normalized
  bytes (`fingerprint::fingerprint`) — so a pair that is equal normalized but
  differs raw is merged, exactly as §4.4's comparison-domain paragraph
  prescribes. The **anchor is always the raw original escaped bytes** (the
  ledger's anchor range is a sub-range of the removal range and W2.7 emits
  `span[anchor]`, never a normalized or masked form), so a merged group's
  marker checksum and echoed line are the first member verbatim. Everything
  else is inherited literally from W2.2 by construction: both stages call the
  same `pub(crate) detect::exact::walk_runs`, hence the same residual-only walk
  (an unclaimed unit is the only candidate, so a run can never straddle an
  earlier stage's committed region), the same `eligible`-only rule (an over-cap
  record is a verbatim wall that is never normalized, never grouped and never
  committed), the same `min_group_size.max(2)` floor, the same maximal-run
  proposal, the same "skip a rejected run whole" rule, the same
  `Proposal::run(group, CommitKind::WsRun)` commit (hence the removal rule and
  the §4.4 gate, with the omitted-copy count priced at its exact decimal
  width), and the same ascending-index discovery order — leftmost-first with no
  hash table on the path (§5.1, §5.4). Frozen readings: (a) the `Scratch` is
  **caller-owned and reused**, so the pipeline allocates it once per compaction
  pass and hands the same `&mut Scratch` to every span; `with_capacity` is
  sized by the longest unit of the span (the normalized form never grows, so
  the buffers never reallocate) and `default()` grows to at most 2× that;
  `reserved()` exposes the capacities so the property is assertable — this is
  the "no per-line allocation" requirement, pinned by test over 2000 lines
  rather than by a global-allocator harness. (b) The run head is
  re-normalized into `Scratch::head` for every candidate instead of being
  cached, which keeps the walker free of per-run state and the total work
  linear in span bytes; the same reading as W2.2 (b). (c) The stage-4 gate
  flag is **not** a parameter: `normalize_ws = false` means the pipeline skips
  stage 4 altogether (there is nothing to configure per call), which is why
  W2.2's raw-domain detector must not and does not know the option. (d) No
  `FingerprintTable` here either, for W2.2's reason (c).
  Tests: 13 integration tests in `crates/core/tests/detect_wsruns.rs` (core total
  230 = 23 lib unit + 8 fingerprint + 38 ledger + 48 locator + 1 locator-alloc +
  9 mask + 11 render + 16 sniff + 10 splice + 31 splitter + 8 ws + 14 exact runs
  + 13 ws runs; workspace total 240, of which 10 are W2.7's and 10 W1.6's proto
  unit tests).
  Exit criteria met: a four-line span whose raw lengths all differ
  (`\t` = 31 B, five spaces = 34 B, mixed = 34 B, plain = 30 B) and whose
  normalized forms are equal is committed by **stage 4 alone** — the same span
  and ledger through `exact_runs` yields zero commits — as one `WsRun` with
  count 3, `removed` = Σ raw lengths + `2*3`, marker length 31; the anchor is
  pinned to the raw `\t` bytes and asserted to differ from its own normalized
  form (so the anchor is raw, not normalized); a 3×raw-identical run followed by
  a 3×ws-equal run commits as `ExactRun 0..2` then `WsRun 3..5`, i.e. stage 4
  only ever sees the residual; a below-threshold ws run (three 7–8-byte padded
  forms) claims nothing, stays free and residual, and the same shape with
  31-byte lines commits, so the rejection is the gate and not a grouping
  failure; `min_group_size` 3 refuses a two-member ws group and 2 commits it
  (`count = 1`, 31-byte marker), 4 refuses a three-member one; an over-cap
  record in the middle of a 401-record dump splits two ws runs, is itself never
  normalized into a group (`is_free`, unclaimed), leaves the bracket-carrying
  `u_head`/`u_tail` verbatim, and the same dump commits nothing through
  `exact_runs`; a 400-record single-line tool dump whose records differ only in
  `\t` vs `\r` padding (equal normalized, unequal raw, and no two adjacent raw
  forms equal) commits as one ws run over the 398 middle records with
  `removed` = `398*200 + 397` and a normalized-equal anchor/member pair; a ws
  run never straddles a committed exact run (with `2..4` claimed by stage 3 the
  ws detector commits only `0..1`, the residual `[0,1,4,5]`-style fragment and
  unit 4 stay verbatim, and the same ledger pre-committed by hand gives the
  identical two commits); leading/trailing/interior padding collapses to one
  form and the anchor keeps its edge whitespace; the scratch is asserted to
  stay at its pre-sized capacity across a 2000-line span and a subsequent
  small span, a `default()` scratch stays within 2× the longest unit, and both
  produce identical commits; empty, single-unit and single-over-cap-line spans
  commit nothing; determinism is checked over two 400-line LCG spans with
  random padding (two ledgers and two differently-initialised scratches ⇒
  identical `commits()` and byte-identical spliced output assembled in-test),
  and a re-run on a committed ledger changes nothing; determinism inputs are
  source-scanned. Deviations from DESIGN: none — §4.4.4, §4.2's escape-unit
  collapse, the comparison-domain paragraph, the removal rule and the
  profitability gate are implemented as written and DESIGN.md is not amended.
  The readings in (a)–(d) resolve points §4.4/§8 leave to the implementation
  (scratch ownership and where the `normalize_ws` switch lives), frozen here
  because §5.7 freezes behaviour per release. No new dependencies.
  Status (W2.5): **complete** (2026-09-26). Stage 6 is
  `quantification_core::detect::templ::template_groups(span: &[u8], ledger: &mut
  Ledger, min_group_size: u32, scratch: &mut Scratch) -> Templated`, plus
  `templ::Scratch` (the caller-owned two-buffer transform, as W2.3's), the
  **stage-7 handoff** `templ::Templated { pub stats: StageStats, pub forms:
  Forms, pub degraded: bool }` with `templ::Forms { pub bytes: Vec<u8>, pub units:
  Vec<Template> }`, `templ::Template { pub masked: Range<usize>, pub id:
  TemplateId, pub hash: u128 }`, `TemplateId(pub u64)`, and the accessors
  `Forms::len` / `is_empty` / `masked(unit) -> &[u8]` / `id(unit) -> TemplateId`
  / `same(left, right) -> bool`; `Forms::units[i]` is the entry of **ledger unit
  `i`**, so `Forms` and the ledger are index-aligned and `forms.masked(i)` /
  `forms.id(i)` are exactly the per-unit masked form and template id §4.4.6's
  handoff promises. `span` and `ledger` are W2.2's arguments unchanged, and the
  module is declared by the one added line `pub mod templ;` in
  `crates/core/src/detect/mod.rs` (that file, not `lib.rs`, holds `detect`'s
  submodule declarations; `lib.rs` keeps its single `pub mod detect;`).
  The comparison domain is §4.4's **masked form**: each unit's raw bytes are
  ws-normalized into `Scratch::ws` (§4.2 / W1.3) and masked into `Scratch::form`
  (§4.6 / W1.5, the frozen six-mask priority order used as written,
  leftmost-longest, hand-written byte automata), and the masked form is appended
  to the per-call `Forms::bytes` arena, so there is no per-unit allocation. Every
  equality claim is verified in the normative order byte-length → xxh3-128 →
  `memcmp` of the **masked** bytes, once inside `FingerprintTable::insert_hashed`
  (the interning pass, and the source of the `Insert::Duplicate(rep)` id) and
  again on the commit path in `Forms::same` — W1.4's verification entry points
  are `pub(crate)` and the group claim is a stage-6 claim, so the stage
  re-derives the same three-step order literally rather than trusting the
  table. The **anchor is always the original raw escaped bytes**:
  `Proposal::run(group, CommitKind::TemplateGroup)` makes the first member the
  anchor and W2.7 emits `span[anchor]`, never a normalized or masked form, so a
  committed group's marker checksum and echoed line are the first line verbatim,
  byte for byte, with its own timestamp/IP/uuid/counter. Frozen readings:
  (a) a stage-6 group is a **contiguous run** of equal masked forms, not the set
  of all same-template units in the span: `Proposal::run` takes a `Range<usize>`
  and derives the count as `len - 1`, and §4.4.1b's removal rule is stated for
  "consecutive units `u_a..u_b`", so a non-contiguous group is not expressible
  in the frozen W2.1 API (and a range spanning the interleaved lines would
  destroy them). This is the same reading as §4.4's "Non-consecutive duplicates
  are **not** compacted in v1 (digest mode deferred)", which leaves digest mode
  to v2 (§10). (b) The `TemplateId` is the **low 64 bits of the xxh3-128 of the
  masked form**, so an id is a pure function of the template bytes: equal
  templates always get equal ids, ids are stable across spans and across input
  orderings, and nothing depends on table probe or insertion order (§5.1,
  §5.4). Unequal templates could in principle share the low 64 bits; §4.4.7
  verifies a stage-7 join by `memcmp` of the masked-form bytes, so such a
  collision costs a missed merge and never a wrong merge — and stage 6 itself
  never keys on the id, only on the three-step verification. The full 128-bit
  `hash` is kept per unit so the normative order uses the whole digest and
  stage 7 gets a cheap pre-filter for free. (c) Coverage is **dense over every
  unit of the span** in ascending index order, committed or not: a unit already
  claimed by stage 3, 4 or 5 and an over-cap `eligible == false` record both
  still receive a masked form and an id, because §4.4.6's handoff is stated for
  "every residual line" (they are the residual of *this* stage) and a dense
  array keeps stage 7's windowed scan index-aligned with the ledger instead of
  needing an offset map; an over-cap unit is still a wall for stage 7 as it is
  here. (d) `FingerprintTable::for_keys(span.len())` pre-sizes the table from
  the span's bytes (W1.4's sizing) and `Insert::Full` **degrades the whole
  span**: the stage returns `Templated { stats: StageStats::default(), forms:
  Forms::default(), degraded: true }` — zero commits, no forms, no panic, no
  silent truncation — which is §7's bounded-memory pass-through signal and
  W2.9's `Stats.degraded`; earlier stages' commits are untouched, they are the
  earlier stages' decisions. (e) The run walk is a local `walk_templates` rather
  than W2.2's `pub(crate) walk_runs`, whose closure receives a `&Unit` while the
  masked comparison needs the unit's index into `Forms`; it is otherwise
  literally W2.2's walker (residual-only, `eligible`-only, the
  `min_group_size.max(2)` floor, the maximal run, skip-a-rejected-run-whole,
  ascending-index discovery ⇒ leftmost-first with no hash-table iteration order
  anywhere on the output path, §5.1/§5.4). Integer-only, no clock, RNG or env
  (§5.3, §5.5). No new dependencies.
  Tests: 17 integration tests in `crates/core/tests/detect_templ.rs` (core total
  247 = 23 lib unit + 8 fingerprint + 38 ledger + 48 locator + 1 locator-alloc +
  9 mask + 11 render + 16 sniff + 10 splice + 31 splitter + 8 ws + 14 exact runs
  + 13 ws runs + 17 template groups; workspace total 257, of which 10 are W2.7's
  and 10 W1.6's proto unit tests). Exit criteria met: a three-line log burst
  (same shape, differing only in timestamp, IP, uuid and duration) that stages 3
  and 4 both refuse — run first on the same span, both yielding zero commits —
  collapses through stage 6 alone into one `TemplateGroup` with count 2,
  `anchor == units[0].range`, `removed` = Σ raw lengths + the two `\n` joiners,
  marker length 31, and a spliced output pinned byte-for-byte to the first line
  plus `⟪×2 rows, template ·7837⟫`; the anchor is asserted to carry its own
  `2026-08-26T10:00:00Z`, `10.0.0.1` and `123e4567-…-426614174000`, to differ
  from the masked form and from its own ws-normalized form, while all three
  masked forms are byte-equal; a two-member group is refused at `min_group_size`
  3, 4 and 9 (nothing claimed, span byte-identical, still two byte-equal masked
  forms under one id) and commits at 0, 1 and 2 with count 1, and a three-line
  group the §4.4 gate refuses on width (`a 1`/`a 2`/`a 3`, `profitable(.., 3, 13)`
  false) also claims nothing while keeping its ids, so the rejection is the gate
  and not a grouping failure; full coverage is asserted with a stage-3 exact run
  pre-committed — all seven units, including the three committed ones, carry a
  masked form equal to `mask(&normalize(raw))` and an id, id equality implies
  masked-byte equality over every pair, and the 401-record dump shows the same
  for the bracket-carrying `u_head`/`u_tail` and the over-cap wall; leftmost-first
  ordering is pinned by two bursts separated by one different line, which commit
  as `0..2` then `4..6` in anchor-offset order, leave the middle unit uncommitted
  and residual, and splice to a byte-pinned output; a group never straddles a
  committed region (with `1..2` claimed by stage 3 the walk commits only `3..5`
  and leaves unit 0 free and residual), and an over-cap record in the middle of a
  401-record dump splits two groups at `1..199` and `201..399` while itself
  staying unclaimed and free; determinism holds over two 400-line generated spans
  (four rotating levels, per-line ts/ip/uuid/duration/counter, which stages 3
  and 4 also refuse) run through two ledgers and two differently-initialised
  scratches — identical `forms`, identical `stats`, identical `commits()`,
  byte-identical spliced output, and a re-run on a committed ledger is a no-op —
  with each unit's id asserted equal to
  `TemplateId(fingerprint(&mask(&normalize(line))))`, and a **permutation** of
  the same five lines reproduces each line's id and masked form, which is the
  insertion-order independence; a span of 64 all-distinct templates commits
  nothing, leaves the span byte-identical and yields 64 pairwise distinct ids;
  table-`Full` is pinned by a 200 000-distinct-template span (pre-sized to
  `MAX_SLOTS`), which returns `degraded == true`, default stats, empty forms,
  zero commits and a byte-identical span, while a 200 000-line span of a *single*
  template does **not** degrade and commits one 200 000-member group — so the
  degradation is the §7 cap, not the line count; the scratch stays at its
  pre-sized capacity across a 2000-line span and a following small span, a
  `default()` scratch stays within 2× the longest unit and produces identical
  output, and the module is source-scanned for the §5.1–§5.5 banned inputs.
  Deviations from DESIGN: none — §4.4.6's algorithm, the comparison-domain
  paragraph, the anchor rule, §4.4.1b's removal rule, the §4.4 profitability
  gate and §7's table-cap degradation are implemented as written and DESIGN.md is
  not amended. The readings in (a)–(e) resolve the points §4.4/§4.6 leave to the
  implementation (group contiguity, id derivation, coverage width, the shape of
  the degradation, and the walker), frozen here because §5.7 freezes behaviour
  per release. No new dependencies.
  Status (W2.4): **complete** (2026-09-26). Stage 5 is
  `quantification_core::detect::blocks::repeated_blocks(span: &[u8], ledger: &mut
  Ledger, min_block_lines: u32, max_block_lines: u32, scratch: &mut Scratch) ->
  StageStats`, plus `blocks::Scratch` (caller-owned, as W2.3's:
  `with_capacity(span_bytes, unit_bytes)`, `Default`, and
  `reserved() -> (usize, usize)` = the ws-arena and staging-buffer capacities)
  and the work meter `blocks::Work { pub compares: u64, pub verifications: u64,
  pub scanned: u64 }` with `Scratch::work() -> Work` and `Scratch::degraded() ->
  bool`. `span` and `ledger` are W2.2's arguments unchanged (the **full** stage-1/1b
  unit list of the span, so W2.1's index-derived `removal_range` and W1.2's
  joiner hazard stay inapplicable); `min_block_lines` / `max_block_lines` are
  taken as arguments, exactly as W2.2/W2.3 take `min_group_size`, and the
  pipeline passes `config::MIN_BLOCK_LINES` (2) and `config::MAX_BLOCK_LINES`
  (64) — §7 has no `RawOptions` field for them, so the consts are the only
  source. The returned `StageStats` holds only this stage's commits
  (`block_repeats == groups_collapsed`, all other counters 0) and W2.9 merges it
  with `StageStats::merge`. Algorithm — one load pass, one capped windowed scan,
  no superlinear path: (i) **load**: every *residual* (`!is_committed`) and
  `eligible` unit is ws-normalized once (`wsnorm::normalize_into`, W1.3) into a
  contiguous arena in `Scratch` and inserted into W1.4's
  `FingerprintTable::for_keys(span.len())` with the fingerprint computed once
  (`fingerprint::fingerprint` + the `pub(crate) insert_hashed`, so §4.4.2's
  byte-length → xxh3-128 → memcmp order is the table's own probe and the hash is
  never recomputed); the per-unit `Insert::{New, Duplicate(rep)}` outcome is
  frozen into an integer **representative id** `ids[i]`, so a fingerprint-sequence
  compare in the scan is one integer equality and no hash table is on the output
  path at all (§5.1, §5.4). The table never iterates, and the arena is laid out in
  ascending unit index, so any run of residual eligible units is contiguous in the
  arena and a block's ws-normalized bytes are one slice. (ii) **scan**: for each
  start `i` ascending, `L` descends from `min(max, room/2)` to `min`, where
  `room` is the count of consecutive residual eligible units from `i`; a
  candidate is accepted when `ids[i+k] == ids[i+L+k]` for all `k < L`, then
  verified **once** by `memcmp` of the two blocks' ws-normalized arena slices,
  then the chain is extended (one fingerprint compare + one memcmp per
  extension, stopping at the first mismatch), then committed with
  `Proposal::repeat(group, anchor_units = L, CommitKind::Block)` — hence
  `count = copies - 1` (§4.7) and the §4.4 gate prices the emitted count at its
  exact decimal width. `room` is tracked with one monotonically advancing cursor,
  not recomputed per start, so the whole stage is `O(N · max_block_lines)`
  fingerprint compares plus `O(N)` free-run probes. The **anchor** is the whole
  first occurrence as **raw original bytes** (W2.7 emits `span[anchor]`), and
  only `eligible` units are ever loaded, so an over-cap record is a wall that is
  never normalized, never hashed and never folded. Frozen readings: (a) the
  commit decision is left entirely to `Ledger::try_commit`; on `Committed` the
  scan **resumes after the committed region** (`i = group.end`) and on any
  rejection (in practice `BelowThreshold`) it advances by one unit and does
  **not** retry a shorter `L` at the same start, mirroring W2.2's (a) — a
  sub-range has strictly smaller `removed_bytes` and a no-larger marker, so it
  can never be more profitable. (b) `min`/`max` are clamped to ≥ 1, and a
  `min > max` pair is the empty candidate range (nothing commits) rather than a
  silent swap. (c) The chain is capped by `room` only — the number of *copies* is
  not bounded by `max_block_lines`, which caps the *period* `L` as §7 says, so a
  long repeat is one commit whose anchor is `L` lines and whose count is
  `copies - 1`. (d) The `FingerprintTable` is allocated per call (one per span;
  `FingerprintTable` has no `clear`, and W1.4's §7 cap makes its worst case
  ≈12 MiB independent of span size), and the arena / `norm` / `ids` vectors keep
  their capacity across spans because they live in the caller-owned `Scratch`.
  (e) **`Insert::Full` degrades the whole span to pass-through**: the load is
  abandoned, `ids`/`norm` are reset to all-`None`, the stage returns default
  stats (zero commits, the span byte-identical, every unit still free and
  residual for stages 6–7) and `Scratch::degraded()` reports `true` — it never
  panics and never commits a truncated prefix. `Insert::Full` is W1.4's
  `is_full()` condition evaluated at the insert that would cross the cap, so no
  span is degraded that could still have been served; a `degraded` span is *not*
  re-served by a later stage because the next stage builds its own table.
  (f) The windowed scan itself is the `pub(crate)` seam
  `windowed_blocks(ledger, ids: &[Option<usize>], min, max, same_bytes: &mut
  impl FnMut(usize, usize, usize) -> bool, work: &mut Work) -> StageStats`, so
  W2.8 re-runs the *same* leftmost-then-longest walker over W2.5's
  `Forms::id` sequence with `min = 1` and a memcmp closure over
  `Forms::masked` — the ordering, chain-extension and commit rules are written
  once. (g) `Work` is diagnostic only (§6.2's `Stats` is untouched): it makes
  the §4.4 "no superlinear path" claim *testable* rather than a prose promise.
  Tests: 19 integration tests in `crates/core/tests/detect_blocks.rs` (core
  total 266 = 23 lib unit + 8 fingerprint + 38 ledger + 48 locator + 1
  locator-alloc + 9 mask + 11 render + 10 splice + 16 sniff + 31 splitter + 8 ws +
  14 exact runs + 13 ws runs + 17 template groups + 19 block runs; workspace
  total 276, of which 10 are W2.5's and 10 W1.6's proto unit tests). Exit
  criteria met: a 2-line block behind **two header lines** commits as one
  `Block` (count 2, anchor = both header-less first-occurrence lines, `removed` =
  the six members plus joiners, headers left residual) on a span where
  `exact_runs` and `ws_runs` both commit nothing — the exact rev-3 → rev-4 case
  that the failure-function formulation missed; **leftmost-then-longest** is
  pinned twice: `a b a b c a b c` commits only `0..4` (the 3-line block starting
  at 2 is proven block-equal in the normalized domain and is nevertheless lost),
  and the same six units *alone* commit the 3-line block, while `a b` × 4
  commits one `L = 4` group with a four-line anchor and `count = 1` — the `L = 2`
  reading would have emitted `count = 3`; the chain-extension test
  (`a b a b a b a ≠b`) commits three copies with `count = 2` and leaves the
  divergent pair verbatim; the single-memcmp path is pinned by
  `work().verifications == 1` for a two-copy block, `== 2` for the
  three-copy-then-divergent chain (verification + the failing extension) and `== 0`
  when no candidate ever matches; a below-threshold block (a
  4-unit `L = 2` block of 4–5-byte lines, `anchor = 10`, `removed = 24`, so
  `10 + 22 ≥ 24`) claims nothing, stays free and residual, re-splices to the
  input byte for byte, and its 30-byte-line twin commits; the gate boundary is pinned to the
  **emitted** count (8 alternating 1-byte lines ⇒ `count 3`, `!profitable`, 10
  lines ⇒ `count 4`, `profitable`); the anchor is byte-identical to the raw
  first occurrence of a block whose members differ **only in padding** (`\t` vs
  ` \t ` vs `\t\t`, unequal raw lengths, equal normalized forms), is asserted
  `!=` its own normalized form, and the spliced output is pinned to
  `anchor bytes + marker` exactly; `min_block_lines` 3 and 9 refuse a 2-line
  block, and a 3×70-line block is **invisible** at `max_block_lines = 64` (no
  `L ≤ 64` is a multiple of the 70-line period) and commits at 128 with a
  70-line anchor; stage-1b record blocks are committed over `,` joiners
  (`removed = 6·200 + 5`, anchor = the two raw first-occurrence records) and an
  over-cap record splits them into two commits while staying unclaimed and free,
  with the same dump minus the wall committing as one `L = 4` group; blocks never
  straddle a region committed by stages 3–4 or by this stage (a hand-committed
  `2..4` leaves the residual `[0,1,4,5]` and a 12-unit span then commits
  `4..12`); a **unique-line flood of 200 004 units** returns default stats, zero
  commits, a byte-identical span, `degraded() == true` and `verifications == 0`
  — and because the block sits at the *front* of that span, the zero commits also
  pin that the degradation is whole-span rather than a truncated prefix — while an
  8-line control span still commits through the same scratch; the
  **KMP-adversarial payload** (a period of 129 = `2·max_block_lines + 1` lines —
  highly repetitive, and the worst case for a periodicity formulation, since no
  `L ≤ 64` is a period) over 40 000 units commits nothing, performs **zero**
  verification memcmps and stays inside the capped work bound
  (`compares ≤ 63·N`, `scanned ≤ N`, `compares + scanned ≤ 65·N`, and the same
  work for twice the units within `2·(half) + 2·max²`), and the same payload
  with a 4-line block prepended still commits that block after the adversarial
  prefix; a generated 60-group span is byte-identical across two ledgers and two
  differently-sized scratches (identical `commits()` and spliced output), a
  re-run on a committed ledger is a no-op, the scratch keeps its capacities
  across a following small span, and the module is source-scanned for the
  §5.1–§5.5 banned inputs. Deviations from DESIGN: none — §4.4.5's windowed
  scan, its comparison domain, the stage ordering, the anchor rule, §4.4.1b's
  removal rule, the §4.4 profitability gate and §7's table-cap degradation are
  implemented as written and DESIGN.md is not amended. One consequence of the
  normative order is recorded rather than worked around: because the candidate
  length is bounded but the **chain is not**, a 4-copy 2-line repeat is committed
  as the longest admissible period (`L = 4`, one 4-line anchor, `count = 1`)
  rather than as `L = 2` with `count = 3` — same anchor bytes preserved, same
  bytes destroyed, and the §4.4 gate prefers the larger `removed_bytes` anyway.
  Likewise the gate's decimal-width carry is *unreachable* for block shapes (a
  commit needs `P·count > 22 + width(count)` for a per-copy cost `P ≥ 3`, and no
  integer `P` puts `count = 9` and `count = 10` on opposite sides of it), so the
  width itself stays pinned by `ledger::marker_len` rather than by a block
  fixture. The readings in (a)–(g) resolve the points §4.4/§7/§8 leave to the
  implementation (rejection handling, parameter clamping, chain extent, table
  lifetime, the degradation shape, the W2.8 seam, and the work meter), frozen
  here because §5.7 freezes behaviour per release. No new dependencies.
  Status (W2.4, W2 review 2026-09-27): **reading (h) added — a commit refuses a
  candidate whose own anchor hides a repeat.** The W2 review found the normative
  idempotence claim (DESIGN.md:344-346, §12's property at 733) **false**, and the
  defect lives in this stage's walker, which stage 7 (W2.8) reuses, so one change
  repairs both. Defect: a commit's own anchor can contain a shorter-period match
  that the `(i asc, L desc)` scan skipped because it committed at a longer `L`
  first. The exact 6-line repro (six log lines whose **template ids** are
  `[R,R,C,R,R,C]`) took `L = 3` at `i = 0`, emitted the three-line anchor with the
  marker glued to its **last** line, and the second pass then collapsed the hidden
  `R R` pair — 422 → 348 B before the fix, and 722 → 573 → 573 B (a fixed point)
  after it. The anchor is the only part of a commit that survives, so a *re-run of
  the same scan over the anchor alone* is exactly the set of groups the output
  still contains: `anchor_is_match_free(ids, at, length, min, same_bytes, work)`
  re-runs the identical windowed comparison — same `equal` fingerprint compare,
  same one `memcmp` verification, same integer-only arithmetic — over
  `[at, at + length)` at every local start, with every period from
  `(length - s)/2` down to `min`, and one verified match inside the anchor
  **rejects the candidate, and the descent continues** to the next smaller `L`.
  Two consequences, which are what the review asked for:
  (i) *leftmost-then-longest is intact for genuine non-overlapping repeats* — the
  start order, the `L` order and the scan are untouched, and a candidate is only
  rejected when its own anchor is collapsible, in which case the leftmost group
  *inside* that anchor is committed instead of the anchor itself. For the
  reviewed repro the primitive period wins, so `[R,R,C]×2` now commits the two
  `R R` pairs (two one-line-anchor `⟪templated block ×1⟫` groups) instead of one
  three-line block; on the 12-entry chat golden corpus **nothing changes** and
  every golden is still reproduced byte-for-byte, and the savings either improve
  or stay equal on every shape the tests pin.
  (ii) *the emitted output stops hiding a group from the next pass* — a second
  pass can only find a group the first pass could have found, except for a match
  inside an anchor (this check) or across the boundary of two adjacent commits
  (the marker-mask residual recorded in the W2.9 hunk). The check must cover
  **every** local start, not only the anchor's own: a period-`p` match at local
  start `s ≥ 1` with `s + 2p < length` does not touch the marker-bearing last
  line, so it survives into the output and the second pass finds it —
  `[A,B,C,B,C]×2` with `p = 2`, `s = 1` is the counterexample that kills the
  weaker "primitive at its start" reading. Cost: integer-only, no allocation, no
  clock/RNG/hash table, and the check runs **only after** a candidate has already
  passed a full `equal` + `memcmp` match, so the §4.4 "no superlinear path" claim
  is untouched in the adversarial case — the 129-period payload still performs
  `verifications == 0` with the same `compares + scanned` as before. The added
  term is at most `L²/4` fingerprint compares per *confirmed* candidate
  (`L ≤ max_block_lines`) and a refused candidate stops at the first match it
  finds, so the amortised total is `O(N · max_block_lines)`; **stated
  honestly**, the worst case is `O(N · max_block_lines²)` for a span where a
  different matching period survives at almost every start, which no measured
  corpus reaches and which is not proven impossible — W4.3's criterion gate is
  where it is re-measured on 8 MiB. Reading (h) refines the candidate set rather
  than the scan order, frozen here because §5.7 freezes behaviour per release.
  The three stage-5 tests that pinned "the longest `L` wins" are re-pinned to the
  new, strictly smaller output: `a b ×4` (previously `L = 4`, a four-line anchor,
  `count = 1`) now commits `L = 2` with a two-line anchor and `count = 3`, because
  the four-line anchor `a b a b` is itself a period-2 repeat; likewise
  `a_block_never_straddles_a_committed_region` and
  `a_block_never_folds_an_over_cap_record`. The new
  `a_block_whose_anchor_itself_repeats_is_never_committed` pins the refusal:
  `[L0,L1,C0,L1,C0]×2` is a real five-line repeat, the five-line candidate is
  refused because its anchor hides a period-2 match at local start 1, and the two
  two-line groups `1..5` and `6..10` commit instead, with `verifications == 4`
  (two candidate verifications, two inside the check). The over-cap tool dump
  gains from the same rule: `edges/single-line-tool-dump-overcap.json` now commits
  **one** block with `count = 1022` (128 057 → **333** B, previously 3 854 B in two
  commits) and is a fixed point. Tests: 20 integration tests in
  `crates/core/tests/detect_blocks.rs` (was 19). No new dependencies.
- **W2.6 Renderer / marker grammar** (§4.5) — exact pinned shapes + CCCC
  checksum. Parallel with W2.2–W2.5 (consumes commit ledger only).
  Status: **complete** (2026-09-26). The module is
  `quantification_core::render`; it renders the §4.5
  `MARKER := OPEN CORE SEP CCCC CLOSE` grammar from the frozen W2.1 pieces and
  nothing else. Public API, frozen for W2.7/W2.9:
  `resolve_style(MarkerStyle, &[u8]) -> MarkerStyle`,
  `render(MarkerStyle, CommitKind, u64, &[u8]) -> Vec<u8>` (owning) and
  `render_into(&mut Vec<u8>, MarkerStyle, CommitKind, u64, &[u8])` (appends to
  a caller buffer, so the splicer emits a marker without a per-commit
  allocation; it asserts its own byte delta). `MarkerStyle::Auto` is **refused**
  by both entry points (assert), exactly as W2.1's `Ledger::new` refuses it.
  **Style resolution (frozen, W2.9 contract):** `resolve_style` is called by the
  pipeline **per eligible span, before `Ledger::new`**, on the span's raw bytes —
  `Auto` ⇒ `Ascii` iff every byte of the span is ASCII, else `Unicode`;
  `Ascii`/`Unicode` are returned unchanged whatever the span contains. The
  resolution must precede `Ledger::new` because W2.1's `marker_bytes` and hence
  the §4.4 profitability gate are style-dependent, and because the splicer
  renders with the same resolved style; the pipeline must pass that one resolved
  style both to `Ledger::new` and to W2.7 (`splice_ledger` reads it back from
  `ledger.marker_style()`, so the two can never diverge). The `CCCC` is written
  nibble-wise from `fingerprint::marker_checksum` (bits 0–15 of fixed-seed
  `xxh3-64` over the **raw** anchor bytes — the original escaped bytes, never a
  ws-normalized or masked form) and the count is written digit-wise, with
  `ledger::decimal_width` asserting the width and `ledger::marker_len` asserting
  the total: `render(...).len() == marker_len(...)` holds for every kind, style
  and count (asserted in `render_into`, so it is checked on the splicer's path
  too). No duplicated framing/core/checksum arithmetic anywhere.
  Tests: 11 integration tests in `crates/core/tests/render.rs` (core total 193 =
  23 lib unit + 8 fingerprint + 38 ledger + 48 locator + 1 locator-alloc +
  9 mask + 11 render + 16 sniff + 31 splitter + 8 ws; workspace total 203).
  Exit criteria met: golden vectors pin all five kinds × both styles at
  `N = 200` (`⟪×200 identical ·0751⟫`, `⟪×200 rows, ws-equal ·0751⟫`,
  `⟪block ×200 ·0751⟫`, `⟪×200 rows, template ·0751⟫`,
  `⟪templated block ×200 ·0751⟫` and the five ascii twins), the exact `CCCC` is
  pinned for seven known anchor byte strings (including the empty anchor,
  `a`, and a `café` + `\\u0041` raw-escape anchor) and two anchors whose
  **ws-normalized forms are equal** are proven to hash differently, which is
  the raw-bytes-not-normalized rule; the width invariant runs over nine counts
  (0, 1, 9, 10, 99, 100, 199, 1000, 12345) and the counts are pinned as plain
  decimal up to `u64::MAX`; auto resolution is asserted both ways (four
  all-ASCII spans ⇒ `Ascii`, three spans with non-ASCII bytes ⇒ `Unicode`) plus
  the forced-style pass-through and the `Auto` panic; escape safety is asserted
  over every kind × both styles × every count — no `"`, no `\`, no control byte,
  valid UTF-8, and a raw marker embedded between two `\u0041` escapes adds
  exactly zero backslashes, which is the §4.2 "valid in any JSON string
  without re-escaping" rule and what makes R3 hold downstream; a source-scan
  test asserts the renderer contains no `HashMap`/`RandomState`/`BTreeMap`/
  clock/env/RNG/float/`format!` (§5.1–§5.5, and no formatting machinery on the
  hot path at all).
  Deviations from DESIGN: none — §4.5's exact rendering, both framing sets, the
  ten `CORE` halves, the `CCCC` definition and the §4.2 escape-safety property
  are implemented as written and DESIGN.md is not amended. The one reading
  §4.5 leaves to the implementation is **where** `Auto` is resolved (the
  "span contains no non-ASCII bytes" predicate is pinned as *the whole span's
  raw bytes*, not just the anchor, and resolution is per span rather than per
  payload); frozen here because §5.7 freezes behaviour per release, and it
  matches W2.1's requirement that `Ledger::new` never sees `Auto`.
  No new dependencies.
- **W2.7 Splicer** (§4.5) — copy buffer + patch recorded ranges; buffer-
  reuse robustness hook for §12 poisoned-buffer test. Parallel with detectors.
  Status: **complete** (2026-09-26). The module is
  `quantification_core::splice`. Public API, frozen for W2.9:
  `spliced_len(input_len, MarkerStyle, &[Commit]) -> usize` (the exact output
  length, so a caller can size a buffer before splicing),
  `splice_into(&[u8], MarkerStyle, &[Commit], &mut Vec<u8>) -> &[u8]` (the
  general form) and `splice_ledger(&[u8], &Ledger, &mut Vec<u8>) -> &[u8]`,
  which reads `marker_style()` and `commits()` straight off the ledger so the
  rendered style can never diverge from the one the §4.4 gate priced. The
  **output buffer is caller-owned and reusable**: `out.clear()` then a single
  `out.reserve(spliced_len(..))` and a forward cursor of `extend_from_slice`
  ranges — one allocation, memcpy-only, and every returned `&[u8]` is the
  freshly written prefix, so a shorter result over a longer previous one cannot
  expose a stale byte (§12's poisoned-buffer requirement, and the ≤10 ms §8
  splice budget's "single output allocation, memcpy ranges"). Assembly is
  exactly §4.5's "copy input buffer, overwrite recorded ranges": **no JSON
  reserialization**, which is why R3 holds trivially. Each commit is applied
  over its `removed` range by emitting `input[commit.anchor]` (the original
  raw anchor bytes, `anchor ⊆ removed`) followed by the W2.6 marker, so
  surviving neighbours end up directly adjacent to the marker; the `,` /
  line-boundary joiners *inside* `removed` are consumed with it and the
  joiners of surviving neighbours are copied verbatim. Commits are consumed in
  the ledger's frozen emit order (ascending anchor byte offset) and are
  **absolute** offsets into `input` exactly as W1.1 pinned them, so a leading
  BOM in bytes 0..3 and every untouched byte outside a span ride along
  unchanged; a per-commit assert rejects any other order (pinned by
  `commits_out_of_emit_order_are_refused`) and `spliced_len` is total
  (`saturating_sub`) so a bogus order cannot underflow before that assert.
  No new dependencies, no clock, no allocation beyond the caller's buffer.
  Tests: 10 integration tests in `crates/core/tests/splice.rs` (core total
  203 = 23 lib unit + 8 fingerprint + 38 ledger + 48 locator + 1 locator-alloc
  + 9 mask + 11 render + 16 sniff + 10 splice + 31 splitter + 8 ws; workspace
  total 213, of which proto/server 10). Exit criteria met: exact output bytes
  are pinned for a multi-commit span (`head\n` + 5 copies of a 40-byte line +
  `\ntail` ⇒ anchor + `⟪×4 identical ·81cc⟫` and nothing else, i.e. the four
  inter-member `\n` joiners are inside the removed range), for two commits in
  one span discovered back-to-front (the ledger's emit order is what the splicer
  consumes, and it is the splicer that must not sort), and for a 5-record
  stage-1b dump where the middle records' `,` joiners stay outside the marker
  while the `,` between the surviving head and tail records is preserved; the
  no-commit case is asserted byte-for-byte equal to the input on three inputs
  (multi-line, JSON-shaped, empty) into a pre-poisoned 128-byte buffer, with
  `spliced_len == input.len()`; a commit at byte 0 and a commit whose range
  ends 2 bytes before the buffer end are pinned with the trailing `\n` escape
  unit surviving; a BOM payload splices the whole buffer and asserts bytes
  0..3, the `{\"content\":\"` prefix, the `\n\"}` tail and the ascii marker are
  byte-identical to the input's, which is the W1.1 absolute-offset contract
  end to end; the **poisoned-buffer reuse test** first writes a 458-byte
  passthrough into the buffer, then refills the buffer's whole capacity with
  `0x00`, then splices a 70-byte result (shorter than the previous one) and
  asserts no poison byte reaches the output and the length is exactly
  `spliced_len`; a property test over 64 LCG-generated spans walks the output
  and the input in lockstep and asserts every copied range is byte-identical
  to the input, every anchor is the input's own bytes and every marker equals
  an independently `format!`-built oracle (it commits more than 32 groups, so
  it is not vacuous), and a final pass pins that 64 reuses of one buffer keep
  the same capacity.
  Deviations from DESIGN: none — §4.5's "copy the input buffer, overwrite
  recorded ranges" is implemented as written and DESIGN.md is not amended. The
  readings frozen here are the ones §4.5 leaves to the implementation: the
  splicer takes **one** commit list over the whole payload buffer (all spans at
  once, absolute offsets) rather than splicing per span, the commit list must
  already be in emit order (W2.9 merges the per-span ledgers by anchor offset
  before calling), and `spliced_len` is exposed as part of the surface for
  pre-sizing. Frozen because §5.7 freezes behaviour per release.
- **W2.8 Stage 7 templated blocks** — after W2.4 + W2.5 (template-id scan,
  min period 1).
  Status: **complete** (2026-09-26). Stage 7 is
  `quantification_core::detect::templ_blocks::templated_blocks(templated: &templ::Templated,
  ledger: &mut Ledger, max_block_lines: u32, scratch: &mut Scratch) -> StageStats`, plus
  `templ_blocks::Scratch` (caller-owned, as W2.4's: `new`, `with_capacity(units)`,
  `Default`, `reserved() -> usize` = the id-sequence capacity, and `work() ->
  detect::blocks::Work`), and the module is declared by the one added line
  `pub mod templ_blocks;` in `crates/core/src/detect/mod.rs` (inserted after
  `pub mod templ;`; no existing line reordered or removed). The **whole stage-6
  handoff is the argument**, not just its `Forms`, so the §4.4.6 degradation
  signal cannot be ignored by accident: `templated.degraded == true` returns
  default `StageStats` **before** the id sequence is built, i.e. zero commits,
  no ids, no work, and W2.9 passes the span through (`Scratch::reserved()` is
  still `0`). The stage takes **no `span`**: every byte it needs is in
  `Forms`, and the anchor is a unit range the ledger derives, so a stage-7
  anchor is structurally always raw original bytes (the module contains no
  `span`, no `mask_into` and no `normalize_into` — asserted by a source scan).
  Algorithm — the stage-5 walker, not a second one: `load` copies
  `Forms::id(i).0` into a dense `Vec<Option<usize>>` (`Some` only for
  `eligible` units, so an over-cap `eligible == false` record is a wall that is
  never hashed, never compared and never folded; the tail beyond
  `Forms::len()` stays `None`, which bounds the walk without an index check),
  and then calls W2.4's `pub(crate) windowed_blocks(ledger, ids, min = 1, max,
  CommitKind::TemplatedBlock, same_bytes, work)`. `min` is the module constant
  `MIN_PERIOD = 1` (§4.4.7's "minimum period lowered to 1", so an adjacent
  match now means "different lines, same template") and `max` is
  `config::MAX_BLOCK_LINES`, passed as an argument exactly as W2.4 takes it
  (§7 has no `RawOptions` field for it). The comparison domain is §4.4's
  **template ids** for candidate selection and **one memcmp of the two
  blocks' masked-form bytes** for the join: the closure slices `Forms::bytes`
  from the first member's `masked.start` to the last member's `masked.end` on
  each side — the two blocks' masked forms are each one contiguous arena
  range because `Forms` is dense and index-aligned with the ledger (W2.5's
  reading (c)) — so a join costs exactly one slice comparison, not one per
  line, and the residual-only guarantee again makes every member a
  participant. The chain extension, the leftmost-then-longest `(i asc, L desc)`
  order, the "resume after the committed region, otherwise advance one unit and
  do not retry a shorter `L`" rejection rule and the `O(N · max_block_lines)`
  cap are W2.4's, written once. The commit itself is
  `Proposal::repeat(group, anchor_units = L, CommitKind::TemplatedBlock)`
  inside `windowed_blocks` (see the W2.4 seam extension below), hence
  `count = copies - 1` (§4.7), the marker `⟪templated block ×N⟫` (§4.5, `N = 0`
  never rendered) and a §4.4 gate priced at the emitted count's exact decimal
  width. **Frozen readings:** (a) **W2.4's seam needed one added parameter.**
  `windowed_blocks` hard-coded `CommitKind::Block` in its `Proposal::repeat`,
  so a stage-7 commit would have carried stage 5's kind and marker; the
  function now takes `kind: CommitKind` and `repeated_blocks` passes
  `CommitKind::Block`. That is the whole change to `blocks.rs` (a signature
  parameter, the one call site, and the constant replaced by the parameter) —
  the scan, the closure signature, the `Work` meter and the ordering are
  untouched, and `min = 1` needed no other relaxation (`min_block_lines.max(1)`
  already admits it, and stage 5's own tests still pass unchanged).
  (b) The `TemplateId` (low 64 bits of the masked form's xxh3-128) is compared
  as a `usize`, which is exact on the 64-bit targets §5.8's determinism gate
  runs; on a 32-bit target the cast is a truncation and can only make two
  unequal templates look equal, which the mandatory memcmp then rejects — a
  missed merge, never a wrong one (§4.4.2's residual-collision property), and
  still a pure integer comparison on the output path (§5.3). (c) The minimum
  period is `1` and the maximum stays `MAX_BLOCK_LINES`: §4.4.7 lowers only the
  minimum, so a block period is still capped at §7's 64 lines while the number
  of *copies* is not (W2.4's reading (c)), and the leftmost-then-longest
  consequence is inherited — `a b a b c a b c` commits only the 2-line block at
  0, not the 3-line block at 2. (d) The chain is extended while the next
  adjacent copy matches and the gate alone decides: a below-threshold block
  claims nothing, stays free and residual, and the scan advances by one unit
  (W2.4's reading (a)). (e) `degraded` is consumed inside the stage rather than
  returned as a second flag, because there is no stage-7-specific degradation
  to report: `Forms` has no cap of its own, and the only degradation that can
  reach stage 7 is W2.5's table fill. (f) The `Work` meter is W2.4's,
  diagnostic only (§6.2's `Stats` is untouched): it makes "one memcmp per
  join" and the capped work bound testable. Integer-only, ascending-index
  discovery only, no hash table on the output path and therefore no iteration
  order anywhere in it (§5.1, §5.4), no clock, RNG or env (§5.3, §5.5).
  Tests: 15 integration tests in `crates/core/tests/detect_templ_blocks.rs`
  (core total 281 = 23 lib unit + 8 fingerprint + 38 ledger + 48 locator + 1
  locator-alloc + 9 mask + 11 render + 10 splice + 16 sniff + 31 splitter + 8 ws
  + 14 exact runs + 13 ws runs + 17 template groups + 19 block runs + 15
  templated blocks; workspace total 291, of which 10 are W2.5's and 10 W1.6's
  proto unit tests). Exit criteria met: a three-role **access-log burst**
  (9 lines: `GET`/`<- 200`/`pool`, all three roles sharing a template across
  entries and differing only in timestamp, IP, uuid, duration and counters, so
  the per-line templates are pinned to their exact `<ts>…<ip>…` masked forms)
  is refused by `exact_runs`, `ws_runs` and `repeated_blocks` and by
  `template_groups` on the same span, and collapses through stage 7 alone into
  one `TemplatedBlock` over `0..8` with `count = 2`, a three-line anchor equal
  to the raw first entry and a 32-byte marker; a **stack trace differing only
  in addresses** (three `at com.example.Svc.<role>(Svc.java:<n>) pc=0x…` frames
  per trace, three traces) likewise commits as one 3-line anchor with `count =
  2`, with the first trace's three 16-hex addresses asserted present in the
  anchor and the two dropped traces' addresses asserted absent, the masked form
  pinned (`…pc=<num>x<hex>`, i.e. the frozen mask list's own output for `0x…`)
  and the spliced output equal to anchor + marker; an **interleaved
  request/response pair** (six lines, two distinct templates alternating)
  collapses at period 2 with a 2-line anchor and `count = 2`; the **min-period-1
  case fires** — a single adjacent same-template pair that stage 6 refuses at
  `min_group_size` 3 commits as `count = 1` with a 1-line anchor and the marker
  pinned byte-for-byte to `⟪templated block ×1 ·1701⟫` (`marker_len` 32 at one
  digit, 33 at two); the anchor is asserted byte-identical to the raw first
  occurrence with its own `10.0.0.0`, uuid, `bytes 900` and `receipt 00-0`
  present, to differ from the concatenation of the two blocks' masked forms, and
  the dropped copies' lines to be absent from the spliced output; a **join is
  rejected when the ids match but the masked bytes differ** — a hand-built
  `Forms` (the type is fully public, so the collision-safety path is testable
  without a hash break) with two colliding ids and disagreeing masked bytes
  commits nothing, re-splices to the input byte for byte and performs exactly
  one verification memcmp, while the same ids with agreeing bytes commit the
  2-line block with a raw anchor, so the rejection is the memcmp and not a
  grouping failure; a **below-threshold** pair (`a 1`/`a 2`, one masked form, 3-byte
  lines) claims nothing, stays free and residual, is byte-identical after
  splicing, has `profitable(.., TemplatedBlock, 1, 3, 8) == false`, and its
  100-byte-line twin commits; **`degraded` is a no-op** both as a hand-built
  `Templated { degraded: true, forms: <forms that would commit> }` (default
  stats, zero work, `reserved() == 0`, span byte-identical) and end to end on a
  200 000-distinct-template span that stage 6 degrades; **leftmost-then-longest**
  is pinned twice on a ten-line span (the 2-line block at 0 wins over the
  3-line block at 4, and the tail alone commits the 3-line block with `count =
  1`); a block **never straddles a committed region** (a hand-committed
  `1..2` leaves the residual `[0, 3, 4, 5]`-shaped fragment and commits only
  `3..6`); an **over-cap record wall** splits a 413-record stage-1b dump's
  templated blocks into `200..205` and `207..212` (each `count = 2`,
  `removed = 6 records + 5 commas`) with the wall unclaimed and free, while 400
  distinct-template filler records commit nothing; a 280-line generated span
  (40 header groups of three committed by stage 6 + 40 interleaved pairs) is
  byte-identical across two ledgers and two differently-sized scratches —
  40 `template_groups` + 40 `templated_blocks`, identical `commits()`, identical
  spliced output, and a re-run on the committed ledger a no-op — with every
  commit asserted against the removal rule and the gate; empty, single-unit and
  over-cap-line spans commit nothing; determinism and banned-input invariants
  are source-scanned. Deviations from DESIGN: none — §4.4.7's algorithm, its
  "verified by one memcmp of the two blocks' masked-form bytes", the
  comparison-domain paragraph, the anchor rule, the stage ordering, §4.4.1b's
  removal rule, the §4.4 profitability gate, §4.7's omitted-copies count and
  §4.5's `⟪templated block ×N⟫` shape are implemented as written and DESIGN.md
  is not amended; the single addition outside this task's files is the `kind`
  parameter of W2.4's already-`pub(crate)` walker, which changes no stage-5
  behaviour. The readings in (a)–(f) resolve the points §4.4.7/§7 leave to the
  implementation (the walker seam, the id width, the caps, rejection handling,
  the degradation shape and the work meter), frozen here because §5.7 freezes
  behaviour per release. No new dependencies.
- **W2.9 Pipeline orchestration + Stats assembly** (§3, §4.5) — after
  W2.2–W2.8. **Gate M2**: chat golden outputs byte-stable ×1000.
  Status: **complete** (2026-09-26). The module is
  `quantification_core::pipeline`; the one added line is `pub mod pipeline;` in
  `crates/core/src/lib.rs` (no existing line reordered or removed) and the
  pipeline is the only new source file. Public API, frozen for W3.1/W3.3/W3.4:
  `ALGO_VERSION: &str = "0.1.0"` (the §5.7 behaviour version, exposed so callers
  can detect a cross-release output change; it is a frozen constant, never
  derived from the clock, the environment or the input);
  `Stats { bytes_in, bytes_out, approx_tokens_in, approx_tokens_out,
  groups_collapsed, exact_runs, ws_runs, block_repeats, template_groups,
  degraded, noop_reason: Option<locator::NoopReason>, elapsed_detect_ns,
  elapsed_compact_ns, elapsed_splice_ns, algo_version: &'static str,
  templated_blocks, options_echo: String, record_splits }` — the §6.2 `Stats`
  message **field-for-field and in §6.2's wire-number order** (1…18) so W3.3 maps
  it 1:1 and mechanically, with two typed deviations: `noop_reason` is
  `Option<locator::NoopReason>` (W1.1's frozen mapping: `degraded =
  noop_reason.is_some()` and `noop_reason.map(as_str)` at the transport edge,
  `""` when compressed) and `algo_version` is the `&'static` frozen constant
  (`.to_string()` at the proto edge). §6.2 field 19 `restore_ids` is
  deliberately **absent**: v1 compression never stores originals, so W3.4 adds
  it (flag-gated, §9) together with the `commits()` walk it derives the ids
  from;
  `trait Clock { fn now_ns(&self) -> u64 }` + `MonotonicClock` (`new`,
  `Default`, `impl Clock` — `Instant`-based, monotonic, read only to fill the
  three `elapsed_*` fields);
  `Compressor { new, with_clock(impl Clock + 'static), Default,
  commits() -> &[ledger::Commit], compress(&[u8], &ResolvedOptions, &mut Vec<u8>)
  -> Stats }`. The entry point takes **resolved** options (W0.2's `config::resolve`
  is the option-resolution seam W3.1 wraps) and a **caller-owned output buffer**,
  exactly the buffer contract W2.7 froze, so one `Compressor` plus one `Vec`
  serves a whole request stream with no per-call output allocation;
  `commits()` exposes the merged, anchor-offset-ascending whole-payload commit
  list of the last call (valid until the next `compress`) — it is what makes the
  "output = input outside the patched ranges" property testable, and it is what
  W3.4 walks in marker output order for §9's `restore_ids` (§9 forbids parsing
  markers). The flow is §3's diagram literally: `sniff::sniff` → `locate_into`
  (the caller-owned-span-vector form, so the span list is reused across calls)
  → per eligible span `resolve_style` → `stage1::split_span_counted` (stages
  1+1b, `record_splits` filled) → `exact_runs` → `ws_runs` (skipped entirely when
  `normalize_ws == false`) → `repeated_blocks` → `template_groups` →
  `templated_blocks` (skipped with stage 6 when `template_dedup == false`) →
  one `splice::splice_into` over the whole payload. Stages run in the §4.4
  normative order on the residual the ledger leaves, and every commit decision
  still belongs to `Ledger::try_commit`, so earlier-stage commitments win all
  overlaps exactly as in W2.1–W2.8. Frozen readings: (a) **spans compact with
  span-relative unit ranges and the commits are shifted on the way out** — the
  detectors index `span[unit.range]`, so the pipeline compacts the payload
  sub-slice `&payload[span.start..span.end]` and adds `span.start` to each
  `Commit::anchor`/`Commit::removed` when merging, which is the whole of the
  absolute-offset contract W1.1 froze and needs no change to any detector; (b)
  **the splice style is per commit, because `Commit` carries it** (rewritten by
  the W2 review 2026-09-27; the previous "one style for the whole commit list"
  reading contradicted §4.5 and is withdrawn). `resolve_style` runs per span
  — W2.6's frozen contract, and it must precede `Ledger::new` because
  `marker_bytes` is style-dependent — and `Ledger::try_commit` stamps its own
  resolved style onto every `Commit` it returns. `pipeline::shift` carries the
  field across the span-relative → absolute shift, so
  `splice::splice_into(input, commits, out)` and `spliced_len(input_len, commits)`
  no longer take a style argument and render every commit in **its own** span's
  resolved style. §4.5 pins the unit of resolution as the *span* ("when the span
  contains no non-ASCII bytes"), and the withdrawn reading resolved `auto` once
  **per payload**, so a pure-ASCII span inside a payload that held any non-ASCII
  byte anywhere was rendered with a `⟪...⟫` marker. The §4.4 gate was
  never wrong (each span's ledger already priced its own style), but the
  *rendering* could disagree with the price; the rendered bytes are now
  byte-identical to the priced bytes by construction, in both directions. The
  ascii marker is **exactly 1 byte longer** than the unicode one for all ten
  kind×style shapes (`"[... "` + `" ...]"` is 5+5 bytes against `⟪` + `⟫` at
  3+3; the `CORE` halves and the `SEP` cancel) — not the "4–5 bytes" this hunk
  previously claimed. (c) **A per-span fingerprint-table
  `Full` degrades that span to verbatim pass-through, not the request** (§7,
  §3): the pipeline records the merged commit length before the span, and on
  `blocks::Scratch::degraded()` or `templ::Templated::degraded` it truncates that
  span's commits back to the recorded length and drops the span's `StageStats`
  entirely, so the degraded span's bytes are copied verbatim — *including* the
  commits stages 3–5 had already made in it, which is the conservative reading
  of §3's "always safe to skip" and is the reading W2.9's brief states. W2.4
  (e)/W2.5 (d) are unaffected: they only promise that the *stage* cannot roll
  back or truncate-prefix its own decision. `Stats.degraded` becomes `true` for
  it while `noop_reason` stays `None`, because the request *was* served (other
  spans are still compressed) — so `degraded` is no longer exactly
  `noop_reason.is_some()`; it is `noop_reason.is_some() || any span degraded`,
  and the counters always describe the emitted output. A whole-request
  `Malformed`/`UnknownSchema` locator pass-through is untouched: input verbatim,
  `degraded = true`, the matching `noop_reason`, zero commits. The request never
  fails. (d) `approx_tokens_*` are `bytes / 4` integer division (§4.5's
  approximate, reporting-only heuristic; the field names carry the `approx_`
  prefix and DESIGN.md is not amended). (e) `elapsed_detect_ns` covers
  sniff + locate, `elapsed_compact_ns` the whole per-span loop, `elapsed_splice_ns`
  the single `splice_into`; the clock is read exactly four times (pinned by a
  source scan) with `saturating_sub`, and a timing value can reach nothing but
  those three fields — `timings_never_reach_the_payload` compresses the same
  payload with a constant clock, a counting clock and the default monotonic
  clock and asserts byte-identical payloads and identical commit lists.
  (f) **Scratch reuse**: the four detector scratches (`wsruns`, `templ`,
  `blocks`, `templ_blocks`), the span vector, the merged commit vector and the
  output vector are owned by the `Compressor` and reused across spans *and*
  across calls; `Stages::reserve` only re-allocates a scratch when the span
  needs more than the capacity already there (so a smaller span after a large
  one reuses it), and the inner loops allocate nothing per line. Two
  allocations per span are inherent to the frozen upstream APIs and are left
  alone: `stage1::split_span_counted`'s unit vector (W1.2 has no caller-owned
  form) and `Ledger::new`'s `claimed` + `commits`. §8's budget buys that
  simplicity. (g) A committed commit list is ascending and disjoint by
  construction (spans are ascending and disjoint per W1.1, per-span ledgers are
  ascending per W2.1), asserted by a `debug_assert!` before the splice and by
  the splicer's own per-commit assert. No hash map, no RNG, no env, no float, no
  wall clock and no sort anywhere in the module (source-scanned like every other
  core module); the only `Instant` is inside `MonotonicClock`. The source scan
  also pins the **normative order textually** — the first occurrence of
  `stage1::split_span_counted(bytes)`, `exact::exact_runs(`,
  `wsruns::ws_runs(`, `blocks::repeated_blocks(`,
  `templ::template_groups(`, `templ_blocks::templated_blocks(` must appear
  left-to-right in that order, `compact_span` must be called before
  `splice_into(payload`, and both after `let detect_start` — swapping the
  stage-3 and stage-4 blocks in the source makes the test fail (verified, then
  reverted), so §4.4's ordering rule is a checked invariant of the module, not a
  convention.
  Tests: 41 integration tests in `crates/core/tests/pipeline.rs` at this point,
  **45 after the W2 review** (core total 322 → 326, workspace total 332 → **340**;
  the four new ones are the anchor-hides-a-shorter-period repro, the generated
  idempotence property test
  (`generated_log_bursts_converge_and_only_diverge_over_an_emitted_marker_or_an_anchor`),
  the mixed-style per-span render test and the `reversible` pin — see the W2 review record at the end of this hunk; the
  other three are W2.4's, ledger's and splice's; 10 of the workspace total are
  W1.6's proto unit tests, and 1 test is `#[ignore]`d, the golden generator).
  Breakdown after the review: 23 lib unit + 8 fingerprint + 39 ledger + 48
  locator + 1 locator-alloc + 9 mask + 11 render + 12 splice + 16 sniff + 31
  splitter + 8 ws + 14 exact runs + 13 ws runs + 17 template groups + 20 block
  runs + 15 templated blocks + 45 pipeline. Twelve golden expected-output
  files were added under `crates/core/tests/fixtures/golden/` (one per chat
  corpus entry: `chat-minified.json`, `chat-pretty.json`, `chat-content-null.json`,
  `chat-mixed-parts.json`, `sniff-overlap-chat-responses.json`, `bom-chat.json`,
  `dup-keys-last-wins.json`, `escaped-structural-keys.json`,
  `newlines-u000a-only.json`, `prior-markers.json`,
  `profitability-below-threshold.json`, `single-line-tool-dump-small.json`),
  regenerated by the ignored `write_the_chat_goldens` test
  (`cargo test --test pipeline -- --ignored write_the_chat_goldens`) and
  reproduced byte-for-byte by `the_chat_goldens_are_reproduced_byte_for_byte`
  on every ordinary run; they are the regression net for M2 and W4. They were
  inspected by hand before being committed: the minified and pretty chat
  variants keep byte-identical envelopes and collapse the 8-line burst to
  `2026-08-25T10:00:01Z INFO hc 10.0.0.1 ok` + `[... x7 rows, template c651 ...]`;
  `bom-chat.json` keeps its `EF BB BF`; `newlines-u000a-only.json` collapses
  across `\u000A`/`\u000a` boundaries; `escaped-structural-keys.json` and
  `dup-keys-last-wins.json` collapse only the last-wins eligible content;
  `chat-mixed-parts.json` leaves the `image_url` part alone;
  `sniff-overlap-chat-responses.json` leaves the root `input` alone;
  `profitability-below-threshold.json` and `single-line-tool-dump-small.json`
  (a single under-cap unit) are byte-for-byte pass-throughs, which is what those
  two W0.3 fixtures exist to pin; and `prior-markers.json` round-trips all three
  prior-marker texts (unicode ×2, ascii ×1) verbatim while its two adjacent
  log lines collapse to `⟪templated block ×1 ·e18b⟫` — the span is non-ASCII, so
  it resolves to the unicode style while the input's ascii marker is *copied*,
  never re-rendered. Exit criteria met: one payload with a compressing span and
  a non-compressing span; three spans merging into one ascending commit list
  with the untouched envelope between commits proven to be exactly
  `"},{"role":"user","content":"`; a 200 004-line unique-line flood in the second
  user span degrading that span alone (its own stage-3 run of 4 identical lines
  survives verbatim) while the first span still collapses, with `degraded` set
  and `noop_reason` `None`; `normalize_ws=false` giving `ws_runs == 0` and the
  same span collapsing through stage 6 instead (and nothing at all with
  `template_dedup=false` as well); `template_dedup=false` zeroing both
  `template_groups` and `templated_blocks` for a payload only stage 6/7 can
  collapse; `min_group_size` 3 vs 4 on a three-line run; the scope policy
  selecting a `tool` span only under `user_and_tools`; R4 with a system prompt
  and an assistant message whose content is byte-identical in the output and
  marker-free; idempotence over the whole 26-fixture corpus
  (`recompress(output) == output` with `groups_collapsed == 0` on the second
  pass) including `prior-markers.json`; every JSON output parsed by a test-local
  strict validator (no new dependency — see the deviation note below); the
  output equal to the input outside the patched ranges for all 26 fixtures, with
  every marker matched against an independent oracle built from the frozen
  `framing`/`core`/`marker_checksum` pieces and valid UTF-8 with no added
  backslash pair; every `Stats` field pinned; `record_splits` 1/0/1/1 over the
  four stage-1b fixtures, with the 128 057-byte over-cap dump collapsing 1023×
  (128 057 → **333** bytes, one `block_repeats` with `count = 1022` — W2.4 reading
  (h) replaced the previous 3 854 bytes in two commits) and the 16385-byte
  over-cap record acting as a wall; `algo_version` pinned; the `options_echo` string and
  both forced marker styles reaching the output; a full `Stats` reproduced 1000×
  under a constant clock; warm-vs-fresh compressors and output-buffer capacity
  across 64 calls; and a check through `commits()` that a span never bleeds into its
  neighbour. Six degenerate payloads (empty, whitespace, `null`, `{}`, `[]`, a
  bare JSON string) are asserted to pass through byte-identically without a
  panic, so §3's "never fail the request" holds for the whole input range, not
  just the interesting shapes.
  Deviations from DESIGN: **three**, all recorded here rather than in DESIGN.md,
  which this review did not amend. §3's architecture, §4.4's stage
  ordering/removal rule/profitability gate, §4.5's splicing and stats list,
  §4.7's contract, §5.1–§5.9, §6.2's `Stats`, §7's table-cap
  degradation and §12's test list are otherwise implemented as written:
  (0) **`§4.4.5`/`§4.4.7` gain one admission rule** (W2.4 reading (h)): a block
  candidate whose own anchor contains a windowed match is refused and the
  descent continues. §4.4.5's `(i asc, L desc)` order is untouched and
  leftmost-then-longest is intact for genuine non-overlapping repeats; the spec
  does not say what a commit must do when its own anchor is itself collapsible,
  so this is a resolution of a gap rather than a contradiction, but it does change
  the set of emitted blocks (and shrinks the output on every shape it touches).
  (1) **`§4.4`'s idempotence claim is not yet established** for arbitrary input —
  see item (6) below for the measured residual (9.36% of a generated corpus, all
  of it one named mechanism) and the two DESIGN-level fixes it needs.
  (2) **`§6.2`'s `reversible` is resolved and echoed but not honoured.**
  `config::resolve` accepts `reversible: true`, `options_echo` reports it, and
  compression output is byte-identical either way (pinned by the new
  `reversible_is_echoed_but_still_not_honoured`). The recommended fix is to
  **reject it exactly like the reserved `AllMessages` scope policy** — a new
  `ResolveError::UnsupportedReversible`, so the option cannot be accepted and
  then ignored — but that is `config.rs`, which is the W0.2 owner's file and
  outside this review's ownership, so it is **not** done here; until W3.4 lands
  the transport must document the option as reserved. W3.1/W3.3 must not present
  it as working. Two further points are recorded here rather than in
  DESIGN.md, and two are inherited readings that later waves should know:
  (3) **R3 is asserted with a test-local strict JSON validator** (recursive
  descent: exact `true`/`false`/`null`, JSON number grammar, `\uXXXX`-style
  escape validation, no raw control byte in a string, no trailing bytes, depth
  capped at 64, leading BOM tolerated) rather than a third-party parser, because
  adding a dev-dependency for one property test is not worth it; W4.1 may swap in
  `serde_json` if it prefers an independent parser, and the *structural* proof
  (output = input outside the patched ranges, plus the fuzz locator's
  "no unescaped quote or control byte inside a span" invariant) is
  implementation-independent. (4) `degraded` is widened from
  `noop_reason.is_some()` to "a pass-through happened anywhere", which is §6.2's
  own field comment ("pass-through happened"); a caller that needs the stronger
  "the whole request was untouched" test must check `noop_reason`.
  (5) **Inherited observation, not a change**: with `template_dedup = true` a
  stage-4 ws run and a stage-6 template group are never *distinguishable* in
  their group selection, because stage 6 masks the ws-normalized form, so every
  ws-equal pair is also template-equal and every template run is also a
  stage-7 candidate at minimum period 1. `min_group_size` therefore bounds
  stages 3/4/6 only — stage 7's minimum is a *period* (§4.4.7), so a caller who
  raises `min_group_size` to be conservative still gets two-member collapses
  from stage 7 (pinned by
  `min_group_size_does_not_gate_the_templated_block_stage`). This is what
  DESIGN.md says, so it is recorded as an observation for W3.1's option
  documentation and W4.1's property tests, not as a deviation. (6)
  **Idempotence — the previous evidence in this hunk was wrong and is replaced
  (W2 review 2026-09-27).** The withdrawn claim was that "emitted markers are
  distinguishable under stages 6/7's comparison domains (the 4-hex `CCCC` differs
  per anchor), so three adjacent emitted markers do not form a group". Markers
  *are* distinguishable as bytes, and idempotence still failed, because the
  comparison domain is not raw bytes: §4.4.7's domain is the **masked form**,
  and the frozen §4.6 mask list turns an all-decimal 4-hex checksum into
  `<num>`. Two emitted markers of the same kind and count whose checksums are both
  decimal (`5161` and `9616`, `4c01` and `9c17`, … — about 15% of checksums are
  all-decimal, and roughly 3% of marker pairs) therefore have **byte-equal
  masked forms**, so the second pass's stage 7 merges them as a "templated
  block". The true mechanisms are two, and only one of them is in scope here:
  * **A (fixed here, in W2.4 reading (h))**: a commit hid a shorter-period match
    inside its own anchor, because the `(i asc, L desc)` descent had already
    committed at a longer `L`. This is the reviewed 6-line repro. See the W2.4
    hunk for the fix, the reading, the cost bound and the three re-pinned
    stage-5 tests.
  * **B (measured, **not** fixed, out of this review's scope)**: the
    marker-mask collision above. Measured on 20 000 deterministic generated
    log-burst payloads (1–3 spans, header + patterned entry groups, per-line
    ts/ip/uuid/duration/counters, random `\t`/space padding, some verbatim
    line repeats; the same LCG constants as `tests/stage1_split.rs`):
    **80.06% (16 011/20 000) were not fixed points before the fix and 9.36%
    (1 872/20 000) after it**, and **all 1 872 residual cases are mechanism B**,
    classified mechanically: every second-pass commit's removed range contains an
    emitted marker (`" ...]"`), and the merge is a masked-domain-only merge (the
    two halves are neither raw-equal nor ws-equal). Zero of 20 000 payloads needed
    a third recompression to stabilise, before or after the fix. A smaller corpus
    (2 000 payloads, the one the test runs) measures 3.15% (63/2 000), the ceiling
    the test pins.
    B **cannot be fixed in code** without amending §4.5: the marker grammar and
    the `CCCC = 4 lowercase hex chars of xxh3-64(anchor)` definition are normative,
    and `render.rs` is not this review's file. The two candidate fixes are (i) a
    checksum that cannot be masked away (a non-decimal prefix, e.g. `0a3f`), which
    changes the §4.5 grammar and every golden's marker bytes, or (ii) a rule that
    a line carrying an emitted marker is never a template/block candidate, which
    changes §4.4.6/7's comparison-domain statement and would have to exempt
    prior-marker payloads (§12 explicitly fixtures those). Both are DESIGN.md
    decisions and are recorded here rather than taken; until one is made,
    DESIGN.md:344-346 and the §12 property at 733 are **not** established for
    arbitrary input, and this hunk no longer claims otherwise.
    **Superseded 2026-09-27 by W2.10:** candidate (ii) is what an independent
    design review then ruled, in the (ii)-shaped form "a unit carrying a
    well-formed §4.5 marker is never a candidate" — implemented as one
    `Unit.eligible` predicate at stage 1 rather than as a per-detector rule, so
    the §4.5 grammar and every golden are untouched. The measured residual for
    (B) and for mechanism (C) is now **0 / 20 000**.
  A **third** mechanism (C: a commit's anchor abutting a surviving neighbour
  its own stage could not see) was found by the new fuzz target and is not
  fixed either; the W2 review record below has its 173-byte reproducer.
  **Both B and C are fixed by W2.10** (2026-09-27): (B) by the stage-1 marker
  eligibility predicate, (C) by the masked-domain admission wall in
  `detect::blocks`; the reproducer is now a fixed point.
  The property is now *enforced* rather than sampled, in
  `recompressing_an_output_is_a_fixed_point` (the 26 fixtures, unchanged) and in
  the new `generated_log_bursts_converge_and_only_diverge_over_an_emitted_marker_or_an_anchor`
  (2 000 generated payloads, deterministic): every payload must reach a fixed
  point within two recompressions, and **every** divergence must be a second-pass
  commit that runs over an emitted marker or over a first-pass anchor, so a
  regression of mechanism A fails the test with the offending group's bytes in
  the message. `a_block_whose_anchor_hides_a_shorter_period_is_not_a_fixed_point_of_itself`
  pins the reviewed repro end-to-end (`twice == once`, `groups_collapsed == 0`
  on the second pass).
  **Gate M2 passes** — measured 2026-09-26, **re-measured 2026-09-27 after the W2
  review fixes and unchanged: the 12 goldens are still reproduced byte-for-byte
  (`the_chat_goldens_are_reproduced_byte_for_byte` green without regenerating a
  single golden file), the ×1000 in-process gate is 0.87 s debug, the fixed-clock
  `Stats` gate 0.87 s, and the cross-process gate 0.01 s** (debug build, i7-9700K):
  - *in-process ×1000*: `gate_m2_chat_outputs_are_byte_stable_over_1000_runs`
    compresses the 12-entry chat golden corpus (2 820 input bytes total; 9 of the
    12 entries change, 3 are the deliberate pass-throughs) once per run — **12 000
    compressions** — and asserts every run's output is byte-identical to run 0's
    for all 12 entries. **0.86 s** debug (12 000 compressions ≈ 72 µs each),
    **77 ms** release. Companion test
    `the_stats_are_byte_stable_over_1000_runs_with_a_fixed_clock` runs the same
    1 000 iterations under an injected constant clock and asserts the **entire
    `Stats` struct** (including the three `elapsed_*` fields) is equal every
    time: 0.88 s debug / 75 ms release.
  - *cross-process*: `gate_m2_outputs_are_identical_across_processes_and_environments`
    re-executes the test binary twice as a **child process** (so each run has a
    fresh OS-seeded `RandomState`), under two deliberately different
    environments — profile A `RUST_BACKTRACE=0 RAYON_NUM_THREADS=1
    RUST_TEST_THREADS=1 LC_ALL=C TZ=UTC`, profile B `RUST_BACKTRACE=full
    RAYON_NUM_THREADS=8 RUST_TEST_THREADS=4 LC_ALL=C.UTF-8
    TZ=Pacific/Auckland` — and each child writes its 12 output buffers plus a
    fingerprint of its process `RandomState` key
    (`RandomState::new().build_hasher()` over one byte) to a report file. The
    parent asserts (i) the two seed fingerprints **differ** (e.g. observed
    `21dfeb2643dfb7ce` vs `69afff959d060535` on one run; three further manual
    child launches gave `dccf1a75047d7f72`, `fe3a0f9a221d579c`,
    `9496a741d8916633` — all distinct), (ii) both children's 12 buffers are
    byte-identical to each other **and** to the parent's own in-process
    compressions, and (iii) at least 4 entries actually changed, so the gate is
    not vacuous. 10 ms wall for both children. The comparison is load-bearing:
    injecting a single extra byte into one child's report makes the gate fail
    (verified, then reverted). The child invocation uses the same
    `--exact <test> --nocapture` libtest argument shape that CI's
    `cargo nextest run` itself uses, and the report path carries the parent's
    pid, so the gate works under both runners; nextest is not installed in this
    environment, so the recorded run is `cargo test` (libtest) — CI's nextest
    job will re-exercise it.
  **W2 review record (2026-09-27)** — the findings and where each one landed.
  Files this review owns and changed: `crates/core/src/{pipeline,splice,ledger}.rs`,
  `crates/core/src/detect/blocks.rs`,
  `crates/core/tests/{pipeline,splice,ledger,detect_blocks}.rs`,
  `fuzz/fuzz_targets/{fuzz_splitter,fuzz_pipeline}.rs`, `fuzz/Cargo.toml`,
  `.github/workflows/fuzz.yml`, this hunk and the W2.4 hunk. No golden file
  changed and `config.rs`/`render.rs`/`templ.rs`/`templ_blocks.rs` were not
  touched.
  - **B1 (idempotence, the normative claim was false)**: fixed in
    `blocks::windowed_blocks` for stage 5 and stage 7 together — see the W2.4
    hunk's reading (h) and item (6) here for the true residual mechanism and the
    measured before/after generated-corpus rate (80.06% → 9.36% of 20 000
    payloads).
  - **B2 (marker style was resolved per payload, §4.5 says per span)**: fixed by
    putting the resolved style on `Commit` (`ledger::Commit::style`, stamped by
    `try_commit`, carried by `pipeline::shift`) and dropping the style parameter
    from `splice::splice_into`/`spliced_len`; `splice_ledger` keeps its shape.
    `splice.rs` also now asserts `anchor ⊆ removed` (the R3 last line of
    defence: without it a regression would silently duplicate bytes), pinned by
    `an_anchor_outside_its_removed_range_is_refused`. The per-span gate pricing
    is untouched and can no longer diverge from the rendered bytes. New
    `each_span_renders_in_its_own_resolved_style` pins a mixed payload (one
    all-ASCII span + one non-ASCII span in the *same* document: the first emits
    `[... x5 rows, template`, the second `⟪×5 rows, template`, exactly one of
    each in the whole output), and `marker_at()` in this test file is now
    **style-exact** (it used to accept either style, which is why B2 slipped
    through) — the style comes from `commit.style`, and the whole 26-fixture
    corpus passes under it.
  - **`Proposal::repeat` truncation**: `ledger::try_commit` now returns
    `InvalidCount` for a group that is not a whole number of copies, so a
    partial copy can never price fewer bytes than it removes (the `repeat`
    constructor may still *derive* a truncated count; it can no longer be
    committed). Pinned by `a_group_that_is_not_a_whole_number_of_copies_is_rejected`.
  - **Reused `spans`**: the unknown-schema path now clears the caller's span
    vector unconditionally instead of leaving the previous call's spans in it.
  - **Misleading test claim**: the "an all-ascii span resolves to the ascii style"
    assertion inside `the_pretty_and_minified_chat_variants_compress_the_same_span`
    only ever saw one span, so it could not reach the (now removed)
    `unanimous == false` branch; its message now says so and points at
    `each_span_renders_in_its_own_resolved_style`, which is the real coverage.
  - **Determinism source scan**: the banned-identifier checks in
    `tests/pipeline.rs`, `tests/ledger.rs` and `tests/detect_blocks.rs` matched
    the **substring** `rand`, so an innocuous identifier like `brand` would have
    been rejected; they now match identifier tokens (splitting on everything
    outside `[A-Za-z0-9_]`), and the pipeline scan carries two self-checks
    (`brand` must pass, `rand::rng()` must fail) so the matcher cannot rot into a
    no-op. The same substring scan still exists in the five test files this
    review does not own (`detect_exact`, `detect_wsruns`, `detect_templ`,
    `detect_templ_blocks`, `splice`); W4.1 should convert them the same way.
  - **`reversible`**: see deviation (2) — out of `config.rs`'s ownership, pinned
    by a test and a recorded recommendation instead of silently fixed.
  - **Fuzz (W0.4/W4.5, no Wave 2 coverage existed)**: `fuzz_splitter`'s
    `assert_eq!(out, data)` was **vacuous** — it concatenated
    `data[at..unit.range.end]` and `data[unit.range.end..stop]` unconditionally, so
    it held for any ascending disjoint unit list. It now rebuilds the output from
    each `unit.range` plus the independently derived gap bytes and asserts every
    gap is a whole run of line-boundary escape units (`\n`, `\u000A`, `\u000a`) or
    a single `,` (the §4.4.1b joiner rule), which is what makes the partition
    meaningful; the two live asserts are kept. New `fuzz_pipeline` runs
    `Compressor::compress` and asserts: no panic; the output equals the input
    outside every reported `Commit` range (walking the commit list) with the
    marker length pinned by the public `ledger::marker_len` and every marker
    valid UTF-8 with no `"`, `\` or control byte; a commit-free payload is a
    byte-for-byte pass-through; the output parses as JSON whenever the input
    does (a compact recursive-descent validator in the target, BOM tolerated,
    depth capped at 64); and idempotence — convergence to a fixed point within
    two recompressions, with **every** intervening divergence required to be the
    marker-mask mechanism of item (6) (a second-pass commit whose removed range
    carries an emitted marker), which is exactly what B1's regression would
    violate. Both new/rewritten targets were checked for non-vacuity by breaking
    the code and observing the crash, then reverting: reverting W2.4 reading (h)
    makes `fuzz_pipeline` panic on the 6-line repro seed
    (`a second pass may only merge emitted markers, got TemplatedBlock over
    "2026-08-25T10:00:01Z INFO hc …"`), and rejecting the `,` joiner makes
    `fuzz_splitter` crash on the 128 KB over-cap dump seed.
  - **Fuzz run counts (2026-09-27)**, all four targets, exit 0, zero crashes,
    corpora seeded from the W0.3 fixtures (the pipeline corpus also carries the
    6-line repro payload, the 173-byte mechanism-C reproducer below, and the
    splitter corpus a 128 KB over-cap `},{` dump so stage 1b is really fuzzed):
    `fuzz_sniff` 200 000 runs (0 s, cov 140 / ft 591, 342 files),
    `fuzz_locator` 200 000 runs (7 s, cov 540 / ft 2 301, 912 files),
    `fuzz_splitter` 200 000 runs (29 s, cov 98 / ft 403, 121 files),
    `fuzz_pipeline` 200 000 runs (1 374 s, cov 1 259 / ft 5 774, 1 543 files /
    20 MB). **Toolchain deviation, unchanged from W0.4/W1.1/W1.2**: nightly is
    still unreachable here (static.rust-lang.org connection timeout), so all
    four runs used the documented fallback — stable 1.98.0 with
    `RUSTC_BOOTSTRAP=1` and `cargo fuzz run --sanitizer none`, i.e. **ASan was
    off** (stable cannot enable it). `.github/workflows/fuzz.yml` keeps the
    nightly+ASan configuration and now also runs on `pull_request` (it was
    `workflow_dispatch`-only, which is why §12's "a fuzz panic is a blocker"
    had no gate) and runs all four targets at 200 runs each.
  - **A third residual mechanism (C) was found by the new fuzz target and is
    NOT fixed** — recorded here because it is a real §4.4 gap, not a coding
    mistake. Minimal reproducer (173 bytes, plain text, so `content_type=text`
    and one whole-payload span): `2026-08-25T11,0:02Z INFO db 1&02
    ok\n2026-08-25T11,00:02Z INFO db 10.1&0.2 ok\n2026-08-25T11:1.1&0.2
    ok\n2026-08-25T11,00:02Z INFO db 10.1&0.2 ok\n2026-08-25T11:1.1&0.2 ok\n`.
    Pass 1: stage 5 commits units 1..4 (a two-line `Block`, anchor = lines
    1-2) because those two lines are ws-equal; lines 0 and 1 are *template*-equal
    but not ws-equal, so nothing merges them. Pass 2: stage 7 (minimum period 1)
    finds the pair (line 0, anchor line 1) and commits it, so the output shrinks
    again (173 → 128 → 119 B, stable at pass 3). The general shape: **a commit's
    anchor is glued to a surviving neighbour that the commit's own stage could
    not see** — stage 7 never examined start 0 in pass 1 because unit 1 was
    already claimed, and the marker is glued to the anchor's *last* line, so the
    anchor's *head* becomes indistinguishable from its left neighbour in the
    output. A per-commit check cannot see this: the match straddles the commit's
    left boundary, and its left context is whatever survived. Closing it needs a
    decision about the whole compaction, not one commit — e.g. compressing to a
    fixed point (re-scan the residual of the spliced output and iterate), or
    treating a line adjacent to an anchor as a wall in §4.4.5/7. Both are
    DESIGN.md changes and are **not** taken here. Because of C the fuzz target
    asserts the property that does hold universally (recompression reaches a
    fixed point within two further passes, and never grows the payload) rather
    than the B-only classification the deterministic test uses, which C would
    false-positive on. The 2 000-payload generated corpus does not reach C, so
    the deterministic test enforces the stricter "marker **or** anchor" rule
    there; the exact mechanism-A regression is pinned by name in both places.
  - **Verification**: `cargo test --workspace` **340 tests green** (341
    collected, the one `#[ignore]`d golden generator), i.e. the 332 of the
    W2.9 baseline plus the 8 this review adds; `cargo fmt --all --check` clean;
    `cargo clippy --workspace --all-targets -- -D warnings` clean; the fuzz crate
    checks and lints clean separately (`fuzz/` is excluded from the workspace, as
    W0.4 recorded); `cargo metadata --locked --manifest-path fuzz/Cargo.toml`
    still succeeds — adding a `[[bin]]` does not touch the lock. No new
    dependency, no golden file and no DESIGN.md change.

- **W2.10 Idempotence: markers are never groupable + the anchor-adjacency wall**
  (W2 review follow-up, 2026-09-27) — the two residual mechanisms the W2.9 hunk
  recorded as unfixed (item (6) **B** and the **C** reproducer) are now closed.
  **Files changed:** `crates/core/src/{stage1,stage1b,config,pipeline}.rs`,
  `crates/core/src/detect/{templ,templ_blocks,blocks}.rs`,
  `crates/core/tests/{pipeline,stage1_split,detect_blocks,detect_templ_blocks,api}.rs`.
  No new dependency, no new fixture, **no golden file changed** (see below), and
  DESIGN.md is **not** amended — the amendments the review requires are quoted in
  the last sub-item and belong to DESIGN.md's owner.

  - **(B) mechanism closed at the stage-1 chokepoint: `Unit.eligible`.** The
    review rejected remapping `CCCC` to a letter alphabet (it lowers the rate
    ~100×, not to zero) and ruled for one eligibility predicate instead, because
    `Unit.eligible` is already honoured by all five detectors
    (`detect/exact.rs:26,33`, `detect/wsruns.rs` through `walk_runs`,
    `detect/blocks.rs:102`, `detect/templ.rs:120,127`, `detect/templ_blocks.rs:74`
    — the review's citations, i.e. line numbers as of before this hunk).
    It is implemented once, in `stage1.rs`:
    `pub fn carries_marker(unit: &[u8], style: MarkerStyle) -> bool` plus the
    grammar check itself, which is **derived from the renderer rather than
    restated**: the five §4.5 `CORE`s come from `ledger::CommitKind::core` and the
    `OPEN`/`SEP`/`CLOSE` framing from `ledger::framing`, so the predicate cannot
    drift from `render.rs`. Cost, per the review: a first-byte skip scan for the
    `OPEN` token per unit (so a line without it is one linear pass and nothing
    else), then O(1) validation of the ten possible `CORE`s, **allocation-free and
    integer-only**; `MarkerStyle::Auto` (never reached in production — the
    pipeline resolves the style per span — one `resolve_style` call per eligible
    span, inside `compact_span` — and `Ledger::new` refuses `Auto`) recognizes
    *both* styles, and a resolved style recognizes only its own, which is why the
    12 chat goldens are unaffected. Two shapes are
    deliberately **not** matched: the bare `OPEN` token (so `[... ` — which §4.5
    itself calls plausible in real logs — does not become mass-ineligible) and
    anything that is not a *well-formed* marker (`[… x identical …]`, a missing
    close, a 3- or 5-hex checksum, an uppercase hex digit, an unknown core). The
    same predicate runs on the stage-1b record path
    (`stage1b::segment_line`), because a stage-1b record is a unit like any other
    and an emitted marker rides a record's last line too.
    **One signature change, propagated mechanically:** `stage1::split_span` and
    `split_span_counted` now take the resolved `MarkerStyle` as a second argument
    (the pipeline passes the same `style` it gives `Ledger::new`; every test call
    site passes its file's `UNICODE` constant). Splitting the eligibility
    decision from the span — the point of keying on the resolved style — is worth
    more than the ~190 mechanical edits, and the compiler checked every one.
  - **(C) mechanism closed by an admission wall, coarser domain, right at the
    chokepoint the review named.** `detect/templ.rs`'s masked arena is now a
    **pre-pass** (`Forms::build(span, units, scratch) -> Option<Forms>`) that
    `pipeline::compact_span` runs *before* stage 5 — the first stage whose anchor
    can be more than one unit — and `template_groups(forms, ledger, min)` is the
    bare windowed walk that consumes it, so stage 6 masks exactly once (the
    review's "DELETES stage 6's duplicate masking"). The arena is handed to
    `blocks::windowed_blocks` as a **second closure beside the existing
    `same_bytes`** (`left_wall: (before, first) -> bool`, one call to
    `Forms::same`), and the check is one `&&` chain in
    `blocks::wall_blocks`: *refuse the commit when the unit immediately before
    `removed.start` — i.e. `at - 1` when it is unclaimed and eligible, which is
    exactly the unit that abuts the anchor in the spliced output — masks equal to
    the anchor's first unit.* It runs only after `equal` + `same_bytes` +
    `anchor_is_match_free` have all passed, i.e. at most once per candidate that
    would otherwise have committed, and it `break`s the `L` descent (the wall does
    not depend on `L`) so the scan moves to the next start. **The right boundary
    needs no wall** because the marker rides the anchor's *last* line, and fix (B)
    makes that unit ineligible in the next pass; the left boundary is the only one
    where a bare anchor line survives, which is why the wall exists. The
    comparison domain is the **masked** one and that is complete rather than
    merely conservative: masking is a pure function of the ws-normalized form, so
    `raw-equal ⊂ ws-equal ⊂ mask-equal`, and the coarsest domain is therefore a
    superset of every domain any later pass can use.
  - **Why the wall is allowed to over-refuse, and where it actually bites.** The
    wall is strictly coarser than stage 5's own ws domain, so it can only refuse a
    commit the committing stage could have made: the output grows, never
    corrupts. This is documented rather than worked around. One stage-5 test had
    to be re-pinned because of it: `a_block_whose_anchor_itself_repeats_is_never_committed`
    used `[L0,L1,C0,L1,C0,L0,…]`, whose anchor head `L1` masks equal to the line
    before it, so the wall now refuses both of its candidates; the payload's
    period-5 head is `H0` instead, which masks differently, and every assertion in
    that test (two refusals, two commits, `verifications == 4`, anchors) is
    unchanged. The refusal itself is now pinned by its own test,
    `a_block_whose_anchor_head_would_glue_to_a_mask_equal_neighbour_is_refused`
    (commit) plus `a_record_anchor_head_that_would_glue_to_a_mask_equal_record_is_refused`
    (the same wall on the **stage-1b record** path, with a control half in which
    the record before the anchor masks differently and the identical candidate
    commits) and, for stage 7, by
    `a_two_unit_anchor_head_that_would_glue_to_a_template_equal_neighbour_is_refused`
    (also with its control half). The control halves are what make these tests
    about the wall and not about the profitability gate: each one asserts
    `profitable(...)` for the very candidate that is refused, and then asserts
    that the same candidate commits once the neighbour's masked form differs.
  - **One recorded non-reachability, stated rather than tested.** A *single-unit*
    anchor never needs the wall (its own marker rides it, so fix (B) covers it),
    but that case cannot be reached either: if `mask(at-1) == mask(at)` then the
    candidate at `at-1` is a period-1 candidate that the scan examines first, its
    chain extension is at least as profitable as the later pair (same anchor cost,
    more removed bytes), and if the chain fails the §4.4 gate so does every pair
    inside it. A `length > 1` exemption was therefore **not** written: it would be
    untestable dead code, and the wall without it is safe by the over-refusal
    argument above. That is also why the fixture with the most markers in the
    corpus, `edges/prior-markers.json`, is untouched at all: its only commit has a
    single-unit anchor.
  - **`reversible: true` is now refused (affirmative-false-promise fix).**
    `config::ResolveError::UnsupportedReversible` is new and `config::resolve`
    rejects **only** `Some(true)`, mirroring how `AllMessages`/`ExplicitPaths` are
    rejected at `config.rs:95-98`; `reversible: false` (and an absent option)
    still resolves and still echoes `false`, which claims nothing. The reason is
    §6.2 field 19's `restore_ids` ("iff reversible=true") plus §9's CCR store:
    echoing `true` next to an empty list lies to a machine client. Tests:
    `config.rs::reversible_true_is_rejected_and_false_resolves` (unit),
    `tests/pipeline.rs::reversible_true_is_rejected` (replaces
    `reversible_is_echoed_but_still_not_honoured`) and
    `tests/api.rs::reversible_true_is_refused_and_false_echoes_false` (replaces
    W3.1's `reversible_is_accepted_and_echoed_but_still_changes_nothing`).
    **W3.4 must re-admit it:** the CCR store, `/v1/restore`, gRPC `Restore` and
    `Stats.restore_ids` are one change, and the rejection is the single `Some(true)`
    match arm in `config::resolve` to flip.
    **Cross-crate consequence, for the transport owner:** the ruling is a
    behaviour change that two committed transport tests encode — W3.2's
    `crates/server/tests/http.rs::reversible_is_accepted_and_reserved` (now a 400,
    not a 200) and W3.3's `crates/proto/src/convert.rs::explicit_false_survives_wire_and_resolves_false`
    (`resolve` now returns `Err`). Both are outside this hunk's ownership and are
    **left failing on purpose**; the transport's own `resolve_message` already
     carries an `UnsupportedReversible` arm (W3.3), so only the two expectations
     need flipping.
     **Done, by W3.4 (2026-09-27, recorded below):** the refusal is gone
     (`ResolveError::UnsupportedReversible` is deleted, not just unused),
     `reversible=true` resolves and is honoured, and all three transport tests
     plus the three core tests now assert the honoured behaviour. The rationale
     above stays as the record of *why* the refusal existed for one wave.
  - **The golden did *not* have to be re-baselined, and here is why.** This hunk
    was told to expect `edges/prior-markers.json`'s golden output to change; it
    does not, and `the_chat_goldens_are_reproduced_byte_for_byte` still passes
    **without regenerating a single golden file**. Mechanically: the fixture's
    three marker lines are units 0, 3 and 4, and only its sole commit matters —
    the stage-7 `TemplatedBlock` over units 1–2, whose anchor is a single unit, so
    neither fix can touch it (fix (B) makes units 0 and 4 ineligible, which only
    removes them as candidates for a group they were never in, and the §4.6 mask
    keys the *ASCII* marker on line 3 to the ascii style, so in this unicode span
    it stays eligible and is not part of the commit). §12's locator-edge-fixture bullet
    (DESIGN.md:738-742) still exercises marker nesting under idempotence, and
    `prior_marker_text_round_trips_untouched` now pins the style keying directly
    (`carries_marker(.., Unicode)` true for the two unicode markers, false for the
    ascii one in the same span, true for that same ascii marker under
    `MarkerStyle::Ascii`).
  - **The property test is now enforced, not sampled.**
    `generated_log_bursts_converge_and_only_diverge_over_an_emitted_marker_or_an_anchor`
    is replaced by **`every_generated_log_burst_is_a_fixed_point`**: the
    `marker || anchor` escape hatch and its 5% ceiling are gone, `divergent` must
    be `0`, and a divergence panics with the offending commit's kind, its removed
    bytes and its anchor. **Measured, not assumed:**
    * **before** (this hunk's parent, `d370dbb` with the core sources reverted):
      **550 / 20 000 generated payloads = 2.75%** were not fixed points, every one
      of them mechanism B (each second-pass commit's removed range contains an
      emitted `" ...]"`, and the merge is masked-domain-only), and **0** needed a
      third recompression. (The W2.9 hunk's 9.36% was measured on a different
      corpus/codepath state; 2.75% is what this tree measures, and the
      classification is the same.)
    * **after:** **0 / 20 000 = 0.00%**, and still **0** needing a third
      recompression. The 2 000-payload corpus the test runs is likewise **0**
      (the W2.9 hunk recorded 63 / 2 000 = 3.15% there; re-measured here after
      the fix, as 0).
    * the fixes cost **nothing measurable** in compression on that corpus: total
      bytes-in → bytes-out is **41.8%** before and **41.8%** after over the same
      20 000 payloads.
    * the generated corpus does **not** reach mechanism C (as the W2.9 hunk
      already noted), so C is pinned by its dedicated tests only, not by the
      corpus. Non-vacuity was checked by breaking the code and watching each test
      fail, then reverting: stubbing `carries_marker` to `false` fails
      `every_generated_log_burst_is_a_fixed_point` (first of 2 000) and
      `two_markers_with_all_decimal_checksums_are_never_merged`; stubbing
      `wall_blocks` to `false` fails
      `a_commit_whose_anchor_head_would_glue_to_a_template_equal_neighbour_is_a_fixed_point`,
      `a_block_whose_anchor_head_would_glue_to_a_mask_equal_neighbour_is_refused`,
      `a_record_anchor_head_that_would_glue_to_a_mask_equal_record_is_refused`
      and
      `a_two_unit_anchor_head_that_would_glue_to_a_template_equal_neighbour_is_refused`
      — and, on the generated corpus, nothing else.
    * two new regression tests pin the mechanisms by name:
      `two_markers_with_all_decimal_checksums_are_never_merged` (anchors hashing
      to `5161` and `9616` — both all-decimal, so both mask to `<num>` — asserting
      `pass2 == pass1` and no commits) and
      `a_commit_whose_anchor_head_would_glue_to_a_template_equal_neighbour_is_a_fixed_point`
      (the mechanism-C payload; note it is **171** bytes as spelled at this hunk's
      lines 1843-1847, not 173 — the five lines plus four `\n` escapes — and it is
      now a fixed point at 162 bytes after one pass, with the stage-5 block at
      units 1..4 refused by the wall and a single stage-7 commit at units 0–1
      emitted instead).
  - **Cost, measured, and one behaviour change callers can see.** (a) One extra
    first-byte scan per unit in stage 1, plus O(1) validation only where an `OPEN`
    token occurs. (b) The masked pre-pass now runs for **every** span, including
    `template_dedup = false`, because the admission wall is defined in the masked
    (coarsest) domain; a §4.4.6 fingerprint table that fills therefore degrades the
    span to pass-through even with template dedup off, which is §7's own
    "pathological unique-line floods degrade to pass-through" and the same
    degradation stage 6 already had on the default path. The end-to-end cost,
    measured on the 104 385 312-byte generated corpus (20 000 payloads, release
    build, i7-9700K, best of 5, whole `Compressor::compress` call including detect
    and splice — so an upper bound on the span-compaction delta, not §8's
    span-only metric): **32.1 MB/s before, 31.4 MB/s after, i.e. −2.2%.** §8's
    ≥160 MB/s span-compaction floor is re-measured by W4.3's criterion gate on
    8 MiB, which this hunk did not run. (c) The pipeline's stage order is
    unchanged and still normative; the pre-pass is not a stage, and
    `the_pipeline_module_has_no_forbidden_determinism_inputs` now pins the
    call-site order as *1, 3, 4, pre-pass, 5, 6, 7*.
  - **One deviation from the review's suggested call-site, and why.** The review
    suggested handing the arena to `blocks::windowed_blocks` "as a SECOND closure
    beside the existing `same_bytes`" with "one boundary check at blocks.rs:168-175";
    that is what landed, but the two closures travel together in one generic
    `blocks::Domain { ids, same_bytes, left_wall }` (a single extra parameter
    would have tripped `clippy::too_many_arguments` at 8/7, and `Domain` keeps the
    walker monomorphised rather than boxing the two comparisons behind `dyn`).
    `Templated` is gone: `template_groups` returns `StageStats` and
    `templated_blocks` takes `Option<&Forms>` (`None` = the degraded span), which
    is the same information the old struct carried.
  - **Verification.** `cargo test --workspace` → **438 green, 2 red, 1 ignored**
    (441 collected) at this hunk's parent `d370dbb`; the two red tests are the
    transport/proto `reversible` expectations listed above, both in files this
    hunk does not own. `crates/core` is **370 green**, up from 361: +2 pipeline
    + 3 `stage1_split` + 2 `detect_blocks` + 1 `detect_templ_blocks` + 1
    `config` unit = +9, with two `reversible` tests renamed rather than added.
    `cargo fmt --all --check` clean;
    `cargo clippy --workspace --all-targets -- -D warnings` clean. The `fuzz/`
    crate (excluded from the workspace, as W0.4 recorded) is untouched, and
    the property `fuzz_pipeline` asserts (convergence to a fixed point within two
    recompressions, never growing) now follows from the fixed point; the crate
    itself is untouched and was **not** re-run here (no nightly toolchain).
  - **DESIGN.md amendments this requires — proposed text, DESIGN.md NOT edited.**
    Four places, each quoted verbatim as it stands today.
    1. **§4.4 item 1 ("Line split"), lines 322-324** — extend the "excluded from
       grouping" notion to marker-shaped units. Today:
       > 1. **Line split**: `memchr`-style scan for `\n` sequences → line slice views.
       >    Lines longer than `max_line_bytes` are excluded from grouping and handed
       >    to stage 1b (bounds table memory and worst-case per-line work).

       Propose appending one sentence to that item:
       >    A unit that contains a well-formed §4.5 marker is likewise excluded
       >    from grouping: the marker rides a committed group's last unit, so
       >    admitting it would let a later pass merge two emitted markers whose
       >    `CCCC` masks to one §4.6 template.
    2. **§4.5's "Accepted risk" paragraph, lines 441-443** — it currently says
       marker-shaped text is "documented, not defended against", which is no
       longer true of the compressor's own output. Today:
       > Accepted risk: a payload that literally contains marker-shaped text may
       > confuse downstream consumers. Markers are chosen to be improbable in logs;
       > documented, not defended against.

       Propose replacing it with:
       > Accepted risk: a payload that literally contains marker-shaped text may
       > confuse downstream consumers. Markers are chosen to be improbable in logs;
       > caller-supplied lookalike text is documented, not defended against. The
       > compressor's *own* markers are: a unit carrying a well-formed marker is
       > ineligible for grouping (§4.4.1), which is what makes recompression a
       > fixed point.
    3. **§4.4's "Comparison domains (normative)" paragraph, lines 313-320** — note
       that ADMISSION, not equality, consults the masked domain at the left
       boundary. Today the whole paragraph is:
       > **Comparison domains (normative).** Each detector fixes one comparison
       > domain, used by *both* its fingerprints and its verifying memcmp:
       > stage 3 — raw bytes; stage 4 — ws-normalized forms (§4.2); stage 5 —
       > ws-normalized forms; stage 6 — masked forms (ws-normalized input, §4.6);
       > stage 7 — template ids, verified by memcmp of masked-form bytes. Anchors
       > are always emitted as raw original bytes regardless of domain. Merging a
       > pair that is equal in a normalized domain but differs raw (stages 4–7) is
       > intended and priced into the §4.7 information-loss contract.

       Propose appending:
       > Admission is not equality and uses the coarsest domain: a block commit
       > (stages 5 and 7) is refused when the surviving unit immediately before
       > it masks equal to the anchor's first unit, because the marker rides the
       > anchor's *last* unit and would leave the head adjacent to a neighbour
       > the committing stage could not see. The masked domain is a superset of
       > every domain a later pass can use, so this rule can only over-refuse.
    4. **§4.4's stage list, items 5 and 7** — one sentence each (same wording, so
       the two stages cannot diverge). Propose appending to item 5 ("Repeated
       blocks"), after its "Scan order `(i asc, L desc)` makes the committed block
       leftmost-then-longest by construction" sentence, and identically to item 7
       ("Template blocks"), after its "Marker: `⟪templated block ×N⟫`" sentence:
       > **Admission wall (normative):** a candidate whose surviving predecessor
       > masks equal to the anchor's first unit is refused; the scan continues at
       > the next start.
    §4.4's own idempotence claim (lines 343-346) and §12's property at line 733
    are then true as written, which is why this hunk asserts `divergent == 0`
    instead of sampling it.

## Wave 3 — API & transports (deps W2.9)

- **W3.1 Library API** — `crates/core` public surface, options resolution
  echo, `strict_validate` flag (§4.1). Sequential first.
  Status: **complete** (2026-09-27). The stable surface is the new module
  `quantification_core::api` (`crates/core/src/api.rs`); `crates/core/src/lib.rs`
  gained the single line `pub mod api;` (no existing line reordered or removed)
  and `crates/core/Cargo.toml` gained the `[features]` table below. **The exact
  signatures W3.2/W3.3/W3.4 build on, frozen here:**
  ```rust
  pub const STRICT_VALIDATE: bool;                       // cfg!(feature = "strict_validate")
  pub use crate::config::{MarkerStyle, RawOptions, ResolveError, ScopePolicy};
  pub use crate::locator::NoopReason;                    // = locator::NoopReason
  pub use crate::pipeline::{ALGO_VERSION, Clock, MonotonicClock, Stats};
  pub use crate::sniff::Schema as ContentType;           // Chat|Responses|Messages|Text

  pub struct Request {
      pub content_type: Option<ContentType>,   // None = AUTO (§6.2's ContentType::Auto)
      pub options: RawOptions,                 // the §6.1 option set, §7 defaults
  }
  impl Request {
      pub fn pinned(content_type: ContentType) -> Self;         // Request::default() = auto
      pub fn with_options(self, options: RawOptions) -> Self;
  }

  pub enum ApiError {
      Options(ResolveError),
      ContentTypeMismatch { pinned: ContentType, sniffed: Option<ContentType> },
      Malformed,                                                // strict_validate only
  }
  impl ApiError { pub fn as_str(&self) -> &'static str; }        // + Display

  pub struct Compressor { /* private: pipeline::Compressor */ }
  impl Compressor {
      pub fn new() -> Self;                                      // MonotonicClock
      pub fn with_clock(clock: impl Clock + 'static) -> Self;   // the W2.9 seam, unchanged
      pub fn compress(
          &mut self,
          payload: &[u8],
          request: &Request,
          out: &mut Vec<u8>,                                    // caller-owned, reused
      ) -> Result<Stats, ApiError>;
  }
  pub fn reserve(out: &mut Vec<u8>, input_len: usize);          // pre-sizing helper
  ```
  One obvious entry point: `compress(bytes, request, out) -> Result<Stats,
  ApiError>`, the compressed bytes landing in the caller's `out`. It is pure
  (§3): no tokio, no IO, no wall clock, no RNG, no env; the `Clock` seam is
  injectable through `with_clock` and can reach nothing but the three
  `elapsed_*` fields (the api module itself never calls `now_ns`, pinned by a
  source scan, and `a_pathological_clock_cannot_change_the_output` injects a
  clock that returns `u64::MAX`/`0` alternately and **panics on a fifth read**,
  asserting byte-identical output). `reserve` is the pre-sizing helper the
  design already had: it is `splice::spliced_len(input_len, &[])` — the
  splicer's own length function with no commits, which is an upper bound on
  every possible output because §4.4's profitability gate never grows a
  payload — so one `Compressor` plus one reserved `Vec<u8>` serves a whole
  request stream with no per-call output allocation
  (`the_reserved_buffer_is_reused_and_never_reallocates`). Options are
  resolved per call through the existing `config::resolve` and the resolved
  options' `options_echo` rides out in `Stats::options_echo` (§6.2 field 17)
  **verbatim** — `api` never reformats it; the canonical field order and the §7
  defaults are pinned end-to-end by
  `the_seven_defaults_reach_the_echo_end_to_end` and
  `every_option_reaches_the_echo_in_the_section_six_one_order`.
  **The pinned-`content_type` path** (the only error §3's degradation policy
  reserves, `422 InvalidArgument`): `Request::pinned(ContentType)` makes the
  caller's claim explicit, and the pin **drives location** — it is not a
  validation-only hint. `ApiError::ContentTypeMismatch` is raised when the
  payload plainly contradicts the pin, decided from `sniff::sniff`'s own
  normative discriminators and nothing else (§4.1's candidate order, frozen by
  W1.1), so no second scanner is needed:
  * `sniff == Some(pinned)` ⇒ never a contradiction;
  * `sniff == None` and the pin is a JSON schema ⇒ contradiction (the payload
    matches no known schema, e.g. `{"foo":1}`);
  * `Text` pinned ⇒ **never** a contradiction (plain text is opaque and the pin
    is a legitimate way to say "compress this whole buffer", including a
    buffer that happens to start with a brace);
  * `Chat`/`Messages` vs `Chat`/`Messages` ⇒ **never** a contradiction in either
    direction — this is the one place a pin may legitimately disagree with the
    sniff, and it is observable: a `tool_result` block is a `Tool` span under a
    `Messages` pin and is not eligible at all under a `Chat` pin, which
    `the_pin_decides_the_schema_and_not_the_sniff` pins (and the same payload
    also shows the `user_and_tools` policy difference);
  * every other pairing (`Responses` vs `Chat`/`Messages`, any JSON pin vs
    `Text`) ⇒ contradiction, because the sniff's discriminators make the two
    schemas mutually exclusive by construction (`Responses` requires root
    `input` and *no* root `messages`; `Chat` requires root `messages`);
  * and a document that the locator cannot parse under a pin is a
    contradiction too, per §4.1's acceptance envelope ("never a 422 unless
    `content_type` was explicitly pinned"), reported after the compression as
    `ContentTypeMismatch` with the same shape.
  Everything else degrades: an unpinned unknown schema is
  `Ok(Stats { degraded: true, noop_reason: Some(UnknownSchema), .. })` with
  byte-identical output, a malformed document is the same with `Malformed`, and
  the two paths are asserted side by side by
  `a_contradiction_is_an_error_while_an_unknown_schema_is_a_pass_through`. No
  payload in the 26-fixture corpus is ever refused
  (`no_fixture_of_the_corpus_is_ever_refused`), and the six degenerate payloads
  (empty, whitespace, `null`, `{}`, `[]`, a bare string) pass through without a
  panic or an error.
  **`strict_validate` (§4.1).** An optional cargo feature **off by default**
  (`[features] default = [], strict_validate = []`). When off, the whole
  validator is `#[cfg]`-ed out and the only thing compiled in its place is
  `fn strict(_payload: &[u8], _pinned: Option<ContentType>) -> Result<(), ApiError>
  { Ok(()) }` — measured, the default release rlib is 728 266 bytes with **zero**
  `api::Parser` symbols against 774 638 bytes with them, so the default build
  pays no code, no allocation and no pass. **Cost when on: one extra full
  O(n) recursive-descent pass over the payload (strict JSON grammar: exact
  `true`/`false`/`null`, no leading zeros, `\uXXXX` validated, no raw control
  byte in a string, no trailing bytes, `json_depth_cap` counted the same way
  the locator counts it — 64 containers accepted, 65 refused — BOM tolerated),
  plus one extra `sniff::sniff` on the unpinned path; allocation-free and
  integer-only, but linear, so per §4.1 it is "acceptable for small payloads
  only" and must not be enabled on the §8 8 MiB hot path blindly.** It never
  changes output bytes for a document it accepts
  (`with_the_flag_a_valid_payload_is_untouched_by_the_parse` diffs the api
  against a raw `pipeline::Compressor` over the whole corpus, and the 12 chat
  goldens are reproduced byte-for-byte in both feature states). It is skipped
  when the effective content type is `Text` (there is no JSON guarantee to
  give for opaque text), it only ever *rejects* — the failure is
  `ApiError::Malformed` for an unpinned request, and a pinned request reports
  every rejection as `ContentTypeMismatch` so that a transport's status mapping
  never depends on the build. §3's `422` therefore stays reserved for
  `ContentTypeMismatch`; a transport should map `Malformed` to `400`.
  Both feature states are tested: 31 tests in the default build, 33 with
  `--features strict_validate` (the extra two are the cfg'd pairs).
  **One change to an existing file, called out.** `pipeline::Compressor::compress`
  is sniff-driven and W1.1's `locate_as` is public, so a pin could not drive
  location without threading the schema into the pipeline. `pipeline.rs` gained
  `Compressor::compress_as(&[u8], Schema, &ResolvedOptions, &mut Vec<u8>) ->
  Stats` and a private `run(..., pinned: Option<Schema>, ...)` that
  `compress` now calls with `None`; the only behavioural line is
  `pinned.or_else(|| sniff::sniff(payload))` in place of `sniff::sniff(payload)`,
  plus `use crate::sniff::{self, Schema}`. `compress` is bit-identical (all 340
  baseline tests and all 12 goldens unchanged) and the W2.9 source scans in
  `tests/pipeline.rs` still hold, including the four-`now_ns()` and
  stage-order invariants. No other existing module was touched.
  **The surface is provably closed**, which is what keeps W3.2/W3.3 from
  reaching around it: `the_public_surface_is_exactly_the_documented_items`
  extracts every `pub` declaration from `api.rs` and compares it to the 21 items
  above (any addition breaks the test and must be recorded here);
  `no_public_signature_exposes_an_internal_type` token-scans every public
  function signature and every public field against an allowlist of public types
  (with a self-check that the scan rejects a synthetic
  `-> &[Commit]` leak), pins the four public fields, and asserts the wrapped
  `pipeline::Compressor` is a **private** field of `api::Compressor`;
  `the_api_module_cannot_reach_the_detectors_the_ledger_or_the_fingerprint_tables`
  token-scans the whole module for `detect`/`ledger`/`fingerprint`/`mask`/
  `keys`/`stage1`/`wsnorm`/`s1`/`render` and for the internal types
  `Commit`/`Span`/`Scratch`/`StageStats`/`Ledger` (the only internal modules it
  may name are `config`, `pipeline`, `sniff`, `splice`, `locator`), and for the
  §5 banned determinism inputs plus `tokio`/`std::io`/`std::fs`/`thread`; and
  the same scan asserts the module carries no comment at all. The s1 spike is
  still reachable only as `quantification_core::spike` and is **not** re-exported
  here. Tests: 31 new integration tests in `crates/core/tests/api.rs`
  (core 330 → 361, workspace 340 → **371**, 372 collected with
  the one `#[ignore]`d golden generator; **373** with
  `--features strict_validate`, which swaps the two default-build degradation
  tests for four strict-parse ones).
  They include the 12 chat goldens
  reproduced through the public API, options resolution and echo end to end
  (`min_group_size` 3 vs 4 on a three-line run, both forced marker styles
  reaching the output, `scope_policy` selecting a `tool_result` span, the §7
  defaults pinned as one string), W2.9 observation (5) carried into the api
  layer (`min_group_size` gates stages 3/4/6 but *not* stage 7, whose minimum
  is a period), W2.9 deviation (2) restated for the transport
  (`reversible` is resolved, echoed and still changes nothing — a transport
  must document it as reserved until W3.4), byte-identical output between the
  auto and a matching pin over the whole corpus, 64 repeated rounds over the
  corpus byte-identical, the pathological-clock test, the buffer-reuse tests,
  and the pass-through/degrade tests. Verification: `cargo test --workspace`
  **371 green** (372 collected, the ignored golden generator),
  `cargo test --workspace --features strict_validate` **373 green**,
  `cargo fmt --all --check` clean, `cargo clippy --workspace --all-targets --
  -D warnings` clean in both feature states, `cargo check` on the excluded
  `fuzz/` crate clean, a default-feature release build inspected for the
  absence of the validator. No new dependency, no golden file and no
  DESIGN.md change.
  **Deviations from DESIGN: two, both recorded here rather than in
  DESIGN.md.** (1) **`§3`'s "422 only for an explicitly pinned `content_type`
  that the payload plainly contradicts" needs a decision §3 does not make: what
  "plainly contradicts" is for a pin that merely *disagrees* with the sniff.**
  The decision above (the sniff's own discriminators decide, with the
  `Chat`/`Messages` family treated as compatible in both directions and `Text`
  as never contradicting) is a reading, not a quote, and it is the reason a
  pin is allowed to change the output at all. (2) **`§4.1`'s `strict_validate`
  is a flag with no defined failure mode**: §4.1 says the feature runs "full
  parse" for "parse guarantees" and that malformed input "never [a 422] unless
  `content_type` was explicitly pinned", but it does not say what a *caller who
  asked for the guarantee* gets when the parse fails. This implementation
  answers: a typed `ApiError::Malformed` for an unpinned request (not a
  pass-through, and deliberately **not** a 422, which §3 reserves) and
  `ContentTypeMismatch` for a pinned one. §3, §4.1, §6.1, §6.2, §7, §8 and §9
  are otherwise implemented as written, and `reversible` stays deviation (2) of
  the W2.9 record.

- **W3.2 HTTP/axum** (§6.1) ∥ **W3.3 gRPC/tonic unary** (§6.2) ∥
  **W3.4 CCR store + Restore** (§9, flag-gated) — all parallel behind W3.1;
  W3.2 implements `X-Stats-*` naming verbatim.
  Status: **complete** (2026-09-27) for W3.2; **W3.3 and W3.4 are recorded
  below**. `crates/server` is now a lib plus a thin bin: `src/lib.rs`
  (router, handlers, error mapping, Prometheus counters),
  `src/options.rs` (query parser + option mapping, the only place a §6.1 option
  is spelled), `src/headers.rs` (`Stats` → `X-Stats-*`), `src/main.rs`
  (`axum::serve` on `QUANT_HTTP_ADDR`, default `127.0.0.1:8080`). Public
  surface: `app(State) -> Router`, `State::{new, default}`,
  `CCR_ENABLED`, `SPAN_PREVIEW_LIMIT = 64`. The transport only calls W3.1 —
  `Compressor::new`/`compress`, `api::reserve`, `Request`/`RawOptions`/`ApiError`,
  `ContentType::parse`, plus `config::REQUEST_BODY_LIMIT`, `config::resolve` and
  `locator::locate` for `/v1/detect`; `crates/core` and `crates/proto` are
  untouched.
  **Endpoints** (every status below is asserted in `tests/http.rs`):

  | Method | Path | Success | Failures |
  |---|---|---|---|
  | POST | `/v1/compress` | 200, spliced bytes verbatim, `X-Stats-*`, `Content-Type` echoed from the request (else `application/json`) | 400/413/422 |
  | POST | `/v1/compress?envelope=json` | 200, `{payload, stats}` as JSON, **no** `X-Stats-*` | 400/413/422 |
  | POST | `/v1/detect` | 200, `{schema, degraded, noop_reason, scope_policy, span_count, spans_truncated, spans[]}` | 400/413 |
  | POST | `/v1/restore` | — | 501 always in this build (see below) |
  | GET | `/healthz` `/readyz` | 200, `{"status":…}` | — |
  | GET | `/metrics` | 200, Prometheus text | — |

  **Header naming is §6.1 lines 559-567 verbatim.** The single-compress path
  emits `X-Stats-Bytes-In`, `-Bytes-Out`, `-Approx-Tokens-In`,
  `-Approx-Tokens-Out`, `-Groups-Collapsed`, `-Exact-Runs`, `-Ws-Runs`,
  `-Block-Repeats`, `-Template-Groups`, `-Templated-Blocks`, `-Record-Splits`,
  `-Degraded` (`true`/`false`), `-Noop-Reason` (only when
  `Stats.noop_reason` is `Some`, i.e. **absent value ⇒ absent header**) and
  `-Algo-Version`; `the_stats_header_names_are_verbatim_and_the_values_are_exact`
  asserts the served set is exactly those names, that each is reachable under the
  normative Camel-Case spelling, and that every value equals the `Stats` field.
  They are *stored* lowercase because `http::HeaderName` rejects any other case
  (`from_static` panics on `X-Stats-…`, and HTTP/2 requires lowercase anyway), so
  the `http_body_util`-served wire form is the lowercase rendering; §6.1 itself
  says "names are case-insensitive (RFC 9110)", and
  `the_header_names_are_case_insensitive` pins that `X-Stats-Bytes-In`,
  `x-stats-bytes-in` and `X-STATS-BYTES-IN` all resolve. **Timings,
  `options_echo` and `restore_ids` never become headers** — they are
  envelope-only, asserted both by the exact-name-set assertion and by
  `envelope_only_never_reach_the_single_compress_headers`, which additionally
  rejects any header whose name contains `timing`/`elapsed`/`options`/`echo`/
  `restore`. The envelope path carries no `X-Stats-*` at all.
  **Options** come from the query on the bare path and from the JSON envelope on
  `?envelope=json`, and are mapped onto `RawOptions` so that `config::resolve`
  does the validating: `scope_policy`, `min_group_size` (int ≥ 2), `normalize_ws`,
  `template_dedup`, `reversible` are `true`/`false` only, `marker_style` is
  `auto|ascii|unicode`, all with the §6.1/§7 defaults. The query parser is
  hand-rolled (percent- and `+`-decoding, first key wins, deterministic
  iteration, no `HashMap`/`RandomState` anywhere on the path), and it is
  **strict**: an unknown key, a garbage value, a reserved `scope_policy`
  (`all_messages`, `explicit_paths` — parsed through so `resolve` refuses it) and
  `min_group_size=1` are all 400 with a message that names the parameter
  (`every_invalid_option_is_a_400`, 13 cases). Booleans accept only `true`/
  `false`, not `1`/`0`. `envelope=json` accepts **only** `envelope` in the query —
  an option there is a 400 telling the caller it belongs in the body — and any
  other `envelope` value is a 400.
  **Error mapping** (§3): `ApiError::ContentTypeMismatch` is the *only* 422,
  reachable only through an explicit `content_type` pin (query `content_type=` or
  the envelope's `content_type`, one of `chat|responses|messages|text`); every
  other outcome of a compress call is a 200 pass-through with stats. `ApiError::
  Options` ⇒ 400 `invalid_options`, `ApiError::Malformed` ⇒ 400 `malformed`
  (only reachable in a `strict_validate` build), query/envelope faults ⇒ 400
  `invalid_argument`; a body over `request_body_limit` ⇒ **413** from axum's
  `DefaultBodyLimit::max(config::REQUEST_BODY_LIMIT)`, a real transport guard
  (a 64 MiB + 1 body is 413 on all three POST routes, and a 3 MiB body is served,
  proving axum's 2 MiB default was replaced); `/v1/restore` ⇒ 501. The only 5xx
  is a panicking `spawn_blocking` task (`internal_error`), which is a server bug,
  not a compression outcome.
  **Core purity.** The compression runs inside `tokio::task::spawn_blocking`
  (so a 64 MiB body never occupies an async worker) and touches nothing but
  W3.1: output bytes cannot depend on tokio, the wall clock or the thread count.
  The `elapsed_*` fields come from W3.1's `Clock` seam — `Compressor::new()`
  installs `MonotonicClock` — and tokio is used only to schedule. A fresh
  `Compressor` and a fresh `Vec` pre-sized with `api::reserve` are built per
  request; see deviation (1).
  **`/v1/restore` is flag-gated and stores nothing.** The cargo feature `ccr` is
  off by default and `CCR_ENABLED` is `cfg!(feature = "ccr")`; both feature
  states answer 501 `not_implemented` (the message says "disabled" vs "not
  implemented yet"), because §9's store is W3.4's and this wave invents none. The
  same store's absence is what makes `reversible=true` a 400
  `invalid_options` rather than a silent no-op: the option is parsed and then
  refused by the core, so it changes no output byte, is never echoed as `true`,
  and there is no `restore_ids` to return
  (`reversible_true_is_refused_and_reversible_false_resolves`).
  **`/v1/detect`** is the §6.1 debugging aid: `locator::locate` with the
  `scope_policy` option (`scope_policy` is its only accepted query key; a
  reserved policy is a 400), reporting the sniffed schema, the degradation and
  the first `SPAN_PREVIEW_LIMIT = 64` eligible spans as
  `{start, end, class}` **absolute byte offsets**, plus `span_count` and
  `spans_truncated` so a truncated preview can never be read as the whole set.
  §13.3's per-span savings stays open — the span preview is the answer for now.
  **Metrics** are four Prometheus families, hand-rendered, deterministic order
  (`BTreeMap` keyed by route and status, §5.2):
  `quantification_http_requests_total{route,status}`,
  `quantification_payload_bytes_total{direction}`, `quantification_pass_through_total`
  and `quantification_build_info{algo_version,ccr}`. `/healthz`, `/readyz` and
  `/metrics` are not themselves counted, so a scrape cannot move a counter.
  Tests: **11 unit** (9 in `options.rs` for the parser/envelope mapping, 2 in
  `lib.rs` for the Prometheus rendering and for serving after the metrics mutex
  is poisoned — §12's "poisoned buffers" spirit, since a per-request output
  buffer leaves no state to poison) and **25 integration** in
  `crates/server/tests/http.rs`. The integration suite drives the real router
  (`tower::ServiceExt::oneshot`, so routing, extractors, the body limit and the
  response are all live) and, in
  `the_wire_format_is_a_real_http_response`, a real server on an ephemeral port
  over a raw `tokio::net::TcpStream`, asserting the `HTTP/1.1 200 OK` status
  line, the `x-stats-*` header lines as hyper writes them and the body. It also
  pins byte-identity with the core (the bare body **is** `compress`'s output and
  the envelope's `payload` is the same bytes), every detector through its
  option, both scope policies on a `tool_result` payload, pass-through +
  `X-Stats-Noop-Reason` for `unknown_schema` and `malformed`, the 400/413/422
  paths, `restore`'s 501, the envelope's 18 stats fields and exact
  `options_echo`, the span preview and its truncation, and that eight identical
  requests answer with byte-identical status, headers **and** body (no timing
  leaks into a header). Workspace total 371 → **407** (36 server tests);
  `cargo test --workspace` **407 green** (408 collected, the one `#[ignore]`d
  golden generator), **409** with `--features quantification-core/strict_validate`
  (the malformed-document test asserts the strict build's 400 there), 36 green
  with `--features ccr`. `cargo fmt --all --check` clean and
  `cargo clippy --workspace --all-targets -- -D warnings` clean in the default,
  `strict_validate` and `ccr` states. Dependencies added: `axum` 0.8 (default
  features), `tokio` 1 (`macros`, `net`, `rt-multi-thread`; `io-util` for the
  test), `serde` 1 + `serde_json` 1, and `tower` 0.5 (`util`) as a dev-dependency
  — `Cargo.lock` therefore gained 7 entries (`serde`, `serde_json`,
  `serde_path_to_error`, `serde_urlencoded`, `form_urlencoded`, `ryu`, `zmij`),
  all MIT / MIT-OR-Apache-2.0 / Apache-2.0-OR-BSL-1.0, so no `deny.toml` change
  is needed; axum, tokio, hyper, http and tower were already in the graph via
  tonic. `deny.toml` itself is untouched.
  **Deviations from DESIGN: three, recorded here rather than in DESIGN.md.**
  (1) **One `Compressor` per request, not per stream.** W3.1 notes that "one
  `Compressor` plus one reserved `Vec<u8>` serves a whole request stream with no
  per-call output allocation", but `api::Compressor` holds
  `Box<dyn Clock + 'static>` (W3.1's injectable seam), which is **not `Send`**,
  so it cannot live in an `Arc<Mutex<…>>` shared state — axum requires
  `State: Send + Sync`. Each request therefore builds its `Compressor` inside its
  `spawn_blocking` task, which keeps the state `Send` and the core untouched; the
  per-request output buffer is still pre-sized with `api::reserve`, so the splice
  still performs a single allocation. Nothing about the output bytes changes, and
  §5.5 (no thread-count influence on output) is satisfied trivially. Making the
  seam `Send` would be a `crates/core` change (W3.1's owner), and is the obvious
  follow-up if per-stream buffer reuse is ever worth measuring.
  (2) **`content_type` is a transport-level addition.** §6.1's HTTP table and
  options table never mention a content-type parameter, yet §3 reserves the 422
  for a caller who "explicitly pins `content_type`" — so the transport must
  expose one. It is an optional `content_type` query parameter (bare path) and
  an optional `content_type` envelope field, accepting exactly the four schema
  names of W3.1's `ContentType::parse`; absent means auto. The *decision* of when
  a pin contradicts a payload is W3.1's, untouched.
  (3) **The envelope's `payload` is a JSON string.** §6.1 says
  `{payload, options} → {payload, stats}` without saying how bytes are carried,
  and a JSON *value* would have to be re-serialized, which §4.5 forbids
  ("no JSON reserialization") and which would break R3's "output = input except
  spliced ranges" for untouched bytes. `payload` is therefore a string in and a
  string out — the exact bytes the core produced, JSON-escaped once by
  `serde_json` — and a non-string `payload` is a 400 with a message that says so.
  The bare path carries raw bytes in both directions and is unaffected. Two
  smaller readings are frozen alongside it, both unpinned by §6.1: the
  single-compress response echoes the request's `Content-Type` (falling back to
  `application/json`), because the output is the input's bytes outside the
  spliced ranges; and a non-UTF-8 payload is reachable only on the bare path.
  DESIGN.md §6.1 should be amended to state both, and to state that
  `?envelope=json` and the bare path are the only two shapes. §3, §4.5, §6.1's
  endpoint table, §6.1's options table, §6.1's header naming, §7's
  `request_body_limit` and §9's flag-gating are otherwise implemented as
  written, and gRPC was W3.3's, now below, with the CCR store still W3.4's.

- **W3.3 gRPC/tonic unary** (§6.2) — the `compressor.v1.Compressor` service
  beside W3.2's HTTP transport, unary only.
  Status: **complete** (2026-09-27). One new source file,
  `crates/server/src/grpc.rs`, plus its suite in
  `crates/server/tests/grpc.rs`; the only lines added to W3.2's files are
  `pub mod grpc;` in `src/lib.rs` and a second listener in `src/main.rs`
  (`QUANT_GRPC_ADDR`, default `127.0.0.1:50051`, served with
  `tonic::transport::Server`), and one match arm in `src/options.rs`
  `resolve_message` (see the last paragraph). No route, header name, option
  spelling or public name of W3.2 changed. `crates/core` and `crates/proto` are
  untouched; the service calls only W3.1 and uses W1.6's
  `convert::{to_raw_options}` and enum conversions as they stand.
  **Public surface:** `grpc::Service::{new, with_store}`, `grpc::RestoreStore`
  (the W3.4 seam), `grpc::server(Service) -> CompressorServer<Service>`
  (limits applied, for `tonic::transport::Server`), `grpc::routes(Service) ->
  tonic::service::Routes` (in-process serving, what the tests drive), and W3.2's
  `CCR_ENABLED` is reused rather than re-spelled.
  **RPC surface — exactly the two §6.2 methods, both unary:**

  | Method | Path | Success | Failures |
  |---|---|---|---|
  | `Compress` | `/compressor.v1.Compressor/Compress` | `CompressResponse{payload, stats}`, payload = the core's bytes verbatim | `InvalidArgument` (3, 400/422 analogue), `OutOfRange` (11) over `request_body_limit`, `Internal` (13) if the blocking task dies |
  | `Restore` | `/compressor.v1.Compressor/Restore` | `RestoreResponse{original}` only with a wired store under `--features ccr` | `Unimplemented` (12) always in the default build, `NotFound` (5) on a store miss |

  **Status-code mapping** (§3, §6.2). gRPC has no 422 and no error-code field,
  so `ApiError::as_str()` is prefixed onto every message and the HTTP status
  becomes `InvalidArgument`: `ApiError::Options` ⇒
  `invalid_options: <W3.2's resolve_message>` (so `min_group_size=1` reads
  `invalid_options: min_group_size=1 is below the minimum of 2` and a reserved
  `scope_policy` reads `… is reserved`), `ApiError::Malformed` ⇒ `malformed:
  …` (only reachable in a `strict_validate` build), and
  `ApiError::ContentTypeMismatch` ⇒ the core's own
  `content_type_mismatch: pinned <pinned> but the payload sniffs as <sniffed>`,
  which is the **only** way an `InvalidArgument` carries §3's reserved meaning
  and is reachable **only** through an explicit `content_type` pin; an unpinned
  unknown schema, a malformed document and a `Text` pin are all a 200-status
  `CompressResponse` with the payload passed through and
  `degraded=true`/`noop_reason` set. An out-of-range enum value on the wire
  (`content_type`, `scope_policy`, `marker_style`) is `InvalidArgument` with
  `invalid_argument: <field>=<value> is not a value of its compressor.v1 enum`,
  because W3.2 answers HTTP's garbage option value with a 400 and parity is the
  point; W1.6's `to_raw_options` would silently default it, so the three
  discriminants are checked before it is called (the file is not modified).
  A message over `request_body_limit` is refused by tonic's own length guard
  before the body is buffered — `max_decoding_message_size(config::REQUEST_BODY_LIMIT)`
  on the generated server — and surfaces as `OutOfRange` with
  `Error, decoded message length too large: found … the limit is: 67108864 bytes`,
  which is tonic's code for that check (the HTTP transport's 413 analogue);
  tonic's 4 MiB default is replaced, so a 5 MiB payload is served.
  **`Stats`** is filled field by field in §6.2's wire order (1…19):
  `bytes_in`/`bytes_out` (the latter also the response length),
  `approx_tokens_in`/`approx_tokens_out` (bytes/4), the five detector counters,
  `templated_blocks`, `record_splits`, `degraded`, `noop_reason`
  (`""` when compressed, `"unknown_schema"`/`"malformed"` on a pass-through),
  the three `elapsed_*_ns`, `algo_version` (`ALGO_VERSION`) and `options_echo`
  (W3.1's canonical string, field order untouched, never reformatted).
  **§6.2 field 19 `restore_ids` is always empty**: §9's store is W3.4's, v1
  compression stores nothing, so a compress answer never reports an id
  (asserted in every stats assertion). `Restore` is feature-gated exactly like
  W3.2's `/v1/restore`: with the `ccr` feature off it answers `Unimplemented`
  with W3.2's "disabled in this build" message; with it on and no store wired
  it answers `Unimplemented` with the "not implemented yet" message; a wired
  store is consulted through `RestoreStore::restore_verified(&str) ->
  Option<Vec<u8>>`, whose `None` (a miss, i.e. §9's length+hash re-verification
   failing) is `NotFound`. No store behaviour is invented here — the trait is an
   interface with no implementation in the tree, and W3.4 plugs one in without
   touching this file. **(W3.4, 2026-09-27: the field is no longer always empty —
   see the W3.4 record below. It did touch this file, for two reasons W3.3 could
   not foresee: the seam had to become shared with the HTTP transport, so
   `RestoreStore` moved to `src/lib.rs` with a `pub use` here (the name
   `grpc::RestoreStore` still resolves), and its `restore_verified` now takes the
   caller's compressed payload, which §9's cheap pre-check needs. No status
   code, no path and no method name of §6.2 changed.)**
  **Option semantics are W3.2's**, because W1.6's `optional bool` restores
  presence: an absent `options` message and an absent `normalize_ws` resolve to
  the §7 default `true` (echo
  `{"scope_policy":"user_content","min_group_size":3,"normalize_ws":true,"template_dedup":true,"marker_style":"auto","reversible":false}`),
  an explicit `false` stays `false` and changes the output, `min_group_size=0`
  is the default 3, and `content_type=AUTO` is the auto sniff. The proto enum
  names are W1.6's (`MARKER_STYLE_*`, `CONTENT_TYPE_*`), a deviation this wave
  inherits unchanged.
  **Core purity.** The compression runs inside `tokio::task::spawn_blocking`,
  and the non-`Send` seam is solved exactly as W3.2 solved it: W3.1's
  `api::Compressor` holds `Box<dyn Clock + 'static>`, which is not `Send`, so it
  cannot live in the `Arc`-shared service state tonic requires; a fresh
  `Compressor::new()` (i.e. `MonotonicClock`) and a fresh `Vec` pre-sized with
  `api::reserve` are built **inside** the blocking closure, so the non-`Send`
  value never crosses a task boundary and the `elapsed_*` fields are the only
  thing tokio can influence. Output bytes cannot depend on tokio, the wall
  clock or the thread count (§5.5); the same `Arc<dyn Clock>`-in-`Service`
  reason also means **no gRPC metrics** — W3.2's four Prometheus families count
  only HTTP, and a fifth family would have had to change W3.2's renderer and
  its test.
  **No streaming, asserted two ways** (§5.6): `the_proto_declares_no_streaming_rpc`
  token-scans `quantification_proto::COMPRESSOR_PROTO` (no `stream` token
  anywhere; exactly the two `rpc` lines of §6.2), and
  `the_service_exposes_two_unary_methods_and_no_streaming_ones` posts raw
  requests to the routing tree: `Compress`/`Restore` are routed (they answer
  something other than `Unimplemented`), while `CompressStream`,
  `CompressBidiStream`, `CompressServerStream`, `CompressChunked`,
  `StreamCompress`, `Subscribe` and `Watch` are not methods of the service at
  all (`grpc-status: 12` with no message, i.e. the generated server's default
  arm).
  **HTTP/gRPC parity is the headline test.**
  `http_and_grpc_answer_with_identical_bytes_and_stats` drives a 15-case table
  (every detector, both scope policies, both marker styles, `min_group_size`,
  a `responses` and a `text` pin, an unknown schema, a malformed document) and
  asserts for each case that the bare HTTP body, the `?envelope=json` payload
  and the gRPC `CompressResponse.payload` are the **same bytes**, that the
  bytes are the core's own output, and that the 13 non-timing `Stats` fields
  plus `options_echo` are equal to the envelope's.
  `every_case_answers_the_core_bytes_and_a_full_stats_message` then asserts the
  full message field by field against the core's `Stats`, and
  `reversible_true_is_refused_by_both_transports_and_false_resolves` asserts
  that `reversible=true` is `InvalidArgument` on gRPC and 400 `invalid_options`
  on HTTP (both naming the option) while `reversible=false` resolves, echoes
  `false` and returns no `restore_ids`.
  Also asserted: every option's effect on the output, the wire round trip of
  `optional bool`, the pinned-contradiction vs matching-pin split, the
  unknown-enum and reserved-option `InvalidArgument`s, `Unimplemented` `Restore`
  in both feature states, the real limit paths, eight repeated identical
  requests encoding to **byte-identical** `CompressResponse`s once the three
  `elapsed_*` fields are zeroed (they are the only non-deterministic bytes, and
  §5 forbids them from touching anything else), and a real HTTP/2 round trip
  over a `TcpListener` for the serving path `main.rs` uses.
  Tests: **9 unit** in `grpc.rs` (the content-type mapping, the status table,
  the `Stats` mapping, the degraded reason, the option presence mapping, the
  unknown-enum refusals, the `ccr` gate, the service name, the proto token
  scan) and **15 integration** in `crates/server/tests/grpc.rs`; 24 new tests
  in total, 20 of them unit-plus-integration green in the default, `ccr` and
  `strict_validate` feature states (`cargo test -p quantification-server`).
  Dependencies added to `crates/server`: `tonic` 0.14 (MIT) and, for the tests,
  `prost` 0.14 (Apache-2.0) — plus `quantification-proto` by path; all four
  were already in the graph through W1.6, so `Cargo.lock` gained no package,
  only the server's own dependency edges, and `deny.toml` needed no change.
  **Deviations from DESIGN: two, recorded here rather than in DESIGN.md.**
  (1) **The gRPC error discriminator is the message, not a code field.** gRPC
  statuses cannot carry §6.1's `error.code`, so the transport prefixes
  `ApiError::as_str()` (`invalid_options`, `malformed`,
  `content_type_mismatch`, `invalid_argument`) onto the message text; a client
  that wants a stable discriminator must match the prefix. §6.2 pins no error
  shape at all, so this is a reading, and DESIGN.md §6.2 should state it next to
  the status table. (2) **Three additions to W3.2's files, all forced.** W3.2's
  `src/lib.rs` needed `pub mod grpc;` (the module is otherwise unreachable) and
  `src/main.rs` a second listener (a transport the binary cannot serve is not a
  transport), both purely additive with no existing line removed or reordered —
  the same shape as W3.1's and W2.9's one-line `pub mod` additions. The third is
  not mine in spirit: the concurrent `crates/core` work added
  `ResolveError::UnsupportedReversible`, which made W3.2's `options.rs`
  `resolve_message` non-exhaustive and left **the whole crate uncompilable**, so
  this wave added the missing arm ("reversible=true is not accepted; the
  reversible store (DESIGN section 9) is not implemented yet") and both
  transports report it identically. Two pre-existing tests encoded the old
  contract and were left failing by that core change; both are re-pointed at the
  new one by the W3 fix wave recorded below. §3's degradation policy, §4.5's
  marker/Stats set, §5's determinism, §6.1's option semantics, §6.2's service
  shape, §6.2's `Stats` message and §7's `request_body_limit` are implemented
  as written.

- **W3 fix wave — the two tests that encoded the pre-`UnsupportedReversible`
  contract** (2026-09-27). No behaviour changed: the core still refuses
  `reversible=true` with `ResolveError::UnsupportedReversible` (400
  `invalid_options` on HTTP, `InvalidArgument` on gRPC), and `reversible=false`
  or absent still resolves to the §7 default.
  - `crates/proto`: `convert::tests::explicit_false_survives_wire_and_resolves_false`
    asserted, as a side effect of its fixture, that `reversible: Some(true)`
    resolves. Its subject is proto3 `optional bool` **presence** for the
    default-true options, so the fixture now sets `reversible` absent and keeps
    the presence assertions (`normalize_ws`/`template_dedup` are `Some(false)`
    after the wire round trip and resolve `false`; the encoded bytes differ from
    `Options::default()`, which is what makes absent ≠ explicit false), and the
    test is renamed
    `explicit_false_presence_survives_the_wire_and_resolves_false`. A separate
    `reversible_true_is_refused_and_absent_or_false_resolves` pins the new
    contract: `Some(true)` survives the wire and then resolves to
    `Err(UnsupportedReversible)`, while absent and `Some(false)` resolve `false`.
  - `crates/server/tests/http.rs`: `reversible_is_accepted_and_reserved`
    (renamed `reversible_true_is_refused_and_reversible_false_resolves`) now
    asserts the query and envelope paths both answer 400 `invalid_options` with
    a message naming the option and no `stats` at all, that `reversible=false`
    is byte-identical to the default answer, and that its `options_echo` ends
    `"reversible":false}` with no `restore_ids`.
  - `crates/server/tests/grpc.rs`:
    `the_reversible_option_is_decided_the_same_way_by_both_transports` accepted
    either outcome ("that option's fate belongs to W3.4"), so its accepting
    branch had become dead code. Renamed
    `reversible_true_is_refused_by_both_transports_and_false_resolves`, it now
    pins the refusal on both transports and the `false` round trip. The
    rationale for refusing rather than echoing: §6.2 field 19 promises
    `restore_ids` iff `reversible=true` and §9's store does not exist, so
    echoing `true` beside an empty list is an affirmative false promise to a
    machine client.
  - `crates/server/src/lib.rs`: the two `/v1/restore` 501 messages said
    "reversible=true is resolved and echoed but stores nothing", which the core
    change made false; they now say the option is refused, so no span has a
    `restore_id`. Message text only — no status, code or gate changed.
  - Verification: `cargo test --workspace` **441 green** (442 collected, the
    one `#[ignore]`d golden generator), **443** with
    `--features quantification-core/strict_validate`, 60 green with
    `-p quantification-server --features ccr`; `cargo fmt --all --check` clean
    and `cargo clippy --workspace --all-targets -- -D warnings` clean in the
    default, `all-features` and `strict_validate` states. W3.3's reported
    `too_many_arguments` in `crates/core/src/detect/blocks.rs` no longer
    reproduces: `windowed_blocks` takes six parameters because 99fc0f7 already
    grouped the closure/domain arguments into `Domain`, so no `#[allow]` was
    needed.

- **W3.4 CCR store + Restore** (§9, flag-gated) — the reversible store,
  `/v1/restore`, gRPC `Restore` and `Stats.restore_ids`; the wave that makes
  `reversible=true` honest.
  Status: **complete** (2026-09-27). Three new files —
  `crates/core/src/ccr.rs` (the store), `crates/core/tests/ccr.rs` (13 tests) and
  `crates/server/tests/restore.rs` (6 tests) — and the minimum wiring: one new
  line in `crates/core/src/lib.rs` (`pub mod ccr;`), `pipeline.rs`
  (`Stats.restore_ids`, the sink field, `set_sink`, the private `reversals`
  walk), `api.rs` (`with_sink`), `render.rs` (`checksum_hex`, factored out of
  the existing `write_checksum`), `config.rs` (the flip), the two guard tests
  that enumerate the `api` surface, `crates/proto/src/convert.rs` (one test
  re-pointed), and `crates/server/src/{lib,grpc,options,main}.rs` plus the two
  transport test files. No new dependency, no golden re-baseline, no DESIGN.md
  change.
  **The store** (`quantification_core::ccr`) is content-addressed, TTL-bounded
  and feature-agnostic — the gate lives in the transports, exactly where W3.2
  and W3.3 put it:

  ```rust
  pub const DEFAULT_TTL_NS: u64 = 900 * 1_000_000_000;   // 15 minutes
  pub const DEFAULT_MAX_BYTES: usize = 67_108_864;       // 64 MiB

  pub struct RestoreId { pub hash: u128, pub len: usize }
  impl RestoreId {
      pub fn of(original: &[u8]) -> Self;                 // xxh3-128 + byte length
      pub fn parse(id: &str) -> Option<Self>;             // strict, canonical only
  }
  impl std::fmt::Display for RestoreId                   // lower-hex(len) form

  pub trait Sink {                                       // the write side
      fn store(&mut self, original: &[u8], marker: &[u8], checksum: [u8; 4])
          -> Option<RestoreId>;
  }

  pub struct Store { /* clock, ttl_ns, max_bytes, bytes, entries */ }
  impl Store {
      pub fn new(ttl_ns: u64, max_bytes: usize) -> Self;
      pub fn with_clock(clock: impl Clock + Send + Sync + 'static,
                        ttl_ns: u64, max_bytes: usize) -> Self;
      pub fn insert(&mut self, id: RestoreId, original: Vec<u8>,
                    marker: Vec<u8>, checksum: [u8; 4]) -> bool;
      pub fn restore(&self, payload: Option<&[u8]>, id: &str) -> Option<Vec<u8>>;
      pub fn len(&self) -> usize; pub fn is_empty(&self) -> bool;
      pub fn bytes(&self) -> usize;
  }

  #[derive(Clone)] pub struct Shared { /* Arc<Mutex<Store>> */ }
  // Shared::{new, with_clock, insert, put, restore, len, is_empty, bytes} + Default
  ```
  **The id is §9's normative format, exactly**:
  `lower-hex(xxh3-128(original_span_bytes)) + ":" + decimal(byte_length)` — 32
  lowercase hex characters, one colon, a canonical decimal (no leading zeros, so
  it round-trips), and `RestoreId::of(bytes).to_string() == id` for every input.
  Nothing time-derived, no process id, no counter, no sequence number: the same
  original always yields the same id, in any process, at any time, which is what
  makes the store content-addressed and the ids safe to cache client-side.
  **"original span bytes" is read as the §4.4 removal-rule range of the committed
  group** — the exact range §4.4 says "the marker replaces exactly that range",
  i.e. the union of the member ranges plus the joiners between them. That is the
  only reading under which `restore` reproduces the input byte for byte
  (`restore_is_the_identity_over_the_corpus` is the proof), and the anchor is
  that range's prefix, so the id's byte length is a length a caller can check
  against the marker it sees. `id = <hex>:<removed range length>`, never the
  anchor's.
  **Nothing may return wrong bytes.** `restore` is a five-step ladder and any
  step that fails is a **miss** (`None` ⇒ HTTP 404 `not_found` / gRPC
  `NotFound`), never a guess:
  1. `RestoreId::parse` — a malformed id (wrong hex width, uppercase, a second
     colon, a non-canonical length, trailing bytes, garbage) is a miss;
  2. the entry must exist and must not be past its TTL;
  3. **the cheap pre-check**, only when the caller supplied a compressed payload
     and it is non-empty: the marker's 4-hex `CCCC` must occur in it, and the
     exact marker bytes the core rendered for that group must occur in it. §9
     and §4.5 are explicit that `CCCC` is "a cheap pre-check only — never the
     storage key", and it is used only here: the key is always the 128-bit hash
     plus the length;
  4. **re-verification, §9's requirement**: `entry.original.len() == id.len`;
  5. `fingerprint(&entry.original) == id.hash`.
  The key and the bytes are stored in *separate* fields precisely so that step 5
  can catch an entry whose bytes no longer hash to their key
  (`a_mutated_entry_is_caught_by_re_verification` mutates the stored `Vec` in
  place), and so that an entry filed under a valid id with different bytes is a
  miss rather than a restoration (`an_entry_whose_bytes_disagree_with_its_key_is_a_miss`).
  **A collision can never overwrite a live entry**: `insert` refuses (and
  reports no id) when an entry with that id holds different bytes, so a
  hypothetical xxh3-128 collision costs the second group its id instead of
  handing the first group's caller the wrong original
  (`a_collision_never_replaces_a_live_entry`).
  **The clock is a seam, never a sleep.** `Store`/`Shared` take
  `impl Clock + Send + Sync` (W2.9's `pipeline::Clock`, the same trait the
  elapsed stats read), defaulting to `MonotonicClock`; `Send + Sync` is what
  makes the store storable in an `Arc<Mutex<…>>` and therefore shareable by
  axum/tonic state, and the tests inject an `AtomicU64` clock they move by hand,
  so TTL expiry is asserted without a wall clock and without flakiness
  (`the_ttl_and_the_byte_bound_are_injected_not_slept`). The core still reads no
  clock of its own on the output path: `reversals` runs *after* the fourth
  `now_ns()` read, so the three `elapsed_*` fields are byte-identical whether
  `reversible` is true or false.
  **The ids come from `commits()`, in marker output order.** `pipeline::run`
  walks the merged commit list — which W2.9 froze as ascending by anchor byte
  offset and which is the order `splice_into` renders markers in — and for each
  commit hands the sink `(payload[commit.removed], the rendered marker,
  checksum_hex(marker_checksum(anchor)))`. One id per committed group, in the
  order the markers appear in the output: `one_id_per_committed_group_in_marker_output_order`
  compares the reported ids against the ids derived from `commits()` element by
  element, and because a permutation would misplace the bytes, the §12 identity
  property is itself the order proof.
  **The one hook in the core, and why it had to be there.** The store must be
  fed from *inside* the splice, because the removed ranges exist nowhere else,
  and the transports must not reach around W3.1's `api`. So the sink is a
  builder beside `with_clock` —
  `api::Compressor::with_sink(mut self, sink: impl Sink + 'static) -> Self`
  delegating to a new `pipeline::Compressor::set_sink(Box<dyn Sink>)` — which is
  why `crates/core/tests/api.rs`'s two enumerating guards moved with it:
  `the_public_surface_is_exactly_the_documented_items` now expects 23 items
  (`Sink`, `with_sink`) instead of 21, and
  `no_public_signature_exposes_an_internal_type` counts 8 public functions and
  allows `sink` as a parameter name and `Sink` as a signature type. `Sink` is a
  *public* type in a new public module, not one of the internals those guards
  exist to keep out of the signature. W3.1's api record asked for exactly this
  ("any addition breaks the test and must be recorded here"); nothing else in
  `api.rs` changed, it still reads no clock of its own and still carries no
  comment.
  **`reversible=true` is re-admitted.** `config::resolve` no longer refuses
  `Some(true)` and `ResolveError::UnsupportedReversible` is **deleted** (a
  never-constructed variant plus a message that can no longer be sent is a trap,
  so W3.2's `resolve_message` lost its arm too — the same forced, purely
  mechanical edit W3.3 recorded for the same reason). Every test that pinned the
  refusal now asserts the honoured behaviour instead of being deleted:
  `config.rs::reversible_true_and_false_both_resolve`,
  `tests/pipeline.rs::reversible_true_resolves_and_without_a_sink_reports_no_id`
  (also asserts the output bytes and the commit list are identical either way),
  `tests/api.rs::reversible_true_resolves_echoes_true_and_changes_no_output_byte`
  plus a new `a_wired_sink_receives_the_committed_range_of_every_group`,
  `crates/proto/src/convert.rs::reversible_true_absent_or_false_all_resolve`,
  `tests/http.rs::reversible_true_resolves_and_false_resolves` and
  `tests/grpc.rs::reversible_true_is_honoured_by_both_transports_and_false_resolves`
  (both assert the ids, their exact format, and that the two transports report
  the same ids for the same bytes).
  **Both transports, one seam.** W3.3's `RestoreStore` is now the seam for both:
  it moved to `crates/server/src/lib.rs` (`grpc::RestoreStore` is a `pub use`
  re-export, so the name W3.3 froze still resolves) and grew the write half,
  `store_committed(&self, original, marker, checksum) -> Option<ccr::RestoreId>`,
  defaulting to `None` so a read-only fake still compiles.
  `impl RestoreStore for ccr::Shared` is the one implementation, and
  `pub(crate) SinkHandle(Arc<dyn RestoreStore>)` adapts it to the core's
  `&mut self` sink trait. `State` grew `with_store`/`without_store`/`store`, and
  `grpc::Service::new()`/`State::new()` now wire `shared_store()` — a real
  `ccr::Shared` when the `ccr` feature is on, `None` when it is off — while
  `with_store` stays the injection point W3.3 froze. `main.rs` builds **one**
  store and hands it to both listeners, so a compress over HTTP is restorable
  over gRPC.

  | Transport | Success | Failures |
  |---|---|---|
  | `POST /v1/restore?restore_id=<id>` (raw compressed body) | 200, the original bytes, `Content-Type: application/octet-stream` | 400 `invalid_argument` (no `restore_id`, an unknown query key), 404 `not_found` (a miss: unknown, expired, evicted, malformed or mismatched id; a payload that is not the one the id came from), 413, 501 `not_implemented` (feature off, or no store wired) |
  | `POST /v1/restore?envelope=json` (`{payload, restore_id}`) | 200, identical bytes | same, plus 400 for a broken envelope |
  | gRPC `Restore` | `RestoreResponse{original}`, byte-identical to the HTTP body | `NotFound` on a miss, `Unimplemented` when the feature is off or no store is wired |

  §6.1 pins neither the request nor the response shape of `/v1/restore`
  ("compressed + id → original"), so both are readings, frozen here: the
  **bare** form carries the compressed bytes as the body and the id in the query
  (the bare compress path already carries arbitrary bytes — W3.2's deviation (3)
  notes a non-UTF-8 payload is reachable there — so nothing is lost and no
  escaping is invented), the **`envelope=json`** form mirrors §6.2's
  `RestoreRequest` field for field and is the shape a polyglot client already
  speaks, and the response is raw bytes labelled `application/octet-stream`
  because a restored original is a fragment of a JSON string interior (escaped
  bytes), not a document. Both compress shapes store (the bare path's ids are
  simply not reported, since §6.1 forbids a `restore_ids` header), so a repeated
  compress of the same payload refreshes the same content-addressed entry
  (`both_compress_shapes_store_the_same_originals`).
  **The properties, and where they are asserted.** `restore(reversible) ==
  identity` is the headline: over all 26 corpus fixtures and 11 generated shapes
  (log bursts of 3–33 rows, a repeated block, a stage-1b single-line record
  dump, a unicode span, two messages with a run each), the compressed output
  with **every** reported id substituted back reproduces the input byte for
  byte, and `restore_ids.len() == groups_collapsed` in every case — the harness
  rebuilds the payload from the output, the commits and the ids alone, with no
  access to the store's internals. The rest: the id format and its round trip
  (`the_ids_are_the_normative_format_and_parse_back`), tampered ids
  (wrong hash, wrong length, truncated, uppercase, two colons, trailing byte,
  garbage, an id from another payload) as misses on both transports
  (`a_tampered_id_is_a_miss_never_wrong_bytes`,
  `a_tampered_id_is_a_miss_on_both_transports`), the corrupted-entry and
  collision cases above, **the marker checksum is demonstrably not the key**
  (`the_marker_checksum_is_not_the_storage_key` constructs the pair: it searches
  4096 candidate anchors for two whose `xxh3-64` low 16 bits agree, puts both
  in one payload, and asserts that both markers carry the *same* four hex digits
  while the two ids differ, the store holds two entries, and each restores its
  own original), the injected TTL and byte bound
  (`the_bound_and_the_ttl_decide_which_restores_succeed_and_nothing_else`:
  a 1-byte store and a zero-TTL store report **no** ids and change **no** output
  byte, and the roomy store still restores), one shared original across two
  groups (`a_shared_original_is_one_entry_and_two_ids`), the forced marker
  styles, the degenerate payloads, and the parity of both transports
  (`http_and_grpc_restore_the_same_original_for_the_same_id` compresses once per
  transport over separate store instances, asserts the same bytes and the same
  ids, then restores every id through gRPC, through the bare HTTP form and
  through the HTTP envelope and gets the same original three times).
  **R1 holds**: `reversible_changes_no_output_byte` diffs the corpus three ways
  (`true` with a store, `false` with a store, `true` with no store) and
  `reversible_true_resolves_and_without_a_sink_reports_no_id` pins it at the
  pipeline; the 12 chat goldens, the 64-round determinism loops and the
  idempotence property tests are unchanged, and the elapsed fields are read
  before the sink ever runs.
  **Feature states.** With `--features ccr` the option resolves, originals are
  stored, `restore_ids` is populated and restore answers 200/404. Without it
  the option *still* resolves and echoes `true` (the core is not feature-gated),
  but no store is wired, so nothing is stored, `restore_ids` is `[]` and restore
  is 501 / `Unimplemented` — pinned in both transports, with the reason spelled
  out in the 501 message so the echo is not read as a promise the build cannot
  keep.
  **Frozen readings** (§5.7 freezes behaviour per release; all seven are
  readings of points §9/§6.1/§7/§13.2 leave open):
  (a) **Eviction policy — §13.2's open question, decided: TTL with an
  oldest-insert-first byte bound.** §9's normative wording is "local TTL cache",
  so TTL is the primary policy and LRU-by-bytes is not used; a reader of a
  restore is not a writer, and recency of *reads* is not observable in what a
  caller can restore. On insert, entries past their TTL are swept, then entries
  are dropped oldest-insert-first until the new one fits, and the sweep/eviction
  is keyed on `stored_at_ns` with ties broken by insertion order, so it is fully
  deterministic. Rationale for evicting rather than refusing: refusing would
  return an id the caller can never use, and the byte bound must not let one
  large request poison the cache for everyone; an entry larger than the whole
  bound, a zero TTL and a colliding id are the three cases that store nothing.
  (b) "original span bytes" = the §4.4 removal-rule range (above).
  (c) The defaults `DEFAULT_TTL_NS` (15 min) and `DEFAULT_MAX_BYTES` (64 MiB);
  DESIGN §7 has no CCR row, and these are the values a single-process server can
  hold without a memory ceiling of its own. Both are constructor arguments, and
  `max_bytes` counts `original + marker` bytes per entry.
  (d) An id is reported **only** when the entry is live, so `restore_ids` never
  contains a dead id at the moment it is returned; a later eviction or expiry can
  still turn it into a miss, which is the documented consequence of (a) and of
  the TTL itself.
  (e) The compressed payload is pre-check *context*, never authority: absent or
  empty skips the pre-check, so a caller who kept only the id can still restore.
  (f) Both HTTP compress shapes store; gRPC always stores; a build with no store
  wired stores nothing and reports nothing.
  (g) `restore_ids` is always present in the envelope and the gRPC `Stats`
  (an empty list when nothing was stored), never an absent key — §6.2 field 19 is
  a `repeated string`, so "absent" and "empty" are the same wire value and one
  shape is easier to consume.
  **Deviations from DESIGN: three, recorded here rather than in DESIGN.md.**
  (1) **§13.2's "CCR store eviction policy under concurrent requests (TTL vs
  LRU-by-bytes)?" is answered by reading (a)** — TTL, with a deterministic
  oldest-insert-first byte bound — and §13.2 should be updated to say so.
  (2) **§6.1's `/v1/restore` row pins no request or response shape**, so the two
  strict shapes and the `application/octet-stream` response above are readings;
  §6.1 should state them, as W3.2's record already asks for its own two. (3) **§7
  has no CCR defaults row** (TTL, bound) and **§9's "return one `restore_id` per
  committed group" is qualified by the flag gate**: with the `ccr` feature off the
  option resolves but no id exists, because §9 also says the module is
  flag-gated and "v1 can ship without it". §3's degradation policy, §4.4's
  removal rule, §4.5's marker and its 4-hex checksum, §4.7's caller guidance, §5's
  determinism, §6.1's option semantics and header naming, §6.2's service shape
  and `Stats` message and §9's id format are implemented as written.
  **Tests and verification.** 27 new tests (7 unit in `ccr.rs`, 13 in
  `crates/core/tests/ccr.rs`, 6 in `crates/server/tests/restore.rs`, 1 net in
  `crates/core/tests/api.rs`); six existing tests re-pointed, no test deleted.
  Workspace **441 → 468 green** (469 collected, the one `#[ignore]`d golden
  generator), **470** with `--all-features` and with
  `--features quantification-core/strict_validate`, **66** with
  `-p quantification-server --features ccr`;
  `cargo fmt --all --check` clean and
  `cargo clippy --workspace --all-targets -- -D warnings` clean in the default,
  `ccr`, `strict_validate` and `--all-features` states. No new dependency, so
  `Cargo.lock` and `deny.toml` are untouched. The `fuzz/` crate does not
  compile — `fuzz_splitter.rs` still calls W2.6's two-argument
  `stage1::split_span` with one — which is **pre-existing** (it fails the same
  way at `b58d361`) and outside this wave's ownership, but it is the one red
  build in the tree and W4.5 should fix it.

## Wave 4 — verification & perf (overlaps Waves 2–3 where noted)

- **W4.1 Property tests** (§12) — R3 parse validity, splice exactness,
  idempotence, marker escape-safety, restore identity. After W2.9.
  Status: **complete, with two normative-claim violations found** (2026-09-27).
  Two new files, no production change, no new dependency, no golden touched:
  `crates/core/tests/property.rs` (13 tests, 1 of them `#[ignore]`d — see
  finding **D**) and `crates/server/tests/property_restore.rs` (3 tests,
  `#![cfg(feature = "ccr")]`, so the default server build compiles it to an
  empty test target). The corpus is generated by the same LCG as
  `tests/stage1_split.rs` (`0x4d31_5eed_0001`, per-test seeds derived from it),
  no wall-clock, no RNG.
  **The shape space** (14 span shapes × 4 envelopes × 9 option sets): log bursts
  with per-line ts/ip/uuid/duration/counters; verbatim exact runs; ws-padded
  runs (`""`, `"  "`, `\t`, `" \t "`); multi-line near-duplicate traces;
  verbatim repeated blocks; single-line `},{` tool dumps (small, and over
  `max_line_bytes` so stage 1b segments 200–550 records); record dumps at
  `max_record_bytes` ± 1; payloads carrying prior-marker text in both styles
  plus four lookalikes; near-misses (a pair that is one line short of a group, a
  block plus a tail line, a run split by a neighbour, two identical records, and
  a run sized exactly on the profitability boundary — 4 × 7-byte lines is kept
  verbatim, 4 × 8-byte lines commits); `\n` / `\u000A` / `\u000a` mixed and
  u000A-only newlines; non-ASCII spans; all-unique spans; empty/one-line spans;
  **ws-paired blocks** (two ws-equal-but-raw-different lines then a third line,
  repeated — the shape that exposes finding D). Envelopes: chat (user / tool /
  assistant / `text` part), Responses (root `input` string, message items,
  `function_call_output`), Anthropic (`tool_result`, `text` part, top-level
  `max_tokens`), plain text, minified and pretty-printed, 1-in-8 with a BOM.
  Options: the default set plus `user_and_tools`, forced `ascii`/`unicode`,
  `min_group_size` 2 and 7, `normalize_ws=false`, `template_dedup=false`, and a
  combined set — so no property is pinned to one configuration.
  **What each test asserts, and its corpus** (all counts measured, and every
  test asserts its own coverage floor so none of them can go vacuous):
  `the_test_local_json_oracle_has_teeth` (22 valid + 22 invalid documents, so
  the R3 oracle is proved to reject before it is trusted);
  `every_generated_output_parses_as_json_or_stays_text` (512 payloads, ≥384 JSON
  + ≥64 text, ≥75 % compressing, > 500 kB of output) — R3; the JSON validator is
  a second, compact copy of the test-local recursive-descent oracle in
  `tests/pipeline.rs` (a third-party parser is still not worth a dev-dependency,
  and two integration test binaries cannot share a module without a `#[path]`
  include that would also become an empty test target);
  `the_output_is_the_input_outside_the_committed_ranges` (512 payloads, ≥200
  commits, > 500 kB of input bytes compared) — a byte walk over the ledger's
  reported ranges, plus the independent length model `spliced_len`, plus a
  re-splice of every committed region back into the output that must reproduce
  the input exactly;
  `every_emitted_marker_matches_the_grammar_and_is_escape_safe` (512 payloads,
  ≥200 markers) — each marker is parsed by an **independent** §4.5 grammar
  parser (the five cores are hard-coded in the test, not read from `render.rs`),
  the kind/count/style/checksum must match the commit, the checksum must equal
  `marker_checksum(anchor)`, no byte may be `"`, `\` or a control character, and
  the marker quoted must parse as a JSON string (the escape-safety proof). The
  test asserts all five commit kinds and both styles appear;
  `no_stage_commits_into_an_already_claimed_range` and
  `every_removed_range_is_the_member_union_plus_its_joiners` (512 payloads each,
  ≥200 commits, > 5 000 units) — the ledger's per-unit claim map, the removal
  rule as `removal_range(first..last+1) == removed`, the anchor as a whole-unit
  prefix of it, the §4.4 profitability gate, and a walk proving the committed
  ranges and the surviving units tile the span with only joiner bytes between
  them; `a_poisoned_reused_output_buffer_never_leaks_a_stale_byte` (320 payloads
  in a deterministically shuffled order, one `Vec` reused through the server's
  own `api::reserve` + `api::Compressor` sequence, refilled with 0x00/0xff/`A`/`{`/
   0x7f between calls, every response compared to a fresh-buffer compression and
  the poison-byte census compared too; > 100 responses shorter than the poison
  fill and > 50 large→small transitions);
  `identical_input_yields_identical_output_under_every_option_and_clock`
  (48 payloads × {`user_content`, `user_and_tools`} × {`auto`, `ascii`,
  `unicode`} × 8 repetitions, alternating the monotonic, frozen, counted and
  backwards-going clocks = 2 304 compressions) plus
  `a_clock_can_never_move_a_single_output_byte` (64 payloads; the injected
  clocks must produce three *different* elapsed triples, so the injection is
  provably not vacuous) and `a_warm_and_a_cold_compressor_agree_on_every_generated_payload`;
  `restore_is_the_identity_for_every_id_a_response_returns` (512 payloads, one
  store per response, ≥300 stored spans) — every returned `restore_id` restores
  the exact removal-rule range, splicing them all back reproduces the input byte
  for byte, `reversible=true` moves no output byte, and a forced marker style
  moves none either.
  **Finding D — §4.4's idempotence claim is false, and it is reachable with
  shipped defaults.** A stage-5 block commit's anchor is the whole first
  occurrence, and `blocks::anchor_is_match_free` only refuses an anchor that
  hides a windowed match of period ≥ `min_block_lines` (= 2). It cannot see a
  **period-one** repetition, because stage 5's minimum period is 2 — but stage 7
  runs with `MIN_PERIOD = 1`. So an anchor of the form `ws-equal pair + one
  other line`, repeated twice, is committed as a 3-line block, and the second
  pass then collapses the two surviving ws-equal lines as a "templated block".
  Minimal reproducer (plain text payload, **default options**, 6 lines joined by
  `\n` escapes, `A`/`B` are the same line with two-space padding on opposite
  sides, `C` is unrelated):
  ```
  A  = "  2026-08-25T10:00:01Z INFO hc 10.0.0.1 took 5ms ok padding"
  B  = "2026-08-25T10:00:01Z INFO hc 10.0.0.1 took 5ms ok padding  "
  C  = "2026-08-25T10:00:01Z ERROR a completely different line of its own"
  payload = A \n B \n C \n A \n B \n C
  pass 1: one Block commit, count 1, anchor = A\nB\nC, removed = all six lines
  output:  A \n B \n C[... block x1 5319 ...]
  pass 2: one TemplatedBlock commit, count 1, over A and B
  output:  A[... templated block x1 dc98 ...] \n C[... block x1 5319 ...]
  ```
  Measured on the 2 048-payload generated corpus: **160/2 048 (7.8 %) diverge**
  across the nine option sets, and **171/2 048 (8.4 %) diverge with the shipped
  default options alone** — every one of the nine option sets is affected. All
  160 are classified mechanically by
  `every_generated_divergence_is_a_block_anchor_hiding_a_period_one_repetition`
  (a `TemplatedBlock`, count ≥ 1, period 1, whose two removed units are
  ws-equal, whose range lies inside the first pass's emitted anchor region, and
  whose third pass is stable); the count is pinned at 160 so a *new* mechanism
  fails the test loudly. `every_generated_payload_reaches_a_fixed_point` is
  therefore `#[ignore]`d with that reason — the assertion is unchanged and still
  asserts `recompress(output) == output` over all 2 048 payloads — and
  `a_block_anchor_that_hides_a_period_one_repetition_is_not_a_fixed_point` pins
  the reproducer above (both commits' exact kind/count/unit range/anchor, the
  second pass running inside the first pass's anchor, and the third pass being
  stable), so a fix breaks a *green* test with a name that says what changed.
  W2.10's mechanisms (B: marker-mask collision, fixed by the stage-1 marker
  eligibility predicate; C: anchor adjacency, fixed by the masked-domain
  admission wall) are unaffected — the residual here is 100 % mechanism D, and
  the wall that misses it is the *period* bound, not the marker predicate. The
  candidate fixes are a code change in `detect::blocks` (extend the anchor
  admission wall to period 1 in the stage-5 domain, i.e. refuse a block whose
  own anchor's first two residual units are equal in the masked domain) or a
  §4.4 amendment; both are outside this wave's ownership, which is why nothing
  here changes production behaviour.
  **Finding S — a `restore_id` can stop restoring its own response (§9).** The
  store is content-addressed and `Store::insert` replaces an existing entry's
  `marker`/`checksum` when the same original is stored again
  (`crates/core/src/ccr.rs`), while `Store::restore` treats a payload that does
  not contain *the entry's* marker as a miss. The same removed bytes can
  therefore be marked twice — once per marker style — and the first response's
  id is then un-restorable (HTTP 404 / gRPC `NotFound`) even though the stored
  bytes are correct. Minimal reproducer: one payload, one shared store,
  `reversible=true`, compressed once with `marker_style=ascii` and once with
  `marker_style=unicode`; both responses report the **same** id
  (`bccde1936da3c9e2627e4635690aa9c2:157` for the fixture below) and
  `restore(ascii_response, id)` is a miss while
  `restore(unicode_response, id)` and `restore(no payload, id)` both return the
  right original. The ladder never returns wrong bytes — it returns a miss where
  §9 promised a hit. Pinned by
  `an_id_stored_under_two_marker_styles_stops_restoring_the_first_response`, and
  `on_a_shared_store_every_restore_miss_is_an_id_another_response_re_stored`
  proves over the 512-payload corpus (two styles per payload, one shared store)
  that **every** miss is of this shape — the entry still holds the exact removal
  range — so the store never loses an original, and the count of shadowed ids is
  non-zero. The identity property itself is asserted per response (a store per
  request), which is the reading of §9 that holds today.
  **Non-vacuity** (mutations applied in a scratch copy of the tree, one at a
  time, then reverted; none of them is in the commit): dropping the anchor copy
  in `splice::splice_into` fails `the_output_is_the_input_outside_the_committed_ranges`;
  dropping `out.clear()` fails `a_poisoned_reused_output_buffer_never_leaks_a_stale_byte`;
  putting a `"` into the ASCII marker's `OPEN` fails both
  `every_generated_output_parses_as_json_or_stays_text` and
  `every_emitted_marker_matches_the_grammar_and_is_escape_safe`;
  making `removal_range` return only the first member fails
  `every_removed_range_is_the_member_union_plus_its_joiners`; making
  `try_commit`'s removed range one unit longer than its group fails
  `no_stage_commits_into_an_already_claimed_range` ("an unclaimed unit lies
  inside …"); appending one byte to the output when the clock reads non-zero
  fails both determinism tests; making the stored original one byte short fails
  `restore_is_the_identity_for_every_id_a_response_returns`; and making
  `Unit.eligible` ignore `carries_marker` again fails the `#[ignore]`d
  idempotence gate (so it is a live detector, not a dead assertion). Removing
  the ledger's `is_free` guard *alone* does **not** fail the double-claim test —
  no detector proposes an overlapping group today — which is why that property is
  a net on the *output* and not a guard test, and why the mutation that fires it
  is an over-claiming removed range.
  **Not established here**: the §4.4 idempotence claim (finding D), the §9
  promise that a returned `restore_id` always restores (finding S), the
  §12 corpus-shape histogram, and the M2/M3 gates (W4.2/W4.3). W4.5 still owns
  the `fuzz_splitter` build break recorded above, and the five test files whose
  determinism source-scan is still a substring match (`detect_exact`,
  `detect_wsruns`, `detect_templ`, `detect_templ_blocks`, `splice`) are still
  unconverted — they are not this wave's files.
- **W4.2 Determinism CI gate** (§5) — 1000× PR / 200k nightly soak / fuzz
  double-run / CPU-feature matrix (baseline vs AVX2 vs NEON). After W2.9.
- **W4.3 Criterion benches + nightly perf gate** (§8 per-stage budgets);
  measure the 8 MiB splice copy explicitly. After W2.9. **Gate M3**:
  ≥100 MB/s p50 aggregate.
  Status: **complete; Gate M3 FAILS on this hardware (2026-09-27).** Two of the
  three §8 stage lines pass with wide margins — schema sniff + span locate at
  1199 MB/s against a ≥400 MB/s floor, and splice + stats at 0.040 ms against
  ≤10 ms — but **span compaction (stages 1–7) misses its ≤50 ms budget by 5.4×
  and its ≥160 MB/s floor by 5.1×, and the aggregate misses the ≥100 MB/s M3
  gate by 3.3× and R2's ≤80 ms by 3.4×.** No compression semantics were changed
  to move a number, and every figure below is re-derived by the harness rather
  than asserted by hand.
  - **What landed.** `crates/core/benches/stages.rs` (criterion, 14 benches,
    one per §8 line and one per §4.4 stage), `crates/core/benches/gate.rs`
    (the M3 gate: p50/p99, per-stage attribution, budget verdicts, a JSON
    report, non-zero exit on a miss), `crates/core/src/perf_payload.rs` (the
    deterministic 8 MiB fixture, behind the new `bench_stages` feature),
    `crates/core/tests/perf_fixture.rs` (4 fixture tests, same feature),
    `.github/workflows/perf.yml` (nightly). `criterion = "0.8.2"` is a
    **dev-dependency only** (`default-features = false`, `cargo_bench_support`;
    no rayon, no plotters), so the default build gains no code and no
    default-build compile time.
  - **The spike harness is superseded, not duplicated.**
    `crates/core/src/s1/benches.rs` (the S1 report harness, `f64` + `.sort()`)
    and the two examples that drove it (`s1_locator`, `s1_correctness`) are
    **deleted**. The M1 prototype scanner `s1/locator.rs` and the `spike` module
    stay — it is the artifact the S1 hunk cites — but it now ships **no
    measurement harness at all**, so the tree has exactly one. The benches pin
    the **normative** `locator::locate_into` + `sniff::sniff`, never the spike
    scanner: M1's 1443–1496 MB/s was a prototype that `locator.rs` replaced.
  - **The fixture is generated in-process, seeded, and never committed.**
    `perf_payload::log_heavy_chat(8 << 20)` is a pure function of its target
    size over a fixed-seed xorshift64 (`0x0bad_c0de_5eed_1234`): no wall clock,
    no RNG, no `/dev/urandom`, no committed 8 MiB blob. It builds a
    `chat/completions` document whose single eligible `user` span is a log tail
    in which **all five detectors and stage 1b fire**: 48 verbatim repeated
    lines, 12 ws-padded lines whose padding is a real `\t` escape, 480
    template lines carrying all six §4.6 masks, a 6-line stack-trace block
    repeated 8× verbatim, a 5-line request/response block repeated 10× with
    per-line ids, and **one over-cap single-line tool dump** (900
    `},{`-separated records, 69 301 B > `max_line_bytes`, so stage 1b segments
    it and the records then group). Newlines are emitted as `\n`, `\u000A` and
    `\u000a` in a fixed 4-cycle and every log line goes through one
    `escape_into` (`"`, `\`, `\t`, `\r`), so the document is valid JSON —
    checked against a real parser during development, and pinned in-build by the
    locator, which would route a malformed one to `degraded=true`.
    **Measured shape of the shipped fixture: 8 399 344 B, 1 eligible span,
    77 000 units, 109 mean unit bytes, 300 groups collapsed,
    8 399 344 → 76 878 B (0.9% of input, a 109× reduction), `degraded =
    false`.** That ratio is far above §12's ≥40% token-reduction target
    because a log tail repeats: the point of the fixture is per-unit work, not
    the ratio, and the ratio's effect on the verdict is bounded below. The gate
    and `perf_fixture` both **fail** if any detector counter (including
    `record_splits`) is zero or the payload degrades, so a fixture that quietly
    stopped exercising a stage cannot turn the gate green.
  - **Method (DESIGN.md §8's protocol, honoured literally).** Release build,
    `taskset -c 2` (the gate prints its own `Cpus_allowed_list`, so an unpinned
    run is visible in the log), one `Compressor` and one output buffer reused
    across iterations so every allocation is warm, **3 warm-up iterations
    measured and discarded** (cold start excluded), 30 measured iterations,
    `Instant` around the whole `Compressor::compress` call for the aggregate and
    the pipeline's own three `elapsed_*` windows plus the feature-gated
    per-stage clocks for the attribution, percentiles by nearest-rank on integer
    nanoseconds (`p50` = 15th of 30, `p99` = 30th), and every threshold
    compared in **integer** arithmetic (`bytes × 10 000 / ns`, tenths of MB/s)
    so no float comparison can gate. Hardware: **Intel Core i7-9700K @ 3.60 GHz
    (8 logical cpus, 12 MiB L3, Linux 6.x)**, the same machine the S1/M1 and W2
    measurements were taken on. **Three consecutive pinned runs of this exact
    source agree within 0.2%** (aggregate p50 275.34 / 275.61 / 275.81 ms),
    taken on an idle box; runs taken while another agent's test binary held ~4
    cores read ~7% slower, which is why a spread is quoted instead of the best
    number. The tables below are the last of those runs, i.e. the committed
    build.
  - **§8, line by line (p50 / p99, 8 399 344 B payload):**

    | §8 line | budget | p50 | p99 | measured rate | verdict |
    |---|---|---|---|---|---|
    | schema sniff + span locate | ≤20 ms, floor ≥400 MB/s | 7.00 ms | 7.01 ms | 1199 MB/s | **PASS** (2.9× inside the budget, 3.0× above the floor) |
    | span compaction (stages 1–7) | ≤50 ms, floor ≥160 MB/s | 268.77 ms | 269.87 ms | 31.2 MB/s | **FAIL** — 5.38× the budget, 5.13× under the floor |
    | splice + stats | ≤10 ms | 0.040 ms | 0.043 ms | 1.9 GB/s over 76 878 B out | **PASS** (243× inside) |
    | 8 MiB splice copy, no commits (the explicit §8 measurement) | ≤10 ms | 0.28 ms | 0.47 ms | 29.7 GB/s | **PASS** (35× inside) |
    | **aggregate (bytes-in / total core time)** | **≥100 MB/s, R2 ≤80 ms** | **275.81 ms** | **276.92 ms** | **30.4 MB/s** | **FAIL** — 3.29× under the M3 floor, 3.45× over R2 |

  - **The 8 MiB splice copy, measured explicitly as §8 demands.** Not inferred:
    the gate additionally times `splice::splice_into(payload, &[], out)` into a
    pre-reserved buffer — the full 8 399 344 B copy with no commits — and
    criterion has it twice more as `splice/8mib_copy_no_commits` (**383.4 µs**)
    and `splice/8mib_splice_with_commits` over the fixture's real 300 commits
    (**14.8 µs**). **§8's ≤10 ms splice budget is met with ~35× headroom, and
    the warm-cache assumption holds on this hardware**: 8.4 MB in 0.28 ms is
    29.7 GB/s, ordinary warm L3/DRAM copy bandwidth for this machine. Splice is
    not where §8 is wrong, and the pipeline's own splice is faster still
    because this fixture collapses to 76 878 B.
  - **Per-stage attribution (in-pipeline, p50 of the same 30 iterations; the
    `bench_stages` clocks read the *injected* `Clock`, so they cost nothing in
    the default build and use exactly the seam `Stats.elapsed_*` uses):**

    | §4.4 stage | p50 | MB/s | share of the compaction window |
    |---|---|---|---|
    | stage 1 line split (+1b record split) | 15 617 379 ns | 537 | 5.8% |
    | stage 3 exact runs | 1 905 624 ns | 4 408 | 0.7% |
    | stage 4 ws-normalized runs | 63 363 300 ns | 132 | 23.6% |
    | stage 6 masked forms (§4.6 automata + xxh3-128) | 135 595 184 ns | 62 | 50.4% |
    | stage 5 repeated blocks | 50 392 517 ns | 167 | 18.8% |
    | stage 6 template groups | 828 709 ns | 10 135 | 0.3% |
    | stage 7 templated blocks | 535 624 ns | 15 681 | 0.2% |
    | compaction unattributed (ledger, merges, `shift`) | 531 152 ns | — | 0.2% |
    | pipeline unattributed (stats assembly, options echo) | 1 465 ns | — | — |

    The criterion benches measure the same work per detector on the *full* unit
    set (`iter_batched`, so split/forms setup is excluded from the timing) and
    agree with the in-pipeline clocks, which is what makes a regression
    attributable to one stage: `stage6_masked_forms` 135.05 ms,
    `stage4_ws_runs` 69.63 ms, `stage5_blocks` 57.36 ms, `stage1_split`
    11.35 ms, `stage7_templated_blocks` 2.79 ms, `stage3_exact_runs` 1.78 ms,
    `stage6_template_groups` 855 µs, `compact/stages1_7` 273.45 ms,
    `end_to_end/compress_8mib` 277.47 ms, `compact/ledger_setup` 2.12 µs (so
    `Ledger::new` is free and nothing hides in setup). Isolated `stage1_split`
    is 4 ms *lower* than in-pipeline (fresh `Vec<Unit>` each iteration vs a
    warm one, i.e. the pipeline's number includes its growth) and isolated
    `stage7_templated_blocks` is 5× higher (in-pipeline, stages 3–6 have
    already claimed nearly every candidate, so stage 7 has almost nothing to
    scan); the other eleven are within 15%.
  - **Where the miss is.** 74.0% of the compaction window is two per-byte
    stages that run over every unit regardless of what commits: §4.6 masking +
    `xxh3-128` at 62 MB/s, and the §4.2 ws-normalization that both it and
    stage 4 redo at 132 MB/s. The stages that *decide* things are nearly free
    (stages 3, 6-grouping and 7 together are 1.2% of the window); stage 5's
    windowed scan is 18.8%. All of it is linear in span bytes, so the miss is a
    **constant-factor** problem — roughly 5× on the normalization/masking line —
    not a superlinear blow-up and not a fixture artifact. Three compositions of
    the fixture were measured while writing this hunk, and the verdict does not
    depend on which one ships: 45% dump-records / 55% log lines, 77 000 units
    → **30.4 MB/s** (shipped); 40% / 60%, 38 556 units, no over-cap line →
    **32.4 MB/s**; a deliberately harsher 88% / 12%, 91 520 units, 99.5% of the
    output removed → **29.6 MB/s**. The W2-review hunk's independent
    end-to-end number on a completely different corpus was 31.4 MB/s, within
    3% of the shipped fixture. Nothing was re-tuned to improve any of these.
  - **R2 is not met.** §8's target is ≤80 ms single core, warm, 8 MB. Measured
    **275.81 ms p50 / 276.92 ms p99**, i.e. **3.4× over**, with the detect line
    (7.00 ms) and the splice line (0.040 ms) together 2.6% of it. R2 is missed
    inside span compaction and nowhere else. Recorded as measured: the budget
    is normative, so the choice between "make masking and ws-normalization
    ~5× faster" and "restate §8" belongs to the design owner, not to this hunk.
    The two cheap-looking wins the table exposes are (a) `wsnorm` and `mask`
    recompute the same bytes three times per unit (stage 4, the stage-6
    pre-pass, stage 5's `load`) and (b) `Forms::build` fingerprints and copies
    every unit's masked form even for units no detector will look at again.
    Both are implementation changes that alter nothing normative; neither was
    made here.
  - **One honest caveat on the detect line.** It is the only §8 line whose
    measurement swings with **code layout**: the same source, payload and box
    measured `elapsed_detect_ns` p50 = 4.52 ms in one build of the gate and
    7.00 ms in the committed one, and `locate/span_locate` = 6.90 ms in the
    criterion binary; adding a single unused function to the gate moved its
    number by 1.6× while the compaction number did not move at all. The
    locator's inner loop is byte-at-a-time, so this is alignment sensitivity,
    not a measurement error, and **every observed variant passes both the
    ≤20 ms budget and the ≥400 MB/s floor** (worst 7.14 ms = 1180 MB/s). It is
    recorded so that a future hunk reading a ~1.6× detect "regression" checks
    the build before believing it.
  - **Nightly perf gate (`.github/workflows/perf.yml`).** Reuses the existing
    conventions (`actions/checkout@v4`, `dtolnay/rust-toolchain@stable`, the
    `run:`-step shape of `ci.yml`/`fuzz.yml`): `schedule` nightly +
    `workflow_dispatch` + `pull_request`, with
    `continue-on-error: ${{ github.event_name == 'pull_request' }}` so **it can
    never block a PR**, while a nightly or a manual run *does* fail the job on
    a regression. Every measurement step is `taskset -c 2 …`. It lints the
    bench-only feature state (the default `--all-targets` cannot, because the
    bench targets are `required-features`), runs the fixture test, then the
    gate (`--iters 30 --json target/perf-gate.json`, non-zero exit on any miss,
    report echoed and uploaded with `target/criterion` under `if: always()`),
    then the criterion stage benchmarks. The gate is a **budget** gate, not a
    baseline-diff gate: §8's floors are the trigger, so it needs no stored
    criterion baseline and cannot rot into "always green". It will be red on
    the first nightly for the reason in the first line of this hunk, which is
    the correct signal, not a misconfiguration.
  - **Two files outside this hunk's ownership were touched, and only as much as
    the feature forced:** `crates/core/tests/pipeline.rs` and
    `crates/core/tests/api.rs`, three clock-read bounds made feature-aware.
    `the_pipeline_module_has_no_forbidden_determinism_inputs` counted exactly
    four `now_ns()` reads in `src/pipeline.rs`; the instrumentation is routed
    **through the injected `Clock` trait**, so that file's other assertion
    (`Instant` never appears below `impl Clock for MonotonicClock`) still
    passes untouched and the count assertion now reads `4 + marks + 1` with
    `marks` cross-checked against `Stage::ALL.len()` under the feature.
    `timings_never_reach_the_payload` and `a_pathological_clock_cannot_change_
    the_output` priced the compaction window at one clock read (the latter
    hard-failing on a fifth) and now price it at `2 × Stage::ALL.len() + 1` /
    `4 + 2 × Stage::ALL.len()` under the feature. Every one of the three keeps
    the *same* claim — no wall clock outside the seam, no stray clock reads,
    output independent of the clock — and none is weakened; the hostile-clock
    test still asserts the same `u64::MAX` compaction window and the same
    byte-identical output under the feature.
  - **Instrumentation shape (the "no runtime cost in the default build"
    constraint).** `StageTimes`, `Stage`, `Compressor::last_stage_times()`,
    `reset_stage_times()`, `compact_span_only()` and the seven `mark`/`record`
    pairs inside `compact_span` are all `#[cfg(feature = "bench_stages")]`, and
    the feature adds one `#[cfg]`-gated field to the existing `Stages` scratch
    bundle rather than a parameter to `compact_span` (that call site would trip
    `clippy::too_many_arguments` at 8/7 without it — the same trap the W2 review
    recorded for `blocks::Domain`). The default build's behaviour is unchanged.
  - **Verification.** `cargo test --workspace` → **480 passed, 0 failed, 2
    ignored** (W4.1's property tests are in that count; `perf_fixture` is
    `#![cfg(feature = "bench_stages")]` and contributes 0 to the default
    build). `cargo test -p quantification-core --features bench_stages` → the
    same suite green **plus** the 4 `perf_fixture` tests and the three
    feature-aware clock bounds. `cargo fmt --all --check` clean;
    `cargo clippy --workspace --all-targets -- -D warnings` clean;
    `cargo clippy -p quantification-core --features bench_stages --lib --benches
    -- -D warnings` clean. `cargo deny` is **not installed in this
    environment**, so the licence/bans check was done by hand: all 33 newly
    locked crates (criterion 0.8.2's tree) declare `MIT`, `Apache-2.0`,
    `BSD-2-Clause` or `Unlicense`, every one inside `deny.toml`'s existing
    allow-list — no new licence, no `deny.toml` edit, no wildcard requirement.
    One new `multiple-versions` **warning** (not `deny`): criterion pulls
    `itertools 0.13` alongside the `0.14` already in the tree. The `fuzz/`
    crate still does not compile for the pre-existing `fuzz_splitter` reason
    the W3.4 hunk records; it is untouched here and is W4.5's.
  - **Left for the next owner, in the order the table suggests:** make
    `wsnorm` + `mask` + `xxh3-128` ~5× faster (one pass, one normalized copy
    shared by stages 4/5/6, one hash of the masked form), then re-run this
    gate. The floors are enforced in code, so the gate turns green the moment
    the work is done, and the criterion group that moved names the stage.
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
