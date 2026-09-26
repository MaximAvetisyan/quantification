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
  A **third** mechanism (C: a commit's anchor abutting a surviving neighbour
  its own stage could not see) was found by the new fuzz target and is not
  fixed either; the W2 review record below has its 173-byte reproducer.
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
