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
