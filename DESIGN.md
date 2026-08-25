# Log Compressor ("quantification") — Design

Status: **design phase, rev 6** — no implementation yet.

Rev 6 changes (implementation-readiness review 2026-08-26):
* Stage 1b made fully normative: brace-preserving record segmentation
  (`u_head`/`u_i`/`u_tail`), a cross-detector **removal rule** for committed
  ranges (member union + inter-unit joiners), idempotence argument (§4.4).
* Per-detector **comparison domains** pinned; stage 5 respecified over
  ws-normalized fingerprints (§4.4).
* Marker rendering grammar pinned exactly, checksum position included (§4.5).
* Stage 6→7 handoff stated: template ids exist for all residual lines (§4.4).
* `X-Stats-*` header naming convention defined (§6.1).
* Proto syntax fixed (one field per declaration), `restore_ids` added, CCR
  id format made normative (§6.2, §9).

Rev 5 changes (design critique 2026-08-26):
* Single-line payloads covered: new **stage 1b record split** re-segments
  over-cap lines on `},{` boundaries, so single-line JSON tool dumps (no
  `\n` escapes at all) compress too; `max_record_bytes` added (§4.4, §7);
  span-shape instrumentation added to corpus requirements (§12).
* **Utility-retention eval**: task-quality harness with answer-parity gates
  joins the success criteria (§12); information-loss contract codified
  (§4.7); value-preserving collapses scheduled v2 (§10).
* Locator schema coverage completed: Responses `function_call_output` items
  (`output`), Anthropic `tool_result` blocks, normative eligibility map and
  acceptance envelope (BOM, malformed-input routing) (§4.1).
* Collision hardening: unit fingerprints upgraded to **xxh3-128** with a
  normative length→hash→memcmp verification order; collision-pressure perf
  fixture added (§4.4, §12).

Rev 4 changes (requirements review 2026-08-26):
* `user_and_tools` promoted into v1 (opt-in scope policy; default stays
  `user_content`) (§4.3).
* Repeated-block detection respecified as a capped windowed scan; rev 3's
  failure-function formulation was prefix-anchored and missed blocks
  preceded by header lines (§4.4.5).
* Normative **profitability gate**: commit a group/block only when
  anchor + marker bytes < removed bytes (§4.4).
* New stage 7: template-id block collapse for multi-line near-duplicates
  (§4.4.7, §4.5).
* Performance budget relaxed to the real requirement: ≤80 ms / 8 MB,
  gate ≥100 MB/s; 3 ms kept as a non-blocking stretch goal (R2, §8).
* Determinism hardened: ISA-dispatch rule + CPU-feature CI matrix (§5.9),
  emit order pinned to byte offsets (§5.4), nightly 200k-run soak and
  fuzz-corpus double-run gate (§5.8, §12).
* Locator rules pinned: duplicate keys last-wins, structural-key escape
  decoding (§4.1); `\u000A`/`\u000a` recognized as line separators (§4.2).
* Token accounting: runtime stats stay bytes/4 (approximate); the blocking
  success metric is computed offline with a real tokenizer (§12, §13.1).
* Markers carry a 4-hex checksum discriminator; CCR keys upgraded to
  xxh3-128 + length (§4.5, §9); stats echo resolved options (§6.2);
  prompt-cache guidance documented (§11).

Rev 3 changes (design review 2026-08-25):
* Targeted **span locator** (escape-aware scanner) replaces the simd-json tape
  walk: keeps raw escaped bytes intact (§4.2), zero-alloc, faster on
  escaped-heavy payloads.
* Unknown/unrecognized schema **degrades to pass-through** with stats instead
  of hard error (422 reserved for explicitly pinned `content_type`
  contradictions).
* Repeated-block detection is **O(N)** via failure-function periodicity, with
  explicit caps (`max_block_lines`, `max_line_bytes`).
* **Near-duplicate compression moved into v1**: ordered-mask template
  grouping (§4.4.6, §4.6). Drain-style *fuzzy* prefix-tree clustering stays v2.
* Performance gate restated in **MB/s** (token-count-derived sizes dropped as
  acceptance criteria).
* Spec fixes: detector ordering/overlap rules, escape-unit whitespace
  normalization, all-ASCII fallback markers, gRPC/API parity, idempotence &
  buffer-reuse tests.

---

## 1. Problem statement

LLM requests routinely embed huge repetitive payloads in *user* content:
pasted logs, tool dumps, CI output. Goal: take a chat-completions-style JSON
body, find repeating lines/blocks inside eligible string fields, and return the
same valid JSON with those spans compacted into a single representative +
marker (`… ×200 …`) — cutting LLM input tokens before the request is sent.

Primary contract:

```
input : {"model": "...", "messages": [
          {"role":"user","content":"2026-08-25T10:00:01Z INFO hc 10.0.0.1 ok\n...(x200 more)\n"}
        ]}
output: same JSON, user content replaced by
        "2026-08-25T10:00:01Z INFO hc 10.0.0.1 ok\n⟪×200 rows, template⟫\n..."
```

Hard requirements (v1):

| # | Requirement |
|---|---|
| R1 | **Deterministic**: same input bytes → bitwise-identical output bytes, every run, any environment, within one released version. |
| R2 | **Fast**: ≤80 ms single-core, in-process, warm, for an 8 MB payload (~1M tokens). Acceptance gated in MB/s (§8): ≥100 MB/s aggregate, p50. Stretch goal, non-blocking: 3 ms. |
| R3 | **Valid JSON out**: output parses; edits confined to designated string spans. |
| R4 | **Scoped**: only eligible message content is rewritten — `role=="user"` by default, `role=="tool"` opt-in via `scope_policy=user_and_tools` (§4.3); system/assistant content untouched. |

Non-goals (v1): streaming/chunked APIs; Drain-style *fuzzy* clustering
(prefix-tree, similarity scores — deferred to DEEP mode, §10); storage/
retrieval of dropped lines (optional CCR, §9); replacing zstd/gzip (§11);
custom user-defined masks (§10).

Plain-text logs remain supported as a degenerate case: `content_type=text`
treats the whole payload as one eligible span.

---

## 2. Prior art (research summary)

| Project | What it does | What we take from it |
|---|---|---|
| [headroomlabs-ai/headroom](https://github.com/headroomlabs-ai/headroom) | Context compressor for AI agents; routes by content type; CCR reversible compression with cached originals. | Service/reversibility shape, routing idea, marker-based output. |
| [logpai/Drain3](https://github.com/logpai/Drain3) (+ Drain ICWS'17) | Online log template miner: mask → prefix tree → clusters. | **Masking idea, pulled into v1** as single-shot ordered-mask template grouping (§4.6). Prefix-tree/fuzzy part stays v2 DEEP. |
| Grafana Loki "patterns" ingester | Mines patterns at ingest; stores repeats as pattern ref + count. | Production validation of "template + count" economics. |
| LogZip / LogShrink / Logram / LogReducer | Lossless/near-lossless via pattern mining. | Validate two-stage design (structure first, bytes second). |

**Conclusion:** v1 wins come from *exact/normalized duplication* plus
*mask-based template grouping* inside known string spans, engineered for hundreds of MB/s
with comfortable headroom against the §8 budget. Fuzzy structural clustering is the v2 DEEP upgrade path.

---

## 3. Architecture

Single binary, thin transports, one pure core crate. **Primary integration is
in-process library use**; HTTP/gRPC exist for polyglot consumers and their
body-copy costs live outside the core budget.

```
 HTTP (axum) ──────────►│ api layer: auth(optional) · limits · encode/decode │
 gRPC (tonic, unary) ───►└───────────────────────┬───────────────────────────┘
                         │ CompressRequest{payload, options}
                         ┌───────────────────────▼───────────────────────────┐
                         │ core pipeline (pure, no IO, single shot)           │
                         │ 1 schema sniff   (chat|responses|messages|text)    │
                         │ 2 span locate    (escape-aware scan; record spans) │
│ 3 span compact   (split→recsplit→hash→runs→blocks  │
│                   →templ→templ-blocks→markers)      │
                         │ 4 splice         (byte-range patch, no reserialize)│
                         └───────────────────────┬───────────────────────────┘
                                                 │ CompressResponse{payload, stats}
                           optional CCR store (restore originals, TTL)
```

* **Core is pure** (`crates/core`): bytes in → bytes+stats out. No tokio, no
  clocks, no randomness. Trivially testable, reusable as a library.
* **Transports are thin** (`crates/server`): axum + tonic unary, calling the
  same core. No streaming endpoints.

### Degradation policy (replaces hard-error-on-unknown)

A compressor must always be safe to skip. Therefore:

* Payload that sniffs as JSON but matches no known schema, or that the locator
  cannot confidently interpret → **pass-through untouched**, with
  `noop_reason` / `degraded=true` in stats. Never fail the request.
* `422 InvalidArgument` **only** when the caller explicitly pins
  `content_type` and the payload plainly contradicts it.
* Policy travels in the request so widening scope later is additive.

### Workspace layout

```
Cargo.toml            (workspace)
crates/
  core/               # schemas, span locator, span compactor, renderer, splicer
  proto/              # .proto + tonic build, shared types
  server/             # bin: axum + tonic + config + telemetry
proto/compressor/v1/compressor.proto
```

---

## 4. Core algorithm (v1)

### 4.1 Schema detection & span location

Two cheap phases:

1. **Prefix sniff** → ranked candidate schema (fixed candidate order:
   chat/completions → Responses → Messages → text).
2. **Span locator**: a single-pass, escape-aware scanner over the raw bytes —
   NOT a general JSON parser. Properties:
   * String-state machine tracks in-string / in-escape (`\"`, `\\`, `\uXXXX`)
     positions; structural bytes outside strings drive a bounded
     message-object state machine (find `messages[]` elements, read `role`,
     record inner ranges of eligible `content` strings and
     `[{type:"text",text}]` parts).
   * Records `(byte_start, byte_end)` ranges of eligible string values
     (per §4.3). Nothing else is interpreted; no tree is built; nothing is
     unescaped. Raw escaped bytes are preserved end-to-end (§4.2 depends on
     this).
    * Zero-alloc hot loop; depth-capped (`json_depth_cap`) state stack;
      span-size-capped (`max_span_bytes`).
    * Duplicate object keys: **last occurrence wins**, matching the
      de-facto behavior of mainstream parsers (JS `JSON.parse`, Go, serde);
      earlier occurrences are ignored by the locator. Not an error, not a
      degrade.
    * Structural keys (`messages`, `role`, `content`, `type`, `text`,
      `input`, `output`, `system`, `tool_use_id`) are matched on their
      **decoded form**: simple
      escapes in *key positions* (`\uXXXX` incl. surrogate pairs, `\"`,
      `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t`) are decoded before the
      comparison, so `"\u0072ole"` still matches `role`. String *values*
      remain raw escaped bytes end-to-end (§4.2).
   * Anything ambiguous or malformed → whole request passes through
     (degradation policy, §3).

**Eligibility map (normative).** Spans are classified by item/block *kind*,
not by message role alone:

| Schema | Eligible string spans | Class |
|---|---|---|
| chat/completions | `messages[i].content` (plain string); `content[j].text` where `type=="text"` | per message `role`: `user` / `tool` |
| Responses | root `input` (plain string); `input[i]` message items as in chat; `input[i]` items with `type=="function_call_output"`: their `output` string | `output` ⇒ `tool`; message items per `role` |
| Messages (Anthropic) | `messages[i].content` plain string; `content[j].text` where `type=="text"`; `content[j]` where `type=="tool_result"`: its `content` string or its `[{type:"text",text}]` parts | `tool_result` ⇒ `tool` regardless of enclosing message role; rest ⇒ `user` |

`scope_policy=user_content` rewrites `user`-class spans; `user_and_tools`
additionally rewrites `tool`-class spans. Anthropic top-level `system` and
all assistant/system spans are never eligible (R4).

**Acceptance envelope (normative).** A leading BOM is skipped by sniff and
locator. Any structural grammar violation — unquoted identifiers, raw
control characters, truncated document, depth > `json_depth_cap` — routes
to pass-through (`degraded=true`, `noop_reason="malformed"`); never a 422
unless `content_type` was explicitly pinned. String interiors stay opaque
raw bytes: they are neither decoded nor validated, so unusual escape forms
(lone surrogates, `\u003A`-style obfuscation) cannot corrupt anything — a
structural key containing them simply fails to match.

**Why not simd-json:** the Rust tape stores *unescaped* strings, which
contradicts §4.2's raw-escaped-byte processing, and tape construction both
allocates heavily and benchmarks below budget on escaped-string-heavy
payloads. Callers who want parse guarantees for untrusted producers can enable
the optional `strict_validate` feature flag (full parse; acceptable for small
payloads only).

### 4.2 Escaped-string handling

Logs live inside JSON strings, so newlines are the **two-byte sequence `\n`**
(backslash + `n`). Rules:

* Split lines on the literal `\n` sequence in the *raw escaped bytes*. Never
  unescape → process → re-escape (slow, corruption-prone).
* Line boundaries are the `\n` escape unit **and** the `\u000A` / `\u000a`
  escape units (all denote U+000A); mixed forms split identically, so a
  producer that emits newlines only as `\uXXXX` still compresses. Tested
  explicitly (§12).
* Whitespace normalization for matching collapses **escape units**, not raw
  bytes: the sequences `\t`, `\n`, `\r` and the literal space each map to a
  single space; edges trimmed; every other byte sequence stays literal. The
  same transform applies to every occurrence ⇒ deterministic.
* Markers contain **no** `"`, `\`, or control characters ⇒ they are valid in
  any JSON string without re-escaping. Raw UTF-8 markers are legal JSON even
  next to `\uXXXX` escapes.
* Accepted limitation: escapes that *encode* structure obliquely (e.g.
  `\u003A` for `:`) are invisible to masking/matching. Deterministic, and rare
  in machine-generated logs.

### 4.3 Rewrite scope (policy)

```
enum ScopePolicy { user_content,        // v1 default
                   user_and_tools,      // v1: adds role=="tool"
                   all_messages,        // reserved
                   explicit_paths }     // reserved (caller passes JSON pointers)
```

v1 implements `user_content` (default) and `user_and_tools`. Role matching is
exact and case-sensitive. `user_content` rewrites only `role=="user"` message
content; `user_and_tools` additionally rewrites `role=="tool"` messages
(function/tool results). System prompts and assistant history are never
modified.

Rationale: agent frameworks place the bulkiest repetitive dumps in `tool`
role messages, and tool output is machine-generated — template compression
there is *safer* than for human prose. The default stays `user_content` for
least surprise; callers optimizing for token savings should pass
`user_and_tools`. Corpus instrumentation should still measure the
user-vs-tool share to validate the default.

### 4.4 Span compaction (per eligible span)

All operations integer-only; the inner loops are allocation-free; arena
scratch buffers. Throughout stages 1–7, **unit** means a stage-1 line or a
stage-1b record; stages 2–7 treat units uniformly.

**Profitability gate (normative, stages 3–7):** a group or block is committed
only if

```
anchor_bytes + marker_bytes < removed_bytes
```

where `removed_bytes` counts the raw escaped bytes of the normative
**removal rule** range — all dropped units plus the joiners between adjacent
members (stage 1b, *Removal rule*) — and `marker_bytes` includes the exact decimal
width of the emitted repeat count. Below-threshold groups are kept verbatim:
collapsing three short lines behind a long marker costs more tokens than it
saves.

Stages run **strictly in the order below**, each operating on the residual
(uncommitted) line sequence left by the previous stage. Earlier-stage
commitments own their lines and win all overlaps. This ordering is normative:
it removes any implementation-defined freedom that could differ between
builds. Output order is likewise normative: markers are emitted strictly by
their anchor's byte offset (offsets are unique, so no tie-break arises) —
never in hash-table iteration order.

**Comparison domains (normative).** Each detector fixes one comparison
domain, used by *both* its fingerprints and its verifying memcmp:
stage 3 — raw bytes; stage 4 — ws-normalized forms (§4.2); stage 5 —
ws-normalized forms; stage 6 — masked forms (ws-normalized input, §4.6);
stage 7 — template ids, verified by memcmp of masked-form bytes. Anchors
are always emitted as raw original bytes regardless of domain. Merging a
pair that is equal in a normalized domain but differs raw (stages 4–7) is
intended and priced into the §4.7 information-loss contract.

1. **Line split**: `memchr`-style scan for `\n` sequences → line slice views.
   Lines longer than `max_line_bytes` are excluded from grouping and handed
   to stage 1b (bounds table memory and worst-case per-line work).
1b. **Record split (single-line fallback)**: every over-cap line is
    re-segmented into *record* units on literal `},{` separator occurrences
    (a plain `memmem` scan suffices: none of these three bytes can occur
    inside an escape unit). **Segmentation is normative**: with separator
    starts `s_1 < … < s_k`, the units are `u_head = [line_start, s_1+1)`,
    middle units `u_i = [s_i+2, s_{i+1}+1)` for `1 ≤ i < k`, and
    `u_tail = [s_k+2, line_end)`; empty units are discarded; a line with no
    separator stays verbatim. Every unit keeps its own braces (`{…}`); a
    leading `[` / trailing `]` therefore rides along in `u_head` / `u_tail`
    only, so those two usually fail to equal their siblings and remain
    verbatim — the clean middle records group normally. No edge
    special-casing exists. Each record is capped at `max_record_bytes`;
    over-long records remain verbatim. Records enter stages 2–7 as ordinary
    units. **Removal rule (normative, all detectors)**: when a committed
    group or block covers consecutive units `u_a..u_b`, the removed range is
    the union of the member ranges *plus the bytes strictly between adjacent
    members* (the joining `\n` escape units, resp. the single `,` separator
    bytes); the marker replaces exactly that range, so surviving neighbours
    end up directly adjacent to it. Idempotence: collapsed regions contain
    no remaining `},{`, and uncommitted regions re-segment identically, so
    the output is a fixed point (property-tested, §12). Motivation: agent
    tool output is frequently a *single-line* JSON array of near-identical
    objects containing zero `\n` escapes — previously exempt in full. The
    split is purely lexical (no JSON interpretation): a `},{` inside a
    nested quoted string merely yields an oddly shaped unit, which
    downstream memcmp-verified grouping treats safely. Trigger, separator,
    and caps are frozen constants; the profitability gate applies unchanged
    (`removed_bytes` = the exact union range above).
2. **Fingerprint**: xxh3-128 (fixed seed) per unit → u128, stored alongside
   the unit's byte length. Every equality claim is verified in normative
   order **byte-length → fingerprint → `memcmp`**. The 128-bit digest makes
   engineered collision floods (adversarial inputs forcing the memcmp path)
   computationally infeasible at ~2^128 work; residual collisions can only
   cause missed merges — never corrupted output.
3. **Exact runs**: consecutive equal fingerprints, verified by memcmp → keep
   first line, emit marker. Cheapest, always safe.
4. **WS-normalized runs**: same, after the escape-unit whitespace collapse of
   §4.2 (deterministic byte transform). Catches aligned/padded duplicates.
5. **Repeated blocks**: windowed scan over the residual fingerprint
   sequence in the **ws-normalized comparison domain** (both the
   fingerprints and the verifying memcmp operate on ws-normalized forms;
   raw-equal blocks are subsumed because normalization is a pure byte
   function). For each start `i` ascending, for each candidate length `L`
   from `max_block_lines` down to `min_block_lines`: if
   `fp[i..i+L] == fp[i+L..i+2L]`, verify the pair once by `memcmp` of the
   two blocks' ws-normalized bytes; on match, extend the chain while the next adjacent copy
   matches (one `memcmp` per extension, chain stops at first mismatch);
   commit. Scan order `(i asc, L desc)` makes the committed block
   leftmost-then-longest by construction; scanning resumes after the
   committed region. Cost is O(N · max_block_lines) fingerprint compares —
   linear with a small capped constant, no superlinear path. (Replaces rev
   3's failure-function formulation: KMP periodicity is prefix-anchored and
   misses blocks preceded by header lines.) After stages 3–4 the residual
   contains no adjacent equal normalized lines, so effective periods are
   ≥2. Covers pasted-duplicate traces.
6. **Template groups (near-duplicates)**: for each residual line, apply the
   ordered mask list (§4.6) to its ws-normalized form → template slice;
   fingerprint the template; collapse groups of equal templates (memcmp-
   verified) of size ≥ `min_group_size` → keep the first line verbatim,
   emit a template marker. Leftmost-first commit. **Handoff:** every
   residual line receives a masked form and a template id whether or not
   its group commits; uncommitted lines keep their bytes verbatim and their
   ids feed stage 7. This catches the dominant
   real-world case: lines differing only in timestamps, IPs, ids, counters.
7. **Template blocks**: rerun the stage-5 windowed scan over the
   *template-id* sequence produced by stage 6, with the minimum period
   lowered to 1 — an adjacent match now means "different lines, same
   template". A join is verified by one `memcmp` of the two blocks'
   masked-form bytes. Anchor: the entire first occurrence, verbatim.
   Marker: `⟪templated block ×N⟫`. Catches multi-line near-duplicates that
   per-line grouping cannot: access-log bursts, stack traces differing only
   in addresses, interleaved request/response pairs.

Non-consecutive duplicates are **not** compacted in v1 (digest mode deferred).

### 4.5 Rendering & splicing

Marker grammar — minimal, greppable, escape-safe:

```
⟪×N identical⟫          (exact run-length)
⟪×N rows, ws-equal⟫     (normalized run-length)
⟪block ×N⟫              (repeated block)
⟪templated block ×N⟫    (repeated block of same-template lines)
⟪×N rows, template⟫     (mask-based template group)
```

* ASCII fallback (all-ASCII, forced or when the span contains no non-ASCII
  bytes): `[... xN identical ...]`, `[... xN rows, ws-equal ...]`,
  `[... block xN ...]`, `[... templated block xN ...]`,
  `[... xN rows, template ...]`.
* **Exact rendering (normative).** `MARKER := OPEN CORE SEP CCCC CLOSE`:
  * unicode: `OPEN = "⟪"`, `CLOSE = "⟫"`, `SEP = " ·"` —
    e.g. `⟪×200 identical ·c5f3⟫`
  * ascii: `OPEN = "[... "`, `CLOSE = " ...]"`, `SEP = " "` —
    e.g. `[... x200 identical c5f3 ...]`

  `CCCC` = 4 lowercase hex chars, bits 0–15 of `xxh3-64(raw anchor bytes)`
  (the preserved verbatim anchor below, hashed as original escaped bytes).
  `CORE`, unicode/ascii respectively: `×N identical` / `xN identical`,
  `×N rows, ws-equal` / `xN rows, ws-equal`, `block ×N` / `block xN`,
  `templated block ×N` / `templated block xN`, `×N rows, template` /
  `xN rows, template`. No other byte varies. Pure function of the anchor
  bytes ⇒ deterministic. Rationale: the bare ASCII shapes are
  plausible in real logs (truncation/diff output), so lookalike text must
  be distinguishable; the checksum also lets `/v1/restore` pre-verify a
  candidate span without extra storage.
* Anchors preserved verbatim (original escaped bytes):
  * line groups (3, 4, 6): the **first line** of the group;
  * block groups (5, 7): the **entire first occurrence** of the block (priced
    deliberately: the model needs one full copy of the repeated trace).
* No template echo, no line numbers — both cost LLM tokens and buy nothing here.
* Output assembly = copy input buffer, overwrite recorded ranges with
  compressed spans. **No JSON reserialization** ⇒ escaping of untouched
  regions is bit-identical by construction (R3 trivially holds).

Accepted risk: a payload that literally contains marker-shaped text may
confuse downstream consumers. Markers are chosen to be improbable in logs;
documented, not defended against.

Stats returned out-of-band (headers / protobuf): bytes_in/out,
approx_tokens_in/out (bytes/4 heuristic, labelled approximate),
group breakdown per detector, elapsed_ns per stage, `algo_version`,
resolved-options echo. Because log text tokenizes at roughly 2.5–3
bytes/token, bytes/4 *understates* true token counts and savings; it is
reporting only and never gates acceptance (§12, §13.1).

### 4.6 Ordered masking (built-in, single-shot)

Template grouping uses a **fixed, prioritized mask list** applied to the
ws-normalized line copy. Matching always happens on escaped bytes; the anchor
line echoed into the output is always the original bytes, never the masked
form.

| Priority | Mask | Matches (informal) | Placeholder |
|---|---|---|---|
| 1 | `{ts}` | RFC3339/ISO-8601 timestamps; syslog `Mon dd hh:mm:ss` | `<ts>` |
| 2 | `{ip}` | IPv4 / IPv6 literals | `<ip>` |
| 3 | `{uuid}` | 8-4-4-4-12 hex | `<uuid>` |
| 4 | `{hex}` | runs of ≥16 hex chars (remaining after 1–3) | `<hex>` |
| 5 | `{dur}` | `\d+([.]\d+)?(ns|us|ms|s|m|h)` | `<dur>` |
| 6 | `{num}` | remaining decimal integers/floats | `<num>` |

Rules:

* Applied in listed priority order; within one mask, leftmost-longest wins.
* Implemented as hand-written byte automata — no regex engine, no
  backtracking, integer comparisons only.
* Placeholders are `[a-z<>]` only — safe inside JSON strings.
* The list is frozen per release; custom masks via API stay v2 (§10).

### 4.7 Information-loss contract

Compaction is lossy by construction; what each detector destroys is normative
knowledge, not an accident:

| Stages | Kept | Destroyed |
|---|---|---|
| 3–5 (runs, blocks) | first copy verbatim + count | every other copy in full |
| 6–7 (templates) | one representative verbatim + count | all masked-field values (timestamps, IPs, uuids, counters) of dropped units |

Aggregates (min/max, distinct counts) are **not** computed; the marker
carries a count only. Loss is confined to committed groups — everything
untouched is bit-identical (R3).

Caller guidance: for requests that must answer per-row questions (lookup,
counting, aggregation), either bypass compression, raise `min_group_size`,
or enable `reversible=true` (§9). Callers may prepend a brief explanation of
the marker grammar (`⟪… ×N⟫` ≈ "N omitted identical rows") to the system
message; the compressor itself never injects or modifies any text outside
eligible spans.

---

## 5. Determinism requirements (R1)

Mandatory implementation rules; violations are review blockers:

1. **Fixed-seed hashing only** (xxh3 constant seed). Rust `std::HashMap`
   (`RandomState`) is banned on all output-affecting paths — iteration order
   varies per process and would break R1 between runs.
2. Ordered containers where order can leak into output (`BTreeMap`,
   `IndexMap`, `Vec` + stable sort by explicit keys).
3. **Integer arithmetic only** on output-affecting paths (no float compares,
   no FMA-sensitive accumulation).
4. Explicit tie-breaks: first occurrence in byte order wins everywhere
   (cluster join, block commit, template group commit, marker placement).
   Markers/groups are emitted strictly in anchor byte-offset order;
   hash-table iteration order never influences output.
5. No wall-clock, RNG, env, or thread-count influence on output. Default
   single-threaded; if parallelism is added later it must be ordered-
   merge-deterministic (proven by the CI gate, not assumed).
6. Single-shot processing only (no streaming ⇒ no chunk-boundary dependence).
   Template grouping is likewise single-shot: no learned state crosses
   requests.
7. Behavior frozen per release; `algo_version` exposed in stats so callers can
   detect cross-release output changes.
8. **CI determinism gate**: PR quick gate — golden corpus (incl. adversarial
   cases) run 1000×, across varying thread counts and locales, asserting
   byte-equal outputs. **Nightly soak** — golden corpus run 200,000×,
   byte-equal. **Fuzz determinism** — every retained fuzz input compressed
   in two fresh processes per nightly, outputs byte-equal.
9. **ISA-independent output**: runtime CPU-feature dispatch (SSE4.2/AVX2/
   NEON) is allowed only where all code paths are specified bit-exact
   (xxh3 qualifies; memchr-class scanning is output-neutral). Mask automata
   and every scanner keep a scalar reference semantics; the CI determinism
   gate additionally runs across a CPU-feature matrix (baseline vs AVX2 vs
   NEON builds) so dispatch variance cannot diverge outputs.

---

## 6. API

### 6.1 HTTP (axum)

| Method | Path | Body → Response | Notes |
|---|---|---|---|
| POST | `/v1/compress` | JSON chat payload → JSON (spliced) | stats in `X-Stats-*` headers; pass-through + `X-Stats-Noop-Reason` on unknown schema |
| POST | `/v1/compress?envelope=json` | `{payload, options}` → `{payload, stats}` | structured stats incl. `degraded`, `noop_reason` |
| POST | `/v1/detect` | payload → detected schema + span preview | debugging |
| POST | `/v1/restore` | compressed + id → original | only if CCR enabled |
| GET | `/healthz`, `/readyz`, `/metrics` | | Prometheus |

Options (query or JSON envelope):

| Option | Values | Default |
|---|---|---|
| `scope_policy` | `user_content` \| `user_and_tools` | `user_content` |
| `min_group_size` | int ≥2 | 3 |
| `normalize_ws` | bool | true |
| `template_dedup` | bool | true |
| `marker_style` | `auto` \| `ascii` \| `unicode` | `auto` |
| `reversible` | bool | false |

**Stats header naming (normative).** Single-compress responses carry
`X-Stats-` + the kebab-cased Stats field name: `X-Stats-Bytes-In`,
`X-Stats-Bytes-Out`, `X-Stats-Approx-Tokens-In`, `X-Stats-Approx-Tokens-Out`,
`X-Stats-Groups-Collapsed`, `X-Stats-Exact-Runs`, `X-Stats-Ws-Runs`,
`X-Stats-Block-Repeats`, `X-Stats-Template-Groups`,
`X-Stats-Templated-Blocks`, `X-Stats-Record-Splits`, `X-Stats-Degraded`
(`true`/`false`), `X-Stats-Noop-Reason`, `X-Stats-Algo-Version`. Timings,
`options_echo`, and `restore_ids` are envelope/gRPC-only. Absent value ⇔
absent header; names are case-insensitive (RFC 9110).

Idempotent, stateless unless `reversible=true`.

### 6.2 gRPC (tonic) — unary only

```proto
syntax = "proto3";
package compressor.v1;

service Compressor {
  rpc Compress(CompressRequest) returns (CompressResponse);
  rpc Restore(RestoreRequest)   returns (RestoreResponse); // iff CCR enabled
}

enum ScopePolicy { USER_CONTENT = 0; USER_AND_TOOLS = 1; // both implemented in v1
                   ALL_MESSAGES = 2; EXPLICIT_PATHS = 3; }
enum MarkerStyle { AUTO = 0; ASCII = 1; UNICODE = 2; }

message CompressRequest {
  bytes       payload      = 1; // complete JSON document or plain text
  ContentType content_type = 2; // AUTO | CHAT | RESPONSES | MESSAGES | TEXT
  ScopePolicy scope_policy = 3;
  Options     options      = 4;
}
message Options {
  uint32      min_group_size = 1; // 0 => server default (3)
  bool        normalize_ws   = 2; // default true
  bool        reversible     = 3;
  MarkerStyle marker_style   = 4; // default AUTO
  bool        template_dedup = 5; // default true
}
message CompressResponse {
  bytes payload = 1;
  Stats stats   = 2;
}
message Stats {
  uint64 bytes_in           = 1;
  uint64 bytes_out          = 2;
  uint64 approx_tokens_in   = 3; // bytes/4 heuristic
  uint64 approx_tokens_out  = 4; // bytes/4 heuristic
  uint64 groups_collapsed   = 5; // total across detectors
  uint64 exact_runs         = 6;
  uint64 ws_runs            = 7;
  uint64 block_repeats      = 8;
  uint64 template_groups    = 9;
  bool   degraded           = 10; // pass-through happened
  string noop_reason        = 11; // "" when compressed
  uint64 elapsed_detect_ns  = 12;
  uint64 elapsed_compact_ns = 13;
  uint64 elapsed_splice_ns  = 14;
  string algo_version       = 15;
  uint64 templated_blocks   = 16; // stage-7 collapses
  string options_echo       = 17; // resolved options, canonical JSON, fixed field order
  uint64 record_splits      = 18; // over-cap lines re-segmented (stage 1b)
  repeated string restore_ids = 19; // iff reversible=true; marker output order (§9)
}
```

Streaming RPCs intentionally absent (R1 §5.6).

---

## 7. Config & tuning defaults

| Param | Default | Rationale |
|---|---|---|
| `min_group_size` | 3 | below this, marker overhead > win |
| `min_block_lines` | 2 | block repeat detection granularity |
| `max_block_lines` | 64 | caps periodicity search and block-marker granularity |
| `max_line_bytes` | 64 KiB | longer lines handed to stage 1b for record split |
| `max_record_bytes` | 16 KiB | stage-1b record cap; longer records kept verbatim |
| `normalize_ws` | true | catches padding variants cheaply |
| `template_dedup` | true | mask-based near-duplicate grouping (§4.4.6, §4.6) |
| `max_span_bytes` | 32 MiB | per-string-span cap; larger spans passed through |
| `json_depth_cap` | 64 | parser-bomb protection (locator state-stack cap) |
| `request_body_limit` | 64 MiB | transport guard |
| hash table | pre-sized from span bytes; hard cap | pathological unique-line floods degrade to pass-through, bounded memory |

Removed vs rev 1: `similarity_threshold`, `max_clusters`, streaming window.
Deferred to v2: Drain prefix-tree fuzzy clustering, custom mask API, digest
mode.

## 8. Performance budget (R2)

Target: **≤80 ms** single core, warm, in-process, **8 MB payload**
(≈1M tokens for English-heavy text). The CI acceptance gate is expressed in
throughput: **aggregate ≥100 MB/s** (bytes-in / total-core-time), p50, pinned
core — never in token-derived payload sizes. Stretch goal, explicitly
non-blocking: ≤3 ms (~2.7 GB/s), kept as an engineering north star.

| Stage | Budget | Technique |
|---|---|---|
| Schema sniff + span locate | ≤20 ms | byte state machine, memchr-class scanning; go/no-go floor ≥400 MB/s on escaped-heavy corpora |
| Span compaction (stages 1–7) | ≤50 ms | memchr split, record split (`memmem` on over-cap lines), xxh3-128, open-address table, windowed block scan, mask automata; floor ≥160 MB/s |
| Splice + stats | ≤10 ms | single output allocation, memcpy ranges |

* Zero-copy views (`&[u8]`) and arena scratch preferred; allocations are
  acceptable outside inner loops — the 80 ms budget buys implementation
  simplicity where the 3 ms stretch would not.
* Every detector is linear in span bytes up to the capped `max_block_lines`
  factor (≤64), so no adversarial input can blow the stage budgets
  (unique-line floods degrade to pass-through via table caps).
* Benchmark protocol (criterion + nightly perf gate in CI): pinned core, warm
  buffers, mimalloc/arena allocator; report p50/p99 separately; cold-start
  measured once, excluded from SLO.
* Measure the 8 MiB splice copy explicitly on target hardware before
  trusting the ≤10 ms budget — warm-cache assumptions are hardware-specific.
* First de-risk task before implementing anything else: benchmark the span
  locator prototype against the 400 MB/s floor on real escaped-heavy payloads.

## 9. Reversibility (CCR-style, optional)

If `reversible=true`: originals of compacted spans stored in local TTL cache
keyed by **xxh3-128 of the span content plus its byte length** (nothing
time-derived in the payload). **Normative id**:
`id = lower-hex(xxh3-128(original_span_bytes)) + ":" + decimal(byte_length)`.
Compress responses with `reversible=true` return one `restore_id` per
committed group in stats (marker output order), so callers address
`/v1/restore` / gRPC `Restore` without parsing markers; the marker's 4-hex
checksum (§4.5) is a cheap pre-check only — never the storage key. `Restore` re-verifies length and
hash before returning a stored original and reports a miss on mismatch rather
than risking wrong restoration; markers embed the low 16 bits of the anchor
hash (§4.5) as a cheap pre-check. `/v1/restore` / gRPC `Restore` returns
original spans. Flag-gated module; v1 can ship without it.

## 10. Out of scope for v1 (roadmap)

| Feature | When | Notes |
|---|---|---|
| **DEEP mode**: Drain prefix-tree fuzzy clustering, similarity-scored merges | v2 | Opt-in, honestly priced at 10–100 ms; integer sim scores, ordered mask lists |
| Custom masks via API | v2 (with DEEP) | ordered `{name, pattern, priority}` list, never unordered maps |
| Digest mode (non-consecutive dedup) | v2 | |
| Value-preserving collapses (keep first+last, distinct-value echo, aggregate counters in markers) | v2 | Mitigates the §4.7 information-loss contract for extraction/counting workloads |
| Streaming / incremental chunking | none planned | incompatible with R1 |
| `all_messages` / explicit-path scopes | v1.x+ | enum values reserved; `user_and_tools` shipped in v1 |

## 11. Composition with byte compression

Structural compaction is orthogonal to zstd/gzip; recommended chain is
**this service → zstd** for wire transfer. Never both-in-one in v1.

### Prompt-cache interplay

Compression rewrites bytes, so compressing mid-conversation invalidates
provider KV/prompt caches for the changed prefix — which can cost more than
the compression saves. Recommended usage: compress once when a payload is
first assembled, then reuse the identical compressed bytes on every later
turn. Determinism (R1) is what makes this viable: byte-stable output keeps
downstream prompt caches effective.

## 12. Testing strategy

* **Determinism gate** (CI, blocking): golden corpus ×1000 runs per PR,
  ×200,000 nightly; byte-equal across varied threads/env/CPU-features
  (§5.8–5.9). Full fuzz corpus compressed twice in fresh processes nightly,
  byte-equal.
* Golden files per schema: OpenAI chat, Responses, Anthropic Messages, plain
  text; incl. pretty-printed and minified variants, and content-shape
  variants: `content: null`, mixed/image content-part arrays, Responses
  `input` as a plain string, Anthropic top-level `system`, chat↔responses
  sniff-overlap payloads, Responses `function_call_output` items, Anthropic
  `tool_result` blocks, and **single-line JSON tool dumps** (array-of-objects
  with no `\n` escapes — exercises stage 1b end-to-end).
* Property tests: output parses as JSON (R3); output = input except spliced
  ranges; restore(reversible) == identity; markers well-formed and escape-safe;
  **idempotence**: recompress(output) == output (modulo stats).
* Splice robustness: server-mode output-buffer-reuse test with poisoned
  buffers (no stale bytes may leak into any response).
* Masking determinism: golden tests pinning mask priority order, leftmost-
  longest resolution, and anchor-echo-is-original-bytes invariants.
* Locator edge fixtures: duplicate object keys (last-wins, §4.1); escaped
  structural keys (`"\u0072ole"`, §4.1); newlines encoded only as
  `\u000A`/`\u000a` (§4.2); payloads containing prior-output marker text
  (marker nesting under idempotence); profitability-gate boundaries
  (groups kept verbatim below threshold, §4.4); stage-1b boundaries
  (bracket-carrying `u_head`/`u_tail`, no-separator over-cap lines,
  records at `max_record_bytes` ± 1, removal-rule union ranges).
* Fuzz: cargo-fuzz on schema sniff / span locator / span splitter (untrusted
  input); JSON bombs (depth, nesting width); any fuzz input that panics or
  produces invalid JSON is a blocker; fuzz inputs that merely fail to compress
  must pass through.
* Adversarial perf fixtures: all-unique-lines flood, single giant line,
  highly periodic patterns (KMP worst cases), deeply nested arrays, millions
  of tiny messages, collision-pressure inputs (neighbors maximizing
  fingerprint-equal / byte-different pairs), and maximal-density `},{`
  segmentation payloads.
* Span-shape instrumentation (blocks default-freeze): candidate reference
  corpora report a histogram of eligible spans — multi-line vs single-line
  vs over-cap share, per schema and role class — so stage-1b coverage of
  the line-model blind spot is measured, not assumed.
* **Success metric (provisional)**: median ≥40% token reduction on a
  golden log-heavy corpus spanning all schemas, measured across all five
  detectors combined. Token counts are computed **offline with a real
  tokenizer** (baseline TBD, §13.1); bytes/4 never gates acceptance.
  Tracked in CI reports; becomes blocking once the reference corpus is
  ratified (§13.4).
* **Task-quality eval (utility retention)**: the golden corpus is paired
  with a task suite — row lookup, count/aggregate, anomaly spotting,
  summarization — executed against baseline vs compressed prompts on at
  least two provider models; the metric is answer-parity per task class.
  Provisional, non-blocking gates: ≥90% parity on summarization/anomaly
  classes, ≥75% on extraction/counting classes. Reported in CI; promoted
  to blocking together with the token-reduction metric once the task suite
  is ratified (§13).
* Bench: criterion stage benchmarks wired to nightly regression gate.

## 13. Open questions

1. Ratify the offline tokenizer baseline gating the §12 success metric
   (o200k_base vs cl100k_base vs provider-specific). Decided rev 4: runtime
   stats stay bytes/4, labelled approximate (§4.5).
2. CCR store eviction policy under concurrent requests (TTL vs LRU-by-bytes)?
3. Should `/v1/detect` also report per-span estimated savings (helps callers
   decide whether to call compress at all)?
4. Ratify the reference corpus (sources, size, schema mix) behind the §12
   success metric, and confirm the ≥40% median target.
5. Ratify the task-quality suite (tasks, models, scoring) and its parity
   gates behind the §12 task-quality eval.
6. Extend stage 1b to further record separators (`", "` element lists,
   NDJSON-in-string) depending on the span-shape histogram (§12)?
