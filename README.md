# quantification

An LLM prompt-input compressor. It takes a chat-style JSON request body, finds
repeating lines and blocks inside the eligible user/tool string spans, and
replaces each committed group with one verbatim representative plus a marker
(`[... x4 rows, template a492 ...]`), cutting the input bytes — and therefore
the input tokens — before the request is sent upstream.

It is **lossless by construction everywhere it does not edit** (R3: the output
parses, and every byte outside a committed group is bit-identical, because the
output is a byte-range splice of the input, never a JSON reserialization) and
**intentionally lossy inside committed groups** (DESIGN.md §4.7): stages 3–5
keep the first copy of a run or block and a count, destroying every other copy;
stages 6–7 additionally destroy the masked field values (timestamps, IPs, uuids,
counters) of the dropped lines. It is not a general-purpose lossless compressor
and it does not replace zstd/gzip.

`DESIGN.md` is the normative design and the source of truth for behaviour; this
README describes what the code does today.

## Quick start

Requires a stable Rust toolchain (edition 2024) and `protoc` on `PATH` for
`quantification-proto`.

```sh
cargo run --release -p quantification-server
# quantification listening on http://127.0.0.1:8080 and grpc://127.0.0.1:50051
```

The binary reads exactly two environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `QUANT_HTTP_ADDR` | `127.0.0.1:8080` | axum HTTP bind address |
| `QUANT_GRPC_ADDR` | `127.0.0.1:50051` | tonic gRPC bind address |

HTTP and gRPC run in the same process, on the same event loop. There is no
config file and no other environment input.

Compress a request body:

```sh
curl -sS -D - -X POST -H 'Content-Type: application/json' \
  --data-binary '{"model":"gpt-4","messages":[{"role":"user","content":"2026-08-25T10:00:01Z INFO hc 10.0.0.1 took 1ms ok\n2026-08-25T10:00:02Z INFO hc 10.0.0.2 took 2ms ok\n2026-08-25T10:00:03Z INFO hc 10.0.0.3 took 3ms ok\n2026-08-25T10:00:04Z INFO hc 10.0.0.4 took 4ms ok\n2026-08-25T10:00:05Z INFO hc 10.0.0.5 took 5ms ok\n"}]}' \
  http://127.0.0.1:8080/v1/compress
```

Response (verified run, byte for byte apart from the `date` header):

```
HTTP/1.1 200 OK
content-type: application/json
x-stats-bytes-in: 314
x-stats-bytes-out: 142
x-stats-approx-tokens-in: 78
x-stats-approx-tokens-out: 35
x-stats-groups-collapsed: 1
x-stats-exact-runs: 0
x-stats-ws-runs: 0
x-stats-block-repeats: 0
x-stats-template-groups: 1
x-stats-templated-blocks: 0
x-stats-record-splits: 0
x-stats-degraded: false
x-stats-algo-version: 0.1.0
content-length: 142

{"model":"gpt-4","messages":[{"role":"user","content":"2026-08-25T10:00:01Z INFO hc 10.0.0.1 took 1ms ok[... x4 rows, template a492 ...]\n"}]}
```

314 bytes in, 142 out; the five near-identical log lines collapse to the first
line plus one template-group marker. `approx_tokens_*` is the `bytes/4` heuristic
and is reporting only — it never gates acceptance (DESIGN.md §4.5).

## Docker

There is **no Dockerfile and no published image in this tree at this commit**
(`git ls-files` has no image definition, and no CI workflow builds one). The
server is one executable driven by two env vars, so a minimal image is all it
needs; the recipe below is written against the facts verified above and has
**not** been built in this environment — neither the image tags nor the build
were exercised, because the container registry is unreachable from this
machine. It builds with the server's `ccr` feature on.

```dockerfile
# syntax=docker/dockerfile:1
FROM rust:1.98-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p quantification-server --features ccr

FROM debian:bookworm-slim
COPY --from=build /src/target/release/quantification-server /usr/local/bin/quantification-server
USER 65532:65532
ENV QUANT_HTTP_ADDR=0.0.0.0:8080 \
    QUANT_GRPC_ADDR=0.0.0.0:50051
EXPOSE 8080 50051
ENTRYPOINT ["/usr/local/bin/quantification-server"]
```

```sh
docker build -t quantification .
docker run --rm -p 8080:8080 -p 50051:50051 quantification
```

Both addresses must be set to `0.0.0.0:…` inside a container: the built-in
defaults bind `127.0.0.1`, which is unreachable from outside the container.

* 8080 = HTTP, 50051 = gRPC.
* With `--features ccr` (as above), `/v1/restore` and gRPC `Restore` are live and
  `reversible=true` returns `restore_ids`. Without the feature, `/v1/restore`
  answers `501 Not Implemented` with
  `{"error":{"code":"not_implemented","message":"the reversible store (DESIGN section 9) is disabled in this build; reversible=true stores no span, so no restore_id is returned"}}`
  and gRPC `Restore` returns `UNIMPLEMENTED` (both statuses verified over HTTP;
  the gRPC mapping is the same constant, asserted in `crates/server/src/grpc.rs`).
* `/metrics` exposes `quantification_build_info{algo_version="0.1.0",ccr="true"}`,
  so a running container reports whether it was built with the feature.

A minimal Kubernetes deployment consistent with that image:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: quantification
spec:
  replicas: 1
  selector:
    matchLabels: { app: quantification }
  template:
    metadata:
      labels: { app: quantification }
    spec:
      terminationGracePeriodSeconds: 30
      containers:
        - name: quantification
          image: quantification
          ports:
            - { name: http, containerPort: 8080 }
            - { name: grpc, containerPort: 50051 }
          env:
            - { name: QUANT_HTTP_ADDR, value: "0.0.0.0:8080" }
            - { name: QUANT_GRPC_ADDR, value: "0.0.0.0:50051" }
          readinessProbe:
            httpGet: { path: /readyz, port: http }
          livenessProbe:
            httpGet: { path: /healthz, port: http }
          securityContext:
            runAsNonRoot: true
            runAsUser: 65532
            runAsGroup: 65532
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: { drop: ["ALL"] }
            seccompProfile: { type: RuntimeDefault }
```

`/healthz` and `/readyz` are unconditional `200` static responses
(`{"status":"ok"}` / `{"status":"ready"}`) — they do not probe the gRPC listener
or the store. `terminationGracePeriodSeconds` is set to 30 s as a placeholder:
`main.rs` at this commit has no SIGTERM handling and no drain grace to match, so
this value has to be reconciled with the shutdown path when it lands.

## API

### HTTP (axum)

| Method | Path | Body → response |
|---|---|---|
| POST | `/v1/compress` | raw payload → spliced payload, stats in `X-Stats-*` headers |
| POST | `/v1/compress?envelope=json` | `{payload, options, content_type?}` → `{payload, stats}`, no stats headers |
| POST | `/v1/detect` | payload → `{schema, scope_policy, span_count, spans_truncated, spans[…], degraded, noop_reason}` (first 64 spans) |
| POST | `/v1/restore` | compressed bytes + `?restore_id=<id>` (or `?envelope=json`) → the stored original, `application/octet-stream`; 501 without the `ccr` feature, 404 on a miss |
| GET | `/healthz` | `{"status":"ok"}` |
| GET | `/readyz` | `{"status":"ready"}` |
| GET | `/metrics` | Prometheus text: `quantification_http_requests_total`, `quantification_payload_bytes_total`, `quantification_pass_through_total`, `quantification_build_info` |

`POST /v1/compress` echoes the request's `Content-Type` on the response when one
is sent, and `application/json` otherwise. `?envelope=json` refuses every other
query key (`400`); the bare form refuses every key except the six options below
plus `content_type`. Unknown query keys are `400 invalid_argument`.

The `X-Stats-*` header set is exactly: `Bytes-In`, `Bytes-Out`,
`Approx-Tokens-In`, `Approx-Tokens-Out`, `Groups-Collapsed`, `Exact-Runs`,
`Ws-Runs`, `Block-Repeats`, `Template-Groups`, `Templated-Blocks`,
`Record-Splits`, `Degraded`, `Algo-Version`, plus `Noop-Reason` only when the
response degraded. `elapsed_*_ns`, `options_echo` and `restore_ids` are
envelope/gRPC only. Header names are emitted lowercase (HTTP header names are
case-insensitive).

### gRPC (tonic) — unary only

Service `compressor.v1.Compressor`, defined in
`crates/proto/compressor/v1/compressor.proto`, no streaming RPCs:

| RPC | Notes |
|---|---|
| `Compress(CompressRequest) → CompressResponse` | `payload`, `content_type`, `scope_policy`, `options`; full `Stats` message back |
| `Restore(RestoreRequest) → RestoreResponse` | `UNIMPLEMENTED` unless the `ccr` feature is on and a store is wired; `NOT_FOUND` on a miss |

`max_decoding_message_size` is the same 64 MiB `request_body_limit` as HTTP. No
server reflection is registered. gRPC and HTTP produce identical payload bytes
and identical stats, asserted end-to-end over a real socket in
`crates/server/tests/grpc.rs`.

### Options

Queryable on the bare form and settable in the `?envelope=json` body. gRPC
carries the same six in `Options`.

| Option | Values | Default | Effect |
|---|---|---|---|
| `scope_policy` | `user_content`, `user_and_tools` | `user_content` | which span classes are rewritten; `all_messages` and `explicit_paths` parse but are refused as `400 invalid_options` |
| `min_group_size` | integer ≥ 2 (`0` ⇒ default) | `3` | minimum group size for the run/template detectors; `1` is `400` |
| `normalize_ws` | `true` / `false` | `true` | enables stage 4 (ws-normalized runs) |
| `template_dedup` | `true` / `false` | `true` | enables stages 6 and 7 (template groups, templated blocks) |
| `marker_style` | `auto`, `ascii`, `unicode` | `auto` | `auto` picks ascii for an all-ASCII span, unicode otherwise, per span |
| `reversible` | `true` / `false` | `false` | store committed originals and return `restore_ids`; needs the `ccr` feature, otherwise nothing is stored and no id is returned |

There is also a `content_type` pin (`chat`, `responses`, `messages`, `text`),
separate from the options. The resolved values are echoed back as
`options_echo` in the envelope and gRPC responses.

Frozen internal limits (`crates/core/src/config.rs`): `min_block_lines` 2,
`max_block_lines` 64, `max_line_bytes` 64 KiB, `max_record_bytes` 16 KiB,
`max_span_bytes` 32 MiB (larger spans are skipped, not degraded),
`json_depth_cap` 64, `request_body_limit` 64 MiB (over it: `413`).

### Error contract

Compression is designed to be safe to skip, so pass-through is the normal
failure mode:

| Situation | Result |
|---|---|
| Sniffs as no known schema | `200`, payload byte-identical, `degraded=true`, `noop_reason=unknown_schema` |
| Malformed / truncated / over the depth cap | `200`, payload byte-identical, `degraded=true`, `noop_reason=malformed` |
| Nothing profitable to collapse | `200`, payload byte-identical, `degraded=false` |
| A `content_type` pin that the payload contradicts | `422`, `content_type_mismatch` (gRPC: `InvalidArgument`) |
| Bad option value, unknown query key, bad envelope | `400`, `invalid_options` / `invalid_argument` |
| `strict_validate` build and a payload that does not parse | `400`, `malformed` |
| Body over 64 MiB | `413` |
| `/v1/restore` without the `ccr` feature | `501`; unknown or expired id with it: `404` |

`422` is reserved for an explicitly pinned `content_type` and never fires on its
own.

## How it works

Four phases, no JSON reserialization anywhere:

1. **Schema sniff** — a single scan of the first 64 KiB for a fixed candidate
   order (chat → responses → messages → text); a leading BOM is skipped.
2. **Span locate** — an escape-aware single-pass byte scanner, not a JSON parser.
   It records `(start, end)` byte ranges of the eligible string values
   (`messages[].content`, `[{type:"text",text}]` parts, Responses `input` /
   `function_call_output.output`, Anthropic `tool_result.content`) and never
   unescapes anything. Duplicate object keys: last occurrence wins. Structural
   keys are matched on their decoded form, so `"\u0072ole"` still matches `role`.
3. **Per-span compaction** — every span is processed independently, in strict
   stage order, each stage seeing only what earlier stages left:

   | Stage | Detector | Comparison domain |
   |---|---|---|
   | 1 | line split on the literal `\n` / `\u000A` escape units | — |
   | 1b | record split of over-cap lines on `},{` | — |
   | 2 | xxh3-128 fingerprint per unit (verified length → hash → memcmp) | raw |
   | 3 | exact runs | raw bytes |
   | 4 | ws-normalized runs | ws-normalized |
   | 5 | repeated blocks, windowed scan, period 2…64 | ws-normalized |
   | 6 | template groups (mask list) of size ≥ `min_group_size` | masked form |
   | 7 | templated blocks, the same windowed scan over stage-6 template ids | template ids |

   The mask list is fixed and prioritized: `{ts}` → `<ts>`, `{ip}` → `<ip>`,
   `{uuid}` → `<uuid>`, `{hex}` → `<hex>`, `{dur}` → `<dur>`, `{num}` → `<num>`,
   applied leftmost-longest, by hand-written byte automata.

4. **Splice** — the output is the input buffer with the committed byte ranges
   overwritten. This is why untouched regions are bit-identical by construction.

### Markers

`MARKER := OPEN CORE SEP CHECKSUM CLOSE`, where the checksum is 4 lowercase hex
digits — bits 0–15 of xxh3-64 of the raw anchor bytes. One real example of each
of the five kinds, all produced by the server, ascii and unicode forms:

| Kind | ASCII | Unicode |
|---|---|---|
| exact run | `[... x3 identical a492 ...]` | `⟪×3 identical ·a492⟫` |
| ws run | `[... x5 rows, ws-equal 915d ...]` | `⟪×5 rows, ws-equal ·915d⟫` |
| repeated block | `[... block x2 52ed ...]` | `⟪block ×2 ·52ed⟫` |
| template group | `[... x4 rows, template a492 ...]` | `⟪×4 rows, template ·a492⟫` |
| templated block | `[... templated block x2 9394 ...]` | `⟪templated block ×2 ·9394⟫` |

Markers contain no `"`, `\` or control character, so they need no re-escaping
inside a JSON string.

### Profitability gate

A group or block is committed only when

```
anchor_bytes + marker_bytes < removed_bytes
```

where `removed_bytes` is the exact byte range the marker replaces (member units
plus the joiners between them) and `marker_bytes` includes the decimal width of
the emitted count. Below the threshold the lines are kept verbatim. This is why
a group of three short lines often survives: three `GET /a 200 Nms` lines are
not collapsed at any `min_group_size` (verified: 92 → 92 bytes, 0 groups),
while four are (108 → 92 bytes, 1 template group).

### Determinism

Same input bytes ⇒ bitwise-identical output bytes. Fixed-seed xxh3 only, no
`RandomState` on any output path, integer arithmetic only, no clock/RNG/env/
thread-count influence, markers emitted strictly in anchor byte order, and
recompression of the output is a fixed point. `algo_version` (`0.1.0`) is
exposed in the stats and as `X-Stats-Algo-Version` so callers can detect a
cross-release output change.

Verified here at 8222e97: 1000 runs over the 36-entry gate corpus (26 golden
fixtures + 10 adversarial cases, 847,098 bytes) are byte-equal, and the
`x86-64` and `x86-64-v3` builds produce identical digests.

## Options that bite

* **Newlines must be escaped.** The splitter works on raw escaped bytes, so it
  splits on the two-byte sequence `\n` (or the escape units `\u000A` /
  `\u000a`). A plain-text body with raw LF bytes is one span, one unit, and does
  not compress: verified, a 150-byte raw-LF text body with three near-identical
  lines comes back as 150 bytes with `groups_collapsed=0` and
  `degraded=false`, while the same content with `\n` escapes collapses to a
  template group.
* **Default scope is `user_content` only.** `role:"tool"` spans are left
  verbatim. Verified on a body with one `tool` and one `user` message: default
  collapses only the user message; `?scope_policy=user_and_tools` collapses both.
  Agent traffic usually puts the bulkiest dumps in tool messages, so
  `user_and_tools` is usually the right setting (DESIGN.md §4.3).
* **`min_group_size` default 3 is a floor, not a promise.** A 3-line group is
  still subject to the profitability gate, and for short lines it usually fails
  it (see above). Lower it to `2` to make the run/template detectors eligible for
  smaller groups; note the gate still applies, so `min_group_size=2` alone does
  not collapse a 2-line group of short lines (verified: 76 → 76 bytes).
* **`reversible=true` is what produces `restore_ids`, and it needs the `ccr`
  feature.** Without the feature the option resolves fine, nothing is stored,
  `restore_ids` comes back empty, and `/v1/restore` is `501`. With the feature
  the ids are `xxh3-128(span) ":" decimal_length` and restore re-verifies length
  and hash before returning anything. Verified:
  `restore_ids: ["ca095a8e313865daf918a2d5c6b85246:62"]` for a 62-byte span,
  and that id returning the original 62 bytes.
* **Assembled payloads can be larger than the log they carry.** A single
  all-distinct line never collapses; `content: null`, `system` and assistant
  spans are never eligible.

## Development

```sh
cargo test --workspace                 # 529 passed, 0 failed, 6 ignored
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

The 6 ignored tests are the long-running ones CI drives explicitly: the 1000-run
byte-stability gate, the 200,000-run nightly soak (chunked, 8 ways), the
cross-process fuzz-corpus replay, the ISA-leg aggregator, and the golden
generator `write_the_chat_goldens`. CI runs `cargo nextest run --workspace` and
`cargo deny check` in addition to fmt and clippy.

Feature states:

| Feature | Crate | Effect |
|---|---|---|
| `strict_validate` | `quantification-core` | full JSON parse before compressing; a payload that does not parse becomes a typed `malformed` error instead of a `degraded` pass-through |
| `bench_stages` | `quantification-core` | per-stage timing (`StageTimes`) and the two benches; `--all-targets` does not cover it, so the perf workflow clippies it separately |
| `ccr` | `quantification-server` | wires the reversible store; enables `/v1/restore`, gRPC `Restore` and `restore_ids` |

`cargo test --workspace --all-features` is the union of those three.

Fuzzing is a standalone crate (`fuzz/`, excluded from the workspace) with four
targets: `fuzz_sniff`, `fuzz_locator`, `fuzz_splitter`, `fuzz_pipeline`.

```sh
cd fuzz
cargo fuzz run fuzz_pipeline --sanitizer address -- -runs=200
```

It **needs a nightly toolchain** — `cargo fuzz` passes `-Zsanitizer=address`
unconditionally. The CI workflow (`.github/workflows/fuzz.yml`) installs
`dtolnay/rust-toolchain@nightly` + `cargo-fuzz` and runs 200 ASan execs of every
target per PR and 15 minutes per target nightly; any crash artifact fails the
job.

Performance gate (DESIGN.md §8 / gate M3), pinned core, warm, p50 and p99, with
a per-stage breakdown:

```sh
taskset -c 2 cargo bench -p quantification-core \
  --features bench_stages --bench gate -- --iters 30 --json target/perf-gate.json
```

It exits non-zero on any failed check. `cargo bench -p quantification-core
--features bench_stages --bench stages` is the separate per-stage criterion
suite.

Building `quantification-proto` requires `protoc` on `PATH` (verified: building
with `PROTOC=/nonexistent/protoc` fails with prost-build's "Could not find
`protoc`"). Nothing else needs system packages.

## Project layout

```
Cargo.toml                workspace: core, eval, proto, server (fuzz/ excluded)
DESIGN.md                 the normative design
AGENTS.md                 repo conventions
crates/core/              the pure compressor library
crates/proto/             compressor.proto + tonic/prost build
crates/server/            the binary: axum routes, tonic service, config
crates/eval/              offline token/task eval harness (quant-eval)
fuzz/                     cargo-fuzz targets and corpus
.github/workflows/        ci, determinism, fuzz, perf, eval
```

| Crate | What it does |
|---|---|
| `quantification-core` | the whole algorithm, bytes in → bytes + `Stats` out. No tokio, no clocks, no IO. `sniff` (schema), `locator` (span ranges), `stage1`/`stage1b` (line/record split), `detect/{exact,wsruns,blocks,templ,templ_blocks}` (stages 3–7), `mask` (the fixed mask list), `wsnorm`, `fingerprint`, `ledger` (commit admission, profitability gate, marker grammar), `render`, `splice`, `pipeline` (the driver), `ccr` (reversible store), `config` (frozen limits and option resolution) |
| `quantification-proto` | `compressor.proto`, `tonic-prost-build`, and the `compressor.v1` types plus core conversion |
| `quantification-server` | `main.rs` (env vars, both listeners), the axum app (`lib.rs`), HTTP option/envelope parsing (`options.rs`), stats headers (`headers.rs`), the tonic service (`grpc.rs`), Prometheus metrics |
| `quantification-eval` | the `quant-eval` binary: real-tokenizer token reduction per corpus stratum and the four task-quality classes with injectable providers. Reporting-only; see `crates/eval/README.md` |

`quantification-core` is the primary integration surface as a library; the
transports are thin and their body-copy costs sit outside the core budget.

## Status and known limits

The algorithm, both transports, the CCR store, the determinism gates and the
fuzz targets exist and are tested. The following are **not** done, and are
recorded as open in the repo history:

* **The per-stage compaction budget is still exceeded.** On this checkout, on an
  Intel i7-9700K pinned to one core, the M3 gate over an 8,399,344-byte
  log-heavy chat payload (77,000 units, compressed to 76,878 bytes, 300 groups)
  reports p50 aggregate 80.9 ms / 103.8 MB/s, detect 7.1 ms, **compaction 73.7 ms
  / 113.9 MB/s**, splice 0.04 ms. Verdict `M3 FAIL`: the aggregate ≥100 MB/s
  floor passes, as do the detect and splice budgets, but the ≤50 ms compaction
  budget, its ≥160 MB/s floor, and the R2 ≤80 ms aggregate budget all fail.
  Reproduced across runs; this is a property of the code on this hardware, not
  measurement noise. `stage6_masked_forms` (34%) and `stage5_blocks` (26%) are
  the two hot stages.
* **The offline evaluation targets are unratified, so every measured reduction
  figure is provisional.** DESIGN.md §13.1 (tokenizer baseline), §13.4
  (reference corpus) and §13.5 (task suite) are open, and the harness refuses
  to gate on them. On the harness's own 8-payload log-heavy stratum the
  `o200k_base` median token reduction is 90.0% (min 44.1%, max 91.7%) and
  `cl100k_base` 89.9%; the golden stratum is 16.9% and the adversarial stratum
  0.0% median. Those populations are the harness's own, not a ratified corpus.
  The task-quality parity gates report `NOT MEASURED` because no provider was
  called — the harness never calls a model without `QUANT_EVAL_PROVIDER_CMD`
  and credentials.
* **The ARM/NEON determinism leg is reported unavailable, not verified.** On this
  x86-64 machine the ISA matrix ran the `x86-64` and `x86-64-v3` legs and they
  agree byte for byte; the `neon` leg was declared unavailable. The DESIGN.md
  §5.9 matrix has three legs and only two were executed.
* **Fuzzing has not been run in this environment.** Only the stable toolchain is
  installed and `rustup toolchain install nightly` cannot reach
  `static.rust-lang.org` from here, so `cargo fuzz` cannot build at all — it is
  not a matter of dropping the sanitizer, the `-Zsanitizer` flag requires nightly
  outright. The targets compile only under `cargo fuzz`'s own build. The
  CI-runs-only fuzz legs (ASan smoke, 15-minute soak, retained-corpus
  determinism replay) have therefore not been exercised locally.

Also open, and worth knowing before relying on this:

* `cargo test --workspace --all-features` is not reliably green:
  `quantification-eval`'s `the_command_transport_pipes_the_prompt_and_reports_a_missing_program`
  fails intermittently ("`/bin/sh` did not finish"). `Injected::run_command`
  requires the stdin writer to succeed before it reports the child's exit
  status, and `sh -c 'exit 3'` closes stdin immediately, so the assertion on
  "exited with" races a `EPIPE`. `cargo test --workspace` with default features
  is stable.
* Only the `user_content` and `user_and_tools` scopes exist; `all_messages` and
  `explicit_paths` parse and are then refused. v2 items (Drain-style fuzzy
  clustering, custom masks, non-consecutive dedup, value-preserving collapses)
  are unimplemented by design (§10).
* Compression rewrites bytes, so compressing mid-conversation invalidates
  provider prompt caches for the changed prefix. Compress once when a payload is
  assembled and reuse the identical bytes afterwards; determinism is what makes
  that workable (DESIGN.md §11).
* A payload that literally contains marker-shaped text is not defended against.
  Documented, not handled (DESIGN.md §4.5).
