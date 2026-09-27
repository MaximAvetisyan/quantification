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
# quantification listening on http://127.0.0.1:8080 and grpc://127.0.0.1:50051 (draining for 25000ms on SIGTERM/SIGINT)
```

The binary reads exactly three environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `QUANT_HTTP_ADDR` | `127.0.0.1:8080` | axum HTTP bind address |
| `QUANT_GRPC_ADDR` | `127.0.0.1:50051` | tonic gRPC bind address |
| `QUANT_SHUTDOWN_GRACE_MS` | `25000` | total drain budget after `SIGTERM`/`SIGINT`; anything that is not a whole number of milliseconds is a startup error (`quantification: QUANT_SHUTDOWN_GRACE_MS=soon is not a whole number of milliseconds`, exit 1) |

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

There is a `Dockerfile` at the repo root, and a `.dockerignore` beside it. It is
an allowlist: everything is excluded, and only `Cargo.toml`, `Cargo.lock`,
`.cargo`/`**` and `crates` are re-included, minus `crates/**/tests`. Measured
by exporting the context (`FROM scratch` + `COPY . /ctx`, no registry needed)
on this checkout, that takes it from **1,554,856 bytes in 122 files to 334,600
bytes in 51** — the 71 excluded files are the `tests/` trees, 1,220,256 bytes
of it, almost all the `crates/core/tests` fixture corpus, and a fixture edit
would otherwise invalidate the `COPY . .` layer and force a full rebuild of
every crate. `crates/**/benches` is deliberately **kept**:
`crates/core/Cargo.toml` declares `[[bench]]` targets, and cargo hard-errors on
a missing declared bench file (`can't find 'gate' bench at 'benches/gate.rs'`
— reproduced). `.cargo` is re-included rather than dropped because a
repo-level `.cargo/config.toml` is a common Rust setting and, under a bare `*`
allowlist, it would vanish silently and change the build — also reproduced.
It is a two-stage build:

* **build** — `rust:1.98-bookworm`, with `protobuf-compiler` installed for
  `quantification-proto`'s `tonic-prost-build`, thin LTO and one codegen unit.
  It stubs every workspace member and builds once to warm the dependency cache,
  copies the real sources, touches every `crates/**/*.rs` (`COPY` preserves
  source mtimes, which would otherwise leave cargo believing the stubs are
  current), and builds `quantification-server` with `--locked --features ccr`.
* **runtime** — `gcr.io/distroless/cc-debian12`: the release binary at
  `/usr/local/bin/quantification-server`, `USER 65532:65532`, no shell and no
  package manager, `STOPSIGNAL SIGTERM`, `EXPOSE 8080 50051`.

  The `USER` line is **numeric on purpose**. A `USER nonroot:nonroot` resolves
  against `/etc/passwd` in the image, and whether `gcr.io/distroless/cc-debian12`
  carries a `nonroot` entry is not something this tree can verify. The failure
  mode is lopsided: a pod would still start, because the manifest's
  `runAsUser: 65532` overrides `USER` — but a plain `docker run`, which the
  quickstart below tells people to use, would fail with "unable to find user".
  `65532:65532` is unconditionally correct and is the same value
  `k8s/quantification.yaml` sets.

```sh
docker build -t quantification .
docker run --rm -p 8080:8080 -p 50051:50051 quantification
```

* 8080 = HTTP, 50051 = gRPC.
* The image sets `QUANT_HTTP_ADDR=0.0.0.0:8080` and
  `QUANT_GRPC_ADDR=0.0.0.0:50051`: both addresses must be `0.0.0.0:…` inside a
  container, because the built-in defaults bind `127.0.0.1`, which is
  unreachable from outside it. `QUANT_SHUTDOWN_GRACE_MS` is not set, so the
  25 s default applies; pass `-e QUANT_SHUTDOWN_GRACE_MS=…` to change it.
* The `ccr` feature is compiled in, so `/v1/restore` and gRPC `Restore` are
  live and `reversible=true` returns `restore_ids`. `/metrics` reports
  `quantification_build_info{algo_version="0.1.0",ccr="true"}`, which is how a
  running container tells you it has the feature. Without the feature
  `/v1/restore` answers `501 Not Implemented` with
  `{"error":{"code":"not_implemented","message":"the reversible store (DESIGN section 9) is disabled in this build; reversible=true stores no span, so no restore_id is returned"}}`
  and gRPC `Restore` returns `UNIMPLEMENTED` (the same constant, asserted in
  `crates/server/src/grpc.rs`); both statuses verified over HTTP.

**The image has still never been built in the environment this was written
in.** No container registry is reachable from this machine — a
`docker pull rust:1.98-bookworm` fails right now with `net/http: TLS handshake
timeout` — so neither base image can be fetched and no image is assembled here.
What was run natively is the content of every build step: the same `cargo
build --release --locked -p quantification-server --features ccr`, the release
binary started and exercised over real sockets, and `ldd` on it, which needs
only `libgcc_s.so.1`, `libm.so.6`, `libc.so.6` and `ld-linux-x86-64.so.2` — no
`libssl`, no `libstdc++`, so the binary does fit `cc-debian12`. That is not the
same thing as a built image, and it is not a claim that the runtime stage, the
ports or the `ENTRYPOINT` have been observed working.

**CI now executes it.** The `image` job in `.github/workflows/ci.yml` runs
`docker build -t quantification:ci .` and then a `docker run` smoke test —
wait for `/healthz`, `POST /v1/compress` a real payload and assert a `200` with
a non-empty body, assert `/v1/restore` is not a `501`, then stop the container —
on every push to `master` and every pull request, and it fails the build if any
of that fails. GitHub's runners do have working registry access, so that job is
the first thing that will ever actually assemble this image, and the first
evidence that `USER 65532:65532` resolves. Until it has been green once, the
Dockerfile is reviewed-but-unbuilt; it is no longer never-executed.

### Kubernetes

`k8s/quantification.yaml` holds a `Deployment` and a `Service` for that image,
and `k8s/README.md` is the contract the manifest assumes; read it for the
details. Five things in it interact with the server's own behaviour:

* `terminationGracePeriodSeconds: 30` against the container's
  `QUANT_SHUTDOWN_GRACE_MS: "25000"`. The grace period has to stay above the
  drain budget: the kubelet starts it at `SIGTERM`, and if it expires first the
  process is `SIGKILL`ed mid-drain. The manifest sets the grace explicitly so
  the relationship is auditable in the manifest instead of being whatever the
  binary happens to default to.
* `replicas: 1` is a **steady-state constraint for `/v1/restore`, not a scaling
  knob**: the CCR store is per-pod and in-process, so a `restore_id` only
  resolves on the pod that issued it, and a second replica can answer a valid id
  with `404`. Compression itself is stateless and scales.
* **`RollingUpdate` with `maxSurge: 1, maxUnavailable: 0` does not close that
  hole, and `replicas: 1` does not close it either.** `maxUnavailable: 0` is
  precisely why the old and new pods *coexist*: both are Ready, both are in the
  Service endpoints, each has its own empty store, and the old pod is not sent
  `SIGTERM` until the new one is Ready. So a compress on the old pod and a
  restore on the new one is the same `404`, reintroduced on **every deploy**,
  node drain and eviction. `replicas: 1` bounds *steady-state* exposure to one
  pod; it was never buying rollout safety.
* Therefore a **`404` from `/v1/restore` has two legitimate causes** — the id
  expired (15-min TTL) or was evicted (64 MiB bound), *or* the compress and the
  restore landed on different pods during a rollout — and the response cannot
  distinguish them. `404` is not the assertion "this id never existed". Callers
  must treat a restore miss as **non-fatal and retryable** and proceed with the
  compressed bytes, which are the deliverable. `k8s/README.md` gives the two
  recipes for real consistency — `strategy: {type: Recreate}` (full downtime per
  deploy, correct only at one replica, and still not across the deploy boundary
  itself) and moving the store out of process (the real fix, and the one
  recommended if restore is load-bearing) — with the trade-offs.
* `readinessProbe` on `/readyz` at `periodSeconds: 1, failureThreshold: 1`, and
  `livenessProbe` on `/healthz` at `periodSeconds: 10`: the drain flips
  `/readyz` to `503`, and the pod has to leave the Service endpoints before the
  listener closes ~2 s later. Of that 2 s settle, up to ~1 s is spent waiting
  for the kubelet's next probe to even observe the flip, so the dataplane
  propagation budget is roughly **1 s, not 2 s**. `progressDeadlineSeconds: 120`
  (default 600) turns a wedged rollout into a `Failed` condition in two minutes
  instead of ten; with `maxUnavailable: 0` it costs no availability.

`/healthz` is an unconditional `200 {"status":"ok"}` and deliberately stays that
way for the whole drain: it is the liveness probe, and a red liveness probe
would have the kubelet restart the pod in the middle of finishing in-flight
requests. `/readyz` is the drain-aware one; neither probes the gRPC listener or
the store. The manifest itself has never been applied to a cluster.

## API

### HTTP (axum)

| Method | Path | Body → response |
|---|---|---|
| POST | `/v1/compress` | raw payload → spliced payload, stats in `X-Stats-*` headers |
| POST | `/v1/compress?envelope=json` | `{payload, options, content_type?}` → `{payload, stats}`, no stats headers |
| POST | `/v1/detect` | payload → `{schema, scope_policy, span_count, spans_truncated, spans[…], degraded, noop_reason}` (first 64 spans) |
| POST | `/v1/restore` | compressed bytes + `?restore_id=<id>` (or `?envelope=json`) → the stored original, `application/octet-stream`; 501 without the `ccr` feature, 404 on a miss |
| GET | `/healthz` | `{"status":"ok"}`, an unconditional `200` for the whole life of the process, drain included |
| GET | `/readyz` | `{"status":"ready"}` while serving; `503 {"status":"draining"}` from the instant of `SIGTERM`/`SIGINT` until the process exits |
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

### Shutdown

On `SIGTERM` or `SIGINT` the process latches a drain, in this order
(`crates/server/src/{main.rs,lib.rs}`):

1. `/readyz` starts answering `503 {"status":"draining"}`, before the listener
   closes, so the pod leaves the Service endpoints while it is still reachable;
2. an endpoint settle of `min(QUANT_SHUTDOWN_GRACE_MS / 4, 2000)` ms — 2000 ms at
   the 25 s default — with both transports still polled, so a request arriving
   in that window is served rather than left in the accept queue;
3. the graceful-shutdown signal is released: both listeners stop accepting and
   in-flight HTTP and gRPC work finishes, bounded by the whole
   `QUANT_SHUTDOWN_GRACE_MS`.

Exit code is 0 on a clean signal-initiated drain, 1 if either transport fails
(the other is drained too, deliberately: a pod serving one transport with the
other dead is worse than a restarted pod), 2 if the grace expires. `/healthz`
stays `200` throughout so the kubelet does not restart the pod mid-drain, and
`/metrics` is unaffected. `crates/server/tests/shutdown.rs` pins all of it,
including that the output bytes and stats headers are identical before and after
a drain.

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
| `/v1/restore` without the `ccr` feature | `501`; a miss with it: `404` — either the id expired/evicted, or (in a multi-pod deployment) the compress and the restore landed on different pods. A `404` is non-fatal and retryable, never "this id never existed" |

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
inside a JSON string. The checksum is a function of the anchor bytes and nothing
else, so it is not comparable across payloads: the anchor is the first line for
the run and template-group kinds (hence `a492` twice above — it is the same
first log line) and the entire first occurrence for the two block kinds. Change
one byte of the anchor and the four hex digits change; recompute them with
`quantification_core::fingerprint::marker_checksum` rather than expecting a
particular value.

### Profitability gate

A group or block is committed only when

```
anchor_bytes + marker_bytes < removed_bytes
```

where `removed_bytes` is the exact byte range the marker replaces (member units
plus the joiners between them) and `marker_bytes` includes the decimal width of
the emitted count. Below the threshold the lines are kept verbatim. This is why
a group of three short lines often survives. Measured on one body
(`{"model":"gpt-4","messages":[{"role":"user","content":…}]}`, `GET /a 200 Nms`
lines, default options): two lines 89 → 89 bytes and three lines 105 → 105
bytes, 0 groups, at `min_group_size` 2 and 3 alike, while four lines collapse
121 → 105 bytes with 1 template group. The comparison is byte-exact, so a
one-byte-longer marker flips a borderline group: those same three lines *do*
commit under `marker_style=unicode` (105 → 104 bytes, 1 template group), the
unicode marker being one byte shorter than the ascii one.

### Determinism

Same input bytes ⇒ bitwise-identical output bytes. Fixed-seed xxh3 only, no
`RandomState` on any output path, integer arithmetic only, no clock/RNG/env/
thread-count influence, markers emitted strictly in anchor byte order, and
recompression of the output is a fixed point. `algo_version` (`0.1.0`) is
exposed in the stats and as `X-Stats-Algo-Version` so callers can detect a
cross-release output change.

Re-verified on this checkout: `gate_outputs_are_byte_stable_over_1000_runs`
(the ignored §5.8 quick gate, run in release) reports `1000 runs over 36
entries (847098 bytes)`, all byte-equal, in 11 s. The CPU-feature half of the
§5.9 matrix was not re-run — see the ARM/NEON bullet under known limits.

## Options that bite

* **Newlines must be escaped.** The splitter works on raw escaped bytes, so it
  splits on the two-byte sequence `\n` (or the escape units `\u000A` /
  `\u000a`). A plain-text body with raw LF bytes is one span, one unit, and does
  not compress: verified, a 135-byte raw-LF text body with three near-identical
  lines comes back as 135 bytes with `groups_collapsed=0` and
  `degraded=false`, while the same three lines as a chat `content` span with
  `\n` escapes collapse to one template group (195 → 135 bytes).
* **Default scope is `user_content` only.** `role:"tool"` spans are left
  verbatim. Verified on a body with one `tool` and one `user` message, four
  `GET /a`-style lines each: default 196 → 180 bytes with 1 template group,
  `?scope_policy=user_and_tools` 196 → 164 bytes with 2.
  Agent traffic usually puts the bulkiest dumps in tool messages, so
  `user_and_tools` is usually the right setting (DESIGN.md §4.3).
* **`min_group_size` default 3 is a floor, not a promise.** A 3-line group is
  still subject to the profitability gate, and for short lines it usually fails
  it (see above). Lower it to `2` to make the run/template detectors eligible for
  smaller groups; note the gate still applies, so `min_group_size=2` alone does
  not collapse a 2-line group of short lines (verified: 89 → 89 bytes).
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
cargo test --workspace                 # 538 passed, 0 failed, 6 ignored
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

The 6 ignored tests are the long-running ones CI drives explicitly: the 1000-run
byte-stability gate, the 200,000-run nightly soak in two tests (a 1-of-8 chunk
and the aggregator that checks the chunks sum to the whole), the cross-process
fuzz-corpus replay, the ISA-leg matrix, and the golden generator
`write_the_chat_goldens`. CI runs `cargo nextest run --workspace` and
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
Dockerfile                the two-stage image; .dockerignore keeps the context to the workspace
k8s/                      Deployment + Service for that image, and the contract they assume
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
| `quantification-server` | `main.rs` (env vars, signal handling, both listeners), the axum app and the drain in `lib.rs` (`serve`, `State::drain`, `shutdown_grace`), HTTP option/envelope parsing (`options.rs`), stats headers (`headers.rs`), the tonic service (`grpc.rs`), Prometheus metrics |
| `quantification-eval` | the `quant-eval` binary: real-tokenizer token reduction per corpus stratum and the four task-quality classes with injectable providers. Reporting-only; see `crates/eval/README.md` |

`quantification-core` is the primary integration surface as a library; the
transports are thin and their body-copy costs sit outside the core budget.

## Status and known limits

The algorithm, both transports, the CCR store, the determinism gates and the
fuzz targets exist and are tested. The following are **not** done, and are
recorded as open in the repo history:

* **The compaction budget is exceeded on every run, and the aggregate floor is
  borderline.** Re-measured on this checkout with the documented protocol
  (`taskset -c 2`, 3 warmups discarded, 30 iterations, p50), seven runs of the
  M3 gate over the 8,399,344-byte log-heavy chat payload (77,000 units,
  compressed to 76,878 bytes, 300 groups) on an Intel i7-9700K (8 logical CPUs,
  `powersave` governor, load average ~5.7 from other work on the box) give:

  | metric | p50 across the 7 runs | throughput across the 7 runs |
  |---|---|---|
  | aggregate | 80.0–88.8 ms | 94.6–104.9 MB/s |
  | detect | 7.1–7.8 ms | 1083–1185 MB/s |
  | compaction | 72.9–81.0 ms | 103.7–115.2 MB/s |
  | splice | 0.04 ms | not gated |

  Verdict `M3 FAIL` in all seven runs: the ≤50 ms compaction budget, its
  ≥160 MB/s floor and the R2 ≤80 ms aggregate budget fail every time, and the
  aggregate ≥100 MB/s floor fails in 4 of the 7 (it passed at 101.7, 104.6 and
  104.9 MB/s, so on this hardware it sits on the line and the box's load is part
  of the answer). The detect (≤20 ms, ≥400 MB/s) and splice (≤10 ms) budgets
  pass in every run. The compaction overrun is ~1.5× the budget and is not
  measurement noise; `stage6_masked_forms` (34–36% of compaction) and
  `stage5_blocks` (25–26%) are the two hot stages. Treat the aggregate figure as
  "at the floor, machine-dependent", not as a pass.
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
* **The ARM/NEON determinism leg is reported unavailable, not verified.** The
  §5.9 matrix has three legs; the last local run of it executed `x86-64` and
  `x86-64-v3`, which agree byte for byte, and declared `neon` unavailable. Only
  two of the three legs have ever run on real hardware.
* **Fuzzing has not been run in this environment.** Only the stable toolchain is
  installed and `rustup toolchain install nightly` cannot reach
  `static.rust-lang.org` from here, so `cargo fuzz` cannot build at all — it is
  not a matter of dropping the sanitizer, the `-Zsanitizer` flag requires nightly
  outright. The targets compile only under `cargo fuzz`'s own build. The
  CI-runs-only fuzz legs (ASan smoke, 15-minute soak, retained-corpus
  determinism replay) have therefore not been exercised locally.
* **The container image has never been built, and the manifest has never been
  applied to a cluster.** No registry is reachable from this machine — a
  `docker pull rust:1.98-bookworm` fails here today with `net/http: TLS
  handshake timeout` — so neither base image can be fetched and no image exists
  locally. What was done is native: the same `cargo build --release --locked …
  --features ccr`, the binary started and exercised over real sockets, and
  `ldd` on it. The drain behaviour, the distroless runtime stage and the probes
  are therefore read off the source, not observed on a pod. The `image` job in
  `.github/workflows/ci.yml` now runs `docker build` and a `docker run` smoke
  test on every push and pull request, so the first actual assembly of the image
  will happen there rather than here; `kubectl`, `kubeconform` and `yamllint`
  are not installed, so the manifest has had **no schema validation at all**,
  only a structural re-check of selectors, probe port names, targetPorts and
  the grace-above-drain relationship. See the Docker section above and
  `k8s/README.md`.

Also open, and worth knowing before relying on this:

* The command transport's stdin-write/exit race is fixed, not merely quiet.
  `Injected::run_command` (`crates/eval/src/tasks.rs`) no longer lets the
  prompt write veto the report: the read error, the write error and the exit
  status are collected separately and judged in priority order — no status,
  then a non-success status, then a read error, then a write error — and
  `ErrorKind::BrokenPipe` on the stdin write is a normal outcome rather than a
  failure. It is pinned by
  `a_child_that_closes_stdin_early_is_reported_by_its_exit_status`
  (`crates/eval/tests/eval.rs`): `sh -c 'exec 0<&-; exit 37'` with an 8 MiB
  prompt the child never reads, its zero-exit variant, and 16 repetitions of
  the original 1-byte case. `cargo test --workspace` is 538 passed and
  `cargo test --workspace --all-features` 550, both 0 failed, 6 ignored.
* `crates/server/tests/shutdown.rs` (8 tests) binds real sockets and has been
  seen to fail on a busy machine with a connection reset in the SIGTERM drain
  path; it passed in every run here, including four full `cargo test
  --workspace` runs and two `cargo test --workspace --all-features` runs. A red
  drain test on a loaded box is worth a rerun before it is believed.
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
