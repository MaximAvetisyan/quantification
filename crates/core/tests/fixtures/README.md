# Golden corpus — W0.3 bootstrap

Input fixtures for the quantification compressor (DESIGN.md rev 6). These are
**inputs only**: golden *outputs* are pinned later, when the detectors they
exercise exist (W1.x/W2.x), so this corpus never has to break meaning.

## Rules

- **Additive only.** Never change an existing fixture's meaning; add a new
  file instead — the corpus grows forever.
- UTF-8 bytes, LF line endings, kebab-case filenames.
- Every file below is listed with its purpose and normative DESIGN § ref.

## Index

### schemas/ — one baseline payload per schema

| File | Purpose | § |
|---|---|---|
| `chat-minified.json` | OpenAI chat completions, single-line JSON; user content = repetitive log lines separated by literal `\n` escapes | §4.1, §4.2 |
| `chat-pretty.json` | same payload as `chat-minified.json`, pretty-printed envelope (identical content-string bytes) | §12 |
| `responses-minified.json` | Responses API `input[]` items, `type:"message"` + `[{"type":"text","text":…}]` parts | §4.1 |
| `responses-pretty.json` | same payload, pretty-printed envelope | §12 |
| `messages-minified.json` | Anthropic Messages, plain-string content | §4.1 |
| `messages-pretty.json` | same payload, pretty-printed envelope | §12 |
| `text-plain.txt` | degenerate plain-text payload (`content_type=text`); not JSON, exempt from parse validation | §1 |

### shapes/ — content-shape variants across schemas

| File | Purpose | § |
|---|---|---|
| `chat-content-null.json` | `"content": null` tolerated; no spans located | §4.1 |
| `chat-mixed-parts.json` | content array `[{type:"text"},{type:"image_url"}]`; only text-part strings eligible, image URL untouched | §4.1 eligibility map |
| `responses-input-string.json` | root `input` as a plain string | §4.1 eligibility map |
| `anthropic-system-top.json` | top-level `system` is never eligible (R4); user message content is | §4.1, R4 |
| `sniff-overlap-chat-responses.json` | contains BOTH `messages` and `input`; fixed candidate order chat → Responses decides: spans come from `messages[].content`, root `input` ignored | §4.1 prefix sniff |
| `responses-function-call-output.json` | `function_call_output.output` string eligible ⇒ tool class; output holds a small single-line JSON array | §4.1 eligibility map |
| `anthropic-tool-result.json` | `tool_result.content` string ⇒ tool class regardless of enclosing user role | §4.1 eligibility map |

### edges/ — locator / escape / stage-1b boundary cases

| File | Purpose | § |
|---|---|---|
| `dup-keys-last-wins.json` | duplicate `model`/`role`/`content` keys; last occurrence wins (role=user, second content eligible) | §4.1 |
| `escaped-structural-keys.json` | keys written `"\u0072ole"`, `"\u0063ontent"` match their decoded form | §4.1 |
| `newlines-u000a-only.json` | line separators ONLY `\u000A` / `\u000a`, mixed case; zero `\n` escapes | §4.2 |
| `bom-chat.json` | leading EF BB BF BOM skipped by sniff and locator | §4.1 acceptance envelope |
| `prior-markers.json` | content already containing marker-shaped text, unicode (`⟪×N … ·hhhh⟫`) and ASCII fallback forms; idempotence input | §12 idempotence, §4.5 |
| `profitability-below-threshold.json` | three groups of ≥ `min_group_size` ultra-short repeats that must stay verbatim: anchor + marker > removed bytes for every group | §4.4 profitability gate |
| `single-line-tool-dump-small.json` | human-scale one-line `[{…},{…},…]` array, ZERO `\n` escapes; stage-1b shape showcase (under-cap, so 1b does not trigger) | §4.4 stage 1b |
| `single-line-tool-dump-overcap.json` | GENERATED — single line of 128001 raw escaped bytes dense with `},{` (3071 separators, 3072 records cycling 3 shapes, max record 43 B); triggers stage 1b end-to-end | §4.4 stage 1b |
| `stage1b-no-separator-overcap.json` | GENERATED — 131072-byte single line with zero `},{` ⇒ must stay verbatim through 1b | §4.4 stage 1b |
| `stage1b-record-len-16383.json` | GENERATED — five identical-shape records padded to exactly `max_record_bytes - 1`, joined by `,` inside brackets; whole line 81921 B > `max_line_bytes` | §4.4 stage 1b cap |
| `stage1b-record-len-16384.json` | GENERATED — records at exactly `max_record_bytes` (cap boundary, still eligible); line 81926 B | §4.4 stage 1b cap |
| `stage1b-record-len-16385.json` | GENERATED — records at `max_record_bytes + 1` (over cap ⇒ stay verbatim); line 81931 B | §4.4 stage 1b cap |

Bracket-carrying `u_head`/`u_tail` (leading `[` / trailing `]`) falls out of
every array dump above automatically (§4.4 stage 1b).

## Generated fixtures

Regenerate with:

```sh
sh crates/core/tests/fixtures/scripts/gen-stage1b-fixtures.sh
```

The script is POSIX sh + coreutils `tr` only, uses fixed inputs (no clock,
RNG, env), self-checks output byte sizes, and must be **byte-idempotent**
(rerunning changes nothing). Committed outputs were produced by it verbatim.

Byte math (raw escaped bytes inside the JSON string value):

- envelope: 51-byte prefix `{"model":"m","messages":[{"role":"user","content":"`
  + line + 4-byte suffix `"}]}` + trailing LF.
- record-len fixtures: record `{"pad":"<pad>","k":<d>}` = `22 + len(pad)`
  raw escaped bytes; pad is `reclen − 22` `x` chars; five copies joined by
  commas inside brackets → line = `5·reclen + 6`.
- `single-line-tool-dump-overcap.json`: 3072 records cycling
  `{"lvl":"info","msg":"heartbeat"}` / `{"lvl":"warn","msg":"slow disk 42"}` /
  `{"lvl":"info","msg":"retry ok"}` (escaped form), comma-joined in brackets.
- `stage1b-no-separator-overcap.json`: `0123456789abcdef` doubled 13× =
  131072 bytes; hex-only alphabet guarantees zero `},{`.

## Validation method

All `*.json` fixtures are validated to parse before commit with Node.js
(`JSON.parse` on the file bytes; the BOM fixture's leading EF BB BF is
stripped before parsing — the committed file keeps its BOM). `text-plain.txt`
is intentionally not JSON. Structural properties of the generated stage-1b
fixtures (record counts, exact raw escaped record lengths, separator density,
over-cap line sizes, absence of `},{` where required) are asserted by the
generator's size checks and were verified byte-wise at commit time.

Full semantic gating arrives when W1 sniff/locator/splitter tests consume this
corpus.
