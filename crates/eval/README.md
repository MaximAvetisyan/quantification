# quantification-eval — W4.6 offline eval harness

Reports the two §12 metrics. **Neither one gates anything**: §12 tracks them in
CI reports, and each becomes blocking only after its §13 ratification.

```
cargo run -p quantification-eval --bin quant-eval
cargo run -p quantification-eval --bin quant-eval -- --tokenizer o200k_base,cl100k_base,bytes/4
cargo run -p quantification-eval --bin quant-eval -- --corpus log_heavy
QUANT_EVAL_JSON=target/eval-report cargo run -p quantification-eval --bin quant-eval
```

| flag / variable | default | meaning |
|---|---|---|
| `--tokenizer <list>` | `o200k_base,cl100k_base` | comma list; §13.1 has not ratified a baseline, so every requested one is measured and reported (`bytes/4` only when named, and never as a §12 measurement) |
| `--corpus <stratum>` | `all` | `log_heavy` (the §12 population), `golden` (the committed fixtures), `adversarial` (the W4.4 generators) |
| `QUANT_EVAL_TOKENIZERS` | — | same as `--tokenizer` |
| `QUANT_EVAL_JSON` | — | write `<path>.tokens.json` and `<path>.tasks.json` |
| `QUANT_EVAL_PROVIDER_CMD` | — | command that reads a prompt on stdin and writes the completion on stdout; run once per declared provider with `QUANT_EVAL_PROVIDER_ID` / `QUANT_EVAL_MODEL` / `QUANT_EVAL_ENDPOINT` in its environment. Unset ⇒ the task-quality section reports `NOT MEASURED` and no model is called |
| `--enforce` | off | exit 1 when a real baseline's log-heavy median misses ≥40%. **Not used by CI**: the corpus (§13.4) and the task suite (§13.5) are unratified |

Exit codes: 0 always, except 2 on an unknown `--tokenizer` / `--corpus` value.

## What it reports

* bytes in/out, the §4.5 per-detector group counts, the `degraded` flag and the
  noop reason for every payload;
* real tokenizer token counts (baseline vs compressed) and the per-stratum
  median reduction, per schema, and per payload;
* the four §12 task classes with their provisional parity gates, per provider.

Strata are reported separately and never pooled: the golden fixtures are mostly
too small to compact, so pooling them into the log-heavy median would answer a
different question than §12 asks.
