#[path = "adversarial_fixtures.rs"]
mod fixtures;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use quantification_core::config::{MarkerStyle, ScopePolicy, resolve};
use quantification_core::locator::{SpanClass, locate_as};
use quantification_core::sniff::{Schema, sniff};
use quantification_core::stage1::split_span_counted;

const CORPUS: &[&str] = &[
    "schemas/chat-minified.json",
    "schemas/chat-pretty.json",
    "schemas/messages-minified.json",
    "schemas/messages-pretty.json",
    "schemas/responses-minified.json",
    "schemas/responses-pretty.json",
    "schemas/text-plain.txt",
    "shapes/anthropic-system-top.json",
    "shapes/anthropic-tool-result.json",
    "shapes/chat-content-null.json",
    "shapes/chat-mixed-parts.json",
    "shapes/responses-function-call-output.json",
    "shapes/responses-input-string.json",
    "shapes/sniff-overlap-chat-responses.json",
    "edges/bom-chat.json",
    "edges/dup-keys-last-wins.json",
    "edges/escaped-structural-keys.json",
    "edges/newlines-u000a-only.json",
    "edges/prior-markers.json",
    "edges/profitability-below-threshold.json",
    "edges/single-line-tool-dump-overcap.json",
    "edges/single-line-tool-dump-small.json",
    "edges/stage1b-no-separator-overcap.json",
    "edges/stage1b-record-len-16383.json",
    "edges/stage1b-record-len-16384.json",
    "edges/stage1b-record-len-16385.json",
];

const SCHEMAS: [Schema; 4] = [
    Schema::Chat,
    Schema::Responses,
    Schema::Messages,
    Schema::Text,
];
const CLASSES: [SpanClass; 2] = [SpanClass::User, SpanClass::Tool];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    MultiLine,
    SingleLine,
    OverCap,
}

const SHAPES: [Shape; 3] = [Shape::MultiLine, Shape::SingleLine, Shape::OverCap];

impl Shape {
    fn of(record_splits: usize, units: usize) -> Self {
        if record_splits > 0 {
            Self::OverCap
        } else if units <= 1 {
            Self::SingleLine
        } else {
            Self::MultiLine
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::MultiLine => "multi_line",
            Self::SingleLine => "single_line",
            Self::OverCap => "over_cap",
        }
    }
}

struct Span {
    corpus: String,
    schema: Schema,
    class: SpanClass,
    shape: Shape,
    bytes: usize,
    units: usize,
    eligible: usize,
    record_splits: usize,
}

fn root(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

fn measure(corpus: &str, payload: &[u8]) -> Vec<Span> {
    let Some(schema) = sniff(payload) else {
        println!("{corpus}: no schema, no eligible span");
        return Vec::new();
    };
    resolve(&Default::default()).expect("the default options resolve");
    let located = locate_as(payload, schema, ScopePolicy::UserAndTools);
    located
        .spans
        .iter()
        .map(|span| {
            let bytes = &payload[span.start..span.end];
            let split = split_span_counted(bytes, MarkerStyle::Auto);
            Span {
                corpus: corpus.to_string(),
                schema,
                class: span.class,
                shape: Shape::of(split.record_splits, split.units.len()),
                bytes: bytes.len(),
                units: split.units.len(),
                eligible: split.units.iter().filter(|unit| unit.eligible).count(),
                record_splits: split.record_splits,
            }
        })
        .collect()
}

fn corpus() -> Vec<Span> {
    let mut spans: Vec<Span> = Vec::new();
    for rel in CORPUS {
        let bytes = std::fs::read(root(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
        spans.extend(measure(rel, &bytes));
    }
    for case in fixtures::suite() {
        spans.extend(measure(case.name, &case.payload));
    }
    spans
}

fn cell(spans: &[Span], schema: Schema, class: SpanClass, shape: Shape) -> usize {
    spans
        .iter()
        .filter(|span| span.schema == schema && span.class == class && span.shape == shape)
        .count()
}

fn per_class(spans: &[Span], schema: Schema, shape: Shape) -> usize {
    CLASSES
        .iter()
        .map(|class| cell(spans, schema, *class, shape))
        .sum()
}

fn per_shape(spans: &[Span], schema: Schema, class: SpanClass) -> usize {
    SHAPES
        .iter()
        .map(|shape| cell(spans, schema, class, *shape))
        .sum()
}

struct Row {
    corpus: String,
    schema: Schema,
    class: SpanClass,
    spans: usize,
    bytes: usize,
    units: usize,
    eligible: usize,
    record_splits: usize,
    multi: usize,
    single: usize,
    over: usize,
}

fn rows(spans: &[Span]) -> Vec<Row> {
    let mut out: Vec<Row> = Vec::new();
    for span in spans {
        let slot = match out.iter_mut().find(|row| {
            row.corpus == span.corpus && row.schema == span.schema && row.class == span.class
        }) {
            Some(row) => row,
            None => {
                out.push(Row {
                    corpus: span.corpus.clone(),
                    schema: span.schema,
                    class: span.class,
                    spans: 0,
                    bytes: 0,
                    units: 0,
                    eligible: 0,
                    record_splits: 0,
                    multi: 0,
                    single: 0,
                    over: 0,
                });
                out.last_mut().expect("the row was just pushed")
            }
        };
        slot.spans += 1;
        slot.bytes += span.bytes;
        slot.units += span.units;
        slot.eligible += span.eligible;
        slot.record_splits += span.record_splits;
        match span.shape {
            Shape::MultiLine => slot.multi += 1,
            Shape::SingleLine => slot.single += 1,
            Shape::OverCap => slot.over += 1,
        }
    }
    out
}

fn report(spans: &[Span]) -> String {
    let rows = rows(spans);
    let mut json = String::from("{\n  \"policy\": \"user_and_tools\",\n  \"corpus\": [\n");
    for (index, row) in rows.iter().enumerate() {
        let _ = writeln!(
            json,
            "    {{\"corpus\": \"{}\", \"schema\": \"{}\", \"class\": \"{:?}\", \"spans\": {}, \"multi_line\": {}, \"single_line\": {}, \"over_cap\": {}, \"bytes\": {}, \"units\": {}, \"eligible_units\": {}, \"record_splits\": {}}}{}",
            row.corpus,
            row.schema.as_str(),
            row.class,
            row.spans,
            row.multi,
            row.single,
            row.over,
            row.bytes,
            row.units,
            row.eligible,
            row.record_splits,
            if index + 1 == rows.len() { "" } else { "," }
        );
    }
    json.push_str("  ],\n  \"totals\": {\n");
    for (index, schema) in SCHEMAS.iter().enumerate() {
        let _ = writeln!(json, "    \"{}\": {{", schema.as_str());
        for (class_index, class) in CLASSES.iter().enumerate() {
            let _ = write!(json, "      \"{class:?}\": {{");
            for (shape_index, shape) in SHAPES.iter().enumerate() {
                let _ = write!(
                    json,
                    "\"{}\": {}{}",
                    shape.as_str(),
                    cell(spans, *schema, *class, *shape),
                    if shape_index + 1 == SHAPES.len() {
                        ""
                    } else {
                        ", "
                    }
                );
            }
            let _ = writeln!(
                json,
                "}}{}",
                if class_index + 1 == CLASSES.len() {
                    ""
                } else {
                    ","
                }
            );
        }
        let _ = write!(
            json,
            "    }}{}{}",
            if index + 1 == SCHEMAS.len() { "" } else { "," },
            if index + 1 == SCHEMAS.len() { "" } else { "\n" }
        );
    }
    json.push_str("\n  }\n}\n");
    json
}

fn permille(part: usize, whole: usize) -> usize {
    part.checked_mul(1000).unwrap_or(0) / whole.max(1)
}

#[test]
fn the_span_shape_histogram_measures_stage_1b_coverage_instead_of_assuming_it() {
    let spans = corpus();
    assert!(!spans.is_empty(), "the corpus located no span at all");
    for shape in SHAPES {
        assert!(
            spans.iter().any(|span| span.shape == shape),
            "no {} span in the corpus: the histogram would be degenerate",
            shape.as_str()
        );
    }
    for class in CLASSES {
        assert!(
            spans.iter().any(|span| span.class == class),
            "no {class:?} span in the corpus"
        );
    }
    println!(
        "{:>44} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6}",
        "corpus", "spans", "multi", "single", "overcap", "mul‰", "sgl‰", "ovc‰"
    );
    for schema in SCHEMAS {
        let total = SHAPES
            .iter()
            .map(|shape| per_class(&spans, schema, *shape))
            .sum::<usize>();
        assert!(total > 0, "no {schema:?} span in the corpus");
        let (multi, single, over) = (
            per_class(&spans, schema, Shape::MultiLine),
            per_class(&spans, schema, Shape::SingleLine),
            per_class(&spans, schema, Shape::OverCap),
        );
        assert_eq!(
            multi + single + over,
            total,
            "{schema:?} shares must add up"
        );
        for class in CLASSES {
            let class_total = per_shape(&spans, schema, class);
            println!(
                "{:>44} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6}",
                format!("{schema:?}/{class:?}"),
                class_total,
                cell(&spans, schema, class, Shape::MultiLine),
                cell(&spans, schema, class, Shape::SingleLine),
                cell(&spans, schema, class, Shape::OverCap),
                permille(multi, total),
                permille(single, total),
                permille(over, total),
            );
            assert_eq!(class_total, per_shape(&spans, schema, class));
        }
    }
    for span in &spans {
        assert!(span.units >= 1, "{}: a span with no unit", span.corpus);
        assert!(
            span.eligible <= span.units,
            "{}: more units than exist",
            span.corpus
        );
        assert_eq!(
            span.shape == Shape::OverCap,
            span.record_splits > 0,
            "{}: the over-cap share is the stage-1b share",
            span.corpus
        );
    }
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/span-shape-report.json");
    std::fs::create_dir_all(path.parent().expect("a parent dir")).expect("target dir");
    let json = report(&spans);
    assert!(
        json.starts_with('{') && json.ends_with("}\n"),
        "the report is json"
    );
    assert!(
        json.len() < 64 * 1024,
        "{} bytes of report: aggregate it harder",
        json.len()
    );
    std::fs::write(&path, &json).expect("the report is written");
    println!("wrote {} ({} bytes)", path.display(), json.len());
}
