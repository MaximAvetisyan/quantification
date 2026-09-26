use crate::config::{JSON_DEPTH_CAP, MAX_SPAN_BYTES, ScopePolicy};
use crate::keys::{
    K_CONTENT, K_INPUT, K_MESSAGES, K_OUTPUT, K_ROLE, K_TEXT, K_TYPE, KEY_COUNT, NO_KEY, key_id,
};
use crate::sniff::{Schema, bom_len, strip_bom};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpanClass {
    User,
    Tool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoopReason {
    Malformed,
    UnknownSchema,
}

impl NoopReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::UnknownSchema => "unknown_schema",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Check {
    Final,
    Role,
    ItemType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Owner {
    frame: u8,
    slot: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub class: SpanClass,
    check: Check,
    read: Owner,
    owner: Owner,
}

#[derive(Clone, Debug)]
pub struct Located {
    pub schema: Option<Schema>,
    pub spans: Vec<Span>,
    pub noop_reason: Option<NoopReason>,
}

impl Located {
    pub fn degraded(&self) -> bool {
        self.noop_reason.is_some()
    }
}

pub fn locate(payload: &[u8], policy: ScopePolicy) -> Located {
    match crate::sniff::sniff(payload) {
        Some(schema) => locate_as(payload, schema, policy),
        None => Located {
            schema: None,
            spans: Vec::new(),
            noop_reason: Some(NoopReason::UnknownSchema),
        },
    }
}

pub fn locate_as(payload: &[u8], schema: Schema, policy: ScopePolicy) -> Located {
    let mut spans = Vec::new();
    let noop_reason = locate_into(payload, schema, policy, &mut spans);
    Located {
        schema: Some(schema),
        spans,
        noop_reason,
    }
}

pub fn locate_into(
    payload: &[u8],
    schema: Schema,
    policy: ScopePolicy,
    out: &mut Vec<Span>,
) -> Option<NoopReason> {
    out.clear();
    let bom = bom_len(payload);
    if schema == Schema::Text {
        if bom < payload.len() {
            out.push(Span {
                start: bom,
                end: payload.len(),
                class: SpanClass::User,
                check: Check::Role,
                read: Owner {
                    frame: 0,
                    slot: NO_KEY,
                },
                owner: Owner {
                    frame: 0,
                    slot: NO_KEY,
                },
            });
        }
        return None;
    }
    let mut scanner = Scanner {
        data: strip_bom(payload),
        schema,
        policy,
        bom,
        depth: 0,
        frames: [Frame::EMPTY; JSON_DEPTH_CAP],
    };
    match scanner.run(out) {
        Ok(()) => None,
        Err(_) => {
            out.clear();
            Some(NoopReason::Malformed)
        }
    }
}

struct Fail;

#[derive(Clone, Copy)]
enum Ctx {
    Root,
    Message,
    Block,
    Part,
    MessagesArr,
    InputArr,
    PartsArr,
    TrArr,
    Other,
}

#[derive(Clone, Copy)]
struct Slot {
    start: usize,
    end: usize,
    form: u8,
}

impl Slot {
    const EMPTY: Slot = Slot {
        start: 0,
        end: 0,
        form: 0,
    };
    const OTHER: Slot = Slot {
        start: 0,
        end: 0,
        form: 2,
    };
}

#[derive(Clone, Copy)]
struct Frame {
    ctx: Ctx,
    arr: bool,
    key: u8,
    owner: Owner,
    first: usize,
    marks: [usize; KEY_COUNT],
    slots: [Slot; KEY_COUNT],
}

impl Frame {
    const EMPTY: Frame = Frame {
        ctx: Ctx::Other,
        arr: false,
        key: NO_KEY,
        owner: Owner {
            frame: 0,
            slot: NO_KEY,
        },
        first: 0,
        marks: [0; KEY_COUNT],
        slots: [Slot::EMPTY; KEY_COUNT],
    };
}

#[derive(Clone, Copy, PartialEq)]
enum St {
    Val,
    ValOrEnd,
    KeyOrEnd,
    Key,
    Colon,
    After,
    Done,
}

enum VEnd {
    Val(usize),
    Obj,
    Arr,
}

struct Scanner<'a> {
    data: &'a [u8],
    schema: Schema,
    policy: ScopePolicy,
    bom: usize,
    depth: usize,
    frames: [Frame; JSON_DEPTH_CAP],
}

impl Scanner<'_> {
    fn run(&mut self, out: &mut Vec<Span>) -> Result<(), Fail> {
        let d = self.data;
        let mut at = 0usize;
        let mut st = St::Val;
        loop {
            match st {
                St::Done => {
                    at = ws(d, at);
                    return if at == d.len() { Ok(()) } else { Err(Fail) };
                }
                St::Val | St::ValOrEnd => {
                    at = ws(d, at);
                    let Some(&b) = d.get(at) else {
                        return Err(Fail);
                    };
                    if st == St::ValOrEnd && b == b']' {
                        at += 1;
                        self.close(out);
                        st = St::After;
                        continue;
                    }
                    st = match self.value(d, at, out)? {
                        VEnd::Val(next) => {
                            at = next;
                            St::After
                        }
                        VEnd::Obj => {
                            at += 1;
                            St::KeyOrEnd
                        }
                        VEnd::Arr => {
                            at += 1;
                            St::ValOrEnd
                        }
                    };
                }
                St::KeyOrEnd | St::Key => {
                    at = ws(d, at);
                    let Some(&b) = d.get(at) else {
                        return Err(Fail);
                    };
                    if b == b'}' {
                        if st == St::Key {
                            return Err(Fail);
                        }
                        at += 1;
                        self.close(out);
                        st = St::After;
                        continue;
                    }
                    if b != b'"' {
                        return Err(Fail);
                    }
                    let (start, end) = string(d, at)?;
                    at = end + 1;
                    self.set_key(key_id(&d[start..end]), out);
                    st = St::Colon;
                }
                St::Colon => {
                    at = ws(d, at);
                    if d.get(at) != Some(&b':') {
                        return Err(Fail);
                    }
                    at += 1;
                    st = St::Val;
                }
                St::After => {
                    at = ws(d, at);
                    if self.depth == 0 {
                        st = St::Done;
                        continue;
                    }
                    match d.get(at) {
                        Some(b',') => {
                            at += 1;
                            st = if self.top().arr { St::Val } else { St::Key };
                        }
                        Some(&b) => {
                            if (b == b'}') == self.top().arr {
                                return Err(Fail);
                            }
                            at += 1;
                            self.close(out);
                            st = St::After;
                        }
                        None => return Err(Fail),
                    }
                }
            }
        }
    }

    fn value(&mut self, d: &[u8], at: usize, out: &mut Vec<Span>) -> Result<VEnd, Fail> {
        match d[at] {
            b'{' => self.push(false, out.len()).map(|()| VEnd::Obj),
            b'[' => self.push(true, out.len()).map(|()| VEnd::Arr),
            b'"' => {
                let (start, end) = string(d, at)?;
                self.on_string(start, end, out);
                Ok(VEnd::Val(end + 1))
            }
            b't' => self.literal(d, at, b"true"),
            b'f' => self.literal(d, at, b"false"),
            b'n' => self.literal(d, at, b"null"),
            b'-' | b'0'..=b'9' => self.number(d, at),
            _ => Err(Fail),
        }
    }

    fn literal(&mut self, d: &[u8], at: usize, want: &[u8]) -> Result<VEnd, Fail> {
        if d.get(at..at + want.len()) != Some(want) {
            return Err(Fail);
        }
        self.set_other();
        Ok(VEnd::Val(at + want.len()))
    }

    fn number(&mut self, d: &[u8], at: usize) -> Result<VEnd, Fail> {
        let mut end = at;
        let mut digits = 0usize;
        while d
            .get(end)
            .is_some_and(|b| matches!(*b, b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-'))
        {
            digits += usize::from(d[end].is_ascii_digit());
            end += 1;
        }
        if digits == 0 {
            return Err(Fail);
        }
        self.set_other();
        Ok(VEnd::Val(end))
    }

    fn push(&mut self, arr: bool, n: usize) -> Result<(), Fail> {
        if self.depth >= JSON_DEPTH_CAP {
            return Err(Fail);
        }
        let at = self.depth;
        let (ctx, owner) = if at == 0 {
            (Ctx::Root, self.frames[0].owner)
        } else {
            let parent = self.frames[at - 1];
            let owner = if parent.arr {
                parent.owner
            } else {
                Owner {
                    frame: (at - 1) as u8,
                    slot: parent.key,
                }
            };
            if !parent.arr && owner.slot != NO_KEY {
                self.frames[at - 1].slots[owner.slot as usize] = Slot::OTHER;
            }
            (self.child_ctx(&parent, arr), owner)
        };
        self.frames[at] = Frame {
            ctx,
            arr,
            key: NO_KEY,
            owner,
            first: n,
            marks: [n; KEY_COUNT],
            slots: [Slot::EMPTY; KEY_COUNT],
        };
        self.depth = at + 1;
        Ok(())
    }

    fn child_ctx(&self, parent: &Frame, arr: bool) -> Ctx {
        if arr {
            match (parent.ctx, parent.key) {
                (Ctx::Root, K_MESSAGES) if self.schema != Schema::Responses => Ctx::MessagesArr,
                (Ctx::Root, K_INPUT) if self.schema == Schema::Responses => Ctx::InputArr,
                (Ctx::Message, K_CONTENT) => Ctx::PartsArr,
                (Ctx::Block, K_CONTENT) => Ctx::TrArr,
                _ => Ctx::Other,
            }
        } else {
            match parent.ctx {
                Ctx::MessagesArr | Ctx::InputArr => Ctx::Message,
                Ctx::PartsArr => Ctx::Block,
                Ctx::TrArr => Ctx::Part,
                _ => Ctx::Other,
            }
        }
    }

    fn top(&self) -> Frame {
        self.frames[self.depth - 1]
    }

    fn set_key(&mut self, key: u8, out: &mut Vec<Span>) {
        let at = self.depth - 1;
        if key == NO_KEY {
            self.frames[at].key = NO_KEY;
            return;
        }
        if self.frames[at].slots[key as usize].form != 0 {
            self.drop_key(at, key, out);
        }
        self.frames[at].key = key;
        self.frames[at].marks[key as usize] = out.len();
    }

    fn set_other(&mut self) {
        if self.depth == 0 {
            return;
        }
        let at = self.depth - 1;
        let key = self.frames[at].key;
        if key != NO_KEY {
            self.frames[at].slots[key as usize] = Slot::OTHER;
        }
    }

    fn on_string(&mut self, start: usize, end: usize, out: &mut Vec<Span>) {
        if self.depth == 0 {
            return;
        }
        let at = self.depth - 1;
        let frame = self.frames[at];
        let key = frame.key;
        if key == NO_KEY {
            return;
        }
        self.frames[at].slots[key as usize] = Slot {
            start,
            end,
            form: 1,
        };
        let check = match (frame.ctx, key) {
            (Ctx::Root, K_INPUT) if self.schema == Schema::Responses => Check::Role,
            (Ctx::Message, K_OUTPUT) => Check::ItemType,
            (Ctx::Message, K_CONTENT)
            | (Ctx::Block, K_CONTENT)
            | (Ctx::Block, K_TEXT)
            | (Ctx::Part, K_TEXT) => Check::Role,
            _ => return,
        };
        if end <= start || end - start > MAX_SPAN_BYTES {
            return;
        }
        let class = match check {
            Check::ItemType => SpanClass::Tool,
            _ => SpanClass::User,
        };
        if class == SpanClass::Tool && self.policy == ScopePolicy::UserContent {
            return;
        }
        out.push(Span {
            start: start + self.bom,
            end: end + self.bom,
            class,
            check,
            read: Owner {
                frame: at as u8,
                slot: key,
            },
            owner: self.frames[at].owner,
        });
    }

    fn slot_bytes(&self, at: usize, key: u8) -> Option<&[u8]> {
        let slot = self.frames[at].slots[key as usize];
        if slot.form == 1 {
            Some(&self.data[slot.start..slot.end])
        } else {
            None
        }
    }

    fn drop_key(&mut self, at: usize, key: u8, out: &mut Vec<Span>) {
        let from = self.frames[at].marks[key as usize];
        if from >= out.len() {
            return;
        }
        let frame = at as u8;
        let mut marks = self.frames[at].marks;
        let mut w = from;
        for r in from..out.len() {
            let span = out[r];
            if (span.read.frame == frame && span.read.slot == key)
                || (span.owner.frame == frame && span.owner.slot == key)
            {
                continue;
            }
            if span.read.frame == frame {
                marks[span.read.slot as usize] = marks[span.read.slot as usize].min(w);
            }
            if span.owner.frame == frame && span.owner.slot != NO_KEY {
                marks[span.owner.slot as usize] = marks[span.owner.slot as usize].min(w);
            }
            out[w] = span;
            w += 1;
        }
        out.truncate(w);
        self.frames[at].marks = marks;
    }

    fn close(&mut self, out: &mut Vec<Span>) {
        let at = self.depth - 1;
        match self.frames[at].ctx {
            Ctx::Part => self.resolve_part(at, out),
            Ctx::Block => self.resolve_block(at, out),
            Ctx::Message => self.resolve_message(at, out),
            _ => {}
        }
        self.depth = at;
    }

    fn resolve_part(&mut self, at: usize, out: &mut Vec<Span>) {
        let first = self.frames[at].first;
        let frame = at as u8;
        let text = self.slot_bytes(at, K_TYPE) == Some(b"text".as_slice());
        compact(first, out, |span| {
            (text && span.read.frame == frame && span.read.slot == K_TEXT).then_some(span)
        });
    }

    fn resolve_block(&mut self, at: usize, out: &mut Vec<Span>) {
        let first = self.frames[at].first;
        let frame = at as u8;
        let tools = self.policy == ScopePolicy::UserAndTools;
        let kind = match self.slot_bytes(at, K_TYPE) {
            Some(b"text") => 1,
            Some(b"tool_result") if self.schema == Schema::Messages => 2,
            _ => 0,
        };
        compact(first, out, |mut span| match kind {
            1 if span.read.frame == frame && span.read.slot == K_TEXT => Some(span),
            2 if tools => {
                if span.read.frame == frame && span.read.slot != K_CONTENT {
                    return None;
                }
                span.class = SpanClass::Tool;
                span.check = Check::Final;
                Some(span)
            }
            _ => None,
        });
    }

    fn resolve_message(&mut self, at: usize, out: &mut Vec<Span>) {
        let first = self.frames[at].first;
        let role = match self.slot_bytes(at, K_ROLE) {
            Some(b"user") => 1,
            Some(b"tool") => 2,
            _ => 0,
        };
        let item = self.schema == Schema::Responses
            && self.slot_bytes(at, K_TYPE) == Some(b"function_call_output".as_slice());
        let tools = self.policy == ScopePolicy::UserAndTools;
        compact(first, out, |mut span| match span.check {
            Check::Role => match role {
                1 => {
                    span.class = SpanClass::User;
                    span.check = Check::Final;
                    Some(span)
                }
                2 if tools => {
                    span.class = SpanClass::Tool;
                    span.check = Check::Final;
                    Some(span)
                }
                _ => None,
            },
            Check::ItemType => (item && tools).then_some(span),
            Check::Final => (span.class == SpanClass::User || tools).then_some(span),
        });
    }
}

fn compact(from: usize, out: &mut Vec<Span>, mut step: impl FnMut(Span) -> Option<Span>) {
    if from >= out.len() {
        return;
    }
    let mut w = from;
    for r in from..out.len() {
        if let Some(span) = step(out[r]) {
            out[w] = span;
            w += 1;
        }
    }
    out.truncate(w);
}

fn ws(d: &[u8], at: usize) -> usize {
    let mut at = at;
    while d
        .get(at)
        .is_some_and(|b| matches!(*b, b' ' | b'\t' | b'\n' | b'\r'))
    {
        at += 1;
    }
    at
}

fn string(d: &[u8], at: usize) -> Result<(usize, usize), Fail> {
    let mut j = at + 1;
    while j < d.len() {
        match d[j] {
            b'\\' => j += 2,
            b'"' => return Ok((at + 1, j)),
            0..=0x1F => return Err(Fail),
            _ => j += 1,
        }
    }
    Err(Fail)
}
