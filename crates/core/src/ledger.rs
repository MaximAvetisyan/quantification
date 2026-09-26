use std::ops::Range;

use crate::config::MarkerStyle;
use crate::stage1::Unit;

const CHECKSUM_BYTES: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CommitKind {
    ExactRun,
    WsRun,
    Block,
    TemplateGroup,
    TemplatedBlock,
}

impl CommitKind {
    pub fn core(self, style: MarkerStyle) -> (&'static str, &'static str) {
        match style {
            MarkerStyle::Unicode => match self {
                Self::ExactRun => ("\u{d7}", " identical"),
                Self::WsRun => ("\u{d7}", " rows, ws-equal"),
                Self::Block => ("block \u{d7}", ""),
                Self::TemplateGroup => ("\u{d7}", " rows, template"),
                Self::TemplatedBlock => ("templated block \u{d7}", ""),
            },
            _ => match self {
                Self::ExactRun => ("x", " identical"),
                Self::WsRun => ("x", " rows, ws-equal"),
                Self::Block => ("block x", ""),
                Self::TemplateGroup => ("x", " rows, template"),
                Self::TemplatedBlock => ("templated block x", ""),
            },
        }
    }
}

pub fn decimal_width(count: u64) -> usize {
    count
        .checked_ilog10()
        .map_or(1, |digits| digits as usize + 1)
}

pub fn framing(style: MarkerStyle) -> (&'static str, &'static str, &'static str) {
    match style {
        MarkerStyle::Unicode => ("\u{27ea}", " \u{b7}", "\u{27eb}"),
        _ => ("[... ", " ", " ...]"),
    }
}

pub fn marker_len(style: MarkerStyle, kind: CommitKind, count: u64) -> usize {
    let (open, sep, close) = framing(style);
    let (prefix, suffix) = kind.core(style);
    open.len()
        + prefix.len()
        + decimal_width(count)
        + suffix.len()
        + sep.len()
        + CHECKSUM_BYTES
        + close.len()
}

pub fn profitable(
    style: MarkerStyle,
    kind: CommitKind,
    count: u64,
    anchor_bytes: usize,
    removed_bytes: usize,
) -> bool {
    anchor_bytes + marker_len(style, kind, count) < removed_bytes
}

pub fn removal_range(units: &[Unit], group: Range<usize>) -> Range<usize> {
    assert!(
        group.start < group.end && group.end <= units.len(),
        "group must index a non-empty run of units"
    );
    let members = &units[group.clone()];
    for pair in members.windows(2) {
        assert!(
            pair[0].range.end <= pair[1].range.start,
            "units must be ascending and disjoint"
        );
    }
    members[0].range.start..members[members.len() - 1].range.end
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub group: Range<usize>,
    pub anchor_units: usize,
    pub count: u64,
    pub kind: CommitKind,
}

impl Proposal {
    pub fn new(group: Range<usize>, anchor_units: usize, count: u64, kind: CommitKind) -> Self {
        Self {
            group,
            anchor_units,
            count,
            kind,
        }
    }

    pub fn run(group: Range<usize>, kind: CommitKind) -> Self {
        Self::repeat(group, 1, kind)
    }

    pub fn repeat(group: Range<usize>, anchor_units: usize, kind: CommitKind) -> Self {
        let copies = group.len().checked_div(anchor_units).unwrap_or(0);
        Self::new(group, anchor_units, copies.saturating_sub(1) as u64, kind)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    pub kind: CommitKind,
    pub first: usize,
    pub last: usize,
    pub count: u64,
    pub anchor: Range<usize>,
    pub removed: Range<usize>,
}

impl Commit {
    pub fn members(&self) -> usize {
        self.last - self.first + 1
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitOutcome {
    Committed(Commit),
    InvalidGroup,
    InvalidAnchor,
    InvalidCount,
    Ineligible,
    Overlapped,
    BelowThreshold,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StageStats {
    pub groups_collapsed: u64,
    pub exact_runs: u64,
    pub ws_runs: u64,
    pub block_repeats: u64,
    pub template_groups: u64,
    pub templated_blocks: u64,
    pub record_splits: u64,
}

impl StageStats {
    pub fn bump(&mut self, kind: CommitKind) {
        self.groups_collapsed += 1;
        match kind {
            CommitKind::ExactRun => self.exact_runs += 1,
            CommitKind::WsRun => self.ws_runs += 1,
            CommitKind::Block => self.block_repeats += 1,
            CommitKind::TemplateGroup => self.template_groups += 1,
            CommitKind::TemplatedBlock => self.templated_blocks += 1,
        }
    }

    pub fn merge(&mut self, other: &StageStats) {
        self.groups_collapsed += other.groups_collapsed;
        self.exact_runs += other.exact_runs;
        self.ws_runs += other.ws_runs;
        self.block_repeats += other.block_repeats;
        self.template_groups += other.template_groups;
        self.templated_blocks += other.templated_blocks;
        self.record_splits += other.record_splits;
    }
}

pub struct Ledger<'u> {
    units: &'u [Unit],
    claimed: Vec<bool>,
    commits: Vec<Commit>,
    marker_style: MarkerStyle,
}

impl<'u> Ledger<'u> {
    pub fn new(units: &'u [Unit], marker_style: MarkerStyle) -> Self {
        assert_ne!(
            marker_style,
            MarkerStyle::Auto,
            "the caller resolves Auto before committing"
        );
        Self {
            units,
            claimed: vec![false; units.len()],
            commits: Vec::new(),
            marker_style,
        }
    }

    pub fn units(&self) -> &'u [Unit] {
        self.units
    }

    pub fn marker_style(&self) -> MarkerStyle {
        self.marker_style
    }

    pub fn commits(&self) -> &[Commit] {
        &self.commits
    }

    pub fn is_committed(&self, unit: usize) -> bool {
        self.claimed[unit]
    }

    pub fn is_free(&self, group: Range<usize>) -> bool {
        if group.start >= group.end || group.end > self.units.len() {
            return false;
        }
        self.claimed[group.clone()].iter().all(|claimed| !claimed)
    }

    pub fn residual(&self) -> impl Iterator<Item = (usize, &'u Unit)> + '_ {
        self.claimed
            .iter()
            .zip(self.units)
            .enumerate()
            .filter(|(_, (claimed, _))| !*claimed)
            .map(|(index, (_, unit))| (index, unit))
    }

    pub fn try_commit(&mut self, proposal: Proposal) -> CommitOutcome {
        let group = &proposal.group;
        if group.start >= group.end || group.end > self.units.len() {
            return CommitOutcome::InvalidGroup;
        }
        if proposal.anchor_units == 0 || proposal.anchor_units > group.len() {
            return CommitOutcome::InvalidAnchor;
        }
        if proposal.count == 0 {
            return CommitOutcome::InvalidCount;
        }
        let members = &self.units[group.clone()];
        if members.iter().any(|unit| !unit.eligible) {
            return CommitOutcome::Ineligible;
        }
        if !self.is_free(group.clone()) {
            return CommitOutcome::Overlapped;
        }
        let removed = removal_range(self.units, group.clone());
        let anchor = removal_range(self.units, group.start..group.start + proposal.anchor_units);
        if !profitable(
            self.marker_style,
            proposal.kind,
            proposal.count,
            anchor.len(),
            removed.len(),
        ) {
            return CommitOutcome::BelowThreshold;
        }
        for unit in &mut self.claimed[group.clone()] {
            *unit = true;
        }
        let commit = Commit {
            kind: proposal.kind,
            first: group.start,
            last: group.end - 1,
            count: proposal.count,
            anchor,
            removed,
        };
        let at = self
            .commits
            .partition_point(|other| other.anchor.start < commit.anchor.start);
        self.commits.insert(at, commit.clone());
        CommitOutcome::Committed(commit)
    }
}
