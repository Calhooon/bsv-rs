use crate::{Result, TOOLCHAIN};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    pub files_over_800: usize,
    pub unwrap_expect: usize,
    pub functions_over_60: usize,
    pub cognitive_complexity_over_25: usize,
    pub missing_docs: usize,
    pub duplicate_windows_40: usize,
    pub pedantic_warnings: usize,
}

impl Metrics {
    fn counters(&self) -> [(&'static str, usize); 7] {
        [
            ("files_over_800", self.files_over_800),
            ("unwrap_expect", self.unwrap_expect),
            ("functions_over_60", self.functions_over_60),
            (
                "cognitive_complexity_over_25",
                self.cognitive_complexity_over_25,
            ),
            ("missing_docs", self.missing_docs),
            ("duplicate_windows_40", self.duplicate_windows_40),
            ("pedantic_warnings", self.pedantic_warnings),
        ]
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LargeFile {
    pub path: String,
    pub lines: usize,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema: u32,
    pub source_commit: String,
    pub toolchain: String,
    pub metrics: Metrics,
    pub files_over_800: Vec<LargeFile>,
}

impl Snapshot {
    pub fn new(commit: &str) -> Self {
        Self {
            schema: 1,
            source_commit: commit.into(),
            toolchain: TOOLCHAIN.into(),
            metrics: Metrics::default(),
            files_over_800: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != 1 || self.toolchain != TOOLCHAIN {
            return Err("baseline schema/toolchain differs; review the measurement change".into());
        }
        if self.source_commit.len() != 40
            || !self
                .source_commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || self.metrics.files_over_800 != self.files_over_800.len()
            || self.files_over_800.iter().any(|file| {
                file.lines <= 800 || !file.path.starts_with("src/") || !file.path.ends_with(".rs")
            })
            || self
                .files_over_800
                .windows(2)
                .any(|pair| pair[0].path >= pair[1].path)
        {
            return Err("invalid baseline provenance or oversized-file inventory".into());
        }
        Ok(())
    }

    pub fn increases(&self, baseline: &Self) -> Vec<String> {
        let mut failures = Vec::new();
        for ((name, current), (_, limit)) in self
            .metrics
            .counters()
            .into_iter()
            .zip(baseline.metrics.counters())
        {
            if current > limit {
                failures.push(format!(
                    "{name}: {current} > {limit} (+{})",
                    current - limit
                ));
            }
        }
        for file in &self.files_over_800 {
            let limit = baseline
                .files_over_800
                .iter()
                .find(|old| old.path == file.path)
                .map_or(800, |old| old.lines);
            if file.lines > limit {
                failures.push(format!(
                    "{}: {} lines > {limit} (+{})",
                    file.path,
                    file.lines,
                    file.lines - limit
                ));
            }
        }
        failures
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_counter_and_each_file_has_an_independent_limit() {
        let mut current = Snapshot::new(&"a".repeat(40));
        current.metrics = Metrics {
            files_over_800: 1,
            unwrap_expect: 1,
            functions_over_60: 1,
            cognitive_complexity_over_25: 1,
            missing_docs: 1,
            duplicate_windows_40: 1,
            pedantic_warnings: 1,
        };
        current.files_over_800.push(LargeFile {
            path: "src/example.rs".into(),
            lines: 801,
        });
        let baseline = Snapshot::new(&"a".repeat(40));
        let failures = current.increases(&baseline);
        assert_eq!(failures.len(), 8);
        assert!(failures.iter().all(|failure| failure.ends_with("(+1)")));
        assert!(baseline.increases(&current).is_empty());
        assert!(current.increases(&current).is_empty());
    }

    #[test]
    fn replacing_an_oversized_file_cannot_hide_behind_a_flat_count() {
        let mut baseline = Snapshot::new(&"a".repeat(40));
        baseline.metrics.files_over_800 = 1;
        baseline.files_over_800.push(LargeFile {
            path: "src/old.rs".into(),
            lines: 900,
        });
        let mut current = Snapshot::new(&"a".repeat(40));
        current.metrics.files_over_800 = 1;
        current.files_over_800.push(LargeFile {
            path: "src/new.rs".into(),
            lines: 850,
        });
        assert_eq!(
            current.increases(&baseline),
            ["src/new.rs: 850 lines > 800 (+50)"]
        );
    }

    #[test]
    fn baseline_rejects_incomplete_or_inconsistent_measurements() {
        assert!(serde_json::from_str::<Metrics>("{}").is_err());
        let mut baseline = Snapshot::new(&"a".repeat(40));
        assert!(baseline.validate().is_ok());
        baseline.metrics.files_over_800 = 1;
        assert!(baseline.validate().is_err());
    }
}
