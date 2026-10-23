#![allow(clippy::unwrap_used)] // checked fixtures for the gate itself
use super::*;

#[test]
fn percentiles_normalize_iterations_before_ranking() {
    let iters: Vec<_> = (1..=100).map(f64::from).collect();
    let times = iters.iter().map(|n| n * 7.0).collect();
    assert_eq!(
        measure(Sample { iters, times }).unwrap(),
        Measurement {
            p50_ns: 7.0,
            p99_ns: 7.0,
            samples: 100
        }
    );
    let sample = Sample {
        iters: vec![1.0; 100],
        times: (1..=100).map(f64::from).collect(),
    };
    let m = measure(sample).unwrap();
    assert_eq!(m.p50_ns, 50.5);
    assert!((m.p99_ns - 99.01).abs() < 1e-10);
}

#[test]
fn refuses_partial_or_invalid_samples() {
    for sample in [
        Sample {
            iters: vec![1.0; 99],
            times: vec![7.0; 99],
        },
        Sample {
            iters: vec![0.0; 100],
            times: vec![7.0; 100],
        },
        Sample {
            iters: vec![1.0; 100],
            times: vec![f64::NAN; 100],
        },
        Sample {
            iters: vec![1.0; 100],
            times: vec![7.0; 101],
        },
    ] {
        assert!(measure(sample).is_err());
    }
}

fn fixture() -> Run {
    let mut benchmarks = BTreeMap::new();
    for id in required_ids() {
        benchmarks.insert(
            id,
            Measurement {
                p50_ns: 90.0,
                p99_ns: 100.0,
                samples: 100,
            },
        );
    }
    Run {
            platform: "test-platform".into(),
            machine: Machine {
                model: "test cpu".into(),
                cores: 2,
            },
            rustc: "test".into(),
            source_commit: "test".into(),
            recorded_unix_seconds: 1,
            settings: Settings::default(),
            corpus: serde_json::json!({"sha256": "a".repeat(64), "rows": 1}),
            memory: ["structure", "scripts"].into_iter().flat_map(|mode| [1_000_000, 10_000_000].map(|bytes| serde_json::json!({
                "mode": mode, "bytes": bytes, "start_rss_bytes": 100, "peak_rss_bytes": 200, "delta_rss_bytes": 100,
            }))).collect(),
            benchmarks,
        }
}

#[test]
fn threshold_is_inclusive_at_five_percent_and_rejects_above_it() {
    let base = fixture();
    let mut actual = base.clone();
    actual
        .benchmarks
        .get_mut("beef_stream/scripts/1000000")
        .unwrap()
        .p99_ns = 105.0;
    assert!(compare(&base, &actual).unwrap());
    actual
        .benchmarks
        .get_mut("beef_stream/scripts/1000000")
        .unwrap()
        .p99_ns = 105.00001;
    assert!(!compare(&base, &actual).unwrap());
}

#[test]
fn a_missing_bench_changed_corpus_or_machine_never_passes() {
    let base = fixture();
    let mut actual = base.clone();
    actual
        .benchmarks
        .remove("wire_codec/getVersion/result_decode");
    assert!(compare(&base, &actual).is_err());
    actual = base.clone();
    actual.corpus["rows"] = 2.into();
    assert!(compare(&base, &actual).is_err());
    actual = base.clone();
    actual.machine.cores = 4;
    assert!(compare(&base, &actual).is_err());
    actual = base.clone();
    actual.benchmarks.clear();
    assert!(validate_run(&actual).is_err());
}
