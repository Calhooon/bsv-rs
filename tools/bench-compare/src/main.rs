//! Run Criterion, then gate empirical p99 against a reviewed machine baseline.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const BENCHES: [&str; 9] = [
    "hash_bench",
    "primitives_bench",
    "script_bench",
    "memory_bench",
    "beef_stream",
    "merkle_path",
    "transaction_sign_verify",
    "wire_codec",
    "script_spend",
];
/// The benches `--skip` may name: each one's ids carry its name as their
/// prefix, so the comparison can drop exactly that bench's rows.
const SKIPPABLE: [&str; 5] = [
    "beef_stream",
    "merkle_path",
    "transaction_sign_verify",
    "wire_codec",
    "script_spend",
];
const MARGIN: f64 = 0.05;
const SAMPLES: usize = 100;
const CALLS: [&str; 28] = [
    "createAction",
    "signAction",
    "abortAction",
    "listActions",
    "internalizeAction",
    "listOutputs",
    "relinquishOutput",
    "getPublicKey",
    "revealCounterpartyKeyLinkage",
    "revealSpecificKeyLinkage",
    "encrypt",
    "decrypt",
    "createHmac",
    "verifyHmac",
    "createSignature",
    "verifySignature",
    "acquireCertificate",
    "listCertificates",
    "proveCertificate",
    "relinquishCertificate",
    "discoverByIdentityKey",
    "discoverByAttributes",
    "isAuthenticated",
    "waitForAuthentication",
    "getHeight",
    "getHeaderForHeight",
    "getNetwork",
    "getVersion",
];

fn required_ids() -> Vec<String> {
    let mut ids: Vec<String> = [
        "sha256",
        "sha512",
        "sha256d",
        "hash160",
        "sha256_hmac",
        "merkle_path/verify_depth20_10000",
        "transaction_sign_verify/sign_100_p2pkh",
        "transaction_sign_verify/verify_100_p2pkh",
        "script_spend/seed_block",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    for mode in ["structure", "scripts"] {
        for bytes in [1_000_000, 10_000_000] {
            ids.push(format!("beef_stream/{mode}/{bytes}"));
        }
    }
    for call in CALLS {
        for operation in [
            "request_encode",
            "request_decode",
            "result_encode",
            "result_decode",
        ] {
            ids.push(format!("wire_codec/{call}/{operation}"));
        }
    }
    ids
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Machine {
    model: String,
    cores: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Measurement {
    p50_ns: f64,
    p99_ns: f64,
    samples: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Run {
    platform: String,
    machine: Machine,
    rustc: String,
    source_commit: String,
    recorded_unix_seconds: u64,
    settings: Settings,
    corpus: Value,
    memory: Vec<Value>,
    benchmarks: BTreeMap<String, Measurement>,
    /// Benches not measured (`--skip`): neither a pass nor a regression.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    skipped: Vec<String>,
}

impl Run {
    fn skips(&self, bench: &str) -> bool {
        self.skipped.iter().any(|b| b == bench)
    }

    fn skips_id(&self, id: &str) -> bool {
        self.skipped.iter().any(|b| {
            id.strip_prefix(b.as_str())
                .is_some_and(|r| r.starts_with('/'))
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Settings {
    sample_size: usize,
    warm_up_seconds: u32,
    measurement_seconds: u32,
    features: String,
    percentile: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self { sample_size: SAMPLES, warm_up_seconds: 1, measurement_seconds: 3,
            features: "wallet".into(),
            percentile: "linear interpolation of sorted sample time_ns / iterations; batch benches stay per batch".into() }
    }
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Baseline {
    schema_version: u32,
    platforms: BTreeMap<String, Run>,
}

#[derive(Deserialize)]
struct Sample {
    iters: Vec<f64>,
    times: Vec<f64>,
}

#[derive(Deserialize)]
struct BenchmarkId {
    full_id: String,
}

struct Options {
    record: bool,
    baseline: PathBuf,
    output: PathBuf,
    from_run: Option<PathBuf>,
    skip: Vec<String>,
}

fn repository() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| "bench-compare must live at tools/bench-compare".into())
        .and_then(|path| Ok(path.canonicalize()?))
}

fn timestamp() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn options(repo: &Path) -> Result<Options> {
    let mut record = false;
    let mut baseline = repo.join("benches/baseline.json");
    let mut output = None;
    let mut from_run = None;
    let mut skip = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--record" => record = true,
            "--baseline" => baseline = args.next().ok_or("--baseline needs a path")?.into(),
            "--output" => {
                output = Some(PathBuf::from(
                    args.next().ok_or("--output needs a directory")?,
                ))
            }
            "--from-run" => {
                from_run = Some(PathBuf::from(
                    args.next().ok_or("--from-run needs a run.json")?,
                ))
            }
            "--skip" => {
                let bench = args.next().ok_or("--skip needs a bench name")?;
                if !SKIPPABLE.contains(&bench.as_str()) {
                    return Err(format!("--skip takes one of {SKIPPABLE:?}, not {bench}").into());
                }
                if !skip.contains(&bench) {
                    skip.push(bench);
                }
            }
            "--help" | "-h" => {
                println!("bench-compare [--record] [--baseline FILE] [--output DIR] [--from-run RUN.json] [--skip BENCH]...\n\
                    Default: run all nine benches and fail any p99 increase over 5%.\n\
                    --record replaces only this platform's baseline; use in a PR explicitly requesting a baseline update.\n\
                    --from-run compares saved evidence without rerunning; cannot be used with --record.\n\
                    --skip BENCH (repeatable) does not run BENCH; it is reported as skipped, never as a pass or a regression.\n\
                    Exit 0 pass, 1 regression, 2 setup error, 3 no baseline entry for this platform/CPU/cores.\n\
                    Set CARGO_TARGET_DIR outside the checkout and BSV_SCRIPT_CORPUS to corpus/seed.");
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }
    if record && from_run.is_some() {
        return Err("--record requires a fresh measurement; cannot use --from-run".into());
    }
    if record && !skip.is_empty() {
        return Err("--record needs every bench; cannot use --skip".into());
    }
    if from_run.is_some() && !skip.is_empty() {
        return Err(
            "--from-run compares the saved run as it names its skips; cannot use --skip".into(),
        );
    }
    let output = match output {
        Some(path) => path,
        None => {
            let base = std::env::var_os("BSV_BENCH_ARTIFACT_DIR")
                .or_else(|| std::env::var_os("CARGO_TARGET_DIR"))
                .or_else(|| std::env::var_os("TMPDIR"))
                .ok_or("set --output or BSV_BENCH_ARTIFACT_DIR/CARGO_TARGET_DIR/TMPDIR outside the checkout")?;
            PathBuf::from(base).join(format!("bench-run-{}-{}", timestamp()?, std::process::id()))
        }
    };
    Ok(Options {
        record,
        baseline,
        output,
        from_run,
        skip,
    })
}

fn command_output(command: &mut Command) -> Result<String> {
    let out = command.output()?;
    if !out.status.success() {
        return Err("machine or source metadata command failed".into());
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

fn machine() -> Result<Machine> {
    let model = if cfg!(target_os = "macos") {
        command_output(Command::new("sysctl").args(["-n", "machdep.cpu.brand_string"]))?
    } else if cfg!(target_os = "linux") {
        let cpu = fs::read_to_string("/proc/cpuinfo")?;
        cpu.lines()
            .find_map(|line| {
                line.strip_prefix("model name")
                    .or_else(|| line.strip_prefix("Model"))
            })
            .and_then(|s| s.split_once(':'))
            .map(|(_, s)| s.trim().to_string())
            .ok_or("CPU model is unavailable")?
    } else {
        return Err("recording supports Linux and macOS CPU metadata".into());
    };
    Ok(Machine {
        model,
        cores: std::thread::available_parallelism()?.get(),
    })
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    let position = (sorted.len() - 1) as f64 * p;
    let low = position.floor() as usize;
    let high = position.ceil() as usize;
    sorted[low] + (sorted[high] - sorted[low]) * (position - low as f64)
}

fn measure(sample: Sample) -> Result<Measurement> {
    if sample.iters.len() != sample.times.len() || sample.times.len() < SAMPLES {
        return Err(format!("need at least {SAMPLES} paired Criterion samples").into());
    }
    let mut values = Vec::with_capacity(sample.times.len());
    for (iters, time) in sample.iters.iter().zip(&sample.times) {
        if !iters.is_finite()
            || *iters < 1.0
            || iters.fract() != 0.0
            || !time.is_finite()
            || *time <= 0.0
        {
            return Err("nonpositive or nonfinite Criterion sample".into());
        }
        let value = time / iters;
        if !value.is_finite() || value <= 0.0 {
            return Err("invalid normalized sample".into());
        }
        values.push(value);
    }
    values.sort_by(f64::total_cmp);
    Ok(Measurement {
        p50_ns: percentile(&values, 0.50),
        p99_ns: percentile(&values, 0.99),
        samples: values.len(),
    })
}

fn measurements(root: &Path, result: &mut BTreeMap<String, Measurement>) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if !path.is_dir() {
            continue;
        }
        if path.file_name().is_some_and(|name| name == "new") && path.join("sample.json").is_file()
        {
            let id: BenchmarkId = serde_json::from_slice(&fs::read(path.join("benchmark.json"))?)?;
            let sample: Sample = serde_json::from_slice(&fs::read(path.join("sample.json"))?)?;
            if result.insert(id.full_id, measure(sample)?).is_some() {
                return Err("duplicate Criterion benchmark id".into());
            }
        } else {
            measurements(&path, result)?;
        }
    }
    Ok(())
}

fn validate_run(run: &Run) -> Result<()> {
    if run.platform.is_empty()
        || run.machine.model.is_empty()
        || run.machine.cores == 0
        || run.settings != Settings::default()
    {
        return Err("missing machine or incompatible benchmark settings".into());
    }
    let count = run.benchmarks.len();
    if count == 0 {
        return Err("empty benchmark run".into());
    }
    for (id, m) in &run.benchmarks {
        if id.is_empty()
            || m.samples < SAMPLES
            || !m.p50_ns.is_finite()
            || !m.p99_ns.is_finite()
            || m.p50_ns <= 0.0
            || m.p99_ns < m.p50_ns
        {
            return Err(format!("invalid measurement: {id}").into());
        }
    }
    for (i, bench) in run.skipped.iter().enumerate() {
        if !SKIPPABLE.contains(&bench.as_str()) || run.skipped[..i].contains(bench) {
            return Err(format!("invalid skipped bench: {bench}").into());
        }
    }
    if let Some(id) = run.benchmarks.keys().find(|id| run.skips_id(id)) {
        return Err(format!("a skipped bench was measured: {id}").into());
    }
    for id in required_ids() {
        if !run.skips_id(&id) && !run.benchmarks.contains_key(&id) {
            return Err(format!("missing benchmark: {id}").into());
        }
    }
    let wire = run
        .benchmarks
        .keys()
        .filter(|id| id.starts_with("wire_codec/"))
        .count();
    if !run.skips("wire_codec") && wire != 28 * 4 {
        return Err(format!("need all 112 wire codec measurements; found {wire}").into());
    }
    if !run.skips("script_spend")
        && (run.corpus["sha256"].as_str().is_none_or(|s| s.len() != 64)
            || run.corpus["rows"].as_u64().unwrap_or(0) == 0)
    {
        return Err("script corpus was absent or its provenance was not reported".into());
    }
    if run.skips("beef_stream") {
        if !run.memory.is_empty() {
            return Err("beef_stream was skipped but reported RSS".into());
        }
        return Ok(());
    }
    if run.memory.len() != 4 {
        return Err("need both BEEF sizes in both modes for RSS".into());
    }
    for mode in ["structure", "scripts"] {
        for bytes in [1_000_000_u64, 10_000_000] {
            let rows: Vec<_> = run
                .memory
                .iter()
                .filter(|m| m["mode"] == mode && m["bytes"] == bytes)
                .collect();
            if rows.len() != 1 {
                return Err("duplicate or missing BEEF RSS measurement".into());
            }
            let start = rows[0]["start_rss_bytes"]
                .as_u64()
                .ok_or("missing start RSS")?;
            let peak = rows[0]["peak_rss_bytes"]
                .as_u64()
                .ok_or("missing peak RSS")?;
            if peak < start || rows[0]["delta_rss_bytes"].as_u64() != Some(peak - start) {
                return Err("inconsistent RSS high water".into());
            }
        }
    }
    Ok(())
}

fn outside_checkout(path: &Path, repo: &Path) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    if absolute
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        return Err("output paths must not contain parent components".into());
    }
    let mut parent = absolute.as_path();
    while !parent.exists() {
        parent = parent
            .parent()
            .ok_or("output path has no existing ancestor")?;
    }
    if parent.canonicalize()?.starts_with(repo) {
        return Err("build and measurement output must be outside the checkout".into());
    }
    Ok(())
}

fn fresh_run(repo: &Path, output: &Path, skip: &[String]) -> Result<Run> {
    if std::env::var_os("BSV_SCRIPT_CORPUS").is_none() && !skip.iter().any(|b| b == "script_spend")
    {
        return Err("BSV_SCRIPT_CORPUS is required for the gate unless --skip script_spend".into());
    }
    let target = PathBuf::from(
        std::env::var_os("CARGO_TARGET_DIR").ok_or("set CARGO_TARGET_DIR outside the checkout")?,
    );
    outside_checkout(&target, repo)?;
    outside_checkout(output, repo)?;
    fs::create_dir_all(&target)?;
    let target = target.canonicalize()?;
    if target.starts_with(repo) {
        return Err("CARGO_TARGET_DIR must be outside the checkout".into());
    }
    if output.exists() {
        return Err("--output must name a fresh directory (stale samples are never reused)".into());
    }
    fs::create_dir_all(output)?;
    let output = output.canonicalize()?;
    if output.starts_with(repo) {
        return Err("benchmark output must be outside the checkout".into());
    }
    let settings = Settings::default();
    let mut command = Command::new("cargo");
    command
        .current_dir(repo)
        .args(["bench", "--locked", "--features", &settings.features]);
    for bench in BENCHES {
        if skip.iter().any(|b| b == bench) {
            println!("SKIPPED {bench}: not run (--skip)");
        } else {
            command.args(["--bench", bench]);
        }
    }
    command.args([
        "--",
        "--noplot",
        "--sample-size",
        &settings.sample_size.to_string(),
        "--warm-up-time",
        &settings.warm_up_seconds.to_string(),
        "--measurement-time",
        &settings.measurement_seconds.to_string(),
    ]);
    command
        .env("CARGO_TARGET_DIR", &target)
        .env("CRITERION_HOME", output.join("criterion"))
        .env("BSV_BENCH_ARTIFACT_DIR", &output)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or("benchmark stdout was not captured")?;
    let mut log = fs::File::create(output.join("bench.log"))?;
    let mut corpus = Value::Null;
    let mut memory = Vec::new();
    for line in BufReader::new(stdout).lines() {
        let line = line?;
        writeln!(log, "{line}")?;
        println!("{line}");
        if let Some(json) = line.strip_prefix("BSV_BENCH_CORPUS ") {
            if !corpus.is_null() {
                return Err("duplicate script provenance record".into());
            }
            corpus = serde_json::from_str(json)?;
        }
        if let Some(json) = line.strip_prefix("BSV_BENCH_MEMORY ") {
            memory.push(serde_json::from_str(json)?);
        }
    }
    if !child.wait()?.success() {
        return Err("a benchmark failed; baseline unchanged".into());
    }
    let mut benchmarks = BTreeMap::new();
    measurements(&output.join("criterion"), &mut benchmarks)?;
    let run = Run {
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        machine: machine()?,
        rustc: command_output(Command::new("rustc").current_dir(repo).arg("--version"))?,
        source_commit: command_output(
            Command::new("git")
                .arg("-C")
                .arg(repo)
                .args(["rev-parse", "HEAD"]),
        )?,
        recorded_unix_seconds: timestamp()?,
        settings,
        corpus,
        memory,
        benchmarks,
        skipped: skip.to_vec(),
    };
    validate_run(&run)?;
    fs::write(output.join("run.json"), serde_json::to_vec_pretty(&run)?)?;
    // This run alone, in the baseline's shape: the scoreboard's input (#84),
    // never written over benches/baseline.json.
    let proposed = Baseline {
        schema_version: 1,
        platforms: BTreeMap::from([(machine_key(&run), run.clone())]),
    };
    fs::write(
        output.join("baseline.json"),
        serde_json::to_vec_pretty(&proposed)?,
    )?;
    println!("Evidence: {}", output.join("run.json").display());
    Ok(run)
}

fn compare(base: &Run, run: &Run) -> Result<bool> {
    validate_run(base)?;
    validate_run(run)?;
    if !base.skipped.is_empty() {
        return Err("a baseline entry must measure every bench".into());
    }
    if base.platform != run.platform || base.machine != run.machine {
        return Err("CPU model/core count differs from baseline; record on matching hardware in a baseline PR".into());
    }
    if base.settings != run.settings || (!run.skips("script_spend") && base.corpus != run.corpus) {
        return Err("benchmark settings or script corpus differ from baseline".into());
    }
    let expected = base.benchmarks.keys().filter(|id| !run.skips_id(id));
    if !expected.eq(run.benchmarks.keys()) {
        return Err("benchmark inventory changed; baseline update needs a PR that says so".into());
    }
    println!("| benchmark | p50 ns | baseline p99 ns | p99 ns | change | status |\n|---|---:|---:|---:|---:|---|");
    let mut passed = true;
    for (id, actual) in &run.benchmarks {
        let expected = &base.benchmarks[id];
        let delta = actual.p99_ns / expected.p99_ns - 1.0;
        let ok = actual.p99_ns <= expected.p99_ns * (1.0 + MARGIN);
        passed &= ok;
        println!(
            "| {id} | {:.2} | {:.2} | {:.2} | {:+.2}% | {} |",
            actual.p50_ns,
            expected.p99_ns,
            actual.p99_ns,
            delta * 100.0,
            if ok { "PASS" } else { "REGRESSION" }
        );
    }
    Ok(passed)
}

/// The verdict's last lines: the measured benches' pass or fail, then each
/// skipped bench by name, which is neither.
fn summary(passed: bool, run: &Run) -> String {
    let mut text = format!(
        "{} ({} of {} benches measured): p99 threshold is +{:.0}%",
        if passed { "PASS" } else { "FAIL" },
        BENCHES.len() - run.skipped.len(),
        BENCHES.len(),
        MARGIN * 100.0
    );
    for bench in &run.skipped {
        text.push_str(&format!(
            "\nSKIPPED {bench}: not measured, neither a pass nor a regression"
        ));
    }
    text
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Pass,
    Regression,
    /// No entry for this platform, CPU model and core count: exit 3, which CI
    /// reads as a warning to record one, never as a pass or a failure.
    NoBaseline,
}

impl Outcome {
    fn code(&self) -> i32 {
        match self {
            Outcome::Pass => 0,
            Outcome::Regression => 1,
            Outcome::NoBaseline => 3,
        }
    }
}

/// Compare a validated run with its machine's entry in the baseline.
fn gate(baseline: &Baseline, measured: &Run) -> Result<Outcome> {
    let platform = machine_key(measured);
    let Some(base) = baseline.platforms.get(&platform) else {
        let recorded: Vec<_> = baseline.platforms.keys().map(String::as_str).collect();
        println!("Recorded baseline entries: {recorded:?}");
        println!("NO BASELINE ENTRY: {platform}");
        return Ok(Outcome::NoBaseline);
    };
    let passed = compare(base, measured)?;
    println!("{}", summary(passed, measured));
    Ok(if passed {
        Outcome::Pass
    } else {
        Outcome::Regression
    })
}

/// One baseline entry per platform, CPU model and core count: hosted runners
/// draw from several CPUs, and a p99 is only compared on the hardware it came from.
fn machine_key(run: &Run) -> String {
    format!(
        "{} / {} / {} cores",
        run.platform, run.machine.model, run.machine.cores
    )
}

fn run() -> Result<Outcome> {
    let repo = repository()?;
    let opts = options(&repo)?;
    let measured: Run = if let Some(path) = &opts.from_run {
        serde_json::from_slice(&fs::read(path)?)?
    } else {
        fresh_run(&repo, &opts.output, &opts.skip)?
    };
    validate_run(&measured)?;
    let platform = machine_key(&measured);
    let mut baseline: Baseline = if opts.baseline.is_file() {
        serde_json::from_slice(&fs::read(&opts.baseline)?)?
    } else if opts.record {
        Baseline {
            schema_version: 1,
            ..Baseline::default()
        }
    } else {
        return Err("baseline is absent; a baseline PR must record it".into());
    };
    if baseline.schema_version != 1 {
        return Err("unsupported baseline schema".into());
    }
    println!(
        "Machine: {}, {} cores ({})",
        measured.machine.model, measured.machine.cores, measured.platform
    );
    for memory in &measured.memory {
        println!("RSS: {memory}");
    }
    for mode in ["structure", "scripts"]
        .into_iter()
        .filter(|_| !measured.skips("beef_stream"))
    {
        let peak = |bytes: u64| -> Result<f64> {
            measured
                .memory
                .iter()
                .find(|m| m["mode"] == mode && m["bytes"] == bytes)
                .and_then(|m| m["peak_rss_bytes"].as_u64())
                .map(|n| n as f64)
                .ok_or_else(|| "missing RSS observation".into())
        };
        let slope = (peak(10_000_000)? - peak(1_000_000)?) / 9_000_000.0;
        println!("BEEF sampled RSS slope ({mode}): {slope:.6} bytes RSS / byte BEEF");
    }
    if opts.record {
        for (id, value) in &measured.benchmarks {
            println!(
                "| {id} | p50 {:.2} ns | p99 {:.2} ns |",
                value.p50_ns, value.p99_ns
            );
        }
        baseline.platforms.insert(platform, measured);
        // Write only after the complete run validates. No scratch file in the checkout.
        fs::write(&opts.baseline, serde_json::to_vec_pretty(&baseline)?)?;
        println!("RECORDED {} (explicit --record)", opts.baseline.display());
        Ok(Outcome::Pass)
    } else {
        gate(&baseline, &measured)
    }
}

fn main() {
    match run() {
        Ok(outcome) => std::process::exit(outcome.code()),
        Err(error) => {
            eprintln!("bench-compare: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests;
