use leanvm_mobile_bench::{
    ACCOUNTS, AGGREGATE_BENCHMARK, AGGREGATION_LEAVES, AGGREGATION_LOG_INV_RATE, DEFAULT_ITERATIONS, DEFAULT_WARMUP,
    FALCON_BENCHMARK, LEAF_LOG_INV_RATE, PROVE_BENCHMARK, SIGNATURES, SPENDS_PER_LEAF, STANDALONE_LOG_INV_RATE,
    STATEPROOF_BENCHMARK, STORAGE_SLOTS,
};
use mobench_sdk::{BenchSpec, MobenchBuf};
use serde_json::Value;
use std::error::Error;
use std::ffi::CStr;

fn run(name: &str) -> Result<Value, Box<dyn Error>> {
    let spec = BenchSpec::new(name, DEFAULT_ITERATIONS, DEFAULT_WARMUP)?;
    let input = serde_json::to_vec(&spec)?;
    let mut output = MobenchBuf::default();
    // SAFETY: the serialized input and writable output live through the synchronous call.
    let status =
        unsafe { leanvm_mobile_bench::mobench_run_benchmark_json(input.as_ptr(), input.len(), &raw mut output) };
    if status != 0 {
        // SAFETY: the SDK returns a live thread-local, nul-terminated error string.
        let error = unsafe { CStr::from_ptr(leanvm_mobile_bench::mobench_last_error_message()) };
        return Err(format!("{name}: {}", error.to_string_lossy()).into());
    }
    // SAFETY: the SDK keeps its nul-terminated error string live on this thread.
    let error = unsafe { CStr::from_ptr(leanvm_mobile_bench::mobench_last_error_message()) };
    assert!(
        error.to_bytes().is_empty(),
        "{name}: successful invocation clears the previous error"
    );
    // SAFETY: a successful SDK call transfers one live byte buffer, freed once after parsing.
    let report = unsafe {
        let bytes = std::slice::from_raw_parts(output.ptr, output.len);
        let parsed = serde_json::from_slice::<Value>(bytes);
        leanvm_mobile_bench::mobench_free_buf(&raw mut output);
        parsed
    }?;
    assert_eq!(report["spec"]["name"], name);
    assert_eq!(report["spec"]["iterations"], DEFAULT_ITERATIONS);
    assert_eq!(report["spec"]["warmup"], DEFAULT_WARMUP);
    assert_eq!(
        report["samples"].as_array().expect("SDK samples").len(),
        DEFAULT_ITERATIONS as usize
    );
    let metrics = &report["custom_metrics"]["run_u64"];
    assert_eq!(metrics["threads"], std::thread::available_parallelism()?.get() as u64);
    assert_eq!(metrics["available_parallelism"], metrics["threads"]);
    let workload: &[(&str, u64)] = match name {
        PROVE_BENCHMARK => &[
            ("spends_per_leaf", SPENDS_PER_LEAF as u64),
            ("leaf_log_inv_rate", u64::from(LEAF_LOG_INV_RATE)),
        ],
        AGGREGATE_BENCHMARK => &[
            ("spends_per_leaf", SPENDS_PER_LEAF as u64),
            ("leaf_log_inv_rate", u64::from(LEAF_LOG_INV_RATE)),
            ("aggregation_leaves", AGGREGATION_LEAVES as u64),
            ("aggregation_log_inv_rate", u64::from(AGGREGATION_LOG_INV_RATE)),
            ("verified_leaves", AGGREGATION_LEAVES as u64),
        ],
        FALCON_BENCHMARK => &[
            ("signatures", SIGNATURES as u64),
            ("log_inv_rate", u64::from(STANDALONE_LOG_INV_RATE)),
        ],
        STATEPROOF_BENCHMARK => &[
            ("accounts", ACCOUNTS as u64),
            ("storage_slots", STORAGE_SLOTS as u64),
            ("log_inv_rate", u64::from(STANDALONE_LOG_INV_RATE)),
        ],
        _ => return Err(format!("unexpected benchmark {name}").into()),
    };
    for (counter, expected) in workload {
        assert_eq!(metrics[*counter], *expected, "{name}: {counter}");
    }
    assert_eq!(metrics.as_object().expect("SDK run counters").len(), workload.len() + 3);
    assert_eq!(
        metrics["verified_proofs"],
        u64::from(DEFAULT_WARMUP + DEFAULT_ITERATIONS)
    );
    Ok(report)
}

fn reject_invalid_spec(name: &str) -> Result<(), Box<dyn Error>> {
    let input = serde_json::to_vec(&serde_json::json!({
        "name": name,
        "iterations": 0,
        "warmup": DEFAULT_WARMUP,
    }))?;
    let mut output = MobenchBuf::default();
    // SAFETY: both buffers live through the synchronous exported ABI call.
    let status =
        unsafe { leanvm_mobile_bench::mobench_run_benchmark_json(input.as_ptr(), input.len(), &raw mut output) };
    // SAFETY: the SDK owns the live thread-local, nul-terminated error string.
    let error = unsafe { CStr::from_ptr(leanvm_mobile_bench::mobench_last_error_message()) };
    let message = error.to_string_lossy().into_owned();
    // SAFETY: the SDK accepts its initialized empty/error buffer and resets it after freeing.
    unsafe { leanvm_mobile_bench::mobench_free_buf(&raw mut output) };
    assert_ne!(status, 0, "{name}: invalid iterations must fail through the C ABI");
    assert!(
        !message.is_empty(),
        "{name}: failure must carry a consumer-visible error"
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut names = mobench_sdk::registry::list_benchmark_names();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            FALCON_BENCHMARK,
            AGGREGATE_BENCHMARK,
            PROVE_BENCHMARK,
            STATEPROOF_BENCHMARK
        ]
    );
    for pass in 1..=2 {
        for name in [
            PROVE_BENCHMARK,
            AGGREGATE_BENCHMARK,
            FALCON_BENCHMARK,
            STATEPROOF_BENCHMARK,
        ] {
            reject_invalid_spec(name)?;
            let report = run(name)?;
            println!("{}", serde_json::json!({ "smoke_pass": pass, "report": report }));
        }
    }
    Ok(())
}
