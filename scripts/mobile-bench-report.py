#!/usr/bin/env python3
"""Validate and render mobile results in the caller's Actions summary."""

import argparse
import json
import math
import os
from pathlib import Path
import re
import statistics


FUNCTION = "leanvm_mobile_bench::shielded_prove"
AGGREGATE_FUNCTION = "leanvm_mobile_bench::shielded_aggregate"
FALCON_FUNCTION = "leanvm_mobile_bench::falcon_prove"
STATEPROOF_FUNCTION = "leanvm_mobile_bench::stateproof_prove"
FUNCTIONS = (FUNCTION, AGGREGATE_FUNCTION, FALCON_FUNCTION, STATEPROOF_FUNCTION)
WORKLOADS = {
    FUNCTION: {"spends_per_leaf": 2, "leaf_log_inv_rate": 2, "verified_proofs": 4},
    AGGREGATE_FUNCTION: {
        "spends_per_leaf": 2,
        "leaf_log_inv_rate": 2,
        "verified_proofs": 4,
        "aggregation_leaves": 2,
        "aggregation_log_inv_rate": 1,
        "verified_leaves": 2,
    },
    FALCON_FUNCTION: {"signatures": 1, "log_inv_rate": 2, "verified_proofs": 4},
    STATEPROOF_FUNCTION: {"accounts": 1, "storage_slots": 1, "log_inv_rate": 2, "verified_proofs": 4},
}
LABELS = {
    FUNCTION: "Shielded, 2 spends",
    AGGREGATE_FUNCTION: "Shielded 2-to-1, two 2-spend leaves / 4 spends total",
    FALCON_FUNCTION: "Falcon-512, verify 1 signature",
    STATEPROOF_FUNCTION: "L1 state proofs, verify 1 account and 1 storage slot",
}
DEVICES = {
    "android": ("Google Pixel 7", "13.0", "Android"),
    "ios": ("iPhone 14", "16", "iOS"),
}
MAX_SAFE_INTEGER = 2 ** 53 - 1
MEMORY_READERS = {
    "android": "Android /proc/self/statm resident pages",
    "ios": "iOS task_info(MACH_TASK_BASIC_INFO) resident_size",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def positive(value):
    return type(value) is int and value > 0


def peak_memory_bytes(result):
    # Pinned mobench timing.rs serializes absolute RSS separately from the
    # legacy peak_memory_kb field, which is only baseline-adjusted growth.
    peaks = [sample.get("process_peak_memory_kb") for sample in result["samples"]]
    require(bool(peaks) and all(positive(value) and value <= MAX_SAFE_INTEGER // 1024 for value in peaks),
            "missing or invalid sampled process peak memory")
    return max(peaks) * 1024


def peak_memory_method(platform):
    return (
        f"Maximum sampled process RSS across this function's three measured iterations; "
        f"mobench samples {MEMORY_READERS[platform]} at 1 ms intervals and iteration boundaries "
        "(KiB converted to bytes). Setup, warmup and teardown are outside the sampling windows, "
        "but their resident allocations, retained proofs and allocator residency can be included. "
        "Not baseline-adjusted growth or an OS lifetime high-water mark; brief peaks may be missed."
    )


def validate_summary(summary, platform, functions):
    model, version, _ = DEVICES[platform]
    require(summary["target"] == platform, "unexpected measured platform")
    require(summary["function"] == (functions[0] if len(functions) == 1 else "multiple"), "unexpected summary function")
    require(type(summary["warmup"]) is int and summary["warmup"] == 1, "unexpected warmup")
    require(type(summary["iterations"]) is int and summary["iterations"] == 3, "unexpected iterations")
    require(summary["devices"] == [f"{model}-{version}"], "unexpected requested device")
    devices = summary["device_summaries"]
    require(len(devices) == 1 and devices[0]["device"] in (model, f"{model}-{version}"), "unexpected measured device")
    entries = devices[0]["benchmarks"]
    require(len(entries) == len(functions) and {entry["function"] for entry in entries} == set(functions), "missing or duplicate summary function")
    require(
        all(type(entry["samples"]) is int and entry["samples"] == 3 and not entry.get("failure") for entry in entries), "incomplete summary samples"
    )


def validate_results(raw, platform):
    model, version, _ = DEVICES[platform]
    measured = {}
    for report in raw:
        devices = report["benchmark_results"]
        require(len(devices) == 1, "unexpected measured device")
        device, entries = next(iter(devices.items()))
        require(device in (model, f"{model}-{version}"), "unexpected measured device")
        require(bool(entries), "empty benchmark report")
        functions = [entry["function"] for entry in entries]
        validate_summary(report["summary"], platform, functions)
        for result in entries:
            function = result["function"]
            require(function in FUNCTIONS and function not in measured, "unexpected or duplicate measured function")
            require(result["spec"] == {"name": function, "warmup": 1, "iterations": 3}, "unexpected measured specification")
            require(not result.get("failure"), "failed benchmark")
            metrics = result["custom_metrics"]["run_u64"]
            for key, value in WORKLOADS[function].items():
                require(type(metrics[key]) is int and metrics[key] == value, f"invalid {key}")
            require(
                positive(metrics["threads"])
                and type(metrics["available_parallelism"]) is int
                and metrics["threads"] == metrics["available_parallelism"],
                "invalid thread count",
            )
            samples = result["samples_ns"]
            require(len(samples) == 3 and all(positive(value) and math.isfinite(value) for value in samples), "invalid samples")
            require([sample["duration_ns"] for sample in result["samples"]] == samples, "sample records disagree")
            peak_memory_bytes(result)
            measured[function] = result
    require(set(measured) == set(FUNCTIONS), "missing benchmark function")
    return measured


def benchmark_metrics(measured):
    return {
        function: {key: result["custom_metrics"]["run_u64"][key] for key in ("threads", "available_parallelism", *WORKLOADS[function])}
        for function, result in measured.items()
    }


def render(directory, repository, head, run_id):
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository), "invalid repository")
    require(re.fullmatch(r"[0-9a-f]{40}", head), "invalid commit")
    require(run_id.isdecimal() and int(run_id) > 0, "invalid run ID")
    metadata = json.loads((directory / "metadata.json").read_text())
    require(metadata["source_repository"] == repository, "source repository mismatch")
    require(metadata["source_sha"] == head, "source commit mismatch")
    require(metadata["workflow_run_id"] == run_id, "workflow run mismatch")
    platform = metadata["platform"]
    require(platform in DEVICES, "unexpected platform")
    model, version, os_name = DEVICES[platform]
    link = f"https://github.com/{repository}/actions/runs/{run_id}"
    prefix = f"### Mobile benchmarks: {model} / {os_name} {version}\n\n[Actions run and full artifacts]({link}) · Source `{head}`.\n\n"
    if metadata["status"] != "complete":
        return prefix + "The device benchmark did not complete successfully. No performance result is published.\n", False, platform
    require(metadata["device_validated"] is True, "device was not validated")
    require(metadata["candidate_device"] == f"{model}-{version}", "unexpected device")
    require(metadata["functions"] == list(FUNCTIONS), "unexpected workload")
    require(metadata["warmup"] == 1 and metadata["iterations"] == 3, "unexpected workload shape")
    raw = json.loads((directory / "raw-results.json").read_text())
    measured = validate_results(raw, platform)
    observed = benchmark_metrics(measured)
    require(metadata["benchmarks"] == observed, "benchmark metrics mismatch")
    require(all(type(value) is int for metrics in metadata["benchmarks"].values() for value in metrics.values()), "invalid benchmark metrics")
    for key in ("threads", "available_parallelism"):
        values = {metrics[key] for metrics in observed.values()}
        if len(values) == 1:
            require(type(metadata[key]) is int and metadata[key] == next(iter(values)), f"{key} mismatch")
        else:
            require(key not in metadata, f"inconsistent shared {key}")
    rows = [
        "| Benchmark | Device / OS | Threads | Median | Sample range | Verified proofs |",
        "|---|---|---:|---:|---:|---:|",
    ]
    sample_rows = []
    for function in FUNCTIONS:
        samples = measured[function]["samples_ns"]
        threads = observed[function]["threads"]
        median = statistics.median(samples) / 1e9
        rows.append(
            f"| {LABELS[function]} | {model} / {os_name} {version} | {threads} | {median:.3f} s | {min(samples) / 1e9:.3f} to {max(samples) / 1e9:.3f} s | 4 / 4 |"
        )
        sample_rows.append(f"`{function.rsplit('::', 1)[1]}` samples: " + ", ".join(f"{value / 1e9:.9f} s" for value in samples) + ".")
    return prefix + "\n".join([*rows, "", *sample_rows, ""]), True, platform


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, nargs="+")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    reports = [render(directory, args.repository, args.head, args.run_id) for directory in args.directory]
    require(len({platform for _, _, platform in reports}) == len(reports), "duplicate platform reports")
    for directory, (section, _, _) in zip(args.directory, reports):
        (directory / "ci-summary.md").write_text(section)
    body = "\n".join(section for section, _, _ in reports)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a") as output:
            output.write(body)
    print(body)
    require(all(success for _, success, _ in reports), "incomplete mobile results")


if __name__ == "__main__":
    main()
