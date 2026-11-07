#!/usr/bin/env python3
"""Run trusted mobile benchmarks without publishing provider logs or signed URLs."""

import argparse
import base64
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import quote


DEVICES = {
    "android": ("Google Pixel 7", "13.0"),
    "ios": ("iPhone 14", "16"),
}
SPEC = importlib.util.spec_from_file_location("mobile_report", Path(__file__).with_name("mobile-bench-report.py"))
reporting = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reporting)
FUNCTIONS = reporting.FUNCTIONS
MOBENCH_REV = "217cfd4f78db1284276a1a1da44e3bf473729f5c"
URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s<>\"'`]+")
PRIVATE_KEY = re.compile(r"url|uri|token|password|credential|authorization|access.?key|username", re.IGNORECASE)


def redactor():
    credentials = [os.environ.get(name, "") for name in ("BROWSERSTACK_USERNAME", "BROWSERSTACK_ACCESS_KEY")]
    values = [value for value in credentials if value]
    if all(credentials):
        values.append(":".join(credentials))
    secrets = set()
    for value in values:
        secrets.update((value, quote(value, safe=""), base64.b64encode(value.encode()).decode()))

    def text(value):
        for secret in sorted(secrets, key=len, reverse=True):
            value = value.replace(secret, "[redacted]")
        return URL.sub("[URL removed]", value)

    def clean(value):
        if isinstance(value, dict):
            return {text(key): clean(item) for key, item in value.items() if not PRIVATE_KEY.search(key)}
        if isinstance(value, list):
            return [clean(item) for item in value]
        if isinstance(value, str):
            return text(value)
        return value

    return text, clean


def normalize_reports(reports, platform):
    raw = {}
    references = set()

    def add(source, report):
        reporting.require("benchmark_results" in report, "missing raw benchmark results")
        reporting.require(source not in raw, "duplicate raw report")
        raw[source] = {"source": source, "summary": report["summary"], "benchmark_results": report["benchmark_results"]}

    for source, report in reports.items():
        if "benchmark_results" in report:
            add(source, report)
        elif "targets" not in report:
            raise ValueError("missing raw benchmark results")
    for source, report in reports.items():
        if "targets" not in report:
            continue
        reporting.require(set(report["targets"]) == {platform}, "unexpected report platform")
        reporting.validate_summary(report["summary"], platform, FUNCTIONS)
        target = report["targets"][platform]
        reporting.validate_summary(target["summary"], platform, FUNCTIONS)
        # The pinned CLI embeds exact copies of its per-function files in the root.
        # Reconcile only these explicit copies, never arbitrary duplicate measurements.
        slugs = {function.replace("_", "__").replace("::", "_"): function for function in FUNCTIONS}
        reporting.require(set(target["functions"]) == set(slugs), "missing or unexpected embedded function")
        for slug, embedded in target["functions"].items():
            reporting.validate_summary(embedded["summary"], platform, (slugs[slug],))
            child = str(Path(source).parent / platform / slug / "summary.json")
            reporting.require(child not in references, "duplicate embedded report")
            references.add(child)
            if child in reports:
                reporting.require(reports[child] == embedded, "embedded and file reports disagree")
            else:
                add(child, embedded)
    return list(raw.values())


def export_reports(source, destination, clean, text, platform):
    reports = {}
    for path in sorted(source.rglob("summary.json")):
        report = json.loads(path.read_text())
        relative = path.relative_to(source)
        reports[str(relative)] = report
        output = destination / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(clean(report), indent=2) + "\n")
        for name in ("summary.md", "results.csv"):
            sibling = path.with_name(name)
            if sibling.is_file():
                output.with_name(name).write_text(text(sibling.read_text()))
    raw = clean(normalize_reports(reports, platform))
    (destination / "raw-results.json").write_text(json.dumps(raw, indent=2) + "\n")
    return raw


def export_sessions(source, destination, clean):
    sessions = []
    for path in sorted(source.rglob("session.json")):
        report = json.loads(path.read_text())
        fields = []

        def collect(value):
            if isinstance(value, dict):
                selected = {
                    key: item for key, item in value.items() if key in ("device", "os", "os_version", "status") and isinstance(item, (str, int, bool))
                }
                if selected:
                    fields.append(selected)
                for item in value.values():
                    collect(item)
            elif isinstance(value, list):
                for item in value:
                    collect(item)

        collect(report)
        sessions.append({"source": str(path.relative_to(source)), "session_id": path.parent.name.removeprefix("session-"), "fields": fields})
    (destination / "sessions.json").write_text(json.dumps(clean(sessions), indent=2) + "\n")


def results_complete(summary, platform):
    try:
        reporting.validate_summary(summary, platform, FUNCTIONS)
    except (ValueError, KeyError, TypeError):
        return False
    return True


def export_diagnostics(private, destination, text):
    excerpts = []
    for name in ("command.log", "command.stdout"):
        path = private / name
        with path.open("rb") as source:
            source.seek(max(0, path.stat().st_size - 16384))
            excerpts.extend(source.read().decode(errors="replace").splitlines()[-20:])
    (destination / "diagnostics.txt").write_text(text("\n".join(excerpts)) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True, choices=DEVICES)
    parser.add_argument("--source-sha", required=True, help="Exact source commit selected by the snapshot workflow")
    args = parser.parse_args()
    platform = args.platform
    device_model, device_os = DEVICES[platform]
    device_id = f"{device_model}-{device_os}"
    target = "aarch64-linux-android" if platform == "android" else "aarch64-apple-ios"
    os.umask(0o077)
    destination = Path("target/mobile-bench-results") / platform
    destination.mkdir(parents=True, exist_ok=False)
    text, clean = redactor()
    metadata = {
        "platform": platform,
        "source_sha": None,
        "source_repository": os.environ.get("GITHUB_REPOSITORY"),
        "trigger_ref": os.environ.get("GITHUB_REF"),
        "event": os.environ.get("GITHUB_EVENT_NAME"),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "workflow_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "rustc": None,
        "mobench_revision": MOBENCH_REV,
        "target": target,
        "profile": "release",
        "rustflags": os.environ.get("RUSTFLAGS", os.environ.get(f"CARGO_TARGET_{target.upper().replace('-', '_')}_RUSTFLAGS")),
        "thread_policy": "available_parallelism",
        "benchmarks": {},
        "candidate_device": device_id,
        "requested_device": device_model,
        "requested_os": platform,
        "requested_os_version": device_os,
        "device_validated": False,
        "functions": list(FUNCTIONS),
        "warmup": 1,
        "iterations": 3,
        "soc": None,
        "thermal_data": None,
        "status": "not_started",
    }
    exit_code = 1
    try:
        metadata["source_sha"] = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
        reporting.require(re.fullmatch(r"[0-9a-f]{40}", args.source_sha), "invalid source commit")
        reporting.require(metadata["source_sha"] == args.source_sha, "source commit mismatch")
        reporting.require(
            re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", metadata["source_repository"] or ""),
            "missing source repository",
        )
        reporting.require((metadata["workflow_run_id"] or "").isdecimal() and int(metadata["workflow_run_id"]) > 0, "missing workflow run")
        metadata["rustc"] = subprocess.check_output(["rustc", "--version"], text=True, stderr=subprocess.DEVNULL).strip()
        if platform == "android":
            metadata.update(
                {
                    "cargo_ndk_version": "4.1.2",
                    "android_ndk_version": "26.1.10909125",
                    "android_sdk": 34,
                    "android_build_tools": "34.0.0",
                }
            )
        else:
            os.environ["XCODE_XCCONFIG_FILE"] = str(Path("ios.xcconfig").resolve(strict=True))
            metadata.update(
                {
                    "ios_deployment_target": "16.0",
                    "ios_runner": "swiftui",
                    "swift_language_version": "5",
                    "xcode_version": subprocess.check_output(["xcodebuild", "-version"], text=True, stderr=subprocess.DEVNULL).strip(),
                    "ios_sdk_version": subprocess.check_output(
                        ["xcrun", "--sdk", "iphoneos", "--show-sdk-version"], text=True, stderr=subprocess.DEVNULL
                    ).strip(),
                }
            )
        if not all(os.environ.get(name) for name in ("BROWSERSTACK_USERNAME", "BROWSERSTACK_ACCESS_KEY")):
            metadata["status"] = "missing_credentials"
            print("BrowserStack credentials are missing. App Automate access and both repository secrets are required.")
            return 1
        with tempfile.TemporaryDirectory(prefix="mobile-bench-private-") as private:
            private = Path(private)
            reports = private / "reports"
            commands = (
                ("device_catalog", ["mobench", "devices", "--platform", platform, "--json"]),
                ("device_validation", ["mobench", "devices", "--platform", platform, "--validate", device_id]),
                (
                    "benchmark_run",
                    [
                        "mobench",
                        "ci",
                        "run",
                        "--target",
                        platform,
                        "--crate-path",
                        ".",
                        "--functions",
                        ",".join(FUNCTIONS),
                        "--devices",
                        device_id,
                        "--release",
                        "--iterations",
                        "3",
                        "--warmup",
                        "1",
                        "--fetch",
                        "--plots",
                        "off",
                        *(
                            ["--android-benchmark-timeout-secs", "1200"]
                            if platform == "android"
                            else ["--ios-completion-timeout-secs", "1200", "--ios-deployment-target", "16.0", "--ios-runner", "swiftui"]
                        ),
                        "--fetch-timeout-secs",
                        "1500",
                        "--output-dir",
                        str(reports),
                        "--fetch-output-dir",
                        str(private / "browserstack"),
                    ],
                ),
            )
            for stage, command in commands:
                metadata["status"] = stage
                with (private / "command.log").open("wb") as log, (private / "command.stdout").open("wb") as stdout:
                    try:
                        result = subprocess.run(command, stdout=stdout, stderr=log, timeout=3600, check=False)
                    except subprocess.TimeoutExpired:
                        metadata["status"] = stage + "_timeout"
                        print(f"Mobile benchmark {stage} timed out.")
                        log.flush()
                        stdout.flush()
                        export_diagnostics(private, destination, text)
                        break
                metadata[stage + "_exit_code"] = result.returncode
                if result.returncode:
                    metadata["status"] = stage + "_failed"
                    export_diagnostics(private, destination, text)
                    print(f"Mobile benchmark {stage} failed (exit {result.returncode}); see sanitized diagnostics.txt.")
                    if stage == "device_validation":
                        print("Check App Automate entitlement, credentials, and the candidate device in BrowserStack.")
                    break
                if stage == "device_catalog":
                    output = (private / "command.stdout").read_text()
                    catalog = json.loads(output[output.index("[") :])
                    matches = [
                        device
                        for device in catalog
                        if device.get("device") == device_model and device.get("os_version") == device_os and device.get("os") == platform
                    ]
                    metadata["catalog_matches"] = [
                        {key: device.get(key) for key in ("device", "os", "os_version", "available")} for device in matches
                    ]
                    if not matches or all(device.get("available") is False for device in matches):
                        metadata["status"] = "candidate_device_unavailable"
                        print(f"The candidate {device_model} / {platform} {device_os} is not available in the authenticated device catalog.")
                        break
                if stage == "device_validation":
                    metadata["device_validated"] = True
            else:
                summary = json.loads((reports / "summary.json").read_text())["summary"]
                if not results_complete(summary, platform):
                    metadata["status"] = "incomplete_results"
                    print("BrowserStack did not return three successful samples for both requested shielded workloads and device.")
                else:
                    metadata["status"] = "complete"
                    exit_code = 0
            raw = export_reports(reports, destination, clean, text, platform)
            export_sessions(private / "browserstack", destination, clean)
            if exit_code == 0:
                measured = reporting.validate_results(raw, platform)
                metadata["benchmarks"] = reporting.benchmark_metrics(measured)
                for key in ("threads", "available_parallelism"):
                    values = {metrics[key] for metrics in metadata["benchmarks"].values()}
                    if len(values) == 1:
                        metadata[key] = next(iter(values))
                metadata["measured_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                metadata["timestamp_basis"] = "collection_completed_at"
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError):
        metadata["status"] = "execution_or_report_error"
        exit_code = 1
        print("Mobile benchmark execution or report export failed. No raw provider diagnostics are published.")
    finally:
        (destination / "metadata.json").write_text(json.dumps(clean(metadata), indent=2) + "\n")
    if exit_code == 0:
        print(f"Both shielded benchmarks completed; sanitized reports are in {destination}.")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
