"""Mobile reporting must not publish invalid, incomplete or stale proof measurements."""

from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("mobile_report", Path(__file__).with_name("mobile-bench-report.py"))
report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(report)
RUN_SPEC = importlib.util.spec_from_file_location("mobile_run", Path(__file__).with_name("mobile-bench-run.py"))
runner = importlib.util.module_from_spec(RUN_SPEC)
RUN_SPEC.loader.exec_module(runner)
HEAD = "a" * 40
REPO = "example/leanVM"


class MobileReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.metadata = {
            "source_repository": REPO,
            "source_sha": HEAD,
            "workflow_run_id": "123",
            "status": "complete",
            "platform": "android",
            "device_validated": True,
            "candidate_device": "Google Pixel 7-13.0",
            "functions": list(report.FUNCTIONS),
            "warmup": 1,
            "iterations": 3,
            "threads": 6,
            "available_parallelism": 6,
        }
        self.result = {
            "function": report.FUNCTION,
            "spec": {"name": report.FUNCTION, "warmup": 1, "iterations": 3},
            "custom_metrics": {
                "run_u64": {"threads": 6, "available_parallelism": 6, "spends_per_leaf": 2, "leaf_log_inv_rate": 2, "verified_proofs": 4}
            },
            "samples_ns": [1_000_000_000, 9_000_000_000, 2_000_000_000],
            "samples": [{"duration_ns": value, "process_peak_memory_kb": peak, "peak_memory_kb": 12}
                        for value, peak in zip((1_000_000_000, 9_000_000_000, 2_000_000_000), (2048, 1024, 3072))],
            # Never trust a separately supplied aggregate instead of the samples.
            "median_ns": 999,
        }
        self.aggregate = deepcopy(self.result)
        self.aggregate.update(function=report.AGGREGATE_FUNCTION, spec={"name": report.AGGREGATE_FUNCTION, "warmup": 1, "iterations": 3})
        self.aggregate["custom_metrics"]["run_u64"].update(aggregation_leaves=2, aggregation_log_inv_rate=1, verified_leaves=2)
        self.aggregate["samples_ns"] = [10_000_000_000, 30_000_000_000, 20_000_000_000]
        self.aggregate["samples"] = [{"duration_ns": value, "process_peak_memory_kb": peak}
                                     for value, peak in zip(self.aggregate["samples_ns"], (4096, 6144, 5120))]
        self.falcon = deepcopy(self.result)
        self.falcon.update(function=report.FALCON_FUNCTION, spec={"name": report.FALCON_FUNCTION, "warmup": 1, "iterations": 3})
        self.falcon["custom_metrics"]["run_u64"] = {
            "threads": 6, "available_parallelism": 6, "signatures": 1, "log_inv_rate": 2, "verified_proofs": 4,
        }
        self.falcon["samples_ns"] = [3_000_000_000, 5_000_000_000, 4_000_000_000]
        self.falcon["samples"] = [{"duration_ns": value, "process_peak_memory_kb": peak}
                                  for value, peak in zip(self.falcon["samples_ns"], (7168, 9216, 8192))]
        self.stateproof = deepcopy(self.result)
        self.stateproof.update(function=report.STATEPROOF_FUNCTION, spec={"name": report.STATEPROOF_FUNCTION, "warmup": 1, "iterations": 3})
        self.stateproof["custom_metrics"]["run_u64"] = {
            "threads": 6, "available_parallelism": 6, "accounts": 1, "storage_slots": 1, "log_inv_rate": 2, "verified_proofs": 4,
        }
        self.stateproof["samples_ns"] = [6_000_000_000, 8_000_000_000, 7_000_000_000]
        self.stateproof["samples"] = [{"duration_ns": value, "process_peak_memory_kb": peak}
                                      for value, peak in zip(self.stateproof["samples_ns"], (12288, 10240, 11264))]
        self.results = [self.result, self.aggregate, self.falcon, self.stateproof]
        self.metadata["benchmarks"] = {result["function"]: deepcopy(result["custom_metrics"]["run_u64"]) for result in self.results}

    def raw_report(self, entries, device="Google Pixel 7"):
        platform = self.metadata["platform"]
        return {
            "summary": {
                "target": platform,
                "function": entries[0]["function"] if len(entries) == 1 else "multiple",
                "warmup": 1,
                "iterations": 3,
                "devices": [self.metadata["candidate_device"]],
                "device_summaries": [{"device": device, "benchmarks": [{"function": entry["function"], "samples": 3} for entry in entries]}],
            },
            "benchmark_results": {device: entries},
        }

    def combined_reports(self):
        # Pinned mobench lib.rs cmd_ci_run: root.targets.<platform>.functions
        # embeds the same reports also written to <platform>/<slug>/summary.json.
        functions = {entry["function"].replace("_", "__").replace("::", "_"): deepcopy(self.raw_report([entry]))
                     for entry in self.results}
        summary = self.raw_report(self.results)["summary"]
        root = {"summary": summary, "targets": {"android": {"summary": deepcopy(summary), "functions": deepcopy(functions)}}}
        return {"summary.json": root, **{f"android/{slug}/summary.json": value for slug, value in functions.items()}}

    def render(self, head=HEAD, device="Google Pixel 7", raw=None):
        (self.directory / "metadata.json").write_text(json.dumps(self.metadata))
        if raw is None:
            raw = [self.raw_report([entry], device) for entry in self.results]
        (self.directory / "raw-results.json").write_text(json.dumps(raw))
        return report.render(self.directory, REPO, head, "123")

    def test_median_and_range_come_from_samples(self):
        body, complete, _ = self.render()
        self.assertTrue(complete)
        self.assertIn("| 6 | 2.000 s | 1.000 to 9.000 s | 4 / 4 |", body)
        self.assertIn("| 6 | 20.000 s | 10.000 to 30.000 s | 4 / 4 |", body)
        self.assertIn("10.000000000 s, 30.000000000 s, 20.000000000 s", body)
        self.assertIn("| Falcon-512, verify 1 signature |", body)
        self.assertIn("| 6 | 4.000 s | 3.000 to 5.000 s | 4 / 4 |", body)
        self.assertIn("| L1 state proofs, verify 1 account and 1 storage slot |", body)
        self.assertIn("| 6 | 7.000 s | 6.000 to 8.000 s | 4 / 4 |", body)

    def test_memory_uses_absolute_sample_maximum_and_binary_units(self):
        measured = report.validate_results([self.raw_report(self.results)], "android")
        self.assertEqual(report.peak_memory_bytes(measured[report.FUNCTION]), 3072 * 1024)
        self.assertEqual(report.peak_memory_bytes(measured[report.AGGREGATE_FUNCTION]), 6144 * 1024)
        self.assertEqual(report.peak_memory_bytes(measured[report.FALCON_FUNCTION]), 9216 * 1024)
        self.assertEqual(report.peak_memory_bytes(measured[report.STATEPROOF_FUNCTION]), 12288 * 1024)
        # Neither baseline-adjusted growth nor a separately supplied aggregate
        # can replace the per-iteration SDK observations.
        self.result["resources"] = {"process_peak_memory_kb": 999999, "total_pss_kb": 888888}
        self.assertEqual(report.peak_memory_bytes(self.result), 3072 * 1024)

    def test_every_memory_sample_is_required_and_must_convert_to_safe_bytes(self):
        for index in range(3):
            for value in (None, 0, -1, True, 1.5, "1024", float("nan"), float("inf"), 2 ** 43):
                with self.subTest(index=index, value=value):
                    entries = deepcopy(self.results)
                    entries[0]["samples"][index]["process_peak_memory_kb"] = value
                    with self.assertRaisesRegex(ValueError, "peak memory"):
                        self.render(raw=[self.raw_report(entries)])
            entries = deepcopy(self.results)
            del entries[0]["samples"][index]["process_peak_memory_kb"]
            with self.assertRaisesRegex(ValueError, "peak memory"):
                self.render(raw=[self.raw_report(entries)])
        self.result["samples"][0]["process_peak_memory_kb"] = (2 ** 53 - 1) // 1024
        self.assertEqual(report.peak_memory_bytes(self.result), ((2 ** 53 - 1) // 1024) * 1024)

    def test_incomplete_run_publishes_no_latency(self):
        self.metadata["status"] = "incomplete_results"
        body, complete, _ = self.render()
        self.assertFalse(complete)
        self.assertNotIn("2.000 s", body)

    def test_iphone_cannot_be_labelled_as_android(self):
        self.metadata["platform"] = "ios"
        self.metadata["candidate_device"] = "iPhone 14-16"
        with self.assertRaisesRegex(ValueError, "unexpected measured device"):
            self.render()

    def test_iphone_provider_name_variants_preserve_device_identity(self):
        self.metadata["platform"] = "ios"
        self.metadata["candidate_device"] = "iPhone 14-16"
        for device in ("iPhone 14", "iPhone 14-16"):
            with self.subTest(device=device):
                body, complete, platform = self.render(device=device)
                self.assertTrue(complete)
                self.assertEqual(platform, "ios")
                self.assertIn("| iPhone 14 / iOS 16 | 6 | 2.000 s |", body)
        with self.assertRaisesRegex(ValueError, "unexpected measured device"):
            self.render(device="iPhone 14-17")

    def test_wrong_source_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "source commit mismatch"):
            self.render("b" * 40)

    def test_wrong_repository_or_workflow_run_is_rejected(self):
        for key, value, message in (
            ("source_repository", "other/leanVM", "source repository mismatch"),
            ("workflow_run_id", "124", "workflow run mismatch"),
        ):
            with self.subTest(key=key):
                original = self.metadata[key]
                self.metadata[key] = value
                with self.assertRaisesRegex(ValueError, message):
                    self.render()
                self.metadata[key] = original

    def test_unverified_proof_or_changed_thread_count_is_rejected(self):
        for key, value in (("verified_proofs", 3), ("threads", 8)):
            with self.subTest(key=key):
                old = self.result["custom_metrics"]["run_u64"][key]
                self.result["custom_metrics"]["run_u64"][key] = value
                with self.assertRaises(ValueError):
                    self.render()
                self.result["custom_metrics"]["run_u64"][key] = old

    def test_invalid_or_conflicting_samples_are_rejected(self):
        for samples in ([0, 1, 2], [True, 1, 2], [float("nan"), 1, 2], [1, 2], [1, 2, 3]):
            with self.subTest(samples=samples):
                self.result["samples_ns"] = samples
                with self.assertRaises(ValueError):
                    self.render()

    def test_combined_entries_preserve_all_four_workloads(self):
        body, complete, _ = self.render(raw=[self.raw_report(self.results)])
        self.assertTrue(complete)
        self.assertIn("| 6 | 2.000 s | 1.000 to 9.000 s |", body)
        self.assertIn("| 6 | 20.000 s | 10.000 to 30.000 s |", body)
        self.assertIn("| 6 | 4.000 s | 3.000 to 5.000 s |", body)
        self.assertIn("| 6 | 7.000 s | 6.000 to 8.000 s |", body)

    def test_missing_duplicate_or_unknown_function_is_rejected(self):
        unknown = deepcopy(self.aggregate)
        unknown["function"] = "other::benchmark"
        for entries in ([self.result], [self.result, self.aggregate], self.results[:-1], self.results[:2] + [self.stateproof],
                        [*self.results, self.aggregate], [*self.results, unknown]):
            with self.subTest(functions=[entry["function"] for entry in entries]), self.assertRaises(ValueError):
                self.render(raw=[self.raw_report(entries)])

    def test_wrong_aggregation_shape_or_verification_is_rejected_even_if_metadata_agrees(self):
        for key, value in (
            ("spends_per_leaf", 1),
            ("leaf_log_inv_rate", 1),
            ("aggregation_leaves", 4),
            ("aggregation_log_inv_rate", 2),
            ("verified_leaves", 1),
            ("verified_proofs", 3),
        ):
            with self.subTest(key=key):
                result = deepcopy(self.aggregate)
                result["custom_metrics"]["run_u64"][key] = value
                self.metadata["benchmarks"][report.AGGREGATE_FUNCTION][key] = value
                with self.assertRaises(ValueError):
                    self.render(raw=[self.raw_report([self.result, result, self.falcon, self.stateproof])])

    def test_single_unit_counts_rates_and_verification_are_required_even_if_metadata_agrees(self):
        for function, keys in (
            (report.FALCON_FUNCTION, ("signatures", "log_inv_rate", "verified_proofs")),
            (report.STATEPROOF_FUNCTION, ("accounts", "storage_slots", "log_inv_rate", "verified_proofs")),
        ):
            for key in keys:
                expected = self.metadata["benchmarks"][function][key]
                for value in (0, expected - 1, expected + 1, True, float(expected), str(expected)):
                    with self.subTest(function=function, key=key, value=value):
                        entries = deepcopy(self.results)
                        result = next(entry for entry in entries if entry["function"] == function)
                        result["custom_metrics"]["run_u64"][key] = value
                        self.metadata["benchmarks"][function][key] = value
                        with self.assertRaisesRegex(ValueError, f"invalid {key}"):
                            self.render(raw=[self.raw_report(entries)])
                self.metadata["benchmarks"][function][key] = expected

    def test_new_workloads_cannot_omit_memory_or_report_failure(self):
        for function in (report.FALCON_FUNCTION, report.STATEPROOF_FUNCTION):
            for mutation in ("memory", "failure", "verification"):
                with self.subTest(function=function, mutation=mutation):
                    entries = deepcopy(self.results)
                    result = next(entry for entry in entries if entry["function"] == function)
                    if mutation == "memory":
                        del result["samples"][1]["process_peak_memory_kb"]
                    elif mutation == "failure":
                        result["failure"] = "proof verification failed"
                    else:
                        del result["custom_metrics"]["run_u64"]["verified_proofs"]
                    with self.assertRaises((ValueError, KeyError)):
                        self.render(raw=[self.raw_report(entries)])

    def test_mixed_thread_counts_are_reported_per_function_not_as_shared(self):
        for key in ("threads", "available_parallelism"):
            self.aggregate["custom_metrics"]["run_u64"][key] = 4
            self.metadata["benchmarks"][report.AGGREGATE_FUNCTION][key] = 4
            del self.metadata[key]
        body, complete, _ = self.render()
        self.assertTrue(complete)
        self.assertIn("| 4 | 20.000 s |", body)
        self.assertIn("| 6 | 2.000 s |", body)
        self.metadata["threads"] = 6
        with self.assertRaisesRegex(ValueError, "inconsistent shared threads"):
            self.render()

    def test_real_combined_report_export_preserves_files_without_double_counting(self):
        source = self.directory / "private"
        destination = self.directory / "export"
        source.mkdir()
        destination.mkdir()
        for relative, value in self.combined_reports().items():
            path = source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value))
            path.with_name("results.csv").write_text(relative)
        text, clean = runner.redactor()
        raw = runner.export_reports(source, destination, clean, text, "android")
        body, complete, _ = self.render(raw=raw)
        measured = report.validate_results(raw, "android")
        self.assertEqual(report.peak_memory_bytes(measured[report.FUNCTION]), 3072 * 1024)
        self.assertEqual(report.peak_memory_bytes(measured[report.AGGREGATE_FUNCTION]), 6144 * 1024)
        self.assertTrue(complete)
        self.assertEqual(body.count("| 6 | 2.000 s |"), 1)
        self.assertEqual(body.count("| 6 | 20.000 s |"), 1)
        self.assertEqual(body.count("| 6 | 4.000 s |"), 1)
        self.assertEqual(body.count("| 6 | 7.000 s |"), 1)
        for relative in self.combined_reports():
            self.assertEqual((destination / relative).with_name("results.csv").read_text(), relative)
        embedded_only = runner.normalize_reports({"summary.json": self.combined_reports()["summary.json"]}, "android")
        self.assertEqual(report.benchmark_metrics(report.validate_results(embedded_only, "android")), self.metadata["benchmarks"])

    def test_combined_report_conflicts_missing_functions_and_duplicate_files_fail(self):
        reports = self.combined_reports()
        aggregate_path = "android/leanvm__mobile__bench_shielded__aggregate/summary.json"
        reports[aggregate_path]["benchmark_results"]["Google Pixel 7"][0]["samples_ns"][0] += 1
        with self.assertRaisesRegex(ValueError, "reports disagree"):
            runner.normalize_reports(reports, "android")
        reports = self.combined_reports()
        del reports["summary.json"]["targets"]["android"]["functions"]["leanvm__mobile__bench_shielded__aggregate"]
        with self.assertRaisesRegex(ValueError, "embedded function"):
            runner.normalize_reports(reports, "android")
        reports = self.combined_reports()
        reports["duplicate/summary.json"] = deepcopy(reports[aggregate_path])
        with self.assertRaisesRegex(ValueError, "duplicate measured function"):
            report.validate_results(runner.normalize_reports(reports, "android"), "android")

    def test_summary_platform_device_sample_counts_and_failures_are_checked(self):
        for key, value in (("target", "ios"), ("devices", ["Google Pixel 7-14.0"]), ("iterations", 2), ("warmup", 0)):
            with self.subTest(key=key):
                summary = self.raw_report(self.results)["summary"]
                summary[key] = value
                self.assertFalse(runner.results_complete(summary, "android"))
        summary = self.raw_report(self.results)["summary"]
        summary["device_summaries"][0]["benchmarks"][1]["failure"] = "verification failed"
        self.assertFalse(runner.results_complete(summary, "android"))

    def test_provider_credentials_and_signed_urls_are_redacted(self):
        with patch.dict("os.environ", {"BROWSERSTACK_USERNAME": "private-user", "BROWSERSTACK_ACCESS_KEY": "private-key"}):
            text, clean = runner.redactor()
            self.assertEqual(text("private-user private-key https://provider.example/result?signature=secret"), "[redacted] [redacted] [URL removed]")
            self.assertEqual(
                clean({"access_key": "private-key", "session_url": "https://provider.example", "message": "private-user", "samples_ns": [1, 2, 3]}),
                {"message": "[redacted]", "samples_ns": [1, 2, 3]},
            )

    def test_failed_iphone_does_not_erase_android_results(self):
        self.render()
        ios = self.directory / "ios"
        ios.mkdir()
        metadata = self.metadata | {"platform": "ios", "candidate_device": "iPhone 14-16", "status": "benchmark_run_failed"}
        (ios / "metadata.json").write_text(json.dumps(metadata))
        argv = ["report", str(self.directory), str(ios), "--repository", REPO, "--head", HEAD, "--run-id", "123"]
        output = io.StringIO()
        with patch("sys.argv", argv), patch("sys.stdout", output), patch.dict("os.environ", {}, clear=True):
            with self.assertRaisesRegex(ValueError, "incomplete mobile results"):
                report.main()
        self.assertIn("| Google Pixel 7 / Android 13.0 | 6 | 2.000 s |", output.getvalue())
        self.assertIn("### Mobile benchmarks: iPhone 14 / iOS 16", output.getvalue())
        self.assertNotIn("| iPhone 14", output.getvalue())


if __name__ == "__main__":
    unittest.main()
