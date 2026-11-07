"""A/B artifacts must never compare fixed16 measurements with historical defaults."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("ab.sh")


class AbResultsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def wrap(self, selection, results):
        path = self.root / "result.json"
        path.write_text(json.dumps(results))
        return subprocess.run(
            ["bash", "-c", 'source "$1"; wrap "$2" 1 base "$3"',
             "ab-test", str(SCRIPT), str(path), selection],
            capture_output=True, text=True,
        )

    def prove(self, base, head):
        selection = "blake2s-batch-16thread"
        work = self.root / "work"
        for side, results in (("base", base), ("head", head)):
            executable = work / side / selection
            executable.parent.mkdir(parents=True)
            executable.write_text(f"#!{sys.executable}\nprint({json.dumps(results)!r})\n")
            executable.chmod(0o755)
        result = subprocess.run(
            ["bash", "-c", '''source "$1"
work=$2 out=$3 ci=false rounds=2 testbed=local pr=1 base=1111111111111111111111111111111111111111
prove blake2s-batch-16thread''', "ab-test", str(SCRIPT), str(work), str(self.root / "out")],
            capture_output=True, text=True, env={**os.environ, "LC_ALL": "C"},
        )
        artifact = self.root / "out/ab-local-blake2s-batch-16thread/ab.json"
        return result, json.loads(artifact.read_text()) if artifact.exists() else None

    def test_historical_default_base_is_discarded_not_reported_as_removed(self):
        head = {"blake2s-batch-16thread": {"latency": {"value": 100}, "threads": {"value": 16}}}
        result, artifact = self.prove({"blake2s-batch": {"latency": {"value": 200}}}, head)
        self.assertEqual(result.returncode, 0, result.stderr)
        timings = {"blake2s-batch-16thread": {"latency": {"value": 100}}}
        topology = {"blake2s-batch-16thread": {"threads": 16}}
        self.assertEqual(artifact["runs"], [
            {"round": 1, "side": "head", "results": timings, "topology": topology},
            {"round": 2, "side": "head", "results": timings, "topology": topology},
        ])

    def test_compatible_base_remains_paired_with_head(self):
        base = {"blake2s-batch-16thread": {"latency": {"value": 200}, "threads": {"value": 16}}}
        head = {"blake2s-batch-16thread": {"latency": {"value": 100}, "threads": {"value": 16}}}
        result, artifact = self.prove(base, head)
        self.assertEqual(result.returncode, 0, result.stderr)
        base_timings = {"blake2s-batch-16thread": {"latency": {"value": 200}}}
        head_timings = {"blake2s-batch-16thread": {"latency": {"value": 100}}}
        topology = {"blake2s-batch-16thread": {"threads": 16}}
        self.assertEqual(artifact["runs"], [
            {"round": 1, "side": "base", "results": base_timings, "topology": topology},
            {"round": 1, "side": "head", "results": head_timings, "topology": topology},
            {"round": 2, "side": "head", "results": head_timings, "topology": topology},
            {"round": 2, "side": "base", "results": base_timings, "topology": topology},
        ])

    def test_head_with_wrong_pool_size_is_fatal(self):
        results = {"blake2s-batch-16thread": {"threads": {"value": 8}}}
        result, artifact = self.prove(results, results)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(artifact)

    def test_fixed16_requires_every_name_and_measured_pool_size(self):
        valid = {"pcs-open-20-16thread": {"threads": {"value": 16}}}
        incompatible = [
            {},
            {"pcs-open-20": {"threads": {"value": 16}}},
            {"pcs-open-20-16thread": {}},
            {"pcs-open-20-16thread": {"threads": {"value": 8}}},
            {**valid, "pcs-commit-20": {"threads": {"value": 16}}},
            {**valid, "pcs-commit-20-16thread": {"threads": {"value": 8}}},
        ]
        for results in incompatible:
            with self.subTest(results=results):
                result = self.wrap("pcs-throughput-16thread", results)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_tree_node_suffixes_preserve_their_identifiers(self):
        selection = "aggregate-leanxmss-100-2to1-16thread"
        results = {
            f"{selection}-{node}": {"latency": {"value": 100}, "threads": {"value": 16}}
            for node in ("first", "node")
        }
        result = self.wrap(selection, results)
        self.assertEqual(result.returncode, 0, result.stderr)
        wrapped = json.loads(result.stdout)
        self.assertEqual(wrapped["results"], {
            f"{selection}-{node}": {"latency": {"value": 100}} for node in ("first", "node")
        })
        self.assertEqual(wrapped["topology"], {
            f"{selection}-{node}": {"threads": 16} for node in ("first", "node")
        })

    def test_serial_and_legacy_cases_need_no_fixed16_pool_evidence(self):
        for selection in ("kernels", "leanxmss-100-1thread", "leanxmss-100-4thread", "leanxmss-100-8thread"):
            with self.subTest(selection=selection):
                results = {selection: {"latency": {"value": 100}}}
                result = self.wrap(selection, results)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)["results"], results)

    def test_legacy_topology_is_metadata_not_a_timing(self):
        selection = "leanxmss-100-4thread"
        results = {selection: {
            "latency": {"value": 100},
            "threads": {"value": 6},
            "performance-threads": {"value": 4},
            "efficiency-threads": {"value": 2},
        }}
        result = self.wrap(selection, results)
        self.assertEqual(result.returncode, 0, result.stderr)
        wrapped = json.loads(result.stdout)
        self.assertEqual(wrapped["results"], {selection: {"latency": {"value": 100}}})
        self.assertEqual(wrapped["topology"], {
            selection: {"threads": 6, "performance-threads": 4, "efficiency-threads": 2}
        })


if __name__ == "__main__":
    unittest.main()
