import unittest
from pathlib import Path

from ai_firewall.detector import HybridDetector
from ai_firewall.io import read_flows
from ai_firewall.model import LinearModel
from ai_firewall.performance import build_performance_report


ROOT = Path(__file__).resolve().parents[1]


class PerformanceTests(unittest.TestCase):
    def test_report_contains_reproducible_latency_cpu_and_memory_metrics(self):
        detector = HybridDetector(LinearModel.load(ROOT / "models" / "baseline.json"))
        report = build_performance_report(
            detector, read_flows(ROOT / "data" / "sample_flows.csv"),
            iterations=3, warmup=1, max_p95_ms=1000, max_peak_mib=1000,
        )
        self.assertTrue(report["passed"])
        self.assertEqual(report["metrics"]["flows_processed"], 18)
        self.assertIn("cpu_percent_single_core", report["metrics"])
        self.assertIn("p95", report["metrics"]["latency_ms"])
        self.assertIn("peak", report["metrics"]["traced_memory_mib"])
        self.assertNotIn("hostname", report["runtime"])


if __name__ == "__main__":
    unittest.main()
