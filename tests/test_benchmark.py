import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ai_firewall.benchmark import build_benchmark_report, chronological_split
from ai_firewall.io import read_flows
from ai_firewall.model import LinearModel
from ai_firewall.schema import FlowRecord


ROOT = Path(__file__).resolve().parents[1]


def flow(index: int, label: str) -> FlowRecord:
    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(hours=12 * index)
    attack = label == "attack"
    return FlowRecord(
        timestamp=timestamp.isoformat().replace("+00:00", "Z"),
        src_ip=f"10.0.0.{index + 1}", dst_ip="192.168.1.10",
        src_port=50000 + index, dst_port=22 if attack else 443,
        protocol="TCP", duration_ms=500, packets=80 if attack else 12,
        bytes_sent=5000 if attack else 1200, bytes_received=500,
        syn_count=40 if attack else 1, rst_count=10 if attack else 0,
        unique_dst_ports_60s=30 if attack else 1,
        connections_60s=40 if attack else 3,
        failed_connections_60s=20 if attack else 0,
        label=label,
    )


class BenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = LinearModel.load(ROOT / "models" / "baseline.json")
        cls.flows = [flow(i, "benign" if i % 2 == 0 else "attack") for i in range(20)]

    def test_chronological_split_has_no_time_overlap(self):
        split = chronological_split(list(reversed(self.flows)), 0.4)
        self.assertEqual(len(split.calibration), 8)
        self.assertEqual(len(split.test), 12)
        self.assertLess(split.calibration[-1].timestamp, split.test[0].timestamp)

    def test_report_contains_daily_false_positives_and_warnings(self):
        report = build_benchmark_report(
            self.model, self.flows, calibration_fraction=0.4, target_fpr=0.0,
            source="synthetic-test",
        )
        self.assertEqual(report["method"], "chronological_holdout_with_benign_threshold_calibration")
        self.assertIn("per_day", report["independent_test"])
        self.assertIn("false_positives_per_day", report["independent_test"])
        self.assertTrue(report["warnings"])
        self.assertEqual(report["source"], "synthetic-test")

    def test_rejects_demo_sized_dataset(self):
        demo = read_flows(ROOT / "data" / "sample_flows.csv")
        with self.assertRaisesRegex(ValueError, "至少需要 8"):
            chronological_split(demo, 0.4)


if __name__ == "__main__":
    unittest.main()
