import importlib.util
import json
import unittest
from argparse import Namespace
from datetime import datetime, timedelta, timezone

from ai_firewall.comparison import build_model_comparison, chronological_model_split
from ai_firewall.cli import run_compare_models
from ai_firewall.schema import FlowRecord


OPTIONAL_MODELS_AVAILABLE = bool(
    importlib.util.find_spec("sklearn") and importlib.util.find_spec("lightgbm")
)


def flow(index: int) -> FlowRecord:
    attack = index % 2 == 1
    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=index)
    return FlowRecord(
        timestamp=timestamp.isoformat().replace("+00:00", "Z"),
        src_ip=f"10.0.{index // 250}.{index % 250 + 1}", dst_ip="192.0.2.10",
        src_port=40000 + index, dst_port=22 if attack else 443,
        protocol="TCP", duration_ms=120 if attack else 1200,
        packets=120 if attack else 12,
        bytes_sent=9000 if attack else 900, bytes_received=500,
        syn_count=80 if attack else 1, rst_count=20 if attack else 0,
        unique_dst_ports_60s=35 if attack else 1,
        connections_60s=60 if attack else 3,
        failed_connections_60s=25 if attack else 0,
        label="attack" if attack else "benign",
    )


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.flows = [flow(index) for index in range(60)]

    def test_three_way_split_is_chronological_and_shared(self):
        split = chronological_model_split(list(reversed(self.flows)), 0.5, 0.2)
        self.assertEqual((len(split.train), len(split.calibration), len(split.test)), (30, 12, 18))
        self.assertLess(split.train[-1].timestamp, split.calibration[0].timestamp)
        self.assertLess(split.calibration[-1].timestamp, split.test[0].timestamp)

    def test_rejects_tiny_dataset(self):
        with self.assertRaisesRegex(ValueError, "至少需要 20"):
            chronological_model_split(self.flows[:19])

    def test_cli_refuses_to_replace_input_csv(self):
        args = Namespace(
            input="same.csv", output="same.csv", overwrite=True,
            train_fraction=0.5, calibration_fraction=0.2,
            target_fpr=0.01, seed=42,
        )
        with self.assertRaisesRegex(ValueError, "不能与输入 CSV 相同"):
            run_compare_models(args)

    @unittest.skipUnless(OPTIONAL_MODELS_AVAILABLE, "comparison extras are not installed")
    def test_compares_all_models_on_identical_test_rows(self):
        report = build_model_comparison(
            self.flows, train_fraction=0.5, calibration_fraction=0.2,
            target_fpr=0.0, seed=7, source="synthetic-test",
        )
        self.assertEqual(report["method"], "shared_chronological_train_calibration_test")
        self.assertEqual(
            set(report["models"]),
            {"logistic_regression", "isolation_forest", "lightgbm"},
        )
        self.assertEqual(report["split"]["test_rows"], 18)
        for model in report["models"].values():
            self.assertEqual(model["independent_test"]["rows"], 18)
            self.assertEqual(model["calibration"]["target_false_positive_rate"], 0.0)
            self.assertIn("version", model["metadata"])
        self.assertEqual(set(report["ranking"]), set(report["models"]))
        self.assertTrue(report["warnings"])
        json.dumps(report, allow_nan=False)


if __name__ == "__main__":
    unittest.main()
