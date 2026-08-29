import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ai_firewall.research import (
    _average_precision,
    aggregate_research_reports,
    build_research_report,
    write_multiseed_bundle,
    write_research_bundle,
)
from ai_firewall.schema import FlowRecord


OPTIONAL_MODELS_AVAILABLE = bool(
    importlib.util.find_spec("sklearn") and importlib.util.find_spec("lightgbm")
)
SHAP_AVAILABLE = bool(
    importlib.util.find_spec("shap") and importlib.util.find_spec("matplotlib")
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
        syn_count=120 if attack else 1, rst_count=20 if attack else 0,
        unique_dst_ports_60s=35 if attack else 1,
        connections_60s=220 if attack else 3,
        failed_connections_60s=25 if attack else 0,
        label="attack" if attack else "benign",
    )


class ResearchExperimentTests(unittest.TestCase):
    def test_average_precision_groups_equal_scores(self):
        self.assertAlmostEqual(
            _average_precision([0.0, 0.0, 0.0, 0.0], [1, 0, 1, 0]),
            0.5,
        )

    @unittest.skipUnless(OPTIONAL_MODELS_AVAILABLE, "comparison extras are not installed")
    def test_builds_five_configurations_at_each_operating_point(self):
        report = build_research_report(
            [flow(index) for index in range(80)],
            target_fprs=(0.0, 0.01), seed=7, source="synthetic-test", batch_size=8,
        )
        self.assertEqual(
            set(report["configurations"]),
            {
                "rule_only", "logistic_regression", "isolation_forest",
                "lightgbm", "hybrid_logistic_rules",
            },
        )
        self.assertEqual(report["target_false_positive_rates"], [0.0, 0.01])
        self.assertEqual(report["split"]["test_rows"], 24)
        for configuration in report["configurations"].values():
            self.assertEqual(set(configuration["operating_points"]), {"0", "0.01"})
            self.assertIn("p95_us_per_row", configuration["latency"])
            for point in configuration["operating_points"].values():
                metrics = point["independent_test"]
                self.assertIn("f1", metrics)
                self.assertIn("average_precision", metrics)
                self.assertIn("recall_ci95", metrics)
                self.assertIn("false_positive_rate_ci95", metrics)
                self.assertIn("explanation_coverage", metrics)
        self.assertEqual(
            report["configurations"]["rule_only"]["operating_points"]["0.01"]
            ["independent_test"]["explanation_coverage"],
            1.0,
        )
        json.dumps(report, allow_nan=False)

    @unittest.skipUnless(OPTIONAL_MODELS_AVAILABLE, "comparison extras are not installed")
    def test_writes_machine_readable_table_and_editable_figures(self):
        report = build_research_report(
            [flow(index) for index in range(80)], target_fprs=(0.01,), batch_size=8,
        )
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "paper"
            outputs = write_research_bundle(report, output_dir)
            self.assertEqual(
                {path.name for path in outputs},
                {
                    "report.json", "metrics.csv", "recall-at-fixed-fpr.svg",
                    "latency-p95.svg", "REPRODUCIBILITY.md",
                },
            )
            self.assertIn("hybrid_logistic_rules", (output_dir / "metrics.csv").read_text())
            self.assertIn("<svg", (output_dir / "recall-at-fixed-fpr.svg").read_text())
            with self.assertRaisesRegex(ValueError, "已存在"):
                write_research_bundle(report, output_dir)

    @unittest.skipUnless(OPTIONAL_MODELS_AVAILABLE, "comparison extras are not installed")
    def test_aggregates_multiple_seeds_with_sample_standard_deviation(self):
        reports = [
            build_research_report(
                [flow(index) for index in range(80)],
                target_fprs=(0.01,), seed=seed, source="same-source", batch_size=8,
            )
            for seed in (7, 9)
        ]
        aggregate = aggregate_research_reports(reports)
        self.assertEqual(aggregate["seeds"], [7, 9])
        recall = next(
            row for row in aggregate["statistics"]
            if row["configuration"] == "logistic_regression"
            and row["target_fpr"] == 0.01
            and row["metric"] == "recall"
        )
        self.assertEqual(recall["n"], 2)
        self.assertIsNotNone(recall["sample_std"])
        with tempfile.TemporaryDirectory() as temporary:
            outputs = write_multiseed_bundle(aggregate, temporary)
            self.assertEqual(len(outputs), 4)
            self.assertIn(
                "Mean ± sample SD",
                (Path(temporary) / "MULTISEED_SUMMARY.md").read_text(encoding="utf-8"),
            )

    @unittest.skipUnless(
        OPTIONAL_MODELS_AVAILABLE and SHAP_AVAILABLE,
        "comparison or SHAP extras are not installed",
    )
    def test_lightgbm_shap_explains_all_reported_alerts_and_writes_plots(self):
        report = build_research_report(
            [flow(index) for index in range(80)],
            target_fprs=(0.01,), seed=7, source="synthetic-shap-test",
            batch_size=8, include_shap=True,
            shap_background_size=10, shap_summary_size=10,
        )
        analysis = report["shap_analysis"]
        self.assertEqual(analysis["explainer"], "TreeExplainer")
        metrics = report["configurations"]["lightgbm"]["operating_points"]["0.01"]
        metrics = metrics["independent_test"]
        self.assertEqual(
            metrics["explanation_coverage"],
            1.0 if metrics["alerts"] else None,
        )
        with tempfile.TemporaryDirectory() as temporary:
            outputs = write_research_bundle(report, temporary)
            names = {path.name for path in outputs}
            self.assertIn("shap-beeswarm.png", names)
            self.assertIn("shap-global-bar.png", names)
            self.assertTrue((Path(temporary) / "shap-analysis.json").is_file())


if __name__ == "__main__":
    unittest.main()
