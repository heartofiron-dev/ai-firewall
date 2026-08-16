import json
import tempfile
import unittest
from pathlib import Path

from ai_firewall.baseline_gate import evaluate_baseline_gate


class BaselineGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.report = self.root / "benchmark.json"
        self.provenance = self.root / "provenance.json"
        self.report.write_text(json.dumps({
            "schema_version": "1.0",
            "calibration": {"target_met": True},
            "independent_test": {
                "true_negative": 1200, "false_positive": 4,
                "false_positive_rate": 0.003322,
                "false_positives_per_day": 1.333333, "recall": 0.9,
                "per_day": {"2026-01-01": {}, "2026-01-02": {}, "2026-01-03": {}},
            },
        }), encoding="utf-8")
        self.statement = {
            "environment_id": "authorized-lab-a",
            "authorization_scope": "owner-approved endpoint metadata",
            "collection_period": "three separate days",
            "labeling_method": "manual review plus controlled replay",
            "authorization_confirmed": True,
            "anonymization_confirmed": True,
            "private_payloads_excluded": True,
            "independent_holdout_confirmed": True,
        }
        self.provenance.write_text(json.dumps(self.statement), encoding="utf-8")

    def tearDown(self):
        self.temporary.cleanup()

    def test_gate_passes_only_with_metrics_and_data_attestations(self):
        result = evaluate_baseline_gate(self.report, self.provenance)
        self.assertEqual(result["status"], "passed")
        self.assertTrue(all(result["checks"].values()))

    def test_gate_fails_when_authorization_is_not_attested(self):
        self.statement["authorization_confirmed"] = False
        self.provenance.write_text(json.dumps(self.statement), encoding="utf-8")
        result = evaluate_baseline_gate(self.report, self.provenance)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["checks"]["authorization_confirmed"])


if __name__ == "__main__":
    unittest.main()
