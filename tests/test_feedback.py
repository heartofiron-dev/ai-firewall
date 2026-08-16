import json
import tempfile
import unittest
from pathlib import Path

from ai_firewall.dashboard import DashboardState, load_alerts
from ai_firewall.detector import HybridDetector
from ai_firewall.feedback import build_feedback_model, review_feedback
from ai_firewall.io import read_flows
from ai_firewall.model import LinearModel


ROOT = Path(__file__).resolve().parents[1]


class FeedbackTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.alerts = self.root / "alerts.jsonl"
        self.pending = self.root / "pending.jsonl"
        self.reviewed = self.root / "reviewed.jsonl"
        detector = HybridDetector(LinearModel.load(ROOT / "models" / "baseline.json"))
        result = detector.analyze(read_flows(ROOT / "data" / "sample_flows.csv")[0])
        self.alerts.write_text(json.dumps(result.to_dict(), ensure_ascii=False) + "\n", encoding="utf-8")
        rows, _, _ = load_alerts(self.alerts, self.pending)
        self.alert_id = rows[0]["_id"]
        DashboardState(self.alerts, self.pending).record_false_positive(self.alert_id)

    def tearDown(self):
        self.temporary.cleanup()

    def test_review_then_retrain_uses_only_sanitized_approved_features(self):
        report = review_feedback(
            self.alerts, self.pending, self.reviewed,
            decision="approve", alert_ids={self.alert_id}, reviewer="tester",
        )
        self.assertEqual(report["written"], 1)
        entry = json.loads(self.reviewed.read_text(encoding="utf-8"))
        self.assertEqual(entry["training_label"], 0)
        self.assertIn("features", entry)
        self.assertNotIn("src_ip", entry)
        self.assertNotIn("process_name", entry)

        model = build_feedback_model(
            ROOT / "data" / "sample_flows.csv", self.reviewed,
            epochs=20, learning_rate=0.03,
        )
        self.assertEqual(model["metadata"]["approved_feedback_rows"], 1)
        self.assertEqual(model["metadata"]["training_policy"], "explicitly_approved_feedback_only")

    def test_review_is_idempotent_and_reject_has_no_training_features(self):
        first = review_feedback(
            self.alerts, self.pending, self.reviewed,
            decision="reject", alert_ids={self.alert_id},
        )
        second = review_feedback(
            self.alerts, self.pending, self.reviewed,
            decision="reject", alert_ids={self.alert_id},
        )
        self.assertEqual(first["written"], 1)
        self.assertEqual(second["written"], 0)
        entry = json.loads(self.reviewed.read_text(encoding="utf-8"))
        self.assertNotIn("features", entry)
        with self.assertRaisesRegex(ValueError, "没有已批准"):
            build_feedback_model(ROOT / "data" / "sample_flows.csv", self.reviewed)

    def test_legacy_alert_without_feature_snapshot_cannot_be_approved(self):
        row = json.loads(self.alerts.read_text(encoding="utf-8"))
        row.pop("feature_snapshot")
        self.alerts.write_text(json.dumps(row) + "\n", encoding="utf-8")
        # Its content fingerprint changed, so a detached pending id is rejected first.
        with self.assertRaisesRegex(ValueError, "找不到"):
            review_feedback(
                self.alerts, self.pending, self.reviewed,
                decision="approve", alert_ids={self.alert_id},
            )


if __name__ == "__main__":
    unittest.main()
