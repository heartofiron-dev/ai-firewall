import unittest
from dataclasses import replace
from pathlib import Path

from ai_firewall.detector import HybridDetector
from ai_firewall.io import read_flows
from ai_firewall.model import LinearModel


ROOT = Path(__file__).resolve().parents[1]


class DetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.detector = HybridDetector(LinearModel.load(ROOT / "models" / "baseline.json"))
        cls.flows = read_flows(ROOT / "data" / "sample_flows.csv")

    def test_benign_examples_do_not_alert(self):
        for flow in self.flows[:2]:
            self.assertFalse(self.detector.analyze(flow).is_alert)

    def test_port_scan_is_explained(self):
        result = self.detector.analyze(self.flows[2])
        self.assertTrue(result.is_alert)
        self.assertIn("PORT_SCAN", result.rule_ids)
        self.assertEqual(result.model_version, "0.1.0")
        self.assertEqual(result.model_algorithm, "bootstrap_linear_risk_model")
        self.assertEqual(result.rule_evidence[0]["rule_id"], "PORT_SCAN")
        self.assertEqual(len(result.top_features), 3)
        magnitudes = [abs(item["contribution"]) for item in result.top_features]
        self.assertEqual(magnitudes, sorted(magnitudes, reverse=True))

    def test_brute_force_is_explained(self):
        result = self.detector.analyze(self.flows[3])
        self.assertTrue(result.is_alert)
        self.assertIn("BRUTE_FORCE", result.rule_ids)

    def test_connection_flood_is_critical(self):
        result = self.detector.analyze(self.flows[4])
        self.assertTrue(result.is_alert)
        self.assertEqual(result.severity, "critical")

    def test_data_spike_and_suspicious_port_alert(self):
        result = self.detector.analyze(self.flows[5])
        self.assertTrue(result.is_alert)
        self.assertIn("DATA_SPIKE", result.rule_ids)
        self.assertIn("SUSPICIOUS_PORT", result.rule_ids)
        self.assertEqual(
            {item["rule_id"] for item in result.rule_evidence},
            {"DATA_SPIKE", "SUSPICIOUS_PORT"},
        )

    def test_suspicious_port_alone_crosses_default_threshold(self):
        flow = replace(
            self.flows[0],
            dst_port=4444,
            bytes_sent=16,
            bytes_received=0,
            packets=5,
            syn_count=1,
            rst_count=0,
            unique_dst_ports_60s=1,
            connections_60s=1,
            failed_connections_60s=0,
        )
        result = self.detector.analyze(flow)
        self.assertTrue(result.is_alert)
        self.assertIn("SUSPICIOUS_PORT", result.rule_ids)
        self.assertGreaterEqual(result.risk_score, 0.60)

    def test_model_only_alert_still_has_structured_explanation(self):
        baseline = self.detector.model
        detector = HybridDetector(LinearModel(
            feature_names=baseline.feature_names,
            means=baseline.means,
            scales=baseline.scales,
            weights=baseline.weights,
            bias=8.0,
            metadata={"algorithm": "test_linear", "version": "test-1"},
        ))
        result = detector.analyze(self.flows[0])
        payload = result.to_dict()
        self.assertTrue(result.is_alert)
        self.assertEqual(result.rule_evidence, [])
        self.assertEqual(result.rule_ids, [])
        self.assertEqual(payload["model_version"], "test-1")
        self.assertEqual(len(payload["top_features"]), 3)


if __name__ == "__main__":
    unittest.main()
