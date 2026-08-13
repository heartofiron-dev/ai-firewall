import unittest
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


if __name__ == "__main__":
    unittest.main()

