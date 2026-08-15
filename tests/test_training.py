import tempfile
import unittest
from pathlib import Path

from ai_firewall.features import extract_features
from ai_firewall.io import read_flows
from ai_firewall.model import LinearModel
from ai_firewall.training import save_model, train_logistic_model


ROOT = Path(__file__).resolve().parents[1]


class TrainingTests(unittest.TestCase):
    def test_training_creates_loadable_model(self):
        flows = read_flows(ROOT / "data" / "sample_flows.csv")
        trained = train_logistic_model(flows, epochs=40, learning_rate=0.03)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "model.json"
            save_model(trained, path)
            model = LinearModel.load(path)
            scores = [model.predict_probability(extract_features(flow)) for flow in flows]
        self.assertTrue(all(0.0 <= score <= 1.0 for score in scores))
        self.assertEqual(trained["metadata"]["training_rows"], len(flows))
        self.assertRegex(model.model_version, r"^sha256:[0-9a-f]{12}$")

    def test_explanation_rejects_invalid_limit(self):
        model = LinearModel.load(ROOT / "models" / "baseline.json")
        flow = read_flows(ROOT / "data" / "sample_flows.csv")[0]
        with self.assertRaisesRegex(ValueError, "limit"):
            model.explain(extract_features(flow), limit=0)


if __name__ == "__main__":
    unittest.main()
