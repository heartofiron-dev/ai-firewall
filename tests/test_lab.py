import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from ai_firewall.detector import HybridDetector
from ai_firewall.io import read_flows
from ai_firewall.lab import (
    LAB_CONFIRMATION,
    SCENARIOS,
    LabObservation,
    run_loopback_lab,
    run_normal_socket_scenario,
    write_lab_report,
)
from ai_firewall.model import LinearModel


ROOT = Path(__file__).resolve().parents[1]


class LoopbackLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.detector = HybridDetector(LinearModel.load(ROOT / "models" / "baseline.json"))
        cls.samples = read_flows(ROOT / "data" / "sample_flows.csv")

    def observation(self, scenario, sample_index, expected_rule):
        flow = replace(
            self.samples[sample_index],
            src_ip="127.0.0.1",
            dst_ip="127.0.0.1",
        )
        return LabObservation(
            scenario=scenario,
            description="deterministic test observation",
            expected_rule=expected_rule,
            flow=flow,
            measurements={"owned_destination_ports": [flow.dst_port]},
        )

    def test_requires_confirmation_before_running_any_socket_scenario(self):
        called = []

        def runner():
            called.append(True)
            return self.observation("normal", 0, None)

        with self.assertRaisesRegex(ValueError, LAB_CONFIRMATION):
            run_loopback_lab(
                self.detector,
                scenario="normal",
                confirmation="",
                runners={"normal": runner},
            )
        self.assertEqual(called, [])

    def test_all_scenarios_produce_expected_detection_with_reviewed_observations(self):
        observations = {
            "normal": self.observation("normal", 0, None),
            "port-scan": self.observation("port-scan", 2, "PORT_SCAN"),
            "brute-force": self.observation("brute-force", 3, "BRUTE_FORCE"),
            "connection-flood": self.observation(
                "connection-flood", 4, "CONNECTION_FLOOD",
            ),
            "data-spike": self.observation("data-spike", 5, "DATA_SPIKE"),
            "suspicious-port": self.observation(
                "suspicious-port", 5, "SUSPICIOUS_PORT",
            ),
        }
        runners = {name: (lambda item=item: item) for name, item in observations.items()}
        report = run_loopback_lab(
            self.detector,
            confirmation=LAB_CONFIRMATION,
            runners=runners,
        )
        self.assertTrue(report["passed"])
        self.assertEqual([item["scenario"] for item in report["scenarios"]], list(SCENARIOS))
        self.assertTrue(all(item["status"] == "passed" for item in report["scenarios"]))
        self.assertFalse(report["safety"]["custom_or_external_targets_supported"])
        self.assertFalse(report["safety"]["packet_capture"])
        self.assertFalse(report["safety"]["firewall_changes"])

    def test_rejects_non_loopback_observation(self):
        observation = self.observation("normal", 0, None)
        unsafe = replace(observation, flow=replace(observation.flow, dst_ip="192.0.2.10"))
        with self.assertRaisesRegex(ValueError, "非 loopback"):
            run_loopback_lab(
                self.detector,
                scenario="normal",
                confirmation=LAB_CONFIRMATION,
                runners={"normal": lambda: unsafe},
            )

    def test_rejects_connection_to_port_not_owned_by_runner(self):
        observation = self.observation("normal", 0, None)
        unsafe = replace(observation, measurements={"owned_destination_ports": [65534]})
        with self.assertRaisesRegex(ValueError, "自己占用"):
            run_loopback_lab(
                self.detector,
                scenario="normal",
                confirmation=LAB_CONFIRMATION,
                runners={"normal": lambda: unsafe},
            )

    def test_actual_normal_scenario_only_uses_owned_loopback_socket(self):
        observation = run_normal_socket_scenario()
        self.assertEqual(observation.flow.src_ip, "127.0.0.1")
        self.assertEqual(observation.flow.dst_ip, "127.0.0.1")
        self.assertIn(
            observation.flow.dst_port,
            observation.measurements["owned_destination_ports"],
        )
        self.assertGreater(observation.flow.bytes_sent, 0)
        self.assertGreater(observation.flow.bytes_received, 0)

    def test_report_write_is_atomic_and_refuses_overwrite(self):
        report = {"schema_version": "1.0", "passed": True}
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "lab-report.json"
            write_lab_report(report, output)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), report)
            with self.assertRaisesRegex(ValueError, "已存在"):
                write_lab_report(report, output)
            write_lab_report(report | {"passed": False}, output, overwrite=True)
            self.assertFalse(json.loads(output.read_text(encoding="utf-8"))["passed"])
            with self.assertRaisesRegex(ValueError, r"\.json"):
                write_lab_report(report, Path(folder) / "lab-report.txt")


if __name__ == "__main__":
    unittest.main()
