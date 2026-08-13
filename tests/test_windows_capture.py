import tempfile
import unittest
from pathlib import Path

from ai_firewall.windows_capture import build_pktmon_commands, validate_capture_request


class WindowsCaptureTests(unittest.TestCase):
    def test_validates_bounded_pcapng_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "capture.pcapng"
            result = validate_capture_request(30, output, platform_name="nt")
        self.assertEqual(result.name, "capture.pcapng")

    def test_rejects_unsafe_duration_and_extension(self):
        with self.assertRaisesRegex(ValueError, "1 到 3600"):
            validate_capture_request(0, "capture.pcapng", platform_name="nt")
        with self.assertRaisesRegex(ValueError, "pcapng"):
            validate_capture_request(30, "capture.etl", platform_name="nt")

    def test_builds_explicit_pktmon_commands(self):
        start, stop, convert = build_pktmon_commands(
            Path("temporary.etl"), Path("capture.pcapng")
        )
        self.assertEqual(start[:3], ["pktmon.exe", "start", "--capture"])
        self.assertEqual(stop, ["pktmon.exe", "stop"])
        self.assertIn("etl2pcap", convert)


if __name__ == "__main__":
    unittest.main()
