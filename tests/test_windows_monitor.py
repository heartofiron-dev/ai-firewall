import json
import unittest

from ai_firewall.windows_monitor import (
    WindowsFlowTracker, parse_connections_json, parse_netstat_output,
)


class WindowsMonitorTests(unittest.TestCase):
    def test_parses_single_connection_object(self):
        payload = json.dumps({
            "local_address": "192.168.1.10", "local_port": 53000,
            "remote_address": "142.250.72.14", "remote_port": 443,
            "state": "Established", "owning_process": 123,
            "process_name": "browser",
        })
        connections = parse_connections_json(payload)
        self.assertEqual(len(connections), 1)
        self.assertEqual(connections[0].process_name, "browser")

    def test_tracker_infers_direction_and_deduplicates(self):
        payload = json.dumps([
            {
                "local_address": "192.168.1.10", "local_port": 3389,
                "remote_address": "10.0.0.55", "remote_port": 51000,
                "state": "Established", "owning_process": 10,
                "process_name": "TermService",
            },
            {
                "local_address": "192.168.1.10", "local_port": 53000,
                "remote_address": "1.1.1.1", "remote_port": 443,
                "state": "Established", "owning_process": 20,
                "process_name": "browser",
            },
        ])
        connections = parse_connections_json(payload)
        tracker = WindowsFlowTracker()
        observations = tracker.observe(connections, 1_700_000_000)
        self.assertEqual(observations[0].direction, "inbound")
        self.assertEqual(observations[0].flow.src_ip, "10.0.0.55")
        self.assertEqual(observations[0].flow.dst_port, 3389)
        self.assertEqual(observations[1].direction, "outbound")
        self.assertEqual(tracker.observe(connections, 1_700_000_001), [])

    def test_parses_netstat_fallback(self):
        payload = """
          TCP    192.168.1.10:53000    1.1.1.1:443    ESTABLISHED    123
          TCP    [::]:135              [::]:0         LISTENING      456
        """
        connections = parse_netstat_output(payload, {123: "browser.exe"})
        self.assertEqual(len(connections), 1)
        self.assertEqual(connections[0].remote_address, "1.1.1.1")
        self.assertEqual(connections[0].process_name, "browser.exe")

    def test_different_processes_have_separate_windows(self):
        rows = []
        for index in range(24):
            rows.append({
                "local_address": "127.0.0.1", "local_port": 50000 + index,
                "remote_address": "127.0.0.1", "remote_port": 60000 + index,
                "state": "Established", "owning_process": 100 + index,
                "process_name": f"process-{index}",
            })
        observations = WindowsFlowTracker().observe(parse_connections_json(json.dumps(rows)), 1_700_000_000)
        self.assertTrue(all(item.flow.connections_60s == 1 for item in observations))
        self.assertTrue(all(item.flow.unique_dst_ports_60s == 1 for item in observations))


if __name__ == "__main__":
    unittest.main()
