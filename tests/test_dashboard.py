from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from ai_firewall.dashboard import DashboardServer, DashboardState, load_alerts


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.alerts = self.root / "alerts.jsonl"
        self.feedback = self.root / "feedback.jsonl"
        self.rows = [
            {
                "timestamp": "2026-08-15T00:00:00Z", "src_ip": "10.0.0.1",
                "dst_ip": "192.0.2.10", "dst_port": 443, "protocol": "TCP",
                "severity": "critical", "risk_score": 0.95,
                "reasons": ["端口扫描"], "rule_ids": ["PORT_SCAN"],
                "process_name": "scanner-test", "direction": "inbound",
                "top_features": [{"contribution": 2.3389}],
            },
            {
                "timestamp": "2026-08-15T00:01:00Z", "src_ip": "127.0.0.1",
                "dst_ip": "127.0.0.1", "dst_port": 3389, "protocol": "TCP",
                "severity": "info", "risk_score": 0.12,
                "reasons": ["正常连接"], "process_name": "browser-test",
                "direction": "outbound",
            },
        ]
        text = "\n".join(json.dumps(row, ensure_ascii=False) for row in self.rows)
        self.alerts.write_text(text + "\n{partial", encoding="utf-8")

    def tearDown(self):
        self.temporary.cleanup()

    def test_loads_filters_and_reports_partial_line(self):
        rows, skipped, feedback_count = load_alerts(
            self.alerts, self.feedback, severity="critical", query="PORT_SCAN",
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["process_name"], "scanner-test")
        self.assertRegex(rows[0]["_id"], r"^[0-9a-f]{16}$")
        self.assertFalse(rows[0]["_feedback"])
        self.assertEqual(skipped, 1)
        self.assertEqual(feedback_count, 0)

        port_rows, _, _ = load_alerts(self.alerts, self.feedback, query="3389")
        self.assertEqual(len(port_rows), 1)
        self.assertEqual(port_rows[0]["process_name"], "browser-test")

    def test_feedback_is_isolated_and_idempotent(self):
        state = DashboardState(self.alerts, self.feedback)
        rows, _, _ = load_alerts(self.alerts, self.feedback)
        alert_id = rows[0]["_id"]
        self.assertTrue(state.record_false_positive(alert_id, "人工复核"))
        self.assertFalse(state.record_false_positive(alert_id))
        entry = json.loads(self.feedback.read_text(encoding="utf-8"))
        self.assertEqual(entry["alert_id"], alert_id)
        self.assertEqual(entry["review_status"], "pending")
        self.assertNotIn("src_ip", entry)

    def test_rejects_unsafe_paths_and_limits(self):
        with self.assertRaisesRegex(ValueError, "同一个文件"):
            DashboardState(self.alerts, self.alerts)
        with self.assertRaisesRegex(ValueError, "max_alerts"):
            DashboardState(self.alerts, self.feedback, max_alerts=0)
        with self.assertRaisesRegex(ValueError, "搜索词"):
            load_alerts(self.alerts, self.feedback, query="x" * 101)

    def test_http_api_rejects_bad_host_and_requires_token(self):
        state = DashboardState(self.alerts, self.feedback)
        server = DashboardServer(("127.0.0.1", 0), state, token="test-token")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            connection.request("GET", "/api/alerts?q=browser", headers={"Host": f"127.0.0.1:{port}"})
            response = connection.getresponse()
            payload = json.loads(response.read())
            self.assertEqual(response.status, 200)
            self.assertEqual(payload["count"], 1)
            self.assertIn("default-src 'none'", response.getheader("Content-Security-Policy"))

            connection.request("GET", "/api/alerts", headers={"Host": "attacker.invalid"})
            bad_host = connection.getresponse()
            bad_host.read()
            self.assertEqual(bad_host.status, 403)

            rows, _, _ = load_alerts(self.alerts, self.feedback)
            body = json.dumps({"alert_id": rows[0]["_id"]})
            connection.request(
                "POST", "/api/feedback", body=body,
                headers={"Host": f"127.0.0.1:{port}", "Content-Type": "application/json"},
            )
            denied = connection.getresponse()
            denied.read()
            self.assertEqual(denied.status, 403)

            connection.request(
                "POST", "/api/feedback", body=body,
                headers={
                    "Host": f"127.0.0.1:{port}", "Content-Type": "application/json",
                    "X-AI-Firewall-Token": "test-token",
                },
            )
            created = connection.getresponse()
            created.read()
            self.assertEqual(created.status, 201)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_second_server_cannot_share_dashboard_port(self):
        state = DashboardState(self.alerts, self.feedback)
        server = DashboardServer(("127.0.0.1", 0), state)
        try:
            with self.assertRaises(OSError):
                DashboardServer(("127.0.0.1", server.server_address[1]), state)
        finally:
            server.server_close()


if __name__ == "__main__":
    unittest.main()
