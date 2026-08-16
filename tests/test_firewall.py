import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ai_firewall.firewall import (
    activate_kill_switch, apply_temporary_block, cleanup_expired_rules,
    deactivate_kill_switch, plan_temporary_block, rollback_rules,
)


class FirewallTests(unittest.TestCase):
    def test_default_is_plan_only_and_protects_private_networks(self):
        plan = plan_temporary_block("8.8.8.8", 600)
        self.assertEqual(plan["remote_address"], "8.8.8.8")
        self.assertTrue(str(plan["name"]).startswith("AI-Firewall-"))
        with self.assertRaisesRegex(ValueError, "允许名单"):
            plan_temporary_block("192.168.1.1", 600)
        with self.assertRaisesRegex(ValueError, "60 秒"):
            plan_temporary_block("8.8.8.8", 30)

    def test_apply_tracks_only_managed_rule_and_kill_switch_rolls_back(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "rules.json"
            calls = []

            def runner(script, arguments):
                calls.append((script, arguments))

            result = apply_temporary_block(
                "8.8.4.4", 600, state, confirmation="APPLY", runner=runner,
            )
            self.assertTrue(result["applied"])
            ledger = json.loads(state.read_text(encoding="utf-8"))
            self.assertEqual(len(ledger["rules"]), 1)
            killed = activate_kill_switch(
                state, rollback=True, confirmation="ROLLBACK", runner=runner,
            )
            self.assertTrue(killed["disabled"])
            self.assertEqual(killed["rolled_back"], 1)
            with self.assertRaisesRegex(ValueError, "kill switch"):
                apply_temporary_block(
                    "1.1.1.1", 600, state, confirmation="APPLY", runner=runner,
                )
            self.assertTrue(deactivate_kill_switch(state, confirmation="ENABLE"))
            self.assertEqual(len(calls), 4)
            self.assertEqual(calls[0][1][-1], "Inbound")
            self.assertEqual(calls[1][1][-1], "Outbound")

    def test_cleanup_removes_only_expired_managed_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "rules.json"
            past = datetime.now(timezone.utc) - timedelta(minutes=1)
            future = datetime.now(timezone.utc) + timedelta(minutes=10)
            state.write_text(json.dumps({"schema_version": "1.0", "rules": [
                {"name": "AI-Firewall-old", "names": ["AI-Firewall-old-In", "AI-Firewall-old-Out"], "expires_at": past.isoformat()},
                {"name": "AI-Firewall-new", "names": ["AI-Firewall-new-In", "AI-Firewall-new-Out"], "expires_at": future.isoformat()},
            ]}), encoding="utf-8")
            calls = []
            result = cleanup_expired_rules(
                state, confirmation="CLEANUP", runner=lambda script, args: calls.append(args),
            )
            self.assertEqual(result, {"removed": 1, "remaining": 1})
            self.assertEqual(calls, [["AI-Firewall-old-In"], ["AI-Firewall-old-Out"]])

    def test_apply_and_rollback_require_explicit_confirmations(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "rules.json"
            with self.assertRaisesRegex(ValueError, "APPLY"):
                apply_temporary_block("8.8.8.8", 600, state, runner=lambda *_: None)
            with self.assertRaisesRegex(ValueError, "ROLLBACK"):
                rollback_rules(state, runner=lambda *_: None)


if __name__ == "__main__":
    unittest.main()
