from __future__ import annotations

from dataclasses import dataclass

from .schema import FlowRecord


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    score: float
    reason: str


def evaluate_rules(flow: FlowRecord) -> list[RuleHit]:
    hits: list[RuleHit] = []

    if flow.unique_dst_ports_60s >= 20 and flow.connections_60s >= 20:
        hits.append(RuleHit("PORT_SCAN", 0.92, "60 秒内访问了大量不同目标端口"))

    auth_ports = {21, 22, 23, 445, 3389, 5900}
    if flow.dst_port in auth_ports and flow.failed_connections_60s >= 10:
        hits.append(RuleHit("BRUTE_FORCE", 0.90, "认证类端口出现连续连接失败"))

    if flow.connections_60s >= 200 or flow.syn_count >= 100:
        hits.append(RuleHit("CONNECTION_FLOOD", 0.96, "短时间连接或 SYN 数量异常"))

    if flow.bytes_total >= 50_000_000 and flow.duration_ms <= 60_000:
        hits.append(RuleHit("DATA_SPIKE", 0.76, "短时间传输数据量异常增大"))

    if flow.dst_port in {4444, 5555, 6667, 31337}:
        # The 0.90 rule floor must still cross the default 0.60 alert threshold.
        hits.append(RuleHit("SUSPICIOUS_PORT", 0.67, "连接到常见恶意工具或后门端口"))

    return hits
