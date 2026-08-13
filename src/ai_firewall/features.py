from __future__ import annotations

from .schema import FlowRecord


FEATURE_NAMES = [
    "duration_ms",
    "packets",
    "bytes_total",
    "avg_packet_bytes",
    "syn_ratio",
    "rst_ratio",
    "unique_dst_ports_60s",
    "connections_60s",
    "failed_connections_60s",
    "high_risk_port",
]

HIGH_RISK_PORTS = {21, 22, 23, 445, 1433, 2375, 3306, 3389, 4444, 5432, 5900, 6379}


def extract_features(flow: FlowRecord) -> dict[str, float]:
    packets = max(flow.packets, 1)
    return {
        "duration_ms": float(flow.duration_ms),
        "packets": float(flow.packets),
        "bytes_total": float(flow.bytes_total),
        "avg_packet_bytes": float(flow.bytes_total) / packets,
        "syn_ratio": float(flow.syn_count) / packets,
        "rst_ratio": float(flow.rst_count) / packets,
        "unique_dst_ports_60s": float(flow.unique_dst_ports_60s),
        "connections_60s": float(flow.connections_60s),
        "failed_connections_60s": float(flow.failed_connections_60s),
        "high_risk_port": 1.0 if flow.dst_port in HIGH_RISK_PORTS else 0.0,
    }

