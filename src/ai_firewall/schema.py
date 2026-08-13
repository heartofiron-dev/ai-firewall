from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FlowRecord:
    """Aggregated metadata for one network flow or observation window."""

    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    duration_ms: float
    packets: int
    bytes_sent: int
    bytes_received: int
    syn_count: int
    rst_count: int
    unique_dst_ports_60s: int
    connections_60s: int
    failed_connections_60s: int
    label: str | None = None

    @property
    def bytes_total(self) -> int:
        return self.bytes_sent + self.bytes_received

