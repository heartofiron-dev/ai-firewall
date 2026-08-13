from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable

from .detector import DetectionResult
from .schema import FlowRecord


REQUIRED_COLUMNS = {
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "duration_ms", "packets", "bytes_sent", "bytes_received", "syn_count",
    "rst_count", "unique_dst_ports_60s", "connections_60s",
    "failed_connections_60s",
}


def read_flows(path: str | Path) -> list[FlowRecord]:
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"CSV 缺少字段: {', '.join(sorted(missing))}")
        flows = []
        for line_number, row in enumerate(reader, start=2):
            try:
                flows.append(FlowRecord(
                    timestamp=row["timestamp"],
                    src_ip=row["src_ip"],
                    dst_ip=row["dst_ip"],
                    src_port=int(row["src_port"]),
                    dst_port=int(row["dst_port"]),
                    protocol=row["protocol"].upper(),
                    duration_ms=float(row["duration_ms"]),
                    packets=int(row["packets"]),
                    bytes_sent=int(row["bytes_sent"]),
                    bytes_received=int(row["bytes_received"]),
                    syn_count=int(row["syn_count"]),
                    rst_count=int(row["rst_count"]),
                    unique_dst_ports_60s=int(row["unique_dst_ports_60s"]),
                    connections_60s=int(row["connections_60s"]),
                    failed_connections_60s=int(row["failed_connections_60s"]),
                    label=(row.get("label") or None),
                ))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"CSV 第 {line_number} 行格式错误: {exc}") from exc
    return flows


def write_jsonl(results: Iterable[DetectionResult], path: str | Path) -> None:
    with Path(path).open("w", encoding="utf-8") as handle:
        for result in results:
            handle.write(json.dumps(result.to_dict(), ensure_ascii=False) + "\n")

