from __future__ import annotations

import argparse
import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path

from ai_firewall.datasets import (
    _RollingContext,
    _binary_label,
    _integer,
    _ip,
    _iso_timestamp,
    _number,
    _port,
    _protocol,
)
from ai_firewall.io import write_flows_csv
from ai_firewall.schema import FlowRecord


COLUMNS = [
    "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol",
    "Timestamp", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "SYN Flag Count",
    "RST Flag Count", "Label",
]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _flows(table, stride: int, stats: dict[str, object]):
    context = _RollingContext()
    global_index = 0
    for batch in table.to_batches(max_chunksize=8192):
        columns = batch.to_pydict()
        for row_index in range(batch.num_rows):
            global_index += 1
            stats["processed_rows"] = global_index
            line = global_index + 1
            value = lambda name: str(columns[name][row_index])
            try:
                timestamp, epoch = _iso_timestamp(value("Timestamp"), line, None)
                rst_count = _integer(value("RST Flag Count"), line, "RST Flag Count")
                flow = FlowRecord(
                    timestamp=timestamp,
                    src_ip=_ip(value("Source IP"), line, "Source IP"),
                    dst_ip=_ip(value("Destination IP"), line, "Destination IP"),
                    src_port=_port(value("Source Port"), line, "Source Port"),
                    dst_port=_port(value("Destination Port"), line, "Destination Port"),
                    protocol=_protocol(value("Protocol")),
                    duration_ms=_number(
                        value("Flow Duration"), line, "Flow Duration", scale=0.001,
                    ),
                    packets=_integer(
                        value("Total Fwd Packets"), line, "Total Fwd Packets",
                    ) + _integer(
                        value("Total Backward Packets"), line, "Total Backward Packets",
                    ),
                    bytes_sent=_integer(
                        value("Total Length of Fwd Packets"), line,
                        "Total Length of Fwd Packets",
                    ),
                    bytes_received=_integer(
                        value("Total Length of Bwd Packets"), line,
                        "Total Length of Bwd Packets",
                    ),
                    syn_count=_integer(value("SYN Flag Count"), line, "SYN Flag Count"),
                    rst_count=rst_count,
                    unique_dst_ports_60s=0,
                    connections_60s=0,
                    failed_connections_60s=0,
                    label=_binary_label(value("Label")),
                )
            except (TypeError, ValueError) as exc:
                stats["skipped_invalid_rows"] = int(stats["skipped_invalid_rows"]) + 1
                message = str(exc)
                if "Timestamp" in message:
                    reason = "missing_or_invalid_timestamp"
                elif "Flow Duration" in message:
                    reason = "invalid_flow_duration"
                elif "IP" in message:
                    reason = "invalid_ip_address"
                elif "端口" in message:
                    reason = "invalid_port"
                else:
                    reason = "other_invalid_required_value"
                reasons = stats["skip_reason_counts"]
                reasons[reason] = reasons.get(reason, 0) + 1
                continue
            enriched = context.enrich(flow, epoch, rst_count > 0, line)
            if (global_index - 1) % stride == 0:
                yield enriched


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "将带完整端点和时间戳的 CICIDS2017 traffic_labels Parquet 文件按时间排序，"
            "计算 60 秒上下文，并确定性抽样为 AI Firewall 统一 CSV。"
        ),
    )
    parser.add_argument("inputs", nargs="+", help="一个或多个 traffic_labels Parquet 文件")
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-rows", type=int, default=100_000)
    parser.add_argument("--source", default="https://huggingface.co/datasets/bvsam/cic-ids-2017")
    parser.add_argument("--overwrite", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        import pyarrow as pa
        import pyarrow.compute as pc
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise SystemExit(
            "缺少 PyArrow；请运行 python -m pip install -e \".[research-data]\""
        ) from exc
    args = build_parser().parse_args(argv)
    if args.max_rows < 20:
        raise ValueError("max_rows 必须至少为 20")
    inputs = [Path(value).resolve() for value in args.inputs]
    missing = [path for path in inputs if not path.is_file()]
    if missing:
        raise ValueError("找不到输入文件: " + ", ".join(str(path) for path in missing))
    output = Path(args.output).resolve()
    manifest = output.with_name(output.stem + "-provenance.json")
    for path in (output, manifest):
        if path.exists() and not args.overwrite:
            raise ValueError(f"输出已存在: {path}；如需替换请添加 --overwrite")
        if path.is_symlink():
            raise ValueError(f"输出不能是符号链接: {path}")
    output.parent.mkdir(parents=True, exist_ok=True)

    tables = [pq.read_table(path, columns=COLUMNS) for path in inputs]
    table = pa.concat_tables(tables, promote_options="default")
    order = pc.sort_indices(table, sort_keys=[("Timestamp", "ascending")])
    ordered = table.take(order)
    stride = max(1, math.ceil(ordered.num_rows / args.max_rows))
    temporary = output.with_name(output.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError(f"临时输出已存在，请先人工检查: {temporary}")
    stats: dict[str, object] = {
        "processed_rows": 0,
        "skipped_invalid_rows": 0,
        "skip_reason_counts": {},
    }
    try:
        selected_rows = write_flows_csv(_flows(ordered, stride, stats), temporary)
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    provenance = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": "CICIDS2017",
        "source": args.source,
        "source_variant": "traffic_labels parquet mirror with normalized timestamps",
        "inputs": [
            {"path": str(path), "bytes": path.stat().st_size, "sha256": _sha256(path)}
            for path in inputs
        ],
        "total_rows": ordered.num_rows,
        "selection": "every_nth_row_after_global_timestamp_sort",
        "stride": stride,
        "selected_rows": selected_rows,
        "skipped_invalid_rows": stats["skipped_invalid_rows"],
        "skip_reason_counts": stats["skip_reason_counts"],
        "output": str(output),
        "output_sha256": _sha256(output),
        "notes": [
            "Every raw row was processed before sampling so 60-second rolling context uses the full input.",
            "Rows with invalid non-finite or negative required values were skipped and counted, not imputed.",
            "The mirror is not the official CIC registration endpoint and must be disclosed in the paper.",
        ],
    }
    manifest.write_text(
        json.dumps(provenance, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
    )
    print(json.dumps(provenance, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
