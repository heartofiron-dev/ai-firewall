from __future__ import annotations

import argparse
import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path

from ai_firewall.datasets import (
    UNSW_NB15_RAW_COLUMNS,
    _RollingContext,
    _binary_label,
    _epoch_timestamp,
    _integer,
    _ip,
    _number,
    _port,
    _protocol,
)
from ai_firewall.io import write_flows_csv
from ai_firewall.schema import FlowRecord


SELECTED_COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes",
    "dbytes", "Spkts", "Dpkts", "Stime", "attack_cat", "Label",
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
            line = global_index
            value = lambda name: str(columns[name][row_index])
            try:
                timestamp, epoch = _epoch_timestamp(value("Stime"), line)
                state = value("state").upper()
                label_value = value("Label") or value("attack_cat")
                flow = FlowRecord(
                    timestamp=timestamp,
                    src_ip=_ip(value("srcip"), line, "srcip"),
                    dst_ip=_ip(value("dstip"), line, "dstip"),
                    src_port=_port(value("sport"), line, "sport"),
                    dst_port=_port(value("dsport"), line, "dsport"),
                    protocol=_protocol(value("proto")),
                    duration_ms=_number(value("dur"), line, "dur", scale=1000.0),
                    packets=_integer(value("Spkts"), line, "Spkts")
                    + _integer(value("Dpkts"), line, "Dpkts"),
                    bytes_sent=_integer(value("sbytes"), line, "sbytes"),
                    bytes_received=_integer(value("dbytes"), line, "dbytes"),
                    syn_count=0,
                    rst_count=int(state == "RST"),
                    unique_dst_ports_60s=0,
                    connections_60s=0,
                    failed_connections_60s=0,
                    label=_binary_label(label_value),
                )
            except (TypeError, ValueError) as exc:
                stats["skipped_invalid_rows"] = int(stats["skipped_invalid_rows"]) + 1
                message = str(exc)
                if "stime" in message:
                    reason = "missing_or_invalid_stime"
                elif "IP" in message:
                    reason = "invalid_ip_address"
                elif "端口" in message:
                    reason = "invalid_port"
                else:
                    reason = "other_invalid_required_value"
                reasons = stats["skip_reason_counts"]
                reasons[reason] = reasons.get(reason, 0) + 1
                continue
            enriched = context.enrich(flow, epoch, state in {"REQ", "RST"}, line)
            if (global_index - 1) % stride == 0:
                yield enriched


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "将一个或多个官方 49 字段、无表头 UNSW-NB15 CSV 按 Stime 排序，"
            "计算 60 秒上下文，并确定性抽样为 AI Firewall 统一 CSV。"
        ),
    )
    parser.add_argument("inputs", nargs="+")
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-rows", type=int, default=100_000)
    parser.add_argument("--source", default="https://doi.org/10.5281/zenodo.10140548")
    parser.add_argument("--overwrite", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        import pyarrow as pa
        import pyarrow.compute as pc
        import pyarrow.csv as pacsv
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

    read_options = pacsv.ReadOptions(column_names=UNSW_NB15_RAW_COLUMNS)
    convert_options = pacsv.ConvertOptions(
        column_types={name: pa.string() for name in UNSW_NB15_RAW_COLUMNS},
        include_columns=SELECTED_COLUMNS,
    )
    tables = [
        pacsv.read_csv(path, read_options=read_options, convert_options=convert_options)
        for path in inputs
    ]
    table = pa.concat_tables(tables, promote_options="default")
    time_values = pc.cast(table.column("Stime"), pa.float64())
    table = table.append_column("_sort_time", time_values)
    order = pc.sort_indices(table, sort_keys=[("_sort_time", "ascending")])
    ordered = table.take(order).drop_columns(["_sort_time"])
    stride = max(1, math.ceil(ordered.num_rows / args.max_rows))
    stats: dict[str, object] = {
        "processed_rows": 0,
        "skipped_invalid_rows": 0,
        "skip_reason_counts": {},
    }
    temporary = output.with_name(output.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError(f"临时输出已存在，请先人工检查: {temporary}")
    try:
        selected_rows = write_flows_csv(_flows(ordered, stride, stats), temporary)
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    provenance = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": "UNSW-NB15",
        "source": args.source,
        "source_variant": "Zenodo archive of official headerless 49-column raw CSV files",
        "inputs": [
            {"path": str(path), "bytes": path.stat().st_size, "sha256": _sha256(path)}
            for path in inputs
        ],
        "total_rows": ordered.num_rows,
        "selection": "every_nth_row_after_global_stime_sort",
        "stride": stride,
        "selected_rows": selected_rows,
        "skipped_invalid_rows": stats["skipped_invalid_rows"],
        "skip_reason_counts": stats["skip_reason_counts"],
        "output": str(output),
        "output_sha256": _sha256(output),
        "notes": [
            "All supplied partitions were globally sorted by Stime before rolling context was calculated.",
            "Every valid raw row was processed before deterministic sampling.",
            "The DOI archive checksum was verified separately before this preparation step.",
        ],
    }
    manifest.write_text(
        json.dumps(provenance, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
    )
    print(json.dumps(provenance, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
