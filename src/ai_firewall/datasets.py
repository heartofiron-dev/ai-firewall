from __future__ import annotations

import csv
import ipaddress
import math
from collections import defaultdict, deque
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .schema import FlowRecord


def _key(value: str) -> str:
    return "".join(character for character in value.strip().lower() if character.isalnum())


def _header_map(fieldnames: list[str] | None) -> dict[str, str]:
    if not fieldnames:
        raise ValueError("数据集 CSV 缺少表头")
    mapped: dict[str, str] = {}
    for original in fieldnames:
        normalized = _key(original)
        if not normalized:
            continue
        if normalized in mapped:
            raise ValueError(f"数据集 CSV 存在重复字段: {original!r}")
        mapped[normalized] = original
    return mapped


def _field(
    row: dict[str, str], headers: dict[str, str], aliases: tuple[str, ...],
    line_number: int, display_name: str, *, required: bool = True,
) -> str:
    for alias in aliases:
        original = headers.get(_key(alias))
        if original is not None:
            value = (row.get(original) or "").strip()
            if value or not required:
                return value
    if required:
        raise ValueError(f"第 {line_number} 行缺少 {display_name}")
    return ""


def _require_header(headers: dict[str, str], aliases: tuple[str, ...], name: str) -> None:
    if not any(_key(alias) in headers for alias in aliases):
        raise ValueError(f"数据集 CSV 缺少字段 {name}")


def _number(value: str, line_number: int, name: str, *, scale: float = 1.0) -> float:
    try:
        parsed = float(value) * scale
    except ValueError as exc:
        raise ValueError(f"第 {line_number} 行的 {name} 不是数字: {value!r}") from exc
    if not math.isfinite(parsed) or parsed < 0:
        raise ValueError(f"第 {line_number} 行的 {name} 必须是有限非负数")
    return parsed


def _integer(value: str, line_number: int, name: str) -> int:
    parsed = _number(value, line_number, name)
    if not parsed.is_integer():
        raise ValueError(f"第 {line_number} 行的 {name} 必须是整数")
    return int(parsed)


def _port(value: str, line_number: int, name: str) -> int:
    if value in {"", "-"}:
        return 0
    try:
        parsed = int(value, 0) if value.lower().startswith("0x") else _integer(value, line_number, name)
    except ValueError as exc:
        raise ValueError(f"第 {line_number} 行的 {name} 不是有效端口: {value!r}") from exc
    if not 0 <= parsed <= 65535:
        raise ValueError(f"第 {line_number} 行的 {name} 超出 0..65535")
    return parsed


def _ip(value: str, line_number: int, name: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError(f"第 {line_number} 行的 {name} 不是有效 IP: {value!r}") from exc


def _protocol(value: str) -> str:
    normalized = value.strip().lower()
    numeric = {"6": "TCP", "6.0": "TCP", "17": "UDP", "17.0": "UDP"}
    return numeric.get(normalized, normalized.upper())


def _binary_label(value: str) -> str:
    normalized = _key(value)
    return "benign" if normalized in {"0", "benign", "normal"} else "attack"


def _iso_timestamp(value: str, line_number: int, timestamp_format: str | None) -> tuple[str, float]:
    try:
        if timestamp_format:
            parsed = datetime.strptime(value, timestamp_format)
        else:
            try:
                parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
            except ValueError:
                parsed = None
                for candidate in (
                    "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M",
                    "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M",
                ):
                    try:
                        parsed = datetime.strptime(value, candidate)
                        break
                    except ValueError:
                        continue
                if parsed is None:
                    raise ValueError
    except ValueError as exc:
        hint = "；日期有歧义时请使用 --timestamp-format"
        raise ValueError(f"第 {line_number} 行的 Timestamp 无法解析: {value!r}{hint}") from exc

    aware = parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    epoch = aware.astimezone(timezone.utc).timestamp()
    if parsed.tzinfo:
        output = parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    else:
        output = parsed.isoformat()
    return output, epoch


def _epoch_timestamp(value: str, line_number: int) -> tuple[str, float]:
    epoch = _number(value, line_number, "stime")
    try:
        output = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (OSError, OverflowError, ValueError) as exc:
        raise ValueError(f"第 {line_number} 行的 stime 超出支持范围") from exc
    return output, epoch


@dataclass(frozen=True)
class _WindowItem:
    timestamp: float
    dst_port: int
    failed: bool


class _RollingContext:
    def __init__(self) -> None:
        self._windows: dict[str, deque[_WindowItem]] = defaultdict(deque)
        self._last_timestamp: dict[str, float] = {}

    def enrich(self, flow: FlowRecord, timestamp: float, failed: bool, line_number: int) -> FlowRecord:
        previous = self._last_timestamp.get(flow.src_ip)
        if previous is not None and timestamp < previous:
            raise ValueError(
                f"第 {line_number} 行在来源 {flow.src_ip} 内时间倒退；"
                "请先按时间排序，以免 60 秒上下文泄漏"
            )
        self._last_timestamp[flow.src_ip] = timestamp
        window = self._windows[flow.src_ip]
        while window and window[0].timestamp < timestamp - 60:
            window.popleft()
        window.append(_WindowItem(timestamp, flow.dst_port, failed))
        return replace(
            flow,
            unique_dst_ports_60s=len({item.dst_port for item in window}),
            connections_60s=len(window),
            failed_connections_60s=sum(item.failed for item in window),
        )


_CIC = {
    "timestamp": ("Timestamp",),
    "src_ip": ("Source IP", "Src IP"),
    "dst_ip": ("Destination IP", "Dst IP"),
    "src_port": ("Source Port", "Src Port"),
    "dst_port": ("Destination Port", "Dst Port"),
    "protocol": ("Protocol",),
    "duration": ("Flow Duration",),
    "fwd_packets": ("Total Fwd Packets", "Tot Fwd Pkts"),
    "bwd_packets": ("Total Backward Packets", "Tot Bwd Pkts"),
    "fwd_bytes": ("Total Length of Fwd Packets", "TotLen Fwd Pkts"),
    "bwd_bytes": ("Total Length of Bwd Packets", "TotLen Bwd Pkts"),
    "syn": ("SYN Flag Count", "SYN Flag Cnt"),
    "rst": ("RST Flag Count", "RST Flag Cnt"),
    "label": ("Label",),
}


_UNSW = {
    "timestamp": ("stime", "start time"),
    "src_ip": ("srcip", "src ip", "source ip"),
    "dst_ip": ("dstip", "dst ip", "destination ip"),
    "src_port": ("sport", "src port", "source port"),
    "dst_port": ("dsport", "dst port", "destination port"),
    "protocol": ("proto", "protocol"),
    "duration": ("dur", "duration"),
    "src_packets": ("spkts", "src packets"),
    "dst_packets": ("dpkts", "dst packets"),
    "src_bytes": ("sbytes", "src bytes"),
    "dst_bytes": ("dbytes", "dst bytes"),
    "state": ("state",),
    "label": ("label",),
    "attack_category": ("attack_cat", "attack category"),
}

UNSW_NB15_RAW_COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes",
    "dbytes", "sttl", "dttl", "sloss", "dloss", "service", "Sload", "Dload",
    "Spkts", "Dpkts", "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz",
    "trans_depth", "res_bdy_len", "Sjit", "Djit", "Stime", "Ltime", "Sintpkt",
    "Dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl",
    "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst",
    "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
    "ct_dst_src_ltm", "attack_cat", "Label",
]


def _validate_headers(headers: dict[str, str], fields: dict[str, tuple[str, ...]], names: tuple[str, ...]) -> None:
    for name in names:
        _require_header(headers, fields[name], name)


def iter_cicids2017(
    path: str | Path, *, timestamp_format: str | None = None, max_rows: int | None = None,
) -> Iterator[FlowRecord]:
    """Convert a headered CICIDS2017/CICFlowMeter CSV without loading it all into memory."""
    context = _RollingContext()
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        headers = _header_map(reader.fieldnames)
        _validate_headers(headers, _CIC, tuple(_CIC))
        for index, row in enumerate(reader):
            if max_rows is not None and index >= max_rows:
                break
            line = index + 2
            timestamp, epoch = _iso_timestamp(
                _field(row, headers, _CIC["timestamp"], line, "Timestamp"),
                line, timestamp_format,
            )
            rst_count = _integer(_field(row, headers, _CIC["rst"], line, "RST Flag Count"), line, "RST Flag Count")
            flow = FlowRecord(
                timestamp=timestamp,
                src_ip=_ip(_field(row, headers, _CIC["src_ip"], line, "Source IP"), line, "Source IP"),
                dst_ip=_ip(_field(row, headers, _CIC["dst_ip"], line, "Destination IP"), line, "Destination IP"),
                src_port=_port(_field(row, headers, _CIC["src_port"], line, "Source Port"), line, "Source Port"),
                dst_port=_port(_field(row, headers, _CIC["dst_port"], line, "Destination Port"), line, "Destination Port"),
                protocol=_protocol(_field(row, headers, _CIC["protocol"], line, "Protocol")),
                duration_ms=_number(_field(row, headers, _CIC["duration"], line, "Flow Duration"), line, "Flow Duration", scale=0.001),
                packets=_integer(_field(row, headers, _CIC["fwd_packets"], line, "Total Fwd Packets"), line, "Total Fwd Packets")
                + _integer(_field(row, headers, _CIC["bwd_packets"], line, "Total Backward Packets"), line, "Total Backward Packets"),
                bytes_sent=_integer(_field(row, headers, _CIC["fwd_bytes"], line, "Total Length of Fwd Packets"), line, "Total Length of Fwd Packets"),
                bytes_received=_integer(_field(row, headers, _CIC["bwd_bytes"], line, "Total Length of Bwd Packets"), line, "Total Length of Bwd Packets"),
                syn_count=_integer(_field(row, headers, _CIC["syn"], line, "SYN Flag Count"), line, "SYN Flag Count"),
                rst_count=rst_count,
                unique_dst_ports_60s=0,
                connections_60s=0,
                failed_connections_60s=0,
                label=_binary_label(_field(row, headers, _CIC["label"], line, "Label")),
            )
            yield context.enrich(flow, epoch, rst_count > 0, line)


def iter_unsw_nb15(path: str | Path, *, max_rows: int | None = None) -> Iterator[FlowRecord]:
    """Convert an official headerless or headered raw UNSW-NB15 flow CSV."""
    context = _RollingContext()
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        probe = next(csv.reader(handle), [])
        has_header = {_key(value) for value in probe} >= {"srcip", "dstip", "stime"}
        if not has_header and len(probe) != len(UNSW_NB15_RAW_COLUMNS):
            raise ValueError(
                "无表头 UNSW-NB15 CSV 必须使用官方 49 字段原始格式；"
                f"当前首行有 {len(probe)} 个字段"
            )
        handle.seek(0)
        reader = csv.DictReader(
            handle, fieldnames=None if has_header else UNSW_NB15_RAW_COLUMNS
        )
        headers = _header_map(reader.fieldnames)
        required = (
            "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
            "duration", "src_packets", "dst_packets", "src_bytes", "dst_bytes", "state",
        )
        _validate_headers(headers, _UNSW, required)
        if not any(_key(alias) in headers for name in ("label", "attack_category") for alias in _UNSW[name]):
            raise ValueError("数据集 CSV 缺少 label 或 attack_cat 字段")
        for index, row in enumerate(reader):
            if max_rows is not None and index >= max_rows:
                break
            line = index + (2 if has_header else 1)
            timestamp, epoch = _epoch_timestamp(
                _field(row, headers, _UNSW["timestamp"], line, "stime"), line
            )
            state = _field(row, headers, _UNSW["state"], line, "state").upper()
            label_value = _field(row, headers, _UNSW["label"], line, "label", required=False)
            if not label_value:
                label_value = _field(
                    row, headers, _UNSW["attack_category"], line, "attack_cat"
                )
            failed = state in {"REQ", "RST"}
            flow = FlowRecord(
                timestamp=timestamp,
                src_ip=_ip(_field(row, headers, _UNSW["src_ip"], line, "srcip"), line, "srcip"),
                dst_ip=_ip(_field(row, headers, _UNSW["dst_ip"], line, "dstip"), line, "dstip"),
                src_port=_port(_field(row, headers, _UNSW["src_port"], line, "sport", required=False), line, "sport"),
                dst_port=_port(_field(row, headers, _UNSW["dst_port"], line, "dsport", required=False), line, "dsport"),
                protocol=_protocol(_field(row, headers, _UNSW["protocol"], line, "proto")),
                duration_ms=_number(_field(row, headers, _UNSW["duration"], line, "dur"), line, "dur", scale=1000.0),
                packets=_integer(_field(row, headers, _UNSW["src_packets"], line, "Spkts"), line, "Spkts")
                + _integer(_field(row, headers, _UNSW["dst_packets"], line, "Dpkts"), line, "Dpkts"),
                bytes_sent=_integer(_field(row, headers, _UNSW["src_bytes"], line, "sbytes"), line, "sbytes"),
                bytes_received=_integer(_field(row, headers, _UNSW["dst_bytes"], line, "dbytes"), line, "dbytes"),
                syn_count=0,
                rst_count=int(state == "RST"),
                unique_dst_ports_60s=0,
                connections_60s=0,
                failed_connections_60s=0,
                label=_binary_label(label_value),
            )
            yield context.enrich(flow, epoch, failed, line)


def iter_dataset(
    dataset: str, path: str | Path, *, timestamp_format: str | None = None,
    max_rows: int | None = None,
) -> Iterator[FlowRecord]:
    if max_rows is not None and max_rows <= 0:
        raise ValueError("max_rows 必须大于 0")
    if dataset == "cicids2017":
        return iter_cicids2017(path, timestamp_format=timestamp_format, max_rows=max_rows)
    if dataset == "unsw-nb15":
        if timestamp_format:
            raise ValueError("--timestamp-format 仅适用于 CICIDS2017")
        return iter_unsw_nb15(path, max_rows=max_rows)
    raise ValueError(f"不支持的数据集格式: {dataset}")
