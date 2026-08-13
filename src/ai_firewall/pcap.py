from __future__ import annotations

import ipaddress
import struct
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Iterator

from .schema import FlowRecord


PCAPNG_BLOCK_TYPE = b"\x0a\x0d\x0d\x0a"
CLASSIC_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000.0),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000.0),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000.0),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000.0),
}


@dataclass(frozen=True)
class _CapturedPacket:
    timestamp: float
    frame: bytes
    link_type: int


@dataclass
class _FlowAccumulator:
    first_seen: float
    last_seen: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packets: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    syn_count: int = 0
    rst_count: int = 0


def _transport_from_ip(packet: bytes) -> tuple[str, str, int, int, str, int, int, int] | None:
    if not packet:
        return None
    version = packet[0] >> 4
    if version == 4:
        if len(packet) < 20:
            return None
        ihl = (packet[0] & 0x0F) * 4
        if ihl < 20 or len(packet) < ihl:
            return None
        total_length = min(struct.unpack("!H", packet[2:4])[0], len(packet))
        protocol_number = packet[9]
        fragment_offset = struct.unpack("!H", packet[6:8])[0] & 0x1FFF
        if fragment_offset:
            return None
        src_ip = str(ipaddress.ip_address(packet[12:16]))
        dst_ip = str(ipaddress.ip_address(packet[16:20]))
        transport = packet[ihl:total_length]
    elif version == 6:
        if len(packet) < 40:
            return None
        protocol_number = packet[6]
        if protocol_number not in {6, 17}:
            return None
        payload_length = struct.unpack("!H", packet[4:6])[0]
        total_length = min(40 + payload_length, len(packet))
        src_ip = str(ipaddress.ip_address(packet[8:24]))
        dst_ip = str(ipaddress.ip_address(packet[24:40]))
        transport = packet[40:total_length]
    else:
        return None

    if protocol_number == 6 and len(transport) >= 20:
        src_port, dst_port = struct.unpack("!HH", transport[:4])
        flags = transport[13]
        return (
            src_ip, dst_ip, src_port, dst_port, "TCP", total_length,
            int(bool(flags & 0x02)), int(bool(flags & 0x04)),
        )
    if protocol_number == 17 and len(transport) >= 8:
        src_port, dst_port = struct.unpack("!HH", transport[:4])
        return src_ip, dst_ip, src_port, dst_port, "UDP", total_length, 0, 0
    return None


def _network_packet(frame: bytes, link_type: int) -> bytes | None:
    if link_type == 1:  # Ethernet
        if len(frame) < 14:
            return None
        offset = 14
        ether_type = struct.unpack("!H", frame[12:14])[0]
        while ether_type in {0x8100, 0x88A8}:
            if len(frame) < offset + 4:
                return None
            ether_type = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
            offset += 4
        if ether_type not in {0x0800, 0x86DD}:
            return None
        return frame[offset:]
    if link_type == 101:  # Raw IPv4/IPv6
        return frame
    if link_type == 113:  # Linux cooked capture v1
        if len(frame) < 16:
            return None
        protocol = struct.unpack("!H", frame[14:16])[0]
        return frame[16:] if protocol in {0x0800, 0x86DD} else None
    raise ValueError(
        f"暂不支持 capture link type {link_type}；当前支持 Ethernet(1)、RAW(101)、Linux SLL(113)"
    )


def _iter_classic(handle: BinaryIO, max_packets: int | None) -> Iterator[_CapturedPacket]:
    header = handle.read(24)
    if len(header) != 24 or header[:4] not in CLASSIC_MAGIC:
        raise ValueError("不是受支持的 classic PCAP 文件")
    endian, fraction_scale = CLASSIC_MAGIC[header[:4]]
    major, minor, _zone, _sigfigs, _snaplen, link_type = struct.unpack(endian + "HHiIII", header[4:])
    if major != 2 or minor != 4:
        raise ValueError(f"不支持的 PCAP 版本 {major}.{minor}")

    packet_count = 0
    while max_packets is None or packet_count < max_packets:
        packet_header = handle.read(16)
        if not packet_header:
            break
        if len(packet_header) != 16:
            raise ValueError("PCAP 数据包头被截断")
        seconds, fraction, included_length, _original_length = struct.unpack(endian + "IIII", packet_header)
        if included_length > 64 * 1024 * 1024:
            raise ValueError("PCAP 数据包长度异常，已停止解析")
        frame = handle.read(included_length)
        if len(frame) != included_length:
            raise ValueError("PCAP 数据包内容被截断")
        packet_count += 1
        yield _CapturedPacket(seconds + fraction / fraction_scale, frame, link_type)


def _parse_options(options: bytes, endian: str) -> dict[int, list[bytes]]:
    parsed: dict[int, list[bytes]] = defaultdict(list)
    offset = 0
    while offset + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[offset:offset + 4])
        offset += 4
        if code == 0:
            break
        if offset + length > len(options):
            raise ValueError("PCAPNG 选项被截断")
        parsed[code].append(options[offset:offset + length])
        offset += (length + 3) & ~3
    return parsed


def _timestamp_resolution(options: bytes, endian: str) -> float:
    values = _parse_options(options, endian).get(9, [])
    if not values or not values[0]:
        return 1e-6
    value = values[0][0]
    return 2.0 ** -(value & 0x7F) if value & 0x80 else 10.0 ** -value


def _iter_pcapng(handle: BinaryIO, max_packets: int | None) -> Iterator[_CapturedPacket]:
    endian: str | None = None
    interfaces: list[tuple[int, float]] = []
    packet_count = 0

    while max_packets is None or packet_count < max_packets:
        prefix = handle.read(8)
        if not prefix:
            break
        if len(prefix) != 8:
            raise ValueError("PCAPNG block header 被截断")

        if prefix[:4] == PCAPNG_BLOCK_TYPE:
            byte_order_magic = handle.read(4)
            if byte_order_magic == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif byte_order_magic == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ValueError("PCAPNG byte-order magic 无效")
            block_length = struct.unpack(endian + "I", prefix[4:8])[0]
            if block_length < 28 or block_length % 4:
                raise ValueError("PCAPNG section header 长度无效")
            remainder = handle.read(block_length - 12)
            if len(remainder) != block_length - 12:
                raise ValueError("PCAPNG section header 被截断")
            if struct.unpack(endian + "I", remainder[-4:])[0] != block_length:
                raise ValueError("PCAPNG section header 长度校验失败")
            interfaces = []
            continue

        if endian is None:
            raise ValueError("PCAPNG 必须以 Section Header Block 开始")
        block_type, block_length = struct.unpack(endian + "II", prefix)
        if block_length < 12 or block_length % 4 or block_length > 64 * 1024 * 1024:
            raise ValueError("PCAPNG block 长度无效")
        remainder = handle.read(block_length - 8)
        if len(remainder) != block_length - 8:
            raise ValueError("PCAPNG block 被截断")
        if struct.unpack(endian + "I", remainder[-4:])[0] != block_length:
            raise ValueError("PCAPNG block 长度校验失败")
        body = remainder[:-4]

        if block_type == 1:  # Interface Description Block
            if len(body) < 8:
                raise ValueError("PCAPNG interface block 被截断")
            link_type = struct.unpack(endian + "H", body[:2])[0]
            interfaces.append((link_type, _timestamp_resolution(body[8:], endian)))
        elif block_type == 6:  # Enhanced Packet Block
            if len(body) < 20:
                raise ValueError("PCAPNG enhanced packet block 被截断")
            interface_id, high, low, captured_length, _original_length = struct.unpack(
                endian + "IIIII", body[:20]
            )
            if interface_id >= len(interfaces):
                raise ValueError(f"PCAPNG 引用了不存在的 interface {interface_id}")
            if captured_length > len(body) - 20:
                raise ValueError("PCAPNG packet data 被截断")
            link_type, resolution = interfaces[interface_id]
            timestamp = ((high << 32) | low) * resolution
            packet_count += 1
            yield _CapturedPacket(timestamp, body[20:20 + captured_length], link_type)


def _flow_key(decoded: tuple[str, str, int, int, str, int, int, int], bidirectional: bool) -> tuple[object, ...]:
    src_ip, dst_ip, src_port, dst_port, protocol, *_ = decoded
    if not bidirectional:
        return src_ip, dst_ip, src_port, dst_port, protocol
    endpoints = sorted(((src_ip, src_port), (dst_ip, dst_port)))
    return endpoints[0], endpoints[1], protocol


def _iso_timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _aggregate(packets: Iterator[_CapturedPacket], bidirectional: bool) -> list[FlowRecord]:
    accumulators: dict[tuple[object, ...], _FlowAccumulator] = {}
    for captured in packets:
        network = _network_packet(captured.frame, captured.link_type)
        decoded = _transport_from_ip(network or b"")
        if decoded is None:
            continue
        src_ip, dst_ip, src_port, dst_port, protocol, byte_count, syn, rst = decoded
        key = _flow_key(decoded, bidirectional)
        accumulator = accumulators.get(key)
        if accumulator is None:
            accumulator = _FlowAccumulator(
                captured.timestamp, captured.timestamp, src_ip, dst_ip,
                src_port, dst_port, protocol,
            )
            accumulators[key] = accumulator
        same_direction = (
            src_ip == accumulator.src_ip and dst_ip == accumulator.dst_ip
            and src_port == accumulator.src_port and dst_port == accumulator.dst_port
        )
        accumulator.first_seen = min(accumulator.first_seen, captured.timestamp)
        accumulator.last_seen = max(accumulator.last_seen, captured.timestamp)
        accumulator.packets += 1
        if same_direction:
            accumulator.bytes_sent += byte_count
        else:
            accumulator.bytes_received += byte_count
        accumulator.syn_count += syn
        accumulator.rst_count += rst

    ordered = sorted(accumulators.values(), key=lambda item: item.first_seen)
    recent_by_source: dict[str, deque[_FlowAccumulator]] = defaultdict(deque)
    records: list[FlowRecord] = []
    for accumulator in ordered:
        recent = recent_by_source[accumulator.src_ip]
        while recent and recent[0].first_seen < accumulator.first_seen - 60:
            recent.popleft()
        recent.append(accumulator)
        records.append(FlowRecord(
            timestamp=_iso_timestamp(accumulator.first_seen),
            src_ip=accumulator.src_ip,
            dst_ip=accumulator.dst_ip,
            src_port=accumulator.src_port,
            dst_port=accumulator.dst_port,
            protocol=accumulator.protocol,
            duration_ms=max((accumulator.last_seen - accumulator.first_seen) * 1000, 0.0),
            packets=accumulator.packets,
            bytes_sent=accumulator.bytes_sent,
            bytes_received=accumulator.bytes_received,
            syn_count=accumulator.syn_count,
            rst_count=accumulator.rst_count,
            unique_dst_ports_60s=len({item.dst_port for item in recent}),
            connections_60s=len(recent),
            failed_connections_60s=sum(item.rst_count > 0 for item in recent),
        ))
    return records


def read_pcap(
    path: str | Path, max_packets: int | None = None, bidirectional: bool = True,
) -> list[FlowRecord]:
    """Read classic PCAP and aggregate flows; reverse packets are merged by default."""
    with Path(path).open("rb") as handle:
        return _aggregate(_iter_classic(handle, max_packets), bidirectional)


def read_pcapng(
    path: str | Path, max_packets: int | None = None, bidirectional: bool = True,
) -> list[FlowRecord]:
    """Read PCAPNG Enhanced Packet Blocks from one or more interfaces/sections."""
    with Path(path).open("rb") as handle:
        return _aggregate(_iter_pcapng(handle, max_packets), bidirectional)


def read_capture(
    path: str | Path, max_packets: int | None = None, bidirectional: bool = True,
) -> list[FlowRecord]:
    """Auto-detect classic PCAP or PCAPNG and return aggregated network flows."""
    capture_path = Path(path)
    with capture_path.open("rb") as handle:
        magic = handle.read(4)
    if magic == PCAPNG_BLOCK_TYPE:
        return read_pcapng(capture_path, max_packets=max_packets, bidirectional=bidirectional)
    if magic in CLASSIC_MAGIC:
        return read_pcap(capture_path, max_packets=max_packets, bidirectional=bidirectional)
    raise ValueError("文件既不是受支持的 classic PCAP，也不是 PCAPNG")

